// SPDX-License-Identifier: GPL-2.0-only
package dataio

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
)

func rangeCDB(sixteen bool, op10, op16 byte, lba uint64, blocks uint32) ([]byte, error) {
	if sixteen {
		cdb := make([]byte, 16)
		cdb[0] = op16
		binary.BigEndian.PutUint64(cdb[2:], lba)
		binary.BigEndian.PutUint32(cdb[10:], blocks)
		return cdb, nil
	}
	if lba > 0xffffffff || blocks > 0xffff {
		return nil, fmt.Errorf("range cannot be encoded in a 10-byte CDB")
	}
	cdb := make([]byte, 10)
	cdb[0] = op10
	binary.BigEndian.PutUint32(cdb[2:], uint32(lba))
	binary.BigEndian.PutUint16(cdb[7:], uint16(blocks))
	return cdb, nil
}

func readWriteCDB(sixteen, write, fua bool, lba uint64, blocks uint32) ([]byte, error) {
	op10, op16 := byte(0x28), byte(0x88)
	if write {
		op10, op16 = 0x2a, 0x8a
	}
	cdb, err := rangeCDB(sixteen, op10, op16, lba, blocks)
	if err == nil && fua {
		cdb[1] = 8
	}
	return cdb, err
}

func synchronizeCacheCDB(sixteen, immed bool, lba uint64, blocks uint32) ([]byte, error) {
	cdb, err := rangeCDB(sixteen, 0x35, 0x91, lba, blocks)
	if err == nil && immed {
		cdb[1] = 2
	}
	return cdb, err
}

type cacheOperation struct {
	name                       string
	sixteen, fua, toEnd, immed bool
	lba                        uint64
	blocks                     uint32
}

func (e *Endpoint) cacheCommand(ctx context.Context, op cacheOperation) error {
	if e.ReadOnly || e.Backend.BlockSize == 0 || op.blocks == 0 || op.blocks > 16 {
		return fmt.Errorf("invalid writable cache-command fixture")
	}
	capacity := e.Backend.Bytes / uint64(e.Backend.BlockSize)
	if op.lba >= capacity || uint64(op.blocks) > capacity-op.lba {
		return fmt.Errorf("cache-command range exceeds fixture capacity")
	}
	length := int(op.blocks) * int(e.Backend.BlockSize)
	payload := make([]byte, length)
	for i := range payload {
		payload[i] = byte(uint64(i)*17 + uint64(i)/uint64(e.Backend.BlockSize)*73 + op.lba)
	}
	write, err := readWriteCDB(op.sixteen, true, op.fua, op.lba, op.blocks)
	if err != nil {
		return err
	}
	if _, err := success(e.rawCDB(ctx, write, payload, 0)); err != nil {
		return err
	}
	if !op.fua {
		blocks := op.blocks
		if op.toEnd {
			blocks = 0
		}
		cdb, err := synchronizeCacheCDB(op.sixteen, op.immed, op.lba, blocks)
		if err != nil {
			return err
		}
		if _, err := success(e.rawCDB(ctx, cdb, nil, 0)); err != nil {
			return err
		}
	}
	// FUA readback must precede any later explicit synchronization. Readback
	// validates command completion and payload, not crash persistence.
	read, err := readWriteCDB(op.sixteen, false, false, op.lba, op.blocks)
	if err != nil {
		return err
	}
	got, err := success(e.rawCDB(ctx, read, nil, length))
	if err != nil {
		return err
	}
	if !bytes.Equal(got, payload) {
		return fmt.Errorf("readback mismatch at LBA %d", op.lba)
	}
	return nil
}

// CacheCommands uses fresh regions in the sparse fixture. Cache-bypass controls
// exercise FUA only: their commandless IMMED path has a separate known defect.
func (e *Endpoint) CacheCommands(ctx context.Context, explicitCache bool) error {
	if err := e.Check(ctx); err != nil {
		return err
	}
	ops := []cacheOperation{
		{name: "WRITE(10) FUA", fua: true, lba: 16, blocks: 1},
		{name: "WRITE(16) FUA cross-page", sixteen: true, fua: true, lba: 31, blocks: 9},
	}
	if explicitCache {
		ops = append(ops,
			cacheOperation{name: "CACHE(10) range", lba: 95, blocks: 9},
			cacheOperation{name: "CACHE(16) range", sixteen: true, lba: 160, blocks: 1},
			cacheOperation{name: "CACHE(10) to end", toEnd: true, lba: 223, blocks: 9},
			cacheOperation{name: "CACHE(16) to end", sixteen: true, toEnd: true, lba: 288, blocks: 1},
			cacheOperation{name: "CACHE(10) IMMED", immed: true, lba: 351, blocks: 9},
			cacheOperation{name: "CACHE(16) IMMED", sixteen: true, immed: true, lba: 416, blocks: 1})
	}
	for _, op := range ops {
		if err := e.cacheCommand(ctx, op); err != nil {
			return fmt.Errorf("%s: %w", op.name, err)
		}
	}
	return nil
}
