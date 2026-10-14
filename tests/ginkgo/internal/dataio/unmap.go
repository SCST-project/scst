// SPDX-License-Identifier: GPL-2.0-only
package dataio

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"time"
)

// fileio deliberately does not advertise LBPRZ. These tests exercise its
// hole-punch implementation on a capable filesystem, not a generic guarantee
// that reads of unmapped blocks return zero. Probe only the newly owned file,
// before exporting it; unsupported hole punching must not look like a pass.
func checkHolePunch(ctx context.Context, f *os.File, run RunFunc, timeout time.Duration) error {
	data := bytes.Repeat([]byte{0xa5}, 4096)
	if _, err := f.WriteAt(data, 0); err != nil {
		return err
	}
	r, err := run(ctx, timeout, "fallocate", "--punch-hole", "--keep-size", "--offset=0", "--length=4096", "--", f.Name())
	if err != nil {
		return err
	}
	if r.ExitCode != 0 {
		return fmt.Errorf("UNMAP requires hole punching in backing_dir: %s", r.String())
	}
	if _, err := f.ReadAt(data, 0); err != nil {
		return err
	}
	if !bytes.Equal(data, make([]byte, len(data))) {
		return fmt.Errorf("UNMAP requires zero-filled holes in backing_dir")
	}
	return nil
}

type unmapCase struct {
	parameterLength  uint16
	descriptorLength uint16
	unmapped         int
	lengthError      bool
}

const (
	unmapStartLBA    = 16
	unmapChunkBlocks = 8 // 4 KiB with the fixture's 512-byte sectors.
	unmapChunks      = 5 // guard, descriptor 0, guard, descriptor 1, guard.
)

func unmapCDB(tc unmapCase) ([]byte, []byte, error) {
	if tc.parameterLength > 40 {
		return nil, nil, fmt.Errorf("UNMAP fixture supports at most two descriptors")
	}
	cdb := make([]byte, 10)
	cdb[0] = 0x42
	binary.BigEndian.PutUint16(cdb[7:9], tc.parameterLength)
	parameters := make([]byte, 40)
	if tc.parameterLength >= 2 {
		binary.BigEndian.PutUint16(parameters[0:2], tc.parameterLength-2)
	}
	binary.BigEndian.PutUint16(parameters[2:4], tc.descriptorLength)
	// Fill both descriptors independently of the expected result. In particular,
	// a truncated descriptor still names valid nonzero data that must survive.
	for i := 0; i < 2; i++ {
		offset := 8 + i*16
		binary.BigEndian.PutUint64(parameters[offset:offset+8], unmapStartLBA+uint64(1+2*i)*unmapChunkBlocks)
		binary.BigEndian.PutUint32(parameters[offset+8:offset+12], unmapChunkBlocks)
	}
	// SG_IO and the CDB declare the same transfer. Malformed descriptor fields
	// reach SCST without relying on transport underflow or timeout behavior.
	return cdb, parameters[:tc.parameterLength], nil
}

func (e *Endpoint) unmapCommand(ctx context.Context, tc unmapCase) error {
	if e.ReadOnly || e.Backend.Handler != "vdisk_fileio" || e.Backend.BlockSize != 512 ||
		e.Backend.Bytes/512 < unmapStartLBA+unmapChunks*unmapChunkBlocks || tc.unmapped < 0 || tc.unmapped > 2 {
		return fmt.Errorf("invalid UNMAP fixture geometry/access or expectation")
	}
	cdb, parameters, err := unmapCDB(tc)
	if err != nil {
		return err
	}
	chunkBytes := unmapChunkBlocks * int(e.Backend.BlockSize)
	want := make([]byte, unmapChunks*chunkBytes)
	for i := range want {
		want[i] = byte(0x51 + i/chunkBytes)
	}
	write, err := readWriteCDB(true, true, false, unmapStartLBA, unmapChunks*unmapChunkBlocks)
	if err != nil {
		return err
	}
	if _, err := success(e.rawCDB(ctx, write, want, 0)); err != nil {
		return fmt.Errorf("UNMAP baseline WRITE: %w", err)
	}
	read, err := readWriteCDB(true, false, false, unmapStartLBA, unmapChunks*unmapChunkBlocks)
	if err != nil {
		return err
	}
	before, err := success(e.rawCDB(ctx, read, nil, len(want)))
	if err != nil {
		return fmt.Errorf("UNMAP baseline READ: %w", err)
	}
	if !bytes.Equal(before, want) {
		return fmt.Errorf("UNMAP baseline data mismatch")
	}
	r, err := e.rawCDB(ctx, cdb, parameters, 0)
	if tc.lengthError {
		// ILLEGAL REQUEST / PARAMETER LIST LENGTH ERROR.
		err = rejection(r, err, 5, [3]byte{5, 0x1a, 0})
	} else {
		_, err = success(r, err)
	}
	if err != nil {
		return fmt.Errorf("UNMAP completion: %w", err)
	}
	for i := 0; i < tc.unmapped; i++ {
		start := (1 + 2*i) * chunkBytes
		clear(want[start : start+chunkBytes])
	}
	after, err := success(e.rawCDB(ctx, read, nil, len(want)))
	if err != nil {
		return fmt.Errorf("UNMAP readback: %w", err)
	}
	if len(after) != len(want) {
		return fmt.Errorf("UNMAP readback: got %d bytes, want %d", len(after), len(want))
	}
	for i := range want {
		if after[i] != want[i] {
			return fmt.Errorf("UNMAP readback at LBA %d byte %d: got %02x, want %02x",
				unmapStartLBA+i/512, i%512, after[i], want[i])
		}
	}
	return nil
}

func (e *Endpoint) UNMAP(ctx context.Context, tc unmapCase) error {
	if err := e.Check(ctx); err != nil {
		return err
	}
	data, err := e.sg(ctx, "sg_inq", "--raw", "--page=0xb2")
	if err != nil {
		return err
	}
	page, err := vpd(data, 0xb2)
	if err != nil {
		return err
	}
	if len(page) < 4 || page[1]&0x80 == 0 {
		return fmt.Errorf("UNMAP fixture does not advertise LBPU")
	}
	return e.unmapCommand(ctx, tc)
}
