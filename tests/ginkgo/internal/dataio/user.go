// SPDX-License-Identifier: GPL-2.0-only
package dataio

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"regexp"
)

type modelBlock struct {
	Path    string  `json:"path"`
	Type    string  `json:"type"`
	Size    uint64  `json:"size"`
	Logical uint32  `json:"log-sec"`
	Model   *string `json:"model"`
	HCTL    *string `json:"hctl"`
}

func modelBlocks(output string) ([]modelBlock, error) {
	var list struct {
		Devices []modelBlock `json:"blockdevices"`
	}
	if err := json.Unmarshal([]byte(output), &list); err != nil {
		return nil, err
	}
	if list.Devices == nil {
		return nil, fmt.Errorf("missing lsblk device list")
	}
	return list.Devices, nil
}

// FindModel addresses the LUN 0 disk whose INQUIRY product identification is
// model. The user-space fileio handler reports its device name there.
func (e *Endpoint) FindModel(ctx context.Context, model string) error {
	r, err := e.Run(ctx, e.Timeout, "lsblk", "--json", "--bytes", "--nodeps",
		"--output", "PATH,TYPE,SIZE,LOG-SEC,MODEL,HCTL")
	if err != nil {
		return err
	}
	if r.ExitCode != 0 {
		return fmt.Errorf("lsblk: %s", r.String())
	}
	devices, err := modelBlocks(r.Stdout)
	if err != nil {
		return err
	}
	var matches []modelBlock
	for _, d := range devices {
		if d.Model != nil && *d.Model == model && d.HCTL != nil &&
			regexp.MustCompile(`^\d+:\d+:\d+:0$`).MatchString(*d.HCTL) {
			matches = append(matches, d)
		}
	}
	if len(matches) != 1 {
		return fmt.Errorf("expected one exported disk with model %s, found %d", model, len(matches))
	}
	d := matches[0]
	if d.Type != "disk" || !regexp.MustCompile(`^/dev/[a-zA-Z0-9/_-]+$`).MatchString(d.Path) ||
		d.Size != e.Backend.Bytes || d.Logical != e.Backend.BlockSize {
		return fmt.Errorf("exported device geometry mismatch: %+v", d)
	}
	e.Path = d.Path
	// Also consumes the unit attention reported for a new LUN.
	_, err = e.sg(ctx, "sg_turs")
	return err
}

func (e *Endpoint) readBlock(ctx context.Context, lba uint64, want []byte) error {
	data, err := success(e.raw(ctx, false, lba, nil))
	if err != nil {
		return err
	}
	if !bytes.Equal(data, want) {
		return fmt.Errorf("READ of LBA %d returned different data", lba)
	}
	return nil
}

// READ CAPACITY CDBs whose replies a handler fault can corrupt.
var (
	ReadCapacity10 = []byte{0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	ReadCapacity16 = []byte{0x9e, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0}
)

// UserHandlerFault checks a disk served by the user-space fileio handler
// across a handler fault. Reading LBA 0, which holds lba0, leaves known bytes
// in a cached handler buffer; later commands may use another buffer. arm
// enables the fault in the handler: with a capacity CDB it replaces the block
// length of that command's reply, otherwise it forks after replying to the
// next command. The fixture must use MADV_DONTFORK on kernels older than 5.9.
// Afterwards geometry, reads and writes must be unaffected on every kernel.
func (e *Endpoint) UserHandlerFault(ctx context.Context, lba0 []byte, arm func() error, capacityCDB []byte) error {
	if err := e.Capacity(ctx); err != nil {
		return fmt.Errorf("before the fault: %w", err)
	}
	if err := e.readBlock(ctx, 0, lba0); err != nil {
		return err
	}
	if err := arm(); err != nil {
		return err
	}
	if capacityCDB != nil {
		request := 8
		if capacityCDB[0] == 0x9e {
			request = 32
		}
		// scst_sense_internal_failure is 0b/44/00.
		r, err := e.rawCDB(ctx, capacityCDB, nil, request)
		if err := rejection(r, err, 11, [3]byte{0xb, 0x44, 0}); err != nil {
			return fmt.Errorf("invalid block length: %w", err)
		}
	} else if _, err := e.sg(ctx, "sg_turs"); err != nil {
		return err
	}
	if err := e.Capacity(ctx); err != nil {
		return fmt.Errorf("after the fault: %w", err)
	}
	if err := e.readBlock(ctx, 0, lba0); err != nil {
		return err
	}
	payload := bytes.Repeat([]byte("SCSTUSER"), int(e.Backend.BlockSize)/8)
	if _, err := success(e.raw(ctx, true, 1, payload)); err != nil {
		return err
	}
	return e.readBlock(ctx, 1, payload)
}
