// SPDX-License-Identifier: GPL-2.0-only
package dataio

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
)

func vpd(data []byte, page byte) ([]byte, error) {
	if len(data) < 4 || data[0] != 0 || data[1] != page {
		return nil, fmt.Errorf("invalid VPD page %02x: %x", page, data)
	}
	n := int(binary.BigEndian.Uint16(data[2:4]))
	if len(data) < 4+n {
		return nil, fmt.Errorf("truncated VPD page %02x", page)
	}
	return data[4 : 4+n], nil
}

func identity83(data []byte, serial string) error {
	descriptors, err := vpd(data, 0x83)
	if err != nil {
		return err
	}
	found := false
	for len(descriptors) > 0 {
		if len(descriptors) < 4 || int(descriptors[3])+4 > len(descriptors) {
			return fmt.Errorf("truncated VPD designator")
		}
		n := int(descriptors[3])
		// ASCII T10 vendor identifier, associated with the logical unit.
		if descriptors[0]&0xf == 2 && descriptors[1]&0x3f == 1 && n >= 8 {
			found = found || strings.TrimRight(string(descriptors[12:4+n]), "\x00 ") == serial
		}
		descriptors = descriptors[4+n:]
	}
	if !found {
		return fmt.Errorf("VPD 83 lacks the fixture's logical-unit identifier %s", serial)
	}
	return nil
}

func (e *Endpoint) Identity(ctx context.Context) error {
	data, err := e.sg(ctx, "sg_inq", "--raw", "--len=96")
	if err != nil {
		return err
	}
	if len(data) < 36 || data[0] != 0 || int(data[4])+5 > len(data) {
		return fmt.Errorf("invalid direct-access INQUIRY: %x", data)
	}
	data, err = e.sg(ctx, "sg_inq", "--raw", "--page=0x80")
	if err != nil {
		return err
	}
	serial, err := vpd(data, 0x80)
	if err != nil {
		return err
	}
	if strings.TrimRight(string(serial), "\x00 ") != e.Backend.Serial {
		return fmt.Errorf("VPD 80 serial mismatch: %q", serial)
	}
	data, err = e.sg(ctx, "sg_inq", "--raw", "--page=0x83")
	if err != nil {
		return err
	}
	return identity83(data, e.Backend.Serial)
}

func capacity(data []byte, sixteen bool) (uint64, uint32, error) {
	if sixteen {
		if len(data) != 32 {
			return 0, 0, fmt.Errorf("READ CAPACITY(16) returned %d bytes", len(data))
		}
		return binary.BigEndian.Uint64(data[:8]), binary.BigEndian.Uint32(data[8:12]), nil
	}
	if len(data) != 8 {
		return 0, 0, fmt.Errorf("READ CAPACITY(10) returned %d bytes", len(data))
	}
	return uint64(binary.BigEndian.Uint32(data[:4])), binary.BigEndian.Uint32(data[4:]), nil
}

func (e *Endpoint) Capacity(ctx context.Context) error {
	for _, sixteen := range []bool{false, true} {
		flag := "--10"
		if sixteen {
			flag = "--16"
		}
		data, err := e.sg(ctx, "sg_readcap", "--raw", flag)
		if err != nil {
			return err
		}
		last, block, err := capacity(data, sixteen)
		if err != nil {
			return err
		}
		want := e.Backend.Bytes/uint64(e.Backend.BlockSize) - 1
		if !sixteen && want > 0xffffffff {
			want = 0xffffffff
		}
		if last != want || block != e.Backend.BlockSize {
			return fmt.Errorf("READ CAPACITY %s: last LBA %d, block %d; want %d, %d", flag, last, block, want, e.Backend.BlockSize)
		}
	}
	return nil
}

func luns(data []byte) ([]int, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("short REPORT LUNS header")
	}
	n := int(binary.BigEndian.Uint32(data[:4]))
	if n%8 != 0 || n > len(data)-8 {
		return nil, fmt.Errorf("truncated/misaligned REPORT LUNS")
	}
	var result []int
	for data = data[8 : 8+n]; len(data) > 0; data = data[8:] {
		// These fixtures use peripheral addressing and simple LUN numbers.
		if data[0] != 0 || !bytes.Equal(data[2:8], make([]byte, 6)) {
			return nil, fmt.Errorf("unexpected LUN encoding: %x", data[:8])
		}
		result = append(result, int(data[1]))
	}
	slices.Sort(result)
	return result, nil
}

func (e *Endpoint) LUNs(ctx context.Context) error {
	data, err := e.sg(ctx, "sg_luns", "--raw", "--maxlen=256")
	if err != nil {
		return err
	}
	got, err := luns(data)
	if err != nil {
		return err
	}
	if !slices.Equal(got, []int{0, 7}) {
		return fmt.Errorf("REPORT LUNS = %v, want only accessible LUNs [0 7]", got)
	}
	return nil
}

// Decode raw sense from sg_raw --verbose. A utility/OS error without a SCSI
// CHECK CONDITION and the exact key/ASC/ASCQ cannot satisfy a negative test.
func sense(stderr string) ([3]byte, error) {
	var result [3]byte
	if !strings.Contains(strings.ToLower(stderr), "scsi status: check condition") {
		return result, fmt.Errorf("missing CHECK CONDITION: %s", stderr)
	}
	_, raw, ok := strings.Cut(stderr, "Raw sense data (in hex)")
	if !ok {
		return result, fmt.Errorf("missing raw sense: %s", stderr)
	}
	_, raw, _ = strings.Cut(raw, "\n")
	var data []byte
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			if len(data) != 0 {
				break
			}
			continue
		}
		var row []byte
		for _, f := range fields {
			if len(f) != 2 {
				break
			}
			b, err := hex.DecodeString(f)
			if err != nil {
				break
			}
			row = append(row, b[0])
		}
		if len(row) != len(fields) {
			break
		}
		data = append(data, row...)
	}
	if len(data) < 8 || int(data[7])+8 > len(data) {
		return result, fmt.Errorf("truncated raw sense: %x", data)
	}
	switch data[0] & 0x7f {
	case 0x70:
		if len(data) < 14 || data[7] < 6 {
			return result, fmt.Errorf("short fixed sense")
		}
		return [3]byte{data[2] & 0xf, data[12], data[13]}, nil
	case 0x72:
		return [3]byte{data[1] & 0xf, data[2], data[3]}, nil
	default:
		return result, fmt.Errorf("unexpected/deferred sense response: %x", data[0])
	}
}

func (e *Endpoint) raw(ctx context.Context, write bool, lba uint64, input []byte) (Reply, error) {
	cdb := make([]byte, 16)
	cdb[0] = 0x88 // READ(16), one logical block.
	if write {
		cdb[0] = 0x8a
	}
	binary.BigEndian.PutUint64(cdb[2:10], lba)
	binary.BigEndian.PutUint32(cdb[10:14], 1)
	// O_RDONLY permits opening a read-only LUN. Root SG_IO still submits the
	// WRITE CDB; its rejection must carry target sense, not an open() error.
	args := []string{"sg_raw", "--readonly", "--verbose", "--binary"}
	if write {
		args = append(args, fmt.Sprintf("--send=%d", len(input)))
	} else {
		args = append(args, fmt.Sprintf("--request=%d", e.Backend.BlockSize))
	}
	args = append(args, e.Path)
	for _, b := range cdb {
		args = append(args, fmt.Sprintf("%02x", b))
	}
	return command(ctx, e.Run, e.Timeout, input, args...)
}

func rejection(r Reply, err error, exit int, want [3]byte) error {
	if err != nil {
		return err
	}
	if r.ExitCode != exit {
		return fmt.Errorf("sg_raw exit %d, want %d: %s", r.ExitCode, exit, r.Stderr)
	}
	got, err := sense(r.Stderr)
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("sense key/ASC/ASCQ %x, want %x: %s", got, want, r.Stderr)
	}
	return nil
}

func (e *Endpoint) ReadOnlyWrite(ctx context.Context) error {
	if err := e.Check(ctx); err != nil {
		return err
	}
	before, err := success(e.raw(ctx, false, 0, nil))
	if err != nil {
		return err
	}
	if len(before) != int(e.Backend.BlockSize) {
		return fmt.Errorf("short baseline READ")
	}
	payload := bytes.Repeat([]byte{0xa5}, len(before))
	if bytes.Equal(payload, before) {
		payload[0] ^= 0xff
	}
	r, err := e.raw(ctx, true, 0, payload)
	// The read-only LUN check uses scst_sense_data_protect (07/00/00).
	if err := rejection(r, err, 7, [3]byte{7, 0, 0}); err != nil {
		return err
	}
	after, err := success(e.raw(ctx, false, 0, nil))
	if err != nil {
		return err
	}
	if !bytes.Equal(before, after) {
		return fmt.Errorf("rejected WRITE changed data")
	}
	return nil
}

func (e *Endpoint) OutOfRange(ctx context.Context) error {
	r, err := e.raw(ctx, false, e.Backend.Bytes/uint64(e.Backend.BlockSize), nil)
	if err := rejection(r, err, 22, [3]byte{5, 0x21, 0}); err != nil {
		return err
	}
	data, err := success(e.raw(ctx, false, 0, nil))
	if err != nil {
		return err
	}
	if len(data) != int(e.Backend.BlockSize) {
		return fmt.Errorf("short valid READ after rejected CDB")
	}
	return nil
}
