// SPDX-License-Identifier: GPL-2.0-only
package dataio

import (
	"encoding/binary"
	"strings"
	"testing"
)

func TestVPDIdentity(t *testing.T) {
	// Target-port identifiers must not substitute for the LU identifier.
	page := []byte{0, 0x83, 0, 15, 2, 1, 0, 11}
	page = append(page, []byte("SCST_FIOabc")...)
	if err := identity83(page, "abc"); err != nil {
		t.Fatal(err)
	}
	port := append([]byte(nil), page...)
	port[5] = 0x11
	for name, data := range map[string][]byte{
		"short header": page[:3], "truncated page": page[:len(page)-1], "port only": port,
		"wrong page": {0, 0x80, 0, 0}, "empty": {0, 0x83, 0, 0},
		"short descriptor": {0, 0x83, 0, 3, 2, 1, 0},
	} {
		t.Run(name, func(t *testing.T) {
			if identity83(data, "abc") == nil {
				t.Fatal("accepted invalid identity")
			}
		})
	}
	if identity83(page, "other") == nil {
		t.Fatal("accepted another disk")
	}
}

func TestCapacityAndLUNs(t *testing.T) {
	ten := []byte{0, 0, 1, 0xff, 0, 0, 2, 0}
	last, block, err := capacity(ten, false)
	if err != nil || last != 511 || block != 512 {
		t.Fatalf("capacity10: %d %d %v", last, block, err)
	}
	sixteen := make([]byte, 32)
	binary.BigEndian.PutUint64(sixteen, 0x100000001)
	binary.BigEndian.PutUint32(sixteen[8:], 4096)
	last, block, err = capacity(sixteen, true)
	if err != nil || last != 0x100000001 || block != 4096 {
		t.Fatalf("capacity16: %d %d %v", last, block, err)
	}
	if _, _, err := capacity(sixteen[:31], true); err == nil {
		t.Fatal("accepted truncated capacity")
	}
	report := make([]byte, 24)
	report[3], report[9] = 16, 7
	got, err := luns(report)
	if err != nil || len(got) != 2 || got[0] != 0 || got[1] != 7 {
		t.Fatalf("LUNs: %v %v", got, err)
	}
	for _, data := range [][]byte{report[:7], report[:23], {0, 0, 0, 1, 0, 0, 0, 0, 0}} {
		if _, err := luns(data); err == nil {
			t.Fatal("accepted malformed LUN list")
		}
	}
	report[8] = 0xc0
	if _, err := luns(report); err == nil {
		t.Fatal("accepted unexpected LUN encoding")
	}
}

const fixedSense = `SCSI Status: Check Condition

Sense Information:
Fixed format, current; Sense key: Data Protect
Additional sense: No additional sense information
 Raw sense data (in hex), sb_len=18, calculated_len=18
        70 00 07 00 00 00 00 0a  00 00 00 00 00 00 00 00
        00 00

`
const descriptorSense = `SCSI Status: Check Condition
 Raw sense data (in hex), sb_len=8, calculated_len=8
        72 05 21 00 00 00 00 00
`

func TestNegativeCDBRequiresActualSense(t *testing.T) {
	if err := rejection(Reply{ExitCode: 7, Stderr: fixedSense}, nil, 7, [3]byte{7, 0, 0}); err != nil {
		t.Fatal(err)
	}
	if err := rejection(Reply{ExitCode: 22, Stderr: descriptorSense}, nil, 22, [3]byte{5, 0x21, 0}); err != nil {
		t.Fatal(err)
	}
	for name, reply := range map[string]Reply{
		"no sense":       {ExitCode: 7, Stderr: "open: Read-only filesystem"},
		"wrong exit":     {ExitCode: 1, Stderr: fixedSense},
		"wrong sense":    {ExitCode: 7, Stderr: descriptorSense},
		"wrong status":   {ExitCode: 7, Stderr: strings.ReplaceAll(fixedSense, "Check Condition", "Good")},
		"deferred sense": {ExitCode: 7, Stderr: strings.ReplaceAll(fixedSense, "70 00 07", "71 00 07")},
		"short sense":    {ExitCode: 7, Stderr: strings.ReplaceAll(fixedSense, "        00 00\n", "")},
	} {
		t.Run(name, func(t *testing.T) {
			if rejection(reply, nil, 7, [3]byte{7, 0, 0}) == nil {
				t.Fatal("accepted unrelated/incomplete failure")
			}
		})
	}
}
