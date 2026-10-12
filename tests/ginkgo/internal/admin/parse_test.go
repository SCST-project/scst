// SPDX-License-Identifier: GPL-2.0-only
package admin

import (
	"reflect"
	"testing"
)

func output(table string) string {
	return "Collecting current configuration: done.\n\n" + table + "\nAll done.\n"
}

func TestDeviceTable(t *testing.T) {
	r, err := Pairs(output("Handler        Device\n---------------------\nvdisk_fileio   -\nvdisk_nullio   first\n               second"), "Handler", "Device")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r, map[string]string{"first": "vdisk_nullio", "second": "vdisk_nullio"}) {
		t.Fatalf("wrong device ownership: %v", r)
	}
	empty, err := Pairs(output("Driver Target\n-------------"), "Driver", "Target")
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty target table: %v %v", empty, err)
	}
	for _, table := range []string{"Driver Target\n orphan", "Driver Target\nlocal one\nlocal one", "No such driver 'local' exists."} {
		if _, err := Pairs(output(table), "Driver", "Target"); err == nil {
			t.Fatalf("accepted malformed table %q", table)
		}
	}
}

func TestAttributes(t *testing.T) {
	r, err := Attributes(output(`Attribute         Value          Writable      KEY
----------------------------------------------------------
measure_latency   1              Yes           Yes
optional          <not set>      Yes           No
trace_level       mgmt           Yes           No
                  pid            Yes           No

Possible trace levels:
  (use trace_level="add <level>", none, all or default to set):
    mgmt, pid,`))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r["trace_level"].Values, []string{"mgmt", "pid"}) || !r["measure_latency"].Key || r["optional"].Values[0] != "<not set>" {
		t.Fatalf("incorrect attributes: %+v", r)
	}
	for _, table := range []string{"Attribute Value Writable KEY\nx  1  perhaps  No", "Attribute Value Writable KEY\nPossible trace levels:", "device not found"} {
		if _, err := Attributes(output(table)); err == nil {
			t.Fatalf("accepted malformed attributes: %q", table)
		}
	}
}

func TestAttributeCapabilityAppendices(t *testing.T) {
	table := `Attribute       Value   Writable   KEY
rel_tgt_id      60000   Yes        Yes
read_only       0       Yes        No`
	for _, appendix := range []string{
		"LUN CREATE attributes available\n-------------------------------\nread_only",
		"Dynamic attributes available\n----------------------------\nportal\nLUN CREATE attributes available\nread_only",
		"LUN CREATE attributes available\nread_only\nInitiator CREATE attributes available\nactive",
		"Device CREATE attributes available\nfilename\nread_only",
		"Target CREATE attributes available:\nsession_name",
	} {
		t.Run(appendix, func(t *testing.T) {
			attrs, err := Attributes(output(table + "\n" + appendix))
			if err != nil {
				t.Fatal(err)
			}
			want := map[string]Attribute{
				"rel_tgt_id": {Values: []string{"60000"}, Writable: true, Key: true},
				"read_only":  {Values: []string{"0"}, Writable: true},
			}
			if !reflect.DeepEqual(attrs, want) {
				t.Fatalf("capability names changed current attributes: %+v", attrs)
			}
		})
	}
	for _, appendix := range []string{
		"LUN CREATE attributes available",
		"LUN CREATE attributes available\nInitiator CREATE attributes available\nactive",
		"LUN CREATE attributes available\nread_only\nLUN CREATE attributes available\nread_only",
		"LUN CREATE attributes available\nread_only\nunexpected output",
		"LUN CREATE attributes available\nread_only\nrel_tgt_id  1  Yes  Yes",
		"Unknown attributes available\nread_only",
	} {
		if _, err := Attributes(output(table + "\n" + appendix)); err == nil {
			t.Fatalf("accepted malformed appendix %q", appendix)
		}
	}
}

func TestAssignmentScopes(t *testing.T) {
	r, err := ParseAssignments(output(`Driver: scst_local
Target: local
Assigned LUNs:
 LUN Device
 0 default_disk
Group: group_a
Assigned LUNs:
 LUN Device
 0 first_disk
Assigned Initiators:
 Initiator
 ini1
 ini2
Group: group_b
Group 'group_b' has no associated LUNs or initiators.`))
	if err != nil {
		t.Fatal(err)
	}
	if r.LUNs[0] != "default_disk" || r.Groups["group_a"].LUNs[0] != "first_disk" || len(r.Groups["group_a"].Initiators) != 2 || len(r.Groups["group_b"].LUNs) != 0 {
		t.Fatalf("scope lost: %+v", r)
	}
	empty, err := ParseAssignments(output("Driver: scst_local\nTarget: local\nDriver/target 'scst_local/local' has no associated LUNs."))
	if err != nil || len(empty.LUNs) != 0 || len(empty.Groups) != 0 {
		t.Fatalf("empty assignments: %v %v", empty, err)
	}
	if _, err := ParseAssignments(output("Driver/target 'scst_local/missing' not found")); err == nil {
		t.Fatal("missing target treated as empty")
	}
}

func TestNamedSections(t *testing.T) {
	r, err := NamedSections(output("Devices\n-------\ndisk\n\nTarget Groups\n------------\nports"), "Devices", "Target Groups")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r, map[string][]string{"Devices": {"disk"}, "Target Groups": {"ports"}}) {
		t.Fatal(r)
	}
	for _, table := range []string{"Devices", "Devices\nDevices\nTarget Groups", "Devices\nUnexpected error\nTarget Groups"} {
		if _, err := NamedSections(output(table), "Devices", "Target Groups"); err == nil {
			t.Fatalf("accepted %q", table)
		}
	}
	if _, err := NamedSections("Devices\n", "Devices"); err == nil {
		t.Fatal("accepted truncated CLI output")
	}
	if _, err := NamedSections(output("Devices")+"late error", "Devices"); err == nil {
		t.Fatal("accepted output after completion")
	}
}

func TestSessions(t *testing.T) {
	r, err := SessionNames(output(`Driver/Target: scst_local/first
 Session: initiator
 Attribute     Value     Writable      KEY
 commands      5         No            No
Driver/Target: scst_local/second
 (no sessions)`))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r, map[string][]string{"scst_local/first": {"initiator"}, "scst_local/second": {}}) {
		t.Fatal(r)
	}
	if _, err := SessionNames(output("Session: orphan")); err == nil {
		t.Fatal("accepted orphan session")
	}
}

func TestSessionLUNsAndScopes(t *testing.T) {
	r, err := ParseSessions(output(`Driver/Target: scst_local/first
Session: initiator
Attribute       Value        Writable   KEY
LUN 0           disk_a       Yes        No
LUN 12          disk_b       Yes        No
commands        17           Yes        No
Session: second
Attribute       Value        Writable   KEY
LUN 0           disk_c       Yes        No
Driver/Target: scst_local/second
(no sessions)
Driver/Target: copy_manager/copy_manager_tgt
Session: copy_manager_sess
Attribute       Value        Writable   KEY
commands        42           Yes        No`))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r["scst_local/first"]["initiator"].LUNs, map[int]string{0: "disk_a", 12: "disk_b"}) ||
		r["scst_local/first"]["second"].LUNs[0] != "disk_c" || len(r["scst_local/second"]) != 0 ||
		len(r["copy_manager/copy_manager_tgt"]["copy_manager_sess"].LUNs) != 0 {
		t.Fatalf("session scope lost: %+v", r)
	}
}

func TestRejectMalformedSessions(t *testing.T) {
	header := "Driver/Target: scst_local/first\nSession: initiator\nAttribute Value Writable KEY\n"
	for _, table := range []string{
		"Driver/Target: /first\n(no sessions)",
		"Driver/Target: scst_local/first",
		"Driver/Target: scst_local/first\n(no sessions)\nSession: initiator",
		"Driver/Target: scst_local/first\n(no sessions)\nDriver/Target: scst_local/first\n(no sessions)",
		"Driver/Target: scst_local/first\nSession: initiator",
		header + "LUN -1  disk  Yes  No",
		header + "LUN bad  disk  Yes  No",
		header + "LUN 0  disk  Yes  No\nLUN 0  disk2  Yes  No",
		header + "LUN 0  disk  Yes  No\nLUN 00  disk2  Yes  No",
		header + "LUN 0  <not set>  Yes  No",
		header + "commands  1  Yes  No\nSession: initiator\nAttribute Value Writable KEY\n(none)",
		header + "unrecognized row",
	} {
		if _, err := ParseSessions(output(table)); err == nil {
			t.Fatalf("accepted malformed sessions %q", table)
		}
	}
}
