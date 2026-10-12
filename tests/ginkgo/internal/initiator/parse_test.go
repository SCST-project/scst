// SPDX-License-Identifier: GPL-2.0-only
package initiator

import "testing"

func TestParsers(t *testing.T) {
	sessions, err := Sessions("tcp: [12] 192.0.2.10:3260,1 iqn.2026-10.test.scst:one (non-flash)\n")
	if err != nil || len(sessions) != 1 || sessions[0].ID != "12" || sessions[0].Portal != "192.0.2.10:3260" || sessions[0].Target != "iqn.2026-10.test.scst:one" {
		t.Fatalf("sessions: %+v %v", sessions, err)
	}
	for _, bad := range []string{"No matching sessions", "tcp: [x] 192.0.2.10:3260,1 iqn.test (non-flash)", "tcp: [1] 192.0.2.10,1 iqn.test (non-flash)"} {
		if _, err := Sessions(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	discovered, err := Discovery("192.0.2.10:3260,1 iqn.test\n")
	if err != nil || discovered["iqn.test"] != "192.0.2.10:3260" {
		t.Fatalf("discovery: %+v %v", discovered, err)
	}
	if _, err := Discovery("iscsiadm: discovery failed"); err == nil {
		t.Fatal("accepted diagnostics as discovery")
	}
	if _, err := Discovery("192.0.2.10:3260,1 iqn.test\n192.0.2.10:3261,2 iqn.test"); err == nil {
		t.Fatal("accepted duplicate target")
	}
	ifaces, err := Ifaces("default tcp,<empty>,<empty>,<empty>,<empty>\nscst_run tcp,<empty>,<empty>,<empty>,iqn.test\n")
	if err != nil || len(ifaces) != 2 || ifaces[1] != "scst_run" {
		t.Fatalf("ifaces: %v %v", ifaces, err)
	}
	if _, err := Ifaces("some error"); err == nil {
		t.Fatal("accepted invalid iface listing")
	}
}
