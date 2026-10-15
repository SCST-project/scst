// SPDX-License-Identifier: GPL-2.0-only
package initiator

import "testing"

func TestTCPConnection(t *testing.T) {
	const portal = "192.0.2.10:3260"
	const row = "0 12 192.0.2.20:45000 192.0.2.10:3260\n"
	got, err := TCPConnection(row, portal)
	if err != nil || got != "192.0.2.20:45000" {
		t.Fatalf("connection = %q, %v", got, err)
	}
	for _, input := range []string{
		"", row + row, "ESTAB " + row,
		"0 0 192.0.2.20:45000 192.0.2.11:3260",
		"x 0 192.0.2.20:45000 " + portal,
		"0 0 *:45000 " + portal,
		"0 0 0.0.0.0:45000 " + portal,
		"0 0 192.0.2.20:0 " + portal,
		"0 0 192.0.2.20:65536 " + portal,
	} {
		if _, err := TCPConnection(input, portal); err == nil {
			t.Errorf("accepted ambiguous or invalid socket: %q", input)
		}
	}
}
