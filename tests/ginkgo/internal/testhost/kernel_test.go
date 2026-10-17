// SPDX-License-Identifier: GPL-2.0-only
package testhost

import "testing"

func TestKernelAtLeast(t *testing.T) {
	for _, tc := range []struct {
		release string
		want    bool
	}{
		{"5.9", true},
		{"5.9.0-fork59", true},
		{"5.9.16", true},
		{"5.10.264", true},
		{"6.17.13-kunit", true},
		{"10.0.1", true},
		{"5.8.18", false},
		{"5.4.0-200-generic", false},
		{"4.18.0-553.el8_10.x86_64", false},
		{"4.20.1", false},
	} {
		got, err := KernelAtLeast(tc.release, 5, 9)
		if err != nil || got != tc.want {
			t.Errorf("KernelAtLeast(%q, 5, 9) = %t, %v; want %t", tc.release, got, err, tc.want)
		}
	}
	for _, release := range []string{"", "5", "abc", "v5.9"} {
		if _, err := KernelAtLeast(release, 5, 9); err == nil {
			t.Errorf("accepted kernel release %q", release)
		}
	}
}
