// SPDX-License-Identifier: GPL-2.0-only
package testhost

import (
	"fmt"
	"regexp"
	"strconv"
)

var kernelRelease = regexp.MustCompile(`^(\d+)\.(\d+)`)

// KernelAtLeast reports whether a `uname -r` release is at least
// major.minor, comparing the same fields as LINUX_VERSION_CODE checks do.
func KernelAtLeast(release string, major, minor int) (bool, error) {
	m := kernelRelease.FindStringSubmatch(release)
	if m == nil {
		return false, fmt.Errorf("unrecognized kernel release %q", release)
	}
	gotMajor, _ := strconv.Atoi(m[1])
	gotMinor, _ := strconv.Atoi(m[2])
	return gotMajor > major || gotMajor == major && gotMinor >= minor, nil
}
