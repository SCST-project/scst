// SPDX-License-Identifier: GPL-2.0-only
// Package cprobe prepares private build inputs for isolated daemon probes.
package cprobe

import (
	"crypto/sha1"
	"fmt"
	"os"
	"path/filepath"
)

// PrepareISCSIHeaders copies the current interface and generates its version
// header using the same SHA-1 input as iscsi-scst/Makefile. The caller puts dir
// first in the compiler include path; the source checkout remains untouched.
func PrepareISCSIHeaders(source, dir string) error {
	data, err := os.ReadFile(filepath.Join(source, "iscsi-scst/include/iscsi_scst.h"))
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "iscsi_scst.h"), data, 0600); err != nil {
		return err
	}
	version := fmt.Sprintf("/* Generated for the isolated probe. */\n#define ISCSI_SCST_INTERFACE_VERSION ISCSI_VERSION_STRING \"_%x\"\n", sha1.Sum(data))
	return os.WriteFile(filepath.Join(dir, "iscsi_scst_itf_ver.h"), []byte(version), 0600)
}
