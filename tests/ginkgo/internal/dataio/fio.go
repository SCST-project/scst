// SPDX-License-Identifier: GPL-2.0-only
package dataio

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

//go:embed verify.fio
var fioTemplate string

func renderFIO(path string, region uint64, direct, verifyOnly bool) string {
	bit := func(b bool) string {
		if b {
			return "1"
		}
		return "0"
	}
	return strings.NewReplacer("@DEVICE@", path, "@REGION@", strconv.FormatUint(region, 10),
		"@OFFSET1@", strconv.FormatUint(region, 10), "@OFFSET2@", strconv.FormatUint(2*region, 10),
		"@DIRECT@", bit(direct), "@VERIFY_ONLY@", bit(verifyOnly)).Replace(fioTemplate)
}

func fioReport(data []byte, region uint64, verifyOnly bool) error {
	var report struct {
		Jobs []struct {
			Name  string `json:"jobname"`
			Error *int   `json:"error"`
			Read  struct {
				Bytes uint64 `json:"io_bytes"`
			} `json:"read"`
			Write struct {
				Bytes uint64 `json:"io_bytes"`
			} `json:"write"`
		} `json:"jobs"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		return fmt.Errorf("fio report: %w", err)
	}
	expected := map[string]bool{"small": true, "medium": true, "large": true}
	if len(report.Jobs) != len(expected) {
		return fmt.Errorf("fio returned %d jobs, want 3", len(report.Jobs))
	}
	for _, j := range report.Jobs {
		if !expected[j.Name] || j.Error == nil || *j.Error != 0 || j.Read.Bytes != region || !verifyOnly && j.Write.Bytes != region {
			return fmt.Errorf("fio job incomplete or failed: %+v (want %d verified bytes)", j, region)
		}
		delete(expected, j.Name)
	}
	return nil
}

func (e *Endpoint) FIO(ctx context.Context) error {
	if err := e.Check(ctx); err != nil {
		return err
	}
	if e.ReadOnly {
		return fmt.Errorf("fio requires a writable fixture")
	}
	region := uint64(e.RegionMB) * 1024 * 1024
	if region == 0 || region*3 > e.Backend.Bytes {
		return fmt.Errorf("fio regions exceed exported capacity")
	}
	direct := e.Backend.Handler == "vdisk_blockio"
	for _, verifyOnly := range []bool{false, true} {
		if verifyOnly {
			if direct {
				break
			}
			// Flush the buffered run, then verify through direct reads. This catches
			// stale/lost target data that a read from the initiator cache could hide.
			if _, err := e.sg(ctx, "sg_sync"); err != nil {
				return err
			}
			if err := e.Check(ctx); err != nil {
				return err
			}
		}
		job := renderFIO(e.Path, region, direct || verifyOnly, verifyOnly)
		suffix := "write-verify"
		if verifyOnly {
			suffix = "direct-verify"
		}
		base := filepath.Join(e.Artifacts, e.Name+"-"+suffix)
		if err := os.WriteFile(base+".fio", []byte(job), 0600); err != nil {
			return err
		}
		reply, err := invoke(ctx, e.Run, e.IOTimeout, struct {
			Args   []string `json:"argv"`
			Config string   `json:"fio_config"`
		}{[]string{"fio"}, job})
		if err != nil {
			return err
		}
		if err := os.WriteFile(base+".json", reply.Data, 0600); err != nil {
			return err
		}
		if err := os.WriteFile(base+".stderr", []byte(reply.Stderr), 0600); err != nil {
			return err
		}
		if reply.ExitCode != 0 {
			return fmt.Errorf("fio exit %d: %s; see %s.json", reply.ExitCode, reply.Stderr, base)
		}
		if err := fioReport(reply.Data, region, verifyOnly); err != nil {
			return err
		}
	}
	return nil
}
