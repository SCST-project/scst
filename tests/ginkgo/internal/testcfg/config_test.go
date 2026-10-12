// SPDX-License-Identifier: GPL-2.0-only
package testcfg

import (
	"os"
	"path/filepath"
	"testing"
)

func configFile(t *testing.T, input string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(input), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadDefaultsAndPaths(t *testing.T) {
	path := configFile(t, `{"admin_command":["./bin/admin","literal argument"],"report_dir":"out","lock_file":"host.lock"}`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	base := filepath.Dir(path)
	if cfg.AdminCommand[0] != filepath.Join(base, "bin/admin") || cfg.AdminCommand[1] != "literal argument" || cfg.ReportDir != filepath.Join(base, "out") || cfg.LockFile != filepath.Join(base, "host.lock") {
		t.Fatalf("paths not resolved against config location: %+v", cfg)
	}
	if cfg.DisposableHost || cfg.CommandTimeout != "30s" || cfg.BuildJobs != 2 || cfg.BuildTimeout != "10m" {
		t.Fatalf("unsafe or missing defaults: %+v", cfg)
	}
}

func TestRejectMalformedConfiguration(t *testing.T) {
	for name, input := range map[string]string{
		"unknown key":         `{"commmand_timeout":"5s"}`,
		"trailing object":     `{} {}`,
		"trailing text":       `{} garbage`,
		"null":                `null`,
		"array":               `[]`,
		"empty command":       `{"admin_command":[]}`,
		"empty argument":      `{"admin_command":["sudo",""]}`,
		"zero timeout":        `{"command_timeout":"0s"}`,
		"negative timeout":    `{"cleanup_timeout":"-1s"}`,
		"missing unit":        `{"suite_timeout":"123"}`,
		"invalid prefix":      `{"name_prefix":"../../scst"}`,
		"poll exceeds settle": `{"poll_interval":"20s","settle_timeout":"2s"}`,
		"empty reports":       `{"report_dir":""}`,
		"zero build jobs":     `{"build_jobs":0}`,
		"negative build jobs": `{"build_jobs":-2}`,
		"invalid build limit": `{"build_timeout":"never"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(configFile(t, input)); err == nil {
				t.Fatal("accepted invalid config")
			}
		})
	}
}
