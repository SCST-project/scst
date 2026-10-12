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
	path := configFile(t, `{"admin_command":["./bin/admin","literal argument"],"report_dir":"out","lock_file":"host.lock","backing_dir":"scratch"}`)
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
	if cfg.AllowKnownCrash || !cfg.FileioThinProvisioning || cfg.StressIterations != 8 || cfg.ScaleLUNs != 256 || cfg.BackingDir != filepath.Join(base, "scratch") {
		t.Fatalf("unsafe or missing scenario defaults: %+v", cfg)
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
		"zero iterations":     `{"stress_iterations":0}`,
		"too many iterations": `{"stress_iterations":1001}`,
		"too few LUNs":        `{"scale_luns":1}`,
		"too many LUNs":       `{"scale_luns":2049}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(configFile(t, input)); err == nil {
				t.Fatal("accepted invalid config")
			}
		})
	}
}

func TestScenarioOverrides(t *testing.T) {
	c, err := Load(configFile(t, `{"stress_iterations":12,"scale_luns":1000,"allow_known_crash":true,"fileio_thin_provisioning":false}`))
	if err != nil {
		t.Fatal(err)
	}
	if c.StressIterations != 12 || c.ScaleLUNs != 1000 || !c.AllowKnownCrash || c.FileioThinProvisioning || c.BackingDir != "" {
		t.Fatalf("scenario overrides lost: %+v", c)
	}
}

func TestISCSIConfiguration(t *testing.T) {
	input := `{"iscsi":{"target_address":"192.0.2.10","port":3260,"login_timeout":"15s","initiator":{"host":"192.0.2.20","user":"root","port":22,"identity_file":"id_test","lock_file":"/tmp/scst-test.lock","disposable_host":false}}}`
	path := configFile(t, input)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ISCSI.Initiator.DisposableHost || cfg.ISCSI.Initiator.IdentityFile != filepath.Join(filepath.Dir(path), "id_test") {
		t.Fatalf("unsafe defaults or bad path: %+v", cfg.ISCSI)
	}
	for name, change := range map[string]func(*ISCSI){
		"wildcard target":      func(i *ISCSI) { i.TargetAddress = "0.0.0.0" },
		"localhost":            func(i *ISCSI) { i.TargetAddress = "127.0.0.1" },
		"IPv6":                 func(i *ISCSI) { i.TargetAddress = "2001:db8::1" },
		"target DNS":           func(i *ISCSI) { i.TargetAddress = "target" },
		"bad port":             func(i *ISCSI) { i.Port = 65536 },
		"bad SSH port":         func(i *ISCSI) { i.Initiator.Port = 0 },
		"SSH option":           func(i *ISCSI) { i.Initiator.Host = "-oProxyCommand=bad" },
		"SSH injection":        func(i *ISCSI) { i.Initiator.Host = "host; command" },
		"nonroot":              func(i *ISCSI) { i.Initiator.User = "tester" },
		"relative remote lock": func(i *ISCSI) { i.Initiator.LockFile = "host.lock" },
		"long login":           func(i *ISCSI) { i.LoginTimeout = "31s" },
		"fractional login":     func(i *ISCSI) { i.LoginTimeout = "1.5s" },
	} {
		t.Run(name, func(t *testing.T) {
			invalid := cfg
			value := *cfg.ISCSI
			invalid.ISCSI = &value
			change(invalid.ISCSI)
			if invalid.Validate() == nil {
				t.Fatal("accepted invalid iSCSI configuration")
			}
		})
	}
	if _, err := Load(configFile(t, `{"iscsi":{"unknown":true}}`)); err == nil {
		t.Fatal("accepted unknown nested field")
	}
}
