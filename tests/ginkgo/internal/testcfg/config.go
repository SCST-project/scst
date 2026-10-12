// SPDX-License-Identifier: GPL-2.0-only
package testcfg

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Config describes one local, disposable SCST host. There are no implicit
// per-user overrides: the named file completely determines a run.
type Config struct {
	AdminCommand   []string `json:"admin_command"`
	DisposableHost bool     `json:"disposable_host"`
	NamePrefix     string   `json:"name_prefix"`
	ReportDir      string   `json:"report_dir"`
	LockFile       string   `json:"lock_file"`
	CommandTimeout string   `json:"command_timeout"`
	CleanupTimeout string   `json:"cleanup_timeout"`
	SettleTimeout  string   `json:"settle_timeout"`
	PollInterval   string   `json:"poll_interval"`
	SuiteTimeout   string   `json:"suite_timeout"`
	BuildTimeout   string   `json:"build_timeout"`
	BuildJobs      int      `json:"build_jobs"`
}

func Load(path string) (Config, error) {
	c := Config{
		AdminCommand: []string{"scstadmin"}, NamePrefix: "scsttest",
		ReportDir: "results", LockFile: "/tmp/scst-ginkgo.lock",
		CommandTimeout: "30s", CleanupTimeout: "2m", SettleTimeout: "10s",
		PollInterval: "100ms", SuiteTimeout: "15m",
		BuildTimeout: "10m", BuildJobs: 2,
	}
	f, err := os.Open(path)
	if err != nil {
		return c, err
	}
	defer f.Close()
	d := json.NewDecoder(f)
	d.DisallowUnknownFields()
	decoded := &c
	if err := d.Decode(&decoded); err != nil {
		return c, fmt.Errorf("test configuration: %w", err)
	}
	if decoded == nil {
		return c, fmt.Errorf("test configuration must be a JSON object")
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return c, fmt.Errorf("test configuration must contain exactly one JSON object")
	}
	if err := c.Validate(); err != nil {
		return c, err
	}
	base, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return c, err
	}
	for _, p := range []*string{&c.ReportDir, &c.LockFile} {
		if !filepath.IsAbs(*p) {
			*p = filepath.Join(base, *p)
		}
	}
	if strings.ContainsRune(c.AdminCommand[0], '/') && !filepath.IsAbs(c.AdminCommand[0]) {
		c.AdminCommand[0] = filepath.Join(base, c.AdminCommand[0])
	}
	return c, nil
}

func (c Config) Validate() error {
	if len(c.AdminCommand) == 0 {
		return fmt.Errorf("admin_command must contain an executable")
	}
	for _, arg := range c.AdminCommand {
		if strings.TrimSpace(arg) == "" || strings.ContainsRune(arg, '\x00') {
			return fmt.Errorf("admin_command contains an empty or invalid argument")
		}
	}
	if !regexp.MustCompile(`^[a-z][a-z0-9_]{0,15}$`).MatchString(c.NamePrefix) {
		return fmt.Errorf("name_prefix must contain 1-16 lowercase letters, digits or underscores and start with a letter")
	}
	if c.ReportDir == "" || c.LockFile == "" {
		return fmt.Errorf("report_dir and lock_file must be nonempty")
	}
	for name, value := range map[string]string{
		"command_timeout": c.CommandTimeout, "cleanup_timeout": c.CleanupTimeout,
		"settle_timeout": c.SettleTimeout, "poll_interval": c.PollInterval,
		"suite_timeout": c.SuiteTimeout,
		"build_timeout": c.BuildTimeout,
	} {
		v, err := time.ParseDuration(value)
		if err != nil || v <= 0 {
			return fmt.Errorf("%s must be a positive Go duration", name)
		}
	}
	if Duration(c.PollInterval) > Duration(c.SettleTimeout) {
		return fmt.Errorf("poll_interval exceeds settle_timeout")
	}
	if c.BuildJobs < 1 {
		return fmt.Errorf("build_jobs must be positive")
	}
	return nil
}

// Duration is used only after Validate has checked all duration fields.
func Duration(s string) time.Duration {
	d, _ := time.ParseDuration(s)
	return d
}
