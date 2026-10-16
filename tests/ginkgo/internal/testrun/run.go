// SPDX-License-Identifier: GPL-2.0-only
package testrun

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"scst-component-tests/internal/admin"
	"scst-component-tests/internal/testcfg"
)

type Environment struct {
	Config             testcfg.Config
	Client             *admin.Client
	ArtifactDir, RunID string
}

func Run(t *testing.T, name string, iscsi bool, assign func(Environment)) {
	var cfg testcfg.Config
	var artifactDir, runID string
	var cli *admin.Client
	RegisterFailHandler(Fail)
	suiteConfig, reporterConfig := GinkgoConfiguration()
	filter, err := resolveLabelFilter(suiteConfig.LabelFilter)
	if err != nil {
		t.Fatal(err)
	}
	suiteConfig.LabelFilter = filter
	if suiteConfig.ParallelTotal != 1 {
		t.Fatal("SCST component tests share host state; parallel execution is unsupported")
	}
	group := "local"
	if iscsi {
		group = "iscsi"
	}
	if directory := os.Getenv("SCST_TEST_PLAN_DIR"); directory != "" {
		// Discover filters in a separate process, before config or host access.
		// Do not reuse the previewed spec tree for the actual run.
		preview := PreviewSpecs(name, suiteConfig, Label(group))
		data, err := json.Marshal(Selection{Group: group, Specs: preview.PreRunStats.SpecsThatWillRun})
		if err == nil {
			err = os.WriteFile(filepath.Join(directory, group+".json"), data, 0600)
		}
		if err != nil {
			t.Fatal(err)
		}
		return
	}
	if !suiteConfig.DryRun {
		path := os.Getenv("SCST_TEST_CONFIG")
		if path == "" {
			t.Skip("set SCST_TEST_CONFIG to an explicit disposable-host configuration")
		}
		var err error
		cfg, err = testcfg.Load(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := ValidateSelection(cfg, []Selection{{Group: group, Specs: 1}}); err != nil {
			t.Fatal(err)
		}
		if os.Geteuid() != 0 {
			t.Fatal("SCST component tests load modules and must run as root")
		}
		// Keep the same lock inode across runs. Removing it would allow another
		// process to lock a new inode while this process still owns the old one.
		fd, err := syscall.Open(cfg.LockFile, syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
		if err != nil {
			t.Fatal(err)
		}
		lock := os.NewFile(uintptr(fd), cfg.LockFile)
		defer lock.Close()
		if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
			t.Fatalf("cannot acquire host lock %s: %v", cfg.LockFile, err)
		}
		if err := os.MkdirAll(cfg.ReportDir, 0700); err != nil {
			t.Fatal(err)
		}
		artifactDir, err = os.MkdirTemp(cfg.ReportDir, "run-")
		if err != nil {
			t.Fatal(err)
		}
		runID = fmt.Sprintf("%x", time.Now().UnixNano())
		data, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(artifactDir, "config.json"), append(data, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
		log, err := os.OpenFile(filepath.Join(artifactDir, "commands.jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		defer log.Close()
		cli = &admin.Client{Command: cfg.AdminCommand, Timeout: testcfg.Duration(cfg.CommandTimeout), Log: log}
		reporterConfig.JSONReport = filepath.Join(artifactDir, "report.json")
		reporterConfig.JUnitReport = filepath.Join(artifactDir, "junit.xml")
		suiteConfig.Timeout = testcfg.Duration(cfg.SuiteTimeout)
		if os.Getenv("SCST_TEST_BUILD") == "1" {
			// Each of the three existing build targets has its own timeout.
			suiteConfig.Timeout += 3 * testcfg.Duration(cfg.BuildTimeout)
		}
		fmt.Fprintf(GinkgoWriter, "Artifacts: %s\n", artifactDir)
		t.Logf("Artifacts: %s", artifactDir)
	}
	assign(Environment{Config: cfg, Client: cli, ArtifactDir: artifactDir, RunID: runID})
	RunSpecs(t, name, suiteConfig, reporterConfig, Label(group))
}
