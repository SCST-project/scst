// SPDX-License-Identifier: GPL-2.0-only
package suite

import (
	"bytes"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"scst-component-tests/internal/dataio"
	"scst-component-tests/internal/testcfg"
	"scst-component-tests/internal/testhost"
)

//go:embed testdata/user_hook.c
var userHookSource []byte

const userBlockSize = 4096

// The lines the hook logs only after it has applied each fault.
var userHookApplied = map[string]*regexp.Regexp{
	"fork":     regexp.MustCompile(`SCST_TEST_HOOK fork child=[1-9][0-9]*\n`),
	"capacity": regexp.MustCompile(`SCST_TEST_HOOK capacity cdb=0x(25|9e)\n`),
}

// userDevice starts usr/fileio/fileio_tgt with the fault hook preloaded. One
// worker thread without multi-command replies limits handler concurrency;
// it does not guarantee reuse of a particular cached buffer. Cleanup removes
// the LUN before stopping the handler, which unregisters the device.
func (f *fixture) userDevice(ctx SpecContext, action, path, trigger string, dontfork bool) (string, *os.File) {
	GinkgoHelper()
	timeout := testcfg.Duration(cfg.CommandTimeout)
	source, hook := f.file("user_hook.c"), f.file("user_hook.so")
	Expect(os.WriteFile(source, userHookSource, 0o644)).To(Succeed())
	r, err := cli.RunProgram(ctx, timeout, "cc", "-shared", "-fPIC", "-O2", "-Wall", "-Werror",
		"-I"+filepath.Join(sourceDir, "scst/include"), "-o", hook, source, "-ldl")
	Expect(err).NotTo(HaveOccurred(), r.String())
	Expect(r.ExitCode).To(BeZero(), r.String())

	// The handler reports its device name as the INQUIRY product (16 bytes).
	name := "u" + dataio.DeviceID(f.prefix)[:15]
	log := must(os.Create(f.file("fileio_tgt.log")))
	dontforkValue := "0"
	if dontfork {
		dontforkValue = "1"
	}
	p, err := testhost.StartProcess(log, "env", "LD_PRELOAD="+hook,
		"SCST_TEST_HOOK_ACTION="+action, "SCST_TEST_HOOK_TRIGGER="+trigger,
		"SCST_TEST_HOOK_DONTFORK="+dontforkValue,
		filepath.Join(sourceDir, "usr/fileio/fileio_tgt"), fmt.Sprintf("--block=%d", userBlockSize),
		"--threads=1", "--multi_cmd=0", name, path)
	if err != nil {
		Expect(log.Close()).To(Succeed())
		Expect(err).NotTo(HaveOccurred())
	}
	deferSpecCleanup(func(ctx SpecContext) {
		if err := f.stopUserDevice(ctx, p, name); err != nil {
			AbortSuite("user-space handler cleanup failed; inspect this disposable host before another run: " + err.Error())
		}
		Expect(log.Close()).To(Succeed())
	})
	Eventually(func() error {
		if err := p.Running(); err != nil {
			return StopTrying(err.Error())
		}
		if _, ok := must(cli.Devices(ctx))[name]; !ok {
			return fmt.Errorf("device %s is not registered yet", name)
		}
		return nil
	}, testcfg.Duration(cfg.SettleTimeout), testcfg.Duration(cfg.PollInterval)).WithContext(ctx).Should(Succeed())
	return name, log
}

func (f *fixture) stopUserDevice(ctx SpecContext, p *testhost.Process, name string) error {
	targets, err := cli.Targets(ctx)
	if err != nil {
		return err
	}
	for _, t := range f.targets {
		if _, ok := targets[t]; ok {
			r, err := cli.Execute(ctx, "-rem_target", t, "-driver", "scst_local")
			if err != nil || r.ExitCode != 0 || r.ReportedError() {
				return fmt.Errorf("%s", r.String())
			}
		}
	}
	// The device is unregistered once every process holding the scst_user
	// file descriptor has exited; SIGTERM reaches the whole process group.
	if err := p.Stop(ctx); err != nil {
		return err
	}
	deadline := time.Now().Add(testcfg.Duration(cfg.SettleTimeout))
	for {
		devices, err := cli.Devices(ctx)
		if err != nil {
			return err
		}
		if _, ok := devices[name]; !ok {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("device %s remains after its handler exited", name)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(testcfg.Duration(cfg.PollInterval)):
		}
	}
}

var _ = Describe("User-space handler devices", Label("scsi", "user", "smoke"), func() {
	DescribeTable("keep replies, geometry and data intact across a handler fault",
		func(ctx SpecContext, action string, capacityCDB []byte) {
			timeout := testcfg.Duration(cfg.CommandTimeout)
			dontfork := false
			if action == "fork" {
				r, err := cli.RunProgram(ctx, timeout, "uname", "-r")
				Expect(err).NotTo(HaveOccurred(), r.String())
				Expect(r.ExitCode).To(BeZero(), r.String())
				// Older kernels require the handler to exclude its buffers
				// from fork. Linux 5.9+ exercises page pinning without that aid.
				dontfork = !must(testhost.KernelAtLeast(strings.TrimSpace(r.Stdout), 5, 9))
			}
			Expect(dataio.RequireTools(ctx, cli.RunProgram, timeout, false)).To(Succeed())
			f := newFixture()
			path := f.backingFile("user")
			lba0 := bytes.Repeat([]byte("SCSTDATA"), userBlockSize/8)
			file := must(os.OpenFile(path, os.O_WRONLY, 0))
			_, err := file.WriteAt(lba0, 0)
			Expect(file.Close()).To(Succeed())
			Expect(err).NotTo(HaveOccurred())

			trigger := f.file("user_trigger")
			d, log := f.userDevice(ctx, action, path, trigger, dontfork)
			session := f.name("session")
			target := f.target(ctx, "target", "session_name="+session)
			f.at(ctx, target, "", "-add_group", "access")
			f.at(ctx, target, "access", "-add_lun", "0", "-device", d)
			f.at(ctx, target, "access", "-add_init", session)

			e := &dataio.Endpoint{Run: cli.RunProgram, Timeout: timeout, IOTimeout: testcfg.Duration(cfg.IO.Timeout),
				Backend: dataio.Backend{Bytes: 16 * 1024 * 1024, BlockSize: userBlockSize}, Artifacts: artifactDir, Name: d}
			Eventually(func() error { return e.FindModel(ctx, d) }, testcfg.Duration(cfg.SettleTimeout),
				testcfg.Duration(cfg.PollInterval)).WithContext(ctx).Should(Succeed())
			arm := func() error {
				return os.WriteFile(trigger, nil, 0o644)
			}
			err = e.UserHandlerFault(ctx, lba0, arm, capacityCDB)
			// Check the fault first: without it, neither I/O result means anything.
			Expect(log.Sync()).To(Succeed())
			out := string(must(os.ReadFile(log.Name())))
			Expect(out).NotTo(ContainSubstring("SCST_TEST_HOOK "+action+" failed"),
				"the handler could not apply the %s fault", action)
			Expect(userHookApplied[action].MatchString(out)).To(BeTrue(),
				"the handler did not apply the %s fault (I/O result: %v)", action, err)
			if dontfork {
				Expect(out).To(MatchRegexp(`SCST_TEST_HOOK dontfork buffers=[1-9][0-9]*\n`),
					"legacy-kernel buffers were not protected before fork")
			} else {
				Expect(out).NotTo(ContainSubstring("SCST_TEST_HOOK dontfork"))
			}
			Expect(err).To(Succeed())
		},
		Entry("handler forks", "fork", nil),
		Entry("handler returns an invalid READ CAPACITY(10) block length", Label("negative"),
			"capacity", dataio.ReadCapacity10),
		Entry("handler returns an invalid READ CAPACITY(16) block length", Label("negative"),
			"capacity", dataio.ReadCapacity16))
})
