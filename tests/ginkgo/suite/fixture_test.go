// SPDX-License-Identifier: GPL-2.0-only
package suite

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"scst-component-tests/internal/admin"
)

type fixture struct {
	prefix                         string
	devices, targets, deviceGroups []string
	backingFiles                   []string
}

var fixtureNumber int

func newFixture() *fixture {
	GinkgoHelper()
	if err := cli.Blocked(); err != nil {
		AbortSuite(err.Error())
	}
	fixtureNumber++
	f := &fixture{prefix: fmt.Sprintf("%s_%s_%d", cfg.NamePrefix, runID, fixtureNumber)}
	deferSpecCleanup(func(ctx SpecContext) {
		if err := f.cleanup(ctx); err != nil {
			AbortSuite("cleanup failed; inspect this disposable host before another run: " + err.Error())
		}
	})
	return f
}

func (f *fixture) name(suffix string) string { return f.prefix + "_" + suffix }
func (f *fixture) file(suffix string) string { return filepath.Join(artifactDir, f.name(suffix)) }

func (f *fixture) do(ctx context.Context, args ...string) {
	GinkgoHelper()
	r, err := cli.Execute(ctx, args...)
	Expect(err).NotTo(HaveOccurred(), r.String())
	Expect(r.ExitCode).To(BeZero(), r.String())
	Expect(r.ReportedError()).To(BeFalse(), r.String())
}

func (f *fixture) reject(ctx context.Context, args ...string) {
	GinkgoHelper()
	r, err := cli.Execute(ctx, args...)
	Expect(err).NotTo(HaveOccurred(), "execution failure is not an expected rejection: %s", r.String())
	Expect(r.ExitCode != 0 || r.ReportedError()).To(BeTrue(), r.String())
}

func (f *fixture) device(ctx context.Context, suffix string) string {
	GinkgoHelper()
	return f.openDevice(ctx, suffix, "vdisk_nullio", "dummy=1,size_mb=8")
}

func (f *fixture) openDevice(ctx context.Context, suffix, handler, attributes string) string {
	GinkgoHelper()
	d := f.name(suffix)
	// Record ownership before invoking a mutation, including partial failures.
	if !slices.Contains(f.devices, d) {
		f.devices = append(f.devices, d)
	}
	f.do(ctx, "-open_dev", d, "-handler", handler, "-attributes", attributes)
	return d
}

// Only newly created files belong to this fixture. Preserve them if SCST
// cleanup fails: unlinking a still-open backing file would hide failure state.
func (f *fixture) backingFile(suffix string) string {
	GinkgoHelper()
	dir := cfg.BackingDir
	if dir == "" {
		dir = artifactDir
	}
	file := must(os.CreateTemp(dir, f.name(suffix)+"-*.img"))
	path := file.Name()
	f.backingFiles = append(f.backingFiles, path)
	err := file.Truncate(16 * 1024 * 1024)
	closeErr := file.Close()
	Expect(err).NotTo(HaveOccurred())
	Expect(closeErr).NotTo(HaveOccurred())
	Expect(strings.ContainsAny(path, " \t\r\n,;\"{}\\")).To(BeFalse(), "backing path must be usable in scstadmin attributes/configuration: %s", path)
	return path
}

func (f *fixture) fileDevice(ctx context.Context, suffix, path string, attributes ...string) string {
	GinkgoHelper()
	return f.openDevice(ctx, suffix, "vdisk_fileio", strings.Join(append([]string{"filename=" + path}, attributes...), ","))
}

func (f *fixture) deviceAttr(ctx context.Context, device, attribute string) string {
	GinkgoHelper()
	return must(cli.Scalar(ctx, attribute, "-list_device", device))
}

func (f *fixture) setDevice(ctx context.Context, device, attributes string) {
	GinkgoHelper()
	f.do(ctx, "-set_dev_attr", device, "-attributes", attributes)
}

func (f *fixture) target(ctx context.Context, suffix string, attributes ...string) string {
	GinkgoHelper()
	t := f.name(suffix)
	if !slices.Contains(f.targets, t) {
		f.targets = append(f.targets, t)
	}
	args := []string{"-add_target", t, "-driver", "scst_local"}
	if len(attributes) != 0 {
		args = append(args, "-attributes", attributes[0])
	}
	f.do(ctx, args...)
	return t
}

func (f *fixture) deviceGroup(ctx context.Context, suffix string) string {
	GinkgoHelper()
	dg := f.name(suffix)
	f.deviceGroups = append(f.deviceGroups, dg)
	f.do(ctx, "-add_dgrp", dg)
	return dg
}

func scope(target, group string) []string {
	args := []string{"-driver", "scst_local", "-target", target}
	if group != "" {
		args = append(args, "-group", group)
	}
	return args
}

func (f *fixture) at(ctx context.Context, target, group string, args ...string) {
	GinkgoHelper()
	f.do(ctx, append(args, scope(target, group)...)...)
}

func (f *fixture) state(ctx context.Context, target string) admin.Assignments {
	GinkgoHelper()
	return must(cli.Assignments(ctx, target))
}

func (f *fixture) luns(ctx context.Context, target, group string) map[int]string {
	GinkgoHelper()
	a := f.state(ctx, target)
	if group == "" {
		return a.LUNs
	}
	Expect(a.Groups).To(HaveKey(group))
	return a.Groups[group].LUNs
}

func (f *fixture) lunReadOnly(ctx context.Context, target, group string, lun string) string {
	GinkgoHelper()
	return must(cli.Scalar(ctx, "read_only", append([]string{"-list_lun_attr", lun}, scope(target, group)...)...))
}

func (f *fixture) cleanup(ctx context.Context) error {
	if err := cli.Blocked(); err != nil {
		return err
	}
	var problems []error
	remove := func(args ...string) {
		r, err := cli.Execute(ctx, args...)
		if err != nil || r.ExitCode != 0 || r.ReportedError() {
			problems = append(problems, fmt.Errorf("%s", r.String()))
		}
	}
	// Remove dependencies before devices; deleting a target removes its groups
	// and LUN assignments. Never clear unrelated configuration for cleanup.
	dgs, err := cli.Names(ctx, "Device Group", "-list_dgrp")
	if err != nil {
		return err
	}
	for _, owned := range f.deviceGroups {
		for _, present := range dgs {
			if owned == present {
				remove("-rem_dgrp", owned, "-force")
			}
		}
	}
	targets, err := cli.Targets(ctx)
	if err != nil {
		return errors.Join(append(problems, err)...)
	}
	for _, t := range f.targets {
		if _, ok := targets[t]; ok {
			remove("-rem_target", t, "-driver", "scst_local")
		}
	}
	devices, err := cli.Devices(ctx)
	if err != nil {
		return errors.Join(append(problems, err)...)
	}
	for _, d := range f.devices {
		if handler, ok := devices[d]; ok {
			remove("-close_dev", d, "-handler", handler)
		}
	}
	if len(problems) != 0 {
		return errors.Join(problems...)
	}
	// A zero exit alone is not evidence that teardown completed.
	devices, err = cli.Devices(ctx)
	if err != nil {
		return err
	}
	targets, err = cli.Targets(ctx)
	if err != nil {
		return err
	}
	dgs, err = cli.Names(ctx, "Device Group", "-list_dgrp")
	if err != nil {
		return err
	}
	if len(devices) != 0 || len(targets) != 0 || len(dgs) != 0 {
		return fmt.Errorf("host is no longer empty: devices=%v targets=%v device_groups=%v", devices, targets, dgs)
	}
	for _, path := range f.backingFiles {
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("remove backing file: %w", err)
		}
	}
	return nil
}
