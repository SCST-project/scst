// SPDX-License-Identifier: GPL-2.0-only
package testhost

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"scst-component-tests/internal/admin"
)

type RunProgram func(context.Context, time.Duration, ...string) (admin.Result, error)

type Options struct {
	SourceDir      string
	KernelDir      string
	Build          bool
	Jobs           int
	BuildTimeout   time.Duration
	CommandTimeout time.Duration
}

var moduleName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_-]*$`)

// Modules tracks only the checkout modules successfully loaded by Prepare.
type Modules struct {
	loaded []string
}

// Prepare loads checkout modules under the suite's host lock and root checks.
// Build controls compilation only; module preparation is always performed.
// CheckEmpty must inspect SCST through scstadmin and reject nonempty state.
// Existing modules remain loaded on build failure. No forced unload is used.
func (m *Modules) Prepare(ctx context.Context, opts Options, run RunProgram, checkEmpty func(context.Context) error, progress io.Writer) error {
	if len(m.loaded) != 0 {
		return fmt.Errorf("checkout modules have not been unloaded")
	}
	if !filepath.IsAbs(opts.SourceDir) || opts.CommandTimeout <= 0 ||
		opts.Build && (opts.Jobs < 1 || opts.BuildTimeout <= 0) {
		return fmt.Errorf("invalid module preparation options")
	}
	command := func(timeout time.Duration, args ...string) (string, error) {
		return runCommand(ctx, timeout, run, args...)
	}
	before, err := loadedModules(ctx, opts.CommandTimeout, run)
	if err != nil {
		return err
	}
	if before["scst"] {
		if err := checkEmpty(ctx); err != nil {
			return fmt.Errorf("refusing to replace configured SCST: %w", err)
		}
	}
	release, err := command(opts.CommandTimeout, "uname", "-r")
	if err != nil {
		return err
	}
	if release == "" || strings.ContainsAny(release, "/\n\r\t ") {
		return fmt.Errorf("invalid running kernel release %q", release)
	}
	if opts.Build {
		kdir := opts.KernelDir
		if kdir == "" {
			kdir = filepath.Join("/lib/modules", release, "build")
		}
		if !filepath.IsAbs(kdir) {
			return fmt.Errorf("KDIR must be absolute")
		}
		// scst_local consumes the core's Module.symvers, so build in order.
		for _, target := range []string{"scst", "scst_local", "scstadm"} {
			fmt.Fprintf(progress, "Building %s for %s\n", target, release)
			if _, err := command(opts.BuildTimeout, "make", "-C", opts.SourceDir,
				fmt.Sprintf("-j%d", opts.Jobs), "KVER="+release, "KDIR="+kdir, target); err != nil {
				return err
			}
		}
	}
	modules := []struct{ name, path string }{
		{"scst", "scst/src/scst.ko"},
		{"scst_vdisk", "scst/src/dev_handlers/scst_vdisk.ko"},
		{"scst_local", "scst_local/scst_local.ko"},
	}
	dependencies := make([][]string, len(modules))
	for i, m := range modules {
		path := filepath.Join(opts.SourceDir, m.path)
		vermagic, err := command(opts.CommandTimeout, "modinfo", "-F", "vermagic", path)
		if err != nil {
			if !opts.Build {
				return fmt.Errorf("cannot inspect %s; use ginkgo-test-build if modules have not been built: %w", path, err)
			}
			return err
		}
		fields := strings.Fields(vermagic)
		if len(fields) == 0 || fields[0] != release {
			return fmt.Errorf("%s was not built for running kernel %s: vermagic=%q", path, release, vermagic)
		}
		deps, err := command(opts.CommandTimeout, "modinfo", "-F", "depends", path)
		if err != nil {
			return err
		}
		if deps == "" {
			continue
		}
		for _, dep := range strings.Split(deps, ",") {
			if !moduleName.MatchString(dep) {
				return fmt.Errorf("invalid dependency %q for %s", dep, path)
			}
			if dep == "scst" {
				// Supplied by this checkout below.
				continue
			}
			if strings.HasPrefix(dep, "scst_") {
				return fmt.Errorf("unexpected SCST dependency %q", dep)
			}
			dependencies[i] = append(dependencies[i], dep)
		}
	}
	// Recheck before unload: a different manager may have changed the host.
	before, err = loadedModules(ctx, opts.CommandTimeout, run)
	if err != nil {
		return err
	}
	if before["scst"] {
		if err := checkEmpty(ctx); err != nil {
			return fmt.Errorf("refusing to replace configured SCST: %w", err)
		}
	}
	// Direct insmod skips the runtime directories created by scst/src/Makefile
	// during installation. The PR directory is needed even for dummy devices.
	fmt.Fprintln(progress, "Preparing SCST runtime directories")
	if _, err := command(opts.CommandTimeout, "mkdir", "-p", "--",
		"/var/lib/scst/pr", "/var/lib/scst/dif_tags", "/var/lib/scst/vdev_mode_pages"); err != nil {
		return err
	}
	for i := len(modules) - 1; i >= 0; i-- {
		if before[modules[i].name] {
			fmt.Fprintf(progress, "Unloading %s\n", modules[i].name)
			if _, err := command(opts.CommandTimeout, "rmmod", modules[i].name); err != nil {
				return err
			}
		}
	}
	for i, module := range modules {
		for _, dep := range dependencies[i] {
			if _, err := command(opts.CommandTimeout, "modprobe", "--", dep); err != nil {
				return err
			}
		}
		fmt.Fprintf(progress, "Loading %s from checkout\n", module.name)
		args := []string{"insmod", filepath.Join(opts.SourceDir, module.path)}
		if module.name == "scst_local" {
			args = append(args, "add_default_tgt=0")
		}
		if _, err := command(opts.CommandTimeout, args...); err != nil {
			return err
		}
		m.loaded = append(m.loaded, module.name)
	}
	return nil
}

// Unload runs after spec cleanup, while the suite still owns its host lock.
// It also handles a partially completed Prepare, but leaves existing modules
// alone if Prepare failed before loading anything. Stop on the first failure.
func (m *Modules) Unload(ctx context.Context, timeout time.Duration, run RunProgram, checkEmpty func(context.Context) error, progress io.Writer) error {
	if len(m.loaded) == 0 {
		return nil
	}
	if err := checkEmpty(ctx); err != nil {
		return fmt.Errorf("refusing to unload SCST: %w", err)
	}
	for len(m.loaded) != 0 {
		name := m.loaded[len(m.loaded)-1]
		fmt.Fprintf(progress, "Unloading %s\n", name)
		if _, err := runCommand(ctx, timeout, run, "rmmod", name); err != nil {
			return err
		}
		loaded, err := loadedModules(ctx, timeout, run)
		if err != nil {
			return err
		}
		if loaded[name] {
			return fmt.Errorf("%s is still loaded after rmmod", name)
		}
		m.loaded = m.loaded[:len(m.loaded)-1]
	}
	return nil
}

func runCommand(ctx context.Context, timeout time.Duration, run RunProgram, args ...string) (string, error) {
	r, err := run(ctx, timeout, args...)
	if err != nil {
		return "", fmt.Errorf("host command: %w\n%s", err, r.String())
	}
	if r.ExitCode != 0 {
		return "", fmt.Errorf("host command: %s", r.String())
	}
	return strings.TrimSpace(r.Stdout), nil
}

func loadedModules(ctx context.Context, timeout time.Duration, run RunProgram) (map[string]bool, error) {
	out, err := runCommand(ctx, timeout, run, "lsmod")
	if err != nil {
		return nil, err
	}
	lines := strings.Split(out, "\n")
	if len(lines) == 0 || strings.Join(strings.Fields(lines[0]), " ") != "Module Size Used by" {
		return nil, fmt.Errorf("unexpected lsmod header")
	}
	modules := make(map[string]bool)
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 3 || !moduleName.MatchString(fields[0]) {
			return nil, fmt.Errorf("invalid lsmod row: %q", line)
		}
		modules[fields[0]] = true
	}
	return modules, nil
}
