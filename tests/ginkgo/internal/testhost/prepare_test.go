// SPDX-License-Identifier: GPL-2.0-only
package testhost

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"scst-component-tests/internal/admin"
)

// The fake observes command ordering without building or accessing modules.
type host struct {
	loaded   bool
	dirtyAt  int
	checks   int
	fail     string
	vermagic string
	deps     string
	calls    [][]string
	limits   []time.Duration
	modules  map[string]bool
	keep     string
	execFail bool
	listing  string
}

func (h *host) run(_ context.Context, limit time.Duration, args ...string) (admin.Result, error) {
	h.calls = append(h.calls, append([]string{}, args...))
	h.limits = append(h.limits, limit)
	r := admin.Result{Args: args}
	if h.modules == nil {
		h.modules = map[string]bool{"unrelated": true}
		if h.loaded {
			for _, name := range []string{"scst", "scst_vdisk", "scst_user", "scst_local"} {
				h.modules[name] = true
			}
		}
	}
	command := strings.Join(args, " ")
	if h.fail != "" && (command == h.fail || strings.HasPrefix(command, h.fail+" ")) {
		r.ExitCode, r.Stderr = 1, "injected failure"
		if h.execFail {
			return r, context.DeadlineExceeded
		}
		return r, nil
	}
	switch args[0] {
	case "lsmod":
		r.Stdout = "Module Size Used by\n"
		names := make([]string, 0, len(h.modules))
		for name := range h.modules {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			r.Stdout += name + " 123 0\n"
		}
		if h.listing != "" {
			r.Stdout = h.listing
		}
	case "uname":
		r.Stdout = "6.12-test\n"
	case "modinfo":
		switch args[2] {
		case "vermagic":
			r.Stdout = "6.12-test SMP mod_unload\n"
			if h.vermagic != "" {
				r.Stdout = h.vermagic
			}
		case "depends":
			if strings.HasSuffix(args[3], "/scst.ko") {
				r.Stdout = "crc32c_generic\n"
			} else {
				r.Stdout = "scst\n"
			}
			if h.deps != "" {
				r.Stdout = h.deps
			}
		default:
			return r, fmt.Errorf("unexpected modinfo arguments: %q", args)
		}
	case "insmod":
		h.modules[strings.ReplaceAll(strings.TrimSuffix(filepath.Base(args[1]), ".ko"), "-", "_")] = true
	case "rmmod":
		if args[1] != h.keep {
			delete(h.modules, args[1])
		}
	case "modprobe":
		h.modules[args[2]] = true
	case "make", "mkdir":
	default:
		return r, fmt.Errorf("unexpected host program: %q", args)
	}
	return r, nil
}

func (h *host) empty(context.Context) error {
	h.checks++
	if h.checks == h.dirtyAt {
		return fmt.Errorf("configured objects remain")
	}
	return nil
}

func options() Options {
	return Options{SourceDir: "/checkout with spaces", Build: true, Jobs: 2,
		BuildTimeout: 10 * time.Minute, CommandTimeout: 30 * time.Second}
}

func TestBuildAndLoadFromCheckout(t *testing.T) {
	for _, build := range []bool{false, true} {
		for _, loaded := range []bool{false, true} {
			t.Run(fmt.Sprintf("build=%t/already-loaded=%t", build, loaded), func(t *testing.T) {
				h := &host{loaded: loaded}
				opts := options()
				opts.Build = build
				wantBuildCount := 0
				if build {
					wantBuildCount = 4
				} else {
					// Loading existing modules must not need any build settings.
					opts.Jobs, opts.BuildTimeout = 0, 0
				}
				if err := new(Modules).Prepare(context.Background(), opts, h.run, h.empty, io.Discard); err != nil {
					t.Fatal(err)
				}
				wantChecks := 0
				if loaded {
					wantChecks = 2
				}
				if h.checks != wantChecks {
					t.Fatalf("empty-host checks: got %d, want %d", h.checks, wantChecks)
				}
				var builds, changes [][]string
				metadata := 0
				for i, args := range h.calls {
					limit := opts.CommandTimeout
					switch args[0] {
					case "make":
						builds = append(builds, args)
						limit = opts.BuildTimeout
					case "modinfo":
						metadata++
					case "mkdir", "rmmod", "modprobe", "insmod":
						if metadata != 8 || len(builds) != wantBuildCount {
							t.Fatal("changed modules before all builds and metadata checks completed")
						}
						changes = append(changes, args)
					}
					if h.limits[i] != limit {
						t.Fatalf("wrong timeout for %q", args)
					}
				}
				var wantBuilds [][]string
				if build {
					for _, target := range []string{"scst", "scst_local", "usr", "scstadm"} {
						wantBuilds = append(wantBuilds, []string{"make", "-C", opts.SourceDir, "-j2", "KVER=6.12-test", "KDIR=/lib/modules/6.12-test/build", target})
					}
				}
				if !reflect.DeepEqual(builds, wantBuilds) {
					t.Fatalf("build order/arguments: %q", builds)
				}
				wantChanges := [][]string{{"mkdir", "-p", "--", "/var/lib/scst/pr", "/var/lib/scst/dif_tags", "/var/lib/scst/vdev_mode_pages"}}
				if loaded {
					wantChanges = append(wantChanges, []string{"rmmod", "scst_local"}, []string{"rmmod", "scst_user"},
						[]string{"rmmod", "scst_vdisk"}, []string{"rmmod", "scst"})
				}
				wantChanges = append(wantChanges,
					[]string{"modprobe", "--", "crc32c_generic"},
					[]string{"insmod", opts.SourceDir + "/scst/src/scst.ko"},
					[]string{"insmod", opts.SourceDir + "/scst/src/dev_handlers/scst_vdisk.ko"},
					[]string{"insmod", opts.SourceDir + "/scst/src/dev_handlers/scst_user.ko"},
					[]string{"insmod", opts.SourceDir + "/scst_local/scst_local.ko", "add_default_tgt=0"})
				if !reflect.DeepEqual(changes, wantChanges) {
					t.Fatalf("module order/arguments: %q", changes)
				}
			})
		}
	}
}

func TestRefuseConfiguredHostBeforeUnload(t *testing.T) {
	for _, build := range []bool{false, true} {
		for _, dirtyAt := range []int{1, 2} {
			t.Run(fmt.Sprintf("build=%t/check-%d", build, dirtyAt), func(t *testing.T) {
				h := &host{loaded: true, dirtyAt: dirtyAt}
				opts := options()
				opts.Build = build
				err := new(Modules).Prepare(context.Background(), opts, h.run, h.empty, io.Discard)
				if err == nil || !strings.Contains(err.Error(), "configured objects") {
					t.Fatalf("dirty host accepted: %v", err)
				}
				for _, args := range h.calls {
					if args[0] == "mkdir" || args[0] == "rmmod" || args[0] == "insmod" || args[0] == "modprobe" || dirtyAt == 1 && args[0] == "make" {
						t.Fatalf("unexpected operation on dirty host: %q", args)
					}
				}
			})
		}
	}
}

func TestMissingModulesWithoutBuild(t *testing.T) {
	h := &host{loaded: true, fail: "modinfo"}
	opts := options()
	opts.Build = false
	err := new(Modules).Prepare(context.Background(), opts, h.run, h.empty, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "ginkgo-test-build") {
		t.Fatalf("missing build instruction: %v", err)
	}
	for _, args := range h.calls {
		if args[0] == "make" || args[0] == "mkdir" || args[0] == "rmmod" || args[0] == "insmod" || args[0] == "modprobe" {
			t.Fatalf("changed host instead of reporting missing modules: %q", args)
		}
	}
}

func TestBuildOrMetadataFailurePreservesLoadedModules(t *testing.T) {
	for name, h := range map[string]*host{
		"build":                 {fail: "make"},
		"metadata":              {fail: "modinfo"},
		"wrong kernel":          {vermagic: "6.13-other SMP"},
		"unexpected dependency": {deps: "scst_other"},
	} {
		t.Run(name, func(t *testing.T) {
			h.loaded = true
			if err := new(Modules).Prepare(context.Background(), options(), h.run, h.empty, io.Discard); err == nil {
				t.Fatal("accepted failure")
			}
			for _, args := range h.calls {
				if args[0] == "mkdir" || args[0] == "rmmod" || args[0] == "insmod" || args[0] == "modprobe" {
					t.Fatalf("changed loaded modules: %q", args)
				}
			}
		})
	}
}

func TestStopAfterModuleCommandFailure(t *testing.T) {
	for _, fail := range []string{"mkdir", "rmmod scst_local", "rmmod scst", "modprobe", "insmod"} {
		t.Run(fail, func(t *testing.T) {
			h := &host{loaded: true, fail: fail}
			err := new(Modules).Prepare(context.Background(), options(), h.run, h.empty, io.Discard)
			if err == nil || !strings.Contains(err.Error(), "injected failure") {
				t.Fatalf("missing failure: %v", err)
			}
			last := strings.Join(h.calls[len(h.calls)-1], " ")
			if last != fail && !strings.HasPrefix(last, fail+" ") {
				t.Fatalf("continued after failure with %s", last)
			}
		})
	}
}

func TestKernelDirectoryOverride(t *testing.T) {
	h := &host{}
	opts := options()
	opts.KernelDir = "/custom kernel/build"
	if err := new(Modules).Prepare(context.Background(), opts, h.run, h.empty, io.Discard); err != nil {
		t.Fatal(err)
	}
	for _, args := range h.calls {
		if args[0] == "make" && args[5] != "KDIR="+opts.KernelDir {
			t.Fatalf("lost kernel directory override: %q", args)
		}
	}
}

func TestUnloadOwnedModules(t *testing.T) {
	for _, tc := range []struct {
		name, fail string
		loaded     bool
		unload     []string
		remaining  []string
	}{
		{name: "complete", unload: []string{"scst_local", "scst_user", "scst_vdisk", "scst"}},
		{name: "replaced", loaded: true, unload: []string{"scst_local", "scst_user", "scst_vdisk", "scst"}},
		{name: "core only", fail: "insmod /checkout with spaces/scst/src/dev_handlers/scst_vdisk.ko", unload: []string{"scst"}},
		{name: "no user handler", fail: "insmod /checkout with spaces/scst/src/dev_handlers/scst_user.ko", unload: []string{"scst_vdisk", "scst"}},
		{name: "no local driver", fail: "insmod /checkout with spaces/scst_local/scst_local.ko", unload: []string{"scst_user", "scst_vdisk", "scst"}},
		{name: "build failure", fail: "make", loaded: true, remaining: []string{"scst", "scst_vdisk", "scst_user", "scst_local"}},
		{name: "replacement failure", fail: "rmmod scst_vdisk", loaded: true, remaining: []string{"scst", "scst_vdisk"}},
		{name: "core load failure", fail: "insmod /checkout with spaces/scst/src/scst.ko"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &host{loaded: tc.loaded, fail: tc.fail}
			m := new(Modules)
			opts := options()
			err := m.Prepare(context.Background(), opts, h.run, h.empty, io.Discard)
			if (err != nil) != (tc.fail != "") {
				t.Fatalf("preparation: %v", err)
			}
			h.fail, h.calls, h.limits = "", nil, nil
			checked := false
			checkEmpty := func(ctx context.Context) error {
				checked = true
				return h.empty(ctx)
			}
			run := func(ctx context.Context, timeout time.Duration, args ...string) (admin.Result, error) {
				if !checked {
					t.Fatal("module command before empty-state check")
				}
				return h.run(ctx, timeout, args...)
			}
			if err := m.Unload(context.Background(), opts.CommandTimeout, run, checkEmpty, io.Discard); err != nil {
				t.Fatal(err)
			}
			if checked != (len(tc.unload) != 0) {
				t.Fatalf("checked host without owned modules: %t", checked)
			}
			var want [][]string
			for _, name := range tc.unload {
				want = append(want, []string{"rmmod", name}, []string{"lsmod"})
			}
			if !reflect.DeepEqual(h.calls, want) {
				t.Fatalf("unload order/verification: got %q, want %q", h.calls, want)
			}
			for _, limit := range h.limits {
				if limit != opts.CommandTimeout {
					t.Fatalf("wrong unload command timeout: %s", limit)
				}
			}
			for _, name := range []string{"scst", "scst_vdisk", "scst_user", "scst_local"} {
				want := false
				for _, remaining := range tc.remaining {
					want = want || name == remaining
				}
				if h.modules[name] != want {
					t.Fatalf("unexpected remaining module %s: %t", name, h.modules[name])
				}
			}
			if !h.modules["unrelated"] || len(tc.unload) != 0 && !h.modules["crc32c_generic"] {
				t.Fatal("unloaded modules outside suite ownership")
			}
			calls, checks := len(h.calls), h.checks
			if err := m.Unload(context.Background(), opts.CommandTimeout, h.run, h.empty, io.Discard); err != nil {
				t.Fatal(err)
			}
			if len(h.calls) != calls || h.checks != checks {
				t.Fatal("repeated cleanup accessed host")
			}
		})
	}
}

func TestUnloadStopsOnFailure(t *testing.T) {
	for _, tc := range []struct {
		name, fail, keep, listing, last string
		dirty, execFail                 bool
	}{
		{name: "configured host", dirty: true},
		{name: "busy local driver", fail: "rmmod scst_local", last: "rmmod scst_local"},
		{name: "busy user handler", fail: "rmmod scst_user", last: "rmmod scst_user"},
		{name: "busy handler", fail: "rmmod scst_vdisk", last: "rmmod scst_vdisk"},
		{name: "busy core", fail: "rmmod scst", last: "rmmod scst"},
		{name: "interrupted command", fail: "rmmod scst_local", execFail: true, last: "rmmod scst_local"},
		{name: "still loaded", keep: "scst_local", last: "lsmod"},
		{name: "verification failed", fail: "lsmod", last: "lsmod"},
		{name: "invalid module list", listing: "invalid output", last: "lsmod"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &host{}
			m := new(Modules)
			if err := m.Prepare(context.Background(), options(), h.run, h.empty, io.Discard); err != nil {
				t.Fatal(err)
			}
			h.calls, h.fail, h.keep, h.listing, h.execFail = nil, tc.fail, tc.keep, tc.listing, tc.execFail
			if tc.dirty {
				h.dirtyAt = h.checks + 1
			}
			if err := m.Unload(context.Background(), options().CommandTimeout, h.run, h.empty, io.Discard); err == nil {
				t.Fatal("unload failure accepted")
			}
			if tc.dirty {
				if len(h.calls) != 0 {
					t.Fatalf("accessed modules on configured host: %q", h.calls)
				}
			} else if last := strings.Join(h.calls[len(h.calls)-1], " "); last != tc.last {
				t.Fatalf("continued after failure: %s", last)
			}
		})
	}
}

func TestISCSIProfile(t *testing.T) {
	h := new(host)
	opts := options()
	opts.ISCSI = true
	m := new(Modules)
	if err := m.Prepare(context.Background(), opts, h.run, h.empty, io.Discard); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(m.loaded, []string{"scst", "scst_vdisk", "iscsi_scst"}) {
		t.Fatalf("wrong modules: %v", m.loaded)
	}
	var builds []string
	for _, args := range h.calls {
		if strings.Contains(strings.Join(args, " "), "scst_local") {
			t.Fatalf("local driver in iSCSI profile: %v", args)
		}
		if args[0] == "make" {
			builds = append(builds, args[len(args)-1])
		}
	}
	if !reflect.DeepEqual(builds, []string{"scst", "iscsi", "scstadm"}) {
		t.Fatalf("wrong build order: %v", builds)
	}
	if err := m.Unload(context.Background(), opts.CommandTimeout, h.run, h.empty, io.Discard); err != nil {
		t.Fatal(err)
	}
	if h.modules["iscsi_scst"] || h.modules["scst"] {
		t.Fatal("iSCSI modules remain loaded")
	}
}
