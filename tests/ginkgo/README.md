# SCST component tests

Ginkgo/Gomega tests exercise SCST management through `scstadmin` on
`scst_local`.

## Setup and run

Use a disposable Linux target with root access, an empty SCST configuration,
Go as specified in [go.mod](go.mod), Perl and kmod utilities. Building requires
SCST build dependencies, Perl `ExtUtils::MakeMaker` and running-kernel headers.
Install dependencies separately; do not run another SCST manager concurrently.

From the repository root:

```sh
cp tests/ginkgo/config.example.json tests/ginkgo/config.local.json
```

Set `disposable_host=true` and choose `admin_command`. `["scstadmin"]` uses the
installed utility, including with `ginkgo-test-build`. To test this checkout:

```json
"admin_command": [
  "/usr/bin/perl",
  "-I/absolute/checkout/scstadmin/scstadmin.sysfs/scst-1.0.0/lib",
  "/absolute/checkout/scstadmin/scstadmin.sysfs/scstadmin"
]
```

Validate the config, then run as root:

```sh
make ginkgo-config GINKGO_CONFIG=tests/ginkgo/config.local.json
make ginkgo-test-build GINKGO_CONFIG=tests/ginkgo/config.local.json
# Reuse modules already built for the running kernel:
make ginkgo-test GINKGO_CONFIG=tests/ginkgo/config.local.json
```

Use `KDIR=/absolute/kernel/build` for headers elsewhere. Both live targets
load checkout modules, replacing existing SCST modules only if unconfigured.
Successful cleanup unloads SCST modules; standard kernel dependencies and
runtime directories under `/var/lib/scst` remain.

## Select tests

The default is `GINKGO_LABEL='local && basic'`. Use the listing below to
select other labels.
`GINKGO_FOCUS` additionally filters spec names by regexp.

```sh
# List every spec and its labels without accessing SCST:
make ginkgo-list GINKGO_LABEL=''
# Select rejection cases:
make ginkgo-test-build GINKGO_CONFIG=tests/ginkgo/config.local.json GINKGO_LABEL=negative
```

An empty label filter selects all specs. `clear-config` tests invoke global
`scstadmin -clear_config -force`.
An empty selection or suite failure stops the run. Parallel runs are
unsupported: use the same `lock_file` and runner user on the host.

## Configuration

[config.example.json](config.example.json) lists defaults; `ginkgo-config`
validates and prints the effective config. The named JSON file overrides
defaults without implicit user overrides. `GINKGO_CONFIG` is relative to the
Make invocation directory; relative config paths resolve against the JSON
file, except interpreter arguments, which need absolute paths. Local profiles
are ignored by Git.

## Checks and recovery

`make ginkgo-check` runs framework unit tests, vet and suite compilation;
it does not access SCST. Neither it nor `ginkgo-list` proves
live behavior. Use the Make targets for live runs: plain `go test` skips specs
without `SCST_TEST_CONFIG` and needs `-count=1 -timeout=0` when running them.

Cleanup removes owned sessions/configuration before closing devices and
unloading modules. A failure or interrupted command stops the run and may
retain modules. Inspect and recover the host before
retrying; never remove a lock file to bypass a held lock.

The printed artifact directory under `report_dir` contains effective config,
command logs, JSON/JUnit reports and scenario inputs. Kernel warnings are not
collected: retain kernel logs when investigating failures.
