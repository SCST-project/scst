# SCST component tests

Ginkgo/Gomega tests exercise management through `scstadmin` and SCSI commands
through sg3_utils. Transports are `scst_local` and TCP iSCSI with a separate
initiator controlled over SSH.

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

The default is `GINKGO_LABEL='local && basic'`. Combine `local` or `iscsi`
with `basic` (management) or `scsi` (protocol checks).
`GINKGO_FOCUS` additionally filters spec names by regexp.

```sh
# List every spec and its labels without accessing either host:
make ginkgo-list GINKGO_LABEL=''
# All except the known-crash case; prepare both hosts first:
make ginkgo-test-build GINKGO_CONFIG=tests/ginkgo/config.local.json GINKGO_LABEL='!known-crash'
```

An empty label filter selects all specs. The `known-crash` case (sync on
inactive fileio) also requires `allow_known_crash=true` and can crash affected
kernels. `clear-config` tests invoke global `scstadmin -clear_config -force`.
Only selected transport groups access hosts. Local teardown finishes before
iSCSI setup; an empty selection or suite failure stops the run. Parallel runs
are unsupported: use the same `lock_file` and runner user on each host.

## Configuration

[config.example.json](config.example.json) lists defaults; `ginkgo-config`
validates and prints the effective config. The named JSON file overrides
defaults without implicit user overrides. `GINKGO_CONFIG` is relative to the
Make invocation directory; relative config paths resolve against the JSON
file, except interpreter arguments, which need absolute paths. Local profiles
are ignored by Git; the initiator lock path must be absolute.

`backing_dir` selects an existing directory for temporary fileio images;
empty uses the artifact directory. Tests never adopt existing backing files.
Avoid whitespace, commas, semicolons, quotes, braces and backslashes in backing
paths. Set `fileio_thin_provisioning=false` if the filesystem cannot support
the TP-enabled case. `stress_iterations` and `scale_luns` control lifecycle
repetition and many-LUN coverage.

## Two-host iSCSI

Run Ginkgo on the target. Add `iscsi` from
[config.iscsi.example.json](config.iscsi.example.json), replace its addresses
and set both `disposable_host` flags to `true`.

- Target: OpenSSH client, `pgrep`, no running `iscsi-scstd`, and a local IPv4
  address with a free TCP port reachable from the initiator. SHA256/SHA3-256
  CHAP requires kernel AF_ALG hash support.
- Initiator: OpenSSH server, Python 3, `pgrep`, Open-iSCSI with SHA3-256
  `node.session.auth.chap_algs` support, running `iscsid`, loaded `iscsi_tcp`
  and no existing sessions. SCST is not needed here.
- Set up noninteractive root SSH from target to initiator with a verified host
  key. `identity_file` is on the target; empty uses normal SSH key selection.
  `iscsi.login_timeout` must be whole seconds below `command_timeout`.

The suite owns its target daemon and initiator sessions/node/iface records.
It preserves existing records and leaves initiator services and modules loaded.

## SCSI commands

Install Python 3, util-linux and sg3_utils on the command host: the target for
`local`, the initiator for `iscsi`. Cases check identity, capacity, LUN
visibility and rejection status/sense on temporary fileio exports.

## Checks and recovery

`make ginkgo-check` runs framework unit tests, vet and suite compilation;
it does not access SCST or remote hosts. Neither it nor `ginkgo-list` proves
live behavior. Use the Make targets for live runs: plain `go test` skips specs
without `SCST_TEST_CONFIG` and needs `-count=1 -timeout=0` when running them.

Cleanup removes owned sessions/configuration before closing devices, deleting
backing files and unloading modules. A failure or interrupted command stops
the run and may retain modules, files and the daemon. Inspect and recover the
affected hosts before retrying; never remove a lock file to bypass a held lock.

The printed artifact directory under `report_dir` contains effective config,
command logs, JSON/JUnit reports and scenario inputs. iSCSI adds SSH, initiator
and daemon logs, which may contain
test CHAP credentials. Kernel warnings are not collected: retain kernel logs
when investigating failures.
