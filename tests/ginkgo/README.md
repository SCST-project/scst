# SCST component tests

Ginkgo/Gomega tests exercise management through `scstadmin`, SCSI commands
through sg3_utils, and data verification through fio. Transports are
`scst_local` and TCP iSCSI with a separate initiator controlled over SSH.

For GitHub Actions, see [CI](../../doc/CI.md).

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
with `basic` (management), `scsi` or `io`; add `fileio` or `blockio` to narrow
the backend. For example, `local && io && fileio` needs no physical disk.
`GINKGO_FOCUS` additionally filters spec names by regexp.

GitHub pull requests use the `ci-pr` label set; pushes to `master` use `ci-push`.
Their definitions live in [labels.json](internal/testrun/labels.json), shared
by the local runner and VM supervisor:

| Label set | Ginkgo expression |
| --- | --- |
| `ci-pr` | `pr && !manual && !race && !stress` |
| `ci-push` | `!race && !manual` |

Each set aliases a whole filter; its definition combines ordinary Ginkgo labels.
The `pr` label marks individual representative specs or table entries: device,
target, LUN and group management, configuration reapplication, failed fileio
creation, iSCSI discovery/login/logout, MD5/SHA256 CHAP, invalid portal handling,
READ CAPACITY, read-only WRITE rejection and verified fileio/blockio I/O.
Adding `basic` or `smoke` alone does not expand this budgeted PR selection.
Pass either a set name or a Ginkgo expression as `GINKGO_LABEL`. Manual workflow
runs use an empty filter and select all specs, including `manual` and
timing-dependent `race` scenarios. The `manual` label excludes a spec from
both automatic CI sets. Other stress tests remain in `ci-push`.

```sh
# List the pull-request selection:
make ginkgo-list GINKGO_LABEL=ci-pr
# List the master push selection:
make ginkgo-list GINKGO_LABEL=ci-push
# List every spec and its labels without accessing either host:
make ginkgo-list GINKGO_LABEL=''
# All specs; prepare both hosts and a block device first:
make ginkgo-test-build GINKGO_CONFIG=tests/ginkgo/config.local.json GINKGO_LABEL=''
```

An empty label filter selects all specs. `clear-config` tests invoke global
`scstadmin -clear_config -force`. Only selected transport groups access hosts.
Local teardown finishes before iSCSI setup; an empty selection or suite
failure stops the run. Parallel runs are unsupported: use the same
`lock_file` and runner user on each host.

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
the TP-enabled cases, including UNMAP. `stress_iterations` and `scale_luns`
control lifecycle repetition and many-LUN coverage.

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

CHAP configuration tests require Python 3 on the target and the ability to
run file-access checks under an unprivileged UID/GID.

The isolated `internal/chap` suite tests the production CHAP implementation
with deterministic entropy I/O: length bounds, short reads, interruptions and
failure cleanup. It runs through `ginkgo-check` and requires `cc`. Interface
headers are prepared in a temporary directory; no daemon or storage is used.
Run it separately with `go test ./internal/chap` from this directory.

The isolated `internal/isns` suite checks production iSNS handlers against
malformed payloads ending at a guard page, including preservation of existing
ACLs. It also runs through `ginkgo-check`; use `go test ./internal/isns` to
run it separately. It requires `cc` and opens no sockets.

## SCSI and I/O

Install Python 3, util-linux and sg3_utils on the command host: the target for
`local`, the initiator for `iscsi`. I/O also needs fio and kernel `io_uring`
support there, plus `lsblk` and `wipefs` on the target for blockio preflight.

Fio verifies CRC32C data using three concurrent
4K, 64K and 128K jobs in disjoint regions; see the shared
[profile](internal/dataio/verify.fio). It checks completed I/O, not performance.
Readback checks do not verify data persistence across a crash or power loss.

The `user` specs run `usr/fileio/fileio_tgt` over `scst_local` with a fault
hook preloaded: the handler either forks or returns an invalid READ CAPACITY
block length. READ CAPACITY, reads and writes must stay correct afterwards.
Before Linux 5.9, the fork fixture applies the required `MADV_DONTFORK` to all
active data buffers and checks that protection was applied before forking.
On Linux 5.9 and later it uses no such protection, exercising page pinning.
Both paths require correct geometry and data; neither depends on selecting a
particular cached buffer to produce an error. The invalid-capacity cases
require CHECK CONDITION with sense `0b/44/00` on every kernel.
The specs need a C compiler on the target to build the hook;
`ginkgo-test-build` also builds `usr`, and the local suite loads `scst_user`.
The fork spec is labelled `manual`; the invalid-capacity specs remain in
`smoke`. To select only the fork spec on a disposable local target:

```sh
make ginkgo-list GINKGO_LABEL='user && manual'
make ginkgo-test-build GINKGO_CONFIG=tests/ginkgo/config.local.json GINKGO_LABEL='user && manual'
```

For manual VM runs on Linux 5.8 or 5.9, see [CI reproduction](../../doc/CI.md#local-reproduction).

The `unmap` specs exercise temporary thin-provisioned fileio exports over
`scst_local` and TCP iSCSI. They require util-linux `fallocate` on the target
and a backing filesystem that supports hole punching.
Setting `fileio_thin_provisioning=false` skips these specs.

```sh
# Both scst_local and TCP iSCSI, using previously built modules:
make ginkgo-test GINKGO_CONFIG=tests/ginkgo/config.local.json GINKGO_LABEL='unmap'
```

| fio backend | Sector size | Access |
| --- | --- | --- |
| `vdisk_fileio` | 512 bytes | `direct=0`, backend `o_direct=0`, temporary file |
| `vdisk_blockio` | 4096 bytes | `direct=1`, configured target block device |

Buffered runs flush and verify again with direct I/O. `io.region_mb` sets MiB
per job (default 64); `io.timeout` limits each fio invocation (default `3m`).
**Blockio overwrites the first `3 * io.region_mb` MiB (default 192 MiB) of
`io.block_device` on the target, with no data restoration.** Set this device
explicitly, preferably by `/dev/disk/by-id/`; missing configuration fails the
selected tests. It must be writable, large enough, 4 KiB aligned in size and
free of partitions, holders, mounts and signatures. No loop device is created.

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
command logs, JSON/JUnit reports and scenario inputs. I/O adds rendered jobs
and fio results; iSCSI adds SSH, initiator and daemon logs, which may contain
test CHAP credentials. Kernel-log collection depends on the selected specs;
retain kernel logs separately when investigating failures.
