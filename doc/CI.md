# Continuous integration

Workflows live in [`.github/workflows`](../.github/workflows). PR checks target
`master`; push checks run after changes reach `master`.

| Workflow | Purpose | Events |
| --- | --- | --- |
| Checkpatch ([PR](../.github/workflows/checkpatch_pull.yml), [push](../.github/workflows/checkpatch_push.yml)) | Patch and commit style | PR, push |
| [CI](../.github/workflows/ci.yml) | Clang build and DEB packaging | PR, push, manual |
| [Packages](../.github/workflows/rpm.yml) | Ubuntu DEBs, RPMs and a published package snapshot | Push to master only |
| [Regression](../.github/workflows/run_regression_tests.yaml) | Module and patched-kernel builds across the kernel matrix | PR, push |
| [KUnit](../.github/workflows/kunit.yml) | Kernel unit tests in QEMU | PR, push, manual |
| [Ginkgo](../.github/workflows/ginkgo.yml) | Local and TCP iSCSI component tests in QEMU | PR, push, manual |
| [Coverity](../.github/workflows/coverity.yml) | Static analysis | Push, upstream repository only |
| [Mailing list](../.github/workflows/mail_notification.yml) | Commit notifications | Push, upstream repository only |

On PRs, [select_checks.py](../scripts/ci/select_checks.py) selects Clang, kernel
regression, KUnit and Ginkgo using [ci-checks.toml](../.github/ci-checks.toml).
Edit that config to change path rules; it is validated before selection.
Unknown paths and changes to the config or selector run every check.
Known unrelated changes skip expensive work; regression selection happens
before creating its matrix jobs. Some documentation is a package or kernel-patch
input and still needs validation. Checkpatch always runs. Packages runs only
after a push to master; the separate Clang build still checks DEB packaging on
PRs. Push and manual runs retain their full checks. Selection errors fail the
workflow; skip reasons appear in the job summary.

Ginkgo uses `ci-pr` for PRs, `ci-push` for master, and all tests for manual runs.
See [test selection](../tests/ginkgo/README.md#select-tests) for the label sets.
Kernel matrices are maintained through `.github/kernel-matrix.conf` and
`nightly/conf/nightly.conf`; VM kernel pins are in `scripts/ci/kernel.env`
and `kernel.SHA256SUMS` and must be updated together.

Further Ginkgo jobs run the local `user` specs on Fedora 33's Linux 5.8.18 and
5.9.16, pinned in `scripts/ci/kernel-5.8.env` and `kernel-5.9.env` with their
`SHA256SUMS`. Linux 5.9 is the first release where `fork()` copies pinned
ordinary anonymous pages, which scst_user relies on. The 5.8 fork fixture
uses the documented `MADV_DONTFORK` protection; the 5.9 fixture exercises
pinning without it. Both require correct geometry and data after the fork.
The invalid-capacity specs check the exact SCSI rejection on both kernels.
The images are otherwise built the same way; these jobs have no iSCSI initiator.

## Results

Start with the failed job's log. KUnit/Ginkgo upload build logs, test reports
and serial consoles as artifacts, retained for seven days. Timeouts, guest
kernel diagnostics and incomplete reports fail the run. Package artifacts
are attached to the Packages workflow; upstream master builds also update
the `master-rpm` prerelease snapshot.

## Local reproduction

Use the commands in the relevant workflow for build and package checks;
[CONTRIBUTING.md](../CONTRIBUTING.md#builds-and-tests) describes local entry
points. [KUnit](KUNIT.md) and [Ginkgo](../tests/ginkgo/README.md) describe their
standalone runners.

To reproduce the CI VM environment, install Docker with Buildx, fakeroot,
tar, mkfs.ext4, Python 3.11+, QEMU with the stream network backend, qemu-img,
ssh-keygen and sha256sum. Builds use a committed Git snapshot and matching
kernel headers. SCST runs inside disposable guests; host devices are not
exported. Use new output directories for each run.

```sh
bash scripts/ci/build-image kunit /tmp/scst-kunit-image
python3 scripts/ci/vm.py kunit /tmp/scst-kunit-image /tmp/scst-kunit-results --timeout 1200

bash scripts/ci/build-image ginkgo /tmp/scst-ginkgo-image
python3 scripts/ci/vm.py ginkgo /tmp/scst-ginkgo-image /tmp/scst-ginkgo-results --ginkgo-label ci-pr
```

Use `--ginkgo-label ci-push` for the master selection; omit it for all specs.
For the scst_user kernel jobs, add the pin name, such as `kernel-5.9`, to
`build-image` and run `vm.py` with `--local-only --ginkgo-label user`.
`--local-only` intersects the resolved label expression with `local`; without
`--ginkgo-label`, it selects all local specs.
QEMU tries KVM then TCG; `--accel tcg` forces emulation. To check the VM
supervisor itself, use `vm.py self-test` with a KUnit image; this intentionally
crashes a guest.

CI tooling checks without builds or VM access:

```sh
python3 scripts/ci/select_checks.py --validate-config
python3 -m unittest discover -s scripts/ci -p 'test_*.py'
```
