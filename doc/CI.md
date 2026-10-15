# Tests in GitHub Actions

KUnit and Ginkgo have independent workflows. Each builds its own SCST modules
and runs tests in disposable QEMU guests within a single job:

- `.github/workflows/kunit.yml`: KUnit modules, supervisor checks for guest
  success, panic and timeout, then `make kunit-run`.
- `.github/workflows/ginkgo.yml`: ordinary SCST modules, `make ginkgo-check`,
  then local and TCP iSCSI tests through `make ginkgo-test`. Pull requests use
  `basic || smoke`; pushes to `master` and manual runs select all tests.

Both run on pushes and pull requests to `master`, or via `workflow_dispatch`.
The Debian package build in `.github/workflows/ci.yml` remains independent.
Ginkgo uses its locally built image directly; no image artifact is uploaded.

Docker builds a committed Git snapshot with the pinned Fedora kernel and
matching headers. QEMU loads SCST only into the guest kernel. It tries KVM
first and falls back to TCG; use `--accel tcg` or `--accel kvm` to select one.
The kernel pins are in `scripts/ci/kernel.env` and `kernel.SHA256SUMS`; update
them together. The Fedora base image is pinned in `scripts/ci/Dockerfile`.

Ginkgo uses separate target and initiator VMs on a private QEMU network,
a disposable 1 GiB block disk and guest ext4 backing files. No host block
devices or external initiators are used.

## Reports and failures

The supervisor keeps serial consoles outside the guests and enforces a hard
deadline. Kernel diagnostics, missing or incomplete test reports, a lost
initiator and timeouts fail the job, even if QEMU exits with status zero.
The KUnit workflow checks panic and timeout handling explicitly under TCG.

After each VM run, the step prints the native test output, including summaries
and failures. Failed runs also print kernel diagnostics and the tail of each
serial console; full logs remain in the artifacts.

Build logs, test reports and serial consoles are uploaded with `if: always()`
and retained for seven days. Ginkgo also saves build metadata and package
versions. VM disks and private SSH keys are not uploaded. A guest crash may
prevent its final report, but the external serial log survives. Upload still
requires a working GitHub runner.

## Local reproduction

Image construction requires Docker with Buildx, fakeroot, tar and mkfs.ext4.
Execution requires Python 3.11+, QEMU with the stream network backend,
qemu-img, ssh-keygen and sha256sum. Use new output directories for each run.
These commands boot disposable guests; self-test intentionally crashes one.

```sh
bash scripts/ci/build-image kunit /tmp/scst-kunit-image
python3 scripts/ci/vm.py self-test /tmp/scst-kunit-image /tmp/scst-vm-selftest --timeout 180 --accel tcg
python3 scripts/ci/vm.py kunit /tmp/scst-kunit-image /tmp/scst-kunit-results --timeout 1200

bash scripts/ci/build-image ginkgo /tmp/scst-ginkgo-image
python3 scripts/ci/vm.py ginkgo /tmp/scst-ginkgo-image /tmp/scst-ginkgo-results --timeout 10000
```

Add `--ginkgo-label 'basic || smoke'` to reproduce the pull-request selection.
The selected filter is printed in stdout and recorded in `result.json`;
both transport reports must confirm that filter.

Supervisor checks without VM or SCST access:

```sh
python3 -m unittest discover -s scripts/ci -p 'test_*.py'
```
