---
name: scst-kernel-update
description: Refresh SCST nightly kernel versions and derived CI matrices from official upstream and distribution archives, and prepare the nightly/update branch. Use for kernel support-list maintenance; adding distribution releases or UEK generations and fixing compatibility regressions are separate work.
---

# SCST kernel updates

Follow the repository's current `AGENTS.md` and `CONTRIBUTING.md`. This skill
captures update policy; it does not authorize builds, live-host operations,
publication, or history rewriting beyond the user's request.

## Branch and source of truth

- Inspect status, worktrees, remotes, and `nightly/update` before switching.
  Resolve spelling from Git rather than creating a second `nighly/update`.
- Fetch the requested base and update branch. Record both SHAs. Rebase on
  current `origin/master` when requested, preserving unrelated work and any
  branch-only compatibility fixes. Already applied commits may be skipped;
  verify patch equivalence rather than replaying them blindly.
- `ABT_KERNELS` in `nightly/conf/nightly.conf` is canonical. Exact versions
  propagate through `scripts/kernel/kernel-matrix` to regression and RPM CI.
  `.github/kernel-matrix.conf` contains selectors and RPM target policy.
  Inspect these consumers each time in case paths or behavior have changed.
- Updating an existing series normally changes only `nightly.conf`. A newly
  requested upstream release also needs its CI selector. Do not duplicate
  exact versions in workflow YAML or regenerate unrelated artifacts.

## Find current versions

Compare the checked-in inventory directly with published latest versions.
Reading every intervening announcement is unnecessary; the mailing list is
useful for release context, EOL notices, and investigating a regression.
Record the retrieval date, old/new versions, and supporting URLs.

For upstream kernels, run the bundled read-only helper from the SCST root:

```sh
python3 .agents/skills/scst-kernel-update/scripts/upstream_candidates.py \
  nightly/conf/nightly.conf
```

It combines <https://www.kernel.org/releases.json> with the official
`https://cdn.kernel.org/pub/linux/kernel/v<major>.x/` indexes. The feed alone
misses final updates of series that have since become EOL. The helper checks
existing upstream series, reports missing current non-RC releases separately,
and never edits files. Network/parse failures are errors, not "up to date".
Verify proposed tarball/patch URLs before applying candidates, especially
when the feed and mirror index temporarily disagree. Exclude RC and linux-next.

For distribution entries, retain the exact distribution/release pair, upstream
baseline, and UEK generation already present. Read
`scripts/kernel/rhel-rpm-functions` for URLs the runner can actually consume.

- Rocky: start at <https://download.rockylinux.org/pub/rocky/>. Inspect the
  exact minor release's `BaseOS/source/tree/Packages/k/` (or `Packages/`).
  Retired minors move to `https://dl.rockylinux.org/vault/rocky/`; a missing
  active directory does not authorize advancing to another minor.
- UEK: start at <https://yum.oracle.com/oracle-linux-10.html> and the analogous
  page for the existing OL major. Select that entry's UEK generation, then
  inspect `index_src.html` for `kernel-uek` source RPMs. The same OL major can
  offer several UEK generations. Keep OL major, UEK generation, and upstream
  baseline distinct; do not select the largest version across repositories.
- Existing AlmaLinux/CentOS entries: inspect the exact release's source vault
  during a full inventory refresh. They can contain a missed final update.
  Keep the baseline and package variant: a CentOS vault can also contain a
  different kernel baseline or `centos.plus`. Do not replace old entries with
  another distribution or delete them because of EOL.

Compare RPM **version and release**, preferably with RPM's comparator or repo
metadata. Alphabetic sorting and blindly taking the last `sort -V` filename
can rank `553.el8_10` above `553.174.1.el8_10`. Keep only the intended package
(`kernel` or `kernel-uek`), not debug, realtime, tools, or development variants.
Verify the exact source RPM exists at a URL supported by the runner. For RPM
CI targets, also verify the exact binary kernel/devel package version is
published in the configured repositories (Rocky kernel-devel may be in
AppStream rather than BaseOS). Indexes/repodata and successful HEAD
requests suffice; do not download large packages just to check availability.

## Apply and validate

- Update each existing series to its newest confirmed published version.
  Keep options (`-nc`, `-ns`, etc.) and ordering. When advancing the upstream
  head, preserve the repository's convention: the new head has full nightly
  checks and the previous head becomes a normal `-nc` entry.
- Add a new upstream series when the request covers that release. Newly
  discovered distribution minors, OL majors, and UEK generations are reported
  separately; adding them requires a separate support change.
- Run `bash -n` and Bash ShellCheck on changed sourced configs, then
  `bash scripts/kernel/kernel-matrix regression` and
  `bash scripts/kernel/kernel-matrix rpm`. Confirm unique resolutions, the
  intended upstream addition, unchanged distro identities/RPM targets, and
  updated exact versions in both outputs. Standalone config lint may report
  existing SC2034 assignments consumed by their sourcing scripts; establish
  the base result and also lint through `kernel-matrix`, without changing the
  repository's ignore policy.
- Inspect the diff and run `git diff --check <base>`. Use the registered
  `nightly build:` commit prefix and required per-commit checks. Keep the
  version refresh separate from compatibility/backport fixes.
- Report base/HEAD, changed versions, incomplete source checks, and which
  validation ran. Matrix generation and lint are not compilation or runtime
  evidence. Investigate CI failures at the exact published HEAD before adding
  backports; no speculative compatibility changes belong in the refresh.

When publishing is authorized, push only the intended branch. If its rebase
requires rewriting remote history, respect the user's authorization and use
`--force-with-lease=refs/heads/nightly/update:<recorded-remote-sha>` rather than
unconditional force. A lease rejection requires inspecting the new remote
state, not retrying with a weaker guard. Do not claim CI ran merely because a
branch was pushed: inspect workflow triggers and any existing PR.
