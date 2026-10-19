# Repository tooling

[README.md](README.md) describes the directories and entry points. For changes
under `kunit/`, also follow its [instructions](kunit/AGENTS.md).

- Keep a moved helper and all its callers, Make targets, CI jobs, packaging
  references, tests, and documentation in the same commit.
- Resolve shared helper paths relative to the owning script. For sourced
  Bash libraries use `BASH_SOURCE` when the caller can live elsewhere.
- Preserve intentional caller-directory semantics for source selection,
  archive contents, patch generation, and module signing.
- Keep path reorganizations separate from changes to analyzer coverage,
  diagnostic filtering, kernel support, or runtime behavior. Document policy
  changes explicitly in their own commits.
- Reuse the shared source and process helpers for analyzer drivers. Keep input
  selection separate from diagnostic policy, retain complete raw reports, and
  propagate missing-tool and process failures. Report no eligible inputs as a
  skip; fail incomplete analyzer runs.
- Keep shared input exclusions in `policy/common.json`, with a reason for each
  rule. Do not add environment-based filters that bypass the reviewed policy.
- Drivers that modify build state must hold the shared build lock around build
  log reset and build-state changes. Other checks do not need the lock.
- Keep analyzer fixture tests isolated in temporary directories and processes.
  They must not compile or load SCST, access live storage, or change services.
- Apply the root safety boundaries to cleanup, signing and runtime helpers.
