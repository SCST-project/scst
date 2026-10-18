# Repository tooling

[README.md](README.md) describes the directories and entry points. Follow the
root guidance and any nested instructions, including [KUnit tooling](kunit/AGENTS.md).

- Keep a moved helper and all its callers, Make targets, CI jobs, packaging
  references, tests, and documentation in the same commit.
- Resolve shared helper paths relative to the owning script. For sourced
  Bash libraries use `BASH_SOURCE` when the caller can live elsewhere.
- Preserve intentional caller-directory semantics for source selection,
  archive contents, patch generation, and module signing.
- Keep path reorganizations separate from changes to analyzer coverage,
  diagnostic filtering, kernel support, or runtime behavior. Document policy
  changes explicitly in their own commits.
- Inspect side effects before running a helper. Syntax checks and lint do not
  authorize cleanup, downloads, builds, signing, deployment, or live-device
  exercises; use the root safety boundaries and the requested task scope.
