# SCST code style

SCST follows the Linux kernel coding style and [CONTRIBUTING.md](../CONTRIBUTING.md).
This document records additional project layout rules. Rule identifiers are
stable and appear in diagnostics from `make scs_lint`.

## SCS.1: KUnit visibility annotations

Place `SCST_KUNIT_VISIBLE`, `SCST_KUNIT_VISIBLE_INLINE`, or direct
`VISIBLE_IF_KUNIT` on a line of its own before a function declaration or
definition. Do not put a return type, function name or other attribute on that
line. Keep the existing signature and other attributes on the following lines.

```c
SCST_KUNIT_VISIBLE
void scst_example(struct scst_cmd *cmd)
{
}
```

This layout does not change visibility, inlining, linkage or the behavior of
KUnit helpers.

`scs_lint` checks all preprocessor branches in the selected project C sources
and headers. Comments, string literals and preprocessor directives (including
macro definitions) are outside this rule. There are no per-file waivers.

Run `make scs_lint` for all tracked project sources or
`scripts/scs_lint/run_scs_lint.sh path/to/file.c` for explicit files.
