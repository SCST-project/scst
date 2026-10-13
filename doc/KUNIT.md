# SCST KUnit tests

KUnit checks SCST functions using private fixtures and simulated dependencies.
Use the latest upstream kernel with native KUnit; API backports are not supported.
Normal builds leave tests disabled and do not require KUnit headers.

## Build

Use a configured and prepared kernel build directory:

```sh
make scst KDIR=/path/to/kernel-build CONFIG_SCST_KUNIT_TEST=y
make kunit-list
```

The single `CONFIG_SCST_KUNIT_TEST` switch includes every suite in its owning
module. `KUNIT_LABEL` never limits compilation. KUnit supports out-of-tree
module builds with `CONFIG_KUNIT=y/m`.

| Module | Labels |
| --- | --- |
| `scst.ko` | `LIB` |

Use a disposable VM for execution: ordinary SCST initialization still
discovers SCSI devices. Native KUnit
registers suites on module initialization and controls their execution.

## Add a suite

Keep suites and shared fixtures under their owning component's `kunit/`
directory. Compile suites as separate objects and add them to the owning
module's list in `scst/src/kunit/objects.mk`. Register suites with
`scst_kunit_suite()`, which supplies the native name and label metadata:

```c
scst_kunit_suite(example_suite, "LIB", "-example",
                 .test_cases = example_cases,
);
```

`make kunit-list KUNIT_LABEL=LIB` discovers these registrations in source;
no build or loaded module is needed. Labels need no separate Makefile list.

Keep private implementation types in `*_priv.h` and test access declarations
in `*_test.h` beside the owning `.c` file. Guard test declarations with
`SCST_KUNIT_ENABLED`; keep forward declarations needed by ordinary builds in
the `.c` file. Fixtures stay under `kunit/` as `*_fixture.{h,c}`.
`scst/src/scst_test.h` supplies `SCST_KUNIT_VISIBLE` and task-scoped
`SCST_KUNIT_REDIRECT`; normal builds retain static functions and disabled
redirects. Test interfaces are not installed headers or module exports.

Fixtures must tolerate failed initialization and assertions. Bound worker
waits; unfinished work must retain its state and module reference and report
`scst_kunit_retain()`. Unsafe cases report `SKIP` pending separate production
fixes. Storage and transport integration belongs in component tests; upstream
QLogic initiator/HBA code is out of scope.

Tooling checks use temporary files and mocked operations, without SCST access:

```sh
python3 -m unittest discover -s scripts/kunit -p 'test_*.py'
```
