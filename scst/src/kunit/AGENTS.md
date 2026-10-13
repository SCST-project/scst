# SCST core KUnit tests

Read [the KUnit guide](../../../doc/KUNIT.md#add-a-suite) for suite organization,
private interfaces and fixture ownership. `<area>/suites/` contains core tests;
handler and transport suites live beside their own components.

`objects.mk` lists test objects per module for out-of-tree Kbuild; `modules.mk`
lists build components and artifacts. Labels live in `scst_kunit_suite()`
registrations. `select.mk` handles public Makefile options and source listing.

Keep implementation types in `*_priv.h` and test access declarations in
`*_test.h` beside the owning source, guarded by `SCST_KUNIT_ENABLED`.
Fixtures stay here; production sources must not include this directory.
