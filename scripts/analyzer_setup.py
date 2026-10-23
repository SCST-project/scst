"""Integration models are separate from source scope and diagnostic exceptions."""

MODELS = {
    "coccicheck": [
        {"path": "scripts/coccinelle/macros.h",
         "reason": "Parser hints supplement installed builtins and retain SCST/KUnit bodies."},
        {"path": "scripts/coccinelle/model.py",
         "reason": "Current source definitions retain SCST declaration bodies at call sites; no synthetic macro contexts are checked."},
        {"path": "scripts/coccinelle/iterators.json",
         "reason": "Current source definitions preserve iterator initialization, conditions and steps without pinned text."},
    ],
}
