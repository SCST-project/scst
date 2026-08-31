# Agent workflow helpers

This directory contains deterministic checks used by the minimal agent harness. The
helpers use the Python standard library, except for pinned Ruff invoked through `uvx`.
They do not compile the product, load or run kernel modules, or evaluate model quality.

`check.py` provides:

- `snapshot` for a non-empty exact commit range, ancestry, `HEAD`, and
  tracked-cleanliness evidence. `--require-no-untracked` also rejects untracked files for
  an isolated deliverable worktree. Only initial validation of a newly prepared result
  worktree uses `--allow-empty`;
- `instructions` for the required `scst-` skill namespace, matching skill frontmatter and
  directory names, directly referenced Markdown files, required `agents/openai.yaml`
  invocation policy, and standalone agent-role TOML consistency.

`lint.py` selects pinned Ruff for existing changed Python files. For changes to agent
instructions or configuration it also runs `check.py instructions` and the focused unit
tests in this directory. `scst-lint-patch` invokes it automatically for the committed
range. Run these examples from the repository root:

```sh
python3 .agents/workflow/lint.py \
  --repository "$PWD" --base <full-base-sha> --head <full-head-sha>
```

Individual checks remain available for diagnosis:

```sh
python3 .agents/workflow/check.py instructions --repository "$PWD"
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s .agents/workflow -p 'test_*.py'
```

These helpers validate observable repository facts. Base and result branches are created
with ordinary Git commands because branch and worktree bootstrap must also work when the
selected base snapshot does not contain these helper files. The helpers do not validate
the semantic meaning of instructions, choose task scope, decide a design, grade a patch,
or replace independent review. They provide no compilation or runtime evidence.
