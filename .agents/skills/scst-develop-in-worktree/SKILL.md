---
name: scst-develop-in-worktree
description: Internal result-branch and raw-worktree lifecycle for scst-develop-task. Preserve the supplied TASK_CONTRACT and user WIP, invoke scst-develop-patch, retain the result branch, and remove only a verified worktree.
---

# Manage one isolated task result

Use this internal lifecycle only when `$scst-develop-task` supplies a complete
`TASK_CONTRACT`. Preserve that contract unchanged. Use one result branch and no more than
one raw worktree for the task at a time. Do not route implementation workers or evolve
the harness from this layer.

Use append mode and no push by default. Rewrite history only when the user explicitly
authorizes it. Only the main agent may perform an explicitly authorized push through
`references/optional-push.md`.

Preserve all user WIP. Never stash, reset, clean, force-remove, or overwrite it.
Unrelated state in another checkout does not block isolated development unless Git
reports a branch-ownership or path collision.

## Resolve the base and result branch

At task start, the applicable `AGENTS.md` records only the initial symbolic local branch
as `TASK_DEFAULT_BASE_REF`. An explicit user-selected local base overrides it. A later
stable-checkout switch changes neither value.

On the first tracked increment, resolve and record:

```text
TASK_WORKTREE_PLAN:
STABLE_REPOSITORY: <canonical repository root recorded for this task>
TASK_DEFAULT_BASE_REF: <refs/heads/local-branch|EXPLICIT_BASE_REQUIRED>
BASE_REF: <refs/heads/local-branch>
START_BASE_TIP: <full commit>
RESULT_BRANCH_PREFIX: <repository-local configured prefix>
RESULT_REF: refs/heads/<configured-prefix>/<short-topic>-<short-id>
START_RESULT_TIP: <full commit>
WORKTREE_PATH: <absolute raw worktree path>
PATCH_BASE: <full commit>
MODE: <append|rewrite>
```

Normalize the selected base under `refs/heads/`, validate it with
`git -C <STABLE_REPOSITORY> check-ref-format <BASE_REF>`, and resolve it only when tracked
implementation starts:

```sh
git -C <STABLE_REPOSITORY> rev-parse --verify '<BASE_REF>^{commit}'
```

A missing or non-local default without an explicit base is `BLOCKED`; never infer a
replacement from a later checkout or another worktree.

Read `scst.chatBranchPrefix` only from repository-local Git configuration. Require exactly
one non-empty relative prefix with no surrounding whitespace, leading `refs/` or `/`, or
trailing `/`. Form a fresh lowercase hyphenated result branch, validate its full ref with
`git check-ref-format`, and require the exact local ref not to exist. Do not infer a
fallback prefix.

The first increment uses append mode and sets both `START_RESULT_TIP` and `PATCH_BASE`
to `START_BASE_TIP`. For every later increment, reuse `RESULT_REF` and resolve its
current tip as the new `START_RESULT_TIP`. In append mode, `PATCH_BASE` equals
`START_RESULT_TIP`. In rewrite mode, obtain explicit authorization for the exact result
history to replace and set `PATCH_BASE` to the last commit that must remain unchanged;
never rewrite `BASE_REF`.

## Create and verify the worktree

Create a unique parent with `mktemp -d` under `/tmp`. For the first increment, create the
branch and worktree atomically:

```sh
git -C <STABLE_REPOSITORY> worktree add -b <result-branch> \
  <WORKTREE_PATH> <START_BASE_TIP>
```

For a later increment, add a worktree for the existing result branch only when Git shows
that it is not checked out.

For either case, verify `git worktree list --porcelain` contains exactly the recorded
worktree/ref ownership, then require the symbolic ref to equal `RESULT_REF` and `HEAD`
to equal `START_RESULT_TIP`:

```sh
git -C <WORKTREE_PATH> symbolic-ref --quiet HEAD
git -C <WORKTREE_PATH> rev-parse HEAD
```

In append mode, require `PATCH_BASE` to equal `START_RESULT_TIP` and run:

```sh
python3 <WORKTREE_PATH>/.agents/workflow/check.py snapshot \
  --repository <WORKTREE_PATH> \
  --base <PATCH_BASE> \
  --head <START_RESULT_TIP> \
  --allow-empty \
  --require-no-untracked
```

In rewrite mode, require `PATCH_BASE` to be a strict ancestor of `START_RESULT_TIP` and
run the same snapshot without `--allow-empty`:

```sh
python3 <WORKTREE_PATH>/.agents/workflow/check.py snapshot \
  --repository <WORKTREE_PATH> \
  --base <PATCH_BASE> \
  --head <START_RESULT_TIP> \
  --require-no-untracked
```

Only the append-mode initial snapshot may have an empty range.

Never switch, detach, restore, reset, or otherwise modify the stable checkout. Use the
result worktree for investigation, editing, commits, lint, and review. Invoke
`$scst-develop-patch` there with the unchanged `TASK_CONTRACT` and:

```text
TASK_RESULT_CONTEXT:
BASE_REF: <BASE_REF>
START_BASE_TIP: <START_BASE_TIP>
RESULT_REF: <RESULT_REF>
WORKTREE_PATH: <absolute path>
START_RESULT_TIP: <START_RESULT_TIP>
PATCH_BASE: <PATCH_BASE>
MODE: <append|rewrite>
```

## Validate and handle the result

Accept one `PATCH_HANDOFF` whose metadata matches the recorded context. Re-run:

```sh
python3 <WORKTREE_PATH>/.agents/workflow/check.py snapshot \
  --repository <WORKTREE_PATH> \
  --base <PATCH_BASE> \
  --head <PATCH_HEAD> \
  --require-no-untracked
```

Also require `RESULT_REF`, worktree `HEAD`, and `PATCH_HEAD` to be identical. A moved
result ref, malformed evidence, dirty worktree, or `PATCH_HANDOFF.STATUS: BLOCKED`
prohibits successful-result handling and routes to `references/blocked-cleanup.md`.

For `READY`, read `references/successful-result.md` completely. It loads
`references/optional-push.md` only for an explicitly authorized main-agent push. Movement
of `BASE_REF` never redirects or rebases the result.

The final workflow report includes the original base, exact result range and branch,
separate base-ref, push, and cleanup outcomes, lint evidence, review status and any
confirmed findings, every preserved or removed path, and the explicit limit that
compilation and runtime validation were not performed.
