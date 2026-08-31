# Successful result handling

Read this file only for a validated `PATCH_HANDOFF` with `STATUS: READY`.

## Preserve the result branch

Require the recorded result ref, its registered result worktree, and worktree `HEAD` to
select `PATCH_HEAD`. Immediately before result handling, run:

```sh
python3 <WORKTREE_PATH>/.agents/workflow/check.py snapshot \
  --repository <WORKTREE_PATH> \
  --base <PATCH_BASE> \
  --head <PATCH_HEAD> \
  --require-no-untracked
```

Require a clean worktree with no active Git operation. Record the base ref's current
value or absence for reporting. Never merge, rebase, fast-forward, compare-and-swap, or
otherwise update the base ref.

Load `optional-push.md` only when the user explicitly authorized the main agent to push.
When push was requested, require that protocol to return `PASS` before cleanup.

## Remove only the result worktree

1. Reverify the recorded result worktree is clean and that its `HEAD` and result ref
   equal `PATCH_HEAD`.
2. From the recorded stable repository, run:

   ```sh
   git worktree remove -- <WORKTREE_PATH>
   ```

   Then verify the path is no longer registered.
3. Verify the result ref still selects `PATCH_HEAD`; do not delete or rename it.
4. Remove the exact temporary parent only when it is empty. Do not use recursive deletion
   or `git worktree prune`.

A cleanup failure does not invalidate the committed result branch. Report every
remaining path precisely and retain the result ref.
