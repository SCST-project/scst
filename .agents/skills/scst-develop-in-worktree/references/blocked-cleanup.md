# Blocked result cleanup

Read this file only after the workflow is blocked. First wait for every command, agent
role, and Git operation associated with the result worktree to stop.

Preserve the worktree and result ref when any of these are true:

- tracked or untracked changes exist;
- `HEAD` differs from the recorded start result commit;
- a Git operation is active;
- the worktree or ref does not match the recorded identity; or
- ownership or recovery state is uncertain.

Report the preserved path, result ref, head, status, and exact reason. Do not repair,
reset, clean, or partially copy it. Always preserve the result ref; it is the user-visible
identity of the implementation task.

An untouched worktree may be removed only when it is registered, fully clean, has no
active Git operation, and both `HEAD` and its result ref still equal the recorded start
result commit:

1. From the recorded stable repository, verify that the stable checkout remains a
   registered worktree and is not the result worktree.
2. Run `git worktree remove -- <WORKTREE_PATH>` for the recorded result worktree.
3. Verify the result ref still selects the recorded start result commit. Do not delete or
   move it.
4. Remove the exact temporary parent only when it is empty. Never use recursive deletion
   or `git worktree prune`.

Cleanup never changes the blocked result or authorizes integration.
