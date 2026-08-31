# Optional main-agent push protocol

Load and follow this file only after the user explicitly authorizes the main agent to
push a validated committed result. Create this temporary state only while the push path
is active:

```text
PUSH_CONTEXT:
PUSH_REMOTE: <remote name>
PUSH_URL: <exact single push URL>
REMOTE_REF: <full remote result-branch ref>
REMOTE_TIP: <full commit|absent>
```

1. Resolve exactly one remote name and push URL, record them, and query the matching
   remote result ref through that URL.
2. Treat this exact `PUSH_URL` and `REMOTE_REF` pair as a first push unless an earlier
   successful push report from this same task records that pair and its pushed
   `PATCH_HEAD` equals the current `START_RESULT_TIP`. For a first push, require the
   remote ref to be absent. For such a proven repeat push, require its remote tip to
   equal `START_RESULT_TIP`. A matching tip on another endpoint or ref does not establish
   prior publication. Record the observed value as `REMOTE_TIP`.
3. Require local `RESULT_REF` and worktree `HEAD` to select `PATCH_HEAD`. In append mode,
   require an existing `REMOTE_TIP` to be an ancestor of `PATCH_HEAD`.
4. Immediately before pushing, query `REMOTE_REF` through `PUSH_URL` and require an exact
   match with `REMOTE_TIP`, including `absent`.
5. Push `PATCH_HEAD` to the exact remote result ref through `PUSH_URL`, never to an alias,
   implicit upstream, or base branch. Protect an existing ref with an exact lease for
   `REMOTE_TIP`, and an absent ref with an exact empty lease. Never use an unqualified
   force push.
6. Query the same URL after success and require `REMOTE_REF` to select `PATCH_HEAD`.

Any endpoint, ref, or lease mismatch is `BLOCKED`. A failed requested push retains the
local result branch and worktree for recovery and prohibits cleanup.
