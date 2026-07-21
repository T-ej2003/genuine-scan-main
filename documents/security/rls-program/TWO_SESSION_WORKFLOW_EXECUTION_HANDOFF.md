# Historical two-session RLS handoff

Date superseded: 2026-07-20 (Europe/London)

This handoff was replaced after risk-analytics checkpoint `33cbe7f` by [THREE_SESSION_WORKFLOW_EXECUTION_HANDOFF.md](./THREE_SESSION_WORKFLOW_EXECUTION_HANDOFF.md).

The accepted Session B workflow set remains unchanged and is sealed by SHA-256 `116815209a0a591ff122a0a7bac9a5958cfa4182742c8483d039261c7ba4e79a`. The former two-session partition JSON was removed so there is only one machine-authoritative assignment file.

Do not use this historical file for current ownership, worktree creation or validation. Use `workflow-three-session-partition.json` and the three `workflow-ownership-session-*.json` files.
