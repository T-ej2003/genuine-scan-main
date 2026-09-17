# Governed rotation terminal retry

Both `rotation-overlap` and `rotation-cleanup` use the existing release-gate
approval and cutover entrypoint. This does not authorize a standalone ECS change.
The original predecessor-only shell deployment remains unchanged.

On each attempt the entrypoint authenticates fresh, current-run production
approval, readiness bytes/source/rotation/state hash, the exact target revision,
and component state. A pending predecessor is checked against its immutable ECS
definition and ECR source. A completed terminal is identified by its exact
backend identity, security release identity, and completed-emergency receipt.
The terminal identity also binds the original predecessor ARN.

If the target is already live, readback must prove the correct account, cluster,
service, task revision, image digest, desired/running count, healthy tasks,
completed deployment, runtime roles/platform, ECS Exec and tag propagation.
The same version-endpoint check used by the shell must pass. The result records
`ALREADY_APPLIED` and `updateServiceCount=0`; an actual switch records `APPLIED`
and `updateServiceCount=1`. The existing overlap receipt preserves that count.
Rotation receipts and backend-recovery evidence use attempt-specific artifact
names, so a rerun cannot collide with or overwrite a prior attempt's evidence.
The rotation receipt resolver authenticates the exact attempt's name, job steps,
timestamp window, digest and run identity. Historical pre-runtime-closure recovery
evidence retains its original, history-bound resolver contract.

Backend and security still commit in one generation-CAS update. An uncertain
write is resolved by rereading: exact committed state is an idempotent success;
the original predecessor can be advanced; any third identity is rejected.
No readiness schema, component-state schema, IAM permission, or additional state
store is introduced.

## Execution and failure review

Here A is the authenticated predecessor and B is the authorized target. State
includes backend **and** security; neither is independently advanced.

| Scenario | Live / durable before | Action | Live / durable after | Result |
| --- | --- | --- | --- | --- |
| First execution | A / A | Existing predecessor CAS, switch, verify, terminal CAS | B / B | Success |
| Failure before switch | A / A | No switch | A / A | Retry original path |
| Failure during switch | A or B / A | Existing shell settlement/rollback | Authenticated readback / A | Never guess; reread on retry |
| Switch succeeds, terminal fails | B / A | Verify B, skip switch, terminal CAS | B / B | Reconciled |
| Write succeeds, response lost | B / B | Verify B and exact terminal identity | B / B | Success, no second write |
| Completed workflow rerun | B / B | Fresh approval/readiness and live verification | B / B | Idempotent success |
| B live without matching rotation evidence | B / A | Reject evidence before deployment | B / A | Fail closed |
| Unknown live X | X / A | Reject readback | X / A | Fail closed |
| Stale approval | A or B / A or B | Reject current-run approval/freshness | Unchanged | Fresh governed approval required |
| Next normal release C | B / B | B recognized as exact predecessor | Normal transaction | No unknown-third-identity deadlock |

## Bounded audit and tests

Initial findings were the predecessor-only rerun gate, one-update-only result
consumers, and a terminal that did not distinguish a pending predecessor from
unrelated durable state. Reconciliation must also retain the shell's version,
runtime, Exec and tag checks; comparing only the task ARN is insufficient.

The component terminal regression executes both modes, first-switch/retry
selection, definite and ambiguous DynamoDB failures, atomic backend/security
commit, idempotent completion, and next-normal predecessor recognition. Negative
cases include identity/hash/account-bound readback, count/convergence, unknown
state, wrong predecessor, and malformed mutation accounting. Existing shell,
approval, receipt and control-plane tests cover their unchanged boundaries.

Backend-health recovery already has authenticated interrupted-recovery and
completed-recovery reconciliation. Normal application deployment already accepts
only its exact authenticated candidate and preserves its transactional CAS.
Neither path is relaxed by this repair.

Operational recommendation: alert on repeated component-terminal failures and
retain the workflow result/receipt. Do not repair them with manual ECS updates
or direct DynamoDB writes.
