# MSCQR production cutover control plane

The governed production path is the single `scripts/aws/run-production-cutover.mjs` entrypoint.
It invokes `runProductionCutoverControlPlane` and receives only reviewed, non-secret configuration.
Rehearsal uses the same orchestrator with deterministic adapters; it does not duplicate transition logic.

The ordering is image authorization, IAM census/convergence, identity establishment, Stage-A saved-plan
validation/apply/postcondition, artifact-signing validation, overlap task-definition materialization and
tag-on-create registration, bounded runtime inventory, rotation preparation, hash-bound readiness,
governed overlap deployment, service/task verification, exact-ARN ECS Exec verification, and strict
onboarding evidence.

Every mutating boundary is adapter-owned and must receive predecessor evidence. The rehearsal records
mutation intent only. Production temporary verifier credentials remain process-scoped; they are never
written with `aws configure`, persisted in evidence, or printed.

The overlap deployment entrypoint validates the same readiness file immediately before the single
`UpdateService` call and requires `propagateTags=TASK_DEFINITION`. The legacy shell wrapper refuses
rotation-overlap invocation unless it is marked as invoked by the governed orchestrator. Actual task
tags are requested with `DescribeTasks --include TAGS` immediately before ECS Exec; the exact selected
task ARN is reused without reselection.

The bounded inventory command is repository-owned and runs inside the approved backend runtime. The
operator supplies no `DATABASE_URL`; only aggregate counts, explicit not-applicable classifications,
and hash-bound evidence leave the runtime boundary.

`READY_FOR_ONBOARDING` is produced only after strict mandatory probes and independent evidence
validation. Missing, unavailable, skipped, malformed, stale, or sensitive evidence fails closed.
