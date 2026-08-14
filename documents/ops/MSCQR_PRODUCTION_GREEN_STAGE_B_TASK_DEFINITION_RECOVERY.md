# Production Green Stage-B task-definition recovery

This contract handles the one reviewed incident where Terraform state points
the backend candidate at revision `:5`, while unmanaged revisions `:6` and
`:7` exist in the same ECS family. Revision `:7` is not source-equivalent and
must never be adopted.

## Recovery sequence

After a reviewed merge, the operator must use
`scripts/aws/recover-stage-b-backend-task-definition.mjs --execute` with the
fresh protected source, current authorized image bindings, Terraform root,
explicit AWS profile, and the exact `:5`/`:7` predecessor evidence. Before
any AWS or Terraform mutation the command verifies the clean protected-main
checkout, exact HEAD/source SHA, source-bound image/release bindings, and a
private unoccupied evidence destination. The producer renders the backend task
definition through the existing Stage-B renderer, registers exactly one
revision, and verifies the returned ACTIVE ARN is newer than `:7` and has the
same semantic fingerprint as the protected source.

The recovery journal is stored beside the evidence output (or at the explicit
`--recovery-state` path). Its state machine is `DISCOVERY`, `PREPARED`,
`REGISTERING`, `REGISTERED`, `READBACK_VERIFIED`, `STATE_RECONCILING`,
`STATE_RECONCILED`, then `COMPLETED`. `registrationCalls` records completed
remote invocation attempts; `registrationMayHaveOccurred` records the
separate crash-safe ambiguity immediately before an outbound request. A failed
revision discovery therefore remains `DISCOVERY` with zero registration calls.

If a request response, describe, or newest readback is lost, a retry describes
only the newest ACTIVE revision. It may resume only when that revision has the
exact canonical fingerprint; a newer noncanonical revision fails closed and no
second registration is attempted. A legacy journal that recorded
`REGISTERING`/`registrationCalls=1` before discovery is immutable failed
evidence: the operator must preserve it and start a new incident only after a
fresh live/state revalidation. The journal also resumes an interruption after
`state rm` or `import` without repeating either completed operation.

Before any adapter runs, the command verifies the exact protected checkout,
source-bound bindings, exact Terraform root, initialized private Stage-B S3
backend metadata, and `TF_WORKSPACE=default`. Recovery discovery requires
`ecs:ListTaskDefinitions` only in `eu-west-2`; AWS requires `Resource: "*"`
for this read API, while the command itself accepts only the fixed backend
family. Registration, tagging, roles, state key, and lock key remain exact.

Only after that readback passes may the reviewed state adapter perform the
exact two-step Terraform state reconciliation for
`aws_ecs_task_definition.candidate["backend"]`: remove the bound `:5` entry,
then import the dynamically returned canonical ARN. The adapter checks the
lineage, serial increments, resource set, family, and replacement ARN after
each operation. It does not apply Terraform, update an ECS service, register a
second task definition, or deregister historical revisions.

The recovery evidence binds the source SHA, family, address, predecessor,
historical revisions, replacement ARN, image digest, semantic fingerprint,
state lineage/serial, registration event, and a deterministic SHA-256.

## Single writer

Terraform owns the retained Stage-B candidate and executor families. The
governed overlap producer is the only non-Terraform registration path for the
backend family, and it is separately guarded by rotation-readiness evidence.
The generic `deploy-ecs-service.sh` registration path rejects all Stage-B
managed families; its existing-task-definition mode remains available to the
governed overlap deployment and performs no registration.

The historical `:6` and `:7` revisions remain immutable evidence. They are not
deregistered by this recovery contract.
