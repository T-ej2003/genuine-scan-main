# Production Green Stage-B task-definition recovery

This contract handles the one reviewed incident where Terraform state points
the backend candidate at revision `:5`, while unmanaged revisions `:6` and
`:7` exist in the same ECS family. Revision `:7` is not source-equivalent and
must never be adopted.

## Recovery sequence

After a reviewed merge, the operator must use
`scripts/aws/recover-stage-b-backend-task-definition.mjs --execute` with the
fresh protected source, current authorized image bindings, Terraform root,
explicit AWS profile, and the exact `:5`/`:7` predecessor evidence. The
producer renders the backend task
definition through the existing Stage-B renderer, registers exactly one
revision, and verifies the returned ACTIVE ARN is newer than `:7` and has the
same semantic fingerprint as the protected source.

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
