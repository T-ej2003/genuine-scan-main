# Production Green Stage-B task-definition recovery

This contract handles the one reviewed incident where Terraform state points
the backend candidate at revision `:5`, while unmanaged historical revisions
`:6`, `:7`, and `:8` exist in the same ECS family. Revision `:8` is the newest
historical evidence, is not source-equivalent to the current protected source,
and must never be adopted or deregistered.

## Recovery sequence

After a reviewed merge, the operator must use
`scripts/aws/recover-stage-b-backend-task-definition.mjs --execute` with the
fresh protected source, current authorized image bindings, the canonical
`--image-authorization` artifact, Terraform root,
explicit AWS profile, and the exact `:5`/`:8` predecessor evidence. Before
any AWS or Terraform mutation the command verifies the clean protected-main
checkout, exact HEAD/tooling SHA, source-bound image-release identity, the
authorized immutable backend digest, and a private unoccupied evidence destination.
The producer performs a complete ACTIVE-family census, renders the backend task
definition through the existing Stage-B renderer, and creates a deterministic
schema-v4 incident identity from the protected source, source-content,
image-authorization, state predecessor, historical newest ARN, and expected
semantic fingerprint. Only the explicit historical-to-new-lineage transition
may register exactly one revision. The returned AWS ARN is used directly; no
revision number is assumed.

Recovery has two provenance domains. The protected checkout and recovery journal
bind `toolingSha` and `toolingTreeSha256`; the source contract also binds
`sourceContractSha256`. The image authorization and rendered task definition
bind `imageReleaseSha`. The renderer writes only `imageReleaseSha` into
`RELEASE_GIT_SHA`. The recovery journal and evidence record both identities and
the exact authorized image digest and image-authorization hash. A legacy revision carrying a tooling SHA in
`RELEASE_GIT_SHA` is a fingerprint mismatch, not a reusable source-equivalent
revision; it remains historical evidence while the new source/image lineage may
start its own reviewed incident.

Fingerprinting accepts only four reviewed ECS readback projections: omitted
container `cpu` versus `0`, omitted `volumesFrom` or `systemControls` versus
empty arrays, and an absent volume `host` versus an empty object. Non-zero
CPU, non-empty collections, meaningful host fields, and every other
task-definition or tag difference remain fail-closed.

The recovery journal is stored beside the evidence output (or at the explicit
`--recovery-state` path). Its state machine is `DISCOVERY`, `PREPARED`,
`REGISTERING`, `REGISTERED`, `READBACK_VERIFIED`,
`STATE_RECONCILING_PRE_REMOVE`, `STATE_RECONCILING_POST_REMOVE`,
`STATE_RECONCILED`, then `COMPLETED`. `registrationCalls` records remote
invocation attempts known to have been sent; `registrationMayHaveOccurred`
records the separate crash-safe ambiguity immediately before an outbound
request. A failed revision census produces no incomplete journal. Once
registration is attempted, the journal is durable before the request and the
returned ARN is persisted immediately.

If a request response, describe, or newest readback is lost, a retry performs a
complete ACTIVE-family census. It may resume only when the current-source
revision and every incident provenance field match; an existing match uses zero
registrations. Fresh registration is allowed only when no match exists and the
newest live revision is explicitly historical. Any unexpected newer revision,
duplicate match, ambiguous prior call, or semantic mismatch fails closed and no
second registration is attempted. Schema-1 and schema-3 journals are immutable
failed evidence and cannot authorize the schema-v4 incident. The journal also resumes an interruption after
`state rm` or `import` without repeating either completed operation.

An already-registered schema-v4 incident may be resumed by a newer protected-main descendant only in its
registered/reconciliation phases. This exception keeps the journal source SHA, incident identity, original
image authorization, image release, replacement ARN, and consumed one-registration budget immutable. The
current clean `origin/main` checkout must prove that it is a strict descendant, derive its own executor
tooling identity, and independently recompute image reuse from the original image release. Reuse is accepted
only for the reviewed non-runtime recovery/tooling, test, documentation, and workflow categories; runtime,
image-affecting, unknown, unrelated, dirty, or non-origin changes fail closed. Exact-source resumes retain
the ordinary source-bound path.

The CLI reads an existing journal only to select this validation path; it never treats journal fields as
authority before the cross-descendant identity, provenance, census, image-reuse, and checkpoint checks pass.
`COMPLETED` is terminal for descendant execution: it is validated as immutable evidence and then rejected
without journal or evidence rewrites, registration, or Terraform mutation.

For a schema-v4 journal created before checkpoint normalization, resume must
also provide `--state-before` pointing to the preserved pre-removal state
backup. Exact legacy raw hashes remain accepted. If Terraform 1.15.7/1.15.8
metadata prevents those raw hashes from being reproduced, the versioned legacy
compatibility validator requires the snapshot's exact lineage, serial, and
`:5` candidate, then proves that the post-removal state differs only by removal
of that candidate plus the allowlisted `terraform_version` and `check_results`
representation changes. Unknown or semantic differences fail closed; the
journal and evidence are never rewritten.

`STATE_RECONCILING_PRE_REMOVE` is an intent checkpoint, not proof that
`state rm` succeeded. On retry, authoritative Terraform readback must be the
exact original predecessor, exact post-removal state, or exact imported state;
only then may the command remove, import, or finalize respectively. Any other
lineage, serial, resource set, or backend ARN fails closed.

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

The historical `:6`, `:7`, and `:8` revisions remain immutable evidence. They
are not adopted or deregistered by this recovery contract.
