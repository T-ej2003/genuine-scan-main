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

When resuming after the preserved Stage-A ingress mutation, the canonical refreshed Stage-A plan may
be the exact indexed `no-op` for `aws_vpc_security_group_ingress_rule.runtime_endpoints_https["<runtime-security-group-id>"]`.
That state is validated with the same endpoint/runtime/protocol/port/source assertions, the ingress
postcondition is re-read, and no Terraform apply is issued. Only an exact `create` plan may apply the
validated saved plan.

The bounded inventory command is repository-owned and runs inside the approved backend runtime. The
operator supplies no `DATABASE_URL`; only aggregate counts, explicit not-applicable classifications,
and hash-bound evidence leave the runtime boundary.

Artifact signing bootstraps four identifier-only containers from the reviewed
`MSCQRProductionGreenStageBArtifactSigningBootstrap-v1.json` names. It performs targeted exact-name
`DescribeSecret` calls, creates only missing containers, captures AWS-returned ARNs, and writes the
runtime binding file atomically. It never uses `ListSecrets`, predicts ARN suffixes, or writes secret
values to bindings or evidence. A container without an `AWSCURRENT` version is represented as
uninitialized from `DescribeSecret` metadata; only the existing Ed25519 producer then writes its
initial value. Bootstrap-returned bindings are the authoritative artifact references used to build
and validate the overlap task input, replacing stale preloaded artifact references without changing
unrelated task inputs.

The later rotation coordinator remains intentionally operator-supplied: its reviewed external
configuration binds the approved rotation ID, source SHA, grace window, and current/previous/pending
JWT/QR secret identifiers. Those are live rotation-state inputs, not derivable secret names, and no
secret values belong in that configuration.

Before MFA, use `npm run stage-b:prepare-cutover-runtime --` with the reviewed approval metadata.
This private preflight derives protected-main SHA, production region and role, overlap deployment
SHA, current runtime metadata, image/IAM/artifact evidence references, and phase-owned output paths.
It validates the complete adapter graph and writes only an identifier-only rotation config and a
redacted manifest in a 0700 runtime directory; config and manifest files are atomic 0600 outputs.
It never creates rotation state or the rotation fixture. Those remain outputs of the coordinator's
`--prepare` phase. The command emits one exact `run-production-cutover.mjs` command only after all
pre-MFA inputs are valid. The pre-MFA bootstrap does not collect onboarding MFA. The onboarding
adapter reads `MSCQR_ONBOARDING_MFA_CODE` only after the live login response enters the MFA challenge
boundary; the code is never written to rotation config, manifests, command lines, or evidence.
The rotation config's logical `qr.previousKeyVersion` must equal the live task's
`QR_SIGN_ACTIVE_KEY_VERSION`; separate `QR_SIGN_*_KEY_VERSION` task bindings remain identifier-only
Secrets Manager references. Bootstrap and execution share the canonical image-authorization validator,
including evidence, signature, attestation, provenance, source-SHA, workflow, release, service-record,
and digest checks.
The source-bound authorization is produced only by `scripts/aws/production-image-authorization.mjs`.
It independently derives the image-impact transition from the two commits and checked-out git tree,
compares the supplied reuse report to that result, composes it with the signed four-image evidence
and current protected-main SHA, then writes one hash-bound private authorization file. Operators
must not copy, relabel, or edit an older authorization artifact.

Cutover input ownership is explicit:

| Class | Inputs |
| --- | --- |
| Repository-derived | region, release role, protected-main SHA, overlap deployment SHA, policy constants, phase paths, inventory role/log target |
| AWS read-only | current task definition ARN, HTTPS production base URL, current QR key-version metadata |
| Existing runtime artifacts | image authorization, IAM evidence, Stage-A plan/root evidence, artifact binding file |
| Human approval | ticket, approver identity/role, reason, verification reference, grace-window policy value |
| Identifier-only external binding | dual-slot JWT/QR secret references, including current/previous key-version references not present in the legacy task |
| Prepare-generated | rotation state and rotation fixture |
| Later-phase generated | readiness, post-deploy, ECS Exec, onboarding, and rotation-close evidence |
| Prohibited | secret values, signing material, DATABASE_URL, MFA codes, and temporary AWS credentials |

The dual-slot identifier manifest is required because the legacy production task exposes only
single-slot JWT/QR bindings and the repository has no canonical name/provisioner for the missing
dual-slot references. The bootstrap validates its exact eu-west-2/account scope and never treats
that manifest as a source of secret values.

Production AWS adapter service commands are invoked through the `aws` executable with the reviewed
profile and `eu-west-2` region; Terraform and runtime commands remain distinct executables. Rotation
deployment receives the SHA returned by the successful preparation step, not a stale command-line
value. The onboarding HTTP client retains every authentication cookie and sends the server-issued
`aq_csrf` value as `x-csrf-token` on mutating requests.

`READY_FOR_ONBOARDING` is produced only after strict mandatory probes and independent evidence
validation. Missing, unavailable, skipped, malformed, stale, or sensitive evidence fails closed.
