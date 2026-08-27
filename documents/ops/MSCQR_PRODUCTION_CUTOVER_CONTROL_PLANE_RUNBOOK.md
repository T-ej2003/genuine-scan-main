# MSCQR production cutover control plane

The governed production path is the single `scripts/aws/run-production-cutover.mjs` entrypoint.
It invokes `runProductionCutoverControlPlane` and receives only reviewed, non-secret configuration.
Rehearsal uses the same orchestrator with deterministic adapters; it does not duplicate transition logic.

The ordering is image authorization, IAM census/convergence, identity establishment, Stage-A saved-plan
validation/apply/postcondition, artifact-signing validation, overlap task-definition materialization and
tag-on-create registration, bounded runtime inventory, rotation preparation, exact rotation Terraform
execution-role convergence, hash-bound readiness,
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

Run `npm run stage-b:bootstrap-artifact-signing -- --source-sha <full-protected-main-sha>` before
runtime preparation. This is the canonical idempotent producer of the runtime binding file; it
requires the exact fetched protected-main identity and the release-deployer profile, and reports
container creation separately from secret-value writes. It emits the source-bound binding at
`~/.mscqr/production-cutover/<full-protected-main-sha>/MSCQRProductionGreenStageBArtifactSigningBindings.runtime.json`
as a 0600 file under a 0700 private directory outside the Git checkout. Pass that emitted path to
`stage-b:prepare-cutover-runtime` as `--artifact-binding`; copying it into the repository is rejected.

The later rotation coordinator remains intentionally operator-supplied: its reviewed external
configuration binds the approved rotation ID, source SHA, grace window, and current/previous/pending
JWT/QR secret identifiers. Those are live rotation-state inputs, not derivable secret names, and no
secret values belong in that configuration.

Before MFA, use `npm run stage-b:prepare-cutover-runtime --` with the reviewed approval metadata.
This private preflight derives protected-main SHA, production region and role, overlap deployment
SHA, current runtime metadata, image/IAM/artifact evidence references, and phase-owned output paths.
It validates the complete adapter graph before live ECS discovery, including the separately hash-bound
release-preflight checker-trust report (`checkerTrust.exact=true` and `checkerTrust.mfaRequired=true`)
and the administrator/KMS report; checker trust is never treated as administrator evidence. It then atomically publishes the
identifier-only rotation config, redacted manifest, canonical onboarding paths, and rotation Terraform
input in a 0700 runtime directory; all four are 0600 outputs.
It never creates rotation state or the rotation fixture. Those remain outputs of the coordinator's
`--prepare` phase. The command emits one exact `stage-b:run-cutover-operator` command only after all
pre-MFA inputs are valid. The launcher obtains the verifier MFA device ARN and strict-onboarding inputs
from the controlling terminal with echo disabled, then invokes the governed entrypoint without
putting them in command arguments, files, or evidence. The pre-MFA bootstrap does not collect onboarding MFA. The onboarding
adapter reads `MSCQR_ONBOARDING_MFA_CODE` only after the live login response enters the MFA challenge
boundary; the code is never written to rotation config, manifests, command lines, or evidence.
The rotation config's logical `qr.previousKeyVersion` must equal the live task's
`QR_SIGN_ACTIVE_KEY_VERSION`; separate `QR_SIGN_*_KEY_VERSION` task bindings remain identifier-only
Secrets Manager references. Bootstrap and execution share the canonical image-authorization validator,
including evidence, signature, attestation, provenance, source-SHA, workflow, release, service-record,
and digest checks.
For the post-apply Stage-A recovery branch, pass the immutable historical Stage-B state used by the
recovery evidence with `--stage-b-state`, and pass the fresh current Stage-B state bound by the
current tfvars report with `--current-stage-b-state`. Runtime revalidation preserves the historical
state as provenance and separately requires the live Stage-B state to match the current state
semantically. The canonical IAM report's nested temporary-capability absence proof is authoritative;
an optional standalone proof is accepted only when it is exactly equivalent.
Runtime preparation records the raw-byte SHA-256 of every private eligibility artifact, including
the IAM report. Cutover consumers validate the private external path and exact recorded hash before
parsing those same captured bytes; replacing a nested self-consistent proof therefore remains invalid.
Release-preflight checker-trust evidence has two authorities: the release-deployer writes the
read-only report, then the exact independent-checker session produces a detached
`PRODUCTION_RELEASE_PREFLIGHT_CHECKER_TRUST_ATTESTATION` with
`npm run stage-b:attest-release-preflight-checker-trust --`. The private 0600 attestation and KMS
signature bind the report bytes, protected source SHA, administrator-report SHA, and exact Role-A
MFA trust. Runtime preparation verifies this detached signature before emitting runtime config;
unsigned, copied, or self-hashed release reports are rejected. The release-deployer remains
verify-only and must never sign this attestation.
The coordinator's rotation fixture is similarly hashed from its persisted private bytes after prepare;
ECS Exec and onboarding consume that exact hash-bound fixture and reject replacement before any probe.
The source-bound authorization is produced only by `scripts/aws/production-image-authorization.mjs`.
Before producing it, the shared protected-main identity helper performs a successful `git fetch origin main`
and resolves the fetched commit from `FETCH_HEAD`; it never treats a stale `refs/remotes/origin/main` as
fresh production identity. HEAD, the requested source SHA, and that fetched SHA must be identical, or no
authorization is written. The same helper is used by the pre-MFA bootstrap and release gate. It independently
derives the image-impact transition from the two commits and checked-out git tree,
compares the supplied reuse report to that result, composes it with the signed four-image evidence
and current protected-main SHA, then writes one hash-bound private authorization file. Operators
must not copy, relabel, or edit an older authorization artifact.

After `rotationPrepare`, the control plane writes a private overlay containing
`production_rotation_enabled=true` and the exact eleven ECS secret references, then runs the existing
Stage-B Terraform root with the canonical Stage-B tfvars as the base and a targeted plan for
`aws_iam_role_policy.execution["backend"]`. The plan is structurally restricted to that reviewed
execution-role policy and is applied exactly once. The resulting role policy is read back and must
contain the eleven base Secrets Manager ARNs derived from those ECS references, with no unrelated
production rotation access. This phase is distinct from Stage A; overlap task registration and
`UpdateService` are rejected unless its convergence evidence is present.

Cutover input ownership is explicit:

| Class | Inputs |
| --- | --- |
| Repository-derived | region, release role, protected-main SHA, overlap deployment SHA, policy constants, phase paths, inventory role/log target |
| AWS read-only | current task definition ARN, HTTPS production base URL, current QR key-version metadata |
| Existing runtime artifacts | image authorization, IAM evidence, Stage-A plan or historical recovery evidence, root evidence, current Stage-B state, canonical artifact binding file |
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
