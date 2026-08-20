# Production backend health recovery

This mode exists only to restore `mscqr-backend-servi-euw2` when its exact
currently deployed immutable `mscqr-backend` digest has disappeared from ECR
and the resulting image-pull failure prevents the mandatory production
dual-slot rotation.

## Security boundary

The `backend-health-recovery` release-gate mode requires:

- a full protected-main source SHA;
- the exact current `mscqr-backend:<revision>` ARN;
- canonical signed image authorization for the replacement digest;
- ECR readback proving the current digest is absent and the replacement exists
  in the immutable `mscqr-backend` repository;
- stopped-task or service-event evidence identifying a missing-digest
  `CannotPullContainerError`;
- human approval bound to the source SHA, current task-definition ARN, and
  replacement digest; and
- the protected GitHub `production` environment approval.

The candidate task definition is derived from the current AWS readback. Only
the backend image and `GIT_SHA`/`RELEASE_GIT_SHA` values may change; both
identity fields must equal the image authorization's authenticated release SHA. Roles,
secrets, database bindings, networking, ports, command, health check, logging,
resources, and every other runtime field must remain byte-semantically equal.

The mode registers at most one matching legacy revision, updates only the
backend service, reconciles ambiguous registration/update outcomes from live
ECS, waits for stability, verifies running digests, verifies backend health,
and publishes recovery evidence. It never deploys frontend/worker workloads,
applies Stage B, or satisfies/bypasses rotation freshness.

## Operator sequence

1. Produce exact JSON bytes for canonical image authorization and human
   approval. Record each file's SHA-256. The approval object must contain
   `ticket`, `approvedBy`, `approverRole`, `reason`, `verificationRef`,
   `sourceSha`, `currentTaskDefinitionArn`, and `recoveryImageDigest`.
2. Dispatch `.github/workflows/release-gate.yml` on protected main with
   `release_mode=backend-health-recovery` and the six recovery inputs.
3. Have a different authorized reviewer approve the GitHub `production`
   environment deployment.
4. Retain the uploaded `backend-health-recovery-evidence` artifact.
5. After backend health is proven, resume the canonical dual-slot rotation.
   This recovery does not create or refresh rotation evidence.

Do not use this mode when the current digest still exists, for frontend or
green candidate families, or to migrate roles/secrets/runtime topology.
