# Production dual-slot rotation coordinator

`backend/scripts/security/rotate-production-signing-material.mjs` is the only
supported production rotation coordinator. It never prints secret material and
requires an explicit mode:

```text
--prepare   stage pending material, promote current/previous slots
--verify    accept only a redacted proof from the deployed overlap runtime
--cleanup   retire all old/pending slots, then verify the cleanup deployment
--status    report only version IDs, slots, and fingerprints
```

The operator supplies a private JSON configuration outside the repository. It
contains only secret identifiers and evidence metadata:

```json
{
  "region": "eu-west-2",
  "expectedRoleArn": "arn:aws:iam::<account>:role/<approved-rotation-role>",
  "rotationId": "2026-08-10-release-rotation",
  "sourceSha": "<full-source-sha>",
  "ticket": "<approved-ticket>",
  "approvedBy": "<security-approver>",
  "approverRole": "Security Lead",
  "reason": "Scheduled production security rotation",
  "minimumGraceSeconds": 2592000,
  "overlapDeploymentSha": "<full-overlap-deploy-sha>",
  "verificationRef": "<workflow-or-run-url>",
  "jwt": {
    "currentSecretId": "<stable-jwt-current-secret-id>",
    "previousSecretId": "<stable-jwt-previous-secret-id>",
    "pendingSecretId": "<stable-jwt-pending-secret-id>"
  },
  "qr": {
    "previousKeyVersion": "<currently deployed legacy QR kid>",
    "privateCurrentSecretId": "<stable-qr-private-current-secret-id>",
    "privatePendingSecretId": "<stable-qr-private-pending-secret-id>",
    "publicCurrentSecretId": "<stable-qr-public-current-secret-id>",
    "publicPreviousSecretId": "<stable-qr-public-previous-secret-id>",
    "publicPendingSecretId": "<stable-qr-public-pending-secret-id>"
  }
}
```

Secret values are stored as JSON in Secrets Manager with a `value` field and
non-secret rotation metadata. ECS must inject only the JSON `value` field. The
pending resources make interrupted preparation resumable without storing a
secret in local state; an unexpected pending rotation ID fails closed.

JWT signing uses `JWT_SECRET_CURRENT`; verification accepts only
`JWT_SECRET_CURRENT` and `JWT_SECRET_PREVIOUS`. Ed25519 QR signing uses the
current private/public pair; verification accepts the current public key or one
explicit previous public key selected by `kid`. There is no arbitrary keyring
and no HMAC downgrade in the rotation path.

The coordinator does not deploy ECS. The existing approved deployment workflow
must perform the overlap deployment and run the deployment-side verifier inside
that task. The verifier uses the compiled application `verifyJwtWithCurrentOrPrevious`
and `verifyQrToken` functions; it is not a public endpoint and does not print
tokens. The deployed image runs from `/app`, where the verifier is invoked with
`npm run security:verify-production-rotation-runtime`. It must also probe the deployed `/api/health` with `--health-url` and
bind `release.gitSha` to `--expected-release-sha`; timeout, non-ready, malformed,
non-200, or mismatched-release responses fail closed. Pass its mode-600 JSON
output to `--verify --runtime-verification-file`.

The persisted state machine is monotonic:

```text
prepared -> overlap-deploy-required -> overlap-ready -> verified -> grace-wait
  -> retirement-started -> retirement-complete -> cleanup-deploy-required
  -> cleanup-runtime-verified -> cleaned
```

`minimumGraceSeconds` is an explicit reviewed operator value. The coordinator
persists `overlapReadyAt`, `verifiedAt`, `cleanupEligibleAt`, and
`retirementTimestamp`; cleanup fails closed before the deadline and has no
force/skip-grace bypass.

Cleanup is two-step and retry-safe: retire `JWT_SECRET_PREVIOUS`,
`QR_SIGN_PUBLIC_KEY_PREVIOUS`, `JWT pending`, `QR private pending`, and
`QR public pending` with one persisted timestamp; then deploy/restart the
service and pass the post-deployment runtime proof. The Stage B cleanup task
definition sets `production_rotation_cleanup_enabled=true`, which removes the
retired JWT and QR previous bindings entirely while retaining every current
binding. Only that proof can produce cleanup evidence.

If the process stops after persisting `cleanup-runtime-verified`, the next
`--cleanup` revalidates the complete persisted overlap and cleanup runtime
proofs, including their exact deployment SHAs and source identity, then
re-reads the secret slots, re-proves retirement, and persists `cleaned` without
retiring or deploying again. Final evidence links only those revalidated
deployment identities, so configuration drift fails closed and repeated
cleanup is idempotent.

State, fixture, verification, and evidence paths must be outside the repository
or explicitly reviewed non-secret evidence locations. They contain identifiers,
version IDs, fingerprints, timestamps, and checks only—not secret values. The
mode-600 fixture contains synthetic signed test credentials, never raw secret
material, and must remain operator-local.

## Pre-overlap authorization boundary

The production ECS Exec verifier is a separate MFA-backed role. Its approved
task identity is the `MSCQRExecTarget=production-backend` task tag, propagated
from the reviewed backend task-definition tags by the governed overlap service
switch. The verifier selects and revalidates the same task ARN, task definition,
cluster, service, healthy/running state, backend container, immutable image
digest, tag, and connected ExecuteCommandAgent before opening ECS Exec. A task
without that marker, or a worker/RLS task, is not an approved target.

The source-only readiness checkpoint is complete only when image authorization,
IAM evidence, identity handoff, Stage-A contract, artifact-signing contract,
overlap task contract, bounded inventory, and `--prepare` state persistence all
pass. It must be evaluated before `UpdateService`; it is distinct from
`READY_FOR_ONBOARDING` and `ROTATION_CLOSED`.

The release gate carries this checkpoint as a mode-600 redacted readiness
evidence file plus its SHA-256 (`rotation_readiness_evidence_json` and
`rotation_readiness_evidence_sha256`). Each required stage records an exact
boolean `valid=true`, a non-secret evidence reference, and that evidence's
SHA-256, bound to the protected source SHA, rotation ID, and persisted rotation
state SHA-256. The gate validates it immediately before the transition step,
and `deploy-ecs-service.sh` validates the same bytes again before any
`UpdateService` call. Missing, stale, malformed, or mismatched evidence fails
closed; the rollback helper remains a separate ownership-aware path.
