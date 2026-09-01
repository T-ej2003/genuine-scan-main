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

The operator supplies a private JSON configuration outside the repository and
passes its exact SHA-256 through `--config-sha256`; the coordinator authenticates
those bytes before parsing or making AWS calls. It
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

During the first authenticated dual-slot migration only, the bootstrap's exact
empty previous-slot markers permit the coordinator to record
`LEGACY_QR_KEYPAIR_UNRECOVERABLE` when the pre-existing QR private/public pair
cannot be parsed as a matching Ed25519 pair. The malformed values are
fingerprint-bound as observed legacy input but are never copied into the
previous slots, treated as trusted keys, or used to fabricate historical
continuity. The pending pair must still parse and match as Ed25519. Runtime and
onboarding then verify a hash-bound current-key fixture and explicitly attest
that no previous QR slot is deployed. QR rollback and verification of QR codes
signed by the malformed legacy pair are unavailable; JWT overlap, the grace
window, cleanup, and every new-material check remain unchanged. Any malformed
legacy QR material outside those authenticated initial-migration markers fails
closed.

If protected main advances solely to make that initial migration consumable,
runtime preparation must also receive the canonical
`--rotation-supersession-evidence` file. It emits an
`initialMigrationSourceAdvance` binding only after matching the three
legacy-current JWT/QR identifiers to the live ECS task definition and proving
the original source is an ancestor of protected main. The coordinator then
independently rechecks the seven superseded slots against their live
deterministic Secrets Manager versions before any write. It preserves the
original marker source SHA separately from the current execution SHA; it never
rewrites historical marker bytes. Missing or modified evidence, another
rotation/material set, an unrelated source, or any non-initial rotation fails
closed.

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

`overlap-ready` and `verified` are authenticated successors of the original
`overlap-deploy-required` state. Both retain `verification.preparedStateSha256`;
readiness and the independently approved deployment receipt remain bound to
that predecessor, never to a successor file hash. A verifier retry therefore
cannot redeploy and may resume only the unfinished coordinator verification.
Only `verified` can feed strict onboarding; `overlap-ready` is an interruption
recovery state and cannot claim onboarding readiness.
  -> retirement-started -> retirement-complete -> cleanup-deploy-required
  -> cleanup-runtime-verified -> cleaned
```

For every new rotation, `minimumGraceSeconds` is an explicit reviewed operator
value of at least 2,592,000 seconds. Longer reviewed values are supported. The coordinator
persists the exact reviewed value with `overlapReadyAt`, `verifiedAt`,
`cleanupEligibleAt`, and `retirementTimestamp`; `cleanupEligibleAt` is always
`overlapReadyAt + minimumGraceSeconds`. A resumed run must match the persisted
grace and anchor. Cleanup fails closed before the deadline and has no
force/skip-grace bypass.

Persisted coordinator state uses schema version 4. Authentic version-3 state
from the prior coordinator is upgraded once at the state-reader boundary:
pre-overlap phases take the exact hash-bound reviewed config value, while
`overlap-ready` and later phases derive the historical grace only from the
unchanged canonical `overlapReadyAt` and `cleanupEligibleAt` timestamps. The
upgrade never changes either timestamp or restarts the cleanup window.
Any state hash used by a later workflow is captured from the post-upgrade bytes;
the original version-3 bytes are validated before the atomic replacement and
are never relabeled as current-schema evidence.

Version-3 compatibility preserves the historical policy rather than applying
the new minimum retroactively. Pre-overlap v3 state is accepted by the overlap
transition without migration because no grace anchor exists; the coordinator
can migrate it only with that transaction's exact reviewed config. Timed v3
state derives a positive whole-second grace solely from its authenticated
`overlapReadyAt` and `cleanupEligibleAt`. Migrated v4 state carries
`graceContract: LEGACY_V3_PRESERVED`; unmarked v4 state is current-policy state
and must retain the 30-day minimum. Both forms retain the same Date-range cap.

The deployment-side verifier accepts either the exact production cluster name
or its full ARN as operator input, uses the full ARN for ECS reads, and persists
only `arn:aws:ecs:eu-west-2:368992683803:cluster/mscqr-prod-euw2-main` in the
runtime proof. The initial-overlap validator consumes that canonical ARN; wrong
accounts, regions, names, aliases, and partial ARNs fail closed.

## Initial-overlap producer/consumer contract

| Persisted field group | Authoritative producer | Persisted representation | Consumers |
| --- | --- | --- | --- |
| `sourceSha`, `rotationId`, `overlapDeploymentSha`, signing-material fingerprints and key versions | approved runtime config plus coordinator preparation | full SHA strings, reviewed rotation ID, redacted fingerprints/versions | coordinator resume, initial-overlap validator |
| Runtime checks, release health, `observedAt`, `healthObservedAt`, invocation reference | image-local runtime verifier | booleans, full source SHA, canonical UTC ISO timestamps, machine reference | ECS verifier, coordinator, initial-overlap validator, onboarding |
| Service, cluster, task definition, image, task and deployment identity | deployment-side ECS verifier after final task re-read | exact service name, canonical cluster ARN, full ARNs/digest, `ecs-svc/<id>` | coordinator persistence, initial-overlap validator, Release Gate |
| `minimumGraceSeconds`, `overlapReadyAt`, `verifiedAt`, `cleanupEligibleAt` | reviewed config plus coordinator | safe integer seconds and canonical UTC ISO timestamps | initial-overlap validator, cleanup executor, Stage-B closure |
| State bytes and state SHA-256 | coordinator atomic mode-600 state file plus release input binding | exact serialized bytes and SHA-256 | Release Gate and Stage-B closure |

Release Gate validates the dispatch inputs in `resolve-deploy-target`, then reconstructs the exact redacted coordinator-state bytes from those same immutable workflow inputs on the fresh `deploy-production-ecs` runner. The state hash and complete overlap contract are revalidated there before same-job environment bindings are published. No runner-local path or `$GITHUB_ENV` value crosses the job boundary, and both RLS and backend mutation steps re-run the validator against the deployment runner's reconstructed bytes.

Runtime proof has no separate `verifiedAt`: `observedAt` belongs to the runtime
producer, while state-level `verifiedAt` records coordinator acceptance. This
distinction prevents producer/consumer timestamp aliasing.

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
