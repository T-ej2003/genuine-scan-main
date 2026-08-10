# Security Key Rotation Runbook

This runbook covers the rotating backend secret families used by the app:

- `JWT_SECRET_CURRENT` / `JWT_SECRET_PREVIOUS`
- `QR_SIGN_HMAC_SECRET_CURRENT` / `QR_SIGN_HMAC_SECRET_PREVIOUS`
- `PRINTER_SSE_SIGN_SECRET_CURRENT` / `PRINTER_SSE_SIGN_SECRET_PREVIOUS`
- `TOKEN_HASH_SECRET_CURRENT` / `TOKEN_HASH_SECRET_PREVIOUS`
- `INCIDENT_HASH_SALT_CURRENT` / `INCIDENT_HASH_SALT_PREVIOUS`
- `IP_HASH_SALT_CURRENT` / `IP_HASH_SALT_PREVIOUS`

Legacy single-slot variables still exist for compatibility, but production should use the dual-slot `CURRENT` / `PREVIOUS` model.

Production Ed25519 QR rotation uses the same two-deploy overlap contract:

- `QR_SIGN_PRIVATE_KEY_CURRENT` and `QR_SIGN_PUBLIC_KEY_CURRENT` are the only signing slots.
- `QR_SIGN_ACTIVE_KEY_VERSION` is the current payload `kid`.
- `QR_SIGN_PUBLIC_KEY_PREVIOUS` and `QR_SIGN_PREVIOUS_KEY_VERSION` are the only previous verification slot.
- A previous private key is never deployed for verification.
- Verification accepts exactly the current key or the one declared previous key; unknown `kid` values fail closed.

## Principles

- Never commit secrets to git.
- Generate at least `32` random bytes for each new secret.
- Deploy the same secret set to every backend instance before switching traffic.
- Rotate in two deployments: `accept both`, then `remove previous`.
- Record environment, deploy SHA, operator, timestamp, and reason.

## Secret Generation

```bash
openssl rand -base64 48
```

## How Rotation Works in This Repo

- Writers always use the `*_CURRENT` secret.
- Verification accepts both `*_CURRENT` and `*_PREVIOUS` during the cutover window.
- JWTs include a `kid` derived from the active signing secret.
- Versioned hashes are stored with a prefix, so historic hashes remain comparable during the cutover.
- After the cutover window, `*_PREVIOUS` is removed in a second deploy.

The canonical production coordinator is `backend/scripts/security/rotate-production-signing-material.mjs`.
It requires an external, operator-owned JSON config containing only secret resource identifiers and the expected
release role; it never prints secret values. Run one explicit mode at a time:

```bash
npm --prefix backend run security:rotate-production-signing-material -- \
  --config /secure/operator/rotation.json --state-file /secure/operator/rotation-state.json \
  --fixture-file /secure/operator/previous-qr-fixture.json --prepare

npm --prefix backend run security:rotate-production-signing-material -- \
  --config /secure/operator/rotation.json --state-file /secure/operator/rotation-state.json \
  --fixture-file /secure/operator/previous-qr-fixture.json --verification-out /secure/operator/verification.json \
  --verify
```

The config maps distinct Secrets Manager resources for JWT current/previous/pending, QR current/private,
QR previous/public, and pending material. It also requires a reviewed `minimumGraceSeconds`. The coordinator
writes only non-secret state and redacted runtime proof to operator-controlled mode-600 files. The deployed-task
verifier uses the compiled application JWT and QR verification functions; it is not a public endpoint.
`--cleanup` first retires all previous/pending slots and stops at `cleanup-deploy-required`. Only after the
approved cleanup deployment restarts tasks may the operator resume with a cleanup runtime proof. It is never
run by CI or implicitly by `--prepare`.

## Standard Two-Deploy Rotation

### 1. Prepare

- Confirm production is healthy.
- Confirm you still have the current live secret values.
- Generate new replacement values.
- Choose a cutover window longer than the affected token/session TTLs.

### 2. Stage the New Secrets

Set the target environment like this:

```bash
export JWT_SECRET_PREVIOUS="<old-jwt>"
export JWT_SECRET_CURRENT="<new-jwt>"

export QR_SIGN_HMAC_SECRET_PREVIOUS="<old-qr-hmac>"
export QR_SIGN_HMAC_SECRET_CURRENT="<new-qr-hmac>"

export PRINTER_SSE_SIGN_SECRET_PREVIOUS="<old-printer-sse>"
export PRINTER_SSE_SIGN_SECRET_CURRENT="<new-printer-sse>"

export TOKEN_HASH_SECRET_PREVIOUS="<old-token-hash>"
export TOKEN_HASH_SECRET_CURRENT="<new-token-hash>"

export INCIDENT_HASH_SALT_PREVIOUS="<old-incident-salt>"
export INCIDENT_HASH_SALT_CURRENT="<new-incident-salt>"

export IP_HASH_SALT_PREVIOUS="<old-ip-salt>"
export IP_HASH_SALT_CURRENT="<new-ip-salt>"
```

Deploy backend and frontend with both slots present.
Record this in `.security/rotation-evidence.json` with linked deploy SHA(s).

### 3. Verify During the Cutover

Run:

- health/internal-release checks
- admin login
- refresh session
- password reset
- invite accept
- verify-email
- printer status SSE
- one public verify flow
- one incident/support flow

During this window:

- old JWTs still verify
- old token hashes still match
- old HMAC-signed QR payloads still verify
- active printer SSE keepalive signatures remain valid until reconnect

### 4. Wait Out the Window

Wait at least:

- access-token TTL
- refresh-token operational buffer
- invite/reset/email-verification link buffer
- any printer/SSE reconnect buffer

For this repo, the practical minimum is the full refresh-token window if you want zero forced re-auth on refresh rotation. If that is too long for the incident, rotate immediately and accept forced reauthentication.

### 5. Retire, Then Cleanup Deploy

After the persisted `cleanupEligibleAt` deadline, run coordinator `--cleanup`.
It retires `JWT_SECRET_PREVIOUS`, `QR_SIGN_PUBLIC_KEY_PREVIOUS`, and all three
pending slots with one immutable `retirementTimestamp`, then stops at
`cleanup-deploy-required`. Deploy/restart tasks after those writes, run the
deployment-side verifier with `ROTATION_RUNTIME_PHASE=cleanup`, and resume
`--cleanup` with that proof. A cleanup deployment observed before retirement is
rejected.

Mark cleanup in `.security/rotation-evidence.json`:

- `cleanupWindowComplete=true`
- `cleanupCompletedAt=<timestamp>`
- `cleanupVerifiedBy=<operator>`
- `linkedDeployShas` includes both deploy SHAs
- previous JWT/QR rejected after cleanup while current JWT/QR remain valid
- all previous and pending slots carry explicit retired metadata

## Secret-Specific Notes

### JWT signing

- Used for admin/staff access tokens and MFA bootstrap tokens.
- Cutover impact is low with dual-slot support.
- Removing `JWT_SECRET_PREVIOUS` too early will force some active sessions to fail verification.

### QR HMAC signing

- Only relevant when QR signing is using HMAC fallback instead of Ed25519 keys.
- With dual-slot support, existing HMAC-signed QR tokens continue to verify during the cutover.
- Long term, Ed25519 keys are still the preferred posture.

### QR Ed25519 / managed bridge posture

- The repo supports local Ed25519 signing today and exposes a managed signer bridge boundary for a future KMS/HSM integration.
- Setting `QR_SIGN_KMS_KEY_REF` / `QR_SIGN_KMS_VERIFY_KEY_REF` alone does not enable managed signing.
- Managed mode is only active when:
  - `QR_SIGN_PROVIDER=managed`
  - the deployed backend registers a managed signer bridge
  - the bridge reports the active key version and key reference
- If managed mode is selected without a registered bridge, MSCQR now fails closed at startup.
- Rotation and revocation for managed signing remain operational responsibilities outside this repo until the runtime bridge is implemented.

### Printer SSE signing

- Existing SSE clients may reconnect during deploy, which is acceptable.
- Dual-slot verification prevents keepalive validation drift during cutover.

### TOKEN_HASH_SECRET

- Covers auth-linked hashed tokens and similar secret-derived comparisons.
- Versioned hashes now allow old and new derived values to match during the cutover.

### INCIDENT_HASH_SALT and IP_HASH_SALT

- Newly written values use the current salt.
- Historic versioned hashes remain comparable during the cutover.
- Remove the previous slot only after the reporting/forensics team is clear on the boundary.

## Emergency Rotation

If a secret is believed compromised:

- rotate immediately
- deploy with `CURRENT` + `PREVIOUS`
- revoke affected sessions or tokens if the compromise scope includes active credentials
- review logs around the compromise window
- remove `PREVIOUS` as soon as the operational buffer closes

## Rollback

Rollback is allowed only if the new deployment is broken and the previous secret is not considered compromised.

- restore the prior values into `*_CURRENT`
- optionally keep the broken new value in `*_PREVIOUS` only if you still need to verify items minted after the failed deploy
- redeploy
- rerun the verification checklist

## Post-Rotation Verification Checklist

- `curl -sS /healthz`
- `curl -sS /api/healthz`
- authenticated `GET /api/internal/release`
- admin login works
- refresh works
- password reset works
- invite acceptance works
- email verification works
- public verify works
- incident submit works
- printer SSE stream reconnects cleanly

## CI policy checks

- `npm run check:rotation-evidence-contract` validates the committed rotation
  evidence shape used by source/control-plane CI. It deliberately exercises a
  non-production stale fixture and reports `ROTATION_EVIDENCE_FRESH=false`.
- `npm run check:rotation-evidence-freshness` validates the real
  `.security/rotation-evidence.json` and enforces the 120-day production
  freshness limit plus cleanup proof.
- `npm run check:rotation-evidence` remains the strict production alias for
  `check:rotation-evidence-freshness`.
- `npm run check:rotation-cleanup`

Source implementation PRs require the contract, runtime, coordinator, secret
leakage, and security checks. They do not constitute a production rotation and
must not be required to make stale operational evidence fresh.

Production release, deployment, scheduled security, and release-candidate
readiness gates require `check:rotation-evidence-freshness` and must remain red
until a real governed rotation has completed. The gate contexts are explicit:

| Consumer | Context | Contract | Freshness | Mutation-capable |
| --- | --- | --- | --- | --- |
| Source PR validation | pull request | required | reported, not required | no |
| Stage B source closure | pull request | required | not required | no |
| Production release/deployment | protected push/manual release | required | required | downstream only |
| Scheduled DR/security validation | scheduled/manual operational run | required | required | no |
| Release-candidate readiness | release push/manual release | required | required | downstream only |

The pull-request workflows select their source-validation command from the
workflow event. This is a semantic gate mode, not a PR, branch, or environment
bypass. Pushes, scheduled checks, and manual production runs keep the strict
freshness path.

After a real rotation, run the strict checks without changing their threshold:

```bash
ROTATION_WINDOW_COMPLETE=true npm run check:rotation-evidence-freshness
ROTATION_WINDOW_COMPLETE=true npm run check:rotation-cleanup
```

The recorded evidence file is not refreshed by source implementation PRs. The
governed lifecycle remains: merge the reviewed mechanism, execute prepare and
the overlap deployment, verify current and previous JWT/QR material, observe
the grace window, execute cleanup, generate machine-verifiable evidence, then
allow the strict freshness gate to pass.

## Operational Notes

- Production should use the `CURRENT` / `PREVIOUS` variables, not only the legacy single-slot names.
- `AUTH_LEGACY_TOKEN_RESPONSE_ENABLED` and `AUTH_SSE_QUERY_TOKEN_ENABLED` should remain `false` in production after the cookie-only auth rollout.
- `AUTH_MFA_ENCRYPTION_KEY` is required in production and should be rotated separately from JWT secrets.
