# Security Key Rotation Runbook

This runbook covers rotation of the following backend secrets:

- `QR_SIGN_HMAC_SECRET`
- `PRINTER_SSE_SIGN_SECRET`
- `INCIDENT_HASH_SALT`
- `TOKEN_HASH_SECRET`
- `IP_HASH_SALT`

These values must never be committed to git. Store them only in your deployment secret manager or server environment.

## Rotation Principles

- Rotate in a controlled maintenance window unless a secret is already known to be compromised.
- Generate new secrets with at least `32` random bytes from a cryptographically secure source.
- Apply the same value set to every backend instance before marking the rotation complete.
- Record the exact deploy SHA, rotation timestamp, operator, and affected environments.
- Verify after rotation with live health checks and one real workflow per affected feature.

## Secret Generation

Use one of these commands to generate a new secret:

```bash
openssl rand -base64 48
```

```bash
python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(48))
PY
```

## Secret Inventory

### `QR_SIGN_HMAC_SECRET`
- Purpose: signs QR payloads when asymmetric `QR_SIGN_PRIVATE_KEY` / `QR_SIGN_PUBLIC_KEY` are not configured.
- Risk of rotation: existing HMAC-signed QR tokens will stop verifying after the backend switches to the new secret.
- Safer long-term direction: move to asymmetric signing and stop relying on the HMAC fallback.

### `PRINTER_SSE_SIGN_SECRET`
- Purpose: signs printer SSE keepalive/trust payloads.
- Risk of rotation: existing live SSE sessions may fail signature checks and reconnect.
- Expected impact: low, short-lived reconnects for active printer pages.

### `INCIDENT_HASH_SALT`
- Purpose: salts incident-related hashes.
- Risk of rotation: newly computed hashes will differ from historic values. Do not expect stable comparisons across the rotation boundary unless you keep an explicit migration strategy.

### `TOKEN_HASH_SECRET`
- Purpose: secret input for token and request fingerprint hashing fallbacks.
- Risk of rotation: any feature relying on deterministic hashes from previous values may no longer match historic derived hashes.

### `IP_HASH_SALT`
- Purpose: salts IP hashing for audit/security utilities.
- Risk of rotation: historical hash comparisons across the cutover will no longer match.

## Standard Rotation Procedure

### 1. Prepare
- Confirm current production is healthy.
- Confirm you have rollback access to the previous secret values.
- Generate a fresh replacement secret for each value you intend to rotate.
- Decide whether the rotation is `routine` or `emergency`.

### 2. Stage
- Apply the new secret values in staging.
- Deploy staging backend.
- Run:
  - backend health checks
  - login flow
  - verify flow
  - incident submit flow
  - printing flow if rotating `PRINTER_SSE_SIGN_SECRET`

### 3. Production rollout
- Update the production environment variables.
- Redeploy all backend instances together.
- Confirm `/healthz`, `/api/healthz`, and `/api/version`.
- Run at least one smoke flow tied to the rotated secret.

### 4. Record
- Update the ops/security log with:
  - secret name
  - environment
  - deploy SHA
  - operator
  - timestamp
  - reason

## Secret-Specific Procedures

### Rotate `QR_SIGN_HMAC_SECRET`

Use this only if the app is still on HMAC QR signing. If asymmetric keys are configured, rotate those instead under a separate asymmetric-key procedure.

Steps:
- Set a maintenance window.
- Update `QR_SIGN_HMAC_SECRET` in the target environment.
- Deploy backend.
- Reissue any operational flows that mint fresh QR tokens after deploy.
- Validate:
  - QR verification for newly issued tokens
  - scan flow for newly issued tokens

Important limitation:
- Existing HMAC-signed tokens minted with the old secret will fail verification after the cutover because the current implementation does not support dual-key verification.

### Rotate `PRINTER_SSE_SIGN_SECRET`

Steps:
- Update `PRINTER_SSE_SIGN_SECRET`.
- Deploy backend.
- Ask manufacturers to refresh active printer setup pages if they see transient disconnects.
- Validate:
  - printer setup page reconnects
  - live printer status events
  - direct-print readiness banner

Expected impact:
- existing SSE sessions may reconnect once

### Rotate `INCIDENT_HASH_SALT`

Steps:
- Confirm no downstream process depends on stable historic incident-hash equality across the cutover.
- Update `INCIDENT_HASH_SALT`.
- Deploy backend.
- Validate:
  - incident creation
  - incident evidence export
  - incident-related audit records

Expected impact:
- old and new hashes will differ for the same input

### Rotate `TOKEN_HASH_SECRET`

Steps:
- Review any feature that compares previously derived token hashes.
- Update `TOKEN_HASH_SECRET`.
- Deploy backend.
- Validate:
  - login/session flows
  - any direct token hashing utilities
  - scan/request fingerprint dependent flows

Expected impact:
- previously derived token hashes are not stable across rotation

### Rotate `IP_HASH_SALT`

Steps:
- Confirm audit analytics do not require cross-rotation hash matching.
- Update `IP_HASH_SALT`.
- Deploy backend.
- Validate:
  - audit logging
  - security event generation
  - abuse/rate-limit telemetry still records correctly

Expected impact:
- old and new IP hashes are not comparable without a migration layer

## Emergency Rotation

If a secret is suspected compromised:

- rotate immediately
- invalidate or reissue affected sessions/tokens where applicable
- note that `QR_SIGN_HMAC_SECRET` emergency rotation invalidates old HMAC-signed QR tokens
- review logs for abuse before and after the rotation timestamp

## Rollback

Rollback is allowed only if the new secret deployment is broken and the old secret is not believed compromised.

Steps:
- restore the previous environment value
- redeploy backend
- rerun the same verification checks
- document the rollback reason and follow-up action

## Post-Rotation Verification Checklist

- `curl -sS /healthz`
- `curl -sS /api/healthz`
- `curl -sS /api/version`
- login works
- verify works
- incident submit works
- support workflow works
- printing workflow works if printer-related secrets changed

## Implementation Notes

Current implementation limitations:

- `QR_SIGN_HMAC_SECRET` rotation is a hard cutover unless you add dual-key verification support.
- `INCIDENT_HASH_SALT`, `TOKEN_HASH_SECRET`, and `IP_HASH_SALT` affect deterministic hashing, so cross-cutover comparisons are not stable by default.
- `PRINTER_SSE_SIGN_SECRET` is low-risk to rotate but active connections may reconnect.

If you want zero-downtime or comparison-safe rotation for these secrets, add explicit multi-key or versioned-hash support before the next rotation cycle.
