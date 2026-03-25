# Security Key Rotation Runbook

This runbook covers the rotating backend secret families used by the app:

- `JWT_SECRET_CURRENT` / `JWT_SECRET_PREVIOUS`
- `QR_SIGN_HMAC_SECRET_CURRENT` / `QR_SIGN_HMAC_SECRET_PREVIOUS`
- `PRINTER_SSE_SIGN_SECRET_CURRENT` / `PRINTER_SSE_SIGN_SECRET_PREVIOUS`
- `TOKEN_HASH_SECRET_CURRENT` / `TOKEN_HASH_SECRET_PREVIOUS`
- `INCIDENT_HASH_SALT_CURRENT` / `INCIDENT_HASH_SALT_PREVIOUS`
- `IP_HASH_SALT_CURRENT` / `IP_HASH_SALT_PREVIOUS`

Legacy single-slot variables still exist for compatibility, but production should use the dual-slot `CURRENT` / `PREVIOUS` model.

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

### 3. Verify During the Cutover

Run:

- health/version checks
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

### 5. Cleanup Deploy

After the cutover window:

```bash
unset JWT_SECRET_PREVIOUS
unset QR_SIGN_HMAC_SECRET_PREVIOUS
unset PRINTER_SSE_SIGN_SECRET_PREVIOUS
unset TOKEN_HASH_SECRET_PREVIOUS
unset INCIDENT_HASH_SALT_PREVIOUS
unset IP_HASH_SALT_PREVIOUS
```

Redeploy again. At that point only the new `CURRENT` secrets remain.

## Secret-Specific Notes

### JWT signing

- Used for admin/staff access tokens and MFA bootstrap tokens.
- Cutover impact is low with dual-slot support.
- Removing `JWT_SECRET_PREVIOUS` too early will force some active sessions to fail verification.

### QR HMAC signing

- Only relevant when QR signing is using HMAC fallback instead of Ed25519 keys.
- With dual-slot support, existing HMAC-signed QR tokens continue to verify during the cutover.
- Long term, Ed25519 keys are still the preferred posture.

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
- `curl -sS /api/version`
- admin login works
- refresh works
- password reset works
- invite acceptance works
- email verification works
- public verify works
- incident submit works
- printer SSE stream reconnects cleanly

## Operational Notes

- Production should use the `CURRENT` / `PREVIOUS` variables, not only the legacy single-slot names.
- `AUTH_LEGACY_TOKEN_RESPONSE_ENABLED` and `AUTH_SSE_QUERY_TOKEN_ENABLED` should remain `false` in production after the cookie-only auth rollout.
- `AUTH_MFA_ENCRYPTION_KEY` is required in production and should be rotated separately from JWT secrets.
