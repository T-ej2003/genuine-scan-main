# Admin MFA Standards Adapter Runbook

This runbook covers the additive admin MFA adapter that supports passkeys/WebAuthn, authenticator-app TOTP, and one-time backup codes.

## What Changed

- Admin login MFA now uses `MfaLoginChallenge` for stable short-lived login tickets instead of repeatedly superseding `AuthMfaChallenge` rows on refresh.
- Passkey verification is delegated to `@simplewebauthn/server`.
- TOTP generation and verification use `otplib`.
- Backup codes are generated with strong randomness, displayed once, stored only as hashes, and consumed atomically.
- Existing `AdminMfaCredential`, `AdminWebAuthnCredential`, and `AuthMfaChallenge` records remain available for compatibility and rollback.

## Required Production Env Vars

- `WEBAUTHN_RP_ID`: production relying party ID. For MSCQR production use `mscqr.com`.
- `WEBAUTHN_ORIGIN`: comma-separated allowed browser origins, for example `https://www.mscqr.com,https://mscqr.com`.
- `WEBAUTHN_RP_NAME`: user-facing relying party name, for example `MSCQR`.
- `AUTH_MFA_ENCRYPTION_KEY`: high-entropy secret for encrypting TOTP secrets. Production must set this explicitly.
- `AUTH_MFA_TOTP_WINDOW`: optional TOTP clock skew window. Keep this small; default is `1`.
- `AUTH_MFA_CHALLENGE_TTL_MINUTES`: optional login challenge TTL. Default is `5`.
- `AUTH_MFA_CHALLENGE_MAX_ATTEMPTS`: optional challenge attempt cap. Default is `5`.
- `AUTH_MFA_BACKUP_CODE_COUNT`: optional backup code count. Default is `8`.

Rate limiting remains separate from MFA factor storage. In ECS production, shared rate-limit/cache configuration should continue to require Redis rather than silently relying on per-task memory.

## Deployment Order

1. Take a database snapshot.
2. Run the Prisma migration `20260616103000_add_standards_mfa_adapter_tables`.
3. Deploy the backend.
4. Smoke test admin login with an enrolled admin:
   - password login returns a stable MFA challenge,
   - one wrong MFA code returns a recoverable error,
   - the next correct TOTP code completes login,
   - a refresh does not immediately produce `410 Gone`,
   - repeated invalid attempts return `429` with `Retry-After`.
5. Smoke test passkey registration and sign-in on `https://www.mscqr.com`.
6. Deploy the frontend.
7. Repeat the login smoke test in a clean browser profile.

## Rollback Notes

- The migration is additive. It does not drop old MFA tables or columns.
- If the frontend must be rolled back, the backend still accepts the existing TOTP and backup-code challenge contract.
- If the backend must be rolled back, leave the additive tables in place; older code ignores them.
- Do not delete `AuthMfaChallenge`, `AdminMfaCredential`, or `AdminWebAuthnCredential` until all admins have migrated and a separate cleanup release is approved.

## Security Checks

- Never log submitted TOTP values, backup codes, WebAuthn challenge tickets, or credential private material.
- Backup codes must be shown only once after setup or rotation.
- A new backup-code row set is authoritative; legacy backup-code fallback is only for users without new backup-code rows.
- WebAuthn verification must validate expected origin, expected RP ID, challenge, signature, and counter.
- Browser state must not elevate auth assurance. Only successful backend MFA verification may issue an admin-MFA session.

## Manual Validation

1. Sign in as an admin with TOTP enabled.
2. Refresh the MFA page before entering a code.
3. Enter one invalid code, then the next valid authenticator code.
4. Confirm the admin session opens without stale `410 Gone`.
5. Try enough invalid codes to confirm a `429` response includes `Retry-After`.
6. Register a passkey and verify it appears in account security.
7. Sign out and sign in with the passkey.
8. Rotate backup codes, use one, then verify the same code cannot be reused.
9. Confirm audit logs record enrollment, success/failure, passkey use, and backup-code use without secrets.
