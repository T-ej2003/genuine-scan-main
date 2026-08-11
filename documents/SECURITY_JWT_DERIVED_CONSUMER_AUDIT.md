# JWT-derived consumer audit

Audited at rotation coordinator HEAD `070a1ffaf0b31527f260c624e8b848291b3ed2c1`.
The audit searched `JWT_SECRET`, `getJwtSecret`, `getJwtSecretSet`, secret-set
fallbacks, HMAC/KDF/cipher call sites, production task bindings, and production
startup guards. No secret values are recorded here.

| Consumer | Source and production reachability | Primary / fallback | Lifetime and persistence | A+B compatibility | Required before JWT rotation |
| --- | --- | --- | --- | --- | --- |
| JWT access, refresh, and database-session tokens | `backend/src/services/auth/tokenService.ts`, production backend | `JWT_SECRET_CURRENT` / previous JWT slot; no universal keyring | Stateless JWTs; active sessions are time-bounded | `verifyJwtWithCurrentOrPrevious` | No |
| Encrypted auth, refresh, database-session, and customer-verify cookies | `backend/src/services/auth/cookieTokenProtectionService.ts`, production backend | Current JWT-derived AES-GCM key / previous JWT-derived key | Browser cookie lifetime; authenticated ciphertext | Current-only seal, current-then-previous open; old key removed by cleanup | No (fixed in this PR's prior work) |
| Customer verification authentication, OTP, and deterministic customer ID | `backend/src/services/customerVerifyAuthService.ts`, production backend | Dedicated `CUSTOMER_VERIFY_OTP_SECRET` and `CUSTOMER_VERIFY_TOKEN_SECRET` / JWT fallback in code | OTP is short-lived; customer token is bounded; IDs may persist | Dedicated production secret is required at startup | No |
| Customer verification OAuth state and exchange | `backend/src/services/customerVerifyOAuthService.ts`, production backend | Dedicated customer verification token secret / JWT fallback in code | OAuth state 15 minutes; exchange 10 minutes; transient browser flow | Dedicated production secret is task-bound and startup-required | No |
| Request/device fingerprint | `backend/src/utils/requestFingerprint.ts`, production backend | `SCAN_FINGERPRINT_SECRET` / token-hash then JWT fallback in code | Request and risk/audit comparisons; values may be persisted | Dedicated production secret is task-bound and startup-required | No |
| IP hash | `backend/src/utils/security.ts`, production backend | `IP_HASH_SALT_CURRENT` / legacy JWT fallback in code | Persisted audit/security rows and comparisons | Dedicated salt is task-bound; JWT rotation does not change it | No |
| Token hashes, refresh tokens, invites, reset links, and challenges | `backend/src/utils/security.ts` and auth/verification consumers, production backend | `TOKEN_HASH_SECRET_CURRENT` / legacy JWT fallback in code | Persisted rows; token TTLs vary by flow | Candidate lookup supports configured current/previous token-hash versions | No |
| QR token signing HMAC fallback | `backend/src/services/qrTokenService.ts`, not production-reachable in the rotation backend task | QR HMAC secret / legacy JWT fallback | Printed QR lifetime can be long-lived | HMAC current/previous lookup exists, but production uses required Ed25519 bindings | No for the QR-token path |
| Compliance-pack and immutable-audit artifact signatures | `backend/src/services/compliancePackService.ts`, `backend/src/services/immutableAuditExportService.ts`, production worker reachable | QR HMAC secret or QR private key / legacy JWT fallback | Downloadable and audit artifacts may outlive a JWT generation | No worker current/previous artifact-signing verification; worker binds legacy `JWT_SECRET` only | **Yes** |
| Printer SSE signatures | `backend/src/controllers/printerAgentController.ts`, production backend | Dedicated `PRINTER_SSE_SIGN_SECRET_CURRENT` / JWT fallback in code | Ephemeral stream messages | Dedicated secret is task-bound and startup-required | No |
| Incident and device hashes | `backend/src/services/securityHashService.ts`, production backend | Dedicated `INCIDENT_HASH_SALT_CURRENT` / JWT fallback in the shared secret resolver | Persisted incident/security records | Dedicated salt is task-bound and startup-required | No |
| MFA encryption and TOTP state | `backend/src/services/auth/mfaService.ts`, `totpMfaProvider.ts`, production backend | Dedicated `AUTH_MFA_ENCRYPTION_KEY` / JWT fallback only when `NODE_ENV !== production` | Persisted encrypted MFA material and short-lived challenges | Production startup rejects missing dedicated key | No; fallback is non-production-only |

## Decision

`MUST_FIX_BEFORE_ROTATION_COUNT=1`: the worker-side compliance-pack and
immutable-audit artifact signer can fall back to legacy `JWT_SECRET`, while the
worker task binds only that legacy JWT value and has no artifact-signing
current/previous verification contract. Existing artifacts can therefore lose
verification when JWT current changes from A to B. This is a separate durable
artifact-signing secret domain, not a small JWT overlap fix, so it is not
implemented in PR #256.

The required follow-up must provision and bind an independently versioned
artifact-signing secret set to the worker, sign new artifacts with current, and
verify historical artifacts with the explicitly bounded current/previous set;
then remove the JWT fallback and add cleanup/retirement evidence. Until that
follow-up is complete, `REAL_PRODUCTION_ROTATION_SAFE_AFTER_CURRENT_PR=false`.

All other JWT fallback paths are either unreachable in production because the
dedicated secret is task-bound and required by `backend/src/index.ts`,
non-production-only, or already have the intended dual-slot behavior.
