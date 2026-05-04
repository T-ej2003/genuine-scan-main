# MSCQR Cookie and Browser Storage Register

Last updated: 2026-05-04

Status: source-of-truth register for implementation planning. This is not a lawyer-approved Cookie Notice and does not replace `/privacy`, `/terms`, or `/cookies`.

Inputs:

- Code audit of current repository cookies, localStorage, sessionStorage, auth/session/CSRF logic, public routes, and deployment configuration.
- Live runtime findings supplied for `https://www.mscqr.com` and `/verify`.
- Current public legal pages, which are live but still show lawyer-review warnings through `src/components/trust/LegalDocumentLayout.tsx`.

Priority rule: live runtime findings are treated as higher priority than stale docs or assumptions. Unknown runtime items stay marked unknown until the source is identified and removed, documented, or formally accepted.

## Runtime-vs-code findings summary

1. Live cookies match several current code-owned cookies: `aq_access`, `aq_csrf`, `aq_refresh`, `aq_vid`, and `gs_device_claim`.
2. Live runtime shows `perf_dv6Tr4n`, which was not found in the current source audit. This is an unknown cookie and must be traced through hosting, proxy, CDN, browser extension, injected script, or deployment middleware before launch approval.
3. Live runtime did not show `mscqr_verify_session` or `mscqr_verify_csrf`, although current code sets them after customer verify auth. This may simply mean the checked browser was not in a customer-authenticated verify session at capture time.
4. Live localStorage shows high-risk legacy token state: `auth_token`, `auth_user`, and `mscqr_verify_customer_token`. Current source does not write these keys; current account security code explicitly flags these key names as risky.
5. Live localStorage shows `mscqr_verify_customer_email`, which current verify code only removes as legacy state. Its live presence means deployed users may still have old personal data persisted from previous builds or flows.
6. Live localStorage shows `mscqr_verify_last_geo`. Current code defines this geolocation cache and reads it, but no current writer was found in the audit. Because it contains location data, it requires immediate privacy and design review.
7. Live localStorage shows `theme`; this aligns with `next-themes` default storage behavior because `ThemeProvider` does not specify a custom storage key.
8. Live localStorage shows `authenticqr-theme`, `loglevel`, `qr_public_base_url`, and `__3g4_session_id`; these were not found as active writes in current source. They should be treated as unknown or legacy until proven otherwise.
9. Live sessionStorage showed no visible keys at the checked moment. Current source can create `mscqr_verify_session_proof:<sessionId>` and `manufacturer-printer-dialog-opened:v1:<userId>` during specific flows.
10. `/cookies` and `/terms` are publicly live but still show the shared lawyer-review warning. They are not production-final legal pages.

## Complete register

| Name | Type | Where observed | Source file / code owner if known | Purpose | Classification | Default lifetime / expiry | Consent recommendation | Notes / risks |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `perf_dv6Tr4n` | cookie | Live on `https://www.mscqr.com` and/or `/verify` | Unknown; no current source match | Unknown | Unknown | Unknown | Block/remove until source and purpose are proven | High risk because it appears live without repo ownership. Trace hosting/CDN/proxy/vendor/browser injection. |
| `aq_access` | cookie | Live | `backend/src/services/auth/tokenService.ts`, `backend/src/controllers/authControllerShared.ts`, `backend/src/middleware/auth.ts` | Operator/admin access session cookie | Strictly necessary | Default 15 minutes via `ACCESS_TOKEN_TTL_MINUTES`; `HttpOnly`, `SameSite=Lax`, path `/`, secure in production | Always allowed as essential | Correct direction: token is protected and not browser-readable. Must be documented. |
| `aq_refresh` | cookie | Live | `backend/src/services/auth/tokenService.ts`, `backend/src/controllers/authControllerShared.ts` | Operator/admin refresh session cookie | Strictly necessary | Default 30 days via `REFRESH_TOKEN_TTL_DAYS`; `HttpOnly`, `SameSite=Lax`, path `/`, secure in production | Always allowed as essential | Long-lived auth cookie. Document and keep rotation/revocation controls. |
| `aq_csrf` | cookie | Live | `backend/src/services/auth/tokenService.ts`, `backend/src/controllers/authControllerShared.ts`, `backend/src/middleware/csrf.ts`, `src/lib/api/internal-client-core.ts` | CSRF double-submit token for cookie-authenticated API mutations | Strictly necessary | Matches refresh/access session window depending on flow; browser-readable by design | Always allowed as essential | Browser-readable, not an auth secret. Must be documented as security storage. |
| `aq_vid` | cookie | Live | `src/lib/anon-device.ts`; consumed by `backend/src/utils/requestFingerprint.ts` | Anonymous public verification device id / request fingerprint input | Functional security / fraud prevention | 1 year; `SameSite=Lax`; `Secure` only on HTTPS | Legal decision needed; recommended essential only if fraud/security necessity is documented | Long-lived device identifier. Needs plain-English disclosure and minimization review. |
| `gs_device_claim` | cookie | Live | `backend/src/controllers/verify/verifySchemas.ts`, ownership claim handlers | Device claim continuity for public verification and ownership interactions | Functional security / fraud prevention | 1 year; `HttpOnly`, `SameSite=Lax`, path `/`, secure in production | Legal decision needed; likely essential for ownership security if justified | Long-lived identifier. Must be documented and retention reviewed. |
| `mscqr_verify_session` | cookie | Code audit only; not in supplied live capture | `backend/src/services/customerVerifyCookieService.ts`; customer verify auth handlers | Customer verify authentication/session continuity | Strictly necessary when customer verify auth is used | Default 720 hours via `CUSTOMER_VERIFY_TOKEN_TTL_HOURS`; `HttpOnly`, `SameSite=Lax`, path `/api` | Always allowed as essential if customer auth is required for verify flow | Not observed live in supplied capture, but current code sets it after email OTP, OAuth, or passkey verify auth. |
| `mscqr_verify_csrf` | cookie | Code audit only; not in supplied live capture | `backend/src/services/customerVerifyCookieService.ts`, `backend/src/middleware/csrf.ts`, `src/lib/api/internal-client-core.ts` | CSRF double-submit token for customer verify cookie mutations | Strictly necessary when customer verify auth is used | Same customer verify session TTL; browser-readable; path `/` | Always allowed as essential when customer auth is active | Not observed live in supplied capture. Browser-readable by design, not an auth secret. |
| `sidebar:state` | cookie | Code audit only; not in supplied live capture | `src/components/ui/sidebar.tsx` | Remembers dashboard sidebar expanded/collapsed state | Functional preference | 7 days; path `/`; no explicit `SameSite` or `Secure` in current setter | Block until functional/preference consent, or replace with server/UI default | Preference cookie needs hardening if kept: explicit `SameSite=Lax`, `Secure` on HTTPS. |
| `__3g4_session_id` | localStorage | Live | Unknown; current source risk list has `_3g4_session_id` with one underscore, live has two | Unknown session/device id | Unknown | Persistent until cleared | Remove/block until source is proven | High risk unknown localStorage identifier. The live name does not exactly match the current risk-list spelling. |
| `auth_token` | localStorage | Live | No current writer found; listed in `src/features/account-settings/types.ts` risk keys | Legacy/unknown auth token storage | Strictly necessary only if legacy auth still depends on it; otherwise high-risk unknown | Persistent until cleared | Remove/refactor immediately; do not consent-gate as a normal optional item | Critical security issue. Current help says tokens should not be in localStorage. Must be cleared/migrated. |
| `auth_user` | localStorage | Live | No current writer found; listed in `src/features/account-settings/types.ts` risk keys | Legacy/unknown user identity cache | Unknown / high-risk legacy | Persistent until cleared | Remove/refactor immediately | May contain personal/account data. Should not be required under cookie-backed auth. |
| `authenticqr-theme` | localStorage | Live | No current writer found; listed in `src/features/account-settings/types.ts` risk keys | Legacy theme preference | Functional preference / legacy | Persistent until cleared | Remove legacy key; if theme remains, use one documented key | Stale brand namespace. Clean up to reduce legacy surface. |
| `loglevel` | localStorage | Live | No current writer found; listed in `src/features/account-settings/types.ts` risk keys | Likely logging library/debug preference, but unproven | Functional/debug / unknown | Persistent until cleared | Remove in production unless actively needed and documented | Can alter client logging behavior. Trace dependency or legacy build origin. |
| `manufacturer-printer-onboarding:v1:<userId>` | localStorage | Live | `src/features/layout/useManufacturerPrinterConnection.ts` | Remembers manufacturer printer onboarding dismissed/completed state | Functional preference | Persistent until cleared | Block until functional/preference consent, unless legal confirms it is necessary for production printing workflow | Contains user id in key. Consider server-side preference or expiry. |
| `mscqr_verify_customer_email` | localStorage | Live | Current code removes this as legacy in `src/features/verify/components/VerifyExperience.tsx`; old docs mention verify continuity | Legacy customer email persistence | Functional legacy / personal data | Persistent until cleared | Remove/refactor immediately; do not write going forward without explicit design/legal approval | Personal data in localStorage. Current code cleanup is good, but live evidence shows stale data remains. |
| `mscqr_verify_customer_token` | localStorage | Live | No current writer found; old docs mention token continuity; guarded by `scripts/check-security-guardrails.mjs` | Legacy customer verify token | High-risk legacy auth/session token | Persistent until cleared | Remove/refactor immediately | Critical. Token-like value in localStorage conflicts with cookie-only verify posture. |
| `mscqr_verify_last_geo` | localStorage | Live | Defined in `src/features/verify/verify-model.ts`; current writer not found in audit | Recent geolocation cache for verify flow | Functional / sensitive personal data | Intended max age 10 minutes in read logic, but localStorage key persists until cleared | Block until explicit consent or redesign to session/memory-only; document if retained | High privacy sensitivity. Even expired data can remain stored. Prefer memory/session-only with clear expiry/delete. |
| `printer-calibration:Canon_TS4100i_series` | localStorage | Live | `src/features/batches/batch-print-operations.ts`, `src/features/batches/useBatchPrintWorkflow.ts` | Local printer calibration profile | Functional preference | Persistent until cleared | Block until functional/preference consent, unless classified as essential to controlled printing | Device/workplace-specific operational preference. Add expiry or server-managed profile. |
| `printer-calibration:Canon_TS4100i_series_2` | localStorage | Live | `src/features/batches/batch-print-operations.ts`, `src/features/batches/useBatchPrintWorkflow.ts` | Local printer calibration profile | Functional preference | Persistent until cleared | Block until functional/preference consent, unless classified as essential to controlled printing | Same as above; confirms multiple printer-specific entries. |
| `qr_public_base_url` | localStorage | Live | Unknown; no current writer found; listed in `src/features/account-settings/types.ts` risk keys | Unknown, likely legacy public QR base URL/config cache | Unknown / legacy config | Persistent until cleared | Remove/block until source is proven | Runtime config in localStorage can cause stale or unsafe routing if consumed by old code. |
| `theme` | localStorage | Live | `next-themes` via `src/components/theme/ThemeProvider.tsx` and `src/main.tsx` | Theme preference | Functional preference | Persistent until cleared | Block until functional/preference consent or make it essential only if accessibility need is documented | Current provider uses default `next-themes` storage key. Document or set explicit MSCQR-owned key later. |
| `aq_missing_help_requests` | localStorage | Code audit only; not in supplied live capture | `src/components/help/HelpAssistantWidget.tsx` | Stores missing-help search requests locally | Functional/support diagnostics | Persistent until overwritten; capped to 100 entries | Block until consent; consider server-side or session-only design | Can include user-entered text and route/role context. Needs minimization. |
| `mscqr_cookie_consent_choice:v1` | localStorage | Code audit only; only if `VITE_ENABLE_COOKIE_CONSENT_UI=true` | `src/components/trust/CookieConsentBanner.tsx` | Stores cookie consent choice | Strictly necessary for consent compliance when banner is enabled | Persistent until cleared | Always allowed as essential once consent system is enabled | Current banner is feature-flagged and does not yet gate optional storage. |
| `manufacturer-printer-dialog-opened:v1:<userId>` | sessionStorage | Code audit only; not in supplied live capture | `src/features/layout/useManufacturerPrinterConnection.ts` | Avoids reopening printer dialog repeatedly in one tab/session | Functional preference | Browser tab/session lifetime | Block until consent if treated as preference; can be allowed if strictly necessary for workflow safety | Contains user id in key. Prefer non-identifying key or server-owned preference. |
| `mscqr_verify_session_proof:<sessionId>` | sessionStorage | Code audit only; not in supplied live capture | `src/features/verify/components/VerifyExperience.tsx` | Proof-bound token for verification session reveal flow | Strictly necessary for security | Browser tab/session lifetime unless removed by flow | Always allowed as essential | Security token in sessionStorage, not localStorage. Keep short-lived and document. |
## Immediate red flags

1. `auth_token` in localStorage: critical. Token-like auth material must not persist in localStorage under MSCQR's cookie-backed auth posture.
2. `auth_user` in localStorage: high risk. User identity/profile data should not remain in legacy localStorage.
3. `mscqr_verify_customer_token` in localStorage: critical. Conflicts with cookie-backed customer verify auth and must be removed or migrated.
4. `mscqr_verify_customer_email` in localStorage: high privacy risk. Personal data remains live despite current cleanup logic.
5. `mscqr_verify_last_geo` in localStorage: high privacy risk. Location data requires explicit design/legal decision and should not persist indefinitely.
6. `perf_dv6Tr4n`: high risk unknown cookie. No source owner found in repo.
7. `__3g4_session_id`: high risk unknown localStorage id. Live spelling differs from the risk-list spelling.
8. Preference storage (`theme`, `authenticqr-theme`, `manufacturer-printer-onboarding:*`, `printer-calibration:*`, `sidebar:state`, `aq_missing_help_requests`) needs consent strategy, expiry, and documentation.
9. `/cookies` and `/terms` are public but still display lawyer-review warning. They are not production-final even though live users can access them.

## Recommended classification

Always allowed as essential:

- `aq_access`
- `aq_refresh`
- `aq_csrf`
- `mscqr_verify_session`
- `mscqr_verify_csrf`
- `mscqr_verify_session_proof:<sessionId>`
- `mscqr_cookie_consent_choice:v1` once the consent system is implemented

Likely essential only with written security justification:

- `aq_vid`
- `gs_device_claim`

Blocked until consent or redesigned as server/session-only:

- `theme`
- `sidebar:state`
- `manufacturer-printer-onboarding:v1:<userId>`
- `manufacturer-printer-dialog-opened:v1:<userId>`
- `printer-calibration:*`
- `aq_missing_help_requests`
- `mscqr_verify_last_geo`

Removed/refactored immediately:

- `auth_token`
- `auth_user`
- `mscqr_verify_customer_token`
- `mscqr_verify_customer_email`
- `authenticqr-theme`
- `qr_public_base_url`
- `loglevel` unless a production owner proves it is required
- `__3g4_session_id` unless a production owner proves it is required
- `perf_dv6Tr4n` unless a production owner proves it is required and legally disclosed

Document in Privacy Notice and Cookie Notice:

- All essential auth and CSRF cookies.
- Customer verification session cookies.
- Device identifiers (`aq_vid`, `gs_device_claim`) if retained.
- Verification proof/session storage.
- Printer workflow storage if retained.
- Theme/UI preferences if retained.
- Support/help diagnostics if retained.
- Sentry, Google OAuth, reCAPTCHA, Nominatim/OpenStreetMap, SIEM/Slack/PagerDuty, SMTP, and object storage where enabled in production.
- Legal status of public pages: remove draft/lawyer-review warning only after legal approval.

## Recommended next implementation order

1. Trace unknown live items: identify owner/source for `perf_dv6Tr4n`, `__3g4_session_id`, `loglevel`, and `qr_public_base_url` using production HTML, response headers, CDN/proxy config, deployed build artifacts, and browser HAR.
2. Add a storage cleanup migration before any banner UI: remove `auth_token`, `auth_user`, `mscqr_verify_customer_token`, legacy customer email, legacy theme/config keys, and unknown keys once ownership is resolved.
3. Add automated guardrails: fail CI on any new token/user/customer-token localStorage writes and add checks for exact live-risk names, including `__3g4_session_id`.
4. Define the consent taxonomy in code: essential, security/fraud-prevention, functional preferences, support diagnostics, analytics/monitoring, marketing.
5. Refactor high-risk storage: move geolocation to memory/session-only with deletion, add TTL cleanup for printer/onboarding/help preferences, and avoid user ids in storage keys where possible.
6. Gate non-essential storage writes behind a central consent API. Do this before implementing the visible banner/preferences UI.
7. Make Sentry, route telemetry, reCAPTCHA, Google OAuth disclosure and gating decisions explicit per environment.
8. Update `/cookies` and `/privacy` from this register and remove lawyer-review warnings only after counsel approves.
9. Implement banner/preferences UI after the storage layer enforces decisions.
10. Re-run live browser/HAR verification on `https://www.mscqr.com`, `/verify`, login, customer verify auth, manufacturer printing, and support flows; compare against this register before release.
