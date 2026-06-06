# MSCQR Phase E2 Enterprise Auth Smoke

Date: 2026-06-06
Status: Yellow until staging-owned real-auth credentials are supplied and an unskipped run is attached.

## Current code status

- `e2e/p2-real-auth-db.spec.ts` now fails closed when `E2E_REAL_AUTH_REQUIRED=true` is set without `E2E_REAL_AUTH=true`.
- The spec covers invalid login, successful seeded login, session persistence, authenticated `/api/auth/me`, logout, role menu isolation, and reset email capture when configured.
- `e2e/enterprise-smoke.spec.ts` already has required-mode behavior through `E2E_REQUIRE_ENTERPRISE_SMOKE=true`.

## Required deployed smoke environment

Use staging-owned or launch-test accounts only. Do not use production customer accounts and do not commit credentials.

Required:

```bash
PLAYWRIGHT_BASE_URL=https://<staging-host>
E2E_REAL_AUTH=true
E2E_REAL_AUTH_REQUIRED=true
E2E_SUPERADMIN_EMAIL=<staging super admin>
E2E_SUPERADMIN_PASSWORD=<redacted>
E2E_LICENSEE_ADMIN_EMAIL=<staging licensee admin>
E2E_LICENSEE_ADMIN_PASSWORD=<redacted>
E2E_MANUFACTURER_EMAIL=<staging manufacturer>
E2E_MANUFACTURER_PASSWORD=<redacted>
```

Recommended command:

```bash
npm run test:p2:e2e-real-auth
```

For the broader enterprise workflow:

```bash
PLAYWRIGHT_BASE_URL=https://<staging-host> E2E_REQUIRE_ENTERPRISE_SMOKE=true npm run test:e2e -- e2e/enterprise-smoke.spec.ts
```

## Evidence to attach

- Timestamped command.
- Staging host.
- Release SHA under test.
- Redacted account identifiers or account fixture names.
- Playwright result showing no skipped required real-auth tests.
- Confirmation that `/api/auth/me` returned authenticated JSON and no raw bearer token/hash fields.

## Launch readiness

Current readiness is Yellow because no staging-owned real-auth credentials were available locally for an unskipped deployed run.

CTO recommendation: make this a release-candidate gate in CI with `E2E_REAL_AUTH_REQUIRED=true` for staging, while keeping local developer runs skippable by default.
