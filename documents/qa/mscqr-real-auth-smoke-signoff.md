# MSCQR Real Deployed Auth Smoke Sign-off

Date: 2026-06-06
Status: Yellow until staging-owned credentials produce an unskipped run.

## Required Mode

Required mode fails closed when `E2E_REAL_AUTH_REQUIRED=true` and real auth is disabled or role credentials are missing.

Use staging-owned launch-test accounts only. Do not use production customer accounts.

```bash
PLAYWRIGHT_BASE_URL=https://<staging-host> \
E2E_REAL_AUTH=true \
E2E_REAL_AUTH_REQUIRED=true \
E2E_SUPERADMIN_EMAIL="$STAGING_SUPERADMIN_EMAIL" \
E2E_SUPERADMIN_PASSWORD="$STAGING_SUPERADMIN_PASSWORD" \
E2E_LICENSEE_ADMIN_EMAIL="$STAGING_LICENSEE_ADMIN_EMAIL" \
E2E_LICENSEE_ADMIN_PASSWORD="$STAGING_LICENSEE_ADMIN_PASSWORD" \
E2E_MANUFACTURER_EMAIL="$STAGING_MANUFACTURER_EMAIL" \
E2E_MANUFACTURER_PASSWORD="$STAGING_MANUFACTURER_PASSWORD" \
npm run test:p2:e2e-real-auth
```

## Covered Assertions

The real-auth smoke covers:

- login page loads
- invalid login fails safely
- seeded `super_admin` login succeeds
- `/api/auth/me` returns authenticated JSON without token/hash/internal fields
- super admin dashboard loads
- logout works
- `/api/auth/me` returns `401` after logout
- direct protected route after logout redirects to login
- licensee admin lands on dashboard/workspace
- manufacturer lands on dashboard/workspace
- wrong-role direct URLs are denied/redirected safely

## Evidence To Attach

- command timestamp
- staging host
- release SHA
- Playwright result with no required-mode skips
- masked account fixture names or role labels only
- confirmation no cookies, bearer tokens, passwords, JWTs, or session values were printed

## Current Sign-off

- Required-mode contract: Green in code.
- Unskipped staging run: Yellow, awaiting staging-owned credentials.

CTO recommendation: make this a staging release-candidate gate. Keep local developer runs skippable, but never allow release-candidate required mode to pass skipped.
