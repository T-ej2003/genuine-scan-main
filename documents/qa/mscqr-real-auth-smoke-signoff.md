# MSCQR Real Deployed Auth Smoke Sign-off

Date: 2026-06-08
Status: Yellow until staging-owned launch-test credentials produce an unskipped run.

## Current Finding

Admin login uses real MFA behavior. `SUPER_ADMIN` and `LICENSEE_ADMIN` accounts enter admin MFA bootstrap unless an enabled admin MFA record has a fresh `lastUsedAt`. There is no global smoke bypass in the auth path.

Use `documents/qa/mscqr-launch-smoke-user-seed-runbook.md` to create launch-test users and, if approved, refresh MFA freshness only for those two launch-smoke admin users.

## Required Mode

Required mode fails closed when:

- `E2E_REAL_AUTH_REQUIRED=true` is set without `E2E_REAL_AUTH=true`
- any role email/password env var is missing
- admin MFA blocks the login and no manual/fresh MFA evidence exists

Use staging-owned launch-test accounts only. Do not use production customer accounts.

## Mac/Operator Command

```bash
set +x
E2E_BASE_URL=https://<staging-or-production-host> \
E2E_API_BASE_URL=https://<staging-or-production-host> \
E2E_REAL_AUTH=true \
E2E_REAL_AUTH_REQUIRED=true \
E2E_SUPERADMIN_EMAIL="$LAUNCH_SMOKE_SUPERADMIN_EMAIL" \
E2E_SUPERADMIN_PASSWORD="$LAUNCH_SMOKE_SUPERADMIN_PASSWORD" \
E2E_LICENSEE_ADMIN_EMAIL="$LAUNCH_SMOKE_LICENSEE_ADMIN_EMAIL" \
E2E_LICENSEE_ADMIN_PASSWORD="$LAUNCH_SMOKE_LICENSEE_ADMIN_PASSWORD" \
E2E_MANUFACTURER_EMAIL="$LAUNCH_SMOKE_MANUFACTURER_EMAIL" \
E2E_MANUFACTURER_PASSWORD="$LAUNCH_SMOKE_MANUFACTURER_PASSWORD" \
npm run test:p2:e2e-real-auth
```

## Covered Assertions

The real-auth smoke covers:

- login page loads
- invalid login fails safely
- seeded super admin login succeeds
- `/api/auth/me` returns authenticated JSON without token/hash/internal fields
- super admin dashboard loads
- logout works
- `/api/auth/me` returns `401` after logout
- direct protected route after logout redirects or denies safely
- licensee admin lands on the scoped workspace
- manufacturer lands on the scoped workspace
- wrong-role direct URLs are denied or redirected safely
- no cookies, bearer tokens, password hashes, JWT secrets, or database URLs appear in page text/API bodies

## Evidence To Attach

- command timestamp
- target host
- deployed `release.gitSha`
- Playwright result showing no required-mode skip
- role labels and masked launch-test emails only
- confirmation that no passwords, cookies, JWTs, session values, bearer tokens, or generated seed passwords were attached

## Current Sign-off

- Required-mode contract: Green in code.
- Launch smoke seed tooling: Green in code, Yellow until operator run.
- Unskipped deployed auth run: Yellow, awaiting launch-test credentials and MFA handling evidence.

CTO recommendation: make this a release-candidate gate against staging first, then run the same smoke against production with launch-test accounts after the release SHA is verified. Disable or rotate these accounts after launch.
