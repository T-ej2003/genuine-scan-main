# MSCQR Phase D Staging Launch Proof

## Scope

Phase D validates the current release candidate like a production launch candidate: release branch integrity, local protected gates, disposable DB migration/auth proof, staging/prod migration checksum readiness, live smoke behavior, deployed public flows, production bundle surface, and export/printer artifact authorization.

## Release Branch Verification

- Branch checked: `codex/phase-d-launch-proof`
- HEAD verified: `9daf50a5a2a621e46d9315a08bde51029faeae90`
- `origin/main` verified: `9daf50a5a2a621e46d9315a08bde51029faeae90`
- Local `main` equals `origin/main`: yes
- Phase C commit present on main: yes, `9daf50a Polish launch header and dashboard layout (#29)`
- Phase C proof doc present: `documents/qa/mscqr-phase-c-launch-readiness-proof.md`
- Migration checksum runbook present: `documents/qa/mscqr-migration-checksum-audit-runbook.md`
- Phase B doc requested by Phase D prompt: not found at `documents/qa/mscqr-phase-b-fullstack-launch-audit.md`

## Local Release Baseline

Commands run before Phase D changes:

- `npm run test:p3:migration-gate` - passed
- `npm run test:p3:auth-security-db` - passed unskipped
- `npm run test:p3:fullstack` - passed
- `npm test` - passed, 43 files / 127 tests
- `npm run typecheck` - passed
- `npm run build` - passed
- `git diff --check` - passed
- `npx playwright test --config=playwright.enterprise.config.ts e2e/phase-c-launch-polish.spec.ts` - passed, 2/2

The P3 migration gate replayed all Prisma migrations from zero against disposable Postgres and ran DB-backed auth/security tests unskipped.

Commands run after Phase D changes:

- `npm run test:p3:auth-security-db` - passed unskipped after adding compliance-pack content proof
- `npm run test:p3:migration-gate` - passed
- `npm run test:p3:fullstack` - passed
- `npm test` - passed, 43 files / 127 tests
- `npm run typecheck` - passed
- `npm run build` - passed
- `git diff --check` - passed
- `npx playwright test --config=playwright.enterprise.config.ts e2e/phase-c-launch-polish.spec.ts` - passed, 2/2
- Bundle surface check for local paths, obvious secret names/key markers, and source maps - passed

Notes:

- Vitest still prints the existing `--localstorage-file was provided without a valid path` warning. It did not fail tests.
- Playwright still prints the existing `NO_COLOR` / `FORCE_COLOR` warning from the dev-server wrapper. It did not fail tests.

## Prisma Checksum Audit

Result: not executed against staging/prod because no safe read-only staging/prod database metadata connection was configured in the local environment.

Checked env availability without printing values:

- `STAGING_DATABASE_URL`: absent
- `DATABASE_URL`: absent for this shell
- `PRODUCTION_DATABASE_URL`: absent
- `PRISMA_DATABASE_URL`: absent
- `P2_TEST_DATABASE_ADMIN_URL`: absent outside the disposable script path
- `P2_TEST_DATABASE_URL`: absent

Required manual audit before launch:

```sql
SELECT migration_name, checksum, finished_at, rolled_back_at, applied_steps_count, logs
FROM "_prisma_migrations"
WHERE migration_name IN (
  '20260304113000_add_direct_print_render_tokens',
  '20260603120000_repair_batch_print_pack_schema'
)
ORDER BY migration_name;
```

Also verify the current database has the repaired print schema expected by `backend/prisma/schema.prisma`, especially `PrintJob`, `PrintRenderToken`, and related QR/print foreign keys.

Launch impact: this remains a launch blocker until a DBA or release owner confirms whether shared/staging/prod already applied the historically edited migration and whether Prisma checksums are safe. Do not use `prisma migrate resolve` without DBA-level review, backup/snapshot, and the checksum audit runbook.

## Live Readiness Smoke

Target audited: `https://www.mscqr.com`

Strict wrapper command:

- `SMOKE_BASE_URL=https://www.mscqr.com SMOKE_API_BASE_URL=https://www.mscqr.com/api SMOKE_REQUIRED=true npm run verify:staging-smoke`
- Result: failed configuration validation because staging smoke login credentials were not present.

Read-only smoke command:

- `SMOKE_BASE_URL=https://www.mscqr.com SMOKE_API_BASE_URL=https://www.mscqr.com/api SMOKE_REQUIRED=true node scripts/smoke-release.mjs`
- Result: passed readiness/live checks, skipped public verify and authenticated smoke because `SMOKE_VERIFY_CODE`, `SMOKE_LOGIN_EMAIL`, and `SMOKE_LOGIN_PASSWORD` were absent.

Endpoint observations:

- `/api/health/ready`: HTTP 200, JSON, status `ready`
- `/api/health/live`: HTTP 200, JSON, status `live`
- Database, Redis, and object storage reported configured and ready by the live readiness payload.
- Production object storage bucket name was intentionally not recorded in this document.
- Live release metadata reports `gitSha: "unknown"`, which weakens release traceability and rollback proof.

## Enterprise Auth Smoke

Result: not executed without skip mode because safe staging-only smoke credentials were not configured.

Required staging-only smoke data:

- `SMOKE_LOGIN_EMAIL`
- `SMOKE_LOGIN_PASSWORD`
- Optional step-up/MFA credentials if enabled for the smoke user.
- A non-customer staging tenant with `super_admin`, `licensee_admin`, and `manufacturer` coverage.
- `SMOKE_VERIFY_CODE` or a seeded signed scan-token fixture for public verification smoke.

Do not use production customer accounts. Do not commit credentials. Keep launch readiness below Green until real deployed login/logout/dashboard/role smoke runs without skip mode.

## Public Deployed Flow Audit

Playwright audited `https://www.mscqr.com` across public and auth-entry routes.

Passed:

- Homepage desktop and mobile have no horizontal overflow.
- Header no longer shows `Request Access` or `Verify Product` in the nav/header.
- Hero/body still contains `Request Access` and `Verify a Product`.
- Mobile menu is visible and opens.
- `/verify` is reachable and renders the public verification page.
- `/login` is reachable and renders the operator login page.
- `/dashboard` redirects anonymous users to `/login`.
- Unknown SPA route renders the customer-safe client 404 page.
- `/scan?t=bad-phase-d-token` renders customer-safe invalid/expired scan copy instead of raw HTTP copy.

Observed:

- `/login`, `/dashboard`, and unknown SPA route produce expected unauthenticated `/api/auth/me` 401 network entries in the browser console. No raw token/backend error was rendered in the UI.
- The web server returns SPA HTML with HTTP 200 for unknown frontend paths; the client renders 404. Monitoring should not treat arbitrary frontend path HTTP 200 as route existence.

## Bundle, Source Map, CDN, And Cache Audit

Local production bundle issue found:

- A normal `npm run build` was affected by local `.env` `NODE_ENV=development`, causing React SWC dev output and absolute build-machine source paths to appear in `dist`.
- Fix made: `npm run build` now runs `NODE_ENV=production vite build`, and `vite.config.ts` also forces `process.env.NODE_ENV = "production"` during build as defense-in-depth.

Post-fix local checks:

- `npm run build` passed.
- `dist` has no `/Users/` or local workspace path strings.
- `dist` has no obvious secret env names or private key markers checked by the Phase D grep.
- `dist` has no `.map` files.

Live cache observations:

- HTML routes are served with no-store/no-cache headers.
- Hashed JS/CSS assets are served with long-lived immutable cache headers.

Remaining bundle notes:

- User-facing local printer setup features legitimately contain localhost/local-network copy.
- Live deployment must be rebuilt from this fixed build command before the bundle fix can be considered deployed.

## Export And Printer Artifact Authorization

DB-backed content coverage now includes:

- Positive QR CSV export content assertion for scoped super-admin export: tenant A QR appears, tenant B QR/brand data is absent.
- Positive compliance-pack artifact assertion: platform admin download of tenant A pack returns a ZIP and `integrity.json` is scoped to tenant A, with standard report files present.
- Current route policy denies licensee-admin compliance-pack downloads, including same-tenant downloads; the positive content proof therefore uses the platform-admin route contract.
- Negative compliance-pack IDOR assertion: tenant A cannot download tenant B compliance pack.
- Printer pack route assertion: own and cross-tenant manufacturer print-pack downloads do not leak tenant B data.

Printer positive artifact limitation:

- Manufacturer print-pack download is intentionally disabled with HTTP 410 and safe copy. Positive printer artifact content proof is blocked until that route is intentionally enabled for a launch-supported printer artifact path. This was not force-enabled for tests.

## Bugs Found And Fixed

Fixed:

- Production build command could emit React dev transform/source-location metadata when local `.env` set `NODE_ENV=development`. Fixed by making `npm run build` set `NODE_ENV=production` before Vite loads config.
- Added an enabled compliance-pack positive content authorization assertion to the DB-backed launch proof.
- Added deterministic disposable compliance ZIP fixtures to the DB seed helper so content authorization tests do not depend on object storage, production secrets, or rebuild-side signing keys.

Not fixed in this pass:

- Live release metadata reports `gitSha: "unknown"`.
- Staging/prod Prisma checksum audit could not be executed without read-only DB metadata credentials.
- Real enterprise auth smoke could not be executed without staging-only smoke credentials.

## Remaining Launch Blockers

P0:

- Staging/prod Prisma checksum audit for `20260304113000_add_direct_print_render_tokens` has not been executed.
- Real enterprise auth smoke has not run without skip mode against the deployed environment.
- The production bundle hardening fix must be deployed and verified on the live target before final launch sign-off.

P1:

- Live `/api/health/live` returns `gitSha: "unknown"`, reducing release traceability.
- No valid public QR/signed scan fixture was available for deployed positive verification smoke.
- Printer positive content proof remains blocked by the intentionally disabled print-pack download route.
- Phase B launch audit document was not found at the requested path.

## Final Verdict

Launch readiness: **Red**

Rationale: local auth/security/migration gates are strong and live readiness endpoints are currently healthy, but final launch proof is incomplete without staging/prod Prisma checksum audit, unskipped enterprise auth smoke, and deployment verification of the production bundle fix. These are release-candidate evidence gaps, not cosmetic issues.

## Required Next Actions

1. Provide a read-only staging/prod metadata connection to audit `_prisma_migrations` using `documents/qa/mscqr-migration-checksum-audit-runbook.md`.
2. Seed staging-only smoke users and run strict authenticated smoke with `SMOKE_REQUIRED=true`.
3. Seed a safe public verify code or signed scan token and run deployed positive QR verification smoke.
4. Deploy the build-command fix and verify live bundles contain no local source paths and no source maps.
5. Set release metadata so `/api/health/live` reports a real git SHA.
