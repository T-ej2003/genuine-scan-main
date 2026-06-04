# MSCQR P2 Production-Shaped Auth/Security Test Notes

## Scope

This P2 pass moves the auth/security automation from P1 real-router + mocked-infra coverage toward production-shaped proof using the real Express app, real Prisma client, and a guarded disposable PostgreSQL database harness.

## Files Changed

- `backend/tests/helpers/p2TestDb.js`
- `backend/tests/helpers/p2SeedFactories.js`
- `backend/tests/p2DbAuthorization.test.js`
- `backend/tests/p2EmailCapture.test.js`
- `backend/src/services/mailTransportService.ts`
- `src/lib/api/internal-client-core.ts`
- `e2e/p1-signed-scan-token.spec.ts`
- `e2e/p2-real-auth-db.spec.ts`
- `backend/package.json`
- `package.json`
- `.env`
- `backend/.env`
- `documents/qa/mscqr-p2-production-shaped-auth-security-test-notes.md`

## Disposable Test DB Harness

Path: `backend/tests/helpers/p2TestDb.js`

- Uses PostgreSQL only.
- Requires either `P2_TEST_DATABASE_URL` or `P2_TEST_DATABASE_ADMIN_URL`.
- Refuses DB names that do not clearly contain `test`, `p2`, `ci`, `tmp`, or `temporary`.
- Refuses production-looking hosts/URLs unless explicitly allowed with `P2_TEST_DATABASE_ALLOW_REMOTE=true`.
- Creates a one-off DB when `P2_TEST_DATABASE_ADMIN_URL` is provided.
- P3 updated this harness to run `prisma validate` and `prisma migrate deploy` when migration folders exist.
- Imports the compiled real app only after `DATABASE_URL` is pointed at the disposable DB.
- Drops only DBs created by the harness.

P3 note: the repo has real migration folders under `backend/prisma/migrations`, so disposable DB setup now uses migration deploy instead of schema push. `db push` remains only as a fallback if migration folders are absent in a future branch.

## Required Env Vars

- `P2_TEST_DATABASE_URL`, or
- `P2_TEST_DATABASE_ADMIN_URL`
- JWT, QR signing, and auth-cookie values are generated at runtime by the test helper unless explicitly provided by a test runner.
- Optional: `EMAIL_CAPTURE_DIR=/tmp/mscqr-email-capture`
- Optional for real browser auth: `E2E_REAL_AUTH=true`
- Optional for reset-link capture E2E: `E2E_EMAIL_CAPTURE_ENABLED=true`

Example local DB setup:

```bash
npm run test:p2:db:up
export P2_TEST_DATABASE_ADMIN_URL="$(node scripts/p2-test-db-env.mjs --print-admin-url)"
npm run test:p2:api-authz-db
```

## Seed/Factory Helpers Added

Path: `backend/tests/helpers/p2SeedFactories.js`

Fixtures seeded with real Prisma writes:

- Super admin with recent admin MFA marker.
- Licensee admin A and unrelated licensee admin B.
- Manufacturer A and unrelated manufacturer B.
- Organization A/B.
- Licensee A/B.
- Batch A/B.
- QR code A/B.
- Signed scan token for QR A.
- Scan event/history A/B.
- Incident A/B.
- Support ticket A/B.
- Support issue report A/B.
- QR allocation request A/B.
- Tenant governance feature flag A/B.
- Compliance pack job A/B.
- Print job/pack fixture A/B.

No `Product` model exists in the current Prisma schema, so P2 maps product-adjacent coverage to the actual batch + QR code domain model.

## Real DB-Backed API Tests Added

Path: `backend/tests/p2DbAuthorization.test.js`

Covered when a P2 disposable DB is configured:

- `POST /api/auth/login`
- `GET /api/auth/me`
- `GET /api/qr/batches`
- `PATCH /api/qr/batches/:id/rename`
- `GET /api/qr/codes/export`
- `GET /api/scan?t=...`
- `GET /api/support/tickets`
- `GET /api/incidents`
- `GET /api/incidents/:id`
- `GET /api/governance/feature-flags`
- `GET /api/governance/compliance/pack/jobs/:id/download`
- `GET /api/manufacturer/print-jobs/:id/pack`

Assertions include:

- Anonymous and invalid-token denial.
- Real login success and invalid-credential denial.
- Correct-role access.
- Wrong-role denial.
- Cross-tenant query-param tampering denial.
- Cross-tenant URL-param tampering denial.
- Cross-tenant mutation denial and DB non-mutation proof.
- QR export CSV content does not include unauthorized tenant rows.
- Signed scan public response does not leak tenant B or admin-only fields.
- Printer pack endpoint is safely disabled (`410`) and does not leak another tenant's pack content.
- Denied responses do not expose stack traces, Prisma internals, bearer tokens, token hashes, password hashes, or configured test secrets.

## Real Auth E2E Tests Added

Path: `e2e/p2-real-auth-db.spec.ts`

These tests are intentionally gated by `E2E_REAL_AUTH=true`.

Covered when a seeded real backend is available:

- Login invalid credentials.
- Seeded manufacturer login.
- Session persistence after reload.
- Logout and protected-route redirect.
- Manufacturer menu/body does not show platform/admin internals.
- Licensee-admin post-login route isolation smoke.
- Password reset request email capture when `E2E_EMAIL_CAPTURE_ENABLED=true` and `EMAIL_CAPTURE_DIR` are set.

Skipped locally because no disposable DB-backed backend was running with seeded credentials.

## Email Capture

Implementation path: `backend/src/services/mailTransportService.ts`

Test path: `backend/tests/p2EmailCapture.test.js`

- Adds JSONL email capture only outside production.
- Requires `EMAIL_CAPTURE_DIR` or `EMAIL_JSON_CAPTURE_DIR`.
- Active automatically in `NODE_ENV=test`, or when `EMAIL_CAPTURE_ENABLED=true` / `E2E_EMAIL_CAPTURE_ENABLED=true` outside production.
- Captures recipient, sender, reply-to, subject, text, HTML, template, diagnostic, and safe error code.
- Does not change production SMTP behavior.

## MFA Coverage

- DB seed helpers create recent admin MFA markers so seeded admin sessions can pass fresh-admin-MFA route checks.
- P2 does not implement full TOTP/WebAuthn browser automation.
- Full TOTP secret provisioning and WebAuthn device simulation remain P3 work.

## Signed QR Scan Coverage

- P2 DB-backed test seeds a real QR record and signs a real `/scan?t=...` token through `qrTokenService`.
- Public response is asserted to include tenant A and not tenant B.
- Existing P1 Playwright signed-scan states still cover valid, expired, tampered, revoked, missing, suspicious duplicate, and mobile rendering.

## Export/Download Content Authorization

- `GET /api/qr/codes/export?licenseeId=<tenant A>` is asserted at CSV content level.
- Export must include `P2A000001`.
- Export must not include `P2B000001` or `P2 Brand B`.
- Manufacturer/licensee-admin export attempts are safely denied without content leakage.
- Compliance pack download IDOR is tested for safe denial/no tenant B file markers.

## Printer Pack/Content Authorization

- `GET /api/manufacturer/print-jobs/:id/pack` currently returns `410` because print-pack download is intentionally disabled.
- P2 asserts authorized own pack request is safely disabled and does not leak unrelated tenant data.
- P2 asserts manufacturer A cannot retrieve manufacturer B pack content by changing IDs.
- Positive printer pack file content proof remains blocked until the feature is re-enabled.

## Public Scan Error-Copy Fix

Path: `src/lib/api/internal-client-core.ts`

- Public `/scan` and `/verify` failures now map empty/raw non-2xx responses to customer-safe messages.
- Raw `HTTP 400`, `HTTP 404`, and route-style technical text such as `Cannot GET ...` are no longer shown for these public verification endpoints.
- Existing signed-scan Playwright coverage now asserts missing-token UI does not show raw HTTP copy.

## `.env NODE_ENV=production` Cleanup

- Changed root `.env` and `backend/.env` from `NODE_ENV=production` to `NODE_ENV=development`.
- No secrets were removed or edited.
- Production deployments should set `NODE_ENV=production` from the hosting/runtime environment, not local development `.env`.

## Commands Run

```bash
npm --prefix backend run test:p2:fullstack
npm run test:p2:e2e-real-auth
npm run test:p2:scan
npm run typecheck
npm run build
npm test
npm --prefix backend run test:p0-authz
npm --prefix backend run test:p1:api-authz
npm run test:p1:e2e-auth
npm run test:p0:fullstack-auth
npx eslint src/lib/api/internal-client-core.ts backend/src/services/mailTransportService.ts e2e/p1-signed-scan-token.spec.ts e2e/p2-real-auth-db.spec.ts
npx eslint e2e/p2-real-auth-db.spec.ts
```

## Test Results

- `npm --prefix backend run test:p2:fullstack`: passed.
- P2 DB-backed authorization suite: skipped safely because neither `P2_TEST_DATABASE_URL` nor `P2_TEST_DATABASE_ADMIN_URL` is configured locally.
- P2 JSON email capture test: passed.
- `npm run test:p2:e2e-real-auth`: passed with 3 skipped by design because `E2E_REAL_AUTH=true` was not set.
- `npm run test:p2:scan`: first attempt failed because no server was listening on `127.0.0.1:8080`; after starting Vite on the configured port, passed 3/3.
- `npm run typecheck`: passed.
- `npm run build`: passed.
- `npm test`: passed, 43 files / 127 tests.
- `npm --prefix backend run test:p0-authz`: passed.
- `npm --prefix backend run test:p1:api-authz`: passed.
- `npm run test:p1:e2e-auth`: passed 3/3 with 1 expected real-auth skip.
- `npm run test:p0:fullstack-auth`: passed 91 frontend tests plus backend P0 authz.
- Targeted ESLint across touched existing files failed on pre-existing `no-explicit-any` debt in existing files.
- `npx eslint e2e/p2-real-auth-db.spec.ts`: passed.

## Real Bugs Found

- Public scan/verify frontend fallback could show raw generic `HTTP 400` / `HTTP 404` copy for empty non-2xx responses.
- Local root/backend `.env` set `NODE_ENV=production`, causing development/test warning noise and risky local semantics.

## Fixes Made

- Added public scan/verify safe fallback messages.
- Added a no-raw-HTTP assertion to signed-scan Playwright coverage.
- Added test-only JSON email capture.
- Added guarded disposable DB harness and DB-backed seed factories/tests.
- Added gated P2 real-auth E2E.
- Changed local `.env` and `backend/.env` `NODE_ENV` to `development`.

## Skipped Tests With Reasons

- P2 DB-backed API tests skip locally until `P2_TEST_DATABASE_URL` or `P2_TEST_DATABASE_ADMIN_URL` is configured.
- P2 real-auth E2E skips unless `E2E_REAL_AUTH=true` and a seeded backend is running.
- P2 reset-link E2E capture skips unless `E2E_EMAIL_CAPTURE_ENABLED=true` and `EMAIL_CAPTURE_DIR` are configured.
- Full TOTP/WebAuthn MFA remains unimplemented for browser automation because the existing flow needs proper encrypted TOTP secret provisioning and/or browser authenticator simulation.
- Positive printer pack content download remains blocked because the production route intentionally returns `410`.

## Remaining Gaps

- Add real migration-history validation once Prisma migration folders exist.
- Add CI service container for Postgres and run `npm run test:p2:api-authz-db` without skips.
- Add full invite accept and password reset E2E against captured JSON emails.
- Add full TOTP verification automation with real encrypted test secrets.
- Add WebAuthn/passkey simulation only if required for release criteria.
- Add positive printer pack content authorization once pack download is re-enabled.
- Expand DB-backed mutation coverage across QR requests, incidents, governance approvals, support responses, audit exports, and direct print-token workflows.
- Address inherited repo-wide lint debt, especially `no-explicit-any` in shared API/test files.

## Recommended P3 Automation

- Add a Docker Compose CI profile for disposable Postgres and run P2 DB tests in CI.
- Add invite/password reset E2E using JSON email capture end to end.
- Add TOTP helper that provisions encrypted test secrets through the production MFA service.
- Add content-level tests for future printer pack ZIP/PDF payloads.
- Add broader governance/support/incident mutation IDOR tests with DB assertions.
- Add production bundle secret scanning and source-map policy checks to CI.

## P3 Follow-Up Status

P3 CI-grade auth/security automation has been added in `documents/qa/mscqr-p3-ci-grade-auth-security-test-notes.md`. It adds `docker-compose.p2-test.yml`, a one-command local DB proof script, migration-backed disposable DB setup, fatal no-skip mode for CI, and `.github/workflows/auth-security-tests.yml`. Local Docker image resolution failed in this workspace, so the DB proof is wired for CI and for healthy local Docker environments but could not complete unskipped on this machine.
