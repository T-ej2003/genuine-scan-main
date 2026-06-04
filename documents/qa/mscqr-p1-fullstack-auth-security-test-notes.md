# MSCQR P1 Full-Stack Auth/Security Test Notes

## Scope

P1 moves the P0 tripwire suite toward stronger end-to-end proof by exercising the real Express router/middleware stack through a test-app factory, adding realistic seeded authorization fixtures, extending public signed `/scan?t=...` coverage, adding deterministic Playwright auth-flow coverage, and cleaning up E2E printer-agent polling noise.

## Files Changed

- `backend/src/app.ts` - new backend app factory that builds the Express app without listening on a port.
- `backend/src/index.ts` - production startup now imports `createBackendApp()` and preserves existing server/listener behavior.
- `backend/tests/helpers/p1TestApp.js` - P1 real-router test app, in-memory seed graph, token helpers, mocked infrastructure boundaries, and safe-denial assertions.
- `backend/tests/p1ApiAuthorizationIntegration.test.js` - P1 direct API authorization, mutation, export, and IDOR checks.
- `backend/tests/p1SignedScanTokenIntegration.test.js` - P1 signed scan-token API checks using production signing helpers.
- `backend/package.json` - added `test:p1:api-authz`.
- `e2e/p1-auth-flows.spec.ts` - P1 deterministic login/MFA/invite/password-reset Playwright coverage, plus gated seeded real-login smoke.
- `e2e/p1-signed-scan-token.spec.ts` - P1 signed `/scan?t=...` public result-state Playwright coverage.
- `src/features/layout/useManufacturerPrinterConnection.ts` - E2E-only printer polling gate.
- `playwright.enterprise.config.ts` - sets `VITE_E2E_DISABLE_PRINTER_AGENT_POLLING=true` for enterprise E2E runs.
- `vite.config.ts` - E2E-only stub for `/api/printer-agent/local/claim` to keep local connector polling from polluting Playwright output.
- `package.json` - added P1 convenience scripts.

## Backend Test-App Factory

- Factory path: `backend/src/app.ts`.
- `createBackendApp()` reuses the real Express middleware/router stack, including CORS, request parsing, sanitization, security headers, request logging, health/version routes, `/api` no-store handling, real API routes, 404 handling, and error handling.
- `backend/src/index.ts` remains responsible for environment validation, Sentry setup, worker startup, bootstrap, `listen()`, and shutdown hooks.
- Tests import the compiled app factory through `backend/tests/helpers/p1TestApp.js`, so protected routers are exercised without opening production ports.

## Seed/Factory Helpers

- Helper path: `backend/tests/helpers/p1TestApp.js`.
- Seeded roles: `SUPER_ADMIN`, `LICENSEE_ADMIN` for licensee A/B, `MANUFACTURER` for manufacturer A/B.
- Seeded tenant graph: unrelated orgs, licensees, manufacturers, products, batches, QR codes, QR allocation requests, scan logs, incidents, support reports/tickets, and print jobs.
- Token helpers use the real backend JWT service after setting test-safe secrets.
- Infrastructure boundaries are mocked only where needed: database client, audit logging, email, object storage, Redis, policy/governance side effects, dashboard side effects, QR scan side effects, and printer-support side effects.

## Backend/API Routes Covered

- Auth/session: `GET /api/auth/me`.
- Licensee/org: `GET /api/licensees`, `GET /api/licensees/export`.
- Users/team: `GET /api/users`, `PATCH /api/users/:id`.
- Manufacturers: `GET /api/manufacturers`.
- Batches/lots: `GET /api/qr/batches`, `PATCH /api/qr/batches/:id/rename`.
- QR/export/mutations: `GET /api/qr/codes/export`, `POST /api/qr/codes/signed-links`, `GET /api/qr/requests`, `POST /api/qr/requests`, `POST /api/qr/requests/:id/approve`.
- Scan history: `GET /api/admin/qr/scan-logs`.
- Incidents/fraud: `GET /api/incidents`, `GET /api/incidents/:id`, `PATCH /api/incidents/:id`, `GET /api/ir/incidents`.
- Governance: `GET /api/governance/feature-flags`.
- Support: `GET /api/support/tickets`, `GET /api/support/reports`.
- Printer workflows: `GET /api/manufacturer/print-jobs`, `POST /api/manufacturer/print-jobs`, `GET /api/manufacturer/print-jobs/:id/pack`.
- Public signed scan: `GET /api/scan?t=...`.

## Authorization Checks Covered

- Anonymous requests rejected.
- Invalid bearer token rejected.
- Expired token rejected where token expiry is supported by existing helpers.
- Wrong-role requests rejected.
- Correct-role reads accepted for selected routes.
- URL param ID tampering rejected for user, batch, incident, QR request, and printer routes.
- Request body ID tampering rejected for user, batch, QR request, and incident mutation paths.
- Query param tenant/manufacturer/licensee tampering rejected for selected list/export routes.
- Cross-tenant reads do not leak unrelated fixture rows for selected list routes.
- Cross-tenant writes do not mutate unrelated fixture rows for selected mutation routes.
- Export paths checked for wrong-role denial and selected allowed-role scoping.
- Denied responses are checked for stack traces, Prisma details, raw tokens, bearer values, JWT-looking strings, and common secret markers.

## Frontend Auth Flows Covered

- Login success through `/login` with mocked API session.
- Logout through the dashboard user menu, followed by protected route redirect back to `/login`.
- Invalid credentials show a safe message.
- MFA challenge screen appears for a pending admin session.
- MFA failure shows a safe message.
- Invite preview and invite acceptance through `/accept-invite`.
- Forgot password request through `/forgot-password`.
- Invalid/expired reset token handling through `/reset-password`.
- Role-based post-login redirect smoke through dashboard access.
- Gated seeded real-login smoke exists but is skipped unless `E2E_REAL_AUTH=true` is provided with seeded backend credentials.

## Signed QR Scan States Covered

- Backend real signed token: valid token.
- Backend real signed token: expired token.
- Backend real signed token: tampered token.
- Backend real signed token: missing token.
- Backend real signed token: token/QR mismatch or revoked-like state.
- Backend real signed token: non-existent QR/product.
- Backend real signed token: duplicate/suspicious scan response path.
- Frontend `/scan?t=...`: valid signed result.
- Frontend `/scan?t=...`: expired, tampered, revoked/deactivated, and missing token states.
- Frontend `/scan?t=...`: suspicious duplicate state on mobile.
- Public result pages are asserted not to expose admin-only fields, token hashes, bearer/JWT values, stack traces, or tenant identifiers.

## Export/Download And Mutation IDOR Checks

- Licensee export denies manufacturer role.
- QR code export denies licensee-admin role and allows super-admin scoped export.
- QR signed-link export/mutation denies licensee-admin wrong-role access.
- QR request create and approve reject cross-tenant/body tampering.
- Batch rename rejects cross-tenant URL/body/query tampering.
- User update rejects cross-tenant URL/body tampering.
- Incident read/update rejects cross-tenant IDs with safe 404/403 behavior.
- Support reports list is scoped for manufacturer role and does not include unrelated fixture rows.
- Printer job list rejects tenant/manufacturer query tampering and does not include unrelated fixture rows.
- Printer pack endpoint currently returns safe `410 Gone`; this is treated as safe denial but not full content-level IDOR proof.

## Printer-Agent Warning Cleanup

- React-side manufacturer printer polling is disabled only when `VITE_E2E_DISABLE_PRINTER_AGENT_POLLING=true`.
- Enterprise Playwright config sets that flag for E2E.
- Vite adds an E2E-only middleware stub for `/api/printer-agent/local/claim`, returning a safe no-work response.
- Production, normal development, and backend connector behavior are unchanged.

## Commands Run

- `PATH=/bin:/usr/bin:/usr/local/bin:/opt/homebrew/bin:$PATH npm --prefix backend run test:p1:api-authz`
- `PATH=/bin:/usr/bin:/usr/local/bin:/opt/homebrew/bin:$PATH npm run test:p1:e2e-auth`
- `PATH=/bin:/usr/bin:/usr/local/bin:/opt/homebrew/bin:$PATH npm run test:p1:scan`
- `PATH=/bin:/usr/bin:/usr/local/bin:/opt/homebrew/bin:$PATH npm run test:p1:fullstack`
- `PATH=/bin:/usr/bin:/usr/local/bin:/opt/homebrew/bin:$PATH npm run test:p0:fullstack-auth`
- `PATH=/bin:/usr/bin:/usr/local/bin:/opt/homebrew/bin:$PATH npm test`
- `PATH=/bin:/usr/bin:/usr/local/bin:/opt/homebrew/bin:$PATH npm run typecheck`
- `PATH=/bin:/usr/bin:/usr/local/bin:/opt/homebrew/bin:$PATH npm run build`
- `PATH=/bin:/usr/bin:/usr/local/bin:/opt/homebrew/bin:$PATH npm run lint`
- `PATH=/bin:/usr/bin:/usr/local/bin:/opt/homebrew/bin:$PATH npx eslint backend/src/app.ts`

## Test Results

- P1 backend/API authorization integration: passed.
- P1 backend signed scan-token integration: passed.
- P1 frontend auth E2E: 3 passed, 1 intentionally skipped seeded real-auth smoke.
- P1 frontend signed scan E2E: 3 passed.
- P1 full-stack script: backend P1 passed, 6 Playwright tests passed, 1 seeded real-auth smoke intentionally skipped.
- Existing P0 full-stack auth/security: 91 Playwright tests passed and backend P0 authz passed.
- Vitest: 43 files passed, 127 tests passed.
- Typecheck: passed.
- Production build: passed.
- Full lint: failed on existing repository-wide lint debt (`1146` errors and `27` warnings), mostly pre-existing `no-explicit-any` and React hook issues. The new `backend/src/app.ts` was checked separately and passes lint.

## Bugs And Fixes

- Test implementation bug fixed: Playwright `**/api/**` route mocks were intercepting Vite source imports such as `/src/lib/api/query-utils.ts`, causing blank pages. P1 mocks now continue non-`/api/` requests.
- E2E environment issue fixed: printer-agent `/api/printer-agent/local/claim` proxy warnings are now stubbed in E2E only.
- Frontend UX gap observed: non-2xx public scan failures can surface as generic `HTTP 400`/`HTTP 404` text. No stack traces or secrets were exposed, but P2 should replace these with friendlier customer-safe copy.
- No confirmed production backend authorization bypass was found in the covered P1 route set.

## Skipped Tests

- `P1 seeded real auth smoke` is skipped unless `E2E_REAL_AUTH=true` is set with a seeded backend and known credentials. This avoids silently depending on external email, production data, or a developer's local database.

## Remaining Gaps

- P1 still uses real routers/controllers with an in-memory Prisma/service test double, not a disposable migrated test database.
- Full production-router plus real test database integration remains P2.
- Real email capture for invite/password-reset is not wired into E2E yet.
- Real TOTP/WebAuthn MFA enrollment and challenge flows are not fully exercised end-to-end.
- Printer pack route is disabled with safe `410`, so export content-level authorization for generated print packs remains pending.
- Governance/support/incident mutation success paths are not exhaustive.
- Long-tail API routes beyond the selected P1 high-risk set still need matrix-driven coverage.
- Root `.env` still triggers Vite's `NODE_ENV=production is not supported` warning during dev/E2E/build.
- The local shell PATH in this workspace does not include `/bin` by default; commands were run with an explicit PATH prefix.

## Recommended P2 Automation

- Add a disposable test database lifecycle: migrate, seed, run real Express app, truncate/rollback, and assert Prisma-backed scoping.
- Add real login, invite, password reset, and MFA E2E against the seeded test backend with a JSON email transport.
- Add content-level export assertions for QR CSVs, reports, support exports, and printer packs.
- Add negative tests for every governance/support/incident mutation route, including bulk actions.
- Add public scan error-copy regression tests so API failures never show `HTTP 400`/`HTTP 404` to customers.
- Add CI jobs for `test:p0:fullstack-auth`, `test:p1:fullstack`, typecheck, build, and backend P1 authz with artifacts for Playwright reports.

## P2 Follow-Up Status

P2 production-shaped auth/security automation has been added in `documents/qa/mscqr-p2-production-shaped-auth-security-test-notes.md`. It introduces a guarded disposable PostgreSQL harness, DB-backed seed factories, content-level QR export and printer-pack denial assertions, JSON email capture, gated real-auth E2E, public scan safe-copy fixes, and local `.env` `NODE_ENV` cleanup. Remaining P2/P3 work depends on a CI/local disposable Postgres service, real Prisma migration history, full invite/reset E2E, full TOTP/WebAuthn automation, and positive printer pack payload generation.
