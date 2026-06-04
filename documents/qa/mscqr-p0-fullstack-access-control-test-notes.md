# MSCQR P0 Full-Stack Access-Control Test Notes

## Scope

This P0 pass adds automated frontend and backend coverage for the highest-risk access-control and frontend trust surfaces discovered in the current codebase. It intentionally avoids broad product refactors and uses the repository's existing test tools.

## Files Changed

- `e2e/helpers/p0-trust-mocks.ts`
- `e2e/p0-access-control.spec.ts`
- `e2e/p0-qr-verification-states.spec.ts`
- `e2e/p0-ui-cleanliness.spec.ts`
- `backend/tests/p0FullstackAuthorization.test.js`
- `documents/qa/mscqr-p0-frontend-route-access-matrix.md`
- `documents/qa/mscqr-p0-backend-authorization-route-matrix.md`
- `documents/qa/mscqr-p0-fullstack-access-control-test-notes.md`
- `package.json`
- `backend/package.json`

## Frontend Tests Added

- `e2e/p0-access-control.spec.ts`
  - Public route auth-bootstrap checks.
  - Anonymous protected-route redirects.
  - Role-specific direct URL access checks for `super_admin`, `licensee_admin`, and `manufacturer`.
  - Role-specific sidebar visibility checks.
  - Invalid/expired session redirect behavior.
  - Logout clearing and protected-route recheck.
- `e2e/p0-qr-verification-states.spec.ts`
  - Public valid/genuine QR result.
  - Invalid/not-found QR result.
  - Blocked/revoked-style QR result.
  - Not-ready/pending QR result.
  - Suspicious duplicate/repeated scan result.
  - Network/API failure result.
  - Mobile valid-result smoke.
- `e2e/p0-ui-cleanliness.spec.ts`
  - Public, auth, QR, and key platform pages are scanned for visible production-facing leaks such as raw JSON, stack traces, placeholder values, TODO/FIXME, debug/internal markers, localhost URLs, exposed JWT-looking strings, bearer tokens, AWS keys, API key/secret assignments, and seed/test fixture labels.

## Backend/API Tests Added

- `backend/tests/p0FullstackAuthorization.test.js`
  - Uses the existing compiled Node test style.
  - Builds a small Express harness with real compiled `authenticate`, RBAC middleware, and tenant isolation middleware.
  - Calls representative protected API paths directly, without frontend involvement.
  - Covers anonymous, invalid-token, expired-token, wrong-role, correct-role, query/body tenant tampering, manufacturer linked-licensee checks, platform-only actions, and safe denial responses.

## Routes Covered

Frontend P0 route coverage includes:

- Public: `/`, `/trust`, `/platform`, `/solutions/brands`, `/verify`, `/help/customer`.
- Protected: `/dashboard`, `/licensees`, `/code-requests`, `/batches`, `/scan-activity`, `/manufacturers`, `/audit-history`, `/incident-response`, `/support`, `/release-readiness`, `/governance`, `/settings`, `/account`, `/printer-setup`.

## API Routes Covered

Backend P0 direct API coverage includes representative routes for:

- `/licensees`
- `/users`
- `/users/:id`
- `/qr/batches`
- `/admin/qr/analytics`
- `/admin/qrs/:id/block`
- `/manufacturer/print-jobs`
- `/ir/incidents`
- `/governance/feature-flags`

The backend authorization matrix documents additional discovered protected API groups as P1/P2 pending where not yet directly automated.

## Roles Covered

- Frontend normalized roles: `super_admin`, `licensee_admin`, `manufacturer`.
- Backend raw roles/aliases represented in tests and matrices: `SUPER_ADMIN`, `LICENSEE_ADMIN`, `MANUFACTURER`.
- Additional discovered aliases documented for follow-up: `PLATFORM_SUPER_ADMIN`, `ORG_ADMIN`, `MANUFACTURER_ADMIN`, `MANUFACTURER_USER`.

## Tenant/Org/Manufacturer/Licensee Scope Checks Covered

- Licensee admin can access own `licenseeId`.
- Licensee admin is denied when changing `licenseeId` in query params.
- Licensee admin is denied when changing `licenseeId` in request body.
- Manufacturer can access a linked licensee.
- Manufacturer is denied for another licensee.
- Manufacturer is denied for platform-only QR block action.
- Licensee admin is denied for manufacturer-only print-job creation.
- Platform admin can access platform-only routes.

## QR States Covered

- Valid/genuine.
- Invalid/not found.
- Blocked/revoked-style state via `publicOutcome: BLOCKED`.
- Not-ready/pending state via `publicOutcome: NOT_READY`.
- Suspicious duplicate/repeated scan via `classification: SUSPICIOUS_DUPLICATE`.
- Network/API failure.
- Mobile valid-result rendering.

## Production UI Cleanliness Covered

The visible text detector covers:

- Public pages: `/`, `/trust`, `/platform`.
- Auth pages: `/login`, `/forgot-password`.
- QR result page: `/verify/VALID-CLEAN-P0`.
- Platform pages for all key roles: dashboard, licensees, QR requests, batches, scan activity, audit history, incident response, support, governance, printer setup, settings.

Allowlist decisions:

- The backend safe-error test allows the project's legitimate text `No token provided` while still rejecting bearer/JWT-looking secrets.
- The UI cleanliness detector avoids overly broad words such as plain `demo`, because marketing/help copy can legitimately use that word. It checks specific inappropriate labels such as `demo mode`, `seed data`, and `fixture data`.

## Commands To Run

- `npm run test:p0:fullstack-auth`
- `npm test`
- `npm run typecheck`
- `npm run build`
- `npm --prefix backend run test:p0-authz`

## Test Results

- `npm run test:p0:fullstack-auth`: passed.
  - Playwright: 91 passed.
  - Backend P0 authz: build passed and `p0 full-stack authorization regression test passed`.
- `npm test`: passed.
  - Vitest: 43 files passed, 127 tests passed.
- `npm run typecheck`: passed.
- `npm run build`: passed.
- `npm --prefix backend run test:p0-authz`: passed.

## Known Gaps And Blockers

- Playwright Chromium was missing locally and had to be installed with `npx playwright install chromium`.
- The dev server prints non-fatal proxy warnings for `/api/printer-agent/local/claim` during tests when no local printer agent/backend is running. Tests still pass, but P1 should mock or suppress local-agent polling in E2E fixtures.
- `.env` currently contains `NODE_ENV=production`, and Vite warns that this is unsupported for development build mode. This did not fail tests, but should be cleaned up in environment configuration.
- Backend P0 tests use an Express harness with real middleware and mocked user/token data. They prove direct API protection independent of frontend hiding, but do not yet exercise the full production router plus real test database.
- Full auth form flows, MFA challenge flows, invite acceptance, password reset, signed scan token flow, export file contents, and all mutation controllers remain P1/P2 coverage.

## Real Bugs Found

- No confirmed frontend route-guard, QR privacy, production cleanliness, or backend authorization bypass was found in this P0 pass.
- Automation defects fixed during implementation:
  - The first Playwright mock matcher was too broad and intercepted Vite source modules containing `/auth/`; it now only handles fetch/xhr/eventstream requests.
  - Strict locator assertions were tightened for duplicate public footer/header links.
  - Backend safe-error detector was narrowed so the legitimate `No token provided` response does not falsely fail while still detecting leaked bearer/JWT material.

## Recommended Next P1 Automation Work

- Add a real backend test-app factory with Supertest or the repo's preferred equivalent so protected production routers can be exercised without a live environment.
- Add seeded E2E coverage for real login/MFA/logout flows using `e2e/fixtures/authenticated.ts`.
- Add frontend tests for legacy redirects and help-role redirects.
- Add signed `/scan?t=` QR verification tests and customer verification session tests.
- Add direct API mutation tests for exports, support workflows, governance mutations, QR request approval/rejection, batch assignment, and incident response actions.
- Add E2E fixture suppression/mocking for local printer-agent polling to remove proxy noise and improve scalability of manufacturer-role tests.
