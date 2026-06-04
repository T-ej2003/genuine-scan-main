# MSCQR Phase E Support, SMTP, And Incident Workflow

## Current Problems Found

- Public `/request-access` was mailto-only and did not persist onboarding requests.
- Public `/help/support` was mostly documentation and did not give users an actionable support report path.
- Platform `/support` handled authenticated issue reports and incident tickets, but did not surface public intake or request-access records.
- SMTP transport existed, but launch readiness needed an opt-in smoke and DNS/inbox runbook.

## Screenshots Reviewed

- Public support/help page showed static compliance/help copy.
- Request-access page stated no backend endpoint was connected.
- Platform support console showed issue cards and response boxes but no request-access queue.
- Incident response already had structured tabs, but broader workflow polish remains Phase E2.

## Models And Migration Added

- Migration: `backend/prisma/migrations/20260604193000_phase_e_support_request_access/migration.sql`
- Added `RequestAccess`.
- Extended `SupportIssueReport` with public reporter/reference/context and email delivery state fields.
- No historical migrations were edited.

## Endpoints Added

- `POST /api/public/request-access`
- `POST /api/public/support`
- `GET /api/support/request-access`
- `PATCH /api/support/request-access/:id`

## Email/SMTP Behavior

- Request-access admin notification.
- Request-access requester acknowledgement.
- Public support admin notification.
- Public support acknowledgement.
- Public support reply email from platform console.
- Opt-in SMTP smoke: `npm run smoke:smtp`.
- JSON capture remains available for tests.

## Role And Scoping Behavior

- Public intake endpoints are unauthenticated but rate limited and validated.
- Request-access console endpoints are platform-admin protected.
- Existing support ticket and incident routes remain protected.
- Public support reports are stored in `SupportIssueReport`; protected listing continues through existing support route guards.

## Security, Rate Limit, And Privacy Protections

- Public endpoint IP and actor rate limits.
- Honeypot fields on public forms.
- Zod validation and request sanitizer.
- Length limits on all public fields.
- Public users receive reference codes, not internal stack traces or raw SMTP errors.
- SMTP delivery failure persists as delivery status/error code for operators.
- Email content avoids secrets and raw internal tokens.

## Tests Added Or Updated

- `backend/tests/phaseESupportIntake.test.js`
- `src/test/phase-e-public-support-forms.test.tsx`
- `e2e/phase-e-support-intake.spec.ts`
- Updated `src/test/support-center-regression.test.tsx`

## Frontend Guardrail Refactor

- `src/features/support/SupportCenterPage.tsx` was reduced below the default 700-line page threshold by extracting the issue-report cards and request-access queue into focused support feature components without changing support workflow behavior.
- The Phase E public intake API methods were also moved into a focused support-intake transport so the frontend code-size budget remains green without adding an allowlist or bypass.

## Commands Run

- `PATH=/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin npm --prefix backend run build`
- `PATH=/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin npm run typecheck`
- `PATH=/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin npx vitest run src/test/phase-e-public-support-forms.test.tsx src/test/support-center-regression.test.tsx`
- `PATH=/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin npm run test:phase-e-support`
- `PATH=/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin npm run smoke:smtp`
- `PATH=/bin:/usr/bin:/usr/local/bin:/opt/homebrew/bin:$PATH npm run test:p3:migration-gate`
- `PATH=/bin:/usr/bin:/usr/local/bin:/opt/homebrew/bin:$PATH npm run test:p3:auth-security-db`
- `PATH=/bin:/usr/bin:/usr/local/bin:/opt/homebrew/bin:$PATH npm run test:p3:fullstack`
- `git diff --check`
- `PATH=/bin:/usr/bin:/usr/local/bin:/opt/homebrew/bin:$PATH npm run check:route-rate-limit-contracts`
- `PATH=/bin:/usr/bin:/usr/local/bin:/opt/homebrew/bin:$PATH npm run check:prisma-scope-guardrails`
- `PATH=/bin:/usr/bin:/usr/local/bin:/opt/homebrew/bin:$PATH npm run check:baseline-secret-patterns`
- `PATH=/bin:/usr/bin:/usr/local/bin:/opt/homebrew/bin:$PATH npm run check:branch-secret-diff`
- `PATH=/bin:/usr/bin:/usr/local/bin:/opt/homebrew/bin:$PATH npx playwright test --config=playwright.enterprise.config.ts e2e/phase-e-support-intake.spec.ts`

## Test Results

- Backend build: passed.
- Typecheck: passed.
- Targeted frontend tests: 2 files / 5 tests passed.
- DB-backed Phase E test: passed against disposable Postgres; all 40 migrations replayed from zero.
- SMTP smoke default mode: safely skipped because `SMTP_SMOKE_ENABLED` was not set.
- P3 migration gate: passed; Prisma validate, migrate replay from zero, and drift check passed.
- P3 DB-backed auth/security gate: passed unskipped.
- P3 fullstack gate: passed, including P0/P1/P2 auth/security regressions, JSON email capture, 44 Vitest files / 130 tests, typecheck, and production build.
- Diff whitespace check: passed.
- Route rate-limit contract check: passed.
- Prisma scope guardrails: passed.
- Baseline and branch secret-pattern checks: passed.
- Phase E Playwright public intake smoke: 3 tests passed.

## Launch Readiness Impact

Phase E code readiness: Yellow.

Overall launch readiness: Red.

Phase E closes the mailto-only and static-public-support product gaps at code level, but launch readiness should stay Yellow until:

- `npm run smoke:smtp` runs with staging-owned SMTP credentials and inbox proof.
- deployed staging validates the new public forms and platform console.

Overall launch readiness remains Red because Phase D launch blockers are still unresolved in this local proof: staging/prod Prisma checksum audit proof, real deployed enterprise auth smoke, and deployed bundle hardening verification still need to be completed and recorded.

## Remaining Work

- Phase E2: richer incident-response UI for linked support issue creation, customer-facing updates, assignee ownership, and timeline polish.
- Add deployed Playwright smoke for public support/request-access once staging includes the migration.
- Decide whether request-access records need CSV export or CRM handoff.
- Add release workflow option to require SMTP smoke for staging/release contexts.

## Recommended Phase F

- Run real staging SMTP smoke and inbox placement audit.
- Seed staging-only support/request-access smoke records.
- Add deployed E2E for request-access, public support, platform support triage, and incident handoff.
- Harden operational dashboards with alerting on email delivery failures and unresolved P1/P2 support issues.
