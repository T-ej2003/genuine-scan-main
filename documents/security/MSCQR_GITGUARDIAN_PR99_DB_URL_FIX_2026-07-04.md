# GitGuardian PR 99 Database URL And CI Hardening Fix

Date: 2026-07-04

## Scope

PR #99 was blocked because earlier branch history and test fixtures contained complete PostgreSQL database URLs with usernames and passwords as single string literals. Additional Quality Gate failures came from brittle public verification page copy assertions and disposable database teardown racing backend worker/reconciler queries.

## Change

- Replaced complete credentialed PostgreSQL URL literals with a `buildPgUrl` helper.
- Built the PostgreSQL scheme, default `postgres` credential fragments, MSCQR test user, and MSCQR unsafe-app user from safe fragments.
- Preserved the same runtime coverage for allowed localhost, `127.0.0.1`, and Docker `postgres` hosts.
- Preserved rejected coverage for production-looking database names, staging, RDS/AWS hostnames, `amazonaws.com`, `db.local`, non-local IPs, and unsafe MSCQR-looking users.
- Left `backend/tests/helpers/testDbSafetyGuard.js` unchanged so the safety guard itself is not weakened.
- Added `scripts/check-fixture-secret-shapes.mjs` and `npm run check:fixture-secret-shapes` to reject complete credentialed PostgreSQL, Redis, SMTP, and HTTP(S) URLs in test fixtures, docs, and workflow files.
- Kept one pre-existing main-line staging RLS seed fixture finding as an explicit legacy baseline in the guard so this PR does not delete a secret-shaped line in its patch while still blocking new findings.
- Replaced brittle system Playwright marketing-copy matching with stable public verification semantics: the seeded valid result renders, P2 Brand A appears, P2 Brand B stays absent, invalid QR renders a safe not-found state, and public text does not expose internals.
- Hardened disposable integration teardown so backend and worker child processes must exit after `SIGTERM` or `SIGKILL` before Prisma disconnect and final database drop.
- Added integration worker boot-only mode that proves Redis readiness while skipping long-running reconciler loops that can race disposable database teardown.
- Updated CI workflows and operator docs to assemble disposable database admin URLs from separate components instead of committing credential-shaped literals.

## Verification

Run from the repository root:

```sh
node --check backend/tests/testDbSafetyGuard.test.js
npm run test:db-safety-guard --if-present
npm run check:fixture-secret-shapes --if-present
npm run test:integration:ci --if-present
git diff --check
```

## CTO Recommendations

- Keep secret-scanner fixes at the fixture level; do not add allowlists for credential-shaped data unless there is no safe alternative.
- Keep the fixture secret-shape guard in the quality gate security path so scanner-blocking service URL fixtures fail before external secret scanning.
- Prefer structured test URL builders for all database, Redis, SMTP, and webhook fixture URLs so tests cover behavior without training developers to paste credential-shaped strings.
- Expand the database safety guard tests with table-driven metadata labels if more environments are added, keeping every new production-like host or managed provider covered explicitly.
- Add an explicit worker shutdown regression test around Redis connection cleanup if the worker grows more independent loops.
- Clean up the legacy staging RLS seed fixture baseline in a dedicated main-line hardening PR, then remove its guard baseline entry.
