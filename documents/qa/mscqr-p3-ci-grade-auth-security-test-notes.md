# MSCQR P3 CI-Grade Auth/Security Test Notes

## Scope

P3 turns the P2 disposable database harness into CI-grade proof by adding local disposable Postgres infrastructure, fatal no-skip mode, migration-backed schema setup, and a focused GitHub Actions workflow for DB-backed authorization/security tests.

## Files Changed

- `docker-compose.p2-test.yml`
- `.github/workflows/auth-security-tests.yml`
- `backend/tests/helpers/p2TestDb.js`
- `backend/tests/p3MigrationReplay.test.js`
- `backend/tests/p3MigrationDrift.test.js`
- `backend/tests/helpers/p2SeedFactories.js`
- `backend/tests/p2DbAuthorization.test.js`
- `backend/prisma/migrations/20260304113000_add_direct_print_render_tokens/migration.sql`
- `backend/prisma/migrations/20260603120000_repair_batch_print_pack_schema/migration.sql`
- `src/test/index-page-navigation.test.tsx`
- `package.json`
- `backend/package.json`
- `README.md`
- `documents/qa/mscqr-p2-production-shaped-auth-security-test-notes.md`
- `documents/qa/mscqr-p3-ci-grade-auth-security-test-notes.md`
- `documents/qa/mscqr-migration-checksum-audit-runbook.md`

## Local Docker/Postgres Setup

Path: `docker-compose.p2-test.yml`

- Service: `p2-postgres`
- Image: `postgres:16`
- Local-only port: `127.0.0.1:55432`
- Admin DB: `mscqr_p2_admin_test`
- User: `mscqr_p2_test`
- Authentication: local-only Postgres trust auth bound to `127.0.0.1` for the disposable test service; app JWT/QR/cookie secrets are generated at runtime by the test wrappers.
- Storage: `tmpfs` mounted at `/var/lib/postgresql/data`
- Healthcheck: `pg_isready -U mscqr_p2_test -d mscqr_p2_admin_test`
- No production data mounts.

Local lifecycle commands:

```bash
npm run test:p2:db:up
npm run test:p2:db:down
npm run test:p2:db:reset
```

One-command local DB proof:

```bash
npm run test:p3:auth-security-db
```

Full local P3 regression command:

```bash
npm run test:p3:fullstack
```

## Required Env Vars

The one-command local proof sets the DB admin URL automatically from the ignored local env file:

```bash
P2_TEST_DATABASE_ADMIN_URL="$(node scripts/p2-test-db-env.mjs --print-admin-url)"
P2_TEST_DATABASE_REQUIRED=true
```

The backend scripts generate test-only JWT, QR signing, and auth-cookie values at runtime.

The harness also sets safe defaults for:

- `AUTH_COOKIE_SECRET_CURRENT`
- `EMAIL_USE_JSON_TRANSPORT=true`
- `EMAIL_DRY_RUN=true`

## CI Workflow

Path: `.github/workflows/auth-security-tests.yml`

Triggers:

- Pull requests.
- Pushes to `main`.
- Pushes to `codex/**`.

CI uses a GitHub Actions Postgres 16 service:

- DB: `mscqr_p2_ci_admin_test`
- User: `postgres`
- Password: generated from GitHub run metadata for the test job only.
- URL: built in the workflow from the generated test-only value.

The workflow sets `P2_TEST_DATABASE_REQUIRED=true`, so DB-backed auth/security tests fail if they would skip.

Required branch-protection check candidate:

```text
Auth Security Tests / db-backed-auth-security
```

Workflow steps:

1. Install frontend dependencies.
2. Install backend dependencies.
3. Run Prisma migration replay gate.
4. Run Prisma migration drift gate.
5. Run DB-backed auth/security proof.
6. Run P2 email capture proof.
7. Run P1 backend auth/security regressions.
8. Run P0 backend auth/security regressions.
9. Run frontend typecheck.
10. Run frontend unit tests.
11. Run frontend production build.

Playwright real-auth E2E remains gated and is not forced in this focused workflow.

## DB Harness Changes

Path: `backend/tests/helpers/p2TestDb.js`

- Adds Prisma schema validation before DB setup.
- Uses `prisma migrate deploy` when migration folders exist.
- Falls back to `prisma db push --skip-generate` only if no migration folders exist.
- Keeps URL guardrails:
  - PostgreSQL only.
  - DB name must contain `test`, `p2`, `ci`, `tmp`, or `temporary`.
  - Production-looking URLs are rejected.
  - Non-local hosts require `P2_TEST_DATABASE_ALLOW_REMOTE=true`.
- Still drops only databases created by the harness.

## No-Skip Enforcement

Path: `backend/tests/p2DbAuthorization.test.js`

- Existing default behavior remains developer-friendly: without DB env, P2 DB tests skip.
- New CI/proof behavior: with `P2_TEST_DATABASE_REQUIRED=true`, a missing DB URL is a hard failure.

## Migration/Schema Validation Approach

The repo has real migrations under `backend/prisma/migrations`, so P3 uses:

```bash
npm --prefix backend exec -- prisma validate --schema prisma/schema.prisma
npm --prefix backend exec -- prisma migrate deploy --schema prisma/schema.prisma
```

`migrate deploy` runs only against disposable test DBs created/selected by the guarded harness. No destructive migration/reset command is run against development or production DBs.

Local migration gate commands:

```bash
npm run test:db:migrate-replay
npm run test:db:drift
npm run test:p3:migration-gate
```

The drift gate uses Prisma-supported migration diff:

```bash
prisma migrate diff \
  --from-migrations prisma/migrations \
  --to-schema-datamodel prisma/schema.prisma \
  --script \
  --shadow-database-url <disposable-test-db-url>
```

The expected clean output is `-- This is an empty migration.`. Any generated SQL fails the gate because it means migration history and `schema.prisma` drifted.

## Migration Replay Incident: PrintJob

Observed failure when running `npm run test:p3:auth-security-db` against a fresh disposable Postgres database:

```text
P3018
Migration name: 20260304113000_add_direct_print_render_tokens
ERROR: relation "PrintJob" does not exist
```

Root cause:

- `schema.prisma` currently contains `model PrintJob`, and printer/direct-print code still depends on it.
- No earlier migration created the `"PrintJob"` table.
- `20260304113000_add_direct_print_render_tokens` was the first migration to reference `"PrintJob"` through `PrintRenderToken.printJobId`.
- The table name/case was correct; the missing base table was the problem.

Fix applied:

- Edited `backend/prisma/migrations/20260304113000_add_direct_print_render_tokens/migration.sql` to create the missing base `"PrintJob"` table, indexes, foreign keys, and `QRCode.printJobId` relation before `PrintRenderToken` is created.
- Added forward repair migration `backend/prisma/migrations/20260603120000_repair_batch_print_pack_schema/migration.sql` to align the replayed schema with current `schema.prisma`, including `BatchPrintPackToken`, current QR token/status columns, licensee profile fields, print/index drift, and obsolete `ProductBatch`/`PrintPackToken` cleanup.
- Updated P2 seed fixtures to explicitly set non-null `Incident.tags`.
- Updated the DB-backed governance test to call the real super-admin feature flag contract with `licenseeId`.

Why this is safe for the disposable proof:

- The proof runs only against guarded disposable test DB names and uses `prisma migrate deploy`, not `prisma db push`.
- The historical edit is required for fresh replay because a later repair migration cannot run if an earlier migration fails.
- The added repair migration is forward-only and guarded with `IF EXISTS`/`IF NOT EXISTS` where the current migration history may vary.

Production/staging risk:

- Editing a historical migration changes its checksum for any shared database that already applied `20260304113000_add_direct_print_render_tokens`.
- Before deploying this migration history to staging/production, inspect `_prisma_migrations` in those environments. If that migration is already applied, use a controlled Prisma checksum/migration-resolution plan instead of blindly deploying the edited history.
- Use `documents/qa/mscqr-migration-checksum-audit-runbook.md` for the required audit and remediation paths.
- The safest long-term CTO-level recommendation is to add migration replay to required CI and establish a policy that generated migrations are never manually deleted or left drifted from `schema.prisma`.

## Mutation/IDOR Coverage

No new route assertions were added in P3 because the priority was making the existing P2 DB suite run under local/CI infrastructure.

Existing P2 DB-backed coverage includes:

- Auth/login and auth/me denial/success.
- Batch list scoping.
- Batch rename cross-tenant mutation denial plus DB non-mutation proof.
- QR CSV export content isolation.
- Signed scan public tenant isolation.
- Support ticket role denial and platform access.
- Incident list/get cross-tenant IDOR denial.
- Governance feature flag role denial/platform access.
- Compliance pack cross-tenant download denial.
- Printer pack own disabled response and cross-tenant denial/no content leak.

## Real Auth E2E Status

`e2e/p2-real-auth-db.spec.ts` remains gated by `E2E_REAL_AUTH=true`.

P3 does not force real-auth browser tests in CI because that requires starting the backend, frontend, seeded DB credentials, and optional JSON email capture in a browser workflow. The path remains ready for a future dedicated workflow.

## Commands Run

```bash
npm run test:p3:auth-security-db
npm run test:db:migrate-replay
npm run test:db:drift
npm run test:p3:migration-gate
docker compose -f docker-compose.p2-test.yml up -d --wait p2-postgres
npm --prefix backend exec -- prisma validate --schema prisma/schema.prisma
npm run test:p3:fullstack
npm run typecheck
npm test
npm run build
npm --prefix backend run test:p0-authz
npm --prefix backend run test:p1:api-authz
npx eslint backend/tests/p3MigrationReplay.test.js backend/tests/p3MigrationDrift.test.js backend/tests/helpers/p2TestDb.js
```

## Test Results

- `npm run test:p3:auth-security-db`: passed unskipped after migration repair.
- `docker compose -f docker-compose.p2-test.yml up -d --wait p2-postgres`: passed; disposable Postgres became healthy.
- Prisma schema validation: passed.
- Prisma migration replay from zero with `prisma migrate deploy`: passed; 39 migrations applied successfully.
- Prisma migration drift detection: passed with empty migration diff.
- P2 DB-backed authorization and content tests: passed unskipped.
- `npm run test:p3:fullstack`: passed after the stale homepage navigation unit test was updated to the current production H1/copy.
- P2 JSON email capture: passed.
- P1 backend API authorization and signed scan-token integration: passed.
- P0 backend full-stack authorization regression: passed.
- `npm run typecheck`: passed.
- `npm test`: passed, 43 files / 127 tests.
- `npm run build`: passed.
- Targeted ESLint for new/changed migration gate files: passed.

## Did DB Tests Run Unskipped?

Yes. `npm run test:p3:auth-security-db` created a fresh disposable database, ran `prisma validate`, replayed all migrations with `prisma migrate deploy`, seeded real DB fixtures, and completed the DB-backed authorization/content tests without skipping.

## Skipped Tests With Reasons

- Real-auth E2E remains gated by `E2E_REAL_AUTH=true`.
- Invite/reset browser flows with JSON email capture remain gated by backend/frontend orchestration.
- Positive printer pack content checks remain blocked by the production route returning intentional `410`.

## Remaining Gaps

- Verify `.github/workflows/auth-security-tests.yml` on GitHub Actions.
- Verify shared/staging/prod Prisma migration checksums before deploying the edited historical migration.
- Add real-auth browser CI workflow if product leadership wants seeded browser auth proof on every PR.
- Add broader DB-backed mutation tests for QR requests, support responses, incident updates, governance approvals, and printer direct-print token workflows.
- Add positive printer pack ZIP/PDF content assertions once pack downloads are re-enabled.

## Recommended P4 Automation

- Run P3 DB proof in CI and make it a required branch protection check.
- Add a dedicated seeded real-auth E2E CI job using JSON email capture.
- Add TOTP provisioning helpers through the production MFA service.
- Expand DB-backed mutation IDOR tests across all admin mutation surfaces.
- Add export artifact content tests for reports, audit bundles, compliance packs, and future printer pack files.
