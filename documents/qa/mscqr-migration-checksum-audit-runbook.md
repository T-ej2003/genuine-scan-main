# MSCQR Migration Checksum Audit Runbook

## Scope

This runbook covers the deployment risk created when `backend/prisma/migrations/20260304113000_add_direct_print_render_tokens/migration.sql` was edited to make fresh Postgres migration replay work again.

It is for staging, production, or any shared database that may already have applied the old version of that migration.

## Why This Matters

Prisma records applied migrations in the `_prisma_migrations` table. Each row includes the migration name, checksum, timestamps, logs, and applied step count.

If a migration file is edited after a database has already applied it, the checksum stored in the database may not match the checksum Prisma calculates from the current repo file. Fresh disposable databases now replay correctly, but an already-migrated shared database may need an explicit audit and remediation plan before the next `prisma migrate deploy`.

## Migration At Risk

Migration:

```text
20260304113000_add_direct_print_render_tokens
```

Reason:

- The original migration referenced `"PrintJob"` before any migration created that table.
- The repaired repo version now creates `"PrintJob"` and `QRCode.printJobId` before creating `PrintRenderToken`.
- That edit changes the historical migration file contents and may change the Prisma checksum for databases that applied the old version.

## What Not To Do

- Do not run `prisma db push` against staging or production to bypass migration history.
- Do not delete rows from `_prisma_migrations`.
- Do not mark migrations as resolved without DBA/CTO-level review.
- Do not run destructive reset/drop commands against shared databases.
- Do not deploy with production secrets in local shells or CI logs.
- Do not assume a fresh CI replay pass means an already-migrated production database has no checksum risk.

## Pre-Audit Requirements

- Confirm you are connected to the intended staging or production database.
- Take a database snapshot or backup first.
- Use read-only credentials for the audit query where possible.
- Have the current repo checkout at the exact commit intended for deployment.
- Confirm `npm run test:p3:migration-gate` and `npm run test:p3:auth-security-db` pass locally or in CI against disposable Postgres.

## Check Whether The Migration Was Applied

Run this against the shared database:

```sql
SELECT
  migration_name,
  checksum,
  finished_at,
  rolled_back_at,
  applied_steps_count,
  logs
FROM "_prisma_migrations"
WHERE migration_name = '20260304113000_add_direct_print_render_tokens';
```

Expected interpretations:

- No row: the database has not applied this migration yet.
- One row with `finished_at` set and `rolled_back_at` null: the database applied a version of this migration.
- Any `logs` value or `rolled_back_at` value: stop and escalate before deploy.

## If The Migration Was Not Applied

The normal forward path is available:

1. Confirm the DB is backed up.
2. Confirm this repo version passed the CI check `Auth Security Tests / db-backed-auth-security`.
3. Run the standard deployment migration step:

```bash
npm --prefix backend exec -- prisma migrate deploy --schema prisma/schema.prisma
```

4. Verify the migration appears in `_prisma_migrations`.
5. Run post-deploy smoke tests and auth/security checks appropriate for the environment.

## If The Old Migration Was Already Applied

Stop and choose one remediation path after DBA/CTO review.

### Option A: Restore Historical File And Move Changes Forward

Use this when the old migration has already shipped broadly.

1. Restore `20260304113000_add_direct_print_render_tokens/migration.sql` to the exact applied historical contents.
2. Keep the schema repair in a forward-only migration.
3. Validate fresh replay from zero.
4. Validate the shared DB can apply only the new forward migration.
5. Deploy after backup and approval.

Tradeoff: this may require reconstructing the old migration exactly from git history or a known deployed artifact.

### Option B: Prisma Resolve With Explicit Review

Use this only when the database schema already matches the intended repaired state and the only mismatch is the checksum metadata.

1. Back up the database.
2. Capture current `_prisma_migrations` row state.
3. Compare actual schema objects for `PrintJob`, `QRCode.printJobId`, and `PrintRenderToken`.
4. Confirm no migration SQL still needs to run.
5. Use Prisma migration resolution only with written approval.

Do not use this option to hide real schema drift.

### Option C: Controlled Forward Repair

Use this when the old migration applied but the database lacks some current schema objects.

1. Keep historical migration contents aligned with the applied checksum.
2. Add a new forward-only repair migration for missing objects.
3. Validate against a cloned staging database before production.
4. Deploy after backup and approval.

## Schema Checks To Run

Fresh replay and drift checks:

```bash
npm run test:p3:migration-gate
```

Full DB-backed auth/security proof:

```bash
npm run test:p3:auth-security-db
```

Full P3 regression:

```bash
npm run test:p3:fullstack
```

Shared DB read-only spot checks:

```sql
SELECT to_regclass('"PrintJob"') AS print_job_table;
SELECT to_regclass('"PrintRenderToken"') AS print_render_token_table;

SELECT column_name
FROM information_schema.columns
WHERE table_name = 'QRCode'
  AND column_name IN ('printJobId', 'tokenHash', 'tokenNonce', 'printedAt');
```

## Pre-Deploy Checklist

- [ ] CI check `Auth Security Tests / db-backed-auth-security` is green for the deploy commit.
- [ ] `npm run test:p3:migration-gate` passes against disposable Postgres.
- [ ] `_prisma_migrations` was checked in the target shared DB.
- [ ] The checksum/remediation path is documented in the release notes.
- [ ] A fresh backup or snapshot exists.
- [ ] DBA/CTO approval is recorded.
- [ ] No `prisma db push` is planned for staging or production.

## Post-Deploy Verification

- [ ] `prisma migrate deploy` completed without checksum or drift errors.
- [ ] `_prisma_migrations` contains the expected latest migration.
- [ ] `PrintJob`, `PrintRenderToken`, `BatchPrintPackToken`, and QR token columns exist.
- [ ] Backend health/version endpoint responds.
- [ ] Auth/session smoke tests pass.
- [ ] QR scan public verification smoke tests pass.
- [ ] Export/printer authorization smoke tests pass where enabled.

## Rollback Considerations

- Prefer restoring from a verified backup/snapshot if migration metadata or schema state is corrupted.
- Do not manually delete Prisma migration rows as a rollback.
- If application rollback is needed but DB schema remains forward-compatible, document the temporary state and keep migration metadata intact.
- If a forward repair migration must be reverted, create a reviewed rollback migration or restore from backup.

## Approval

Required approvers:

- CTO or delegated senior backend owner.
- DBA or infrastructure owner for staging/production databases.
- Security owner when the deployment touches auth, QR verification, printer packs, export data, or tenant isolation.

## CTO Recommendation

Make `Auth Security Tests / db-backed-auth-security` a required branch-protection check and keep `npm run test:p3:migration-gate` in CI permanently. Migration replay and drift failures are production-readiness failures, not optional QA findings.
