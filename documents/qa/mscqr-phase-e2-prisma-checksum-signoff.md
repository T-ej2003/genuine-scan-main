# MSCQR Phase E2 Prisma Checksum Sign-off

Date: 2026-06-06
Status: Yellow until staging/prod read-only metadata evidence is attached.

## Scope

At-risk migrations:

- `20260304113000_add_direct_print_render_tokens`
- `20260603120000_repair_batch_print_pack_schema`

Repo files inspected:

- `documents/qa/mscqr-migration-checksum-audit-runbook.md`
- `backend/prisma/migrations/20260304113000_add_direct_print_render_tokens/migration.sql`
- `backend/prisma/migrations/20260603120000_repair_batch_print_pack_schema/migration.sql`

## Safe automation status

No staging or production database credentials were available in the local environment during Phase E2. No staging/prod DB queries were run and no sign-off is faked.

## Manual read-only sign-off checklist

Run only with staging/prod credentials owned for launch verification. Do not print DB URLs, passwords, or connection strings in tickets/logs.

1. Connect read-only to staging.
2. Run:

```sql
SELECT migration_name, checksum, started_at, finished_at, rolled_back_at, applied_steps_count, logs
FROM _prisma_migrations
WHERE migration_name IN (
  '20260304113000_add_direct_print_render_tokens',
  '20260603120000_repair_batch_print_pack_schema'
)
ORDER BY migration_name;
```

3. Confirm both rows exist.
4. Confirm `finished_at IS NOT NULL`.
5. Confirm `rolled_back_at IS NULL`.
6. Confirm `applied_steps_count > 0`.
7. Confirm `logs IS NULL OR logs = ''`.
8. Compare the returned checksums against the checksums recorded from the same migration SQL files in this repository revision.
9. Repeat the same read-only query for production.
10. Attach redacted evidence showing only `migration_name`, checksum/state fields, environment name, timestamp, and operator.

## Launch readiness

- Staging checksum sign-off: Yellow, pending read-only evidence.
- Production checksum sign-off: Yellow, pending read-only evidence.
- DB mutation performed by Phase E2: None.

CTO recommendation: keep this gate Yellow, not Green, until both environments have a redacted `_prisma_migrations` evidence capture tied to the intended release SHA.
