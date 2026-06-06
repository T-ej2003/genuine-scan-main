# MSCQR Prisma Checksum Sign-off

Date: 2026-06-06
Status: Yellow until staging and production read-only metadata evidence is attached.

## Scope

This sign-off covers read-only Prisma migration metadata for:

- `20260304113000_add_direct_print_render_tokens`
- `20260603120000_repair_batch_print_pack_schema`

The evidence command queries only `_prisma_migrations`; it does not run `prisma migrate`, `prisma db push`, `prisma migrate resolve`, or any DB mutation.

## Automated Evidence Command

Use staging/prod read-only credentials supplied through the environment. Do not echo the URL.

```bash
PRISMA_CHECKSUM_ENABLED=true \
PRISMA_CHECKSUM_REQUIRED=true \
PRISMA_CHECKSUM_ENVIRONMENT=staging \
PRISMA_CHECKSUM_DATABASE_URL="$STAGING_READONLY_DATABASE_URL" \
npm run smoke:prisma-checksum
```

Repeat for production:

```bash
PRISMA_CHECKSUM_ENABLED=true \
PRISMA_CHECKSUM_REQUIRED=true \
PRISMA_CHECKSUM_ENVIRONMENT=production \
PRISMA_CHECKSUM_DATABASE_URL="$PROD_READONLY_DATABASE_URL" \
npm run smoke:prisma-checksum
```

Expected Green result:

- `ok: true`
- both migration rows present
- `finished: true`
- `rolledBack: false`
- `logsPresent: false`
- `checksumMatches: true`

Any `checksum_mismatch`, `db_row_missing`, `rolled_back`, `not_finished`, or `logs_present` result is Yellow/Red and requires DBA/CTO review before launch.

## Manual SQL Fallback

If the script cannot run, execute this read-only SQL through an approved DB console:

```sql
SELECT migration_name, checksum, started_at, finished_at, rolled_back_at, applied_steps_count, logs
FROM "_prisma_migrations"
WHERE migration_name IN (
  '20260304113000_add_direct_print_render_tokens',
  '20260603120000_repair_batch_print_pack_schema'
)
ORDER BY migration_name;
```

Attach redacted evidence showing only migration metadata, environment, timestamp, release SHA, and operator. Do not include connection strings.

## Current Sign-off

- Staging: Yellow, awaiting read-only evidence.
- Production: Yellow, awaiting read-only evidence.
- Local mutation: None.

CTO recommendation: keep this launch blocker open until both environments have matching, timestamped evidence tied to the intended release SHA.
