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

##Real Evidence:
## Real deployed DB metadata evidence

Environment: production EC2 deployed backend container  
Checked at UTC: 2026-06-06T11:58:47.429Z  
Evidence type: read-only Prisma migration metadata query  
Command location: EC2 `/home/ubuntu/genuine-scan-main`, `docker compose exec -T backend node -`

Query scope:

```sql
SELECT
  migration_name,
  checksum,
  finished_at,
  rolled_back_at,
  applied_steps_count,
  logs
FROM "_prisma_migrations"
WHERE migration_name IN (
  '20260304113000_add_direct_print_render_tokens',
  '20260603120000_repair_batch_print_pack_schema'
)
ORDER BY migration_name;

##Result:
{
  "checkedAt": "2026-06-06T11:58:47.429Z",
  "evidenceType": "read_only_prisma_migration_metadata",
  "migrations": [
    {
      "migration_name": "20260304113000_add_direct_print_render_tokens",
      "checksum": "088de3165a0165edc50e5107f86e4198d8556d6834f6ab732b97bb5360da151a",
      "finished_at": "2026-04-26T21:29:35.875Z",
      "rolled_back_at": null,
      "applied_steps_count": 0,
      "logs": ""
    },
    {
      "migration_name": "20260603120000_repair_batch_print_pack_schema",
      "checksum": "64496c72c50ae0b9c4204765ec54fb6803555215d3b6cae00e38e75e5e52fc94",
      "finished_at": "2026-06-06T00:18:42.833Z",
      "rolled_back_at": null,
      "applied_steps_count": 1,
      "logs": null
    }
  ]
}

//Assessment:

* 20260304113000_add_direct_print_render_tokens is present in _prisma_migrations.
* It has rolled_back_at: null.
* It has empty logs.
* It has applied_steps_count: 0, so this DB did not execute schema-changing steps for that migration record.
* 20260603120000_repair_batch_print_pack_schema is present.
* It has rolled_back_at: null.
* It has applied_steps_count: 1.
* It has no error logs.

Status: GREEN for this deployed production DB metadata check.

Launch condition:

This sign-off covers the deployed DB reached by the production EC2 backend container on 2026-06-06 at 11:58:47 UTC. If staging uses a separate DB, run the same read-only metadata query against staging before marking staging Green.//
