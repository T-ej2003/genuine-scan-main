# MSCQR Staging RLS Manual SQL Review Runbook

Date: 2026-07-09
Environment: staging only
Scope: manual review and deliberate staging execution only
Production impact: none

## Hard Warning

Do not run these SQL templates in production.

Do not place these SQL files under `backend/prisma/migrations`.
Do not run them from CI/CD, Terraform, Prisma, application startup, or automated deployment hooks.
Do not enable any RLS route flag until the SQL has been reviewed, deliberately applied in staging, and baseline evidence exists.

Templates:
- `documents/security/mscqr_staging_rls_candidate_templates_2026-07-09.sql`
- `documents/security/mscqr_staging_rls_candidate_rollback_2026-07-09.sql`

Source documents:
- `documents/ops/MSCQR_STAGING_RLS_VALIDATION_PLAN_2026-07-09.md`
- `documents/ops/MSCQR_STAGING_RLS_DB_TOUCH_MAP_2026-07-09.md`
- `documents/security/mscqr_staging_rls_prototype.sql`

## Preflight Checklist

- Confirm the target is staging, not production.
- Confirm all three route flags remain disabled:
  - `MSCQR_STAGING_RLS_BATCHES_READ_ENABLED`
  - `MSCQR_STAGING_RLS_BATCH_ALLOCATION_MAP_ENABLED`
  - `MSCQR_STAGING_RLS_MANUFACTURER_PRINTERS_READ_ENABLED`
- Confirm `DATABASE_URL` remains the existing default application read/write credential.
- Confirm `RLS_READ_DATABASE_URL` is provisioned separately for the reviewed non-owner runtime credential, does not exactly equal `DATABASE_URL`, and is not printed or copied into review evidence.
- Confirm an enabled route flag with a missing, malformed, non-PostgreSQL, database-name-less, equal-to-default, unreachable, or unsafe-posture RLS URL fails startup and readiness without falling back to the default client.
- Confirm the SQL files are outside `backend/prisma/migrations`.
- Confirm no hardcoded user IDs, licensee IDs, org IDs, batch IDs, printer IDs, emails, tokens, hostnames, secrets, or production references were added.
- Confirm the migration/owner role and runtime role are different exact PostgreSQL roles.
- Confirm reviewer approval for `mscqr_runtime_role`. The templates require `-v mscqr_runtime_role=<reviewed_non_owner_staging_runtime_db_role>`.
- Confirm the runtime role is `NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`, owns none of the 16 protected tables, and inherits no owner or bypass role.
- Confirm `PUBLIC` is not used as the helper grant target. `PUBLIC` is forbidden for this validation because staging may already have unrelated `app_rls` helpers.
- Confirm staging backend is healthy before any SQL apply window.
- Confirm rollback SQL has been reviewed in the same review session as the candidate SQL.

## Backup And Snapshot Checklist

- Take or verify a fresh staging database snapshot before applying SQL.
- Record the snapshot identifier in the private operator notes, not in this repository.
- Confirm the operator can restore staging from the snapshot if rollback is insufficient.
- Confirm the rollback template is locally available in the same terminal session.
- Confirm CloudWatch access is available for application logs and proof events.

## Dry-Run And Review Checklist

- Review the candidate template section by section before execution:
  - shared context helpers
  - non-recursive access helpers
  - shared tenant tables
  - batch and allocation-map tables
  - raw SQL summary tables
  - printer local-agent/profile/status tables
- Confirm `ManufacturerLicenseeLink` policy does not call `app_rls.can_access_licensee`.
- Confirm `PrinterRegistration` policy is a non-recursive parent policy and does not depend on `Printer`.
- Confirm `Printer` may depend on `PrinterRegistration`, but `PrinterRegistration` does not depend back on `Printer`.
- Confirm `PrinterProfileSnapshot` depends through `PrinterProfile` and visible `Printer`.
- Confirm no policy includes `Printer.isActive`; inactive behavior must stay in the application query filter.
- Confirm `PrintItem`, `PrintSession`, and `PrintJob` visibility preserves QR reservable-summary left-join count correctness.
- Confirm no write policy is added. These templates cover read-only candidate endpoints.

## Required Database Role Model

The migration/owner role applies Prisma migrations and owns schemas and tables. It is never the application runtime identity used to prove RLS. The runtime role is a distinct, non-owner role with only `CONNECT`, `USAGE` on required schemas, explicit `SELECT` on the 16 candidate tables, and `EXECUTE` on the 17 exact helper signatures. No sequence privilege is required while this candidate remains SELECT-only.

The application must preserve `DATABASE_URL` for the existing default Prisma read/write client and use `RLS_READ_DATABASE_URL` only for the staged RLS read client. The RLS URL must authenticate as the reviewed runtime role, must not exactly equal `DATABASE_URL`, and must never be derived from or fall back to either the migration/owner URL or `DATABASE_URL`. PostgreSQL table owners normally bypass RLS; `FORCE ROW LEVEL SECURITY` narrows that risk, but a dedicated non-owner remains mandatory because it makes the runtime trust boundary independently testable and prevents an owner/admin connection from becoming the staged RLS data plane.

Only these routes may use the separate client, and only when their exact flag is enabled:

| Route | Flag |
| --- | --- |
| `GET /api/qr/batches` | `MSCQR_STAGING_RLS_BATCHES_READ_ENABLED` |
| `GET /api/qr/batches/:id/allocation-map` | `MSCQR_STAGING_RLS_BATCH_ALLOCATION_MAP_ENABLED` |
| `GET /api/manufacturer/printers` | `MSCQR_STAGING_RLS_MANUFACTURER_PRINTERS_READ_ENABLED` |

The default client continues to serve every mutation and all non-staged reads. This is required because the RLS role has no INSERT, UPDATE, DELETE, or sequence privileges and no write policies. Switching the global client would break authentication, administration, batch/QR lifecycle, printing, printer management, rollups, and manufacturer-licensee link writes.

## Exact Pre-Apply Staging Checks

Run these read-only catalog checks through approved private operator tooling. Do not paste connection strings or results containing private infrastructure values into the repository.

```sql
SELECT session_user, current_user, current_role, current_setting('row_security');

SELECT rolname, rolsuper, rolcreatedb, rolcreaterole, rolreplication,
       rolbypassrls, rolcanlogin
FROM pg_roles
WHERE rolname IN ('<migration_owner_role>', '<runtime_role>');

SELECT c.relname, owner.rolname AS table_owner,
       c.relrowsecurity, c.relforcerowsecurity,
       pg_has_role('<runtime_role>', c.relowner, 'USAGE') AS runtime_owns_or_inherits_owner,
       has_table_privilege('<runtime_role>', c.oid, 'SELECT') AS runtime_has_select
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
JOIN pg_roles owner ON owner.oid = c.relowner
WHERE n.nspname = 'public'
  AND c.relname = ANY(ARRAY[
    'Organization', 'Licensee', 'User', 'ManufacturerLicenseeLink',
    'Batch', 'InventoryStatusRollup', 'QRCode', 'PrintJob', 'PrintSession',
    'PrintItem', 'PrinterRegistration', 'Printer', 'PrinterAttestation',
    'PrinterAgentSession', 'PrinterProfile', 'PrinterProfileSnapshot'
  ])
ORDER BY c.relname;

WITH RECURSIVE inherited(role_oid, role_name) AS (
  SELECT granted.oid, granted.rolname
  FROM pg_auth_members m
  JOIN pg_roles member ON member.oid = m.member
  JOIN pg_roles granted ON granted.oid = m.roleid
  WHERE member.rolname = '<runtime_role>'
  UNION ALL
  SELECT granted.oid, granted.rolname
  FROM inherited
  JOIN pg_auth_members m ON m.member = inherited.role_oid
  JOIN pg_roles granted ON granted.oid = m.roleid
)
SELECT DISTINCT role_name FROM inherited ORDER BY role_name;
```

Gate: the runtime role must have no elevated attributes, no transitive memberships, and no ownership result. Do not reapply in staging until the disposable harness, backend typecheck, changed-file lint, and document guards all pass and the runtime connection secret is independently reviewed.

The pre-apply identity evidence must come from the same private `RLS_READ_DATABASE_URL` credential and session shape that the backend will use. Capture only secret-free booleans/counts proving `session_user`, `current_user`, `current_role`, `row_security`, safe direct attributes, no inherited roles, no protected-table ownership, and the intended narrow grants. After a later candidate apply with every route flag still disabled, the first one-flag startup probe must separately prove all 16 protected tables have RLS and FORCE RLS, exact SELECT access, 16 candidate policies, and EXECUTE on the 17 exact helpers before traffic. Do not retain the URL, password, hostname, or raw connection diagnostics in repository evidence.

When any staged flag is enabled, startup connects the lazy, process-level RLS Prisma client and refuses to serve if configuration, connectivity, or the runtime posture check fails. `/health/ready` and `/health/db` treat that connection as required and report a secret-free degraded result on failure. With every flag disabled, `RLS_READ_DATABASE_URL` is optional, the second client/pool is not created, and readiness behaves as before. Graceful shutdown drains and disconnects both cached clients; requests never create or disconnect a Prisma client.

## Disposable Harness Gate

Before manual staging apply, the disposable SQL harness must pass against a local disposable database.

Non-mutating guard/unit check:

```bash
npm run check:rls:disposable-sql-harness
```

Separate-client configuration, lifecycle, readiness, and route-wiring check:

```bash
npm --prefix backend run test:rls:read-client
```

Full disposable apply/rollback proof placeholder:

```bash
npm run test:p2:db:up
createdb -h 127.0.0.1 -p 55432 -U mscqr_p2_test mscqr_rls_harness_runtime_role_test

env -u DATABASE_URL -u TEST_DATABASE_URL -u P2_TEST_DATABASE_URL \
MSCQR_DISPOSABLE_RLS_HARNESS_CONFIRM=MSCQR_RUN_DISPOSABLE_RLS_HARNESS \
MSCQR_DISPOSABLE_RLS_DATABASE_URL="postgresql://mscqr_p2_test@127.0.0.1:55432/mscqr_rls_harness_runtime_role_test" \
MSCQR_DISPOSABLE_RLS_RUNTIME_ROLE="mscqr_rls_harness_runtime_$(date +%s)" \
npm run test:rls:disposable-sql-harness

dropdb -h 127.0.0.1 -p 55432 -U mscqr_p2_test mscqr_rls_harness_runtime_role_test
```

The disposable database URL must be local-only and the database name must include `rls_harness`, `disposable`, `test`, or `ci`. The harness refuses staging, production, RDS, AWS, Supabase, Neon, Render, Railway, public-host, and non-local/shared-looking database URLs. It also refuses a missing runtime role, `PUBLIC`, reuse of the URL owner as runtime, unsafe runtime attributes, runtime table ownership, inherited roles, and candidate SQL under Prisma migrations. It prints sanitized connection metadata only, never a full database URL or password.

The harness proves:
- candidate SQL applies cleanly to the disposable schema
- expected `app_rls` helpers exist after apply
- expected candidate SELECT policies exist after apply
- candidate tables have RLS and FORCE RLS enabled after apply
- `session_user` remains the owner while `current_user` and `current_role` are the explicit non-owner runtime role for every RLS assertion
- all 17 helpers fail closed with missing context and are not executable by `PUBLIC`
- exact IDs match for platform, licensee, manufacturer, organization, unrelated-tenant, missing, malformed, empty-string, and tenant-A-to-tenant-B cases
- INSERT, UPDATE, and DELETE are denied on all 16 tables
- optional route-specific runtime tests pass in disposable P2 databases when `--run-route-tests` is used
- rollback removes policies, helpers, schema objects, table grants, and table RLS settings

The harness does not replace manual SQL review, baseline capture, staging snapshot approval, or CloudWatch proof-event validation.

Do not claim readiness unless the full disposable route run uses a separate runtime connection URL, executes all three real route/service query graphs inside one transaction each, detects any nested fallback to the default client, proves concurrent tenant context isolation and transaction-local cleanup, and confirms runtime writes are still denied.

## Manual psql Command Placeholders

Use placeholders only. Do not write real secrets or hostnames into repository files or PR comments.

Review-only parse in a safe disposable environment:

```bash
psql "$STAGING_REVIEW_DATABASE_URL" \
  -v ON_ERROR_STOP=1 \
  -v mscqr_runtime_role="$REVIEWED_NON_OWNER_STAGING_RUNTIME_DB_ROLE" \
  -f documents/security/mscqr_staging_rls_candidate_templates_2026-07-09.sql
```

Rollback in the same staging validation window if needed:

```bash
psql "$STAGING_REVIEW_DATABASE_URL" \
  -v ON_ERROR_STOP=1 \
  -v mscqr_runtime_role="$REVIEWED_NON_OWNER_STAGING_RUNTIME_DB_ROLE" \
  -f documents/security/mscqr_staging_rls_candidate_rollback_2026-07-09.sql
```

The placeholder `STAGING_REVIEW_DATABASE_URL` must be resolved from private operator tooling, not committed or printed.
The placeholder `REVIEWED_NON_OWNER_STAGING_RUNTIME_DB_ROLE` must be the exact reviewed runtime role, must not be `PUBLIC`, and must not own protected tables.

## Apply Order

This is the exact future sequence; it is documentation only and was not executed by this change:

1. Keep all route flags disabled.
2. Provision and privately review a distinct `RLS_READ_DATABASE_URL` credential for the exact non-owner runtime role; keep `DATABASE_URL` unchanged.
3. Prove runtime identity, attributes, membership, ownership, and grants from that credential without printing it.
4. Run the complete local separate-client, route, concurrent-context, write-denial, rollback, and document gates.
5. Capture baseline outputs for the three candidate endpoints.
6. Confirm staging DB snapshot and rollback readiness.
7. Apply `mscqr_staging_rls_candidate_templates_2026-07-09.sql` manually in staging.
8. Run read-only smoke checks with flags still disabled to detect broad staging regressions caused by table RLS enablement; confirm no RLS read pool exists.
9. Enable only `MSCQR_STAGING_RLS_MANUFACTURER_PRINTERS_READ_ENABLED` and restart. Startup and readiness must prove the separate RLS connection and posture before traffic.
10. Validate `GET /api/manufacturer/printers`, then disable the printer flag and restart.
11. Enable only `MSCQR_STAGING_RLS_BATCHES_READ_ENABLED` and restart.
12. Validate `GET /api/qr/batches`, then disable the batch-list flag and restart.
13. Enable only `MSCQR_STAGING_RLS_BATCH_ALLOCATION_MAP_ENABLED` and restart.
14. Validate `GET /api/qr/batches/:id/allocation-map`, then disable the allocation-map flag and restart.
15. Confirm readiness reports the RLS dependency disabled and the extra client/pool is gone; retain `DATABASE_URL` as the default read/write path.

Do not enable all three flags together during first validation.

## Rollback Order

1. Disable every staged RLS route flag.
2. Restart the affected backend process and confirm readiness reports the RLS dependency disabled, so the separate pool is drained and no route can use the runtime credential.
3. Run `mscqr_staging_rls_candidate_rollback_2026-07-09.sql` manually in staging.
4. Confirm candidate policies are gone.
5. Confirm candidate helper functions are gone.
6. Confirm table RLS and FORCE RLS are disabled for the candidate table set.
7. Re-run read-only baseline endpoint checks through the unchanged default client.
8. Escalate to staging snapshot restore only if rollback does not restore expected behavior.

Disabling the flags is the application rollback and leaves all writes on `DATABASE_URL`. The private `RLS_READ_DATABASE_URL` value may remain configured while all flags are false because it is optional and unused, but remove or rotate it after rollback according to the approved credential lifecycle. To rotate before a later validation, keep every flag false, provision/review the replacement restricted credential, update only `RLS_READ_DATABASE_URL`, restart, enable one flag so startup probes the replacement, validate, disable it again, then revoke the old login after all old processes and pools are gone.

Rollback is a go/no-go gate, not an afterthought. Before reapply approval, prove the rollback file is byte-for-byte the reviewed companion, is locally available to the operator, receives the same exact `mscqr_runtime_role`, and removes runtime table/function/schema grants as well as policies and RLS flags.

## Validation Order

Validate actor classes:
- platform admin
- licensee admin
- org admin
- manufacturer admin or user
- cross-tenant user
- missing tenant context user

Validate data cases:
- batch owned by licensee A
- batch owned by licensee B
- manufacturer child batch
- parent/root/source allocation lineage
- batch with QR codes
- batch with inventory rollup
- batch with print item, session, and job history
- network printer under scoped licensee
- network printer under another licensee
- local-agent printer assigned to current user
- local-agent printer registered by current user
- local-agent printer with latest attestation
- local-agent printer with connected agent session
- local-agent printer with profile and profile snapshot
- inactive printer with `includeInactive` behavior controlled by the application filter

Compare:
- HTTP status
- response object IDs
- row counts
- QR status summaries
- reservable QR summary counts
- printer connection/status fields
- proof event success fields

## CloudWatch Proof-Event Checks

Expected proof events:
- `staging_rls_manufacturer_printers_read_proof`
- `staging_rls_batches_read_proof`
- `staging_rls_batch_allocation_map_proof`

For each enabled flag, confirm:
- `flagEnabled=true`
- expected `contextClass`
- `success=true`
- row count or result shape matches baseline
- no `rls_context_missing`
- no `rls_context_forbidden`
- no `database_error`
- no `unexpected_error`
- no raw user, licensee, batch, printer, device, token, IP, hostname, or email identifiers appear in proof logs

## Stop And Fail Criteria

Stop immediately and disable the active flag if:
- startup succeeds when an enabled flag has missing or invalid `RLS_READ_DATABASE_URL`
- `RLS_READ_DATABASE_URL` equals `DATABASE_URL`, or runtime identity/posture cannot be proven
- the RLS client cannot connect or readiness does not become degraded on RLS dependency failure
- an enabled route query or nested helper uses the default Prisma client
- transaction-local context leaks after commit/rollback or between concurrent tenants
- any candidate endpoint returns 500
- cross-tenant data appears
- baseline and RLS-enabled object IDs differ unexpectedly
- baseline and RLS-enabled counts differ unexpectedly
- proof event is missing
- proof event reports failure
- CloudWatch shows database or RLS errors
- missing app context does not fail closed
- platform admin bypass fails
- manufacturer linked-licensee access fails
- local-agent printer status loses registration, attestation, session, profile, or snapshot data
- raw SQL reservable summaries drift from baseline

If disabling the flag is insufficient, run the rollback SQL. If rollback is insufficient, use the staging snapshot restore path.

## Remaining Review Risks

- Enabling table RLS affects staging table access globally, even though the route flags control only the staged application read paths.
- The template intentionally adds SELECT policies only. All application writes on these 16 tables are blocked for the runtime role until separately designed write policies and grants exist.
- Helper and table grants are scoped to the reviewed `mscqr_runtime_role` only. Rollback revokes the exact helper signatures and table grant and revokes schema usage only when rollback removes the candidate-created `app_rls` schema.
- Raw SQL summaries are sensitive to left-join visibility. Validate IDs and counts, not only HTTP 200.
- Batch allocation-map lineage relies on linked-licensee access to preserve parent/root/source visibility for authorized focus batches.
- Printer local-agent policies depend on the PR #109 transaction-aware read graph; do not validate these SQL templates against older backend revisions.

## Senior Engineering Recommendation

Keep the three credential purposes permanently distinct: migration/owner, default application read/write, and staged RLS read-only. Treat the implemented startup/readiness posture probe, route-scoped transaction injection, and one-extra-pool capacity as release gates. For scalability, add a staging RLS proof dashboard keyed by route, flag, context class, exact-ID delta, failure category, and p95 duration, plus a CI-generated policy-to-table coverage manifest so future tables cannot silently escape the 16-table inventory.
