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
- Confirm the SQL files are outside `backend/prisma/migrations`.
- Confirm no hardcoded user IDs, licensee IDs, org IDs, batch IDs, printer IDs, emails, tokens, hostnames, secrets, or production references were added.
- Confirm reviewer approval for `mscqr_staging_app_role`. The candidate and rollback templates require `-v mscqr_staging_app_role=<reviewed_staging_app_db_role>`.
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

## Disposable Harness Gate

Before manual staging apply, the disposable SQL harness must pass against a local disposable database.

Non-mutating guard/unit check:

```bash
npm run check:rls:disposable-sql-harness
```

Full disposable apply/rollback proof placeholder:

```bash
MSCQR_DISPOSABLE_RLS_HARNESS_CONFIRM=MSCQR_RUN_DISPOSABLE_RLS_HARNESS \
MSCQR_DISPOSABLE_RLS_DATABASE_URL="$LOCAL_DISPOSABLE_RLS_HARNESS_DATABASE_URL" \
MSCQR_DISPOSABLE_RLS_APP_ROLE="$LOCAL_DISPOSABLE_APP_DB_ROLE" \
node scripts/run-disposable-rls-sql-harness.mjs --prepare-schema --run-route-tests
```

The disposable database URL must be local-only and the database name must include `rls_harness`, `disposable`, `test`, or `ci`. The harness refuses staging, production, RDS, AWS, Supabase, Neon, Render, Railway, public-host, and non-local/shared-looking database URLs. It also refuses `PUBLIC` as the app role and prints sanitized connection metadata only, never a full database URL or password.

The harness proves:
- candidate SQL applies cleanly to the disposable schema
- expected `app_rls` helpers exist after apply
- expected candidate SELECT policies exist after apply
- candidate tables have RLS and FORCE RLS enabled after apply
- optional route-specific runtime tests pass in disposable P2 databases when `--run-route-tests` is used
- rollback SQL runs cleanly
- expected candidate policies, helpers, schema objects, and table RLS settings are removed after rollback

The harness does not replace manual SQL review, baseline capture, staging snapshot approval, or CloudWatch proof-event validation.

## Manual psql Command Placeholders

Use placeholders only. Do not write real secrets or hostnames into repository files or PR comments.

Review-only parse in a safe disposable environment:

```bash
psql "$STAGING_REVIEW_DATABASE_URL" \
  -v ON_ERROR_STOP=1 \
  -v mscqr_staging_app_role="$REVIEWED_STAGING_APP_DB_ROLE" \
  -f documents/security/mscqr_staging_rls_candidate_templates_2026-07-09.sql
```

Rollback in the same staging validation window if needed:

```bash
psql "$STAGING_REVIEW_DATABASE_URL" \
  -v ON_ERROR_STOP=1 \
  -v mscqr_staging_app_role="$REVIEWED_STAGING_APP_DB_ROLE" \
  -f documents/security/mscqr_staging_rls_candidate_rollback_2026-07-09.sql
```

The placeholder `STAGING_REVIEW_DATABASE_URL` must be resolved from private operator tooling, not committed or printed.
The placeholder `REVIEWED_STAGING_APP_DB_ROLE` must be the exact reviewed staging app DB role and must not be `PUBLIC`.

## Apply Order

1. Keep all route flags disabled.
2. Capture baseline outputs for the three candidate endpoints.
3. Confirm staging DB snapshot and rollback readiness.
4. Apply `mscqr_staging_rls_candidate_templates_2026-07-09.sql` manually in staging.
5. Run read-only smoke checks with flags still disabled to detect broad staging regressions caused by table RLS enablement.
6. Enable only `MSCQR_STAGING_RLS_MANUFACTURER_PRINTERS_READ_ENABLED`.
7. Validate `GET /api/manufacturer/printers`.
8. Disable the printer flag.
9. Enable only `MSCQR_STAGING_RLS_BATCHES_READ_ENABLED`.
10. Validate `GET /api/qr/batches`.
11. Disable the batch-list flag.
12. Enable only `MSCQR_STAGING_RLS_BATCH_ALLOCATION_MAP_ENABLED`.
13. Validate `GET /api/qr/batches/:id/allocation-map`.
14. Disable the allocation-map flag.

Do not enable all three flags together during first validation.

## Rollback Order

1. Disable every staged RLS route flag.
2. Run `mscqr_staging_rls_candidate_rollback_2026-07-09.sql` manually in staging.
3. Confirm candidate policies are gone.
4. Confirm candidate helper functions are gone.
5. Confirm table RLS and FORCE RLS are disabled for the candidate table set.
6. Re-run read-only baseline endpoint checks.
7. Escalate to staging snapshot restore only if rollback does not restore expected behavior.

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
- The template intentionally adds SELECT policies only. Staging writes to these tables may fail during the validation window unless the active app role bypasses RLS or the test window avoids those writes.
- Helper grants are scoped to the reviewed `mscqr_staging_app_role` only. Rollback revokes candidate helper function signatures from that role and revokes schema usage only when rollback removes the candidate-created `app_rls` schema, so unrelated helpers are not disrupted.
- Raw SQL summaries are sensitive to left-join visibility. Validate IDs and counts, not only HTTP 200.
- Batch allocation-map lineage relies on linked-licensee access to preserve parent/root/source visibility for authorized focus batches.
- Printer local-agent policies depend on the PR #109 transaction-aware read graph; do not validate these SQL templates against older backend revisions.

## Senior Engineering Recommendation

After this manual template review, the next best hardening is a disposable-db SQL harness that applies these templates, runs the three route-specific runtime tests, proves rollback symmetry, and emits a redacted policy coverage report. The best scalability feature is a small staging RLS proof dashboard with route, flag, context class, row-count delta, failure category, and p95 duration so manual validation stops depending on log spelunking.
