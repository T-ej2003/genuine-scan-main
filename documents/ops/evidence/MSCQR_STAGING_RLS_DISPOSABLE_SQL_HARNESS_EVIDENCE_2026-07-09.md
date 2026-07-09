# MSCQR Staging RLS Disposable SQL Harness Evidence

Date: 2026-07-09
Scope: local disposable database mechanical proof
Production impact: none

## Summary

The disposable RLS SQL harness was run locally from clean `main` against local Docker Postgres only.

No staging database was touched.
No production database was touched.
No SQL was applied outside the disposable local database.
No Prisma migrations were created.
No RLS flags were enabled.
No Terraform apply was run.
Production was not touched.

Route runtime tests were intentionally skipped in this mechanical proof. This run proves candidate SQL apply/rollback mechanics only; route runtime proof and baseline capture remain required before any manual staging apply.

## Command Shape

The local run used this shape:

```bash
npm run test:p2:db:up
unset DATABASE_URL
unset TEST_DATABASE_URL
unset P2_TEST_DATABASE_URL
MSCQR_DISPOSABLE_RLS_HARNESS_CONFIRM=MSCQR_RUN_DISPOSABLE_RLS_HARNESS
MSCQR_DISPOSABLE_RLS_DATABASE_URL=<local disposable PostgreSQL URL>
MSCQR_DISPOSABLE_RLS_APP_ROLE=mscqr_p2_test
node scripts/run-disposable-rls-sql-harness.mjs --prepare-schema --no-evidence-file
```

The disposable database URL pointed to local Docker Postgres on `127.0.0.1:55432` and database `mscqr_p2_admin_test`. The full database URL was not recorded.

## Sanitized Result

```json
{
  "status": "passed",
  "target": {
    "protocol": "postgresql",
    "host": "127.0.0.1",
    "hostCategory": "local",
    "port": "55432",
    "databaseName": "mscqr_p2_admin_test",
    "usernamePresent": true,
    "passwordPresent": false
  },
  "checkedUrlEnv": [
    "MSCQR_DISPOSABLE_RLS_DATABASE_URL"
  ],
  "candidateSql": "documents/security/mscqr_staging_rls_candidate_templates_2026-07-09.sql",
  "rollbackSql": "documents/security/mscqr_staging_rls_candidate_rollback_2026-07-09.sql",
  "appRoleSource": "explicit",
  "prepareSchema": true,
  "routeRuntimeTests": "skipped",
  "rollbackRan": true
}
```

## Checks Passed

- `prisma_schema_prepared`
- `preexisting_candidate_objects_absent`
- `candidate_sql_applied`
- `expected_helpers_policies_and_forced_rls_present`
- `rollback_sql_ran`
- `candidate_objects_removed_after_rollback`

## What This Proves

- The candidate SQL template applies cleanly to a disposable local schema.
- The expected `app_rls` helper functions are created by the candidate template.
- The expected candidate SELECT policies are created by the candidate template.
- Candidate tables have RLS and FORCE RLS enabled after template apply.
- The rollback template runs cleanly after candidate apply.
- Candidate helper functions, policies, schema objects, and table RLS settings are removed after rollback.
- The harness safety gates accepted only local disposable database metadata for this run.

## What This Does Not Prove

- It does not prove staging data behavior.
- It does not prove endpoint baseline parity.
- It does not prove route runtime behavior under the staged RLS flags.
- It does not prove CloudWatch proof-event behavior.
- It does not replace manual SQL review.
- It does not approve manual staging apply.

## Next Recommended Step

Before any manual staging apply, run route runtime proof and baseline capture:

1. Run the disposable route-specific runtime checks against local disposable databases.
2. Capture staging baseline outputs with all RLS flags disabled.
3. Review baseline IDs, row counts, printer status fields, batch summaries, allocation-map lineage, and raw SQL count outputs.
4. Only after successful baseline review, schedule a deliberate staging-only manual SQL apply window with rollback and snapshot readiness.
