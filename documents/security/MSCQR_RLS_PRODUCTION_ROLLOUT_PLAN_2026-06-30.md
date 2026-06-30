# MSCQR RLS Production Rollout Plan - 2026-06-30

This is an operations plan for a future production MSCQR Row Level Security rollout. It does not enable production RLS, does not enable global RLS, does not create Prisma migrations, does not wire additional runtime routes, and does not change the production database.

## Sources Reviewed

- Staging-only PostgreSQL RLS prototype design: `documents/security/MSCQR_STAGING_RLS_PROTOTYPE_DESIGN_2026-06-28.md`
- Staging prototype SQL: `documents/security/mscqr_staging_rls_prototype.sql`
- Staging rollback SQL: `documents/security/mscqr_staging_rls_rollback.sql`
- Runtime wiring inventory: `documents/security/MSCQR_RLS_RUNTIME_WIRING_INVENTORY_2026-06-29.md`
- Policy performance and index analysis: `documents/security/MSCQR_RLS_POLICY_PERFORMANCE_INDEX_ANALYSIS_2026-06-29.md`
- Non-applied index rollout plan: `documents/security/MSCQR_RLS_INDEX_ROLLOUT_PLAN_2026-06-29.md`
- Batch list staging wiring and proof: `documents/security/MSCQR_RLS_BATCHES_READ_STAGING_WIRING_2026-06-29.md`, `documents/security/MSCQR_RLS_BATCHES_STAGING_PROOF_2026-06-29.md`
- Batch allocation-map staging wiring: `documents/security/MSCQR_RLS_BATCH_ALLOCATION_MAP_STAGING_WIRING_2026-06-30.md`
- Manufacturer printer read staging wiring: `documents/security/MSCQR_RLS_MANUFACTURER_PRINTERS_STAGING_WIRING_2026-06-30.md`

## Current State

- Production RLS is currently not enabled.
- Application-layer tenant isolation remains the primary production protection.
- Existing controller, middleware, and service authorization must remain in place even after any future RLS rollout.
- Staged route-level RLS runtime wiring exists only for these three proven routes:
  - `GET /api/qr/batches` behind `MSCQR_STAGING_RLS_BATCHES_READ_ENABLED`
  - `GET /api/qr/batches/:id/allocation-map` behind `MSCQR_STAGING_RLS_BATCH_ALLOCATION_MAP_ENABLED`
  - `GET /api/manufacturer/printers` behind `MSCQR_STAGING_RLS_MANUFACTURER_PRINTERS_READ_ENABLED`
- No global or table-level production RLS should be enabled without explicit rollout approval, a reviewed rollback plan, and a production database change window.
- The staged route flags are route-specific proof gates, not permission to enable table RLS globally.

## Preconditions

All items below must be complete before any production rollout phase that changes runtime behavior:

- Current CI checks are green.
- Each current staged RLS flag has been tested individually in staging.
- All three current staged RLS flags have been tested together in staging.
- Staging proof telemetry has been reviewed by the rollout owner and security owner.
- Proof telemetry and generic request telemetry emit no unsafe identifiers.
- The index rollout plan has been reviewed for selected route/table candidates.
- Staging `EXPLAIN` or `EXPLAIN ANALYZE` evidence has been collected with realistic row counts for affected queries.
- A rollback owner is assigned and available for the entire production window.
- The production window is approved by engineering, operations, and business owner.
- Production DB snapshot, backup, PITR, and restore posture are confirmed before any DB change.
- Production RDS connection mode, pooling mode, and runtime role ownership behavior are understood.
- Table owner bypass and `FORCE ROW LEVEL SECURITY` behavior are accounted for.
- The production application role `BYPASSRLS` state has been checked and recorded.
- Any future table-RLS change has reviewed rollback SQL, lock timeouts, statement timeouts, and catalog verification queries.

## Staging Validation Checklist

Use this checklist before promoting any route-level behavior toward production:

1. Capture flag-off baseline response shapes, counts, status codes, p50 latency, and p95 latency for all three target routes.
2. Enable `MSCQR_STAGING_RLS_BATCHES_READ_ENABLED=true` by itself.
3. Validate `GET /api/qr/batches` for licensee, manufacturer, and platform-admin contexts.
4. Compare response shapes and counts against the flag-off baseline.
5. Check p50 and p95 latency against the target threshold.
6. Check `staging_rls_batches_read_proof` telemetry for success rate, duration, row count, context class, and failure category.
7. Unset the batch-list flag and confirm fallback to the non-RLS cached read path.
8. Enable `MSCQR_STAGING_RLS_BATCH_ALLOCATION_MAP_ENABLED=true` by itself.
9. Validate `GET /api/qr/batches/:id/allocation-map` for owned, linked-manufacturer, and unauthorized contexts.
10. Compare response shapes and status behavior against the flag-off baseline.
11. Check p50 and p95 latency against the target threshold.
12. Check `staging_rls_batch_allocation_map_proof` telemetry for success rate, duration, result shape, context class, and failure category.
13. Unset the allocation-map flag and confirm fallback to the non-RLS runtime read path.
14. Enable `MSCQR_STAGING_RLS_MANUFACTURER_PRINTERS_READ_ENABLED=true` by itself.
15. Validate `GET /api/manufacturer/printers` for manufacturer, unauthorized tenant/manufacturer, and supported platform-admin contexts.
16. Compare response shapes and counts against the flag-off baseline.
17. Check p50 and p95 latency against the target threshold.
18. Check `staging_rls_manufacturer_printers_read_proof` telemetry for success rate, duration, row count, context class, and failure category.
19. Unset the manufacturer-printer flag and confirm fallback to the non-RLS runtime read path.
20. Enable all three flags together in staging.
21. Re-run all three route validations and compare response shapes, counts, status codes, p50 latency, and p95 latency against baseline.
22. Confirm proof events and generic request telemetry contain no user IDs, tenant IDs, organization IDs, manufacturer IDs, printer IDs, batch IDs, QR codes, customer identifiers, device names, IP addresses, request tokens, secrets, email addresses, or raw exception text.
23. Confirm public verification, scan mutation, printer dispatch, workers, exports, incidents, support, evidence-heavy routes, and admin global views emit no staged RLS proof events.
24. Unset all flags and confirm all target routes return to flag-off behavior.

## Production Rollout Phases

### Phase 0 - No-Op Documentation And Owner Signoff

- Land this production rollout plan, operator checklist, and machine-readable checklist.
- Assign rollout owner, rollback owner, security reviewer, database reviewer, and business approver.
- Confirm this phase does not enable production RLS, production route flags, global RLS, or DB changes.
- Record the approved target routes and explicit out-of-scope routes.

### Phase 1 - Index Readiness

- Review `documents/security/MSCQR_RLS_INDEX_ROLLOUT_PLAN_2026-06-29.md`.
- Select only indexes backed by route-specific staging evidence and realistic row counts.
- If indexes are needed, ship them through a separately approved online-index runbook or migration plan.
- Use `CREATE INDEX CONCURRENTLY` only where PostgreSQL supports it, with reviewed lock timeout, statement timeout, invalid-index cleanup, and `DROP INDEX CONCURRENTLY IF EXISTS ...` rollback.
- Do not combine index rollout with table-level RLS enablement.

### Phase 2 - Deploy Runtime Code With All RLS Flags Off

- Deploy the backend build containing the existing route-scoped runtime wrappers and proof telemetry.
- Keep all RLS route flags off by default.
- Confirm no table-level production RLS is enabled.
- Confirm app-layer authorization is still the active production tenant isolation control.

### Phase 3 - Explicitly Approved Internal/Admin Smoke

- Proceed only if the rollout owner explicitly approves one route flag for a production or production-equivalent internal smoke.
- Enable only one route flag at a time and only for the agreed environment/scope.
- Prefer internal/admin smoke traffic before tenant traffic.
- Confirm proof telemetry is present, redacted, and route-specific.
- Confirm no non-target routes are affected.
- Roll back immediately by unsetting the route flag if status codes, latency, telemetry, or route scope deviate.

### Phase 4 - Limited Tenant Canary

- Proceed only after Phase 3 is clean and documented.
- Canary one route and one limited tenant population at a time.
- Compare response counts, response shapes, status-code mix, p50 latency, p95 latency, and failure categories against baseline.
- Keep public verification, scan mutation, printer dispatch, workers, exports, incidents, support, and admin global surfaces outside the canary.
- Require rollback owner presence during the canary window.

### Phase 5 - Expand Route Flags After Clean Telemetry

- Expand only route-by-route.
- Each route must have its own flag, proof event, runtime test, staging evidence, production rollback note, and telemetry-redaction review.
- Do not reuse an existing flag for a different route.
- Do not enable table-level RLS as part of route-flag expansion.
- Stop expansion if any route affects non-target surfaces, increases 401/403/404/500 unexpectedly, leaks identifiers, or regresses latency materially.

### Phase 6 - Table-Level Production RLS Enablement Planning

- Start this phase only after route-level confidence exists and a separate table-level production RLS approval is granted.
- Produce a table-by-table plan covering target tables, policies, owners, `BYPASSRLS`, `FORCE ROW LEVEL SECURITY`, lock/timeout behavior, rollback SQL, and catalog verification.
- Prove rollback in staging before production.
- Keep app-layer authorization in place permanently.
- Do not enable global/table-level production RLS from this document alone.

## Rollback Plan

### Immediate Route Rollback

1. Unset the affected route flag, or set it to `false`.
2. Restart or redeploy the affected backend process so the runtime environment is explicit.
3. Confirm the target route returns to its flag-off behavior.
4. Confirm staged RLS proof events stop for that route.
5. Recheck status-code mix, p50 latency, p95 latency, and application error rate.

Affected flags:

- `MSCQR_STAGING_RLS_BATCHES_READ_ENABLED`
- `MSCQR_STAGING_RLS_BATCH_ALLOCATION_MAP_ENABLED`
- `MSCQR_STAGING_RLS_MANUFACTURER_PRINTERS_READ_ENABLED`

### Application Rollback

1. Disable all route flags.
2. Redeploy the previous backend image or SHA.
3. Confirm health checks, target route smoke tests, and non-target route smoke tests.
4. Keep app-layer authorization and existing route middleware unchanged.

### Database Rollback Boundary

Do not enable table-level RLS unless rollback SQL, lock timeout, statement timeout, monitoring, and verification queries have already been approved.

If table-level RLS is ever enabled in a future approved phase, rollback order is:

1. Disable all route flags.
2. Disable `FORCE ROW LEVEL SECURITY` where needed.
3. Disable RLS on the affected tables.
4. Verify `relrowsecurity=false` and `relforcerowsecurity=false` for every affected table.
5. Verify policies are removed or inactive according to the approved rollback SQL.
6. Re-run application-layer authorization smoke tests.

Rollback SQL must clear `FORCE` before or alongside disabling RLS, following the staging rollback precedent in `documents/security/mscqr_staging_rls_rollback.sql`.

## Safe Production Verification Queries

The queries in this section are read-only catalog checks. They must be run by an approved operator using the normal production database access process. Do not paste secrets, connection strings, real tenant IDs, or credentials into runbooks or tickets.

### RLS And FORCE State By Table

```sql
WITH target(name) AS (
  VALUES
    ('Organization'),
    ('Licensee'),
    ('User'),
    ('Batch'),
    ('QRCode'),
    ('PrintJob'),
    ('PrintItem'),
    ('QrScanLog'),
    ('Incident'),
    ('AuditLog'),
    ('Printer'),
    ('TenantFeatureFlag'),
    ('VerificationDecision'),
    ('PrintReissueRequest'),
    ('BatchPrintPackToken'),
    ('CustomerVerificationSession'),
    ('SupportTicket')
)
SELECT
  n.nspname AS schema_name,
  c.relname AS table_name,
  c.relrowsecurity,
  c.relforcerowsecurity
FROM target t
JOIN pg_class c ON c.relname = t.name
JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = 'public'
ORDER BY c.relname;
```

Expected before table-level production RLS approval: `relrowsecurity=false` and `relforcerowsecurity=false`.

### Rollback Completion Summary

```sql
WITH target(name) AS (
  VALUES
    ('Organization'),
    ('Licensee'),
    ('User'),
    ('Batch'),
    ('QRCode'),
    ('PrintJob'),
    ('PrintItem'),
    ('QrScanLog'),
    ('Incident'),
    ('AuditLog'),
    ('Printer'),
    ('TenantFeatureFlag'),
    ('VerificationDecision'),
    ('PrintReissueRequest'),
    ('BatchPrintPackToken'),
    ('CustomerVerificationSession'),
    ('SupportTicket')
)
SELECT
  count(*) AS table_count,
  bool_and(NOT c.relrowsecurity) AS all_relrowsecurity_false,
  bool_and(NOT c.relforcerowsecurity) AS all_relforcerowsecurity_false
FROM target t
JOIN pg_class c ON c.relname = t.name
JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = 'public';
```

Expected after rollback: `table_count=17`, `all_relrowsecurity_false=true`, and `all_relforcerowsecurity_false=true`.

### Policies By Table

```sql
WITH target(name) AS (
  VALUES
    ('Organization'),
    ('Licensee'),
    ('User'),
    ('Batch'),
    ('QRCode'),
    ('PrintJob'),
    ('PrintItem'),
    ('QrScanLog'),
    ('Incident'),
    ('AuditLog'),
    ('Printer'),
    ('TenantFeatureFlag'),
    ('VerificationDecision'),
    ('PrintReissueRequest'),
    ('BatchPrintPackToken'),
    ('CustomerVerificationSession'),
    ('SupportTicket')
)
SELECT
  schemaname,
  tablename,
  policyname,
  permissive,
  roles,
  cmd
FROM pg_policies p
JOIN target t ON t.name = p.tablename
WHERE p.schemaname = 'public'
ORDER BY tablename, policyname;
```

Expected before production table-RLS approval and after rollback: no rows for the target protected tables, unless a separately approved production policy rollout says otherwise.

### Runtime Role BYPASSRLS Status

```sql
SELECT
  r.rolname,
  r.rolbypassrls
FROM pg_roles r
WHERE r.rolname IN (current_user, '<app_runtime_role_name>')
ORDER BY r.rolname;
```

Expected for normal app runtime roles: `rolbypassrls=false`, unless a separately approved DBA exception exists and is documented.

### Table Owner Role

```sql
WITH target(name) AS (
  VALUES
    ('Organization'),
    ('Licensee'),
    ('User'),
    ('Batch'),
    ('QRCode'),
    ('PrintJob'),
    ('PrintItem'),
    ('QrScanLog'),
    ('Incident'),
    ('AuditLog'),
    ('Printer'),
    ('TenantFeatureFlag'),
    ('VerificationDecision'),
    ('PrintReissueRequest'),
    ('BatchPrintPackToken'),
    ('CustomerVerificationSession'),
    ('SupportTicket')
)
SELECT
  n.nspname AS schema_name,
  c.relname AS table_name,
  owner.rolname AS table_owner,
  owner.rolbypassrls AS owner_bypassrls,
  c.relforcerowsecurity
FROM target t
JOIN pg_class c ON c.relname = t.name
JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = 'public'
JOIN pg_roles owner ON owner.oid = c.relowner
ORDER BY c.relname;
```

Use this to verify whether table ownership could bypass RLS and whether `FORCE ROW LEVEL SECURITY` would be required for production proof.

## Go Criteria

Proceed only when all are true:

- Staging route telemetry success rate is acceptable for every target route.
- p50 and p95 latency remain within the approved target threshold.
- Proof telemetry and generic request telemetry show no identifier leakage.
- No unexpected 401, 403, 404, or 500 increase is observed.
- Rollback has been tested by unsetting flags and confirming flag-off behavior.
- Rollback owner, rollout owner, security owner, and database owner have signed off.
- Production DB backup/snapshot posture is confirmed before any future DB change.
- Non-target routes show no RLS proof events and no behavior change.

## No-Go Criteria

Stop or roll back if any are true:

- Public verification is affected.
- Scan mutation is affected.
- Print dispatch, test-print, replacement-label, or printer-agent flows are affected.
- Worker failures increase.
- Tenant IDs, user IDs, organization IDs, manufacturer IDs, printer IDs, QR codes, customer identifiers, device names, IP addresses, tokens, secrets, emails, or raw exception text appear in proof or generic request telemetry.
- Query latency regresses materially from baseline.
- Route flags affect non-target routes.
- Unexpected 401, 403, 404, or 500 responses increase.
- RLS context appears to leak outside its transaction.
- Rollback cannot be executed immediately by the assigned rollback owner.

## Explicitly Out Of Scope

- Production RLS enablement from this PR.
- Global production table RLS enablement.
- Prisma migrations.
- Production DB changes.
- Runtime wiring for additional routes.
- Removing or weakening app-layer authorization.
- Public verification RLS runtime wiring.
- Scan mutation RLS runtime wiring.
- Printer heartbeat, dispatch, test-print, and replacement-label flows.
- Printer gateway and local-agent protocol flows.
- Workers, outboxes, schedulers, and background jobs.
- Exports, downloads, streams, and long-running report generation.
- Incidents, support, evidence-heavy routes, and public intake/tracking flows.
- Auth middleware hydration and bootstrap flows.

## Future Expansion

- Continue route-by-route after the #86 and #87 pattern: one route, one flag, one proof event, one runtime test, one rollback note, and one staging evidence package.
- Each new route needs an explicit route owner, rollback owner, security reviewer, and route-specific out-of-scope list.
- Each new route must prove flag-off baseline, flag-on response equivalence, p50/p95 latency, safe proof telemetry, and fallback by unsetting the flag.
- Connector and printer-agent contexts need a separate design because they are not normal browser-authenticated tenant users.
- Public verification needs a separate anonymous/minimized DTO or database function design and must not receive raw tenant-table visibility.
- Worker and outbox jobs need explicit service-role policy design plus per-job transaction boundaries before any RLS runtime wiring.
- Incident/support/evidence routes should be split into metadata-only reads before becoming candidates.
- Large reporting and analytics routes need realistic row counts, query plans, and index evidence before route wrapping.

## CTO Recommendations

1. Treat production RLS as a phased defense-in-depth program, not a switch. The first production milestone should be route-level proof with all table RLS still disabled.
2. Build a small staged RLS dashboard before tenant canaries. Minimum panels: route, flag, context class, success rate, failure category, row/result count, p50, p95, and redaction audit count.
3. Make rollback ownership explicit in release tickets. The person who can unset flags and redeploy must be online before any production flag is touched.
4. Keep indexing separate from RLS enforcement. Online indexes are a scalability prerequisite, but combining index DDL and RLS policy enforcement increases rollback risk.
5. Require a dedicated design for printer-agent, public verification, and worker contexts before touching those surfaces. They carry different trust models and should not inherit tenant-user assumptions.
6. Keep app-layer authorization tests permanent. RLS should catch mistakes below the application layer, not replace the business authorization model.
