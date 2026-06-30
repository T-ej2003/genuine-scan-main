# MSCQR RLS Production Rollout Checklist - 2026-06-30

This operator checklist supports `documents/security/MSCQR_RLS_PRODUCTION_ROLLOUT_PLAN_2026-06-30.md`. It is a planning artifact only. Do not enable production RLS, global RLS, Prisma migrations, route wiring, or production database changes from this checklist.

## Owner Signoff

- [ ] Rollout owner assigned.
- [ ] Rollback owner assigned and available for the full window.
- [ ] Security reviewer approved the route scope.
- [ ] Database reviewer approved the catalog checks and any future DB-change boundary.
- [ ] Business owner approved the production window.

## Preflight

- [ ] Current CI checks are green.
- [ ] App-layer tenant authorization remains enabled.
- [ ] No production table RLS is enabled.
- [ ] No global RLS rollout is approved.
- [ ] No Prisma migration is included in this change.
- [ ] Production backup, snapshot, PITR, and restore posture are confirmed before any future DB change.
- [ ] Production RDS role ownership, `BYPASSRLS`, and `FORCE ROW LEVEL SECURITY` behavior are understood.
- [ ] Index readiness plan is reviewed.
- [ ] Staging `EXPLAIN` or `EXPLAIN ANALYZE` evidence exists with realistic row counts.

## Staging Validation

- [ ] Capture flag-off baseline response shape, count, status-code mix, p50 latency, and p95 latency.
- [ ] Enable only `MSCQR_STAGING_RLS_BATCHES_READ_ENABLED`; validate `GET /api/qr/batches`.
- [ ] Unset `MSCQR_STAGING_RLS_BATCHES_READ_ENABLED`; confirm fallback.
- [ ] Enable only `MSCQR_STAGING_RLS_BATCH_ALLOCATION_MAP_ENABLED`; validate `GET /api/qr/batches/:id/allocation-map`.
- [ ] Unset `MSCQR_STAGING_RLS_BATCH_ALLOCATION_MAP_ENABLED`; confirm fallback.
- [ ] Enable only `MSCQR_STAGING_RLS_MANUFACTURER_PRINTERS_READ_ENABLED`; validate `GET /api/manufacturer/printers`.
- [ ] Unset `MSCQR_STAGING_RLS_MANUFACTURER_PRINTERS_READ_ENABLED`; confirm fallback.
- [ ] Enable all three staged route flags together; compare response shapes and counts against baseline.
- [ ] Review p50 and p95 latency for each route.
- [ ] Review proof telemetry success rate and failure categories.
- [ ] Confirm no tenant, user, organization, manufacturer, printer, batch, QR, customer, token, secret, email, raw exception, device, or IP identifiers appear in proof or generic request telemetry.
- [ ] Confirm non-target routes emit no staged RLS proof events.

## Production Phases

- [ ] Phase 0: Documentation and owner signoff only.
- [ ] Phase 1: Index readiness reviewed; any index rollout remains separately approved.
- [ ] Phase 2: Runtime code deployed with all route flags off.
- [ ] Phase 3: One explicitly approved internal/admin smoke flag only, if approved.
- [ ] Phase 4: Limited tenant canary only after clean smoke telemetry.
- [ ] Phase 5: Route flags expanded one route at a time after clean telemetry.
- [ ] Phase 6: Table-level production RLS enablement planned only after route-level confidence and separate approval.

## Immediate Rollback

- [ ] Unset affected route flag or set it to `false`.
- [ ] Restart or redeploy the affected backend process.
- [ ] Confirm target route returns to flag-off behavior.
- [ ] Confirm staged proof event stops for the route.
- [ ] Confirm status-code mix, p50 latency, p95 latency, and application errors return to baseline.

## Future Table-RLS Rollback Boundary

- [ ] Do not enable table RLS unless rollback SQL, lock timeout, statement timeout, and verification queries are approved.
- [ ] If table RLS is ever enabled, disable route flags first.
- [ ] Disable `FORCE ROW LEVEL SECURITY` where needed.
- [ ] Disable RLS on affected tables.
- [ ] Verify `relrowsecurity=false` and `relforcerowsecurity=false` for every affected table.
- [ ] Verify policies are removed or match the approved rollback state.

## Go

- [ ] Staging telemetry success rate is acceptable.
- [ ] Latency is within target.
- [ ] No identifier leakage exists.
- [ ] No unexpected 401, 403, 404, or 500 increase exists.
- [ ] Rollback has been tested.
- [ ] Owner signoff is complete.

## No-Go

- [ ] Public verification is affected.
- [ ] Scan mutation is affected.
- [ ] Print dispatch, test-print, replacement-label, heartbeat, or printer-agent flows are affected.
- [ ] Worker failures increase.
- [ ] Unsafe identifiers appear in telemetry.
- [ ] Query latency regresses materially.
- [ ] RLS flags affect non-target routes.
- [ ] Rollback owner cannot execute immediate rollback.

## CTO Recommendations

- Keep production table RLS disabled until route-level proof is stable and rollback is rehearsed.
- Build route-level RLS observability before tenant canaries.
- Separate online index work from RLS enforcement work.
- Design public verification, printer-agent, and worker contexts independently before wiring them.
- Keep app-layer authorization as the permanent business control.
