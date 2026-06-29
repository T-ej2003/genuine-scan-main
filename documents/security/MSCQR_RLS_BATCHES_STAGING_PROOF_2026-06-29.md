# MSCQR RLS Batches Staging Proof - 2026-06-29

This document records the staging-readiness proof for the already-wired runtime RLS path on one route only.

## Exact Route

- HTTP route: `GET /api/qr/batches`
- Express registration: `protectedReadRouter.get("/qr/batches", qrReadPreAuthRouteLimiter, authenticate, qrReadRouteLimiter, protectedReadRouteLimiter, enforceTenantIsolation, getBatches)`
- Controller: `backend/src/controllers/qrController.ts#getBatches`
- Route read helper: `backend/src/services/stagingRlsBatchReadService.ts#listScopedBatchReadPayload`

No other route is wired by this proof.

## Exact Flag

`MSCQR_STAGING_RLS_BATCHES_READ_ENABLED=true`

Default: false. When the flag is disabled, `GET /api/qr/batches` keeps the existing cached application-layer read path and does not emit the staging RLS proof event.

## Expected Logs And Metrics

When the flag is enabled, the backend emits one structured event per `GET /api/qr/batches` route read:

- log message: `staging_rls_batches_read_proof`
- `metric`: `staging_rls_batches_read`
- `route`: `GET /api/qr/batches`
- `flagEnabled`: `true`
- `contextClass`: one of `tenant_user`, `manufacturer`, or `platform_admin`
- `durationMs`: route helper duration in milliseconds
- `rowCount`: number of rows returned in the response page
- `success`: `true` or `false`
- `failureCategory`: `null` on success, or a safe category such as `rls_context_missing`, `rls_context_forbidden`, `database_error`, or `unexpected_error`

The proof event must not include user IDs, licensee IDs, manufacturer IDs, organization IDs, QR codes, customer identifiers, request tokens, secrets, email addresses, or raw exception text.

The generic `HTTP request completed` telemetry for `GET /api/qr/batches` is also redacted while the flag is enabled:
actor user ID, role, licensee ID, and organization ID are set to `null`, and `actorContextClass` is used instead.

## Manual Staging Validation Checklist

1. Confirm the deployment has no production RLS rollout or global RLS flag enabled.
2. Set `MSCQR_STAGING_RLS_BATCHES_READ_ENABLED=true` only in the staging backend environment.
3. Restart the staging backend process so the flag state is explicit.
4. Sign in as a licensee admin and call `GET /api/qr/batches`; confirm the response still shows only authorized batches.
5. Sign in as a manufacturer and call `GET /api/qr/batches`; confirm the response still shows only authorized manufacturer-scoped batches.
6. Sign in as a platform admin and call `GET /api/qr/batches`; confirm the route still follows existing platform authorization.
7. Check logs for `staging_rls_batches_read_proof` events with the exact route, safe context class, duration, row count, and success state.
8. Confirm the proof logs and `GET /api/qr/batches` request telemetry do not contain raw user, tenant, QR, customer, token, or secret values.
9. Confirm no public verification, scan, print dispatch, worker, export, incident, support, or admin global route has a new RLS proof event.
10. Run the local/P2 validation command before promoting the same flag state: `npm --prefix backend run test:rls:batches-read-runtime`.

## Rollback

Unset `MSCQR_STAGING_RLS_BATCHES_READ_ENABLED`, or set it to `false`, then restart the affected staging backend process. The route returns to the existing cached application-layer read path and stops emitting staging RLS proof events.

## Explicit Out Of Scope

- Production RLS enablement.
- Global RLS enablement.
- Prisma migrations.
- Automatic application of prototype SQL to staging or production.
- Actual index migrations from the non-applied index candidate SQL.
- Public verification routes.
- Scan routes.
- Printing or print dispatch routes.
- Worker processes.
- Export routes.
- Incident routes.
- Support routes.
- Admin global views.
- Removing or weakening existing app-layer authorization.

## CTO Recommendations

1. Keep #85 limited to proof quality: safe events, staging log review, and latency/row-count evidence.
2. Before #86, define route admission criteria: app-layer scope already present, transaction-local context available, safe proof events, and rollback tested.
3. Add alerting only after staging noise is understood; start with dashboard panels for failure category, p95 duration, and row-count anomalies.
4. Do not expand to public verification, printing, workers, exports, incidents, support, or admin global views until each has a separate context design and fail-closed test.
