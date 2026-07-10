# MSCQR RLS Batch Allocation Map Staging Wiring - 2026-06-30

This document records the route-scoped staged RLS runtime wiring for the next safe read route after `GET /api/qr/batches`.

## Exact Route

- HTTP route: `GET /api/qr/batches/:id/allocation-map`
- Express registration: `protectedReadRouter.get("/qr/batches/:id/allocation-map", qrReadPreAuthRouteLimiter, authenticate, qrReadRouteLimiter, protectedReadRouteLimiter, enforceTenantIsolation, getBatchAllocationMap)`
- Controller: `backend/src/controllers/qrController.ts#getBatchAllocationMap`
- Route read helper: `backend/src/services/stagingRlsBatchAllocationMapService.ts#getScopedBatchAllocationMapPayload`

Request telemetry treats only `GET /api/qr/batches/<one path segment>/allocation-map` and the same path with a trailing slash as this staging route. Sibling batch child routes such as `/api/qr/batches/:id/validation-evidence`, mutation routes, and deeper paths are not classified as allocation-map proof traffic.

## Exact Flag

`MSCQR_STAGING_RLS_BATCH_ALLOCATION_MAP_ENABLED=true`

Default: false. When the flag is disabled, the route keeps the existing app-layer authorization and allocation-map read behavior and does not emit allocation-map staging RLS proof events.

When enabled, this flag makes `RLS_READ_DATABASE_URL` mandatory. The value must be a valid PostgreSQL URL with a database name, must differ from `DATABASE_URL`, and must authenticate as the reviewed non-owner, non-bypass, SELECT-only runtime role. It never falls back to the default datasource. Startup and readiness fail closed if the dedicated client cannot connect or its role/table/policy/helper posture is unsafe.

## Flag Behavior

Flag off:

- `GET /api/qr/batches/:id/allocation-map` follows the existing scoped batch check and allocation-map read path.
- No transaction-local RLS context is set for this route.
- No allocation-map proof event is emitted.

Flag on:

- Only `GET /api/qr/batches/:id/allocation-map` uses transaction-local app context through `set_config(..., true)`.
- The existing scoped `findScopedBatch` authorization check still runs before the allocation-map payload is returned.
- The scoped authorization and allocation-map services read `Batch` and `QRCode` data through the same transaction on the separately cached RLS client after context is set; no nested read may escape to the default client.
- `DATABASE_URL` remains the unchanged default read/write client for the flag-off path, every mutation, and all unrelated routes.
- Public verification, scans, printing, workers, exports, incidents, support, admin global views, and sibling batch routes are unchanged.

## Expected Proof Telemetry

When the flag is enabled, the backend emits one structured event per allocation-map route read:

- log message: `staging_rls_batch_allocation_map_proof`
- `metric`: `staging_rls_batch_allocation_map`
- `route`: `GET /api/qr/batches/:id/allocation-map`
- `flagEnabled`: `true`
- `contextClass`: one of `tenant_user`, `manufacturer`, or `platform_admin`
- `durationMs`: route helper duration in milliseconds
- `resultShape`: `allocation_map`, `not_found`, or `unknown`
- `success`: `true` or `false`
- `failureCategory`: `null` on success, or a safe category such as `rls_context_missing`, `rls_context_forbidden`, `database_error`, or `unexpected_error`

The proof event must not include raw user IDs, licensee IDs, manufacturer IDs, organization IDs, batch IDs, QR codes, customer identifiers, request tokens, secrets, email addresses, or raw exception text.

Generic `HTTP request completed` telemetry for this route is also redacted while the flag is enabled: actor user ID, role, licensee ID, and organization ID are set to `null`, and `actorContextClass` is used instead.

## Why This Route Is Next

This route is the next safe candidate because it is a read-only tenant/manufacturer batch detail path, already sits behind authentication, rate limits, `enforceTenantIsolation`, and an app-layer scoped batch lookup, and reads the same protected `Batch` and `QRCode` surfaces as the existing batch-list staged RLS path.

The allocation-map path is small enough to validate route-by-route without touching public verification, scan ingestion, print dispatch, worker execution, exports, support, incidents, or admin global surfaces.

## Rollback

Unset `MSCQR_STAGING_RLS_BATCH_ALLOCATION_MAP_ENABLED`, or set it to `false`, then restart the affected staging backend process. The dedicated pool is no longer required or initialized, the route returns to the existing default-client read path, and allocation-map staging RLS proof events stop.

## Validation Checklist

1. Confirm no production RLS enablement or global RLS flag is active.
2. Confirm no Prisma migration was created for this rollout step.
3. Privately verify that `RLS_READ_DATABASE_URL` is distinct from `DATABASE_URL` and proves the exact restricted runtime identity before setting `MSCQR_STAGING_RLS_BATCH_ALLOCATION_MAP_ENABLED=true`.
4. Sign in as a licensee admin and call `GET /api/qr/batches/:id/allocation-map` for an owned batch; confirm the allocation map is returned.
5. Sign in as a manufacturer linked to the licensee and call the same route; confirm existing manufacturer access still works.
6. Sign in as a different tenant and call the route for the first tenant's batch; confirm the response fails closed with the existing not-found/forbidden behavior.
7. Call the route with a trailing slash and confirm it is classified and redacted the same way.
8. Call a sibling route such as `GET /api/qr/batches/:id/validation-evidence`; confirm it is not classified as allocation-map RLS telemetry.
9. Confirm proof logs contain only the safe fields listed above and do not contain raw tenant, user, batch, QR, customer, token, or secret values.
10. Confirm transaction-local context does not leak after the route transaction.
11. Run `npm --prefix backend run test:rls:batch-allocation-map-runtime`.
12. Run `npm --prefix backend run test:rls:read-client`.
13. Run the standard RLS and scope guardrail checks before promotion.

## Explicit Out Of Scope

- Production RLS enablement.
- Global RLS enablement.
- Prisma migrations.
- Reusing `MSCQR_STAGING_RLS_BATCHES_READ_ENABLED` for this route.
- Wiring any route other than `GET /api/qr/batches/:id/allocation-map`.
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

1. Keep the next rollout gate evidence-based: require p95 duration, proof failure-category counts, and redaction checks from staging before selecting another route.
2. Add a small operational dashboard for staged RLS routes after this path proves stable, grouped by route, context class, success, failure category, and duration.
3. Treat each future route as a separate rollback unit with its own flag, proof event, and P2 runtime test.
4. Delay write routes, public verification, printing, worker, export, support, incident, and admin global RLS work until each has a dedicated context design and abuse-case review.
