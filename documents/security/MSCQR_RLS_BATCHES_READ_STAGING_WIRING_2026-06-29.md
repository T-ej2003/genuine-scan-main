# MSCQR RLS Batches Read Staging Wiring - 2026-06-29

This document records the staging-only runtime RLS wiring for one route:
`GET /api/qr/batches`, registered as `protectedReadRouter.get("/qr/batches", ..., getBatches)` in
`backend/src/routes/index.ts`.

## Exact Flag

`MSCQR_STAGING_RLS_BATCHES_READ_ENABLED=true`

Default: false. When unset, empty, or set to a false-like value, the route keeps the existing behavior and uses the
existing cached batch-list read path.

## Exact Route

- HTTP route: `GET /api/qr/batches`
- Express route registration: `protectedReadRouter.get("/qr/batches", qrReadPreAuthRouteLimiter, authenticate, qrReadRouteLimiter, protectedReadRouteLimiter, enforceTenantIsolation, getBatches)`
- Controller: `backend/src/controllers/qrController.ts#getBatches`
- Runtime helper: `backend/src/lib/stagingRlsBatchReadContext.ts`
- Read service path under the flag: `backend/src/services/batchAllocationService.ts#listBatchOperationalSummaries`

No other route is wired by this change.

## Flag-Off Behavior

With `MSCQR_STAGING_RLS_BATCHES_READ_ENABLED` disabled, `GET /api/qr/batches` continues to:

- run through existing authentication, rate limits, and `enforceTenantIsolation`;
- build the same app-layer scoped `where` filter;
- use `listCachedBatchOperationalSummaries`;
- preserve the existing app-layer authorization contract.

## Flag-On Behavior

With `MSCQR_STAGING_RLS_BATCHES_READ_ENABLED=true`, only `GET /api/qr/batches` wraps the route's scoped query
construction and batch summary reads in a Prisma transaction. The wrapper sets transaction-local PostgreSQL settings
using `set_config(..., true)`:

- `app.user_id`
- `app.role`
- `app.licensee_id`
- `app.manufacturer_id`
- `app.organization_id`
- `app.is_platform_admin`

The context is derived from the authenticated user claims after normal authentication. Platform admin is set only when
the authenticated role is an explicit platform role. Public verification, printer-agent, and background-worker contexts
are rejected for this route helper.

The flag-on path intentionally bypasses the existing read cache so the selected route exercises database reads under
the transaction-local RLS context instead of serving rows computed outside RLS.
Batch summary reads on this transaction-backed path run sequentially for predictable transaction-client behavior during
staging proof.

## Why Only This Route

The runtime inventory identified `GET /qr/batches` as the lowest-risk first candidate because it is a read route with
existing app-layer tenant scoping and no direct external side effects. This route is useful for validating the runtime
pattern while avoiding public verification, scans, printing, workers, exports, incidents, support, and admin global
views.

## Rollback

Rollback is operationally simple:

1. Unset `MSCQR_STAGING_RLS_BATCHES_READ_ENABLED`, or set it to `false`.
2. Restart the affected backend process so the deployment environment is known-clean.
3. Confirm `GET /api/qr/batches` still returns through the existing cached batch-list path.

This change does not add a Prisma migration and does not apply prototype SQL automatically.

## Out Of Scope

- Production RLS enablement.
- Global RLS runtime wiring.
- Full authentication/session hydration under RLS.
- Public verification, scan, print, worker, export, incident, support, and admin global view routes.
- Applying `documents/security/mscqr_staging_rls_prototype.sql` automatically.
- Index rollout from the non-applied RLS index candidate artifacts.
- Removing or weakening app-layer authorization.

## Validation

The new gated disposable-DB test command is:

```bash
npm --prefix backend run test:rls:batches-read-runtime
```

The test keeps RLS setup local to the P2 disposable database. It applies test-only `Batch` and `QRCode` RLS policies
inside that disposable database to prove the route's batch-list reads need transaction-local context, then rolls those
test policies back before the database is dropped.

## CTO Recommendations

1. Keep #85 focused on proving the staging runtime path with realistic latency and row-count evidence before adding
   another route.
2. Add route-level observability for RLS-enabled reads: route, context type, result count, duration, and whether the
   RLS flag was active. Do not log raw tenant IDs unless the existing logging policy permits it.
3. Do not expand into public verification, printing, or workers until those contexts have separate RLS role designs and
   fail-closed tests.
4. Before production planning, decide how auth hydration will work under RLS. The current one-route wrapper starts
   after authentication, so full forced RLS on `User` still needs a separate design.
