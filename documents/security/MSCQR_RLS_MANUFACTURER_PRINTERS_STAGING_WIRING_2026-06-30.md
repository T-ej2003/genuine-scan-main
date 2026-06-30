# MSCQR RLS Manufacturer Printers Staging Wiring - 2026-06-30

This document records the route-scoped staged RLS runtime wiring for the next read-only route after the batch list and allocation-map rollout steps.

## Exact Route Chosen

- HTTP route: `GET /api/manufacturer/printers`
- Express registration: `protectedReadRouter.get("/manufacturer/printers", authenticate, requireOpsUser, printReadRouteLimiter, protectedReadRouteLimiter, enforceTenantIsolation, listPrinters)`
- Controller: `backend/src/controllers/printerController.ts#listPrinters`
- Route read helper: `backend/src/services/stagingRlsManufacturerPrintersReadService.ts#listScopedManufacturerPrintersReadPayload`
- Underlying read service: `backend/src/services/printerRegistryService.ts#listRegisteredPrintersForManufacturer`

Request telemetry treats only `GET /api/manufacturer/printers` and the same path with a trailing slash as this staging route. Sibling printer routes such as `/api/manufacturer/printers/:id/test`, `/api/manufacturer/printers/:id/test-label`, `/api/manufacturer/printers/:id/discover`, mutation routes, printer-agent status, heartbeat, events, print dispatch, and local-agent lifecycle routes are not classified as manufacturer-printer RLS proof traffic.

## Exact Flag

`MSCQR_STAGING_RLS_MANUFACTURER_PRINTERS_READ_ENABLED=true`

Default: false. When the flag is disabled, the route keeps the existing app-layer authorization and printer list/status read behavior and does not emit manufacturer-printer staging RLS proof events.

## Flag Behavior

Flag off:

- `GET /api/manufacturer/printers` follows the existing scoped printer list path.
- No transaction-local RLS context is set for this route.
- No manufacturer-printer proof event is emitted.

Flag on:

- Only `GET /api/manufacturer/printers` uses transaction-local app context through `set_config(..., true)`.
- The existing authentication, `requireOpsUser`, `enforceTenantIsolation`, and scoped printer-list predicates still run.
- The printer list service reads the selected printer rows and printer profile metadata through the same transaction client after context is set.
- Public verification, scans, print dispatch, print jobs, replacement flows, workers, exports, incidents, support, admin global views, printer-agent heartbeat/status/events, test-print, and printer mutation routes are unchanged.

## Expected Proof Telemetry

When the flag is enabled, the backend emits one structured event per manufacturer-printer route read:

- log message: `staging_rls_manufacturer_printers_read_proof`
- `metric`: `staging_rls_manufacturer_printers_read`
- `route`: `GET /api/manufacturer/printers`
- `flagEnabled`: `true`
- `contextClass`: one of `tenant_user`, `manufacturer`, or `platform_admin`
- `durationMs`: route helper duration in milliseconds
- `rowCount`: coarse count of returned rows
- `success`: `true` or `false`
- `failureCategory`: `null` on success, or a safe category such as `rls_context_missing`, `rls_context_forbidden`, `database_error`, or `unexpected_error`

The proof event must not include raw user IDs, licensee IDs, manufacturer IDs, organization IDs, printer IDs, printer names, device names, IP addresses, QR codes, request tokens, secrets, email addresses, or raw exception text.

Generic `HTTP request completed` telemetry for this route is also redacted while the flag is enabled: actor user ID, role, licensee ID, and organization ID are set to `null`, and `actorContextClass` is used instead.

## Why This Route Is Safe Enough After Batch Routes

This route is a read-only operational list/status path that already sits behind authentication, rate limits, `requireOpsUser`, `enforceTenantIsolation`, and service-level scope predicates. It has no print dispatch, print confirmation, test-print, heartbeat, stream, export, replacement, public verification, scan, support, incident, worker, or admin-global side effects.

The route is useful for the next route-by-route RLS expansion because it exercises the protected `Printer` surface with manufacturer and platform-admin context while keeping the blast radius limited to a single read path and a dedicated rollback flag.

## Rollback

Unset `MSCQR_STAGING_RLS_MANUFACTURER_PRINTERS_READ_ENABLED`, or set it to `false`, then restart the affected staging backend process. The route returns to the existing non-RLS runtime read path and stops emitting manufacturer-printer staging RLS proof events.

## Validation Checklist

1. Confirm no production RLS enablement or global RLS flag is active.
2. Confirm no Prisma migration was created for this rollout step.
3. Set `MSCQR_STAGING_RLS_MANUFACTURER_PRINTERS_READ_ENABLED=true` only in the staging backend environment.
4. Sign in as a manufacturer and call `GET /api/manufacturer/printers`; confirm only allowed printer list/status rows are returned.
5. Sign in as a different manufacturer or tenant and call the route; confirm the response fails closed or matches the existing filtered-list behavior.
6. Sign in as platform admin, if this route is supported for that role; confirm platform-admin context is explicit and expected.
7. Call the route with a trailing slash and confirm it is classified and redacted the same way.
8. Call sibling printer routes such as `POST /api/manufacturer/printers/:id/test`; confirm they are not classified as manufacturer-printer RLS telemetry.
9. Confirm proof logs contain only the safe fields listed above and do not contain raw tenant, user, printer, device, IP, QR, token, or secret values.
10. Confirm transaction-local context does not leak after the route transaction.
11. Run `npm --prefix backend run test:rls:manufacturer-printers-read-runtime`.
12. Run the standard RLS and scope guardrail checks before promotion.

## Explicit Out Of Scope Printer Routes

- `POST /api/manufacturer/printers`
- `PATCH /api/manufacturer/printers/:id`
- `DELETE /api/manufacturer/printers/:id`
- `POST /api/manufacturer/printers/:id/relink-local-agent`
- `POST /api/manufacturer/printers/:id/test`
- `POST /api/manufacturer/printers/:id/test-label`
- `POST /api/manufacturer/printers/:id/discover`
- `GET /api/manufacturer/printer-agent/status`
- `GET /api/manufacturer/printer-agent/events`
- `POST /api/manufacturer/printer-agent/heartbeat`
- `/api/printer-agent/local/*`
- `/api/print-gateway/*`
- Any print job, replacement-label, dispatch, confirmation, worker, public verification, scan, export, incident, support, or admin global route.

## CTO Recommendations

1. Keep the next RLS expansion route-by-route with one flag, one proof event, and one P2 runtime test per route.
2. Before considering printer write or heartbeat routes, design separate RLS context rules for connector-authenticated actors versus browser-authenticated users.
3. Add a staged RLS dashboard after this route proves stable, grouped by route, context class, success, failure category, row count, and p95 duration.
4. Treat printer names, network addresses, local device names, and connector identifiers as sensitive operational metadata in logs even when they are visible in the authenticated UI.
