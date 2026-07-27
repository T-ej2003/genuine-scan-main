# Session A dashboard snapshot implementation checklist

Date: 2026-07-21 (Europe/London)

Coordination base: `22bfdb0cfd19d7b435b1390611b452a419923f9f`

Status: PostgreSQL 18 application-path certified in the clean-room full-table runner.

## Exact workflow family

- `workflow-internal-backend-src-services-dashboard-snapshot-service-ts-compute-dashboard-snapshot`
- `workflow-internal-backend-src-services-dashboard-snapshot-service-ts-load-inventory-aggregate`

Registered roots:

- `GET /api/dashboard/stats`
- the initial snapshot on `GET /api/events/dashboard`

Both roots call `getDashboardSnapshot` in `backend/src/services/dashboardSnapshotService.ts`. The HTTP response remains the four existing summary counts. The SSE initial response remains the same summary plus the existing QR status aggregate.

## Discovery completed before editing

- [x] Read the HTTP and SSE routes, authentication, tenant-isolation middleware, controllers, service, cache implementation, schema and existing tests.
- [x] Verified the current rollup-first behavior: a non-zero `InventoryStatusRollup` aggregate is authoritative; an all-zero aggregate falls back to `QRCode` grouping/counting.
- [x] Verified tenant administrators use their database-hydrated licensee and organization.
- [x] Verified manufacturers currently aggregate their own batches/QRs across every active linked licensee when no selector is supplied, or one linked licensee when selected.
- [x] Verified platform administrators currently receive the global fixed-cardinality aggregate without a selector, or one active selected licensee aggregate when supplied.
- [x] Verified cache namespace `dashboard-snapshot`, TTL 20 seconds, and existing response shapes.
- [x] Verified there is no direct dashboard service unit test and no PostgreSQL 18 application-path proof.
- [x] Confirmed `dashboardSnapshotService.ts` and `canonicalDbContext.ts` are Session A-owned. Session B owns authentication; Session C owns manufacturer-scope code. Neither will be edited in this family.

## Frozen-contract reconciliation

The current platform-global aggregate and manufacturer linked-licensee-set aggregate cannot be represented by a single-licensee ordinary RLS policy. Narrowing either actor to one tenant would remove existing supported behavior. The exact bounded correction is a fixed-result database function with:

- a fixed `dashboard-snapshot-read` purpose;
- nonblank request attribution;
- database-revalidated active User role and state;
- fresh MFA for platform actors;
- exact tenant scope for licensee/organization administrators;
- the current active membership set plus `manufacturerId = actor` for manufacturers;
- an optional selector that can only narrow a database-validated scope;
- a fixed result of four summary counts and eight QR status counts;
- no raw row, email, password, token, MFA, WebAuthn, recovery, metadata or network/device field exposure;
- immutable bounded read attribution in the same transaction;
- fixed `search_path`, no dynamic SQL, PUBLIC EXECUTE revoked and exact authenticated-app EXECUTE only.

The workflow inventory must add its currently omitted `ManufacturerLicenseeLink` dependency and the active Licensee/Organization columns used to revalidate scope. The application runtime receives no dashboard table SELECT grant for this function-only workflow.

## Implementation checklist

- [x] Replace global Prisma dashboard reads with one canonical `REPEATABLE READ` transaction and transaction-client-only exact function calls.
- [x] Validate user/session shape, selector, role, assurance, request ID and route surface before database work.
- [x] Revalidate actor and current membership before every cache hit so stale membership fails closed.
- [x] Derive a privacy-preserving cache key from the database-approved scope; do not log raw actor or tenant IDs through cache telemetry.
- [x] Preserve the 20-second versioned cache, rollup/fallback rule, status meanings and response schemas.
- [x] Attribute every delivered HTTP/SSE initial snapshot; serialize only after commit.
- [x] Add exact generator support and expected routine/grant evidence at the coherent A01 wave integration checkpoint.
- [x] Correct workflow/command/family manifests only from implementation evidence; do not broaden generic authenticated-user table grants.

## Required focused proof

- [x] TypeScript build and direct service boundary tests.
- [x] HTTP and SSE initial response contract tests.
- [x] PostgreSQL 18 application-path positives: licensee administrator, organization administrator, manufacturer linked set, manufacturer selected tenant, global platform aggregate and selected-licensee platform aggregate.
- [x] PostgreSQL 18 negatives: blank/malformed selector, foreign tenant, stale/revoked manufacturer membership, inactive/disabled actor, forged role, blank request ID, lower platform assurance and wrong purpose.
- [x] Exact fixed projection and prohibited-column proof.
- [x] Rollup and fallback equivalence.
- [x] Cache-hit revalidation and per-request attribution.
- [x] One repeatable-read transaction, no protected query before context and no global Prisma access.

## Gate result

- Source contract: `87c127f611e6ec3914521158958d4bf5ad7388590d0eca08c6c67c045e3298a3`
- Package checksum: `e41c2722d7da33719f1f6f962ab685edfe9ccd778d840b3626264a88a3dceb09`
- Full clean-room result: 75/75 FORCE RLS tables, 48 policies, 78 column privileges, zero database or managed-role residue.
- Certified workflows: both dashboard workflow IDs above, through REST, SSE initial snapshot and SSE delta authorization paths.

## Recorded integration dependencies

- The long-lived SSE delta subscription currently snapshots manufacturer membership only once and can outlive revocation; its controller and route files are not assigned to an implementation session. Session A will resolve that integration seam before the complete A01 wave is certified.
- The scoped Batch/QR selector family is deliberately deferred to the A03/A04 integration checkpoint. Its live roots span allocation-map reads plus delete, assign, rename and release mutations, so changing the selector alone would leave TOCTOU, atomic-audit and exact-purpose failures.
