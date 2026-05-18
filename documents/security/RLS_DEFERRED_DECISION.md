# RLS Deferred Decision

Status: deferred for this multi-tenant isolation hardening release.

PostgreSQL Row Level Security is not enabled in this release because the current Prisma setup uses one shared `PrismaClient` configured only from `DATABASE_URL`, and the application has not yet introduced a guaranteed request-scoped database context for every protected query. Enabling RLS without transaction-local context would either block legitimate workflows or risk applying stale tenant context on pooled connections.

## Why Deferred

- The backend does not currently set `app.user_id`, `app.licensee_id`, `app.manufacturer_id`, or `app.platform_role` for every Prisma operation.
- Many routes perform multiple direct Prisma calls outside a single transaction boundary. `SET LOCAL` would only be safe inside transactions that wrap all protected table access.
- Public QR verification legitimately reads QR data but must return sanitized DTOs. RLS needs a dedicated public verification policy or service role design before enforcement.
- PgBouncer or transaction-pooling behavior is not declared in this repository. Session-level settings would be unsafe until pooling mode is confirmed.

## Compensating Controls In This Release

- Backend scope derivation is centralized in `backend/src/services/accessControlService.ts`.
- Auth middleware rehydrates current DB user state and blocks disabled, deleted, or inactive users.
- Protected QR, batch, dashboard, user-management, incident, notification, audit export, and public verification paths have scoped controller/service checks.
- `scripts/check-prisma-scope-guardrails.mjs` blocks unreviewed protected-model Prisma access in controllers/services.
- `scripts/security-scope-allowlist.json` now allows only exact file, model, and method findings with a reason, a non-widening explanation, and an owner/follow-up note.
- Tenant isolation regression tests and security response-surface tests are included in the trust-critical backend suite.
- `npm run security:release-gate` runs build, isolation tests, scanner tests, trust-critical tests, frontend build/typecheck, and security-scope lint.

## First Tables For RLS Rollout

Enable RLS in this order after request-scoped DB context exists:

1. `User`
2. `QRCode`
3. `Batch`
4. `Incident`
5. `AuditLog`
6. `Notification`
7. `QrScanLog`
8. Support/report/export tables that contain tenant or user data

## Required Architecture Before Enabling

1. Add a helper that wraps protected Prisma work in a transaction and calls `SELECT set_config('app.user_id', ..., true)`, `app.licensee_id`, `app.manufacturer_id`, and `app.role` at transaction scope.
2. Confirm production pooling mode. Transaction-local settings are compatible with transaction pooling only when every protected query runs inside the same transaction.
3. Backfill and index ownership columns before policies become enforcing.
4. Add policy tests that prove cross-licensee/manufacturer/platform reads and writes fail at the database layer.
5. Roll out in staging with RLS in report-only style first where possible, then enforce table by table.

## Revisit Trigger

RLS should be revisited before onboarding additional enterprise tenants, before exposing bulk self-service exports to non-platform admins, or when the remaining Prisma allowlist entries are reduced enough that protected data access is mostly routed through scoped repositories.
