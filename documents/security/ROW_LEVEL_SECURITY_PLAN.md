# PostgreSQL Row Level Security Plan

Runtime RLS is not enabled in this pass. The application currently uses pooled Prisma connections and several public verification flows, so enabling policies without a reliable per-request database session context would risk either overexposure or production outages.

Final release decision: RLS is formally deferred for this multi-tenant isolation hardening release. See `documents/security/RLS_DEFERRED_DECISION.md` for the deployment decision, compensating controls, and staged rollout requirements.

Prerequisites before enabling RLS:

- Define one canonical tenant context for each request: `platform_id`, `licensee_id`, `manufacturer_id`, and `user_id`.
- Set that context in PostgreSQL with transaction-local settings such as `SET LOCAL app.user_id = ...` for every Prisma transaction that touches protected tables.
- Confirm connection pooling mode supports transaction-local settings. PgBouncer transaction pooling needs careful validation.
- Backfill missing ownership fields before adding `NOT NULL` constraints.
- Add indexes for scoped lookups before enforcing policies, especially `(licensee_id, id)`, `(manufacturer_id, id)`, `(user_id, id)`, and `(licensee_id, created_at)`.
- Add RLS in phases, starting with append/read-heavy sensitive tables where ownership is already explicit.

Recommended first RLS tables:

- `User`
- `QRCode`
- `Batch`
- `Incident`
- `AuditLog`
- `Notification`
- `SupportTicket`
- `QrScanLog`

Policy shape:

- Super/platform admin context can read platform-wide rows only where explicitly intended.
- Licensee admin context reads/writes rows matching `licensee_id`.
- Manufacturer context reads/writes rows matching `manufacturer_id` or rows linked through manufacturer/licensee join tables.
- End-user context reads/writes only rows matching `user_id`.
- Public QR verification should use a dedicated read-only database role or service path that returns sanitized DTOs, not raw table rows.

Until RLS is introduced, backend isolation is enforced through `backend/src/services/accessControlService.ts`, scoped controller/service queries, and `scripts/check-prisma-scope-guardrails.mjs`.
