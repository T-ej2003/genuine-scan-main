# MSCQR Staging-Only PostgreSQL RLS Prototype Design - 2026-06-28

## Scope And Non-Goals

This is a staging/disposable database hardening prototype for PostgreSQL Row Level Security. It is not a production rollout plan.

Hard constraints:

- Do not enable RLS in production.
- Do not change the production database.
- Do not apply Prisma migrations automatically.
- Do not remove existing backend Prisma/service/controller tenant authorization.
- Keep this prototype as defense-in-depth, not as the primary authorization mechanism.

Current production evidence states RLS is off on all public application tables and no policies exist. Tenant isolation remains enforced by backend application-layer authorization.

Prototype artifacts:

- Prototype SQL: `documents/security/mscqr_staging_rls_prototype.sql`
- Rollback SQL: `documents/security/mscqr_staging_rls_rollback.sql`
- This design and test plan: `documents/security/MSCQR_STAGING_RLS_PROTOTYPE_DESIGN_2026-06-28.md`

## Session Context Contract

Only transaction-local PostgreSQL settings should be used:

| Key | Required for | Notes |
|---|---|---|
| `app.user_id` | authenticated user and self-owned records | Empty for public verification and worker contexts. |
| `app.role` | role-specific policy branches | Values should be normalized backend role strings, plus explicit service roles such as `public_verification` and `background_worker` in staging. |
| `app.licensee_id` | licensee-scoped users and tenant-owned rows | Empty for platform admins and service-only contexts unless intentionally scoped. |
| `app.manufacturer_id` | manufacturer users and print worker acting for a manufacturer | Usually the manufacturer user ID. |
| `app.organization_id` | org-scoped rows such as `Organization`, `Printer`, and `User` | Empty if no org context exists. |
| `app.is_platform_admin` | explicit platform bypass | Must be `true` only for platform/super-admin paths that are intentionally global. |

Important: session context must never be set with session-level `SET` on pooled connections. Use `SET LOCAL` inside a transaction only.

## Safe Prisma Transaction Helper Design

Implemented prototype helper: `backend/src/lib/rlsTransactionContextPrototype.ts`.

Do not wire this into production as part of the prototype. The helper exists so staging/P2 tests can validate transaction-local `app.*` session context before any future runtime rollout. Current production tenant authorization remains the application-layer controller/service checks.

Intended shape for staging tests:

```ts
type RlsContext = {
  userId?: string | null;
  role: string;
  licenseeId?: string | null;
  manufacturerId?: string | null;
  organizationId?: string | null;
  isPlatformAdmin?: boolean;
};

export async function withRlsContext<T>(
  prisma: PrismaClient,
  context: RlsContext,
  fn: (tx: Prisma.TransactionClient) => Promise<T>
): Promise<T> {
  return prisma.$transaction(async (tx) => {
    await tx.$executeRaw`SELECT set_config('app.user_id', ${context.userId ?? ""}, true)`;
    await tx.$executeRaw`SELECT set_config('app.role', ${context.role}, true)`;
    await tx.$executeRaw`SELECT set_config('app.licensee_id', ${context.licenseeId ?? ""}, true)`;
    await tx.$executeRaw`SELECT set_config('app.manufacturer_id', ${context.manufacturerId ?? ""}, true)`;
    await tx.$executeRaw`SELECT set_config('app.organization_id', ${context.organizationId ?? ""}, true)`;
    await tx.$executeRaw`SELECT set_config('app.is_platform_admin', ${context.isPlatformAdmin ? "true" : "false"}, true)`;
    return fn(tx);
  });
}
```

Rules for this helper:

- It must wrap every protected Prisma read/write that expects RLS.
- It must not reuse a Prisma transaction from another request context.
- It must not issue protected queries before the `set_config(..., true)` calls.
- It must not use session-level `SET`.
- It must preserve current app-layer authorization checks.
- It must reject `public_verification` when `app.is_platform_admin` is requested, so public verification cannot accidentally receive platform-admin policy context.

Local P2 transaction-context command:

```sh
MSCQR_RLS_CONTEXT_PROTOTYPE_TEST=true npm --prefix backend run test:rls:context-prototype
```

The context test creates a disposable local P2 database and proves context exists inside the transaction, disappears after commit, does not leak across transactions, requires explicit platform-admin context, and keeps public verification non-admin.

## Model Ownership Map

| Prisma model | Physical table | Ownership path | Classification | Prototype access intent |
|---|---|---|---|---|
| `Organization` | `"Organization"` | `Organization.id`; licensee via `"Licensee"."orgId"`; users via `"User"."orgId"` | platform-global / tenant-owned root | Platform admins can read all. Licensee users read own org. Manufacturers read own org only. |
| `Licensee` | `"Licensee"` | Direct `id`, `orgId`; manufacturer links via `"ManufacturerLicenseeLink"` | tenant-owned | Licensee users read own licensee. Manufacturers read linked licensees. Platform admins read all. |
| `User` | `"User"` | `id`, `licenseeId`, `orgId`; manufacturer link identity when `id = app.manufacturer_id` | user-owned / tenant-owned | Self read. Licensee admins read own licensee users. Manufacturers read self and linked-tenant-safe rows only where app already allows. |
| `Batch` | `"Batch"` | Direct `licenseeId`, optional `manufacturerId`; links through `"ManufacturerLicenseeLink"` | tenant-owned | Licensee reads own batches. Manufacturer reads assigned or linked-licensee batches. |
| `QRCode` | `"QRCode"` | Direct `licenseeId`, optional `batchId`, optional `printJobId` | tenant-owned / public-minimized | Tenant/linked manufacturer read. Public verification should use service path only, not arbitrary raw table access. |
| `PrintJob` | `"PrintJob"` | `batchId -> Batch.licenseeId`, direct `manufacturerId` | tenant-owned / worker-system | Licensee via batch. Manufacturer via direct manufacturer ID or linked batch. Worker explicit. |
| `PrintItem` | `"PrintItem"` | `printSessionId -> PrintSession.batchId`, `qrCodeId -> QRCode.licenseeId` | worker-system / tenant-owned | Tenant through related QR/session. Manufacturer through print session/job. Worker explicit. |
| `QrScanLog` | `"QrScanLog"` | Direct `licenseeId`, optional `batchId`, `qrCodeId` | tenant-owned / public-minimized append | Tenant read own logs. Public scan logging should stay in the application service or a future narrow DB function. Worker explicit. |
| `Incident` | `"Incident"` | Direct nullable `licenseeId`; optional `qrCodeId`, `scanEventId` | tenant-owned / public-minimized create | Tenant read own incidents. Public report creation should stay in the application service or a future narrow DB function. Platform global IR explicit. |
| `AuditLog` | `"AuditLog"` | Nullable `userId`, `orgId`, `licenseeId` | tenant-owned / platform-global | Licensee read own audit rows. User self audit limited. Platform audit explicit. |
| `Printer` | `"Printer"` | Nullable `licenseeId`, `orgId`, `assignedUserId`, `createdByUserId`, `printerRegistrationId` | user-owned / tenant-owned / worker-system | User reads assigned local printers. Licensee reads tenant network printers. Gateway/worker explicit. |
| `TenantFeatureFlag` | `"TenantFeatureFlag"` | Direct `licenseeId` | tenant-owned | Licensee-scoped read; platform can manage all. |
| `VerificationDecision` | `"VerificationDecision"` | Nullable `licenseeId`, `batchId`, `qrCodeId`, `code` | public-minimized / tenant-owned | Public verification reads only through the minimized prototype function; tenants can read own derived decisions. |
| `PrintReissueRequest` | `"PrintReissueRequest"` | Nullable `licenseeId`, `manufacturerId`, `batchId`; original/replacement print jobs | tenant-owned / workflow | Licensee/manufacturer through direct columns or linked jobs. |
| `BatchPrintPackToken` | `"BatchPrintPackToken"` | `batchId -> Batch.licenseeId`, `createdByUserId` | worker-system / tenant-owned secret-bearing | Only creating user, tenant admins, platform, or explicit worker/service path. |
| `CustomerVerificationSession` | `"CustomerVerificationSession"` | `verificationDecisionId -> VerificationDecision.licenseeId`, `qrCodeId`, `code`, customer identifiers | public-minimized / user-owned | Customer proof token path must stay in the app service unless a future narrow DB function is designed. |
| `SupportTicket` | `"SupportTicket"` | Nullable `licenseeId`, `incidentId -> Incident.licenseeId`, `assignedToUserId` | tenant-owned / platform-global support | Platform support global explicit. Licensee read own support rows only if app route permits. Public tracking service minimized. |

Related join/link table used by policies:

| Table | Classification | Notes |
|---|---|---|
| `"ManufacturerLicenseeLink"` | join/link table | Defines manufacturer-to-licensee access. Policies should treat this table as sensitive because widening it widens manufacturer visibility. |

## Prototype Policy Strategy

The prototype SQL creates helper functions under `app_rls` and table policies for the requested tables only.

Every protected table is configured with both `ENABLE ROW LEVEL SECURITY` and
`FORCE ROW LEVEL SECURITY`. PostgreSQL table owners bypass row-level security
unless `FORCE` is set. This matters for staging/P2 validation because Prisma
migrations and disposable test databases can leave the Prisma connection role as
the owner of migrated tables. Without `FORCE`, tests executed through that role
could pass while bypassing the prototype policies, creating false confidence.
The rollback SQL therefore clears `FORCE` with `NO FORCE ROW LEVEL SECURITY`
before disabling RLS.

The policies intentionally do not grant generic public access to raw tenant tables. Public verification is represented as an explicit service context:

- `app.role = 'public_verification'`
- `app.is_platform_admin = 'false'`

Because PostgreSQL RLS is row-level, not column-level, the public verification context must not get blanket raw table reads on `QRCode` or `VerificationDecision`. The prototype SQL instead includes a narrow `app_rls.public_verify_qr_safe(public_code text)` function that returns only QR-safe fields for staging tests. Production should keep using the application service DTO path unless a DBA-reviewed database function/view contract is adopted.

Background jobs/workers are represented explicitly:

- `app.role IN ('background_worker', 'system_worker')`

This keeps public and worker access visible in test setup instead of accidentally inheriting tenant or platform access.

## Staging/Disposable DB Test Plan

Run this only against a disposable staging database restored from sanitized data or seeded fixtures.

Local P2 behavioral command:

```sh
MSCQR_RLS_PROTOTYPE_TEST=true npm --prefix backend run test:rls:prototype
```

The command starts the local P2 Postgres service, creates a disposable database, applies current Prisma migrations, applies the non-production prototype SQL, verifies the RLS behaviors, applies rollback SQL from fail-safe cleanup, confirms RLS/FORCE are disabled, and drops the temporary database. It also includes a forced-failure cleanup regression so persistent P2 databases are not left with prototype RLS enabled after post-apply assertion failures.

1. Prepare
   - Apply `documents/security/mscqr_staging_rls_prototype.sql` manually with a DBA-owned session.
   - Confirm no production database URL is present.
   - Confirm `SELECT relname, relrowsecurity, relforcerowsecurity FROM pg_class WHERE relnamespace = 'public'::regnamespace AND relrowsecurity;` returns only the prototype target tables and shows both `relrowsecurity = true` and `relforcerowsecurity = true`.

2. Licensee isolation
   - Seed licensee A and licensee B, each with a batch.
   - In one transaction set `app.role = 'LICENSEE_ADMIN'`, `app.licensee_id = licensee_a`, `app.is_platform_admin = false`.
   - Assert `SELECT * FROM "Batch" WHERE "licenseeId" = licensee_a` returns rows.
   - Assert `SELECT * FROM "Batch" WHERE "licenseeId" = licensee_b` returns zero rows.
   - Assert attempted update/delete of licensee B batch affects zero rows or errors.

3. Manufacturer linked-licensee isolation
   - Seed manufacturer M linked only to licensee A in `"ManufacturerLicenseeLink"`.
   - Set `app.role = 'MANUFACTURER'`, `app.manufacturer_id = manufacturer_m`, `app.user_id = manufacturer_m`.
   - Assert M can read licensee A batch/QR/print rows.
   - Assert M cannot read licensee B batch/QR/print rows.
   - Add link to licensee B inside a separate admin transaction and assert access changes only after the link exists.

4. Public verification minimized path
   - Set `app.role = 'public_verification'` with no user/licensee/manufacturer context.
   - Assert direct raw `SELECT * FROM "Batch"` and `SELECT * FROM "User"` return zero rows.
   - Assert direct raw `SELECT * FROM "QRCode"` and `SELECT * FROM "VerificationDecision"` return zero rows for public verification context.
   - Assert `SELECT * FROM app_rls.public_verify_qr_safe('<public-code>')` returns only QR-safe/minimized fields.
   - Confirm the application service still maps rows to sanitized DTOs and does not expose raw table fields.

5. Platform admin bypass
   - Set `app.is_platform_admin = true`, `app.role = 'PLATFORM_SUPER_ADMIN'`.
   - Assert cross-licensee reads work.
   - Reset context inside a new transaction with `app.is_platform_admin = false`; assert cross-licensee reads stop.

6. Background worker explicit access
   - Set `app.role = 'background_worker'`.
   - Assert print worker queries on `PrintJob`, `PrintItem`, `QRCode`, `Printer`, and `BatchPrintPackToken` work.
   - Set `app.role = 'LICENSEE_ADMIN'` with no matching tenant and assert the same worker-wide query does not work.

7. Rollback
   - Apply `documents/security/mscqr_staging_rls_rollback.sql`.
   - Assert `relrowsecurity = false`, `relforcerowsecurity = false`, and policies are removed for the target tables.
   - Re-run application-layer authorization tests to confirm current app auth remains the controlling mechanism.

## Production Rollout Risks And Blockers

Production blockers:

- No production-safe request-scoped Prisma transaction helper is wired for every protected query.
- Existing protected flows still perform multiple Prisma calls outside one guaranteed transaction boundary.
- Pooling mode must be confirmed. Session-level settings are unsafe with pooled connections; transaction-local settings require every protected query to run inside the same transaction.
- Public verification and customer verification sessions need service-role policy coverage plus DTO-level tests before enforcement.
- Worker jobs need explicit role/context design so background processing does not silently fail or become over-broad.
- Some ownership columns are nullable by design (`Incident.licenseeId`, `AuditLog.licenseeId`, `Printer.licenseeId`, `VerificationDecision.licenseeId`, `PrintReissueRequest.licenseeId`). Policies must decide whether nullable rows are platform-only, public-service-only, or backfilled before production.
- Prisma migrations must not auto-apply this prototype. Rollout needs a DBA-reviewed staged migration and rollback window.

Scalability blockers:

- Relation-based policies on `PrintItem`, `PrintJob`, `BatchPrintPackToken`, `CustomerVerificationSession`, and `SupportTicket` can add planner overhead. Staging must benchmark common list/detail/report queries before any production rollout.
- Add or confirm indexes for policy predicates, especially tenant and relation columns used in `EXISTS` checks.
- Large analytics/reporting paths should remain app-scoped and may need read replicas/materialized views before RLS enforcement.

Security recommendations:

- Treat RLS as a second lock, not the primary lock.
- Keep application-layer authorization and route guard tests unchanged.
- Add a CI check that blocks production deployment if prototype RLS SQL appears under `backend/prisma/migrations`.
- Add a staging-only smoke test that verifies `SET LOCAL` context is cleared after transaction commit.
