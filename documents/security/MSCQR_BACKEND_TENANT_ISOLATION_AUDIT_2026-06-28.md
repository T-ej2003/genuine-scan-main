# MSCQR Backend Tenant Isolation Audit - 2026-06-28

## Executive Summary

This audit inspected Prisma access paths in the requested backend roots for tenant-owned models and the requested operations:
`findMany`, `findFirst`, `findUnique`, `update`, `updateMany`, `delete`, `deleteMany`, `upsert`, `$queryRaw`, and `$queryRawUnsafe`.

No PostgreSQL RLS migration was added. No broad refactor was made.

Results:

- Existing roots scanned: `backend/src/controllers`, `backend/src/services`, `backend/src/middleware`, `backend/tests`.
- Requested roots not present in this checkout: `backend/src/lib`, top-level `tests`.
- Tenant-owned models reviewed: `Organization`, `Licensee`, `User`, `Batch`, `QRCode`, `PrintJob`, `PrintItem`, `QrScanLog`, `Incident`, `AuditLog`, `Printer`, `TenantFeatureFlag`, `VerificationDecision`, `PrintReissueRequest`, `BatchPrintPackToken`, `CustomerVerificationSession`, `SupportTicket`.
- Prisma access paths inventoried: 478 across source and backend tests.
- `$queryRawUnsafe`: none found.
- Confirmed production tenant leak: none found in this pass.
- Regression tests added for the highest-risk platform-global routes: support tickets and IR incidents now prove licensee/manufacturer users cannot list or detail cross-tenant records.

Primary test command:

```sh
PATH=/bin:/usr/bin:/usr/local/bin:/opt/homebrew/bin npm --prefix backend run test:p2:db
```

## Classification Legend

- Scoped and safe: query has a direct tenant/manufacturer/user predicate, or is protected by a scoped loader before mutation.
- Intentionally global super_admin only: query is global by design and route/function access is restricted to platform/super-admin roles.
- Public but minimized/safe: public endpoint uses opaque identifiers, rate limits, bounded selects, or returns minimized data.
- Unsafe missing tenant scope: confirmed tenant-owned query reachable by a lower-privileged tenant without scope. None confirmed.
- Unknown/manual review required: low-level helper relies on caller preconditions or operational context; safe in current call sites but should not be reused casually.

## High-Risk Findings And Fixes

| File path | Function | Model | Classification | Risk level | Evidence | Test command |
|---|---|---|---|---|---|---|
| `backend/src/controllers/supportController.ts` | `listSupportTickets`, `getSupportTicket`, `patchSupportTicket`, `addSupportMessage` | `SupportTicket`, `Incident`, `AuditLog` | Intentionally global super_admin only | Medium before regression, low after | Routes use `requirePlatformAdmin` at `backend/src/routes/index.ts:2189-2206`; controller also applies licensee fallback if reused outside platform routes | `PATH=/bin:/usr/bin:/usr/local/bin:/opt/homebrew/bin npm --prefix backend run test:p2:db` |
| `backend/src/controllers/irIncidentController.ts` | `listIrIncidents`, `getIrIncident`, `patchIrIncident`, event/action/review/communication handlers | `Incident`, `QRCode`, `User`, `Licensee`, `AuditLog`, `VerificationDecision` | Intentionally global super_admin only | Medium before regression, low after | Routes use `requirePlatformAdmin` at `backend/src/routes/index.ts:2320-2342` | `PATH=/bin:/usr/bin:/usr/local/bin:/opt/homebrew/bin npm --prefix backend run test:p2:db` |
| `backend/tests/p2DbAuthorization.test.js` | P2 DB authorization flow | `SupportTicket`, `Incident` | Scoped regression coverage | Low | Added denials and no-leak assertions at lines 112-114 and 133-141 | `PATH=/bin:/usr/bin:/usr/local/bin:/opt/homebrew/bin npm --prefix backend run test:p2:db` |

## Production Query Classification Matrix

| File path | Function / access path | Model(s) | Classification | Risk level | Notes |
|---|---|---|---|---|---|
| `backend/src/middleware/tenantIsolation.ts` | `enforceTenantIsolation`, `getEffectiveLicenseeId` | `Licensee`, request tenant context | Scoped and safe | Low | Blocks non-platform explicit foreign `licenseeId`; manufacturers are restricted to linked/default licensees. |
| `backend/src/services/accessControlService.ts` | `buildScopedWhere`, `buildScopedUserWhere`, `buildIncidentScopeWhere`, `findScopedBatch`, `findScopedQrCode` | `Batch`, `QRCode`, `User`, `Incident` | Scoped and safe | Low | Central scope builder for tenant/manufacturer/incident access. |
| `backend/src/controllers/qrController.ts` | Batch list/detail/create/rename/delete/bulk-delete/release/assign-manufacturer flows | `Batch`, `QRCode`, `User`, `Licensee`, `Printer` | Scoped and safe | Low | Uses scoped loaders and same-licensee/manufacturer predicates before direct update/delete calls. |
| `backend/src/controllers/qrController.ts` | QR export, signed-link generation, legacy rotation, admin block QR/batch | `QRCode`, `Batch` | Intentionally global super_admin only | Low | Protected by platform admin routes; scoped export by `licenseeId` is covered in P2 DB test. |
| `backend/src/controllers/licenseeController.ts` | Licensee CRUD | `Licensee`, `Organization`, `User` | Intentionally global super_admin only | Low | Platform-admin management surface. |
| `backend/src/controllers/userController.ts` | User create/update/delete/restore/list | `User`, `Licensee`, `Organization` | Scoped and safe | Low | Target user checks use role/scope validation; mutations happen after scoped target validation. |
| `backend/src/controllers/auditController.ts` | `getLogs`, `exportLogsCsv` | `AuditLog`, `User` | Scoped and safe | Low | Tenant admins get own `licenseeId`; manufacturers are limited to own user; platform roles can review globally. |
| `backend/src/controllers/auditController.ts` | Fraud report list/respond | `AuditLog` | Intentionally global super_admin only | Low | Explicit super-admin function and route restrictions. |
| `backend/src/controllers/incidentController.ts` and `backend/src/services/incidentService.ts` | Tenant-facing incident list/detail/report/update helpers | `Incident`, `QRCode`, `QrScanLog`, `SupportTicket` | Scoped and safe / public minimized for report | Low | Uses `buildIncidentScopeWhere`; public incident report derives tenant context from QR data. |
| `backend/src/controllers/irIncidentController.ts` | IR incident console | `Incident`, `QRCode`, `User`, `VerificationDecision` | Intentionally global super_admin only | Low | Platform-only route gate; regression tests added for licensee denial. |
| `backend/src/controllers/supportController.ts` | Platform support console | `SupportTicket`, `Incident`, `AuditLog` | Intentionally global super_admin only | Low | Platform-only route gate; regression tests added for licensee/manufacturer denial. |
| `backend/src/controllers/supportController.ts` | `trackSupportTicketPublic` | `SupportTicket` | Public but minimized/safe | Medium | Rate-limited reference lookup with optional email check; returns only status/priority/timestamps/SLA state. |
| `backend/src/controllers/governanceController.ts` and `backend/src/services/governanceService.ts` | Feature flags, retention, compliance pack/report/download, evidence bundle | `TenantFeatureFlag`, `Incident`, `AuditLog`, `Licensee` | Intentionally global super_admin only or scoped approval context | Low | Governance routes use platform admin gates except approval workflow, which validates requester/reviewer context. |
| `backend/src/services/sensitiveActionApprovalService.ts` | Approval execution | `QRCode`, `Batch`, `Printer`, `TenantFeatureFlag`, approval rows | Scoped and safe | Medium | Direct mutations occur after approval authorization; keep as controlled workflow only. |
| `backend/src/controllers/qrLogController.ts` and `backend/src/services/scanLogReportingService.ts` | Scan log reporting/history | `QrScanLog`, `QRCode`, `Batch` | Scoped and safe | Low | Licensee/manufacturer filters are resolved before query construction; raw SQL is parameterized. |
| `backend/src/services/qrTrackingAnalyticsService.ts` | Tracking analytics raw SQL | `QrScanLog`, `QRCode`, `Batch` | Scoped and safe | Low | Raw SQL uses `Prisma.sql` parameters; relation name is escaped and not direct user input. |
| `backend/src/services/analyticsService.ts` and rollup services | Dashboard/rollup metrics | `Batch`, `QRCode`, `QrScanLog` | Scoped and safe / platform global where authorized | Low | Caller supplies tenant scope; platform aggregate use is intentional. |
| `backend/src/controllers/print-job/queryHandlers.ts` and `backend/src/services/printJobScopeService.ts` | Print job list/detail/status/control | `PrintJob`, `PrintItem`, `Batch`, `Printer` | Scoped and safe | Low | Uses `buildScopedPrintJobWhere` by platform/licensee/manufacturer. |
| `backend/src/services/networkDirectPrintService.ts` and `backend/src/services/networkIppPrintService.ts` | User-visible operational views and dispatch workers | `PrintJob`, `PrintItem`, `Batch` | Scoped and safe for user views; intentionally worker-global for dispatch | Medium | Worker functions load jobs by ID for internal execution; not tenant-facing route surfaces. |
| `backend/src/controllers/printAgentJobController.ts` | Local-agent claim/ack/confirm/fail | `Printer`, `PrintJob`, `PrintItem`, `Batch`, `QRCode`, `AuditLog` | Scoped and safe | Medium | Device request is verified, then job is constrained by manufacturer ID, printer registration, printer ID, and print session. |
| `backend/src/controllers/printerGatewayController.ts` | Site gateway heartbeat/claim/ack/confirm/fail | `Printer`, `PrintJob`, `PrintItem`, `Batch`, `QRCode` | Scoped and safe | Medium | Gateway authenticates by printer gateway ID/secret; jobs are constrained to authenticated `printerId` and print mode. |
| `backend/src/controllers/printerController.ts` and `backend/src/services/printerRegistryService.ts` | Printer list/create/update/test/delete | `Printer` | Scoped and safe | Medium | Controllers load printer through `getRegisteredPrinterForManufacturer`; low-level upsert/delete helpers rely on caller pre-scope. |
| `backend/src/services/printerRegistryService.ts` | `upsertManagedNetworkPrinter`, `deleteNetworkDirectPrinter` | `Printer` | Unknown/manual review required | Medium | Current call sites pre-check scope; these helpers should remain internal or gain explicit scoped params before wider reuse. |
| `backend/src/services/printValidationEvidenceService.ts` | Evidence lookup | `Batch`, `PrintJob`, `QRCode`, `User` | Scoped and safe by caller precondition | Medium | Called from scoped print/validation flows; direct batch/job lookup should not become a public route helper without scope wrapper. |
| `backend/src/services/printReservationService.ts` | Reservable QR raw SQL | `QRCode`, `PrintItem`, `Batch` | Scoped and safe by caller precondition | Medium | Raw SQL is parameterized and batch-bound; callers should continue to load scoped batch first. |
| `backend/src/services/printReissueService.ts` and `backend/src/services/printReissueRequestWorkflowService.ts` | Reissue request create/list/decide/start and print pack projection | `PrintReissueRequest`, `PrintJob`, `PrintItem`, `QRCode`, `Batch` | Scoped and safe | Medium | Requests are scoped by print job/requester/approver context; projection SQL runs over already-scoped IDs. |
| `backend/src/services/verificationDecisionService.ts` | Public verification decision creation | `VerificationDecision`, `QRCode`, `Batch`, `Licensee` | Public but minimized/safe | Medium | Decision context comes from QR verification path, not arbitrary tenant request params. |
| `backend/src/services/verificationDecisionReadService.ts` | Latest decision lookup by QR/batch IDs | `VerificationDecision` | Scoped and safe by caller precondition | Medium | Read helper trusts scoped input ID sets; current call sites pass IDs from scoped queries. |
| `backend/src/services/customerVerificationSessionService.ts` | Customer proof/session lifecycle | `CustomerVerificationSession`, `VerificationDecision`, `QRCode` | Public but minimized/safe | Medium | Uses opaque session/proof identifiers and constrained response snapshots. |
| `backend/src/services/publicVerificationPostScanService.ts` and public scan controllers | Public scan mutation/read path | `QRCode`, `QrScanLog`, `Incident`, `VerificationDecision` | Public but minimized/safe | Medium | Public by product design; data is derived from QR/signature verification and existing rate-limit/security tests. |
| `backend/src/services/policyEngineService.ts` and `backend/src/services/soarService.ts` | Policy detection and containment | `QrScanLog`, `QRCode`, `Incident` | Scoped and safe / internal global worker | Medium | Internal policy processing may scan cross-tenant events, then writes tenant-owned outcomes with derived tenant context. |
| `backend/src/services/attentionQueueService.ts` | Latest attention rows | `Incident`, `PrintJob`, `SupportTicket`, `AuditLog` | Scoped and safe / platform aggregate | Low | Tenant filters are used for tenant views; platform aggregate is expected. |
| `backend/src/services/auth/*` | Auth, MFA, invite, password reset, email verification | `User`, `Licensee`, `Organization` | Scoped and safe / public auth minimized | Medium | Auth lookups are by credential/token/email flows; user-management routes still enforce tenant role boundaries. |
| `backend/src/services/auth/superAdminBootstrapService.ts` | Bootstrap lock and platform admin creation | `User`, `Organization` | Intentionally global super_admin/bootstrap only | Medium | Uses advisory lock and configured platform bootstrap context. |
| `backend/tests/*.js` | Fixtures, mocks, and authz assertions | Tenant-owned models in test data | Scoped and safe for test-only use | Low | Test DB setup intentionally creates cross-tenant records to verify isolation. |

## Raw SQL Review

No `$queryRawUnsafe` calls were found.

Raw SQL found in production source uses `Prisma.sql`, `Prisma.join`, or operational `Prisma.raw` for escaped identifiers/DDL. Tenant-sensitive raw SQL paths were classified as safe when one of these holds:

- The SQL includes resolved `licenseeId`, `manufacturerId`, or `batchId` predicates.
- The input IDs were loaded by a scoped Prisma query immediately before projection.
- The raw statement is operational DDL/partition management, not a tenant-facing read.

Manual-review raw SQL helpers:

- `backend/src/services/hotEventPartitionService.ts`: uses `Prisma.raw` for partition DDL and inspection. This is operational/admin code, not a tenant query path.
- `backend/src/services/printReservationService.ts`: batch-bound reservation SQL must remain behind scoped batch loaders.
- `backend/src/services/printReissueService.ts`: projection SQL should continue to receive already-scoped print job IDs.

## Regression Tests Added

Updated `backend/tests/p2DbAuthorization.test.js`:

- Licensee admin is denied from `/api/support/tickets` and response must not leak another tenant support marker.
- Licensee admin is denied from `/api/ir/incidents` and response must not leak another tenant incident marker.
- Licensee admin is denied from `/api/ir/incidents/:id` for another tenant's incident and response must not leak the incident marker.

These tests specifically protect the highest-risk global read surfaces where controller queries are intentionally broad but must remain platform-only.

## CTO Recommendations

1. Keep PostgreSQL RLS deferred for now, but add a route-to-query authorization contract test that maps every platform-global controller to `requirePlatformAdmin`.
2. Convert caller-precondition helpers into named scoped loaders over time, especially `upsertManagedNetworkPrinter`, `deleteNetworkDirectPrinter`, `verificationDecisionReadService`, `printReservationService`, and reissue projection helpers.
3. Add a static Prisma audit script in CI that fails on new tenant-owned `findUnique/update/delete` calls unless the nearby code uses a scoped helper, platform-only guard, or a documented public-minimized exemption.
4. Require email or one-time verification for public support ticket tracking if support tickets may ever expose sensitive incident status to customers or distributors.
5. Add per-tenant query budget and pagination ceilings to all analytics/reporting raw SQL paths before larger customer scale, especially scan-log history and tracking analytics.
6. Keep worker-global print dispatch functions isolated from Express routes; expose only scoped operational views to authenticated users.

## Final Classification

- Scoped and safe: dominant pattern across tenant-facing controllers and service loaders.
- Intentionally global super_admin only: support console, IR console, governance, licensee management, admin QR operations, fraud-report review.
- Public but minimized/safe: scan/verification/session/support-track flows.
- Unsafe missing tenant scope: none confirmed.
- Unknown/manual review required: low-level helper functions that depend on current caller preconditions, listed above.
