# MSCQR Staging RLS DB Touch Map

Date: 2026-07-09
Environment: staging
Scope: discovery only
Production impact: none

This report documents the query and table surface for the first staging RLS validation candidates:

- `GET /api/qr/batches`
- `GET /api/qr/batches/:id/allocation-map`
- `GET /api/manufacturer/printers`

No RLS flags were enabled. No database policies were applied. No Terraform apply was run. Production was not touched.

## Discovery Sources

Runtime path files inspected:

- `backend/src/routes/index.ts`
- `backend/src/controllers/qrController.ts`
- `backend/src/controllers/printerController.ts`
- `backend/src/services/stagingRlsBatchReadService.ts`
- `backend/src/services/stagingRlsBatchAllocationMapService.ts`
- `backend/src/services/stagingRlsManufacturerPrintersReadService.ts`
- `backend/src/services/accessControlService.ts`
- `backend/src/services/manufacturerScopeService.ts`
- `backend/src/services/batchAllocationService.ts`
- `backend/src/services/printReservationService.ts`
- `backend/src/services/printerRegistryService.ts`
- `backend/src/services/printerConnectionService.ts`
- `backend/src/printing/registry/printerProfileService.ts`
- `backend/src/lib/stagingRlsBatchReadContext.ts`
- `backend/src/lib/rlsTransactionContextPrototype.ts`
- `backend/src/observability/stagingRlsBatchReadProof.ts`
- `backend/src/observability/stagingRlsBatchAllocationMapProof.ts`
- `backend/src/observability/stagingRlsManufacturerPrintersReadProof.ts`
- `backend/tests/rlsBatchesReadRuntimeP2.test.js`
- `backend/tests/rlsBatchAllocationMapRuntimeP2.test.js`
- `backend/tests/rlsManufacturerPrintersReadRuntimeP2.test.js`
- `backend/tests/rlsTransactionContextPrototypeP2.test.js`
- `backend/tests/rlsPolicyExplainPrototypeP2.test.js`
- `documents/security/mscqr_staging_rls_prototype.sql`

## Endpoint Touch Map

### GET /api/qr/batches

Route:
- `protectedReadRouter.get("/qr/batches", ..., authenticate, ..., enforceTenantIsolation, getBatches)`

Controller and services:
- `getBatches`
- `listScopedBatchReadPayload`
- `buildScopedWhere`
- `resolveScopedLicenseeAccess`
- `listBatchOperationalSummaries` when the staged flag is on
- `listCachedBatchOperationalSummaries` when the staged flag is off
- `enrichBatchSummaries`
- `listReservableQrCodeSummaries`

Prisma and raw SQL reads:
- `Batch.findMany`
- `Batch.count`
- `Batch.include.licensee`
- `Batch.include.manufacturer`
- `Batch.include.parentBatch`
- `Batch.include.rootBatch`
- `Batch._count.qrCodes`
- `InventoryStatusRollup.findMany`
- `QRCode.groupBy` by `batchId`
- `QRCode.groupBy` by `batchId,status`
- Raw SQL reservable summary over `QRCode q`
- Raw SQL left joins to `PrintItem pi`, `PrintSession ps`, and `PrintJob pj`
- Potential `ManufacturerLicenseeLink.findMany` when manufacturer linked licensee IDs are not already present in auth claims

Touched tables/models:
- `Batch`
- `Licensee`
- `User`
- `ManufacturerLicenseeLink`
- `InventoryStatusRollup`
- `QRCode`
- `PrintItem`
- `PrintSession`
- `PrintJob`

Important behavior:
- Current app scoping protects the route with `buildScopedWhere`.
- Licensee/org users are scoped by licensee.
- Manufacturer users are scoped by accessible licensee IDs plus `Batch.manufacturerId`.
- Platform admins keep broad visibility through `app.is_platform_admin`.
- Raw SQL left joins mean hidden print rows can change reservable counts, not just remove optional details.

### GET /api/qr/batches/:id/allocation-map

Route:
- `protectedReadRouter.get("/qr/batches/:id/allocation-map", ..., authenticate, ..., enforceTenantIsolation, getBatchAllocationMap)`

Controller and services:
- `getBatchAllocationMap`
- `getScopedBatchAllocationMapPayload`
- `findScopedBatch`
- `buildScopedWhere`
- `resolveScopedLicenseeAccess`
- `getBatchAllocationMap` from `batchAllocationService`
- `enrichBatchSummaries`
- `listReservableQrCodeSummaries`

Prisma and raw SQL reads:
- `Batch.findFirst` for the requested batch
- `Batch.findFirst` again for the focus batch inside allocation map loading
- `Batch.findMany` for source, parent, child, and root lineage under the focus licensee
- `Batch.include.licensee`
- `Batch.include.manufacturer`
- `Batch._count.qrCodes`
- `InventoryStatusRollup.findMany`
- `QRCode.groupBy` by `batchId`
- `QRCode.groupBy` by `batchId,status`
- Raw SQL reservable summary over `QRCode q`
- Raw SQL left joins to `PrintItem pi`, `PrintSession ps`, and `PrintJob pj`
- Potential `ManufacturerLicenseeLink.findMany` when manufacturer linked licensee IDs are not already present in auth claims

Touched tables/models:
- `Batch`
- `Licensee`
- `User`
- `ManufacturerLicenseeLink`
- `InventoryStatusRollup`
- `QRCode`
- `PrintItem`
- `PrintSession`
- `PrintJob`

Important behavior:
- Current app scoping first proves the requested batch is visible.
- After the focus batch is visible, the allocation-map query reads related lineage batches by `licenseeId`.
- A policy that only allows `Batch.manufacturerId = app.manufacturer_id` can break allocation maps by hiding parent/root/source rows that are licensee-owned but unassigned.
- Raw SQL left joins have the same count-safety risk as the batch list route.

### GET /api/manufacturer/printers

Route:
- `protectedReadRouter.get("/manufacturer/printers", authenticate, requireOpsUser, ..., enforceTenantIsolation, listPrinters)`

Controller and services:
- `listPrinters`
- `resolveScope`
- `resolveAccessibleLicenseeIdsForUser`
- `listScopedManufacturerPrintersReadPayload`
- `listRegisteredPrintersForManufacturer`
- `printerListWhere`
- `getPrinterProfileForPrinter`
- `getPrinterConnectionStatusForUser`
- `loadLatestRegistrationForUser`
- `buildLocalPrinterStatus`
- `buildPrinterRegistryStatus`

Prisma reads:
- `ManufacturerLicenseeLink.findMany` can run before the staged transaction when manufacturer auth claims do not include linked licensee IDs
- `Printer.findMany`
- `Printer.include.printerRegistration`
- `PrinterProfile.findUnique`
- `PrinterProfile.include.onboardingSnapshot`
- `PrinterProfile.include.snapshots`
- `PrinterRegistration.findFirst`
- `PrinterRegistration.include.attestations`
- `PrinterRegistration.include.agentSessions`

Touched tables/models:
- `ManufacturerLicenseeLink`
- `Printer`
- `PrinterRegistration`
- `PrinterProfile`
- `PrinterProfileSnapshot`
- `PrinterAttestation`
- `PrinterAgentSession`
- `User`

Important behavior:
- Current app scoping protects network printers by `licenseeId`, non-empty `licenseeIds`, or `orgId`; an explicitly empty linked-licensee set now fails closed instead of falling through to all network printers.
- Current app scoping protects local-agent printers by `Printer.assignedUserId` or `Printer.printerRegistration.userId`.
- Under the staged printer flag, manufacturer linked-licensee resolution now runs inside the transaction-local RLS context when linked IDs are not supplied.
- `getPrinterConnectionStatusForUser` now accepts a Prisma client and uses the staged transaction client for `PrinterRegistration`, `PrinterAttestation`, and `PrinterAgentSession` reads.
- `getPrinterProfileForPrinter` already accepts the staged transaction client, and the printer list path passes it through.
- `rlsManufacturerPrintersReadRuntimeP2.test.js` now validates network printers plus local-agent assigned-user, registration, latest attestation, connected agent session, printer profile, and profile snapshot coverage.

## Table Policy Shape

| Table/model | Tenant/scope columns | Relationship | Current app-layer protection | Proposed SELECT policy shape | Platform admin bypass | Manufacturer access | Risk notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `Batch` | `licenseeId`, `manufacturerId`, `parentBatchId`, `rootBatchId` | Batch belongs to a licensee and may be assigned to a manufacturer user. | `buildScopedWhere`; allocation-map first uses `findScopedBatch`. | Direct `licenseeId`; direct `manufacturerId`; optionally linked-licensee access through `ManufacturerLicenseeLink` for lineage reads. | Required. | Direct for assigned child batches; linked-licensee access is needed for allocation-map lineage. | A manufacturer-only policy can hide parent/root rows; a broad linked-licensee policy is less strict than batch-list app filtering and relies on app-layer scope. |
| `Licensee` | `id`, `orgId` | Owns batches, QR codes, printers, users, and links. | Included only after scoped batch selection in these routes. | Direct `id = app.licensee_id` or linked through `ManufacturerLicenseeLink`; org fallback only if needed. | Required. | Through `ManufacturerLicenseeLink`. | If hidden, batch includes can lose licensee metadata. |
| `User` | `id`, `licenseeId`, `orgId`, `role` | Manufacturer is a `User`; user also owns local-agent registrations. | Included as batch manufacturer after scoped batch selection. | Direct self, direct tenant/org, or `EXISTS Batch WHERE Batch.manufacturerId = User.id AND visible Batch`. | Required. | Direct self for manufacturer actor; relation-based for licensee seeing assigned manufacturers. | Existing prototype user policy may not expose external manufacturer rows for licensee batch includes unless relation-based access is added. |
| `ManufacturerLicenseeLink` | `manufacturerId`, `licenseeId` | Defines manufacturer-to-licensee access. | Used by `resolveAccessibleLicenseeIdsForUser` when claims lack links. | Direct current manufacturer, direct current licensee, or platform admin. Avoid recursive `can_access_licensee` calls inside this table's own policy. | Required. | Direct `manufacturerId = app.manufacturer_id`. | The staged printer read wrapper now resolves missing linked-licensee IDs inside the transaction context; manual SQL still must avoid recursive helper policies. |
| `InventoryStatusRollup` | `batchId`, `licenseeId`, `manufacturerId` | Rollup for batch inventory counts. | Queried only for already selected batch IDs. | Direct `licenseeId`; direct `manufacturerId`; or `EXISTS Batch WHERE Batch.id = InventoryStatusRollup.batchId AND visible Batch`. | Required. | Direct and relation-based. | Must align with `QRCode` policy or rollup-vs-fallback counts can mismatch. |
| `QRCode` | `licenseeId`, `batchId`, `printJobId` | QR code belongs to licensee and usually a batch. | Queried only for scoped batch IDs in these endpoints. | Direct `licenseeId` or `EXISTS Batch WHERE Batch.id = QRCode.batchId AND visible Batch`. | Required. | Through `Batch` and linked licensee. | GroupBy and raw SQL summaries depend on this being the base visible table. |
| `PrintItem` | `printSessionId`, `qrCodeId` | No direct tenant column; belongs to QR and print session. | Only touched through raw SQL joins from scoped QR batches. | `EXISTS QRCode WHERE QRCode.id = PrintItem.qrCodeId AND visible QRCode`, plus optional session relation. | Required. | Through QR/batch/session relation. | If hidden in left joins, QR rows can be overcounted as reservable. |
| `PrintSession` | `batchId`, `manufacturerId`, `printerRegistrationId`, `printerId` | Session belongs to a batch and manufacturer. | Only touched through raw SQL joins from scoped QR batches. | Direct `manufacturerId` or `EXISTS Batch WHERE Batch.id = PrintSession.batchId AND visible Batch`. | Required. | Direct and through batch relation. | Must be visible enough for reusable-print SQL predicates. |
| `PrintJob` | `batchId`, `manufacturerId`, `printerId` | Print job belongs to batch and manufacturer. | Only touched through raw SQL joins from scoped QR batches. | Direct `manufacturerId` or `EXISTS Batch WHERE Batch.id = PrintJob.batchId AND visible Batch`. | Required. | Direct and through batch relation. | Hidden job rows can alter raw SQL recovery and reservable summaries. |
| `Printer` | `licenseeId`, `orgId`, `assignedUserId`, `createdByUserId`, `printerRegistrationId` | Network printers are licensee/org scoped; local printers are user/registration scoped. | `printerListWhere`. | Direct licensee/org, direct assigned/created user, or `EXISTS PrinterRegistration WHERE id = printerRegistrationId AND userId = app.user_id`. | Required. | Through linked licensee for network printers; direct user/registration for local-agent printers. | Current test policy covers `Printer` only; local-agent status tables still need coverage. |
| `PrinterRegistration` | `userId`, `licenseeId`, `orgId` | Owns local-agent trust, attestations, sessions, and local printers. | `getPrinterConnectionStatusForUser(userId)` and printer include. | Direct `userId = app.user_id`, direct licensee/org, or `EXISTS Printer WHERE Printer.printerRegistrationId = PrinterRegistration.id AND visible Printer`. | Required. | Usually direct current user for local-agent; licensee/org for admin review only if intended. | Status reads are now transaction-aware under the staged printer wrapper; manual SQL should still test missing-context fail-closed behavior. |
| `PrinterAttestation` | `printerRegistrationId` | Trust heartbeat history for a registration. | Latest attestation is included under the current user's registration. | `EXISTS PrinterRegistration WHERE id = printerRegistrationId AND visible PrinterRegistration`. | Required. | Through registration. | Missing attestation can mark local agent stale or untrusted. |
| `PrinterAgentSession` | `registrationId`, `activePrintJobId` | Persistent local-agent session for a registration. | Connected session is included under the current user's registration. | `EXISTS PrinterRegistration WHERE id = registrationId AND visible PrinterRegistration`. | Required. | Through registration. | Missing session can mark persistent session disconnected. |
| `PrinterProfile` | `printerId` | Profile for a visible printer. | Looked up per printer returned by `Printer.findMany`. | `EXISTS Printer WHERE Printer.id = printerId AND visible Printer`. | Required. | Through visible printer. | If hidden, capability fields disappear from printer rows. |
| `PrinterProfileSnapshot` | `printerProfileId` | Snapshot history for a profile. | Included through visible profile lookup. | `EXISTS PrinterProfile JOIN Printer WHERE visible Printer`. | Required. | Through visible printer/profile. | If hidden, latest discovery snapshot and capability discovery can disappear. |

## Policy Dependencies

Required helper concepts for Part 2 manual templates:

- `app_rls.current_user_id()`
- `app_rls.current_licensee_id()`
- `app_rls.current_manufacturer_id()`
- `app_rls.current_organization_id()`
- `app_rls.is_platform_admin()`
- `app_rls.can_access_licensee(licensee_id)`
- `app_rls.can_access_batch(batch_id)`
- `app_rls.can_access_qr(qr_id)`
- `app_rls.can_access_printer(printer_id)`
- `app_rls.can_access_printer_registration(registration_id)`
- `app_rls.can_access_printer_profile(profile_id)`

Dependency ordering:

1. Context helpers.
2. Non-recursive `ManufacturerLicenseeLink` policy or helper.
3. `Licensee`, `User`, and `Batch`.
4. `QRCode`, `InventoryStatusRollup`, `PrintJob`, `PrintSession`, `PrintItem`.
5. `Printer`, `PrinterRegistration`, `PrinterAttestation`, `PrinterAgentSession`, `PrinterProfile`, `PrinterProfileSnapshot`.

Avoid recursive policies:

- Do not implement `ManufacturerLicenseeLink` access by calling `can_access_licensee`, because `can_access_licensee` itself reads `ManufacturerLicenseeLink`.
- Do not make `can_access_printer_registration` depend on `Printer` if the `Printer` policy simultaneously depends on `PrinterRegistration` without a non-recursive base case.

## Existing RLS Code Findings

The staging wrappers are false by default and set transaction-local values with `set_config(..., true)`:

- `MSCQR_STAGING_RLS_BATCHES_READ_ENABLED`
- `MSCQR_STAGING_RLS_BATCH_ALLOCATION_MAP_ENABLED`
- `MSCQR_STAGING_RLS_MANUFACTURER_PRINTERS_READ_ENABLED`

The blocked runtime context classes are:

- `public_verification`
- `printer_agent`
- `background_worker`
- `system_worker`

Proof logging exists for all three candidate endpoints and only records coarse route, flag, context class, duration, result shape or row count, success, and failure category.

Resolved by read-graph hardening:

- `getPrinterConnectionStatusForUser` and its registration loaders accept an optional Prisma client and use the staged transaction client for `PrinterRegistration`, `PrinterAttestation`, and `PrinterAgentSession`.
- `listPrinters` no longer performs manufacturer linked-licensee resolution before the staged wrapper for the read route.
- `stagingRlsManufacturerPrintersReadService` owns the read-route context derivation and resolves missing manufacturer linked-licensee IDs inside the transaction context.
- `rlsManufacturerPrintersReadRuntimeP2.test.js` now seeds and validates local-agent registration, latest attestation, connected agent session, printer profile, and profile snapshot data.

Remaining gaps before manual SQL templates:

- `documents/security/mscqr_staging_rls_prototype.sql` does not define policies for every discovered candidate table. Missing for these routes: `ManufacturerLicenseeLink`, `InventoryStatusRollup`, `PrintSession`, `PrinterRegistration`, `PrinterAttestation`, `PrinterAgentSession`, `PrinterProfile`, and `PrinterProfileSnapshot`.
- Manual templates still need non-recursive helper design for `ManufacturerLicenseeLink`, `PrinterRegistration`, `PrinterProfile`, and `PrinterProfileSnapshot`.

## Risk Notes

- Raw SQL left joins in `listReservableQrCodeSummaries` can produce incorrect counts if `PrintItem`, `PrintSession`, or `PrintJob` policies hide rows that are needed only to classify QR codes.
- `QRCode.groupBy` and `InventoryStatusRollup.findMany` must have equivalent scoping or visible count summaries can diverge.
- `Batch._count.qrCodes` runs as a relation count and must be validated against direct `QRCode` policy behavior.
- Batch allocation-map reads related lineage rows after the focus batch is authorized. Strict `manufacturerId`-only batch policy can hide parent/root/source rows for manufacturer users.
- Printer local-agent status is now transaction-aware under the staged printer route; manual policies still need missing-context fail-closed tests.
- Manufacturer linked-licensee lookup is now transaction-aware under the staged printer route; manual policies still need non-recursive link-table access.
- Platform admin bypass must be explicit and tested for every table; otherwise admin baselines can falsely fail.
- Sibling printer routes and QR child routes must remain outside the staged telemetry classification.

## Recommended Validation Order

1. Do not apply policies yet. First create manual, non-migration SQL templates and rollback templates that cover the full discovered table set.
2. Validate batch-list templates first on a disposable/staging clone because they exercise the broadest batch summary surface.
3. Validate allocation-map templates second, with parent/root/source and manufacturer-child lineage fixtures.
4. Validate printer network rows third with the full `Printer` plus `ManufacturerLicenseeLink` policy shape.
5. Validate printer local-agent rows fourth with `PrinterRegistration`, `PrinterAttestation`, `PrinterAgentSession`, `PrinterProfile`, and `PrinterProfileSnapshot` policies enabled together.
6. Only after per-route success, run combined flag checks in staging.

## Manual Review Checklist

- Confirm all candidate route flags are false before baseline.
- Confirm no production hostname, production DB URL, production secret, or production Terraform workspace is used.
- Confirm manual SQL templates are not placed under `backend/prisma/migrations`.
- Confirm rollback SQL drops every policy/function introduced by the manual template.
- Confirm `ManufacturerLicenseeLink` policy is non-recursive.
- Confirm `PrinterRegistration`, `PrinterAttestation`, and `PrinterAgentSession` policies are applied only with the staged transaction-aware printer read path.
- Confirm local-agent fixtures include registration, latest attestation, connected agent session, local printer row, printer profile, and profile snapshots.
- Confirm batch fixtures include parent/root/child lineage, rollup rows, QR codes, print items, print sessions, and print jobs.
- Confirm raw SQL count outputs match baseline IDs and counts, not only HTTP 200.
- Confirm proof events contain no raw user, licensee, batch, printer, device, token, IP, or email identifiers.
- Confirm platform admin, licensee admin, org admin, manufacturer, cross-tenant user, and missing-tenant cases are covered.
- Confirm all route checks are read-only.

## Part 2 Recommendation

Create `documents/security/mscqr_staging_rls_candidate_templates_2026-07-09.sql` and a paired rollback file as non-applied, manually reviewed artifacts. Split the template into route-labeled sections and include the full printer local-agent status/profile table set now that the staged route owns those reads.

Senior engineering recommendation: treat this as a scale-hardening milestone, not only a compliance task. The best next feature is a small staging RLS dashboard that shows route, flag state, context class, success/failure category, row-count deltas, and p95 duration from proof events. The best security fix remaining is a reusable test helper that applies candidate table policies in disposable databases so every future staged route proves its full read graph before manual SQL templates are reviewed.
