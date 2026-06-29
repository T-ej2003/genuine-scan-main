# MSCQR RLS Policy Performance and Index Analysis - 2026-06-29

This is a staging-only analysis for the non-applied MSCQR PostgreSQL RLS prototype. It does not enable RLS in production, does not change the production database, does not create Prisma migrations, and does not replace existing backend application-layer tenant authorization.

## Sources Inspected

- Prototype policy SQL: `documents/security/mscqr_staging_rls_prototype.sql`
- Rollback SQL: `documents/security/mscqr_staging_rls_rollback.sql`
- Runtime wiring inventory: `documents/security/MSCQR_RLS_RUNTIME_WIRING_INVENTORY_2026-06-29.md`
- Prisma schema indexes: `backend/prisma/schema.prisma`
- Migration-created indexes: `backend/prisma/migrations/**/*.sql`
- Candidate route/service paths:
  - `backend/src/controllers/qrController.ts`
  - `backend/src/services/batchAllocationService.ts`
  - `backend/src/controllers/incidentController.ts`
  - `backend/src/services/incidentService.ts`
  - `backend/src/controllers/printerController.ts`
  - `backend/src/services/printerRegistryService.ts`
  - `backend/src/controllers/printerAgentController.ts`
  - `backend/src/services/verificationDecisionReadService.ts`

## Executive Summary

The prototype policies are structurally viable for a staging experiment, but relation-heavy RLS predicates will add planner work on the exact tables that are high-volume or user-facing: `QRCode`, `QrScanLog`, `VerificationDecision`, `PrintItem`, `Batch`, `Incident`, `SupportTicket`, and `Printer`. Most direct tenant keys already have single-column indexes. The main index risk is that existing indexes do not always match future RLS plus route ordering shapes, especially list endpoints that combine tenant filters with `updatedAt`, `createdAt`, or status.

Before enabling RLS on any high-volume staging runtime path, add the needed indexes separately and validate with staging `EXPLAIN ANALYZE` against realistic row counts. Production index creation must use a separate `CONCURRENTLY` plan with lock and rollback analysis.

## RLS Predicate Families and Required Indexes

| Predicate family | Prototype usage | Required index support | Current status |
| --- | --- | --- | --- |
| Direct tenant key | `licenseeId`, `manufacturerId`, `orgId`, user ownership columns | B-tree on direct key, preferably composite with route sort key for lists | Mostly present as single-column or scoped composite indexes |
| `can_access_licensee` | `ManufacturerLicenseeLink(manufacturerId, licenseeId)` and direct licensee match | Composite `(manufacturerId, licenseeId)` plus reverse lookup by `licenseeId` | Covered by composite primary key and `licenseeId` index |
| `can_access_organization` | `Licensee(orgId)` then `can_access_licensee(id)` | `Licensee(orgId)` and link table support | Covered |
| `can_access_batch` | `Batch(id)` plus batch `licenseeId`/`manufacturerId` | Batch primary key, direct tenant keys, and list-sort composites | Primary and direct keys covered; route-sort composites are recommended |
| `can_access_qr` | `QRCode(id)` plus `licenseeId` and `batchId` | QR primary key, `licenseeId`, `batchId`, and batch-list composite | Primary/direct keys covered; batch route composite recommended |
| Print session relation | `PrintItem.printSessionId -> PrintSession.id`, then `PrintSession.batchId/manufacturerId` | `PrintItem(printSessionId, state, issueSequence)`, `PrintSession(batchId,status)`, `PrintSession(manufacturerId,status)` | Covered |
| QR relation | `PrintItem.qrCodeId`, `Incident.qrCodeId`, `VerificationDecision.qrCodeId` | Unique/index on QR relation columns | Covered, but latest-decision descending variants recommended |
| Public safe verification | `QRCode(code)` and latest `VerificationDecision` by `qrCodeId OR code ORDER BY createdAt DESC LIMIT 1` | Unique QR code plus decision indexes by `(qrCodeId, createdAt DESC)` and `(code, createdAt DESC)` | QR code covered; ascending decision indexes exist, descending partial variants recommended for latest lookup |

## Current Index Coverage by Focus Table

### Batch

Existing indexes include `licenseeId`, `manufacturerId`, `parentBatchId`, `rootBatchId`, lifecycle fields, `releasedAt`, `printedAt`, `printPackDownloadedAt`, and `suspendedAt`.

Policy coverage is adequate for `can_access_batch` and direct tenant checks. The runtime candidate `GET /qr/batches` orders by `updatedAt DESC, createdAt DESC`, so single-column tenant indexes may still force extra sorting at scale. Add separate recommendations for `(licenseeId, updatedAt DESC, createdAt DESC, id)` and `(manufacturerId, updatedAt DESC, createdAt DESC, id)`.

### QRCode

Existing indexes include unique `code`, unique/indexed `displayCode`, `licenseeId`, `batchId`, `status`, `printJobId`, `tokenHash`, `issuanceMode/customerVerifiableAt`, `lastSignedVerificationAt`, `(licenseeId,batchId,status)`, and `(licenseeId,status,updatedAt)`.

Policy coverage is good for direct QR and batch relation predicates. The allocation-map candidate and batch enrichment paths are likely to benefit from `(batchId, createdAt, id)` when RLS is active and the planner also has to apply batch/tenant policy predicates.

### QrScanLog

Existing indexes include `licenseeId`, `batchId`, `code`, `scannedAt`, `(qrCodeId, scannedAt)`, `(qrCodeId, isTrustedOwnerContext, scannedAt)`, and `(licenseeId, batchId, scannedAt)`.

This is one of the stronger tables today. No immediate new index is recommended for the first staging candidates. For future reporting, validate whether `(licenseeId, scannedAt DESC, id)` or `(batchId, scannedAt DESC, id)` is needed after realistic scan-log row counts are loaded.

### VerificationDecision

Existing indexes include `(qrCodeId, createdAt)`, `(code, createdAt)`, `(licenseeId, createdAt)`, `(outcome, createdAt)`, and `(riskBand, createdAt)`.

The prototype safe public function performs a latest lookup with `qrCodeId OR code` and `ORDER BY createdAt DESC LIMIT 1`. PostgreSQL can scan b-tree indexes backward, but the `OR` may produce a bitmap-or plus sort at high volume. Add non-applied recommendations for partial descending indexes on `(qrCodeId, createdAt DESC)` and `(code, createdAt DESC)`, and validate whether the function should eventually split the `OR` into two indexed branches if staging plans remain expensive.

### PrintItem

Existing indexes include unique `qrCodeId`, `(printSessionId, state, issueSequence)`, `(state, updatedAt)`, `(pipelineState, updatedAt)`, `currentRenderTokenHash`, `deviceJobRef`, and `(confirmationDeadlineAt, state)`.

Policy support is adequate for `PrintItem` through both QR and `PrintSession`. No new index is recommended before the first read-only staging candidates. Future printer-agent/session wiring remains deferred because it mixes RLS, protocol I/O, state mutation, and long-running session behavior.

### PrintJob

Existing indexes include `batchId`, `manufacturerId`, `printerId`, `(printMode, status)`, `pipelineState`, `status`, and `reprintOfJobId`.

Policy support is adequate for batch/manufacturer access. If staging later wraps print operational views under RLS, add route-specific composite indexes only after measuring actual filters and sort keys.

### PrintSession

Existing indexes include unique `printJobId`, `(manufacturerId, status)`, `(batchId, status)`, `printerRegistrationId`, and `printerId`.

The RLS relation from `PrintItem` to `PrintSession` is covered through the `PrintSession` primary key and existing batch/manufacturer composites. No immediate recommendation for the first staging candidates.

### Incident

Existing indexes include `qrCodeId`, `qrCodeValue`, `scanEventId`, `licenseeId`, `status`, `severity`, `priority`, `createdAt`, and `assignedToUserId`.

The candidate `GET /incidents` builds a scoped `where` clause, applies optional status/severity/assigned/date filters, and orders by `createdAt DESC`. Existing single-column indexes are useful but may not be enough once RLS adds `licenseeId` or QR relation predicates. Add recommendations for `(licenseeId, createdAt DESC, id)`, `(licenseeId, status, createdAt DESC, id)`, and `(qrCodeId, createdAt DESC, id)`.

### SupportTicket

Existing indexes include unique `incidentId`, unique `referenceCode`, `licenseeId`, `status`, `priority`, `assignedToUserId`, and `createdAt`.

RLS can allow access by direct `licenseeId`, assigned user, or linked `Incident`. The unique `incidentId` supports the incident relation, but list/read paths that include support metadata should have a tenant-plus-sort recommendation: `(licenseeId, createdAt DESC, id)`.

### ManufacturerLicenseeLink

Existing indexes include primary key `(manufacturerId, licenseeId)`, `licenseeId`, and `(manufacturerId, isPrimary)`.

This is already aligned with `can_access_licensee` and manufacturer linked-licensee checks. No new index is recommended now.

### Printer

Existing indexes include `(connectionType,isActive)`, `(connectionType,deliveryMode,isActive)`, `(orgId,isActive)`, `(licenseeId,isActive)`, `(licenseeId,host,port)`, `(assignedUserId,isActive)`, and `(gatewayId,isActive)`.

The printer list candidate filters local-agent rows by `assignedUserId` or printer registration user, and network rows by tenant scope. Current indexes cover most branches. A partial recommendation for `(createdByUserId,isActive)` is included because the RLS policy can authorize by creator, but no first-candidate route currently appears to depend on creator lookup.

## Representative Query Shapes Analyzed

| Query path | Runtime source | RLS context | Main tables | Index risk |
| --- | --- | --- | --- | --- |
| Licensee batch list: `GET /qr/batches` | `qrController.getBatches`, `batchAllocationService.listCachedBatchOperationalSummaries` | `tenant_user`, `manufacturer_user`, `platform_admin` | `Batch`, `QRCode` count relation, `ManufacturerLicenseeLink` | Medium: tenant filters exist, but list sort uses `updatedAt DESC, createdAt DESC` |
| Batch allocation-map read | `qrController.getBatchAllocationMap`, `batchAllocationService.getBatchAllocationMap` | `tenant_user`, `manufacturer_user`, `platform_admin` | `Batch`, `QRCode` count relation | Medium: lineage OR uses `id`, `parentBatchId`, `rootBatchId`; those are indexed, but RLS adds tenant checks |
| Incident list | `incidentController.listIncidents`, `incidentService.listIncidentsScoped` | `tenant_user`, `manufacturer_user`, `platform_admin` | `Incident`, `SupportTicket`, incident child tables | High: list sort/filter should use tenant-plus-time composites before staging runtime RLS |
| Incident metadata read | `incidentController.getIncident`, `incidentService.getIncidentByIdScoped` | `tenant_user`, `manufacturer_user`, `platform_admin` | `Incident`, `SupportTicket` | Low for id lookup, medium when includes expand |
| Manufacturer printer list/status read | `printerController.listPrinters`, `printerRegistryService.listRegisteredPrintersForManufacturer`, `printerAgentController.getPrinterConnectionStatus` | `manufacturer_user`, `tenant_user`, `platform_admin` | `Printer`, `PrinterRegistration`, `PrinterProfile` | Medium: direct printer branches are indexed, profile/status enrichment runs additional reads |
| QRCode lookup by code | Public verification and internal QR reads | `public_verification`, `tenant_user`, `manufacturer_user` | `QRCode` | Low: `QRCode.code` is unique |
| Latest `VerificationDecision` by QR/code | `app_rls.public_verify_qr_safe`, `verificationDecisionReadService` latest helpers | `public_verification`, tenant contexts | `VerificationDecision`, `QRCode` | High: `OR` plus latest ordering can become expensive |
| Manufacturer linked-licensee access | `can_access_licensee`, scope services | `manufacturer_user` | `ManufacturerLicenseeLink`, tenant-owned target tables | Low: link table indexes are aligned |

## Risky Missing or Weak Index Shapes

These are recommendations only and are captured in `documents/security/mscqr_rls_index_recommendations_non_applied.sql`.

- `Batch(licenseeId, updatedAt DESC, createdAt DESC, id)`
- `Batch(manufacturerId, updatedAt DESC, createdAt DESC, id)` with `manufacturerId IS NOT NULL`
- `QRCode(batchId, createdAt, id)` with `batchId IS NOT NULL`
- `Incident(licenseeId, createdAt DESC, id)` with `licenseeId IS NOT NULL`
- `Incident(licenseeId, status, createdAt DESC, id)` with `licenseeId IS NOT NULL`
- `Incident(qrCodeId, createdAt DESC, id)` with `qrCodeId IS NOT NULL`
- `SupportTicket(licenseeId, createdAt DESC, id)` with `licenseeId IS NOT NULL`
- `VerificationDecision(qrCodeId, createdAt DESC)` with `qrCodeId IS NOT NULL`
- `VerificationDecision(code, createdAt DESC)` with `code IS NOT NULL`
- `Printer(createdByUserId, isActive)` with `createdByUserId IS NOT NULL`

## EXPLAIN Prototype Harness

Added local-only harness: `backend/tests/rlsPolicyExplainPrototypeP2.test.js`.

Command:

```bash
MSCQR_RLS_EXPLAIN_PROTOTYPE_TEST=true npm --prefix backend run test:rls:explain-prototype
```

The harness uses the existing P2 disposable database path, applies Prisma migrations, seeds minimal representative data, applies the non-production prototype SQL, uses a non-superuser app role with transaction-local RLS context, runs `EXPLAIN` for representative query shapes, asserts the plans compile and return rows, applies rollback SQL in `finally`, and drops the disposable database when the harness created one.

It intentionally does not use `EXPLAIN ANALYZE`; row counts in the local seed are too small to produce trustworthy performance numbers.

## Rollout Warnings and Blockers

- Relation-heavy RLS policies can add planner overhead even when application queries are already tenant-scoped.
- Production rollout requires staging `EXPLAIN ANALYZE` with realistic row counts for batches, QR codes, scan logs, verification decisions, incidents, support tickets, print items, and printer/session tables.
- Recommended indexes must be added separately before enabling RLS on high-volume tables.
- Production index creation needs a `CONCURRENTLY` plan, lock analysis, index build monitoring, and rollback plan.
- Public verification, scan mutations, printer-agent dispatch/session flows, compliance exports, audit exports, and background workers remain deferred runtime-wiring paths until explicit context and side-effect boundaries are designed.

## CTO Recommendations

1. Treat RLS as defense-in-depth, not a replacement for service/controller authorization. Keep existing app-layer checks as the primary authorization contract.
2. Before staging RLS runtime wiring, add observability for query duration, row counts, and context type on only the first candidate endpoints.
3. Start with one read-only endpoint, preferably `GET /qr/batches`, then compare staging p95/p99 latency before expanding.
4. Split public verification into a permanently minimized database API surface. The `public_verify_qr_safe` function is the right direction, but it needs realistic latest-decision plan testing.
5. Keep printer-agent and worker paths out of the first runtime experiment. Those paths need a dedicated service-account/agent authorization design before database-enforced isolation can be trusted at scale.
