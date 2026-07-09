# MSCQR Staging RLS Validation Plan

Date: 2026-07-09
Environment: staging
Scope: planning only
Production impact: none

## Purpose

This document defines the safe staging-only plan for Row Level Security validation.

This document does not enable RLS.
This document does not apply database policies.
This document does not change production.
This document does not run Terraform apply.

## Roadmap Position

Completed:
- Staging runtime secrets sync
- Staging smoke test

Current:
- RLS validation on staging planning

Not started:
- Staging hardening PR
- Production RLS rollout plan

PR 108 must remain draft and must not be merged as part of this RLS validation step.

Discovery companion:
- `documents/ops/MSCQR_STAGING_RLS_DB_TOUCH_MAP_2026-07-09.md`

## Candidate Endpoints

First read-only staging RLS validation candidates:

- GET /api/qr/batches
- GET /api/qr/batches/:id/allocation-map
- GET /api/manufacturer/printers

These endpoints already have authentication, rate limiting, and tenant isolation middleware before controller execution.

## Existing Feature Flags

The RLS code paths are already feature-flagged and disabled by default.

Flags:

- MSCQR_STAGING_RLS_BATCHES_READ_ENABLED
- MSCQR_STAGING_RLS_BATCH_ALLOCATION_MAP_ENABLED
- MSCQR_STAGING_RLS_MANUFACTURER_PRINTERS_READ_ENABLED

No flag should be enabled until this plan is reviewed and a dedicated staging validation step is approved.

## Existing Transaction Context

The staging RLS wrappers set transaction-local PostgreSQL config values:

- app.user_id
- app.role
- app.licensee_id
- app.manufacturer_id
- app.organization_id
- app.is_platform_admin

The context is set through set_config(..., true) inside a Prisma transaction.

Runtime roles blocked from staging RLS context:

- public_verification
- printer_agent
- background_worker
- system_worker

## Endpoint 1: GET /api/qr/batches

Controller:
- backend/src/controllers/qrController.ts
- getBatches

Service:
- backend/src/services/stagingRlsBatchReadService.ts
- listScopedBatchReadPayload

App-layer scope:
- buildScopedWhere(user, requestedLicenseeId, manufacturerField: "manufacturerId")

Expected behaviour:
- Platform admin can read broad scoped batches.
- Licensee or org tenant users are restricted by accessible licensee IDs.
- Manufacturer users are restricted by manufacturerId and accessible licensee IDs.

Read path discovered:
- ManufacturerLicenseeLink.findMany can be used by manufacturer scope resolution when linked licensee IDs are not already present in the authenticated session.
- Batch.findMany
- Batch.count
- Batch includes Licensee
- Batch includes manufacturer User
- Batch includes parentBatch and rootBatch
- Batch count of qrCodes
- InventoryStatusRollup.findMany
- QRCode.groupBy by batchId and status
- QRCode groupBy for ranges
- Raw SQL reservable QR summary

Raw SQL reservable summary touches:
- QRCode
- PrintItem
- PrintSession
- PrintJob

Tables requiring validation coverage:
- Batch
- Licensee
- User
- ManufacturerLicenseeLink
- InventoryStatusRollup
- QRCode
- PrintItem
- PrintSession
- PrintJob

Validation objective:
RLS-enabled results must match app-layer scoped baseline results for each tested actor class.

## Endpoint 2: GET /api/qr/batches/:id/allocation-map

Controller:
- backend/src/controllers/qrController.ts
- getBatchAllocationMap

Service:
- backend/src/services/stagingRlsBatchAllocationMapService.ts
- getScopedBatchAllocationMapPayload

App-layer scope:
- findScopedBatch(user, batchId)
- getBatchAllocationMap(batchId, licenseeId: focusBatch.licenseeId)

Expected behaviour:
- Requested batch is checked with scoped access first.
- Inaccessible batch returns not found.
- Visible batch reads allocation map restricted to the focus batch licensee.
- Related lineage batches stay inside the same licensee.

Read path discovered:
- ManufacturerLicenseeLink.findMany can be used by manufacturer scope resolution when linked licensee IDs are not already present in the authenticated session.
- Batch.findFirst
- Batch.findMany related lineage
- Batch includes Licensee
- Batch includes manufacturer User
- Batch count of qrCodes
- InventoryStatusRollup.findMany
- QRCode.groupBy by batchId and status
- QRCode groupBy for ranges
- Raw SQL reservable QR summary

Tables requiring validation coverage:
- Batch
- Licensee
- User
- ManufacturerLicenseeLink
- InventoryStatusRollup
- QRCode
- PrintItem
- PrintSession
- PrintJob

Validation objective:
RLS-enabled allocation map results must match baseline for visible batches and preserve not-found behaviour for inaccessible batches.

## Endpoint 3: GET /api/manufacturer/printers

Controller:
- backend/src/controllers/printerController.ts
- listPrinters

Service:
- backend/src/services/stagingRlsManufacturerPrintersReadService.ts
- listScopedManufacturerPrintersReadPayload

App-layer scope:
- listRegisteredPrintersForManufacturer
- printerListWhere

Expected behaviour:
- Local-agent printers are visible when assignedUserId matches current user.
- Local-agent printers are visible when printerRegistration.userId matches current user.
- Network printers are visible when scoped licensee or organization access matches.
- Manufacturers with an explicitly empty linked-licensee set fail closed for network-printer rows instead of falling through to all active network printers.
- Inactive printers are excluded unless includeInactive=true.

Read path discovered:
- ManufacturerLicenseeLink.findMany is now owned by the staged read service when manufacturer linked licensee IDs are not already supplied.
- Printer.findMany
- include PrinterRegistration
- PrinterProfile lookup per printer
- PrinterProfileSnapshot lookup through profile snapshots
- getPrinterConnectionStatusForUser for local-agent printer status
- latest local-agent status/session/attestation data used to build registry status
- Note: getPrinterConnectionStatusForUser now accepts the staged transaction client and uses it for PrinterRegistration, PrinterAttestation, and PrinterAgentSession reads.

Tables requiring validation coverage:
- Printer
- PrinterRegistration
- PrinterProfile
- PrinterProfileSnapshot
- PrinterAgentSession
- PrinterAttestation
- User
- ManufacturerLicenseeLink

Validation objective:
RLS-enabled printer list results must match current app-layer scoped results for local-agent and network printer cases.

Pre-template status:
The staged printer read path now owns the local-agent status/profile read graph under `MSCQR_STAGING_RLS_MANUFACTURER_PRINTERS_READ_ENABLED=true`. Manual SQL templates can include PrinterRegistration, PrinterAttestation, PrinterAgentSession, PrinterProfile, and PrinterProfileSnapshot, provided the templates keep non-recursive helper policies and retain rollback coverage.

## Required Actor Test Matrix

The staging validation must test:

- Platform admin
- Licensee admin
- Org admin
- Manufacturer admin or user
- Cross-tenant user
- User with missing tenant context

## Required Data Cases

The staging validation should include:

- Batch owned by licensee A
- Batch owned by licensee B
- Manufacturer child batch
- Parent or root allocation lineage
- Batch with QR codes
- Batch with inventory rollup
- Batch with print item, session, and job history
- Local-agent printer assigned to user
- Local-agent printer registered by user
- Local-agent printer with active PrinterAgentSession status
- Local-agent printer with PrinterAttestation history
- Local-agent printer with PrinterProfile and PrinterProfileSnapshot history
- Network printer under scoped licensee
- Network printer under different licensee
- Inactive printer includeInactive path

## Validation Method

Baseline mode:
- Keep all RLS flags disabled.
- Capture endpoint outputs for known test users.
- Store row counts and object IDs.

Candidate mode:
- Enable one flag at a time.
- Redeploy staging backend only.
- Call the specific endpoint as known test users.
- Compare row counts and object IDs against baseline.
- Inspect CloudWatch proof events.
- Disable the flag immediately if mismatch or 500 occurs.

Recommended first flag order:
1. MSCQR_STAGING_RLS_MANUFACTURER_PRINTERS_READ_ENABLED
2. MSCQR_STAGING_RLS_BATCHES_READ_ENABLED
3. MSCQR_STAGING_RLS_BATCH_ALLOCATION_MAP_ENABLED

Do not enable all three flags at once during first validation.

## Proof Events

Expected proof events:

- staging_rls_batches_read_proof
- staging_rls_batch_allocation_map_proof
- staging_rls_manufacturer_printers_read_proof

Each event should report:

- flagEnabled
- contextClass
- durationMs
- rowCount or resultShape
- success
- failureCategory

Failure categories to watch:

- rls_context_missing
- rls_context_forbidden
- database_error
- unexpected_error

## Pass Criteria

A candidate endpoint passes only if:

- RLS-enabled output matches baseline output.
- Cross-tenant data remains hidden.
- Manufacturer sees only assigned or linked data.
- Platform admin receives expected broad results.
- Existing error behaviour is not degraded.
- Proof events are emitted with success=true.
- CloudWatch has no database or RLS errors.
- Disabling the flag restores baseline path.

## Fail Criteria

Stop immediately if:

- Candidate endpoint returns 500.
- Cross-tenant data leaks.
- App context is missing.
- Query path breaks due missing table RLS policy.
- Baseline and RLS rows mismatch.
- Proof event is missing.

## Staging-Only Guardrails

Do not:

- Enable production RLS.
- Run production DB migrations.
- Change production environment variables.
- Enable all RLS flags at once.
- Apply DB policies without reviewed migration.
- Use real customer data for destructive testing.
- Rotate runtime secrets during RLS validation.
- Merge PR 106 as part of RLS validation.

## Proposed Execution Order

1. Document this validation plan.
2. Create a read-only staging RLS baseline capture script.
3. Analyse and standardise printer rows/status data before baseline capture.
4. Capture baseline outputs for the three candidate endpoints.
5. Prepare staging-only migration and policy review for required tables.
6. Enable one RLS flag at a time.
7. Compare outputs and proof events.
8. Document evidence.
9. Draft production rollout plan only after staging passes.

## Current Status

This plan is documentation only.

No RLS flags have been enabled.
No database policies have been applied.
No production resources have been touched.
No Terraform apply has been run for this task.
