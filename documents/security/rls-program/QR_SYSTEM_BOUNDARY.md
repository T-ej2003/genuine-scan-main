# QR System Boundary

## Release status

Release Fix 4 closes every active QR-owned `QRCode` and `QRRange` path. The
remaining 47 direct Prisma expressions are explicitly owned by later releases
or quarantined; none is an active Release Fix 4 authority path. The
authenticated application role has no direct table or column privilege on
`QRCode` or `QRRange`.

All public QR functions verify `aq_db_session` with
`app_auth.require_authenticated_session`. PostgreSQL derives the live actor,
role, organization, licensee, and manufacturer links. The only admitted roles
are `SUPER_ADMIN`, `PLATFORM_SUPER_ADMIN`, `LICENSEE_ADMIN`, and
`MANUFACTURER_ADMIN`.

## Migrated application paths

- range allocation and QR generation;
- QR list, statistics, batch summaries, tracking inventory, and audit-export
  projections;
- batch creation from unassigned QR capacity;
- batch rename through the same tenant-bound command capability;
- batch deletion and bulk deletion with QR disassociation;
- manufacturer assignment with child-batch creation;
- allocation-request approval;
- break-glass token metadata binding;
- QR scope lookup and eligible administrative deletion.

The legacy immutable-code report and rotation dashboard feature is retired
atomically: its mount request, card, count, refresh, CSV export, rotation
controls, and browser API methods are removed together. The backend
deprecation endpoints remain fail-closed because `QRCode.code` cannot change.

Analytics rollup refresh is owned by the dedicated worker. Its distributed
lease invokes two exact worker-only SQL functions; the worker has no direct
table or column privileges. The process starts one loop, retains its stop
handle for `SIGINT`/`SIGTERM`, and the HTTP process starts no duplicate.

## SQL boundary

| Function | Purpose |
| --- | --- |
| `qr_allocate_range(text,text,text,text,integer,integer,text,text)` | Platform allocation, range, received batch, immutable QR identities, event, audit, and outbox |
| `qr_approve_allocation_request(text,text,text,text,text)` | Atomic approval plus allocation for one pending request |
| `qr_batch_command(text,text,text,text,jsonb)` | Fixed `CREATE_BATCH`, `DELETE_BATCH`, `BULK_DELETE_BATCHES`, `ASSIGN_MANUFACTURER`, `RENAME_BATCH`, or `AUDIT_CODE_EXPORT` command |
| `qr_read_codes(text,text,text,text,text,text,integer,integer)` | Minimal tenant-scoped QR projection |
| `qr_inventory_projection(text,text,text,text,text,text,text,text,integer,integer)` | Batch-led, database-paginated inventory projection with an independent matching-batch total |
| `qr_export_codes(text,text,text,text)` | Capability-scoped immutable audit-export projection for batch, QR, trace-event, and policy-alert evidence |

The immutable package boundary reads the complete exact-batch QR, `TraceEvent`, and `PolicyAlert` evidence in one PostgreSQL statement snapshot. Evidence rows require both the verified batch licensee and batch ID, are deduplicated by primary key, and are ordered by `(createdAt, id)`; zero matches intentionally return `[]`. There is no row cap or partial-package fallback: any authorization or query failure aborts before hashing and signing. Ordinary application roles retain no direct evidence-table access.
| `qr_stats(text,text,text,text)` | Status totals |
| `qr_delete_codes(text,text,text,text[],text[])` | Eligible administrative deletion |
| `qr_get_code_scope(text,text,text,text)` | Minimum QR scope for the deferred incident block path |
| `qr_bind_break_glass_tokens(text,text,text,text,jsonb)` | Atomic token metadata binding without identity mutation |
| `refresh_inventory_status_rollups(text)` | Worker-only checkpointed inventory aggregation |
| `refresh_scan_metrics_hourly_rollups(text)` | Worker-only checkpointed hourly scan aggregation |

`qr_bind_actor` and `qr_write_audit` are owner-only helpers. The application
role has exact EXECUTE on the ten QR signatures; the worker has exact EXECUTE
on the two rollup signatures. Neither runtime role can execute the helpers or
access the protected tables directly. PUBLIC has no execution.

## Lifecycle matrix

| Fixed action | Allowed source | Result |
| --- | --- | --- |
| Allocate range | unused per-licensee numeric capacity | new `DORMANT` QR rows |
| Create batch | unbatched `DORMANT` rows | selected rows become `ALLOCATED` |
| Assign manufacturer | source-batch `DORMANT`, `ACTIVE`, or `ALLOCATED` rows without print job | selected rows become `ALLOCATED` in a linked child batch |
| Rename batch | tenant-owned batch visible to a platform or licensee administrator | only the reviewed batch name changes |
| Delete batch | unprinted, unreleased, lineage-free batch; QR not `PRINTED`, `REDEEMED`, or `SCANNED` | eligible QR rows return to unbatched `DORMANT` |
| Bulk delete batches | same constraints for one licensee | eligible QR rows return to unbatched `DORMANT` |
| Bind token metadata | exact generated QR IDs in one licensee | status and immutable code unchanged |

Printing transitions, physical confirmation, sample confirmation, release
approval, public scan transitions, and incident block/unblock actions are not
performed by these functions.

## Identity, allocation, and atomicity

- `QRCode.code` is generated once and is never updated.
- `displayCode` is the licensee prefix plus a fixed-width allocated number; no
  `displayCode || code` fallback exists.
- A per-licensee advisory transaction lock prevents overlapping ranges without
  serializing independent licensees.
- uniqueness constraints reject duplicate internal and display codes.
- batch selection uses row locks and exact affected-row checks.
- application token signing remains in Node. Allocation and
  `qr_bind_break_glass_tokens` execute in one reviewed Prisma transaction, so a
  binding failure rolls back the range, batch, QR rows, allocation event,
  audit, and outbox. Raw signing secrets never enter SQL, audit, or outbox.
- token binding accepts only the two active producer formats: a 64-character
  lowercase hexadecimal allocation nonce or the canonical 22-character
  base64url `randomNonce()` value.
- the generation transaction retains the configured
  `ALLOCATION_TX_TIMEOUT_MS` and `ALLOCATION_TX_MAX_WAIT_MS` values.
- allocation-request approval locks one pending request and performs approval
  and allocation in one database transaction.
- allocation-request creation and approval share the same inclusive
  `1..200,000` quantity contract. Larger requests fail before a pending,
  permanently unapprovable row can be persisted.

## Review regression corrections

- Destructive QR deletion is admitted only for `SUPER_ADMIN`,
  `PLATFORM_SUPER_ADMIN`, and an in-scope `LICENSEE_ADMIN`. The route,
  controller, SQL role check, and row-local DELETE policy independently deny
  `MANUFACTURER_ADMIN`.
- CSV export reads deterministic `(displayCode, createdAt, id)` pages inside one
  repeatable-read transaction into a private mode-0600 temporary file. It does
  not emit a response until every row in the database-reported total has been
  written and audited, then removes the file after transmission. There is no
  hidden 500,000-row success cap; an incomplete page sequence fails closed.
- Batch summaries select and paginate matching batches before grouping QR
  statuses. The SQL boundary returns the matching-batch total independently
  from status rows, including an empty page beyond the final offset.
- The inventory projection is batch-led. Empty and fully reassigned source
  batches remain visible with `totalCodes = 0` and an empty `counts` object;
  no artificial QR status is emitted.
- Tracking analytics receive paginated batch rows plus database-computed
  totals and trend buckets from the complete filtered scope. Page changes no
  longer alter aggregate quantities or `distinctCodes`.

## Manufacturer scope

`MANUFACTURER_ADMIN` scope is reconstructed from current
`ManufacturerLicenseeLink` rows. A live linked actor can read only linked QR
inventory. Link removal, inactive organization, inactive or suspended
licensee, forged selectors, or a deprecated role fails closed. Manufacturer
assignment itself remains a `LICENSEE_ADMIN` action against an active linked
manufacturer; a link grants scope, not ownership.

## Policies and grants

Nineteen `qr_system_*` policies cover exact `SELECT`, `INSERT`, `UPDATE`, and
`DELETE` commands on `Organization`, `Licensee`,
`ManufacturerLicenseeLink`, `User`, `QRRange`, `QRCode`, `Batch`,
`QrAllocationRequest`, `AllocationEvent`, `AuditLog`, and
`SecurityEventOutbox`. FORCE RLS remains enabled. The function owner is
NOLOGIN, non-BYPASSRLS, and owns no protected application table.

The package verifier and PostgreSQL catalog prove:

- application `QRCode`/`QRRange` table privileges: 0;
- application `QRCode`/`QRRange` column privileges: 0;
- PUBLIC QR function executions: 0;
- application QR executions: 10;
- internal helper application executions: 0.

## Direct-access inventory

The final runtime scan contains 47 direct `QRCode`/`QRRange` Prisma
expressions:

| Category | Expressions | Files and counts |
| --- | ---: | --- |
| QR-owned and migrated | 0 | none |
| Printing-owned, Release Fix 5 | 17 | `batchReleaseService.ts` 4; `printConfirmationService.ts` 1; `printLifecycleService.ts` 3; `printOperationControlService.ts` 1; `printSampleScanService.ts` 1; `printValidationEvidenceService.ts` 3; `replacementChainService.ts` 3; `qrService.ts` 1 (`markBatchAsPrinted`) |
| Public verification deferred | 20 | verify controllers 9; `authenticatedRepositories.ts` 5; `integrationSeamRepositories.ts` 1; `publicVerificationPostScanService.ts` 1; `qrService.ts` 2 (`recordScan`); `analyticsService.ts` 2 (scan-risk analytics) |
| Incident response deferred | 5 | `irIncidentController.ts` 1; `incidentActionsService.ts` 2; `policyEngineService.ts` 2 |
| Exact analytics worker boundary | 1 | `analyticsRollupService.ts` 1; dedicated worker only, lease-bound with two operation-scoped SQL functions |
| Dead or quarantined | 4 | `legacyQrRotationService.ts` 2; `qrProvenanceBackfillService.ts` 2 |
| Test, fixture, migration, or administrative runtime authority | 0 | excluded from the production runtime scan |

The legacy rotation service has no runtime registration and the exposed legacy
route remains fail-closed. Its former dashboard caller and all related controls
were removed atomically, avoiding misleading zero values and failed actions.
Provenance backfill has no production caller. Analytics rollup runs only in the
dedicated worker through its exact lease-bound SQL authority; it is not an
application QR table authority path.

## PostgreSQL 18.4 proof

A fresh loopback PostgreSQL 18.4 database applied all 52 Prisma migrations and
the exact generated package. The focused proof passed platform allocation,
licensee and manufacturer reads, batch association, manufacturer assignment,
allocation-request approval, inventory projection, audit export, exhaustion,
same-licensee and independent-licensee concurrency, rollback, audit/outbox
atomicity, and catalog assertions.

Denied probes covered cross-tenant access, stale manufacturer link, deprecated
role, missing/forged/expired/revoked capability, forged GUC, generic context
installer, oversized allocation, repeated approval, and direct QR table
`SELECT`, `INSERT`, `UPDATE`, and `DELETE`.

## Rollback

The exact rollback uses no CASCADE, removes the ten application functions, two
worker functions, two helpers, and twenty-nine QR policies, and preserves authentication, tenant
directory, administration, application tables, and data. Printing, public
verification, and incident paths remain owned by their later release fixes.
