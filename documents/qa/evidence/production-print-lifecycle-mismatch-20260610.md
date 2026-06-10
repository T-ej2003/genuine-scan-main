# Production Print Lifecycle Mismatch - 2026-06-10

## Symptom

London production accepted previous manufacturer print jobs for batch `c9dabd08-9393-4be3-bb33-0269b543285d`, but a new `POST /api/manufacturer/print-jobs` returned `409 INVALID_STATE_TRANSITION` at `transaction_started/reservation_started`.

The batch showed remaining inventory in the manufacturer Batches UI, but the backend state machine saw `lifecycleState = DRAFT` and blocked `PRINT_REQUESTED`.

## DB Evidence

- Batch `c9dabd08-9393-4be3-bb33-0269b543285d`
- `printedAt = 2026-06-09T19:47:16.454Z`
- `lifecycleState = DRAFT`
- Latest print jobs include confirmed local-agent jobs.
- Latest sessions completed with all items issued and confirmed.
- QR counts include `ALLOCATED: 971`, `PRINTED: 21`, `ACTIVATED: 4`, `REDEEMED: 4`.

## Root Cause

`createPrintJobRecords` correctly requests the `PRINT_REQUESTED` batch transition before reserving QR items. That transition requires the batch to be at least `CODES_GENERATED`.

Manufacturer child allocation code creates printable child batches as `CODES_GENERATED`, but the production batch drifted back or remained at `DRAFT`. The confirmation path only advanced batches from `PRINT_ACKNOWLEDGED` to `PRINT_CONFIRMED`, so drifted `DRAFT` batches with real print evidence could remain contradictory.

The frontend used QR availability only and ignored lifecycle readiness, so it showed "Ready to print" and enabled the start action for a lifecycle-blocked batch.

## Code Fix

- Added backend batch print lifecycle reconciliation/readiness service.
- Print job creation now performs safe scoped reconciliation before QR reservation.
- Print confirmation now repairs stale pre-confirmation lifecycle states to `PRINT_CONFIRMED` from confirmed print evidence.
- `/api/qr/batches` summaries now include `printReadiness`.
- Manufacturer Batches UI and print dialog gate `Start print run` on backend readiness, while still showing ready QR quantity.
- Structured `INVALID_STATE_TRANSITION` responses now carry user-safe lifecycle recovery fields.
- Diagnostic test-label controller now allows manufacturer ops users for scoped printers without granting network endpoint configuration.

## Production Repair

Dry-run first:

```bash
npm --prefix backend run data:reconcile-batch-print-lifecycle -- --batchId c9dabd08-9393-4be3-bb33-0269b543285d --json
```

Review the output. It should identify only the expected batch and target `PRINT_CONFIRMED`.

Apply only after review:

```bash
npm --prefix backend run data:reconcile-batch-print-lifecycle -- --batchId c9dabd08-9393-4be3-bb33-0269b543285d --apply --json
```

Optional tenant-scoped dry-run:

```bash
npm --prefix backend run data:reconcile-batch-print-lifecycle -- --licenseeId 7fc56797-1250-4d09-b679-a6e23e26d682 --manufacturerId bfaa1070-5dfe-479e-abb0-e2ae8025c8a3 --json
```

The script updates only `Batch.lifecycleState` and audit evidence. It does not mutate QR statuses, print jobs, print items, or sessions.

## Manual Validation

1. Run dry-run and confirm expected drift only.
2. Run apply for reviewed batch ids.
3. Confirm the batch no longer has `DRAFT` plus print evidence.
4. Start a 1-label print run.
5. Confirm `PrintJob`, `PrintSession`, and `PrintItem` rows are created.
6. Confirm `local_agent_claim` reports available work and then issued/confirmed items.
7. Confirm physical Zebra ZT410 output.
8. Confirm QR status increments from `ALLOCATED` to `PRINTED` without duplicates or skipped serials.
9. Repeat with 10 labels.
10. Validate pause, resume, and stop flows.

## Remaining Risks

- If an old allocation path created `DRAFT` child batches with ALLOCATED QR inventory but no print evidence, the new reconciliation can safely move manufacturer child batches with lineage and allocated QR evidence to `CODES_GENERATED`.
- Truly draft batches remain blocked and now show a required previous step in the UI.
- Existing terminal `RELEASED`, `FAILED`, and `VOIDED` batches remain blocked for new print runs.
