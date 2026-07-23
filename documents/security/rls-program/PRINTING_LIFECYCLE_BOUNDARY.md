# Release Fix 5: Printing Lifecycle Boundary

## Frozen dependency

Release Fix 5 starts at `4908b68` and does not alter the Release Fix 1-4
authority models. `QRCode.code` remains immutable. Public verification is not
part of this boundary.

## Production call-path inventory

The pre-implementation scan found 265 direct Prisma expressions over printing
models in 31 production files. They are classified below by their actual
runtime entry point; migrations, tests, fixtures, and the generated SQL package
are not runtime authority.

| Production entry point | Runtime identity | Current implementation | Tables touched | Boundary required |
| --- | --- | --- | --- | --- |
| `POST /manufacturer/print-jobs` | authenticated application | controller, `printJobCreationTransactionService`, reservation service | `Batch`, `QRCode`, `Printer`, `PrintJob`, `PrintSession`, `PrintItem`, `PrintItemEvent`, audit/idempotency | authenticated create/readiness capability |
| print-job list, detail and events routes | authenticated application | `networkDirectPrintService`, query handlers, realtime service | print job/session/item/event and printer projections | authenticated printing projection |
| pause, resume, stop and abandon routes | authenticated application | `printOperationControlService`, `printLifecycleService` | `PrintJob`, `PrintSession`, `PrintItem`, `PrintItemEvent`, `PrintAuditEvent` | authenticated fixed lifecycle operation |
| direct-print token, resolve, confirm and fail routes | authenticated application | direct-print handlers and confirmation service | `PrintRenderToken`, `PrintJob`, `PrintSession`, `PrintItem`, `PrintItemEvent`, `QRCode` | authenticated render/confirmation capability |
| `POST /printer-agent/local/{claim,ack,confirm,fail}` | connector through backend | request-auth service and `printerAgentJobController` | `PrinterRegistration`, `Printer`, `PrintJob`, `PrintSession`, `PrintItem`, `PrintItemEvent` | connector-evidence capability; connector receives no DB credentials |
| persistent connector session/chunk flow | connector through WebSocket backend | `printerAgentSessionService` | `PrinterAgentSession`, `PrintJobChunk`, printer registration/profile, print job/session/item/event | connector-session claim/evidence capability |
| network TCP/IPP dispatch | application/worker | network direct and IPP services | printer, job, session, item and event rows | worker dispatch/evidence capability |
| physical confirmation and reconciliation | worker/application | confirmation service and reconciler | job/session/item/event, QR status | exact worker/application confirmation capability |
| sample scan and quorum | authenticated application | sample-scan and policy services | job/session/item, QR, batch, print audit, audit log | authenticated sample-evidence capability |
| batch release | authenticated application | `batchReleaseService`, QR controller | batch, QR, job/item evidence, approval/audit | authenticated maker-checker release capability |
| reissue request list/create/approve/reject/start | authenticated application | reissue workflow and reissue service | request, original/replacement jobs, session/items, QR, audit | authenticated reissue request/decision/execution capabilities |
| printer registration, mapping, readiness and test labels | authenticated application or connector through backend | registry, connection, mapping, relink and test-label services | printer, registration, profile/snapshot, attestation, agent session | authenticated/connector printer-registry capabilities |
| timeout/reconciliation maintenance | dedicated worker | confirmation reconciler and batch lifecycle reconciliation | job/session/item/event/audit | exact worker maintenance capability |
| diagnostics and attention projections | authenticated application | diagnostics, validation evidence and attention queue | printer and printing projections only | authenticated read projection |

### Direct-access file inventory

| File | Direct expressions | Classification |
| --- | ---: | --- |
| `services/printerAgentSessionService.ts` | 38 | persistent connector session/chunk runtime |
| `services/printLifecycleService.ts` | 25 | print state machine runtime |
| `services/printerRegistryService.ts` | 22 | printer administration/runtime readiness |
| `services/networkDirectPrintService.ts` | 22 | network dispatch and projections |
| `controllers/printerGatewayController.ts` | 15 | connector gateway evidence |
| `services/networkIppPrintService.ts` | 14 | IPP dispatch |
| `controllers/printerAgentJobController.ts` | 12 | local connector claim/evidence |
| `services/printReissueService.ts` | 10 | replacement execution |
| `services/printReissueRequestWorkflowService.ts` | 10 | replacement request/decision |
| `services/printOperationControlService.ts` | 10 | pause/resume/stop |
| `services/printConfirmationService.ts` | 10 | acknowledgement/physical confirmation |
| `services/printerConnectionService.ts` | 9 | registration/trust reads |
| `services/localAgentClaimService.ts` | 8 | local connector item claim |
| `controllers/print-job/shared.ts` | 8 | authenticated printer/job readiness |
| `services/printerTestLabelService.ts` | 6 | isolated test-label lifecycle |
| `services/printJobCreationTransactionService.ts` | 6 | print-job creation |
| `services/localAgentPrinterRelinkService.ts` | 6 | connector printer mapping |
| `services/printValidationEvidenceService.ts` | 5 | evidence projection |
| `services/batchReleaseService.ts` | 5 | release readiness/mutation |
| `services/printSampleScanService.ts` | 4 | sample evidence |
| `services/batchPrintLifecycleReconciliationService.ts` | 4 | worker reconciliation |
| all remaining 10 files | 20 | confirmation, diagnostics, registry gates, state/read projections |

## Runtime identities

- `authenticated application`: presents `aq_db_session`; PostgreSQL derives the
  live actor, role, organisation, licensee, and manufacturer links.
- `background worker`: the existing restricted worker role; it receives exact
  worker-function execution only.
- `connector`: remains an HTTP/WebSocket client. The backend verifies its
  registration, signed nonce, timestamp, device, printer, job, and payload
  binding before invoking connector-evidence SQL. No database credential is
  added to the connector.
- `migration administrator`: package installation and rollback only.
- `auth function owner`: existing `NOLOGIN`, `NOBYPASSRLS` controlled owner;
  it owns no protected application table.

## Capability registry

The implementation uses fifteen public functions with fixed operation
registries, not arbitrary table/JSON patch commands:

1. `app_rls.printing_readiness`
2. `app_rls.printing_printer_administration`
3. `app_rls.printing_idempotency`
4. `app_rls.printing_connector_registration`
5. `app_rls.printing_test_label_job`
6. `app_rls.printing_create_job`
7. `app_rls.printing_control_job`
8. `app_rls.printing_connector_event`
9. `app_rls.printing_connector_identity`
10. `app_rls.printing_gateway_job`
11. `app_rls.printing_record_sample`
12. `app_rls.printing_release_batch`
13. `app_rls.printing_reissue_request`
14. `app_rls.printing_worker_reconcile`
15. `app_rls.printing_worker_network_job`

`app_rls.printing_bind_actor` and `app_rls.printing_write_audit` are
owner-only helpers and have no runtime execution grant.

Each capability declares exact columns, policies, grantees, callers, workflow
IDs, rollback objects, and PostgreSQL probes in the authoritative generator
contract.

## Final runtime disposition

- Active print-job create, list, detail, control, direct confirmation, sample,
  release, reissue, printer administration, connector, persistent-session,
  gateway, network-dispatch, test-label, diagnostics, and reconciliation paths
  call the reviewed repository functions.
- The application and worker roles have no direct printing-table privileges.
  Connector software remains an HTTP/WebSocket client and receives no database
  credential.
- The legacy direct reissue implementation is unreachable from production
  routes and fails closed with `PRINT_REISSUE_DIRECT_PATH_RETIRED`. The active
  request/approve/execute path is `printReissueRequestWorkflowService` through
  `printing_reissue_request`.
- The legacy heartbeat body is unexported and explicitly quarantined. The
  exported heartbeat route verifies the signed connector identity and calls
  `printing_connector_registration`.
- Generic `ActionIdempotencyKey` access was removed from print-job creation and
  printer test-label creation. `printing_idempotency` supports exact
  begin/complete operations and expires an unfinished key on a pre-commit
  abort, permitting a safe retry without exposing table access.

## State, scope, and evidence

- PostgreSQL locks the batch/job/session rows and enforces
  `DRAFT -> CODES_GENERATED -> PRINT_ACKNOWLEDGED -> PRINT_CONFIRMED ->
  SAMPLE_VERIFIED -> RELEASED`, plus the existing `FAILED` and `VOIDED`
  behavior.
- Print-job membership is selected from the authoritative batch QR rows.
  Connector acknowledgement is bound to registration, device, printer, job,
  item, nonce, timestamp, and payload hash. `QRCode.code` is never updated.
- Reissue approval and print start remain separate. Approval does not create
  replacement work; `EXECUTE` revalidates printer attestation and creates at
  most one replacement under row locks.
- Sample quorum is evaluated from database evidence for
  `ONE_PER_PRINT_JOB`, `ONE_PER_ROLL`, `ONE_PER_N_LABELS`, and `PERCENTAGE`.
  Release requires physical confirmation, sample quorum, approval, and a
  checker distinct from the maker.
- Application, connector, and worker transitions write immutable audit
  evidence within the same database transaction. Connector test-label
  acknowledgement, confirmation, and failure now write exact audit/outbox
  evidence rather than relying on a post-boundary Prisma write.

## Grants, policies, and rollback

- The generated package contains 40 operation-specific Release Fix 5 policies,
  15 exact runtime function grants, and no public execution grant.
- The controlled owner is `NOLOGIN`, `NOBYPASSRLS`, and owns no protected
  application table.
- Rollback drops only the 40 Release Fix 5 policies, the 15 public functions,
  and the two internal helpers. It uses no `CASCADE` and preserves Release
  Fixes 1-4 and application data.

## PostgreSQL 18.4 evidence

The focused clean-room proof installs the real migration history and generated
package, then proves:

- capability, role, tenant, manufacturer-link, printer-attestation, connector,
  worker, maker-checker, lifecycle, quorum, concurrency, idempotency, immutable
  QR identity, audit/outbox, direct-access denial, and forged-context denial;
- one concurrent print-job creation wins and the conflicting transaction fails
  closed;
- an aborted pre-commit idempotency reservation can be retried safely;
- exact rollback removes every Release Fix 5 object while Release Fixes 1-4
  remain callable; and
- disposable database and managed-role residue are both zero.

## Deferred surfaces

- Public `/verify/:code`, signed scans, consumer decisions, and scan-risk logic
  remain deferred to Public Verification.
- Printer transport implementation, label dimensions, and connector packaging
  are preserved. Release Fix 5 controls their database evidence but does not
  add hardware behavior.
