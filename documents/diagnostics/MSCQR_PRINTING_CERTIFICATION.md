# MSCQR printing certification — 14 November 2026

This is the evidence record for the existing manufacturer printing path. No production deployment, production data change, historical replay, or physical label was performed. **The complete workflow is not certified for deployment.** The implementation branch is `fix/printing-worker-recovery`, based on protected main with restoration commit `19d7f2c2` cherry-picked. PR #841 run `43606879909` exercised the branch source on hosted PostgreSQL 18.4.

SOURCE_SHA=`bde15ec247d6abeeb8bb6a0e6cd6ba4f082dc73d` (fetched protected `origin/main`; PR #839 merge `cbdcc209b1058f903bbafd19742484b2ba03e827`, PR #840 merge is main). Baseline Git trees: backend `29247ad9e3266b14c2e561d4e268372ede855015`, frontend `ac5baa5b912e542e05e8a0ab1903b9cc28c9a056`, connector `4562803df430b24380d49c3f16efc832e62b0dcc`. Baseline `backend/src/rls-waves/session-c/c02/printingLifecycle.sql` SHA-256: `23178d3f2502a8576a1746f98e07635f4e8a814ce774b422b0ec07deb6218ccf`. The worktree patch changes no printing SQL.

POSTGRESQL_MIGRATION_PACKAGE=`backend/prisma/migrations/`, `scripts/rls/sql/generated/`, `scripts/aws/production-printing-restoration-package.mjs`, `scripts/aws/production-printing-restoration-scope.json`, and the bounded three-routine delta in `scripts/aws/apply-production-printing-routine-delta.mjs`. Historical predecessor digests remain pinned in the scope file and were not edited. Production RDS `mscqr-production-rls-green-phase2` reports PostgreSQL 18.4.

PRODUCTION_REVISIONS=Read-only ECS inspection refreshed 14 November 2026: backend service has two running tasks on `mscqr-production-rls-green-backend-candidate:47`, image `mscqr-backend@sha256:2fd512ed1bf6eaf027d16c55de2dbb4f6265bf3c7e32b3a81c34fd52755d6197`; frontend has two on `mscqr-frontend:28`, image `mscqr-web@sha256:e2246d898c0f456db9732a5c08bdb888791a384bff73a32ece1fbb38f1121a48`; support email worker has one on `mscqr-production-support-email-worker:2` with `MSCQR_WORKER_MODE=support-response-email`. No printing worker service exists in the cluster. Backend `RUN_BACKGROUND_WORKERS=false`. Task definition `RELEASE_GIT_SHA` values do not prove image source; prior ECR provenance tied the backend/frontend digests to `5fec457aad39cf22320e820b071943dec3e96ec0`, predating #839/#840. The public `/api/public/connector/releases/latest` endpoint refreshed 14 November advertises `2026.11.6.2`, minimum `2026.11.6.1`, with `productionSignedAvailable=false`; the sanitized Windows sample reported installed `2026.11.6.2`. A current signed fresh installer has not been demonstrated.

FUNCTIONALITY_INVENTORY=

| Capability | Classification | Existing source and evidence |
| --- | --- | --- |
| Manufacturer registration and printer ownership | PARTIALLY_WORKING | `backend/src/services/printerRegistryService.ts`, `backend/src/controllers/printerController.ts`, `src/pages/PrinterSetup.tsx`; sanitized sample has several active ZT410 registrations, and a prior test used an older one. |
| Connector installation and update | BROKEN | `backend/src/services/connectorReleaseService.ts`, `backend/src/local-print-agent/install/windows/`, `src/pages/ConnectorDownload.tsx`; live public release has no signed Windows distribution at the required minimum build. Fresh installation itself was not attempted. |
| Connector authentication, device registration, signed session | PARTIALLY_WORKING | `backend/src/services/printerAgentSessionBoundaryService.ts`, `backend/src/services/printerAgentSigningService.ts`, `backend/src/controllers/printerAgentController.ts`; protocol tests pass and 39 sanitized READY samples exist, but current physical connector test was not run. |
| Printer discovery, selection, health | PARTIALLY_WORKING | `backend/src/services/localAgentPrinterMappingService.ts`, `backend/src/services/zebraPrinterStatusService.ts`, `src/features/layout/useManufacturerPrinterConnection.ts`, `src/pages/PrinterDiagnostics.tsx`; sampled READY status does not prove correct registration at dispatch. |
| Test-label printing | PARTIALLY_WORKING | `backend/src/services/printerTestLabelService.ts`, `backend/src/controllers/printerAgentTestJobController.ts`; historical request remained PENDING on an older registration. |
| Batch selection, QR reservation, job creation | PARTIALLY_WORKING | `src/features/batches/useBatchPrintWorkflow.ts`, `backend/src/services/printJobCreationTransactionService.ts`, `backend/src/rls-waves/session-c/c02/printingLifecycle.sql`; disposable SQL test covers atomic reservation and concurrent conflict; production remains unverified. |
| Job acquisition and print payload | PARTIALLY_WORKING | `backend/src/controllers/printerAgentJobController.ts`, `backend/src/services/printPayloadService.ts`, `backend/src/local-print-agent/directPrintWorker.ts`; claim, payload, duplicate-delivery tests pass at protocol boundary. |
| ZPL and Windows spooler submission | PARTIALLY_WORKING | `backend/src/printing/canonicalLabel.ts`, `backend/src/printing/renderers/`, `backend/src/local-print-agent/render.ts`, `backend/src/local-print-agent/dispatchJournal.ts`; synthetic captured output and journal tests pass, actual Windows spooler and Zebra remain unverified. |
| Signed ACK and backend confirmation | PARTIALLY_WORKING | `backend/src/services/printerAgentSigningService.ts`, `backend/src/controllers/printerAgentJobController.ts`, `backend/src/services/printConfirmationService.ts`; protocol and SQL tests pass, historical ACK lacked backend confirmation. |
| Progress, completion, history | PARTIALLY_WORKING | `backend/src/controllers/printJobEventsController.ts`, `backend/src/services/printJobRealtimeService.ts`, `src/components/printing/PrintProgressDialog.tsx`, `src/features/batches/useRecoverablePrintProgress.ts`; browser recovery flow passes, historical snapshot was stuck SENT. |
| Stop, recovery, reissue | PARTIALLY_WORKING | `backend/src/services/printOperationControlService.ts`, `backend/src/services/printReissueRequestWorkflowService.ts`, `backend/src/rls-waves/session-c/c02/printingLifecycle.sql`; merged #839 guard and #840 null-deadline reconciliation are jointly exercised in `backend/tests/rls-wave-c/c02/printingLifecyclePostgres18.test.js`; production remains unverified. |
| QR inventory reconciliation | PARTIALLY_WORKING | `backend/src/services/batchPrintLifecycleReconciliationService.ts`, `backend/src/rls-waves/session-c/c02/printingLifecycle.sql`; disposable DB test passes; no production inventory mutation or fresh authoritative QR read was made. |
| Direct network / IPP modes | UNVERIFIED live | `backend/src/services/networkDirectPrintService.ts`, `backend/src/services/networkIppPrintService.ts`, `backend/src/printing/ippClient.ts`; source tests exist, no printer used. |

Historical May–June source commits `91be5a46a`, `3da8e9c7c`, `539bbed47`, `bbd44d1c1`, and `b807445b5` established Windows RAW ZPL, receipt ordering, persistent signed sessions, and reissue. These were compared with current modules; historical behavior is not treated as proof of correctness. `documents/diagnostics/MSCQR_PRINTING_RESTORATION.md` contains the earlier source and evidence checkpoint.

## Source-derived state transition matrix

The authoritative paths are `backend/src/rls-waves/session-c/c02/printingLifecycle.sql` and `backend/prisma/schema.prisma`. `M` means a tenant-bound manufacturer session and print capability; `C` means a signed connector session bound to the registration, printer and item; `W` means the database worker role. Each transition is transactional in the SQL function. A 201, spooler receipt or ACK alone never establishes physical output.

| Current state | Allowed event / authority | Next state and database effect | Inventory, retry and recovery |
| --- | --- | --- | --- |
| Job `PENDING` | Create / M; claim / C; pause or stop / M | Create reserves items and binds QR identities; claim sends one item and advances job to `SENT`; pause to `PAUSED`; stop to `STOPPED` | Duplicate create conflicts/idempotency applies. Unissued stopped items require guarded reissue; no automatic release. |
| Job `SENT` | ACK, confirm or fail / C; pause or stop / M; expiry / W | ACK retains `SENT` until confirmation; valid confirm advances to `CONFIRMED` only when all items qualify; expiry pauses for operator action | Issued or acknowledged identities stay bound. Duplicate signed receipts are idempotent; uncertain output blocks replay. |
| Job `PAUSED` | Valid late confirm / C; resume / M only if no uncertain item; expiry / W; stop / M | Resume advances to `SENT` with `RESUME_PENDING` pipeline/session; valid final confirmation may complete; stop retains uncertainty | No automatic issuance on an uncertain printer; worker repeats are idempotent. |
| Job `CONFIRMED` | Duplicate confirm / C; governed reissue / M and approver | Confirmation is idempotent; a separately approved replacement creates a new job | Confirmed QR remains printed; original evidence is retained. |
| Job `PARTIALLY_COMPLETED` | Read/history; governed reissue request / M and approver | Original job remains as evidence; approved replacement is a distinct job | Item evidence controls eligible range; status alone is insufficient. |
| Job `FAILED` | Read/history; governed reissue request / M and approver | No automatic claim or retry; replacement needs approval | Issued/failed identities remain protected until evidence is resolved. |
| Job `CANCELLED` | Read/history; execute an already approved reissue / M | Terminal for ordinary printing | SQL accepts governed execution only; it does not infer unprinted identities from status. |
| Job `STOPPED` | Late ACK/confirm/fail / C for in-flight items; guarded reissue / M and approver | Late evidence updates original item; guarded reissue moves only matched cancelled, unissued identities into a replacement job | Uncertain physical output is rejected; concurrent reissue is idempotent and tenant-bound. |
| Item `RESERVED` | Claim / C; stop / M | `ISSUED` on claim or `CANCELLED` on safe stop | QR is bound to the job; no second reservation. Cancelled QR is not automatically replayed. |
| Item `ISSUED` | Signed ACK or fail / C; stop / M | `AGENT_ACKED`, `FAILED` or uncertainty held at operator action | Physical outcome can be unknown; keep identity bound. |
| Item `AGENT_ACKED` | Signed confirmation / C; deadline expiry / W | `PRINT_CONFIRMED` with valid evidence, otherwise `NEEDS_OPERATOR_ACTION` while still acknowledged | NULL deadline uses `agentAckedAt + 10 minutes`; late confirm remains possible; no replay. |
| Item `PRINT_CONFIRMED` | Duplicate valid receipt / C | Idempotent terminal confirmation | QR is `PRINTED`; preserve evidence. |
| Item `CLOSED` | Read/history | Historical terminal state | No new physical attempt inferred. |
| Item `FROZEN` | Operator review only | Remains `NEEDS_OPERATOR_ACTION` | QR identity stays protected; reissue and resume reject uncertainty. |
| Item `FAILED` | Duplicate fail / C; operator review | Idempotent failure | Do not infer an unprinted QR from failure alone. |
| Item `CANCELLED` | Guarded STOPPED reissue / M and approver | Rebinds to replacement as `RESERVED` only if no issue, dispatch, ACK, device job or confirmation evidence exists | Concurrent recovery is serialized; uncertain items are rejected. |

The SQL uses printer advisory locks and row locks with `SKIP LOCKED` for claims and worker reconciliation. The connector dispatch journal protects physical submission across duplicate delivery and restart. The existing distributed lease reduces overlap; SQL remains authoritative if two workers run during ECS deployment.

## Prepared printing worker configuration

The isolated Terraform root `infra/aws/terraform/production-printing-worker/` reuses the reviewed Stage B worker task template, IAM roles, database and Redis secrets, VPC settings and CloudWatch log group. It creates one separately managed Fargate service only when applied later under the governed infrastructure route. Its own encrypted and locked state key keeps it separate from the support worker.

| Setting | Prepared value and source |
| --- | --- |
| WORKER_ENTRYPOINT | `node dist/worker.js`, inherited from `production-green-stage-b/task-definitions/green-worker-candidate.json` |
| WORKER_MODE | `MSCQR_WORKER_MODE=printing`; `RUN_PRINT_RECONCILER=true`; `RUN_DISTRIBUTED_LEASES=true` |
| REQUIRED_ENVIRONMENT | Existing template `RELEASE_GIT_SHA`, object storage bucket/region and worker role; SMTP settings removed |
| DATABASE_CONNECTION | Existing worker role via `DATABASE_URL` and `MSCQR_C03_WORKER_DATABASE_URL` secrets; existing Redis URL for cross-task lease; SMTP password removed |
| TASK_CPU / TASK_MEMORY | 512 CPU units / 1024 MiB, inherited from reviewed worker template; no independent load sizing claim |
| DESIRED_COUNT | Default 0; validated range 0 or 1 for later activation |
| HEALTH_CHECK | Worker exits on failed startup database/Redis checks; ECS monitors the essential process; per-cycle completion, duration and errors go to CloudWatch. There is no separate HTTP health endpoint or continuous database success probe. |
| LOGGING | Existing `/ecs/mscqr-production/rls-green-worker` group, `printing` stream prefix |
| RESTART_BEHAVIOR | ECS service replaces exited tasks; process restarts re-enter idempotent SQL reconciliation |
| DEPLOYMENT_OVERLAP_BEHAVIOR | ECS 100/200 percent allows brief two-task overlap; Redis lease and SQL advisory/row locks protect duplicate processing. Local two-process test exercises the SQL boundary. |

The image variable requires an immutable `mscqr-worker@sha256:...` URI and an exact source SHA; Terraform compares the digest with the ECR image at that source tag. No image was built or published, no Terraform plan or apply was run, and no ECS service was changed. The existing normal-release lane rejects worker-impacting changes, so this root needs its governed infrastructure review before activation.

CONFIRMED_ROOT_CAUSES=

1. `197d65b3-cbea-4ff4-8a2f-258e4dcf5493` was `SENT` with an `AGENT_ACKED` item and NULL `confirmationDeadlineAt`; the former reconciler selected only explicit expired deadlines. PR #840 supplies the `agentAckedAt + 10 minutes` fallback. The origin of the NULL deadline and physical output are unknown. A create request on the same batch returned 409 because this job remained active; that guard is correct.
2. `9b5eef27-14d8-40f5-a4e1-f210bedadb29` stopped before item issuance; the QR remained bound while normal creation requires an unbound allocation. PR #839 adds guarded recovery only for proven unissued identities and rejects uncertain output. Neither historical job was replayed.
3. Frontend copy described all unconfirmed labels as recoverable, overstating the guarded rule. `src/components/printing/PrintProgressDialog.tsx` and the batch workflow now say only proven unissued items can recover. The STOPPED row offers the existing guarded request action.
4. Print job query handlers and local agent errors could return raw 500 exception text, including database details. `backend/src/controllers/print-job/queryHandlers.ts` and `backend/src/controllers/printerAgentJobController.ts` now return stable public messages while preserving actionable 4xx codes.
5. The sampled PENDING test label targeted an older printer registration while current READY samples used a newer registration. The frontend could retain or choose a saved default local printer profile from that older registration; a focused regression reproduced this selection defect and the workflow now filters against the active registration. The sanitized records do not establish why that historical request remained PENDING or prove a spooler failure.
6. The current production topology does not start `startPrintConfirmationReconciler()`: backend has `RUN_BACKGROUND_WORKERS=false`, and the only separate worker is in `support-response-email` mode. Source starts reconciliation only under enabled background workers or worker mode `all` (`backend/src/index.ts`, `backend/src/worker.ts`). This is a confirmed deployment configuration defect, outside this no-deploy work.

FIXES_IMPLEMENTED=Existing guarded recovery made available for STOPPED rows; misleading recovery/completion copy corrected; database exceptions redacted at print HTTP boundaries; stale default printer profiles from older connector registrations are no longer selected. The existing worker binary now has isolated `MSCQR_WORKER_MODE=printing`; one dedicated ECS task/service configuration is prepared at desired count zero. Regression coverage includes print HTTP responses, registration selection, worker startup, live scheduling and concurrent process execution. No new print state machine, API, table, queue, or authentication mechanism was introduced. PR #839/#840 SQL and historical digest files were preserved.

SIMPLIFICATIONS=The policy contract now derives its expected names from the generated policy catalogue instead of a fixed count. The existing `handleUserSafeError` is reused for print read/abandon errors. No production logic was removed without replacement.

BACKEND_TESTS=PASS: backend build; print response, reservation, payload, reissue range, local ACK, signed trust, printer session, dispatch journal, Windows adapter, and direct worker tests. New 409/500 redaction regression passed. PR #841 backend and quality-gates jobs passed at source commit `20953398` (PR head `1f439a65` before this documentation update).

FRONTEND_TESTS=PASS: production build, TypeScript check, 78 Vitest tests across six printing files plus 23 start-print dialog tests, including the older-registration regression. PR #841 frontend job and Playwright smoke passed at the same source. The earlier manufacturer recovery Playwright test passed once (9.8 s) on an isolated local Vite server with auth bootstrap enabled. The default system-test server disables bootstrap, so that fixture cannot authenticate under its default config; this is a test harness limit, not a production login result.

DATABASE_TESTS=PASS on local disposable PostgreSQL 18.6: printing-family certification reports `application-path-certified`, migrations from zero, rollback verified, and no residue (`documents/diagnostics/MSCQR_PRINTING_LOCAL_PG18_CERTIFICATION.json`). It launches the actual worker process for one, ten, and 150 synthetic acknowledged items, kills its database session to verify recovery, and overlaps two worker processes. The combined test covers STOPPED guards, NULL deadline, late/duplicate ACK, concurrent creation/recovery, tenant isolation, atomic reservation, ownership and FORCE RLS. PR #841 run `43606879909` passed the authentication, QR and printing application-path step on PostgreSQL 18.4, plus the full RLS package verifier. Static SQL and bounded routine-delta contracts pass (22/22). Local full-package verifier previously hit a Homebrew catalogue privilege mismatch (`subscription_conninfo_acl`); the hosted verifier passed.

CONNECTOR_TESTS=PASS for signed protocol, dispatch journal duplicate/restart/reconnect, payload, and synthetic Windows adapter tests. UNVERIFIED for a running actual Windows connector with actual spooler submission. The synthetic adapter is not a substitute for hardware.

END_TO_END_TESTS=PARTIAL: browser manufacturer recovery interaction and backend/SQL lifecycle pass separately; one, ten and 150 synthetic items traversed actual worker scheduling and SQL on local PostgreSQL 18.6. No single test runs actual frontend + backend + PostgreSQL 18.4 + Windows connector + controlled printer capture together. Hardware-path throughput and physical confirmation were not demonstrated. The provided evidence does not identify a physical-output result.

SECURITY_TESTS=PASS at exercised boundaries: signed session/ACK tamper, tenant isolation, duplicate delivery, concurrent reservation/recovery, uncertain-output refusal, redacted 500 responses. Production source, permissions, and inventory were read only. No historical identity was automatically reissued.

PERFORMANCE_RESULTS=Local PostgreSQL 18.6 worker process startup plus reconciliation measured one item in 925 ms, ten in 466 ms, and 150 with two overlapping workers in 10,963 ms (`documents/diagnostics/MSCQR_PRINTING_WORKER_PERFORMANCE.json`). These are one sample each, include startup and scheduler delay, and are neither p50/p95/p99 nor physical print throughput. Representative baseline/post-fix job creation, reservation, connector acquisition, ACK, frontend progress and hardware throughput remain UNVERIFIED. No timeout was increased.

MIGRATION_CERTIFICATION=PARTIAL. Clean-room PostgreSQL 18.4 hosted printing certification and local 18.6 rollback passed; the bounded incremental migration package and historical digests were preserved. An authenticated, current production catalogue comparison and final target-schema upgrade were not executed. No production migration was run.

UNVERIFIED_BOUNDARIES=Actual Windows connector fresh installation/update and signed release availability; selected registration on the physical device; spooler submission and Zebra output; live ACK-to-confirmation on merged source; live reconciler activation after deployment; production QR inventory; full 18.4 end-to-end suite; baseline/post-fix latency.

REMAINING_DEFECTS=The production release has no active print reconciler in its observed ECS topology, and the public connector release lacks a signed Windows distribution at the required minimum build. The deployed images predate #839/#840. The historical acknowledged item remains uncertain and must retain its QR identity. The default browser test configuration disables authentication bootstrap for the recovery fixture. These block a claim of normal live printing or deployment readiness.

SOFTWARE_CERTIFIED=UNVERIFIED
DATABASE_UPGRADE_CERTIFIED=UNVERIFIED
CONNECTOR_CERTIFIED=UNVERIFIED
PHYSICAL_PRINTING_VERIFIED=UNVERIFIED
PRODUCTION_DEPLOYMENT_READY=FAIL

RESTORATION_COMMIT=`19d7f2c2f0b6d8dda8d67fcce6b16835aa676bbe` (preserved by cherry-pick `7d147de8` on current protected main).
PRINTING_WORKER_IMPLEMENTED=PASS: isolated mode in `backend/src/worker.ts` starts the existing reconciler and no unrelated background loop.
PRINTING_WORKER_MODE=`MSCQR_WORKER_MODE=printing`.
PRINTING_WORKER_TESTS=PASS on local PostgreSQL 18.6 and hosted PostgreSQL 18.4 for actual process startup, shutdown, scheduling, restart, NULL/expired deadlines, database disconnect and two-process overlap; static isolation and fail-closed startup tests pass.
RECONCILER_ACTIVE_IN_TEST=PASS: actual worker logs successful cycles and commits one, ten and 150 synthetic item reconciliations.
RECONCILER_PRODUCTION_STATUS=FAIL: the backend has workers disabled and the only separate service is support email mode.
CONNECTOR_AUTHENTICATION=PASS in signed protocol/session tests; live Windows identity unverified.
CONNECTOR_REGISTRATION=PASS in source and frontend selection tests; physical selected registration unverified.
CONNECTOR_DISPATCH=PASS in protocol/journal tests with controlled synthetic output; actual Windows spooler unverified.
CONNECTOR_ACK=PASS in signature, tamper, duplicate and backend-boundary tests; live physical ACK unverified.
CONNECTOR_INSTALLER_STATUS=FAIL: no production-signed current Windows installer demonstrated; signing/publication remains external.
FRONTEND_PRINTING_TESTS=PASS for printing Vitest cases, TypeScript and production build; one local manufacturer recovery browser test passed in prior restoration evidence.
BACKEND_PRINTING_TESTS=PASS for focused printing, worker and connector suites and PR #841 backend job.
POSTGRESQL_18_4_TESTS=PASS for disposable hosted clean-room printing application path at source commit `20953398`, run `43606879909`. Incremental migration from the actual deployed catalogue remains unverified.
REMAINING_HARDWARE_BOUNDARIES=Actual Windows connector installation, selected ZT410 registration, Windows spooler receipt and Zebra output; no physical label was printed.
RELEASE_CANDIDATE_SHA=`88a149aa2f84b6bf0fa3f9e4bbcc015690b4b7fa` (brand-neutral ZPL source commit on PR #841; exact-head hosted checks pending at this record update). Prior hosted PostgreSQL 18.4 evidence is bound to `20953398`, not this new source SHA.

PRINTING_SOFTWARE_READY=UNVERIFIED
PRINTING_WORKER_READY=PASS for local software and validated configuration; production activation remains FAIL as reported separately.
DATABASE_READY=UNVERIFIED
CONNECTOR_SOFTWARE_READY=UNVERIFIED
SIGNED_INSTALLER_READY=FAIL
PHYSICAL_ZEBRA_VERIFIED=UNVERIFIED
PRODUCTION_DEPLOYMENT_READY=FAIL

## Brand-neutral ZPL connector compatibility — 14 November 2026

ZPL_BRAND_AGNOSTIC=PASS at the software protocol boundary for synthetic 300 dpi ZPL and ZSIM profiles. Compatibility is based on the registered printer's language and DPI, not its vendor or queue name. Actual non-Zebra hardware remains UNVERIFIED.

HARDCODED_VENDOR_RESTRICTIONS=Removed Zebra/ZDesigner name ranking and instructions from the local connector selection and manufacturer setup path. Zebra odometer commands remain confined to direct-network confirmation, where that vendor-specific proof is required; they are not used for Windows RAW ZPL dispatch.

PRINTER_DISCOVERY=Windows printer language and DPI hints come from the installed driver, not a user-editable queue name. Unknown DPI remains unknown. The connector supports explicit operator confirmation of ZPL mode, 300 dpi, 40 × 50 mm media, and at least 472 printable dots; confirmation is bound to the selected queue, driver/model and port, and expires when those change. Driver metadata and operator confirmation are not physical capability tests.

PRINTER_REGISTRATION=Heartbeat preserves each discovered queue's own capability and calibration profile. A selected queue's confirmation is no longer copied to other registrations. The existing signed registration, manufacturer scope and native printer ID checks remain in force.

PRINTER_SELECTION=Explicit missing printer IDs fail rather than silently using another default queue. Virtual Fax/PDF queues are rejected even if they advertise ZPL/300 dpi. Registration selection and connector payload language/DPI are checked before job creation, test-label enqueue and RAW dispatch; an unsupported ZPL profile returns a setup-specific error before QR reservation or durable dispatch reservation.

ZPL_COMPATIBILITY=The current MSCQR label contract is 300 dpi, `^PW472`, `^LL591`, nominal 40 × 50 mm media, one bounded `^GFA` graphic and one `^BQN` QR. Payload safety validates the required dimensions and command structure. The printer must implement the subset emitted by `backend/src/printing/printPayloadSafety.ts` and `backend/src/services/printPayloadService.ts`; neither a vendor name nor a Windows driver proves physical support.

RAW_DISPATCH=The persistent and polling connector paths use the registered language/DPI, preflight the approved payload before reserving dispatch, retain the existing journal's no-replay rule, submit RAW data through the existing Windows spooler, and send signed ACKs. Job creation now uses the same existing payload resolver as rendering, including `AUTO` mode, so the recorded payload type matches actual output. A spooler receipt is not proof of physical output. The persistent one-item chunk path was corrected to carry DPI.

VENDOR_SPECIFIC_DIAGNOSTICS=Zebra status/odometer checks remain optional for the Windows connector and are used only by the separate strict direct-network route. Non-Zebra ZPL-compatible Windows queues do not need a Zebra status command.

REGRESSION_TESTS=PASS locally: backend build; synthetic Zebra, TSC/ZPL and ZSIM profiles; unknown/203 dpi rejection; queue-name and virtual-printer spoofing rejection; operator confirmation and identity-change invalidation; signed persistent chunk DPI; unsupported profile blocked before reservation and spooler; journal replay protection; `AUTO` payload-type consistency; backend job-creation preflight; frontend printer setup/diagnostics and failure copy; frontend typecheck, production build, code-size budget and 44 focused Vitest cases. Actual Windows connector and physical printer were not run in this environment.

REMAINING_HARDWARE_VERIFICATION=UNVERIFIED: installed Windows connector, selected physical queue identity, 300 dpi/media/printable width on each intended model, RAW spooler output, ZPL emulation fidelity, printed QR scan quality and physical completion. Signed installer availability and production worker activation remain separate release blockers. No deployment or physical printing occurred.
