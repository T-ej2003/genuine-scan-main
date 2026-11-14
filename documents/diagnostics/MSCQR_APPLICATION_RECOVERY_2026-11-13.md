# MSCQR application recovery, 13 November 2026

## Scope and evidence

Production backend source `5fec457aad39cf22320e820b071943dec3e96ec0` was compared with the protected-main source at the time of this investigation. Evidence came from the local Mac CloudWatch export and the sanitized Windows acceptance archive. The original evidence remains outside this repository. These records cover the observed window; they do not establish current database state or physical output.

| UTC | Correlated observation | Confidence |
| --- | --- | --- |
| 14:16:49 | Dashboard events and notifications returned 503 on separate backend tasks after about 2.0 s. No actor context was populated. | Confirmed |
| 14:17:04 | Dashboard stats and attention queue returned 503 after about 2.0 s. | Confirmed |
| 14:20:28–33 | Print creation request `9ce51ddb…` for batch `3f0eb49e…` failed with `ACTIVE_PRINT_JOB_EXISTS`, mapped to HTTP 409. | Confirmed |
| 14:23:08–10 | A different batch, `f2ab2624…`, received HTTP 201 for one local-agent item: job `9b5eef27…`, session `4fd4dae3…`. | Confirmed |
| 14:25:38–39 | The one-item job was stopped. Its later API projection showed `STOPPED`, no `sentAt`, no confirmation deadline and no confirmation. | Confirmed |
| 14:25:52–58 | Printer status and attention queue returned 503; the latter took 8.2 s. | Confirmed |
| 14:33:23–14:45:32 | Windows collection observed 39 connector heartbeats but began after the print attempt. No correlated Windows queue event or physical label was recorded. | Confirmed coverage limit |
| 14:38:35–36 | Authenticated job reads showed historical job `197d65b3…` still `SENT` with acknowledged item and active session; newer job remained stopped. | Confirmed |

The historical job's item has `PRINTER_ACKNOWLEDGED` pipeline state and a null confirmation deadline. Its physical outcome is unknown. The 409 guard is scoped to the same batch and manufacturer, so the historical job is a plausible conflict only if its omitted batch identity matches the 14:20 request. The exported API projection does not prove that match.

## Printing transition contract

Canonical behavior is in `backend/src/rls-waves/session-c/c02/printingLifecycle.sql`; the browser path is `src/features/batches/batch-print-operations.ts`, the controller is `backend/src/controllers/print-job/createPrintJobHandler.ts`, and connector delivery starts in `backend/src/services/printerAgentSessionBoundaryService.ts`. The table records supported transitions, not evidence that each transition occurred on 13 November.

| Operation | Preconditions and authority | State/evidence after success | Duplicate and recovery rule |
| --- | --- | --- | --- |
| Create | Manufacturer admin, batch/printer scope, live attestation, no active job for same batch | Job `PENDING`, session `ACTIVE`, items `RESERVED`; QR rows become `ACTIVATED` and bound to job in one transaction | SQL batch lock and active-job guard reject overlap; HTTP 201 means queued only |
| Local claim | Trusted, fresh, signed connector session; printer/registration match | One `RESERVED` item becomes `ISSUED`, job becomes `SENT` | Printer lock, item row lock and state guard prevent duplicate issue |
| Connector ACK | Same registration, printer, session, job and issued item | `AGENT_ACKED`, device reference and confirmation deadline | Repeated ACK is idempotent; ACK is not proof of physical output |
| Connector CONFIRM | Previously acknowledged item and valid connector boundary | `PRINT_CONFIRMED`, QR `PRINTED`; parent completes only after all items resolve | Repeated confirmation is idempotent; forged/cross-session input is rejected |
| Connector FAIL | Issued or acknowledged item, authenticated connector | `FAILED` for known failure or `FROZEN`/`NEEDS_OPERATOR_ACTION` for indeterminate outcome | No automatic replay of uncertain output |
| Pause/resume | Authorized actor and compatible parent state | Pause blocks new claims; resume requires no unresolved issued, acknowledged or frozen item | Outstanding valid receipts remain eligible while paused |
| Stop | Authorized actor | Unissued items become `CANCELLED`; issued/uncertain items retain evidence and require action | Stops future issuance; never proves earlier output failed |
| Abandon | Authorized actor, no issue or physical evidence | Cancels an unissued job | Rejects any recorded issue, ACK, device reference or confirmation evidence |
| Reconcile | Worker role; expired acknowledged items with a deadline | Parent pauses and item needs operator action, retaining confirmability | Bounded worker pass; late valid confirmation can resolve uncertainty |

The local claim SQL currently selects the oldest `PENDING`/`SENT` job for a printer before checking for a `RESERVED` item. An older `SENT` job with no reserved item can therefore yield `available:false` while a newer job remains queued. The historical job and newer job use the same printer, so this is a plausible explanation for no dispatch. It is **not** proven as the live cause: the historical session's registration binding and a correlated claim result were not in the exported evidence. Do not change this safety behavior until that boundary is reproduced and the printer-level uncertainty rule is established.

The 14:23 job was committed, and one QR was bound to it by the atomic creation function. The observed API projection shows no issue, ACK or confirmation; it does not disclose the QR identifier or authoritative current QR state. It is a controlled recovery candidate only after a tenant-scoped read verifies that no issue or physical evidence exists. The historical acknowledged item is not a retry candidate. Neither job was changed during this investigation.

The `print_job_created` telemetry stage was emitted before the create SQL call. A rejected 409 therefore produced a false creation stage. This branch renames the pre-call stage to `print_job_creation_started`; the existing post-call `print_items_created` event carries committed job/session IDs. A deterministic test reproduced the old false event and passes with the correction. This is a telemetry correction, not physical printing recovery.

## Other application findings

| Domain | Evidence and source boundary | Classification and next proof |
| --- | --- | --- |
| Dashboard and printer-status 503 | Failed requests had no actor context. `backend/src/middleware/auth.ts` returns the observed 503 text only for `P2028` from session hydration; `withDatabaseAuthenticatedSession` performs capability validation, actor revalidation and manufacturer scope loading. Successful requests occurred between failures. | Auth hydration boundary confirmed; exact SQL, pool wait or lock cause unverified. Capture bounded per-stage timings for those operations before changing transaction behavior. Do not increase timeouts blindly. |
| Dashboard totals | `app_rls.dashboard_snapshot_data` aggregates live `QRCode.status` under scoped RLS and reports `rollup_authoritative=false`. | Source definition is authoritative; production totals were not compared to a current tenant-scoped QR count. |
| Batch latency | A successful batch-list request recorded about 1.6 s scope, 1.6 s rows, 1.3 s total and 5.3 s enrichment inside a 9.8 s transaction. | Sequential enrichment is the largest measured stage; its internal SQL is not individually timed. Profile the four bounded operational reads before altering the query. |
| Batch count freshness | `backend/src/services/batchAllocationService.ts` accepts a rollup when its status-count sum equals the live QR count. A status change can preserve the sum while making the distribution stale. The deployed support-email worker mode does not start analytics refresh. | Source-level stale-distribution defect confirmed. Current production quantity discrepancy remains unverified; repair must use authoritative status counts or a proven freshness signal, then certify the 100k+ path. |
| Support 403 | Current frontend calls `POST /support/reports` (plural). Backend route enforces authentication, operations role, tenant isolation and CSRF; manufacturer roles are allowed by `requireOpsUser`. No correlated support POST appears in the supplied backend window. | Exact rejecting gate unverified. Reported singular `/support/report` is not the current route; capture response/request ID and sanitized rejection stage before modifying authorization. |
| Connector binding | Windows evidence shows three active default ZT410 profiles. The live agent and selected printer registration differ from the older expected agent and the November 12 setup-test profile. | Profile-selection risk confirmed; a routing defect for the 14:23 job is unverified. Match job session registration to the signed live connector session before changing code. |

## Recovery order and limits

1. Obtain an authorized, tenant-scoped read of the two jobs' batch and registration bindings, item events, QR status and `printJobId`, connector claim result, and signed receipt state. The sanitized job endpoint omitted several of these fields. Preserve the historical uncertain item and do not replay it.
2. Reproduce the old-job/new-job claim behavior in disposable PostgreSQL 18.4. If safe dispatch is intended after an older physical outcome is resolved, change the SQL only with a complete state-machine and duplicate-print regression.
3. Isolate the intermittent auth-hydration `P2028` stage using existing bounded telemetry. This is the first failing dependency for dashboard/printer-status 503, not evidence of a dashboard SQL failure.
4. Measure batch enrichment SQL, then fix stale status distribution without sacrificing tenant isolation or 100k+ response time. Activate an existing all-mode worker only after separate operational authorization.
5. Capture a correlated support POST 403 and test the exact rejecting middleware before changing security logic.
6. Run a controlled Windows/Zebra acceptance after the uncertain historical job receives explicit operator reconciliation. A queue response, signed ACK, or spool acceptance alone is not physical confirmation.

No production SQL, ECS, IAM, printer or business-record mutation was performed. Local tests do not establish production readiness.
