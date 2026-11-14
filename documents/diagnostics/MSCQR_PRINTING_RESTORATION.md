# MSCQR printing restoration checkpoint

Status on 14 November 2026: **PRINTING_OPERATIONAL=false**. This is a source and evidence checkpoint. No production printing, database update, service deployment, or inventory recovery was performed.

## Implementation map

| Boundary | Current implementation |
| --- | --- |
| Manufacturer action and progress | `src/features/batches/batch-print-operations.ts`, `src/components/printing/PrintProgressDialog.tsx`, `src/lib/api/internal-client-printing.ts` and `internal-client-printing-operations.ts` |
| HTTP authorization and handlers | `backend/src/routes/index.ts` (manufacturer print, reissue, test-label and connector routes), `backend/src/controllers/print-job/`, `backend/src/controllers/printerAgentJobController.ts` |
| Authoritative state | `backend/src/rls-waves/session-c/c02/printingLifecycle.sql`; `backend/prisma/schema.prisma` models `PrintJob`, `PrintSession`, `PrintItem`, `PrintItemEvent`, `PrintJobChunk`, `QRCode`, `Printer` and `PrinterAgentSession` |
| Connector and physical dispatch | `backend/src/services/printerAgentSessionService.ts`, `backend/src/local-print-agent/`, connector installation under `backend/src/local-print-agent/install/windows/` |
| Recovery | `app_rls.printing_control_job`, `printing_reissue_request`, `printing_worker_reconcile`, `backend/src/services/printConfirmationReconciler.ts` |

The current HTTP create path requires authenticated manufacturer scope, recent sensitive authentication, tenant isolation and CSRF. SQL creation binds QRs to a job and reserves items atomically. Connector claim, signed receipts and confirmation are distinct transitions. `src/features/batches/batch-print-operations.ts` labels HTTP acceptance as queued and waits for backend-confirmed progress; it does not treat a 201 as physical completion.

May–June commits `91be5a46a`, `3da8e9c7c`, `539bbed47`, `bbd44d1c1` and `b807445b5` introduced or changed Windows RAW ZPL, ACK sequencing, signed persistent sessions and reissue. They are historical leads, not proof of current device behavior. The present signed-session and FORCE RLS controls remain required.

## Functionality inventory

| Capability | Evidence status |
| --- | --- |
| Printer registration, connector authentication, device identity, printer discovery, selection and heartbeat | Partially working: the sampled current connector was trusted and READY, but three active default ZT410 profiles had different agent identities. The November 12 test targeted an older registration. |
| Connector installation and version compatibility | Unverified for a fresh install; sanitized package identifies the installed connector, but no installation or update was run. |
| Printer health and diagnostic test label | Partially working: health was READY in 39 samples; the earlier test label remained PENDING on a different registration. No physical test was performed in this evidence window. |
| Batch selection, job creation and QR reservation | Partially working: one later job committed with one reserved item; a separate request correctly returned HTTP 409 for an active job on its batch. |
| Dispatch, physical label generation, connector ACK and confirmation | Partially working: an older item was issued and acknowledged; its physical output and backend confirmation remain unknown. The later job was never issued. |
| Progress and print history | Partially working: authenticated GET and SSE exposed job, item and session snapshots, but one historical GET returned 503. Snapshots are not a full event history. |
| Pause, stop, failure recovery, reissue and duplicate-print protection | Partially working: the later job stopped before issuance; PR #839 adds guarded reissue for that class and remains under CI/review. The older acknowledged item must remain protected. |
| Network direct and IPP modes | Source and PostgreSQL integration tests exist; live physical behavior is unverified here. |
| QR inventory reconciliation | Unverified in production: the sanitized job response omits authoritative QR code association and no approved recovery was executed. |

## Confirmed defects and root causes

1. **Pre-dispatch stop strands an activated QR.** `printing_control_job` cancels an unissued item but ordinary creation requires an unbound `ALLOCATED` QR. The existing reissue path excluded `STOPPED` on CREATE. PR #839 extends that path only for matching, unissued, no-evidence items and keeps the old records. It does not authorize production recovery.
2. **Reissue could cross batch release.** Review of PR #839 found that an approved request could EXECUTE after a batch became `RELEASED`. The local correction locks and checks the batch at CREATE and EXECUTE, retains idempotent request lookup, and leaves confirmed pre-release reissue eligible. Disposable PostgreSQL 18 certification passed; hosted CI and new review are pending.
3. **An acknowledged historical item with a null deadline is invisible to the reconciler.** The manufacturer-scoped November 13 readback shows `AGENT_ACKED`, `agentAckedAt` present, `confirmationDeadlineAt` null, parent `SENT`/`ACTIVE`. The previous `printing_worker_reconcile` selected only `confirmationDeadlineAt < now_at`. A PostgreSQL regression returned `0` before correction, then `1` after using `agentAckedAt + 10 minutes` only when the explicit deadline is missing. The item stays acknowledged and bound to its QR, the parent pauses for operator action, a second pass returns `0`, and a valid late confirmation resolves it. A recent acknowledgement with no explicit deadline remains confirmable. The origin of the historical null remains unverified; current SQL and TypeScript ACK writers normally set a deadline.
4. **The active-job conflict is correctly associated.** The older acknowledged job's batch ID matches the batch on the HTTP 409 create request in the Mac evidence. The active-job guard must remain; this conflict does not authorize an automatic replay or release.

## Evidence and limits

Original records remain outside Git in `~/Desktop/MSCQR-LIVE-DIAGNOSTICS`, `~/Desktop/MSCQR-WINDOWS-EVIDENCE-SANITIZED.zip` and `~/Desktop/MSCQR-PRINT-JOB-READBACK.zip`. The readback observed the older job as `SENT` with one acknowledged, unconfirmed item and the newer job as `STOPPED` with one cancelled, unissued item. The latter had no recorded connector ACK or confirmation. These are different batches. The Windows connector sampled on November 13 used the newer registration, whereas the November 12 pending test label used an older registration. The Windows spooler was running and its queue was empty during the later collection, which cannot prove whether earlier output occurred. Operational PrintService logging was unavailable. Reconciliation worker activation and current catalogue state were not authenticated by these packages.

## Source changes and tests

- PR #839: stopped-item recovery and batch-release guard. Local PostgreSQL 18.6 application-path certification, rollback checks, RLS package verification, source security check and backend build passed. Hosted PostgreSQL 18.4 CI and fresh Codex review are pending for the latest head.
- Separate legacy-null-deadline correction: local source change and PostgreSQL 18.6 application-path certification passed, including recent/overdue cases, late confirmation, bounded worker behavior, rollback, RLS package verification and source security. It has not been merged or deployed. PostgreSQL 18.4 hosted CI remains required.

## Performance and remaining acceptance

No representative printing latency benchmark or controlled Zebra output was measured in this work. The supplied backend task definition has `RUN_BACKGROUND_WORKERS=false`; the separate production worker's current mode and reconciliation activity remain unverified. Physical output, signed receipt, backend confirmation and final QR inventory must be correlated in one authorized test using the current bound Windows connector and ZT410. Preserve the older uncertain item; do not replay, confirm, abandon or release it from this checkpoint. A fresh tenant-scoped read is needed before any operational reconciliation.
