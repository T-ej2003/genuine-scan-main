# Print Operations Pause/Resume/Reissue Evidence - 2026-06-09

## Scope

This pass adds production controls for manufacturer print runs and role-scoped replacement-label approvals.

## Root Cause

Physical Zebra ZT410 validation exposed that bulk print lifecycle traffic was sharing the same low request family as generic gateway job actions. A normal connector can claim, acknowledge, and confirm many labels quickly, so larger print runs could hit `429` during valid work. The UI also had no explicit operator controls for pause, resume, stop, or replacement-label approval.

## State Machine

- Print jobs now support `PAUSED`, `PARTIALLY_COMPLETED`, and `STOPPED`.
- Print sessions now support `PAUSED`, `RESUME_PENDING`, `RETRY_WAITING`, `STOPPING`, and `STOPPED`.
- Print items now support `CANCELLED`.
- Pipeline state now includes paused/resume/retry/stop states.

Pause stops new claims by moving the session out of `ACTIVE`. Resume returns paused/retry-waiting sessions to `ACTIVE`. Stop closes the session, cancels unconfirmed items, releases unconfirmed QR codes back to allocated state, and preserves already confirmed printed labels.

## Backend Routes

- `POST /api/manufacturer/print-jobs/:id/pause`
- `POST /api/manufacturer/print-jobs/:id/resume`
- `POST /api/manufacturer/print-jobs/:id/stop`
- `GET /api/manufacturer/print-reissue-requests`
- `POST /api/manufacturer/print-jobs/:id/reissue-request`
- `POST /api/manufacturer/print-reissue-requests/:id/approve`
- `POST /api/manufacturer/print-reissue-requests/:id/reject`

Pause and stop require an audit reason. Reissue approval/rejection requires a decision note.

## Rate Limit Behavior

Before: local-agent and gateway lifecycle routes shared `gateway.jobs` at 90/minute.

After: print lifecycle claim/ack/confirm/fail routes use `print.lifecycle` with `PRINT_LIFECYCLE_RATE_LIMIT_PER_MIN` defaulting to 1800/minute. Print-job creation and operator mutations remain under stricter print mutation limits.

If lifecycle traffic is limited, the response includes `RATE_LIMITED`, `Retry-After`, and user-safe cooldown copy. The frontend shows that printing is cooling down and tells the operator to try again after 90 seconds while preserving confirmed labels.

## Reissue Approval Workflow

- Manufacturer requests replacement labels from a confirmed/locked print run.
- Manufacturer request targets licensee/brand admin review.
- Licensee/brand admin request targets super-admin review.
- Licensee/brand admin cannot approve out-of-scope requests or self-approve.
- Super admin can approve super-admin-level escalations.
- Approval calls the existing controlled reissue allocator after authorization, preserving QR reservation and replacement-chain behavior.
- Super admins receive audit visibility when a licensee/brand admin approves a manufacturer request.

## Frontend Behavior

- Recent print runs show requested, printed, pending, and failed counts.
- Active runs show Pause printing and Stop printing.
- Paused/retry-waiting runs show Resume printing.
- Pause/stop open reason dialogs and disable submit until a useful reason is entered.
- Confirmed/locked runs show Request reissue.
- Licensee/super-admin batch workspace includes a pending reissue review queue with mandatory decision notes.

## Tests Run

- `npm --prefix backend run prisma:generate`
- `npm run typecheck`
- `npm --prefix backend run build`
- `npm test -- --run src/test/dialog-recovery-states.test.tsx src/test/internal-client-printing.test.ts`
- `node backend/tests/printOperationControlService.test.js`
- `node backend/tests/rateLimitEnforcement.test.js`

## Remaining Physical Validation

Validate on Windows with Zebra ZT410 300dpi:

1. Start a print run larger than 5 labels.
2. Confirm no `429` storm during normal claim/ack/confirm traffic.
3. Pause with a reason and confirm no new labels are dispatched.
4. Resume and confirm the run continues from remaining labels.
5. Stop with a reason and confirm confirmed labels stay printed while remaining labels are not marked printed.
6. Confirm dashboard/history counts update after pause/resume/stop/reissue.
7. Submit manufacturer reissue request and verify only the correct licensee admin can see it.
8. Approve/reject as licensee admin and confirm super-admin audit visibility.
9. Submit licensee-admin reissue request and confirm super-admin approval is required.

## CTO Recommendations

- Add a printer-session websocket/SSE stream so long print runs update counts without polling.
- Add an operator recovery checklist for stopped/failed runs that guides media reload, calibration, and sample scan proof.
- Add dashboard alerts for repeated lifecycle cooldowns by printer model and workstation.
- Add a periodic job that reconciles print-session counts against print-item states and reports any drift before operators see stale quantities.
