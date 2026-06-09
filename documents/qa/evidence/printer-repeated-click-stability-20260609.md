# MSCQR Printer Repeated-Click Stability Evidence

Date: 2026-06-09

## Root cause

Physical Zebra ZT410 validation proved the printer path could produce output, but real operator behavior exposed UI request storms. Printer diagnostics, setup, dashboard refreshes, heartbeat reports, test-label actions, and batch print actions could be clicked or remounted quickly enough to create overlapping API calls. Some POST actions received a fresh idempotency key per click, so the backend could not always recognize the same user intent.

## Changed files

- `src/lib/api/internal-client-printing-request-control.ts`
- `src/lib/api/internal-client-printing.ts`
- `src/pages/PrinterDiagnostics.tsx`
- `src/pages/PrinterSetup.tsx`
- `src/features/layout/useManufacturerPrinterConnection.ts`
- `src/features/layout/components/PrinterDialogs.tsx`
- `src/features/layout/DashboardLayoutShell.tsx`
- `src/features/batches/useBatchPrintWorkflow.ts`
- `backend/src/controllers/printerController.ts`
- `backend/src/controllers/print-job/createPrintJobHandler.ts`
- `backend/src/routes/index.ts`
- `src/test/internal-client-printing.test.ts`
- `backend/tests/idempotencyService.test.js`

## Rate-limit behavior before and after

Before: repeated refresh/test clicks could stack `/api/manufacturer/printers`, `/api/manufacturer/printer-agent/heartbeat`, `/api/manufacturer/print-jobs`, `/api/auth/me`, and `/api/dashboard/stats` activity until printer and dashboard reads hit 429 responses.

After: printer status/list/heartbeat calls dedupe identical in-flight work, retain last-known-good printer status through bounded 429 cooldown, and poll less aggressively in setup/diagnostics views. Print read limits remain enforced but now allow normal production polling headroom. Print mutation limits remain security controls and are not used for correctness.

## Repeated-click behavior

Print job creation, printer test-label actions, relink/abandon/confirm/sample-scan/release, pending-print refresh, diagnostics refresh, and setup test/save actions now have single-flight guards. Buttons show loading or disabled states such as `Connector checking...`, `Please wait...`, `Saving...`, `Checking...`, and the existing `printing` states.

## Idempotency behavior

Frontend print-job creation and test-label mutations now send stable action-scoped `x-idempotency-key` values and reuse the same in-flight promise for repeated clicks. Backend print-job creation already used scoped idempotency; active-job reuse now completes the idempotency record so repeated keys replay the safe resume payload. Backend live test-label printing now requires and records idempotency scoped by tenant/manufacturer/user/printer, preventing cross-tenant replay.

## Remaining physical printer validation status

Code and automated tests cover repeated-click safety. A final Windows validation should still be run with the Zebra ZT410 300dpi attached to confirm operator-facing timing, button states, connector heartbeat timing, and physical duplicate-label prevention under real spooler latency.

## Manual Windows Zebra ZT410 validation

1. Sign in as the manufacturer operator on Windows with the MSCQR Connector running.
2. Open Printer Setup and confirm the ZDesigner ZT410 300dpi printer is selected.
3. Double-click `Refresh status`, `Check again`, and live `Test label` buttons rapidly. Confirm the UI shows loading/disabled text and DevTools shows one effective mutation per action.
4. Open Batches, choose a saved printer profile, enter a small quantity, and double-click the print/start action. Confirm exactly one print job is created and exactly one intended label run is queued.
5. While the job is pending, rapidly click refresh/retry. Confirm the UI tracks the existing job rather than creating a new one.
6. Watch Network for 429 responses. If a 429 occurs, confirm requests pause/back off and the UI shows a friendly paused/checking state without stack traces, tokens, cookies, render URLs, passwords, or raw secrets.
