# MSCQR Printer Physical Validation Runbook

Status: required for full launch Green.

## Scope

Direct printing is launch-critical. Validate all required printer paths with real hardware and no fabricated success.

Required hardware:
- Windows machine.
- Zebra ZT410 300dpi printer.
- USB connection.
- Network/LAN connection.
- Access to MSCQR deployed environment.
- Print-capable MSCQR account.

## A. Windows connector install/startup/health

1. Download the latest MSCQR Windows connector from MSCQR.
2. Install connector on Windows.
3. Confirm connector starts after install.
4. Confirm connector is reachable/healthy.
5. Capture:
   - connector version
   - install result
   - health/status screenshot
   - connector log path
   - Windows printer list showing Zebra ZT410 300dpi

Pass criteria:
- Connector installed.
- Connector running.
- Connector sees usable Zebra printer.
- No secret leakage in installer/status output.

## B. Windows USB/local connector positive print

1. Connect Zebra ZT410 300dpi via USB.
2. Confirm Windows can see the printer.
3. Confirm Windows native test page or printer status is healthy.
4. Log into MSCQR as print-capable role.
5. Open Printer Setup / Diagnostics.
6. Select the Zebra USB printer.
7. Trigger MSCQR test print or label print.
8. Confirm physical output.
9. Capture:
   - UI success screenshot
   - connector log showing job claim/dispatch/completion
   - backend/worker logs if applicable
   - print job ID
   - physical label/output photo

Pass criteria:
- Physical output exists.
- Job reaches success/completed only after connector/device success.
- No raw token, bearer token, cookie, password, render URL, stack trace, or cross-tenant data.

## C. Windows network printer positive print

1. Connect Zebra ZT410 300dpi to LAN/network.
2. Record redacted IP/hostname.
3. Confirm Windows can reach printer.
4. Confirm Windows can print to the network printer, if connector-mediated.
5. Configure MSCQR network printer route.
6. Trigger MSCQR network/direct test print or label print.
7. Confirm physical output.
8. Capture:
   - route configuration redacted
   - UI success screenshot
   - connector/worker dispatch logs
   - print job ID
   - physical label/output photo

Pass criteria:
- Physical output exists over network path.
- Job lifecycle records success accurately.
- Timeout/retry behavior is bounded.
- No secrets or cross-tenant data leak.

## D. Disabled/unreachable/failure safety

Validate:

1. Printer disabled.
2. Printer offline/unplugged.
3. Wrong printer IP/hostname.
4. Connector stopped.
5. Unauthorized role attempts print.
6. Tenant A attempts tenant B printer/job access if routes accept IDs.

Pass criteria:
- Friendly bounded error.
- No stack trace.
- No raw token/render URL/cookie/bearer token/password.
- No cross-tenant data.
- Job is marked failed/pending safely.
- API/worker timeout is bounded.

## Final Green requirement

Printer can be marked launch Green only after:
- Windows connector install/startup/health evidence is attached.
- Windows USB/local connector positive artifact is attached.
- Windows network printer positive artifact is attached.
- Disabled/unreachable/failure safety artifact is attached.
- Cross-tenant printer denial is attached.
- Secret leakage review is attached.

