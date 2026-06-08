# MSCQR Printer Launch Evidence Matrix

Status: RED until all required printer modes have physical positive artifacts.

## Launch-critical requirement

Direct printing is a core MSCQR launch capability. MSCQR must not be marked fully launch Green until physical printer evidence exists for:

1. Windows USB/local connector positive print.
2. Windows network printer positive print.
3. Disabled/unreachable/failure safety posture.

## Physical validation hardware

- Test OS: Windows
- Printer: Zebra ZT410 300dpi
- USB path: required
- Network path: required
- Failure/safety path: required

## Required evidence per mode

For each printer mode, attach:

- Environment: production/staging host.
- User role used.
- Tenant/workspace used.
- Printer mode.
- Printer make/model.
- OS and connector version if local connector is used.
- Print job ID.
- Batch ID or QR label scope.
- Timestamp UTC.
- Redacted backend/worker/connector logs.
- UI screenshot showing job success/failure state.
- Physical printed output photo or printer/device log.
- Secret leakage check: no raw token, render URL, bearer token, cookie, password, stack trace, or cross-tenant data.

## Evidence matrix

| Gate | Required | Status | Evidence |
|---|---:|---|---|
| Windows connector install/startup/health | Yes | RED | Pending Windows validation |
| Windows USB/local connector positive print | Yes | RED | Pending physical Zebra ZT410 USB print |
| Windows network printer positive print | Yes | RED | Pending physical Zebra ZT410 network print |
| Disabled printer safe failure | Yes | RED | Pending failure test |
| Unreachable printer safe failure | Yes | RED | Pending failure test |
| Connector stopped safe failure | Yes | RED | Pending failure test |
| Cross-tenant printer/job denial | Yes | RED | Pending auth/security test |
| Token/render URL leakage check | Yes | RED | Pending response/log review |
| Worker/job lifecycle correctness | Yes | RED | Pending job state proof |

## Current launch status

Printer gate: RED / BLOCKING

Reason:
Direct printer connection is key to MSCQR. USB-only proof does not validate network printing. Disabled-route proof alone does not validate positive physical printing.

