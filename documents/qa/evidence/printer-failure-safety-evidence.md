# MSCQR Printer Evidence: Failure and Safety Routes

Status: RED / PENDING VALIDATION

## Scope

Validate printer-disabled, unreachable, connector-stopped, unauthorized, and cross-tenant safety behavior.

## Required failure cases

1. Printer disabled in MSCQR.
2. Zebra printer offline/unplugged.
3. Wrong network printer IP/hostname.
4. MSCQR connector stopped.
5. Unauthorized role attempts print route.
6. Tenant A attempts tenant B printer/job access if route accepts IDs.

## Expected behavior

- Friendly bounded error.
- No raw stack trace.
- No raw render URL.
- No bearer token.
- No cookie.
- No password or secret.
- No cross-tenant printer/job data.
- Job state is failed/pending safely.
- API/worker timeout is bounded.
- No API worker exhaustion.
- No duplicate QR state corruption.

## Evidence to attach

- Timestamp UTC:
- Environment:
- User role:
- Tenant/workspace:
- Failure case tested:
- Route/UI/API tested:
- Response/status:
- UI screenshot:
- Backend/worker/connector log excerpt:
- Secret leakage check:
- Job lifecycle result:

## Pass/fail

Status: RED until all required failure cases are validated.

