# MSCQR Printer Evidence: Windows USB / Local Connector Positive Print

Status: RED / PENDING PHYSICAL VALIDATION

## Scope

Validate MSCQR local connector printing on Windows using a physical Zebra ZT410 300dpi printer over USB.

## Hardware

- OS: Windows
- Printer: Zebra ZT410 300dpi
- Connection mode: USB
- MSCQR connector: pending version capture

## Required proof

- Windows sees Zebra ZT410 300dpi as an installed printer.
- Windows native test page or printer status confirms printer availability.
- MSCQR connector installs successfully.
- MSCQR connector starts successfully.
- MSCQR connector reports healthy/ready state.
- MSCQR UI can select/use the printer.
- MSCQR creates a real print job.
- Connector receives/claims/dispatches the job.
- Physical Zebra output is printed.
- Job lifecycle reaches success/completed only after device/connector success.
- Evidence is redacted and excludes secrets.

## Evidence to attach

- Timestamp UTC:
- Host/environment:
- User role:
- Tenant/workspace:
- Connector version:
- Printer name as shown by Windows:
- MSCQR printer ID:
- Print job ID:
- Batch ID / QR scope:
- UI screenshot:
- Connector log excerpt:
- Backend/worker log excerpt:
- Physical output photo:
- Secret leakage check result:

## Pass/fail

Status: RED until physical print evidence is attached.

