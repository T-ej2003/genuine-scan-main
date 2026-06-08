# MSCQR Printer Evidence: Windows Network Printer Positive Print

Status: RED / PENDING PHYSICAL VALIDATION

## Scope

Validate MSCQR network printer path on Windows using a physical Zebra ZT410 300dpi printer over LAN/network.

## Hardware

- OS: Windows
- Printer: Zebra ZT410 300dpi
- Connection mode: network/LAN
- Printer IP/hostname: pending redacted capture
- MSCQR connector/direct route: pending architecture confirmation

## Required proof

- Zebra ZT410 300dpi is reachable over network.
- Windows can reach printer IP/hostname.
- Windows can print to the network printer, or MSCQR supported dispatch component can reach it directly.
- MSCQR network printer route is configured.
- MSCQR creates a real network print job.
- Supported dispatch path sends the job to the printer.
- Physical Zebra output is printed.
- Job lifecycle reaches success/completed only after device/connector success.
- Network failure behavior is bounded.
- Evidence is redacted and excludes secrets.

## Evidence to attach

- Timestamp UTC:
- Host/environment:
- User role:
- Tenant/workspace:
- Printer IP/hostname redacted:
- Printer make/model:
- Printer route/mode:
- Connector version if connector-mediated:
- MSCQR printer ID:
- Print job ID:
- Batch ID / QR scope:
- UI screenshot:
- Connector/worker dispatch log excerpt:
- Physical output photo:
- Secret leakage check result:

## Architecture decision required

Record which path is validated:

- Windows connector to network printer
- Backend/worker direct network dispatch
- Other supported route

## Pass/fail

Status: RED until physical network print evidence is attached.

