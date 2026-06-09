# MSCQR Printer Physical Validation Evidence

Status: In progress

Branch: evidence/printer-usb-network-physical-validation
Base: 7aa4a3c / origin/main after PR #39

## Hardware

- Windows machine: pending
- Printer: Zebra ZT410 300 dpi
- USB path: pending
- Network path: pending

## Connector

- Windows connector version: pending
- Installer publisher: pending
- Connector reachable locally: pending
- Connector protocol: pending

## USB validation

Status: pending

Required proof:
- Windows sees Zebra ZT410 300 dpi over USB
- MSCQR Connector sees the printer
- MSCQR Printer Setup reports ready/usable
- MSCQR test label prints physically
- Backend/agent evidence shows dispatch/ack/confirmation path
- No fallback/demo/virtual printer used

## Network validation

Status: pending

Required proof:
- Zebra ZT410 has LAN IP
- Windows can reach printer IP
- Raw 9100/ZPL or configured network queue path validated
- MSCQR sees network printer route
- MSCQR test label prints physically
- Backend/agent evidence shows dispatch/ack/confirmation path
- No fallback/demo/virtual printer used

## Final decision

Printer posture: pending

