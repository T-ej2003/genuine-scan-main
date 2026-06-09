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


## USB raw WinSpool physical print evidence

Status: GREEN for Windows USB raw physical printer output.

Evidence captured:
- Windows detected Zebra printer queue: `ZDesigner ZT410-300dpi ZPL`
- Driver: `ZDesigner ZT410-300dpi ZPL`
- Port: `USB001`
- PrinterStatus: `Normal`
- Printer Type: `Local`
- Raw WinSpool send result: `RAW_WINSPOOL_SEND_OK`
- Bytes sent: `233`
- Physical output: photo captured showing `MSCQR P4 USB RAW PRINT PROOF`, Zebra ZT410 300dpi USB001, UTC timestamp, and barcode output.

Evidence files:
- `mscqr-p4-usb-raw-winspool.txt`
- `mscqr-p4-usb-raw-label.zpl`
- `WhatsApp Image 2026-06-09 at 19.40.08.jpeg`

Decision:
- Windows USB raw printer path is physically validated.
- This proves the Windows workstation, Zebra ZT410 300dpi driver, USB001 queue, and raw ZPL path can produce physical output.
- This does not yet prove an MSCQR app-created print job completed through the deployed backend/agent lifecycle.

Remaining:
- MSCQR app-created USB print job proof.
- Windows network printer physical print proof.
- Failure safety proof.

