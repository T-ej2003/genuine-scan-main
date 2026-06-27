# Official MSCQR ZPL Wordmark Safety Contract - 2026-06-27

## Production Issue

After the official MSCQR brand asset rollout, secure print runs could be created and claimed by the local connector, but physical printing did not start. The connector rejected the approved payload before Windows RAW spooler dispatch because its packaged safety profile still rejected `^GF/^GFA` raster graphics.

No labels were printed in that failure mode because the printer queue was not reached.

## Root Cause

The stylised MSCQR wordmark cannot be reproduced portably with normal ZPL text such as `^FDMSCQR^FS`. Industrial ZPL-compatible printers need the official SVG wordmark converted into a deterministic one-bit bitmap and emitted as a bounded `^GFA` graphic.

Backend safety had learned to accept the official graphic, but the deployed connector safety profile had not. That backend/connector drift blocked launch printing before spooler dispatch.

## Safety Contract

Production labels retain the official MSCQR wordmark through the shared contract in `backend/src/printing/zplCompatibilityContract.ts`.

- Profile: `zpl_300dpi_generic`
- Label: `40x50mm`, `300dpi`, `472x591` dots
- Printer language: ZPL/ZPL-II compatible
- Official graphic id: `mscqr_official_wordmark_v1`
- Graphic command: `^GFA`
- Graphic dimensions: `267x60` dots
- Graphic bytes: `2040`
- Graphic data hash: `d5707dfffaa6c4a614db9ecdbba27505134d36bf904f664d5b2d85656994f854`
- Normalized graphic hash: `a7926928e5e8d2cce6767620ebe7ec4c89c7a3e8c29bf519bbaf6122e979cf6a`
- Connector requirement: MSCQR Connector `2026.6.26` or newer

Backend and connector validation both enforce the same constraints:

- Exactly one raster graphic is allowed.
- The raster graphic must match the official hash and dimensions.
- The graphic must be placed only in the approved header region.
- Arbitrary, repeated, oversized, mutated, or out-of-bounds `^GF/^GFA` payloads are rejected.
- The payload must fit the generic 300dpi ZPL size budget.
- The QR quiet zone and serial text regions must not overlap the wordmark.

## Printer Compatibility

The primary production profile is generic industrial `zpl_300dpi_generic`, not a Zebra ZT410-only profile. Examples that should validate when they advertise ZPL and 300dpi:

- `ZDesigner ZT410-300dpi ZPL`
- `ZDesigner ZT411-300dpi ZPL`
- `Honeywell 300dpi ZPL`
- `TSC 300dpi ZPL`
- `Printronix 300dpi ZPL`

`Generic / Text Only` and unknown non-ZPL queues must be rejected before print unless the connector has an explicit, audited RAW ZPL-compatible profile. 203dpi ZPL profiles are rejected until scaling is implemented and physically validated.

## Operator UX Contract

Before connector acceptance, the UI must show preparation states, not printing states. If payload validation fails before print:

- The modal says `Print did not start`.
- The visible message says `The print payload was blocked before reaching the printer. No labels were printed. Use diagnostic test label or contact admin.`
- Printed count remains `0`.
- Remaining labels stay recoverable.
- The operator is guided to run the diagnostic label, update the connector, refresh the connector, or choose a compatible 300dpi ZPL printer.

## Manual Launch Validation

1. Install MSCQR Connector `2026.6.26` or newer.
2. Confirm connector status at `http://127.0.0.1:17866/status`.
3. Confirm the selected printer advertises ZPL/ZPL-II and 300dpi.
4. Run the diagnostic label; it must exercise the same official wordmark `^GFA` allowlist path.
5. Print a one-label production run.
6. Confirm connector accepts payload, Windows queue receives a RAW job, and the physical label prints.
7. Scan the QR code and verify it opens the MSCQR verification route.
8. Confirm the wordmark does not overlap the QR quiet zone, serial, or scan domain.
9. Confirm recent runs only show printed confirmation after connector/backend acknowledgement.
