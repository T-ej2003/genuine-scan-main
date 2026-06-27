# Zebra ZPL Wordmark Fallback - 2026-06-27

## Production Issue

After the official MSCQR brand asset rollout, secure Zebra print runs could be created and claimed by the local connector, but physical printing did not start. The connector rejected the approved payload before sending it to the Windows RAW spooler with:

```text
Generated ZPL looks unsafe for this Zebra profile. Use diagnostic test label or adjust label template.
```

The user-facing sanitized form was:

```text
Payload rejected before print: generated Zebra ZPL looks unsafe for this profile.
```

## Root Cause

The backend production ZPL renderer embedded the official wordmark as a Zebra `^GFA` raster graphic. The backend safety profile had been relaxed to allow one bounded raster graphic, but the deployed connector/local helper safety profile still rejected `^GF/^GFA` payloads before spooler dispatch. That created a safety-profile mismatch:

- Backend task definition 42 generated and accepted `^GFA` wordmark ZPL.
- The active connector profile rejected the same payload before printing.
- The printer queue/spooler was not reached, so no physical labels were printed.

Task definition 41's stable Zebra label shape used plain text `^FDMSCQR^FS` branding and no raster graphic. The launch-safe fix restores that connector-compatible ZPL shape.

## Fix Applied

Production Zebra ZPL temporarily uses semantic text branding:

```zpl
^FO0,18^FB600,1,0,C,0^A0N,34,34^FDMSCQR^FS
```

The official web/app SVG assets remain active for browser UI, favicons, metadata, and PDF/browser-rendered surfaces. The generated ZPL wordmark module remains in the repo for future hardware validation, but production ZPL does not emit it.

The backend ZPL safety profile is aligned back to the connector launch profile:

- Production QR label ZPL must contain exactly one QR command.
- Production QR label ZPL must not contain `^GF/^GFA` raster graphics.
- Arbitrary and official generated raster graphics are both rejected until the packaged connector and physical Zebra path are validated together.
- Diagnostics redact QR payload text and graphic fields from logs.

## Operator UX Contract

If a print payload is blocked before the printer queue:

- The UI must not say labels printed.
- Printed count remains `0`.
- Remaining labels stay recoverable.
- The modal title says `Print did not start`.
- The visible message says: `The print payload was blocked before reaching the printer. No labels were printed. Use diagnostic test label or contact admin.`

## Manual Zebra Validation Steps

1. Confirm connector status at `http://127.0.0.1:17866/status`.
2. In Printer Setup, run the diagnostic Zebra RAW ZPL test label.
3. Start one production print run for a single label on `ZDesigner ZT410-300dpi ZPL`.
4. Confirm the connector accepts the payload and the Windows spooler receives a job.
5. Confirm the physical label prints with one centered QR code, `MSCQR`, `AUTHENTICITY CHECK`, `scan.mscqr.com`, and the human serial.
6. Scan the QR and verify it opens the MSCQR verification route.
7. Confirm recent print runs show printed confirmation only after connector/backend confirmation.

## Future Re-enable Criteria for Official ZPL Wordmark

Only re-enable the generated `^GFA` wordmark after all of these pass:

- Backend payload safety accepts only the exact generated official graphic bounds.
- Packaged connector safety accepts the same exact bounded graphic.
- Oversized, malformed, repeated, or arbitrary `^GF/^GFA` payloads remain rejected.
- Diagnostic test label uses the same safety path and catches profile rejection.
- ZT410 300dpi physical validation confirms no QR quiet-zone overlap and no scan reliability regression.
