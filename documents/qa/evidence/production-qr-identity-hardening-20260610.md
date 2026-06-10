# Production QR Identity Hardening - 2026-06-10

## Production Symptom

During controlled Zebra ZT410 print testing, a production-like label printed a public verify URL with an enumerable visible serial:

`https://www.mscqr.com/verify/TBD0000000030`

That label must be treated as compromised because adjacent serials are guessable.

## Root Cause

Public verification lookup was already exact-code based, but print pipeline identity was ambiguous:

- `PrintItem.code` was populated from `displayCode || QRCode.code` in print-job creation and legacy session repair.
- Label rendering accepted `displayCode` as the visible serial and allowed placeholder values such as `TBD...`.
- Transport code then used `PrintItem.code` as though it were safe public identity.

## Code Fix

- `QRCode.code` remains the only public verify identity.
- Print item reservation now stores `QRCode.code`, never `displayCode`.
- Label rendering uses `publicVerifyCode` for QR URLs and generated `humanSerial` for visible support text.
- ZPL output shows a clean MSCQR authenticity label with one centered QR, `AUTHENTICITY CHECK`, `scan.mscqr.com`, and `Serial: <humanSerial>`.
- ZPL output no longer prints raw job IDs, batch IDs, raw public tokens as visible text, or `TBD...`.
- Human serials are generated from configurable region, brand, factory, line, year, scoped sequence, and checksum.
- Optional JSON metadata was added to `Batch`, `Licensee`, and `User`; `Printer.metadata` is reused for line codes.
- Production npm commands for lifecycle reconciliation and print-test use node-compatible wrappers instead of `tsx`.
- Static guard `npm run check:print-qr-identity` blocks dangerous verify/display serial patterns in print and public verify code.

## Serialisation

Safe format:

`{REGION}-{BRAND}-{FACTORY}-{LINE}-{YY}-{SEQ}-{CHECK}`

Examples:

- `UK-ABR-KRT-L01-26-000042-...`
- `EU-NOV-MIL-L03-26-000188-...`
- `US-ARC-DAL-L07-26-003301-...`

Fallbacks when metadata is incomplete:

- `RGN`
- `BRD`
- `FAC`
- `L00`

Fallbacks are audited through generated serial warnings in code paths and never use `TBD` or `QRCode.code`.

## Production Repair Guidance

Old labels printed with `/verify/TBD...` must be voided and reissued through controlled reissue. Do not rotate exposed QR public identities in place. The reissue path should create replacement QR rows, print the replacement `QRCode.code`, and keep old-to-new mapping internal through replacement-chain audit records.

Recommended post-deploy checks:

1. Run `npm run check:print-qr-identity`.
2. Build backend so Prisma client includes the metadata fields.
3. Run lifecycle repair dry-run before any apply action.
4. Print one replacement label and inspect ZPL/physical output.
5. Confirm QR payload resolves to a non-enumerable `QRCode.code`.
6. Confirm visible serial is generated and does not resolve through `/verify/:code`.
7. Confirm old `/verify/TBD...` labels return not found or replacement-required according to existing replacement policy.

## Remaining Risk

Previously exposed enumerable test labels remain unsafe until voided/reissued. This fix prevents new production labels from using visible serials as public verify identity, but it cannot make already printed enumerable labels trustworthy.
