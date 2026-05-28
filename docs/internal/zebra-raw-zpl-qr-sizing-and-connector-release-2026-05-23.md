# Zebra RAW ZPL QR Sizing and Windows Connector Release - Internal Engineering Note

## Purpose

This note records the Windows Local Print Connector, Zebra RAW ZPL, QR physical sizing, validation, and deployment work completed for MSCQR on 2026-05-23.

This is an internal engineering note. It includes more detail than the client report, but it still avoids credential material, raw QR payloads, private infrastructure addresses, private hostnames, and internal access values.

## Relevant Commits

- `edf325a` - Force qs 6.15.2 across backend dependency tree.
- `c399e20` - Fix Zebra raw ZPL printing and local agent confirmation states.
- `63f15df` - Publish source-versioned Windows connector release metadata.
- `e648f96` - Publish Windows connector 2026.5.23.
- `424303d` - Fix Zebra RAW ZPL QR physical sizing.
- `c81583a` - Refactor batch print workflow under size budget.

Production servers were manually reset to include:

- `c81583a` - Refactor batch print workflow under size budget.
- `424303d` - Fix Zebra RAW ZPL QR physical sizing.

## Windows Connector Release Record

Connector packages documented for the 2026.5.23 release:

- `MSCQR-Connector-Windows-2026.5.23.exe`
- `MSCQR-Connector-Windows-2026.5.23.zip`

The connector release manifest advertises `2026.5.23` as the latest version. The connector smoke check confirms the source version, manifest version, installer filename, and artifact readability.

No new connector release was created as part of this documentation work.

## Code Signing and Trust

The Windows connector executable is prepared for signed distribution through the controlled signing pipeline.

High-level signing flow:

1. Build the Windows connector payload.
2. Stage installer files.
3. Sign the staged executable artifacts.
4. Compile the Windows installer.
5. Sign the final installer artifact.
6. Verify signatures.
7. Publish the signed connector metadata and artifact.

Client-facing placeholders:

- [Azure signing profile]
- [Certificate provider]
- [Signing verification screenshot]

Do not place signing credentials, certificate private material, tenant details, or cloud account identifiers in client evidence.

## Zebra RAW ZPL Printing Summary

Zebra RAW ZPL is the preferred production path for Zebra label printers when MSCQR needs exact control over QR size, position, and printer commands.

The connector sends approved ZPL directly to the Windows RAW printer path. This avoids browser rendering and raster conversion for the Zebra path.

Operator diagnostics should confirm:

- Connector installed and reachable.
- Zebra printer detected.
- Correct printer selected.
- Zebra RAW ZPL profile selected.
- Diagnostic label prints.
- Real MSCQR label prints.
- Printed QR scans from a phone.

## QR Physical Sizing Implementation

The QR sizing work was centralized in:

- `backend/src/printing/zebraQrSizing.ts`

Implemented utility behavior:

- `mmToDots(mm, dpi)`
- `calculateQrMagnificationForTargetMm({ targetMm, dpi, qrModuleCount? })`
- `getZebraQrConfig({ targetMm = 25, dpi = 300 })`

Sizing defaults and limits:

- Default target: 25 mm.
- Optional target: 28 mm through configuration.
- Default DPI: 300.
- Supported DPI values: 203, 300, 600.
- Target mm clamp: 15 through 35.
- Zebra magnification clamp: the supported Zebra-safe range.
- QR module count is data-aware through the existing `qrcode` dependency.

The ZPL renderer now computes:

```zpl
^BQN,2,<magnification>
```

from the real QR payload's module count instead of from label width.

This prevents long signed MSCQR verification payloads from creating oversized QR blocks.

## Representative QR Sizing Result

For a representative long MSCQR verification payload:

- Target: 25 mm.
- DPI: 300.
- Target dots: about 295.
- QR module count: 69.
- Selected magnification: 4.
- Estimated printed size: 276 dots.
- Estimated physical size: about 23.37 mm.

Why not exact 25 mm: Zebra QR magnification is an integer, so physical QR size changes in steps. With 69 modules:

- Magnification 4 gives about 23.37 mm.
- Magnification 5 would be about 29.21 mm.

The selected value is the closest safe result for the real payload.

Do not include real signed QR payloads in docs or screenshots.

## Changed Files

- `backend/src/printing/zebraQrSizing.ts` - Central source of truth for Zebra QR target size, DPI, module-count estimation, and magnification.
- `backend/src/printing/canonicalLabel.ts` - Passes the desired QR target size into the canonical label block.
- `backend/src/printing/renderers/index.ts` - Uses the centralized Zebra QR sizing logic when rendering ZPL.
- `backend/src/services/printPayloadService.ts` - Wires printer calibration and diagnostic ZPL through the same QR sizing path.
- `backend/src/local-print-agent/state.ts` - Persists the optional QR target size in local connector calibration state.
- `src/features/batches/useBatchPrintWorkflow.ts` - Sends the QR target size as part of the print calibration payload.
- `src/features/batches/batchPrintWorkflowHelpers.ts` - Holds extracted batch print calibration helper logic to keep the feature hook under the code-size budget.
- `backend/tests/zebraQrSizing.test.js` - Covers QR sizing math, defaults, clamps, and magnification behavior.
- `backend/tests/printPayloadService.test.js` - Confirms production and diagnostic ZPL use centralized QR sizing.
- `backend/package.json` - Includes the Zebra QR sizing test in the backend test sequence.

## Validation Commands Used

The following commands were used during validation:

```sh
git status --short
grep -RIn "\^BQN\|BQN\|Diagnostic Zebra RAW ZPL\|ZPL" backend src shared scripts --exclude-dir=node_modules
npm --prefix backend run connector:smoke
npm --prefix backend test -- --runInBand
npm --prefix backend run build
npm run typecheck
npm run build
git diff --check
docker compose --env-file .env --env-file backend/.env config
docker compose --env-file .env --env-file backend/.env build --no-cache backend frontend
docker compose --env-file .env --env-file backend/.env up -d --force-recreate backend worker frontend
docker ps
curl http://localhost:4000/health/ready
```

Manual validation:

- Zebra RAW ZPL diagnostic print.
- Phone scan of printed diagnostic label.
- Real MSCQR label print.
- Phone scan of printed MSCQR QR label.

Evidence placeholders:

- [Backend tests screenshot]
- [Frontend build screenshot]
- [Deployment terminal proof screenshot]
- [Zebra printed QR photo]
- [Phone scan success screenshot]

## Deployment Record

Deployment was completed manually from Mac Terminal using Ansible after the GitHub workflow failed on command formatting.

Safe explanation:

- The workflow used a `docker ps --format` command with Go template braces such as `{{.Names}}`.
- Ansible interpreted those braces as Jinja template syntax.
- This was a workflow command formatting issue.
- It was not a product runtime issue and did not indicate a failed application build.
- Manual deployment avoided the template conflict.

Production update summary:

- All configured production regions were updated successfully.
- Mumbai, Cape Town, and London were updated.
- Private server addresses and hostnames are intentionally omitted.

Deployment checks:

- Compose config passed.
- Backend and frontend images rebuilt.
- Backend, worker, and frontend recreated.
- Backend readiness health check passed.
- Containers running after deployment.

## Follow-Up Recommendations

1. Fix the GitHub workflow command formatting by escaping or avoiding Go template braces inside Ansible-managed commands.
2. Add a workflow smoke step that checks connector release metadata after deployment.
3. Keep Zebra RAW ZPL as the production path for Zebra label printers.
4. Add a clean admin control for QR print size only where it helps operators, using labels such as "25 mm" and "28 mm" rather than internal setting names.
5. Keep collecting client evidence: printed QR photo, phone scan screenshot, and installer signature verification screenshot.
6. Add a short operator runbook for first-label validation before batch printing.

## Client-Safe Evidence Rules

Evidence shared with clients should not include:

- Credential material.
- Raw signed QR payloads.
- Private network addresses.
- Private server names.
- Cloud account identifiers.
- Internal access values.

Use screenshots that show success states without exposing sensitive details.
