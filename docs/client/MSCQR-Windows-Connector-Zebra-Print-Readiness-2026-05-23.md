# MSCQR Windows Connector and Zebra QR Print Readiness Report

## Executive Summary

MSCQR now has a Windows Local Print Connector path ready for Zebra label printing with RAW ZPL support. This means a Windows workstation can receive approved print jobs from the MSCQR admin console and send Zebra-compatible label commands directly to the locally installed printer.

The latest connector version published in the release manifest is `2026.5.23`. The Zebra QR label path has also been updated so QR codes are sized for practical phone scanning on 300 DPI Zebra printers, with a default target of 25 mm square and optional support for 28 mm where label stock or scanning distance requires it.

This report is client-shareable. It avoids credential material, private infrastructure details, raw QR payloads, and internal-only deployment values.

## What Was Delivered

- A Windows connector package for local workstation printing.
- Zebra RAW ZPL printing support for label printers that need direct printer commands.
- Printer diagnostics so operators can confirm connector and printer readiness.
- A known-good Zebra diagnostic label path.
- Data-aware Zebra QR sizing for MSCQR labels.
- Validation evidence for builds, tests, connector metadata, and deployment checks.
- A simple acceptance checklist for client sign-off.

## Windows Connector Package

The MSCQR Windows Connector was packaged as:

- `MSCQR-Connector-Windows-2026.5.23.exe`
- `MSCQR-Connector-Windows-2026.5.23.zip`

The connector lets the browser-based MSCQR admin console communicate with printers connected to the local Windows computer. In plain terms, it acts as the bridge between MSCQR in the browser and the printer installed on the workstation.

The connector supports:

- Local printer discovery.
- Printer setup checks.
- Diagnostic label printing.
- Zebra RAW ZPL label printing.
- Normal print workflows where supported by the selected printer and setup.

The MSCQR connector release manifest points admins and operators to the latest available connector version. The latest version in the manifest is `2026.5.23`.

## Code Signing and Trust

The Windows connector executable is prepared for signed distribution through the MSCQR signing pipeline.

Code signing improves installation trust because Windows can identify that the installer is an expected MSCQR connector package from a known publisher. This helps reduce Windows security friction during installation and makes it easier for client IT teams to validate the installer before rollout.

The signing pipeline uses a controlled signing process with:

- [Azure signing profile]
- [Certificate provider]
- [Signing verification screenshot]

No signing keys, signing credentials, certificate private material, or cloud account details are included in this report.

Client verification steps:

1. Confirm the installer filename is `MSCQR-Connector-Windows-2026.5.23.exe`.
2. Confirm the installer is obtained from the official MSCQR connector download page or approved client delivery channel.
3. Check Windows file properties and confirm the publisher/signature shown matches the expected MSCQR publisher information.
4. Compare the installer version shown in MSCQR with the version installed on the workstation.
5. Keep a screenshot of the signature check for project evidence: [Signing verification screenshot].

## Printer Compatibility

MSCQR supports printer workflows through the configured print path. For Zebra label printers, the preferred production path is Zebra RAW ZPL when exact label commands are required.

Zebra RAW ZPL means MSCQR sends Zebra printer language commands directly to the printer through the Windows connector. This is used when we need reliable control over QR placement, QR size, label dimensions, and print behavior.

Where applicable, MSCQR also supports normal browser or operating-system supported printing flows. Those flows are useful for general printers, but Zebra label production should use the compatible Zebra RAW ZPL profile when exact label output matters.

Printer setup and diagnostics should confirm:

- The connector is installed.
- The connector is running.
- The printer is detected.
- The correct print mode is selected.
- The diagnostic test label prints.
- The MSCQR QR label prints.
- The printed QR scans successfully from a phone.

## Zebra RAW ZPL QR Sizing

The Zebra QR sizing work centralizes the sizing logic in:

`backend/src/printing/zebraQrSizing.ts`

The ZPL renderer now computes:

```zpl
^BQN,2,<magnification>
```

from the actual QR payload module count instead of from the label width. This matters because long signed MSCQR verification URLs can require larger QR versions. If the system used only label width, the QR could become too large and less consistent for scanning.

The updated behavior:

- Default QR target is 25 mm.
- Default Zebra printer resolution is 300 DPI.
- Supported DPI values are 203, 300, and 600.
- Target size is safely limited to 15 mm through 35 mm.
- Zebra QR magnification is safely limited to the supported Zebra range.
- QR module count is data-aware using the existing QR library already present in the project.
- Long signed MSCQR URLs no longer create oversized QR blocks.

In simple terms: Zebra QR size changes in steps because Zebra uses an integer magnification value. MSCQR now checks the real QR content, estimates the QR module count, and chooses the closest safe magnification for that exact payload.

Because of Zebra's stepped sizing, the printed QR may be slightly under or over the requested physical size. The system chooses the nearest safe option that keeps the QR scannable and avoids excessive size.

Representative sizing result:

- 25 mm at 300 DPI is approximately 295 dots.
- 28 mm at 300 DPI is approximately 331 dots.
- A sample long signed MSCQR URL used magnification `4`.
- The estimated QR size for that sample was around 23.37 mm.

No real signed QR URL payloads are included in this report.

Evidence placeholders:

- [Sample QR test image]
- [Real production QR scan proof]

## Recommended Zebra Setup

Recommended Zebra profile:

- Print mode: Zebra RAW ZPL.
- Printer resolution: 300 DPI by default.
- QR print size: 25 mm by default.
- Optional QR print size: 28 mm where label stock, print quality, or scanning distance requires a larger QR.
- Label stock: match the saved MSCQR printer profile.
- Driver data type: RAW where Windows configuration exposes this setting.
- ZPL mode: enabled.
- Darkness and speed: set conservatively, then adjust only after test print and scan proof.

Recommended operator flow:

- Install the latest MSCQR Windows Connector.
- Open the MSCQR printer setup or connector download page.
- Confirm the connector is detected.
- Select the Zebra printer.
- Confirm the printer profile uses Zebra RAW ZPL.
- Print the diagnostic label.
- Scan the diagnostic QR.
- Print one MSCQR label.
- Scan the MSCQR QR from a phone.
- Continue batch printing only after a successful scan.

## Validation Evidence

The following checks were used to validate the connector and Zebra print work. Evidence screenshots should be attached where available.

| Check | What it proved |
| --- | --- |
| `git status --short` | Confirmed the working tree state before and after changes. |
| `grep -RIn "\^BQN\|BQN\|Diagnostic Zebra RAW ZPL\|ZPL" backend src shared scripts --exclude-dir=node_modules` | Confirmed the project locations that generate or handle Zebra ZPL and QR commands. |
| `npm --prefix backend run connector:smoke` | Confirmed connector release metadata, source version, latest manifest version, installer filename, and artifact readability. |
| `npm --prefix backend test -- --runInBand` | Confirmed backend print, connector, QR sizing, and related service tests passed. |
| `npm --prefix backend run build` | Confirmed backend TypeScript build completed successfully. |
| `npm run typecheck` | Confirmed frontend TypeScript type checks passed. |
| `npm run build` | Confirmed frontend production build completed successfully. |
| `git diff --check` | Confirmed no whitespace or patch formatting issues. |
| `docker compose --env-file .env --env-file backend/.env config` | Confirmed the deployment compose configuration rendered successfully. |
| `docker compose --env-file .env --env-file backend/.env build --no-cache backend frontend` | Confirmed backend and frontend images could be rebuilt from the current code. |
| `docker compose --env-file .env --env-file backend/.env up -d --force-recreate backend worker frontend` | Confirmed backend, worker, and frontend services were recreated during deployment. |
| `docker ps` | Confirmed expected containers were running after deployment. |
| `curl http://localhost:4000/health/ready` | Confirmed backend readiness health check passed. |
| Manual Zebra RAW ZPL diagnostic print | Confirmed the printer accepted the known-good ZPL diagnostic label. |
| Manual QR scan from printed label | Confirmed the printed QR could be scanned successfully from a phone. |

Evidence placeholders:

- [Backend tests screenshot]
- [Frontend build screenshot]
- [Deployment terminal proof screenshot]
- [Zebra printed QR photo]
- [Phone scan success screenshot]

## Deployment Summary

Deployment was completed manually from Mac Terminal using Ansible after a GitHub workflow command formatting issue.

The workflow issue was caused by a `docker ps --format` command that used Go template braces such as `{{.Names}}`. Ansible interpreted those braces as Jinja template syntax. This was a workflow command formatting issue, not a product or runtime issue.

The manual deployment avoided the template conflict and updated all configured production regions successfully.

Production servers were reset to include:

- `c81583a` - Refactor batch print workflow under size budget.
- `424303d` - Fix Zebra RAW ZPL QR physical sizing.

All configured production regions were updated successfully.

Deployment checks completed:

- Compose config passed.
- Backend and frontend were rebuilt.
- Backend, worker, and frontend were recreated.
- Backend health check passed.
- Containers were running after deployment.

Private server names, private network addresses, and internal access details are intentionally not included in this client-facing report.

## Client Acceptance Checklist

- [ ] Connector installer is available.
- [ ] Connector installs successfully on Windows.
- [ ] Printer appears in connector/admin console.
- [ ] Zebra RAW ZPL diagnostic label prints.
- [ ] QR code is approximately 25 mm or selected target size.
- [ ] QR scans from phone.
- [ ] Scan opens the expected MSCQR verification page.
- [ ] Batch print workflow produces scannable labels.

## Evidence Placeholders

Attach the following evidence before final client sign-off:

- [Signing verification screenshot]
- [Backend tests screenshot]
- [Frontend build screenshot]
- [Deployment terminal proof screenshot]
- [Sample QR test image]
- [Zebra printed QR photo]
- [Phone scan success screenshot]
- [Real production QR scan proof]

## Appendix: Technical Notes

The QR sizing logic is intentionally data-aware. A QR code contains a grid of modules, and the number of modules changes depending on payload length. Zebra ZPL then applies an integer magnification to each module. Because that magnification is an integer, the printed QR size changes in steps.

For example, a long MSCQR verification payload may require 69 modules. At magnification 4, the printed QR is about 276 dots. On a 300 DPI printer, that is about 23.37 mm. At magnification 5, the printed QR would be about 29.21 mm. The system chooses the closest safe result for the real payload, which keeps the QR scannable without making it too large.

The default target remains 25 mm, and 28 mm is available when a larger QR is operationally preferred.
