# MSCQR Zebra ZT410 DB-Backed Printing

## Validated Printer Setup

- Printer: Zebra ZT410-300dpi ZPL
- Printer OS/Firmware: Link-OS 6.2
- Transport validated: Wi-Fi
- Protocol validated: raw TCP socket
- Port: 9100
- Payload language: ZPL
- Validation result: a Windows workstation sent ZPL to TCP 9100, the printer physically printed QR labels, and a phone scan opened the MSCQR verification route.

The validation IP `10.45.144.9` was a hotspot test address only. It must not be hardcoded as a production default.

## Factory Network Requirements

- Reserve a static DHCP address for the printer.
- Allow workstation/server access to TCP 9100.
- Disable client isolation between the print workstation/server and the printer.
- Keep the printer on a reachable factory Wi-Fi or Ethernet network.
- Register production printers as MSCQR printer profiles instead of relying on environment fallbacks.

## Safe Print Lifecycle

MSCQR print adapters must never create QR identifiers. Only the backend/database may issue public verification codes.

The backend enforces this transition chain regardless of frontend behavior:

1. `codes_generated`
2. `print_acknowledged`
3. `physical_print_confirmed`
4. `sample_scan_verified`
5. `approval_pending`, only when high-value approval is required
6. `released`

Rules:

- Cannot print before database-backed QR codes exist.
- Cannot confirm physical print before printer acknowledgement.
- Cannot sample-scan before physical confirmation.
- Cannot release before required sample-scan proof.
- Cannot release high-value batches without a different authorized checker.
- Cannot rotate or mutate public QR identity after print, scan, release, or external exposure.
- Duplicate clicks must return existing state or a safe blocked reason, not duplicate audit noise.
- Reprints must go through explicit reissue/reprint workflow so duplicate attempts remain visible.

Batch lifecycle states are intentionally stricter than the printer socket result:

- `created` / `DRAFT`
- `codes_generated`
- `payload_generated`
- `sent_to_printer` / `PRINT_ACKNOWLEDGED`
- `operator_confirmed_printed` / `PRINT_CONFIRMED`
- `sample_scan_verified` / `SAMPLE_VERIFIED`
- `released`
- `failed`

## Production Operator Procedure

The manufacturer/admin frontend should stay a guided wizard:

```txt
Generate labels -> Print -> Confirm -> Scan sample -> Release
```

1. Create or select the garment batch in MSCQR.
2. Generate or allocate QR labels through the MSCQR backend. Public verification codes must start with `c_`; human-readable display serials are not authentication secrets.
3. Select a saved DB printer profile such as `Zebra ZT410-300dpi ZPL`, raw TCP, port `9100`.
4. Send the print job. MSCQR records socket success as sent/acknowledged only.
5. Confirm `Labels physically printed` only after checking the physical label output.
6. Scan one printed label in the admin print workflow, or follow the configured sample policy:
   - one per print job
   - one per roll
   - one per N labels
   - percentage with a minimum count
7. MSCQR accepts the sample only when the scanned public code belongs to that exact print job.
8. Release the batch for downstream garment handling only after print acknowledgement, physical confirmation, and required sample-scan proof are recorded.
9. Do not release or ship a batch from printer socket success alone.

Common blocked reasons are intentionally operator-friendly:

- `QR_CODES_REQUIRED`: Generate labels before printing or release.
- `PRINT_ACK_REQUIRED`: Print job has not been sent yet.
- `PHYSICAL_CONFIRMATION_REQUIRED`: Confirm physical printing before sample scan.
- `SAMPLE_SCAN_REQUIRED`: Scan one printed label before release.
- `APPROVAL_REQUIRED`: A second authorized checker must approve this high-value release.
- `BATCH_ALREADY_RELEASED`: The batch is already locked for supply-chain release.
- `QR_NOT_IN_PRINT_JOB`: The scanned sample QR belongs to a different print job or is unknown.

For high-value batches, MSCQR can require dual-operator maker-checker release approval:

- `BATCH_RELEASE_DUAL_APPROVAL_ENABLED=false` by default.
- `BATCH_RELEASE_DUAL_APPROVAL_QUANTITY_THRESHOLD=<count>` makes approval mandatory when the batch quantity is at or above the threshold.
- The requester cannot approve their own release request.
- An authorized checker must grant or reject the request:
  - platform admin for any batch, with an explicit audit reason
  - licensee/organization admin for their own brand workspace
  - manufacturer admin/checker linked to the owning manufacturer/brand scope
- Normal manufacturer operators cannot approve high-value release.
- The actor who confirmed physical print or submitted the sample scan cannot approve that same high-value release.
- Audit events are written for `batch_release_approval_requested`, `batch_release_approval_granted`, `batch_release_approval_rejected`, and `batch_released`.
- Rejection leaves the batch unreleased and visible for operator correction.

## Manufacturing Validation Evidence

Validation evidence remains backend/API-only for now. Do not add a Manufacturing Evidence frontend panel until it directly reduces operator mistakes or is needed for enterprise onboarding.

If needed by platform/admin support, the scoped endpoint can retrieve a safe report:

```bash
GET /api/qr/batches/<batchId>/validation-evidence
```

The default report excludes raw ZPL, secrets, stack traces, printer credentials, and developer internals.

## Printer Profiles

Production Zebra routes must be stored as DB printer profiles. Environment values such as `ZEBRA_PRINTER_HOST`, `ZEBRA_PRINTER_PORT`, `ZEBRA_PRINTER_TIMEOUT_MS`, and `ZEBRA_PRINTER_LANGUAGE` are development/runtime fallbacks only and must not be the source of production printer identity.

Recommended production profile:

- Name: `Zebra ZT410-300dpi ZPL`
- Connection type: `NETWORK_DIRECT`
- Transport: raw TCP
- Port: `9100`
- Language: `ZPL`
- Delivery mode: direct only when the network route is certified and operator confirmation/sample scan are enforced

Only platform, organization, or licensee admin roles should configure printer host/port. Manufacturer/operator users may use saved printers for assigned print jobs but must not change factory network endpoints.

## Legacy Public Code Rotation

Legacy predictable public codes are reported by brand, batch, and status when `QRCode.code` does not start with `c_`.

Rotation is intentionally conservative:

- Eligible: unprinted, unscanned, unredeemed, unexposed legacy rows with safe statuses such as `DORMANT`, `ACTIVE`, or `ALLOCATED`.
- Never rotate: rows with `printedAt`, `scannedAt`, scan count, `redeemedAt`, print-job linkage, signed-token issuance, customer-verifiable timestamps, scan logs, verification decisions, print audit events, external audit evidence, printed batches, or downloaded print packs.
- The old predictable value is retained only as `displayCode` when needed for operator display. Public lookup identity becomes a new high-entropy `c_...` code.

Platform admins can export the inventory from the dashboard or run:

```bash
npm --prefix backend run mscqr:legacy-report -- --csv --out /tmp/mscqr-legacy-public-code-report.csv
```

Scheduled risk reporting should use the shared scheduled job mode:

```bash
npm --prefix backend run mscqr:legacy-report -- --scheduled
```

The scheduled command writes JSON and CSV artifacts locally under `backend/uploads/legacy-qr-risk-reports` unless `LEGACY_QR_REPORT_OUTPUT_DIR` is set. If MSCQR object storage is configured with `OBJECT_STORAGE_BUCKET` and region credentials, the same JSON, CSV, and `latest.json` report are uploaded under `legacy-qr-risk-reports/` or `LEGACY_QR_REPORT_OBJECT_PREFIX`.

The backend worker can also run this daily when enabled:

```bash
LEGACY_QR_REPORT_SCHEDULER_ENABLED=true
LEGACY_QR_REPORT_SCHEDULER_HOUR_UTC=3
LEGACY_QR_REPORT_SCHEDULER_MINUTE_UTC=15
```

The report is read-only and includes `generatedAt`, total legacy rows, grouped brand/batch/status counts, obvious blocker reason counts, obvious protected rows, and potentially rotatable rows. When a previous `latest.json` report is available, the job logs an alert if `totalLegacyCodes` increases. The rotation endpoint still performs a per-code audit evidence check before changing any public code.

Never rotate a QR code after it has been printed, scanned, shipped/released, linked to a print job, downloaded in a pack, used in signed/customer verification, or referenced by external audit evidence.

## Zebra Manual Validation

Use a non-production environment and an existing assigned batch with allocated labels:

```bash
npm --prefix backend run mscqr:print-test -- --batch <batchId> --printer <printerId> --count 10
```

Add `--send` only when the Zebra printer is physically ready:

```bash
npm --prefix backend run mscqr:print-test -- --batch <batchId> --printer <printerId> --count 10 --send
```

The command refuses to invent labels locally. It prints only labels reserved through the MSCQR backend print-job transaction.

## Release Readiness Integration Test

The Postgres-backed P2 release readiness test applies the real Prisma schema/migrations to a disposable database and validates:

- organization, brand, manufacturer, operator, and Zebra printer profile fixtures
- DB-backed QR label generation
- print job send/acknowledgement without a real printer
- physical print confirmation
- exact print-job sample scan proof
- batch release and audit evidence
- public-code rotation blocked after release
- wrong-job sample scan rejection
- `/verify/:code` exact lookup for released and unknown codes

Start the local disposable Postgres service, then run:

```bash
npm run test:p2:db:up
npm run test:p2:release-readiness
```

The harness refuses production-looking database URLs. Use either `P2_TEST_DATABASE_ADMIN_URL` for disposable database creation or `P2_TEST_DATABASE_URL` pointing at a database whose name clearly contains `test`, `p2`, `ci`, `tmp`, or `temporary`.

CI runs this in `.github/workflows/auth-security-tests.yml` against a GitHub Actions Postgres service using only `mscqr_p2_ci_*_test` database names. The P2 harness also refuses production-looking providers and non-local hosts unless explicitly allowed for a test environment.

## Lint Debt Ratchet

The repository still has existing lint debt. Do not attempt a repo-wide cleanup inside Zebra/QR hardening work. Use:

```bash
npm run lint:hardening
npm run lint:ratchet
```

`lint:hardening` checks the backend services and scripts touched by this hardening lane. `lint:ratchet` compares full-repo ESLint errors and warnings against `.security/lint-debt-baseline.json` and fails only if debt increases.

After an intentional cleanup, lower the baseline with:

```bash
npm run lint:baseline
```

Never raise the baseline to hide new issues.
