# Uncertain production print retirement

## Objective

Retire one acknowledged print item whose physical output cannot be established, without replaying its QR or discarding its history. The November 10 ZT410 job is the first intended use. Its physical outcome remains **UNKNOWN**.

## Existing mechanisms

`printing_control_job` owns job and item transitions; the connector journal reserves the attempted dispatch; `printing_connector_event` authenticates late receipts; printer claims stop when an earlier job needs operator action. Consumer verification classifies `BLOCKED` QR codes as blocked.

## Retirement contract

The verified cancellation package has manifest SHA-256 `d506fb1403ea5a1367e6d76eb1a580530cadaadb12e565ae5b55e1e06c93c421`: connector stopped, queue empty before and after, owner observed `ALL JOBS CLEARED`, Zebra paused with DATA off, and all four journals unchanged. Windows Codex subsequently moved the original per-user Startup entry to a preserved location; its SHA-256 is `d2c8f71b7e703865abb94c9353eef08c5a9e2f54deaeb9644a18f961c7dac459`, the unchanged target script hash is `9e1e3323079a75fdf1ea3057b5ea3bbc4cf190949ea3c0ebfd33d2ac363bf68c`, and the isolation evidence manifest hash is `62ea58f862458a7e18749188d760113bfdb6ee79a9750e648439f9bc278cf8a0`. The connector still has zero processes and listeners. These observations establish a current boundary, not the November 10 physical outcome.

A recently authenticated, tenant-bound print operator supplies a reason and that exact manifest hash to `POST /api/manufacturer/print-jobs/197d65b3-cbea-4ff4-8a2f-258e4dcf5493/retire-uncertain`. The route and SQL function are limited to this job, item `15ed142e-0e30-4270-8bd0-3bcc304875f0`, and evidence hash. The database transition also requires one `AGENT_ACKED` item in a paused job needing operator action, no print confirmation, and the QR still bound to that job. In one transaction it blocks the QR, cancels the item, stops the session and job, and appends `PrintAuditEvent` and `AuditLog` records. It never deletes the journal, unbinds the QR, or declares the historical label unprinted. Repeating the request with the same evidence hash is idempotent; a different hash or a late confirmation cannot reopen the retired item.

## Release and verification

Install the changed function, QR column grants and QR update policy through the existing exact predecessor-gated combined C02 package before activating backend/worker code that calls the operation. Verify the production catalogue, then retire the historical job and confirm the old QR is `BLOCKED`, the item is `CANCELLED`, the job is `STOPPED/STOPPED`, and audit records are present. Confirm the printer's maintenance checkpoint is `ACTIVE`; a separately fenced checkpoint requires a specifically reviewed recovery release, because the existing release only supports connector upgrades. Verify the current registration and RAW ZPL profile before one new manufacturer-dashboard print job. Keep the Windows Startup entry disabled until the coordinated connector restart; its preserved path is `C:\Users\karat\Documents\Codex\2026-11-15\mscqr-november-10-printer-blockage-windows\outputs\mscqr-nov10-readonly-evidence-20261115\startup-autostart-disabled-20261115\disabled-entry\MSCQR Connector.vbs`. A human must confirm the physical label and scan readability before success is reported.

## Limits

The evidence hash is an audit reference, not proof of the physical outcome. The printer must remain isolated until the historical identity is retired and the actual checkpoint and claim guards are verified. No automatic retry or old-QR reissue is allowed.
