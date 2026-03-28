# Production DB Partition Cutover

This repo now supports a production-safe cutover for the hot event tables:

- `AuditLog`
- `TraceEvent`
- `Notification`
- `SecurityEventOutbox`

`QrScanLog` is handled with a strict hybrid path:

- live `QrScanLog` stays non-partitioned because `Incident.scanEventId` still references `QrScanLog.id`
- cold, incident-unlinked scan history moves into the partitioned `QrScanLogArchive`
- `QrScanLogReportingView` keeps historical reporting queries pointed at both live and archived scan history

## One-time prep

Run the Prisma migration first:

```bash
cd backend
npx prisma migrate deploy
npx prisma generate
```

## Preview SQL without touching the database

```bash
cd backend
npm run db:partitions:cutover -- --offline --tables AuditLog,TraceEvent,Notification,SecurityEventOutbox --historic-months 24 --future-months 3 --print-sql
```

If you omit `--offline`, the command tries to inspect the live database first and falls back to an offline SQL preview if the database is unreachable.

## Production cutover

Recommended order:

1. Put the app in a low-write maintenance window.
2. Stop the worker so background jobs do not create surprise backfill traffic.
3. Run the partition cutover.
4. Start the worker and app again.
5. Warm future partitions and archive scan logs.

Commands:

```bash
cd backend

# stop background processing first at the deploy layer
npm run db:partitions:cutover -- --execute --tables AuditLog,TraceEvent,Notification,SecurityEventOutbox --historic-months 24 --future-months 3 --delta-grace-hours 24
npm run db:partitions:ensure -- --historic-months 24 --future-months 3
npm run db:scan-archive:run -- --execute --refresh-rollups --older-than-days 180 --batch-size 5000 --max-batches 20
```

## Ongoing maintenance

The worker now performs recurring hot-table maintenance:

- pre-creates future monthly partitions for partitioned event tables
- keeps `QrScanLogArchive` and `QrScanLogReportingView` provisioned
- archives old scan-log rows in bounded batches when the archive is enabled

Useful manual commands:

```bash
cd backend
npm run db:partitions:ensure -- --future-months 6
npm run db:scan-archive:run -- --execute --older-than-days 180 --batch-size 5000 --max-batches 10
```

## Safety notes

- Do not run trace backfill jobs during the live cutover window.
- Keep the legacy tables after cutover until production validation is complete.
- The cutover script leaves `__legacy_*` tables in place intentionally for rollback and audit review.
