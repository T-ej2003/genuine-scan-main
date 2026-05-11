# Database Rollback And Reconciliation

Last updated: 2026-05-11

## When To Roll Back

- Restored database fails integrity checks.
- App cannot connect to recovered database.
- Schema is incompatible with deployed app.
- Read-only smoke tests fail.
- Object storage verification fails.
- Security reviewer rejects the recovery posture.
- Incident commander decides London or another path is safer.

## Stop Exposing Standby Safely

- Stop promoting the standby region.
- Keep write freeze active.
- If DNS was changed, follow the manual DNS rollback checklist.
- Preserve app, database, and object storage logs.

## Preserve Restored DB

- Do not delete recovered DB immediately.
- Do not wipe data.
- Do not drop schemas or tables.
- Keep snapshots and restore identifiers for evidence.
- Restrict access if the restored database is no longer serving traffic.

## Avoid Split-Brain Writes

- Do not allow writes in both primary and recovered DB without an explicit approved plan.
- Record the exact time writes were enabled or disabled.
- Assign a reconciliation owner if any writes occurred.
- Keep all write logs and audit trails.

## Compare Primary And Recovered Data

- Identify tables or records touched during the recovery window.
- Compare audit logs and write timestamps.
- Confirm QR verification and print workflow consistency.
- Record any missing or divergent records.
- Approve reconciliation steps before changing data.

## Evidence To Preserve

| Evidence | Owner | Location |
| --- | --- | --- |
| Restored DB identifier |  |  |
| Snapshot/backup identifier |  |  |
| Write-freeze time |  |  |
| Write-enable time, if any |  |  |
| App commit |  |  |
| Health check output |  |  |
| Reconciliation notes |  |  |

## What Not To Do

- Do not delete recovered DB immediately.
- Do not wipe data.
- Do not allow writes in both places without explicit approved plan.
- Do not hide failed restore evidence.
- Do not paste secrets into the incident record.
