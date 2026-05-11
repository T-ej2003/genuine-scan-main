# Object Storage Rollback And Reconciliation

Last updated: 2026-05-11

## Preserve Objects

- Preserve objects written during recovery or drill.
- Preserve logs and object metadata evidence.
- Do not delete production objects during rollback.
- Do not delete buckets.
- Do not decommission MinIO.

## Compare Object References With DB Rows

- Identify database rows that reference objects created or read during recovery.
- Confirm every referenced object exists.
- Confirm object metadata matches expected owner/context.
- Record missing object references.
- Assign reconciliation owner before closing incident.

## Reconcile Missing Objects

- Determine whether missing object is a copy issue, upload issue, permission issue, or DB reference issue.
- Restore/copy only approved required objects.
- Do not bulk delete or overwrite objects.
- Preserve before/after evidence.

## Owner/Evidence Table

| Item | Owner | Evidence | Status |
| --- | --- | --- | --- |
| Object reference comparison |  |  |  |
| Missing object review |  |  |  |
| Test object cleanup decision |  |  |  |
| Final reconciliation approval |  |  |  |

## Do-Not-Do List

- Do not delete buckets.
- Do not delete production objects.
- Do not decommission MinIO.
- Do not hide missing-object evidence.
- Do not allow writes before database and storage gates are approved.
