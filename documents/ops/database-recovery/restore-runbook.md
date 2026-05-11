# Database Restore Runbook

Last updated: 2026-05-11

This runbook is documentation only. It intentionally avoids destructive database commands.

## Preconditions

- Incident commander approved restore drill or recovery.
- Target region selected.
- Recovery point selected.
- Backup/snapshot is usable.
- Restore permissions verified.
- KMS/encryption access verified.
- Required secrets available through approved secure channel.
- Write freeze or maintenance-mode decision recorded.

## Restore Flow

1. Choose target region: Mumbai (`ap-south-1`) or Cape Town (`af-south-1`).
2. Choose recovery point: latest usable backup or approved snapshot.
3. Create or select restored DB in the target region through approved database tooling.
4. Record restore start time.
5. Record restore completion time.
6. Verify security groups and subnets.
7. Verify credentials source without exposing secrets.
8. Update selected standby app env using approved secret process.
9. Restart app using the existing deployment process.
10. Run health checks:
    - `scripts/health-check-regions.sh mumbai`
    - `scripts/health-check-regions.sh capetown`
11. Run read-only smoke tests.
12. Approve writes only after validation.

## App Restart

Use existing deployment and Docker Compose behavior. Do not change production deployment behavior from this runbook.

Preferred standby health validation after env update:

```bash
scripts/health-check-regions.sh standby
```

## Read-Only Smoke Tests

- Backend ready endpoint passes.
- Login page loads.
- Public verify entry loads.
- Safe read-only QR lookup passes if approved.
- Backend logs show no database connection errors.

## Rollback Plan

- Stop exposing standby if validation fails.
- Preserve restored DB for investigation.
- Restore previous app env through approved secret process if it was changed.
- Keep writes frozen until incident commander resolves next step.
- Do not destroy recovered data.

## Evidence Capture

| Evidence | Value/Link |
| --- | --- |
| Target region |  |
| Recovery point |  |
| Restore start time |  |
| Restore end time |  |
| Restored endpoint identifier |  |
| App commit |  |
| Health check result |  |
| Read-only smoke result |  |
| Write gate approver |  |
