# AWS Multi-Region Phase 3: Manual Failover Readiness and Recovery Runbook

Last updated: 2026-05-11

## Summary

Phase 2 made Mumbai and Cape Town standby app servers manually deployable and health-checkable. Phase 3 proves manual failover readiness without implementing automatic failover.

The key question for Phase 3 is: if London dies, can MSCQR manually recover service through Mumbai or Cape Town with a known RTO and RPO?

Use the drill pack for execution evidence and operator checklists:

- [Manual failover drill pack](manual-failover-drill/README.md)
- [Command sheet](manual-failover-drill/command-sheet.md)
- [RTO/RPO template](manual-failover-drill/rto-rpo-template.md)
- [Database restore checklist](manual-failover-drill/database-restore-checklist.md)
- [Object storage checklist](manual-failover-drill/object-storage-checklist.md)
- [Rollback checklist](manual-failover-drill/rollback-checklist.md)

## Preconditions

- Standby app servers are deployed and healthy.
- Backups are verified.
- Database restore process is documented.
- Object storage access is verified.
- Operator has SSH and Ansible access.
- Required secrets are available through approved secure channels.
- Health check endpoints are known.
- Rollback owner is identified.

## Manual Failover Runbook Draft

1. Confirm primary outage.
2. Announce incident and assign operator.
3. Freeze writes or enable maintenance mode if available.
4. Capture latest backup/snapshot state.
5. Restore database to selected standby region or point standby to approved recovered database.
6. Verify object storage access.
7. Update selected standby region app environment using approved secrets.
8. Restart app using Ansible/Docker Compose.
9. Run health checks:
   - `/healthz`
   - `/api/health/ready`
10. Verify core user journeys.
11. Manually update DNS only if explicitly approved.
12. Monitor logs, metrics, and error rates.
13. Roll back if recovery validation fails.

## RTO/RPO Measurement Checklist

- Incident start time.
- Outage confirmation time.
- Backup/snapshot selected.
- Restore start time.
- Restore end time.
- App restart time.
- Health check pass time.
- DNS change time, if used.
- User journey verification time.
- Estimated data loss window.
- Final measured RTO.
- Final measured RPO.

## Database Backup/Restore Checklist

- Identify source database.
- Identify latest usable backup/snapshot.
- Verify restore target region.
- Restore database.
- Validate connectivity from standby app server.
- Verify migrations/schema compatibility.
- Run read-only smoke checks before allowing writes.

## Object Storage Verification Checklist

- Verify required bucket/object storage endpoint.
- Verify credentials through approved secret source.
- Verify app can read required assets.
- Verify upload/write behavior only after database recovery plan is approved.
- Do not decommission MinIO as part of Phase 3.

## Maintenance/Write-Freeze Notes

- Use the preferred maintenance mode if available.
- If maintenance mode is not available, use an operator-led write freeze.
- Document risk if writes cannot be frozen.
- Avoid split-brain writes.

## Manual DNS Update Procedure

This section is documentation only. Do not implement DNS automation in Phase 3. Do not add Route 53 failover routing.

1. Confirm approval before any DNS change.
2. Lower TTL in planned drills where appropriate.
3. Update DNS manually only after app and data checks pass.
4. Record the old DNS value for rollback.
5. Verify propagation.

## Rollback Procedure

- Stop or disable standby exposure if validation fails.
- Restore previous DNS value if changed.
- Keep logs and timestamps.
- Do not destroy recovered data.
- Escalate for database reconciliation if writes occurred.

## Quarterly Recovery Drill Checklist

- Pick target standby region.
- Verify inventory access.
- Verify backup restore path.
- Verify object storage access.
- Deploy latest `main`.
- Run health checks.
- Measure RTO/RPO.
- Record gaps and follow-up tasks.

## Explicit Exclusions

- No automatic failover.
- No Route 53 failover routing.
- No active-active writes.
- No MinIO decommission.
- No destructive Docker cleanup.
- No public DNS/certbot for Mumbai or Cape Town unless approved in a later phase.

## Future Phases

- Phase 4: [controlled manual DNS cutover](aws-multi-region-phase-4.md) only after manual failover is proven.
- Phase 5: [database recovery strategy](aws-multi-region-phase-5.md) before any real DNS cutover.
- Phase 6: [object storage DR hardening](aws-multi-region-phase-6.md), only after DB recovery is proven.

## Later Phases

- [Phase 4 controlled manual DNS cutover](aws-multi-region-phase-4.md)
- [Phase 5 database recovery strategy](aws-multi-region-phase-5.md)
- [Phase 6 object storage DR hardening](aws-multi-region-phase-6.md)
- [Final multi-region disaster recovery runbook](aws-multi-region-disaster-recovery-runbook.md)
