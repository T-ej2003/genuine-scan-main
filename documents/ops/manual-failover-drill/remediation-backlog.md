# Manual Failover Drill Remediation Backlog

This backlog tracks gaps found during the 11 May 2026 Mumbai and Cape Town manual failover drills.

## Drill Summary

- Mumbai app deploy: Passed
- Mumbai health checks: Passed
- Mumbai deployed commit: 6fa84f3
- Mumbai measured app-only RTO: 4 minutes 23 seconds

- Cape Town app deploy: Passed
- Cape Town health checks: Passed
- Cape Town deployed commit: 6fa84f3
- Cape Town measured app-only RTO: 3 minutes 55 seconds

## Mumbai Drill Gaps

- [ ] Database restore was not tested in this app-only drill.
- [ ] Object storage access was not independently verified beyond existing running MinIO/container health.
- [ ] Manual DNS cutover was not tested.
- [ ] Manual DNS rollback was not tested.
- [ ] Maintenance/write-freeze procedure was not tested.
- [ ] RPO cannot be confirmed until database backup/snapshot timing is verified.

## Cape Town Drill Gaps

- [ ] Database restore was not tested in this app-only drill.
- [ ] Object storage access was not independently verified beyond existing running MinIO/container health.
- [ ] Manual DNS cutover was not tested.
- [ ] Manual DNS rollback was not tested.
- [ ] Maintenance/write-freeze procedure was not tested.
- [ ] RPO cannot be confirmed until database backup/snapshot timing is verified.

## Shared Remediation Items Before Phase 4

- [ ] Confirm latest production database backup/snapshot schedule.
- [ ] Confirm database restore process for Mumbai.
- [ ] Confirm database restore process for Cape Town.
- [ ] Confirm whether standby apps should use restored regional DBs or an approved recovered DB endpoint.
- [ ] Confirm object storage access from Mumbai.
- [ ] Confirm object storage access from Cape Town.
- [ ] Confirm manual DNS cutover approval owner.
- [ ] Confirm manual DNS rollback steps.
- [ ] Confirm maintenance/write-freeze process.
- [ ] Define acceptable RTO target.
- [ ] Define acceptable RPO target.
- [ ] Add core journey verification to next drill.

## Notes

- Phase 3 remains manual failover readiness only.
- This drill proved standby app deployment and health checks.
- This drill did not prove database recovery.
- This drill did not prove object storage recovery.
- This drill did not implement DNS automation.
- No automatic failover is implemented.
- No Route 53 failover routing is implemented.
- No active-active database write setup is implemented.
- No MinIO cleanup or decommissioning is included.
