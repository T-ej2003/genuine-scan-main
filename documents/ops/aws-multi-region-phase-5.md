# AWS Multi-Region Phase 5: Database Recovery Strategy

Last updated: 2026-05-31

## Summary

Phase 5 documents how MSCQR should recover database service for a selected standby region during a disaster recovery event. For the current roadmap, this maps to Phase A and is complete by operator evidence and approval.

Phase 5 does not implement active-active writes, database replication, automatic failover, Route 53 automation, or destructive cleanup.

## Goal

Define a safe, repeatable database recovery strategy that can be tested before any real DNS cutover. The recovery path must make clear which database endpoint a standby app is allowed to use, who approves write access, and how RTO/RPO evidence is captured.

## Current Status

- Phase 2 standby app servers are manually deployable and health-checkable.
- Phase 3 manual failover app drills were recorded.
- Phase 4 manual DNS cutover tabletop was recorded.
- Phase A DB recovery is complete by operator evidence and approval. Do not reopen it during Phase C.
- Phase B controlled Route 53 cutover is complete for Mumbai production.
- Phase C MinIO decommission / S3 proof is the active phase.
- Phase D automatic failover remains blocked until Phase C is complete.

## Why Phase 5 Exists

Application health alone does not prove disaster recovery. MSCQR must know whether a standby region can connect to an approved recovered database, whether the schema matches the deployed app commit, and how much data loss is expected from the chosen recovery point.

## Entry Criteria From Phase 4

- Target standby region selected: Mumbai or Cape Town.
- Standby app deploy and health checks pass.
- Manual DNS cutover process is documented.
- Manual DNS rollback process is documented.
- DNS will not move until database recovery, object storage, TLS, rollback, and write gate are approved.

## Database Recovery Strategy

Recommended current-stage approach:

1. Restore from an RDS/Aurora snapshot or approved backup into the selected standby region.
2. Validate network access from the selected standby app server.
3. Update the standby app environment using the approved secret process.
4. Restart the app through the existing deployment/Docker Compose process.
5. Run health checks and read-only smoke tests.
6. Approve writes only after incident-command, database, storage, and security gates pass.

This is not active-active. This is not automated failover. Only one recovered database should accept production writes unless a future approved architecture explicitly changes that rule.

## Decision Matrix

| Option | When to use | RTO/RPO impact | Risk | Current recommendation |
| --- | --- | --- | --- | --- |
| Restore from snapshot | Preferred controlled recovery path when a known snapshot is recent enough. | RTO depends on restore time; RPO equals snapshot age. | Data loss window may be larger than desired. | Recommended for current-stage drills. |
| Restore from latest backup | Use when automated backup is newer than manual snapshot. | RTO depends on restore time; RPO depends on backup recency. | Requires backup integrity and restore permissions. | Acceptable after backup verification. |
| Point app to approved recovered DB endpoint | Use after restore is complete and approved. | Fast app cutover after DB endpoint is ready. | Wrong endpoint can create data integrity risk. | Required final app step before write gate. |
| Future replication/global database | Later phase only after manual recovery is proven. | Lower potential RPO/RTO. | Higher complexity and split-brain risk. | Not part of Phase 5 implementation. |

## RTO/RPO Impact

- RTO includes outage confirmation, write freeze, backup selection, restore time, app env update, app restart, health checks, core journey validation, and approved DNS cutover if used.
- RPO is the time gap between the latest usable recovery point and the outage/write-freeze time.
- Phase 5 must record both measured restore duration and estimated data loss window.

## Manual Recovery Flow

1. Confirm primary database is unavailable or unsafe.
2. Freeze writes or enable maintenance mode if available.
3. Select target standby region.
4. Select latest approved recovery point.
5. Restore database to approved target.
6. Validate network and TLS connectivity from standby app server.
7. Update standby app env through approved secret process.
8. Restart app using existing deployment process.
9. Run `/healthz` and `/api/health/ready`.
10. Run read-only smoke tests.
11. Approve writes only after validation.
12. Preserve evidence and timestamps.

## Mumbai Recovery Flow

- Target region: `ap-south-1`.
- Restore or select approved recovered database endpoint for Mumbai.
- Confirm Mumbai app server can resolve and connect to the recovered endpoint.
- Confirm security groups/subnets allow only intended access.
- Update Mumbai standby app env using approved secret process.
- Run:
  - `scripts/health-check-regions.sh mumbai`
  - read-only smoke tests
- Keep writes frozen until write gate approval.

## Cape Town Recovery Flow

- Target region: `af-south-1`.
- Restore or select approved recovered database endpoint for Cape Town.
- Confirm Cape Town app server can resolve and connect to the recovered endpoint.
- Confirm security groups/subnets allow only intended access.
- Update Cape Town standby app env using approved secret process.
- Run:
  - `scripts/health-check-regions.sh capetown`
  - read-only smoke tests
- Keep writes frozen until write gate approval.

## App Environment Update After DB Recovery

- Use approved secret handling only.
- Do not paste database URLs or passwords into docs, tickets, Slack, or commits.
- Update only the selected standby region environment.
- Record the credential source name, not the secret value.
- Restart app through the existing Ansible/Docker Compose deployment process.

## Connectivity Validation

- Confirm DNS resolution for the recovered DB endpoint.
- Confirm network route from standby app server.
- Confirm security group ingress from the app server only.
- Confirm DB TLS/SSL requirements.
- Confirm backend ready endpoint reports database ready.
- Inspect backend logs for connection errors without exposing secrets.

## Migration/Schema Compatibility Check

- Record deployed app commit.
- Record restored DB schema/migration state.
- Confirm the restored DB is compatible with the deployed app.
- Do not run schema-changing migrations unless explicitly approved.
- Prefer read-only checks first.

## Read-Only Smoke Tests

- Backend ready endpoint.
- Login page load.
- Public verify entry load.
- Safe read-only QR verification lookup if approved.
- Admin read-only dashboard load with approved test account if available.

## Write Gate Approval

Writes may resume only after:

- Incident commander approval.
- Database operator approval.
- Storage operator approval.
- Security reviewer approval.
- App health checks pass.
- Core journeys pass.
- Rollback path is confirmed.

## Rollback And Reconciliation Notes

- Stop exposing standby if validation fails.
- Preserve restored DB for investigation.
- Do not delete recovered data immediately.
- Do not allow writes in both primary and recovered DB unless an explicit approved plan exists.
- If writes occurred, assign reconciliation owner before closing the incident.

## Completion Checklist

- [ ] Current DB inventory completed.
- [ ] Backup/snapshot checklist passed.
- [ ] Restore runbook tabletop completed.
- [ ] Restore drill completed in non-production or approved recovery target.
- [ ] Mumbai connectivity checklist completed.
- [ ] Cape Town connectivity checklist completed.
- [ ] RPO measurement recorded.
- [ ] Rollback/reconciliation owner identified.
- [ ] Write gate approval process documented.

## Explicit Exclusions

- No active-active writes.
- No automatic failover.
- No Route 53 automation.
- No destructive DB cleanup.
- No MinIO cleanup or deletion during Phase A database recovery.
- No database replication implementation in Phase 5.

## Future Phase Handoff

Phase C covers MinIO decommission / S3 proof after DB recovery and Mumbai controlled cutover are complete.
