# Database Restore Checklist

Last updated: 2026-05-11

## Scope

This checklist prepares and verifies manual database recovery for Phase 3. It does not implement active-active writes, database replication, or automatic failover.

## Pre-Restore Gates

- [ ] Incident commander approved database recovery drill scope.
- [ ] Target standby region selected: Mumbai / Cape Town.
- [ ] Source database identifier recorded.
- [ ] Latest usable backup/snapshot identified.
- [ ] Backup/snapshot timestamp recorded in the RTO/RPO template.
- [ ] Restore target region confirmed.
- [ ] Restore target network/security group access confirmed.
- [ ] Required secrets are available through approved secure channels.
- [ ] Write freeze or maintenance decision recorded.
- [ ] Split-brain write risk reviewed.

## Restore Procedure Checklist

- [ ] Start restore using the approved database console or approved CLI profile.
- [ ] Record restore start time.
- [ ] Monitor restore progress.
- [ ] Record restore completion time.
- [ ] Confirm restored database endpoint.
- [ ] Confirm database TLS/SSL requirements.
- [ ] Confirm application database user exists with intended privileges.
- [ ] Confirm no production secret values were pasted into notes or tickets.

## Connectivity Validation

- [ ] Connect from selected standby app server to restored database.
- [ ] Verify DNS/network path or private endpoint access.
- [ ] Verify connection string is stored through approved secret handling.
- [ ] Run read-only connectivity check.
- [ ] Confirm application can start against restored database in the selected standby region.

## Schema And Migration Validation

- [ ] Record deployed app commit.
- [ ] Confirm restored database schema version is compatible with deployed app commit.
- [ ] Check migration status using approved Prisma/database workflow.
- [ ] Do not run schema-changing migrations during the drill unless explicitly approved.
- [ ] Run read-only smoke checks before allowing writes.

## Write Re-Enable Gate

Writes may resume only after:

- [ ] Incident commander approval.
- [ ] Database restore validation passed.
- [ ] Object storage validation passed.
- [ ] App health checks passed.
- [ ] Core journeys passed.
- [ ] Rollback path is understood.

## Failure Handling

- [ ] Stop recovery attempt if restore integrity is uncertain.
- [ ] Preserve restored database for investigation.
- [ ] Do not destroy recovered data.
- [ ] Escalate for reconciliation if any writes occurred.
- [ ] Record blocker, owner, and next action in the RTO/RPO template.
