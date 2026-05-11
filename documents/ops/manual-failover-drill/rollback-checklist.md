# Manual Failover Rollback Checklist

Last updated: 2026-05-11

## Scope

This checklist preserves evidence and returns MSCQR to the approved state when manual recovery validation fails or a drill ends. It does not automate DNS, prune Docker resources, remove MinIO, or destroy recovered data.

## Rollback Decision Gate

- [ ] Incident commander owns rollback decision.
- [ ] Rollback reason recorded.
- [ ] Current standby region recorded.
- [ ] Last successful validation step recorded.
- [ ] Whether writes occurred is recorded.
- [ ] Database reconciliation owner assigned if writes occurred.

## App Exposure Rollback

- [ ] Stop promoting the standby region.
- [ ] If a manual DNS change was made, record current DNS value.
- [ ] Restore previous DNS value only with explicit approval.
- [ ] Verify DNS propagation, if DNS was changed.
- [ ] If no DNS was changed, record "no DNS rollback required."

## Application Rollback

- [ ] Record current deployed commit.
- [ ] Redeploy known-good commit or `main` only through approved Ansible flow.
- [ ] Run `/healthz`.
- [ ] Run `/api/health/ready`.
- [ ] Capture Docker Compose status.
- [ ] Preserve backend, frontend, and worker logs.

## Database Rollback

- [ ] Preserve restored database instance/snapshot for investigation.
- [ ] Do not destroy recovered data.
- [ ] Record whether standby accepted writes.
- [ ] If writes occurred, escalate for reconciliation.
- [ ] Confirm primary database remains source of truth unless incident command approved otherwise.

## Object Storage Rollback

- [ ] Preserve object storage logs and evidence.
- [ ] Do not delete buckets, volumes, or MinIO data.
- [ ] If a test object was written, record its key and assigned cleanup owner.
- [ ] Do not clean up test objects until evidence retention requirements are met.

## Communications And Evidence

- [ ] Announce rollback decision to incident channel.
- [ ] Record rollback start and end time.
- [ ] Attach RTO/RPO worksheet.
- [ ] Attach command output summaries.
- [ ] Attach health check results.
- [ ] Attach blocker and follow-up owners.

## Post-Rollback Review

- [ ] Classify drill result: pass / partial / fail.
- [ ] Identify top three gaps.
- [ ] Assign owners and due dates.
- [ ] Schedule follow-up drill if needed.
