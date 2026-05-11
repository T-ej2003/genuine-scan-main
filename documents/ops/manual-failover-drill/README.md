# MSCQR Manual Failover Drill Pack

Last updated: 2026-05-11

## Purpose

This pack gives operators a repeatable paper trail for Phase 3 manual failover readiness. It is documentation only. It does not implement DNS automation, automatic failover, active-active database writes, or MinIO cleanup.

Use it to prove whether MSCQR can recover through Mumbai or Cape Town with a measured RTO and RPO when London is unavailable.

## Drill Artifacts

- [Command sheet](command-sheet.md): safe operator commands for deploy, health checks, logs, and evidence capture.
- [RTO/RPO template](rto-rpo-template.md): timestamp and measurement worksheet.
- [Database restore checklist](database-restore-checklist.md): database recovery gates before writes resume.
- [Object storage checklist](object-storage-checklist.md): read/write verification gates without decommissioning MinIO.
- [Rollback checklist](rollback-checklist.md): recovery rollback and evidence-preservation checklist.

## Drill Scope

Included:

- Select one standby target: Mumbai or Cape Town.
- Confirm standby deployment readiness.
- Confirm backup and restore procedure.
- Confirm object storage access.
- Run health checks.
- Record RTO/RPO evidence.
- Capture gaps and follow-up tasks.

Excluded:

- No automatic failover.
- No Route 53 failover routing.
- No DNS automation.
- No active-active writes.
- No public DNS/certbot setup for Mumbai or Cape Town.
- No Docker prune/remove cleanup.
- No MinIO cleanup, deletion, migration, or decommission.

## Drill Roles

| Role | Name | Responsibility |
| --- | --- | --- |
| Incident commander |  | Approves drill start, recovery gates, and rollback. |
| App operator |  | Runs Ansible/Docker Compose commands and captures service evidence. |
| Database operator |  | Verifies backup, restore target, connectivity, and schema compatibility. |
| Storage operator |  | Verifies bucket/endpoint access and object read/write gates. |
| Security/Compliance reviewer |  | Confirms secrets handling and evidence retention. |
| Communications owner |  | Records timeline, status updates, and customer/internal messages. |

## Standard Drill Flow

1. Pick target standby region.
2. Confirm inventory and SSH/Ansible access.
3. Deploy latest `main` to standby using the known-good deploy path.
4. Run standby health checks.
5. Select backup/snapshot candidate.
6. Validate database restore procedure in the approved target.
7. Verify object storage access.
8. Complete RTO/RPO worksheet.
9. Decide whether the drill passes, fails, or needs a follow-up drill.
10. Record findings and owners.

## Evidence To Attach

- Git commit deployed.
- Ansible command output summary.
- Docker Compose service status.
- `/healthz` and `/api/health/ready` results.
- Database snapshot/restore identifiers.
- Object storage access verification notes.
- RTO/RPO worksheet.
- Rollback notes, even if rollback was not needed.

## Safety Rules

- Use placeholders or approved secure channels for secrets.
- Do not paste secrets into docs, tickets, Slack, or commit history.
- Do not modify real DNS during a drill unless explicitly approved by incident command.
- Do not allow writes until database recovery and object storage gates are approved.
- Do not destroy recovered data during rollback.
