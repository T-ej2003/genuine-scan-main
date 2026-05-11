# AWS Multi-Region Disaster Recovery Runbook

Last updated: 2026-05-11

## Overview

This is the top-level MSCQR operator runbook for multi-region disaster recovery. It links the standby deployment, manual failover, controlled DNS cutover, database recovery, and object storage recovery documentation.

## Current Status By Phase

- Phase 2: standby servers ready and manually deployable.
- Phase 3: manual failover drill recorded.
- Phase 4: manual DNS cutover tabletop recorded.
- Phase 5: database recovery documentation added.
- Phase 6: object storage recovery documentation added.

## Phase Links

- [Phase 2 standby deployment](aws-multi-region-phase-2.md)
- [Phase 3 manual failover readiness](aws-multi-region-phase-3.md)
- [Phase 4 controlled manual DNS cutover](aws-multi-region-phase-4.md)
- [Phase 5 database recovery strategy](aws-multi-region-phase-5.md)
- [Phase 6 object storage DR hardening](aws-multi-region-phase-6.md)
- [Database recovery pack](database-recovery/README.md)
- [Object storage recovery pack](object-storage-recovery/README.md)
- [Manual failover drill pack](manual-failover-drill/README.md)

## Incident Severity Assumptions

Use this runbook for severe regional incidents where London cannot safely serve traffic or where incident command has approved a disaster recovery drill.

Do not use it for cosmetic UI issues, isolated support tickets, or short-lived alerts that clear before validation.

## Golden Rule

Do not move DNS until app, DB, object storage, TLS, rollback, and write gate are approved.

Do not run apply commands without incident commander approval.

## Operator Sequence

1. Confirm outage.
2. Assign roles.
3. Freeze writes or enable maintenance mode.
4. Select target region.
5. Deploy and verify standby app.
6. Restore or recover DB.
7. Verify DB connectivity.
8. Verify object storage.
9. Run core journeys.
10. Approve manual DNS cutover.
11. Monitor.
12. Roll back if needed.

## Commands

Run from the operator workstation:

```bash
cd /Users/abhiramteja/Downloads/genuine-scan-main
git pull origin main
scripts/deploy-standby.sh standby
scripts/health-check-regions.sh standby
scripts/health-check-regions.sh mumbai
scripts/health-check-regions.sh capetown
dig +short www.mscqr.com
dig +short mscqr.com
curl -fsS https://www.mscqr.com/healthz
curl -fsS https://www.mscqr.com/api/health/ready
```

These commands observe or deploy through the existing safe deployment path. They do not change DNS or delete data.

## DR Automation Commands

Use the operator-controlled automation guide for the full framework:

```text
documents/ops/aws-dr-automation.md
```

Safe local commands:

```bash
scripts/dr/dr-preflight.sh
scripts/dr/check-standby.sh standby
scripts/dr/deploy-standby.sh standby
scripts/dr/dns-inventory.sh www.mscqr.com
scripts/dr/public-health.sh
AWS_REGION=eu-west-2 DB_IDENTIFIER=mscqr-prod scripts/dr/db-readiness.sh
BUCKET=mscqr-prod-assets scripts/dr/object-storage-readiness.sh
```

Generate review artifacts without applying changes:

```bash
HOSTNAME=www.mscqr.com TARGET_VALUE=standby.example.com TTL=60 ACTION=UPSERT scripts/dr/generate-route53-change-batch.sh
HOSTNAME=www.mscqr.com ROLLBACK_VALUE=primary.example.com TTL=60 scripts/dr/generate-route53-rollback-batch.sh
SOURCE_DB_IDENTIFIER=mscqr-prod TARGET_REGION=ap-south-1 SNAPSHOT_IDENTIFIER=rds:mscqr-prod-2026-05-11 TARGET_DB_IDENTIFIER=mscqr-dr-recovery-20260511 scripts/dr/generate-db-restore-plan.sh
```

Approval-gated commands:

```bash
HOSTED_ZONE_ID=Zxxxxxxxx CHANGE_BATCH_FILE=artifacts/dr/<timestamp>/route53-change-batch.json CONFIRM_DNS_CUTOVER=I_APPROVE_MANUAL_DNS_CUTOVER scripts/dr/apply-route53-change.sh
HOSTED_ZONE_ID=Zxxxxxxxx ROLLBACK_BATCH_FILE=artifacts/dr/<timestamp>/route53-rollback-batch.json CONFIRM_DNS_ROLLBACK=I_APPROVE_MANUAL_DNS_ROLLBACK scripts/dr/apply-route53-rollback.sh
TARGET_REGION=ap-south-1 SNAPSHOT_IDENTIFIER=rds:mscqr-prod-2026-05-11 TARGET_DB_IDENTIFIER=mscqr-dr-recovery-20260511 CONFIRM_DB_RESTORE=I_APPROVE_DB_RESTORE_TO_RECOVERY_TARGET scripts/dr/apply-db-restore-approved.sh
BUCKET=mscqr-prod-assets CONFIRM_OBJECT_WRITE_TEST=I_APPROVE_OBJECT_STORAGE_WRITE_TEST scripts/dr/object-storage-write-test-approved.sh
```

Every DR script writes evidence under `artifacts/dr/<timestamp>/`. Those artifacts are intentionally ignored by Git.

## RTO/RPO Evidence Links

- [Manual failover RTO/RPO template](manual-failover-drill/rto-rpo-template.md)
- [Database RPO measurement template](database-recovery/rpo-measurement-template.md)
- [Manual DNS tabletop evidence](manual-dns-cutover/tabletop-drill-2026-05-11.md)

## Rollback Rules

- Roll back if health checks fail after cutover.
- Roll back if TLS is invalid.
- Roll back if DB recovery is rejected.
- Roll back if object storage read path fails.
- Roll back if core journeys fail.
- Preserve restored DB and object storage evidence.
- Do not destroy recovered data during rollback.

## What Not To Do

- Do not implement automatic failover.
- Do not run Route 53 apply automation without explicit incident commander approval.
- Do not implement health-check-driven DNS switching.
- Do not allow active-active writes.
- Do not wipe or destructively clean up databases.
- Do not delete buckets or production objects.
- Do not decommission MinIO.
- Do not paste secrets into evidence.
- Do not overwrite real `.env` files or `ops/deploy/inventory.ini`.

## Quarterly Drill Checklist

- [ ] Pick target standby region.
- [ ] Verify inventory and SSH/Ansible access.
- [ ] Deploy latest `main` to standby.
- [ ] Run health checks.
- [ ] Select database recovery point.
- [ ] Run database restore tabletop or approved restore drill.
- [ ] Verify object storage read path.
- [ ] Review manual DNS cutover checklist.
- [ ] Measure RTO/RPO.
- [ ] Record gaps and owners.

## Final Readiness Checklist

- [ ] Standby app deploy is repeatable.
- [ ] Standby health checks pass.
- [ ] Database recovery drill completed.
- [ ] DB connectivity from Mumbai verified.
- [ ] DB connectivity from Cape Town verified.
- [ ] Object storage read path from Mumbai verified.
- [ ] Object storage read path from Cape Town verified.
- [ ] Write gate approval path documented.
- [ ] TLS readiness confirmed.
- [ ] Manual DNS rollback path confirmed.
- [ ] RTO/RPO targets defined.
- [ ] Incident roles assigned.
