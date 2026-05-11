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

## Read-Only Smoke Test Workflow

Before any apply workflow is considered, operators can run safe read-only smoke tests from GitHub Actions:

```text
GitHub repo -> Actions -> AWS DR Operations -> Run workflow
```

Available operations:

- `public-health`: checks `https://www.mscqr.com/healthz` and `https://www.mscqr.com/api/health/ready`.
- `dns-inventory`: captures read-only DNS inventory for `www.mscqr.com` or the selected hostname.
- `object-storage-readiness`: performs read-only S3 listing and optional `head-object` using OIDC role `AWS_DR_OBJECT_STORAGE_ROLE_ARN`.
- `db-readiness`: performs read-only RDS inventory and snapshot checks using the protected `dr-db-restore` environment.
- `generate-db-restore-plan`: creates a markdown restore plan artifact before any approved DB restore drill.

This workflow does not deploy, SSH, use real inventory, change DNS, restore databases, or write/delete objects. Use it before any apply workflow; do not use apply workflows for smoke tests.

Before a DB restore drill, run `db-readiness` first, then run `generate-db-restore-plan`, then get incident commander approval before using the DB restore operation in `AWS DR DB Apply`.

Approved DB restore requires an approved DB subnet group and, when appropriate, approved VPC security group IDs. The current London restore drill used these values from readiness output:

- DB subnet group: `rds-ec2-db-subnet-group-1`
- VPC security group: `sg-07db1a9130c6df8d5`

These are examples from the current drill. Re-validate them before production incident use.

## Region-Local DB Recovery Path

The Mumbai test proved that a private London RDS endpoint is not a valid standby target from `ap-south-1`. For real standby recovery, copy or restore the DB into the selected standby region first, then point only that standby app at the region-local endpoint.

Mumbai target region is `ap-south-1`; Cape Town target region is `af-south-1`; London/source is `eu-west-2`.

Run sequence:

1. `AWS DR Operations` -> `aws-topology-inventory`.
2. `AWS DR Operations` -> `generate-cross-region-snapshot-copy-plan`.
3. `AWS DR Snapshot Apply` -> `apply-cross-region-snapshot-copy-approved`.
4. `AWS DR DB Apply` -> `apply-region-local-db-restore-approved`.
5. `AWS DR Operations` -> `target-region-db-readiness` until `available`.
6. `AWS DR Operations` -> `diagnose-standby-db-network`.
7. `AWS DR Standby DB Test` -> `test-standby-recovered-db`.
8. `AWS DR Standby DB Test` -> `rollback-standby-db-env` after evidence.
9. `AWS DR Cleanup Apply` -> cleanup only after explicit cleanup approval.

This sequence still does not change DNS, Route 53, London, primary DB, MinIO, or production object storage.

## Standby Recovered DB Connection Test

After a recovery DB is available, validate one standby app against it before any traffic movement is considered. Use only `mumbai` or `capetown`; do not target London, primary, `standby`, `standby_regions`, or all hosts.

GitHub workflow:

```text
GitHub repo -> Actions -> AWS DR Standby DB Test -> Run workflow
```

For the current Mumbai drill:

```text
operation: test-standby-recovered-db
target_region: mumbai
recovered_db_host: mscqr-dr-restore-test-20260511.c3ewey6o6mq5.eu-west-2.rds.amazonaws.com
recovered_db_port: 5432
recovered_db_name: postgres
recovered_db_user: postgres
confirmation: I_APPROVE_STANDBY_RECOVERED_DB_TEST
```

The workflow uses the protected `dr-standby-db-test` environment, reads `RECOVERED_DB_PASSWORD` from an Environment secret, backs up `/home/ubuntu/genuine-scan-main/backend/.env`, updates only the selected standby `DATABASE_URL`, restarts only that standby app stack, and runs `/healthz` plus `/api/health/ready`.

Rollback is required after a drill unless incident command explicitly keeps the standby pointed at the recovered DB:

```text
operation: rollback-standby-db-env
target_region: mumbai
backup_path_for_rollback: /home/ubuntu/genuine-scan-main/backend/.env.backup.dr-YYYYMMDDTHHMMSSZ
confirmation: I_APPROVE_STANDBY_DB_ENV_ROLLBACK
```

Record the env backup path, health check result, workflow artifact name, and timestamps in the RTO/RPO evidence. This test does not change DNS, Route 53, production DB, object storage, MinIO, or London.

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
