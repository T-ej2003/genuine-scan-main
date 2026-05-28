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
- Regional ALB test records: Mumbai and Cape Town are available through `dr-mumbai.mscqr.com` and `dr-capetown.mscqr.com`; production DNS is currently rolled back to London EC2 `13.135.108.69`.

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

## Regional HTTPS Entrypoint

Route 53 is authoritative for `mscqr.com`. The professional public HTTPS path for all regions is regional ALB plus ACM:

```text
Route 53 -> regional ALB HTTPS 443 with ACM -> EC2 frontend HTTP 80
```

This avoids copying Let's Encrypt private keys into standby containers. London currently still has working local TLS; Mumbai and Cape Town should receive public HTTPS through regional ALBs before any production DNS cutover is considered.

Use `AWS DR ALB Apply` for inventory, plan generation, and protected ALB/ACM apply. This workflow does not cut over `mscqr.com` or `www.mscqr.com`. DNS cutover remains in `AWS DR DNS Apply`.

Recommended Mumbai entrypoint sequence:

1. `AWS DR ALB Apply` -> `aws-regional-alb-inventory`.
2. `AWS DR ALB Apply` -> `generate-regional-alb-plan`.
3. `AWS DR ALB Apply` -> `apply-regional-alb-entrypoint-approved`.
4. `AWS DR ALB Apply` -> `generate-route53-regional-test-records` for `dr-mumbai.mscqr.com`.
5. Apply the test record only through `AWS DR DNS Apply` after approval.
6. Verify `https://dr-mumbai.mscqr.com/healthz`.
7. Generate the production ALB cutover plan.
8. Use `AWS DR DNS Apply` only after final incident commander approval.

ALB subnet selection is intentionally constrained to one subnet per Availability Zone and only chooses subnets whose effective route table has `0.0.0.0/0 -> igw-*`. `MapPublicIpOnLaunch=true` is only a tie-breaker inside the same AZ. The ALB apply script fails before `CreateLoadBalancer` if fewer than two distinct Availability Zones have public IGW-routed subnets, and it calls `set-subnets` when an existing ALB is attached to stale/private subnets. ACM validation CNAMEs are the only Route 53 records that ALB apply may UPSERT; production cutover JSON is generated separately for later approval.

The raw `*.elb.amazonaws.com` ALB hostname is not on the MSCQR ACM certificate, so direct HTTPS checks against that hostname without `-k` are expected to fail certificate hostname verification. Use `curl --resolve www.mscqr.com:443:<ALB_IP> https://www.mscqr.com/healthz` or a regional alias with matching certificate coverage for cert-valid smoke tests.

## Scaling And Observability Readiness

Before final DNS cutover, run `AWS DR Regional Readiness` for Mumbai and Cape Town. This workflow is read/plan-only and does not change DNS, enable access logs, attach WAF, create ASGs, mutate RDS/S3, or delete resources.

Current app scaling gate: ASG_STATUS=CONDITIONALLY_READY. Review `documents/ops/aws-asg-multi-instance-readiness.md`, `documents/ops/aws-asg-rolling-deploy-policy.md`, and run `node scripts/dr/check-asg-multi-instance-readiness.mjs` before any ASG create/attach discussion.

Phases before final cutover:

1. Current stable state: London EC2 remains production DNS.
2. Test-record validation: `dr-mumbai.mscqr.com` and `dr-capetown.mscqr.com` pass HTTPS health checks.
3. Scaling readiness: capacity inventory and ASG/launch-template plan artifacts exist for both regions.
4. Observability readiness: CloudWatch alarm plan, ALB access log plan, and WAF plan artifacts exist for both regions.
5. Final production DNS cutover: use only the protected DNS workflow after incident commander approval.
6. Rollback: restore London ALB or London EC2 DNS rollback JSON if validation fails.

Recommended operations per region:

1. `verify-regional-alb-health`.
2. `regional-capacity-inventory`.
3. `generate-regional-cloudwatch-alarm-plan`.
4. `generate-alb-access-log-plan`.
5. `generate-waf-plan`.
6. `generate-asg-launch-template-plan`.

## Staged Hardening Apply

Use `AWS DR Hardening Apply` only after readiness artifacts are reviewed. It is protected by `dr-hardening-apply` and exact confirmation tokens.

Apply order:

1. `verify-hardening-state` baseline.
2. `apply-cloudwatch-alarms`.
3. `apply-alb-access-logs`.
4. `apply-waf-count-mode`.
5. `verify-hardening-state`.
6. `generate-asg-apply-plan`.
7. `apply-asg-launch-template-approved` only after app state risks are resolved, `ASG_WEB_INSTANCE_PROFILE_ARN` or `ASG_WEB_INSTANCE_PROFILE_NAME` is explicitly supplied, `ASG_ASSOCIATE_PUBLIC_IP` is intentionally set for the selected subnet design, `ASG_KEY_NAME` is supplied for debug retries, `ASG_REPO_URL`/`ASG_REPO_BRANCH`/`ASG_REPO_DIR` identify the checkout to clone or refresh, and the rollout is treated as a no-production-DNS validation drill.

Hardening does not perform production DNS cutover, delete AWS resources, mutate RDS, mutate application S3 buckets, copy Let's Encrypt keys, or move WAF rules to BLOCK mode. WAF remains COUNT mode only in this phase.

ASG apply is intentionally last because current single-node assumptions may include node-local Redis, MinIO, secrets, sessions, migrations, worker behavior, and filesystem state. ASG_STATUS=CONDITIONALLY_READY means the repo-side blockers are closed, but the first live create/attach plus replacement-instance drill still needs evidence. The launch template must include explicit ASG web instance profile input, deterministic UserData bootstrap, optional debug `ASG_KEY_NAME`, and the expected `ASG_ASSOCIATE_PUBLIC_IP` networking shape. For Mumbai's first retry, use `ASG_ASSOCIATE_PUBLIC_IP=true` because the selected public subnets have `MapPublicIpOnLaunch=false`, and use `ASG_KEY_NAME=mscqr-prod-mumbai` so failed nodes can be inspected. Because the selected AMI is not app-baked, UserData must also install/check Git, Docker, Docker Compose, AWS CLI, Node.js 24, and npm 11, then clone or refresh the repo through `ASG_REPO_URL`, `ASG_REPO_BRANCH`, and `ASG_REPO_DIR`. Docker Compose installation must not depend solely on apt: the latest Mumbai no-DNS failure proved Docker could install and start while `docker-compose-plugin` was unavailable and `docker compose` failed with `docker: unknown command: docker compose`; UserData now falls back to a pinned Compose v2 CLI plugin under `/usr/local/lib/docker/cli-plugins/docker-compose`. The next retry moved past Compose and failed while running `scripts/dr/bootstrap-asg-web-node.sh`, so UserData now checks AWS CLI through apt plus official AWS CLI v2 fallback and mirrors bootstrap output to cloud-init console while preserving the exit code. The latest retry reached repo HEAD `c97edfe` and failed with `ERROR: node is required`, so UserData now installs/verifies Node.js 24/npm 11 before invoking the bootstrap script. The following retry reached SSM env render and failed because `SMTP_FROM` was treated as required; source review confirmed `SMTP_FROM` is optional for boot and the backend falls back to `SMTP_USER` as the From address when it is absent. The next retry reached Compose interpolation and failed because `QR_SIGN_PRIVATE_KEY` was in `backend/.env` but not in Compose's interpolation environment. The fix writes project `.env` as a persistent root/backend union for later diagnostics and adds a temporary root/backend union env file passed with `docker compose --env-file`, while preserving `backend/.env` for the backend container. The next retry started the backend but deadlocked frontend startup on backend deep readiness; the fix now uses backend `/health/live` for container health. The latest retry proved backend and frontend containers start and the node reaches `/healthz` plus `/api/health/ready` waits; bootstrap now treats `/healthz` as the hard edge-liveness gate and records degraded `/api/health/ready` as `CONDITIONALLY_READY` dependency evidence with no-secret diagnostics. The preferred production design is private ASG subnets with NAT Gateway or VPC endpoints, then `ASG_ASSOCIATE_PUBLIC_IP=false`. Do not use final production DNS cutover until at least the selected region has healthy multi-target evidence and a reviewed rollback plan.

Mumbai no-DNS ASG debug retry inputs:

Latest failure evidence: ASG instances launched with public IP, `KeyName`, and instance profile; `git` was already installed; Docker installed and the service was active; apt did not provide `docker-compose-plugin`; Compose was missing, so the repo was not cloned and app containers never started; ALB target health failed; later SSH saw `PublicIp=None` after ASG replacement; the original Mumbai EC2 remained healthy; no DNS cutover happened.

Latest retry evidence: Docker Compose fallback succeeded, verification reached, and the failure moved to `running bootstrap script` after confirming `scripts/dr/bootstrap-asg-web-node.sh` exists. Treat missing AWS CLI or hidden bootstrap output as the likely cause until the next console log proves otherwise; the repo fix adds AWS CLI prerequisite handling and tees bootstrap output to cloud-init console without printing SSM values or env files.

Latest Node prerequisite evidence: AWS CLI installed from apt and verified, repo clone succeeded to HEAD `c97edfe`, then bootstrap failed with `ERROR: node is required.` The repo fix adds `node --version` and `npm --version` checks, installs Node.js from pinned NodeSource major 24 when needed, and keeps the old/manual Mumbai target healthy while new ASG instances are retried.

Latest SSM env-render evidence: fresh ASG nodes reached `Fetching ASG web-node parameters from SSM path /mscqr/prod/ap-south-1/asg-web/ in ap-south-1...` and failed with `backendEnv missing required SSM parameter(s): SMTP_FROM`. The repo fix moves `SMTP_FROM` to optional/recommended ASG SSM configuration, documents `/mscqr/prod/ap-south-1/asg-web/SMTP_FROM` as the authorized sender override to create before email validation, and keeps true missing required SSM errors actionable with full parameter paths and no values.

Latest Compose interpolation evidence: fresh ASG nodes rendered 9 root env keys and 135 backend env keys, consumed 130 SSM parameter names, and then failed with `error while interpolating services.backend.environment.QR_SIGN_PRIVATE_KEY`. The names-only preflight showed `/mscqr/prod/ap-south-1/asg-web/QR_SIGN_PRIVATE_KEY` exists, so the repo-side issue was interpolation scope, not proof that the secret value was absent. The bootstrap now fails early for empty required values, writes project `.env` as a persistent Compose interpolation env, and passes a generated temp env file to Compose so QR signing keys are available without printing them.

Latest ASG health evidence: fresh ASG nodes got through Docker image builds, backend startup, backend container health, frontend/Nginx startup, and waits for `http://127.0.0.1/healthz` plus `http://127.0.0.1/api/health/ready`. Apply briefly reached `HEALTHY_TARGET_COUNT=2`, then later inspection showed ASG and ALB health disagreeing or flapping. The repo fix keeps `/healthz` independent of backend dependencies and hard-fails only if edge liveness or host port 80 fails; degraded `/api/health/ready` now logs `CONDITIONALLY_READY` dependency evidence with no-secret diagnostics for listener state, HTTP status/timing, Nginx logs, Docker health output, direct backend probes, and sanitized database/Redis/object-storage readiness.

Safe names-only SSM preflight before retry:

```bash
aws ssm describe-parameters \
  --region ap-south-1 \
  --parameter-filters "Key=Path,Option=Recursive,Values=/mscqr/prod/ap-south-1/asg-web/" \
  --query 'Parameters[].Name' \
  --output text | tr '\t' '\n' | sort
```

Local no-secret Compose interpolation preflight before retry:

```bash
node scripts/dr/check-asg-compose-interpolation.mjs --docker-compose-config
```

```bash
TARGET_REGION_GROUP=mumbai
AWS_REGION=ap-south-1
SOURCE_INSTANCE_ID=i-04ae3b689ab72a68a
SOURCE_AMI=ami-07216ac99dc46a187
SOURCE_INSTANCE_TYPE=t3.medium
SOURCE_SECURITY_GROUP=sg-0771ea7e59f7a49d4
TARGET_GROUP_ARN=arn:aws:elasticloadbalancing:ap-south-1:368992683803:targetgroup/mscqr-mumbai-frontend-tg/68982ccd4d8c26c1
ASG_WEB_INSTANCE_PROFILE_ARN=arn:aws:iam::368992683803:instance-profile/mscqr-asg-web-instance-profile-aps1
ASG_ASSOCIATE_PUBLIC_IP=true
ASG_KEY_NAME=mscqr-prod-mumbai
ASG_REPO_URL=https://github.com/T-ej2003/genuine-scan-main.git
ASG_REPO_BRANCH=main
ASG_REPO_DIR=/home/ubuntu/genuine-scan-main
ROLLBACK_ALARM_NAMES_CSV=MSCQR-mumbai-ALB-5XX,MSCQR-mumbai-Target-5XX,MSCQR-mumbai-TargetResponseTime-p95,MSCQR-mumbai-UnhealthyHosts
MIN_SIZE=2
DESIRED_CAPACITY=2
MAX_SIZE=4
```

For apply only:

```bash
CONFIRM_ASG_APPLY=I_APPROVE_REGIONAL_ASG_CREATE_AND_ATTACH
```

If targets fail or ASG and ALB health disagree, collect read-only evidence first:

```bash
TARGET_REGION_GROUP=mumbai \
AWS_REGION=ap-south-1 \
ASG_NAME=mscqr-mumbai-dr-asg \
TARGET_GROUP_ARN=arn:aws:elasticloadbalancing:ap-south-1:368992683803:targetgroup/mscqr-mumbai-frontend-tg/68982ccd4d8c26c1 \
npm run ops:asg-health-evidence
```

Optional SSH deep inspection requires `ENABLE_ASG_SSH_DEEP_INSPECTION=I_APPROVE_READ_ONLY_SSH` and `ASG_SSH_KEY=/Users/abhiramteja/Desktop/keys/mscqr-prod-mumbai.pem`. Immediate rollback remains:

```bash
aws autoscaling update-auto-scaling-group --region ap-south-1 --auto-scaling-group-name mscqr-mumbai-dr-asg --min-size 0 --desired-capacity 0 --max-size 4
```

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

After rollback and evidence capture, use `AWS DR Cleanup Apply` only with incident commander approval to delete recovery test DB instances and copied manual DR snapshots. Cleanup must target only identifiers that clearly include DR/recovery/test markers, such as `mscqr-dr-mumbai-restore-test-20260511` or `mscqr-dr-mumbai-copy-20260511`.

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
- [ ] `documents/ops/aws-asg-multi-instance-readiness.md` is no longer `ASG_STATUS=BLOCKED` before any ASG create/attach.
- [ ] `node scripts/dr/check-asg-multi-instance-readiness.mjs` passes in the release branch.
