# AWS DR Automation Framework

Last updated: 2026-05-11

This guide covers the MSCQR operator-controlled AWS multi-region DR automation framework. The rule is simple: automate evidence and reversible preparation; require explicit human approval for traffic movement, restore execution, and write tests.

## Automated

- Local DR readiness preflight.
- Standby health checks through the existing Ansible health path.
- Standby deployment wrapper through the existing deploy path.
- DNS inventory capture.
- Public production health checks.
- Route 53 change batch generation for review.
- Route 53 rollback batch generation for review.
- Read-only RDS inventory and snapshot readiness inspection.
- DB restore plan generation.
- Read-only AWS topology inventory for region-local DB recovery.
- Cross-region snapshot copy plan generation.
- Target-region DB readiness inspection.
- Standby-to-DB network diagnostics.
- Read-only regional ALB/ACM inventory.
- Regional ALB/ACM implementation plan generation.
- Route 53 ALB cutover and regional test-record change batch generation.
- Object storage read-path inspection.
- Evidence capture under `artifacts/dr/<timestamp>/`.
- CI validation and AWS DR safety scanning.

## Approval-Gated

- DNS cutover apply requires `CONFIRM_DNS_CUTOVER=I_APPROVE_MANUAL_DNS_CUTOVER`.
- DNS rollback apply requires `CONFIRM_DNS_ROLLBACK=I_APPROVE_MANUAL_DNS_ROLLBACK`.
- DB restore to a new recovery target requires `CONFIRM_DB_RESTORE=I_APPROVE_DB_RESTORE_TO_RECOVERY_TARGET`.
- Cross-region snapshot copy requires `CONFIRM_SNAPSHOT_COPY=I_APPROVE_CROSS_REGION_SNAPSHOT_COPY`.
- Region-local DB restore requires `CONFIRM_REGION_LOCAL_DB_RESTORE=I_APPROVE_REGION_LOCAL_DB_RESTORE`.
- Object storage write test requires `CONFIRM_OBJECT_WRITE_TEST=I_APPROVE_OBJECT_STORAGE_WRITE_TEST`.
- Optional deletion of the generated write-test object requires `CONFIRM_DELETE_TEST_OBJECT=I_APPROVE_DELETE_DR_TEST_OBJECT`.
- Recovery DB cleanup requires `CONFIRM_RECOVERY_DB_CLEANUP=I_APPROVE_RECOVERY_DB_CLEANUP` and either a final snapshot identifier or `CONFIRM_SKIP_FINAL_SNAPSHOT=I_APPROVE_SKIP_FINAL_SNAPSHOT`.
- Copied DR snapshot cleanup requires `CONFIRM_DR_SNAPSHOT_CLEANUP=I_APPROVE_DR_SNAPSHOT_CLEANUP`.
- Regional ALB/ACM entrypoint apply requires `CONFIRM_REGIONAL_ALB_APPLY=I_APPROVE_REGIONAL_ALB_ENTRYPOINT_APPLY`.

Do not run apply commands without incident commander approval.

## Local Preflight

```bash
scripts/dr/dr-preflight.sh
```

This checks branch, latest commit, working tree state, documents, guardrails, whitespace, and shell syntax. It does not deploy or touch AWS.

## Standby Health

```bash
scripts/dr/check-standby.sh standby
scripts/dr/check-standby.sh mumbai
scripts/dr/check-standby.sh capetown
```

## Standby Deploy

```bash
scripts/dr/deploy-standby.sh standby
```

This wraps `scripts/deploy-standby.sh` and runs the standby health check afterward. It does not perform destructive cleanup.

## DNS Inventory

```bash
scripts/dr/dns-inventory.sh www.mscqr.com
```

## Public Health

```bash
scripts/dr/public-health.sh
```

## Route 53 Cutover Batch

```bash
HOSTNAME=www.mscqr.com \
TARGET_VALUE=standby.example.com \
TTL=60 \
ACTION=UPSERT \
scripts/dr/generate-route53-change-batch.sh
```

Review the generated `artifacts/dr/<timestamp>/route53-change-batch.json` before any apply.

## Approved DNS Cutover

```bash
HOSTED_ZONE_ID=Zxxxxxxxx \
CHANGE_BATCH_FILE=artifacts/dr/<timestamp>/route53-change-batch.json \
CONFIRM_DNS_CUTOVER=I_APPROVE_MANUAL_DNS_CUTOVER \
scripts/dr/apply-route53-change.sh
```

This prints current DNS, applies the reviewed Route 53 batch, waits for the change when possible, and runs public health checks.

## Route 53 Rollback Batch

```bash
HOSTNAME=www.mscqr.com \
ROLLBACK_VALUE=primary.example.com \
TTL=60 \
scripts/dr/generate-route53-rollback-batch.sh
```

## Approved DNS Rollback

```bash
HOSTED_ZONE_ID=Zxxxxxxxx \
ROLLBACK_BATCH_FILE=artifacts/dr/<timestamp>/route53-rollback-batch.json \
CONFIRM_DNS_ROLLBACK=I_APPROVE_MANUAL_DNS_ROLLBACK \
scripts/dr/apply-route53-rollback.sh
```

## DB Readiness

```bash
AWS_PROFILE=dr-operator \
AWS_REGION=eu-west-2 \
DB_IDENTIFIER=mscqr-prod \
scripts/dr/db-readiness.sh
```

The command is read-only and may also use `DB_CLUSTER_IDENTIFIER` for Aurora-style clusters.

## DB Restore Plan

```bash
SOURCE_DB_IDENTIFIER=mscqr-prod \
TARGET_REGION=ap-south-1 \
SNAPSHOT_IDENTIFIER=rds:mscqr-prod-2026-05-11 \
TARGET_DB_IDENTIFIER=mscqr-dr-recovery-20260511 \
scripts/dr/generate-db-restore-plan.sh
```

## Approved DB Restore

```bash
TARGET_REGION=ap-south-1 \
SNAPSHOT_IDENTIFIER=rds:mscqr-prod-2026-05-11 \
TARGET_DB_IDENTIFIER=mscqr-dr-recovery-20260511 \
DB_SUBNET_GROUP_NAME=rds-ec2-db-subnet-group-1 \
DB_VPC_SECURITY_GROUP_IDS=sg-07db1a9130c6df8d5 \
CONFIRM_DB_RESTORE=I_APPROVE_DB_RESTORE_TO_RECOVERY_TARGET \
scripts/dr/apply-db-restore-approved.sh
```

The restore script creates only a new recovery target. It refuses identifiers that look like production primary and does not delete, overwrite, modify primary, or fail over. If the AWS restore command fails, the script exits non-zero and the workflow fails.

## Region-Local DB Recovery

Do not point Mumbai or Cape Town at a private London RDS endpoint. The supported DR path is to copy or restore the database into the selected standby region, verify the region-local endpoint, then point only that standby app at the region-local recovered DB.

Target mapping: Mumbai -> `ap-south-1`, Cape Town -> `af-south-1`, London/source -> `eu-west-2`.

Exact Mumbai sequence:

1. `AWS DR Operations` -> `aws-topology-inventory`.
2. `AWS DR Operations` -> `generate-cross-region-snapshot-copy-plan`.
3. `AWS DR Snapshot Apply` -> `apply-cross-region-snapshot-copy-approved`.
4. `AWS DR DB Apply` -> `apply-region-local-db-restore-approved`.
5. `AWS DR Operations` -> `target-region-db-readiness` until `available`.
6. `AWS DR Operations` -> `diagnose-standby-db-network`.
7. `AWS DR Standby DB Test` -> `test-standby-recovered-db`.
8. `AWS DR Standby DB Test` -> `rollback-standby-db-env` after evidence capture.
9. `AWS DR Cleanup Apply` -> cleanup only after explicit cleanup approval.

Local commands:

```bash
SOURCE_REGION=eu-west-2 TARGET_STANDBY=mumbai TARGET_REGION=ap-south-1 SOURCE_DB_IDENTIFIER=mscqr-prod-db scripts/dr/aws-dr-topology-inventory.sh
SOURCE_REGION=eu-west-2 TARGET_REGION=ap-south-1 SOURCE_SNAPSHOT_IDENTIFIER=rds:mscqr-prod-db-YYYY-MM-DD-HH-MM TARGET_SNAPSHOT_IDENTIFIER=mscqr-dr-mumbai-copy-YYYYMMDD TARGET_STANDBY=mumbai scripts/dr/generate-cross-region-snapshot-copy-plan.sh
CONFIRM_SNAPSHOT_COPY=I_APPROVE_CROSS_REGION_SNAPSHOT_COPY SOURCE_REGION=eu-west-2 TARGET_REGION=ap-south-1 SOURCE_SNAPSHOT_IDENTIFIER=rds:mscqr-prod-db-YYYY-MM-DD-HH-MM TARGET_SNAPSHOT_IDENTIFIER=mscqr-dr-mumbai-copy-YYYYMMDD scripts/dr/apply-cross-region-snapshot-copy-approved.sh
CONFIRM_REGION_LOCAL_DB_RESTORE=I_APPROVE_REGION_LOCAL_DB_RESTORE TARGET_STANDBY=mumbai TARGET_REGION=ap-south-1 SNAPSHOT_IDENTIFIER=mscqr-dr-mumbai-copy-YYYYMMDD TARGET_DB_IDENTIFIER=mscqr-dr-mumbai-restore-test-YYYYMMDD DB_SUBNET_GROUP_NAME=<approved-mumbai-db-subnet-group> DB_VPC_SECURITY_GROUP_IDS=<approved-mumbai-db-security-group> scripts/dr/apply-region-local-db-restore-approved.sh
TARGET_STANDBY=mumbai TARGET_REGION=ap-south-1 TARGET_DB_IDENTIFIER=mscqr-dr-mumbai-restore-test-YYYYMMDD scripts/dr/target-region-db-readiness.sh
DB_HOST=<region-local-rds-endpoint> DB_PORT=5432 scripts/dr/diagnose-standby-db-network.sh mumbai
```

Cleanup is separate and dangerous:

```bash
CONFIRM_RECOVERY_DB_CLEANUP=I_APPROVE_RECOVERY_DB_CLEANUP TARGET_REGION=ap-south-1 TARGET_DB_IDENTIFIER=mscqr-dr-mumbai-restore-test-YYYYMMDD FINAL_SNAPSHOT_IDENTIFIER=mscqr-dr-mumbai-final-YYYYMMDD scripts/dr/cleanup-recovery-db-approved.sh
```

## Regional ALB/ACM Entrypoint

Route 53 is now authoritative for `mscqr.com`. Raw EC2 DNS cutover is not the professional standby path because Mumbai and Cape Town do not have region-local TLS certificates inside the frontend container. The approved entrypoint model is:

```text
Route 53 -> regional ALB HTTPS 443 with ACM -> EC2 frontend HTTP 80
```

London currently keeps its local Let's Encrypt/Nginx HTTPS path, but ALB/ACM should become the common entrypoint pattern for London, Mumbai, and Cape Town. Do not copy Let's Encrypt private keys into standby containers.

GitHub workflow:

```text
GitHub repo -> Actions -> AWS DR ALB Apply -> Run workflow
```

Required protected environment:

- `dr-alb-entrypoint-apply`

Required environment variable on that environment:

- Preferred: `AWS_DR_ALB_APPLY_ROLE_ARN`
- Backward-compatible: `DR_ALB_APPLY_ROLE_TO_ASSUME`

Mumbai first-run values:

```text
Branch: main
operation: aws-regional-alb-inventory
target_region_group: mumbai
aws_region: ap-south-1
ec2_public_ip: 15.206.45.108
domain_name: mscqr.com
www_domain_name: www.mscqr.com
hosted_zone_id: Z0569586VLFIGGVI7HAZ
```

Then run the same values with:

```text
operation: generate-regional-alb-plan
```

After review and protected-environment approval, run:

```text
operation: apply-regional-alb-entrypoint-approved
confirm_regional_alb_apply: I_APPROVE_REGIONAL_ALB_ENTRYPOINT_APPLY
```

The ALB apply workflow may create or reuse the regional ALB security group, target group, ALB, ACM certificate, ACM DNS validation records, HTTP redirect listener, and HTTPS listener. It does not cut over `mscqr.com` or `www.mscqr.com`.

Inventory, plan, and apply artifacts list candidate subnets separately from selected ALB subnets. The selected ALB subnet list is one subnet per Availability Zone and only includes subnets whose effective route table has `0.0.0.0/0 -> igw-*`. `MapPublicIpOnLaunch=true` is only a tie-breaker when more than one public subnet exists in the same AZ. The scripts fail clearly if fewer than two distinct Availability Zones have public IGW-routed subnets.

When an ALB already exists, the approved apply script compares its current subnet set to the selected public unique-AZ subnet set and runs `set-subnets` only when they differ. This keeps the workflow rerunnable and fixes stale private-subnet ALB attachments without deleting the ALB.

ACM DNS validation is resilient to AWS timing delays: the apply script waits for `ResourceRecord` values before UPSERTing validation CNAMEs, skips that wait when a reused certificate is already `ISSUED`, and never writes production cutover records.

After the apply artifact contains `ALB_DNS_NAME` and `ALB_HOSTED_ZONE_ID`, generate a DNS review plan:

```text
operation: generate-route53-alb-cutover-plan
alb_dns_name: <ALB_DNS_NAME>
alb_hosted_zone_id: <ALB_HOSTED_ZONE_ID>
rollback_ip: 13.135.108.69
```

For validation before production cutover, generate a regional test record plan locally or in a reviewed operator session:

```text
operation: generate-route53-regional-test-records
target_region_group: mumbai
aws_region: ap-south-1
alb_dns_name: <ALB_DNS_NAME>
alb_hosted_zone_id: <ALB_HOSTED_ZONE_ID>
```

Apply the generated test-record JSON only through `AWS DR DNS Apply` after approval, then test:

```bash
curl -fsS https://dr-mumbai.mscqr.com/healthz
```

The raw AWS ALB DNS hostname is not covered by the MSCQR ACM certificate, so `curl https://<alb>.elb.amazonaws.com/healthz` without `-k` is expected to fail hostname verification. For a certificate-valid smoke test before DNS cutover, either use a regional alias that is covered by the certificate, or resolve the production hostname to an ALB IP:

```bash
dig +short <ALB_DNS_NAME>
curl -fsS --resolve www.mscqr.com:443:<ALB_IP> https://www.mscqr.com/healthz
```

Production cutover must use ALB alias records, not raw EC2 IPs, and must still go through the existing approved DNS workflow.

Cape Town uses the same sequence with:

```text
target_region_group: capetown
aws_region: af-south-1
ec2_public_ip: 15.240.28.113
```

Only after Mumbai and Cape Town inventory, plan, apply, and regional test-record validation pass should operators move into the protected DNS cutover phase.

## Regional Scaling And Reliability Readiness

Current stable state before final DNS cutover:

- Production DNS points to London EC2 `13.135.108.69`.
- Mumbai ALB is healthy and available through `dr-mumbai.mscqr.com`.
- Cape Town ALB is healthy and available through `dr-capetown.mscqr.com`.
- Production cutover/rollback plans exist, but production DNS must not be changed by readiness work.
- ASG_STATUS=CONDITIONALLY_READY in `documents/ops/aws-asg-multi-instance-readiness.md`, with a required no-DNS live replacement-instance drill still pending.

Use this workflow for read-only evidence and plan generation:

```text
GitHub repo -> Actions -> AWS DR Regional Readiness -> Run workflow
```

Required protected environment:

- `dr-regional-readiness`

Required environment variable on that environment:

- Preferred: `AWS_DR_REGIONAL_READINESS_ROLE_ARN`
- Backward-compatible: `DR_REGIONAL_READINESS_ROLE_TO_ASSUME`

Supported operations:

- `verify-regional-alb-health`: captures ALB, listener, target-health, and HTTPS smoke evidence.
- `regional-capacity-inventory`: captures EC2 instance type, status, EBS volumes, and CloudWatch CPU evidence. Optional memory/disk/Docker host checks require `ENABLE_REMOTE_HOST_CHECKS=I_APPROVE_READ_ONLY_REMOTE_HOST_CHECKS` and operator-supplied SSH context locally.
- `generate-regional-cloudwatch-alarm-plan`: creates an alarm plan for ALB 5XX, target 5XX, unhealthy hosts, latency, EC2 CPU, and disk if `CWAgent` metrics exist.
- `generate-alb-access-log-plan`: creates a plan for ALB access logs to an approved S3 logging bucket. It does not enable logging.
- `generate-waf-plan`: creates a WAF managed-rule and rate-limit plan. It does not create or attach WAF.
- `generate-asg-launch-template-plan`: creates an ASG/launch-template migration plan from the current instance evidence. It does not create launch templates, ASGs, AMIs, or EC2 instances.

Mumbai readiness values:

```text
target_region_group: mumbai
aws_region: ap-south-1
ec2_public_ip: 15.206.45.108
alb_arn: arn:aws:elasticloadbalancing:ap-south-1:368992683803:loadbalancer/app/mscqr-mumbai-alb/025ad0cb77546ee0
alb_dns_name: mscqr-mumbai-alb-1249752376.ap-south-1.elb.amazonaws.com
target_group_arn: arn:aws:elasticloadbalancing:ap-south-1:368992683803:targetgroup/mscqr-mumbai-frontend-tg/68982ccd4d8c26c1
test_hostname: dr-mumbai.mscqr.com
```

Cape Town readiness values:

```text
target_region_group: capetown
aws_region: af-south-1
ec2_public_ip: 15.240.28.113
alb_arn: arn:aws:elasticloadbalancing:af-south-1:368992683803:loadbalancer/app/mscqr-capetown-alb/b7defd5707ad181c
alb_dns_name: mscqr-capetown-alb-1730011881.af-south-1.elb.amazonaws.com
target_group_arn: arn:aws:elasticloadbalancing:af-south-1:368992683803:targetgroup/mscqr-capetown-frontend-tg/a9b43fd2d346e26d
test_hostname: dr-capetown.mscqr.com
```

Recommended readiness sequence per region:

1. `verify-regional-alb-health`.
2. `regional-capacity-inventory`.
3. `generate-regional-cloudwatch-alarm-plan`.
4. `generate-alb-access-log-plan`.
5. `generate-waf-plan`.
6. `generate-asg-launch-template-plan`.

Do not proceed to final production DNS cutover until test-record validation, scaling readiness, observability readiness, and rollback evidence are all captured for both Mumbai and Cape Town.

Before any ASG create/attach approval, run and review:

```bash
node scripts/dr/check-asg-multi-instance-readiness.mjs
```

The current ASG gate is conditionally ready at repo level: shared Redis, shared object storage, ASG secret injection, worker singleton behavior, bootstrap repeatability, health grace, and rolling deployment policy are documented and gated in-repo. The source of truth is `documents/ops/aws-asg-multi-instance-readiness.md`, `documents/ops/aws-asg-multi-instance-readiness.checklist.json`, and `documents/ops/aws-asg-rolling-deploy-policy.md`.

## Approved Regional Hardening Apply

After readiness plans are reviewed, use the hardening workflow for staged, approval-gated changes:

```text
GitHub repo -> Actions -> AWS DR Hardening Apply -> Run workflow
```

Required protected environment:

- `dr-hardening-apply`

Required environment variable on that environment:

- Preferred: `AWS_DR_HARDENING_APPLY_ROLE_ARN`
- Backward-compatible: `DR_HARDENING_APPLY_ROLE_TO_ASSUME`

Confirmation tokens:

- CloudWatch alarms: `I_APPROVE_CLOUDWATCH_ALARM_APPLY`
- ALB access logs: `I_APPROVE_ALB_ACCESS_LOGS_APPLY`
- WAF COUNT mode: `I_APPROVE_WAF_COUNT_MODE_APPLY`
- ASG create and attach: `I_APPROVE_REGIONAL_ASG_CREATE_AND_ATTACH`

Safe hardening order per region:

1. `verify-hardening-state` baseline.
2. `apply-cloudwatch-alarms`.
3. `apply-alb-access-logs`.
4. `apply-waf-count-mode`.
5. `verify-hardening-state`.
6. `generate-asg-apply-plan`.
7. Run `apply-asg-launch-template-approved` only after `ASG_STATUS=CONDITIONALLY_READY` or `READY` is present in `documents/ops/aws-asg-multi-instance-readiness.md`, the rolling policy checklist is reviewed, and the rollout is explicitly treated as a no-production-DNS validation drill.
8. Consider production DNS cutover only after ASG health and app state risks are solved.

Rollback notes:

- CloudWatch alarm changes are non-traffic-impacting.
- ALB access logs are non-traffic-impacting, but require an approved logging bucket.
- WAF COUNT mode is non-blocking; do not move rules to BLOCK in this phase.
- ASG apply creates extra capacity and attaches it to the target group. It does not detach or delete the source instance, terminate instances, or change DNS.
- The first ASG rollout must keep production DNS on London EC2 and must include the replacement-instance drill from `documents/ops/aws-asg-rolling-deploy-policy.md`.
- ASG launch templates must use explicit `ASG_WEB_INSTANCE_PROFILE_ARN` or `ASG_WEB_INSTANCE_PROFILE_NAME`. Do not reuse the source instance profile automatically.

Mumbai hardening values:

```text
target_region_group: mumbai
aws_region: ap-south-1
ec2_public_ip: 15.206.45.108
alb_arn: arn:aws:elasticloadbalancing:ap-south-1:368992683803:loadbalancer/app/mscqr-mumbai-alb/025ad0cb77546ee0
alb_dns_name: mscqr-mumbai-alb-1249752376.ap-south-1.elb.amazonaws.com
target_group_arn: arn:aws:elasticloadbalancing:ap-south-1:368992683803:targetgroup/mscqr-mumbai-frontend-tg/68982ccd4d8c26c1
source_instance_id: i-04ae3b689ab72a68a
source_ami: ami-07216ac99dc46a187
source_instance_type: t3.medium
source_security_group: sg-0771ea7e59f7a49d4
test_hostname: dr-mumbai.mscqr.com
alb access logs prefix: mscqr/alb/mumbai
waf_web_acl_name: mscqr-mumbai-regional-waf
min_size: 2
desired_capacity: 2
max_size: 4
```

Mumbai ASG plan/apply environment:

```bash
TARGET_REGION_GROUP=mumbai
AWS_REGION=ap-south-1
SOURCE_INSTANCE_ID=i-04ae3b689ab72a68a
SOURCE_AMI=ami-07216ac99dc46a187
SOURCE_INSTANCE_TYPE=t3.medium
SOURCE_SECURITY_GROUP=sg-0771ea7e59f7a49d4
TARGET_GROUP_ARN=arn:aws:elasticloadbalancing:ap-south-1:368992683803:targetgroup/mscqr-mumbai-frontend-tg/68982ccd4d8c26c1
ASG_WEB_INSTANCE_PROFILE_ARN=<approved-asg-web-instance-profile-arn>
# Or, if using a profile name instead of ARN:
# ASG_WEB_INSTANCE_PROFILE_NAME=<approved-asg-web-instance-profile-name>
ROLLBACK_ALARM_NAMES_CSV=MSCQR-mumbai-ALB-5XX,MSCQR-mumbai-Target-5XX,MSCQR-mumbai-TargetResponseTime-p95,MSCQR-mumbai-UnhealthyHosts
MIN_SIZE=2
DESIRED_CAPACITY=2
MAX_SIZE=4
```

Add this only for the protected apply operation, never for plan generation:

```bash
CONFIRM_ASG_APPLY=I_APPROVE_REGIONAL_ASG_CREATE_AND_ATTACH
```

Cape Town hardening values:

```text
target_region_group: capetown
aws_region: af-south-1
ec2_public_ip: 15.240.28.113
alb_arn: arn:aws:elasticloadbalancing:af-south-1:368992683803:loadbalancer/app/mscqr-capetown-alb/b7defd5707ad181c
alb_dns_name: mscqr-capetown-alb-1730011881.af-south-1.elb.amazonaws.com
target_group_arn: arn:aws:elasticloadbalancing:af-south-1:368992683803:targetgroup/mscqr-capetown-frontend-tg/a9b43fd2d346e26d
source_instance_id: i-064223a25caf64770
source_ami: ami-0026d53e1887d8949
source_instance_type: t3.medium
source_security_group: sg-0d8f560e4f6452aa5
test_hostname: dr-capetown.mscqr.com
alb access logs prefix: mscqr/alb/capetown
waf_web_acl_name: mscqr-capetown-regional-waf
min_size: 2
desired_capacity: 2
max_size: 4
```

## Approved Recovery Cleanup

Cleanup is destructive to test recovery resources. Run it only after evidence artifacts are captured and the incident commander approves cleanup. Never target production DBs, production snapshots, automated `rds:` snapshots, S3, MinIO, DNS, or London/primary resources.

GitHub path:

```text
GitHub repo -> Actions -> AWS DR Cleanup Apply -> Run workflow
```

Mumbai recovery DB cleanup:

```text
Branch: main
operation: cleanup-recovery-db-approved
aws_region: ap-south-1
target_db_identifier: mscqr-dr-mumbai-restore-test-20260511
target_snapshot_identifier: blank
final_snapshot_identifier: blank
skip_final_snapshot: true
confirm_recovery_db_cleanup: I_APPROVE_RECOVERY_DB_CLEANUP
confirm_skip_final_snapshot: I_APPROVE_SKIP_FINAL_SNAPSHOT
confirm_dr_snapshot_cleanup: blank
```

Mumbai copied snapshot cleanup:

```text
Branch: main
operation: cleanup-dr-snapshot-approved
aws_region: ap-south-1
target_db_identifier: blank
target_snapshot_identifier: mscqr-dr-mumbai-copy-20260511
final_snapshot_identifier: blank
skip_final_snapshot: false
confirm_recovery_db_cleanup: blank
confirm_skip_final_snapshot: blank
confirm_dr_snapshot_cleanup: I_APPROVE_DR_SNAPSHOT_CLEANUP
```

Cape Town recovery DB cleanup:

```text
Branch: main
operation: cleanup-recovery-db-approved
aws_region: af-south-1
target_db_identifier: mscqr-dr-capetown-restore-test-20260512
target_snapshot_identifier: blank
final_snapshot_identifier: blank
skip_final_snapshot: true
confirm_recovery_db_cleanup: I_APPROVE_RECOVERY_DB_CLEANUP
confirm_skip_final_snapshot: I_APPROVE_SKIP_FINAL_SNAPSHOT
confirm_dr_snapshot_cleanup: blank
```

Cape Town copied snapshot cleanup:

```text
Branch: main
operation: cleanup-dr-snapshot-approved
aws_region: af-south-1
target_db_identifier: blank
target_snapshot_identifier: mscqr-dr-capetown-copy-20260512
final_snapshot_identifier: blank
skip_final_snapshot: false
confirm_recovery_db_cleanup: blank
confirm_skip_final_snapshot: blank
confirm_dr_snapshot_cleanup: I_APPROVE_DR_SNAPSHOT_CLEANUP
```

## Standby Recovered DB Connection Test

Use this only after the approved DB restore has created a recovery DB target and the incident commander has approved a single-standby validation. This test changes the selected standby server only, creates a timestamped backup of `/home/ubuntu/genuine-scan-main/backend/.env`, updates only `DATABASE_URL`, restarts the selected standby Docker Compose app services, runs `/healthz` and `/api/health/ready`, and records evidence under `artifacts/dr/<timestamp>/`.

Targets are intentionally limited to `mumbai` or `capetown`. Do not use this path for London, primary, `standby`, `standby_regions`, or all hosts. This path does not change DNS, Route 53, production DB, buckets, MinIO, or London.

Local test example:

```bash
RECOVERED_DB_HOST=mscqr-dr-restore-test-20260511.c3ewey6o6mq5.eu-west-2.rds.amazonaws.com \
RECOVERED_DB_PORT=5432 \
RECOVERED_DB_NAME=postgres \
RECOVERED_DB_USER=postgres \
RECOVERED_DB_PASSWORD='<from approved secret channel>' \
scripts/dr/test-standby-recovered-db.sh mumbai
```

The password is passed through the process environment and is not printed. The Ansible playbook marks password-bearing tasks as `no_log`.

Local rollback example:

```bash
scripts/dr/rollback-standby-db-env.sh mumbai /home/ubuntu/genuine-scan-main/backend/.env.backup.dr-YYYYMMDDTHHMMSSZ
```

### GitHub Standby DB Test Workflow

Protected environment required:

```text
dr-standby-db-test
```

Environment secrets required:

- `RECOVERED_DB_PASSWORD`: password for the approved recovered DB target.
- `STANDBY_ANSIBLE_INVENTORY`: standby-only Ansible inventory containing `mumbai` and `capetown`.
- `STANDBY_SSH_PRIVATE_KEY`: SSH private key for the selected standby server.
- `STANDBY_KNOWN_HOSTS`: pinned known_hosts entries for the standby servers.

Click-by-click setup:

1. GitHub repo -> Settings -> Environments.
2. New environment -> `dr-standby-db-test`.
3. Add required reviewers for approval.
4. Add Environment secrets: `RECOVERED_DB_PASSWORD`, `STANDBY_ANSIBLE_INVENTORY`, `STANDBY_SSH_PRIVATE_KEY`, and `STANDBY_KNOWN_HOSTS`.
5. Confirm the inventory contains only standby targets needed for this drill and does not include London/primary as the selected limit.

Click-by-click Mumbai test:

1. GitHub repo -> Actions -> AWS DR Standby DB Test -> Run workflow.
2. Branch: `aws-dr-finish`.
3. operation: `test-standby-recovered-db`.
4. target_region: `mumbai`.
5. recovered_db_host: `mscqr-dr-restore-test-20260511.c3ewey6o6mq5.eu-west-2.rds.amazonaws.com`.
6. recovered_db_port: `5432`.
7. recovered_db_name: `postgres`.
8. recovered_db_user: `postgres`.
9. backup_path_for_rollback: blank.
10. confirmation: `I_APPROVE_STANDBY_RECOVERED_DB_TEST`.
11. Run workflow and approve the `dr-standby-db-test` environment prompt.
12. Download the evidence artifact and copy the printed env backup path for rollback.

Click-by-click rollback:

1. GitHub repo -> Actions -> AWS DR Standby DB Test -> Run workflow.
2. Branch: `aws-dr-finish`.
3. operation: `rollback-standby-db-env`.
4. target_region: `mumbai`.
5. backup_path_for_rollback: paste the backup path printed by the test, for example `/home/ubuntu/genuine-scan-main/backend/.env.backup.dr-YYYYMMDDTHHMMSSZ`.
6. confirmation: `I_APPROVE_STANDBY_DB_ENV_ROLLBACK`.
7. Run workflow and approve the `dr-standby-db-test` environment prompt.
8. Download the evidence artifact and confirm health checks passed after rollback.

## Object Storage Readiness

```bash
BUCKET=mscqr-prod-assets scripts/dr/object-storage-readiness.sh
BUCKET=mscqr-prod-assets TEST_OBJECT_KEY=known/read/path.txt scripts/dr/object-storage-readiness.sh
```

## Approved Object Storage Write Test

```bash
BUCKET=mscqr-prod-assets \
CONFIRM_OBJECT_WRITE_TEST=I_APPROVE_OBJECT_STORAGE_WRITE_TEST \
scripts/dr/object-storage-write-test-approved.sh
```

To delete only the generated `dr-tests/<timestamp>/healthcheck.txt` object:

```bash
BUCKET=mscqr-prod-assets \
CONFIRM_OBJECT_WRITE_TEST=I_APPROVE_OBJECT_STORAGE_WRITE_TEST \
CONFIRM_DELETE_TEST_OBJECT=I_APPROVE_DELETE_DR_TEST_OBJECT \
scripts/dr/object-storage-write-test-approved.sh
```

## GitHub Actions

- `AWS DR Validation` validates scripts, guardrails, and Ansible syntax without production secrets, SSH, or deploy.
- `AWS DR Operations` is `workflow_dispatch` only and exposes read-only or artifact-only checks. It does not include DNS apply, snapshot copy apply, DB restore apply, cleanup, or object write-test apply.
- `AWS DR DNS Apply` handles approved Route 53 cutover and rollback only.
- `AWS DR Snapshot Apply` handles approved cross-region snapshot copy only.
- `AWS DR DB Apply` handles approved DB restore and region-local DB restore only.
- `AWS DR Cleanup Apply` handles approved recovery DB cleanup only.
- `AWS DR Object Storage Apply` handles approved object-storage write tests only.
- `AWS DR Standby DB Test` is `workflow_dispatch` only and validates one selected standby app against an already-restored recovery DB behind the protected `dr-standby-db-test` environment.
- Standby deploy from Actions requires an approved `STANDBY_ANSIBLE_INVENTORY` secret and an intentional `deploy-standby` selection.

Protected environment and IAM setup are documented in:

```text
documents/ops/aws-dr-protected-environments.md
```

## Read-Only GitHub Actions Smoke Tests

Click path:

```text
GitHub repo -> Actions -> AWS DR Operations -> Run workflow
```

Run these smoke tests from branch `aws-dr-finish`:

1. Public health

```text
Branch: aws-dr-finish
operation: public-health
target_region: standby
hostname: www.mscqr.com
```

2. DNS inventory

```text
Branch: aws-dr-finish
operation: dns-inventory
target_region: standby
hostname: www.mscqr.com
```

3. Object storage readiness

```text
Branch: aws-dr-finish
operation: object-storage-readiness
target_region: standby
bucket: mscqr-prod-euw2-artifacts-368992683803-eu-west-2-an
test_object_key: blank
```

`public-health` and `dns-inventory` do not change AWS and do not require AWS credentials. `object-storage-readiness` uses OIDC only when `AWS_DR_OBJECT_STORAGE_ROLE_ARN` is configured and performs read-only S3 checks: `aws s3 ls` and optional `aws s3api head-object`. Each run uploads `artifacts/dr/**` as a GitHub artifact.

4. DB readiness

```text
Branch: aws-dr-finish
operation: db-readiness
target_region: standby
aws_region: eu-west-2
db_identifier: blank initially
```

5. DB restore plan generation

```text
Branch: aws-dr-finish
operation: generate-db-restore-plan
aws_region: eu-west-2
source_db_identifier: <approved source identifier>
db_snapshot_identifier: <approved snapshot id, if used>
target_db_region: eu-west-2 / ap-south-1 / af-south-1
target_db_identifier: mscqr-dr-restore-test-YYYYMMDD
recovery_point: blank unless using point-in-time planning
db_subnet_group_name: rds-ec2-db-subnet-group-1
db_vpc_security_group_ids: sg-07db1a9130c6df8d5
```

`db-readiness` uses the `dr-db-restore` environment and OIDC to run read-only RDS describe commands. `generate-db-restore-plan` writes a markdown artifact only. Actual DB restore remains in `AWS DR DB Apply` and requires confirmation plus protected environment approval.

Additional region-local DB operations:

- `aws-topology-inventory`: read-only source/target AWS topology evidence.
- `generate-cross-region-snapshot-copy-plan`: markdown snapshot copy plan only.
- `target-region-db-readiness`: read-only recovery DB status and endpoint evidence.
- `diagnose-standby-db-network`: read-only DNS/TCP check from one standby to a DB endpoint.

Do not run apply workflows for smoke tests.

## Troubleshooting Object Storage Readiness

If `object-storage-readiness` fails with:

```text
AWS_DR_OBJECT_STORAGE_ROLE_ARN is required
```

or:

```text
AWS_DR_OBJECT_STORAGE_ROLE_ARN is missing.
```

check:

1. GitHub repo -> Settings -> Environments.
2. Open `dr-object-storage-write-test`.
3. Confirm the Environment variable exists:
   `AWS_DR_OBJECT_STORAGE_ROLE_ARN`
4. Confirm the value is the object storage role ARN:
   `arn:aws:iam::<account-id>:role/MSCQRGitHubDRObjectStorageRole`
5. Re-run `AWS DR Operations` -> `object-storage-readiness`.

The current expected setup is a GitHub Environment variable exposed through `vars.AWS_DR_OBJECT_STORAGE_ROLE_ARN`. If the ARN is stored as an Environment secret instead, update the workflow wiring to use `secrets.AWS_DR_OBJECT_STORAGE_ROLE_ARN`.

## Troubleshooting DB Readiness

`db-readiness` and `generate-db-restore-plan` run under the `dr-db-restore` GitHub Environment. Configure one of these Environment variables:

- Preferred: `AWS_DR_DB_RESTORE_ROLE_ARN`
- Backward-compatible: `DR_DB_RESTORE_ROLE_TO_ASSUME`

If both are missing, the workflow fails before AWS authentication with:

```text
Set AWS_DR_DB_RESTORE_ROLE_ARN or DR_DB_RESTORE_ROLE_TO_ASSUME on the dr-db-restore environment.
```

Do not store static AWS access keys for this workflow.

## Troubleshooting Approved DB Restore

If an approved DB restore fails with:

```text
InvalidSubnet: No default subnet detected in VPC
```

set:

```text
db_subnet_group_name: rds-ec2-db-subnet-group-1
```

Optionally set:

```text
db_vpc_security_group_ids: sg-07db1a9130c6df8d5
```

These values came from the current London restore drill and should be re-validated before production incident use. A dedicated recovery subnet group/security group is preferable once approved.

## Safety Guarantees

- No blind automatic failover.
- No health-check-triggered DNS switching.
- No unattended production DNS cutover.
- No unattended production DB restore.
- No standby recovered DB test without a single `mumbai` or `capetown` target and protected environment approval.
- No active-active multi-write.
- No destructive cleanup unless it targets a recovery DB identifier and passes the explicit `dr-recovery-cleanup` approval gate.
- No bucket deletion or production database deletion.
- No Docker prune, volume wiping, or MinIO decommission.
- No secrets, real `.env`, or real `ops/deploy/inventory.ini` committed.
- Documentation-only changes do not wake the production deploy chain.
