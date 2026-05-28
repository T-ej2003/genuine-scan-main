# AWS ASG Rolling Deploy Policy

Last updated: 2026-05-28

ASG_STATUS=CONDITIONALLY_READY

This document defines the approved rolling deploy and instance refresh contract for MSCQR ASG web nodes. It does not create ASGs, change Route 53, mutate RDS or application S3 data, or claim that live rollout has already been tested.

## Scope

- Applies only to ASG web nodes running `docker compose -f docker-compose.asg-web.yml up -d --build backend frontend`.
- Applies to Mumbai and Cape Town regional ALB target groups.
- Assumes singleton workers remain outside the web ASG.
- Production DNS must remain on London EC2 during ASG rollout validation.

## Policy Values

Source of truth: `documents/ops/aws-asg-rolling-deploy-policy.checklist.json`

- Launch template instance profile: explicit `ASG_WEB_INSTANCE_PROFILE_ARN` or `ASG_WEB_INSTANCE_PROFILE_NAME`; ARN wins when both are set.
- Launch template bootstrap: base64 `UserData` that can boot a plain Ubuntu 22.04 host by installing/checking Git, Docker, Docker Compose, AWS CLI, Node.js 24, and npm 11, including apt attempts plus manual Docker Compose/AWS CLI fallbacks and pinned-major NodeSource setup, cloning/updating the repository, and running `scripts/dr/bootstrap-asg-web-node.sh "$TARGET_REGION_GROUP" "$AWS_REGION"` from `ASG_REPO_DIR`.
- Launch template repository inputs: required `ASG_REPO_URL`, default `ASG_REPO_BRANCH=main`, and default `ASG_REPO_DIR=/home/ubuntu/genuine-scan-main`. Mumbai debug retry should use `ASG_REPO_URL=https://github.com/T-ej2003/genuine-scan-main.git`, `ASG_REPO_BRANCH=main`, and `ASG_REPO_DIR=/home/ubuntu/genuine-scan-main`.
- Launch template SSH key: optional `ASG_KEY_NAME`; when set it must become `KeyName` in `LaunchTemplateData`, and Mumbai debug retry should use `ASG_KEY_NAME=mscqr-prod-mumbai`.
- Launch template public IP association: `ASG_ASSOCIATE_PUBLIC_IP=false` by default; accepted values are only `true` and `false`.
- When `ASG_ASSOCIATE_PUBLIC_IP=true`, launch template data must use `NetworkInterfaces[0].AssociatePublicIpAddress=true` with `Groups=[SOURCE_SECURITY_GROUP]` and no top-level `SecurityGroupIds`.
- When `ASG_ASSOCIATE_PUBLIC_IP=false`, launch template data must use top-level `SecurityGroupIds=[SOURCE_SECURITY_GROUP]` and no `NetworkInterfaces`.
- ALB target group deregistration delay: 60 seconds.
- ASG health check type: `ELB`.
- ASG health check grace period: 900 seconds.
- ASG default instance warmup: 900 seconds.
- Instance refresh minimum healthy percentage: 100.
- Instance refresh maximum healthy percentage if supported: 150.
- Instance refresh checkpoints: 50 percent and 100 percent.
- Instance refresh checkpoint wait: 300 seconds.
- Initial ASG capacity for first production-safe rollout: `min=2 desired=2 max=4`.
- Required healthy current ASG target count after ASG apply and after each replacement step: at least 2. Healthy legacy/source targets that remain registered in the same target group are diagnostics only and do not satisfy ASG readiness.

## Required Alarms

Before, during, and after refresh, the following CloudWatch alarms must remain green for the target region:

- ALB 5XX
- target 5XX
- target response time
- unhealthy hosts

The machine-readable policy stores region-specific placeholder names for Mumbai and Cape Town. Before a real apply, operators must provide the reviewed concrete alarm names to the apply path.

## Smoke Tests

Every rollout batch and replacement step must pass:

- `GET /healthz`
- `GET /api/health/ready`
- target group healthy count is at least 2
- ALB 5XX alarm remains `OK`
- target 5XX alarm remains `OK`
- target response time alarm remains `OK`

`/healthz` is shallow liveness only. `/api/health/ready` must confirm `database.ready=true`, `redis.configured=true`, `redis.ready=true`, `objectStorage.configured=true`, and `objectStorage.ready=true`.

## Go/No-Go Checklist

- Production DNS still points to London EC2.
- Regional test hostname is healthy before the rollout starts.
- `node scripts/dr/check-asg-multi-instance-readiness.mjs` passes.
- The ASG web instance profile has been tested from an EC2 role against the target region SSM prefix before apply.
- Generated launch template data contains `IamInstanceProfile`, `UserData`, `MetadataOptions.HttpTokens=required`, `ImageId`, `InstanceType`, and the expected networking shape for `ASG_ASSOCIATE_PUBLIC_IP`.
- For debug retries, generated launch template data contains `KeyName=mscqr-prod-mumbai` so failed nodes can be inspected without relying on console output alone.
- UserData mirrors non-secret status and failure lines to cloud-init console output and writes the full bootstrap log to `/var/log/mscqr-asg-bootstrap.log`.
- UserData installs/checks `git`, `docker.io`, `docker compose`, `aws --version`, `node --version`, and `npm --version`; if `docker compose version` is unavailable, it tries apt `docker-compose-plugin` and then installs a pinned Compose v2 plugin under `/usr/local/lib/docker/cli-plugins/docker-compose` when apt cannot provide it; if AWS CLI is unavailable, it tries apt `awscli` and then installs AWS CLI v2 from the official installer when apt cannot provide it; if Node.js/npm are unavailable or outside `node >=24 <27` and `npm >=11`, it configures NodeSource `node_24.x` and installs `nodejs`; if `ASG_REPO_DIR` is missing, it clones `ASG_REPO_URL`; if `ASG_REPO_DIR` is already a git checkout, it fetches/resets `ASG_REPO_BRANCH`; if the path exists but is not a git checkout, it fails without deleting it.
- UserData tees bootstrap script output to `/var/log/mscqr-asg-bootstrap.log` and cloud-init console output, and preserves the bootstrap script exit code without relying on `pipefail`.
- `scripts/dr/bootstrap-asg-web-node.sh` is the launch-template bootstrap path.
- ASG bootstrap renders the project `.env` and a temporary bootstrap env file as root/backend union env files, then runs `docker compose --env-file "$compose_env_path" -f docker-compose.asg-web.yml ...` so Compose-required secrets such as `QR_SIGN_PRIVATE_KEY` are available at interpolation time and later plain `docker compose ps` diagnostics can still parse the file. Values are never printed.
- All ASG bootstrap Compose invocations, including diagnostics, must use the generated `--env-file` so required interpolation variables such as `QR_SIGN_ACTIVE_KEY_VERSION` remain available until bootstrap exits.
- Backend container health uses `/health/live` for process liveness so frontend/Nginx can start; loopback `/healthz` plus host-primary-IP `/healthz` are the hard edge-liveness gates for ALB target health, while `/api/health/ready` remains dependency-readiness evidence for database, Redis, and object storage.
- Required SSM parameters under the regional ASG web prefix exist before apply; missing required diagnostics must include the full parameter path without printing values.
- Required SSM parameters that exist with empty values fail before Compose with key/path-only diagnostics.
- `SMTP_HOST`, `SMTP_USER`, and `SMTP_PASS` are required for production email. `SMTP_FROM` is optional but recommended as an authorized sender override because the backend can boot and use the authenticated SMTP mailbox as From when it is absent.
- `RUN_BACKGROUND_WORKERS=false`, `RUN_DB_MIGRATIONS_ON_START=false`, and `COMPLIANCE_PACK_SCHEDULER_ENABLED=false` remain forced.
- Regional Redis and regional S3/default-credential object storage are green through readiness.
- CloudWatch alarms are green before the first attach and before each refresh checkpoint decision.
- The previous launch template version remains available for rollback.

No-go if any required alarm is red, any smoke test fails, or target group healthy count cannot stay at 2 or above.

## Manual Rollback

If rollout health degrades:

1. Stop the rollout by canceling the active instance refresh.
2. Keep production DNS unchanged.
3. Revert the ASG to the previous launch template version if the new launch template is implicated.
4. Restore healthy capacity before terminating or deregistering any new unhealthy instance.
5. Re-run `GET /healthz`, `GET /api/health/ready`, and target-health checks.
6. Capture CloudWatch alarm state, target health, launch template version, and smoke-test evidence.

Rollback criteria:

- any new target fails `/healthz`
- any new target fails `/api/health/ready`
- target group healthy count drops below 2
- ALB 5XX or target 5XX alarms enter `ALARM`
- target response time alarm enters `ALARM`
- operator smoke tests fail on the regional test hostname

## Replacement-Instance Drill

This is the remaining live go/no-go after repo hardening.

Mumbai no-DNS retry inputs for the next drill:

Latest Mumbai failure evidence: ASG instances launched with public IP, `KeyName`, and instance profile; `git` was already installed; Docker installed and the service was active; apt did not provide `docker-compose-plugin`; `docker compose` returned `docker: unknown command: docker compose`; the bootstrap failed while checking Docker Compose before repo clone, so app containers never started and ALB target health failed. A later SSH attempt saw `PublicIp=None` because ASG had already terminated/replaced the node. The original Mumbai EC2 stayed healthy and no DNS cutover happened. The retry fix is the pinned manual Compose v2 plugin fallback after the apt attempt.

Latest retry evidence: Docker Compose fallback succeeded and verification reached; the repo bootstrap found `scripts/dr/bootstrap-asg-web-node.sh`; failure moved to `running bootstrap script`. The likely causes are missing AWS CLI for SSM Parameter Store reads or bootstrap details hidden only in the node-local log. The current fix adds AWS CLI prerequisite handling and mirrors bootstrap output to cloud-init console without printing secrets.

Latest Node prerequisite evidence: AWS CLI installed from apt and verified, repo clone succeeded to HEAD `c97edfe`, then the SSM bootstrap failed with `ERROR: node is required.` The current fix installs and verifies Node.js 24/npm 11 before running `scripts/dr/bootstrap-asg-web-node.sh`, so the next retry should test app/bootstrap health rather than missing host runtime.

Latest SSM env-render evidence: fresh ASG nodes reached `/mscqr/prod/ap-south-1/asg-web/` SSM fetch and then failed with `backendEnv missing required SSM parameter(s): SMTP_FROM`. Source review showed `SMTP_FROM` is not a startup requirement; it is an optional sender override and the backend falls back to the authenticated SMTP mailbox when absent. The manifest now treats `/mscqr/prod/ap-south-1/asg-web/SMTP_FROM` as optional/recommended, and true missing required SSM errors include full paths.

Latest Compose interpolation evidence: the next retry rendered 9 root env keys and 135 backend env keys, consumed 130 SSM parameter names, then failed while interpolating `services.backend.environment.QR_SIGN_PRIVATE_KEY` even though the SSM parameter name existed. Root cause: Compose interpolation does not read service `env_file` values before resolving `${QR_SIGN_PRIVATE_KEY:?...}`. The current fix persists the project `.env` as a root/backend union, passes a temporary union env file through `docker compose --env-file`, and adds a local `docker compose config` validation with dummy values.

Latest ASG stabilization evidence: the next retry proved loopback `/healthz`, host-primary-IP `/healthz`, and at least one public `/healthz` probe, but ASG nodes still churned. Console timing showed cold plain-Ubuntu bootstrap reaching frontend `/healthz` at roughly 295 seconds, while the committed ASG health grace/default warmup were still 180 seconds. The target group also still contained legacy/source instance `i-04ae3b689ab72a68a`, so total target-group healthy count could report 2 even when only one current ASG instance was healthy. The current policy raises health grace and default warmup to 900 seconds and makes apply/evidence count only current ASG instance IDs as satisfying readiness; legacy/source healthy targets are printed separately.

Safe names-only SSM preflight before retry:

```bash
aws ssm describe-parameters \
  --region ap-south-1 \
  --parameter-filters "Key=Path,Option=Recursive,Values=/mscqr/prod/ap-south-1/asg-web/" \
  --query 'Parameters[].Name' \
  --output text | tr '\t' '\n' | sort
```

Read-only ASG/ALB evidence capture when health disagrees:

```bash
TARGET_REGION_GROUP=mumbai \
AWS_REGION=ap-south-1 \
ASG_NAME=mscqr-mumbai-dr-asg \
TARGET_GROUP_ARN=arn:aws:elasticloadbalancing:ap-south-1:368992683803:targetgroup/mscqr-mumbai-frontend-tg/68982ccd4d8c26c1 \
npm run ops:asg-health-evidence
```

Optional SSH deep inspection uses the same command with `ALLOW_SSH_DEEP_INSPECTION=true` and `ASG_SSH_KEY=/Users/abhiramteja/Desktop/keys/mscqr-prod-mumbai.pem`.

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

Add only for protected apply, not plan generation:

```bash
CONFIRM_ASG_APPLY=I_APPROVE_REGIONAL_ASG_CREATE_AND_ATTACH
```

1. Create and attach the regional ASG with `min=2 desired=2 max=4` and no production DNS cutover.
2. Wait for at least 2 healthy current ASG targets on the regional ALB target group; do not count the legacy/source target if it is still registered.
3. Run the smoke tests on the regional test hostname:
   `https://dr-mumbai.mscqr.com/healthz` or `https://dr-capetown.mscqr.com/healthz`
   `https://dr-mumbai.mscqr.com/api/health/ready` or `https://dr-capetown.mscqr.com/api/health/ready`
4. Start a one-instance replacement step, either through instance refresh with the documented checkpoints or by a controlled single-instance replacement without decrementing desired capacity.
5. Confirm the new ASG instance reaches healthy target state and both health endpoints pass.
6. Confirm CloudWatch alarms remain green and target response time stays within the approved baseline.
7. Record artifacts under `artifacts/dr/` and link them in the incident or rollout record.

This drill is successful only when current-ASG healthy target count returns to at least 2 after replacement and no rollback criteria fire.

## Operator Rule

Do not perform production DNS cutover during ASG rollout validation. The purpose of the first ASG rollout is to prove launch-template bootstrap, healthy replacement, and rollback safety behind the regional ALB only.
