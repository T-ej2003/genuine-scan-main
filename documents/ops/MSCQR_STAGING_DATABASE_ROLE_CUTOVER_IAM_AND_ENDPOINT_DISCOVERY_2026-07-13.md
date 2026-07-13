# MSCQR staging database-role cutover IAM and endpoint discovery

Date: 2026-07-13
Scope: account `368992683803`, `eu-west-2`, cluster `mscqr-staging-euw2-main`, service `mscqr-staging-backend-service-euw2`.

## Outcome

The ECS database-role cutover now has a dedicated MFA-gated human role, separate source-user and assume-role templates, a least-privilege runtime policy, Terraform resources/outputs, sanitized endpoint discovery, a fresh verification-receipt gate, and fail-closed URL validation. This work did not enable RLS, run Terraform apply, or make any AWS mutation.

The role/profile target is `mscqr-staging-database-role-cutover`. It is isolated from the database-role operator and Terraform plan/apply roles. The apply role may manage the Terraform-owned role but is not trusted to assume it and receives no cutover runtime actions.

## Exact AWS calls

| Phase | Call | Scope and purpose |
|---|---|---|
| identity | `sts:GetCallerIdentity` | Refuse the wrong account, region, or assumed role. |
| service | `ecs:DescribeServices` | Exact cluster/service only; capture task definition and stability. |
| task definitions | `ecs:DescribeTaskDefinition` | Read backend/admin definitions, tags, route flags, and secret references. |
| consumer inventory | `ecs:ListTaskDefinitions`, `ecs:ListServices`, `events:ListRules`, `events:ListTargetsByRule` | Fail on an unreviewed service, schedule, sidecar, or database consumer. |
| receipt proof | `ecs:DescribeTasks` | Corroborate the fresh verification receipt against a stopped admin task with exit code zero. |
| secret metadata | `secretsmanager:DescribeSecret` | Exact app secret ARN pattern; no secret value. |
| registration | `ecs:RegisterTaskDefinition` | Only `mscqr-staging-backend:*`, after structural proof that only `DATABASE_URL.valueFrom` changed. |
| role delegation | `iam:PassRole` | Exact staging task/execution roles and only `ecs-tasks.amazonaws.com`. |
| cutover/rollback | `ecs:UpdateService` | Exact staging backend service and backend task-definition family. |
| runtime proof | `ecs:ListTasks`, `ecs:ExecuteCommand` | Sole running task for the exact service; fixed `current_database()/current_user` SELECT in container `backend`. |
| Exec encryption | `kms:GenerateDataKey` | Terraform-created staging ECS Exec KMS key only. |

The ECS waiter is backed by `DescribeServices`. Health and smoke checks use credential-free `curl`, not AWS APIs. The role has no Lambda invocation, `ecs:RunTask`, secret-value read/write, RDS action, PostgreSQL mutation, RLS action, or production resource. SSM Messages channel permissions remain on the ECS task role; the human caller does not require them.

## Unavoidable wildcard resources

`Resource: "*"` exists only for APIs whose authorization model has no usable per-resource ARN in this workflow:

- `sts:GetCallerIdentity`;
- `ecs:DescribeTaskDefinition`;
- `ecs:ListServices`, constrained to the exact cluster and region;
- `ecs:ListTaskDefinitions`, region-constrained with the controller's fixed staging family prefix;
- `ecs:ListTasks`, constrained to the exact cluster and region for Fargate;
- `events:ListRules`, region-constrained with the controller's fixed staging name prefix.

All other entries use exact ARNs or staging-only ARN patterns. The JSON runtime template retains `${STAGING_APP_DATABASE_SECRET_ARN_PATTERN}` for operator substitution so a complete secret ARN shape is not committed; Terraform constructs the exact staging app-secret pattern from account and region variables. `RegisterTaskDefinition` uses `task-definition/mscqr-staging-backend:*`; `UpdateService` uses the exact service plus task-definition-family condition.

## Endpoint discovery

```bash
AWS_PROFILE='mscqr-staging-plan' \
AWS_REGION='eu-west-2' \
scripts/aws/discover-staging-endpoints.sh
```

The script requires the exact `mscqr-staging-terraform-plan-role`, makes read-only calls only, emits sanitized JSON, and fails unless exactly one reviewed staging origin is attached to the exact ECS service and resolves in DNS.

Live read-only discovery on 2026-07-13 found:

- active internet-facing ALB `mscqr-stg-alb-euw2`;
- base URL `http://mscqr-stg-alb-euw2-1729860344.eu-west-2.elb.amazonaws.com`;
- HTTP listener `:80` forwarding to `mscqr-stg-backend-tg-euw2`;
- ECS attachment to container `backend:4000`;
- target-group health path `/health/live`;
- no API Gateway candidate, staging Route 53 record, or staging CloudFront distribution.

The earlier bare `aws elbv2 describe-load-balancers` result used the wrong/implicit credential context. Explicit `--profile mscqr-staging-plan --region eu-west-2` discovers the ECS attachment and ALB. Terraform already declared these resources and exported `staging_alb_dns_name`; this change adds `staging_base_url` and `staging_health_url`. No hostname was invented.

## Cutover safety

Cutover no longer invokes the database-role broker. `verify --apply` writes a sanitized `verification-receipt.json`. Cutover requires the receipt to be less than 45 minutes old, bound to the current backend task definition, complete for app/migrator/RLS-read roles, false for every RLS route flag, and corroborated by the stopped executor task while ECS still exposes it.

Before dry-run or apply, the controller requires the exact cutover role, confirms the current admin-secret classification, accepts only a mode-`0600` generated receipt under `scratch/staging-database-role-credentials-*`, rejects placeholder/example URLs, requires one staging-marked origin for health and smoke, resolves the host, performs credential-free checks, reads only app-secret metadata, and proves the sole proposed task-definition change. Dry-run reports these facts plus `mutatesAws: false`; it explicitly distinguishes live read-preflight proof from apply-only permissions that were statically reviewed but not executed. Apply retains automatic rollback to the captured prior revision.

## Exact next live bootstrap commands

These commands require separate approval and were not run by this change.

Attach the source-user assume policy after creating the dedicated user and enrolling MFA through the reviewed IAM bootstrap process:

```bash
aws iam put-user-policy \
  --profile '<approved-iam-bootstrap-profile>' \
  --user-name 'mscqr-staging-database-role-cutover-user' \
  --policy-name 'AssumeMscqrStagingDatabaseRoleCutover' \
  --policy-document 'file://documents/ops/iam/MSCQR_STAGING_DATABASE_ROLE_CUTOVER_ASSUME_ROLE_POLICY_2026-07-13.json'
```

Review a Terraform plan, then apply only after separate approval:

```bash
AWS_PROFILE='mscqr-staging-terraform-apply' AWS_REGION='eu-west-2' \
terraform -chdir=infra/terraform/staging-api plan

AWS_PROFILE='mscqr-staging-terraform-apply' AWS_REGION='eu-west-2' \
terraform -chdir=infra/terraform/staging-api apply
```

Configure the profile after MFA enrollment:

```ini
[profile mscqr-staging-database-role-cutover]
role_arn = arn:aws:iam::368992683803:role/mscqr-staging-database-role-cutover
source_profile = mscqr-staging-database-role-cutover-user
role_session_name = reviewed-database-role-cutover
mfa_serial = <dedicated-cutover-user-mfa-device-arn>
region = eu-west-2
```

Re-run the complete permission matrix to emit a fresh receipt:

```bash
export AWS_PROFILE='mscqr-staging-database-role-operator'
export AWS_REGION='eu-west-2'
export MSCQR_STAGING_VPC_EXECUTOR='disposable-ecs-admin-task'
export MSCQR_STAGING_DB_ADMIN_TASK_DEFINITION_ARN='arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-staging-database-role-admin:2'
export MSCQR_STAGING_DATABASE_VERIFY_CONFIRM='MSCQR_VERIFY_STAGING_DATABASE_ROLE_CREDENTIALS'
scripts/aws/verify-staging-database-role-permissions.sh --apply
```

Use the exact receipt path printed by verification, then run the non-mutating preview:

```bash
export AWS_PROFILE='mscqr-staging-database-role-cutover'
export AWS_REGION='eu-west-2'
export MSCQR_STAGING_DATABASE_ROLE_VERIFICATION_RECEIPT='scratch/staging-database-role-credentials-REPLACE_WITH_PRINTED_TIMESTAMP/verification-receipt.json'
export MSCQR_STAGING_HEALTH_URL='http://mscqr-stg-alb-euw2-1729860344.eu-west-2.elb.amazonaws.com/health/live'
export MSCQR_STAGING_REPRESENTATIVE_SMOKE_URLS='http://mscqr-stg-alb-euw2-1729860344.eu-west-2.elb.amazonaws.com/health/ready'
scripts/aws/cutover-staging-ecs-database-role.sh
```

Do not type the receipt-path marker literally. Only after reviewing dry-run JSON should a separately approved operator add `--apply` and `MSCQR_STAGING_ECS_DATABASE_ROLE_CUTOVER_CONFIRM=MSCQR_CUTOVER_STAGING_ECS_TO_APP_DATABASE_ROLE`.

## Current blockers and recommendations

- The dedicated source user, MFA device, Terraform-managed role, and local profile do not yet exist live.
- The earlier successful permission matrix predates the new receipt format and must be rerun.
- Local `terraform output` remains blocked by MFA-gated provider assumption; endpoint discovery avoids Terraform state and the verified admin task ARN is documented above.
- GitHub staging variables could not be refreshed because local GitHub authentication is invalid; historical production-facing smoke variables must not be used.
- The endpoint is HTTP-only. Add ACM-backed HTTPS and dedicated staging DNS next, then require HTTPS in the validator.
- Add CloudTrail/EventBridge alarms for cutover-role registration, service update, Exec, and PassRole events.
- Continuously detect any staging runtime task definition that references the admin database secret.
- Move the admin executor to a minimal digest-pinned image and use signed, write-once verification receipts.
- Increase backend desired count to two before production-scale adoption so deployments preserve capacity.
