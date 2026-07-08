# MSCQR Staging Terraform Plan Runbook

Date: 2026-07-02
Scope: first staging Terraform plan for `infra/terraform/staging-api`.

This runbook is plan-only. It does not authorize `terraform apply`, AWS
mutation, deployment, production database access, production/global/table RLS
enablement, runtime route wiring, or committed private Terraform inputs.

## Purpose

Generate the first staging Terraform plan through a repeatable wrapper before
any future staging apply approval. The wrapper creates private local evidence
under `.terraform-plans/staging/` and prints only a safe summary.

## Preconditions

- PR #96 required GitHub checks are configured and verified for `main` or for a
  path-scoped ruleset.
- The operator has assumed the least-privilege staging Terraform plan role for
  plan generation only.
- AWS caller identity is verified with `npm run check:staging-aws-identity`.
- Root identity is not active.
- The AWS account ID is the approved staging account, default `368992683803`,
  unless `STAGING_AWS_ACCOUNT_ID` is explicitly reviewed for a staging-only
  exception.
- The region is `eu-west-2` unless `STAGING_AWS_REGION` is explicitly reviewed
  for a staging-only exception.
- No production account, production role, production DB, production Redis,
  production S3, production ECS, production ALB, or production Secrets Manager
  reference is present.
- Private Terraform inputs are prepared outside committed evidence through only:
  - `infra/terraform/staging-api/staging.auto.tfvars`
  - `infra/terraform/staging-api/*.local.tfvars`
  - `TF_VAR_*` environment variables
- Private inputs include staging-only VPC/subnet IDs, narrow operator CIDRs,
  an immutable staging backend image URI, and staging Secrets Manager ARNs under
  `mscqr/staging/*`.
- Private inputs pass `npm run check:staging-private-inputs`, including zero
  tracked private tfvars and zero tracked `.terraform-plans/` artifacts.

## Commands

Run from the repository root:

```sh
npm run check:staging-terraform
npm run check:staging-iam-policies
npm run check:staging-private-inputs
npm run check:staging-aws-identity
MSCQR_STAGING_TERRAFORM_PLAN_ENABLED=true MSCQR_STAGING_TERRAFORM_PLAN_CONFIRM=MSCQR_GENERATE_STAGING_PLAN_ONLY npm run plan:staging-terraform
```

The wrapper runs:

```sh
terraform -chdir=infra/terraform/staging-api init
terraform -chdir=infra/terraform/staging-api fmt -check
terraform -chdir=infra/terraform/staging-api validate
terraform -chdir=infra/terraform/staging-api plan -out=<local private plan path>
```

Do not run raw `terraform plan` for the first staging plan. Use the wrapper so
confirmation gates, identity checks, private input checks, ignored evidence
paths, and safe summary output stay consistent.

The plan cannot proceed until private inputs pass
`npm run check:staging-private-inputs`. Prepare those inputs using
`documents/ops/MSCQR_STAGING_PRIVATE_TFVARS_PREPARATION_2026-07-02.md`.

## Private Evidence To Save

Save these privately outside the repository or in the ignored
`.terraform-plans/staging/` directory:

- Sanitized plan summary JSON.
- Terraform plan text, only after review confirms it is safe for the private
  evidence store.
- AWS caller identity safe summary.
- Screenshot or export proving the PR #96 required status checks are enabled.
- Private cost estimate notes after the first real plan is generated.

## Evidence Not To Commit

Do not commit:

- Terraform plan binary.
- Terraform plan text, summary JSON, or error evidence from `.terraform-plans/`.
- Real tfvars.
- Subnet IDs if considered private.
- VPC IDs if considered private.
- Operator public IPs.
- Tokens, secrets, passwords, private keys, connection strings, session tokens,
  or raw credential material.

## No-Apply Policy

This runbook stops at plan generation. `terraform apply` is forbidden here even
if the plan is clean. Apply approval requires an apply-specific approval record,
checklist, evidence review, explicit human approval, and the separate staging
apply role described in
`documents/ops/MSCQR_STAGING_APPLY_ROLE_SETUP_2026-07-08.md`.

Cost evidence must be created after the first real plan and before any future
apply approval. Use
`documents/ops/MSCQR_STAGING_COST_ESTIMATION_EVIDENCE_2026-07-02.md`.

## End-to-End Apply Sequence

Use this sequence when the plan has passed review and a separate human apply
approval exists:

A. Generate plan-only evidence through
`MSCQR_STAGING_TERRAFORM_PLAN_ENABLED=true
MSCQR_STAGING_TERRAFORM_PLAN_CONFIRM=MSCQR_GENERATE_STAGING_PLAN_ONLY npm run
plan:staging-terraform`.

B. Record separate human apply approval with reviewed plan counts, security
group evidence, private-input guard evidence, identity guard evidence, cost
evidence, rollback notes, and the exact commit.

C. Select the separate staging apply role, not the plan role. Verify it before
the approved apply window. The role must have the permissions boundary template
`documents/ops/iam/MSCQR_STAGING_TERRAFORM_APPLY_PERMISSIONS_BOUNDARY_2026-07-08.json`
attached before this step:

```sh
set +x
AWS_PROFILE="<staging-apply-profile>" \
AWS_REGION="eu-west-2" \
npm run check:staging-aws-apply-identity
```

Then apply only the exact reviewed saved plan through the wrapper:

```sh
set +x
AWS_PROFILE="<staging-apply-profile>" \
AWS_REGION="eu-west-2" \
MSCQR_STAGING_TERRAFORM_APPLY_ENABLED=true \
MSCQR_STAGING_TERRAFORM_APPLY_CONFIRM=MSCQR_APPLY_STAGING_TERRAFORM_ONCE \
MSCQR_STAGING_TERRAFORM_APPLY_EXPECTED_ADD_COUNT=38 \
MSCQR_STAGING_TERRAFORM_APPLY_EXPECTED_CHANGE_COUNT=0 \
npm run apply:staging-terraform -- ".terraform-plans/staging/<approved-plan>.tfplan"
```

Do not run raw `terraform apply`. The wrapper refuses missing gates, root,
non-`eu-west-2`, non-assumed-role identity, plan/read roles, production-looking
role/profile names, missing saved plan evidence, destroy actions, unexpected
change counts, world-open ingress, secret URL patterns, production-looking plan
text, raw apply options, and `TF_CLI_ARGS*` overrides. This runbook records the
approved sequence; this PR does not authorize execution of that command.

D. Sync the staging runtime endpoint secrets with the post-apply script. First
run the dry-run:

```sh
set +x
AWS_PROFILE="<staging-provisioning-profile>" \
AWS_REGION="eu-west-2" \
node scripts/sync-staging-runtime-secrets.mjs --dry-run
```

Then, only after the dry-run evidence is accepted:

```sh
set +x
AWS_PROFILE="<staging-provisioning-profile>" \
AWS_REGION="eu-west-2" \
MSCQR_STAGING_SECRET_SYNC_ENABLED=true \
MSCQR_STAGING_SECRET_SYNC_CONFIRM=MSCQR_UPDATE_STAGING_RUNTIME_SECRETS \
node scripts/sync-staging-runtime-secrets.mjs --sync-secrets
```

The script updates only `mscqr/staging/database-url` and
`mscqr/staging/redis-url`. It refuses root, non-`eu-west-2`, production-looking
secret names, DB identifiers, endpoints, hosts, URLs, and `mscqr.com` domains.
It prints redacted evidence only.
Current Terraform does not configure Redis auth or in-transit TLS; record that
temporary staging limitation in the apply evidence until the cache is upgraded.

E. Force a new staging ECS deployment only after secret sync:

```sh
set +x
AWS_PROFILE="<staging-provisioning-profile>" \
AWS_REGION="eu-west-2" \
MSCQR_STAGING_ECS_REDEPLOY_ENABLED=true \
MSCQR_STAGING_ECS_REDEPLOY_CONFIRM=MSCQR_FORCE_STAGING_ECS_REDEPLOY \
node scripts/sync-staging-runtime-secrets.mjs --force-ecs-redeploy
```

F. Run the staging health check against the reviewed staging ALB URL. Do not use
`mscqr.com`, production CloudFront, production ALB, production RDS, production
Redis, or production Secrets Manager values as staging evidence.

G. Disable or delete any long-lived access keys for
`mscqr-staging-apply-operator` after the controlled apply window and record the
key shutdown evidence.

Terraform outputs and state may contain staging endpoint hostnames, ports,
resource identifiers, database name, and database username. They must not
contain the DB password, the final `DATABASE_URL`, the final `REDIS_URL`, Redis
credentials, private tfvars, or plan artifacts committed to git.

## Human Review Before Any Future Apply

Before any future apply approval is considered, a reviewer must confirm:

- Resource names are staging or stg scoped.
- Account ID is correct.
- No production DB, Redis, S3, ECS, ALB, subnet, security group, or Secrets
  Manager reference appears.
- Any production-looking resource name is an apply blocker.
- Any planned destroy action is an apply blocker.
- Any `0.0.0.0/0` ingress or `::/0` ingress is an apply blocker.
- ALB ingress is restricted to reviewed operator CIDRs only.
- ALB egress is restricted to the staging ECS security group on port 4000.
- ECS ingress is restricted to the staging ALB security group on port 4000.
- DB ingress is restricted to the staging ECS security group on port 5432.
- Redis ingress is restricted to the staging ECS security group on port 6379.
- ECS broad egress, if still present, is documented as temporary staging-only
  outbound access for ECR, Secrets Manager, CloudWatch Logs, STS, package
  endpoints, and AWS APIs. It is not inbound exposure.
- ECS Exec logging is present.
- ECS Exec CloudWatch logging uses KMS-backed encryption.
- KMS key and rotation settings are present.
- Cost estimate is accepted for ALB, ECS, RDS, Redis, CloudWatch Logs, KMS, and
  S3.
- The apply role setup runbook is complete and the plan role is not used for
  apply.
- The apply permissions boundary template is attached to the apply role.
- `npm run check:staging-aws-apply-identity` passed for the selected apply
  profile.
- The apply command uses `npm run apply:staging-terraform` with the exact saved
  `.tfplan` path and explicit gates.
- The saved plan summary has `applyAllowed=false`, `destroy=0`, and the reviewed
  add/change counts.
- Plan text does not contain `DATABASE_URL`, `REDIS_URL`, `postgres://`,
  `postgresql://`, or `redis://`.

## Blocked Plan Handling

If credentials, private tfvars, VPC IDs, subnet IDs, staging secret ARNs, or
other private inputs are missing, do not fake a plan. The wrapper exits with
`blocked_before_plan` and prints the missing private input names without
printing values.

The PR can still land the wrapper and runbook when live planning is blocked by
missing private inputs.

## Rollback Note

A Terraform plan does not mutate AWS and has no infrastructure rollback step.
Rollback for an actual apply belongs to a future apply runbook and must include
state handling, resource rollback, and evidence preservation.

## CTO Recommendations

- Treat the first staging plan as a governance artifact, not just a Terraform
  command. The reusable wrapper gives auditability before any AWS mutation is
  allowed.
- Add a future cost-estimation step that consumes the generated plan privately
  and stores only sanitized cost totals in the approval record.
- Keep real networking inputs and operator CIDRs outside git permanently; use a
  secrets manager, secure runbook vault, or approved local operator store for
  plan-only execution.
- Replace temporary broad ECS egress with private VPC endpoints and managed
  prefix-list scoped egress before this staging pattern is promoted to a
  production baseline.
