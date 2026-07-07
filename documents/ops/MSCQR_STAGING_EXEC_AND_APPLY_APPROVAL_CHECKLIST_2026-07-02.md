# MSCQR Staging Exec and Apply Approval Checklist

Date: 2026-07-02
Scope: staging API Terraform and controlled ECS Exec only.

This checklist is preparation-only. It does not authorize production changes, database mutation outside approved staging tasks, deployment, global RLS enablement, or new runtime route wiring.

## Hard Boundaries

- Do not use root credentials for `terraform apply` or `ecs execute-command`.
- Do not point Terraform, seed scripts, collectors, or ECS Exec commands at production DB, Redis, S3, ECS, ALB, or Secrets Manager resources.
- Do not print tokens, private keys, passwords, connection strings, raw secret values, or full sensitive response bodies into terminal output or evidence.
- Do not run production/global/table RLS enablement from this workflow.
- Do not use ECS Exec as a normal shell. It is break-glass or controlled staging migration/seed access only.

## Before Terraform Apply

- [ ] PR is approved and all required checks are green.
- [ ] Branch protection or a repository ruleset is enabled and verified for `main` before any staging Terraform plan/apply review continues. See `documents/ops/MSCQR_GITHUB_BRANCH_PROTECTION_REQUIRED_CHECKS_2026-07-02.md`.
- [ ] Required status check is enabled and verified: `Staging Infra Validation/Terraform staging validate`.
- [ ] Required status check is enabled and verified: `Staging Infra Validation/Staging IAM policy lint`.
- [ ] First staging plan was generated through `npm run plan:staging-terraform`; raw first-plan commands are not accepted. See `documents/ops/MSCQR_STAGING_TERRAFORM_PLAN_RUNBOOK_2026-07-02.md`.
- [ ] Plan evidence is stored privately under `.terraform-plans/staging/` or the approved private evidence store, not committed to git.
- [ ] Private tfvars were prepared with `documents/ops/MSCQR_STAGING_PRIVATE_TFVARS_PREPARATION_2026-07-02.md` and passed `npm run check:staging-private-inputs`.
- [ ] `npm run check:staging-private-inputs` reported zero tracked private tfvars and zero tracked `.terraform-plans/` artifacts.
- [ ] Cost evidence was created after the first real plan using `documents/ops/MSCQR_STAGING_COST_ESTIMATION_EVIDENCE_2026-07-02.md`.
- [ ] `terraform apply` remains forbidden until a separate apply approval PR/checklist is approved.
- [ ] `npm run check:staging-terraform` passed locally or in CI.
- [ ] `npm run check:staging-iam-policies` passed locally or in CI.
- [ ] `npm run check:staging-aws-identity` passed with a staging Terraform provisioning role.
- [ ] CI result is understood as syntax/safety validation only; it does not prove AWS deployability.
- [ ] `terraform init -backend=false` completed in the same checkout before validation.
- [ ] `terraform fmt -check` and `terraform validate` passed for `infra/terraform/staging-api`.
- [ ] Validation did not depend on stale local `.terraform` state; if provider schema loading failed, the provider cache was reinstalled and validation was rerun.
- [ ] A human-reviewed `terraform plan` exists and is attached to the approval record.
- [ ] Apply approval is not granted until the reviewed plan artifact is attached and explicitly approved.
- [ ] First real plan was run only with the reviewed least-privilege staging provisioning role.
- [ ] The plan was generated with `allowed_account_ids = [var.account_id]` still present in `providers.tf`.
- [ ] AWS caller identity was recorded and is not the account root user.
- [ ] The caller assumed a least-privilege staging provisioning role explicitly.
- [ ] The state/backend decision is documented, including where state is stored and who can read or write it.
- [ ] Every planned resource name is staging or stg scoped.
- [ ] No planned resource name looks production-scoped; any prod/production-looking resource name blocks apply.
- [ ] No production DB, Redis, S3 bucket, ECS cluster, ALB, subnet, security group, or Secrets Manager ARN is referenced.
- [ ] `allowed_operator_cidrs` are narrow, reviewed, and do not include `0.0.0.0/0`, `::/0`, or broad office/VPN ranges without written justification.
- [ ] The plan has `destroy = 0`; any destroy count blocks apply unless a separate explicit destroy approval record exists.
- [ ] No security group ingress rule allows `0.0.0.0/0`; any IPv4 world-open ingress blocks apply.
- [ ] No security group ingress rule allows `::/0`; any IPv6 world-open ingress blocks apply.
- [ ] ALB ingress is restricted to reviewed operator CIDRs only.
- [ ] ALB egress is restricted to the staging ECS security group on port 4000.
- [ ] ECS ingress is restricted to the staging ALB security group on port 4000.
- [ ] DB ingress is restricted to the staging ECS security group on port 5432.
- [ ] Redis ingress is restricted to the staging ECS security group on port 6379.
- [ ] ECS broad egress, if still present, is accepted only as temporary staging outbound access for ECR, Secrets Manager, CloudWatch Logs, STS, package endpoints, and AWS APIs; it is not inbound exposure.
- [ ] ECS Exec logging is configured with `logging = "OVERRIDE"`.
- [ ] ECS Exec CloudWatch log group is `/aws/ecs/mscqr-staging/exec`.
- [ ] ECS Exec log retention is at least 30 days and not more than the approved staging retention window.
- [ ] ECS Exec CloudWatch log group is encrypted with a staging KMS key.
- [ ] KMS key rotation is enabled and key deletion window is not shortened.
- [ ] Operator IAM policy review is complete and `ecs:ExecuteCommand` remains staging-only.
- [ ] Rollback plan is written, including Terraform rollback, ECS desired count handling, and evidence preservation.
- [ ] Cost limit is understood for ALB, ECS, RDS, Redis, CloudWatch Logs, and KMS.
- [ ] Approval record includes approver, ticket or evidence ID, date, exact branch/commit, and exact plan command.

## After Terraform Apply

- [ ] Apply was run only after separate human approval; this checklist entry records the result and does not authorize apply by itself.
- [ ] Terraform output review confirms staging RDS endpoint/address/port and staging Redis primary endpoint/address/port exist.
- [ ] Terraform output review confirms no password, token, or full connection URL was emitted.
- [ ] Terraform state location remains private and access controlled.
- [ ] Terraform state does not contain the final `DATABASE_URL` or final `REDIS_URL` written by the post-apply sync script.
- [ ] `node scripts/sync-staging-runtime-secrets.mjs --dry-run` passed with `AWS_PROFILE="<staging-provisioning-profile>"` and `AWS_REGION="eu-west-2"`.
- [ ] Dry-run evidence printed only redacted URL previews and did not print passwords, tokens, full secret values, private tfvars, Terraform state, or plan artifacts.
- [ ] Runtime secret sync was approved after dry-run evidence review.
- [ ] Runtime secret sync used `MSCQR_STAGING_SECRET_SYNC_ENABLED=true` and `MSCQR_STAGING_SECRET_SYNC_CONFIRM=MSCQR_UPDATE_STAGING_RUNTIME_SECRETS`.
- [ ] Runtime secret sync updated only `mscqr/staging/database-url` and `mscqr/staging/redis-url`.
- [ ] `DATABASE_URL` was constructed from staging RDS endpoint metadata plus an approved password source and was written only to Secrets Manager.
- [ ] `REDIS_URL` was constructed from the staging Valkey endpoint and port and was written only to Secrets Manager.
- [ ] Redis auth status is recorded. Current Terraform does not configure Redis auth; if no approved `MSCQR_STAGING_REDIS_PASSWORD` was supplied, the staging Redis URL is unauthenticated.
- [ ] ECS redeploy was approved after the two runtime secrets were updated.
- [ ] ECS redeploy used `MSCQR_STAGING_ECS_REDEPLOY_ENABLED=true` and `MSCQR_STAGING_ECS_REDEPLOY_CONFIRM=MSCQR_FORCE_STAGING_ECS_REDEPLOY`.
- [ ] Health check used only the reviewed staging ALB URL and did not use `mscqr.com` or a production hostname.
- [ ] Post-apply evidence records plan evidence, apply approval, secret sync redacted evidence, ECS redeploy evidence, and health check result without secrets.

## Before ECS Execute-Command

- [ ] Ticket, approval, or evidence ID exists for this ECS Exec session.
- [ ] Operator role is confirmed and root credentials are not active.
- [ ] Operator policy is staging-only and based on `documents/ops/iam/MSCQR_STAGING_ECS_EXEC_OPERATOR_POLICY_2026-07-02.json`.
- [ ] Target cluster is `mscqr-staging-euw2-main`.
- [ ] Target service is `mscqr-staging-backend-service-euw2`.
- [ ] Target task ARN belongs to the staging cluster and staging backend service.
- [ ] Target container is `backend`.
- [ ] Exact command is approved and pasted into the evidence record before execution.
- [ ] Command is non-interactive where possible and scoped to the approved migration, seed, or diagnostic.
- [ ] Command is not expected to print tokens, credentials, private keys, connection strings, OTP secrets, or raw customer data.
- [ ] No production task, cluster, service, database, Redis, or object storage resource will be touched.
- [ ] CloudTrail lookup path is recorded for `ecs:ExecuteCommand`.
- [ ] CloudWatch log group location is recorded as `/aws/ecs/mscqr-staging/exec`.
- [ ] Start time, end time, operator role ARN, task ARN, and command summary are recorded.
- [ ] Post-command CloudTrail review is complete.
- [ ] Post-command CloudWatch review is complete.
- [ ] Any unexpected output, error, or secret exposure risk is escalated and recorded.

## Evidence Fields

Record these fields in the associated ticket or evidence pack:

- Approval ID:
- Approver:
- Operator role ARN:
- AWS account ID:
- AWS region:
- Git branch and commit:
- Terraform plan artifact location:
- ECS cluster:
- ECS service:
- ECS task ARN:
- Command summary:
- CloudTrail event lookup:
- CloudWatch log group:
- Post-review result:
- Follow-up actions:

## CTO Recommendations

- Treat ECS Exec access as a temporary control plane, not an operating model. The scalable path is repeatable migrations, seed jobs, and one-shot task definitions that produce structured evidence without shell access.
- Add an EventBridge rule for `ExecuteCommand` CloudTrail events before routine staging usage, then send alerts to the operational channel and evidence ledger.
- Prefer a dedicated staging provisioning role and a separate break-glass operator role. Combining infrastructure apply and shell access in one role increases blast radius.
- Replace temporary broad ECS egress with VPC endpoints and prefix-list scoped rules before production reuse, then make broad ECS egress a plan-review blocker too.
