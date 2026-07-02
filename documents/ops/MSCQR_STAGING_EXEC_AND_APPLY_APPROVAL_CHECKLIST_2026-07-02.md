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
- [ ] `npm run check:staging-terraform` passed locally or in CI.
- [ ] `npm run check:staging-iam-policies` passed locally or in CI.
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
- [ ] No production DB, Redis, S3 bucket, ECS cluster, ALB, subnet, security group, or Secrets Manager ARN is referenced.
- [ ] `allowed_operator_cidrs` are narrow, reviewed, and do not include `0.0.0.0/0`, `::/0`, or broad office/VPN ranges without written justification.
- [ ] ECS Exec logging is configured with `logging = "OVERRIDE"`.
- [ ] ECS Exec CloudWatch log group is `/aws/ecs/mscqr-staging/exec`.
- [ ] ECS Exec log retention is at least 30 days and not more than the approved staging retention window.
- [ ] ECS Exec CloudWatch log group is encrypted with a staging KMS key.
- [ ] KMS key rotation is enabled and key deletion window is not shortened.
- [ ] Operator IAM policy review is complete and `ecs:ExecuteCommand` remains staging-only.
- [ ] Rollback plan is written, including Terraform rollback, ECS desired count handling, and evidence preservation.
- [ ] Cost limit is understood for ALB, ECS, RDS, Redis, CloudWatch Logs, and KMS.
- [ ] Approval record includes approver, ticket or evidence ID, date, exact branch/commit, and exact plan command.

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
