# Production Green Stage B Terraform

This production-only root creates fixed task definitions, Stage B-owned execution/candidate roles and log groups, the broker Lambda/numbered `reviewed` alias, its replay table, and its alias-qualified invocation permission. It creates no security group, ECS service, task run, database, secret value, ALB, listener, target group, DNS, or traffic resource.

Stage A exclusively owns `/ecs/mscqr-production/full-rls-green`, `/aws/lambda/mscqr-production-rls-approval-broker`, the executor task role, the executor security group, its database/AWS-endpoint/S3/DNS egress, and the green database security group. Stage B consumes the exact `stage_b_prerequisites` output and adds only separately managed executor and broker runtime policies; it never recreates or imports those Stage A resources.

Use only an MFA-backed non-root `mscqr-production-release-deployer` session with the dedicated encrypted production state backend and `production` workspace. Supply Stage A output ARNs/IDs and secret ARNs only through an untracked absolute tfvars file. Set `stage_a_executor_networking_ready=true` only after the reviewed Stage A egress is applied. The four image inputs must be ECR `@sha256` references; the release, source-contract, migration, and package checksum inputs are mandatory.

Plan only:

```sh
MSCQR_STAGE_B_PLAN_ENABLED=true MSCQR_STAGE_B_PLAN_CONFIRM=MSCQR_GENERATE_STAGE_B_PLAN_ONLY \
  node scripts/plan-production-green-stage-b.mjs /absolute/private/stage-b.tfvars
```

Review the saved JSON plan. Stop on any delete or any resource outside the listed control-plane types. A separately approved operator runbook must authorize `terraform apply`; this repository does not provide an apply wrapper.
