# Production Green Stage B Terraform

This production-only root creates fixed task definitions, their roles and log groups, a no-default-egress task security group, the broker Lambda/`reviewed` alias, its replay table, and its alias-qualified invocation permission. It creates no ECS service, task run, database, secret value, ALB, listener, target group, DNS, or traffic resource.

Use only an MFA-backed non-root `mscqr-production-release-deployer` session with the dedicated encrypted production state backend and `production` workspace. Supply Stage A output ARNs/IDs and secret ARNs only through an untracked absolute tfvars file. The four image inputs must be ECR `@sha256` references; the release, source-contract, migration, and package checksum inputs are mandatory.

Plan only:

```sh
MSCQR_STAGE_B_PLAN_ENABLED=true MSCQR_STAGE_B_PLAN_CONFIRM=MSCQR_GENERATE_STAGE_B_PLAN_ONLY \
  node scripts/plan-production-green-stage-b.mjs /absolute/private/stage-b.tfvars
```

Review the saved JSON plan. Stop on any delete or any resource outside the listed control-plane types. A separately approved operator runbook must authorize `terraform apply`; this repository does not provide an apply wrapper.
