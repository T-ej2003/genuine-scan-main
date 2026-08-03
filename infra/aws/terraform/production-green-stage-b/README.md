# Production Green Stage B Terraform

This production-only root creates fixed task definitions, Stage B-owned execution/candidate roles and log groups, the broker Lambda/numbered `reviewed` alias, its replay table, and its alias-qualified invocation permission. It creates no security group, ECS service, task run, database, secret value, ALB, listener, target group, DNS, or traffic resource.

Stage A exclusively owns `/ecs/mscqr-production/full-rls-green`, `/aws/lambda/mscqr-production-rls-approval-broker`, the executor task role, the executor security group, its database/AWS-endpoint/S3/DNS egress, the green database security group, and the empty Phase 4 read-only-canary database URL handle. Stage B consumes the exact `stage_b_prerequisites` output, including `read_only_canary_database_secret_arn`, and adds only separately managed executor and broker runtime policies; it never recreates or imports those Stage A resources.

Use only an MFA-backed non-root `mscqr-production-release-deployer` session with the dedicated encrypted production state backend and `production` workspace. Generate the private tfvars file only with the source-controlled generator; the Stage-A prerequisite file must conform to [`stage-a-prerequisites.schema.json`](./stage-a-prerequisites.schema.json) and be an explicit reviewed input. Set `stage_a_executor_networking_ready=true` only after the reviewed Stage A egress is applied. The five image inputs must be ECR `@sha256` references; the release, source-contract, migration, and package checksum inputs are derived and mandatory.

The generator verifies the signed schema-v3 image evidence, derives all five Terraform image variables without digest reconstruction, derives retained definitions from the supplied production state backup, and atomically writes mode-0600 outputs only after validation. Do not use heredocs, inline scripts, copied tfvars, manual digest values, or post-generation edits.

```sh
npm run stage-b:generate-tfvars -- \
  --image-evidence /absolute/private/image-evidence.json \
  --image-evidence-signature /absolute/private/image-evidence.signature.json \
  --state-backup /absolute/private/production-state.json \
  --stage-a-input /absolute/private/stage-a-prerequisites.json \
  --broker-package /absolute/private/production-green-stage-b-broker.zip \
  --tooling-sha "$TOOLING_SHA" \
  --tooling-tree-sha256 "$TOOLING_TREE_SHA256" \
  --image-release-sha "$IMAGE_RELEASE_SHA" \
  --workflow-run-id "$WORKFLOW_RUN_ID" \
  --canonical-artifact-sha256 "$CANONICAL_ARTIFACT_SHA256" \
  --workspace production \
  --output /absolute/private/production-green-stage-b.tfvars \
  --binding-report /absolute/private/production-green-stage-b-tfvars.binding.json
```

Record the generated tfvars SHA and binding-report SHA. Closure and the apply wrapper must receive both files and the binding-report SHA; a modified tfvars file or missing report is rejected.

## Generator input inventory

| Terraform inputs | Authoritative source | Emitted/logged |
| --- | --- | --- |
| `account_id`, `aws_region`, image-release identity | reviewed Stage B contract and signed image evidence | tfvars and binding report |
| `backend_image`, `worker_image`, `executor_image`, `canary_image`, `read_only_canary_image` | exact signed schema-v3 image records; the read-only canary intentionally reuses the signed `rls-canary` record | tfvars and binding report; digest only in safe report metadata |
| `canonical_image_evidence_sha256` | canonical signed report | tfvars and binding report |
| `tooling_sha`, tooling-tree digest | explicit protected-main identifiers | tfvars / binding report |
| Stage-A VPC, subnet, cluster, security-group, role, log-group, secret, approval, and receipt inputs | explicit reviewed prerequisite JSON validated by `stage-a-prerequisites.schema.json` | tfvars; only its hash is reported |
| `broker_package_path` | explicit output of the reviewed broker package builder | tfvars; raw and base64 SHA-256 in report |
| `source_contract_sha256`, `migration_set_digest`, `package_checksum_sha256` | source-controlled `generated/checksums.json` bytes and fields | tfvars and binding report |
| retained candidate/executor maps | supplied production Terraform state backup after lineage, serial, family, revision, broker policy, and address checks | tfvars and retained counts in report |

`stage_a_executor_networking_ready` and `log_retention_days` are contract values; the former must be proven true in the prerequisite JSON and the latter remains the reviewed Terraform default of 30 days. No sensitive secret values are accepted or emitted.

The release role's backend access is defined by `documents/ops/iam/MSCQRProductionGreenStageBWorkspaceState-v2.json`: it uses `s3:GetBucketLocation`, `s3:ListBucket` only with Terraform's exact `env:/` workspace prefix, exact production state read/write, and exact `.tflock` lifecycle access. `HeadBucket`, state deletion, the configured default key, and unrestricted bucket listing are not deployment gates or permissions.

Plan only:

```sh
MSCQR_STAGE_B_PLAN_ENABLED=true MSCQR_STAGE_B_PLAN_CONFIRM=MSCQR_GENERATE_STAGE_B_PLAN_ONLY \
  node scripts/plan-production-green-stage-b.mjs /absolute/private/production-green-stage-b.tfvars \
  --binding-report /absolute/private/production-green-stage-b-tfvars.binding.json \
  --binding-report-sha256 "$TFVARS_BINDING_REPORT_SHA256" \
  --tooling-tree-sha256 "$TOOLING_TREE_SHA256" \
  --image-release-sha "$IMAGE_RELEASE_SHA"
```

Review the saved JSON plan. Stop on any delete or any resource outside the listed control-plane types. A separately approved operator runbook must authorize `terraform apply`; this repository does not provide an apply wrapper.
