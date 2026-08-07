# Production Green Stage B Terraform

This production-only root creates fixed task definitions, Stage B-owned execution/candidate roles and log groups, the broker Lambda/numbered `reviewed` alias, its replay table, and its alias-qualified invocation permission. It creates no security group, ECS service, task run, database, secret value, ALB, listener, target group, DNS, or traffic resource.

Stage A exclusively owns `/ecs/mscqr-production/full-rls-green`, `/aws/lambda/mscqr-production-rls-approval-broker`, the executor task role, the executor security group, its database/AWS-endpoint/S3/DNS egress, the green database security group, and the empty Phase 4 read-only-canary database URL handle. Stage B consumes the exact `stage_b_prerequisites` output, including `read_only_canary_database_secret_arn`, and adds only separately managed executor and broker runtime policies; it never recreates or imports those Stage A resources.

Use only an MFA-backed non-root `mscqr-production-release-deployer` session with the dedicated encrypted production state backend configured directly to the existing production state key and `TF_WORKSPACE=default`. The explicit `deployment_environment = "production"` variable retains the environment guard without workspace indirection. Generate the Stage-A prerequisite artifact first from the exact Stage-A state backup plus read-only live networking evidence; do not construct it by hand. It must conform to [`stage-a-prerequisites.schema.json`](./stage-a-prerequisites.schema.json), bind the exact Stage-A object, lineage, serial, SHA and tooling identity, and prove private multi-AZ NAT routing. Its recorded lineage, serial, and SHA must exactly equal the parsed bound backup; the binding report records those parsed backup values. Stage A (`02afb75a-f902-ab8a-f4c1-751d4aef7837`, serial >=35) and Stage B (`4e438e59-8b8b-194d-030c-5ede0c26344a`, serial >=76) state contracts are independent and cannot be substituted. The five image inputs must be ECR `@sha256` references; the release, source-contract, migration, and package checksum inputs are derived and mandatory.

The generator emits canonical HCL tfvars only to an absolute `.tfvars` path, records the format and filename in the binding report, verifies the signed schema-v3 image evidence, derives all five Terraform image variables without digest reconstruction, derives retained definitions from the supplied production state backup, and atomically writes mode-0600 outputs only after validation. Do not use `.json`/`.tfvars.json` names, heredocs, inline scripts, copied tfvars, manual digest values, or post-generation edits.

```sh
node scripts/aws/generate-production-green-stage-a-prerequisites.mjs \
  --stage-a-state-backup /absolute/private/production-stage-a-state.json \
  --stage-a-state-object mscqr/production/rls-green/stage-a/terraform.tfstate \
  --tooling-sha "$TOOLING_SHA" \
  --tooling-tree-sha256 "$TOOLING_TREE_SHA256" \
  --output /absolute/private/stage-a-prerequisites.json

npm run stage-b:generate-tfvars -- \
  --image-evidence /absolute/private/image-evidence.json \
  --image-evidence-signature /absolute/private/image-evidence.signature.json \
  --state-backup /absolute/private/production-state.json \
  --stage-a-input /absolute/private/stage-a-prerequisites.json \
  --stage-a-state-backup /absolute/private/production-stage-a-state.json \
  --broker-package /absolute/private/production-green-stage-b-broker.zip \
  --tooling-sha "$TOOLING_SHA" \
  --tooling-tree-sha256 "$TOOLING_TREE_SHA256" \
  --image-release-sha "$IMAGE_RELEASE_SHA" \
  --workflow-run-id "$WORKFLOW_RUN_ID" \
  --canonical-artifact-sha256 "$CANONICAL_ARTIFACT_SHA256" \
  --environment production \
  --output /absolute/private/production-green-stage-b.tfvars \
  --binding-report /absolute/private/production-green-stage-b-tfvars.binding.json
```

Build the broker package first with the protected-main identities. The reviewed packager writes the ZIP and its mode-0600 canonical manifest as one transactional pair; both hashes are required downstream.

```sh
node scripts/aws/package-production-green-stage-b-broker.mjs \
  /absolute/private/production-green-stage-b-broker.zip \
  --tooling-sha "$TOOLING_SHA" \
  --tooling-tree-sha256 "$TOOLING_TREE_SHA256"
```

The manifest is written beside the ZIP as `broker.zip.manifest.json` and fixes entry order, timestamps (`1980-01-01T00:00:00Z`), modes, DEFLATE level 9, lockfile/source/contract identities, raw ZIP SHA-256, and `SHA256(Buffer.from(zipBytes.toString("base64")))` rendered as lowercase hex for `base64Sha256`. The shared validator loads the source-controlled manifest schema, recomputes lockfile/source/contract provenance, and compares every manifest entry to the ZIP central directory and extracted bytes. The packager rejects symlinks, special files, cache/debug files, lockfile mutation, and non-canonical tooling identities.

Record the generated tfvars SHA and binding-report SHA. Closure, plan generation, and both wrapper modes must receive --tfvars, --tfvars-binding-report, --tfvars-binding-report-sha256, and --tooling-tree-sha256; a modified tfvars file, missing provenance, or current broker ZIP byte mismatch is rejected before Terraform execution. The real apply path repeats the ZIP check immediately before applying the saved plan.

Refresh-only is available only through `npm run stage-b:refresh-only -- --closure-mode production ...`. It validates the canonical `.tfvars` contract, initialized backend metadata, protected checkout, and `TF_WORKSPACE=default` before running one untargeted refresh-only plan. `--terraform-data-dir` must be an existing private directory, `--backend-metadata` must be its exact `terraform.tfstate` child, and both Terraform subprocesses receive that same directory as `TF_DATA_DIR`. It never accepts an output plan path or Terraform `-out` flag.

## Partial-apply recovery

A failed approved apply can leave Terraform state and configuration ahead of one remote
mutation. The original refresh report remains immutable and reports `RESOURCE_DRIFT`.
Only a separately published, administrator-produced
`STAGE_B_PARTIAL_APPLY_RECOVERY_ATTESTATION` may produce a
`REVIEWED_PARTIAL_APPLY_RESIDUE` result, and only for its exact root-managed resource,
lineage, serial, source SHA, refresh SHA, and state/live/configuration values.

This attestation is a retrospective administrator review. Preserved historical apply
logs remain `RAW_FORENSIC`; signing their hashes later does not claim they were signed
when the failure occurred. The attestation authorizes neither a plan nor an apply. A
fresh authoritative plan must independently contain the exact reviewed alias update and
must bind the attestation through the audit, approval, permission, closure, validator,
and verify-only chain. Unknown drift remains fatal and the old saved plan is invalid.

Every security-sensitive recovery consumer independently verifies the attestation report
and signature bytes, their SHA-256 domains, the administrator KMS signature, and the
exact source, lineage, serial, refresh, and alias bindings; audit and approval stages
propagate that verified digest through their signed/bound artifacts. The unsigned
recovery classification is derived/cache evidence only; `attestationVerified` is not
an authorization signal.
Pull-request provenance mode never turns recovery inputs into production authorization.

Future apply wrappers should publish a structured signed failure artifact at failure time,
including source and plan hashes, state identity, failed resource/provider operation,
target identity, result classification, and stdout/stderr hashes. That forward-looking
artifact does not change the trust classification of historical logs.

## Generator input inventory

| Terraform inputs | Authoritative source | Emitted/logged |
| --- | --- | --- |
| `account_id`, `aws_region`, image-release identity | reviewed Stage B contract and signed image evidence | tfvars and binding report |
| `backend_image`, `worker_image`, `executor_image`, `canary_image`, `read_only_canary_image` | exact signed schema-v3 image records; the read-only canary intentionally reuses the signed `rls-canary` record | tfvars and binding report; digest only in safe report metadata |
| `canonical_image_evidence_sha256` | canonical signed report | tfvars and binding report |
| `tooling_sha`, tooling-tree digest | explicit protected-main identifiers | tfvars / binding report |
| Stage-A VPC, subnet, cluster, security-group, role, log-group, secret, approval, and receipt inputs | canonical prerequisite generator: exact Stage-A state backup plus read-only AWS subnet/route/security-group/ECS/RDS evidence | tfvars; prerequisite and source-state hashes are reported |
| `broker_package_path` | explicit output of the reviewed broker package builder | tfvars; raw and base64 SHA-256 in report |
| `source_contract_sha256`, `migration_set_digest`, `package_checksum_sha256` | source-controlled `generated/checksums.json` bytes and fields | tfvars and binding report |
| retained candidate/executor maps | supplied production Terraform state backup after lineage, serial, family, revision, broker policy, and address checks | tfvars and retained counts in report |

`stage_a_executor_networking_ready` and `log_retention_days` are contract values; the former must be proven true in the prerequisite JSON and the latter remains the reviewed Terraform default of 30 days. No sensitive secret values are accepted or emitted.

The release role's backend access is defined by `documents/ops/iam/MSCQRProductionGreenStageBWorkspaceState-v2.json`: it uses `s3:GetBucketLocation`, exact production state read/write, and exact `.tflock` lifecycle access. The legacy workspace base key, state deletion, workspace listing, and unrestricted bucket listing are not deployment gates or permissions.

Plan only:

```sh
MSCQR_STAGE_B_PLAN_ENABLED=true MSCQR_STAGE_B_PLAN_CONFIRM=MSCQR_GENERATE_STAGE_B_PLAN_ONLY \
  node scripts/plan-production-green-stage-b.mjs /absolute/private/production-green-stage-b.tfvars \
  --binding-report /absolute/private/production-green-stage-b-tfvars.binding.json \
  --binding-report-sha256 "$TFVARS_BINDING_REPORT_SHA256" \
  --tooling-tree-sha256 "$TOOLING_TREE_SHA256" \
  --image-release-sha "$IMAGE_RELEASE_SHA" \
  --closure-mode production
```

Review the saved JSON plan. Stop on any delete or any resource outside the listed control-plane types. A separately approved operator runbook must invoke scripts/apply-production-green-stage-b.mjs with the complete canonical tfvars provenance options; direct Terraform apply is not an approved path.

Both wrapper modes run `terraform -chdir=infra/aws/terraform/production-green-stage-b show -json` against the selected saved plan and pass the reviewed deployment environment, including `TF_DATA_DIR`, `TF_WORKSPACE`, `HOME`, `PATH`, and Terraform CLI configuration. Provider discovery must therefore use the initialized release-local data directory; repository-root or ambient `.terraform` discovery is not an accepted fallback.
