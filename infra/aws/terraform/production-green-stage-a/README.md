# Production green Stage A Terraform

This is the only Terraform root for isolated green infrastructure. It owns new
green RDS, KMS, security groups, empty secret handles, executor/broker roles,
and log groups. It does not own or import blue ECS, ECR, ALB, DNS, RDS, or
existing Secrets Manager resources.

The state bucket is an external prerequisite. AWS root must not plan or apply.
An authorised assumed role must initialise with explicit, approved coordinates:

```sh
terraform -chdir=infra/aws/terraform/production-green-stage-a init -upgrade=false \
  -backend-config='bucket=<approved-dedicated-production-state-bucket>' \
  -backend-config='key=mscqr/production/rls-green/stage-a/terraform.tfstate' \
  -backend-config='region=eu-west-2' \
  -backend-config='encrypt=true' \
  -backend-config='use_lockfile=true'
```

The bucket must meet `production-state-backend-prerequisite.json`; it must not
be the staging state bucket or the production artifact bucket. The immediate
operator path is MFA-gated `mscqr-production-bootstrap-operator` assuming the
external `mscqr-production-release-deployer` role for no more than one hour.
The bootstrap user has no console password or standing access key and may only
assume that role; a temporary access key is permitted solely to obtain the MFA
STS session and must be deleted before Terraform runs. Root, the checker,
GitHub deploy, and application/runtime roles cannot assume the release role.
No GitHub OIDC trust is added here; that later migration requires separate
review. The checker must be distinct from the release deployer.

## Root-drop orphan recovery boundary

The canonical orphan-recovery command is bound to this Terraform root, the
initialized S3 backend coordinates above, and the `default` workspace. It
removes inherited Terraform redirect variables and uses only the exact
production Stage-A `TF_VAR_*` inputs already supplied to the normal reviewed
launch: `TF_VAR_aws_region`, `TF_VAR_vpc_id`, `TF_VAR_private_subnet_ids`,
`TF_VAR_runtime_security_group_ids`, `TF_VAR_s3_prefix_list_id`,
`TF_VAR_vpc_dns_resolver_cidr`, `TF_VAR_checker_principal_arns`,
`TF_VAR_release_role_arn`, and `TF_VAR_receipt_bucket_arn`. The recovery
command rejects every other `TF_VAR_*` key and does not fall back to a local
`terraform.tfvars`. It validates the exact variable set with a non-mutating
Terraform plan saved to the reviewed private plan path, shows and machine-
classifies those exact plan bytes, and requires only the root-drop key and
alias creates before import. Any auto-loaded `terraform.tfvars` or
`*.auto.tfvars` file is rejected. It uses the release-deployer
profile for every Terraform subprocess. Before import it compares the live
state lineage, serial, and exact state-byte SHA-256 with the fresh census
identity; any mismatch fails closed. Recovery imports only the authenticated
root-drop key and may apply only the exact Terraform-managed alias plan. The
census source SHA must equal the clean execution checkout HEAD, and the
pre-import classifier proves the alias expression targets
`aws_kms_key.root_drop.key_id`. Post-mutation failures expose deterministic
recovery accounting at the CLI boundary. The
census captures the complete paginated KMS key-ID universe before inspection
and again afterward; any changed, incomplete, duplicated, or malformed
enumeration fails closed instead of producing `NO_CANDIDATE`. This is a
bounded consistency check, not a claim that AWS eventual consistency is a
transactional snapshot. The adoption contract also requires the exact
`root_drop` description (`Root-only MSCQR production cutover evidence signing
key`) before an orphan can be authenticated.

Stage A also manages the one exact inline role-chain policy on the existing
`mscqr-production-independent-checker` role that permits only
`sts:AssumeRole` into the Stage A-owned
`mscqr-production-rls-independent-checker` role. It does not own the source
role, its trust policy, or any other source-role permission.
The checker IAM user must enter that source role through its MFA-gated trust;
the role-to-role trust intentionally has no second-hop MFA condition because
AWS role chaining does not create a fresh MFA request. The target trusts only
the exact source role, and the final target-role session ARN is bound into the
signed approval. The second-hop profile must not add another `mfa_serial` or
substitute a different principal.

Stage A creates no ECS task definition, ECS service, Lambda function, image
binding, runtime secret value, broker invocation, canary, or traffic switch.
The executor security group has no default egress. It permits only green-DB
TCP/5432, reviewed AWS interface endpoint and S3 TCP/443, and exact VPC resolver
DNS paths required by the later Stage B executor.

`manage_master_user_password = true` asks RDS—not Terraform—to create the
KMS-encrypted administrator secret when the database is created. It is separate
from the 15 empty application/runtime secret handles, including the dedicated
Phase 4 read-only-canary database URL handle. Terraform exposes only
the ARN through `rds_managed_administrator_secret`; neither application runtime
roles nor plans, logs, Git, or receipts may receive the password value. Only
the later approved broker/executor administration path may use it.

Stage B is release activation after immutable backend, worker, and executor
images exist. It attaches least-privilege execution policies, creates fixed
executor/canary task definitions and the reviewed broker, then runs mandatory
green canaries before any backend/worker cutover. Frontend remains
`mscqr-frontend:20`.
## Stage B ownership boundary

Stage A exclusively owns the green database and executor security groups, the executor and broker log groups, the executor and broker roles, approval resources, runtime-role secret resources, and the empty Phase 4 read-only-canary database URL handle. Its `stage_b_prerequisites` output is the only supported handoff to the Production Green Stage B root.

The executor security group has no default egress. Stage A permits only PostgreSQL to the green database security group, HTTPS to its private ECR API, ECR Docker, CloudWatch Logs, Secrets Manager, and KMS interface endpoints and the regional S3 prefix list, and TCP/UDP DNS to the exact VPC resolver `/32`. Stage B must consume this group and must not recreate or mutate its network rules.

The five interface endpoints share one Stage A-owned security group that accepts TCP/443 only from the executor security group and the exact `runtime_security_group_ids` set. The runtime ingress is required for ECS execution-role secret retrieval; it adds no endpoint egress or internet access. The S3 gateway prefix list and VPC resolver remain separate exact inputs.
