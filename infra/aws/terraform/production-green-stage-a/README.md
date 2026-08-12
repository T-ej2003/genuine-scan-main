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
