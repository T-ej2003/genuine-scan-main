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

Stage A creates no ECS task definition, ECS service, Lambda function, image
binding, runtime secret value, broker invocation, canary, or traffic switch.
The executor security group has explicit empty egress, so no executor can send
traffic in Stage A. Stage B must choose and review either NAT TCP/443 plus
green-DB TCP/5432, or approved VPC-endpoint TCP/443 plus green-DB TCP/5432,
before it creates a runnable executor task.

`manage_master_user_password = true` asks RDS—not Terraform—to create the
KMS-encrypted administrator secret when the database is created. It is separate
from the 14 empty application/runtime secret handles. Terraform exposes only
the ARN through `rds_managed_administrator_secret`; neither application runtime
roles nor plans, logs, Git, or receipts may receive the password value. Only
the later approved broker/executor administration path may use it.

Stage B is release activation after immutable backend, worker, and executor
images exist. It attaches least-privilege execution policies, creates fixed
executor/canary task definitions and the reviewed broker, then runs mandatory
green canaries before any backend/worker cutover. Frontend remains
`mscqr-frontend:20`.
