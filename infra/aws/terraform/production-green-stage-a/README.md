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
be the staging state bucket or the production artifact bucket. A plan requires
an externally approved independent checker principal and the exact external
`mscqr-production-release-deployer` role. The checker must be distinct from the
release deployer.

Stage A creates no ECS task definition, ECS service, Lambda function, image
binding, runtime secret value, broker invocation, canary, or traffic switch.
Executor egress is deliberately absent in Stage A. Stage B must make an
explicit reviewed choice between approved NAT egress and required VPC endpoints
for ECR, Secrets Manager, KMS, S3, and CloudWatch before it creates a runnable
executor task.

Stage B is release activation after immutable backend, worker, and executor
images exist. It attaches least-privilege execution policies, creates fixed
executor/canary task definitions and the reviewed broker, then runs mandatory
green canaries before any backend/worker cutover. Frontend remains
`mscqr-frontend:20`.
