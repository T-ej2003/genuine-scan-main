# Production ECS Exec verifier identity

The release-deployer is intentionally denied `ecs:ExecuteCommand`. Deployment mutation and runtime
shell verification are separate trust boundaries.

## Reviewed identity

- Role: `arn:aws:iam::368992683803:role/mscqr-production-ecs-exec-verifier`
- Policy: `MSCQR_PRODUCTION_ECS_EXEC_OPERATOR_POLICY.json`
- Trust: `MSCQR_PRODUCTION_ECS_EXEC_OPERATOR_TRUST_POLICY.json`
- Provisioning: administrator-only, through the reviewed IAM publication path
- Trust principal: `mscqr-production-bootstrap-operator`, with MFA required

The policy permits only the production backend ECS Exec target and the read APIs required to select
and verify that task. It contains no service deployment, task registration, `iam:PassRole`,
`ssm:StartSession`, or Secrets Manager value access.

## Invocation boundary

Run `scripts/aws/verify-production-rotation-via-ecs-exec.mjs` only under an assumed session for
the verifier role, with `--credential-source inherited-ecs-exec-verifier-session`. The helper
forwards only that STS session, rejects profile/default credential selection, checks the caller
ARN before any ECS discovery, and rejects the release-deployer or any other identity. The fixture
is transferred through the controlled PTY stdin path; it is not a command-line argument or
task-definition environment value.

Administrator preflight reports release-deployer and verifier evaluations separately. The report is
invalid unless the exact Stage-A ingress, deployment, rollback, PassRole, release-deployer ECS Exec
deny, and verifier ECS Exec allow evidence are all present. It also records live trust-policy and
operator-policy canonical hashes; simulation evidence alone is insufficient. The ListTasks proof
uses Resource `*` with exact production cluster and region conditions, matching AWS IAM semantics.

## Approved backend task identity

The verifier policy requires the task resource tag
`MSCQRExecTarget=production-backend`. Terraform applies that tag only to the backend candidate
task definition, and the governed rotation service switch sets `propagateTags=TASK_DEFINITION`.
The verifier requests task tags, requires the exact marker, and revalidates the same task ARN
immediately before `ecs:ExecuteCommand`. Worker, RLS executor, RLS canary, wrong-container,
missing-marker, unhealthy, and ambiguous targets fail closed. This marker is the stable boundary
across ECS task replacement; an individual task ARN is never hard-coded.

The release-deployer may set this marker only during the reviewed backend
`RegisterTaskDefinition` request. Its separate `ecs:TagResource` authority is
limited to the standard Terraform tags and cannot add or change
`MSCQRExecTarget`; the verifier role has no tagging authority. Non-backend
task-definition registration statements exclude the marker entirely.
