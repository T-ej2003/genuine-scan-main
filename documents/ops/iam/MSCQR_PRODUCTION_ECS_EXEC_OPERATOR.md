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
the verifier role. The helper checks the caller ARN before any ECS discovery and rejects the
release-deployer or any other identity. The fixture is transferred through the controlled PTY
stdin path; it is not a command-line argument or task-definition environment value.

Administrator preflight reports release-deployer and verifier evaluations separately. The report is
invalid unless the exact Stage-A ingress, deployment, rollback, PassRole, release-deployer ECS Exec
deny, and verifier ECS Exec allow evidence are all present.
