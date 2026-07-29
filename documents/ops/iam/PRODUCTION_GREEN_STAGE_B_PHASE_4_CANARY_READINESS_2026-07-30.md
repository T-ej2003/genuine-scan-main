# Production Green Stage B Phase 4 canary readiness — 2026-07-30

## Scope and boundary

Stage B infrastructure is complete in the `production` workspace: 34 Terraform
addresses, with final apply `2 added, 0 changed, 0 destroyed`. The reviewed
broker is `mscqr-production-rls-approval-broker`, version `1`, alias
`reviewed`. This report is preparation only. It does not invoke the broker,
run ECS, execute RLS, create an approval, claim a replay row, or contact the
database.

## Registered application-canary binding

The only registered application-canary task definition is:

    arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-full-rls-green-application-canary:1

It binds the exact immutable image:

    368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@sha256:60256bb3ed3b72d5b65a8811b6f5c3a18b859fa88ba86a6b1843fa346fd29c9a

Its task role is
`arn:aws:iam::368992683803:role/mscqr-production-rls-green-canary-task` and
its execution role is
`arn:aws:iam::368992683803:role/mscqr-production-rls-green-canary-execution`.
Its fixed `awsvpc` network contract uses only security group
`sg-051a24aedff773761` and private subnets `subnet-068d949017bd2ce45` and
`subnet-07e0a76e3a5241138`, with public IP assignment disabled.

The task receives the application database secret reference, whose documented
logical production database identity is `mscqr_prod_app`; its pre-auth path is
the separate `mscqr_prod_preauth` identity. Secret values were not read.

## Broker and approval boundary

The only deployed invocation permission is alias-qualified to `reviewed` and
names `arn:aws:iam::368992683803:role/mscqr-production-release-deployer` as
its principal. The deployed Terraform permission has no source condition; the
adjacent invocation-policy JSON is explicitly a design contract, not an
AddPermission payload. This must be reconciled before any future broker use if
the `aws:PrincipalArn` condition in that design contract is required.

The broker contract accepts only a signed, fixed-field approval naming the
exact release, image digests, task-definition ARNs, network SG, checker,
deployer, executor, expiry and nonce. It accepts no task, image, command,
environment, role, or network override. The replay table claims the
`approvalMode` key with a conditional write and TTL; explicit ECS rejections
release a claim, while transport-uncertain outcomes remain blocked for manual
reconciliation. The broker has no authority for service updates, task
registration, traffic controls, RDS, runtime secret reads, or SQL.

## Read-only canary assessment

**Not ready to run.** The registered application-canary image entry point is
`node scripts/production-green-application-canary.mjs`. It starts the backend
and executes ordinary and administrator login/MFA smoke journeys. Those
journeys can create authentication/session/audit state, so this task is not a
read-only canary and cannot meet the Phase 4 requirement that the canary be
incapable of changing RLS, schema, roles, policies, application data, or
traffic.

There is therefore no approved read-only canary command to execute from the
current Stage B task definitions. The release-deployer also remains explicitly
denied `ecs:RunTask`; that is a required safety boundary, not an IAM gap.

The safe Phase 4 implementation prerequisite is a separately reviewed
read-only canary task definition and a dedicated database identity whose only
database capability is an allowlisted `SELECT`/function-read probe. It must
have no mutation routes, no session issuance, no MFA challenge completion, no
replay-table write authority, no broker invocation, no `ecs:RunTask` grant to
the release-deployer, and no ability to update services or traffic.

## Future run criteria

When a separate read-only task is approved, its command must be fixed in the
task definition (not an ECS override) and perform only the reviewed probe.
Success requires: fixed task definition and image digest, exact SG/subnets,
read-only database identity, expected allowlisted reads, expected cross-tenant
denial, exit code zero, and no database/RLS/catalog/traffic mutation.

Stop immediately for any nonzero exit, unexpected query, credential or role
identity mismatch, attempted write, RLS/schema/role/policy operation, ECS
service or traffic operation, approval/replay interaction, or evidence that an
ECS task has broader authority than the reviewed probe.

Collect only redacted evidence: task-definition ARN/revision and image digest,
task exit status and timestamps, task role/execution role, SG/subnets, selected
read-only probe results, CloudWatch log references, and before/after database
catalog and traffic attestations. Do not collect secret values, tokens,
database URLs, credentials, or raw sensitive response bodies.
