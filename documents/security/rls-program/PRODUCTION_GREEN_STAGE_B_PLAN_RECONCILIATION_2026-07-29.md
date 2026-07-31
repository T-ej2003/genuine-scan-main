# Production Green Stage B plan reconciliation — 2026-07-29

## Scope and identity

- Checkout SHA: `6a8e94477949336616695bf3712ca0fd8ca85efa` (clean detached checkout).
- Terraform root: `infra/aws/terraform/production-green-stage-b`.
- Workspace: `production`.
- Caller: `arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/abhi-phase3`.
- Account: `368992683803`; region: `eu-west-2`.

## Reconciliation

## Reviewed immutable revision-rollover exception

Normal Terraform destroys remain forbidden. The only permitted exception is a
same-family `aws_ecs_task_definition` delete/create revision rollover for an
allowlisted Stage B address. The plan validator requires a fresh live reference
audit supplied with explicit SHA-256 values for both the audit file and the
current `terraform show -json` output. Every old ARN must be present in that
audit with matching family and `container_definitions` as its only replacement
path, zero service/running/pending references, and a retained rollback ARN.

This exception does not authorize ECS service updates, task execution, database
actions, broker invocation, ALB, DNS, or traffic changes. Any non-task-definition
destroy, unknown address/family, missing or mismatched audit binding, non-zero
reference, or missing rollback ARN remains fail-closed.

The initial refreshed state contained the seven expected IAM roles and the
`stage-b-executor-runtime` inline policy. All seven role instances were marked
`tainted`, which forced replacements and caused the plan-only wrapper to reject
the first plan (`33 add`, `7 destroy`). The AWS refresh completed for every
instance and showed no configuration drift. The seven stale Terraform taint
flags were cleared from state; no AWS resource API mutation was performed.

The fresh saved plan then passed the repository plan-only guard:

- `26 to add`, `0 to change`, `0 to destroy`, `0 replacements`.
- The eight pre-existing state addresses are all `no-op`.
- The plan contains no ECS service, `RunTask` invocation, database resource,
  secret or secret-version resource, ALB, DNS, listener, target-group, or
  traffic resource.

Direct IAM policy introspection is not permitted to this deployment role, so
the stated v3/default-policy and recovery-policy hashes were not independently
read in this session. The plan-only operation itself succeeded under the stated
release-deployer session.

## Remaining additions, ordered

1. `aws_cloudwatch_log_group.stage_b["backend"]`
2. `aws_cloudwatch_log_group.stage_b["canary"]`
3. `aws_cloudwatch_log_group.stage_b["worker"]`
4. `aws_dynamodb_table.replay`
5. `aws_ecs_task_definition.candidate["backend"]`
6. `aws_ecs_task_definition.candidate["canary"]`
7. `aws_ecs_task_definition.candidate["worker"]`
8. `aws_ecs_task_definition.executor["full-rls-admin-bootstrap"]`
9. `aws_ecs_task_definition.executor["full-rls-admin-ownership"]`
10. `aws_ecs_task_definition.executor["full-rls-capability-preflight"]`
11. `aws_ecs_task_definition.executor["full-rls-role-provision"]`
12. `aws_ecs_task_definition.executor["full-rls-role-verify"]`
13. `aws_ecs_task_definition.executor["full-rls-rollback"]`
14. `aws_ecs_task_definition.executor["full-rls-runtime-policy"]`
15. `aws_ecs_task_definition.executor["full-rls-verification"]`
16. `aws_iam_role_policy.broker`
17. `aws_iam_role_policy.candidate_object_storage["backend"]`
18. `aws_iam_role_policy.candidate_object_storage["canary"]`
19. `aws_iam_role_policy.candidate_object_storage["worker"]`
20. `aws_iam_role_policy.execution["backend"]`
21. `aws_iam_role_policy.execution["canary"]`
22. `aws_iam_role_policy.execution["executor"]`
23. `aws_iam_role_policy.execution["worker"]`
24. `aws_lambda_alias.reviewed`
25. `aws_lambda_function.broker`
26. `aws_lambda_permission.release_deployer`

## Reproducible plan digest

Saved plan: `.terraform-plans/production-green-stage-b.tfplan`.

The SHA-256 is `e334c1999d860f3242a06cff43d00774738b7685a15a57e8f6ee4a8f9a7fe33c`, over the canonical ordered JSON array of every resource address and its action list from `terraform show -json`:

```sh
terraform -chdir=infra/aws/terraform/production-green-stage-b show -json /private/tmp/genuine-scan-stage-b-aws/.terraform-plans/production-green-stage-b.tfplan | jq -c '[.resource_changes[] | {address, actions: .change.actions}] | sort_by(.address)' | shasum -a 256
```

No apply was run. No ECS task, RLS operation, service, database, secret value,
or traffic resource was mutated. The only state mutation was clearing the seven
stale Terraform taint flags needed to make existing partial resources no-op.

## Apply attempt — stopped on AccessDenied

The exact saved plan was revalidated against the recorded digest and applied
under the recorded release-deployer identity. Terraform stopped on the first
authorization failure, as required. Four additions completed before the stop:

- `aws_dynamodb_table.replay`
- `aws_iam_role_policy.candidate_object_storage["backend"]`
- `aws_iam_role_policy.candidate_object_storage["canary"]`
- `aws_iam_role_policy.candidate_object_storage["worker"]`

The release-deployer lacks `logs:TagResource` for tagged CloudWatch log-group
creation and `ecs:TagResource` for tagged task-definition registration. No IAM
policy was broadened and no retry, re-plan, task run, RLS command, service,
database, secret-value, ALB, DNS, or traffic operation was performed after the
failure. Post-apply cloud verification was deliberately not run because the
operator instruction requires an immediate stop on AccessDenied.
