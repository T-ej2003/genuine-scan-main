# Production Green Stage B provider recovery — 2026-07-29

## Exact correction

MSCQRProductionGreenStageBProviderRecovery default version is now v2. The
canonical SHA-256 is regenerated from the reviewed source document during the
live-policy semantic verification below.

The prior live v1 policy is preserved in
[MSCQRProductionGreenStageBProviderRecovery-v1-live.json](./MSCQRProductionGreenStageBProviderRecovery-v1-live.json).
The reviewed v2 source is
[MSCQRProductionGreenStageBProviderRecovery-v2.json](./MSCQRProductionGreenStageBProviderRecovery-v2.json).

The only changes are:

1. The three exact CloudWatch Logs tagging resources now use the required
   trailing colon-star form.
2. A separate ecs:TagResource statement permits only the eleven reviewed
   task-definition family/revision patterns.
3. Exact Stage B apply recovery permissions now cover only the reviewed log groups
   and task-definition family/revision patterns.

The global iam:ListAttachedRolePolicies statement and exact DynamoDB replay
table tagging statement are unchanged.

## Stage B release-deployer apply correction

The Stage B Terraform apply may register immutable revisions for the exact Stage B
task-definition families and create the four Stage B-owned candidate log groups.
The source policy therefore also permits `ecs:DeregisterTaskDefinition` only for
those reviewed family ARN patterns and `logs:CreateLogGroup` only for the backend,
worker, application-canary, and read-only-canary Stage B log groups. The shared
`/ecs/mscqr-production/full-rls-green` executor log group remains Stage A-owned
and is intentionally excluded from Stage B creation authority.
The existing exact tagging statements include the same read-only-canary log-group
and task-definition ARNs because Terraform tags both resources during creation.

Merging source alone does not update AWS. The live managed policy must be version-updated after merge. After merge, an authorized IAM
administrator must create a new default managed-policy version from the exact
merged document and verify the live document semantically before any retry:

```sh
set -euo pipefail
POLICY_NAME='MSCQRProductionGreenStageBProviderRecovery'
POLICY_DOCUMENT="$PWD/documents/ops/iam/MSCQRProductionGreenStageBProviderRecovery-v2.json"
ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
POLICY_ARN="$(aws iam get-policy --policy-arn "arn:aws:iam::${ACCOUNT_ID}:policy/${POLICY_NAME}" --query Policy.Arn --output text)"
NEW_VERSION_ID="$(aws iam create-policy-version \
  --policy-arn "$POLICY_ARN" \
  --policy-document "file://${POLICY_DOCUMENT}" \
  --set-as-default \
  --query PolicyVersion.VersionId --output text)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
aws iam get-policy-version --policy-arn "$POLICY_ARN" --version-id "$NEW_VERSION_ID" \
  --query PolicyVersion.Document --output json > "$TMP_DIR/live-policy.json"
cmp <(jq -S . "$POLICY_DOCUMENT") <(jq -S . "$TMP_DIR/live-policy.json")
```

The update must preserve the single intended release-deployer attachment. If AWS
reports the five-version limit, delete only an explicitly reviewed non-default
version. Root may perform only this policy-version update when no approved
non-root administrator exists; root must not run Terraform and must be logged out
immediately afterward. Obtain a fresh MFA-backed release session for the
release-deployer after the live update. Do not retry the failed apply until the live managed policy
matches this source document.
The failed Stage B apply must not be retried before the live managed policy matches source.

## Permanent plan-bound reference audit

The permanent MFA-backed release-deployer policy includes the read-only ECS and
broker calls required to produce the rollover audit: `ListServices`,
`DescribeServices`, `ListTasks`, `DescribeTasks`, `DescribeTaskDefinition`, and
`lambda:GetFunctionConfiguration`. These calls are restricted to the reviewed
production cluster, Stage B task-definition families, and approval-broker
function. No temporary policy is required.

Whenever the plan JSON changes, the release-deployer must perform a fresh
read-only audit and bind it to the exact plan SHA-256. Every old revision must
have zero service, running-task, and pending-task references, matching family and
replacement path, and a retained rollback ARN. The validator must accept the
matching audit and both explicit hashes before any apply; otherwise apply remains
forbidden.

The recovery sequence is: verify the fresh caller, revalidate the saved plan and
reference audit, apply that exact full plan without `-target`, then verify the
new task-definition revisions and retained rollback ARNs. No ECS service update,
task execution, broker invocation, database action, ALB, DNS, or traffic change
is part of this correction.

## Validation

- Access Analyzer policy validation returned zero findings.
- Exact request-tag context allowed all three log-group and all eleven
  task-definition tagging requests.
- Unrelated log groups/task-definition families and missing/wrong tags were
  denied.
- ecs:RunTask and ecs:UpdateService remain explicit denies; ECS service
  creation and task-definition deregistration outside the exact Stage B family
  list, plus DynamoDB data-plane/destructive actions, remain denied.
- The attached live v2 document was fetched after creation and its canonical
  SHA-256 matched the reviewed source.

## Fresh Stage B plan — stop before apply

The MFA-backed release session was still
arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/abhi-phase3.
Terraform refreshed state and confirmed the four partial-apply additions are
present: the replay table and three candidate object-storage inline policies.

Saved plan: .terraform-plans/production-green-stage-b.tfplan

- 22 to add, 0 to change, 0 to destroy, 0 replacements
- 12 existing resources are no-op
- No ECS service/task run, database/secret-value, ALB, DNS, CloudFront, or
  traffic resource is planned.

The ordered address/action digest is
8e64ea891e4a189230cc176dc3eea323343a95ec251905b4c94398a3a0036af5.
Reproduce it with:

    terraform -chdir=infra/aws/terraform/production-green-stage-b show -json /private/tmp/genuine-scan-stage-b-aws/.terraform-plans/production-green-stage-b.tfplan | jq -c '[.resource_changes[] | {address, actions: .change.actions}] | sort_by(.address)' | shasum -a 256

Remaining additions, in canonical order:

1. aws_cloudwatch_log_group.stage_b["backend"]
2. aws_cloudwatch_log_group.stage_b["canary"]
3. aws_cloudwatch_log_group.stage_b["worker"]
4. aws_ecs_task_definition.candidate["backend"]
5. aws_ecs_task_definition.candidate["canary"]
6. aws_ecs_task_definition.candidate["worker"]
7. aws_ecs_task_definition.executor["full-rls-admin-bootstrap"]
8. aws_ecs_task_definition.executor["full-rls-admin-ownership"]
9. aws_ecs_task_definition.executor["full-rls-capability-preflight"]
10. aws_ecs_task_definition.executor["full-rls-role-provision"]
11. aws_ecs_task_definition.executor["full-rls-role-verify"]
12. aws_ecs_task_definition.executor["full-rls-rollback"]
13. aws_ecs_task_definition.executor["full-rls-runtime-policy"]
14. aws_ecs_task_definition.executor["full-rls-verification"]
15. aws_iam_role_policy.broker
16. aws_iam_role_policy.execution["backend"]
17. aws_iam_role_policy.execution["canary"]
18. aws_iam_role_policy.execution["executor"]
19. aws_iam_role_policy.execution["worker"]
20. aws_lambda_alias.reviewed
21. aws_lambda_function.broker
22. aws_lambda_permission.release_deployer

No Terraform apply was run after this recovery plan.

## Approved-plan apply attempt — stopped

The saved plan digest, caller identity, production workspace, and all plan
action constraints were revalidated immediately before apply. Terraform then
applied the exact saved plan without replanning.

The following resources completed before the stop:

- the three Stage B CloudWatch log groups;
- the four Stage B execution-role inline policies.

Terraform then reported that it could not read each newly registered ECS task
definition by ARN. This is an unexpected post-registration read failure, not a
permission change request. Per the stop rule, no retry, re-plan, IAM change, or
post-apply cloud inspection was performed. The final registration/state status
of the eleven task definitions and all downstream resources is therefore
unverified.
