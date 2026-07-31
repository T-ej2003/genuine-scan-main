# Production Green Stage B provider recovery — 2026-07-29

## Post-merge P1 correction — historical v3 and deployable split

The post-merge review finding is valid. The permanent Stage B reference-audit
policy previously scoped `ecs:DescribeTaskDefinition` to task-definition ARN
patterns, but the recorded CloudTrail/IAM simulation evidence in
[PRODUCTION_GREEN_STAGE_B_ECS_READBACK_RECOVERY_2026-07-30.md](./PRODUCTION_GREEN_STAGE_B_ECS_READBACK_RECOVERY_2026-07-30.md)
shows that AWS evaluates this action against `Resource "*"`. ARN-scoped
statements are implicitly denied, and the current AWS authorization model does
not support a resource-level ARN restriction for this action.
In AWS IAM, `ecs:DescribeTaskDefinition` therefore requires `Resource "*"`.

The corrective source change sets only the dedicated read-only
`ecs:DescribeTaskDefinition` statement to `Resource "*"`. This grants
read-only task-definition metadata access; it does not grant task execution or
service mutation authority. The exact twelve source-controlled Stage B task-
definition families remain enforced by the Stage B audit generator and
validator, which reject `mscqr-backend`, `mscqr-frontend`, unknown families, and
unknown Terraform addresses.

The live managed policy remains on the pre-correction version until the
separately authorized update after this corrective PR is merged. No fresh audit,
Terraform plan/apply, AWS runtime, service, database, broker, ALB, DNS, or
traffic action is authorized by this correction.

## Version history and exact correction

`MSCQRProductionGreenStageBProviderRecovery-v2.json` is the immutable historical
artifact produced by PR #161 and is preserved for audit and rollback. Its byte SHA-256 is
`dccfa7c5cf64c266fd9ea1deabd78f6ed1b43b20132f729642cc5e2ceb65bc71`.

The prior live v1 policy is preserved in
[MSCQRProductionGreenStageBProviderRecovery-v1-live.json](./MSCQRProductionGreenStageBProviderRecovery-v1-live.json).
The reviewed v2 source is
[MSCQRProductionGreenStageBProviderRecovery-v2.json](./MSCQRProductionGreenStageBProviderRecovery-v2.json).
V3 is the post-merge correction and its new source artifact is:
[MSCQRProductionGreenStageBProviderRecovery-v3.json](./MSCQRProductionGreenStageBProviderRecovery-v3.json).

V3 equals v2 except for the dedicated read-only
`DescribeStageBTaskDefinitionsReadOnly` statement: its
`ecs:DescribeTaskDefinition` `Resource` changes from the original twelve ARN
patterns to `"*"`, as required by AWS IAM. AWS managed-policy version IDs are
discovered from the live policy; this runbook does not assume that AWS's next
version ID will literally be `v3`.

The original v2 recovery changes were:

1. The three exact CloudWatch Logs tagging resources now use the required
   trailing colon-star form.
2. A separate ecs:TagResource statement permits only the twelve reviewed
   task-definition family/revision patterns.
3. Exact Stage B apply recovery permissions now cover only the reviewed log groups
   and task-definition family/revision patterns.

The global iam:ListAttachedRolePolicies statement and exact DynamoDB replay
table tagging statement are unchanged.

The v3 correction is only the dedicated read-only
`ecs:DescribeTaskDefinition` statement's `Resource "*"` value; all other v2
statements, actions, resources, and conditions remain unchanged. V3 is now
historical because the combined document is 6,651 AWS-counted characters,
which exceeds the 6,144 AWS managed-policy limit by 507 characters.

The deployable split is:

- `MSCQRProductionGreenStageBProviderRecovery-v4.json` is v3 minus the seven
  permanent reference-audit read statements and contains only the reviewed
  provider-recovery control-plane permissions.
- `MSCQRProductionGreenStageBReferenceAuditReadOnly-v1.json` is the permanent
  companion containing exactly those seven read-only statements, including the
  isolated wildcard `ecs:DescribeTaskDefinition` metadata read.

V2 remains the immutable PR #161 artifact, v3 remains the immutable corrected
wildcard artifact, v4 is the deployable provider-recovery artifact, and
`ReferenceAuditReadOnly-v1` is the deployable companion. The live managed
policy remains on its pre-correction version until the separately authorized
update of both policies. AWS managed-policy version IDs must be discovered
from each live policy and are not assumed to match repository suffixes.

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

Merging source alone does not update AWS. The live provider-recovery policy
must be version-updated after merge from v4, and the companion policy must be created or
updated from `ReferenceAuditReadOnly-v1`. The two policies must be attached
only to `mscqr-production-release-deployer`. After merge, an authorized IAM
administrator must discover each live policy ARN, create or update its default
managed-policy version from the exact source artifact, and verify both live
documents semantically before any retry:

```sh
set -euo pipefail
PROVIDER_POLICY_NAME='MSCQRProductionGreenStageBProviderRecovery'
AUDIT_POLICY_NAME='MSCQRProductionGreenStageBReferenceAuditReadOnly'
PROVIDER_DOCUMENT="$PWD/documents/ops/iam/MSCQRProductionGreenStageBProviderRecovery-v4.json"
AUDIT_DOCUMENT="$PWD/documents/ops/iam/MSCQRProductionGreenStageBReferenceAuditReadOnly-v1.json"
ROLE_NAME='mscqr-production-release-deployer'
ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
PROVIDER_POLICY_ARN="$(aws iam get-policy --policy-arn "arn:aws:iam::${ACCOUNT_ID}:policy/${PROVIDER_POLICY_NAME}" --query Policy.Arn --output text)"
AUDIT_POLICY_ARN="$(aws iam get-policy --policy-arn "arn:aws:iam::${ACCOUNT_ID}:policy/${AUDIT_POLICY_NAME}" --query Policy.Arn --output text 2>/dev/null || aws iam create-policy \
  --policy-name "$AUDIT_POLICY_NAME" \
  --policy-document "file://${AUDIT_DOCUMENT}" \
  --query Policy.Arn --output text)"
PROVIDER_VERSION_ID="$(aws iam create-policy-version \
  --policy-arn "$PROVIDER_POLICY_ARN" \
  --policy-document "file://${PROVIDER_DOCUMENT}" \
  --set-as-default \
  --query PolicyVersion.VersionId --output text)"
AUDIT_VERSION_ID="$(aws iam create-policy-version \
  --policy-arn "$AUDIT_POLICY_ARN" \
  --policy-document "file://${AUDIT_DOCUMENT}" \
  --set-as-default \
  --query PolicyVersion.VersionId --output text)"
aws iam attach-role-policy --role-name "$ROLE_NAME" --policy-arn "$PROVIDER_POLICY_ARN"
aws iam attach-role-policy --role-name "$ROLE_NAME" --policy-arn "$AUDIT_POLICY_ARN"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
aws iam get-policy-version --policy-arn "$PROVIDER_POLICY_ARN" --version-id "$PROVIDER_VERSION_ID" \
  --query PolicyVersion.Document --output json > "$TMP_DIR/live-policy.json"
aws iam get-policy-version --policy-arn "$AUDIT_POLICY_ARN" --version-id "$AUDIT_VERSION_ID" \
  --query PolicyVersion.Document --output json > "$TMP_DIR/live-audit-policy.json"
cmp <(jq -S . "$PROVIDER_DOCUMENT") <(jq -S . "$TMP_DIR/live-policy.json")
cmp <(jq -S . "$AUDIT_DOCUMENT") <(jq -S . "$TMP_DIR/live-audit-policy.json")
ATTACHMENTS="$(aws iam list-attached-role-policies --role-name "$ROLE_NAME" \
  --query "AttachedPolicies[?PolicyName=='${PROVIDER_POLICY_NAME}' || PolicyName=='${AUDIT_POLICY_NAME}']" --output json)"
test "$(jq 'length' <<<"$ATTACHMENTS")" -eq 2
test "$(jq -r 'map(.PolicyName) | sort | join(",")' <<<"$ATTACHMENTS")" = "${AUDIT_POLICY_NAME},${PROVIDER_POLICY_NAME}"
```

`PROVIDER_VERSION_ID` and `AUDIT_VERSION_ID` are the actual AWS-managed-policy
version IDs returned by AWS; do not substitute or assume literal `v3`, `v4`, or
`v1` identifiers when executing this update. If the companion policy does not
exist, the documented `create-policy` branch creates it from the exact
source-controlled artifact; otherwise the command updates its default version.
The final checks require exactly two matching attachments, with the exact two
policy names, on the exact release-deployer role. Review the complete role
attachment list for any pre-existing unexpected authority before continuing.

The update must preserve the single intended release-deployer role boundary. If AWS
reports the five-version limit, delete only an explicitly reviewed non-default
version. Root may perform only this policy-version update when no approved
non-root administrator exists; root must not run Terraform and must be logged out
immediately afterward. Obtain a fresh MFA-backed release session for the
release-deployer after the live update. Do not retry the failed apply until the live
policies match these source documents.
The failed Stage B apply must not be retried before the live managed policy matches source.

## Permanent plan-bound reference audit

The permanent MFA-backed release-deployer policy pair includes the read-only ECS and
broker calls required to produce the rollover audit: `ListServices`,
`DescribeServices`, `ListTasks`, `DescribeTasks`, `DescribeTaskDefinition`, and
`lambda:GetFunctionConfiguration`. `ecs:DescribeTaskDefinition` is read-only
metadata access and must use `Resource "*"`; AWS does not enforce a
task-definition ARN resource restriction for that action. The exact twelve
source-controlled Stage B task-definition families are enforced by the Stage B
audit generator and validator, while service/task listing remains cluster
constrained and the broker read remains exact-function constrained. No
temporary policy is required.

The release role is not granted task execution or service mutation authority:
it has no `ecs:RunTask`, `ecs:StopTask`, `ecs:UpdateService`, or service
creation/deletion permission. The wildcard is therefore limited to the single
read-only metadata statement and is compensated by the application-layer audit
and validator contract.

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

## Validation and release boundary

- The repository policy tests require a dedicated read-only
  `ecs:DescribeTaskDefinition` statement with exactly `Resource "*"` and no
  other action.
- The audit generator and plan validator accept only the exact twelve
  source-controlled Stage B task-definition families. Blue service families,
  unknown families, and unknown addresses remain rejected.
- The recorded ECS readback evidence confirms the wildcard requirement and the
  separate read-only policy recovery; it is cross-referenced above.
- No live managed-policy update, fresh audit, Terraform plan/apply, or runtime
  operation is claimed until this corrective PR is merged and separately
  approved for operator execution.

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
