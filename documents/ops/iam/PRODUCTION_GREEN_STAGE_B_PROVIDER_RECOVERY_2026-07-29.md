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

- `MSCQRProductionGreenStageBProviderRecovery-v4.json` preserves the v3
  provider-recovery permissions except for the seven permanent reference-audit
  read statements previously moved to the companion policy. V4 additionally
  grants the read-only Terraform-refresh actions `iam:GetRole`,
  `iam:ListRolePolicies`, and `iam:ListAttachedRolePolicies` for exactly these
  administrator-created and imported Terraform roles:
  `arn:aws:iam::368992683803:role/mscqr-production-full-rls-green-read-only-canary-execution`
  and
  `arn:aws:iam::368992683803:role/mscqr-production-full-rls-green-read-only-canary-task`.
  It additionally grants read-only `iam:GetRolePolicy` only for the execution
  role because Terraform refreshes its imported inline policy resource; the
  task role has no inline policy. These grants exist only so the locked AWS
  provider can refresh the imported roles; they add no IAM mutation authority
  and use no wildcard IAM resource. The provider does not need
  `iam:ListRoleTags` or `iam:ListInstanceProfilesForRole` during refresh. The
  policy still contains no `ecs:DeregisterTaskDefinition` authority.
- `MSCQRProductionGreenStageBReferenceAuditReadOnly-v1.json` is the permanent
  companion containing the seven moved read-only statements, the additional
  `ReadStageBBrokerReviewedAlias` statement, and the additional region-bound
  `ReadStageALivePrerequisites` statement required before canonical handoff
  generation. `DescribeStageBTaskDefinitionsReadOnly` is one of the seven moved
  statements, not an additional statement.

V2 remains the immutable PR #161 artifact, v3 remains the immutable corrected
wildcard artifact, v4 is the deployable provider-recovery artifact, and
`ReferenceAuditReadOnly-v1` is the deployable companion. The live managed
policy remains on its pre-correction version until the separately authorized
update of both policies. AWS managed-policy version IDs must be discovered
from each live policy and are not assumed to match repository suffixes.

The old `stage-b-broker` inline-policy model is rejected. AWS authorizes
`iam:PutRolePolicy` at the role level and cannot constrain the embedded
`PolicyName`, so granting it would allow replacement of any inline policy on
the broker role. Terraform now manages the exact dedicated customer-managed
policy `mscqr-production-rls-approval-broker-runtime` and the exact
`aws_iam_role_policy_attachment.broker` attachment to
`arn:aws:iam::368992683803:role/mscqr-production-rls-approval-broker`.

The locked AWS provider refreshes that managed policy with
`iam:GetPolicy`, `iam:GetPolicyVersion`, `iam:ListPolicyVersions`, and the
broker attachment with `iam:ListAttachedRolePolicies`, each scoped to the
exact managed-policy or broker-role ARN. Ordinary policy updates use
`iam:CreatePolicyVersion` and, when the provider prunes old versions,
`iam:DeletePolicyVersion` on the exact managed-policy ARN. The provider sets
the new version as default through `CreatePolicyVersion`; no
`iam:SetDefaultPolicyVersion` grant is required. The release role receives no
`iam:PutRolePolicy`, `iam:DeleteRolePolicy`, or arbitrary attachment authority.

The initial migration is administrator-controlled: create the exact managed
policy, attach it only to the broker role, verify semantic equivalence with
`stage-b-broker`, then import
`aws_iam_policy.broker` and
`aws_iam_role_policy_attachment.broker` after destination-address and state-
backup checks. Remove the old inline policy only after the managed attachment,
equivalence proof, fresh plan, audit, and permission preflight succeed; use an
administrator-controlled cleanup path for the exact old inline policy rather
than expanding the release role. All earlier plans, audits, and permission
reports are stale after this model correction.
The permission manifest binds that write to the exact Terraform address,
resource type, `update` action, role name, and inline policy name; no other
inline policy or IAM role is covered. This is the only additional IAM write in
the reviewed plan and does not add role creation, attachment, passing, or
deletion authority. After this merge, the previously saved plan and audit are
stale and must not be reused; a new plan-bound permission report is required.

## Stage B release-deployer apply correction

The Stage B Terraform apply registers immutable revisions for the exact Stage B
task-definition families and retains prior revisions. The AWS provider supports
`skip_destroy`, but it is not Terraform lifecycle protection: an old state entry
with a changed `container_definitions` value still plans `delete,create`, and the
provider can call `ecs:DeregisterTaskDefinition` before registration. The release
model therefore uses append-only addresses. The current `candidate` and
`executor` collections are create-only; revision-keyed entries in the explicit
`retained_candidate_task_definitions` and `retained_executor_task_definitions`
maps create historical resources with `ignore_changes = all` and
`skip_destroy = true`. Both maps default to `{}`, so fresh deployments do not
create duplicate task-definition revisions. The general release-deployer policy contains no
deregistration authority. Old inactive revisions are retained for a separate,
reviewed housekeeping process outside this release role. `logs:CreateLogGroup`
and `logs:PutRetentionPolicy` remain limited to the backend, worker,
application-canary, and read-only-canary Stage B log groups. The shared
`/ecs/mscqr-production/full-rls-green` executor log group remains Stage A-owned
and is intentionally excluded from Stage B creation authority.
Terraform refresh also requires the read-only `logs:ListTagsForResource` action;
it is limited to those same four exact log-group ARNs without a trailing `:*`.
The existing exact tagging statements include the same read-only-canary log-group
and task-definition ARNs because Terraform tags both resources during creation.

## Failed-apply IAM correction — stop before retry

The first apply of the validated plan stopped because the release-deployer's live
policy did not authorize `logs:PutRetentionPolicy`, and the previously proposed
`ecs:DeregisterTaskDefinition` wildcard would have granted unrelated production
task-definition deregistration. AWS does not support resource-level scoping for
that action, so it is removed entirely. The Terraform task-definition retention
setting is the correction: old revisions remain registered and cleanup is
deferred to a separate controlled housekeeping path. `logs:PutRetentionPolicy`
is limited to the four exact Stage B log-group ARN patterns, also constrained to
`eu-west-2`.

Before the first append-only plan, the operator must separately and explicitly
add the eleven deployed revision-1 definitions to the private revision-keyed
history maps, back up state, verify source presence and destination absence, and
move the eleven current state addresses to those destinations. The exact
`terraform state mv` commands are recorded in the reconciliation document; they
are not run by this PR or automatically. The read-only-canary family has no
prior state entry and is not moved. After that migration the expected
task-definition shape is twelve current `create` actions, eleven retained
`no-op` actions, and zero task-definition deletes or replacements. Every later
release adds a unique generation and moves all twelve current addresses,
including read-only-canary, without touching older generations. Retained
revision selection is based on the highest numeric ECS revision per family, not
Terraform map, generation-key, or resource ordering.
The validator rejects every task-definition delete, destroy, or delete/create
replacement.

A partial append-only apply may leave a safe retry shape: each of the twelve
current addresses is either `create` or an exact-release `no-op`, and those two
counts must sum to twelve. A current no-op must match the intended image,
release/provenance metadata, package/runtime inputs, immutable task settings,
tags, and current broker mapping; retained history remains no-op only. The
audit records `currentCreates` and `currentNoOps` separately. If the broker
update failed after a current definition was registered, the retry audit also
records that current no-op in the atomic broker rollover evidence: the live
broker ARN must be an exact member of the retained ARN set and the planned
broker mapping must target that exact current resource address. Every broker
mode must appear exactly once in the audit mapping and must resolve to its
expected task-definition family; missing, duplicated, swapped, or unrelated
mode mappings fail closed, as does retained live mapping without its matching
atomic rollover evidence. ECS observation is centralized and complete: the
shared helper discovers all services and RUNNING/PENDING tasks in the exact
production cluster, consumes all pages, describes every reference, and rejects
unknown services, task ARNs, malformed or reserved task-definition families,
duplicate entries, incomplete responses, or AccessDenied. Valid unrelated
workloads such as `mscqr-backend` remain in the evidence with
`stageBScoped=false` and are excluded from Stage B reference decisions. The
validator also requires schema version,
the exact production cluster ARN, and a caller ARN for the MFA-backed release
deployer before accepting the audit.

After this corrective PR is merged, update the live provider managed policy from
v4 and verify the complete attachment set before any Terraform retry. Do not
retry the previous saved plan, manually delete the partial log group, manually
set retention, manually deregister task definitions, or change any runtime,
service, database, ALB, DNS, or traffic resource. Refresh the MFA-backed release
session, reconcile the partial state, create exactly one fresh plan and one
plan-bound reference audit, and stop for independent review before apply.

### Canonical ECS read-only observation contract

The reference-audit companion is the single source-controlled home for the
ECS observation contract. It contains exactly these read actions:

- `ecs:ListServices`
- `ecs:DescribeServices`
- `ecs:ListTasks`
- `ecs:DescribeTasks`
- `ecs:DescribeTaskDefinition`

`ListServices` and `ListTasks` are unavoidable because the audit must discover
the complete service set and active task set before it can
prove that no reference was omitted. AWS evaluates those List operations with
`Resource: "*"`; the companion policy restricts them with the exact
`aws:RequestedRegion=eu-west-2` and `ecs:cluster=arn:aws:ecs:eu-west-2:368992683803:cluster/mscqr-prod-euw2-main`
conditions. `DescribeServices` uses the exact production service ARN pattern
plus the same conditions. The runtime `DescribeTasks` API call is authorized
against `Resource: "*"`; its isolated read-only statement retains the exact
region and cluster conditions. AWS does not provide a
resource-level scope for `ecs:DescribeTaskDefinition`, so that read uses the
isolated `Resource: "*"` statement with only the exact region condition.
`ListClusters` and `DescribeClusters` are not required: the exact production
cluster ARN is already a source-controlled Stage B contract value.

All five reads are performed by the shared
`scripts/aws/production-green-stage-b-ecs-observations.mjs` helper. It consumes
the exact cluster, fully consumes list pagination, describes every returned
service/task and referenced task definition, rejects AccessDenied, incomplete
pages, duplicate/unknown ARNs, reserved unknown families, and response identity
mismatches. Valid unrelated shared-cluster workloads remain visible but are not
used for Stage B decisions. The active task set is discovered once with
`ListTasks(desiredStatus=RUNNING)`; `PENDING` evidence is derived from
`DescribeTasks.lastStatus`, never from `ListTasks(desiredStatus=PENDING)`, and
transitional statuses are recorded separately. The read-only post-apply command
`scripts/aws/verify-production-green-stage-b-ecs-observations.mjs` uses the same
helper and writes deterministic evidence.
RUNNING/PENDING/transitional evidence. The reference-audit path and any
post-apply ECS readback must use this helper; they must not issue ad hoc
List/Describe calls.

The companion policy must be attached to the exact
`mscqr-production-release-deployer` role before Phase 0 verification or audit
generation. A failed List call is an authorization blocker, not an empty ECS
observation, and must stop the release before any plan or runtime action.

Merging source alone does not update AWS. The live provider-recovery policy must be version-updated after merge from v4, and the companion policy must be created
or updated from `ReferenceAuditReadOnly-v1`. The sequence below is failure-safe:
all pre-mutation checks and the companion update, attachment, semantic readback,
complete entity verification, and read-only simulation occur before the provider
policy is changed. A companion failure therefore leaves the existing combined
provider default intact:

```sh
set -euo pipefail
PROVIDER_POLICY_NAME='MSCQRProductionGreenStageBProviderRecovery'
AUDIT_POLICY_NAME='MSCQRProductionGreenStageBReferenceAuditReadOnly'
PROVIDER_DOCUMENT="$PWD/documents/ops/iam/MSCQRProductionGreenStageBProviderRecovery-v4.json"
AUDIT_DOCUMENT="$PWD/documents/ops/iam/MSCQRProductionGreenStageBReferenceAuditReadOnly-v1.json"
FINAL_WRITE_POLICY_NAME='MSCQRProductionGreenStageBFinalApplyWrite'
FINAL_WRITE_DOCUMENT="$PWD/documents/ops/iam/MSCQRProductionGreenStageBFinalApplyWrite-v1.json"
ROLE_NAME='mscqr-production-release-deployer'
EXPECTED_ACCOUNT_ID='368992683803'
EXPECTED_ROLE_ARN="arn:aws:iam::${EXPECTED_ACCOUNT_ID}:role/${ROLE_NAME}"
ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

# A. Pre-mutation validation
test "$ACCOUNT_ID" = "$EXPECTED_ACCOUNT_ID"
ROLE_ARN="$(aws iam get-role --role-name "$ROLE_NAME" --query Role.Arn --output text)"
test "$ROLE_ARN" = "$EXPECTED_ROLE_ARN"
PROVIDER_POLICY_ARN="arn:aws:iam::${ACCOUNT_ID}:policy/${PROVIDER_POLICY_NAME}"
AUDIT_POLICY_ARN="arn:aws:iam::${ACCOUNT_ID}:policy/${AUDIT_POLICY_NAME}"
FINAL_WRITE_POLICY_ARN="arn:aws:iam::${ACCOUNT_ID}:policy/${FINAL_WRITE_POLICY_NAME}"
aws iam get-policy --policy-arn "$PROVIDER_POLICY_ARN" --output json > "$TMP_DIR/provider-policy.json"
test "$(jq -r '.Policy.PolicyName' "$TMP_DIR/provider-policy.json")" = "$PROVIDER_POLICY_NAME"
test "$(jq -r '.Policy.Arn' "$TMP_DIR/provider-policy.json")" = "$PROVIDER_POLICY_ARN"
PROVIDER_DEFAULT_VERSION_ID="$(jq -r '.Policy.DefaultVersionId' "$TMP_DIR/provider-policy.json")"
test -n "$PROVIDER_DEFAULT_VERSION_ID"
test "$(jq -r '.Policy.AttachmentCount' "$TMP_DIR/provider-policy.json")" = 1
test "$(jq -r '.Policy.PermissionsBoundaryUsageCount' "$TMP_DIR/provider-policy.json")" = 0
PROVIDER_VERSION_COUNT="$(aws iam list-policy-versions --policy-arn "$PROVIDER_POLICY_ARN" --query 'Versions | length(@)' --output text)"
test "$PROVIDER_VERSION_COUNT" -lt 5

AUDIT_POLICY_EXISTS=true
if aws iam get-policy --policy-arn "$AUDIT_POLICY_ARN" --output json > "$TMP_DIR/audit-policy.json" 2>"$TMP_DIR/audit-policy.error"; then
  test "$(jq -r '.Policy.PolicyName' "$TMP_DIR/audit-policy.json")" = "$AUDIT_POLICY_NAME"
  test "$(jq -r '.Policy.Arn' "$TMP_DIR/audit-policy.json")" = "$AUDIT_POLICY_ARN"
  test "$(jq -r '.Policy.AttachmentCount' "$TMP_DIR/audit-policy.json")" -le 1
  test "$(jq -r '.Policy.PermissionsBoundaryUsageCount' "$TMP_DIR/audit-policy.json")" = 0
  AUDIT_VERSION_COUNT="$(aws iam list-policy-versions --policy-arn "$AUDIT_POLICY_ARN" --query 'Versions | length(@)' --output text)"
  test "$AUDIT_VERSION_COUNT" -lt 5
else
  grep -q 'NoSuchEntity' "$TMP_DIR/audit-policy.error"
  AUDIT_POLICY_EXISTS=false
fi

ROLE_ATTACHMENTS="$(aws iam list-attached-role-policies --role-name "$ROLE_NAME" --output json)"
ROLE_ATTACHMENT_COUNT="$(jq '.AttachedPolicies | length' <<<"$ROLE_ATTACHMENTS")"
ROLE_POLICY_LIMIT="$(aws iam get-account-summary --query 'SummaryMap.RolePolicyListSizeLimit' --output text)"
test "$ROLE_ATTACHMENT_COUNT" -le "$ROLE_POLICY_LIMIT"

reject_unexpected_entities() {
  local policy_arn="$1" entities_file="$2" require_role="$3"
  aws iam list-entities-for-policy --policy-arn "$policy_arn" --output json > "$entities_file"
  test "$(jq '.PolicyUsers | length' "$entities_file")" -eq 0
  test "$(jq '.PolicyGroups | length' "$entities_file")" -eq 0
  test "$(jq '.PolicyRoles | length' "$entities_file")" -le 1
  if [[ "$(jq '.PolicyRoles | length' "$entities_file")" -eq 1 ]]; then
    test "$(jq -r '.PolicyRoles[0].RoleName' "$entities_file")" = "$ROLE_NAME"
  fi
  if [[ "$require_role" = true ]]; then
    test "$(jq '.PolicyRoles | length' "$entities_file")" -eq 1
  fi
}

reject_unexpected_entities "$PROVIDER_POLICY_ARN" "$TMP_DIR/provider-entities.json" true
if [[ "$AUDIT_POLICY_EXISTS" = true ]]; then
  reject_unexpected_entities "$AUDIT_POLICY_ARN" "$TMP_DIR/audit-entities.json" false
  AUDIT_ROLE_COUNT="$(jq '.PolicyRoles | length' "$TMP_DIR/audit-entities.json")"
else
  AUDIT_ROLE_COUNT=0
fi
if [[ "$AUDIT_ROLE_COUNT" -eq 0 && "$ROLE_ATTACHMENT_COUNT" -ge "$ROLE_POLICY_LIMIT" ]]; then
  echo 'Refusing companion attachment: release-role managed-policy quota is full.' >&2
  exit 1
fi

# B. Companion create/update
if [[ "$AUDIT_POLICY_EXISTS" = true ]]; then
  AUDIT_VERSION_ID="$(aws iam create-policy-version \
    --policy-arn "$AUDIT_POLICY_ARN" \
    --policy-document "file://${AUDIT_DOCUMENT}" \
    --set-as-default \
    --query PolicyVersion.VersionId --output text)"
else
  aws iam create-policy \
    --policy-name "$AUDIT_POLICY_NAME" \
    --policy-document "file://${AUDIT_DOCUMENT}" \
    --query Policy.Arn --output text | grep -Fx "$AUDIT_POLICY_ARN"
  AUDIT_VERSION_ID="$(aws iam get-policy --policy-arn "$AUDIT_POLICY_ARN" \
    --query Policy.DefaultVersionId --output text)"
fi

# C. Companion attach and complete verification
aws iam attach-role-policy --role-name "$ROLE_NAME" --policy-arn "$AUDIT_POLICY_ARN"
aws iam get-policy-version --policy-arn "$AUDIT_POLICY_ARN" --version-id "$AUDIT_VERSION_ID" \
  --query PolicyVersion.Document --output json > "$TMP_DIR/live-audit-policy.json"
cmp <(jq -S . "$AUDIT_DOCUMENT") <(jq -S . "$TMP_DIR/live-audit-policy.json")

verify_complete_policy_entities() {
  local policy_arn="$1" policy_name="$2" metadata_file="$TMP_DIR/${policy_name}-metadata.json" entities_file="$TMP_DIR/${policy_name}-entities.json"
  aws iam get-policy --policy-arn "$policy_arn" --output json > "$metadata_file"
  aws iam list-entities-for-policy --policy-arn "$policy_arn" --output json > "$entities_file"
  test "$(jq -r '.Policy.PolicyName' "$metadata_file")" = "$policy_name"
  test "$(jq -r '.Policy.AttachmentCount' "$metadata_file")" = 1
  test "$(jq -r '.Policy.PermissionsBoundaryUsageCount' "$metadata_file")" = 0
  test "$(jq '.PolicyRoles | length' "$entities_file")" -eq 1
  test "$(jq '.PolicyGroups | length' "$entities_file")" -eq 0
  test "$(jq '.PolicyUsers | length' "$entities_file")" -eq 0
  test "$(jq -r '.PolicyRoles[0].RoleName' "$entities_file")" = "$ROLE_NAME"
}

verify_complete_policy_entities "$AUDIT_POLICY_ARN" "$AUDIT_POLICY_NAME"

# Read-only IAM simulation proves the release role can complete the audit before
# the provider policy is replaced. A denied result stops before provider mutation.
simulate_audit_read() {
  local action="$1" resource="$2" result
  result="$(aws iam simulate-principal-policy \
    --policy-source-arn "$ROLE_ARN" \
    --action-names "$action" \
    --resource-arns "$resource" \
    --context-entries \
      ContextKeyName=aws:RequestedRegion,ContextKeyValues=eu-west-2,ContextKeyType=string \
      ContextKeyName=ecs:cluster,ContextKeyValues=arn:aws:ecs:eu-west-2:368992683803:cluster/mscqr-prod-euw2-main,ContextKeyType=string \
    --output json)"
  test "$(jq -r '.EvaluationResults[0].EvalDecision' <<<"$result")" = allowed
}
simulate_audit_read iam:ListAttachedRolePolicies '*'
simulate_audit_read ecs:ListServices '*'
simulate_audit_read ecs:DescribeServices 'arn:aws:ecs:eu-west-2:368992683803:service/mscqr-prod-euw2-main/*'
simulate_audit_read ecs:ListTasks '*'
simulate_audit_read ecs:DescribeTasks '*'
simulate_audit_read ecs:DescribeTaskDefinition '*'
simulate_audit_read lambda:GetFunctionConfiguration 'arn:aws:lambda:eu-west-2:368992683803:function:mscqr-production-rls-approval-broker'
simulate_audit_read lambda:GetFunctionConfiguration 'arn:aws:lambda:eu-west-2:368992683803:function:mscqr-production-rls-approval-broker:*'

# D. Final-write companion create/update, attach, and complete verification
# This block is reached before any provider-policy mutation.
validate_final_write_entities() {
  local entities_file="$1"
  aws iam list-entities-for-policy --policy-arn "$FINAL_WRITE_POLICY_ARN" --output json > "$entities_file"
  test "$(jq '.PolicyUsers | length' "$entities_file")" -eq 0
  test "$(jq '.PolicyGroups | length' "$entities_file")" -eq 0
  test "$(jq '.PolicyRoles | length' "$entities_file")" -le 1
  if [[ "$(jq '.PolicyRoles | length' "$entities_file")" -eq 1 ]]; then
    test "$(jq -r '.PolicyRoles[0].RoleName' "$entities_file")" = "$ROLE_NAME"
  fi
}
FINAL_WRITE_EXISTS=true
if aws iam get-policy --policy-arn "$FINAL_WRITE_POLICY_ARN" --output json > "$TMP_DIR/final-write-policy.json" 2>"$TMP_DIR/final-write-policy.error"; then
  test "$(jq -r '.Policy.PolicyName' "$TMP_DIR/final-write-policy.json")" = "$FINAL_WRITE_POLICY_NAME"
  FINAL_WRITE_DEFAULT_VERSION_ID="$(jq -r '.Policy.DefaultVersionId' "$TMP_DIR/final-write-policy.json")"
  FINAL_WRITE_VERSION_COUNT="$(aws iam list-policy-versions --policy-arn "$FINAL_WRITE_POLICY_ARN" --query 'Versions | length(@)' --output text)"
  test "$FINAL_WRITE_VERSION_COUNT" -lt 5
  validate_final_write_entities "$TMP_DIR/final-write-entities-before.json"
  aws iam get-policy-version --policy-arn "$FINAL_WRITE_POLICY_ARN" --version-id "$FINAL_WRITE_DEFAULT_VERSION_ID" \
    --query PolicyVersion.Document --output json > "$TMP_DIR/live-final-write-policy.json"
  if cmp <(jq -S . "$FINAL_WRITE_DOCUMENT") <(jq -S . "$TMP_DIR/live-final-write-policy.json"); then
    FINAL_WRITE_VERSION_ID="$FINAL_WRITE_DEFAULT_VERSION_ID"
  else
    FINAL_WRITE_VERSION_ID="$(aws iam create-policy-version --policy-arn "$FINAL_WRITE_POLICY_ARN" \
      --policy-document "file://${FINAL_WRITE_DOCUMENT}" --set-as-default \
      --query PolicyVersion.VersionId --output text)"
  fi
else
  grep -q 'NoSuchEntity' "$TMP_DIR/final-write-policy.error"
  FINAL_WRITE_EXISTS=false
  aws iam create-policy --policy-name "$FINAL_WRITE_POLICY_NAME" \
    --policy-document "file://${FINAL_WRITE_DOCUMENT}" \
    --query Policy.Arn --output text | grep -Fx "$FINAL_WRITE_POLICY_ARN"
  FINAL_WRITE_VERSION_ID="$(aws iam get-policy --policy-arn "$FINAL_WRITE_POLICY_ARN" \
    --query Policy.DefaultVersionId --output text)"
fi

# Reject users, groups, or another role before attachment. An empty entity set
# is valid for a newly created policy; the exact role is required afterward.
FINAL_WRITE_ENTITIES="$TMP_DIR/final-write-entities.json"
validate_final_write_entities "$FINAL_WRITE_ENTITIES"
ROLE_ATTACHMENTS="$(aws iam list-attached-role-policies --role-name "$ROLE_NAME" --output json)"
FINAL_WRITE_ATTACHED="$(jq -r --arg name "$FINAL_WRITE_POLICY_NAME" 'any(.AttachedPolicies[]; .PolicyName == $name)' <<<"$ROLE_ATTACHMENTS")"
if [[ "$FINAL_WRITE_ATTACHED" = false ]]; then
  test "$ROLE_ATTACHMENT_COUNT" -lt "$ROLE_POLICY_LIMIT"
  aws iam attach-role-policy --role-name "$ROLE_NAME" --policy-arn "$FINAL_WRITE_POLICY_ARN"
fi
aws iam get-policy-version --policy-arn "$FINAL_WRITE_POLICY_ARN" \
  --version-id "$FINAL_WRITE_VERSION_ID" --query PolicyVersion.Document --output json \
  > "$TMP_DIR/live-final-write-policy.json"
cmp <(jq -S . "$FINAL_WRITE_DOCUMENT") <(jq -S . "$TMP_DIR/live-final-write-policy.json")
verify_complete_policy_entities "$FINAL_WRITE_POLICY_ARN" "$FINAL_WRITE_POLICY_NAME"

# E. Provider v4 update — reached only after final-write setup succeeds
PROVIDER_VERSION_ID="$(aws iam create-policy-version \
  --policy-arn "$PROVIDER_POLICY_ARN" \
  --policy-document "file://${PROVIDER_DOCUMENT}" \
  --set-as-default \
  --query PolicyVersion.VersionId --output text)"

# F. Provider and unchanged audit verification
aws iam get-policy-version --policy-arn "$PROVIDER_POLICY_ARN" --version-id "$PROVIDER_VERSION_ID" \
  --query PolicyVersion.Document --output json > "$TMP_DIR/live-provider-policy.json"
cmp <(jq -S . "$PROVIDER_DOCUMENT") <(jq -S . "$TMP_DIR/live-provider-policy.json")
verify_complete_policy_entities "$PROVIDER_POLICY_ARN" "$PROVIDER_POLICY_NAME"
aws iam get-policy-version --policy-arn "$AUDIT_POLICY_ARN" --version-id "$AUDIT_VERSION_ID" \
  --query PolicyVersion.Document --output json > "$TMP_DIR/live-audit-policy-final.json"
cmp <(jq -S . "$AUDIT_DOCUMENT") <(jq -S . "$TMP_DIR/live-audit-policy-final.json")
verify_complete_policy_entities "$AUDIT_POLICY_ARN" "$AUDIT_POLICY_NAME"

# G. Final three-policy role verification
FINAL_ATTACHMENTS="$(aws iam list-attached-role-policies --role-name "$ROLE_NAME" --output json)"
jq -e --arg provider "$PROVIDER_POLICY_NAME" --arg audit "$AUDIT_POLICY_NAME" --arg final_write "$FINAL_WRITE_POLICY_NAME" \
  '([.AttachedPolicies[].PolicyName] | index($provider)) != null and ([.AttachedPolicies[].PolicyName] | index($audit)) != null and ([.AttachedPolicies[].PolicyName] | index($final_write)) != null' \
  <<<"$FINAL_ATTACHMENTS" >/dev/null
```

Final attachment verification must include `FINAL_WRITE_POLICY_NAME`; all three
managed policies must have exactly one role attachment, zero user/group
attachments, and zero permissions-boundary usage. The administrator must then
log out before the release-deployer session is refreshed.

`PROVIDER_VERSION_ID` and `AUDIT_VERSION_ID` are the actual AWS-managed-policy
version IDs returned by AWS; do not substitute or assume literal `v3`, `v4`, or
`v1` identifiers. The pre-mutation checks reject an unreviewed five-version
cleanup, a full release-role attachment quota, an unexpected policy principal,
or an account, role, or policy identity mismatch. For each policy, complete
entity verification requires `AttachmentCount=1`,
`PermissionsBoundaryUsageCount=0`, one role named
`mscqr-production-release-deployer`, zero groups, and zero users. If the
provider update or any later readback fails, stop and report the exact AWS
state; do not automatically roll back the provider default.

The update must preserve the single intended release-deployer role boundary. If AWS
reports the five-version limit, delete only an explicitly reviewed non-default
version. Root may perform only this policy-version update when no approved
non-root administrator exists; root must not run Terraform and must be logged out
immediately afterward. **H. Root/admin logout and fresh MFA release session:**
log the root or administrator session out immediately, then obtain a fresh MFA-backed release session for `mscqr-production-release-deployer`. Do not retry the
failed apply until both live policies match these source documents.
The failed Stage B apply must not be retried before both live policies match source.
The failed Stage B apply must not be retried before the live managed policy matches source; with this split, both live policies must match source.

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

When the same plan registers a current task definition and updates the broker,
the pre-apply audit records a planned atomic broker rollover. This is accepted
only when Terraform's plan configuration references
`local.broker_task_definition_arns`, the plan marks the corresponding task
definition ARN as relevant, the live broker ARN exactly equals the matching
retained revision's `before.arn`, and both resources are changed by that same
plan and plan SHA.
Unknown broker `after` values are never accepted from strings alone. Create-only
and no-op task definitions, missing dependencies, mismatched families, and
unrelated or stale broker references remain rejected.

The release role is not granted task execution or service mutation authority:
it has no `ecs:RunTask`, `ecs:StopTask`, `ecs:UpdateService`, or service
creation/deletion permission. The wildcard is therefore limited to the single
read-only metadata statement and is compensated by the application-layer audit
and validator contract.

Whenever the plan JSON changes, the release-deployer must perform a fresh
read-only audit and bind it to the exact plan SHA-256. Retained revisions may
remain referenced by the existing services and tasks; the audit accepts only
the exact full ARN of any explicitly retained revision for that family, not
just the newest revision or a same-family revision. The newest numeric ECS
revision is sequencing evidence only, while all retained generations remain
evidence. The audit also proves that the broker transition targets the new
current ARN. For append-only plans, the validator additionally compares the
exact current and retained task-definition entries, classification counts,
newest revision evidence, complete service/RUNNING/PENDING observations, and
broker mapping evidence against that same plan; missing, extra, stale, or
unrecorded entries invalidate the audit.
The validator also obtains the caller identity through the read-only
`aws sts get-caller-identity` check in its trusted validation process and
requires that observed ARN to equal the audit's `callerArn`; a caller-supplied
ARN or matching audit hash alone is not an attestation.
Any superseded legacy rollover, unknown family, or unrelated reference remains
fail-closed. The validator must accept the matching audit and both explicit
hashes before any apply; otherwise apply remains forbidden.

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
15. aws_iam_policy.broker
16. aws_iam_role_policy_attachment.broker
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

## Final partial-apply retry write contract

The failed retry registered the eleven existing current task-definition families
as revision 2, while the read-only-canary task definition was not registered.
The broker update was also denied, so its package, checksum, alias, and mappings
remain on the previous release. The next plan must treat the eleven revision-2
definitions as current same-release no-ops and the read-only-canary definition as
the sole current create.

The complete remaining write contract is source-controlled in
`MSCQRProductionGreenStageBFinalApplyWrite-v1.json`. It is a separate managed
policy because adding the retry writes to the already bounded v4 provider policy
would exceed AWS's 6,144-character managed-policy limit. It contains only:

- `ecs:RegisterTaskDefinition` for
  `mscqr-production-full-rls-green-read-only-canary:*`, requiring the exact
  production, Terraform, and `full-rls-green-stage-b` request tags and the exact
  permitted tag-key set (`Environment`, `ManagedBy`, `Component`);
- `lambda:UpdateFunctionConfiguration`, `lambda:UpdateFunctionCode`,
  `lambda:PublishVersion`, and `lambda:UpdateAlias` for the exact approval-broker
  function, constrained by its production/component resource tags.

The administrator must publish and attach this companion only to
`mscqr-production-release-deployer`, alongside v4 and the read-only audit
companion, before the fresh retry plan. No Lambda invocation, ECS task execution,
service update, IAM mutation, deregistration, database, ALB, DNS, or traffic
authority is granted. The old saved plan and audit remain stale and must not be
reused.

The preflight consumes the AWS CLI simulator schema exactly as returned by IAM:
`EvaluationResults`, `EvalActionName`, `EvalResourceName`, `EvalDecision`,
`MatchedStatements`, and `MissingContextValues`. CamelCase substitutes are not
accepted. The trusted caller must be the STS assumed-role ARN
`arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/<session>`;
the IAM role ARN is not sufficient.

The apply wrapper runs `terraform show -json` against the exact saved binary plan,
hashes the binary as `savedPlanSha256`, canonicalizes the generated JSON with
stable key ordering, and verifies `canonicalPlanJsonSha256` against the approved
plan and permission report. Lambda write simulations include RequestedRegion and
all three exact ResourceTag contexts required by the final-write policy.

## Final partial-retry PassRole correction and preflight

## Attested alias-only recovery lifecycle

When a reviewed partial apply proves an alias residue such as live version `2` and
attested desired version `3`, recovery is a separate Terraform lifecycle. The
canonical tfvars producer derives `stage_b_recovery_alias_target_version` from the
verified signed attestation; operators cannot select the version. Recovery-only
configuration binds broker package/environment and task-definition inputs to the
current verified state, removes current ECS resources from configuration after the
retained-history reconciliation, and permits exactly one non-no-op: the concrete
reviewed-alias update from the attested live version to the attested desired version.

The recovery plan must contain no ECS, broker-function, or broker-policy mutation.
`assertRecoveryOnlyPlan` and the recovery-only reference audit enforce this before
approval and again before apply. After the alias update is verified, the recovery
lifecycle ends; the next normal release starts a fresh evidence chain and resumes
the normal `aws_lambda_function.broker.version` alias expression.

The later partial apply proved that ECS task-definition registration needs
`iam:PassRole` for both the configured execution role and task role. The final
write companion therefore grants `iam:PassRole` only for:

- `arn:aws:iam::368992683803:role/mscqr-production-full-rls-green-read-only-canary-execution`
- `arn:aws:iam::368992683803:role/mscqr-production-full-rls-green-read-only-canary-task`

The statement requires `iam:PassedToService=ecs-tasks.amazonaws.com`. It does
not permit passing either role to Lambda, EC2, or another service, and adds no
role or policy creation, update, attachment, invocation, task execution,
service update, or task-definition deregistration authority.

Before any later apply, run
`scripts/aws/validate-production-green-stage-b-permissions.mjs` against the
exact plan and `MSCQRProductionGreenStageBPermissionManifest-v1.json`. The
preflight simulates every refresh, registration, tagging, Lambda-update,
alias-update, and PassRole combination derived from that plan and checks recent
CloudTrail denials after administrator publication. Its report is bound to the
plan SHA and must be supplied to
`scripts/apply-production-green-stage-b.mjs` with the plan-bound audit and valid
Stage B validator result. Missing, stale, denied, unscoped, or unreviewed
permission evidence blocks apply before Terraform is invoked.

Preflight generation and Terraform apply use separate identities. No reviewed
non-root Stage B audit principal exists, so the approved generator is the
administrator/root identity `arn:aws:iam::368992683803:root`; it simulates the
exact release role and performs the supplemental CloudTrail lookup. The
release-deployer is never granted `iam:SimulatePrincipalPolicy` or
`cloudtrail:LookupEvents`, and the apply wrapper never calls either API. The
report records `reportGeneratorCallerArn`, `simulatedRoleArn`, `applyRoleArn`,
the manifest SHA256, both plan hashes, the policy-publication window, and the
CloudTrail result. The administrator logs out immediately after generation;
the fresh MFA-backed release session only consumes the report.

Before image publication where release credentials are already available, and always
before backend initialization, run the two-section `npm run
stage-b:production-preflight` boundary documented in
`MSCQRProductionGreenStageBDeploymentCapabilities-v1.md`. Administrator/root owns policy
inspection, IAM simulation, forbidden controls, and signing. The release-deployer only
verifies that signed report and executes the aggregated safe-read probes; it never calls
IAM simulation or mutation APIs as probes.

The generated graph is verified with `npm run stage-b:capability-graph:verify`; regenerate
it only with `npm run stage-b:capability-graph:generate`. The reviewed credential order is
administrator/root preflight and signature, complete credential clearing, bootstrap-user
MFA `aws sts get-session-token --duration-seconds 129600`, exact
`aws sts assume-role --duration-seconds 3600` into
`mscqr-production-release-deployer`, bootstrap credential clearing, then release preflight.
The root `aws login --profile default` lifetime is external and must be checked with
`aws sts get-caller-identity` immediately before administrator use; an expired token or
caller mismatch stops the phase. Use the explicit phase launcher commands for the
administrator producer lifecycle: it records the exact PID, waits for terminal state,
and classifies the producer as `RUNNING`, `SUCCEEDED`, `FAILED`, or `TIMED_OUT` after
the bounded 1200-second process timeout. An empty output directory while `RUNNING` is
not a failed preflight. Invoke the initial phase explicitly with
`npm run stage-b:administrator-capability-preflight`; invoke the later plan-bound phase
only with `npm run stage-b:plan-bound-permission-preflight` after `PLAN_APPROVED` exists.
Each public preflight invocation asserts its exact caller. The administrator invocation
accepts only the explicit initial phase and its output/lifecycle paths. The plan-bound
permission invocation requires the exact approved plan, audit, and permission-manifest
inputs. The release invocation accepts only
`--identity release-deployer` plus those signed administrator artifacts and the canonical
backend, state, handoff, image-evidence, broker-package, tfvars, and binding-report inputs.
Invalid administrator evidence is recorded but never signed. The release phase aggregates
all independent direct-read failures and cannot initialize Terraform until that set is
empty.

The manifest explicitly enumerates all twelve possible current task-definition
create addresses: backend, worker, application-canary, read-only-canary, and
the eight executor modes. Each address independently proves
`ecs:RegisterTaskDefinition`, `ecs:TagResource`, PassRole for its exact
execution role, and PassRole for its exact task role with
`iam:PassedToService=ecs-tasks.amazonaws.com`. Unknown, duplicate, missing,
or family/address-mismatched entries fail before simulation.

The permission report is authenticated, not merely checksummed. The approved
administrator/root generator signs the canonical report digest with the existing
source-controlled Stage B asymmetric KMS key
`arn:aws:kms:eu-west-2:368992683803:key/437cdebd-95e7-4aba-8f0f-2ca08edb0478`,
using `MessageType=DIGEST` and `RSASSA_PSS_SHA_256`. It publishes the report and
detached signature together with the key ARN, algorithm, canonical report hash,
and signing timestamp. The release-deployer has only `kms:Verify` for that exact
key; it cannot sign reports. The apply wrapper performs the same key, algorithm,
hash, freshness, and signature checks in verification-only and real-apply modes.
A report SHA256 supplied by the release caller is integrity evidence only and is
never treated as authenticity. Missing, modified, stale, wrong-key, wrong-
algorithm, or self-asserted reports fail closed. No KMS key is created by this
contract or by the correction PR.

The manifest normalizes every required and forbidden evaluation as an exact
action/resource/context tuple and rejects any intersection at load time. The
exact ECS task-role PassRole tuples are therefore never also listed as forbidden;
forbidden examples use unrelated roles or a different `iam:PassedToService`
context. This keeps the twelve required mappings simulatable without weakening
the unrelated-role, wrong-service, wildcard, and wrong-account denials.

## Alias-only recovery evidence closure

The recovery-only lifecycle is represented by the exact `RECOVERY_ALIAS_ONLY` plan
profile and `recovery-alias-only` broker operation. Capture, approval, permission,
closure, and apply binding preserve both values; recovery evidence cannot fall back
to the baseline profile. Its broker evidence is limited to the reviewed alias with
`brokerUpdatePresent=false`, `brokerActions=["no-op"]`, and no pending broker
reference validation.

Recovery Terraform derives `BROKER_TASK_DEFINITIONS_JSON` and the broker IAM
`ecs:RunTask` resources from the same `active_broker_task_definition_arns` mapping.
In recovery-only mode that mapping is the verified state-derived recovery input; in
normal mode it is the planned broker mapping. This keeps the broker environment and
policy on one exact task-definition identity set.

Plan-bound administrator permission selection is profile-aware and authenticated by
the approved plan evidence. `NORMAL_STAGE_B_RELEASE` retains the existing broker
function, ECS, and managed-policy mutation mappings. `RECOVERY_ALIAS_ONLY` requires
the shared backend/apply mechanics plus the exact reviewed alias update mapping; it
does not require broker-policy, broker-function, or ECS mutation permissions because
those actions are forbidden by the approved recovery plan. A missing or mismatched
profile binding remains a fail-closed error.

## Broker Lambda environment safety after partial apply

The broker Lambda environment is capped before Terraform can apply it: the
UTF-8 JSON payload must remain at or below the reviewed 3500-byte safety bound,
inside AWS's 4096-byte aggregate limit. The broker keeps only the ten required
operational bindings in Lambda environment variables. Pre-deployment inventory
settings are derived at runtime from those authenticated broker bindings and the
fixed Stage B contract, so the same inventory task, image, roles, secret, RLS
role, network, and log-group values remain validated without duplicating them in
the environment.

The failed apply's observed legacy payload was 4405 UTF-8 bytes. The repaired
ten-binding payload is 3443 bytes in the canonical production plan; the contract
also rejects any future payload above 3500 bytes during planning.

After a partial apply, the consumed apply attempt is never retried. The current
remote state and the successful ECS/IAM mutations are reconciled first; a fresh
recovery plan uses the explicit `PARTIAL_APPLY_RECOVERY` profile and must contain
only the remaining reviewed Lambda mutations plus state-only cleanup of the
eleven deposed task-definition objects, with no duplicate ECS registration and no
service cutover before post-apply convergence.
