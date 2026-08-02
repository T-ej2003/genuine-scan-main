# Production Green Stage B plan reconciliation — 2026-07-29

## Scope and identity

- Checkout SHA: `6a8e94477949336616695bf3712ca0fd8ca85efa` (clean detached checkout).
- Terraform root: `infra/aws/terraform/production-green-stage-b`.
- Workspace: `production`.
- Caller: `arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/abhi-phase3`.
- Account: `368992683803`; region: `eu-west-2`.

## Reconciliation

## Permanent reference-audit IAM correction

The post-merge P1 finding is valid: AWS requires
`ecs:DescribeTaskDefinition` to use `Resource "*"`; ARN-scoped statements are
implicitly denied for this action. The read is limited to read-only task-
definition metadata in its own statement. The recorded production result is
cross-referenced in
[PRODUCTION_GREEN_STAGE_B_ECS_READBACK_RECOVERY_2026-07-30.md](../../ops/iam/PRODUCTION_GREEN_STAGE_B_ECS_READBACK_RECOVERY_2026-07-30.md).

The exact twelve source-controlled Stage B task-definition families remain
enforced by the Stage B audit generator and plan validator. The validator
rejects `mscqr-backend`, `mscqr-frontend`, unknown families, and unknown
Terraform addresses. Service and task listing remain cluster constrained, and
the broker Lambda read remains exact-function constrained. The release role is
not granted task execution or service mutation authority.

PR #161's v2 policy artifact remains immutable history for audit and rollback.
The [v2 artifact](../../ops/iam/MSCQRProductionGreenStageBProviderRecovery-v2.json)
is preserved, while the wildcard correction is preserved in the historical
[v3 artifact](../../ops/iam/MSCQRProductionGreenStageBProviderRecovery-v3.json).
The combined v3 document is 6,651 AWS-counted characters, 507 over the 6,144
managed-policy limit. The upcoming live update therefore loads the deployable
[v4 provider-recovery artifact](../../ops/iam/MSCQRProductionGreenStageBProviderRecovery-v4.json)
and creates or updates the [ReferenceAuditReadOnly-v1 companion](../../ops/iam/MSCQRProductionGreenStageBReferenceAuditReadOnly-v1.json).
V4 retains the reviewed recovery control-plane statements; the companion
contains exactly the seven permanent read-only audit statements. Both policies
attach only to `mscqr-production-release-deployer`. The live managed policies
remain on their pre-correction state until the separately authorized update
after the corrective PR merges. AWS's actual managed-policy version IDs must
be discovered from each live policy rather than assumed to be repository
suffixes.

The final refresh-contract correction adds two additional read-only IAM
permissions to the provider policy. `iam:ListAttachedRolePolicies` is scoped
to both administrator-created and imported read-only-canary role ARNs, while
`iam:GetRolePolicy` is scoped only to the execution role because it owns the
imported inline policy:

- `arn:aws:iam::368992683803:role/mscqr-production-full-rls-green-read-only-canary-execution`
- `arn:aws:iam::368992683803:role/mscqr-production-full-rls-green-read-only-canary-task`

The already-merged `iam:GetRole` and `iam:ListRolePolicies` grants remain
scoped to those same two roles. The execution-role-only `iam:GetRolePolicy`
grant is required to refresh the imported inline policy; no inline-policy read
is granted for the task role. These read-only refresh permissions do not allow
IAM role or policy creation, update, attachment, passing, or deletion, and use
no wildcard IAM resource. No runtime, service, secret, database, networking,
ALB, DNS, or traffic authority is added, and `ecs:DeregisterTaskDefinition`
remains absent.

The exact current plan also changes the broker inline policy resource
`aws_iam_role_policy.broker` in place. Its required write is
`iam:PutRolePolicy`, scoped only to
`arn:aws:iam::368992683803:role/mscqr-production-rls-approval-broker`, for the
`stage-b-broker` inline policy. The permission preflight maps and simulates
that exact address/type/action/resource tuple and rejects any other IAM role
policy update, create, delete, replacement, wildcard, or role mismatch. The
grant introduces no broader IAM mutation authority. The prior plan and audit
are stale after this merge and must not be reused.

## Append-only task-definition registration model

Normal Terraform destroys remain forbidden, including every
`aws_ecs_task_definition` `delete`, `destroy`, or `delete,create` replacement.
`skip_destroy = true` is an AWS provider argument, not Terraform lifecycle
protection; it does not remove replacement actions from a plan when an existing
state entry changes. The release role consequently retains no
`ecs:DeregisterTaskDefinition` authority.

The source model takes explicit revision-keyed history maps
`retained_candidate_task_definitions` and `retained_executor_task_definitions`.
Both default to `{}`, so a fresh deployment has exactly twelve current task
definition creates and zero retained resources. Each supplied entry contains a
generation key such as `<generation>-backend` plus the exact historical task
definition JSON. Retained resources use `ignore_changes = all`, while current
`candidate[...]` and `executor[...]` addresses register only the new release.

Before the first rollover, add the eleven existing revision-1 definitions to the
private history maps under one release generation. Back up state, verify every
source exists and every destination is absent, then run the separately approved
commands below. The destination key must match the map entry:

```sh
generation=<release-sha-prefix>
TF_WORKSPACE=production terraform -chdir=infra/aws/terraform/production-green-stage-b state pull > "/private/tmp/mscqr-stage-b-production-${generation}.state.backup.json"
TF_WORKSPACE=production terraform -chdir=infra/aws/terraform/production-green-stage-b state list

TF_WORKSPACE=production terraform -chdir=infra/aws/terraform/production-green-stage-b state mv 'aws_ecs_task_definition.candidate["backend"]' 'aws_ecs_task_definition.candidate_retained["<generation>-backend"]'
TF_WORKSPACE=production terraform -chdir=infra/aws/terraform/production-green-stage-b state mv 'aws_ecs_task_definition.candidate["canary"]' 'aws_ecs_task_definition.candidate_retained["<generation>-canary"]'
TF_WORKSPACE=production terraform -chdir=infra/aws/terraform/production-green-stage-b state mv 'aws_ecs_task_definition.candidate["worker"]' 'aws_ecs_task_definition.candidate_retained["<generation>-worker"]'
TF_WORKSPACE=production terraform -chdir=infra/aws/terraform/production-green-stage-b state mv 'aws_ecs_task_definition.executor["full-rls-admin-bootstrap"]' 'aws_ecs_task_definition.executor_retained["<generation>-full-rls-admin-bootstrap"]'
TF_WORKSPACE=production terraform -chdir=infra/aws/terraform/production-green-stage-b state mv 'aws_ecs_task_definition.executor["full-rls-admin-ownership"]' 'aws_ecs_task_definition.executor_retained["<generation>-full-rls-admin-ownership"]'
TF_WORKSPACE=production terraform -chdir=infra/aws/terraform/production-green-stage-b state mv 'aws_ecs_task_definition.executor["full-rls-capability-preflight"]' 'aws_ecs_task_definition.executor_retained["<generation>-full-rls-capability-preflight"]'
TF_WORKSPACE=production terraform -chdir=infra/aws/terraform/production-green-stage-b state mv 'aws_ecs_task_definition.executor["full-rls-role-provision"]' 'aws_ecs_task_definition.executor_retained["<generation>-full-rls-role-provision"]'
TF_WORKSPACE=production terraform -chdir=infra/aws/terraform/production-green-stage-b state mv 'aws_ecs_task_definition.executor["full-rls-role-verify"]' 'aws_ecs_task_definition.executor_retained["<generation>-full-rls-role-verify"]'
TF_WORKSPACE=production terraform -chdir=infra/aws/terraform/production-green-stage-b state mv 'aws_ecs_task_definition.executor["full-rls-rollback"]' 'aws_ecs_task_definition.executor_retained["<generation>-full-rls-rollback"]'
TF_WORKSPACE=production terraform -chdir=infra/aws/terraform/production-green-stage-b state mv 'aws_ecs_task_definition.executor["full-rls-runtime-policy"]' 'aws_ecs_task_definition.executor_retained["<generation>-full-rls-runtime-policy"]'
TF_WORKSPACE=production terraform -chdir=infra/aws/terraform/production-green-stage-b state mv 'aws_ecs_task_definition.executor["full-rls-verification"]' 'aws_ecs_task_definition.executor_retained["<generation>-full-rls-verification"]'
```

The migration preserves all eleven existing revisions. It is not performed by
this PR, and no import, `state rm`, or `state mv` has been executed here. The
read-only-canary has no prior state and remains the twelfth current create.
Before the first successful read-only-canary creation, every retained generation
must independently contain exactly the same eleven families: backend, worker,
application-canary, and the eight executor modes. Multiple complete eleven-family
generations are valid; validation groups entries by immutable generation key and
does not infer validity from one global retained count. A generation with ten or
twelve entries, a missing family, a duplicate family, or a read-only-canary entry
is rejected in this pre-canary history.
After the first rollover, the plan contains twelve current creates and eleven
retained no-ops. For the second rollover, add a second generation to the maps,
move all twelve current state instances, including
`candidate["read_only_canary"]`, to that generation's unique retained
addresses, and leave the first generation untouched. Once read-only-canary has
been created, each newly rotated generation must contain all twelve families;
older eleven-family generations remain valid permanently. Every later rollover
therefore contains all twelve families in its newest retained generation and
twelve current creates. Duplicate generation keys, occupied destinations,
missing sources, static family-only keys, and retained creates are rejected.
The audit keeps every retained generation, groups entries by family, and selects
the newest retained entry by the highest numeric ECS revision, never by map,
generation-key, or resource ordering. The audit still proves the exact twelve
family allowlist, complete service/task reads, and plan-bound broker mapping to
the new current addresses.

A retry after a partial append-only apply may safely contain a mixture of current
`create` and current `no-op` actions. The current counts must always total twelve;
no-op definitions must exactly match the intended release and must not use a
retained ARN. If the broker update lags a partial task-definition registration,
the no-op current family is included in the atomic broker proof: the live broker
must reference an exact retained ARN and the plan must target the exact current
task-definition address. Services, RUNNING tasks, and PENDING tasks may reference any
explicitly retained full ARN for the exact family. The newest retained revision
is sequencing evidence only, not the sole permitted live reference; older
retained generations remain represented and protected.

The validator binds append-only audit contents to the exact plan, including all
current and retained entries, classification counts, newest-revision evidence,
complete service/RUNNING/PENDING observations, and broker mappings. Missing,
extra, stale, or unrecorded evidence is rejected. Broker evidence must contain
the complete exact mode set once each, with each mode mapped to its expected
family; swapped, duplicated, missing, or unrelated mappings are rejected, and
every retained live broker mapping must have matching atomic rollover evidence.
The trusted validation process obtains `aws sts get-caller-identity` and
requires that observed caller ARN to equal the audit `callerArn`; an
audit-supplied ARN or matching hash is not accepted as caller attestation.
Cluster-wide ECS observations for unrelated workloads remain recorded but are
outside the Stage B family decision; unknown `mscqr-production-*` families are
still rejected.
The audit consumer also requires the shared schema version, the exact production
cluster ARN, and the MFA-backed release-deployer caller identity.

This model does not authorize ECS service updates, task execution, database
actions, broker invocation, ALB, DNS, or traffic changes. Old inactive revision
cleanup is a separate controlled housekeeping process.

The permanent release-deployer policy supplies the read-only calls needed for
this audit; no temporary policy is required. The audit is regenerated whenever
the plan JSON changes and is accepted only when its file SHA-256, embedded plan
SHA-256, old ARNs, zero live references, family matches, and rollback ARNs all
verify.

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

## Final retry permission boundary

The partial apply completed eleven current task-definition registrations at
revision 2, but did not register the read-only-canary definition and did not
update the broker. The retry plan therefore permits eleven current no-ops plus
one exact read-only-canary create, with all eleven revision-1 retained entries
remaining no-op and no task-definition deletion.

The remaining write APIs are isolated in the source-controlled
`MSCQRProductionGreenStageBFinalApplyWrite-v1.json` companion because placing
them in v4 would exceed AWS's managed-policy document limit. The companion is
limited to exact read-only-canary registration with the three required request
tags and tag-key allowlist, plus the four Lambda update/release actions for the
exact approval broker function. It is attached only to the release-deployer
role. v4 continues to carry the bounded refresh/read and previously reviewed
recovery permissions; the audit companion remains read-only.

This split adds no IAM mutation authority, no deregistration authority, no task
execution, no Lambda invocation, and no service, database, ALB, DNS, or traffic
authority. The final retry still requires a fresh exact-SHA image set, a new
plan-bound audit, and a valid validator result before applying the saved plan.

The failed retry also proved the complete ECS role-passing boundary. Registering
the read-only-canary task definition requires `iam:PassRole` for both its exact
execution and task role ARNs, conditioned on
`iam:PassedToService=ecs-tasks.amazonaws.com`. The final-write policy adds only
that two-ARN statement; no other role, service, IAM mutation, ECS execution,
service update, Lambda invocation, or deregistration authority is introduced.

The source-controlled permission manifest records the evidence-backed refresh,
registration, tagging, broker, alias, and PassRole API combinations. A fresh
permission preflight must simulate every combination and inspect recent
CloudTrail denials before apply. The apply wrapper requires that report, the
exact plan SHA, the fresh audit SHA, and a valid validator result to bind to the
same saved plan; Terraform cannot be invoked without all four gates.

Preflight generation is administrator-operated and apply is
release-operated. Because no reviewed non-root audit principal exists, the
approved root/admin generator simulates the release-deployer policy and runs
the supplemental CloudTrail lookup; the release-deployer receives neither
permission and the wrapper never calls those APIs. The report binds the
generator identity, simulated role, exact manifest hash, binary/canonical plan
hashes, and CloudTrail query window. The manifest explicitly covers all twelve
current task-definition create addresses and their exact registration, tagging,
execution-role PassRole, and task-role PassRole evaluations.

The permission gate uses the real PascalCase IAM simulator response contract and
rejects missing or nonempty `MissingContextValues`. Caller evidence must be the
exact STS assumed-role ARN. The saved binary plan is verified with both
`savedPlanSha256` and a stable-key `canonicalPlanJsonSha256` derived from
`terraform show -json`; an approved JSON file cannot be paired with another
binary plan. Lambda write checks supply `aws:RequestedRegion` plus the exact
Environment, ManagedBy, and Component ResourceTag contexts.

Permission-preflight reports are administrator-authenticated detached artifacts.
The root/admin generator signs the canonical report digest with the existing
source-controlled Stage B asymmetric KMS key
`arn:aws:kms:eu-west-2:368992683803:key/437cdebd-95e7-4aba-8f0f-2ca08edb0478`
using `RSASSA_PSS_SHA_256` and `MessageType=DIGEST`. The release-deployer may
verify only that exact key and cannot sign or replace a report. The apply wrapper
requires the trusted key ARN, algorithm, report hash, detached signature,
timestamp, exact plan bindings, manifest binding, generator identity, and
CloudTrail window before either verification-only or real apply. A report hash
alone is not an authenticity proof, and no KMS key is created by this contract.

The permission manifest also requires the normalized required/forbidden
action-resource-context tuple sets to be disjoint. The twelve exact task-role
PassRole tuples are required only with `iam:PassedToService=ecs-tasks.amazonaws.com`;
forbidden cases use unrelated roles or a different service context, so the same
decision is never required to be both allowed and denied.
