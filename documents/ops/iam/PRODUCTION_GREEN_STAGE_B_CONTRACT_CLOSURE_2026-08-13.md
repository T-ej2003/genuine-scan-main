# Production Green Stage B contract closure

This source-only change closes the Stage B semantic-census gaps identified for
protected source `f2f7a4a803a55492095f0d869dc0f51f8f5e2abe`. It does not
apply Terraform or change any AWS resource.

## Contract authority

The semantic gate now validates every root Stage B Terraform declaration and
all 95 configured attributes. It classifies source fields as exact immutable,
source-bound, reviewed transition, provider normalization, computed-only,
sensitive hash-bound, or rejected. Unknown declarations, fields, references,
outputs, and checks remain fail-closed.

The backend ECS Exec inline-policy create is admitted only for
`aws_iam_role_policy.backend_ecs_exec`, the backend task role, the fixed
policy name, and the four reviewed SSM message-channel actions. It rejects a
role substitution, policy-name substitution, wildcard action, extra action,
condition, or any unrelated inline-policy change.

Broker environment validation uses the same canonical reference set in
Terraform configuration and plan semantics. It binds both the inventory
database-secret reference and inventory RLS role without accepting injected or
deleted variables.

## Apply capability

The release-deployer manifest and FinalApplyWrite policy add only
`iam:PutRolePolicy` for the exact backend task role. Preflight derives that
evaluation only when the reviewed backend ECS Exec inline-policy create is in
the saved plan. It separately proves deny for another role, wildcard target,
DeleteRolePolicy, AttachRolePolicy, trust-policy changes, and permissions
boundary changes.

Existing `iam:PassRole` for the backend task role is unchanged because the
already-reviewed backend task-definition registration requires it; this change
does not expand PassRole.

To keep both managed-policy documents under AWS's 6,144-character limit, the
existing broker policy-version prune statement is housed in ProviderRecovery.
FinalApplyWrite is 6,063 characters and ProviderRecovery is 6,075 characters.
The allowed action/resource tuple is unchanged by that placement move.

## Required production evidence after merge

Run the normal Stage B preflight against a fresh saved plan. It must report
the exact backend inline-policy `iam:PutRolePolicy` evaluation as allowed and
all negative IAM evaluations as denied before Terraform apply is permitted.
