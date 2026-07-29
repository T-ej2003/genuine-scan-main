# Production Green Stage B ECS readback recovery — 2026-07-30

## Root cause and correction

CloudTrail recorded the exact failed action:

    ecs:DescribeTaskDefinition on resource: *

The existing registration policy incorrectly scoped that action to
task-definition ARNs. IAM simulation confirmed the ARN-scoped request is an
implicit deny because this ECS action requires Resource star.

The new separately attached, read-only policy is
MSCQRProductionGreenStageBTaskDefinitionDescribeRead. Its canonical SHA-256 is:

    ce5565e8b15706a5e9a7f4e91ef17d0cf52e05a23e313e8fd1afe181ce96b194

It contains one statement: ecs:DescribeTaskDefinition with Resource star.
Access Analyzer returned zero findings. Live simulation allows that read while
ecs:RunTask and ecs:UpdateService remain explicit denies and
ecs:DeregisterTaskDefinition remains denied.

## Live task-definition reconciliation

All eleven task definitions are ACTIVE, revision 1, registered by the
mscqr-production-release-deployer abhi-phase3 session between
00:00:38.230 and 00:00:38.520 Europe/London. Every definition has the exact
production/Terraform/full-rls-green-stage-b tags and an immutable ECR digest.
The candidate definitions use their exact candidate task/execution roles; all
eight executor definitions use the exact executor task/execution roles.

- mscqr-production-rls-green-backend-candidate
- mscqr-production-rls-green-worker-candidate
- mscqr-production-full-rls-green-application-canary
- mscqr-production-full-rls-green-full-rls-admin-bootstrap
- mscqr-production-full-rls-green-full-rls-admin-ownership
- mscqr-production-full-rls-green-full-rls-capability-preflight
- mscqr-production-full-rls-green-full-rls-role-provision
- mscqr-production-full-rls-green-full-rls-role-verify
- mscqr-production-full-rls-green-full-rls-rollback
- mscqr-production-full-rls-green-full-rls-runtime-policy
- mscqr-production-full-rls-green-full-rls-verification

All eleven addresses were already present in Terraform state, so no import was
performed. Their post-readback stale taint flags were cleared only after live
identity, tag, image, and role verification.

## Fresh plan — stop before apply

The refreshed saved plan at
.terraform-plans/production-green-stage-b.tfplan has:

- 4 to add
- 30 no-op
- 0 change
- 0 destroy
- 0 replacement

Remaining addresses, in canonical order:

1. aws_iam_role_policy.broker
2. aws_lambda_alias.reviewed
3. aws_lambda_function.broker
4. aws_lambda_permission.release_deployer

Its canonical address/action SHA-256 is:

    996b15c5ed63139ae6868d9f147ea625b7eee0c410315f173f1fa104b5844cf0

Reproduce with:

    terraform -chdir=infra/aws/terraform/production-green-stage-b show -json /private/tmp/genuine-scan-stage-b-aws/.terraform-plans/production-green-stage-b.tfplan | jq -c '[.resource_changes[] | {address, actions: .change.actions}] | sort_by(.address)' | shasum -a 256

No Terraform apply was run after this plan. No ECS task, RLS command, service,
database content, secret value, ALB, DNS, or traffic resource was mutated by
this recovery.

## Lambda code-signing read recovery — stop before apply

The subsequent three-resource apply created the broker Lambda and its published
version `1`, then Terraform failed its provider read with:

    lambda:GetFunctionCodeSigningConfig on arn:aws:lambda:eu-west-2:368992683803:function:mscqr-production-rls-approval-broker

Read-only reconciliation found 32 Terraform addresses. The function is active
and in state with the approved `nodejs24.x` runtime, `index.handler`, `x86_64`,
code SHA-256 `p55BonWJcV1A23kBpTP2N4dMRudnIPIFx50flC8rLwU=`, exact broker role,
and exact Stage B tags. It has no VPC attachment and no code-signing
configuration. Version `1` exists; the `reviewed` alias and its permission do
not yet exist. CloudTrail lookup returned no matching events in its available
history.

The original release session reproduced the exact implicit deny. A standalone
policy, `MSCQRProductionGreenStageBBrokerCodeSigningRead`, was created and
attached only to `mscqr-production-release-deployer`. It has one statement:
`lambda:GetFunctionCodeSigningConfig` on only the exact broker function ARN.
Its canonical SHA-256 is:

    b00e3a0f8a0d6d84ed0532ad059cb6290dcdef6a4ce61494352374f5444b5dab

Access Analyzer returned zero findings. Principal simulation allows only the
exact read and denies the unrelated function plus all code-signing mutation,
invoke, update, and delete actions. A fresh MFA-backed `abhi-phase3` session
successfully performed the exact read; the original session was stale.

The stale Terraform taint from the failed provider read was cleared only after
the live function matched configuration. A new saved plan at
`.terraform-plans/production-green-stage-b.tfplan` contains:

- 2 to add
- 32 no-op
- 0 change
- 0 destroy
- 0 replacement

Remaining addresses, in canonical order:

1. aws_lambda_alias.reviewed
2. aws_lambda_permission.release_deployer

Its canonical address/action SHA-256 is:

    f48075e846b19bbdcf4f560bfd20b3ac310263c4067ac3ae27e2aaa571d01978

No Terraform apply was run after this plan. No ECS task, RLS command, service,
database content, secret value, ALB, DNS, or traffic resource was mutated by
this recovery.

## Final-four apply attempt — stopped

The saved-plan caller, workspace, digest, action counts, and exact four
addresses were revalidated before apply. The broker inline policy completed.
Lambda creation then stopped with AccessDenied for lambda:TagResource on the
exact broker function ARN. No retry, re-plan, state inspection, or reactive IAM
change was performed after that failure.

## Lambda tagging recovery — stop before apply

Read-only reconciliation found 31 Terraform addresses: the broker inline
policy is live and in state, while the broker Lambda, version, reviewed alias,
and alias-qualified permission do not exist. No successful CreateFunction
CloudTrail event exists; the tagged create was rejected atomically.

MSCQRProductionGreenStageBBrokerLambdaTag is a separate one-statement policy
attached only to the release-deployer. Its canonical SHA-256 is:

    bec0f1e72bc8f7c97588ff54f636432d6b4d7f2e557698692ba7168f9ded5537

It allows lambda:TagResource only for the exact broker function with the exact
eu-west-2 production/Terraform/full-rls-green-stage-b tag context. Access
Analyzer returned zero findings. Exact tagging simulation is allowed; unrelated
or wrongly tagged functions and invoke/update/delete/remove-permission actions
remain denied.

A completely fresh saved plan now has 3 additions, 31 no-op resources, zero
change, zero destroy, and zero replacement. The remaining addresses are:

1. aws_lambda_alias.reviewed
2. aws_lambda_function.broker
3. aws_lambda_permission.release_deployer

Its canonical address/action SHA-256 is:

    9baf0a63861f1547f0ea3f702e85f1a4830f7a3c292da615760ec70dc3091996

No Terraform apply was run after this plan. No ECS task, RLS command, service,
database content, secret value, ALB, DNS, or traffic resource was mutated by
this recovery.
