# Production Green Stage B release-role IAM reconciliation

## Decision

The canonical release-role authority is eight managed policies and no inline
policies. Live IAM publication is a separate administrator operation after this
source change is reviewed and merged.

The production-shaped plan updates
`aws_lambda_alias.reviewed`. AWS authorizes `lambda:UpdateAlias` against the
underlying Lambda function resource, so the permission manifest evaluates the
action against:

    arn:aws:lambda:eu-west-2:368992683803:function:mscqr-production-rls-approval-broker

AWS documents `UpdateAlias` as the operation that updates a named function
alias, with the function and alias name both present in the request path. The
Lambda service-authorization contract maps this action to the function resource
type; the alias name remains an API request field and is enforced by the
Terraform plan, closure, and apply bindings. No wildcard Lambda resource is
required.

The canonical FinalApplyWrite SHA-256 changes from
`0038d24898d2a20f806949d3329b8c29fb329e4f7e9b2406fb96ff97c2d2fa9b`
to
`04ce6d5f63d91ff81faeca0718411fe8554367822777be17fc16739cc1c67bee`.

Primary references:

- [AWS Lambda actions, resources, and condition keys](https://docs.aws.amazon.com/service-authorization/latest/reference/list_awslambda.html)
- [AWS Lambda UpdateAlias API](https://docs.aws.amazon.com/lambda/latest/api/API_UpdateAlias.html)
- [Amazon ECS actions, resources, and condition keys](https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonelasticcontainerservice.html)
- [IAM SimulatePrincipalPolicy API](https://docs.aws.amazon.com/IAM/latest/APIReference/API_SimulatePrincipalPolicy.html)

`UpdateExactStageBBrokerFunctionRelease` remains limited to code,
configuration, and version operations on the unqualified function.
`UpdateExactStageBBrokerReviewedAlias` separately permits only
`lambda:UpdateAlias` on the broker function resource and retains the reviewed
region and resource-tag conditions. The Terraform alias binding restricts the
operation to the `reviewed` alias. Alias creation, deletion, invocation, and
wildcard Lambda authority remain absent.

## ECS task-definition simulation context

AWS defines `ecs:compute-compatibility`, `ecs:privileged`, `ecs:task-cpu`,
and `ecs:task-memory` as `RegisterTaskDefinition` condition keys. IAM
simulation does not infer request context: every referenced key must be passed
through `ContextEntries`. The permission generator therefore derives the four
values from each selected plan change and requires exact equality with its
source-controlled family mapping before simulation:

| Task-definition family | Compatibility | Privileged | CPU | Memory (MiB) |
|---|---:|---:|---:|---:|
| `mscqr-production-rls-green-worker-candidate` | `FARGATE` | `false` | 512 | 1024 |
| `mscqr-production-full-rls-green-read-only-canary` | `FARGATE` | `false` | 256 | 512 |
| Other ten reviewed Stage B families | `FARGATE` | `false` | 1024 | 2048 |

`ecs:compute-compatibility` is supplied as a `stringList`, CPU and memory as
`numeric`, and `ecs:privileged` as a `string`, matching the ECS service
authorization types and the IAM simulation API. Region, exact request tags,
and the exact tag-key set remain mandatory. Missing, duplicate, unknown, or
cross-family values fail before report signing.

## Administrator preflight denial context

The production-shaped plan fixture carries the reviewed Terraform variable
shape: `account_id.value=368992683803` and `aws_region.value=eu-west-2`.
The preflight has no fallback for either value.

AWS principal simulation reports condition keys referenced by attached
canonical policies even while a forbidden action remains denied. The manifest
therefore records the exact decision and order-independent missing-context set:

| Evaluation | Decision | Expected set |
|---|---|---|
| `backend-bucket-delete` | `implicitDeny` | FULL-14 |
| `backend-bucket-policy-write` | `implicitDeny` | FULL-14 |
| `backend-encryption-write` | `implicitDeny` | FULL-14 |
| `backend-legacy-lock-delete` | `explicitDeny` | EMPTY |
| `backend-legacy-lock-read` | `explicitDeny` | EMPTY |
| `backend-legacy-state-read` | `explicitDeny` | EMPTY |
| `backend-legacy-state-write` | `explicitDeny` | EMPTY |
| `backend-list-bucket-not-required` | `implicitDeny` | FULL-14 |
| `backend-other-production-workspace-read` | `implicitDeny` | FULL-14 |
| `backend-other-stage-b-key-read` | `implicitDeny` | FULL-14 |
| `backend-state-delete` | `explicitDeny` | EMPTY |
| `backend-unrelated-bucket-read` | `implicitDeny` | FULL-14 |
| `backend-versioning-write` | `implicitDeny` | FULL-14 |
| `backend-wildcard-object-read` | `implicitDeny` | FULL-14 |
| `create-iam-role` | `implicitDeny` | FULL-14 |
| `deregister-task-definition` | `implicitDeny` | FULL-14 |
| `execute-ecs-task` | `implicitDeny` | FULL-14 |
| `invoke-broker` | `implicitDeny` | FULL-14 |
| `pass-to-lambda` | `implicitDeny` | PASSROLE-13 |
| `pass-unrelated-role` | `implicitDeny` | PASSROLE-13 |
| `update-ecs-service` | `implicitDeny` | FULL-14 |

`FULL-14` is the sorted set `aws:RequestTag/Component`,
`aws:RequestTag/Environment`, `aws:RequestTag/ManagedBy`,
`aws:RequestedRegion`, `aws:ResourceTag/Component`,
`aws:ResourceTag/Environment`, `aws:ResourceTag/ManagedBy`, `aws:TagKeys`,
`ecs:cluster`, `ecs:compute-compatibility`, `ecs:privileged`, `ecs:task-cpu`,
`ecs:task-memory`, and `iam:PassedToService`. `PASSROLE-13` omits
`iam:PassedToService` because both PassRole controls supply it. `EMPTY` has no
keys. Thus 16 implicit denials have non-empty sets and five explicit backend
denials have empty sets.

| Condition keys | Reviewed statement origins |
|---|---|
| `aws:RequestTag/Component`, `Environment`, `ManagedBy` | `RegisterExactStageBReadOnlyCanaryTaskDefinition`; `TagExactStageBLogs`; `TagExactReplayTable`; `TagExactStageBTaskDefinitions`; `RegisterExactStageBTaskDefinitions1024`; `RegisterExactStageBTaskDefinitionWorker` |
| `aws:RequestedRegion` | Region-bound FinalApplyWrite, ProviderReadOnly, ProviderRecovery, ReferenceAuditReadOnly, and TaskDefinitionRegistration statements |
| `aws:ResourceTag/Component`, `Environment`, `ManagedBy` | `UpdateExactStageBBrokerFunctionRelease`; `UpdateExactStageBBrokerReviewedAlias` |
| `aws:TagKeys` | Canary and task-definition registration statements plus the ProviderRecovery tag statements |
| `ecs:cluster` | `ListStageBServicesAndTasks`; `DescribeStageBServicesAndTasks` |
| `ecs:compute-compatibility`, `ecs:privileged`, `ecs:task-cpu`, `ecs:task-memory` | `RegisterExactStageBTaskDefinitions1024`; `RegisterExactStageBTaskDefinitionWorker` |
| `iam:PassedToService` | `PassExactStageBReadOnlyCanaryRolesToEcsTasks`; `PassOnlyExactStageBTaskRolesToEcsTasks` |

Validation fails for an unexplained key, source-condition drift, a different
deny kind, or any missing, extra, duplicate, or wrong observed key. Required
evaluations still reject every non-empty missing-context set. Signed reports
preserve expected and observed sets; closure and apply revalidate them against
the bound manifest SHA.

## Canonical attachment set

The release role must have exactly these sorted managed-policy ARNs:

1. `arn:aws:iam::368992683803:policy/MSCQRProductionGreenStageARelease`
2. `arn:aws:iam::368992683803:policy/MSCQRProductionGreenStageBBrokerCodeSigningRead`
3. `arn:aws:iam::368992683803:policy/MSCQRProductionGreenStageBFinalApplyWrite`
4. `arn:aws:iam::368992683803:policy/MSCQRProductionGreenStageBProviderReadOnly`
5. `arn:aws:iam::368992683803:policy/MSCQRProductionGreenStageBProviderRecovery`
6. `arn:aws:iam::368992683803:policy/MSCQRProductionGreenStageBReferenceAuditReadOnly`
7. `arn:aws:iam::368992683803:policy/MSCQRProductionGreenStageBTaskDefinitionRegistration`
8. `arn:aws:iam::368992683803:policy/MSCQRProductionGreenStageBWorkspaceState`

The allowed inline-policy set is empty.

## Live drift disposition

| Live authority | Disposition | Reason |
|---|---|---|
| Same-named inline `MSCQRProductionGreenStageARelease` | Remove after managed replacement is attached and simulated | Legacy Stage A create/write authority conflicts with managed ownership. The managed source permits only exact Stage A state read for handoff generation. |
| `MSCQRProductionGreenStageAReadOnlyCanarySecretCreate` | Detach as legacy recovery | Stage A secret creation is not in the Stage B plan. |
| `MSCQRProductionGreenStageBBrokerCodeSigningRead` | Retain canonical | Exact provider read required for broker refresh; source and live document already match. |
| `MSCQRProductionGreenStageBBrokerLambdaTag` | Detach as legacy recovery | The current plan has no Lambda tag mutation. |
| `MSCQRProductionGreenStageBControlPlaneCreate` | Replace with `MSCQRProductionGreenStageBProviderReadOnly` | Its reads remain necessary, but its create/write statements are not plan-derived. |
| `MSCQRProductionGreenStageBTaskDefinitionDescribeRead` | Detach as superseded duplicate | `ReferenceAuditReadOnly` already supplies the required single-action `Resource: "*"` read. |
| `MSCQRProductionGreenStageBTaskDefinitionRegistration` | Retain canonical | The production-shaped plan creates twelve exact task definitions and requires exact ECS/PassRole authority. |
| `MSCQRProductionGreenStageBFinalApplyWrite` | Publish corrected source version | Live lacks broker managed-policy version mutations and the exact alias resource split. |
| `MSCQRProductionGreenStageBWorkspaceState` | Publish corrected source version | Source implements the reviewed direct production key and denies legacy base-key access; live retains obsolete workspace listing/base-key semantics. |

## Pre-publication proof

The candidate source policy union was evaluated with AWS IAM custom-policy
simulation against the production-shaped plan:

- required evaluations: 89/89 allowed
- required failures: 0
- forbidden evaluations: 21/21 denied
- forbidden allowed: 0
- unresolved missing context: 0
- supplementary provider reads: 55/55 allowed

No report may be signed and no IAM publication may occur unless deterministic
source generation and the same complete simulation remain green.

## Reviewed publication order

1. Create the missing managed Stage A policy from reviewed source.
2. Create the managed provider-read-only policy and publish the source-controlled
   task-registration policy if needed.
3. Publish new default versions of FinalApplyWrite and WorkspaceState while
   retaining their prior defaults for rollback.
4. Attach all eight canonical policies.
5. Simulate all required and forbidden evaluations against the resulting role.
6. Only after successful simulation, remove the same-named Stage A inline policy
   and detach the three legacy/superseded policies plus ControlPlaneCreate.
7. Recollect policy versions, hashes, attachments, and inline policy names; then
   run the administrator production preflight.

This document authorizes no live change by itself.
