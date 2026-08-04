# Production Green Stage B release-role IAM reconciliation

## Decision

The canonical release-role authority is eight managed policies and no inline
policies. Live IAM publication is a separate administrator operation after this
source change is reviewed and merged.

The production-shaped plan updates
`aws_lambda_alias.reviewed`. The permission manifest therefore evaluates
`lambda:UpdateAlias` against the exact qualified resource:

    arn:aws:lambda:eu-west-2:368992683803:function:mscqr-production-rls-approval-broker:reviewed

AWS documents `UpdateAlias` as the operation that updates a named function
alias, with the function and alias name both present in the request path. The
Lambda service-authorization contract supports resource-level authorization for
this action. IAM custom-policy simulation rejected the unqualified function ARN
for the plan's qualified resource and allowed the exact `reviewed` alias ARN.
No wildcard alias is required.

The canonical FinalApplyWrite SHA-256 changes from
`c6a199ee44124979416af1893878a09bcca227dc0f1fd41d1075b571e96728ca`
to
`0038d24898d2a20f806949d3329b8c29fb329e4f7e9b2406fb96ff97c2d2fa9b`.

Primary references:

- [AWS Lambda actions, resources, and condition keys](https://docs.aws.amazon.com/service-authorization/latest/reference/list_awslambda.html)
- [AWS Lambda UpdateAlias API](https://docs.aws.amazon.com/lambda/latest/api/API_UpdateAlias.html)
- [Amazon ECS actions, resources, and condition keys](https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonelasticcontainerservice.html)
- [IAM SimulatePrincipalPolicy API](https://docs.aws.amazon.com/IAM/latest/APIReference/API_SimulatePrincipalPolicy.html)

`UpdateExactStageBBrokerFunctionRelease` remains limited to code,
configuration, and version operations on the unqualified function.
`UpdateExactStageBBrokerReviewedAlias` separately permits only
`lambda:UpdateAlias` on the exact `reviewed` alias and retains the reviewed
region and resource-tag conditions. Alias creation, deletion, invocation, and
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
