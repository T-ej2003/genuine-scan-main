# Normal production deployment

After the one-time component-state bootstrap, an ordinary backend or frontend PR is merged to `main`. GitHub Actions classifies the affected live component, builds its immutable image, deploys it, verifies health and authenticated smoke checks, rolls back automatically on failure, and records only the components that are actually live.

Explicitly approve the protected GitHub `production-normal-deploy` environment when prompted. It is reserved for `.github/workflows/production-deploy.yml` and retains required-reviewer protection under the solo-operator contract below. No Codex session, Stage-B authorization, KMS evidence, JSON artifact construction, digest copying, Terraform command, or ECS command is part of a normal application release.

## Solo-operator approval

MSCQR currently has one authorized production operator and reviewer: **T-ej2003**
(GitHub User ID `183396573`). For `production-normal-deploy`,
`production-component-state-bootstrap` and
`production-component-infrastructure-activation`, that user may initiate and
explicitly approve the same operation. Each environment requires exactly that
User reviewer, only branch `main`, and disabled administrator bypass.
`prevent_self_review=false` is mandatory: enabling GitHub Prevent self-review
would prevent the sole initiator from approving. This deliberate solo-operator
exception does not automatically approve any run or permit arbitrary admins,
other users or teams to approve.

GitHub's environment gate applies before any step in the protected job runs,
including OIDC credential acquisition. Both normal classification/reconciliation
and deployment jobs reference `production-normal-deploy`; classification can
reconcile an interrupted mutation and is therefore gated too. The bootstrap
job references its bootstrap environment before OIDC and conditional state
creation. The activation authorization job references its activation environment
before creating the source/plan-bound authorization artifact; the local installer
separately authenticates that actual approval before applying a saved plan.

The exception preserves MFA-backed human provenance where required, exact
protected-main source binding, saved Terraform plan and SHA256 bindings for
infrastructure activation, fixed AWS account/region and OIDC subjects, remote-state
ownership/locking, replay prevention, durable audit evidence, deployment
verification and fail-closed behavior. Normal application releases do not acquire
a manual Terraform-plan ceremony. The authoritative environment contract is
[`github-environment-contract.json`](../../infra/aws/terraform/production-component-deployment-state/github-environment-contract.json).

If another production operator/reviewer is authorized later, reconsider this
contract; Prevent self-review and independent approval may then be enabled through
a reviewed change. No second-person approval exists in the current model.
Historical security/recovery maker-checker governance is unchanged.

Security/infrastructure changes use the stronger reviewed lane. Recovery uses its dedicated recovery lane.

Backend and frontend state keep two source identities. `sourceSha` authenticates the image currently running with its digest and task definition. `establishedThroughSha` records the protected-main revision through which deployment or recovery was completed and is the baseline for the next normal change range. Normal deployment advances both to its candidate; historical-image recovery preserves the image source and advances only the authenticated reconciliation baseline.

Overlap and cleanup rotations commit the verified backend identity and security identity together. The terminal checks the deployment result against fresh ECS/ECR reads, retaining the image source separately from the rotation revision. A mismatch leaves both component records unchanged.

Legacy backend-health recovery records only the canonical `mscqr-backend` target after validating recovery evidence and fresh task/digest readback. Its artifact source and completed-recovery revision remain separate. This does not widen the green-family app-only activation boundary; legacy-to-green migration still belongs to the stronger lane.

Successful recovery/rotation terminals also atomically record their source and evidence identity in `completedEmergencyWork` in the same component-state item. Normal preparation uses these operation-specific completions only for the operation's explicit source paths in a lagging range. Later edits, unrelated emergency code, and unrelated security work still require the stronger lane. Bootstrap and normal releases cannot create these completions; no operator action is added to routine deployment.

Interrupted normal releases are reconciled automatically before the next workflow classifies changes, even when `main` has advanced. The existing DynamoDB item holds one bounded normal intent/receipt: exact predecessors and registered candidates are persisted before ECS updates; completion is recorded only after stability, readiness and authenticated smoke. A verified receipt permits the exact live release to commit atomically before the new range is calculated. An unverified interrupted attempt restores its recorded predecessors instead. The receipt is removed atomically with component commit (or after verified rollback); GitHub artifacts and protected-main ancestry alone never authorize adoption of a live task. See [normal retry boundaries](NORMAL_DEPLOYMENT_RETRY.md).

## One-time bootstrap

Before the first normal deployment, configure `production-component-state-bootstrap` with the exact solo-operator approval contract above, then run **Bootstrap Production Component Deployment State** from protected `main` and explicitly approve it as T-ej2003. The workflow reads the current backend and frontend ECS/ECR identities, proves their protected-main source tags, initializes each reconciliation baseline to that proven source, and conditionally creates the single state record. It rejects an existing record and never uses workflow history as deployment state.

## Troubleshooting

- A normal workflow that fails after a service mutation rolls the exact authenticated predecessor back and preserves its automatic journal artifact.
- Runner loss or a failed state terminal is handled by the next current-main run; do not manually edit deployment state or rerun an obsolete source revision.
- A workflow that reports unknown or drifted live state stops without forcing a service update; use the reviewed recovery lane to reconcile that component.
