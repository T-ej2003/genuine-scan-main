# Production green Stage B image publisher identity

This repository-only package establishes the permanent control-plane contract for
publishing the four approval-bound Stage B images. It does not apply Terraform, configure
GitHub, publish an image, access AWS, connect to a database, read or write a secret, launch
a task, invoke the broker, deploy a service, or change traffic.

## Workflow boundary

`.github/workflows/production-green-stage-b-images.yml` is the sole manual dispatcher. It
is loaded from protected `main` and accepts exactly one value, `release_sha`. The
workflow definition ref and release source are deliberately separate: the dispatcher
checks out and builds the exact 40-character release commit, while the workflow itself
is loaded from `main`.

Use the checked-in dispatcher wrapper, which rejects commit-valued workflow refs and
nonexistent release commits:

`node scripts/aws/dispatch-production-green-stage-b-images.mjs <release_sha>`

The wrapper dispatches exactly:

`gh workflow run production-green-stage-b-images.yml --ref main -f release_sha=<release_sha>`

The workflow checks that its definition ref is `refs/heads/main`, verifies the checked-out
HEAD equals `release_sha`, and calls the fixed reusable workflow
`.github/workflows/production-green-stage-b-image-build.yml`.

The reusable job runs in the protected `production-stage-b-image-publish` environment. It
independently repeats the release and generated-package checks before it requests GitHub
OIDC credentials. All
repository names, image targets, labels, service identities, region, account, platform,
source contract, and migration digest are fixed in reviewed source; no caller can override
them. It publishes only backend, worker, RLS executor, and canary digest images, scans them,
and creates/validates signed SBOM and provenance attestations.

## Proposed AWS role

Terraform root:
`infra/aws/terraform/production-green-stage-b-image-publisher/`

Role: `mscqr-production-stage-b-image-publisher`

AWS IAM accepts GitHub's `aud` and `sub` as trust-policy condition keys. It cannot use
the auxiliary `repository` or `job_workflow_ref` claims as direct IAM condition keys. The
repository-wide custom-sub proposal is superseded: the repository template stays default.
The role therefore permits only GitHub's existing OIDC provider when these supported
claims match:

- `aud`: `sts.amazonaws.com`;
- `sub`:
  `repo:T-ej2003/genuine-scan-main:environment:production-stage-b-image-publish`.

Create the protected `production-stage-b-image-publish` environment outside Terraform.
Its solo-operator contract authorizes `T-ej2003` to dispatch publication without manual reviewer approval;
it requires protected `main` deployment branches, no reviewer or wait timer, no unprotected branch or tag
access, and only the non-secret `PRODUCTION_STAGE_B_IMAGE_PUBLISH_ROLE` variable. It needs no AWS
credential secrets. Protected-main ancestry, exact-SHA validation, GitHub OIDC, the isolated ECR-only
publisher role and permissions boundary, immutable digests, scanning, signing, SBOM, and provenance remain
the publication controls. Both publisher workflows fail visibly unless `github.actor` is exactly `T-ej2003`
before they can enter the environment-bound job or request OIDC. The live GitHub environment must match this
source-controlled solo-operator contract.
Only the reviewed publisher workflow may reference this environment. Another workflow may
do so only through a reviewed change merged to protected main; environment approval and
the exact ECR-only IAM role remain the operational boundary. Existing repository OIDC
consumers remain on default subjects and require no dual-trust migration. The historical
custom-sub inventory is retained as superseded evidence and must not be applied.

The role has no console login or access keys. Its only allow statements are
`ecr:GetAuthorizationToken` and image publication/read/scan operations on
`mscqr-backend` and `mscqr-worker`; executor and canary intentionally share the backend
repository. It explicitly denies ECS, Lambda, Secrets Manager, RDS, and IAM actions.

## Apply and verification procedure

An MFA-backed non-root operator must first receive separate approval for the isolated
Terraform plan. Root must not plan or apply. The plan must create only this IAM role, its
exact managed ECR-only policy, and their attachment. After apply, verify the role ARN and output hashes, then set only the
protected GitHub `production-stage-b-image-publish` environment variable:

`PRODUCTION_STAGE_B_IMAGE_PUBLISH_ROLE=<publisher_role_arn>`

Do not set a repository-level duplicate, and preserve the source-controlled no-reviewer, no-wait-timer,
and branch controls. Verify a fixed-SHA dispatch can assume the role only through the
reusable job, then inspect all four immutable ECR digest labels and signed attestations.

Before image publication, use the canonical dispatcher and reusable image workflow. The
workflow-definition gate must verify `refs/heads/main`, then the release gate must verify
the exact `release_sha` before dependency installation or OIDC credentials. A failed gate
stops publication; no separate identity-probe workflow is required or accepted as a substitute
for those source and release checks.

Rollback is a separately approved destroy of this isolated Terraform role followed by
removal of the one environment variable. It does not delete published images or alter any
application infrastructure.
