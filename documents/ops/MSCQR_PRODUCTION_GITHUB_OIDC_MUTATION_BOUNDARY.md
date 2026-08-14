# MSCQR production GitHub OIDC mutation boundary

## Current contract

The human emergency path remains the only MFA-backed operator path:

`mscqr-production-bootstrap-operator` → MFA → `mscqr-production-release-deployer`.

The reviewed CI path is separate:

protected `production` environment → GitHub OIDC →
`mscqr-production-github-actions-mutation` → `.github/workflows/release-gate.yml`.

The CI role is trusted only for the repository's current GitHub OIDC default
environment subject, `repo:T-ej2003/genuine-scan-main:environment:production`,
with audience `sts.amazonaws.com`. The release gate independently requires the
workflow to be `workflow_dispatch` on `refs/heads/main`, the exact current
`origin/main` SHA, the `production` environment approval, and the exact CI
caller role. Pull requests, forks, other branches, other environments, the
legacy `github-actions-mscqr-deploy` role, and the image-publisher role are not
accepted production callers.

`source/tooling SHA`, `image release SHA`, and immutable image digest remain
separate evidence fields. Recovery journals and task-definition fingerprints
retain their existing fail-closed/resume rules.

## Source-managed infrastructure

`infra/aws/terraform/production-github-actions-identity` defines the dedicated
read-only and mutation roles and attaches only the existing reviewed Stage A /
Stage B policy sources. It does not manage the human role, image publisher,
OIDC provider, or GitHub environment. No apply is authorized by this PR.

The `production` environment must be configured remotely with required
reviewers and exactly the `main` deployment branch policy. The workflow reads
and rejects any other configuration; it does not configure GitHub remotely.

The old broad `github-actions-mscqr-deploy` role remains break-glass cleanup
work until its source-managed retirement/import plan is independently reviewed.
It is not referenced by the release gate and cannot satisfy the canonical caller
contract.

## Operator boundary

Run the release gate only after source/image evidence and the read-only
preflights pass. The CI mutation role is short-lived OIDC access; static AWS
credentials are not a CI fallback. Human break-glass remains outside the
workflow and must continue to use the MFA-backed release-deployer path.

Before remote apply, review the generated trust policy, role policy attachments,
capability graph, environment readback, rollback/recovery evidence, and the
legacy-role retirement plan. Never add a second production writer or bypass the
canonical release gate.
