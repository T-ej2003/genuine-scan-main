# Governed production web release

Production web evidence is intentionally separate from the mature four-image Stage-B object. Coordinated release consumes both authorizations and requires their exact protected `sourceSha` values to match. This preserves existing Stage-B consumers and permits web-only publication only when canonical image-impact evidence requires it.

## Publication and evidence

Dispatch `.github/workflows/production-web-image.yml` from protected `main` with only `release_sha`. Environment `production-web-image-publish` requires review with self-review prevention and exposes only `PRODUCTION_WEB_IMAGE_PUBLISH_ROLE`. GitHub OIDC is the sole credential path. Account `368992683803`, region `eu-west-2`, repository `mscqr-web`, context `.`, `Dockerfile.ecs-frontend`, platform `linux/amd64`, and the full SHA tag are fixed in source.

The workflow authenticates immutable ECR configuration, publishes and reads back one digest, scans critical vulnerabilities, produces SBOM and provenance attestations, applies and verifies keyless Cosign evidence, and retains `production-web-image/web-image.jsonl` for 90 days.

`scripts/aws/production-web-release-contract.mjs` defines 24-hour schema-v1 evidence and authorization binding source, run/artifact identity, reviewer, repository, digest, platform, build identity, account/region, ECR readback, and canonical image-impact hash. A governed administrator signs web evidence with the existing root-attestation KMS key. A complete coordinated release therefore expects two KMS signatures: unchanged Stage-B evidence plus web evidence. Mixed-source pairs fail closed.

## Activation and rollback

The release deployer captures stable `mscqr-frontend-servi-euw2`, derives `mscqr-frontend` registration input from its current task definition, and changes only `frontend.image` to the authenticated digest. AWS-normalized registration readback must equal the candidate. Immediately before one `UpdateService`, task definition, opaque PRIMARY deployment ID, image, desired count, and 2/2/0 state must still equal the predecessor.

Registration failure performs no service update. Update, stabilization, `/login`, or health failure may roll back only to the exact captured predecessor while the service still points at the failed candidate. Arbitrary service, family, image, or rollback inputs are rejected.

AWS IAM cannot resource-scope or field-constrain `ecs:RegisterTaskDefinition`. The release role therefore uses the AWS-supported wildcard resource for that API only. The security boundary is the isolated release principal, fixed source constructor, exact `iam:PassRole` closure, full AWS-materialized readback, and exact service/predecessor CAS; callers cannot supply task fields.

## Governed operator sequence

1. Merge reviewed source and derive exact image impact.
2. Publish/authenticate four Stage-B images when required.
3. Separately publish/authenticate web when required.
4. KMS-sign both evidence objects and generate both authorizations.
5. Verify one source SHA across Stage-B, web, DB package, backend, and frontend candidates.
6. Verify the database before backend activation.
7. Activate backend, then frontend under exact predecessor CAS.
8. Verify health and G06/G11 behavior; run controlled physical-printer acceptance separately.

Adding this contract performs no publication, signing, IAM application, ECS update, or production mutation.
