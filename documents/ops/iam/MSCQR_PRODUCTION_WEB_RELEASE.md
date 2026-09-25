# Governed production web release

Production web evidence is intentionally separate from the mature four-image Stage-B object. Coordinated release consumes both authorizations and requires their exact protected `sourceSha` values to match. This preserves existing Stage-B consumers and permits web-only publication only when canonical image-impact evidence requires it.

## Publication and evidence

Dispatch `.github/workflows/production-web-image.yml` from protected `main` with only `release_sha`. Environment `production-web-image-publish` requires review by `T-ej2003`, permits that operator to approve their own deployment, and allows deployments only from protected `main`; it exposes only `PRODUCTION_WEB_IMAGE_PUBLISH_ROLE`. GitHub OIDC is the sole credential path. Account `368992683803`, region `eu-west-2`, repository `mscqr-web`, context `.`, `Dockerfile.ecs-frontend`, platform `linux/amd64`, and the full SHA tag are fixed in source.

This environment is operator-configured, not managed by Terraform. After this contract change merges and before the next publication, configure the GitHub environment with required reviewer `T-ej2003`, self-review permitted, and protected-`main`-only deployment branches; verify those live settings before dispatch. The repository contract does not itself update GitHub environment settings.

The workflow authenticates immutable ECR configuration, publishes and reads back one digest, scans critical vulnerabilities, produces SBOM and provenance attestations, applies and verifies keyless Cosign evidence, and retains `production-web-image/web-image.jsonl` for 90 days.

`scripts/aws/production-web-release-contract.mjs` defines 24-hour schema-v1 evidence and authorization binding source, run/artifact identity, reviewer, repository, digest, platform, build identity, account/region, ECR readback, and canonical image-impact hash. `scripts/aws/produce-production-web-image-evidence.mjs` is the sole governed web-evidence producer: it starts from a clean exact protected-main checkout, authenticates the exact successful web-publication workflow run and immutable artifact archive, checks SBOM/provenance hashes and the fixed supply-chain verifier, reads back immutable ECR state, verifies the authenticated Stage-B impact is web-required, signs exactly once with the existing root-only attestation key, verifies that signature, and atomically writes evidence, signature, and authorization. A complete coordinated release therefore expects two KMS signatures: unchanged Stage-B evidence plus web evidence. Mixed-source pairs fail closed.

The evidence producer is a root-attested operator operation, not a generic signer or JSON construction step. Its fixed command is:

```sh
node scripts/aws/produce-production-web-image-evidence.mjs \
  --source-sha <exact-protected-main-sha> \
  --stage-b-authorization <private-stage-b-authorization.json> \
  --stage-b-authorization-sha256 <exact-file-sha256> \
  --web-workflow-run-id <successful-production-web-image-run-id> \
  --output-dir <new-private-0700-directory-outside-the-repository>
```

The caller cannot select a repository, Dockerfile, platform, account, region, KMS key, artifact member, or output filename. The command accepts only the canonical root-attestation profile fixed in source and refuses any workflow, source, artifact, ECR, impact, or signature mismatch before producing the authorization.

## Activation and rollback

The release deployer captures stable `mscqr-frontend-servi-euw2`, derives `mscqr-frontend` registration input from its current task definition, and changes only `frontend.image` to the authenticated digest. AWS-normalized registration readback must equal the candidate. Immediately before one `UpdateService`, task definition, opaque PRIMARY deployment ID, image, desired count, and 2/2/0 state must still equal the predecessor.

Registration failure performs no service update. Update, stabilization, `/login`, or health failure may roll back only to the exact captured predecessor while the service still points at the failed candidate. Arbitrary service, family, image, or rollback inputs are rejected.

AWS IAM cannot resource-scope or field-constrain `ecs:RegisterTaskDefinition`. The release role therefore uses the AWS-supported wildcard resource for that API only. The security boundary is the isolated release principal, fixed source constructor, exact `iam:PassRole` closure, full AWS-materialized readback, and exact service/predecessor CAS; callers cannot supply task fields.

## Terraform state and publisher provisioning

The `infra/aws/terraform/production-web-release` root owns the publisher role, its boundary and permissions policy, and the narrowly scoped `MSCQRProductionFrontendActivation` inline policy on the existing `mscqr-production-release-deployer` role. That release-deployer role remains externally owned and is read as a Terraform data source; its frontend policy is required by the governed activation path.

An MFA-backed, non-root production operator must use the dedicated encrypted production S3 state and S3 lockfile. AWS root must not plan or apply:

```sh
TF_WORKSPACE=default terraform -chdir=infra/aws/terraform/production-web-release init \
  -upgrade=false -input=false \
  -backend-config='bucket=mscqr-production-terraform-state-368992683803-eu-west-2' \
  -backend-config='key=mscqr/production/web-release/terraform.tfstate' \
  -backend-config='region=eu-west-2' \
  -backend-config='encrypt=true' \
  -backend-config='use_lockfile=true'
test "$(TF_WORKSPACE=default terraform -chdir=infra/aws/terraform/production-web-release workspace show)" = default
aws sts get-caller-identity
```

Verify the caller is in account `368992683803` under the approved non-root operator role. Before creating the saved plan, compare every managed address with live AWS and import any pre-existing object with the pinned workspace, replacing both placeholders with the exact Terraform address and provider import ID:

```sh
TF_WORKSPACE=default terraform -chdir=infra/aws/terraform/production-web-release import '<terraform-address>' '<provider-id>'
```

A plan created before an import must be discarded and recreated. Review the final plan and stop for any unexpected update, delete, or replacement:

```sh
TF_WORKSPACE=default terraform -chdir=infra/aws/terraform/production-web-release plan -out=web-release.tfplan
TF_WORKSPACE=default terraform -chdir=infra/aws/terraform/production-web-release apply web-release.tfplan
```

After apply, verify the exact publisher trust/policy and boundary, then set `PRODUCTION_WEB_IMAGE_PUBLISH_ROLE` on the protected `production-web-image-publish` environment to the Terraform `publisher_role_arn` output. This procedure does not configure GitHub or mutate resources until the separately reviewed Terraform apply.

## Governed operator sequence

1. Merge reviewed source and derive exact image impact.
2. Publish/authenticate four Stage-B images when required.
3. Separately publish/authenticate web when required.
4. Run the fixed governed web-evidence producer above; it KMS-signs web evidence once and generates the web authorization atomically.
5. Verify one source SHA across Stage-B, web, DB package, backend, and frontend candidates.
6. Verify the database before backend activation.
7. Activate backend, then frontend under exact predecessor CAS.
8. Verify health and G06/G11 behavior; run controlled physical-printer acceptance separately.

Adding this contract performs no publication, signing, IAM application, ECS update, or production mutation.
