# Production green Stage B image publisher

This isolated root creates only `mscqr-production-stage-b-image-publisher`, its exact
managed ECR publication policy, and their attachment. It does not manage Stage A, databases, networking,
secrets, ECS, Lambda, broker resources, services, traffic, or GitHub configuration.

The repository OIDC subject template remains default and is not changed by this root. The
publisher uses the dedicated protected GitHub environment
`production-stage-b-image-publish`, producing the exact default subject
`repo:T-ej2003/genuine-scan-main:environment:production-stage-b-image-publish`.
The dispatcher remains `.github/workflows/production-green-stage-b-images.yml` and accepts
only an exact merged release SHA. Configure the environment according to
`github-environment-contract.json`; do not add repository variables or AWS credential
secrets. The historical repository-wide proposal in
`documents/security/rls-program/PRODUCTION_GREEN_STAGE_B_OIDC_SUBJECT_TRANSITION.json`
is superseded and must not be applied.

An MFA-backed, non-root operator must use the approved dedicated production state
backend and plan before apply. AWS root must not plan or apply:

```sh
terraform -chdir=infra/aws/terraform/production-green-stage-b-image-publisher init \
  -upgrade=false -input=false \
  -backend-config='bucket=mscqr-production-terraform-state-368992683803-eu-west-2' \
  -backend-config='key=mscqr/production/rls-green/stage-b-image-publisher/terraform.tfstate' \
  -backend-config='region=eu-west-2' \
  -backend-config='encrypt=true' \
  -backend-config='use_lockfile=true'
terraform -chdir=infra/aws/terraform/production-green-stage-b-image-publisher plan -out=publisher.tfplan
terraform -chdir=infra/aws/terraform/production-green-stage-b-image-publisher apply publisher.tfplan
```

After verified apply, set the protected GitHub `production-stage-b-image-publish`
environment variable
`PRODUCTION_STAGE_B_IMAGE_PUBLISH_ROLE` to the `publisher_role_arn` output. Do not set
a repository-level duplicate. Verify the exact trust and policy hashes, dispatch the
SHA-only workflow for a merged main commit, and inspect its four digest attestations.

Rollback is an approved Terraform destroy of this isolated role followed by removal of
that one environment variable. It does not delete images or alter application runtime.
This repository package performs no AWS mutation until a separately approved apply.
