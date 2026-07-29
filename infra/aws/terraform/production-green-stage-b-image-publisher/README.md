# Production green Stage B image publisher

This isolated root creates only `mscqr-production-stage-b-image-publisher` and its
inline ECR publication policy. It does not manage Stage A, databases, networking,
secrets, ECS, Lambda, broker resources, services, traffic, or GitHub configuration.

AWS IAM can evaluate GitHub's `aud` and `sub` claims, but not the auxiliary
`repository` or `job_workflow_ref` claims directly. The role therefore requires the
repository-level subject template in `oidc-subject-template.json`: protected `production`,
this repository, and the exact reusable workflow are encoded into one exact `sub` value.
The dispatcher remains `.github/workflows/production-green-stage-b-images.yml` and
accepts only an exact merged release SHA. Apply the template only through the documented
dual-trust migration in
`documents/security/rls-program/PRODUCTION_GREEN_STAGE_B_OIDC_SUBJECT_TRANSITION.json`.

An MFA-backed, non-root operator must use the approved dedicated production state
backend and plan before apply. AWS root must not plan or apply:

```sh
terraform -chdir=infra/aws/terraform/production-green-stage-b-image-publisher init \
  -upgrade=false -input=false \
  -backend-config='bucket=<approved-production-state-bucket>' \
  -backend-config='key=mscqr/production/rls-green/stage-b-image-publisher/terraform.tfstate' \
  -backend-config='region=eu-west-2' \
  -backend-config='encrypt=true' \
  -backend-config='use_lockfile=true'
terraform -chdir=infra/aws/terraform/production-green-stage-b-image-publisher plan -out=publisher.tfplan
terraform -chdir=infra/aws/terraform/production-green-stage-b-image-publisher apply publisher.tfplan
```

After verified apply, set the protected GitHub `production` environment variable
`PRODUCTION_STAGE_B_IMAGE_PUBLISH_ROLE` to the `publisher_role_arn` output. Do not set
a repository-level duplicate. Verify the exact trust and policy hashes, dispatch the
SHA-only workflow for a merged main commit, and inspect its four digest attestations.

Rollback is an approved Terraform destroy of this isolated role followed by removal of
that one environment variable. It does not delete images or alter application runtime.
This repository package performs no AWS mutation until a separately approved apply.
