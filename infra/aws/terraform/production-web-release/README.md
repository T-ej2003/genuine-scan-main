# Production web release infrastructure

This root owns the GitHub OIDC web image-publisher role, its permissions boundary and policy, and the narrowly scoped `MSCQRProductionFrontendActivation` inline policy on the existing `mscqr-production-release-deployer` role. The release-deployer role itself is externally owned and is read only as a Terraform data source; its frontend policy is required by the governed frontend activation path.

An MFA-backed, non-root production operator must use the dedicated encrypted production S3 state and S3 lockfile. AWS root must not plan or apply:

```sh
terraform -chdir=infra/aws/terraform/production-web-release init \
  -upgrade=false -input=false \
  -backend-config='bucket=mscqr-production-terraform-state-368992683803-eu-west-2' \
  -backend-config='key=mscqr/production/web-release/terraform.tfstate' \
  -backend-config='region=eu-west-2' \
  -backend-config='encrypt=true' \
  -backend-config='use_lockfile=true'
aws sts get-caller-identity
terraform -chdir=infra/aws/terraform/production-web-release plan -out=web-release.tfplan
terraform -chdir=infra/aws/terraform/production-web-release apply web-release.tfplan
```

Verify the caller is in account `368992683803` under the approved non-root operator role before planning. Review every plan action; import any pre-existing Terraform-managed object before apply and stop for any unexpected update, delete, or replacement. After apply, verify the exact publisher trust/policy and boundary, then set `PRODUCTION_WEB_IMAGE_PUBLISH_ROLE` on the protected `production-web-image-publish` environment to the Terraform `publisher_role_arn` output. This procedure does not configure GitHub or mutate resources until the separately reviewed Terraform apply.
