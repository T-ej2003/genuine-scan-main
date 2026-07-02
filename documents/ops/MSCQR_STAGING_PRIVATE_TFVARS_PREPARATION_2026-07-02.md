# MSCQR Staging Private Tfvars Preparation

Date: 2026-07-02
Scope: private Terraform input preparation for the first staging API plan.

This runbook prepares private local inputs only. It does not authorize
`terraform apply`, AWS mutation, deployment, production database use,
production/global/table RLS enablement, runtime route wiring, or committing real
Terraform values.

## Purpose

Prepare the private Terraform variables required before the first real staging
Terraform plan can run through `npm run plan:staging-terraform`.

Current required private inputs:

- `account_id`
- `vpc_id`
- `public_subnet_ids`
- `app_private_subnet_ids`
- `db_private_subnet_ids`
- `allowed_operator_cidrs`
- `backend_image_uri`
- `staging_secret_arns`

## Why These Stay Outside Git

Private tfvars can expose account topology, subnet placement, operator source
networks, staging image provenance, and secret names. Even when values are not
passwords, they are operationally sensitive and must stay out of commits, pull
requests, issues, chat, screenshots, and committed documentation.

Allowed private paths used by the plan wrapper:

- `infra/terraform/staging-api/staging.auto.tfvars`
- `infra/terraform/staging-api/*.local.tfvars`

These paths are gitignored. Confirm locally with:

```sh
git check-ignore -v infra/terraform/staging-api/staging.auto.tfvars
git check-ignore -v infra/terraform/staging-api/example.local.tfvars
```

If a private tfvars file exists, it should appear only as ignored local material,
not as an added or modified tracked file:

```sh
git status --short --ignored infra/terraform/staging-api/staging.auto.tfvars infra/terraform/staging-api/*.local.tfvars
```

Expected ignored files are shown with `!!`. Stop if any private tfvars file is
shown as `A`, `M`, or another tracked status.

Never commit:

- VPC IDs.
- Subnet IDs.
- Operator CIDRs or public IPs.
- Real backend image URI if considered sensitive.
- Real secret ARNs.
- Passwords, tokens, access keys, session credentials, or private keys.
- Terraform plan binary.
- Raw plan output if it contains private infrastructure details.

## Redacted Template

Use this only as a shape reference. Do not replace `REDACTED`, `ACCOUNT_ID`, or
example addresses in committed files.

```hcl
account_id = "123456789012"
vpc_id = "vpc-REDACTED"
public_subnet_ids = ["subnet-REDACTED-a", "subnet-REDACTED-b"]
app_private_subnet_ids = ["subnet-REDACTED-a", "subnet-REDACTED-b"]
db_private_subnet_ids = ["subnet-REDACTED-a", "subnet-REDACTED-b"]
allowed_operator_cidrs = ["x.x.x.x/32"]
backend_image_uri = "ACCOUNT_ID.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend:STAGING_TAG"
staging_secret_arns = {
  database_url = "arn:aws:secretsmanager:eu-west-2:ACCOUNT_ID:secret:mscqr/staging/database-url-REDACTED"
}
```

The real `staging_secret_arns` object must include every required secret key from
`infra/terraform/staging-api/variables.tf`.

## Private Storage Guidance

- Store actual tfvars only on local encrypted disk or in a private operator
  folder with restricted permissions.
- If available, store the source values in 1Password, Bitwarden, or approved
  Secrets Manager notes; keep committed docs redacted.
- Do not paste values into PRs, issues, chat, screenshots, or committed docs.
- Screenshot evidence must redact private values before it is shared.
- Keep copied plan evidence under `.terraform-plans/staging/` or another
  approved private evidence store.

## Operator Commands

Run from the repository root:

```sh
cp infra/terraform/staging-api/terraform.tfvars.example infra/terraform/staging-api/staging.auto.tfvars
# Edit infra/terraform/staging-api/staging.auto.tfvars locally with private values.
git check-ignore -v infra/terraform/staging-api/staging.auto.tfvars
git status --short --ignored infra/terraform/staging-api/staging.auto.tfvars infra/terraform/staging-api/*.local.tfvars
npm run check:branch-secret-diff
npm run check:staging-private-inputs
npm run check:staging-aws-identity
MSCQR_STAGING_TERRAFORM_PLAN_ENABLED=true MSCQR_STAGING_TERRAFORM_PLAN_CONFIRM=MSCQR_GENERATE_STAGING_PLAN_ONLY npm run plan:staging-terraform
```

Only run the final plan command after the private input checker and AWS identity
guard pass. If the checker reports `blocked_missing_private_tfvars`, prepare the
private local file first. If it reports blockers, fix the local private inputs
without pasting values into git or chat.

## CTO Recommendations

- Keep one canonical private tfvars source per operator group and rotate access
  when operators change.
- Treat operator CIDRs as temporary approval data. Refresh them before each
  plan/apply review instead of reusing stale home or office addresses.
- Prefer immutable digest-pinned staging backend images once the first staging
  plan is ready for apply review.
