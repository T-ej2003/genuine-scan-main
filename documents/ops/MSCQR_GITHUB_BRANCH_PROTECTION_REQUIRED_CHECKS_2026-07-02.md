# MSCQR GitHub Branch Protection Required Checks

Date: 2026-07-02
Scope: staging infrastructure validation gates for pull requests targeting `main`.

This document is operator-safe configuration guidance. It does not run Terraform,
mutate AWS, deploy services, use a production database, enable production or
global RLS, wire runtime routes, or authorize any bypass for `terraform apply`.

Hard boundaries for this document:

- No terraform plan.
- No terraform apply.
- No AWS mutation.
- No deployment.
- No production DB.
- No production/global/table RLS enablement.
- No runtime route wiring.
- No secrets in committed files.

## Purpose

Require the PR #95 staging infrastructure validation workflow before staging
infrastructure changes can merge to `main`.

The required status checks are:

- `Staging Infra Validation/Terraform staging validate`
- `Staging Infra Validation/Staging IAM policy lint`

## Scope

Protected branch:

- `main`

File and path scope:

- `infra/terraform/staging-api/**`
- `documents/ops/iam/**`
- `.github/workflows/staging-infra-validation.yml`
- `scripts/check-staging-terraform-validate.mjs`
- `scripts/check-staging-iam-policies.mjs`
- `package.json`

The ruleset configuration is documentation-only in this PR. No repository rule,
branch protection rule, GitHub API mutation, Terraform state, AWS resource, or
deployment is managed from this change.

## Why This Is Required

The first staging Terraform plan or apply must not happen from an unprotected
merge path. PR #95 added lightweight validation that runs without AWS credentials
and proves the staging Terraform root and staging operator IAM policy templates
still satisfy repository safety checks.

Branch protection makes those checks a merge precondition before any staging
operator can treat `main` as the source of truth for Terraform review. This is a
process control, not deployability proof. A passing check does not authorize
`terraform plan`, `terraform apply`, ECS Exec, production database access, AWS
mutation, production or global RLS enablement, deployment, or runtime route
wiring.

## GitHub Configuration

Use GitHub repository settings to configure either a repository ruleset or branch
protection rule:

1. Open the GitHub repository.
2. Go to **Settings**.
3. Go to **Rules** and then **Rulesets**, or go to **Branches** if rulesets are
   not available for this repository.
4. Target branch: `main`.
5. Enable **Require a pull request before merging**.
6. Enable **Require status checks to pass**.
7. Select these exact required checks:
   - `Staging Infra Validation/Terraform staging validate`
   - `Staging Infra Validation/Staging IAM policy lint`
8. Enable **Require branches to be up to date before merging** if this repository
   already uses up-to-date branch requirements or if the team accepts the extra
   rebase/update cost for staging infrastructure changes.
9. Enable **Require conversation resolution before merging**.
10. Restrict bypass permissions to owner/admin only.
11. Keep force-push disabled.
12. Keep branch deletions disabled.
13. Require signed commits only if this repository already enforces signed
    commits. Otherwise, treat signed commits as optional for this ruleset.

## Path-Specific Options

GitHub branch protection required checks are commonly branch-wide. If the
repository cannot make these required checks path-specific without rulesets, use
one of these options:

- Option A: require the two staging validation checks globally on all PRs to
  `main`.
- Option B: use GitHub rulesets with file path restrictions, if available, and
  apply the rule only to the paths listed in this document.

Recommended for now: require the checks globally if path-scoped rulesets are
unavailable. The workflow is lightweight, read-only, does not require AWS
credentials, and is safe to run on unrelated pull requests.

## Verification

After the ruleset or branch protection rule is enabled:

1. Open a test PR touching `infra/terraform/staging-api/README.md`.
2. Confirm both required checks appear on the PR:
   - `Staging Infra Validation/Terraform staging validate`
   - `Staging Infra Validation/Staging IAM policy lint`
3. Confirm merge is blocked until both checks pass.
4. Temporarily test an IAM policy lint failure in a throwaway branch and confirm
   the failed `Staging Infra Validation/Staging IAM policy lint` check blocks
   merge.
5. Temporarily test a Terraform validation failure in a throwaway branch and
   confirm the failed `Staging Infra Validation/Terraform staging validate` check
   blocks merge.
6. Confirm no AWS credentials are required for either check.
7. Restore the throwaway branch changes before closing or deleting test branches.

Do not use verification failures as a reason to bypass `terraform apply`
approval. Fix the repository validation or the branch-protection configuration
instead.

## Rollback And Change Control

- Do not disable required checks without owner approval.
- Any temporary bypass must be documented with reason, PR, approver, time, and
  restoration proof.
- Bypass must not be used for `terraform apply` approval.
- If a check is renamed, update this document, the checklist, and the protected
  branch configuration in the same approved change.
- If GitHub settings drift, restore required checks before any staging Terraform
  plan/apply review continues.

## CTO Recommendations

- Prefer a GitHub ruleset with path restrictions when the repository plan
  supports it; keep global required checks as the fallback because the workflow
  is cheap and read-only.
- Add a follow-up repository ruleset export or evidence screenshot to the
  staging approval record so branch-protection state is auditable before the
  first real staging Terraform plan.
- Keep staging infrastructure merge gates separate from apply approval. Merge
  checks prove repository safety; apply approval still needs reviewed plan
  evidence, least-privilege AWS identity, and explicit human approval.
