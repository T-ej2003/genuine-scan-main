# Release Candidate Gate Setup

This repository now includes `.github/workflows/release-candidate-gate.yml` with two merge-gate jobs:

- `Release Candidate Gate / rc-trust-critical`
- `Release Candidate Gate / rc-staging-smoke`

## What this gate enforces

- Trust-critical test coverage before production merge.
- A staging smoke check using `npm run smoke:release`.
- Fail-fast behavior when staging credentials/config are missing.

## Required staging configuration

Set these in the repository before expecting `rc-staging-smoke` to pass:

### Repository Variables

- `STAGING_SMOKE_BASE_URL` (required)
- `STAGING_SMOKE_API_BASE_URL` (optional)
- `STAGING_SMOKE_VERIFY_CODE` (optional)
- `STAGING_SMOKE_BATCH_PRINT_ENDPOINT` (optional)
- `STAGING_SMOKE_BATCH_PRINT_PAYLOAD_JSON` (optional)
- `STAGING_SMOKE_INCIDENT_ENDPOINT` (optional)
- `STAGING_SMOKE_INCIDENT_PAYLOAD_JSON` (optional)
- `STAGING_SMOKE_EVIDENCE_URL` (optional)
- `STAGING_SMOKE_EVIDENCE_PATH` (optional)

### Repository Secrets

- `STAGING_SMOKE_LOGIN_EMAIL` (required)
- `STAGING_SMOKE_LOGIN_PASSWORD` (required)
- `STAGING_SMOKE_ADMIN_MFA_CODE` (optional when MFA challenge is expected)
- `STAGING_SMOKE_ADMIN_STEP_UP_CODE` (optional)
- `STAGING_SMOKE_STEP_UP_PASSWORD` (optional)

## GitHub branch enforcement requirement

GitHub only allows required status checks / rulesets with branch protection enabled.

If branch protection is available for your plan:

1. Open repository `Settings`.
2. Open `Branches`.
3. Add/update protection rule for `main`.
4. Enable `Require a pull request before merging`.
5. Enable `Require status checks to pass before merging`.
6. Mark both checks as required:
   - `Release Candidate Gate / rc-trust-critical`
   - `Release Candidate Gate / rc-staging-smoke`
7. Save changes.

If branch protection is not available on your current plan, the workflow still runs and reports failures, but GitHub cannot hard-block merges until branch protection/rulesets are enabled.
