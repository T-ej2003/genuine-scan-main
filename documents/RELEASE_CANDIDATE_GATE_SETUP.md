# Release Candidate Gate Setup

This repository now includes `.github/workflows/release-candidate-gate.yml` with two merge-gate jobs. GitHub Actions publishes the job names as the required check contexts:

- `rc-trust-critical`
- `rc-staging-smoke`

## What this gate enforces

- Trust-critical test coverage before production merge.
- A staging smoke check using `npm run verify:staging-smoke`.
- Fail-fast behavior when staging credentials/config are missing.

## Required staging configuration

Set these in the repository before expecting `rc-staging-smoke` to pass:

### Repository Variables

- `STAGING_SMOKE_BASE_URL` (required)
- `STAGING_SMOKE_API_BASE_URL` (optional override; derived from base URL when missing)
- `STAGING_SMOKE_VERIFY_CODE` (required)
- `STAGING_SMOKE_BATCH_PRINT_ENDPOINT` (required)
- `STAGING_SMOKE_BATCH_PRINT_PAYLOAD_JSON` (required)
- `STAGING_SMOKE_INCIDENT_ENDPOINT` (required)
- `STAGING_SMOKE_INCIDENT_PAYLOAD_JSON` (required)
- `STAGING_SMOKE_EVIDENCE_URL` or `STAGING_SMOKE_EVIDENCE_PATH` (at least one required)
- `RC_PROVENANCE_BACKFILL_EVIDENCE_REF` (required for release evidence)
- `RC_SECRET_ROTATION_EVIDENCE_REF` (required for release evidence)
- `RC_INCIDENT_DRILL_EVIDENCE_REF` (required for release evidence)

### Repository Secrets

- `STAGING_SMOKE_LOGIN_EMAIL` (required)
- `STAGING_SMOKE_LOGIN_PASSWORD` (required)
- `STAGING_SMOKE_ADMIN_MFA_CODE` or `STAGING_SMOKE_ADMIN_STEP_UP_CODE` or `STAGING_SMOKE_STEP_UP_PASSWORD` (at least one required)

## GitHub branch enforcement requirement

GitHub only allows required status checks / rulesets with branch protection enabled.

If branch protection is available for your plan:

1. Open repository `Settings`.
2. Open `Branches`.
3. Add/update protection rule for `main`.
4. Enable `Require a pull request before merging`.
5. Enable `Require status checks to pass before merging`.
6. Mark both checks as required:
   - `rc-trust-critical`
   - `rc-staging-smoke`
7. Save changes.

If branch protection is not available on your current plan, the workflow still runs and reports failures, but GitHub cannot hard-block merges until branch protection/rulesets are enabled.

## Phase 1 local release evidence — 2026-07-24

Baseline: `44ef0de8e1ca154663b5b3f45c14c15109806076` on
`rls-full-integration`.

- The disposable P2 integration stack now uses PostgreSQL 18.4, applies Prisma
  migrations, and installs the exact generated RF7 ownership, policy, grant,
  and verification package before application fixtures run.
- Printing readiness uses only its reviewed `QRCode` projection, and sample
  membership failures emit and map the established `QR_NOT_IN_PRINT_JOB`
  lifecycle contract without exposing PostgreSQL or Prisma internals.
- The release-candidate trust-critical gate, security release gate, frontend
  and backend suites and builds, production dependency audits, integration
  suite, deterministic generation, full RLS verification, and PostgreSQL 18.4
  certification passed locally.
- Generated RLS inventory: 79 tables, 77 FORCE-RLS targets, 339 policies,
  60 column-privilege cells, and 16 authoritative SQL inputs. Source contract:
  `79ed6c312c88d01f09601fe04f3c3d5de11bace66a11fcfef8814262bc034ae1`.
- This evidence is local Phase 1 certification only. No staging smoke,
  deployment, AWS, production, shared database, push, or Phase 2 action was
  performed.
