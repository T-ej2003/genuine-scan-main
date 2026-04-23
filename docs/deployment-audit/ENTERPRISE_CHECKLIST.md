# Enterprise Deployment Checklist

Use this checklist for production releases. It aligns with the Deployment Audit workflow and the release gate.

## Change control
- [ ] Scope approved and PR reviewed.
- [ ] Release notes capture user-facing changes and breaking risks.
- [ ] Environment-specific configuration updated (no credential changes in code).
- [ ] `.github/workflows` deployment controls are committed and enabled in remote repository.
- [ ] `Release Candidate Gate / rc-trust-critical` passed on the release candidate branch.
- [ ] `Release Candidate Gate / rc-staging-smoke` passed against staging.
- [ ] `main` branch protection requires both Release Candidate Gate checks before merge.
- [ ] `release-checklist-artifact` JSON uploaded and reviewed.

## Security and compliance
- [ ] CodeQL SAST completed in `deployment-audit` workflow.
- [ ] Dependency vulnerability scan completed (OSV).
- [ ] Gitleaks secrets scan completed.
- [ ] IaC scan completed when IaC files are present.
- [ ] Trivy container scan completed when a Dockerfile is present.
- [ ] Rotation evidence and cleanup checks passed.
- [ ] Customer auth cutover check passed (bearer compat disabled when enforcement is active).

## Supply chain integrity
- [ ] SBOM generated and uploaded as an artifact.
- [ ] Provenance attestation generated for SBOM artifact.
- [ ] Audit artifacts retained for release evidence.
- [ ] Lint debt report artifact retained (`lint-debt-report.json` + issue template).

## Runtime readiness
- [ ] `/healthz` returns `status: ok`.
- [ ] Public version endpoint is disabled (`PUBLIC_VERSION_ENDPOINT_ENABLED=false`).
- [ ] Authenticated `/api/internal/release` returns release metadata for platform admins.
- [ ] Internal release metadata includes signing provider and key version.
- [ ] Required env vars set: `DATABASE_URL`, `JWT_SECRET`.
- [ ] SMTP configured (or accepted as a known limitation).
- [ ] `npm --prefix backend run prisma:migrate status` passes in release environment.
- [ ] Migration chain validated in a clean non-production database.

## Observability
- [ ] Structured logging configured if needed (`LOG_FORMAT=json`, `LOG_LEVEL`).
- [ ] Error handling validated for critical paths.
- [ ] CloudWatch metric filters applied for trust events.
- [ ] CloudWatch alarms applied and SNS/on-call routing confirmed.
- [ ] Alert test-fire evidence archived.

## Trust evidence
- [ ] Provenance backfill dry-run artifact archived.
- [ ] Provenance backfill execute artifact archived.
- [ ] Incident drill evidence attached for replay, break-glass, signer misconfig, legacy provenance, and challenge failures.
- [ ] Secret rotation evidence includes linked deploy SHAs and cleanup state.

## Rollback readiness
- [ ] Rollback plan reviewed: `docs/deployment-audit/ROLLBACK.md`.
- [ ] Prior stable build or image identified.
