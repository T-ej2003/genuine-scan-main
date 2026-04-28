# Full Deployment Audit Report

Date: 2026-02-21  
Project: `genuine-scan-main`  
Auditor: Codex (automated + code inspection)

## 1. Scope

This audit covered:

- Build and test readiness (frontend + backend)
- Prisma migration reliability
- Container/deployment configuration (`Dockerfile`, `backend/Dockerfile`, `docker-compose.yml`, `nginx.conf`)
- Environment variable coverage and documentation quality
- Runtime readiness endpoints and operational docs
- CI/CD release-gate readiness from repository state

## 2. Evidence Collected

## 2.1 Executed checks

- `npm --prefix backend run build` -> passed
- `npm run build` -> passed
- `npm --prefix backend test` -> passed
- `npm test` -> passed
- `docker compose config` -> passed (compose syntax and resolution valid)
- `npm --prefix backend run prisma:migrate status` -> failed with migration-chain error

## 2.2 Static inspection

- Backend runtime and health endpoints: `backend/src/index.ts`
- API route registration: `backend/src/routes/index.ts`
- Env usage inventory: all `process.env.*` references under `backend/src`
- Frontend env usage inventory: all `import.meta.env.*` references under `src`

## 3. Findings

## Critical

1. Migration chain is not reproducible on clean environments.

- Severity: Critical
- Evidence: `prisma migrate status` returned `P3006` and failed in migration `20260213120000_add_incident_response`.
- Root cause: migration alters table `QrScanLog`, but that table is not created by prior migrations.
- Impact: fresh deployments (new environments / shadow DB / CI migration validation) can fail before app startup.
- Required action:
  1. Add a corrective migration or baseline/squashed migration to guarantee `QrScanLog` exists before it is altered.
  2. Validate with:
     - `npm --prefix backend run prisma:migrate status`
     - `npx prisma migrate reset` in a non-production validation database.

## High

2. CI/CD workflow files are currently local-only (not tracked in git).

- Severity: High
- Evidence: `git ls-files .github/workflows` returned no tracked files.
- Impact: release gate and deployment audit workflows do not run in remote repository until committed.
- Required action:
  1. Add and commit workflow files under `.github/workflows`.
  2. Verify GitHub Actions is enabled and runs on `main`.

3. Environment template was incomplete relative to code usage.

- Severity: High
- Evidence: many env keys used in backend code were missing from `backend/.env.example`.
- Impact: high risk of misconfiguration and production drift.
- Action completed in this audit:
  - Replaced `backend/.env.example` with a full, human-readable reference grouped by function.

## Medium

4. Frontend had no `.env.example`.

- Severity: Medium
- Impact: operators may miss required frontend variables during deployment.
- Action completed in this audit:
  - Added root `.env.example` with `VITE_API_URL`, `VITE_GOOGLE_OAUTH_URL`, and `VITE_API_PROXY_TARGET`.

5. Backend deployment documentation was outdated and inconsistent.

- Severity: Medium
- Examples:
  - incorrect default runtime port references
  - stale endpoint and lifecycle notes
- Action completed in this audit:
  - Replaced `documents/backend/README.md` with a deployment-accurate runbook.

## 4. What Passed

- Frontend production build succeeds.
- Backend TypeScript build succeeds.
- Frontend tests pass.
- Backend tests pass.
- Docker compose configuration is syntactically valid.
- Runtime health and version endpoints are implemented (`/health`, `/healthz`, `/health/db`, `/version`).

## 5. Deployment Readiness Status

Current status: **NOT READY for clean-environment production rollout**  
Blocking reason: migration reproducibility failure (`P3006` on `QrScanLog`).

Existing environments that already have required tables may run, but this is not acceptable for reliable industrial deployment.

## 6. Immediate Remediation Plan (ordered)

1. Fix Prisma migration chain (critical blocker).
2. Commit and enable CI audit/gate workflows in repository.
3. Run migration validation in a clean non-production DB.
4. Re-run release checks:
   - backend build + tests
   - frontend build + tests
   - prisma migrate status
5. Promote only after all above are green.

## 7. Files Updated During This Audit

- `.env.example` (added frontend env reference)
- `backend/.env.example` (expanded full backend env reference)
- `documents/backend/README.md` (deployment-accurate backend runbook)
- `documents/deployment-audit/FULL_DEPLOYMENT_AUDIT_2026-02-21.md` (this report)
