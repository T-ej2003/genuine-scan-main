# MSCQR Production CI/CD and Disposable Integration Runbook

Date: 2026-07-03

## Canonical Production Deployment Path

The canonical production path is:

1. Dispatch `Release Train` from `main`, optionally with an exact `target_sha`.
2. `Release Train` resolves an exact commit on `origin/main`.
3. Required gates run for that exact commit: `quality-gate.yml`, `secret-scan.yml`, and `deployment-audit.yml`.
4. `Release Gate` checks out the exact SHA, verifies the checkout is clean, and verifies the SHA is still reachable from `origin/main`.
5. Dependencies install with `npm ci` in the root and backend packages.
6. Backend build and backend tests run.
7. Frontend typecheck, tests, and production build run.
8. Disposable integration tests run against GitHub Actions PostgreSQL and Redis service containers.
9. The separate governed image-publisher workflow builds, scans, signs, and publishes immutable images for:
   - `mscqr-backend`
   - `mscqr-web`
   - `mscqr-worker`
10. Release Gate authenticates the signed image authorization; it does not publish images.
11. Release Gate derives the exact Terraform-managed Stage-B backend candidate revision from authenticated state and activates it without registering another task definition.
12. Backend public health smoke checks must pass.
13. No worker service update is issued because production currently has no worker ECS service; worker image and candidate contracts remain governed for future topology.
14. The reviewed frontend task definition `mscqr-frontend:20` is preserved.
15. Frontend and public health smoke checks must pass.
16. The workflow summary records SHA, authenticated images, preserved frontend identity, exact backend candidate, and smoke results.

The deployment must not deploy `latest`. The SHA tag and digest refs are the deployable identities.

## Required GitHub Configuration

Production environment or repository variables/secrets:

- Release Gate uses the source-controlled exact role
  `arn:aws:iam::368992683803:role/mscqr-production-release-deployer` through
  GitHub OIDC. It does not accept a role variable or static AWS credentials.
- Release Gate fails before credential establishment until protected
  `MSCQR_PRODUCTION_RELEASE_DEPLOYER_OIDC_ROLLOUT.json` enables the OIDC attempt.
  That source phase is not trust evidence; AWS STS remains the live authority.
  Follow `documents/ops/iam/MSCQR_PRODUCTION_RELEASE_DEPLOYER_OIDC.md` for the
  one-time root-administrator convergence and protected source-phase sequence.
- `production` GitHub Environment: must require at least one reviewer.

Current live `eu-west-2` ECS discovery and production Terraform state contain no
worker ECS service. Do not configure worker service variables or grant worker
`UpdateService` authority until an independently reviewed topology introduces it.

## Disposable Integration Tests

CI runs `npm run test:integration:ci` in `quality-gate.yml` on pull requests and `main` pushes. The job starts:

- PostgreSQL service container with disposable DB `mscqr_p2_integration_test`
- Redis service container at `redis://127.0.0.1:6379/0`

The integration harness:

- applies Prisma migrations to a newly created disposable test DB,
- seeds deterministic P2 users, tenants, batches, QR codes, and print data,
- boots the compiled backend over real HTTP,
- boots the worker briefly when Redis is configured,
- verifies backend health, auth/session handling, tenant rejection, public valid/invalid verification, and audit logging,
- runs Playwright against the real frontend dev server proxied to the test backend.

Local run:

```bash
npm install
npm --prefix backend install
npm run test:integration
```

The local command starts disposable PostgreSQL on `127.0.0.1:55432` and disposable Redis on `127.0.0.1:56379` through `docker-compose.p2-test.yml`.

CI-equivalent run when PostgreSQL and Redis are already running:

```bash
export P2_TEST_DATABASE_REQUIRED=true
export P2_TEST_DB_PROTOCOL=postgresql
export P2_TEST_DB_USER=mscqr_rls_cert_admin
export P2_TEST_DB_HOST=127.0.0.1
export P2_TEST_DB_PORT=5432
export P2_TEST_DB_NAME=mscqr_p2_integration_test
admin_scheme="${P2_TEST_DB_PROTOCOL}:"
admin_authority="${P2_TEST_DB_USER}@${P2_TEST_DB_HOST}:${P2_TEST_DB_PORT}"
export P2_TEST_DATABASE_ADMIN_URL="${admin_scheme}//${admin_authority}/${P2_TEST_DB_NAME}"
export REDIS_URL="redis://127.0.0.1:6379/0"
npm run test:integration:ci
```

## Test DB Safety Guard

Disposable schema setup calls `backend/tests/helpers/testDbSafetyGuard.js` before migrations or seed actions. The guard rejects:

- production/staging markers such as `prod`, `production`, and `staging`,
- AWS/RDS/cloud-hosted markers such as `rds.amazonaws.com` and `amazonaws.com`,
- non-local hosts unless explicitly allowed for a controlled CI/container case,
- MSCQR-named DB hosts or users outside approved disposable naming.

Allowed examples:

```text
protocol=postgresql user=postgres host=localhost port=5432 database=mscqr_integration_test
protocol=postgresql user=postgres host=127.0.0.1 port=5432 database=mscqr_integration_test
protocol=postgresql user=postgres host=postgres port=5432 database=mscqr_integration_test
```

Never point `P2_TEST_DATABASE_ADMIN_URL` or `P2_TEST_DATABASE_URL` at staging or production.

## Post-Deploy Smoke Checks

`Release Gate` runs `scripts/aws/verify-production-smoke.sh` after ECS service stability. Backend rollout checks:

- `/api/health`
- `/health/ready`

Frontend/public rollout checks:

- `/`
- `/login`
- `/api/health`
- `/health/ready`

The smoke check fails closed on non-2xx responses and on JSON health payloads that do not report success, ready, healthy, or `status=ok/ready`.

## Operator Notes

- Use `Release Train` for normal production deployments from `main`.
- Do not deploy mutable image tags.
- Do not bypass `quality-gate.yml`, `secret-scan.yml`, or `deployment-audit.yml` except through the explicit `Release Gate` expert override during an emergency.
- Introduce any future worker ECS service through Terraform and a separate reviewed activation/IAM contract before changing Release Gate.
