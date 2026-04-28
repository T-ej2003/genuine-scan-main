# Release Smoke Tests

Use the smoke script after deploys to validate the live release with real cookies, CSRF, login, optional step-up auth, and optional workflow checks.

## Basic Health

```bash
SMOKE_BASE_URL=https://staging.example.com npm run verify:staging-smoke
```

This validates:

- `/api/health/ready`
- `/api/health/live`
- `/api/internal/release` (after authenticated admin session)

## Public Verify

```bash
export SMOKE_BASE_URL=https://staging.example.com
export SMOKE_VERIFY_CODE=AADS00000020001
npm run verify:staging-smoke
```

## Authenticated Login

```bash
export SMOKE_LOGIN_EMAIL=ops@example.com
export SMOKE_LOGIN_PASSWORD='strong-password'
npm run verify:staging-smoke
```

## Admin MFA Login

If the login lands in MFA bootstrap mode:

```bash
export SMOKE_LOGIN_EMAIL=admin@example.com
export SMOKE_LOGIN_PASSWORD='strong-password'
export SMOKE_ADMIN_MFA_CODE=123456
npm run verify:staging-smoke
```

## Sensitive Step-Up Auth

Manufacturer/password step-up:

```bash
export SMOKE_LOGIN_EMAIL=manufacturer@example.com
export SMOKE_LOGIN_PASSWORD='strong-password'
export SMOKE_STEP_UP_PASSWORD='strong-password'
npm run verify:staging-smoke
```

Admin MFA step-up:

```bash
export SMOKE_LOGIN_EMAIL=admin@example.com
export SMOKE_LOGIN_PASSWORD='strong-password'
export SMOKE_ADMIN_MFA_CODE=123456
export SMOKE_ADMIN_STEP_UP_CODE=123456
npm run verify:staging-smoke
```

## Batch Print Smoke

```bash
export SMOKE_LOGIN_EMAIL=manufacturer@example.com
export SMOKE_LOGIN_PASSWORD='strong-password'
export SMOKE_STEP_UP_PASSWORD='strong-password'
export SMOKE_BATCH_PRINT_ENDPOINT=/manufacturer/print-jobs
export SMOKE_BATCH_PRINT_PAYLOAD_JSON='{"batchId":"<batch-id>","printerId":"<printer-id>","copies":1}'
npm run verify:staging-smoke
```

## Incident Creation Smoke

```bash
export SMOKE_LOGIN_EMAIL=admin@example.com
export SMOKE_LOGIN_PASSWORD='strong-password'
export SMOKE_ADMIN_MFA_CODE=123456
export SMOKE_ADMIN_STEP_UP_CODE=123456
export SMOKE_INCIDENT_ENDPOINT=/incidents
export SMOKE_INCIDENT_PAYLOAD_JSON='{"title":"Smoke incident","severity":"medium","summary":"Created by smoke check"}'
npm run verify:staging-smoke
```

## Evidence Retrieval Smoke

```bash
export SMOKE_LOGIN_EMAIL=admin@example.com
export SMOKE_LOGIN_PASSWORD='strong-password'
export SMOKE_EVIDENCE_PATH=/support/reports/<report-id>/attachment/<attachment-id>
npm run verify:staging-smoke
```

Use only non-production or intentionally safe test records for workflow smokes that create data.

## Local Dev Smoke (only for local runtime)

```bash
npm run smoke:dev-local
```

`smoke:release` now requires an explicit `SMOKE_BASE_URL` for release safety.
