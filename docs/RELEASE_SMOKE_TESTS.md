# Release Smoke Tests

Use the smoke script after deploys to validate the live release with real cookies, CSRF, login, optional step-up auth, and optional workflow checks.

## Basic Health

```bash
npm run smoke:release
```

This validates:

- `/api/health/ready`
- `/api/version`

## Public Verify

```bash
export SMOKE_VERIFY_CODE=AADS00000020001
npm run smoke:release
```

## Authenticated Login

```bash
export SMOKE_LOGIN_EMAIL=ops@example.com
export SMOKE_LOGIN_PASSWORD='strong-password'
npm run smoke:release
```

## Admin MFA Login

If the login lands in MFA bootstrap mode:

```bash
export SMOKE_LOGIN_EMAIL=admin@example.com
export SMOKE_LOGIN_PASSWORD='strong-password'
export SMOKE_ADMIN_MFA_CODE=123456
npm run smoke:release
```

## Sensitive Step-Up Auth

Manufacturer/password step-up:

```bash
export SMOKE_LOGIN_EMAIL=manufacturer@example.com
export SMOKE_LOGIN_PASSWORD='strong-password'
export SMOKE_STEP_UP_PASSWORD='strong-password'
npm run smoke:release
```

Admin MFA step-up:

```bash
export SMOKE_LOGIN_EMAIL=admin@example.com
export SMOKE_LOGIN_PASSWORD='strong-password'
export SMOKE_ADMIN_MFA_CODE=123456
export SMOKE_ADMIN_STEP_UP_CODE=123456
npm run smoke:release
```

## Batch Print Smoke

```bash
export SMOKE_LOGIN_EMAIL=manufacturer@example.com
export SMOKE_LOGIN_PASSWORD='strong-password'
export SMOKE_STEP_UP_PASSWORD='strong-password'
export SMOKE_BATCH_PRINT_ENDPOINT=/manufacturer/print-jobs
export SMOKE_BATCH_PRINT_PAYLOAD_JSON='{"batchId":"<batch-id>","printerId":"<printer-id>","copies":1}'
npm run smoke:release
```

## Incident Creation Smoke

```bash
export SMOKE_LOGIN_EMAIL=admin@example.com
export SMOKE_LOGIN_PASSWORD='strong-password'
export SMOKE_ADMIN_MFA_CODE=123456
export SMOKE_ADMIN_STEP_UP_CODE=123456
export SMOKE_INCIDENT_ENDPOINT=/incidents
export SMOKE_INCIDENT_PAYLOAD_JSON='{"title":"Smoke incident","severity":"medium","summary":"Created by smoke check"}'
npm run smoke:release
```

## Evidence Retrieval Smoke

```bash
export SMOKE_LOGIN_EMAIL=admin@example.com
export SMOKE_LOGIN_PASSWORD='strong-password'
export SMOKE_EVIDENCE_PATH=/support/reports/<report-id>/attachment/<attachment-id>
npm run smoke:release
```

Use only non-production or intentionally safe test records for workflow smokes that create data.
