# MSCQR Final Launch Blocker Evidence Pack

Date: 2026-06-06
Branch: `codex/final-launch-evidence-pack`
Status: Yellow until staging/prod credentials and evidence are supplied.

This pack collects the final launch blockers that require proof rather than feature work. Do not fake sign-offs and do not attach secrets.

## Evidence Index

| Area | Evidence doc | Current status |
|---|---|---|
| Prisma checksum metadata | `documents/qa/mscqr-prisma-checksum-signoff.md` | Yellow |
| Real deployed auth smoke | `documents/qa/mscqr-real-auth-smoke-signoff.md` | Yellow |
| SMTP smoke and inbox proof | `documents/qa/mscqr-smtp-smoke-signoff.md` | Yellow |
| Printer artifact launch sign-off | `documents/qa/mscqr-printer-artifact-launch-signoff.md` | Green for disabled no-leak, Yellow for positive artifact |
| Incident/SLA launch scope | `documents/qa/mscqr-incident-sla-launch-scope.md` | Green foundation, Yellow drill |

## Local Verification Commands

Run before attaching final evidence:

```bash
npm run typecheck
npm test
npm run test:health-release
npm run smoke:smtp
SMTP_SMOKE_REQUIRED=true npm run smoke:smtp
E2E_REAL_AUTH_REQUIRED=true npm run test:p2:e2e-real-auth
npm --prefix backend run test:prisma-checksum-smoke
npm run smoke:prisma-checksum
PRISMA_CHECKSUM_REQUIRED=true npm run smoke:prisma-checksum
git diff --check
```

The required-mode failure checks should fail when credentials/context are intentionally absent. That is expected and proves fail-closed behavior.

## Manual Staging/Production Evidence Commands

### Prisma checksum

```bash
PRISMA_CHECKSUM_ENABLED=true \
PRISMA_CHECKSUM_REQUIRED=true \
PRISMA_CHECKSUM_ENVIRONMENT=staging \
PRISMA_CHECKSUM_DATABASE_URL="$STAGING_READONLY_DATABASE_URL" \
npm run smoke:prisma-checksum
```

```bash
PRISMA_CHECKSUM_ENABLED=true \
PRISMA_CHECKSUM_REQUIRED=true \
PRISMA_CHECKSUM_ENVIRONMENT=production \
PRISMA_CHECKSUM_DATABASE_URL="$PROD_READONLY_DATABASE_URL" \
npm run smoke:prisma-checksum
```

### Real deployed auth

```bash
PLAYWRIGHT_BASE_URL=https://<staging-host> \
E2E_REAL_AUTH=true \
E2E_REAL_AUTH_REQUIRED=true \
E2E_SUPERADMIN_EMAIL="$STAGING_SUPERADMIN_EMAIL" \
E2E_SUPERADMIN_PASSWORD="$STAGING_SUPERADMIN_PASSWORD" \
E2E_LICENSEE_ADMIN_EMAIL="$STAGING_LICENSEE_ADMIN_EMAIL" \
E2E_LICENSEE_ADMIN_PASSWORD="$STAGING_LICENSEE_ADMIN_PASSWORD" \
E2E_MANUFACTURER_EMAIL="$STAGING_MANUFACTURER_EMAIL" \
E2E_MANUFACTURER_PASSWORD="$STAGING_MANUFACTURER_PASSWORD" \
npm run test:p2:e2e-real-auth
```

### SMTP inbox proof

```bash
SMTP_SMOKE_ENABLED=true \
SMTP_SMOKE_REQUIRED=true \
SMTP_SMOKE_TO="$STAGING_SMOKE_INBOX" \
SMTP_HOST="$STAGING_SMTP_HOST" \
SMTP_PORT="$STAGING_SMTP_PORT" \
SMTP_USER="$STAGING_SMTP_USER" \
SMTP_PASS="$STAGING_SMTP_PASS" \
SMTP_FROM="$STAGING_SMTP_FROM" \
REQUEST_ACCESS_NOTIFY_EMAIL="$STAGING_REQUEST_ACCESS_INBOX" \
SUPPORT_NOTIFY_EMAIL="$STAGING_SUPPORT_INBOX" \
npm run smoke:smtp
```

## Go/No-go Rules

Green to launch only when:

- staging and production Prisma checksum evidence is attached and `ok: true`
- real deployed auth smoke is unskipped and Green
- SMTP smoke has provider acceptance plus inbox proof
- printer artifact route decision is explicitly signed off
- incident/SLA manual launch owner and drill evidence are attached
- standard CI/release gates are Green

No-go if:

- any required smoke passes by skipping
- any secret appears in logs
- Prisma metadata is missing/mismatched without approved remediation
- auth smoke uses production customer accounts
- SMTP smoke uses production personal/customer inboxes
- printer artifacts are enabled without scoped content proof

## Current Recommendation

Do not mark final launch Green from this local branch alone. The tooling is ready, but the launch blockers remain Yellow until staging/prod evidence is supplied and attached.
