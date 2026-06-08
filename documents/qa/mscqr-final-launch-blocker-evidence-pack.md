# MSCQR Final Launch Blocker Evidence Pack

Date: 2026-06-08
Branch: `codex/final-launch-evidence-pack`
Status: Yellow until deployed auth and SMTP evidence are supplied.

This pack collects launch blockers that require proof rather than feature work. Do not fake sign-offs, attach secrets, or mutate production data except through explicitly approved operator commands.

## Evidence Index

| Area | Evidence doc | Current status |
|---|---|---|
| Prisma checksum metadata | `documents/qa/mscqr-prisma-checksum-signoff.md` | Green for recorded production metadata, Yellow if separate staging metadata remains unverified |
| Launch smoke user seed | `documents/qa/mscqr-launch-smoke-user-seed-runbook.md` | Green tooling, Yellow until operator seed evidence is attached |
| Real deployed auth smoke | `documents/qa/mscqr-real-auth-smoke-signoff.md` | Yellow |
| SMTP smoke and inbox proof | `documents/qa/mscqr-smtp-smoke-signoff.md` | Yellow |
| Printer artifact launch sign-off | `documents/qa/mscqr-printer-artifact-launch-signoff.md` | Green for disabled no-leak, Yellow for positive artifact if enabled later |
| Incident/SLA launch scope | `documents/qa/mscqr-incident-sla-launch-scope.md` | Green foundation, Yellow for live drill evidence |

## Local Verification Commands

Run before attaching final evidence:

```bash
npm --prefix backend run test:launch-smoke-seed
npm --prefix backend run test:prisma-checksum-smoke
npm run test:health-release
npm run smoke:smtp
SMTP_SMOKE_REQUIRED=true npm run smoke:smtp
E2E_REAL_AUTH_REQUIRED=true npm run test:p2:e2e-real-auth
npm test
npm run typecheck
npm run build
node scripts/check-architecture-guardrails.mjs
npm run verify:ci:frontend
git diff --check
```

The required-mode checks should fail when credentials/context are intentionally absent. That failure proves fail-closed behavior and must not be hidden.

## Manual Prisma DB Sign-off

Use read-only metadata credentials. Do not run `prisma migrate resolve`, `prisma db push`, or any mutation.

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

Attach the JSON output only after verifying it does not contain DB URLs or secrets.

## Manual Launch Smoke User Seed

Run only from the app host/container where the intended DB env is already present.

```bash
set +x
cd /opt/mscqr/genuine-scan-main

NODE_ENV=production \
LAUNCH_SMOKE_SEED_ENABLED=true \
LAUNCH_SMOKE_CONFIRM=MSCQR_CREATE_LAUNCH_SMOKE_USERS \
LAUNCH_SMOKE_REFRESH_ADMIN_MFA=true \
LAUNCH_SMOKE_MFA_CONFIRM=MSCQR_REFRESH_LAUNCH_SMOKE_ADMIN_MFA \
LAUNCH_SMOKE_LICENSEE_PREFIX=LSMK \
LAUNCH_SMOKE_SUPERADMIN_EMAIL="$LAUNCH_SMOKE_SUPERADMIN_EMAIL" \
LAUNCH_SMOKE_LICENSEE_ADMIN_EMAIL="$LAUNCH_SMOKE_LICENSEE_ADMIN_EMAIL" \
LAUNCH_SMOKE_MANUFACTURER_EMAIL="$LAUNCH_SMOKE_MANUFACTURER_EMAIL" \
npm run seed:launch-smoke-users
```

Store generated passwords in the approved secret manager. Do not paste them into evidence.

## Manual Real Deployed Auth Sign-off

```bash
set +x
E2E_BASE_URL=https://<staging-or-production-host> \
E2E_API_BASE_URL=https://<staging-or-production-host> \
E2E_REAL_AUTH=true \
E2E_REAL_AUTH_REQUIRED=true \
E2E_SUPERADMIN_EMAIL="$LAUNCH_SMOKE_SUPERADMIN_EMAIL" \
E2E_SUPERADMIN_PASSWORD="$LAUNCH_SMOKE_SUPERADMIN_PASSWORD" \
E2E_LICENSEE_ADMIN_EMAIL="$LAUNCH_SMOKE_LICENSEE_ADMIN_EMAIL" \
E2E_LICENSEE_ADMIN_PASSWORD="$LAUNCH_SMOKE_LICENSEE_ADMIN_PASSWORD" \
E2E_MANUFACTURER_EMAIL="$LAUNCH_SMOKE_MANUFACTURER_EMAIL" \
E2E_MANUFACTURER_PASSWORD="$LAUNCH_SMOKE_MANUFACTURER_PASSWORD" \
npm run test:p2:e2e-real-auth
```

Attach timestamp, deployed SHA, Playwright result, and role labels/masked emails only.

## Manual SMTP Inbox Sign-off

```bash
set +x
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

Attach the JSON output plus provider/inbox proof for the generated `smokeId`.

## Production Bundle/SHA Evidence

Record:

- `/api/health/live` status and JSON body with non-`unknown` `release.gitSha`
- `/api/health/ready` status and JSON body
- `/api/auth/me` logged-out response as `401` JSON, not HTML/`502`
- intended release commit SHA
- deployed SHA comparison result
- asset/source-map check result if applicable

## Go/No-go Rules

Green to launch only when:

- staging and production Prisma checksum evidence is attached or the environment split is explicitly signed off
- launch smoke users are created with redacted evidence
- real deployed auth smoke is unskipped and Green
- SMTP smoke has provider acceptance plus inbox proof
- printer artifact route decision is explicitly signed off
- incident/SLA owner and launch drill evidence are attached or accepted as launch MVP scope
- standard CI/release gates are Green

No-go if:

- any required smoke passes by skipping
- any secret appears in logs or docs
- Prisma metadata is missing/mismatched without approved remediation
- auth smoke uses production customer accounts
- SMTP smoke uses production personal/customer inboxes
- printer artifacts are enabled without scoped content proof

## Current Recommendation

Do not mark final launch Green from this branch alone. The tooling is stronger now, including operator-controlled launch user seeding, but real deployed auth and SMTP remain Yellow until credentials are supplied and unskipped evidence is attached.


## SMTP deployed provider smoke

Status: GREEN

Evidence:
- `documents/qa/evidence/smtp-smoke-evidence.txt`
- Smoke ID: `SMTP-20260608T142542Z-9bd03f`
- SMTP auth verification: passed
- Required SMTP smoke: `ok: true`
- Provider accepted all intended recipients for request-access, support, support reply, and incident update templates.


## Printer launch blocker

Status: RED / BLOCKING

Evidence:
- `documents/qa/evidence/printer-launch-evidence-matrix.md`
- `documents/qa/evidence/printer-windows-usb-positive-evidence.md`
- `documents/qa/evidence/printer-windows-network-positive-evidence.md`
- `documents/qa/evidence/printer-failure-safety-evidence.md`
- `documents/qa/mscqr-printer-physical-validation-runbook.md`

Decision:
- Direct printing is launch-critical for MSCQR.
- Launch Green requires physical validation for Windows connector health, Windows USB/local connector printing, Windows network printer printing, and disabled/failure safety.
- USB-only proof does not validate network printing.
- Disabled/failure posture does not validate positive physical printing.
- Network printer validation cannot be deferred if MSCQR is launching with direct printer connection as a core capability.

Required before full launch Green:
1. Windows connector install/startup/health proof.
2. Positive Windows USB/local connector print artifact.
3. Positive Windows network printer print artifact.
4. Disabled/unreachable/failure route safety proof.
5. Cross-tenant printer/job denial proof.
6. Secret leakage check for print routes, logs, and generated artifacts.
