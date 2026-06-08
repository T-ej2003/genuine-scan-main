# MSCQR Launch Smoke User Seed Runbook

Date: 2026-06-08
Status: Yellow until an operator runs this against the intended staging/production environment and records redacted evidence.

This runbook creates exactly three launch-test users for deployed auth smoke:

- `MSCQR Launch Smoke Platform` with role `SUPER_ADMIN`
- `MSCQR Launch Smoke Licensee` with role `LICENSEE_ADMIN`
- `MSCQR Launch Smoke Manufacturer` with role `MANUFACTURER`

Use staging-owned or launch-test emails only. Do not use customer accounts, personal inboxes, or production secrets in docs.

## Safety Contract

The script refuses unless all of these are true:

- `LAUNCH_SMOKE_SEED_ENABLED=true`
- `NODE_ENV=production` or `NODE_ENV=staging`
- `LAUNCH_SMOKE_CONFIRM=MSCQR_CREATE_LAUNCH_SMOKE_USERS`
- `DATABASE_URL` is already present in the runtime environment
- all three launch smoke email env vars are valid email addresses

The script does not print `DATABASE_URL`, cookies, JWTs, session values, or password hashes. Generated passwords are printed only to stdout during the operator run unless `LAUNCH_SMOKE_REDACT_CREDENTIALS=true`.

## EC2/Host Seed Command

Run from the deployed app host or backend container where the backend `DATABASE_URL` is already present. Use `set +x` so shell tracing cannot leak values.

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

If passwords are not supplied, strong random passwords are generated and printed once. Store them in the approved secret manager, then use them for the real-auth smoke. Do not paste generated passwords into Git, Slack, screenshots, or evidence docs.

Optional explicit password env vars:

```bash
LAUNCH_SMOKE_SUPERADMIN_PASSWORD="$SECRET_VALUE"
LAUNCH_SMOKE_LICENSEE_ADMIN_PASSWORD="$SECRET_VALUE"
LAUNCH_SMOKE_MANUFACTURER_PASSWORD="$SECRET_VALUE"
```

## Redacted Evidence Command

After credentials are stored, rerun only if an operator intentionally wants redacted seed evidence and accepts that passwords will rotate unless explicit password env vars are supplied.

```bash
set +x
NODE_ENV=production \
LAUNCH_SMOKE_SEED_ENABLED=true \
LAUNCH_SMOKE_CONFIRM=MSCQR_CREATE_LAUNCH_SMOKE_USERS \
LAUNCH_SMOKE_REDACT_CREDENTIALS=true \
LAUNCH_SMOKE_LICENSEE_PREFIX=LSMK \
LAUNCH_SMOKE_SUPERADMIN_EMAIL="$LAUNCH_SMOKE_SUPERADMIN_EMAIL" \
LAUNCH_SMOKE_SUPERADMIN_PASSWORD="$LAUNCH_SMOKE_SUPERADMIN_PASSWORD" \
LAUNCH_SMOKE_LICENSEE_ADMIN_EMAIL="$LAUNCH_SMOKE_LICENSEE_ADMIN_EMAIL" \
LAUNCH_SMOKE_LICENSEE_ADMIN_PASSWORD="$LAUNCH_SMOKE_LICENSEE_ADMIN_PASSWORD" \
LAUNCH_SMOKE_MANUFACTURER_EMAIL="$LAUNCH_SMOKE_MANUFACTURER_EMAIL" \
LAUNCH_SMOKE_MANUFACTURER_PASSWORD="$LAUNCH_SMOKE_MANUFACTURER_PASSWORD" \
npm run seed:launch-smoke-users
```

Attach only the `redactedEvidence` block.

## MFA Finding

Admin roles currently require admin MFA. The launch seed does not add a global MFA bypass. If `LAUNCH_SMOKE_REFRESH_ADMIN_MFA=true` and `LAUNCH_SMOKE_MFA_CONFIRM=MSCQR_REFRESH_LAUNCH_SMOKE_ADMIN_MFA`, it refreshes existing admin MFA freshness markers only for the two launch-smoke admin users so the deployed auth smoke can run non-interactively.

If that flag is not used, complete manual MFA setup/challenge for the launch-test admin users before running real-auth smoke.

## Refusal Cases

The script intentionally refuses when:

- enable or confirmation flags are missing
- `NODE_ENV` is not staging/production
- `DATABASE_URL` is absent
- emails are missing or malformed
- an existing email belongs to a non-launch-smoke named user
- an existing user is soft-deleted unless `LAUNCH_SMOKE_REACTIVATE_DELETED=true`
- MFA freshness is requested without the MFA confirmation phrase

## CTO Recommendation

Keep these accounts short-lived and scoped to launch evidence. After launch, rotate or disable them, retain the audit row and redacted evidence, and move recurring deployment smoke to dedicated CI-owned test accounts with automated credential rotation.
