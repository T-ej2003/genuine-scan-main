# Resend Password Setup Link Runbook

This runbook is for a platform admin/operator who needs to resend the account setup link for an existing MSCQR user, including `victoria@mscqr.com`.

## Safety Contract

- Do not create duplicate users.
- Do not print raw invite or password reset tokens.
- Run a dry-run first.
- Use setup invite only when the user exists, is active, is not deleted, has `status=INVITED`, and has no password hash.
- Use password reset only when the user already has a password or setup invite is not applicable.
- SMTP provider acceptance is not inbox delivery. Confirm inbox placement separately if needed.

## Required Runtime Variables

Database:

- `DATABASE_URL`

Frontend URL used in setup/reset email links:

- `WEB_APP_BASE_URL`, falling back to the first `CORS_ORIGIN`, then `http://localhost:8080`

SMTP:

- `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURE`, `SMTP_REQUIRE_TLS`
- `SMTP_USER`, `SMTP_PASS`
- `SMTP_FROM` is recommended; sender fallback is `SMTP_USER`

Supported SMTP aliases also exist in code:

- user: `SMTP_USER`, `SMTP_USERNAME`, `EMAIL_USER`, `MAIL_USER`
- password: `SMTP_PASS`, `SMTP_PASSWORD`, `EMAIL_PASS`, `MAIL_PASS`, `MAIL_PASSWORD`
- host: `SMTP_HOST`, `EMAIL_HOST`, `MAIL_HOST`
- from: `SMTP_FROM`, `AUTH_EMAIL_FROM`, `EMAIL_FROM`, `MAIL_FROM`, `SUPERADMIN_FROM_EMAIL`

## 1. Confirm User Exists

From a shell with production `DATABASE_URL` loaded:

```bash
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -x -c "SELECT id, email, role, status, \"isActive\", (\"deletedAt\" IS NOT NULL) AS deleted, (\"passwordHash\" IS NOT NULL) AS \"hasPassword\", \"orgId\", \"licenseeId\" FROM \"User\" WHERE email = 'victoria@mscqr.com';"
```

Expected setup-invite state:

- one row
- `role=PLATFORM_SUPER_ADMIN`
- `status=INVITED`
- `isActive=t`
- `deleted=f`
- `hasPassword=f`

If `hasPassword=t`, do not use a setup invite; use password reset.

## 2. Confirm The Actor Admin Exists

```bash
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -x -c "SELECT id, email, role, status, \"isActive\", (\"deletedAt\" IS NOT NULL) AS deleted FROM \"User\" WHERE email = 'administration@mscqr.com';"
```

Expected actor state:

- one row
- `role=SUPER_ADMIN` or `role=PLATFORM_SUPER_ADMIN`
- `isActive=t`
- `deleted=f`

## 3. Mac Terminal Path

Use this when your Mac shell has production `DATABASE_URL`, `WEB_APP_BASE_URL`, and SMTP variables loaded, or when you are pointed at a secure local production-like environment.

Build first because the operator script imports compiled backend services:

```bash
cd /Users/abhiramteja/Downloads/genuine-scan-main
npm --prefix backend run build
```

Dry-run:

```bash
npm --prefix backend run auth:resend-setup-link -- --email victoria@mscqr.com --actor-email administration@mscqr.com --mode setup
```

Apply setup invite resend:

```bash
npm --prefix backend run auth:resend-setup-link -- --email victoria@mscqr.com --actor-email administration@mscqr.com --mode setup --apply
```

If the dry-run or confirm query shows `hasPassword=true`, send a password reset instead:

```bash
npm --prefix backend run auth:resend-setup-link -- --email victoria@mscqr.com --actor-email administration@mscqr.com --mode reset --apply
```

## 4. ECS Production Path

The backend production image uses `WORKDIR /app` and includes `scripts`, `dist`, and `node_modules` under `/app`.

Set your deployment identifiers:

```bash
export AWS_REGION=eu-west-2
export ECS_CLUSTER=mscqr-prod-euw2-main
export ECS_SERVICE=mscqr-backend-servi-euw2
export ECS_CONTAINER=backend
```

Find a running backend task:

```bash
export ECS_TASK_ARN="$(aws ecs list-tasks --region "$AWS_REGION" --cluster "$ECS_CLUSTER" --service-name "$ECS_SERVICE" --desired-status RUNNING --query 'taskArns[0]' --output text)"
test "$ECS_TASK_ARN" != "None"
```

Dry-run inside the running backend task:

```bash
aws ecs execute-command \
  --region "$AWS_REGION" \
  --cluster "$ECS_CLUSTER" \
  --task "$ECS_TASK_ARN" \
  --container "$ECS_CONTAINER" \
  --interactive \
  --command "npm run auth:resend-setup-link -- --email victoria@mscqr.com --actor-email administration@mscqr.com --mode setup"
```

Apply setup invite resend:

```bash
aws ecs execute-command \
  --region "$AWS_REGION" \
  --cluster "$ECS_CLUSTER" \
  --task "$ECS_TASK_ARN" \
  --container "$ECS_CONTAINER" \
  --interactive \
  --command "npm run auth:resend-setup-link -- --email victoria@mscqr.com --actor-email administration@mscqr.com --mode setup --apply"
```

If the account already has a password, use reset mode:

```bash
aws ecs execute-command \
  --region "$AWS_REGION" \
  --cluster "$ECS_CLUSTER" \
  --task "$ECS_TASK_ARN" \
  --container "$ECS_CONTAINER" \
  --interactive \
  --command "npm run auth:resend-setup-link -- --email victoria@mscqr.com --actor-email administration@mscqr.com --mode reset --apply"
```

## 5. EC2 Docker Compose Path

On a production EC2 host that runs the repo with Docker Compose:

```bash
cd /home/ubuntu/genuine-scan-main
docker compose exec backend npm run auth:resend-setup-link -- --email victoria@mscqr.com --actor-email administration@mscqr.com --mode setup
docker compose exec backend npm run auth:resend-setup-link -- --email victoria@mscqr.com --actor-email administration@mscqr.com --mode setup --apply
```

If the account already has a password:

```bash
cd /home/ubuntu/genuine-scan-main
docker compose exec backend npm run auth:resend-setup-link -- --email victoria@mscqr.com --actor-email administration@mscqr.com --mode reset --apply
```

## 6. Verify Audit And Email Provider Result

For setup invite resends:

```bash
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -x -c "SELECT \"createdAt\", action, \"entityType\", \"entityId\", details FROM \"AuditLog\" WHERE action IN ('AUTH_INVITE_CREATED', 'AUTH_EMAIL_SENT', 'AUTH_EMAIL_FAILED', 'OPERATOR_PASSWORD_SETUP_LINK_RESENT') ORDER BY \"createdAt\" DESC LIMIT 10;"
```

For password reset sends:

```bash
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -x -c "SELECT \"createdAt\", action, \"entityType\", \"entityId\", details FROM \"AuditLog\" WHERE action IN ('AUTH_PASSWORD_RESET_REQUESTED', 'AUTH_EMAIL_SENT', 'AUTH_EMAIL_FAILED') ORDER BY \"createdAt\" DESC LIMIT 10;"
```

Look for:

- `emailDelivered=true`, or an `AUTH_EMAIL_SENT` row, to confirm SMTP provider acceptance.
- `emailErrorCode` and `emailDiagnostic` if provider acceptance failed.
- No raw token in command output or audit details.

## Recommendation Backlog

- Add a first-class platform-admin UI action for "Resend setup link" that does not expose raw links in API responses.
- Add an operator-only endpoint that returns delivery metadata but never returns invite/reset URLs.
- Add CloudWatch metric filters for `AUTH_EMAIL_FAILED` by template.
- Add a scheduled expired-invite cleanup job and dashboard count of invited users with expired setup links.
- Add an inbox-placement checklist for critical admin onboarding, because SMTP acceptance does not prove inbox delivery.
