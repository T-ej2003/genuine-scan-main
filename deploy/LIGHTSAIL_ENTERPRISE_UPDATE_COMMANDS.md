# Lightsail Security Rollout Commands (2026-03-25)

Use this sequence for the security-hardening release on the Docker-based Lightsail instance.

## 0) Required backend env updates

Edit `/home/ubuntu/genuine-scan-main/backend/.env` before rebuilding. Production now expects secure cookie/auth settings, HTTPS public URLs, MFA encryption, email verification, and dual-slot secret rotation support.

Minimum required additions or updates:

```dotenv
NODE_ENV=production
COOKIE_SECURE=true
AUTH_LEGACY_TOKEN_RESPONSE_ENABLED=false
AUTH_SSE_QUERY_TOKEN_ENABLED=false
EMAIL_VERIFICATION_TTL_HOURS=24

WEB_APP_BASE_URL=https://www.mscqr.com
PUBLIC_ADMIN_WEB_BASE_URL=https://www.mscqr.com
PUBLIC_VERIFY_WEB_BASE_URL=https://www.mscqr.com
PUBLIC_SCAN_WEB_BASE_URL=https://www.mscqr.com

AUTH_MFA_ENCRYPTION_KEY=<32+ byte random secret>

JWT_SECRET_CURRENT=<new jwt signing secret>
JWT_SECRET_PREVIOUS=<old jwt signing secret during cutover only>

TOKEN_HASH_SECRET_CURRENT=<new token hash secret>
TOKEN_HASH_SECRET_PREVIOUS=<old token hash secret during cutover only>

IP_HASH_SALT_CURRENT=<new ip hash salt>
IP_HASH_SALT_PREVIOUS=<old ip hash salt during cutover only>

INCIDENT_HASH_SALT_CURRENT=<new incident hash salt>
INCIDENT_HASH_SALT_PREVIOUS=<old incident hash salt during cutover only>

PRINTER_SSE_SIGN_SECRET_CURRENT=<new printer sse signing secret>
PRINTER_SSE_SIGN_SECRET_PREVIOUS=<old printer sse signing secret during cutover only>

# Only if your deployment still uses QR HMAC signing instead of Ed25519:
QR_SIGN_HMAC_SECRET_CURRENT=<new qr hmac secret>
QR_SIGN_HMAC_SECRET_PREVIOUS=<old qr hmac secret during cutover only>
```

Notes:
- Keep `*_PREVIOUS` populated only during a rotation window. Remove them in the cleanup deploy after old tokens and signatures have aged out.
- `JWT_SECRET` remains legacy compatibility only. Prefer `JWT_SECRET_CURRENT`.
- Production startup now fails if the public URLs above are not HTTPS.
- The frontend does not need any new secret env vars for this rollout.

## 1) Update code on Lightsail

```bash
ssh ubuntu@<YOUR_LIGHTSAIL_IP>
cd /home/ubuntu/genuine-scan-main
/usr/bin/git fetch origin
/usr/bin/git checkout codex/industry-grade-hardening
/usr/bin/git pull --ff-only origin codex/industry-grade-hardening
export GIT_SHA=$(/usr/bin/git rev-parse HEAD)
export VITE_APP_ENV=production
export SENTRY_ENVIRONMENT=production
```

## 2) Run the database migration before the containers restart

The release adds `User.emailVerifiedAt`, `User.pendingEmail`, `User.pendingEmailRequestedAt`, and `EmailVerificationToken`.

```bash
cd /home/ubuntu/genuine-scan-main/backend
PATH=/usr/local/bin:/usr/bin:/bin npx prisma generate
PATH=/usr/local/bin:/usr/bin:/bin npx prisma migrate deploy
```

## 3) Rebuild and restart Docker Compose

```bash
cd /home/ubuntu/genuine-scan-main
export GIT_SHA=$(/usr/bin/git rev-parse HEAD)
export VITE_APP_ENV=production
export SENTRY_ENVIRONMENT=production
docker compose build --pull --no-cache backend frontend
docker compose up -d --force-recreate
docker compose ps
docker compose logs backend --tail 160
docker compose logs frontend --tail 160
```

## 4) Post-deploy verification

```bash
curl -sS https://www.mscqr.com/api/healthz
curl -sS https://www.mscqr.com/api/version
curl -sS https://www.mscqr.com/api/health/latency
curl -I https://www.mscqr.com/index.html
```

Application checks:
- log in through the browser without reading a token from the response body
- confirm the app stays authenticated after refresh
- confirm notifications and printer-status streams connect with cookies only
- open the email verification link for a pending email change and confirm the account updates cleanly
- confirm `/batches`, `/manufacturers`, and `/support` still load for each role

## 5) Secret-rotation cutover sequence

Use this exact order for zero-downtime rotation:

1. Stage new secrets in the `*_CURRENT` variables and move the old values into `*_PREVIOUS`.
2. Deploy this release with both current and previous secrets present.
3. Keep `AUTH_LEGACY_TOKEN_RESPONSE_ENABLED=false` and `AUTH_SSE_QUERY_TOKEN_ENABLED=false`.
4. Wait out the longest relevant window:
   - access token TTL
   - refresh token lifetime
   - password reset / email verification token TTL
   - any operational grace period you require
5. Remove the `*_PREVIOUS` variables from `backend/.env`.
6. Redeploy once more with the cleanup env set.

Do not remove previous secrets in the same deploy that introduces new current secrets.

## 6) Optional live smoke suite

Run only when you have safe credentials and reserved test data.

```bash
cd /home/ubuntu/genuine-scan-main
E2E_BASE_URL=https://www.mscqr.com \
E2E_SUPERADMIN_EMAIL=... \
E2E_SUPERADMIN_PASSWORD=... \
E2E_LICENSEE_ADMIN_EMAIL=... \
E2E_LICENSEE_ADMIN_PASSWORD=... \
E2E_MANUFACTURER_EMAIL=... \
E2E_MANUFACTURER_PASSWORD=... \
E2E_LICENSEE_BATCH_QUERY="Ready source batch" \
E2E_ASSIGN_MANUFACTURER_NAME="Ready manufacturer" \
E2E_MANUFACTURER_BATCH_QUERY="Allocated batch for print" \
E2E_PRINTER_PROFILE_NAME="Ready printer profile" \
E2E_VERIFY_CODE=A0000000051 \
PATH=/usr/local/bin:/usr/bin:/bin npm run test:e2e
```
