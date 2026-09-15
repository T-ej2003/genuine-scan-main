# AWS EC2 Deployment (mscqr.com / www.mscqr.com)

This project is now configured to:

- start on HTTP first (port 80) if no TLS cert exists
- switch to HTTPS automatically (port 443) when Let's Encrypt certs are present at `deploy/certbot/conf`
- redirect `mscqr.com` to `https://www.mscqr.com`

## 1. AWS prerequisites (EC2)

- Create an EC2 instance (Ubuntu 22.04 LTS recommended).
- Open Security Group inbound rules:
  - `22` (SSH) from your IP
  - `80` (HTTP) from `0.0.0.0/0`
  - `443` (HTTPS) from `0.0.0.0/0`
- Ensure outbound internet access is enabled.
- If backend uses RDS:
  - allow EC2 security group to reach RDS on `5432`
- For the one-time initial-admin bootstrap, attach a deployment-only instance profile (or use an equally scoped assumed role) after `full-rls-role-provision` records the exact migration-secret ARN. Its only secret permission is `secretsmanager:GetSecretValue` on that exact ARN. Do not attach this permission to the ordinary backend runtime role or use a wildcard resource.

## 2. Namecheap DNS (recommended)

Use DNS host records (not just URL redirect records) so SSL works directly on your EC2 server:

- `A` record: host `@` -> `EC2_PUBLIC_IP`
- `CNAME` record: host `www` -> `mscqr.com`

Wait for DNS propagation, then verify:

```bash
dig +short mscqr.com
dig +short www.mscqr.com
```

## 3. Server setup (Docker + Compose)

```bash
sudo apt update
sudo apt install -y awscli ca-certificates curl git

curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER
newgrp docker

docker --version
docker compose version
aws --version
```

## 4. Deploy app code to EC2

```bash
git clone <your-repo-url> genuine-scan-main
cd genuine-scan-main
```

Update runtime values before first boot:

- `backend/.env`
  - `DATABASE_URL`
  - `JWT_SECRET`
  - `CORS_ORIGIN`
  - `PUBLIC_*_WEB_BASE_URL`
  - Do not place the initial super-admin password or deployment database URL in this runtime file. The one-time deployment-only bootstrap below supplies them separately.
  - `SMTP_HOST=mail.privateemail.com`
  - `SMTP_PORT=465` with `SMTP_SECURE=true` for Namecheap Private Email, or `SMTP_PORT=587` with `SMTP_SECURE=false` and `SMTP_REQUIRE_TLS=true` for STARTTLS troubleshooting
  - `SMTP_USER=<full mailbox>`, `SMTP_PASS=<mailbox password or app password>`, and `SMTP_FROM=<authorized mscqr.com sender>`
  - `EMAIL_DOMAIN=mscqr.com`

## 5. Provision the deployment-only migration credential, bootstrap the initial administrator, and start (HTTP mode)

Before starting the ordinary backend, complete the canonical RLS package phases in this order: `full-rls-admin-bootstrap`, `full-rls-role-provision`, `full-rls-role-verify`, Prisma migration during `full-rls-admin-ownership`, `full-rls-runtime-policy`, `full-rls-verification`, then `full-rls-application-canary`. The existing production RLS executor creates the target database first, then generates the login password for `mscqr_prd_rls_phase2_migration` and writes its TLS database URL only to the exact Secrets Manager handle `mscqr/production/rls-green/phase2/database-url/migration`; it never embeds that credential in generated SQL or runtime configuration. The bootstrap function and its RLS policy do not exist until the final two phases complete.

The bootstrap host must use that deployment-only instance profile or assumed role with exactly `secretsmanager:GetSecretValue` on the recorded migration secret. Verify the caller before reading it; do not use the ordinary runtime identity, static credentials, or the application `DATABASE_URL`. Capture the result directly into the one-shot process environment; do not echo it or add it to an `.env` file. The silent prompt keeps the initial credential out of shell history and command output; the process stores only its Argon2id hash.

```bash
set -euo pipefail
aws sts get-caller-identity >/dev/null
IFS= read -rsp "Initial administration@mscqr.com password: " SUPER_ADMIN_BOOTSTRAP_PASSWORD
echo
IFS= read -rsp "Confirm initial administration@mscqr.com password: " SUPER_ADMIN_BOOTSTRAP_PASSWORD_CONFIRM
echo
if [ "$SUPER_ADMIN_BOOTSTRAP_PASSWORD" != "$SUPER_ADMIN_BOOTSTRAP_PASSWORD_CONFIRM" ]; then
  unset SUPER_ADMIN_BOOTSTRAP_PASSWORD SUPER_ADMIN_BOOTSTRAP_PASSWORD_CONFIRM
  printf '%s\n' 'Initial administrator passwords do not match.' >&2
  exit 1
fi
unset SUPER_ADMIN_BOOTSTRAP_PASSWORD_CONFIRM
export SUPER_ADMIN_BOOTSTRAP_PASSWORD
export SUPER_ADMIN_BOOTSTRAP_DATABASE_URL="$(aws secretsmanager get-secret-value \
  --region eu-west-2 \
  --secret-id mscqr/production/rls-green/phase2/database-url/migration \
  --version-stage AWSCURRENT \
  --query SecretString \
  --output text)"
export SUPER_ADMIN_EMAIL='administration@mscqr.com'
export SUPER_ADMIN_NAME='MSCQR Administration'
export SUPER_ADMIN_BOOTSTRAP_AUTO_VERIFY='true'
docker compose run --rm --no-deps \
  -e SUPER_ADMIN_BOOTSTRAP_PASSWORD \
  -e SUPER_ADMIN_BOOTSTRAP_DATABASE_URL \
  -e SUPER_ADMIN_EMAIL \
  -e SUPER_ADMIN_NAME \
  -e SUPER_ADMIN_BOOTSTRAP_AUTO_VERIFY \
  backend npm run auth:bootstrap-super-admin
unset SUPER_ADMIN_BOOTSTRAP_PASSWORD SUPER_ADMIN_BOOTSTRAP_DATABASE_URL SUPER_ADMIN_EMAIL SUPER_ADMIN_NAME SUPER_ADMIN_BOOTSTRAP_AUTO_VERIFY
```

The command succeeds only when it creates the first super-admin. It refuses an existing super-admin or a conflicting configured email. After it succeeds, start the runtime containers; ordinary backend startup never receives the migration identity.

Start app before TLS cert exists. Frontend container will use HTTP config automatically.

```bash
docker compose --profile worker up -d --build redis backend worker frontend
docker compose ps
```

After the first successful login, change the initial password through the normal account flow and complete MFA enrollment. The deployment-only bootstrap variables were already removed from the operator shell and are not runtime configuration.

Verify HTTP:

```bash
curl -I http://mscqr.com
curl -I http://www.mscqr.com
```

Expected: `mscqr.com` redirects to `www.mscqr.com`.

## 6. Issue Let's Encrypt certificate (Certbot in Docker)

The compose file mounts:

- `./deploy/certbot/www` -> ACME webroot
- `./deploy/certbot/conf` -> certificates

Run Certbot directly:

```bash
docker run --rm \
  -v "$(pwd)/deploy/certbot/www:/var/www/certbot" \
  -v "$(pwd)/deploy/certbot/conf:/etc/letsencrypt" \
  certbot/certbot certonly --webroot \
  -w /var/www/certbot \
  -d mscqr.com -d www.mscqr.com \
  --email administration@mscqr.com \
  --agree-tos --no-eff-email
```

Or use the repo helper, which wraps the same command and restarts the frontend after the cert lands:

```bash
sh deploy/certbot/issue-letsencrypt.sh
```

Optional helper flags:

```bash
MSCQR_BOOTSTRAP_HTTP=true sh deploy/certbot/issue-letsencrypt.sh
MSCQR_LE_EMAIL=ops@example.com sh deploy/certbot/issue-letsencrypt.sh
```

## 7. Switch frontend container to HTTPS mode

Restart frontend after cert issuance. The image entrypoint will detect cert files and load HTTPS config automatically.

```bash
docker compose restart frontend
docker compose ps
```

Verify HTTPS:

```bash
curl -I https://mscqr.com
curl -I https://www.mscqr.com
```

Expected:

- `https://mscqr.com` -> `https://www.mscqr.com/...`
- `https://www.mscqr.com` -> `200`

## 8. Cert renewal (cron)

Add a cron job (or systemd timer wrapper) to renew and then restart frontend:

```bash
crontab -e
```

Example (runs daily at 3:15 AM) using the repo helper:

```cron
15 3 * * * cd /home/ubuntu/genuine-scan-main && /bin/sh deploy/certbot/renew-letsencrypt.sh
```

Dry-run the renewal helper before you install cron:

```bash
MSCQR_CERTBOT_DRY_RUN=true sh deploy/certbot/renew-letsencrypt.sh
```

## 9. Deploy updates later

```bash
cd /home/ubuntu/genuine-scan-main
git pull
docker compose --profile worker up -d --build redis backend worker frontend
```

## 10. Production checks

- Frontend loads over HTTPS
- Login works for `administration@mscqr.com`
- SMTP provider accepts the diagnostic recipient:
  `SMTP_TEST_TO=admin@example.com npm --prefix backend run check:smtp`
- Incident/customer/invite email sends show provider acceptance only when the intended recipient appears in the accepted list
- Gmail inbox placement is checked separately with the trace ID from `check:smtp`; see `documents/EMAIL_DELIVERABILITY_RUNBOOK.md`
- DNS authentication is checked with `EMAIL_DOMAIN=mscqr.com npm --prefix backend run check:email:dns`
- Backend can connect to RDS
- `/api` routes work through Nginx

## Notes

- The frontend container now exposes both `80` and `443`.
- TLS cert/private key files are kept out of git via `.gitignore`.
- If certs are missing, the frontend automatically falls back to HTTP mode until cert issuance is completed.
