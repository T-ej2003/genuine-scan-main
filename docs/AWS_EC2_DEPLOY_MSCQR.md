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
sudo apt install -y ca-certificates curl git

curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER
newgrp docker

docker --version
docker compose version
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
  - `SUPER_ADMIN_EMAIL=administration@mscqr.com`
  - `SUPER_ADMIN_BOOTSTRAP_ENABLED=true` for first production boot only
  - `SUPER_ADMIN_BOOTSTRAP_PASSWORD=<long unique first-login password>`
  - `SUPER_ADMIN_BOOTSTRAP_AUTO_VERIFY=true` so the initial configured super admin can sign in before SMTP verification is proven
  - `SMTP_*` values (especially `SMTP_PASS`)

## 5. First boot (HTTP mode)

Start app before TLS cert exists. Frontend container will use HTTP config automatically.

```bash
docker compose up -d --build
docker compose ps
```

After the first successful super admin login and MFA setup, remove the bootstrap secret and disable the startup bootstrap:

```bash
# in backend/.env
SUPER_ADMIN_BOOTSTRAP_ENABLED=false
SUPER_ADMIN_BOOTSTRAP_PASSWORD=
```

Then restart the backend container.

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
docker compose up -d --build
```

## 10. Production checks

- Frontend loads over HTTPS
- Login works for `administration@mscqr.com`
- Incident customer email sends successfully (check live delivery info in UI)
- Backend can connect to RDS
- `/api` routes work through Nginx

## Notes

- The frontend container now exposes both `80` and `443`.
- TLS cert/private key files are kept out of git via `.gitignore`.
- If certs are missing, the frontend automatically falls back to HTTP mode until cert issuance is completed.
