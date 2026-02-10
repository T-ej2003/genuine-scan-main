# Genuine Scan

Licensee + manufacturer QR authenticity platform.

## Quick Start (Local)
1. Backend: `cd backend && npm run dev`
2. Frontend: `npm run dev`

Set these environment variables in `backend/.env`:
- `QR_SIGN_PRIVATE_KEY` (Ed25519 private key, PEM)
- `QR_SIGN_PUBLIC_KEY` (Ed25519 public key, PEM)
- `PUBLIC_SCAN_WEB_BASE_URL` (e.g. `http://localhost:8080`)
- `SCAN_RATE_LIMIT_PER_MIN` (optional, default `60`)
- `QR_TOKEN_EXP_DAYS` (optional, default `3650`)

## Docker (Production Style)
This repo is dockerized for:
- Frontend: Vite build artifacts served by Nginx.
- Backend: Node + TypeScript + Prisma API.
- Reverse proxy: Nginx proxies `/api/*` to backend service.
- Database: external AWS RDS PostgreSQL via `DATABASE_URL`.

Files added:
- `Dockerfile` (frontend build + Nginx runtime)
- `nginx.conf` (SPA routing + API reverse proxy)
- `backend/Dockerfile` (backend build + runtime)
- `docker-compose.yml` (frontend + backend stack)
- `.dockerignore` (smaller/cleaner build context)

### Required Environment Variables (Compose)
Set these in a root `.env` file (same folder as `docker-compose.yml`):
- `DATABASE_URL` (RDS connection string)
- `JWT_SECRET`
- `QR_SIGN_PRIVATE_KEY` + `QR_SIGN_PUBLIC_KEY` (preferred), or `QR_SIGN_HMAC_SECRET`

Optional:
- `FRONTEND_PORT` (default `80`)
- `CORS_ORIGIN`
- `PUBLIC_SCAN_WEB_BASE_URL`
- `PUBLIC_VERIFY_WEB_BASE_URL`
- `SCAN_RATE_LIMIT_PER_MIN`
- `QR_TOKEN_EXP_DAYS`
- `JWT_EXPIRES_IN`

### Local Docker Run
1. Build images:
   - `docker compose build --no-cache`
2. Start stack:
   - `docker compose up -d`
3. Run DB migrations (one-off):
   - `docker compose run --rm backend npx prisma migrate deploy`
4. Verify services:
   - `docker compose ps`
   - `curl http://localhost/`
   - `curl http://localhost/api/health`
5. View logs:
   - `docker compose logs -f backend`
   - `docker compose logs -f frontend`

### AWS Lightsail Deploy Guide (Ubuntu)
1. Provision instance:
   - Ubuntu LTS, open ports `80` and `443` (if TLS later), and optionally `22` for SSH.
2. Install Docker Engine + Compose plugin:
   - `sudo apt-get update`
   - `sudo apt-get install -y ca-certificates curl gnupg`
   - `sudo install -m 0755 -d /etc/apt/keyrings`
   - `curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg`
   - `sudo chmod a+r /etc/apt/keyrings/docker.gpg`
   - `echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null`
   - `sudo apt-get update`
   - `sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin`
   - `sudo usermod -aG docker $USER`
   - Re-login SSH session, then verify: `docker --version && docker compose version`
3. Deploy code:
   - `git clone <your-repo-url>`
   - `cd genuine-scan-main`
4. Create `.env` in repo root with production values (`DATABASE_URL`, `JWT_SECRET`, signing keys, etc.).
5. Build and start:
   - `docker compose build`
   - `docker compose up -d`
6. Run production migrations:
   - `docker compose run --rm backend npx prisma migrate deploy`
7. Verify:
   - `docker compose ps`
   - `curl http://127.0.0.1/api/health`
   - Open `http://<lightsail-public-ip>/` in browser.
8. Update deployment on new release:
   - `git pull`
   - `docker compose build`
   - `docker compose run --rm backend npx prisma migrate deploy`
   - `docker compose up -d`

### Troubleshooting (Docker/Lightsail)
1. CORS errors:
   - Ensure frontend calls `/api` (already default in app).
   - Set `CORS_ORIGIN` to your public URL if browser still reports origin rejection.
2. Wrong API base URL:
   - Frontend defaults to `/api`.
   - If overridden, check `VITE_API_URL` is not forcing old `http://localhost:4000/api`.
3. Prisma connection failures:
   - Validate `DATABASE_URL` points to RDS and credentials are correct.
   - Confirm Lightsail instance can reach RDS (VPC/security group/NACL rules).
   - For SSL RDS URLs, ensure connection params (`sslmode=require` or equivalent) are correct.
4. Migration errors:
   - Run: `docker compose run --rm backend npx prisma migrate status`
   - Then: `docker compose run --rm backend npx prisma migrate deploy`
5. Backend appears down behind frontend:
   - Check backend logs: `docker compose logs -f backend`
   - Check Nginx logs: `docker compose logs -f frontend`

## Database (AWS RDS)
This project is configured to run on **AWS RDS PostgreSQL**. Ensure `DATABASE_URL` in `backend/.env` points to your RDS instance with SSL enabled.

Quick health check:
```
backend/scripts/check-db.sh
```

## Security Model (Threat Notes)
Prevented / detected:
- Forged QR payloads (signed tokens verified server-side).
- QR reuse (first scan redeems, further scans show fraud warning).
- Uncontrolled printing (print jobs + confirm lock printed codes).
- Batch compromise response (admin can block QR codes or full batches).

Not fully preventable:
- Someone can still photograph a physical label. Reuse will be detected and flagged as already redeemed.

## QR Security: Why It Can’t Be Usefully Duplicated
This system does **not** rely on sequential IDs or client-side checks. Every QR contains a **signed token** that is verified on the server. Copies of a QR image still fail after the first valid redemption.

How it works:
- **Signed payload (Ed25519)**: Each QR encodes a token with `qr_id`, `batch_id`, `licensee_id`, `manufacturer_id` (optional), `iat`, `exp`, and a random `nonce`. The server verifies the signature using the public key.
- **Server-side one-time redemption**: The first valid consumer scan transitions the QR to `REDEEMED`. Any later scan returns a fraud warning and the last redemption timestamp.
- **Print-lock handshake**: Manufacturers must create a print job and confirm printing. Only confirmed codes become `PRINTED`. Scans before printing return “Not activated / suspicious.”
- **Token hashing & audit logs**: Tokens are hashed in the database; events are logged (CREATED, PRINTED, REDEEMED, BLOCKED).
- **Rate limiting & abuse signals**: Scan endpoint is rate-limited and records scan counts, IPs, and device metadata.

### Technology Used
- **Ed25519 signatures** (server-side signing + verification)
- **One-time redemption state machine** (`DORMANT → PRINTED → REDEEMED`)
- **Print jobs with lock tokens** (manufacturer accountability)
- **Audit logging** for every lifecycle event
- **Scan rate limiting** + scan metadata capture

## Operational Flow
1. Super Admin allocates QR ranges to Licensees (creates received batches).
2. Licensee allocates quantities to Manufacturers (by batch).
3. Manufacturer creates a print job, downloads the signed QR pack, and confirms printing.
4. Consumer scans `/scan?t=...` and receives authenticity results.

## User Manual (Admins & Manufacturers)
Full manual: `docs/USER_MANUAL.md`

### Super Admin (Platform Owner)
1. Create Licensee: add brand name, location, support details, and licensee admin credentials.
2. Allocate QR batch: generate a new batch for a licensee (these appear as “Received” batches).
3. Monitor usage: use QR Tracking to review scan history, counts, and fraud warnings.
4. Audit oversight: view all logs and filter by licensee to investigate suspicious activity.
5. Block compromised codes: block a QR or whole batch if you suspect leakage or abuse.

### Licensee Admin (Brand Owner)
1. Manage manufacturers: create manufacturer users under your licensee.
2. Assign batches by quantity: split a received batch and allocate a quantity to a manufacturer.
3. Keep batches sequential: the system always allocates the next available codes in order.
4. Review printing status: track printed vs unprinted batches and view allocation history.
5. Audit your scope: audit logs are limited to your licensee and your manufacturers only.

### Manufacturer (Production Partner)
1. See assigned batches: only batches allocated to your manufacturer appear.
2. Create print job: choose quantity, generate signed QR tokens, and download the pack.
3. Confirm printing: click “Confirm Printed” after physical printing is complete.
4. One-time protection: each QR can be redeemed once; re-scans will show a fraud warning.
5. If printing fails: discard the pack and create a new print job for a fresh set of codes.

### Consumer (Public Scan)
1. Scan the QR: opens the verify page with brand and manufacturing details.
2. Authentic first scan: shows “Genuine” and redemption timestamp.
3. Duplicate scan: shows “Already redeemed / possible counterfeit.”
