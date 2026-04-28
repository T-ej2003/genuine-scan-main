# Lightsail Printing Update Commands (2026-03-12)

## Purpose

Use these commands in the AWS Lightsail browser terminal opened with `Connect using SSH`.

This deployment uses Docker Compose. Do not use `systemctl restart mscqr-backend` for the MSCQR app containers.

## 1. Confirm your local repository is ready

Run this on your local machine before you connect to Lightsail:

```bash
cd /Users/abhiramteja/Downloads/genuine-scan-main
git rev-parse HEAD
git status --short
```

Expected result:

- `git rev-parse HEAD` prints the commit you are about to deploy
- `git status --short` is empty before you push

## 2. Standard Lightsail Docker update

After you push to GitHub, open Lightsail `Connect using SSH` and run:

```bash
cd ~/genuine-scan-main
git fetch origin
git checkout <YOUR_BRANCH>
git pull --ff-only origin <YOUR_BRANCH>
git rev-parse HEAD
git status --short

docker compose build backend frontend
docker compose run --rm backend npx prisma migrate deploy
docker compose up -d --force-recreate backend frontend
docker compose ps
docker compose logs backend --tail=80
docker compose logs frontend --tail=80
curl -fsS http://127.0.0.1/healthz
```

## 3. Verify Lightsail matches local

Run this on Lightsail:

```bash
cd ~/genuine-scan-main
git rev-parse HEAD
git status --short
docker compose ps
```

Expected result:

- the Lightsail `git rev-parse HEAD` value matches the commit from your local machine
- `git status --short` is empty
- `docker compose ps` shows `backend` healthy and `frontend` running

## 4. Connector download smoke checks

Run this after the deploy to confirm the installer page and real download routes are healthy:

```bash
curl -fsS https://www.mscqr.com/api/public/connector/releases/latest
curl -I https://www.mscqr.com/api/public/connector/download/2026.3.12/macos
curl -I https://www.mscqr.com/api/public/connector/download/2026.3.12/windows
```

Expected result:

- the release endpoint returns `success: true`
- the Mac and Windows download requests return `HTTP/2 200`
- `Content-Disposition` is present for both installer downloads

## 4B. Managed printer UX smoke checks

Run these browser checks after the deploy for the manufacturer console:

1. Open `https://www.mscqr.com/printer-diagnostics`
2. Confirm the `Saved managed printer` card is fully clickable
3. Confirm clicking it opens the managed printer dialog with create, update, delete, and `Check`
4. Confirm the `NETWORK_DIRECT` card can open the factory-printer create flow
5. Confirm the `NETWORK_IPP` card can open both backend-direct and site-gateway create flows
6. Open `https://www.mscqr.com/dashboard` as a manufacturer and confirm the printer badge no longer forces `Install Connector` when a managed network route is already ready
7. Log in as a manufacturer with a ready workstation printer and confirm `Printing Status` auto-opens once immediately after login
8. Close `Printing Status`, then open `https://www.mscqr.com/batches` and `https://www.mscqr.com/audit-logs`
9. Confirm the `Printing Status` dialog does not auto-open again during that same login session unless you click the printer badge manually

## 5. Full container refresh

Use this only when you want a full rebuild and clean container recreate:

```bash
cd ~/genuine-scan-main
docker compose down --remove-orphans
docker compose build --no-cache backend frontend
docker compose run --rm backend npx prisma migrate deploy
docker compose up -d backend frontend
docker compose ps
```

## 6. Connector release checks

The packaged connector artifacts now live inside the repo under:

```text
backend/local-print-agent/releases/
```

To confirm the latest packaged connector files exist on Lightsail after pull:

```bash
cd ~/genuine-scan-main
find backend/local-print-agent/releases -maxdepth 3 -type f | sort
cat backend/local-print-agent/releases/manifest.json
```

You should see:

- the latest `manifest.json`
- the Mac installer package
- the Windows installer package

## 7. If a site connector workstation is used

If a private factory network uses the connector as a site gateway:

1. Pull the new code on Lightsail with the commands above.
2. Redeploy the latest connector package to the site workstation.
3. If needed, refresh the workstation `agent.env` values:

```dotenv
PRINT_GATEWAY_BACKEND_URL=https://your-mscqr-host/api
PRINT_GATEWAY_ID=<gateway-id>
PRINT_GATEWAY_SECRET=<bootstrap-secret>
```

4. Re-open `Printer Setup` in MSCQR and confirm the site gateway returns to `online`.
