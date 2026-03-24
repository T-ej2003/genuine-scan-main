# Lightsail Update Commands (2026-03-24)

Use this sequence to push the current repo-hardening update and deploy it on Lightsail.

## 0) Local git push
```bash
cd /Users/abhiramteja/Downloads/genuine-scan-main
git status
git checkout -b codex/industry-grade-hardening
git add README.md .env.example deploy/LIGHTSAIL_ENTERPRISE_UPDATE_COMMANDS.md docker-compose.yml Dockerfile backend/Dockerfile package.json package-lock.json vite.config.ts tsconfig.app.json tsconfig.incremental-strict.json playwright.enterprise.config.ts src/vite-env.d.ts
git add src/App.tsx src/main.tsx src/pages/Batches.tsx src/pages/Dashboard.tsx src/pages/Incidents.tsx src/pages/SupportCenter.tsx src/pages/Verify.tsx
git add src/components/layout/DashboardLayout.tsx src/components/batches/LicenseeBatchWorkspaceDialog.tsx src/components/page-patterns src/features src/lib/api-client.ts src/lib/api src/lib/query-client.tsx src/lib/query-keys.ts src/lib/support-diagnostics.ts src/lib/observability
git add e2e
git add shared
git add backend/.env.example backend/package.json backend/package-lock.json backend/src/index.ts backend/src/routes/index.ts backend/src/controllers/healthController.ts
git add backend/src/controllers/printJobController.ts backend/src/controllers/printerAgentController.ts backend/src/controllers/verifyController.ts
git add backend/src/controllers/print-job backend/src/controllers/verify
git add backend/src/observability
git add backend/src/services/networkDirectPrintService.ts backend/src/services/printerConnectionService.ts
git add -u backend/dist dist
git commit -m "Harden architecture and add release observability"
git push -u origin codex/industry-grade-hardening
```

If you are already on your preferred branch, keep the same `git add`, `git commit`, and `git push` flow and skip the branch-creation line.

## 1) SSH and update code on Lightsail
```bash
ssh ubuntu@<YOUR_LIGHTSAIL_IP>
cd /home/ubuntu/genuine-scan-main
/usr/bin/git fetch --all
/usr/bin/git checkout codex/industry-grade-hardening
/usr/bin/git pull --ff-only
export GIT_SHA=$(/usr/bin/git rev-parse HEAD)
export VITE_APP_ENV=production
export SENTRY_ENVIRONMENT=production
# Optional if you are enabling Sentry in this deploy shell:
# export VITE_SENTRY_DSN=https://<frontend-dsn>
# export SENTRY_DSN_BACKEND=https://<backend-dsn>
```

## 2) Backend migrate/build/test
```bash
cd /home/ubuntu/genuine-scan-main/backend
PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin npm ci
PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin npm run prisma:generate
PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin npx prisma migrate deploy
PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin npm run build
```

## 3) Frontend build/test
```bash
cd /home/ubuntu/genuine-scan-main
PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin npm ci
PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin npm run typecheck:incremental
PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin npm run build
```

### Optional live workflow smoke
Run only when you have safe test credentials and batches/printers reserved for smoke coverage.

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
PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin npm run test:e2e
```

## 4A) If you run Docker Compose
```bash
cd /home/ubuntu/genuine-scan-main
export GIT_SHA=$(/usr/bin/git rev-parse HEAD)
export VITE_APP_ENV=production
export SENTRY_ENVIRONMENT=production
# Optional:
# export VITE_SENTRY_DSN=https://<frontend-dsn>
docker compose build --pull --no-cache backend frontend
docker compose up -d --force-recreate
docker compose ps
docker compose logs backend --tail 120
docker compose logs frontend --tail 120
```

If the previous backend build failed with `Cannot find module '../../../shared/contracts/printing'`, this clean rebuild is the fix. The backend image now builds from the repo root so the shared contracts are available during `tsc`.

### Optional mock printer for isolated network-direct testing
```bash
cd /home/ubuntu/genuine-scan-main
docker compose -f docker-compose.yml -f docker-compose.mock-printer.yml up -d --build mock-printer
docker compose -f docker-compose.yml -f docker-compose.mock-printer.yml ps mock-printer
curl -sS http://127.0.0.1:3001/status
```

Register the printer in the app as:
- host: `mock-printer`
- port: `9100`
- language: `ZPL`

## 4B) If you run PM2/systemd (non-Docker)
```bash
cd /home/ubuntu/genuine-scan-main/backend
PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin npm run build
pm2 restart genuine-scan-backend

cd /home/ubuntu/genuine-scan-main
pm2 restart genuine-scan-frontend
pm2 save
```

### Optional mock printer for isolated network-direct testing
```bash
cd /home/ubuntu/genuine-scan-main/backend
nohup node mock-printer/server.js > /tmp/mock-printer.log 2>&1 &
curl -sS http://127.0.0.1:3001/status
```

Register the printer in the app as:
- host: `127.0.0.1`
- port: `9100`
- language: `ZPL`

### Workstation printers now use the MSCQR Connector
Run this on the manufacturer workstation, not on Lightsail.

Standard rollout:

- open the `Install Connector` page in MSCQR
- download the Mac or Windows package for that workstation
- run the installer once
- confirm the printer already appears in the operating-system printer list
- open `Printer Setup` in MSCQR and confirm the printer shows as ready

Versioned connector packages now live in:

```text
backend/local-print-agent/releases/
```

On Lightsail, you can verify the packaged connector files with:

```bash
cd ~/genuine-scan-main
find backend/local-print-agent/releases -maxdepth 3 -type f | sort
cat backend/local-print-agent/releases/manifest.json
```

For enterprise rollout, distribute the packaged connector through Jamf, Intune, Kandji, or the manufacturer's normal software deployment process. The repository now includes the signed-package target for macOS, but a real production signature still requires your organization's Developer ID certificate outside source control.

## 5) Smoke checks
```bash
curl -sS https://www.mscqr.com/api/healthz
curl -sS https://www.mscqr.com/api/version
curl -sS https://www.mscqr.com/healthz
curl -sS https://www.mscqr.com/api/health/latency
curl -sS https://www.mscqr.com/api/public/connector/releases/latest
curl -I https://www.mscqr.com/api/public/connector/download/2026.3.12/macos
curl -I https://www.mscqr.com/api/public/connector/download/2026.3.12/windows
```

## 6) DB verify (new tables)
```bash
cd /home/ubuntu/genuine-scan-main/backend
PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin npx prisma studio
# verify presence of:
# PrintSession, PrintItem, PrintItemEvent,
# PrinterRegistration, PrinterAttestation,
# ForensicEventChain, ActionIdempotencyKey
```
