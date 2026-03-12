# Lightsail Update Commands (2026-03-05)

Use these on your Lightsail instance to deploy the security/print-state-machine update.

## 1) SSH and update code
```bash
ssh ubuntu@<YOUR_LIGHTSAIL_IP>
cd /home/ubuntu/genuine-scan-main
/usr/bin/git fetch --all
/usr/bin/git checkout <YOUR_BRANCH>
/usr/bin/git pull --ff-only
```

## 2) Backend migrate/build/test
```bash
cd /home/ubuntu/genuine-scan-main/backend
PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin npm ci
PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin npm run prisma:generate
PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin npx prisma migrate deploy
PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin npm test
```

## 3) Frontend build/test
```bash
cd /home/ubuntu/genuine-scan-main
PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin npm ci
PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin npm test
PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin npm run build
```

## 4A) If you run Docker Compose
```bash
cd /home/ubuntu/genuine-scan-main
docker compose up -d --build
docker compose ps
docker compose logs backend --tail 120
docker compose logs frontend --tail 120
```

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
