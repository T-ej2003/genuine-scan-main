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

### Workstation printers now use the local print agent
Run this on the manufacturer workstation, not on Lightsail. The agent now supports the normal OS-managed printer path on macOS, Linux, and Windows.

macOS or Linux:
```bash
cd /path/to/genuine-scan-main/backend
npm ci
npm run build
npm run print:agent
```

Windows PowerShell:
```powershell
cd C:\path\to\genuine-scan-main\backend
npm ci
npm run build
npm run print:agent
```

The browser on that same workstation should then load:
```bash
curl -sS http://127.0.0.1:17866/status
```

## 5) Smoke checks
```bash
curl -sS https://www.mscqr.com/api/healthz
curl -sS https://www.mscqr.com/api/version
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
