# Lightsail Printing Update Commands

## Purpose

Use these commands on the Lightsail instance after the printing architecture and production printer UX cleanup changes are pushed to GitHub.

Update the branch name if you deploy from a branch other than the one shown below.

```bash
cd /path/to/genuine-scan-main
git fetch origin
git checkout codex/printing-architecture-ipp-gateway
git pull --ff-only origin codex/printing-architecture-ipp-gateway

cd backend
npm ci
npx prisma generate
npx prisma migrate deploy
npm run build

cd ..
npm ci
npm run build
```

## If the backend runs under a service manager

Restart the backend after the build and migration steps.

Example:

```bash
sudo systemctl restart mscqr-backend
sudo systemctl status mscqr-backend --no-pager
```

## If a site gateway workstation is used

Redeploy the updated signed workstation connector package or refresh its `agent.env` values so the site gateway can continue polling outbound.
