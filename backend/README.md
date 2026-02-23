# Authentic QR Backend

Backend API for Genuine Scan / Authentic QR.

This file is deployment-focused. For product features and UI workflows, see `/README.md`.

## Runtime profile

- Framework: Express + TypeScript
- Database: PostgreSQL via Prisma
- Default API port: `4000`
- Base API path: `/api`
- Health endpoints:
  - `GET /health`
  - `GET /healthz`
  - `GET /health/db`
  - `GET /version`

## Local setup

1. Install packages

```bash
cd backend
npm install
```

2. Create env file

```bash
cp .env.example .env
```

3. Set required values in `.env`

- `DATABASE_URL`
- `JWT_SECRET`

4. Generate Prisma client and run migrations

```bash
npm run prisma:generate
npm run prisma:migrate
```

5. Run backend

```bash
npm run dev
```

## Production build

```bash
npm run build
npm run start
```

## Docker

`backend/Dockerfile` builds and runs the service on port `4000`.

Important:
- Keep `PORT=4000` inside container unless all upstream proxy paths are updated.
- Ensure env secrets are provided at runtime (not baked into image).

## Deployment validation checklist

Run before release:

```bash
npm run build
npm test
npm run prisma:migrate status
```

Then verify:

- `GET /healthz` returns `{"status":"ok", ...}`
- `GET /health/db` returns database reachable
- `GET /version` returns app name, version, git sha

## Critical migration note

As of `2026-02-21`, migration reproducibility from a clean shadow database fails at:

- `backend/prisma/migrations/20260213120000_add_incident_response/migration.sql`

Reason:
- The migration alters table `QrScanLog`, but that table is not created in earlier migration history.

Action required before production promotion to new environments:
- Fix migration chain (or create a safe baseline/squash migration) and re-run:
  - `npm run prisma:migrate status`
  - `npx prisma migrate reset` (in non-production validation DB)

Without this fix, greenfield deployments can fail during migration.
