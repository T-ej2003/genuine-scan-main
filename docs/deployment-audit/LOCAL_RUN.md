# Local Run (Dev + Deployment Audit)

Use this for a repeatable local validation before release.

## Prerequisites

- Node.js 18+ (Node 20 recommended)
- npm 9+
- PostgreSQL reachable from local machine
- Docker (optional; needed only for container scan/build validation)

## Step 1: Install dependencies

```bash
npm install
npm --prefix backend install
```

## Step 2: Configure environment

Backend:

```bash
cp backend/.env.example backend/.env
```

Frontend:

```bash
cp .env.example .env
```

Minimum required backend values:

- `DATABASE_URL`
- `JWT_SECRET`
- `PORT=4000`

## Step 3: Validate migrations and build

```bash
npm --prefix backend run prisma:generate
npm --prefix backend run prisma:migrate status
npm --prefix backend run build
npm run build
```

If `prisma:migrate status` fails with `P3006`, migration history is not clean for fresh environments. Do not deploy until corrected.

## Step 4: Run tests

```bash
npm --prefix backend test
npm test
npm run verify:rc-local
```

## Step 5: Start services locally

Terminal 1 (backend):

```bash
npm --prefix backend run dev
```

Terminal 2 (frontend):

```bash
npm run dev
```

## Step 6: Smoke-check runtime

- `http://localhost:4000/health`
- `http://localhost:4000/healthz`
- `http://localhost:4000/health/db`
- `http://localhost:4000/health/live`
- `http://localhost:8080` (frontend)

Local-only smoke:

```bash
npm run smoke:dev-local
```

Release/staging smoke:

```bash
SMOKE_BASE_URL=https://staging.example.com npm run verify:staging-smoke
```

## Optional local audit scans

If tools are installed locally:

```bash
mkdir -p audit-artifacts
gitleaks detect --source . --report-format sarif --report-path audit-artifacts/gitleaks.sarif
osv-scanner -r . --format json --output audit-artifacts/osv-results.json
trivy config --format sarif --output audit-artifacts/iac-trivy.sarif .
```
