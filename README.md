# MSCQR

Production-grade, multi-tenant QR issuance, controlled-print, verification, anomaly-detection, and auditability platform.

Zebra ZT410 raw TCP validation and DB-backed print lifecycle notes are documented in
[`documents/ZEBRA_ZT410_DB_BACKED_PRINTING.md`](documents/ZEBRA_ZT410_DB_BACKED_PRINTING.md).


## 1. What This System Is

MSCQR is designed for anti-counterfeit operations across four user types:

- Super Admin: platform owner across all licensees.
- Licensee Admin: tenant operator for one licensee/brand.
- Manufacturer: scoped production user who prints assigned batches.
- Customer: public verifier who checks the MSCQR record for a product label and can report suspicious products.

Core outcome:

- Every QR code is generated, assigned, printed, scanned, and audited with strict server-side state control.
- High-risk behavior (multi-scan, geo drift, velocity spikes) is detected and can trigger automatic blocking policies.
- Batch-level immutable audit exports can be generated for compliance/investigation.

## 2. Read This First (Quick Start)

Prerequisites:

- Node.js 24 LTS
- npm 11+
- PostgreSQL reachable from your machine/runtime
- `psql` CLI installed (for `backend/scripts/check-db.sh`)

Install dependencies:

```bash
npm install
npm --prefix backend install
```

Configure backend env:

```bash
cp backend/.env.example backend/.env
```

Set at minimum in `backend/.env`:

- `DATABASE_URL`
- `JWT_SECRET`
- `PORT=4000` (recommended, matches frontend dev proxy defaults)

Generate Prisma client and run migrations:

```bash
npm --prefix backend run prisma:generate
npm --prefix backend run prisma:migrate
```

Optional: seed demo data:

```bash
npm --prefix backend run prisma:seed
```

Run backend and frontend:

```bash
npm --prefix backend run dev
npm run dev
```

Open app:

- Frontend (Vite): `http://localhost:8080`
- Backend API: `http://localhost:4000/api`
- Health: `http://localhost:4000/health`
- DB health: `http://localhost:4000/health/db`
- Latency summary: `http://localhost:4000/health/latency`

Targeted verification:

```bash
npm run typecheck:incremental
npm --prefix backend run build
npm run build
npm run verify:rc-local
```

Environment setup/doctor scripts:

```bash
bash scripts/dev/doctor.sh
```

See [documents/DEV_ENV_SETUP.md](documents/DEV_ENV_SETUP.md) for required toolchain installation.

Optional live smoke run against a ready environment:

```bash
E2E_BASE_URL=http://localhost:8080 \
E2E_SUPERADMIN_EMAIL=... \
E2E_SUPERADMIN_PASSWORD=... \
E2E_LICENSEE_ADMIN_EMAIL=... \
E2E_LICENSEE_ADMIN_PASSWORD=... \
E2E_MANUFACTURER_EMAIL=... \
E2E_MANUFACTURER_PASSWORD=... \
E2E_LICENSEE_BATCH_QUERY="Batch name" \
E2E_ASSIGN_MANUFACTURER_NAME="Manufacturer name" \
E2E_MANUFACTURER_BATCH_QUERY="Allocated batch" \
E2E_PRINTER_PROFILE_NAME="Ready printer profile" \
E2E_VERIFY_CODE=A0000000051 \
npm run test:e2e
```



## 4. Architecture

Frontend:

- React 18 + TypeScript + Vite
- React Router + TanStack Query
- Tailwind + Shadcn/Radix
- Recharts for dashboard visuals

Backend:

- Express + TypeScript
- Prisma + PostgreSQL
- JWT auth + role checks + tenant isolation middleware
- SSE for realtime dashboard/event streams

High-level flow:

1. Super Admin allocates QR inventory to a licensee.
2. Licensee Admin creates/assigns batches to manufacturers.
3. Manufacturer creates direct-print jobs and issues one-time render tokens via authenticated print agent.
4. Customer scans signed token (`/scan?t=...`) or verifies by code (`/verify/:code`).
5. System logs events, computes risk/SLA metrics, applies policy controls, and supports immutable audit export.

