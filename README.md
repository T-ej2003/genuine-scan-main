# Genuine Scan (AuthenticQR)

Production-grade, multi-tenant QR authenticity platform for secure code issuance, controlled print operations, consumer verification, anomaly detection, and auditability.

## 1. What This System Is

AuthenticQR is designed for anti-counterfeit operations across three user types:

- Super Admin: platform owner across all licensees.
- Licensee Admin: tenant operator for one licensee/brand.
- Manufacturer: scoped production user who prints assigned batches.

Core outcome:

- Every QR code is generated, assigned, printed, scanned, and audited with strict server-side state control.
- High-risk behavior (multi-scan, geo drift, velocity spikes) is detected and can trigger automatic blocking policies.
- Batch-level immutable audit exports can be generated for compliance/investigation.

## 2. Read This First (Quick Start)

Prerequisites:

- Node.js 18+ (Node 20 recommended)
- npm 9+
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

## 3. Repository Layout

```text
.
├── src/                              # Frontend React app
│   ├── pages/                        # Route pages
│   ├── components/                   # Shared and feature UI
│   ├── contexts/                     # Auth/session context
│   └── lib/api-client.ts             # API client
├── backend/
│   ├── src/
│   │   ├── controllers/              # HTTP handlers
│   │   ├── services/                 # Core business logic
│   │   ├── middleware/               # Auth/RBAC/tenant isolation
│   │   ├── routes/                   # API route registration
│   │   └── config/database.ts        # Prisma client
│   ├── prisma/
│   │   ├── schema.prisma             # Data model + enums
│   │   ├── migrations/               # Migration history
│   │   └── seed.ts                   # Seed script
│   ├── scripts/                      # Ops/dev scripts
│   └── tests/                        # Lightweight backend tests
├── docs/
│   └── USER_MANUAL.md                # Role-based user SOPs
├── docker-compose.yml
├── Dockerfile                        # Frontend image
├── backend/Dockerfile                # Backend image
└── nginx.conf                        # Frontend reverse proxy for /api
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

## 5. Roles and Access Model

Backend roles (`backend/prisma/schema.prisma`):

- `SUPER_ADMIN`
- `LICENSEE_ADMIN`
- `MANUFACTURER`

Frontend route access (`src/App.tsx`):

- `/dashboard`: all authenticated roles
- `/licensees`: super admin
- `/qr-codes`: super admin
- `/qr-requests`: super admin, licensee admin
- `/batches`: super admin, licensee admin, manufacturer
- `/manufacturers`: super admin, licensee admin
- `/qr-tracking`: super admin, licensee admin, manufacturer
- `/audit-logs`: super admin, licensee admin
- `/account`: all authenticated roles
- `/verify`, `/verify/:code`, `/scan`: public

RBAC middleware (`backend/src/middleware/rbac.ts`):

- `requireSuperAdmin`
- `requireLicenseeAdmin`
- `requireManufacturer`
- `requireAnyAdmin`
- `requireOpsUser` (super admin, licensee admin, manufacturer)

Tenant isolation (`backend/src/middleware/tenantIsolation.ts`):

- Non-super admins cannot operate outside their own `licenseeId`.
- Super admin may optionally scope many endpoints with `licenseeId` query/body/param.

## 6. Core Domain and Lifecycle

QR statuses (`QRStatus`):

- `DORMANT`
- `ACTIVE`
- `ALLOCATED`
- `ACTIVATED`
- `PRINTED`
- `REDEEMED`
- `BLOCKED`
- `SCANNED` (legacy compatibility)

Formal trace event taxonomy (`TraceEventType`):

- `COMMISSIONED`
- `ASSIGNED`
- `PRINTED`
- `REDEEMED`
- `BLOCKED`

Typical status progression:

1. `DORMANT` after allocation/generation.
2. `ALLOCATED` when attached to a batch.
3. `ACTIVATED` when a print job reserves and signs tokens.
4. `PRINTED` when job is confirmed/downloaded.
5. `REDEEMED` on first successful scan.
6. `BLOCKED` by admin action or policy engine.

## 7. Security Model

Code-level assessment: highly secure,  enterprise-strong t (strongly high).

Implemented protections:

- Signed QR tokens (Ed25519 preferred; HMAC fallback).
- Token hash + nonce binding in DB (`tokenHash`, `tokenNonce`).
- Licensee/batch/manufacturer binding checks at scan time.
- One-time redemption semantics.
- IP-based scan rate limiting (`SCAN_RATE_LIMIT_PER_MIN`).
- Audit logs for sensitive transitions.
- Policy engine for anomaly-triggered auto-block.

Token signing behavior (`backend/src/services/qrTokenService.ts`):

- Preferred mode: `QR_SIGN_PRIVATE_KEY` + `QR_SIGN_PUBLIC_KEY`.
- Fallback mode: `QR_SIGN_HMAC_SECRET`.
- If neither is set, signing/verification cannot run.

## 8. Advanced Modules (Industrial-grade Additions)

### 8.1 Trace Timeline

Endpoints:

- `GET /api/trace/timeline`

Features:

- Uses formal taxonomy: `COMMISSIONED`, `ASSIGNED`, `PRINTED`, `REDEEMED`, `BLOCKED`.
- Backfills trace events from audit logs where needed.
- Supports filters: `eventType`, `batchId`, `manufacturerId`, `qrCodeId`, `limit`, `offset`.

### 8.2 Batch SLA Analytics

Endpoint:

- `GET /api/analytics/batch-sla`

Outputs:

- Time-to-print
- Time-to-first-scan
- Stuck batch detection (`STUCK_WAITING_PRINT`, `STUCK_WAITING_FIRST_SCAN`)

Controls:

- Policy-driven `stuckBatchHours` (override via query).

### 8.3 Risk Scoring

Endpoint:

- `GET /api/analytics/risk-scores`

Batch risk formula (`backend/src/services/analyticsService.ts`):

- `score = min(100, multiScan*12 + geoDrift*22 + velocitySpike*28 + openAlerts*5)`

Manufacturer risk formula:

- `score = min(100, multiScan*8 + geoDrift*16 + velocitySpike*22 + openAlerts*4 + batches*2)`

Risk levels:

- `LOW` (<35)
- `MEDIUM` (35-64)
- `HIGH` (65-84)
- `CRITICAL` (85+)

### 8.4 Policy Engine

Endpoints:

- `GET /api/policy/config`
- `PATCH /api/policy/config`
- `GET /api/policy/alerts`
- `POST /api/policy/alerts/:id/ack`

Policy defaults (`SecurityPolicy`):

- `autoBlockEnabled = true`
- `autoBlockBatchOnVelocity = false`
- `multiScanThreshold = 2`
- `geoDriftThresholdKm = 300`
- `velocitySpikeThresholdPerMin = 80`
- `stuckBatchHours = 24`

Alert types (`PolicyAlertType`):

- `MULTI_SCAN`
- `GEO_DRIFT`
- `VELOCITY_SPIKE`
- `STUCK_BATCH`
- `AUTO_BLOCK_QR`
- `AUTO_BLOCK_BATCH`

### 8.5 Immutable Batch Audit Export

Endpoint:

- `GET /api/audit/export/batches/:id/package`

ZIP package contents (`backend/src/services/immutableAuditExportService.ts`):

- `batch-manifest.json`
- `batch-manifest.csv`
- `trace-events.json`
- `event-chain.jsonl` (hash-linked chain)
- `policy-alerts.json`
- `integrity.json` (file hashes + signature)
- `README.txt`

Signature:

- Ed25519 if private key exists, otherwise HMAC-SHA256 fallback.

## 9. API Map (Current Backend)

All routes below are mounted under `/api` unless noted.

Public:

- `POST /auth/login`
- `GET /verify/:code`
- `GET /scan?t=...`
- `GET /health`

Authenticated:

- `GET /auth/me`
- `GET /dashboard/stats`
- `GET /events/dashboard` (SSE; supports `?token=`)

Licensees (super admin):

- `POST /licensees`
- `GET /licensees`
- `GET /licensees/:id`
- `PATCH /licensees/:id`
- `DELETE /licensees/:id`
- `GET /licensees/export`

Users/manufacturers:

- `POST /users` (any admin)
- `GET /users` (any admin)
- `PATCH /users/:id` (any admin)
- `DELETE /users/:id` (any admin)
- `GET /manufacturers` (any admin)
- `PATCH /manufacturers/:id/deactivate` (any admin)
- `PATCH /manufacturers/:id/restore` (any admin)
- `DELETE /manufacturers/:id` (any admin)

QR inventory and batches:

- `POST /qr/ranges/allocate` (super admin)
- `POST /qr/generate` (super admin)
- `POST /admin/licensees/:licenseeId/qr-allocate-range` (super admin)
- `POST /qr/batches` (licensee admin)
- `GET /qr/batches`
- `POST /qr/batches/:id/assign-manufacturer` (licensee admin)
- `POST /qr/batches/admin-allocate` (super admin helper)
- `GET /qr/codes` (super admin)
- `GET /qr/codes/export` (super admin)
- `GET /qr/stats`
- `DELETE /qr/batches/:id` (any admin)
- `POST /qr/batches/bulk-delete` (any admin)
- `DELETE /qr/codes` (any admin)

Manufacturer print jobs:

- `POST /manufacturer/print-jobs`
- `GET /manufacturer/print-jobs/:id/pack?token=...`
- `POST /manufacturer/print-jobs/:id/confirm`

QR requests:

- `POST /qr/requests` (any admin)
- `GET /qr/requests` (any admin)
- `POST /qr/requests/:id/approve` (super admin)
- `POST /qr/requests/:id/reject` (super admin)

Audit/logging:

- `GET /audit/logs` (any admin)
- `GET /audit/logs/export` (any admin)
- `GET /audit/stream` (any admin SSE)
- `GET /admin/qr/scan-logs` (ops users)
- `GET /admin/qr/batch-summary` (ops users)

Trace/analytics/policy:

- `GET /trace/timeline`
- `GET /analytics/batch-sla` (any admin)
- `GET /analytics/risk-scores` (any admin)
- `GET /policy/config` (any admin)
- `PATCH /policy/config` (any admin)
- `GET /policy/alerts` (any admin)
- `POST /policy/alerts/:id/ack` (any admin)
- `GET /audit/export/batches/:id/package` (any admin)

Blocking/admin controls:

- `POST /admin/qrs/:id/block` (super admin)
- `POST /admin/batches/:id/block` (super admin)

Incident response:

- `POST /incidents/report` (public)
- `GET /incidents` (any admin)
- `GET /incidents/:id` (any admin)
- `PATCH /incidents/:id` (any admin)
- `POST /incidents/:id/events` (any admin)
- `POST /incidents/:id/evidence` (any admin)
- `POST /incidents/:id/email` (any admin; `/incidents/:id/notify-customer` kept as backward-compatible alias)

Account:

- `PATCH /account/profile`
- `PATCH /account/password`

Process-level health routes (not under `/api`):

- `GET /health`
- `GET /health/db`

Route source of truth: `backend/src/routes/index.ts`

## 10. Environment Variables

Backend (`backend/.env`):

Required:

- `DATABASE_URL`: PostgreSQL DSN.
- `JWT_SECRET`: JWT signing key.

Recommended:

- `QR_SIGN_PRIVATE_KEY`: Ed25519 private key PEM (`\\n` escaped newlines supported).
- `QR_SIGN_PUBLIC_KEY`: Ed25519 public key PEM.

Fallback signing option:

- `QR_SIGN_HMAC_SECRET`: used only if Ed25519 keys are not set.

Optional:

- `PORT` (default `4000`)
- `NODE_ENV` (`development`/`production`)
- `JWT_EXPIRES_IN` (default `7d`)
- `CORS_ORIGIN` (comma-separated origins)
- `PUBLIC_SCAN_WEB_BASE_URL`
- `PUBLIC_VERIFY_WEB_BASE_URL`
- `SCAN_RATE_LIMIT_PER_MIN` (default `60`)
- `QR_TOKEN_EXP_DAYS` (default `3650`)
- `PRINT_JOB_LOCK_TTL_MINUTES` (default `45`; validity window for direct-print job lock token)
- `DIRECT_PRINT_TOKEN_TTL_SECONDS` (default `90`; one-time render token lifespan)
- `DIRECT_PRINT_MAX_BATCH` (default `250`; max one-time render tokens per issuance call)
- `QR_ZIP_HIGH_VOLUME_THRESHOLD` (default `100000`)
- `QR_ZIP_ULTRA_VOLUME_THRESHOLD` (default `1000000`)
- `QR_ZIP_STANDARD_LEVEL` (default `6`)
- `QR_ZIP_HIGH_LEVEL` (default `8`)
- `QR_ZIP_ULTRA_LEVEL` (default `9`)
- `QR_ZIP_STANDARD_PNG_WIDTH` (default `768`)
- `QR_ZIP_HIGH_PNG_WIDTH` (default `640`)
- `QR_ZIP_ULTRA_PNG_WIDTH` (default `512`)
- `QR_ZIP_STANDARD_PNG_CONCURRENCY` (default auto by CPU, capped at `16`)
- `QR_ZIP_HIGH_PNG_CONCURRENCY` (default auto by CPU, capped at `20`)
- `QR_ZIP_ULTRA_PNG_CONCURRENCY` (default auto by CPU, capped at `24`)
- `QR_ZIP_STANDARD_DB_CHUNK_SIZE` (default `2000`)
- `QR_ZIP_HIGH_DB_CHUNK_SIZE` (default `5000`)
- `QR_ZIP_ULTRA_DB_CHUNK_SIZE` (default `10000`)
- `PUBLIC_ADMIN_WEB_BASE_URL` (used in incident alert emails; default falls back to verify base URL)
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURE`, `SMTP_USER`, `SMTP_PASS` (incident email delivery transport)
- `SUPERADMIN_ALERT_EMAILS` (optional comma-separated override for admin incident alerts)
- `EMAIL_USE_JSON_TRANSPORT` (`true` for local JSON transport testing)
- `INCIDENT_HASH_SALT` (salt for hashing IP / user-agent fingerprints)
- `INCIDENT_RATE_LIMIT_WINDOW_MS` (default `3600000`)
- `INCIDENT_RATE_LIMIT_MAX_PER_KEY` (default `8`)
- `INCIDENT_SPAM_MAX_PER_HOUR` (default `5`)
- `INCIDENT_CAPTCHA_ENABLED` (`true/false`, default `false`)
- `INCIDENT_CAPTCHA_BYPASS_TOKEN` (optional local bypass token)
- `RECAPTCHA_SECRET_KEY` (required if captcha is enabled without bypass)
- `INCIDENT_UPLOAD_MAX_BYTES` (default `5242880`)
- `INCIDENT_UPLOAD_MAX_FILES` (default `4`)
- `INCIDENT_EVIDENCE_MAX_BYTES` (default `8388608`)
- `GEO_REVERSE_ENABLED` (`true/false`, default `true`)
- `GEO_REVERSE_TIMEOUT_MS` (default `1200`)
- `POLICY_RAPID_REPEAT_MINUTES` (default `30`)
- `POLICY_RAPID_REPEAT_DISTANCE_KM` (default `80`)

Incident email sender behavior:

- `EMAIL_FROM` is no longer used.
- Admin-triggered incident emails use the logged-in admin profile email from DB as the attempted sender.
- If SMTP provider rejects sender mismatch (common with Gmail SMTP), delivery retries once with `SMTP_USER` as `from` and the admin email as `reply-to`.
- Communication + timeline logs include attempted sender, used sender, reply-to, delivery status, provider message id, and error details.
- If `SMTP_HOST` is omitted, host auto-inference is attempted from `SMTP_USER` for common providers (`gmail.com`, `outlook/hotmail/live`, `yahoo`, `icloud`, `zoho`).
- Real delivery still requires valid SMTP credentials (`SMTP_USER` + `SMTP_PASS`). For Gmail, use an App Password and enable SMTP access on the account.
- Backward-compatible env aliases are also supported: `EMAIL_HOST/EMAIL_PORT/EMAIL_SECURE/EMAIL_USER/EMAIL_PASS` and `MAIL_HOST/MAIL_PORT/MAIL_SECURE/MAIL_USER/MAIL_PASS`.

Frontend/root:

- `VITE_API_URL` (defaults to `/api`)

Vite dev proxy (`vite.config.ts`):

- Frontend runs on `8080`.
- `/api` proxies to `http://localhost:4000` unless `VITE_API_PROXY_TARGET` is set in shell environment.

## 11. Seed Data and Demo Credentials

Seed command:

```bash
npm --prefix backend run prisma:seed
```

Seeded users (`backend/prisma/seed.ts`):

- `admin@authenticqr.com` / `admin123` (super admin)
- `admin@acme.com` / `licensee123` (licensee admin)
- `admin@beta.com` / `licensee123` (licensee admin)
- `factory1@acme.com` / `manufacturer123` (manufacturer)
- `factory2@acme.com` / `manufacturer123` (manufacturer)

Do not use these credentials in production.

## 12. Common Workflows

Super Admin:

1. Create/manage licensees.
2. Allocate QR ranges to licensees.
3. Approve/reject QR requests.
4. Monitor global analytics, trace, policy alerts.
5. Block compromised QRs/batches.

Licensee Admin:

1. Manage manufacturers in own tenant.
2. Create/assign batches.
3. Monitor batch status + scan activity.
4. Review audit logs and anomaly alerts.

Manufacturer:

1. View assigned batches.
2. Create print job with quantity/range.
3. Issue one-time short-lived direct-print render tokens.
4. Confirm print (or auto-confirm when all direct-print tokens are consumed).
5. Track scans for own batches.

Consumer/public:

1. Scan tokenized URL (`/scan?t=...`) or verify plain code (`/verify/:code`).
2. Receive authenticity result + warning context where applicable.

## 13. Scripts and Commands

Frontend (root):

```bash
npm run dev
npm run build
npm run test
npm run lint
```

Backend:

```bash
npm --prefix backend run dev
npm --prefix backend run build
npm --prefix backend run test
npm --prefix backend run prisma:generate
npm --prefix backend run prisma:migrate
npm --prefix backend run prisma:seed
```

Useful backend scripts:

```bash
PGCONNECT_TIMEOUT=5 bash backend/scripts/check-db.sh
node backend/scripts/create-super-admin.js <email> <password> [name]
npx tsx backend/scripts/cleanup-demo.ts
```

## 14. Troubleshooting

### Login/API returns 503 (like `/api/auth/login` -> 503)

This usually means backend is running but cannot reach PostgreSQL.

Check in order:

1. Backend process is up:

```bash
curl -i http://localhost:4000/health
```

2. Database reachability endpoint:

```bash
curl -i http://localhost:4000/health/db
```

3. Direct DB check script:

```bash
PGCONNECT_TIMEOUT=5 bash backend/scripts/check-db.sh
```

4. Validate `DATABASE_URL` host/port/db/user/password.
5. If using AWS RDS, confirm:
   - DB status is `Available`.
   - Security Group allows inbound `5432` from your app host.
   - NACL/route table permits traffic.
   - SSL settings in `DATABASE_URL` match server requirements.
   - CA path is valid when using cert pinning (example cert: `backend/certs/global-bundle.pem`).
6. Confirm backend port matches frontend proxy target (`4000` by default).

### CORS errors

- Add frontend origin(s) to `CORS_ORIGIN`.
- Multiple values are supported as comma-separated list.

### Prisma issues after schema changes

```bash
npm --prefix backend run prisma:generate
npm --prefix backend run prisma:migrate
npm --prefix backend run build
```

### Dashboard realtime not updating

- Confirm `GET /api/events/dashboard?token=...` is reachable.
- Ensure token is valid.
- UI falls back to polling when SSE disconnects.

## 15. Docker Deployment

Build and run:

```bash
docker compose build
docker compose up -d
```

Run migrations in container:

```bash
docker compose run --rm backend npx prisma migrate deploy
```

Access:

- Frontend at `http://localhost:${FRONTEND_PORT:-80}`
- API via frontend reverse proxy at `/api/*`

Important compose note:

- Backend container is not host-published by default (`expose` only).
- Host can access API through frontend (`/api`) unless you explicitly add a backend `ports` mapping.

## 16. Testing and Verification

Backend tests (`backend/package.json`):

- Builds TS output.
- Runs `backend/tests/qrService.test.js`.
- Runs `backend/tests/scanSecurity.test.js`.

Frontend tests:

- `vitest` via `npm run test`.

Recommended smoke checks after changes:

1. `npm --prefix backend run build`
2. `npm --prefix backend run test`
3. `npm run build`
4. `npm run test`
5. Login + dashboard load + scan flow sanity check in UI.

## 17. Operational and Security Checklist (Production)

- Rotate all secrets (DB, JWT, signing keys).
- Use Ed25519 keys; keep private key in secret manager.
- Restrict CORS to real frontend domains only.
- Enforce TLS end-to-end.
- Lock down DB network exposure.
- Run migrations via CI/CD (`prisma migrate deploy`).
- Monitor `/health` and `/health/db`.
- Centralize logs and alerting.
- Validate backup/restore process.
- Review RBAC and tenant isolation in staging before release.

## 18. Key Files to Understand First

If you are onboarding and want the fastest deep understanding, read these in order:

1. `backend/src/routes/index.ts` (full API surface + guards)
2. `backend/prisma/schema.prisma` (data model, enums, relations)
3. `backend/src/controllers/scanController.ts` (scan security path)
4. `backend/src/services/policyEngineService.ts` (anomaly detection + auto-block)
5. `backend/src/services/analyticsService.ts` (SLA and risk scoring)
6. `backend/src/services/immutableAuditExportService.ts` (audit package)
7. `src/pages/Dashboard.tsx` (main UX entry point)
8. `src/pages/QRTracking.tsx` (ops tracking UX)
9. `src/lib/api-client.ts` (frontend API contract)
10. `docs/USER_MANUAL.md` (operator SOP)

## 19. Connectivity and QR ZIP Download Speed Guide

The print-pack ZIP endpoints are optimized for high volumes using:

- Streamed ZIP output (no giant in-memory ZIP buffer before sending).
- Chunked DB reads (`code` cursor pagination).
- Concurrent PNG rendering with adaptive profiles.
- Adaptive compression/size profiles:
  - `standard`: < `100000` QRs (default 768px PNG, zip level 6)
  - `high`: >= `100000` QRs (default 640px PNG, zip level 8)
  - `ultra`: >= `1000000` QRs (default 512px PNG, zip level 9)

### Download speed expectations

Approximate transfer formula:

- `seconds ~= (zip_size_MB * 8) / link_Mbps`

Example transfer times for a 1 GB ZIP:

- 20 Mbps: ~6.8 minutes
- 50 Mbps: ~2.7 minutes
- 100 Mbps: ~1.4 minutes
- 300 Mbps: ~27 seconds

Local machine (`localhost`) note:

- Network bandwidth is usually not the bottleneck.
- Throughput is mostly limited by CPU (PNG generation/compression) and disk write speed in the browser download path.

## 20. Help Assistant (Free)

AuthenticQR now includes a fully local, no-cost in-app assistant:

- Floating widget: **Help** button at bottom-right on all pages.
- Assistant panel: local KB search + role-aware suggestions.
- No paid AI APIs required (no OpenAI/Gemini keys).

### Open documentation pages

- Help hub: `/help`
- Role pages:
  - `/help/superadmin` (alias of `/help/super-admin`)
  - `/help/licensee` (alias of `/help/licensee-admin`)
  - `/help/manufacturer`
  - `/help/customer`

### Local knowledge base source

- File: `src/help/kb.ts`
- Each entry includes:
  - `id`
  - `role` (`all|super_admin|licensee|manufacturer|customer`)
  - `keywords[]`
  - `title`
  - `answer` (markdown)
  - `linksToRoutes[]`

Search/scoring logic lives in `src/help/kb-search.ts`.

### Rule-based scan explanation (customer verify page)

- `Verified Again`: friendly repeat-verification messaging with “Show details”.
- `Possible Duplicate`: reasons generated from scan signals (multi-device, burst scans, location/country drift) with clear action CTAs.
- Fraud report form auto-attaches scan metadata and stores incident report in DB.

### Screenshots for docs/help pages

- Store docs images under `public/docs/`.
- Help pages automatically check image availability and only show capture reminders for missing files.

Optional automated capture:

```bash
npm run docs:screenshots
```

Supported environment variables for capture script:

- `DOCS_BASE_URL`
- `DOCS_SUPERADMIN_EMAIL`, `DOCS_SUPERADMIN_PASSWORD`
- `DOCS_LICENSEE_ADMIN_EMAIL`, `DOCS_LICENSEE_ADMIN_PASSWORD`
- `DOCS_MANUFACTURER_EMAIL`, `DOCS_MANUFACTURER_PASSWORD`
- `DOCS_QR_CODE`

Generate consolidated DOCX manual from markdown:

```bash
npm run docs:docx
```

Generated outputs (current):

- `docs/USER_MANUAL_v2.docx`
- `docs/SUPER_ADMIN_GUIDE.docx`
- `docs/LICENSEE_ADMIN_GUIDE.docx`
- `docs/MANUFACTURER_GUIDE.docx`
- `docs/CUSTOMER_VERIFICATION_GUIDE.docx`

Optional legacy generator:

```bash
npm run docs:docx:roles
```

---

Source documentation in repo:

- `docs/USER_MANUAL.md`
- `/help/*` pages in the web app
