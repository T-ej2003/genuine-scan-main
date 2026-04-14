# Genuine Scan (MSCQR)

Production-grade, multi-tenant QR issuance, controlled-print, verification, anomaly-detection, and auditability platform.

## Delivery Standards

- Feature-first frontend domains now live under `src/features/` for `batches`, `printing`, `verify`, `incidents`, `dashboard`, and `layout`.
- Route files under `src/pages/` remain as thin wrappers so page imports stay stable while domain logic moves behind feature modules.
- Server state should be loaded through React Query hooks such as `useDashboardStats`, `useBatches`, `usePrintJobs`, and `useIncident`, not ad-hoc page fetches.
- Generated build artifacts like `dist/` and `backend/dist/` are not source and should stay out of commits.
- Incremental TypeScript tightening lives in `tsconfig.incremental-strict.json`; use it for newly refactored modules before broadening repo-wide strictness.
- Release metadata is propagated through the frontend build, backend health/version payloads, support diagnostics, and optional Sentry telemetry so one deploy maps to one release tag.
- Critical path smoke coverage lives in `e2e/enterprise-smoke.spec.ts` and targets login, batch allocation, print job start, public verify reporting, and support follow-up.

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

See [docs/DEV_ENV_SETUP.md](docs/DEV_ENV_SETUP.md) for required toolchain installation.

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

## 3. Repository Layout

```text
.
├── src/                              # Frontend React app
│   ├── features/                     # Feature-first UI/data domains
│   ├── pages/                        # Thin route wrappers
│   ├── components/                   # Shared and feature UI
│   ├── contexts/                     # Auth/session context
│   └── lib/api-client.ts             # Stable API client entrypoint
├── e2e/                              # Playwright smoke coverage for critical workflows
├── shared/contracts/                 # Shared DTO/type boundaries
├── backend/
│   ├── src/
│   │   ├── controllers/              # HTTP handlers
│   │   ├── observability/            # Release metadata, request metrics, Sentry hooks
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
│   ├── SUPER_ADMIN_GUIDE.md          # Super Admin manual source
│   ├── LICENSEE_ADMIN_GUIDE.md       # Licensee Admin manual source
│   ├── MANUFACTURER_GUIDE.md         # Manufacturer manual source
│   ├── CUSTOMER_VERIFICATION_GUIDE.md # Customer manual source
├── DOCUMENTS/                        # Generated DOCX copies of repo markdown
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

- `/login`, `/accept-invite`, `/forgot-password`, `/reset-password`: public auth flows
- `/dashboard`: all authenticated roles
- `/licensees`: super admin
- `/qr-requests`: super admin, licensee admin
- `/batches`: super admin, licensee admin, manufacturer
- `/printer-diagnostics`: manufacturer
- `/manufacturers`: super admin, licensee admin
- `/qr-tracking`: super admin, licensee admin, manufacturer
- `/audit-logs`: super admin, licensee admin, manufacturer
- `/support`: super admin
- `/ir`, `/ir/incidents/:id`: super admin
- `/incidents`: super admin
- `/governance`: super admin
- `/account`: all authenticated roles
- `/qr-codes`: authenticated redirect to `/qr-tracking`
- `/product-batches`: redirect to `/batches`
- `/verify`, `/verify/:code`, `/scan`, `/help/*`: public

RBAC middleware (`backend/src/middleware/rbac.ts`):

- `requireSuperAdmin`
- `requireLicenseeAdmin`
- `requireManufacturer`
- `requireAnyAdmin`
- `requireAuditViewer`
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
4. `PRINTED` when direct-print render is resolved/confirmed.
5. `REDEEMED` on first successful scan.
6. `BLOCKED` by admin action or policy engine.

## 7. Security Model

Code-level assessment: strong server-governed QR controls with important limits called out explicitly below.

Implemented protections:

- Signed QR tokens (Ed25519 preferred; HMAC fallback).
- Token hash + nonce binding in DB (`tokenHash`, `tokenNonce`).
- Licensee/batch/manufacturer binding checks at scan time.
- Customer-ready lifecycle gating plus replay-aware downgrade semantics.
- IP-based scan rate limiting (`SCAN_RATE_LIMIT_PER_MIN`).
- Audit logs for sensitive transitions.
- Policy engine for anomaly-triggered auto-block.

Token signing behavior (`backend/src/services/qrTokenService.ts`):

- Preferred mode: `QR_SIGN_PRIVATE_KEY` + `QR_SIGN_PUBLIC_KEY`.
- Production hardening can require Ed25519 with `QR_SIGN_ENFORCE_ED25519_IN_PRODUCTION=true`.
- `QR_SIGN_ACTIVE_KEY_VERSION` pins the signing key version that MSCQR records in verification evidence and trust metrics.
- `QR_SIGN_PROVIDER=managed` plus `QR_SIGN_KMS_KEY_REF` / `QR_SIGN_KMS_VERIFY_KEY_REF` select a future managed signer bridge, but the bridge must actually be registered by the deployed backend build. MSCQR does not pretend managed signing exists when only the refs are present.
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

- `POST /manufacturer/printer-agent/heartbeat`
- `GET /manufacturer/printer-agent/status`
- `POST /manufacturer/print-jobs`
- `POST /manufacturer/print-jobs/:id/direct-print/tokens`
- `POST /manufacturer/print-jobs/:id/direct-print/resolve`
- `POST /manufacturer/print-jobs/:id/confirm`
- `GET /manufacturer/print-jobs/:id/pack?token=...` (disabled by design; returns `410`)

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
- `QR_SIGN_ACTIVE_KEY_VERSION`: explicit signing key version for evidence, observability, and future rotation hygiene.
- `QR_SIGN_PROVIDER`: `env` (default) or `managed`; `managed` fails closed unless the runtime registers a managed signer bridge.

Fallback signing option:

- `QR_SIGN_HMAC_SECRET`: used only if Ed25519 keys are not set.

Optional:

- `PORT` (default `4000`)
- `NODE_ENV` (`development`/`production`)
- `ALLOW_BREAK_GLASS_QR_GENERATE` (default `false`; keep disabled in production so customer-verifiable labels stay on the managed print path)
- `QR_SIGN_ENFORCE_ED25519_IN_PRODUCTION` (default `true`; refuse production startup if QR signing falls back to HMAC)
- `QR_SIGN_KMS_KEY_REF` / `QR_SIGN_KMS_VERIFY_KEY_REF` (managed signer integration points; inert unless `QR_SIGN_PROVIDER=managed` and a bridge is registered)
- `VERIFY_REPLAY_HARDENING_ENABLED` (default `true`; downgrade changed-context signed-label reuse to review-required semantics)
- `VERIFY_REPLAY_RAPID_REUSE_THRESHOLD_10M` (default `3`; repeat threshold for rapid changed-context signed-label reuse)
- `VERIFY_REPLAY_IP_VELOCITY_THRESHOLD_10M` (default `2`; IP velocity threshold for replay review escalation)
- `VERIFY_REPLAY_CHANGED_CONTEXT_LOOKBACK_MINUTES` (default `15`; recent-window check for changed-context signed-label reuse)
- `VERIFY_SESSION_PROOF_BINDING_REQUIRED` (default `true`; require a short-lived proof-bound session token before revealing signed-scan results)
- `VERIFY_SESSION_PROOF_TTL_MINUTES` (default `30`; lifespan of the proof-bound verification session token)
- `VERIFY_REQUIRE_GOVERNED_PRINT_PROVENANCE` (default `true`; restrict strongest customer-verifiable semantics to governed print + confirmed readiness)
- `VERIFY_OBSERVABILITY_LOGGING_ENABLED` (default `true`; emit privacy-minimized structured `verification_trust_metric` events for replay, provenance, challenge, and signing monitoring)
- `JWT_EXPIRES_IN` (default `7d`)
- `CORS_ORIGIN` (comma-separated origins)
- `PUBLIC_SCAN_WEB_BASE_URL`
- `PUBLIC_VERIFY_WEB_BASE_URL`
- `SCAN_RATE_LIMIT_PER_MIN` (default `60`)
- `QR_TOKEN_EXP_DAYS` (default `3650`)
- `PRINT_JOB_LOCK_TTL_MINUTES` (default `45`; validity window for direct-print job lock token)
- `DIRECT_PRINT_TOKEN_TTL_SECONDS` (default `90`; one-time render token lifespan)
- `DIRECT_PRINT_MAX_BATCH` (default `250`; max one-time render tokens per issuance call)
- `PRINT_AGENT_HEARTBEAT_TTL_SECONDS` (default `35`; printer heartbeat freshness gate for manufacturer print-job creation)
- `NOTIFICATION_REALTIME_ALERTS_EMAIL_ENABLED` (default `true`; mirror web notifications to admin email inboxes in real time)
- `NOTIFICATION_REALTIME_ALERT_EMAIL_SUBJECT_PREFIX` (default `[MSCQR Real-time Alert]`)
- `QR_ZIP_HIGH_VOLUME_THRESHOLD` (default `100000`)
- `QR_ZIP_ULTRA_VOLUME_THRESHOLD` (default `1000000`)
- `QR_ZIP_STANDARD_LEVEL` (default `6`)
- `QR_ZIP_HIGH_LEVEL` (default `8`)

Operational monitoring before premium rollout:

- Proof-tier mix: signed-label vs manual record-check traffic.
- Replay review-required rate: how often changed-context signed reuse is downgraded.
- Same-context vs changed-context signed repeats: expected customer reuse versus replay-like spread.
- Limited-provenance rate: governed-print-confirmed labels versus legacy or restricted provenance decisions.
- Break-glass issuance usage: any direct generation event should be rare, explained, and auditable.
- Challenge-required frequency and completion rate: identity-based review completion versus abandoned suspicious checks.
- Signing profile health: active key version, provider mode, and any legacy HMAC fallback warnings.
- Observability catalog, metrics mapping, and alert templates live under [docs/observability/](docs/observability/).
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

### Admin MFA cadence controls

- `ADMIN_LOGIN_MFA_CYCLE_DAYS` (default `28`): max age of previous admin MFA success allowed for new password sign-ins before a fresh MFA challenge is required.
- `ADMIN_STEP_UP_WINDOW_MINUTES` (default `30`): freshness window for sensitive admin actions after login.
- `AUTH_PASSWORD_STEP_UP_WINDOW_MINUTES` (default `30`): freshness window for sensitive password step-up on non-admin roles.
- `AUTH_MFA_TOTP_WINDOW` (default `1`): accepted TOTP drift window in 30-second steps (`1` = +/-30 seconds).

Recommended production posture:

- Keep `ADMIN_LOGIN_MFA_CYCLE_DAYS=28` for predictable sign-in UX.
- Keep `ADMIN_STEP_UP_WINDOW_MINUTES` short (for example `30`) to preserve high-risk action protection.

## 11. Seed Data and Demo Credentials

Seed command:

```bash
npm --prefix backend run prisma:seed
```

Seeded users (`backend/prisma/seed.ts`):

- `admin@mscqr.com` / `admin123` (super admin)
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
2. Receive the MSCQR verification result with warning context where applicable.

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

Local-only shortcut with dev-safe object storage defaults:

```bash
docker compose -f docker-compose.yml -f docker-compose.local.yml up -d --build
```

Production note:
- `docker-compose.yml` is now fail-closed for object storage credentials. Set `MINIO_ROOT_USER`, `MINIO_ROOT_PASSWORD`, `OBJECT_STORAGE_ACCESS_KEY`, and `OBJECT_STORAGE_SECRET_KEY` explicitly in runtime env.

Run migrations in container:

```bash
docker compose run --rm backend npx prisma migrate deploy
```

Access:

- Frontend at `http://localhost:${FRONTEND_PORT:-80}`
- API via frontend reverse proxy at `/api/*`

HTTPS for production (`mscqr.com` / `www.mscqr.com`):

- The frontend container already supports HTTP-first boot and automatic HTTPS cutover when Let's Encrypt certs exist in `deploy/certbot/conf`.
- Issue a certificate with `sh deploy/certbot/issue-letsencrypt.sh`
- Dry-run renewal with `MSCQR_CERTBOT_DRY_RUN=true sh deploy/certbot/renew-letsencrypt.sh`
- Full EC2/DNS instructions live in `docs/AWS_EC2_DEPLOY_MSCQR.md`

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
6. `npm run verify:release`

Historical provenance maintenance:

- Dry-run legacy provenance review: `npm --prefix backend run data:backfill-qr-provenance -- --limit 500 --json`
- Execute only after review: `npm --prefix backend run data:backfill-qr-provenance -- --execute --limit 500`
- Unknown historical labels stay unknown unless direct governed-print evidence exists.

## 17. Operational and Security Checklist (Production)

- Rotate all secrets (DB, JWT, signing keys).
- Use Ed25519 keys; keep private key in secret manager.
- If `QR_SIGN_PROVIDER=managed`, verify the managed signer bridge is present before rollout; refs alone are not enough.
- Restrict CORS to real frontend domains only.
- Enforce TLS end-to-end.
- Lock down DB network exposure.
- Run migrations via CI/CD (`prisma migrate deploy`).
- Monitor `/health` and `/health/db`.
- Centralize logs and alerting.
- Validate backup/restore process.
- Review RBAC and tenant isolation in staging before release.
- Review [docs/observability/VERIFICATION_TRUST_EVENT_CATALOG.md](docs/observability/VERIFICATION_TRUST_EVENT_CATALOG.md) and [docs/PREMIUM_LAUNCH_INCIDENT_RUNBOOK.md](docs/PREMIUM_LAUNCH_INCIDENT_RUNBOOK.md) before premium launch.

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
10. `docs/SUPER_ADMIN_GUIDE.md` (role-accurate admin SOP)

## 19. Connectivity and Export Throughput Notes

Manufacturer printing uses secure direct-print only:

- One-time short-lived render tokens.
- Authenticated print lock token.
- No downloadable manufacturer ZIP/PNG print packs.

Admin bulk export ZIP endpoints remain optimized for high volumes using:

- Streamed ZIP output (no giant in-memory ZIP buffer before sending).
- Chunked DB reads (`code` cursor pagination).
- Concurrent PNG rendering with adaptive profiles.
- Adaptive compression/size profiles:
  - `standard`: < `100000` QRs (default 768px PNG, zip level 6)
  - `high`: >= `100000` QRs (default 640px PNG, zip level 8)
  - `ultra`: >= `1000000` QRs (default 512px PNG, zip level 9)

### Admin export speed expectations

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

MSCQR now includes a fully local, no-cost in-app assistant:

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

- `MSCQR confirmed this code again`: repeat-verification messaging that keeps proof and scan-history details visible.
- `Review required`: unusual scan signals (multi-device, burst scans, location/country drift) with clear action CTAs.
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

Generate DOCX copies for every markdown file in the repo:

```bash
npm run docs:docx
```

Generated outputs are written under `DOCUMENTS/` using the same relative paths as the source markdown.

Examples:

- `DOCUMENTS/README.docx`
- `DOCUMENTS/backend/README.docx`
- `DOCUMENTS/docs/SUPER_ADMIN_GUIDE.docx`
- `DOCUMENTS/docs/LICENSEE_ADMIN_GUIDE.docx`
- `DOCUMENTS/docs/MANUFACTURER_GUIDE.docx`
- `DOCUMENTS/docs/CUSTOMER_VERIFICATION_GUIDE.docx`

---

Source documentation in repo:

- `docs/SUPER_ADMIN_GUIDE.md`
- `docs/LICENSEE_ADMIN_GUIDE.md`
- `docs/MANUFACTURER_GUIDE.md`
- `docs/CUSTOMER_VERIFICATION_GUIDE.md`
- `/help/*` pages in the web app
