# MSCQR P0 Backend/API Authorization Route Matrix

## Scope

This matrix records the P0 API authorization contract discovered from:

- `backend/src/routes/index.ts`
- `backend/src/routes/modules/authRoutes.ts`
- `backend/src/routes/modules/realtimeRoutes.ts`
- `backend/src/routes/modules/governanceRoutes.ts`
- `backend/src/routes/auditRoutes.ts`
- `backend/src/middleware/auth.ts`
- `backend/src/middleware/rbac.ts`
- `backend/src/middleware/tenantIsolation.ts`
- `backend/src/services/accessControlService.ts`
- `backend/src/services/manufacturerScopeService.ts`

Backend auth uses Bearer/cookie access tokens, `authenticate` / `authenticateAnySession`, role middleware, CSRF for cookie-backed mutations, recent MFA/sensitive-action middleware for high-risk mutations, and tenant/licensee/manufacturer scoping in middleware and service/controller helpers.

Roles and raw role aliases:

- Platform: `SUPER_ADMIN`, `PLATFORM_SUPER_ADMIN`
- Licensee/org admin: `LICENSEE_ADMIN`, `ORG_ADMIN`
- Manufacturer: `MANUFACTURER`, `MANUFACTURER_ADMIN`, `MANUFACTURER_USER`

## Auth And Session Endpoints

| Method | Route/path | Feature area | Allowed roles | Denied roles | Scope requirement | Unauthenticated response | Invalid-token response | Wrong-role response | Cross-tenant response | Automated coverage |
|---|---|---|---|---|---|---|---|---|---|---|
| POST | `/auth/login` | Login | Public | N/A | N/A | N/A | N/A | N/A | N/A | Existing auth/MFA tests |
| GET | `/auth/me` | Current session | Any valid platform session or MFA bootstrap | Anonymous, invalid, expired | Hydrates user/org/licensee from DB | 401 | 401 | N/A | N/A | Existing auth tests; P0 frontend invalid-session |
| POST | `/auth/refresh` | Session refresh | Cookie session with CSRF | Anonymous/invalid | Cookie + CSRF | Safe denial | Safe denial | N/A | N/A | Existing CSRF/cookie tests |
| POST | `/auth/logout` | Logout | Any valid session with CSRF/cookie or bearer path | Anonymous/invalid | Clears session | Safe denial | Safe denial | N/A | N/A | P0 frontend logout |
| GET | `/auth/sessions` | Session list | Valid authenticated user | Anonymous/invalid | User-owned sessions | 401 | 401 | N/A | N/A | Existing auth session tests |
| POST | `/auth/sessions/revoke-all` | Session revocation | Valid authenticated user | Anonymous/invalid | User-owned sessions + CSRF | 401/403 | 401 | N/A | N/A | Existing auth session tests |
| POST | `/auth/sessions/:id/revoke` | Session revocation | Valid authenticated user | Anonymous/invalid | User-owned session + CSRF | 401/403 | 401 | N/A | N/A | Existing auth session tests |
| POST | `/auth/invite` | Admin invite | `SUPER_ADMIN`, `PLATFORM_SUPER_ADMIN`, `LICENSEE_ADMIN`, `ORG_ADMIN` | Manufacturer roles, anonymous | Tenant isolation in controller/service; recent admin MFA + CSRF | 401/403 | 401 | 403 | 403/404 expected | Existing contract; pending P1 API integration |

## P0 Protected API Route Matrix

| Method | Route/path | Feature area | Allowed roles | Denied roles | Organization/licensee/manufacturer scoping requirement | Expected unauthenticated response | Expected invalid-token response | Expected wrong-role response | Expected cross-tenant response | Automated coverage |
|---|---|---|---|---|---|---|---|---|---|---|
| GET | `/internal/release` | Internal release metadata | Platform roles | Licensee/manufacturer/anonymous | Platform-only | 401 | 401 | 403 | N/A | Pending P1 |
| GET | `/security/abuse/rate-limits` | Security ops | Platform roles | Licensee/manufacturer/anonymous | Platform-only | 401 | 401 | 403 | N/A | Pending P1 |
| GET | `/security/abuse/rate-limits/alerts` | Security ops alerts | Platform roles | Licensee/manufacturer/anonymous | Platform-only | 401 | 401 | 403 | N/A | Pending P1 |
| GET | `/licensees` | Licensee/brand admin | Platform roles | Licensee/manufacturer/anonymous | Platform-only | 401 | 401 | 403 | N/A | P0 backend direct API |
| GET | `/licensees/:id` | Licensee detail | Platform roles | Licensee/manufacturer/anonymous | Platform-only | 401 | 401 | 403 | N/A | Pending P1 |
| GET | `/licensees/export` | Licensee export | Platform roles | Licensee/manufacturer/anonymous | Platform-only export | 401 | 401 | 403 | N/A | Pending P1 export |
| POST/PATCH/DELETE | `/licensees`, `/licensees/:id`, `/licensees/:id/admin-invite/resend` | Licensee mutation | Platform roles | Licensee/manufacturer/anonymous | Platform-only + recent admin MFA + CSRF for cookie auth | 401/403 | 401 | 403 | N/A | Pending P1 mutation |
| GET | `/users` | User/team management | Platform and licensee/org admin | Manufacturer/anonymous | Licensee admins scoped to own licensee; platform can scope by query | 401 | 401 | 403 | 403/404, no query | P0 backend direct API |
| POST/PATCH/DELETE | `/users`, `/users/:id` | User/team mutations | Platform and licensee/org admin | Manufacturer/anonymous | Body/query/params `licenseeId` cannot widen tenant; recent admin MFA + CSRF for cookie auth | 401/403 | 401 | 403 | 403/404, no mutation | P0 backend direct API for body tamper |
| GET | `/manufacturers` | Manufacturer management | Platform and licensee/org admin | Manufacturer/anonymous | Licensee admins see only own linked manufacturer users | 401 | 401 | 403 | 403/404 | Pending P1 |
| PATCH/DELETE | `/manufacturers/:id/*` | Manufacturer mutation | Platform and licensee/org admin | Manufacturer/anonymous | Tenant scoped; recent admin MFA + CSRF | 401/403 | 401 | 403 | 403/404, no mutation | Pending P1 |
| POST | `/qr/ranges/allocate` | QR range allocation | Platform roles | Licensee/manufacturer/anonymous | Platform-only + MFA + CSRF | 401/403 | 401 | 403 | N/A | Pending P1 |
| POST | `/qr/generate` | QR generation | Platform roles | Licensee/manufacturer/anonymous | Platform-only + MFA + CSRF | 401/403 | 401 | 403 | N/A | Pending P1 |
| POST | `/admin/licensees/:licenseeId/qr-allocate-range` | Allocate QR to licensee | Platform roles | Licensee/manufacturer/anonymous | Platform-only; target licensee in params | 401/403 | 401 | 403 | N/A | Pending P1 |
| GET | `/qr/batches` | Batch list | Platform, licensee/org admin, manufacturer roles | Anonymous/invalid | Tenant isolation; manufacturer limited to linked licensees and owned manufacturer resources in service/controller | 401 | 401 | N/A | 403/404 | P0 backend direct API |
| POST | `/qr/batches` | Batch create | Platform and licensee/org admin | Manufacturer/anonymous | Tenant isolation; recent admin MFA + CSRF | 401/403 | 401 | 403 | 403/404 | P0 backend direct API wrong role |
| GET | `/qr/batches/:id/allocation-map` | Batch allocation map | Authenticated ops roles | Anonymous/invalid | Tenant and manufacturer ownership | 401 | 401 | N/A | 403/404 | Pending P1 |
| POST/PATCH/DELETE | `/qr/batches/:id/*`, `/qr/batches/bulk-delete` | Batch mutation | Platform and licensee/org admin for most; some require platform | Manufacturer/anonymous where not allowed | Tenant scope + recent auth + CSRF | 401/403 | 401 | 403 | 403/404, no mutation | Pending P1 |
| GET | `/qr/codes` | Raw QR code list | Platform roles | Licensee/manufacturer/anonymous | Platform-only raw code visibility | 401 | 401 | 403 | N/A | Pending P1 |
| GET | `/qr/codes/export` | Raw QR export | Platform roles | Licensee/manufacturer/anonymous | Platform-only export | 401 | 401 | 403 | N/A | Existing controller surface; pending route API |
| POST | `/qr/codes/signed-links` | Signed scan links | Platform roles | Licensee/manufacturer/anonymous | Platform-only + MFA + CSRF | 401/403 | 401 | 403 | N/A | Pending P1 |
| GET | `/qr/stats` | QR stats | Authenticated platform/licensee/manufacturer | Anonymous/invalid | Tenant isolation | 401 | 401 | N/A | 403/404 | Pending P1 |
| DELETE | `/qr/codes` | Bulk QR delete | Platform and licensee/org admin | Manufacturer/anonymous | Tenant isolation + MFA + CSRF | 401/403 | 401 | 403 | 403/404, no mutation | Pending P1 |
| GET | `/manufacturer/printers`, `/manufacturer/print-jobs` | Print ops reads | Ops roles per route; manufacturer-specific routes scoped | Anonymous/invalid | Tenant isolation; manufacturer linked licensee and job ownership | 401 | 401 | 403 where route requires manufacturer | 403/404 | P0 backend direct API for print jobs |
| POST/PATCH/DELETE | `/manufacturer/printers/*`, `/manufacturer/print-jobs/*` | Print ops mutations | Manufacturer or ops roles depending route | Wrong role/anonymous | Tenant/manufacturer scoping + recent auth + CSRF | 401/403 | 401 | 403 | 403/404, no mutation | P0 backend direct API wrong role for create print job |
| GET | `/qr/requests` | QR request list | Platform and licensee/org admin | Manufacturer/anonymous | Tenant isolation | 401 | 401 | 403 | 403/404 | Pending P1 |
| POST | `/qr/requests` | QR request create | Platform and licensee/org admin | Manufacturer/anonymous | Tenant isolation + MFA + CSRF | 401/403 | 401 | 403 | 403/404 | Pending P1 |
| POST | `/qr/requests/:id/approve`, `/qr/requests/:id/reject` | QR request approval | Platform roles | Licensee/manufacturer/anonymous | Platform-only + MFA + CSRF | 401/403 | 401 | 403 | N/A | Pending P1 |
| GET | `/audit/logs`, `/audit/logs/export`, `/audit/stream` | Audit logs/history | Platform, licensee/org admin, manufacturer roles | Anonymous/invalid | Tenant isolation; manufacturer scoped to linked/owned resources where service applies | 401 | 401 | N/A | 403/404 | Existing response surface; pending P1 route API |
| GET | `/audit/fraud-reports` | Fraud report review | Platform roles | Licensee/manufacturer/anonymous | Platform-only | 401 | 401 | 403 | N/A | Pending P1 |
| POST | `/audit/fraud-reports/:id/respond` | Fraud response | Platform roles | Licensee/manufacturer/anonymous | Platform-only + MFA + CSRF | 401/403 | 401 | 403 | N/A | Pending P1 |
| GET | `/trace/timeline` | Trace timeline | Authenticated ops roles | Anonymous/invalid | Tenant isolation | 401 | 401 | N/A | 403/404 | Pending P1 |
| GET | `/analytics/batch-sla`, `/analytics/risk-scores` | Analytics | Platform and licensee/org admin | Manufacturer/anonymous | Tenant isolation | 401 | 401 | 403 | 403/404 | Pending P1 |
| GET/PATCH | `/policy/config` | Policy config | Platform and licensee/org admin | Manufacturer/anonymous | Tenant isolation; mutation requires MFA + CSRF | 401/403 | 401 | 403 | 403/404 | Pending P1 |
| GET/POST | `/policy/alerts`, `/policy/alerts/:id/ack` | Policy alerts | Platform and licensee/org admin | Manufacturer/anonymous | Tenant isolation; ack requires MFA + CSRF | 401/403 | 401 | 403 | 403/404 | Pending P1 |
| GET | `/audit/export/batches/:id/package` | Batch audit package export | Platform and licensee/org admin | Manufacturer/anonymous | Tenant isolation | 401 | 401 | 403 | 403/404 | Pending P1 export |
| GET | `/telemetry/route-transition/summary` | Route telemetry summary | Platform and licensee/org admin | Manufacturer/anonymous | Tenant isolation | 401 | 401 | 403 | 403/404 | Pending P1 |
| GET/PATCH/POST | `/support/tickets*` | Platform support tickets | Platform roles | Licensee/manufacturer/anonymous | Platform-only; mutations require MFA + CSRF | 401/403 | 401 | 403 | N/A | Pending P1 |
| GET/POST | `/support/reports*` | Support issue reports | Ops roles for reads/create; platform for responses | Wrong role/anonymous | Tenant isolation for ops reads/files; platform-only responses | 401/403 | 401 | 403 | 403/404 | Pending P1 |
| GET | `/admin/qr/scan-logs`, `/admin/qr/batch-summary`, `/admin/qr/analytics` | QR scan analytics | Ops roles | Anonymous/invalid | Tenant isolation; manufacturer linked licensee scope | 401 | 401 | N/A | 403/404 | P0 backend direct API for analytics |
| GET/PATCH/POST | `/incidents*` | Scoped incidents | Platform and licensee/org admin; manufacturer where audit viewer/ops allows route group? | Anonymous/invalid | Tenant isolation and incident ownership scope | 401/403 | 401 | 403 where route requires admin | 403/404, no mutation | Existing controller surface; pending P1 route API |
| GET/POST/PATCH | `/ir/incidents*`, `/ir/policies*`, `/ir/alerts*` | Platform incident response | Platform roles | Licensee/manufacturer/anonymous | Platform-only | 401/403 | 401 | 403 | N/A | P0 backend direct API |
| POST | `/admin/qrs/:id/block`, `/admin/batches/:id/block` | Admin block actions | Platform roles | Licensee/manufacturer/anonymous | Platform-only + MFA + CSRF for cookie auth | 401/403 | 401 | 403 | N/A | P0 backend direct API wrong role |
| PATCH | `/account/profile`, `/account/password` | Account settings | Valid authenticated user | Anonymous/invalid | Own account only + recent sensitive auth + CSRF for cookie auth | 401/403 | 401 | N/A | N/A | Pending P1 |
| GET | `/governance/feature-flags`, `/governance/evidence-retention`, `/governance/compliance/report`, `/governance/compliance/pack/jobs`, `/governance/approvals` | Governance/readiness | Platform roles | Licensee/manufacturer/anonymous | Platform-only | 401 | 401 | 403 | N/A | P0 backend direct API for feature flags |
| POST/PATCH | `/governance/*` mutation routes | Governance mutations | Platform roles | Licensee/manufacturer/anonymous | Platform-only + recent admin MFA + CSRF | 401/403 | 401 | 403 | N/A | Pending P1 mutation |

## Public QR/Customer Verification API Surface

| Method | Route/path | Feature area | Auth model | Scope/security requirement | Automated coverage |
|---|---|---|---|---|---|
| GET | `/verify/:code` | Public QR verification | Public + optional customer auth | Strict fail-closed presentation; no internal IDs/admin data | Existing public verify strict tests; P0 frontend QR states |
| POST/GET | `/verify/session/*` | Customer verification session | Customer verify cookie/bearer session for protected steps | Customer CSRF for cookie mutations; no platform auth leakage | Existing customer verification tests |
| GET/POST | `/verify/auth/*` | Customer OAuth/OTP/passkey | Public or customer verify auth depending route | Verify-specific rate limits and CSRF for cookie mutations | Existing customer auth tests |
| POST | `/verify/report-fraud`, `/fraud-report`, `/incidents/report` | Public fraud/incident report | Public | Upload signature enforcement and public rate limits | Existing public scan/verify tests; pending P1 UI |
| GET | `/scan` | Signed scan token | Public + optional customer auth | Signed token replay/rate limit protections | Existing public scan tests; pending P1 frontend signed-token |

## Coverage Notes

- New P0 backend test after this pass: `backend/tests/p0FullstackAuthorization.test.js`.
- The P0 backend test uses the repo’s existing compiled Node test style and calls representative protected API paths directly through an Express harness using real `authenticate`, RBAC middleware, and tenant isolation.
- Existing backend tests already cover lower-level controller/service security surfaces such as scoped where builders, disabled users, public verify presentation redaction, route security contracts, CSRF, cookie token protection, and security response surfaces.
- P1 should add live-router or Supertest-style integration if the repo adopts a shared test app/test DB harness.
