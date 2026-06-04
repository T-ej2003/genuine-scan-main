# MSCQR Pre-Commit Safety Audit

Date: 2026-06-03

## Scope

This audit reviewed the current uncommitted P0/P1/P2/P3/P3.5 auth-security, migration-gate, and QA automation patch before commit. The goal was to identify product-code regressions, generated artifacts, unsafe migration behavior, and security-test weakening risk.

## Files Inspected

- `git status --short`
- `git diff --stat`
- `backend/src/index.ts`
- `backend/src/app.ts`
- `src/pages/QRCodes.tsx`
- `src/App.tsx`
- `src/app/route-metadata.ts`
- `src/lib/api/internal-client-printing.ts`
- `src/lib/api/internal-client-core.ts`
- `src/pages/Index.tsx`
- `.github/workflows/auth-security-tests.yml`
- `docker-compose.p2-test.yml`
- `backend/prisma/migrations/20260304113000_add_direct_print_render_tokens/migration.sql`
- `backend/prisma/migrations/20260603120000_repair_batch_print_pack_schema/migration.sql`
- `gitleaks-report.json`
- References to `QRCodes`, `/qr-codes`, `internal-client-printing`, and deleted printer client methods.

## Suspicious Changes Reviewed

### Backend App Factory

`backend/src/index.ts` was heavily reduced because the Express app creation moved into `backend/src/app.ts`. The reviewed app factory preserves the production middleware and route surface:

- CORS and body parsers.
- Security headers and JSON sanitization.
- Request telemetry.
- Health/readiness endpoints.
- `/api` no-store behavior.
- Public, auth, organization, product, QR, print, support, governance, export, audit, and admin route mounting.
- 404 and error handling.

Production startup behavior remains in `backend/src/index.ts`, including server listen behavior and background worker startup. This is a production-safe testability refactor, pending verification commands below.

### `src/pages/QRCodes.tsx` Deletion

The deleted page is no longer imported by name. Current QR management surfaces are split across:

- `/code-requests`
- `/batches`
- `/scan-activity`
- `/printer-setup`
- public `/verify` and `/scan`

The deletion is safe only with a legacy route contract preserved. This audit restored `/qr-codes` as a protected redirect to `/scan-activity`, restored the `/qr-codes` route alias, and restored private noindex SEO handling for the legacy path.

### `src/lib/api/internal-client-printing.ts` Deletions

Deleted client functions such as direct render-token and direct printer-job helpers are not referenced by current frontend code outside the client module. Backend direct-print routes remain mounted and are covered by auth/security tests, with unsupported direct browser printing returning safe disabled responses where applicable.

Printer workflow coverage now focuses on:

- QR request print job creation.
- Print job relinking/abandoning.
- Test label flow.
- Printer status updates.
- Backend direct API authorization and content isolation tests.

### Homepage Rewrite

`src/pages/Index.tsx` was rewritten as part of public trust/marketing hardening. It still exposes public access paths for request access and product verification. This is larger product-surface churn than the auth-security test harness changes and should be reviewed as a product/design change if the team wants a smaller milestone commit.

### Generated Scanner Artifact

`gitleaks-report.json` was an untracked generated scanner report containing redacted finding metadata and source links. It should not be committed. This audit removed it from the working tree and added `gitleaks-report.json` to `.gitignore`.

## Files Fixed By This Audit

- `.gitignore`: added `gitleaks-report.json`.
- `src/App.tsx`: restored protected `/qr-codes` legacy redirect to `/scan-activity`.
- `src/app/route-metadata.ts`: restored `/qr-codes` as an alias for scan activity.
- `src/components/seo/SeoController.tsx`: restored `/qr-codes` as a private noindex path.
- `gitleaks-report.json`: removed generated report from the working tree.

## Migration Safety

The P3.5 migration gate correctly documents that historical migration `20260304113000_add_direct_print_render_tokens` was edited to repair fresh replay. Fresh disposable DB replay now passes, but shared/staging/prod databases that already applied the old migration may have a Prisma checksum mismatch. The checksum audit runbook must be followed before deployment to any shared environment.

## Reference Checks

To be rerun after audit fixes:

- `rg -n "QRCodes" src backend e2e documents package.json || true`
- `rg -n "internal-client-printing|requestDirectPrintTokens|resolveDirectPrintToken|confirmDirectPrintItem|reportDirectPrintFailure|confirmPrintJob|printWithLocalAgent" src backend e2e documents package.json || true`
- `rg -n "path=\"/qr-codes\"|/qr-codes" src/App.tsx src/app/route-metadata.ts src/components/seo/SeoController.tsx documents/qa || true`

## Verification Commands

To be run after audit fixes:

- `npm run test:p3:migration-gate`
- `npm run test:p3:auth-security-db`
- `npm run test:p3:fullstack`
- `npm test`
- `npm run typecheck`
- `npm run build`
- Targeted lint on changed audit files where feasible.

## Test Results

- `npm run test:p3:migration-gate`: passed with disposable Postgres; Prisma schema validated, all 39 migrations replayed with `prisma migrate deploy`, and migration drift gate passed.
- `npm run test:p3:auth-security-db`: passed unskipped with disposable Postgres and DB-backed authorization/content tests.
- `npm run test:p3:fullstack`: passed after audit fixes. This reran DB-backed auth/security proof, JSON email capture, P1 API authz, P1 signed scan-token tests, P0 authz, frontend typecheck, Vitest, and production build.
- `npm test`: passed standalone, 43 files / 127 tests. Vitest emitted repeated inherited `--localstorage-file` warnings.
- `npm run typecheck`: passed standalone before the backend startup lint fix, and passed again inside `test:p3:fullstack` after the fix.
- `npm run build`: passed standalone before the backend startup lint fix, and passed again inside `test:p3:fullstack` after the fix.
- Targeted lint on changed code files passed after replacing two `catch (error: any)` startup handlers with `unknown`-safe handling.

The local process `PATH` was missing `/bin` and `/usr/bin`; verification commands were rerun with a local PATH prefix so npm could spawn `/bin/sh`. This is an execution-environment issue, not a repo failure.

## Commit Recommendation

Safe to commit: yes, after this audit's narrow fixes.

Recommended commit plan:

1. Migration replay and CI gate hardening.
2. Backend app factory, DB harness, auth/security tests, and seed helpers.
3. Frontend E2E trust/auth/scan tests and minimal testability fixes.
4. QA documentation and runbooks.
5. Public homepage/marketing rewrite, if the team wants product-surface changes reviewed separately.

If the team requires one milestone commit, keep the commit message explicit that it includes auth-security automation, migration repair/gates, docs, and a public homepage refresh.

Recommended one-commit message if used:

`test: add full-stack auth-security gates and migration replay proof`

## Remaining Risks

- Historical migration checksum mismatch risk on any shared database that already applied the old `20260304113000_add_direct_print_render_tokens` migration.
- Real-auth E2E remains gated unless a disposable seeded backend is started with `E2E_REAL_AUTH=true`.
- Direct browser print flows are intentionally not restored; printer backend authorization/content tests are the proof path.
- The old dedicated QR inventory page is gone; `/qr-codes` is preserved as a redirect, but product owners should confirm `/scan-activity`, `/code-requests`, and `/batches` fully cover the expected QR management workflow.
- The public homepage rewrite is product-surface churn inside a security automation milestone; it passes tests/build but deserves product/design review if the milestone is split.
- Vitest emits repeated inherited `--localstorage-file` warnings; the warnings are non-fatal but should be cleaned up in a follow-up test-environment hardening pass.
