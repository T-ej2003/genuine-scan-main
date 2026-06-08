# MSCQR Printer Artifact Launch Sign-off

Date: 2026-06-08
Status: Yellow for positive printer artifact proof; Green for disabled-route no-leak posture.

## Current Route State

The browser/downloadable printer artifact paths are intentionally disabled:

- `GET /api/manufacturer/print-jobs/:id/pack` returns `410`
- `POST /api/manufacturer/print-jobs/:id/direct-print/tokens` returns `410`
- `POST /api/manufacturer/print-jobs/:id/direct-print/resolve` returns `410`
- browser direct-print confirm/fail paths return `410`

The supported launch direction is connector/certified printer claiming work directly from the server, not browser-mediated artifact download.

## Existing No-leak Proof

Automated tests assert:

- own disabled print-pack route returns safe `410`
- cross-tenant print-pack attempts are denied/no-leak
- disabled direct-print token route does not return token-like values
- lower roles cannot use manufacturer direct-print token routes
- printer-agent malformed/invalid claim does not expose job data

Relevant tests:

- `backend/tests/p2DbAuthorization.test.js`
- `backend/tests/phaseE2RoleTenantIdor.test.js`
- `backend/tests/localAgentDirectWorkerProtocol.test.js`
- `backend/tests/localAgentPrintFlow.test.js`

## Launch Sign-off

For launch with routes disabled:

- No printer artifact bytes are exposed through browser/download endpoints.
- Disabled responses must remain JSON and must not include QR codes, pack hashes, render tokens, lock tokens, tenant names, stack traces, or secrets.
- Positive artifact proof is not required unless product intends to enable downloadable/browser-mediated artifacts.

## Before Enabling Artifacts

Do not enable printer artifact routes until all of these are implemented and tested:

- positive scoped artifact download for own manufacturer/licensee only
- cross-tenant artifact denial with parsed body/header checks
- ZIP/PDF/content parsing proving no other tenant QR/batch/manufacturer markers
- filename and metadata no-leak proof
- render-token expiry proof
- render-token single-use proof
- connector/local-agent claim proof tied to manufacturer/printer registration
- audit event proof for artifact issuance/download

## Current Sign-off

- Disabled route no-leak: Green subject to DB-backed gate passing in CI.
- Positive artifact proof: Yellow, intentionally blocked by disabled route.

CTO recommendation: keep browser/downloadable printer artifacts disabled for launch unless a dedicated printer-artifact release candidate is tested end to end.
