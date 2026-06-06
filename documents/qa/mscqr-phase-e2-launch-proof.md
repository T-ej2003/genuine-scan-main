# MSCQR Phase E2 Launch Proof

Date: 2026-06-06
Branch: `codex/phase-e2-role-tenant-idor-printer`
Local SHA: `a1d26469272e1b3bb1a624bee348248a9c0e917f`

## Production read-only health

Live-safe production checks were run without credentials and without mutation.

| Check | Result |
|---|---|
| `GET https://www.mscqr.com/api/health/live` | `200` JSON |
| `release.gitSha` | `a1d26469272e1b3bb1a624bee348248a9c0e917f` |
| `release.shortGitSha` | `a1d26469272e` |
| `GET https://www.mscqr.com/api/health/ready` | `200` JSON, `status: ready` |
| Database readiness | configured and ready |
| Redis readiness | configured and ready |
| Object storage readiness | configured and ready |
| `GET https://www.mscqr.com/api/auth/me` logged out | `401` JSON, not `502` HTML |

The deployed SHA matches the current branch base/main SHA inspected during Phase 0.
No source-map/local-workspace-path probe was automated in this phase because no deployed asset manifest URL was required for the auth/health proof; keep that check in the browser asset smoke before final launch.

## Phase E2 proof added

- DB-backed role/tenant/IDOR test: `backend/tests/phaseE2RoleTenantIdor.test.js`
- UI role visibility smoke: `e2e/phase-e2-role-visibility.spec.ts`
- Route-risk matrix: `documents/qa/mscqr-phase-e2-role-tenant-idor-route-matrix.md`
- Prisma checksum sign-off checklist: `documents/qa/mscqr-phase-e2-prisma-checksum-signoff.md`
- Enterprise auth smoke sign-off: `documents/qa/mscqr-phase-e2-enterprise-auth-smoke.md`
- SMTP smoke sign-off: `documents/qa/mscqr-phase-e2-smtp-smoke-signoff.md`

## Confirmed bug fixed

Support issue report listing was scoped to the reporter for non-platform users but returned raw rows. Phase E2 now redacts internal notes and delivery-error fields from non-platform support report responses while preserving platform visibility.

## Disabled printer route sign-off

Browser-mediated print pack download and direct-print render token flows remain disabled with safe `410` JSON. Phase E2 proves safe disabled behavior and no token/tenant marker leakage. Positive printer artifact proof remains blocked until the business intentionally re-enables artifact downloads or provides a staging connector/printer proof path.

## Remaining launch blockers

| Blocker | Status | Reason |
|---|---|---|
| Staging/prod Prisma checksum audit | Yellow | Awaiting read-only `_prisma_migrations` evidence from staging/prod. |
| Real deployed enterprise auth smoke | Yellow | Awaiting staging-owned launch-test credentials and unskipped Playwright run. |
| SMTP smoke and inbox proof | Yellow | Awaiting staging SMTP credentials and inbox/provider proof. |
| Printer positive artifact proof | Yellow | Artifact/download route intentionally disabled with `410`; enabling requires additional scoped positive tests. |
| Incident SLA/timeline/handoff foundation | Mostly Green | Schema/service foundation exists through `IncidentHandoff`, SLA fields, and support workflow artifacts; operational drill evidence still recommended. |

## CTO recommendations

- Keep required launch gates fail-closed only in staging/release-candidate contexts; keep local dev safe-skippable.
- Before enabling printer artifacts, add ZIP/PDF content parsing, single-use token expiry, connector claim, and filename no-leak tests.
- Add a recurring staging job that captures redacted auth, SMTP, checksum, and health evidence by release SHA.
- Expand support/incident tenant tests once customer-facing ticket tracking gains authenticated tenant views.
