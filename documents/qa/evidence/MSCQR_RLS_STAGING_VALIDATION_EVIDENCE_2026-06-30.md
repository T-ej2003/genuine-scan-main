# MSCQR RLS Staging Validation Evidence - 2026-06-30

This evidence pack is for staging-only validation of the three already-wired MSCQR staged RLS runtime routes. It does not enable production RLS, does not enable global or table-level RLS, does not create Prisma migrations, does not wire additional routes, and does not change any production database.

## Scope

Validated routes:

| Route | Flag | Proof event |
| --- | --- | --- |
| `GET /api/qr/batches` | `MSCQR_STAGING_RLS_BATCHES_READ_ENABLED` | `staging_rls_batches_read_proof` |
| `GET /api/qr/batches/:id/allocation-map` | `MSCQR_STAGING_RLS_BATCH_ALLOCATION_MAP_ENABLED` | `staging_rls_batch_allocation_map_proof` |
| `GET /api/manufacturer/printers` | `MSCQR_STAGING_RLS_MANUFACTURER_PRINTERS_READ_ENABLED` | `staging_rls_manufacturer_printers_read_proof` |

Out of scope:

- Production RLS.
- Global or table-level RLS.
- Runtime wiring for additional routes.
- Prisma migrations.
- Production DB changes.
- Removing or weakening app-layer authorization.
- Public verification, scans, print dispatch, workers, exports, incidents, support, and admin global views.

## Cross-Links

- Production rollout plan: `documents/security/MSCQR_RLS_PRODUCTION_ROLLOUT_PLAN_2026-06-30.md`
- Operator runbook: `documents/ops/MSCQR_RLS_STAGING_VALIDATION_RUNBOOK_2026-06-30.md`
- Batch list staging wiring: `documents/security/MSCQR_RLS_BATCHES_READ_STAGING_WIRING_2026-06-29.md`
- Batch list staging proof: `documents/security/MSCQR_RLS_BATCHES_STAGING_PROOF_2026-06-29.md`
- Batch allocation-map staging wiring: `documents/security/MSCQR_RLS_BATCH_ALLOCATION_MAP_STAGING_WIRING_2026-06-30.md`
- Manufacturer printer staging wiring: `documents/security/MSCQR_RLS_MANUFACTURER_PRINTERS_STAGING_WIRING_2026-06-30.md`
- Machine-readable checklist: `documents/security/mscqr_rls_staging_validation_checklist.json`

## Evidence Handling Rules

- Record route templates, status codes, response shape summaries, safe row counts, timing summaries, and pass/fail only.
- Do not store raw response bodies.
- Do not store tenant IDs, user IDs, licensee IDs, manufacturer IDs, organization IDs, printer IDs, printer names, device names, batch IDs, QR codes, customer identifiers, request tokens, auth cookies, secrets, email addresses, or raw exception text.
- Use a safe staging batch ID only as an input to the run. Do not paste that ID into this evidence pack.
- If using `scripts/collect-rls-staging-validation-evidence.mjs`, store only the generated safe summary JSON.

## Run Metadata

| Field | Value |
| --- | --- |
| Staging environment name | `<staging-env>` |
| Deployed backend SHA | `<sha>` |
| Validation date/time UTC | `<timestamp>` |
| Operator | `<name/role>` |
| Rollback owner | `<name/role>` |
| Security reviewer | `<name/role>` |
| Staging base URL | `<redacted-safe-host-only>` |
| Collector summary file | `<documents/qa/evidence/rls-staging-validation-safe-summary-*.json or n/a>` |
| Baseline auth contexts used | `<licensee/manufacturer/platform-admin labels only>` |
| Safe staging batch ID source | `<ticket/reference; do not paste ID>` |

## Preflight Evidence

| Check | Evidence | Pass/Fail | Notes |
| --- | --- | --- | --- |
| Environment confirmed staging-only | `<host/env proof without secrets>` | `<pass/fail>` | |
| Current deployed SHA confirmed | `<sha>` | `<pass/fail>` | |
| All three route flags initially false/off | `<config source or deploy env summary>` | `<pass/fail>` | |
| Baseline auth/test users exist | `<role labels only>` | `<pass/fail>` | |
| Rollback owner available | `<role/name>` | `<pass/fail>` | |
| App-layer authorization still enabled | `<smoke/test reference>` | `<pass/fail>` | |
| No global/table RLS enabled | `<catalog summary if checked>` | `<pass/fail>` | |

## Validation Evidence Matrix

| Route | Flag | Baseline status | Flag-on status | Rollback status | Row count comparison | Latency comparison | Telemetry safe yes/no | Pass/Fail | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `GET /api/qr/batches` | `MSCQR_STAGING_RLS_BATCHES_READ_ENABLED` | `<status>` | `<status>` | `<status>` | `<same/expected delta>` | `<p50/p95 delta>` | `<yes/no>` | `<pass/fail>` | |
| `GET /api/qr/batches/:id/allocation-map` | `MSCQR_STAGING_RLS_BATCH_ALLOCATION_MAP_ENABLED` | `<status>` | `<status>` | `<status>` | `<same/expected delta>` | `<p50/p95 delta>` | `<yes/no>` | `<pass/fail>` | |
| `GET /api/manufacturer/printers` | `MSCQR_STAGING_RLS_MANUFACTURER_PRINTERS_READ_ENABLED` | `<status>` | `<status>` | `<status>` | `<same/expected delta>` | `<p50/p95 delta>` | `<yes/no>` | `<pass/fail>` | |
| Combined three flags | All three flags | `<status set>` | `<status set>` | `<status set>` | `<same/expected delta>` | `<p50/p95 delta>` | `<yes/no>` | `<pass/fail>` | |

## Baseline Flag-Off Evidence

| Route | Status | Shape summary | Safe count | p50 ms | p95 ms | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| `GET /api/qr/batches` | `<status>` | `<shape>` | `<count>` | `<ms>` | `<ms>` | |
| `GET /api/qr/batches/:id/allocation-map` | `<status>` | `<shape>` | `<count>` | `<ms>` | `<ms>` | |
| `GET /api/manufacturer/printers` | `<status>` | `<shape>` | `<count>` | `<ms>` | `<ms>` | |

## One-By-One Flag Evidence

| Step | Flag state | Route validated | Status | Shape/count result | Latency result | Rollback confirmed | Pass/Fail |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Batch list flag on | only `MSCQR_STAGING_RLS_BATCHES_READ_ENABLED=true` | `GET /api/qr/batches` | `<status>` | `<result>` | `<result>` | `<yes/no>` | `<pass/fail>` |
| Allocation-map flag on | only `MSCQR_STAGING_RLS_BATCH_ALLOCATION_MAP_ENABLED=true` | `GET /api/qr/batches/:id/allocation-map` | `<status>` | `<result>` | `<result>` | `<yes/no>` | `<pass/fail>` |
| Manufacturer printers flag on | only `MSCQR_STAGING_RLS_MANUFACTURER_PRINTERS_READ_ENABLED=true` | `GET /api/manufacturer/printers` | `<status>` | `<result>` | `<result>` | `<yes/no>` | `<pass/fail>` |

## Combined Flag Evidence

| Check | Result | Pass/Fail | Notes |
| --- | --- | --- | --- |
| All three flags enabled in staging only | `<result>` | `<pass/fail>` | |
| All three target routes match baseline shape/count expectations | `<result>` | `<pass/fail>` | |
| p50 latency within threshold | `<result>` | `<pass/fail>` | |
| p95 latency within threshold | `<result>` | `<pass/fail>` | |
| Proof telemetry emitted only for target routes | `<result>` | `<pass/fail>` | |
| No non-target route affected | `<result>` | `<pass/fail>` | |
| All three flags unset after validation | `<result>` | `<pass/fail>` | |
| Baseline behavior returned | `<result>` | `<pass/fail>` | |

## Telemetry Redaction Evidence

Allowed proof telemetry fields:

- `metric`
- `route`
- `flagEnabled`
- `contextClass`
- `durationMs`
- `rowCount` or another safe coarse result count
- `success`
- `failureCategory`

Forbidden telemetry fields or values:

- user IDs
- licensee IDs
- manufacturer IDs
- organization IDs
- printer IDs
- printer names or device names
- batch IDs
- QR codes
- customer identifiers
- request tokens
- secrets
- email addresses
- raw exception text

| Proof event | Allowed fields only | Forbidden identifiers absent | Generic request telemetry redacted | Pass/Fail | Notes |
| --- | --- | --- | --- | --- | --- |
| `staging_rls_batches_read_proof` | `<yes/no>` | `<yes/no>` | `<yes/no>` | `<pass/fail>` | |
| `staging_rls_batch_allocation_map_proof` | `<yes/no>` | `<yes/no>` | `<yes/no>` | `<pass/fail>` | |
| `staging_rls_manufacturer_printers_read_proof` | `<yes/no>` | `<yes/no>` | `<yes/no>` | `<pass/fail>` | |

## Latency Evidence

Use the flag-off baseline as the comparison point for each route.

| Route | Baseline p50 | Flag-on p50 | p50 delta | Baseline p95 | Flag-on p95 | p95 delta | Result |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `GET /api/qr/batches` | `<ms>` | `<ms>` | `<delta>` | `<ms>` | `<ms>` | `<delta>` | `<pass/warn/no-go>` |
| `GET /api/qr/batches/:id/allocation-map` | `<ms>` | `<ms>` | `<delta>` | `<ms>` | `<ms>` | `<delta>` | `<pass/warn/no-go>` |
| `GET /api/manufacturer/printers` | `<ms>` | `<ms>` | `<delta>` | `<ms>` | `<ms>` | `<delta>` | `<pass/warn/no-go>` |

Warning threshold: p95 above baseline by more than 25 percent or more than 250 ms, whichever is lower.

No-go threshold: p95 above baseline by more than 50 percent, p95 above baseline by more than 500 ms, any repeated timeout, or any material status-code regression.

Realistic staging row counts are required before this evidence can support any production canary discussion.

## Rollback Evidence

| Flag | Rollback action | Proof events stopped | Route returned to baseline | No global/table RLS enabled | Pass/Fail | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| `MSCQR_STAGING_RLS_BATCHES_READ_ENABLED` | unset flag and restart/redeploy if needed | `<yes/no>` | `<yes/no>` | `<yes/no>` | `<pass/fail>` | |
| `MSCQR_STAGING_RLS_BATCH_ALLOCATION_MAP_ENABLED` | unset flag and restart/redeploy if needed | `<yes/no>` | `<yes/no>` | `<yes/no>` | `<pass/fail>` | |
| `MSCQR_STAGING_RLS_MANUFACTURER_PRINTERS_READ_ENABLED` | unset flag and restart/redeploy if needed | `<yes/no>` | `<yes/no>` | `<yes/no>` | `<pass/fail>` | |
| Combined flags | unset all flags and restart/redeploy if needed | `<yes/no>` | `<yes/no>` | `<yes/no>` | `<pass/fail>` | |

## No-Go Review

| No-go condition | Observed? | Evidence reference | Action |
| --- | --- | --- | --- |
| Any non-target route affected | `<yes/no>` | `<reference>` | `<rollback/continue>` |
| Public verification affected | `<yes/no>` | `<reference>` | `<rollback/continue>` |
| Print dispatch affected | `<yes/no>` | `<reference>` | `<rollback/continue>` |
| Worker errors increase | `<yes/no>` | `<reference>` | `<rollback/continue>` |
| IDs or secrets appear in telemetry | `<yes/no>` | `<reference>` | `<rollback/continue>` |
| Unexpected 401/403/404/500 increase | `<yes/no>` | `<reference>` | `<rollback/continue>` |
| Latency materially regresses | `<yes/no>` | `<reference>` | `<rollback/continue>` |
| Flag rollback does not restore baseline | `<yes/no>` | `<reference>` | `<rollback/continue>` |

## Final Signoff

| Role | Decision | Name | Date | Notes |
| --- | --- | --- | --- | --- |
| Rollout owner | `<pass/fail>` | `<name>` | `<date>` | |
| Rollback owner | `<pass/fail>` | `<name>` | `<date>` | |
| Security reviewer | `<pass/fail>` | `<name>` | `<date>` | |
| Database reviewer | `<pass/fail>` | `<name>` | `<date>` | |
