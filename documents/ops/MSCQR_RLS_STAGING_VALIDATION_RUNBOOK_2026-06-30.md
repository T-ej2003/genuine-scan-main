# MSCQR RLS Staging Validation Runbook - 2026-06-30

This runbook validates the three already-wired staged RLS routes in staging only. It does not enable production RLS, does not enable global or table-level RLS, does not create Prisma migrations, does not wire additional routes, and does not change any production database.

## References

- Evidence template: `documents/qa/evidence/MSCQR_RLS_STAGING_VALIDATION_EVIDENCE_2026-06-30.md`
- Production rollout plan from PR #88: `documents/security/MSCQR_RLS_PRODUCTION_ROLLOUT_PLAN_2026-06-30.md`
- Batch list staging wiring: `documents/security/MSCQR_RLS_BATCHES_READ_STAGING_WIRING_2026-06-29.md`
- Batch list staging proof: `documents/security/MSCQR_RLS_BATCHES_STAGING_PROOF_2026-06-29.md`
- Batch allocation-map staging wiring: `documents/security/MSCQR_RLS_BATCH_ALLOCATION_MAP_STAGING_WIRING_2026-06-30.md`
- Manufacturer printer staging wiring: `documents/security/MSCQR_RLS_MANUFACTURER_PRINTERS_STAGING_WIRING_2026-06-30.md`
- Machine-readable checklist: `documents/security/mscqr_rls_staging_validation_checklist.json`
- Optional safe collector: `scripts/collect-rls-staging-validation-evidence.mjs`

## Approved Route And Flag Scope

| Route | Flag | Validation scope |
| --- | --- | --- |
| `GET /api/qr/batches` | `MSCQR_STAGING_RLS_BATCHES_READ_ENABLED` | Staging read-only batch list |
| `GET /api/qr/batches/:id/allocation-map` | `MSCQR_STAGING_RLS_BATCH_ALLOCATION_MAP_ENABLED` | Staging read-only allocation map using one safe staging batch ID |
| `GET /api/manufacturer/printers` | `MSCQR_STAGING_RLS_MANUFACTURER_PRINTERS_READ_ENABLED` | Staging read-only manufacturer printer list |

Current flags are process-wide environment flags. They are not tenant-scoped controls. Do not use this runbook against production and do not call a staging run tenant-limited unless traffic is isolated by a separate mechanism.

## Preflight

1. Confirm the target environment is staging only.
2. Confirm `STAGING_BASE_URL` points to a staging host and not `mscqr.com`, any `*.mscqr.com` subdomain, `production`, or `prod`.
3. Confirm the current deployed backend SHA.
4. Confirm all three route flags are initially false/off:
   - `MSCQR_STAGING_RLS_BATCHES_READ_ENABLED`
   - `MSCQR_STAGING_RLS_BATCH_ALLOCATION_MAP_ENABLED`
   - `MSCQR_STAGING_RLS_MANUFACTURER_PRINTERS_READ_ENABLED`
5. Confirm baseline auth/test users exist for the required contexts without recording user IDs.
6. Confirm a safe staging batch exists for allocation-map validation, without recording the batch ID in evidence.
7. Confirm the rollback owner is available for the whole validation window.
8. Confirm existing app-layer authorization remains enabled.
9. Confirm no global/table RLS enablement is part of this run.

## Optional Safe Collector Setup

The collector does not enable flags and does not mutate data. It only sends `GET` requests to the three approved route templates and writes safe summaries.
It uses manual redirect handling. Approved-route `3xx` responses are recorded as redirect evidence and are not followed to `/login` or any other `Location`.

Dry-run:

```sh
node scripts/collect-rls-staging-validation-evidence.mjs --dry-run
```

Host guard self-check:

```sh
node scripts/collect-rls-staging-validation-evidence.mjs --self-check-host-guard
```

Actual collection:

```sh
STAGING_BASE_URL="https://staging.example.internal" \
STAGING_AUTH_TOKEN="<token from secure operator session>" \
STAGING_BATCH_ID="<safe staging batch id>" \
RLS_VALIDATION_SAMPLES=5 \
node scripts/collect-rls-staging-validation-evidence.mjs
```

Rules:

- Pass bearer auth only through `STAGING_AUTH_TOKEN`.
- The collector rejects `mscqr.com` and `*.mscqr.com` by default, plus hosts containing `production` or `prod`.
- If staging is ever hosted under an MSCQR subdomain, operators must use a separately reviewed explicit allowlist mechanism rather than allowing the whole parent domain. This script does not currently implement that allowlist.
- Do not paste tokens into evidence.
- Do not commit generated evidence containing real hostnames unless the host is safe to disclose.
- The generated summary must not contain raw response bodies or IDs.
- The generated summary records `success_2xx`, `redirect_3xx`, `client_error_4xx`, and `server_error_5xx` outcomes separately.
- Redirect evidence must record only coarse redirect facts such as `redirected`, `redirectStatusCategory`, and `locationPresent`; it must not record raw `Location` values.
- Any `3xx` from an approved route is a warning/no-go until auth, proxy, and routing behavior are fixed and fresh evidence is collected.

## Baseline Flag-Off Validation

With all three flags off:

1. Call `GET /api/qr/batches`.
2. Call `GET /api/qr/batches/:id/allocation-map` using the safe staging batch ID.
3. Call `GET /api/manufacturer/printers`.
4. Record status, response shape summary, safe row/result counts, p50 latency, and p95 latency if available.
5. Record whether each route returned `success_2xx`, `redirect_3xx`, `client_error_4xx`, or `server_error_5xx`.
6. Do not store tenant IDs, user IDs, printer IDs, batch IDs, QR codes, request tokens, auth cookies, redirect `Location` values, or secrets.

Expected result: all three routes match current app-layer authorization behavior and no staged RLS proof events are emitted.

## One-By-One Flag Validation

### Batch List

1. Enable only `MSCQR_STAGING_RLS_BATCHES_READ_ENABLED=true` in staging.
2. Restart or redeploy the staging backend if env var changes require it.
3. Validate `GET /api/qr/batches`.
4. Compare status, response shape, safe row count, p50, and p95 against baseline.
5. Check `staging_rls_batches_read_proof` telemetry.
6. Unset `MSCQR_STAGING_RLS_BATCHES_READ_ENABLED`.
7. Restart or redeploy if needed.
8. Confirm proof events stop and route behavior returns to baseline.

### Batch Allocation Map

1. Enable only `MSCQR_STAGING_RLS_BATCH_ALLOCATION_MAP_ENABLED=true` in staging.
2. Restart or redeploy the staging backend if env var changes require it.
3. Validate `GET /api/qr/batches/:id/allocation-map` using the safe staging batch ID.
4. Compare status, response shape, safe result count, p50, and p95 against baseline.
5. Check `staging_rls_batch_allocation_map_proof` telemetry.
6. Unset `MSCQR_STAGING_RLS_BATCH_ALLOCATION_MAP_ENABLED`.
7. Restart or redeploy if needed.
8. Confirm proof events stop and route behavior returns to baseline.

### Manufacturer Printers

1. Enable only `MSCQR_STAGING_RLS_MANUFACTURER_PRINTERS_READ_ENABLED=true` in staging.
2. Restart or redeploy the staging backend if env var changes require it.
3. Validate `GET /api/manufacturer/printers`.
4. Compare status, response shape, safe row count, p50, and p95 against baseline.
5. Check `staging_rls_manufacturer_printers_read_proof` telemetry.
6. Unset `MSCQR_STAGING_RLS_MANUFACTURER_PRINTERS_READ_ENABLED`.
7. Restart or redeploy if needed.
8. Confirm proof events stop and route behavior returns to baseline.

## Combined Flag Validation

1. Enable all three staged route flags in staging.
2. Restart or redeploy the staging backend if env var changes require it.
3. Validate all three approved routes.
4. Compare status, response shape, safe row/result counts, p50, and p95 against baseline.
5. Confirm proof telemetry exists only for the three target routes.
6. Confirm non-target routes, public verification, scan mutation, print dispatch, workers, exports, incidents, support, and admin global views are unaffected.
7. Unset all three flags.
8. Restart or redeploy if needed.
9. Confirm proof events stop and baseline behavior returns.

## Telemetry Validation

Proof telemetry may include only:

- `metric`
- `route`
- `flagEnabled`
- `contextClass`
- `durationMs`
- `rowCount` or safe coarse result count
- `success`
- `failureCategory`

Proof telemetry and generic request telemetry must not include:

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

If any forbidden identifier appears in proof or generic request telemetry, stop the validation, unset the active flag, and record a no-go.

## Latency Validation

Compare each flag-on route against its own flag-off baseline.

Warning threshold:

- p95 increases by more than 25 percent from baseline; or
- p95 increases by more than 250 ms from baseline.

No-go threshold:

- p95 increases by more than 50 percent from baseline; or
- p95 increases by more than 500 ms from baseline; or
- any repeated timeout occurs; or
- any material status-code regression occurs.

Realistic staging row counts are required before this evidence can support production canary planning.

## Rollback Validation

For each one-by-one flag test and for the combined flag test:

1. Unset the active route flag or set it to `false`.
2. Restart or redeploy the staging backend if env var changes require it.
3. Confirm the related proof event stops.
4. Confirm route status, response shape, and safe row/result count return to baseline.
5. Confirm no table-level staging or production global RLS was enabled.
6. Record rollback evidence in `documents/qa/evidence/MSCQR_RLS_STAGING_VALIDATION_EVIDENCE_2026-06-30.md`.

## No-Go Criteria

Stop validation and roll back if any condition is true:

- Any non-target route is affected.
- Public verification is affected.
- Scan mutation is affected.
- Print dispatch is affected.
- Worker errors increase.
- IDs or secrets appear in proof telemetry or generic request telemetry.
- Any approved route returns a `3xx` redirect during collection; fix auth/proxy/routing before accepting evidence.
- 401, 403, 404, or 500 responses increase unexpectedly.
- Latency materially regresses.
- Flag rollback does not restore baseline behavior.
- Any global/table-level RLS is enabled as part of this staging validation.

## Evidence Template

Record final evidence in `documents/qa/evidence/MSCQR_RLS_STAGING_VALIDATION_EVIDENCE_2026-06-30.md` using the table with these columns:

- route
- flag
- baseline status
- flag-on status
- rollback status
- row count comparison
- latency comparison
- telemetry safe yes/no
- pass/fail
- notes

## CTO Recommendations

1. Run this evidence pack before any production canary discussion. It is the minimum proof that the three staged routes behave predictably under route flags.
2. Treat telemetry redaction as a release gate, not a logging cleanup task.
3. Keep sample sizes high enough to make p95 meaningful before production planning. A single request is a smoke test, not performance evidence.
4. Do not expand RLS to public verification, printing, workers, exports, incidents, support, or admin global views until each has its own context design and rollback unit.
