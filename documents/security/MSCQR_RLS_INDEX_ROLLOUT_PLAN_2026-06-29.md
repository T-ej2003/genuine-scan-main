# MSCQR RLS Index Rollout Plan - 2026-06-29

This is a production-readiness plan for indexes that may be needed before future MSCQR RLS runtime experiments. It does not enable RLS in production, does not enable RLS in staging, does not wire runtime routes into RLS, does not remove existing application-layer authorization, and does not create a Prisma migration.

## Sources Reviewed

- PR #82 analysis: `documents/security/MSCQR_RLS_POLICY_PERFORMANCE_INDEX_ANALYSIS_2026-06-29.md`
- PR #82 non-applied SQL: `documents/security/mscqr_rls_index_recommendations_non_applied.sql`
- Reviewed rollout SQL: `documents/security/mscqr_rls_index_rollout_candidates_non_applied.sql`
- Prisma schema: `backend/prisma/schema.prisma`
- Prisma migrations: `backend/prisma/migrations/**/*.sql`
- RLS boundary guardrail: `scripts/check-rls-prototype-boundaries.mjs`
- Migration replay/drift gates: `.github/workflows/auth-security-tests.yml`, `backend/tests/p3MigrationReplay.test.js`, `backend/tests/p3MigrationDrift.test.js`

## Decision

Do not add a real Prisma migration in this PR.

The current migration history uses ordinary `CREATE INDEX` / `CREATE INDEX IF NOT EXISTS` statements and has no established `CREATE INDEX CONCURRENTLY` production migration pattern. The CI migration gates replay Prisma migrations and check Prisma schema drift, but they do not prove production-safe online index creation with lock timeouts, statement timeouts, invalid-index cleanup, or release monitoring. PostgreSQL also does not allow `CREATE INDEX CONCURRENTLY` inside a transaction block, so the production release vehicle should be an explicitly reviewed DBA/release runbook rather than a default Prisma migration unless the repo adds and proves that pattern separately.

## Classification Legend

- `already_exists`: The schema or migration history already has an index/constraint that supports this path.
- `safe_candidate`: Low-risk index shape worth validating first in staging, still non-applied until DBA/release approval.
- `needs_more_staging_evidence`: Plausible index shape, but requires realistic row counts and `EXPLAIN ANALYZE` before selection.
- `defer_until_route_wiring`: Do not add until the specific route is wrapped and measured under staging-only RLS context.
- `rejected_duplicate_or_low_value`: Do not add because existing indexes already cover the path or the expected value is weak.

## Reviewed Index Classifications

| Table / query path | Index or support shape | Classification | Rationale |
| --- | --- | --- | --- |
| `Batch` licensee list for `GET /qr/batches` | Existing `Batch(licenseeId)` | `already_exists` | Supports direct tenant predicate but not list ordering. |
| `Batch` manufacturer list for `GET /qr/batches` | Existing `Batch(manufacturerId)` | `already_exists` | Supports direct manufacturer predicate but not list ordering. |
| `Batch` licensee list ordering | `Batch(licenseeId, updatedAt DESC, createdAt DESC, id)` | `safe_candidate` | Matches the first planned staging route ordering and keeps equality key before sort keys. |
| `Batch` manufacturer list ordering | `Batch(manufacturerId, updatedAt DESC, createdAt DESC, id) WHERE manufacturerId IS NOT NULL` | `safe_candidate` | Same first-route shape for manufacturer users, with a partial predicate to avoid null-heavy index bloat. |
| `QRCode` code lookup | Unique `QRCode(code)` | `already_exists` | Public/internal exact code lookup is already backed by a unique b-tree. |
| `QRCode` batch relation predicates | Existing `QRCode(batchId)` and `QRCode(licenseeId, batchId, status)` | `already_exists` | Supports relation checks and scoped status filtering. |
| `QRCode` batch enrichment ordering/count support | `QRCode(batchId, createdAt, id) WHERE batchId IS NOT NULL` | `safe_candidate` | Useful for batch relation scans and allocation-map/enrichment paths; validate after `Batch` first-route plans. |
| `QRCode` generic createdAt ordering without batch/tenant key | Standalone `QRCode(createdAt)` | `rejected_duplicate_or_low_value` | Not recommended for RLS rollout; route predicates should stay tenant/batch anchored. |
| `PrintItem` print-session relation | Existing `PrintItem(printSessionId, state, issueSequence)` | `already_exists` | Covers print-session predicate plus operational ordering. |
| `PrintItem` QR relation | Unique `PrintItem(qrCodeId)` | `already_exists` | QR-to-print-item checks are already unique-backed. |
| `PrintItem` batch relation through QR/session | New direct batch index on `PrintItem` | `rejected_duplicate_or_low_value` | `PrintItem` has no direct `batchId`; adding denormalized indexing is a broad schema change and not needed for first RLS candidates. |
| `PrintJob` batch predicate | Existing `PrintJob(batchId)` | `already_exists` | Supports batch-scoped print-job reads. |
| `PrintJob` manufacturer predicate | Existing `PrintJob(manufacturerId)` | `already_exists` | Supports manufacturer-scoped print-job reads. |
| `PrintJob` printer predicate | Existing `PrintJob(printerId)` | `already_exists` | Supports printer relation checks. |
| `PrintJob` future list composites | Route-specific `(manufacturerId, status/createdAt)` or `(batchId, status/createdAt)` variants | `defer_until_route_wiring` | Print job routes mix reads, SSE, reissue state, and print lifecycle behavior; measure the actual wrapped query first. |
| `VerificationDecision` latest by QR | Existing `VerificationDecision(qrCodeId, createdAt)` | `already_exists` | PostgreSQL can scan b-trees backward, but this does not settle OR/latest behavior at scale. |
| `VerificationDecision` latest by code | Existing `VerificationDecision(code, createdAt)` | `already_exists` | Same as above for code lookups. |
| `VerificationDecision` latest by QR descending partial | `VerificationDecision(qrCodeId, createdAt DESC) WHERE qrCodeId IS NOT NULL` | `needs_more_staging_evidence` | Candidate only if realistic `EXPLAIN ANALYZE` shows expensive latest lookup or bitmap/sort behavior. |
| `VerificationDecision` latest by code descending partial | `VerificationDecision(code, createdAt DESC) WHERE code IS NOT NULL` | `needs_more_staging_evidence` | Candidate only if the public verification function remains expensive after testing; splitting the OR may be better. |
| `QrScanLog` QR/reporting predicates | Existing `QrScanLog(qrCodeId, scannedAt)`, `QrScanLog(qrCodeId, isTrustedOwnerContext, scannedAt)`, and `QrScanLog(licenseeId, batchId, scannedAt)` | `already_exists` | Strong coverage for QR, trusted-owner, and tenant/batch reporting shapes. |
| `QrScanLog` future tenant time feed | `QrScanLog(licenseeId, scannedAt DESC, id)` | `needs_more_staging_evidence` | Reporting routes need realistic scan-log volume before another large index is justified. |
| `QrScanLog` standalone scannedAt variant | Additional standalone `QrScanLog(scannedAt DESC)` | `rejected_duplicate_or_low_value` | Existing `scannedAt` plus tenant/batch composites are better aligned with authorization. |
| `Incident` tenant latest list | `Incident(licenseeId, createdAt DESC, id) WHERE licenseeId IS NOT NULL` | `defer_until_route_wiring` | Incident handlers are relation-heavy and include evidence/support data; split metadata-only route before indexing. |
| `Incident` tenant status latest list | `Incident(licenseeId, status, createdAt DESC, id) WHERE licenseeId IS NOT NULL` | `defer_until_route_wiring` | Same defer reason; useful only after the exact list filters are wrapped and measured. |
| `Incident` QR relation latest | `Incident(qrCodeId, createdAt DESC, id) WHERE qrCodeId IS NOT NULL` | `defer_until_route_wiring` | Relation-heavy incident reads should not lead the RLS rollout. |
| `SupportTicket` tenant latest list | `SupportTicket(licenseeId, createdAt DESC, id) WHERE licenseeId IS NOT NULL` | `defer_until_route_wiring` | Defer unless support route inventory proves a narrow read-only path. |
| `Printer` manufacturer/status read | Existing `Printer(orgId, isActive)`, `Printer(licenseeId, isActive)`, `Printer(assignedUserId, isActive)`, and connection indexes | `already_exists` | Current read/status candidates are mostly covered. |
| `Printer` creator-owned policy branch | `Printer(createdByUserId, isActive) WHERE createdByUserId IS NOT NULL` | `needs_more_staging_evidence` | The prototype policy allows creator access, but first printer reads do not appear creator-driven. |
| `ManufacturerLicenseeLink` linked-licensee access | Primary key `(manufacturerId, licenseeId)`, `licenseeId`, and `(manufacturerId, isPrimary)` | `already_exists` | Aligned with manufacturer linked-licensee access and reverse lookup needs. |

## First Indexes Recommended for Staging Validation

Validate these first because they map directly to the agreed #84 first route, `GET /qr/batches`, and do not require broad runtime wiring:

1. `Batch(licenseeId, updatedAt DESC, createdAt DESC, id)`
2. `Batch(manufacturerId, updatedAt DESC, createdAt DESC, id) WHERE manufacturerId IS NOT NULL`
3. `QRCode(batchId, createdAt, id) WHERE batchId IS NOT NULL`

The first two should be tested against licensee and manufacturer users with the actual `listCachedBatchOperationalSummaries` query shape. The QRCode candidate should be validated only after the batch list plan shows whether relation/count enrichment remains a bottleneck.

## Deferred Indexes

`Incident` and `SupportTicket` indexes are deferred because the current handlers load relation-heavy payloads rather than a narrow metadata-only route. Add them only after a route split or inventory update proves the wrapped staging query is read-only, tenant-scoped, and measurable.

`VerificationDecision` descending partial indexes need staging evidence because the existing `(qrCodeId, createdAt)` and `(code, createdAt)` indexes may satisfy backward scans. If the latest lookup remains expensive, first evaluate splitting the `OR` into two indexed branches before adding both indexes.

`QrScanLog` future reporting indexes are deferred until reporting routes are wrapped and seeded with realistic scan volume. This table can become very large, so index bloat and write amplification matter.

`Printer(createdByUserId, isActive)` needs evidence because current candidate reads appear to use org/licensee/assigned-user branches. Keep printer mutation, discovery, test-label, and local-agent protocol routes out of this phase.

`PrintJob` and `PrintItem` are not first-wave index targets. Existing relation indexes are adequate for RLS predicate support, while print runtime paths remain deferred because they combine authorization, printer trust, physical print confirmation, and state mutation.

## Production Release Requirements

Before any production index build:

1. Run staging `EXPLAIN ANALYZE` with realistic row counts for selected tables.
2. Confirm index names, duplicate coverage, estimated size, and write amplification.
3. Use `CREATE INDEX CONCURRENTLY` where PostgreSQL supports it.
4. Apply a lock/timeout plan, including `lock_timeout`, `statement_timeout`, monitoring, and invalid-index cleanup.
5. Schedule index builds outside peak write windows for QR/scan/verification-heavy tables.
6. Prepare rollback as `DROP INDEX CONCURRENTLY IF EXISTS ...`, reviewed separately.
7. Keep RLS disabled in production and staging until the route-specific staging runtime proof is complete.

## Guardrails

`scripts/check-rls-prototype-boundaries.mjs` now checks that `mscqr_rls_index*_non_applied.sql` files stay under `documents/security/` and are not referenced by package scripts, GitHub workflow automation, deploy automation, or Prisma migrations. The deploy automation scan includes `deploy/` and the Ansible playbooks under `ops/deploy/`, including `ops/deploy/deploy.yml` and `ops/deploy/deploy-standby.yml`. This keeps reviewed SQL as a human-approved artifact rather than an automatic database change.

## CTO Recommendations

1. Build a formal online-index runbook before PR #87, including timeouts, observability, invalid-index cleanup, and rollback commands.
2. Capture staging p50/p95/p99 latency and row counts for `GET /qr/batches` before and after candidate indexes; index rollout without latency evidence is not production engineering.
3. Add query-plan snapshots to the RLS evidence package, but keep them route-specific so the team does not over-index speculative paths.
4. Treat RLS as defense-in-depth. Existing controller/service authorization must remain the business authority even after database policies are introduced.
5. For scale, prioritize composite tenant-plus-sort indexes over standalone time indexes; they reduce both planner ambiguity and cross-tenant scan risk.
