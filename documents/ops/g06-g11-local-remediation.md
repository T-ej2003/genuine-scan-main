# G06 / G11 local remediation record

Baseline: `6d5a48ce7c32b12ce8671731392f92ddfa625a88`.
Authority: the accepted G06/G11 mappings in `/private/tmp/mscqr-platform-audit.KQjWTE/remediation-groups.json`.

Status: implemented and locally validated. FIXED means source repair with regression evidence, not production certification.
No production operation, push, release, physical printing, or deployment has been performed.

## Boundaries

Only connector wire/receipt contracts and the mapped frontend request/release contracts are in scope.
No grant or policy expansion, database provisioning, maker/checker redesign, incident authorization,
worker activation, printing lifecycle redesign, or public-verification change is authorized here.
Local generated SQL changes affect only the reviewed printing function implementations.

## Implemented locally

- C21: stream URLs use the configured REST API base; job IDs remain encoded.
- P01: hello verification preserves the connector's signed registration/selector bytes while independently binding resolved registration, agent, and device identities.
- P13: the active verifier honors the existing strict mTLS flag and pinned certificate, projected by the canonical identity function.
- P02: the shared claim repository hydrates UTC JSON timestamps inside its transaction and rejects invalid projections before commit.
- P03: the exact signing instant is supplied to and persisted by the canonical job-creation function.
- P09: action receipts are excluded from latest readiness-attestation selection; trust/freshness/connected checks remain mandatory.
- P08: bounded terminal receipts deduplicate label/chunk completion, reject conflicts, and require a real signed acknowledgement. Socket processing is ordered and bounded.
- P16: committed WebSocket progress publishes tenant/manufacturer-bound invalidations through the existing realtime channel. Heartbeats publish canonical committed connection status, not caller-supplied connectivity.
- C06: the release wrapper adapts the actual top-level backend envelope locally; other response contracts are unchanged.
- C15: editing a policy does not resend its immutable tenant selector.
- C20/C23: client types match the backend policy-create fields and manufacturer administrator role.
- C14: the affected upload wrappers select the exact canonical idempotency header; generated identity is retained across authentication-refresh retry.
- C01/C02/C04/C05: audit, fraud, export and trace requests carry explicit tenant/purpose; missing scope and forbidden exports remain denied.
- C03/C07/C08/C09: batch, compliance and allocation-map requests carry selected tenant; stale tenant responses are discarded.
- D007: immutable built-image source is distinct from deployment source; missing/invalid build identity reports unknown.
- C18: four wrappers retain bounded pagination metadata; active batch, manufacturer and user directories expose page controls without unbounded fetches.

## Final validation

- `npm run verify:ci:backend`: PASS, including build, startup, trust-critical, complete existing backend suites and 14 added compiled regressions. The cross-contract test uses backend-installed tsx, not frontend build dependencies.
- `npm run verify:ci:frontend`: PASS, including typecheck, architecture guardrails, budgets, 66 files / 262 tests and production build.
- Real disposable PostgreSQL 18 printing-lifecycle certification: passed, including delayed signing-instant persistence and readiness after a claim receipt. The harness also verified its existing privilege denials, transactional rollback, and failure-injection checks.
- Disposable evidence: `/private/tmp/mscqr-platform-audit.KQjWTE/g06-printing-certification.json`.

- `npm run rls:full-verify`: PASS, 16 tests. Repeated generation produces identical bytes.
- `npm run lint:security-scope`: PASS, 21 changed security files.
- ESLint across 55 changed/new JS/TS files: 260 diagnostics versus baseline 265; no per-file/rule increases. Raw repository lint is not claimed clean.
- Security/Prisma scope, public metadata, print QR identity, RLS prototype, documents and fixture-secret guards: PASS.
- `git diff --check`: PASS.

The PostgreSQL certification covers the printing family (38 fixtures), not the whole platform. Generated contract: `be203107ae158c0244766c8423baf7d5af4bd1829159969dff7df4dbe761aabb`. Migration digest unchanged: `6642442a81cd98c7a132d241fa98e50ae231510896c9da67ab70d86b050d02db`.

## Per-ledger regression evidence

All 23 entries below are FIXED locally: G06 8/8 and G11 15/15; blocked within these mappings: 0. Other groups retain their previous status.

| Group / ID | Regression test |
| --- | --- |
| G06 C21 | `src/test/internal-client-printing.test.ts` |
| G06 P01, P13 | `backend/tests/printerAgentActiveBoundary.test.js` |
| G06 P02 | `backend/tests/printingClaimProjection.test.js` |
| G06 P03, P09 | `backend/tests/rls-wave-c/c02/printingLifecyclePostgres18.test.js` |
| G06 P08 | `backend/tests/printerAgentActiveBoundary.test.js`, `printerSessionReceiptOrdering.test.js` |
| G06 P16 | `backend/tests/printerHeartbeatRealtime.test.js`, `printRealtimeIsolation.test.js` |
| G11 C01, C02, C05 | `backend/tests/g11FrontendBackendContracts.test.mjs`, `src/test/dashboard-audit-scope.test.tsx` |
| G11 C04, C09, C06, C20, C23 | `src/test/remediation-client-contracts.test.ts` |
| G11 C03 | `src/test/batch-tenant-selector.test.tsx` |
| G11 C07 | `src/test/governance-regression.test.tsx` |
| G11 C08 | `src/test/release-readiness.test.tsx` |
| G11 D007 | `backend/tests/immutableImageReleaseMetadata.test.js` |
| G11 C15 | `src/test/ir-regression.test.tsx` |
| G11 C14 | `src/test/internal-client-core.test.ts`, `remediation-client-contracts.test.ts` |
| G11 C18 | `src/test/remediation-client-contracts.test.ts`, `batch-pagination.test.tsx`, `user-directory-pagination.test.tsx`, `manufacturers-linking.test.tsx` |

## Security evidence

Generated role, ownership-grant, runtime-grant and policy SQL is identical to baseline after removing source-hash substitutions. No grants expanded and no RLS policy weakened. Actual frontend serializers are tested against unchanged backend scope/purpose/assurance checks, including missing scope, stale assurance and foreign-tenant denial. Strict connector signature/session/mTLS checks remain enforced. Signed acknowledgement is mandatory; transport acceptance does not invent physical evidence. No forbidden workflow was enabled.

## Compatibility and remaining work

Source requires Windows Connector build `2026.6.26` for persistent sessions, REST minimum `2026.6.16`, and retains `local-agent-direct-v2`.
No protocol version, signature algorithm, or unsigned fallback was introduced. Shipped-binary compatibility is not inferred from source tests.
G06 includes canonical printing-function source and generated artifact changes: it is not an app-only rollout. A separately authorized release must coordinate functions with backend code. G11 requires frontend/backend artifacts when release is authorized. No image was built or published here. Database-boundary, outbox, worker, lifecycle, projection and public-auth repairs remain outside this work; integrated onboarding is not certified.

Recommendation: retain bounded receipt history and explicit tenant-bound client requests; do not substitute broader database privileges or polling-only behavior for contract correctness. Physical-device acceptance remains a separately authorized release activity.

`PRODUCTION_MUTATION_PERFORMED=false`
`READY_FOR_ONBOARDING=false`
