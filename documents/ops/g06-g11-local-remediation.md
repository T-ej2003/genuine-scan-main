# G06 / G11 local remediation record

## PR 531 exact-head review correction

- Batch and audit-history controllers now end loading immediately when a super administrator clears the required brand scope. Existing scope/offset guards continue rejecting late success, late failure, and stale `finally` updates; no unscoped request is issued. Batch paging reports offset and total as zero in the no-scope state.
- Regression coverage exercises pending brand A requests, scope clearing, late success and failure, brand B recovery, paging state, and unchanged licensee-admin behavior. Audit-history coverage proves the same independently confirmed loading invariant without changing REST/SSE authorization or filtering.
- Deployment Audit Gitleaks identified one historical function-symbol name in prose at commit `616f94c69e7fef0a6090d86567100d40aad11f7a`. Inspection of that commit and current source confirms no credential, token, private/signing key, or runtime secret value is present. The existing exact-finding JSON baseline now contains only that commit/file/rule/line fingerprint; history scanning and generic API-key detection remain enabled.
- Validation uses Gitleaks v8.24.2 with the Deployment Audit history command, the current-tree `--no-git` command, and an isolated synthetic generic API-key commit that must still fail detection. No scanner rule, path, rule class, commit, or regex was excluded.

Recommendation: keep no-scope transitions explicit in every scoped async controller, and retain a synthetic negative control whenever adding a historical scanner disposition. Production, physical printer, and coordinated release acceptance remain separate gates.

## PR 529: SSE compatibility and RF7 secret-scan disposition

Correction based on `9191ec43e99eb010117aa65ff0dae3e664dac69b`:

- Audit streaming accepts only optional UUID `licenseeId` and optional string `token` after the existing `authenticateSSE` middleware. The middleware, production compatibility-mode switch, authentication sources, required platform brand scope, and server tenant/event filters are unchanged. The controller never authenticates or serializes the query token.
- Both reported RF7 generic-api-key matches were source-symbol references, not credentials. Their exact source/symbol pairs are retained in the structural regression fixtures in `scripts/tests/rf7-contract-inventory.test.mjs`. One is the customer verification E2E delivery predicate; the other returns a boolean from configured signing-key presence. The generator never evaluates either function or embeds their runtime values.
- Reachable-function references now contain separate `source` and `symbol` fields. Exact identities, ordering, reachability and reconciliation semantics are preserved. No scanner rules, exclusions, authentication policy, grants, RLS, or connector trust were changed.

Validation: actual middleware/controller SSE regressions passed (cookie/header, enabled/disabled production query compatibility, missing/invalid scope, extra keys, foreign tenant, non-serialization); all 18 compiled G06/G11 tests passed. Backend validation passed; frontend validation passed (67 files / 263 tests, including stale/cross-brand protections). RF7 static tests, 71 app-only/image-impact tests, security-source verification, 16 RLS tests, security-scope lint, and document checks passed.

The exact CI Gitleaks v8.24.2 command passed on a clean tracked-file snapshot. A first local scan also included ignored compiled `backend/dist` and matched a generated JavaScript symbol assignment; that file is not committed or present in the secret-scan checkout. No real secret was found. Repeated RF7 generation is deterministic, and normalized comparison with the predecessor preserves all non-location security metadata and every reachable source/symbol identity.

Recommendation: retain structural source references for generated inventories and middleware-to-handler contract tests at authentication boundaries. Physical printer acceptance and coordinated printing SQL/backend release remain separate, unperformed release gates. This correction does not authorize deployment or onboarding.

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

### F01 identity-continuity correction

The accepted hello's `selectedPrinterId` is the authenticated wire selector for the entire
WebSocket session. It is not rewritten to the resolved native identifier. The independently
resolved `printerId` remains the database/authorization identity; chunk projections retain
their canonical native printer identity separately. Subsequent messages cannot select a new
signing identity, and the strict message schema does not admit a selector field.

The real connector serializer and active backend verifier now exercise both database-ID and
native-ID hello forms through heartbeat, chunk acknowledgement, label confirmation and chunk
confirmation. Regressions reject alternate/foreign signing selectors, registration/session
substitution, replay, confirmation before acknowledgement and messages after session closure.
No SQL, protocol, grant, policy or signature algorithm changes are part of this correction.

Validation: focused socket/session/trust/receipt/realtime tests PASS; G06/G11 compiled suite
15/15 PASS; `verify:ci:backend` PASS; `verify:ci:frontend` PASS (66 files, 262 tests plus build);
`rls:full-verify` PASS (16 tests); `lint:security-scope` PASS; `git diff --check` PASS.
The standalone trust test requires the existing generated-test-secret wrapper; rerunning
through that wrapper passed. No credential fixture or production access was introduced.

Source requires Windows Connector build `2026.6.26` for persistent sessions, REST minimum `2026.6.16`, and retains `local-agent-direct-v2`.
No protocol version, signature algorithm, or unsigned fallback was introduced. Shipped-binary compatibility is not inferred from source tests.
G06 includes canonical printing-function source and generated artifact changes: it is not an app-only rollout. A separately authorized release must coordinate functions with backend code. G11 requires frontend/backend artifacts when release is authorized. No image was built or published here. Database-boundary, outbox, worker, lifecycle, projection and public-auth repairs remain outside this work; integrated onboarding is not certified.

Recommendation: retain bounded receipt history and explicit tenant-bound client requests; do not substitute broader database privileges or polling-only behavior for contract correctness. Physical-device acceptance remains a separately authorized release activity.

`PRODUCTION_MUTATION_PERFORMED=false`
`READY_FOR_ONBOARDING=false`
# PR 529 review corrections

The follow-up preserves both original commits and the authenticated hello wire
selector. Strict mTLS now requires a stored registration pin and matching trusted
proxy fingerprint; the existing comparison is exact after trimming the incoming
header. No TOFU, pin persistence, case-folding or signature-only fallback is added.
Proxy authority comes only from the socket peer allowlist, never forwarded IPs.
Operators must configure the actual terminating proxy peer; this is not a claim
that production proxy configuration has been validated.

Audit live subscriptions are paused for platform administrators without a brand.
Selected brand identity is sent to the server, which validates it and intersects
it with existing role/ownership filtering before serializing events. Subscription
keys include the brand; cleanup and stale-callback guards prevent old subscriptions
from repopulating state. Existing tenant/manufacturer authority is not expanded.

RF7 extracts conditional query-only suffixes independently of route paths and
retains dynamic path segments. The generated inventory is refreshed, not exempted.
The app-only health contract now predicts immutable image identity, independently
of task deployment variables; missing/malformed image metadata remains fail-closed.
Tests execute the actual release metadata source rather than assert a source shape.

All 26 previously unclassified frontend runtime paths are image-affecting Docker
build inputs. **Image reuse is incompatible; later authorized publication is
required.** Tests remain test-only and unknown paths still fail closed. This does
not authorize publication or deployment. Printing SQL/backend remains a coordinated
release unit; physical-printer acceptance is still outstanding.

Local validation: focused mTLS/active connector/audit-stream tests PASS; real
serializer continuation retained; RF7 8/8 PASS; app-only and image-contract suites
305/305 PASS (including disposable PostgreSQL checks); backend CI validation PASS;
frontend CI validation PASS; security source validation PASS; full RLS verification
16/16 PASS. No grants, RLS policies, IAM or production state changed. The additional
activation fixture was updated to immutable health identity, and the audit page
stays within its existing size budget without raising the limit.

Recommendation: retain these negative regressions as release gates, and separately
verify proxy-peer configuration and physical connector acceptance before any future
coordinated release. Do not relax trust or tenant boundaries for compatibility.
