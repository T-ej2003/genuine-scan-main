# Full-System Runtime Batch 001 Review

Date: 2026-07-16

Programme stage: full-system runtime implementation

Authorization architecture: frozen

Dominant boundary: bounded authenticated licensee read
Transaction model: one transaction-local canonical context and one repeatable-read Prisma transaction

Current-status note (2026-07-20): this document preserves the historical Batch 001 review. The later foundation checkpoint implemented the frozen platform risk-analytics slice, moved the deterministic family count to 318 without changing the exact 428 workflows, and replaced the rejected in-place rollback draft with clean-room blue/green database destruction and exact marked-role cleanup.

## Outcome

This batch considered two stable families and two workflows. It implemented one family and one workflow, then stopped deterministically at the first incompatible family. It did not generate or execute SQL, enable RLS, modify database authority, call infrastructure, or change staging or production.

## Phase A final review corrections

- Database scope authority: authentication now uses the current `User` row and database membership links only. Tenant administrators fail closed when database organization/licensee scope is missing or disagrees with a nonblank token claim; platform scope is cleared; manufacturer token scope may only select a database-verified membership.
- Alert parent integrity: every unresolved alert is projected without details and every populated batch, QR, manufacturer membership, incident and policy-rule parent must resolve to the same active canonical tenant before candidate scoring. PolicyRule validation selects only identifiers plus `isActive`; missing, inactive, duplicate or conflicting parents deny before successful attribution.
- Platform denial invariant: an exact actor-self `User` hydration transaction is permitted. Platform actors are then denied before any `Licensee`, `Organization`, `Batch`, `QRCode`, `QrScanLog`, `PolicyAlert`, manufacturer projection, analytics or `RISK_ANALYTICS_READ` access while `platform-licensee-selector-validation-boundary-pending` remains unresolved.
- Route-chain proof: `backend/tests/riskAnalyticsRouteChain.test.js` distinguishes the approved actor-self transaction from the forbidden risk-analytics transaction and tenant-resource queries.

### Phase A gate result

The gate completed before any full-database SQL or shutdown work began. The backend build, risk analytics focused suite, production-access scan, context plan, manifest validator, status commands, 27 programme tests, context check, document guard, branch secret-diff guard and `git diff --check` all passed serially. The resulting programme counts were 77 tables, 428 workflows, 316 families, five runtime-implemented workflows, 59 contract-only workflows, 364 blocked workflows and five pending PostgreSQL certifications. No P1/P2 issue remained in stale token scope, alert parent integrity or the platform denial invariant.

| Measure | Limit | Used |
| --- | ---: | ---: |
| Families considered | 12 | 2 |
| Workflows considered | 30 | 2 |
| Production files changed | 12 | 2 |
| Test files changed | 12 | 2 |
| Net production/test lines | 3,000 | 724 net additions; 872 inserted/deleted lines |

## Families and workflows considered

### Implemented: risk analytics

- Family: `family-simple-tenant-scoped-reads-analyticsservice-2c20deef24`
- Workflow: `workflow-internal-backend-src-services-analytics-service-ts-get-risk-analytics`
- Registered root: `GET /api/analytics/risk-scores`
- Call chain: route limiters -> `authenticate` -> `requireAnyAdmin` -> tenant isolation -> `getRiskAnalyticsController` -> `buildRiskAnalyticsBoundary` -> `withCanonicalDbContext` -> `getRiskAnalytics`
- Implemented actor ceiling: database-hydrated active `LICENSEE_ADMIN`/`ORG_ADMIN` only.
- Scope: tenant administrators use their database organization/licensee and may only select the same licensee. After approved actor-self authentication hydration, every platform actor is denied before tenant-selector, analytics-table or success-attribution access while `platform-licensee-selector-validation-boundary-pending` remains unresolved.
- Frozen platform contract: `SUPER_ADMIN`/`PLATFORM_SUPER_ADMIN` still require database revalidation, fresh MFA and one exact validated licensee, but no actor-only broad `Licensee`/`Organization` visibility is authorized or implemented.
- Assurance and purpose: tenant password or MFA assurance, fixed allowlisted `tenant-risk-analytics` purpose and nonblank request ID. Generated rules carry `minimumAssuranceByActorClass`; the pending platform contract remains `mfa-verified`.
- Bounds: lookback 1-720 hours, output limit 1-200, 5,000 candidate batches, and 50,000 QR, scan and unresolved-alert rows. Each internal ceiling queries one overflow sentinel and denies rather than truncating.
- Snapshot: all parent validation, policy, batch, QR, scan and alert reads plus attribution use the supplied transaction client under one repeatable-read transaction.
- Projection: explicit tenant-safe analytics fields; manufacturer results return only `User.id` and `User.name`. Parent validation additionally filters on `role`, `isActive`, `status`, `deletedAt` and `disabledAt`; those predicate-only columns are selectable by the restricted runtime but never serialized. Email, password/hash, token, MFA, WebAuthn, recovery, metadata, platform-security state, raw alert details, scan IP/device/user-agent, audit payload and private manufacturer records remain unreadable.
- Ordering: deterministic score and stable-ID tie-breaks.
- Selection: every scoped tenant batch remains in the historical analytics universe, including batches with no recent scan or unresolved alert. The tenant batch set fails above 5,000 rather than truncating; bounded in-window scans and every bounded unresolved alert regardless of age supply risk signals, every referenced parent must resolve inside that universe, every batch is scored, and the requested limit is applied only after final risk ranking.
- Parent integrity: each scan must prove the same canonical licensee across `QrScanLog`, `QRCode` and `Batch`, a nonblank batch, exact QR-to-batch binding and consistent repeated QR parent mapping. Every populated unresolved-alert batch, QR, manufacturer link, incident and policy-rule parent must also resolve to the same canonical tenant before it can affect a candidate or score.
- Attribution: immutable `RISK_ANALYTICS_READ` details record actor, role, assurance, request, purpose, organization, licensee, workflow, route, success outcome, analyzed/returned counts and timestamp in the same transaction before controller serialization. No denial path writes success attribution.
- Hidden mutation removed: risk analytics reads `SecurityPolicy` with an exact fallback projection and no longer calls the create-capable `getOrCreateSecurityPolicy` helper.

Production changes are confined to the risk controller/service plus shared authentication and manufacturer-scope hydration. Focused coverage is in `backend/tests/riskAnalyticsContext.test.js`, `backend/tests/riskAnalyticsRouteChain.test.js` and the programme regression assertions. The implementation reuses the existing canonical context helper and introduces no repository abstraction.

### Retained blocker and deterministic stop

- Family: `family-simple-tenant-scoped-reads-auditcontroller-627bac35ff`
- Workflow: `workflow-http-backend-src-controllers-audit-controller-ts-respond-to-fraud-report`
- Registered root: `POST /api/audit/fraud-reports/:id/respond`
- Root chain: audit mutation limiters -> `authenticate` -> `requirePlatformAdmin` -> recent administrator MFA -> tenant isolation -> CSRF -> `respondToFraudReport`
- Blocker code: `incompatible-read-mutation-root`
- Exact blocker: the root reads a report through global Prisma, appends a response audit record through another global-client path, and constructs customer-delivery state. It lacks one database-validated report/licensee purpose scope, transaction-client propagation, immutable ownership protection, durable delivery enqueue, idempotency and database concurrency enforcement.
- Required resolution: process it in a platform-mutation batch that combines bounded lookup, compare-and-set or unique idempotency, response attribution and durable delivery enqueue in one canonical transaction with replay and concurrency tests.

This is not a new product decision. It is an exact runtime and concurrency blocker. The batch stops because the workflow is a mutation with side effects and is incompatible with the current read-only transaction model.

## Focused test evidence

`backend/tests/riskAnalyticsContext.test.js` proves:

- tenant own-scope allow; foreign, blank, missing, inactive, suspended and parent-inconsistent denial;
- approved actor-self authentication hydration followed by platform denial before tenant selector, analytics-table or success-attribution access while the exact selector boundary remains pending;
- frozen future platform MFA/selector semantics without claiming runtime implementation;
- canonical context before protected reads, one transaction client and no global Prisma in the protected service path;
- post-score limiting over all scoped tenant batches, independent batch/scan/alert/QR ceilings, bounded scan lookback and deterministic ordering;
- idle-batch, alert-only and bounded-empty behavior, old unresolved-alert inclusion, acknowledged-alert exclusion, minimal manufacturer-name projection and the historical aggregate manufacturer-ID fallback;
- foreign, orphaned, null and QR-to-batch-inconsistent scan parent denial before attribution;
- foreign, orphaned, inactive, duplicate and multi-parent-inconsistent alert denial before scoring or attribution;
- database tenant-scope removal/mismatch denial, platform scope clearing and database-verified manufacturer membership narrowing;
- explicit projections and exclusion of sensitive nested data;
- atomic read attribution and commit-before-serialization behavior;
- no create-capable policy helper in the analytics path.

The full programme test also fixes the implemented/blocked counts, requires the family to remain licensee-admin-only and transaction-client-only, retains the platform actor as contract-pending with its exact blocker, enforces actor-specific platform MFA in every mixed rule, preserves PostgreSQL status as pending, and prevents scanner helper functions from becoming duplicate pseudo-workflows.

## Full evidence-review addendum

The rejected in-place SQL evidence is no longer part of the deployment contract. The clean-room generator starts from zero, refuses pre-existing managed roles/application objects/grants/policies/memberships/default ACLs, applies Prisma migrations through the restricted identity, installs exact column grants and policies, verifies the catalog bidirectionally, and destroys failed green candidates with exact package-marked role cleanup. The generated execution report owns current policy/column counts. Foundation proof still certifies zero essential application workflows; Batch 001 therefore retains `postgresqlCertificationStatus=pending`.

## Programme counts

| Measure | Before | After |
| --- | ---: | ---: |
| Tables | 77 | 77 |
| Workflows | 428 | 428 |
| Families | 316 | 316 |
| Implemented workflows | 4 | 5 |
| Contract-only workflows | 59 | 59 |
| Blocked workflows | 365 | 364 |
| Workflows requiring runtime changes | 424 | 423 |
| PostgreSQL certifications pending | 4 | 5 |

No contract-only workflow was promoted. The new implementation remains pending the single full-system disposable PostgreSQL certification required by the authoritative plan.

Post-review authentication and scope hardening preserves all 428 workflow dispositions and the current deterministic total is 318 families. Complete MFA disablement remains its own exact multi-table, durable-audit-atomic mutation family. Private technical closures are folded into their registered functional root and cannot inflate the workflow inventory.

## Next deterministic family

`family-simple-tenant-scoped-reads-auditcontroller-627bac35ff` remains next. It should be handled only in a compatible platform-mutation batch after the exact scope, transaction propagation, delivery durability, idempotency and concurrency blockers above are implemented and tested.

## Engineering recommendations

The next implementation group should establish the smallest reusable durable-delivery and idempotency primitive already anticipated by the frozen command semantics, then apply it only to compatible platform mutations. Keep platform analytics separate: a future global risk view requires its already-frozen dedicated aggregate projection and purpose rather than widening this tenant family. At scale, preserve keyset pagination and database aggregation for analytics dimensions; do not materialize unbounded cross-tenant rows in application memory.
