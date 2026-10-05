# Startex incident remediation — work in progress

Incident: `STARtex-20261002-ROUTE-TRANSITION-500`.
Baseline and fetched protected main: `38da72c31d275182fcadec54a8be996906d5fc32`.
Integrated before publication onto protected main `7ba87409bdf44e43ad2f7d2c5c709498ac496320` (PR #612, Stage B deployment provenance only). No investigated customer/RLS call path changed in that range; generated package verification passed after rebase.
Branch: `codex/startex-incident-remediation`. Original developer checkout is untouched.

## Implemented boundaries

- Telemetry validates input, performs no persistence, and returns honest HTTP 202 / `TELEMETRY_NOT_PERSISTED`. Summary/readiness cannot report healthy telemetry when unavailable.
- Support retains bounded redacted evidence, excludes telemetry from interactive reports, and coalesces simultaneous failures with business-critical priority. Existing popup cooldown remains.
- Allocation LIST, CREATE, and REJECT have separate capability-derived database functions, bounded selectors, atomic audit, and existing hardened owner/RLS generation. APPROVE remains separate, with explicit self-approval and MFA checks. Post-commit notification failure no longer misreports a failed transaction.
- Analytics projects only tenant-scoped sanitized aggregates/events, excludes sensitive scan fields, bounds event windows to 90 days and pages to 200. Platform users select a tenant. Raw scan-table access is not granted.
- REISSUE_LIST bypasses subject resolution and sends no sentinel. Its role matrix and CREATE/REVIEW/APPROVE/EXECUTE operations are unchanged. List-row joins preserve the active tenant/batch and Licensee Admin organization checks previously supplied by subject binding. ORG_ADMIN is not added.

Historical actor and exact production printing predicate remain unknown. The source defect is independent: the versioned UUID sentinel passed validation but entered Batch lookup. No further historical log access is required for the structural repair.

## Hostile review — source findings

1. **Medium / availability:** `printingLifecycle.sql:611` reads `approvalReferenceId`, absent from the function-owner SELECT projection in `named-sql-function-contracts.mjs:905`. Added only that owner column; no runtime table grant, role expansion, or RLS weakening.
2. **Medium / error integrity:** `qrSystemRepository.ts:14` classified any PostgreSQL `42501` as expected authorization failure. Removed that broad match. Only named capability/authorization denials receive controlled 403; unexpected privilege defects remain business failures.
3. **Tenant binding:** bypassing a nonexistent list subject must not discard active-licensee/organization and batch-tenant consistency checks. Added those checks to the list projection without granting another role or tenant authority; wrong-org and inactive-tenant tests return no rows.

Review scope: changed SQL functions, generated owner privileges/policies, HTTP validation/error mapping, UI diagnostics, and their regression tests. Parameterized SQL, fixed search paths, authoritative capability binding, bounded selectors, atomic lifecycle/audit operations, and no PUBLIC/runtime table grants are retained. Runtime security conclusions require PostgreSQL certification; source review alone is not clearance to deploy.

## Fresh PR review and CI corrections

### Final intended-path audit (reviewed head 2f78eed5)

Traced the changed telemetry/support, allocation lifecycle, tracking analytics, and reissue-list paths against their existing UI callers and protected-main contracts. Manufacturer analytics now defaults to the authenticated, version-checked selection; the database still checks live links and ownership, including explicit accessible selectors and multiple linked tenants. Activity filters bind scan-event status, with latest matching-event status for totals/batches and distinct-code historical trends; inventory retains current-state filters. Allocation lists restore page-bounded requester display identity and decision-actor names/notes without runtime table access.

Additional regressions corrected: historical aggregates no longer use current inventory state or double-count one code with multiple event states; activity batch quantities retain their original scope semantics; sanitized decision badges/filters are restored inside the existing analytics capability with four display fields only; omitted sensitive scan context displays unavailable rather than incorrectly claiming anonymous context; newly projected timestamps retain UTC offsets. Decision/trust reads require the verified analytics capability, selected tenant, and current manufacturer batch ownership. No new function, runtime table grant, PUBLIC EXECUTE, role, MFA exception, or RLS bypass is introduced.

Tracking refreshes when the authenticated selected tenant changes, so switching a manufacturer's tenant cannot leave the previous selection's results on screen. Local and CI printing certification use UTC without changing application lifecycle semantics.

Final hostile-review corrections: stale tracking responses cannot overwrite a newer selection/filter result; decision enrichment is inlined into bounded latest-result lookups rather than materializing the tenant's full decision history. The explicit tenant predicate permits the existing tenant/time index to constrain those lookups. Security gates continue to deny direct decision/trust table access.

Final local gates passed: PostgreSQL 18.6 QR application-path certification (`mscqr-startex-native-proof-NYg7ju/qr-system.json`) and UTC printing certification (`mscqr-startex-native-proof-BsVI3f/printing-lifecycle.json`), both under the production-equivalent application identity with real HTTP, tenant denial, capability and lifecycle cases; 18 frontend contract/support tests; 10 focused backend test files; 12 smoke-contract tests; backend/frontend TypeScript and production frontend build; generated package/checksum verification, Prisma scope guardrails and diff whitespace checks. Evidence directories are under `/var/folders/tc/k7yqlkj13mv8ftdf0gs_yjc80000gn/T/`. These certify the affected workflow families, not every unrelated workflow in the full RLS inventory. Existing version-matched dependencies were reused; no dependency install or lockfile change was required. Original dirty checkout remains untouched; disk free is approximately 2.4 GiB.

The final intended-path/hostile review has no remaining identified P1/P2. No direct runtime table grant, PUBLIC EXECUTE, RLS/MFA weakening or ORG_ADMIN expansion was added. Release recommendation: require clean CI and fresh review on the exact pushed head, then use governed deployment and customer-path/cross-tenant production smoke; local certification alone does not close the incident. Retain bounded sanitized projections and indexed latest-decision lookups as tenant volume grows.

Regression proof is in the production-identity PostgreSQL test: omitted/explicit/multiple manufacturer selections, inaccessible/revoked selections, historical/current-state divergence across events/totals/trends/batches, attribution for create/approve/reject with notes, decision/trust projection isolation, forged context, and direct protected-table denial. Final certification and exact-head CI/review remain release gates.

PR #613 review found two genuine issues, both corrected: manufacturer reissue listings now re-check current batch ownership and tenant membership (including revoked-link/forged-context regressions), and telemetry summary outages are classified as observability, including trailing slashes and query strings. No role was added. The obsolete analytics Prisma `batch.findMany` exception was removed rather than weakening its guardrail. CI's existing database uses PostgreSQL 18.6; QR certification retains its strict major-18 assertion and no longer requires an obsolete 18.4 patch number.

After corrections, printing certification passed on PostgreSQL 18.6 UTC at `/var/folders/tc/k7yqlkj13mv8ftdf0gs_yjc80000gn/T/mscqr-startex-native-proof-lFRrfA/printing-lifecycle.json`; QR certification passed on PostgreSQL 18.6 UTC at `/var/folders/tc/k7yqlkj13mv8ftdf0gs_yjc80000gn/T/mscqr-startex-native-proof-g1ljyp/qr-system.json`. Both include actual HTTP and hostile database-identity cases. Support tests passed again. Initial PR frontend CI passed with clean locked dependencies; final-head CI/review remains required.

## Verification status

- Backend TypeScript build: passed.
- Controlled telemetry test: passed.
- Analytics repository-delegation test: passed (not security proof).
- Generated RLS package/checksum verifier: passed after review corrections (80 tables, 78 FORCE RLS targets, 372 policies).
- QR PostgreSQL 18.4 runtime identity, real HTTP allocation/analytics/telemetry, hostile selectors/GUCs, inactive/revoked capabilities, and direct-table-denial certification: passed. Evidence: `/var/folders/tc/k7yqlkj13mv8ftdf0gs_yjc80000gn/T/mscqr-startex-cert-w3nsEZ/qr-system.json`.
- Printing PostgreSQL 18.6 (UTC), full existing lifecycle regression, list roles/tenant binding, capability denials, protected-table denial, and real HTTP certification: passed. Evidence: `/var/folders/tc/k7yqlkj13mv8ftdf0gs_yjc80000gn/T/mscqr-startex-native-proof-hXJltl/printing-lifecycle.json`. Malformed request IDs receive controlled HTTP 403; no authorization rule was weakened.
- Support diagnostics: 6 tests passed. Frontend TypeScript: passed. Incomplete shared frontend packages were restored only into isolated dependencies from exact lockfile URLs with integrity checks; no dependency versions or shared installation changed. The local production build still encounters incomplete unrelated transitive packages; required CI must verify the build with a fresh locked installation.
- Authenticated smoke contract: 13 tests passed, including affected-business-5xx deployment failure and honest telemetry non-persistence. Smoke now exercises manufacturers, batches, allocation requests, analytics, print jobs, and reissue listing for Licensee Admin.
- Existing unrelated QR export-controller fixture fails because its mock omits `mutateBatch`; its controller and test are unchanged. Do not repair or disguise that baseline failure in this incident.
- Existing CI now runs both QR and printing PostgreSQL application-path certification against its existing disposable database. Required CI, fresh review, governed deployment, and production smoke remain release gates. Production has not been changed; incident remains open.

## Operational boundaries and follow-up

The historical repository reader is `scripts/aws/production-backend-log-diagnostic.mjs`, restricted to `/ecs/mscqr-backend`, recovery run `34223529621`, fixed streams, and an expiring grant. It uses DescribeLogStreams/GetLogEvents, not FilterLogEvents. It is not an authorized Startex reader; no IAM change or root-profile bypass was attempted.

Deploy only through governed Lane B for the database/security changes, then the protected application path. Require full certification, required CI/review, and tenant-authenticated production smoke before customer retest. Do not infer success from ECS health.

Separate follow-up: governed security-preparation upload-artifact digest normalization mismatch. Not changed in this incident. Recommended release hardening: certify reachable protected-table business paths and require authenticated smoke of these exact routes; do not substitute broad privileges or suppress business failures.

## Exact-head closure: a9058584 review counterexamples

### Effective client scope and immutable reason contracts

The request coordinator previously keyed only HTTP parameters, truncated keys at 240 characters and replaced punctuation. Manufacturer-derived tenants therefore shared a cache/dedup entry; long queries could also collide. The existing coordinator now includes the authenticated server projection (actor, raw role, organization, selected licensee, tenant/link versions, active state and non-secret session/assurance identity), a monotonic invalidation generation and losslessly encoded query identity. This also repairs the same affected-path defect in QR stats, batches, dashboard stats and licensee lists. Useful same-scope caching, cooldown and deduplication remain enabled.

Authoritative auth reads cannot themselves use a cached projection. AuthProvider retains its existing refresh throttle/in-flight guard. Login/logout and trusted identity changes invalidate cached and pending reads. Cross-tab messages/storage markers invalidate but never authorize: shared-cookie identity must be refreshed through `/auth/me`. HTTP 304 caching and cooldowns are scope-bound; an authorization-changing refresh cannot automatically replay a previous-scope mutation. Scope is checked after headers **and** asynchronous body parsing. Pages gate rendered data/dialogs by current scope before effects complete; sequence/generation checks suppress obsolete responses, including A→B→A, unmount/remount and StrictMode. Draft decisions are cleared before a new authenticated scope paints. Backend capability/RLS remains authoritative; no client selector grants authority.

Historical rejection details were `{decisionNote: canonicalNoteOrNull}`. Request middleware removes C0 controls (except tab/newline/carriage return), then the schema trims JavaScript whitespace and permits at most 500 UTF-16 code units. Omission is permitted; explicit HTTP null is rejected; the database's optional note is nullable. SQL now applies the same control removal/trim/UTF-16 bound and uses the same canonical value for mutation and immutable audit/outbox. Ordinary Unicode, quotes, backslashes, multiline text and HTML-like text remain inert JSON/plain text, not executable HTML. Existing code had no secret-content redaction policy for decision reasons; this change does not invent one or add authentication fields. PostgreSQL cannot represent NUL; HTTP middleware removes it before SQL. CREATE also restores its historical `{quantity,batchName}` audit details. Existing APPROVE metadata and maker/checker semantics are unchanged. No duplicate controller audit is reintroduced.

### Pass 1 — failure/concurrency injection

Machine tests cover tenant cache hits/misses, delayed/reordered responses, rapid A→B→A, failed/rate-limited B without A fallback, default/explicit manufacturer selection, Licensee Admin, platform selectors, logout and actor/role/org/link/session changes, concurrent scopes, cache expiry/revalidation, remount and StrictMode. They also test the gap between authoritative HTTP scope and React state, cookie-auth 304 reuse, and mutation replay following an identity-changing refresh.

PostgreSQL 18 tests exercise ordinary/null/empty/max-length/Unicode/quoted/control/HTML/multiline notes; invalid HTTP and database notes; exact immutable JSON; later mutable-row edits; retry/duplicate denial; explicit rollback; and injected outbox failure after audit insertion. Successful mutation/audit/outbox commit together; failure preserves neither decision nor audit. Real HTTP proves exactly one rejection event, existing approval, sanitized attribution, manufacturer defaults/multiple selected tenants, activity history, authorization denials and telemetry isolation.

### Pass 2 — fresh attacker review of the complete PR

Every attempt below is blocked by the final code and named executable regression contract; no material counterexample remains unresolved locally.

| # | Attempt | BLOCKED_BY |
| --- | --- | --- |
| 1 | Manufacturer B reads cached analytics A without a selector | scoped coordinator; `request-coordinator.test.ts` |
| 2 | Old A response wins after A→B→A | generation/state ownership + page sequence; coordinator/page tests |
| 3 | Late B overwrites current A | page scope/reference checks; rapid-switch page test |
| 4 | React paints A while trusted scope has advanced to B | scope-current render gate; projection-lag page test |
| 5 | Failed/429 B falls back to A | per-scope last-good state; coordinator/page tests |
| 6 | Primary/default manufacturer link changes but query does not | link/version identity; default-scope coordinator test |
| 7 | Platform A/B concurrent selectors dedup together | lossless query identity; concurrent platform client test |
| 8 | Logout/new user reuses previous cache or pending work | epoch + actor/session identity; coordinator/core tests |
| 9 | Role/org/active/session/link change retains privileged cached data | authenticated scope dimensions; parameterized coordinator tests |
| 10 | Long/punctuation-different queries collide | untruncated URI encoding; coordinator key test |
| 11 | Revalidation or expiry changes tenant identity | scope-bound TTL/force refresh; coordinator test |
| 12 | StrictMode or remount resurrects stale response | cleanup sequence + scope gate; page tests |
| 13 | Cookie-auth 304 returns A under B | scoped HTTP cache; core 304 test |
| 14 | Auth refresh changes actor then replays old mutation | post-refresh scope guard; core mutation-replay test |
| 15 | Forged cross-tab marker installs foreign authority | invalidate-only marker + authoritative refresh; storage-marker test |
| 16 | Foreign selector/GUC bypasses capability or ownership | actual runtime identity, live links and FORCE RLS; QR PostgreSQL tests |
| 17 | Raw control/quoted/script-like reason changes audit structure | shared canonicalization + JSONB construction; note matrix |
| 18 | Later mutable reason edit erases decision history | original immutable event; PostgreSQL edit-after-rejection tests |
| 19 | Outbox failure leaves unaudited rejected state | one SQL transaction; injected failure/rollback tests |
| 20 | Retry or controller duplicates rejection audit | lifecycle lock/state denial, SQL-only audit; real HTTP and SQL counts |
| 21 | Maker rejects/approves own request or loses MFA | existing separated roles/MFA; QR PostgreSQL lifecycle denials |
| 22 | Anonymous/inactive/wrong-org/expired/revoked actor reads tenant data | authenticated capability and live actor binding; PostgreSQL denials |
| 23 | Telemetry suppression hides real QR/printing business failures | narrow classification; support and telemetry tests |
| 24 | Subject-free reissue listing widens printing role/tenant scope | unchanged role matrix + list ownership predicates; printing PostgreSQL tests |

### Final local evidence and release boundary

QR and printing clean-room PostgreSQL 18.6 UTC certification both passed under the production-equivalent runtime identity. QR evidence contract hash: `07673b057575f357f57ebe460ae3952f596a7e3fd3e93b0a8dd3a1c141f7c083`. Frontend/API/auth/support: 49 tests passed; focused backend auth/tenant/printing/QR/CSRF/telemetry/security suites passed; generated RLS/capability contracts: 24 tests passed. These local results supersede the earlier incomplete-dependency/build observations above; dependencies/versions/lockfiles were not changed for this correction.

Recommendation: retain these invariant regressions in required CI and require fresh review of the exact published head. Bounded caching/pagination remain the scaling mechanism; no new infrastructure is warranted. This phase authorizes only updating PR #613 and requesting review: **no merge, AWS mutation, production database/RLS execution or deployment**. Local certification is not production incident closure.

## Protected-main integration for production release

Integrated current protected main `043a284e6937b3cc035c4a18a6bacd00589f475b` into the published PR #613 branch in an isolated worktree. All thirteen conflicts were derived RLS SQL/manifests and were regenerated from the combined canonical sources. No #622 AWS executor, IAM policy, release workflow, application dependency or Dockerfile was replaced.

The four new QR repository operations are attributed to their exact registered HTTP controllers. Removed telemetry database access is also removed from the active platform read contract and blocked read batch; the endpoint continues to return truthful non-persistence without a table grant. Source scanning proves 327 workflows and 207 context families. Session B retains its exact existing workflow-set digest; the QR repository remains Session C-owned while its registered QR callers retain Session A lifecycle classification. All associated inventories, partition outputs, call-path evidence and sealed SQL/checksums are generated, not patched by hand.

Production acceptance still requires governed database installation, exact application image/service cutover and tenant-authenticated smoke of the QR request/allocation/tracking paths. Local certification and healthy ECS alone do not prove the customer workflow is deployed. Retain the existing cross-tenant, lifecycle and scope-switching tests as required release checks.

### Integrated candidate validation

The integrated tree passes all 295 frontend tests, the complete backend/source release verification, 38 inventory/partition tests, 24 sealed RLS package tests, 187 ownership/generic-release/security contracts and 567 focused Stage-B contracts. PostgreSQL 18 UTC clean-room certification independently proves the QR and printing application paths, including cross-tenant/capability denials and lifecycle/audit rollback. The generated source-contract hash is `66571358d685fe45344666d4df8ad19cc8272c5aeb768a7d46cc1c3420755867`; the sealed package-checksum hash is `8bad35fb96eb02437a37d74b2622c7dc46c712dda19636cbf583688ebd52258c`. Workflow YAML and the capability graph pass.

Fresh canonical browser closure and instrumented frontend compilation confirm braces 3.0.3 executes only against the same four repository-controlled Tailwind content globs; it is absent from browser/backend/worker/server runtime. The HIGH unpatched finding remains visible. The unchanged broad boundary changes from `c167232b2b892236c60cbcd761880cdebc1d0cf4344611cb0a708866a0cf94af` to `c61066acbc87e783f191afc61f9d739b00002a2f17417d6c2a5d4c350f0059d8`, covering 46 changed inputs. The security owner explicitly authorized this exact hash-only rebinding after validation. All other acceptance fields, including rationale, owner, advisory/version, non-runtime conclusion, scope and expiry, remain byte-for-byte semantically unchanged. The canonical runtime gate must pass before push.

Final review found zero valid unresolved security/correctness findings. The complete Stage-B invocation passed 1,304/1,305; its Git-cloning CLI fixture initially cloned the old pre-merge HEAD and correctly rejected a backwards fixture fetch. That unchanged fixture then passed both tests against an isolated integrated Git snapshot, covering all 1,305 Stage-B cases without changing an assertion or production code. The exact final worktree secret-diff scan passes all 75 changed files; the fixture guard passes 1,541 files and OSV policy contracts pass 89/89. The known unchanged workflow-delegation baseline assertion remains out of scope. Before the separately authorized hash-only rebind, no candidate was pushed, acceptance changed, production execution performed or MFA consumed.

The exact authorized hash-only rebind passes the canonical OSV runtime gate: one visible HIGH unpatched braces finding, 204 authenticated browser packages, unchanged non-runtime acceptance and expiry 2026-11-02. After rebinding, all 89 OSV/security policy tests and 23 artifact-contract tests pass; the capability graph and dependency closure report zero violations.

## Exact-head P2 corrections

Tracking analytics now retains the existing non-sensitive `isTrustedOwnerContext` and `scanCount` contract through canonical SQL, generated SQL, the backend JSON response and TrackingWorkspace. Missing owner/count/sequence values render as unknown/unavailable; they cannot assert External, zero or a repeat scan. Tenant predicates and sensitive-field exclusions remain unchanged. Sibling scan reporting already supplies these fields; aggregate/inventory projections are not individual scan rows.

CREATE and REJECT are the only audit producers newly moved into SQL by this PR. Their business mutation, single AuditLog fact and complete B03 SecurityEventOutbox processing source remain in one database transaction. The shared QR helper now calls the existing scoped B03 enqueue function instead of inserting an incomplete, unclaimable outbox row. The existing SIEM consumer validates payload digest and actor/tenant metadata before projecting these two actions to the existing Redis audit stream and four existing cache namespaces. Redis failure retains the outbox retry path. Audit-ID deduplication protects active subscribers and the frontend feed; cache version bumps are safely repeatable. Delivery remains at least once, not an exactly-once network guarantee.

| Side effect | Previous application path | Corrected atomic SQL path |
| --- | --- | --- |
| AuditLog | One application insert | One transactional SQL insert |
| SIEM source | Existing enqueue | Same scoped B03 enqueue, with digest, request, idempotency and expiry bindings |
| Forensic/trace | CREATE/REJECT map to no event | Same classification; no invented chain append |
| Audit stream | Local/Redis publish | Existing durable outbox consumer publishes, audit-ID deduplicated |
| Cache invalidation | Four namespace version bumps | Same four bumps before successful outbox completion |

Sibling APPROVE, allocation and bulk-delete SQL audit producers already existed on protected main; this PR did not replace their application audit paths. They share the corrected canonical enqueue metadata but do not gain a new forensic classification. Read/list/tracking and non-persisted telemetry operations add no audit producer.

Production verification must authenticate a worker artifact containing this consumer correction, the installed canonical SQL and a tenant-scoped stream/cache smoke. Retaining an old worker alone is not proof of the new downstream processing. Local tests prove CREATE and REJECT rollback when the durable outbox insert fails, single audit/outbox facts, uncertain stream-response replay, tenant/digest substitution rejection, truthful tracking and existing forensic no-event classification. No production mutation was performed. Recommendation: keep these regressions in required CI and verify the worker consumer identity during the governed release; no additional queue, role or event framework is needed.

Final P2 validation: full source-release verification passes (296 frontend tests plus complete backend checks); tracking regressions pass 8/8; durable audit/replay and tenant-stream tests pass 3/3; Stage-B passes 1,305/1,305; inventory/partition passes 38/38; sealed RLS passes 24/24; artifact contracts pass 23/23; OSV/security policy tests pass 89/89. PostgreSQL 18 QR clean-room certification passes with CREATE/REJECT outbox-failure rollback, exact single audit facts, truthful tracking and tenant/capability negatives. Workflow YAML and capability graph pass. Hostile review has no valid unresolved finding.

The unchanged broad OSV boundary now hashes to `d76560e2f9c7da7c597a9b46f3e8f24f69dfaf7ff2c7fd34c63855d21f5f4c6a`, covering sixteen changed executable inputs since the reviewed head. The canonical runtime gate rejects only the prior `c61066acbc87e783f191afc61f9d739b00002a2f17417d6c2a5d4c350f0059d8` binding after its fresh browser build. The affected finding remains visible, the expiry remains 2026-11-02, and no acceptance field has been changed. This correction remains local pending exact security-owner FROM→TO authorization; no commit or push was performed for it.

## Complete CREATE/REJECT audit contract parity

The bounded old/new audit comparison additionally identified organization attribution: the old application audit derived `orgId` from the target licensee, not the acting platform administrator. Both atomic operations now use the target organization independently authenticated by `qr_bind_actor`. Action, entity, entity ID, actor, tenant, canonical details and UTC timestamps remain unchanged in meaning. CREATE/REJECT remain the only application-audit producers migrated by this PR; existing forensic and trace classifiers still return no event for either action.

The existing server-side `hashIp(req.ip)` supplies the existing keyed/versioned fingerprint to the scoped repository function. The controller's strict schema rejects client IP/hash fields; no raw IP enters SQL or the durable event. `req.ip` continues to come from the existing trusted-client-IP middleware, with generic Express proxy trust disabled. Missing legitimate IP remains null. The fingerprint, correct tenant/organization, business mutation, single AuditLog fact and authenticated B03 outbox source commit together.

Internal allocation audit processing no longer depends on optional external SIEM activation. Existing outbox fields carry a bounded `projection:<row-id>` receipt after stream/cache processing; webhook failure retains it so a delivery retry skips those projections. A disabled external sink finishes as `FAILED` with `lastError=SIEM_SINK_DISABLED`, `sinkEventId=disabled:<row-id>` and null `sentAt`. Claiming excludes that explicit terminal disabled outcome; it cannot busy-retry or masquerade as an external `SENT` receipt. Enabled delivery retains its existing sink identity, webhook idempotency key, retry and `SENT` semantics. No schema migration, new queue or role is needed.

The interval between external stream/cache effects and their durable projection marker remains at least once: uncertain responses can repeat cache invalidation safely, while subscribers/frontend deduplicate by stable audit ID. Once the marker exists, external-delivery retries perform neither projection again. No exactly-once network guarantee is claimed. The canonical lease, digest, expiry and worker authority remain enforced, including terminal marker replay and denial of false external completion before required internal processing.

Recommendation: retain no-webhook, enabled-webhook retry, client-attribution rejection and real PostgreSQL outbox-state regressions in required CI. Production acceptance must still authenticate the installed SQL and worker consumer artifact; local proof grants no production execution authority.

Final audit-parity validation: focused projection/tenant-stream/rollback-signature coverage passes 5/5; complete source-release verification passes, including 296 frontend tests and complete backend checks; Stage-B passes 1,305/1,305; artifact contracts pass 23/23; sealed RLS passes 24/24; security policy passes 89/89; inventory/partition passes 38/38. Both QR-system and B03 durable-outbox PostgreSQL 18 certifications authenticate the same final sealed package, with zero disposable database/role residue and unchanged blue fingerprint. CREATE and REJECT retain keyed IP/target-organization attribution, atomic audit/outbox rollback, tenant denial, and optional-SIEM/internal-projection independence. The final hostile review also corrected and regression-tested the three rollback function signatures affected by the new hash argument; no valid unresolved finding remains. Acceptance is unchanged pending one exact final reviewed-input authorization. No commit, push, production execution or AWS mutation occurred.

## Allocation-role and analytics-page corrections

Protected-main history permitted ORG_ADMIN allocation requests; frontend normalization still renders that role as a licensee administrator. The current B01 actor/refresh and operational-read boundaries independently bind ORG_ADMIN to its live User licensee and matching organization, with no arbitrary tenant switching. This correction reuses that exact authority for allocation list/create only, including MFA assurance, the scoped repository call and purpose-bound owner RLS. Other QR capabilities, approvals/rejections and direct-table access remain denied to ORG_ADMIN. The schema permits one licensee per organization; PostgreSQL regression fixtures cover foreign licensees/organizations, forged request/GUC scope, mismatched live associations and positive default authenticated context.

Analytics now selects its batch page by descending creation time and ascending batch ID before LIMIT/OFFSET, then uses the same order inside the JSON aggregate. A focused sibling check also made the scan-event aggregate explicitly retain its existing descending timestamp/ID page order. Five immutable local fixture batches/events exceed a two-row page with UUID and time order deliberately opposed, including equal timestamps, overlapping offsets, correct counts and attached decisions. No frontend pagination or release-framework change is required. Recommendation: retain these exact positive/negative scope and pagination regressions in the existing PostgreSQL 18 certification gate. No production mutation is authorized by this local correction.

Final role/order validation passes: PostgreSQL 18 QR clean-room application certification authenticates the final sealed package, including ORG_ADMIN own-scope HTTP/SQL positives, cross-organization/licensee and forged-scope negatives, mismatched live membership/MFA denials, and five-row recency/event pages with deterministic ties/offsets and correctly attached decisions/counts. Full source-release verification passes, frontend passes 296/296, Stage-B 1,305/1,305, focused audit/tracking 6/6, inventory/partition 38/38, sealed RLS 24/24, artifact contracts 23/23 and security policy 89/89. Capability graph and 95 workflow YAML files validate. The focused hostile review has zero valid unresolved findings; acceptance semantics remain unchanged pending exact final hash authorization. No push or production mutation has occurred for this correction.
