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
