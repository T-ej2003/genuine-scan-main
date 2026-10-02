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
