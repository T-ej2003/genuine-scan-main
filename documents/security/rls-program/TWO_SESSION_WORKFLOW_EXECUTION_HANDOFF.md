# Full RLS two-session execution handoff

Date: 2026-07-20 (Europe/London)

## Frozen foundation

- Final foundation commit: `061b3134ba89db84e0564b893e920a2601c14452`
- Certified source contract: `2c1d2c305b7f788d56ac78a231597285cceaf1dae399302f090c4a6fa110319f`
- PostgreSQL 18 foundation result: 75/75 FORCE RLS tables certified; workflow application-path result remains honestly 0/428 until the implementation waves complete.
- Deployment model: fresh green database only. Current staging and production databases remain untouched blue rollback targets.

The exhaustive source of truth is `workflow-two-session-partition.json`. Exact per-session workflow IDs and editable production files are in `workflow-ownership-session-a.json` and `workflow-ownership-session-b.json`.

Machine validation proves:

- authoritative workflow IDs: 428;
- assignment rows: 428;
- unique assigned IDs: 428;
- missing IDs: 0;
- duplicate IDs: 0;
- unknown IDs: 0;
- generic catch-all assignments: 0;
- editable production-file overlap: 0.

Run the proof with:

```sh
npm run rls:partition-check
```

## Session boundaries

Session A is the sole integration owner. It owns 284 workflows and exclusively owns all authoritative manifests, generators, generated SQL, checksums, certification harness/evidence, Prisma schema/migrations, staging infrastructure, integration, activation and rollback. Its local PostgreSQL 18 namespace is `mscqr_rls_wave_a_integration`.

Session B owns 144 workflows across auth/account security, public/proof/support, and workers/scheduled/outbox/delivery. Its local PostgreSQL 18 namespace is `mscqr_rls_wave_b_auth_public_workers`. The exact 76 editable production files and 47 existing test files are machine-listed in `workflow-ownership-session-b.json`; it may also create files only under the namespaced paths declared there.

The following cross-domain files are Session A integration seams and Session B must not edit them:

- `backend/src/controllers/incidentController.ts`
- `backend/src/services/compliancePackService.ts`
- `backend/src/services/governanceService.ts`
- `backend/src/services/replacementChainService.ts`

Session B owns `backend/src/middleware/auth.ts`; Session A must not edit it before Session B integration. For any B workflow requiring an A-owned seam, Session B implements the transaction-only repository/function/test boundary in a B-owned file and records the exact requested integration change in its wave-local result manifest. Session A applies and certifies that thin seam during sequential integration.

## Worktree and branch

The reproducible creation commands are:

```sh
cd /Users/abhiramteja/Downloads/genuine-scan-main
git worktree add -b rls-wave-auth-public-workers /Users/abhiramteja/Downloads/genuine-scan-rls-auth 061b3134ba89db84e0564b893e920a2601c14452
```

After Session A commits this partition contract, fast-forward the still-clean Session B branch to that coordination commit before implementation. This preserves the certified foundation as the branch point while making the read-only ownership files and validator available in both worktrees.

Session B database setup must use a dedicated PostgreSQL 18 database named exactly:

```text
mscqr_rls_wave_b_auth_public_workers
```

It must never use `mscqr_rls_wave_a_integration`, a staging endpoint, or a production endpoint. Warm local infrastructure is allowed for focused loops; the wave gate must start from a fresh database/container.

## Exact Session B prompt

```text
You are Session B for the MSCQR full-database RLS programme.

Worktree:
/Users/abhiramteja/Downloads/genuine-scan-rls-auth

Branch:
rls-wave-auth-public-workers

Certified foundation branch point:
061b3134ba89db84e0564b893e920a2601c14452

Authoritative ownership contract:
documents/security/rls-program/workflow-ownership-session-b.json

Partition validator:
npm run rls:partition-check

Diff ownership validator after recording the coordination start SHA:
npm run rls:session-b-ownership-check -- --base <session-b-start-sha>

Local PostgreSQL 18 database namespace:
mscqr_rls_wave_b_auth_public_workers

Implement and application-path certify every one of the 144 workflow IDs in your ownership file. The wave covers authentication, pre-authentication, sessions, MFA/WebAuthn, invitations, password reset, email verification, actor-owned account security, public raw/signed QR verification, proof-bound public status, customer trust/ownership, support/intake, workers, scheduled jobs, durable outbox and delivery.

Preserve every existing route, actor, response, error, sorting, filtering, pagination, lifecycle, audit, notification, idempotency and concurrency behavior. Do not disable a supported workflow, add a blanket 503, trust role/JWT strings as authority, use global Prisma inside a protected transaction, broaden columns, or classify difficulty as product prohibition.

Edit only productionFiles and existingTestFiles listed in workflow-ownership-session-b.json, plus its allowedNewPathRules. Do not edit the four integrationOwnerOnlyFiles. Do not edit any forbiddenGlobalPathRules: global manifests, partition files, generators, generated SQL, checksums, certification harness/evidence, Prisma schema/migrations, staging infrastructure or programme-wide evidence are Session A-only.

Before the first edit, record `git rev-parse HEAD` as the Session B coordination start SHA. Run `npm run rls:session-b-ownership-check -- --base <that-sha>` after each family and before commit; it must report zero unauthorized files and zero deletions/renames.

For an owned workflow that reaches an integrationOwnerOnlyFile, implement the exact repository/function/test boundary in a B-owned file and add an integration request to documents/security/rls-program/waves/session-b-auth-public-workers-result.json. Include the target symbol, required call shape, transaction ordering, security invariant, expected response preservation and focused test that Session A must run. Do not patch the A-owned file.

For each workflow prove the production root and full call chain, database-revalidated actor and scope, assurance and purpose, exact columns, blank/foreign/stale denial, same-transaction protected access, compare-and-set concurrency, deterministic replay/idempotency, immutable attribution and atomic outbox effects. Use actual application paths and registered worker/scheduler paths.

Use tiered validation: focused build/unit/static checks after edits; focused PostgreSQL 18 application-path and negative tests after each family; then a fresh-database wave gate. Keep a warm local PostgreSQL 18 database only for focused loops. Do not run or regenerate the global full-RLS package.

At the completed wave gate, run one standardized independent read-only review of the complete Session B diff. Findings must state severity, file/line, executable exploit or regression path, violated frozen contract, required correction and checkpoint-blocking status. Fix every real P0-P2 finding and perform only a focused re-review of those fixes unless they redesign the authorization architecture.

Write documents/security/rls-program/waves/session-b-auth-public-workers-result.json with: foundation SHA, branch head SHA, all 144 workflow IDs and final local status, changed files, application-path proofs, positive/negative PostgreSQL results, fresh database identity, review findings/fixes, requested Session A integration changes, requested global manifest changes, unresolved blockers, and confirmation that no staging/production endpoint or global artifact was touched.

Commit the completed, tested and reviewed wave on rls-wave-auth-public-workers. Report the commit SHA and exact merge prerequisites to Session A. Do not merge, regenerate global artifacts, touch staging, or wait for Session A-owned workflows.
```

## Integration order

Session A continues its own workflow families immediately. Session B is integrated only after its branch is committed, focused tests and fresh PostgreSQL 18 wave gate are green, its one wave review has zero unresolved P0-P2 findings, and its result manifest accounts for all 144 IDs. Session A then applies any recorded thin seam/global requests, merges once, regenerates the authoritative package, and runs the integration certification gate.

## CTO recommendations

1. Enforce the ownership JSON in CI against the Session B diff so forbidden global or A-owned paths cannot enter review accidentally.
2. Keep Session B's database credentials and container name distinct from Session A's, and include the database identity in every PostgreSQL evidence row.
3. Require query-plan and pool-saturation evidence for auth hydration, public verification hot paths and worker claim loops before staging; correctness alone is not a scalability gate.
4. Add durable delivery lag, lease-contention and dead-letter metrics while implementing B03 so operational regressions are visible before traffic reaches green.
