# Full RLS three-session execution handoff

Date: 2026-07-21 (Europe/London)

## Coordination checkpoint

- Risk-analytics application-path checkpoint: `33cbe7ff019efefad242f654f0aa96c44c5b963c`
- Authoritative workflows at partition time: 428
- Session A: 177 workflows
- Session B: 144 workflows, unchanged from the accepted two-session partition
- Session C: 107 workflows
- Missing, duplicate, unknown and generic catch-all assignments: zero
- Editable production-file overlap: zero
- Editable test-file overlap: zero
- Current staging and production databases remain untouched.

The machine source of truth is `workflow-three-session-partition.json`. Exact workflow IDs, workflow families, editable production files and permitted existing tests are in `workflow-ownership-session-a.json`, `workflow-ownership-session-b.json` and `workflow-ownership-session-c.json`.

Session B ownership is sealed by workflow-set SHA-256 `116815209a0a591ff122a0a7bac9a5958cfa4182742c8483d039261c7ba4e79a`. Repartitioning did not transfer any Session B workflow.

## Session C scope

Session C owns four coherent families:

1. `c-01-administration-general-mutations`: 8 workflows.
2. `c-02-audit-fraud-trace-alerts`: 17 workflows.
3. `c-03-governance-policies-incidents-compliance`: 55 workflows.
4. `c-04-operator-recovery-startup-migration-cli`: 27 workflows.

The programme integration runner remains Session A-owned even though it is a CLI root. Authentication/public/worker workflows remain Session B-owned. Printing-specific recovery remains with Session A's printing lifecycle family; account recovery remains with Session B's auth family. This keeps each state machine with its existing business owner instead of splitting shared lifecycle code.

Session C may edit exactly 39 existing production files and 21 existing test files listed in its ownership JSON. It may create files only under its declared namespaced paths. Its local PostgreSQL 18 database is:

```text
mscqr_rls_wave_c_admin_governance_operator
```

## Mixed-file ownership

Session A exclusively edits:

- `backend/src/lib/canonicalDbContext.ts`
- `backend/src/routes/index.ts`
- `backend/src/services/replacementChainService.ts`

Session B exclusively edits:

- `backend/src/middleware/auth.ts`

Session C exclusively edits:

- `backend/src/controllers/incidentController.ts`
- `backend/src/controllers/licenseeController.ts`
- `backend/src/controllers/tracePolicyController.ts`
- `backend/src/controllers/userController.ts`
- `backend/src/services/compliancePackService.ts`
- `backend/src/services/governanceService.ts`
- `backend/src/services/manufacturerScopeService.ts`

If a workflow needs a seam in another session's file, implement the transaction-only repository or function in an owned file and record the exact seam request in the wave-local result manifest. Do not cross the ownership boundary.

## Worktree contract

Planned worktree and branch:

```text
/Users/abhiramteja/Downloads/genuine-scan-rls-admin
rls-wave-admin-governance-operator
```

Create them only after the coordination artifacts are committed. The worktree must start from that clean coordination commit, whose parent includes `33cbe7f`:

```sh
cd /Users/abhiramteja/Downloads/genuine-scan-main
SESSION_C_COORDINATION_SHA=$(git rev-parse HEAD)
git merge-base --is-ancestor 33cbe7ff019efefad242f654f0aa96c44c5b963c "$SESSION_C_COORDINATION_SHA"
git worktree add -b rls-wave-admin-governance-operator /Users/abhiramteja/Downloads/genuine-scan-rls-admin "$SESSION_C_COORDINATION_SHA"
```

## Exact Session C prompt

```text
You are Session C for the MSCQR clean-room full-database RLS programme.

Worktree:
/Users/abhiramteja/Downloads/genuine-scan-rls-admin

Branch:
rls-wave-admin-governance-operator

Required base ancestor:
33cbe7ff019efefad242f654f0aa96c44c5b963c

At startup, record `git rev-parse HEAD` as the Session C coordination SHA. It must be the clean coordination commit containing workflow-three-session-partition.json and workflow-ownership-session-c.json.

Authoritative ownership contract:
documents/security/rls-program/workflow-ownership-session-c.json

Partition evidence:
documents/security/rls-program/workflow-three-session-partition.json

Diff ownership check:
node scripts/rls/check-session-b-file-ownership.mjs --session session-c --base <session-c-coordination-sha>

Local PostgreSQL 18 database namespace:
mscqr_rls_wave_c_admin_governance_operator

Implement and application-path certify all 107 assigned workflow IDs. The four exact families are administration/general mutations; audit/fraud/trace/alerts; governance/policies/incidents/compliance; and operator/recovery/startup/migration/CLI. The system-integration runner is not yours.

Before editing a family, write and maintain a short checklist in documents/security/rls-program/waves/session-c/: production root and full call chain read; frozen contracts read; current tests read; schema fields verified; database accesses and transaction boundaries mapped; shared dependencies identified; owned files confirmed; positive and negative evidence planned.

Edit only productionFiles and existingTestFiles in workflow-ownership-session-c.json plus allowedNewPathRules. Do not edit prohibitedSharedFiles or integrationOwnerOnlyFiles. Do not edit global workflows/command semantics/context-family manifests, partition files, generators, generated SQL/evidence, checksums, full certification harness, Prisma schema/migrations, staging infrastructure or programme-wide evidence. Record requested global or integration-owner changes in documents/security/rls-program/waves/session-c-admin-governance-operator-result.json.

Preserve routes, methods, supported actors, response schemas, legitimate platform/tenant/operator capabilities, errors where not security-sensitive, filtering, sorting, pagination, lifecycle transitions, aggregates, audit, delivery, idempotency and concurrency. Do not disable supported workflows, add blanket 503s, trust role/JWT strings as authority, use global Prisma inside protected transactions, broaden projections, or turn implementation difficulty into product prohibition.

Make coherent family-level changes after reading the complete call chain. Reuse existing proven context, transaction, validation, compare-and-set, attribution and outbox primitives only where their semantics match. Avoid unrelated refactors and duplicated authorization logic. Establish the root cause of a failed test before changing code again.

For each completed workflow prove the actual registered application/operator/CLI path; database-revalidated actor and scope; required assurance and purpose; exact columns; blank, malformed, foreign and stale denial; same-transaction protected access; database-enforced concurrency; deterministic replay/idempotency; immutable attribution; atomic outbox effects; and serialization only after commit.

During implementation run only changed-code syntax/type checks, focused family tests and the smallest focused PostgreSQL 18 application-path gate. Keep one local database warm for iteration. At each coherent family boundary run its focused positive/negative application-path tests and smallest relevant PostgreSQL gate. Do not run global generators, checksums, document gates, the full backend suite or the 75-table certification.

Perform one direct self-inspection of the staged Session C diff while working. When all 107 dispositions and focused proofs are ready, run one complete Session C wave gate and one standardized independent read-only review. Each finding must include severity, file/line, executable exploit or regression path, violated frozen contract, required correction and whether it blocks. Fix every real P0-P2 issue, perform only a focused re-review of materially changed security boundaries, rerun affected tests, and rerun the Session C wave gate once. Record P3 cleanup separately.

Before committing, the ownership check must report zero unauthorized files and zero deletions/renames. The result manifest must contain the base and branch-head SHAs, all 107 workflow IDs and dispositions, changed files, database identity, positive/negative application-path results, concurrency/replay results where applicable, review findings/fixes, requested Session A seams/global changes, unresolved blockers, and confirmation that no staging/production endpoint or global artifact was touched.

Commit the complete tested and reviewed Session C wave on rls-wave-admin-governance-operator. Report the commit SHA and merge prerequisites to Session A. Do not merge, regenerate global artifacts, touch staging/production, or wait for Session A.
```

## Session A integration rule

Session A continues its 177 workflows while Sessions B and C operate. It integrates a session branch only after that branch is committed, its exact ownership check and fresh PostgreSQL wave gate are green, one wave review has no unresolved P0-P2 findings, and its result manifest accounts for every assigned workflow. Session A applies requested thin seams, merges sequentially, and alone regenerates global artifacts and runs full 75-table certification.

## CTO recommendations

1. Enforce both isolated-session ownership JSON files in CI before accepting either branch.
2. Add per-wave query-plan, lock-wait and pool-saturation budgets; administration and incident bursts must not starve authentication or public verification.
3. Require immutable operator correlation IDs and durable outbox lag metrics before green traffic so recovery and compliance actions remain observable under retry.
4. Keep Session C's database role and container names unique and include both in every PostgreSQL evidence record.
