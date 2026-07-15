# Full-database RLS programme architecture

## Scope and authority

This directory is the machine-readable programme authority for taking every Prisma-backed production table and active database workflow toward PostgreSQL `ENABLE ROW LEVEL SECURITY` plus `FORCE ROW LEVEL SECURITY`. It is inventory and harness foundation only. It does not authorize or implement an application authorization change, policy, RLS enablement, database mutation, AWS action, staging action, or production action.

`tables.json` owns table classification and readiness, `workflows.json` owns functional access, `runtime-identities.json` owns execution identities, and `decisions.json` owns unresolved rules. The scanners regenerate schema/access evidence while retaining human-maintained decisions and status. The shared-table apply at `documents/security/mscqr_staging_rls_shared_batch_phase_apply_2026-07-15.sql` remains blocked.

## Final database role model

- Protected tables are owned by a dedicated `NOLOGIN`, `NOSUPERUSER`, `NOBYPASSRLS` owner that runtime roles cannot reach with membership or `SET ROLE`.
- LOGIN roles are separated by authenticated application, restricted read, worker/job family, migration, staging operator, and ephemeral production break-glass purpose.
- Named authentication functions use a dedicated `NOLOGIN` owner with only exact column grants. Runtime roles never own those functions.
- No runtime or operator identity uses superuser or `BYPASSRLS`. Migration and operator authority does not imply application authority.

Exact environment role names and credential splits remain blocked by `decision-runtime-role-split`, `decision-object-ownership-chain`, and `decision-operator-administration`.

## Canonical transaction context

Authenticated database work occurs inside one transaction that validates and sets the six transaction-local settings already used by the prototype: actor/user ID, normalized role, licensee ID, organization ID, manufacturer ID, and platform-administrator boolean. Context is derived from authenticated server state, never accepted directly from request or queue payloads, and the transaction client cannot escape its callback. Missing, malformed, forged, stale, or cross-tenant context fails closed.

Command-specific assurance, column and lifecycle rules remain `decision-policy-command-semantics`. Future changes should reuse the existing transaction-context primitive after it is promoted and certified; no second context implementation is needed.

## Table categories

- `tenant-owned`: a proven direct tenant column is authoritative.
- `actor-owned`: an actor ownership column controls self-scoped access.
- `parent-inherited`: authorization follows a reviewed parent relationship.
- `platform-reference`: shared reference data requires an explicit platform visibility rule.
- `security-sensitive`: identity, credential, token, challenge, approval, or security state requires a special boundary.
- `append-only-audit`: writes append immutable evidence and ordinary runtime updates/deletes are denied.
- `operational-system`: a restricted job/system command owns the operation.
- `migration-only`: runtime receives no table command.
- `intentionally-non-rls`: permitted only with a written security justification and compensating controls.

Scanner classifications are conservative starting points. A table with unresolved ownership remains blocked by `decision-table-ownership-classification`; absence of a direct tenant column is never proof of platform-wide access.

## Policy inheritance and non-recursive parent chains

Policies use the shortest approved ownership path. Direct tenant or actor columns take precedence over parent joins. Parent-inherited policies may depend only on a reviewed acyclic dependency DAG, and policy predicates must not query a table that can reach the original table through another policy. Stable helper functions may expose validated transaction settings but must not become generic table readers. Every dependency is covered by catalog inspection, recursion/timeout tests, and `EXPLAIN` evidence.

## Pre-authentication function rules

Irreducible login, recovery, invitation, verification, refresh, MFA, and WebAuthn commands use one exact named `SECURITY DEFINER` function per command only when no authenticated context exists. Functions have typed scalar inputs/outputs, fixed `search_path=pg_catalog`, fully qualified objects, least-privilege column grants, a `NOLOGIN` owner, PUBLIC/read-role revokes, replay and concurrency tests, and generic caller responses. No function accepts arbitrary SQL, table, column, predicate, or JSON query instructions. Exact boundaries remain `decision-pre-auth-boundary`.

## Worker authorization rules

Workers and schedules do not receive global tenant bypass. They verify job identity, tenant and authorization version against durable data, establish transaction-local scope, use a restricted job-family role, and record idempotency/retry evidence. Cross-tenant aggregation or maintenance requires a separately reviewed narrow function or operator workflow. Queue payload scope alone is insufficient. The remaining design is `decision-worker-identity-model`.

## Administrator ceilings

Tenant administrators stay inside their proven tenant and assignable-role ceiling. Platform administrators do not receive blanket write predicates: each cross-tenant command requires explicit purpose, assurance, column/lifecycle rules and audit. Production break-glass is ephemeral, dual-approved, time-bound, incident-linked, non-owning and fully recorded. No administrator can set arbitrary RLS context, assume an owner, create objects, use superuser, or use `BYPASSRLS`.

## Direct Prisma migration strategy

Inventory direct calls first, then move each canonical workflow—not each technical call site—behind the approved transaction repository, pre-auth function, or restricted system boundary. Keep existing behavior while RLS remains off; characterize allowed/denied scenarios before changing callers. A static scanner prevents new unmapped access. Retire a direct path only with import, registration, replacement and test evidence. Do not add a parallel repository abstraction where the existing transaction primitive is sufficient.

## Policy generation strategy

Policies are generated only from reviewed table ownership plus reviewed workflow command contracts. Generation must be deterministic, command-specific, role-specific, dependency-ordered and fail closed on unresolved decisions. Generated SQL, rollback and catalog verification are separate review artifacts; no Prisma migration, startup path, workflow, or harness automatically executes activation SQL.

## Full-database testing strategy

1. Static tests prove exhaustive schema/access representation, stable IDs, valid references, registration evidence, blocked apply and deterministic output.
2. Unit tests characterize each workflow's allowed/denied scenarios, context construction, assurance and field/lifecycle rules.
3. Disposable PostgreSQL P2 tests run exact roles, grants, functions, policies and FORCE RLS from a clean database, covering empty/valid/forged/stale/cross-tenant context, every command equivalence class, owner/grant catalogs, recursion, timeouts, rollback and planner evidence.
4. Route/job tests prove application behavior using the disposable database. Passing mechanical SQL tests alone is not runtime proof.

## Staging activation sequence

After every blocking decision is resolved and disposable certification passes: freeze checksums; capture a no-mutation preflight; obtain separate human approval; apply through the approved staging-VPC operator path; verify catalog/roles/policies; run login, recovery, MFA, administration, tenant, print, scan, worker and schedule smoke tests; observe a canary; and capture redacted evidence. Any failure invokes the reviewed rollback and restores the stable revision before further work. The current blocked shared-table apply is not unblocked by this programme foundation.

## Production activation sequence

Require approved staging evidence, security sign-off, operational readiness, backups/restoration proof, lock/performance budgets, monitoring and rollback rehearsal. Freeze exact artifacts; use a separate human-authorized maintenance window; activate in dependency-safe phases with catalog and workflow gates after each phase; stop on any denial anomaly, leakage, recursion, latency or error-budget breach. Production approval is distinct from merge, CI and staging approval.

## Rollback principles

Rollback is deterministic, table/phase-scoped and checksum-paired with apply. It never weakens unrelated protected tables, deletes business/audit evidence, or silently grants broad access. Application compatibility must remain available before activation; rollback restores the prior reviewed role/policy state and is followed by catalog plus workflow verification. Emergency access follows the break-glass identity, never superuser or `BYPASSRLS` runtime design.

## Completion definition

The programme is complete only when every Prisma model and active production access site is represented; every table and workflow has approved ownership, command and identity rules; direct access is migrated or explicitly certified; all blocking decisions are resolved; unit and disposable PostgreSQL tests pass; generated policy/apply/rollback/verification artifacts are reviewed and deterministic; staging activation and rollback evidence passes; production approvals and monitoring are ready; and phased production activation proves FORCE RLS without authorization regression or cross-tenant disclosure.

Until then, `next-work-item.mjs` returns one compact independent item with only its canonical files, relevant architecture sections and required tests.
