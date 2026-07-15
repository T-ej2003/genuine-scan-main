# Full-database RLS programme architecture

## Scope and authority

This directory is the machine-readable programme authority for taking every Prisma-backed production table and active database workflow toward PostgreSQL `ENABLE ROW LEVEL SECURITY` plus `FORCE ROW LEVEL SECURITY`. It is inventory and harness foundation only. It does not authorize or implement an application authorization change, policy, RLS enablement, database mutation, AWS action, staging action, or production action.

`tables.json` owns table classification and readiness, `workflows.json` owns functional access, `runtime-identities.json` owns execution identities, and `decisions.json` owns unresolved rules. The scanners regenerate schema/access evidence while retaining human-maintained decisions and status. The shared-table apply at `documents/security/mscqr_staging_rls_shared_batch_phase_apply_2026-07-15.sql` remains blocked.

## Final database role model

`decision-runtime-role-split` is resolved. Development uses `mscqr_dev_*`, staging uses `mscqr_staging_*`, and production uses `mscqr_prod_*`. Every applicable LOGIN identity has a distinct credential source per environment. Protected tables are owned by `*_owner`; approved authentication functions are owned by `*_auth_owner`. Both owners are `NOLOGIN`, `NOSUPERUSER`, and `NOBYPASSRLS`, and no runtime, migration, or operator role has membership in or a `SET ROLE` path to either owner.

| Logical identity | Environment role-name pattern | Login | Permitted schemas | Command classes | Ownership | SET ROLE | CREATE | SECURITY DEFINER execution | Credential source | Rotation expectation |
|---|---|---|---|---|---|---|---|---|---|---|
| Authenticated application | `mscqr_{dev,staging,prod}_app` | LOGIN | `public`, `app_rls` | CONNECT, USAGE, workflow-generated table commands, authenticated helpers | None | No | No | Approved authenticated helper signatures only | Dedicated app secret per environment | Managed rotation and immediate exposure rotation |
| Restricted read | `mscqr_{dev,staging,prod}_rls_read` | LOGIN | `public`, `app_rls` | CONNECT, USAGE, approved SELECT, pure context helpers | None | No | No | Pure transaction-context helpers only | Dedicated read secret per environment | Managed independently from app/operator credentials |
| Pre-authentication executor | `mscqr_{dev,staging,prod}_preauth` | LOGIN | `app_auth` only | CONNECT, USAGE, EXECUTE on exact signatures | None; no table grants | No | No | Exact named `app_auth` functions only | Dedicated pre-auth secret per environment | Managed independently; never shared with app/worker/migration |
| Worker | `mscqr_{dev,staging,prod}_worker` | LOGIN | `public`, `app_rls` | CONNECT, USAGE, workflow-generated commands and worker helpers | None | No | No | Approved worker signatures only | Dedicated worker secret per environment | Managed independently from scheduled/app credentials |
| Scheduled job | `mscqr_{dev,staging,prod}_scheduled` | LOGIN | `public`, `app_rls` | CONNECT, USAGE, schedule-generated commands and helpers | None | No | No | Approved scheduled signatures only | Dedicated scheduled secret per environment | Managed independently from worker/app credentials |
| Migration | `mscqr_{dev,staging,prod}_migration` | LOGIN | Reviewed deployment schemas | CONNECT, USAGE, reviewed DDL, mandatory ownership transfer | No enduring protected-object ownership | No | Approved deployment only | None | Dedicated deployment secret per environment | Deployment-only retrieval and managed rotation |
| Table owner | `mscqr_{dev,staging,prod}_owner` | NOLOGIN | `public` | Protected table/policy ownership | Protected tables and policies | No | No | None | None | Not applicable |
| Authentication-function owner | `mscqr_{dev,staging,prod}_auth_owner` | NOLOGIN | `app_auth`, `pg_catalog` | Function/schema ownership and exact required column privileges | `app_auth` and approved functions only; no application tables | No | No | Owns functions; never executes as a runtime identity | None | Not applicable |
| Operator administration | `mscqr_{dev,staging,prod}_operator` | Broker-controlled LOGIN | Approved schemas only | Broker command allowlist and temporary narrow grants | None | No | No | Approved operator signatures only | Ephemeral broker credential per environment | Automatic expiry and revocation after each operation |
| Production break-glass | `mscqr_prod_breakglass_<incident>_<nonce>` or equivalent temporary grant | Ephemeral LOGIN only | Incident-approved only | Incident command allowlist only | None | No | No | Incident-approved exact signatures only | Broker-issued after dual approval and strong MFA; no standing credential | Hard expiry plus automatic revocation on completion or failure |

The break-glass name is a creation pattern, not a standing reusable role. Issuance requires dual approval, strong MFA, an incident/ticket, explicit expiry, an exact command allowlist, an immutable audit transcript, and automatic revocation. Development and staging do not define a production break-glass identity; they use their broker-controlled operator roles.

Migration may perform required DDL only through an explicitly approved deployment and ownership-transfer process. It must transfer protected tables and policies to `*_owner`, and approved `app_auth` objects to `*_auth_owner`, before the deployment is complete. Migration and operator authority never implies application authority. `decision-object-ownership-chain` and `decision-operator-administration` remain open for the exact transfer and broker implementation; they do not reopen the resolved identity split.

## Canonical transaction context

Authenticated database work occurs inside one transaction that validates and sets the six transaction-local settings already used by the prototype: actor/user ID, normalized role, licensee ID, organization ID, manufacturer ID, and platform-administrator boolean. Context is derived from authenticated server state, never accepted directly from request or queue payloads, and the transaction client cannot escape its callback. Missing, malformed, forged, stale, or cross-tenant context fails closed.

Command-specific assurance, column and lifecycle rules remain `decision-policy-command-semantics`. Future changes should reuse the existing transaction-context primitive after it is promoted and certified; no second context implementation is needed.

## Table categories

- `tenant-root`: the top-level tenant boundary. `Organization.id` is canonical; ordinary tenant actors cannot create or delete roots.
- `tenant-owned`: a proven direct tenant column is authoritative.
- `actor-owned`: an actor ownership column controls self-scoped access.
- `parent-inherited`: authorization follows a reviewed parent relationship.
- `platform-reference`: shared reference data requires an explicit platform visibility rule.
- `security-sensitive`: identity, credential, token, challenge, approval, or security state requires a special boundary.
- `append-only-audit`: writes append immutable evidence and ordinary runtime updates/deletes are denied.
- `operational-system`: a restricted job/system command owns the operation.
- `migration-only`: runtime receives no table command.
- `intentionally-non-rls`: permitted only with a written security justification and compensating controls.

`decision-table-ownership-classification` is resolved. The deterministic catalogue contains 1 tenant root, 10 tenant-owned, 2 actor-owned, 15 parent-inherited, 27 security-sensitive, 11 append-only audit, 9 operational-system, 2 migration-only, 0 platform-reference, and 0 intentionally non-RLS tables. Seventy-five tables target FORCE RLS. `BatchPrintPackToken` and `PrintRenderToken` are migration-only because the registration-aware production scanner finds no active reader or writer; they receive no runtime commands and do not target FORCE RLS unless a future registered workflow reactivates them.

## Physical ownership and row-ownership taxonomy

Every protected application table is logically owned by `identity-table-owner`, the environment-specific `*_owner` NOLOGIN role. Runtime LOGIN roles, migration, operator, and break-glass identities own no protected table. Migration may create reviewed objects only if the deployment transfers protected tables/policies to `*_owner` and approved authentication functions/schema to `*_auth_owner` before completion. This document changes no current database owner.

Row authorization stops at one of five terminal boundaries: direct tenant root/key, direct actor key, exact security/public function or repository, approved restricted system job, or migration-only denial. Nullable tenant fields have table-specific NULL semantics in `tables.json`; NULL never means all tenants. Security-sensitive tables require named pre-auth/public functions, actor-owned repositories, restricted worker functions, or operator-only commands rather than ordinary broad authenticated access. Append-only tables permit scoped reads and inserts; UPDATE is denied, and DELETE exists only for the explicitly recorded retention lifecycle.

## Policy inheritance and non-recursive parent chains

Policies use the shortest approved ownership path. Direct tenant or actor columns take precedence over parent joins. Parent-inherited policies may depend only on a reviewed acyclic dependency DAG, and policy predicates must not query a table that can reach the original table through another policy. Stable helper functions may expose validated transaction settings but must not become generic table readers. Every dependency is covered by catalog inspection, recursion/timeout tests, and `EXPLAIN` evidence.

The approved graph in `policy-dependency-graph.json` has 77 nodes and 38 explicit edges. Evaluation layers are: layer 0 terminal boundaries (39 tables), layer 1 (28), layer 2 (8), layer 3 (1), and layer 4 (1). Every edge contains one join key, future source-index requirement, reason, protected-dependency status, and an explicit no-hidden-helper assertion. The graph is acyclic, has no self-edge, no planner-sensitive hidden dependency, and no dependency on a runtime-owned object. The deepest path is the print evidence chain and remains one-directional toward `Batch`.

## Exception policy

An intentionally non-RLS classification requires proof that cross-tenant/actor data cannot exist, exact GRANT-only controls, all runtime readers/writers, and a written security justification. No current table meets or needs that exception. Migration-only is separate: the two runtime-unused token tables have registration/import evidence showing no active workflow and the validator rejects any future production access until they are reclassified.

## Approved ownership review groups

| Group | Scope | Tables | Resolved | Edges | Confidence high/medium/low |
|---|---|---:|---:|---:|---:|
| A | Security-sensitive and identity | 21 | 21 | 15 | 18/3/0 |
| B | Tenant roots and membership | 3 | 3 | 0 | 3/0/0 |
| C | Batch and QR lifecycle | 15 | 15 | 5 | 14/1/0 |
| D | Printing and printers | 13 | 13 | 11 | 11/2/0 |
| E | Audit, incident and governance | 18 | 18 | 7 | 10/8/0 |
| F | Operational/system | 7 | 7 | 0 | 0/7/0 |
| G | Reference and remaining | 0 | 0 | 0 | 0/0/0 |

The generated `TABLE_OWNERSHIP_REVIEW.md` is the concise table-by-table review. `tables.json` remains authoritative if summary counts drift.

## Unresolved semantic decisions

Ownership classification itself has no unresolved table decision. Policy command/column/lifecycle semantics (`decision-policy-command-semantics`), exact pre-auth functions (`decision-pre-auth-boundary`), durable worker/job authority (`decision-worker-identity-model`), the executable object-transfer chain (`decision-object-ownership-chain`), and broker/operator implementation (`decision-operator-administration`) remain blocking implementation decisions. They do not reopen the approved category, owner, FORCE target, or parent DAG.

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
