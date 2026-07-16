# Full-database RLS programme architecture

## Scope and authority

This directory is the machine-readable programme authority for taking every Prisma-backed production table and active database workflow toward PostgreSQL `ENABLE ROW LEVEL SECURITY` plus `FORCE ROW LEVEL SECURITY`. It is inventory and harness foundation only. It does not authorize or implement an application authorization change, policy, RLS enablement, database mutation, AWS action, staging action, or production action.

`tables.json` owns table classification and readiness, `workflows.json` owns functional access, `command-semantics.json` owns command authorization, `pre-auth-functions.json` owns exact pre-authentication function contracts, `worker-boundaries.json` owns non-interactive job authority, `runtime-identities.json` owns execution identities, and `decisions.json` owns unresolved rules. The scanners regenerate schema/access evidence while retaining human-maintained decisions and status. The shared-table apply at `documents/security/mscqr_staging_rls_shared_batch_phase_apply_2026-07-15.sql` remains blocked.

## Final database role model

`decision-runtime-role-split` is resolved. Development uses `mscqr_dev_*`, staging uses `mscqr_staging_*`, and production uses `mscqr_prod_*`. Every applicable LOGIN identity has a distinct credential source per environment. Protected tables are owned by `*_owner`; approved authentication functions are owned by `*_auth_owner`. Both owners are `NOLOGIN`, `NOSUPERUSER`, and `NOBYPASSRLS`, and no runtime, migration, or operator role has membership in or a `SET ROLE` path to either owner.

| Logical identity | Environment role-name pattern | Login | Permitted schemas | Command classes | Ownership | SET ROLE | CREATE | SECURITY DEFINER execution | Credential source | Rotation expectation |
|---|---|---|---|---|---|---|---|---|---|---|
| Authenticated application | `mscqr_{dev,staging,prod}_app` | LOGIN | `public`, `app_rls` | CONNECT, USAGE, workflow-generated table commands, authenticated helpers | None | No | No | Approved authenticated helper signatures only | Dedicated app secret per environment | Managed rotation and immediate exposure rotation |
| Restricted read | `mscqr_{dev,staging,prod}_rls_read` | LOGIN | `public`, `app_rls` | CONNECT, USAGE, approved SELECT, pure context helpers | None | No | No | Pure transaction-context helpers only | Dedicated read secret per environment | Managed independently from app/operator credentials |
| Pre-authentication executor | `mscqr_{dev,staging,prod}_preauth` | LOGIN | `app_auth` only | CONNECT, USAGE, EXECUTE on the seven signatures in `pre-auth-functions.json` | None; no table grants | No | No | Exact named `app_auth` functions only | Dedicated pre-auth secret per environment | Managed independently; never shared with app/worker/migration |
| Worker | `mscqr_{dev,staging,prod}_worker` | LOGIN | `public`, `app_rls` | CONNECT, USAGE, workflow-generated commands and worker helpers | None | No | No | Approved worker signatures only | Dedicated worker secret per environment | Managed independently from scheduled/app credentials |
| Scheduled job | `mscqr_{dev,staging,prod}_scheduled` | LOGIN | `public`, `app_rls` | CONNECT, USAGE, schedule-generated commands and helpers | None | No | No | Approved scheduled signatures only | Dedicated scheduled secret per environment | Managed independently from worker/app credentials |
| Migration | `mscqr_{dev,staging,prod}_migration` | LOGIN | Reviewed deployment schemas | CONNECT, USAGE, reviewed DDL, mandatory ownership transfer | No enduring protected-object ownership | No | Approved deployment only | None | Dedicated deployment secret per environment | Deployment-only retrieval and managed rotation |
| Table owner | `mscqr_{dev,staging,prod}_owner` | NOLOGIN | `public`, `app_rls` | Protected table/policy and approved worker-function ownership | Protected tables, policies, and exact `app_rls` worker functions | No | No | Owns SECURITY INVOKER functions; never executes as runtime | None | Not applicable |
| Authentication-function owner | `mscqr_{dev,staging,prod}_auth_owner` | NOLOGIN | `app_auth`, `pg_catalog` | Function/schema ownership and exact required column privileges | `app_auth` and approved functions only; no application tables | No | No | Owns functions; never executes as a runtime identity | None | Not applicable |
| Operator administration | `mscqr_{dev,staging,prod}_operator` | Broker-controlled LOGIN | Approved schemas only | Broker command allowlist and temporary narrow grants | None | No | No | Approved operator signatures only | Ephemeral broker credential per environment | Automatic expiry and revocation after each operation |
| Production break-glass | `mscqr_prod_breakglass_<incident>_<nonce>` or equivalent temporary grant | Ephemeral LOGIN only | Incident-approved only | Incident command allowlist only | None | No | No | Incident-approved exact signatures only | Broker-issued after dual approval and strong MFA; no standing credential | Hard expiry plus automatic revocation on completion or failure |

The break-glass name is a creation pattern, not a standing reusable role. Issuance requires dual approval, strong MFA, an incident/ticket, explicit expiry, an exact command allowlist, an immutable audit transcript, and automatic revocation. Development and staging do not define a production break-glass identity; they use their broker-controlled operator roles.

Migration may perform required DDL only through an explicitly approved deployment and ownership-transfer process. It must transfer protected tables and policies to `*_owner`, and approved `app_auth` objects to `*_auth_owner`, before the deployment is complete. Migration and operator authority never implies application authority. `decision-object-ownership-chain` and `decision-operator-administration` remain open for the exact transfer and broker implementation; they do not reopen the resolved identity split.

## Canonical transaction context

Authenticated database work occurs inside one transaction that validates and sets the six transaction-local settings already used by the prototype: actor/user ID, normalized role, licensee ID, organization ID, manufacturer ID, and platform-administrator boolean. Context is derived from authenticated server state, never accepted directly from request or queue payloads, and the transaction client cannot escape its callback. Missing, malformed, forged, stale, or cross-tenant context fails closed.

Worker transactions use a separate system context: `app.system_identity`, `app.job_id`, `app.job_type`, `app.organization_id`, `app.licensee_id`, `app.manufacturer_id`, `app.initiating_user_id`, `app.request_id`, and `app.auth_assurance=system-verified`. Every value is transaction-local, installed in the same transaction as protected commands, derived from verified durable job evidence, and automatically cleared at transaction end. Worker context never sets `app.role`, platform-admin state, or a human executor identity.

`decision-policy-command-semantics` is resolved by `command-semantics.json`. Future changes should reuse the existing transaction-context primitive after it is promoted and certified; no second context implementation is needed.

## Command authorization semantics

The 75 FORCE RLS targets have deterministic rules for each registered production workflow command plus one default-deny DELETE rule per table. `COUNT` is SELECT, `UPSERT` is INSERT plus UPDATE, and raw Prisma access is classified by the SQL execution primitive and statement verb; wildcard `ALL` is forbidden. Each rule binds the application actor class separately from the database runtime identity and records assurance, scope, allowed/protected columns, lifecycle conditions, `WITH CHECK`, special-function/worker/approval boundaries, audit, deletion consequences, allow/deny cases, evidence, confidence, and status.

Canonical actors are `anonymous`, `authenticated-user`, `manufacturer`, `operator`, `checker`, `licensee-admin`, `platform-admin`, `restricted-read`, `pre-auth-runtime`, `worker`, `scheduled-job`, `migration`, `operator-admin`, and `break-glass`. Canonical assurance is `none`, `password-verified`, `mfa-bootstrap`, `mfa-verified`, `step-up-verified`, `system-verified`, `operator-approved`, or `dual-approved-break-glass`. Actor classes never imply database role membership, ownership, `SET ROLE`, superuser, or `BYPASSRLS`.

INSERT and UPDATE rules split mutable columns from protected server-controlled columns. Tenant/actor ownership, platform role, audit actor, approval actor, immutable QR identity, print/release evidence, token/hash/secret, primary identity, timestamps, and lifecycle fields cannot be client assigned. A protected value may be written only by its exact trusted server context or named boundary and must pass the recorded `WITH CHECK`. Security-sensitive SELECT rules omit secret-bearing columns; secret material is available only through the named repository/function contract.

Batch lifecycle writes preserve the existing `DRAFT`, `CODES_GENERATED`, `PRINT_ACKNOWLEDGED`, `PRINT_CONFIRMED`, `SAMPLE_VERIFIED`, and `RELEASED` ordering. `FAILED` and `VOIDED` are terminal, release cannot silently mutate, and release approval preserves a different maker/checker. Printing, account/authentication, incident, governance, job, and retention status fields require their canonical service transition; client-selected initial states and unvalidated terminal transitions are denied.

Hard DELETE defaults to prohibited on all 75 protected tables. Exact registered exceptions are classified as actor self-delete, tenant-admin delete, retention delete, migration-only cleanup, or operator-approved deletion. Every exception remains scope-, lifecycle-, assurance-, dependent-data-, retention/legal-, and audit-bound; it does not create a general DELETE policy. Append-only evidence never permits UPDATE and permits DELETE only through its recorded retention/redaction command.

Licensee administrators remain tenant-bound and cannot assign platform roles, move rows between tenants, rewrite ownership, or reset protected security state without the recorded MFA/audit boundary. Platform administration is route-guarded, scoped, assured, purpose-audited, and command-specific—never `USING (true)`. Operator administration and production break-glass remain ephemeral allowlists with approval, expiry, and immutable audit. Background commands use durable system verification and restricted worker/scheduled boundaries, never a human actor or queue-payload authority.

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

## Object ownership and migration authority chain

`decision-object-ownership-chain` is resolved by `object-ownership-chain.json`. In development, staging and production the table owner is respectively `mscqr_dev_owner`, `mscqr_staging_owner` and `mscqr_prod_owner`; the auth owner is the corresponding `*_auth_owner`; and the deployment-only migrator is `*_migration`. Both owners are NOLOGIN, NOSUPERUSER, NOCREATEDB, NOCREATEROLE, NOREPLICATION, NOBYPASSRLS and NOINHERIT. Runtime roles never join either owner, and migration has no enduring ownership or membership.

The preferred migration path separates DDL execution from ownership transfer. After migration creates or alters the reviewed objects, an audited broker-controlled executor transfers each fully qualified object to its exact NOLOGIN owner. Migration itself receives no owner membership. The broker may receive one target-owner membership at a time with `ADMIN FALSE`, `INHERIT FALSE`, `SET TRUE`, solely because PostgreSQL 18 ownership transfer requires the executor to have the relevant object authority and be able to assume the new owner. `CREATEROLE` alone is not treated as blanket grant or transfer authority. Every temporary membership is audited and revoked before verification. A migration-membership fallback uses the same non-inheriting, SET-only shape only under a separately reviewed exception and can never report success while membership remains.

Object transfer is explicit and per object; database-wide `REASSIGN OWNED` is not the normal mechanism because it cannot preserve the table-owner/auth-owner boundary. Tables, application sequences, enums/composite types, views/materialized views, procedures, and `app_rls` SECURITY INVOKER helpers use the table owner. Indexes, constraints, policies and triggers follow their owning table, while called trigger functions are verified separately. `app_auth` and its seven exact SECURITY DEFINER functions use the auth owner. `public` and `app_rls` belong to the table owner; extension-owned schemas and objects remain with an allowlisted managed extension owner. Publications and subscriptions are absent from the application contract and fail closed if introduced without a separately approved platform owner.

Default privileges are normalized independently for every possible creator—migration, table owner and auth owner—because PostgreSQL applies defaults to future objects created by the current role and does not inherit another role's defaults. PUBLIC and runtime roles receive no application table, sequence, schema, type, function or procedure access through defaults. Exact runtime grants are generated only from `command-semantics.json` after ownership transfer. PUBLIC and runtime CREATE are denied on protected schemas; PUBLIC routine EXECUTE is explicitly revoked.

The nine-step completion gate authenticates the deployment identity, verifies the environment/attributes and clean membership baseline, records an exact owner snapshot, obtains controlled authority, performs reviewed DDL, transfers every changed object, normalizes grants/defaults, revokes temporary authority, and runs catalog verification. Catalog checks cover all 77 tables, sequence dependencies, schema owners/CREATE ACLs, function owners/security modes/EXECUTE ACLs, types, membership closure, default ACLs and optional extension/publication/subscription objects. Migration, runtime, and environment-admin LOGIN ownership must all be zero. Transfer or revocation failure always fails deployment; rollback may restore only a prior approved NOLOGIN owner and never a runtime or migration owner.

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

Ownership classification, policy command semantics, pre-authentication boundaries, worker/job authority, and the object-transfer chain have no unresolved architecture decision. Broker/operator implementation (`decision-operator-administration`) remains blocking. It does not reopen the approved category, owner, FORCE target, parent DAG, command contract, pre-auth function contract, worker contract, object ownership contract, or administrator ceiling.

## Pre-authentication function rules

`decision-pre-auth-boundary` is resolved. Eleven selected workflows reduce to seven exact `app_auth` functions: `lookup_password_user(text)`, `record_password_failure(text,timestamp without time zone,integer,integer)`, `request_password_reset(text,text,timestamp without time zone,timestamp without time zone,text,text)`, `consume_password_reset_token(text[],text,timestamp without time zone)`, `lookup_invitation_token(text[],timestamp without time zone)`, `consume_invitation_token(text[],text,text,timestamp without time zone)`, and `consume_email_verification_token(text[],timestamp without time zone)`. Exact nullability, return columns and column privileges are authoritative in `pre-auth-functions.json`; this document does not generate SQL.

Four workflows move behind canonical actor context because identity is already proven: successful password-login state reset uses `password-verified`, email-change initiation uses `step-up-verified`, and MFA challenge creation/consumption use the signed bootstrap identity at `mfa-bootstrap`. They must not retain pre-auth-runtime command rules or direct contextless table access.

All seven functions use typed fixed arguments/returns, `SECURITY DEFINER`, `SET search_path=pg_catalog`, fully qualified application objects, no dynamic SQL, no caller-owned functions, and no caller-set `app.*` authority. The owner is `identity-auth-function-owner` (`NOLOGIN`); only `identity-pre-auth-app` may execute. PUBLIC, restricted-read and authenticated-app EXECUTE are denied after the role split. The pre-auth runtime has CONNECT, `app_auth` USAGE and exact EXECUTE only—no table privileges, public CREATE, ownership, `SET ROLE`, restricted-read helpers, superuser or `BYPASSRLS`.

Password lookup normalizes once, validates shape, returns the minimum current verification/context projection, and fails closed on case-insensitive duplicates. Failed-login recording can change only counter, lockout and update timestamp with bounded inputs and atomic increments. Reset request keeps a constant-success external response. Reset, invite and email consumption lock exactly one token/account binding, enforce expiry/unused state, consume once atomically, and revoke sessions where current product semantics require it. Invitation consumption never creates a user or writes role/tenant keys; licensee/manufacturer invitations cannot promote platform administrators. Exact tests and secret-column justifications are in the function manifest.

## Worker authorization rules

`decision-worker-identity-model` is resolved by `worker-boundaries.json`. Registration evidence identifies three non-interactive execution workflows: actor-derived audit-outbox recovery and platform-scoped SIEM delivery use `identity-worker`; scheduled compliance maintenance uses the distinct `identity-scheduled-job`. The scanner now classifies the synchronous attention-queue dashboard read as HTTP and `queueAuditLogOutbox`/`queueSecurityEvent` as durable producers rather than consumers. Names containing “queue” are not worker-registration evidence.

Every job is loaded from a durable row, checks an allowlisted job type, immutable canonical payload digest, correlation ID, maximum age and idempotency key, and revalidates tenant/actor references before context installation. JSON tenant, actor, role, or platform-admin claims are never authority. Actor-derived audit work preserves the initiating actor as origin evidence while recording `identity-worker` as executor. SIEM delivery uses the outbox row ID as its stable external event ID. Scheduled compliance partitions by verified licensee/organization and must remove its current platform-user lookup rather than impersonate a human administrator.

Retries keep the same job ID, digest and idempotency key; conflicting payloads are denied and terminal results are returned instead of repeated. Database row locks/CAS or unique schedule keys enforce one logical winner; Redis/process leases are optimizations only. Retry exhaustion retains immutable dead-letter evidence, cancellation stops new claims without publishing partial success, and audit records system identity, job/type, tenant, initiating actor when present, request ID, outcome and attempt.

Two exact future `app_rls` SECURITY INVOKER functions are required: `consume_audit_log_outbox(text,text,timestamp without time zone)` atomically inserts immutable audit evidence and consumes one row; `claim_compliance_pack_slice(text,timestamp without time zone,integer)` performs bounded tenant partition claims. They are owned by the NOLOGIN table-owner identity, execute with the caller's exact grants and RLS context, and grant no bypass. Neither accepts JSON queries, table/column names, predicates, roles or tenant authority. SIEM uses exact table commands plus a database compare-and-set because external delivery cannot be made atomic by a database function. These contracts create no SQL or runtime grant.

## Administrator ceilings

Tenant administrators stay inside their proven tenant and assignable-role ceiling. Platform administrators do not receive blanket write predicates: each cross-tenant command requires explicit purpose, assurance, column/lifecycle rules and audit. Production break-glass is ephemeral, dual-approved, time-bound, incident-linked, non-owning and fully recorded. No administrator can set arbitrary RLS context, assume an owner, create objects, use superuser, or use `BYPASSRLS`.

## Direct Prisma migration strategy

Inventory direct calls first, then move each canonical workflow—not each technical call site—behind the approved transaction repository, pre-auth function, or restricted system boundary. Keep existing behavior while RLS remains off; characterize allowed/denied scenarios before changing callers. A static scanner prevents new unmapped access. Retire a direct path only with import, registration, replacement and test evidence. Do not add a parallel repository abstraction where the existing transaction primitive is sufficient.

## Policy generation strategy

Policies are generated only from reviewed table ownership plus `command-semantics.json`. Generation must preserve exact actor/identity/assurance/scope/column/lifecycle boundaries, be deterministic, command-specific, role-specific and dependency-ordered, and fail closed on unresolved implementation decisions. Generated SQL, rollback and catalog verification are separate review artifacts; no Prisma migration, startup path, workflow, or harness automatically executes activation SQL.

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
