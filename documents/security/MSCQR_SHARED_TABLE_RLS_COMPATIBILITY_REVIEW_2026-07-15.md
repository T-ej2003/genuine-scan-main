# MSCQR Shared-Table RLS Compatibility Review — 2026-07-15

## Executive decision

**NO GO for shared-table FORCE RLS.** The apply file must remain blocked. The deterministic inventory found 222 direct shared-table operations (177 application/operational and 45 test-only characterizations). Only five have exact reviewed policy-plus-context or named-function proof. The other 217 are denied by the reviewed posture; 166 are rollout-blocking and 51 are high risk.

Revision 7 must keep serving while the compatibility slices in the implementation plan are completed. Context propagation alone is insufficient: the reviewed policies have no `User` INSERT/DELETE capability, no cross-user UPDATE capability, and no write capability for `Organization`, `Licensee`, or `ManufacturerLicenseeLink`. Pre-authentication and system operations also need separate authorization boundaries.

The exhaustive operation-level record is [the machine-readable matrix](mscqr_shared_table_rls_compatibility_matrix_2026-07-15.json). Every row includes a stable ID, source line, execution surface, context status, conservative policy outcome, risk, remediation, and source evidence. The scanner and contract test regenerate/check this set; this report does not replace it.

## Inventory method and limits

The AST scanner covers `backend/src`, `backend/scripts`, `scripts`, `backend/prisma/seed.ts`, and production-modeling P2 tests. It finds shared-table Prisma delegate calls on `prisma`, `tx`, and other injected clients, plus tagged/called raw SQL that names `Organization`, `Licensee`, `User`, or `ManufacturerLicenseeLink`. Generated output and dependencies are excluded.

The classification is intentionally fail closed. An operation is `allowed` only when the exact reviewed predicate and a transaction-local context, or one of the two exact reviewed `app_auth` functions, proves it. Syntactic use of a variable named `tx` is not treated as RLS context unless it is nested under the reviewed context wrapper.

## Matrix totals

### By table and command

| Table | SELECT | COUNT | INSERT | UPDATE | DELETE | UPSERT | RAW_SQL | Total |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Organization | 3 | 0 | 7 | 2 | 1 | 2 | 0 | 15 |
| Licensee | 25 | 3 | 6 | 5 | 4 | 1 | 1 | 45 |
| User | 70 | 7 | 15 | 31 | 5 | 7 | 7 | 142 |
| ManufacturerLicenseeLink | 7 | 0 | 5 | 2 | 3 | 3 | 0 | 20 |
| **Total** | **105** | **10** | **33** | **40** | **13** | **13** | **8** | **222** |

`UPSERT` is recorded separately because it needs both INSERT and UPDATE authorization. `COUNT` is separately recorded because it is a SELECT whose correctness depends on visibility, not merely whether the query executes.

### By authentication stage

| Stage | Operations |
|---|---:|
| pre-auth | 12 |
| password-verified | 2 |
| fully-authenticated | 78 |
| system | 130 |

### By context and remediation

| Classification | Operations |
|---|---:|
| no transaction-local context | 217 |
| transaction-local context | 5 |
| proven allowed | 5 |
| requires repository wrapper | 44 |
| requires transaction context | 10 |
| requires a new, separately reviewed policy | 23 |
| requires a narrow SECURITY DEFINER boundary | 10 |
| requires system-role redesign | 130 |

The 130 `system` rows include 45 test-only operations that model production behavior. The matrix retains them so the scanner cannot silently lose P2 coverage; 177 rows are application or operational code.

## Exact blocking operation groups

The matrix rows with `compatibilityRisk=blocking` are the exact registry. The production blockers group as follows.

### Pre-auth identity operations

The two reviewed named functions are compatible: `lookup_password_user(text)` and `record_password_failure(text,timestamp without time zone,integer,integer)`. The transaction-local successful-login UPDATE is also compatible. These remaining paths are blocking:

- `authBootstrapRepository.ts:33` fallback password lookup and `:97` fallback failure UPDATE: retire after the named functions are guaranteed present; they cannot remain as FORCE-RLS compatibility fallbacks.
- `passwordResetService.ts:35,122`: reset lookup and completion have no actor context. Use two narrowly shaped functions, with one-time-token validation bound to the mutation; never expose a generic user lookup/update function.
- `emailVerificationService.ts:218,232`: confirmation lookup and mutation require a named token-bound boundary.
- `inviteService.ts:586,596,654`: invite acceptance User read/update and preview Licensee read require invite-token-bound functions or a transaction context derived from a validated invite, not caller-supplied tenant claims.
- `authService.ts:596`: refresh-session User lookup must obtain context from the validated refresh-token record before reading `User`, or use a narrowly reviewed session-refresh boundary.

### Self-service authenticated operations

Actor-self SELECT and UPDATE predicates are sufficient only when trusted claims are installed transaction-locally and the row's role still matches `app.role`. Blocking/high-risk direct paths include:

- `accountController.ts:56,152` profile/password updates and its supporting reads.
- `authController.ts:96` `/auth/me` read, where a Prisma transaction exists but the scanner does not prove the RLS settings are installed by the reviewed wrapper.
- `authAdminSecurityController.ts`, `authSessionController.ts`, and MFA/WebAuthn services that read the `User` row outside the claims context transaction.
- `emailVerificationService.ts:96` authenticated email-change request.

Move these paths behind a shared repository API that requires an authorization context and owns the complete Prisma transaction. Do not pass a transaction client after the context transaction has ended. Self-service policy tests must also prove that `role`, `licenseeId`, `orgId`, status, and security-control fields cannot be changed through over-posting even where row-level UPDATE is allowed; RLS is not column authorization.

### Licensee administrator operations

Tenant listing can be repaired with `app.user_id`, `app.role=licensee_admin`, `app.licensee_id`, and `app.organization_id` in one transaction. Creation and cross-user lifecycle cannot:

- `userController.ts:270` and `userService.ts:24`: User creation (INSERT).
- `inviteService.ts:338`: invited User creation (INSERT).
- `userController.ts:542,675,685,707,764,784`: cross-user update, deactivate/delete-state transitions, and restore.
- `userController.ts:631`: hard User DELETE.
- `userController.ts:660`: linked manufacturer-link DELETE.

Any future policy must bind the target to the actor's licensee/organization, enforce an explicit assignable-role lattice, prohibit platform-role creation/elevation, require recent MFA for sensitive lifecycle mutations, and write an immutable audit event. Route guards alone do not supply database authorization.

### Platform administrator operations

The reviewed SELECT predicate makes `app.is_platform_admin()` sufficient at the database layer for platform-wide reads. That is not sufficient as an application authorization design. Before using it, each route must prove a platform role from signed claims, an active fully authenticated session, recent MFA for sensitive operations, CSRF protection where applicable, and auditable purpose/actor/request metadata.

Blocking platform lifecycle paths include `licenseeController.ts:270,278,298,528,569`, `inviteService.ts:196`, and platform bootstrap/repair scripts. No permissive platform-wide write policy should be introduced. Prefer named repository commands with command-specific authorization; emergency/repair operations need a distinct operator workflow and evidence record.

### Background and system operations

The matrix records 130 system-stage calls across seeds, repair/cleanup scripts, startup bootstrap, compliance scheduling, dashboard snapshots, notifications, incident email, and validation tooling. A human actor must not be fabricated for them.

- Actor-derived jobs must carry an immutable actor ID, tenant IDs, authorization version, and enqueue-time assurance; workers must revalidate current authorization and set transaction context.
- Tenant jobs without a human actor need queue-payload tenant scope and a restricted system runtime role whose policies allow only that job's command and tenant fields.
- Cross-tenant platform maintenance should use a separate NOLOGIN owner plus narrowly named functions only where a row-policy design is impossible; functions must validate inputs, fix `search_path`, receive column-level grants, and emit audit evidence.
- Startup bootstrap, demo cleanup, seed, and repair scripts must be retired in deployed runtimes or moved to explicit operator-only tooling. Generic background bypass, table ownership, superuser, and `BYPASSRLS` are prohibited.

Likely retirements are the pre-candidate auth fallbacks after boundary deployment, duplicate `.js`/`.ts` maintenance implementations after build-entrypoint reconciliation, demo cleanup from non-development images, and startup super-admin creation once an operator bootstrap is established.

### Organization, Licensee, and link mutations

There are 41 mutations across these three tables. All are blocking: ten require separately reviewed command policies and 31 system/test operations require a system design. Twenty-nine are in application or operational code and 12 are test-only characterizations. Important application paths are organization/licensee creation and deletion, incident containment suspension/reactivation, and manufacturer link upsert/removal.

Ownership rules must be explicit:

- Organization mutation is platform lifecycle only; no tenant administrator may change organization identity or active state.
- Licensee mutation is platform lifecycle except narrowly defined incident containment. Containment needs a recorded incident, authorized responder, reason, bounded transition, and audit event.
- Link mutation must verify that the actor controls the manufacturer or licensee side as explicitly designed, cannot link across unrelated organizations, and cannot use `isPrimary` to acquire broader access. Creation/removal should be idempotent command operations, not a generic UPSERT exposed to callers.

## Policy dependency and recursion review

The reviewed dependency graph is:

```text
Licensee SELECT
  -> can_access_licensee(target)
     -> ManufacturerLicenseeLink SELECT policy

ManufacturerLicenseeLink SELECT
  -> context-only non-recursive predicate

User SELECT
  -> Batch / PrintJob EXISTS
     -> their FORCE-RLS SELECT policies
     -> can_access_batch / can_access_print_job
     -> can_access_licensee
     -> ManufacturerLicenseeLink SELECT policy
```

The deliberate link predicate avoids the direct cycle `Link -> can_access_licensee -> Link`. That design must not change. `Licensee -> helper -> Link` is therefore not recursively cyclic under the reviewed definitions.

The `User` predicate remains rollout-blocking and planner-sensitive because it reads `Batch` and `PrintJob`, which are themselves FORCE-RLS protected. The six batch policies are assigned only to the read role, while the shared User policy is also assigned to the app role. For the app role, nested Batch/PrintJob visibility can therefore differ from the read role and silently remove User rows. P2 must prove both roles, empty and valid contexts, query plans, non-recursion, and tenant non-leakage. A policy must never rely on table-owner behavior because FORCE RLS applies to owners.

## Direct access boundary

Forty-four operations require a repository wrapper and ten already use an injected client but lack the reviewed context wrapper. Controllers and services should not call shared delegates directly. The repository contract should accept a verified authorization object, open the transaction, set all six `app.*` values, execute one bounded command, and prevent the transaction client from escaping. This keeps connection-pool reuse safe and makes missing context fail before SQL execution.

## Characterization decisions

| Operation | Without RLS today | Reviewed FORCE-RLS outcome | Required design |
|---|---|---|---|
| contextless User SELECT/background read | works | denied/empty | system design or contextual repository |
| self User SELECT/UPDATE | works | allowed with exact context | transaction repository plus column authorization |
| cross-user UPDATE/admin MFA reset | works with route grants | denied | command-specific reviewed policy |
| User INSERT/invitation | works | denied | command-specific reviewed INSERT policy |
| User DELETE | works | denied | prefer soft lifecycle; otherwise separately reviewed DELETE |
| licensee-admin listing | works | same-licensee with context | contextual repository |
| platform-admin listing | works | platform-wide when context flag is true | signed role + active MFA assurance + audit gate |
| password-reset lookup | works | only reviewed lookup function works | narrow token/identity boundary |
| password-reset completion | works | denied | narrow one-time-token mutation boundary |
| MFA self-service User touch | works | actor-self with context | contextual repository |
| Organization/Licensee/link SELECT | works | context-scoped | contextual repository plus dependency P2 |
| link creation/removal | works | denied | command-specific reviewed policies |

These outcomes are asserted in `backend/tests/rlsAuthBootstrapP2.test.js` using the authoritative candidate policy template on a disposable database. No candidate policy was changed.

## Rollout dependencies and implementation slices

```text
A repository/context boundary
  -> C self-service
  -> D licensee-admin lifecycle
  -> E platform-admin lifecycle
  -> G organization/licensee/link commands

B pre-auth named functions

F system operations

A+B+C+D+E+F+G
  -> H complete disposable P2 policy proof
  -> I human review, remove block, staging canary
```

Recommended order is A, B, C, D, E, F, G, H, then I. B can be designed in parallel with A but must deploy atomically with its grants/policies. The first implementation slice should be **Slice A**, because it makes context use deterministic and removes repeated controller-level transaction mistakes without prematurely inventing write policy semantics.

## CTO recommendations beyond the minimum

1. Make shared-table access an enforced architecture boundary with an ESLint/AST check that rejects new direct delegates outside approved repositories. This scales better than continually expanding an allowlist.
2. Introduce typed authorization commands (`listTenantUsers`, `changeOwnPassword`, `deactivateTenantUser`) rather than a generic repository. Each command should declare actor assurance, tenant scope, allowed columns, and audit event.
3. Add policy dependency tests using `EXPLAIN (VERBOSE, COSTS OFF)` and statement timeouts for both app/read roles. This catches recursion and planner regressions before staging.
4. Version queue authorization payloads and reject stale versions. A worker should never trust tenant identifiers without reconciling them to the referenced job row.
5. Keep the apply block machine-checked until Slice H evidence is signed off. A green build is not authorization to remove it.
