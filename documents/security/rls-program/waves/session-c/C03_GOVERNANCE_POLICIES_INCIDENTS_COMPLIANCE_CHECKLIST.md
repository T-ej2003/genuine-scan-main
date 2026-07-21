# Session C C03 governance, policies, incidents, and compliance checklist

Family: `c-03-governance-policies-incidents-compliance` (55 workflows)

Coordination commit: `22bfdb0cfd19d7b435b1390611b452a419923f9f`

Focused PostgreSQL database: `mscqr_rls_wave_c_admin_governance_operator`

## Pre-edit investigation

- [x] Authoritative Session C ownership and C03 workflow IDs read.
- [x] Every registered HTTP/internal production root and complete caller chain read once.
- [x] Frozen workflow, actor, scope, assurance, purpose, command, and table contracts read.
- [x] Existing focused governance/incident/compliance/IR tests read.
- [x] Protected schema fields, relations, indexes, constraints, and generated client names verified.
- [x] Every protected database access and transaction/serialization boundary mapped.
- [x] Shared dependencies and Session A/Session B seams identified without editing their files.
- [x] C03 production/test ownership and allowed new paths confirmed.
- [x] Positive and negative application-path evidence planned per shared boundary.

## Transaction map and seams

- Governance flags, retention, compliance packs, and exports currently use global Prisma; job state, business effects, and audit are split across transactions. Convert the controller/service boundary once and keep artifact I/O outside database transactions.
- Incident and IR controllers currently read, mutate, append events, audit, notify, and invoke containment across separate transactions. Convert each protected repository action to one canonical transaction, then perform email/file/notification serialization after commit.
- Policy engines and tamper/degradation processing are invoked by public verification/intake paths. Their frozen authenticated-app contract cannot authorize those callers. Session A must supply restricted pre-auth worker identities/functions that derive scope from the QR or incident row; caller-provided scope is never authority.
- Incident reads/writes and PolicyRule, SecurityPolicy, SensitiveActionApproval, User, and RefreshToken operations are named-function-only. Session A must generate the exact C03 functions and grants; C03 will call named functions rather than broaden direct table grants.
- Current incident detail responses contain protected contact, location, notes, evidence, and communication fields excluded by the frozen direct projection. Session A must approve a purpose-specific incident-detail function returning the existing response fields under a bounded licensee and fresh platform-MFA boundary.
- Sensitive-action approvals are currently vulnerable to read/update/action races and partial execution. Convert to one serializable maker-checker transaction with row locking/CAS, immutable requester attribution, deterministic replay, and atomic audit/outbox intent.
- Forensic chain append currently has a read-previous/insert race. Add a transaction-aware repository with a per-scope PostgreSQL advisory transaction lock and audit-log dedupe.
- C02 owns `auditService.ts` and `traceEventService.ts` and is adding a backward-compatible transaction-local audit primitive. C03 consumes that export and does not edit either shared file.

## Required proof

- [ ] Registered route/internal caller reaches the converted canonical boundary.
- [ ] Actor and active organization/licensee/manufacturer/platform scope are revalidated in the same transaction.
- [ ] Required assurance and explicit purpose are installed and enforced.
- [ ] Queries and mutations use exact permitted columns and projections.
- [ ] Ownership and actor attribution are immutable.
- [ ] State transitions use compare-and-set or row locking as applicable.
- [ ] Duplicate/replay behavior is deterministic.
- [ ] Audit and outbox effects commit atomically with protected changes.
- [ ] Foreign tenant, stale membership, disabled actor, wrong role, and wrong assurance are denied.
- [ ] Responses and external side effects occur only after transaction commit.
- [ ] Focused syntax/type tests and C03 application-path tests pass.
- [ ] Fresh PostgreSQL 18 C03 family gate passes with RLS enabled and forced.

## Ownership boundaries

C03 may edit only its assigned controller/service files, assigned existing tests, and new paths under `backend/src/rls-waves/session-c/**`, `backend/tests/rls-wave-c/**`, and this Session C documentation directory. It will not edit `canonicalDbContext.ts`, authentication middleware, route registration, replacement-chain integration, global workflow/command/table manifests, generators, generated SQL/evidence, Prisma schema/migrations, staging infrastructure, or the shared Session C result manifest.

Any required Session A or integration-owner change will be reported to the Session C root with its exact signature and executable evidence.

## Implementation status

- [x] C03 selector and resource actor boundaries added with active user/parent revalidation seams and canonical context reinstall.
- [x] PolicyRule list/create/update application paths converted through one canonical actor/resource transaction and named-function repository.
- [x] Policy mutations reject protected ownership input, lock updates, deterministically replay by request ID, and couple audit/outbox writes to the protected transaction.
- [x] Focused PostgreSQL 18 policy proof covers positive create/list/update, concurrent replay, immutable attribution, inactive parent, disabled actor, wrong role/assurance, protected-column and direct-table denial.
- [ ] Platform-global and manufacturer-specific policy variants remain blocked on a reviewed Session A scope contract; the product engine consumes both and Session C does not convert that ambiguity into a prohibition.
- [ ] PolicyAlert list/link remains blocked on the durable incident-authorization product state owned by Session A.
- [x] Exact Session A and integration-owner signatures recorded in `C03_INTEGRATION_SEAMS.md`.
- [x] Changed TypeScript compiles and focused IR pagination plus C03 actor/resource tests pass.
- [ ] Recovered sensitive approval, governance, retention, compliance and incident conversions still require their focused SQL packages and PostgreSQL application-path gates before certification.
- [ ] Session A functions exist in the canonical GREEN package; until then the converted paths deliberately fail closed.
- [x] PolicyRule local function package and focused PostgreSQL 18 application-path gate green.
- [ ] Governance/retention/compliance function package integrated and PostgreSQL-certified.
- [ ] Incident detail/mutation/evidence boundary converted and certified.
- [ ] Containment, policy-worker, approval and tamper-worker boundaries converted and certified.
- [ ] Fresh PostgreSQL 18 C03 family gate green.
