# MSCQR Shared-Table RLS Compatibility Implementation Plan — 2026-07-15

## Purpose and safety boundary

This plan turns the 2026-07-15 compatibility matrix into reviewable implementation slices. It does not authorize a policy, migration, AWS action, database mutation, or staging rollout. The shared-table apply remains intentionally blocked until Slice H passes and Slice I receives separate human approval.

All policy changes must start from the reviewed candidate definitions, stay manually executable and staging-only until proven, and preserve revision 7, the six read-role-only batch policies, printer RLS OFF, and both disabled feature flags.

## Dependency order

`A -> C -> D/E/G`, `B` may follow A in parallel, and `F` can proceed independently after the system-role threat model. Slices A–G must complete before H. Only H can unblock a review of I.

## Slice A — Shared repository/context boundary

- **Likely files:** `backend/src/lib/rlsTransactionContextPrototype.ts`, a new shared-table repository module under `backend/src/repositories`, direct callers identified with `requiredRemediation=repository-wrapper|transaction-context`, and the deterministic scanner rule.
- **Policy requirements:** none; preserve reviewed predicates.
- **Tests:** unit tests for all six settings, pooled-connection reset, thrown callback rollback, missing/invalid context rejection, transaction-client non-escape, and representative HTTP reads.
- **Migration/staging impact:** none; application-only, feature-gated if needed.
- **Rollback:** revert callers to the prior repository interface while RLS remains OFF; do not remove the apply block.
- **Security risks:** caller-forged `isPlatformAdmin`, role normalization mismatch, context leakage through pooled connections, or a transaction client escaping its scope.
- **Dependencies:** none.
- **Exit criteria:** every authenticated shared-table access either uses the repository or is explicitly classified as pre-auth/system; a static check rejects new direct access.

## Slice B — Pre-auth SECURITY DEFINER functions

- **Likely files:** `authBootstrapRepository.ts`, password reset, email verification, invite, refresh-session repositories; reviewed staging SQL/rollback only after design approval.
- **Policy requirements:** one narrowly named function per irreducible command. Exact input/output columns, fixed `search_path=pg_catalog`, least-privilege column grants, NOLOGIN/NOBYPASSRLS owner, PUBLIC/read-role revoke, app-role EXECUTE only.
- **Tests:** duplicate/case-variant identities, expired/used/wrong token, concurrency/replay, timing-safe generic responses, function catalog ownership/grants, and empty-context denial of fallback SQL.
- **Migration/staging impact:** manual atomic staging phase with functions, grants, auth-owner policies, and FORCE RLS only after all compatibility slices; never Prisma migration/startup.
- **Rollback:** drop only new named functions and their grants; retain the two already reviewed functions when still used.
- **Security risks:** generic query capability, token oracle, replay, search-path injection, excessive owner grants, or functions callable by the read role.
- **Dependencies:** Slice A for authenticated continuations; independent for pure pre-auth commands.
- **Exit criteria:** all ten currently blocked pre-auth rows use approved named boundaries or validated-context transactions; legacy fallback paths are retired.

## Slice C — Self-service User operations

- **Likely files:** account/auth controllers, MFA/WebAuthn/session services, email-change service, shared User repository, input schemas.
- **Policy requirements:** retain actor-self row predicate initially; add column/command authorization outside RLS. Any predicate change needs separate review.
- **Tests:** own read/update, foreign-row denial, role/org/licensee/status over-posting, password/MFA assurance, stale session, disabled/deleted account, CSRF, and audit event.
- **Migration/staging impact:** application deployment only until Slice H.
- **Rollback:** disable new path flag or revert repository callers; RLS remains blocked.
- **Security risks:** actor-self RLS allows any table-granted column unless application commands constrain data; session claims may be stale.
- **Dependencies:** A.
- **Exit criteria:** every self-service row is transaction-local, only command-approved fields mutate, and MFA/session tests pass under candidate FORCE RLS.

## Slice D — Licensee-admin User lifecycle

- **Likely files:** `userController.ts`, `userService.ts`, invite service/controller, authorization/audit services, User repository.
- **Policy requirements:** separately reviewed tenant-bound INSERT and command-specific cross-user UPDATE; DELETE should be retired in favor of audited lifecycle state unless a hard-delete requirement is approved. Enforce an assignable-role lattice in database-visible semantics.
- **Tests:** same-tenant success; cross-tenant denial; platform-role elevation denial; self-escalation denial; active MFA requirement; invite replay; concurrent activation/deactivation; audit completeness.
- **Migration/staging impact:** candidate policy SQL only after application commands exist; manual disposable proof before staging.
- **Rollback:** remove command policy and disable command route, preserving read policy and data.
- **Security risks:** horizontal tenant escalation, role elevation, orphaned manufacturer links, destructive delete cascades, and incomplete audit.
- **Dependencies:** A, then C assurance primitives.
- **Exit criteria:** all 23 same-licensee rows are contextual or command-authorized; no broad cross-user UPDATE predicate exists.

## Slice E — Platform-admin User lifecycle

- **Likely files:** platform/licensee controllers, super-admin bootstrap, repair/break-glass tooling, sensitive-action approval and audit services.
- **Policy requirements:** command-specific semantics; never a blanket `is_platform_admin()` write policy. Separate interactive administration from operator repair.
- **Tests:** signed platform role, active session, recent MFA, dual approval where required, cross-tenant audit purpose, role ceiling, break-glass expiry, and non-platform denial.
- **Migration/staging impact:** no automatic bootstrap at startup; operator tooling must be dry-run-first and separately authorized.
- **Rollback:** disable individual admin commands; retain evidence and avoid destructive data rollback.
- **Security risks:** a forged/stale context flag becoming universal write authority, unaudited cross-tenant support, permanent break-glass access.
- **Dependencies:** A and assurance/audit primitives from C; coordinate with F for scripts.
- **Exit criteria:** every platform lifecycle command has explicit assurance, authorization, column set, and audit contract.

## Slice F — Background/system operations

- **Likely files:** compliance/dashboard/notification/incident services, queue producers/consumers, startup bootstrap, seeds, cleanup and repair scripts, runtime packaging.
- **Policy requirements:** per-job tenant policies for restricted runtime roles or narrow NOLOGIN-owner functions. No generic system bypass, ownership execution, or BYPASSRLS.
- **Tests:** forged/missing queue scope, stale authorization version, cross-tenant payload, retry/idempotency, job-to-tenant reconciliation, least-privilege grants, and audit/evidence output.
- **Migration/staging impact:** new roles/functions require separately reviewed manual staging SQL and secret/task design; no AWS changes in this discovery phase.
- **Rollback:** stop/disable the individual job and revoke its narrow grants; preserve queued evidence for reconciliation.
- **Security risks:** confused deputy, tenant scope supplied only by queue payload, unlimited cross-tenant maintenance, and deployment images containing unsafe scripts.
- **Dependencies:** threat model and inventory ownership decision; A when jobs derive human context.
- **Exit criteria:** all 130 system rows are retired, actor-derived, or assigned to an approved least-privilege runtime design; test-only rows mirror those decisions.

## Slice G — Organization/Licensee/link mutations

- **Likely files:** `licenseeController.ts`, `inviteService.ts`, `incidentActionsService.ts`, `manufacturerScopeService.ts`, seed/operator tools.
- **Policy requirements:** platform-only organization lifecycle; command-specific licensee lifecycle/containment; non-recursive manufacturer-link INSERT/UPDATE/DELETE semantics. Preserve the context-only link SELECT predicate.
- **Tests:** unrelated-org denial, invalid manufacturer/licensee pair, primary-link invariants, last-link removal, containment reason/incident binding, concurrency, and link-helper non-recursion.
- **Migration/staging impact:** new policies only after disposable P2 proof; manually applied atomically with rollback.
- **Rollback:** revoke/drop only the new command policies and disable commands; do not undo valid business data automatically.
- **Security risks:** creating a link that grants tenant visibility, recursive policy evaluation, cross-org linkage, and destructive cascades.
- **Dependencies:** A; D/E authorization model; F for seed/operator paths.
- **Exit criteria:** all 41 Organization/Licensee/link mutations have an approved command or are retired, and dependency plans are stable under FORCE RLS.

## Slice H — Full P2 policy verification

- **Likely files:** dedicated disposable P2 suites, candidate apply/rollback only after policies are approved, matrix/report regeneration.
- **Policy requirements:** exact reviewed aggregate from B–G; no broad fallback policies.
- **Tests:** every matrix row or command equivalence class, both app/read roles, empty/valid/forged contexts, CRUD denial, auth functions, planner/recursion `EXPLAIN`, timeouts, grants/owners, rollback, and full login/MFA/account/admin/job routes.
- **Migration/staging impact:** disposable PostgreSQL only; no staging mutation.
- **Rollback:** run candidate rollback only in the disposable database and assert baseline restoration.
- **Security risks:** false confidence from catalog-only tests, untested role differences, policy recursion, or characterization assertions weakened to pass.
- **Dependencies:** A–G complete.
- **Exit criteria:** deterministic matrix has no unexplained blocking/high operation; all P2 suites pass from a clean disposable database; security review signs exact predicates.

## Slice I — Remove apply block and rerun canary

- **Likely files:** shared apply/rollback, execution verification, runbook/evidence paths. The block is changed only in this slice after approval.
- **Policy requirements:** frozen output of H, exact roles/grants/functions, atomic postconditions, no printer/allocation-map expansion.
- **Tests:** all local contracts and H; manual preflight; post-apply verification; login/password-reset/MFA/admin smoke; revision 9 canary only.
- **Migration/staging impact:** separate human-authorized staging maintenance window. Revision 7 stays stable until canary evidence and cutover approval.
- **Rollback:** narrow shared-phase rollback, followed by revision 7 validation; preserve six batch policies.
- **Security risks:** stale helper image/evidence, incomplete smoke coverage, lock impact, or flag drift.
- **Dependencies:** H plus human security/operations approval.
- **Exit criteria:** block removal is separately reviewed, verification proves the ten-table posture and route compatibility, canary passes, and service cutover receives explicit approval.

## Recommended first slice

Start with Slice A. It is application-only, reversible while shared RLS remains OFF, and creates the enforcement point every authenticated slice needs. In parallel, prepare Slice B function specifications without SQL implementation. Do not start with policies: policy semantics should be derived from tested command contracts, not from current broad Prisma behavior.

## Scalability and hardening recommendations

- Generate a CI architecture check from the scanner so new direct shared-table calls fail review immediately.
- Use one transaction per authorization command; batch reads inside it to avoid N+1 context setup and preserve predictable pool behavior.
- Attach an authorization version to sessions and queues so role/tenant changes invalidate stale work.
- Capture structured decision evidence (`command`, actor/system identity, tenant, assurance, policy version, result) without secrets or row payloads.
- Maintain a policy dependency DAG test and statement-time budget. RLS correctness that degrades into nested scans is not production-ready.
