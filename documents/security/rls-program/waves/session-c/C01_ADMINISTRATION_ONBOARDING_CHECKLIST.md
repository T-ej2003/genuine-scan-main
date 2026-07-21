# Session C C01 administration/onboarding checklist

Date: 2026-07-21 (Europe/London)

Coordination SHA: `22bfdb0cfd19d7b435b1390611b452a419923f9f`

Status: pre-edit discovery complete. Session A's Tuesday restricted-pilot workflow-scope artifact is not present in its worktree yet, so the launch-critical subset is not inferred here.

## Family inspected

`c-01-administration-general-mutations` contains eight owned workflows:

- `workflow-http-backend-src-controllers-licensee-controller-ts-create-licensee`
- `workflow-http-backend-src-controllers-licensee-controller-ts-delete-licensee`
- `workflow-http-backend-src-controllers-licensee-controller-ts-update-licensee`
- `workflow-http-backend-src-controllers-user-controller-ts-create-user`
- `workflow-http-backend-src-controllers-user-controller-ts-delete-user`
- `workflow-http-backend-src-controllers-user-controller-ts-restore-manufacturer`
- `workflow-http-backend-src-controllers-user-controller-ts-update-user`
- `workflow-internal-backend-src-services-manufacturer-scope-service-ts-upsert-manufacturer-licensee-link`

## Required pre-edit checks

- [x] Production roots and complete registered HTTP call chain read: authentication, role guard, fresh-admin-MFA guard, tenant isolation, CSRF, controller, shared scope helper, audit, invite and idempotency paths.
- [x] Frozen contracts read: `ARCHITECTURE.md`, `MANUFACTURER_BOOTSTRAP_REVIEW.md`, `manufacturer-bootstrap-boundary.json`, `context-boundary-families.json`, `workflows.json`, `command-semantics.json`, `tables.json` and `workflow-ownership-session-c.json`.
- [x] Current focused evidence read: `phaseE2RoleTenantIdor.test.js`, the `updateUser` IDOR case in `securityRouteSurface.test.js`, and the existing manufacturer bootstrap/RLS tests. Existing tests do not prove these mutation paths end to end.
- [x] Schema fields verified for `User`, `Organization`, `Licensee`, `ManufacturerLicenseeLink`, `Batch`, `RefreshToken`, `AuditLog`, `AuditLogOutbox`, `SecurityEventOutbox` and `ActionIdempotencyKey`.
- [x] Database accesses and transaction boundaries mapped.
- [x] Shared dependencies and cross-session callers identified.
- [x] Owned production/test files and allowed new paths confirmed.
- [x] Positive and negative application-path evidence planned.

## Current transaction map and blockers

1. `createLicensee` performs idempotency, duplicate Licensee/User reads and response completion outside the Organization/Licensee/User transaction. Audit, SIEM outbox and optional invite creation happen after commit. A failure can therefore leave business state without atomic attribution/outbox, and replay completion is not atomic with the mutation.
2. `updateLicensee` and `deleteLicensee` use global Prisma for scope/dependency checks and mutation, then append audit after commit. Delete uses four independent counts and a later delete instead of one locked/CAS decision.
3. `createUser`, `updateUser`, `deleteUser` and `restoreManufacturer` perform actor/target/tenant reads before their mutation transactions. Audit is outside every mutation transaction. Soft disable/unlink does not atomically revoke `RefreshToken` rows.
4. The frozen command rules require named-function boundaries for protected `User` INSERT/UPDATE/DELETE columns. The current generated package grants only already-certified workflows, so Session A must add the exact functions/grants before full-system integration.
5. The generic `upsertManufacturerLicenseeLink` workflow is recorded as manufacturer/password authority, but every live mutation caller is administrative (`userController.ts` or Session B-owned `inviteService.ts`). A manufacturer must never self-create membership. The global workflow/command actor mapping needs Session A correction; Session C will preserve the helper signature for Session B callers.
6. Current controller projections include or set protected columns not directly grantable under the frozen rules, including User email/password/role/tenant/lifecycle fields and Licensee ownership/contact fields. These belong behind exact named functions or corrected reviewed column semantics, not broader table grants.

## Owned implementation boundary

Session C may change:

- `backend/src/controllers/licenseeController.ts`
- `backend/src/controllers/userController.ts`
- `backend/src/services/manufacturerScopeService.ts`
- new `backend/src/rls-waves/session-c/**` repositories
- new `backend/tests/rls-wave-c/**` tests

Session C will not change `backend/src/lib/canonicalDbContext.ts`, `backend/src/middleware/auth.ts`, `backend/src/routes/index.ts`, Session B's `inviteService.ts`, Prisma schema/migrations, generated SQL/manifests or programme-wide artifacts. Exact required seams will be recorded in the Session C result manifest.

## Planned launch proof

For each Session A-marked launch-critical mutation:

- Positive: registered controller path, database-revalidated active actor and parent Organization/Licensee, exact role/assurance/purpose, exact response contract, one transaction, immutable audit plus durable outbox, and serialization after commit.
- Negative: blank/malformed target or request attribution, foreign tenant, stale/revoked manufacturer link, disabled actor, inactive/suspended parent, wrong role, wrong assurance, protected-column attempt and stale state.
- Concurrency/replay: one database winner for duplicate create/link/disable/restore, stable replay result, conflicting replay denial, no lost primary-link transition, and no dependency-check/delete race.
- Revocation: disable/unlink revokes current database membership and applicable refresh sessions atomically; a stale access token is denied by database revalidation.
- Projection: no password/token/MFA/recovery/metadata fields and no foreign identifiers serialize.

## Session A seams already demonstrated

- Exact named `app_rls` administration functions and column grants for User lifecycle/identity mutations and Licensee root creation.
- Correct `upsertManufacturerLicenseeLink` actor/assurance mapping to the owning admin workflow; no manufacturer self-link grant.
- Workflow-command inclusion for atomic `AuditLog`, `SecurityEventOutbox`, refresh-session revocation and mutation idempotency where the launch scope requires them.
- A valid server UUID request-correlation seam before canonical context installation if the registered middleware can still supply arbitrary text.
