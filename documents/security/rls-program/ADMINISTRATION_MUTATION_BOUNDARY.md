# Release Fix 3: administration mutation boundary

Manufacturer invitation accepts the legacy external payload `MANUFACTURER` only at the shared invite-service transport boundary and immediately normalizes it to `MANUFACTURER_ADMIN`. The deprecated value is never persisted and is not accepted as an authenticated role, capability claim, policy role, or database actor.

Release Fix 3 moves the existing licensee and user administration mutations behind eight exact `app_rls` functions. Each function verifies the encrypted `aq_db_session` capability through `app_auth.require_authenticated_session`, derives the live actor and tenant relationships, installs operation-local context, and executes under FORCE RLS as the existing NOLOGIN auth function owner.

## Active routes

- `POST`, `PATCH`, and `DELETE /api/licensees`
- `POST`, `PATCH`, and `DELETE /api/users`
- manufacturer deactivate, restore, and hard-delete routes already backed by `userController`
- `POST /api/auth/invite`
- `POST /api/licensees/:id/admin-invite/resend`

QR, batch, printing, verification, policy, incident, export, and manufacturer-directory reads are outside this release fix.

## Authority and assignment

`SUPER_ADMIN` and `PLATFORM_SUPER_ADMIN` retain only the existing platform mutations. `LICENSEE_ADMIN` may mutate or invite a `MANUFACTURER_ADMIN` only within its own active, unsuspended licensee and organization. `MANUFACTURER_ADMIN` is an approved assignable identity but no current administration mutation route grants it mutation authority. `ORG_ADMIN`, `MANUFACTURER`, `MANUFACTURER_USER`, unknown roles, self-promotion, and tenant assignment of platform roles are denied.

The request body supplies selectors and mutation values, never authority. Capability validity, actor status, MFA assurance, organization state, licensee suspension, target role, and manufacturer links are checked from protected database rows. The application role has no direct protected-table mutation grant and cannot execute internal context helpers.

## Atomicity and rollback

Business state, token/capability revocation, audit evidence, security outbox records, and invitation state share one PostgreSQL transaction. Invitation preparation serializes by target scope, leaves one live invitation, stores only the token hash, and links an already-active manufacturer without issuing a redundant invite. `administrationRollback.sql` removes only the Release Fix 3 public and internal routines; generated policies and grants are removed by the clean-room package rollback.

Email delivery remains outside the database transaction, matching existing behaviour: a durable invite can succeed while delivery reports a warning. No real email is sent by local certification.

## Focused release certification

The Release Fix 3 probe installs the official generated package over the real Prisma migration history in a fresh loopback PostgreSQL 18.4 database. It proves platform licensee creation, tenant-scoped manufacturer-admin creation, invitation preparation, exact response projections, audit and `AUDIT_LOG` outbox atomicity, and transaction rollback. It also proves denial for deprecated/inactive roles, platform-role assignment by a tenant actor, cross-tenant selectors, missing or forged capabilities, direct table mutation, forged GUCs, and direct execution of the generic context installer.

Catalog assertions cover FORCE RLS, the exact eight application-executable signatures, PUBLIC execution count zero, operation-specific policies, the NOLOGIN/non-BYPASSRLS owner, and zero protected tables owned by that function owner. The focused rollback removes only the eight public boundaries and five internal helpers, while retaining `app_auth.require_authenticated_session`. The disposable database, administrator, and nine generated roles are removed after the probe; the cleanup assertions require all three residue counts to be zero.

## Deferred hardening recommendations

After the release slice, consolidate controller error translation into one typed database-error mapper, add request-level idempotency to non-create mutations where product semantics permit retry, and expose administrative audit correlation IDs in privileged support tooling without exposing token or capability material. These are post-release improvements and do not broaden this boundary.
