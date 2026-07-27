# Authentication Release Boundary

Release Fix 1 covers only `POST /auth/login`, `POST /auth/logout`, and `GET /auth/me`.

Login begins with the reviewed password lookup boundary. That lookup binds the exact matched user inside the transaction. The authentication-closure functions then derive live user, tenant, manufacturer-link, MFA, and recent-session state from database rows. Successful login state, the risk signal, an optional MFA login challenge, refresh-token creation, and their audit outbox records are written only by the dedicated `NOLOGIN` authentication function owner. The pre-auth runtime role has no table privileges.

Authenticated requests first verify the encrypted `aq_db_session` capability through `app_auth.require_authenticated_session`. Logout and `/auth/me` then consume the verified session binding through exact `app_rls` functions. User, tenant, role, and manufacturer identifiers from JWT claims or request context are comparisons only and cannot establish database authority.

The generated package keeps FORCE RLS enabled. PUBLIC has no execution right on the eight release functions, runtime grants name exact signatures, and `app_rls.install_actor_context` remains unavailable to runtime roles. `AuthWebAuthnChallenge` receives no new Release Fix 1 policy because none of the three scoped routes directly accesses that table; its existing separate WebAuthn routes remain outside this release fix and fail closed under the restricted role.

Operation-specific policy coverage is limited to an actor-bound `INSERT` on `AuthSessionRiskSignal`, an actor/challenge-hash-bound `INSERT` on `MfaLoginChallenge`, exact login/session access on `User` and `RefreshToken`, and the live tenant/MFA rows required to derive the actor. The `RefreshToken` policy compares the selected row directly with the verified capability binding; it does not recursively query `RefreshToken` from its own predicate.

The focused PostgreSQL 18 certification installs the package on a fresh migration-derived database and exercises restricted pre-auth and application roles. It covers login and MFA challenge creation, risk isolation, capability issue/verify/expiry/revocation, `/auth/me`, cross-actor and cross-tenant denial, stale licensee and manufacturer-link denial, logout audit/revocation atomicity, rollback, forged GUCs, exact catalogue grants, FORCE RLS, and owner safety. The disposable database and roles are removed after the probe.

This release fix deliberately does not change dashboard, batch, refresh-rotation, B03 outbox, tenant-administration, QR, printing, or public-verification boundaries.
