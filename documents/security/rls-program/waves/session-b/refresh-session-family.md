# Session B refresh/session application-path proof

Status: local PostgreSQL 18 proof GREEN; Session A package/grant integration pending.

- Foundation SHA: `f1163b83e039af7129c5879f0957a441d1219fa9`
- Branch: `rls-wave-auth-public-workers`
- Database: `mscqr_rls_wave_b_auth_public_workers` (PostgreSQL 18, six family tables with RLS enabled and forced)
- Registered roots exercised/mapped: `POST /auth/refresh`, `POST /auth/logout`, `GET /auth/sessions`, `POST /auth/sessions/revoke-all`, `POST /auth/sessions/:id/revoke`
- Focused checks: backend build; `refreshSessionBoundary.test.js`; `securityBoundary.test.js`; `authenticatedControllerDenial.test.js`; `workflowRegistry.test.js`; `refreshSessionPostgres18.test.js`
- PostgreSQL result: the five registered Express roots and their authentication, CSRF and limiter chains reach the canonical boundaries; rotation/audit/outbox are atomic; contention has one winner; later replay revokes the family; MFA-bootstrap consumption is atomic; expired/revoked/disabled/stale/foreign paths deny; and the non-login/non-superuser/non-`BYPASSRLS` function owner executes through forced-RLS policies with exact column/command grants.
- The database-backed current-session/auth-state projection now lives in Session B-owned `authenticatedSessionProjection.ts`; the unowned shared controller helper is unchanged from the foundation, and its legacy no-boundary lookup fails closed rather than falling back to global Prisma.

## Automatically covered workflow IDs

- `workflow-internal-backend-src-services-auth-auth-service-ts-refresh-session`
- `workflow-internal-backend-src-services-auth-refresh-token-service-ts-create-refresh-token`
- `workflow-internal-backend-src-services-auth-refresh-token-service-ts-find-refresh-token-by-raw`
- `workflow-internal-backend-src-services-auth-refresh-token-service-ts-list-active-refresh-tokens-for-user`
- `workflow-internal-backend-src-services-auth-refresh-token-service-ts-revoke-all-user-refresh-tokens`
- `workflow-internal-backend-src-services-auth-refresh-token-service-ts-revoke-password-only-refresh-tokens-for-user`
- `workflow-internal-backend-src-services-auth-refresh-token-service-ts-revoke-refresh-token-by-id`
- `workflow-internal-backend-src-services-auth-refresh-token-service-ts-revoke-refresh-token-by-raw`
- `workflow-internal-backend-src-services-auth-refresh-token-service-ts-rotate-refresh-token`

## Exact Session A seam

Add these static `SECURITY DEFINER` functions to the canonical package with fixed owner/search path and EXECUTE only for the environment-scoped pre-authentication runtime role:

- `app_auth.claim_refresh_token_rotation(text[], timestamp without time zone, text)`
- `app_auth.load_refresh_session_state(text, text[], text, text, timestamp without time zone, text)`
- `app_auth.create_refresh_mfa_challenge(text, text[], text, text, text, integer, text, text[], text, text, integer, timestamp without time zone, timestamp without time zone, text)`
- `app_auth.revoke_refresh_token_scope(text, text[], text, text, text, timestamp without time zone)`
- `app_auth.complete_refresh_token_rotation(text, text[], text, text, text, timestamp without time zone, text, text, timestamp without time zone, timestamp without time zone, timestamp without time zone)`

Add the authenticated half with EXECUTE only for the environment-scoped authenticated application role:

- `app_rls.revalidate_authenticated_actor(text, text, text, text, timestamp without time zone, text)`
- `app_rls.load_authenticated_actor()`
- `app_rls.create_refresh_token(text, text, text, timestamp without time zone, text, text, timestamp without time zone, timestamp without time zone, timestamp without time zone)`
- `app_rls.find_refresh_token_by_hashes(text[])`
- `app_rls.find_refresh_token_by_id(text, text)`
- `app_rls.list_active_refresh_tokens(text, timestamp without time zone)`
- `app_rls.revoke_refresh_token_by_hashes(text[], text, timestamp without time zone)`
- `app_rls.revoke_all_refresh_tokens(text, text, timestamp without time zone)`
- `app_rls.revoke_password_only_refresh_tokens(text, text, timestamp without time zone)`
- `app_rls.revoke_refresh_token_by_id(text, text, text, timestamp without time zone)`
- `app_rls.enqueue_audit_log_outbox(jsonb, text, text, text, text, text, text, text, text, timestamp without time zone, text)`

The functions own RefreshToken lookup/insert/update, active User and membership revalidation/locking, MFA-challenge insert, and durable audit/outbox insert. Every follow-on must rebind predecessor ID and actor ID to the presented 1..3 token hashes; caller-set `app.*` settings are never authority. Results must match the exact projections enforced in `sessionCredentialRepository.ts`. Blank, malformed, ambiguous, expired, revoked, disabled, stale, foreign-scope, wrong-MFA, forged-bearer, contention-loser and replay paths deny deterministically.

Deploy `PREAUTH_DATABASE_URL` and `AUTHENTICATED_APP_DATABASE_URL` as distinct, same-environment runtime credentials. The pre-authentication identity receives only the `app_auth` functions above; the authenticated identity receives only the exact `app_rls` session functions. Neither identity receives protected table grants, owner, superuser, `BYPASSRLS`, or `SET ROLE` capability. Install functions and grants before activating either credential.

For workflow `workflow-internal-backend-src-services-auth-refresh-token-service-ts-list-active-refresh-tokens-for-user` only, update Session A-owned command `command-refresh-token-select-1e564ffb471c` and `app_rls.list_active_refresh_tokens(text, timestamp without time zone)` so the same-actor session-list projection explicitly allows `createdIpHash` and `createdUserAgent`. These fields are required by the existing session-security response and risk calculation; only the already-hashed IP and bounded user-agent are returned, never the token hash, replacement hash, or a foreign actor's row. Blank actor/session context, stale or disabled actor/membership, expired or revoked session, foreign scope, wrong role/assurance/purpose, and unexpected projection remain denied. Evidence is the five-root PostgreSQL proof plus `authSessionMetadata.test.js`.

No Session A-owned generator/global artifact, staging endpoint, or production endpoint was changed or used by this local proof.
