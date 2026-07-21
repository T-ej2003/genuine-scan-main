# Session B invitation/account-activation application-path proof

Status: local PostgreSQL 18 exact-function proof GREEN; Session A package/grant integration and the subsequent login/delivery families remain pending.

- Foundation SHA: `f1163b83e039af7129c5879f0957a441d1219fa9`
- Branch: `rls-wave-auth-public-workers`
- Database: `mscqr_rls_wave_b_auth_public_workers` (PostgreSQL 18; five invitation tables plus the shared six-table session foundation, all with RLS enabled and forced)
- Real registered roots exercised: `POST /api/auth/invite`, `POST /api/licensees/:id/admin-invite/resend`, `GET /api/auth/invite-preview`
- Activation exercised through the production `acceptInvite` service and pre-authentication runtime identity. The registered `POST /api/auth/accept-invite` root is mapped but its post-activation automatic-login response will be certified with the next login/session family.
- Focused checks: backend build; `invitationBoundary.test.js`; `recentAdminMfaMiddleware.test.js`; `workflowRegistry.test.js`; `securityBoundary.test.js`; `authenticatedControllerDenial.test.js`; `authInviteEmailSenderPolicy.test.js`; `refreshSessionPostgres18.test.js`; `invitationPostgres18.test.js`.
- Application guard contracts: canonical session denial clears authentication cookies and returns 401; only a typed stale-MFA result returns 428; database/configuration/projection faults continue to the central error handler. Invite acceptance uses the registered 120-character name ceiling and rejects 121 characters before database access.

The proof covers platform create/resend, same-tenant create, active-manufacturer link, exact preview and activation projections, database-derived actor/session/scope/assurance/purpose, deterministic same-request retry, one live invite under concurrent preparation, one activation winner, replay/expiry/ambiguity/stale/disabled/foreign/wrong-role/wrong-assurance/wrong-purpose/wrong-identity denial, rollback on forced audit-outbox failure, post-commit serialization, exact grants, direct-table denial and a non-login/non-superuser/non-`BYPASSRLS` function owner.

## Automatically covered workflow IDs

- `workflow-http-backend-src-controllers-licensee-invite-controller-ts-resend-licensee-admin-invite`
- `workflow-internal-backend-src-services-auth-invite-service-ts-accept-invite`
- `workflow-internal-backend-src-services-auth-invite-service-ts-create-invite`
- `workflow-internal-backend-src-services-auth-invite-service-ts-get-invite-preview`
- `workflow-internal-backend-src-services-auth-invite-service-ts-get-or-create-platform-org-id`
- `workflow-internal-backend-src-services-auth-invite-service-ts-infer-org-id-for-licensee`
- `workflow-internal-backend-src-services-auth-invite-service-ts-resolve-invite-actor-context`

The last three legacy helper workflows are absorbed by the single atomic `prepare_invitation` repository boundary; they are not separate runtime queries.

## Exact Session A seams

Install these fixed-search-path `SECURITY DEFINER` contracts under the reviewed non-bypass function owner:

- Authenticated-app only: `app_rls.prepare_invitation(text,text,text,text,text,text,text,text,text,boolean,boolean,text,timestamp without time zone,timestamp without time zone,text,text)`.
- Authenticated-app only: `app_rls.require_recent_mfa_session(text,timestamp without time zone,integer)`.
- Pre-authentication only: `app_auth.lookup_invitation_token(text[],timestamp without time zone)`.
- Pre-authentication only: `app_auth.consume_invitation_token(text[],text,text,timestamp without time zone,text,text,text)`.

`prepare_invitation` must revalidate and lock the actor/session/current membership and target, enforce platform or same-licensee authority plus current MFA/step-up assurance and exact purpose, preserve the platform organization and active-manufacturer link behavior, leave one live invite, and atomically write its durable audit/outbox row. It returns exactly the 17 fields enforced by `invitationRepository.ts`.

`consume_invitation_token` must lock exactly one unused/unexpired invite and its bound active invited user; update password, activation, verification, lockout and invite-consumption state; and write `AUTH_INVITE_ACCEPTED` audit/outbox in the same transaction. It returns exactly `inviteId,id,email,name,role,licenseeId,orgId,status`. Blank, malformed, duplicate, ambiguous, expired, used, replayed or foreign-bound candidates return no activation.

Update the Session A-owned pre-auth contract projection to include `inviteId` and the request/IP/user-agent arguments above. In Session A-owned `licenseeController.ts:createLicensee`, pass the live actor session ID and canonical authenticated transaction boundary to the existing `createInvite` call; do not add a global-Prisma fallback.

The worker/outbox family must replace the current post-commit best-effort email-delivery audit with a durable encrypted delivery job before production activation. The login family must then exercise the complete `POST /api/auth/accept-invite` activation-to-session response. These are ordered follow-on families, not certified by this local invitation proof.

No Session A-owned generator/global artifact, staging endpoint or production endpoint was changed or used.
