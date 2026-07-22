# MSCQR pre-authentication boundary review

This review records the seven production SQL boundaries generated from the authoritative named-function contracts, including exact ownership, grants, FORCE-RLS policies, rollback, and PostgreSQL 18 probes.

Selected workflows: 10; exact functions: 7; moved behind actor context: 3; operator-only: 0; retired: 0.

## Workflow reconciliation

| Workflow | Group | Boundary | Function/assurance |
|---|---|---|---|
| workflow-internal-backend-src-services-auth-auth-service-ts-login-with-password | not actually pre-auth and must move behind canonical actor context | ordinary-authenticated-context | password-verified |
| workflow-internal-backend-src-services-auth-email-verification-service-ts-confirm-email-verification | email-verification consumption | exact-security-definer-function | preauth-fn-consume-email-verification |
| workflow-internal-backend-src-services-auth-invite-service-ts-accept-invite | invitation/setup-link consumption | exact-security-definer-function | preauth-fn-consume-invitation |
| workflow-internal-backend-src-services-auth-invite-service-ts-get-invite-preview | invitation/setup-link lookup | exact-security-definer-function | preauth-fn-lookup-invitation |
| workflow-internal-backend-src-services-auth-mfa-adapter-ts-complete-stable-mfa-login-challenge | not actually pre-auth and must move behind canonical actor context | ordinary-authenticated-context | mfa-bootstrap |
| workflow-internal-backend-src-services-auth-mfa-adapter-ts-create-stable-mfa-login-challenge | not actually pre-auth and must move behind canonical actor context | ordinary-authenticated-context | mfa-bootstrap |
| workflow-internal-backend-src-services-auth-password-reset-service-ts-request-password-reset | password-reset request | exact-security-definer-function | preauth-fn-request-password-reset |
| workflow-internal-backend-src-services-auth-password-reset-service-ts-reset-password-with-token | password-reset completion | exact-security-definer-function | preauth-fn-consume-password-reset |
| workflow-startup-backend-src-services-auth-auth-bootstrap-repository-ts-find-pre-candidate-password-user | password-login lookup | exact-security-definer-function | preauth-fn-lookup-password-user |
| workflow-startup-backend-src-services-auth-auth-bootstrap-repository-ts-record-password-login-failure | failed-login recording | exact-security-definer-function | preauth-fn-record-password-failure |

## Exact function families

| Function | Purpose | Reads | Writes | One-time |
|---|---|---|---|---:|
| preauth-fn-consume-email-verification (`app_auth.consume_email_verification_token`) | Atomically consume one account-bound email-verification token, apply its exact verification/email-change state, and revoke sessions after an email change. | table-email-verification-token, table-refresh-token, table-user | table-audit-log-outbox, table-email-verification-token, table-refresh-token, table-user | yes |
| preauth-fn-consume-invitation (`app_auth.consume_invitation_token`) | Atomically activate the existing account bound to one invitation without changing its role or tenant ownership. | table-invite, table-licensee, table-organization, table-user | table-audit-log-outbox, table-invite, table-user | yes |
| preauth-fn-consume-password-reset (`app_auth.consume_password_reset_token`) | Atomically consume one valid reset token, activate/update its bound account password, and revoke existing sessions. | table-password-reset, table-refresh-token, table-user | table-audit-log-outbox, table-password-reset, table-refresh-token, table-user | yes |
| preauth-fn-lookup-invitation (`app_auth.lookup_invitation_token`) | Return the minimal preview for one valid invitation token without exposing its hash or unrelated tenant data. | table-invite, table-licensee, table-organization, table-user | none | yes |
| preauth-fn-lookup-password-user (`app_auth.lookup_password_user`) | Find exactly one password-login candidate without actor context and return only password-verification/account-state/context bootstrap fields. | table-user | none | no |
| preauth-fn-record-password-failure (`app_auth.record_password_failure`) | Atomically increment one normalized account's failed-login counter and establish bounded lockout state. | table-user | table-user | no |
| preauth-fn-request-password-reset (`app_auth.request_password_reset`) | Issue a reset-token row for exactly one eligible account while preserving a constant-success external response. | table-user | table-audit-log-outbox, table-password-reset | yes |

Exact arguments, return columns, table/column exposure, normalization, duplicate-state handling, expiry, locking, replay, transaction and P2 requirements live in `pre-auth-functions.json`.

## Execution grants and certification

The LOGIN pre-auth runtime receives only CONNECT, app_auth USAGE and EXECUTE on the seven exact signatures. PUBLIC, restricted-read and authenticated-app execution are denied; the NOLOGIN auth owner owns only app_auth and approved functions and receives exact required table-column privileges. The checked-in production definitions, rollback, generated policies and PostgreSQL 18 probe are maintained by the named-function contract registry.

All token functions reject ambiguous matches. Reset, invitation and email-consumption functions lock the token row and atomically consume it with account/session mutations. Reset request uses a constant-success external response. Invitation consumption never writes role or tenant ownership and cannot elevate a licensee invitation to a platform role.

