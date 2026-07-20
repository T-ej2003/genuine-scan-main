# MSCQR Operator Administration Review

This document reviews `operator-boundaries.json`. It creates no role, procedure, policy, grant, credential, infrastructure action, or runtime behavior.

## Identity model and environment ceilings

`identity-operator` is an individually attributable standing but restricted LOGIN named `mscqr_dev_operator`, `mscqr_staging_operator`, or `mscqr_prod_operator`. It owns nothing, has no owner membership, SET ROLE, superuser, BYPASSRLS, CREATE, migration credential, direct table privilege, application impersonation, broad visibility, or arbitrary SQL. Development may use disposable local actions but preserves the same forbidden capabilities. Staging may run exact activation, rollback, recovery and certification boundaries after evidence checks. Production additionally requires ticket, purpose, exact release/change binding, independent approval and immutable audit; staging success is never production approval.

Production break-glass is an individually attributable broker-issued identity with two distinct approvers, strong MFA, incident/ticket/purpose, an exact boundary allowlist and a maximum 30-minute lifetime. It is neither shared nor standing and cannot become an owner, migrator, SQL shell or policy bypass.

## Approved action classes

| Boundary | Class | Environments | Identity | Exact command/procedure | Max scope |
|---|---|---|---|---|---|
| operator-boundary-catalog-verification | catalog-verification | development, staging, production | identity-operator | app_ops.catalog_verification | catalog metadata for the exact programme manifest only |
| operator-boundary-health-readiness | read-diagnostics | development, staging, production | identity-operator | app_ops.health_readiness | one allowlisted component |
| operator-boundary-failed-job-summary | read-diagnostics | development, staging, production | identity-operator | app_ops.failed_job_summary | 100 rows within one tenant and job type |
| operator-boundary-tenant-incident-summary | read-diagnostics | development, staging, production | identity-operator | app_ops.tenant_incident_summary | one incident and at most 100 redacted events |
| operator-boundary-print-diagnostic | read-diagnostics | development, staging | identity-operator | app_ops.print_diagnostic | one batch aggregate; no QR payload rows |
| operator-boundary-deployment-preflight | deployment-preflight | development, staging, production | identity-operator | mscqr-operator deployment-preflight | catalog and release metadata only |
| operator-boundary-migration-broker | migration-broker | development, staging, production | identity-operator | mscqr-operator migration-broker | exact reviewed migration object set |
| operator-boundary-credential-rotation | credential-rotation | development, staging, production | identity-operator | mscqr-operator rotate-runtime-credential | one runtime identity credential and its registered consumers |
| operator-boundary-account-setup-link-reissue | account-recovery | development, staging, production | identity-operator | app_ops.reissue_account_setup_link | one existing account |
| operator-boundary-locked-account-recovery | account-recovery | development, staging, production | identity-operator | app_ops.recover_locked_account | one exact account |
| operator-boundary-operator-mfa-repair | mfa-repair | development, staging | identity-operator | app_ops.reset_account_mfa | one exact account |
| operator-boundary-breakglass-mfa-repair | mfa-repair | production | identity-production-break-glass | app_ops.reset_account_mfa | one exact account |
| operator-boundary-session-revocation | session-revocation | development, staging, production | identity-operator | app_ops.revoke_account_sessions | all sessions for one exact account |
| operator-boundary-tenant-security-recovery | tenant-security-recovery | development, staging, production | identity-operator | app_ops.recover_tenant_security_state | one tenant root and explicitly enumerated access links |
| operator-boundary-contain-user | incident-containment | development, staging, production | identity-operator | app_ops.contain_user | one exact user and that user's sessions |
| operator-boundary-contain-tenant | incident-containment | development, staging, production | identity-operator | app_ops.contain_tenant_access | one tenant and its enumerated access links |
| operator-boundary-contain-qr-batch | incident-containment | development, staging, production | identity-operator | app_ops.contain_qr_or_batch | one batch or one QR identity; released identity fields remain immutable |
| operator-boundary-contain-job-type | incident-containment | development, staging, production | identity-operator | app_ops.contain_job_type | one allowlisted job type and one tenant; platform scope requires explicit platform approval |
| operator-boundary-contain-credential | incident-containment | development, staging, production | identity-operator | app_ops.suspend_credential | one exact credential or connector |
| operator-boundary-retention-redaction | data-retention-redaction | development, staging, production | identity-operator | app_ops.redact_retained_evidence | one evidence object; immutable audit record is appended, never deleted |
| operator-boundary-job-recovery | job-recovery | development, staging, production | identity-operator | app_ops.recover_failed_job | one failed durable job |
| operator-boundary-staging-rls-fixture | RLS-readiness-check | staging | identity-operator | app_ops.prepare_rls_validation_fixture | one reserved synthetic tenant fixture with bounded QR count |
| operator-boundary-rls-readiness | RLS-readiness-check | development, staging, production | identity-operator | mscqr-operator rls-readiness | catalog metadata and bounded canary assertions only |
| operator-boundary-rls-activation | RLS-activation-control | staging, production | identity-operator | mscqr-operator rls-activate | one checksum-bound green build and traffic switch; blue database mutation is prohibited |
| operator-boundary-rls-rollback | RLS-rollback-control | staging, production | identity-operator | mscqr-operator rls-rollback | one recorded green database and its exact package-marked roles only |
| operator-boundary-breakglass-issuance | break-glass-only | production | identity-production-break-glass | mscqr-security-broker issue-breakglass | only targets permitted by the issued boundary allowlist |
| operator-boundary-prohibited-platform-role-repair | prohibited | development, staging, production | identity-production-break-glass | backend/scripts/repair-admin-accounts.js | zero rows |
| operator-boundary-prohibited-seed-and-test-data | prohibited | development, staging, production | identity-operator | registered Prisma/enterprise/launch-smoke seed and QR-reset workflows | zero rows |
| operator-boundary-prohibited-audit-browser | prohibited | development, staging, production | identity-operator | scripts/run-system-integration.mjs direct AuditLog SELECT | zero rows |

## Diagnostic model

Catalog verification exposes only programme-scoped ownership, RLS/FORCE, policy, grant, membership and signature metadata. Health is aggregate and redacted. Failed jobs are limited to one tenant/job type and 100 rows. Incident inspection is limited to one tenant/incident and redacted events. Print diagnostics return one batch aggregate, never QR payload rows. Direct audit-log browsing and secret/user enumeration remain prohibited.

## Migration broker

The exact migration broker command binds environment, reviewed migration ID, checksum, release SHA, preflight, approval, ticket and purpose. It follows `object-ownership-chain.json`: per-object transfer, privilege normalization, unconditional revocation and catalog verification. The operator receives neither migration credentials nor owner membership; any ownership or membership residue fails closed.

## Account, MFA and incident recovery

Setup-link reissue, locked-account recovery, MFA reset and session revocation each target one account, preserve role and tenant, revoke relevant sessions, return no hashes, require reason/approval and append immutable audit evidence. Production MFA repair additionally requires the 30-minute dual-approved break-glass identity. Incident procedures separately scope one user, tenant, QR/batch, job type or credential; they cannot change ownership or platform-admin status.

## RLS readiness, activation and rollback

Readiness binds release, policy, grant, role and baseline digests. Activation is staging/production only and binds readiness, exact release/migrations/baseline, approval, ticket, maintenance window, independent checker and checksum-paired rollback. Production also requires staging evidence. The operator verifies through normal non-bypass authority. Rollback is a separate exact command paired to the activation ID and artifact; disabling FORCE outside it is prohibited.

## Break-glass lifecycle

1. incident declared.
2. ticket created.
3. two distinct approvers approve.
4. broker creates individually attributable ephemeral credential.
5. exact boundary allowlist attached.
6. expiry fixed at no more than 30 minutes.
7. every command records actor/ticket/purpose/result.
8. automatic revocation at expiry.
9. early revocation remains available.
10. post-use catalog and data audit.
11. credential and memberships verified absent.

## Forbidden actions

- arbitrary SQL execution.
- ownership changes outside the migration broker.
- role membership changes outside the approved broker.
- disabling FORCE RLS without the paired rollback control.
- granting BYPASSRLS or superuser.
- direct platform-admin flag changes.
- tenant ownership changes.
- credential or token hash exposure.
- audit evidence deletion or attribution clearing.
- unbounded cross-tenant SELECT.
- permanent or shared break-glass credentials.

## Audit requirements

Every attempted action records the human actor, execution identity, ticket, approval, purpose, target, before/after digest, result, time bounds and revocation. Mutations are idempotent and transaction-bound; a conflicting retry is denied. Break-glass adds approvers, allowlist digest, credential lifecycle and post-use catalog/data audit.

## Remaining implementation work

Implement the exact `app_ops` procedures and operator/broker commands in later reviewed work, generate grants from this allowlist, retire prohibited scripts from protected runtime images, add disposable PostgreSQL certification and rehearse staged activation/rollback. This contract does not authorize execution.

