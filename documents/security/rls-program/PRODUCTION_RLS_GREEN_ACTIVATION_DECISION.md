# ADR: Production full-RLS activation uses an approval-gated isolated green cluster

Status: accepted in code; infrastructure and database remain unapplied.

Production login is not live-fixed until AWS applies the isolated green stack, the broker executes the approved package, restricted secret values are populated, and ECS activates the current release. The repository is ready for that sequence. On an empty green database, the approval-bound ownership phase provisions only two marked canary administrators and an isolation-control tenant from injected secrets; the platform canary then invites first pilot users through the normal audited setup-link flow. The mandatory journey covers password setup, email verification when required, MFA enrollment/completion, login, refresh, `/api/auth/me`, dashboard, QR, tenant isolation, and logout. A known-broken staging endpoint may be skipped only when the mandatory green pre-traffic canary replaces it.

PR #131 alone may record `known-blue-production-auth-http-500-pr131` when the existing `https://www.mscqr.com/api` blue deployment passes ready/live health and then returns HTTP 500 specifically from password login. The exception additionally requires the exact production-green branch, pull-request number, repository, and activation file scope; every other event, endpoint, stage, status, or health result fails closed. It does not relax the production activation workflow's mandatory green pre-traffic application canary.

## Decision

The current application release stays in place. Production RLS is installed from zero on a separate PostgreSQL 18 green instance because PostgreSQL roles are cluster-wide and the existing blue cluster must not be modified.

Production package generation and every executor launch require the same short-lived KMS-signed approval. The approval binds the production environment, release SHA, deployment ID, green database, source-contract digest, ordered migration digest, database administrator, approval and change IDs, exact independent checker session, KMS key, issue time, and expiry. A reviewed Lambda alias is the only `ecs:RunTask` authority; callers cannot select a task definition, network, command, environment, secret, or container override.

The generated SQL records the approved release, migration digest, approval-contract digest, approval ID, ticket, checker identity, expiry, and executing database administrator in `mscqr_rls_install.state`.

Runtime activation is all-or-nothing: the backend receives `DATABASE_URL`, `AUTHENTICATED_APP_DATABASE_URL`, `PREAUTH_DATABASE_URL`, and `MSCQR_C03_PREAUTH_DATABASE_URL`; the worker receives its restricted URL. Normal fail-closed application configuration is unchanged. No runtime role is a superuser, owner, `BYPASSRLS`, `CREATEDB`, or `CREATEROLE`.

## Consequences

- Blue remains untouched and receives no package role, policy, function, migration, or credential change.
- Green infrastructure can be provisioned before the two-hour approval window. Release-bound task definitions and the broker are enabled only after exact package digests exist.
- Traffic cannot switch until zero-based migrations, catalog verification, authenticated application canaries, refresh/MFA, `/auth/me`, dashboard stats, and QR stats pass.
- The zero-based contract is not a data-replication mechanism. If production has required customer data, activation stops until a separately reviewed data-transfer and reconciliation contract is approved.
- Automated cleanup is safe only before accepted green writes. After writes, incident and data-reconciliation authority is required.

## Rejected alternatives

- Application-layer Prisma fallback: it bypasses the designed database boundary and cannot cover the current route surface safely.
- Installing roles on blue: roles are cluster-wide and would mutate the live rollback target.
- Direct workflow `ecs:RunTask`: it permits unreviewed overrides and does not bind the independent approval to execution.
- Long-lived approval: it weakens release, package, database, and operator binding.
