# Production Green Phase 4A: read-only RLS canary

This is a separately reviewed, fixed-command package for a future one-shot production RLS isolation check. No production task, SQL, Lambda, ECS action, Terraform apply, image publication, secret creation, or AWS mutation was executed while implementing it.

## Threat model and boundaries

The threat is a task or credential becoming an application mutation path, a tenant selector being supplied at launch, cross-tenant visibility, or a broker/retry causing an ambiguous repeat. The task runs only `node scripts/production-green-read-only-rls-canary.mjs`; it rejects arguments and environment outside its fixed runtime allowlist. It has no HTTP client use, login, MFA, OTP, session, audit, write SQL, broker invocation, DynamoDB, ECS, IAM, service-update, or S3 permission.

The execution role can pull the immutable reviewed backend image, write only its dedicated CloudWatch stream, and read exactly `mscqr/production/rls-green/phase4/read-only-canary-database-url-*`. The empty task role has no runtime permissions. ECS networking is the Stage A executor group `sg-051a24aedff773761`, using only the approved private production subnets selected by the reviewed private Stage A production subnet inputs, with `assign_public_ip` remaining `false`.

## Query allowlist and evidence

Only these source-controlled statements are issued: `BEGIN READ ONLY`; the identity `SELECT` for `current_user`, `current_database()`, `transaction_read_only`, `session_user`, and `application_name`; `SELECT ... FROM app_rls.production_read_only_canary_probe()`; `COMMIT` or error-only `ROLLBACK`. The function returns only `same_tenant_visible` and `foreign_tenant_invisible`; it reads the initializer-owned green-only control object under FORCE RLS and returns no rows, URLs, credentials, tokens, or identifiers.

The JSON evidence contains status, deterministic exit code (0 pass, 20 input contract, 21 database/identity, 22 isolation), role, application name, and a boolean database verification. Failure evidence redacts the URL length only.

## Database privilege matrix

| Principal | Allowed | Explicitly absent |
|---|---|---|
| `mscqr_prod_rls_canary_read` | LOGIN, CONNECT to `mscqr_production`, USAGE `app_rls`, EXECUTE one zero-argument probe | ownership, membership, CREATE, table write/read grants, BYPASSRLS, role administration |
| `mscqr_prod_auth_owner` | owns the reviewed stable probe and receives the narrowly scoped RLS policy | task credential, canary role membership |

The reviewed ownership phase creates `app_rls.production_read_only_canary_control` from the deterministic initializer-created canary and isolation-control licensees. It contains only those two green-only scope identifiers, is FORCE RLS, and grants the canary role no table access. `production-green-phase-4-read-only-canary-provision.sql` validates negative privileges, derives the canary scope only from that control object, sets statement/lock/idle transaction timeouts and `default_transaction_read_only=on`, and ends with its canary-only revoke/drop rollback procedure. It embeds no password, secret, fixture UUID, or business record. Before first provisioning, the approved secret process generates one dedicated credential and writes the matching PostgreSQL URL to the dedicated canary secret. A DBA then enters that same generated value only through psql's hidden `\password` prompt. Existing credentials are preserved unless the DBA supplies the explicit `canary_credential_rotation=true` mode under a new approved secret-rotation record; rollback never prints, reuses, or retains a credential. RDS IAM authentication is not configured: the task has no `rds-db:connect` authority, so the static dedicated-secret credential is the only supported authentication method.

## Approval, launch, stop, and rollback

Before deployment, a DBA must verify the initializer receipt and its green-only control object, apply the provisioning SQL, create/populate the dedicated secret, and confirm the green database name/endpoint. Security must review the immutable image digest, task-definition ARN, role/policy diff, and the exact secret ARN. Release management must manually approve a one-shot execution and capture evidence. Stop on any identity mismatch, non-read-only transaction, missing own-scope control record, foreign visibility, launch ambiguity, or unavailable evidence; do not automatically retry an ambiguous result.

The future approval binding is the exact registered ARN for `mscqr-production-full-rls-green-read-only-canary`; command, environment, network, task-role, and image overrides are prohibited. The existing broker is deliberately unchanged: its replay protection and manual approval model remain a future integration decision, and this task has no broker or replay-table access. Its documented `aws:PrincipalArn` condition duplicates the restriction already provided by an exact release-deployer `Principal`; AWS evaluates both, so it is defensible as defense-in-depth but does not broaden authority. Any cleanup of that redundant condition is a separate Terraform change.

Rollback is the explicit canary-only revoke/drop sequence in the provisioning file, then task-definition deregistration after approvals. Never revoke shared grants, policies, roles, or secrets as part of this rollback.
