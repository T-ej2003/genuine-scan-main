# MSCQR Staging RLS Manual SQL Review Runbook

Date: 2026-07-09
Environment: staging only
Scope: manual review and deliberate staging execution only
Production impact: none

## Hard Warning

Do not run these SQL templates in production.

Do not place these SQL files under `backend/prisma/migrations`.
Do not run them from CI/CD, Terraform, Prisma, application startup, or automated deployment hooks.
Do not enable any RLS route flag until the SQL has been reviewed, deliberately applied in staging, and baseline evidence exists.

Templates:
- `documents/security/mscqr_staging_rls_candidate_templates_2026-07-09.sql`
- `documents/security/mscqr_staging_rls_candidate_rollback_2026-07-09.sql`

Source documents:
- `documents/ops/MSCQR_STAGING_RLS_VALIDATION_PLAN_2026-07-09.md`
- `documents/ops/MSCQR_STAGING_RLS_DB_TOUCH_MAP_2026-07-09.md`
- `documents/security/mscqr_staging_rls_prototype.sql`

## 2026-07-15 Security Review Gate

This review supersedes any older instruction in this runbook that described one
runtime database role or one all-or-nothing candidate apply. The reviewed model
uses three exact, distinct roles:

- `mscqr_staging_app`: existing application LOGIN role. Its reviewed
  operational baseline is defined by
  `mscqr_staging_database_role_separation_template_2026-07-10.sql`.
- `mscqr_staging_rls_read`: SELECT-only staged-route LOGIN role.
- a dedicated candidate-managed auth owner: NOLOGIN, NOINHERIT and
  NOBYPASSRLS; it owns only `app_auth` and the two auth functions.

Candidate apply must receive all three role variables plus all three literal
phase variables. Auth helpers are installed in every phase, but table
enforcement is independent:

| Phase variable | Tables affected | Safe first-use posture |
| --- | --- | --- |
| `mscqr_enable_shared_force_rls` | `Organization`, `Licensee`, `User`, `ManufacturerLicenseeLink` | `false`; broad auth/recovery compatibility is incomplete |
| `mscqr_enable_batch_force_rls` | `Batch`, `InventoryStatusRollup`, `QRCode`, `PrintJob`, `PrintSession`, `PrintItem` | `true` only for the reviewed batches route window |
| `mscqr_enable_printer_force_rls` | six printer tables | `false` until its separate route window |

Application feature flags select which query path the process uses. They do not
enable, disable or scope PostgreSQL RLS. `FORCE ROW LEVEL SECURITY` is global to
every query using that table, even when every application flag is false.
Consequently, task definition `:8` enabling only
`MSCQR_STAGING_RLS_BATCHES_READ_ENABLED=true` must use a candidate apply with
shared=false, batch=true and printer=false. A batches-only rollout must never
silently force RLS on `User`.

### Staging evidence incorporated

- The original candidate denied password login because the pre-auth query saw
  null actor user, role, licensee and assurance settings.
- Password reset hash generation and persistence were independently verified;
  login returned 200 only after the pre-candidate application table privileges
  were restored.
- With RLS rolled back, password login, MFA challenge, MFA completion,
  `/api/auth/me`, batches and printers returned 200; an inaccessible allocation
  map returned the expected 404.
- The previous rollback revoked candidate/runtime grants without restoring the
  operational baseline. It left `User`, `Licensee`,
  `ManufacturerLicenseeLink`, `Batch` and `Printer` unreadable and required an
  emergency restoration of schema, table, sequence and function privileges.

The corrected candidate never rewrites the application or read-role baseline
grants. Rollback removes only candidate schemas, functions, policies, grants,
ownership and RLS settings. The disposable harness captures schema, table,
sequence and function privileges, memberships and role attributes before apply
and requires an empty diff after rollback.

## Password-Login Bootstrap Correction

With `User` FORCE RLS active, `POST /api/auth/login` previously called
`prisma.user.findUnique({ where: { email } })` while `app.user_id`, `app.role`,
and authentication assurance were empty. The authenticated-only `User` SELECT
policy correctly returned no row, and the service incorrectly classified a
valid account as `USER_NOT_FOUND` and returned the generic 401.

The candidate now creates two exact functions in the dedicated `app_auth`
schema:

- `app_auth.lookup_password_user(text)` accepts one already-normalized email
  and returns only password-login fields.
- `app_auth.record_password_failure(text, timestamp, integer, integer)` performs
  only the atomic failed-attempt and lockout mutation.

Both functions are `SECURITY DEFINER`, use only schema-qualified application
objects and a fixed `pg_catalog` search path, revoke `PUBLIC`, and grant EXECUTE
only to `mscqr_staging_app` (never to the RLS read role). Their owner is a dedicated `NOLOGIN`,
`NOINHERIT`, `NOBYPASSRLS` role with column-level `User` privileges and exact
owner-only RLS policies. The runtime role cannot assume that role, receives no
broad pre-authentication `User` SELECT or UPDATE capability, and cannot redirect
either function with caller-supplied actor, role, tenant, licensee, or RLS
session variables.

After password verification, the application derives transaction-local RLS
context only from the database-returned bootstrap row. Successful-attempt reset,
lock clearing, optional password rehash, `lastLoginAt`, session construction,
manufacturer scope, and MFA bootstrap reads then run in that verified context.
Wrong-password and unknown-email responses remain the same generic 401.

### Pre-authentication flow inventory

| Route/flow | Tables touched at trust transition | State | Current forced-`User` compatibility | Required boundary | Broad rollout blocker |
| --- | --- | --- | --- | --- | --- |
| `POST /api/auth/login` | `User`, MFA/challenge, refresh and audit tables | Pre-auth then verified | Implemented and regression-tested | Exact normalized-email lookup; atomic failure function; database-row-derived context only after password verification | No for this route |
| TOTP/WebAuthn login completion | MFA factors/challenges, `User`, `Licensee`, link, `RefreshToken`, `AuditLog` | Signed MFA bootstrap | Implemented and forced-RLS tested | Signed bootstrap claims establish transaction-local context before session issuance | No for login completion |
| `GET /api/auth/me` | `User`, `Licensee`, link, refresh/MFA state | Authenticated | Implemented and forced-RLS tested | Signed access claims establish one transaction-local read context | No |
| `POST /api/auth/forgot-password` | `User`, `PasswordReset` | Pre-auth | Blocked | Exact email reset-request boundary | Yes |
| `POST /api/auth/reset-password` | `PasswordReset`, `User` | Pre-auth token | Blocked | Atomic valid-token consumption and exact user mutation | Yes |
| Invite preview/accept/setup | `Invite`, `User`, `Licensee` | Pre-auth token | Blocked | Exact invite-token boundary; verified inviter context for creation | Yes |
| Email verification/change | verification token, `User` | Pre-auth token | Blocked | Atomic token consumption and collision checks inside trusted SQL | Yes |
| `POST /api/auth/refresh` / session bootstrap | `RefreshToken`, `User`, `Licensee`, link | Pre-auth refresh token | Blocked | Context derived from a verified refresh record, never request claims | Yes |
| WebAuthn setup and non-login step-up | `User`, WebAuthn/MFA tables | Authenticated | Not comprehensively forced-RLS validated | Signed authenticated-claims context at every direct `User` access | Yes |
| Staged batch reads | batch family plus shared tenant/link lookups | Authenticated | Compatible with shared RLS left disabled | Signed claims on the dedicated read transaction | No for batch-only phase |
| Staged printer reads | printer family plus shared tenant/link lookups | Authenticated | Route-specific validation required | Signed claims on the dedicated read transaction | Yes until its phase gate passes |

These unresolved flows are candidate-wide deployment blockers if they are
required in the validation window. Do not broaden `app_auth` or weaken `User`
RLS to cover them; add one exact, reviewed trust boundary per token type.

## Preflight Checklist

- Confirm the target is staging, not production.
- Confirm all three route flags remain disabled:
  - `MSCQR_STAGING_RLS_BATCHES_READ_ENABLED`
  - `MSCQR_STAGING_RLS_BATCH_ALLOCATION_MAP_ENABLED`
  - `MSCQR_STAGING_RLS_MANUFACTURER_PRINTERS_READ_ENABLED`
- Confirm `DATABASE_URL` remains the existing default application read/write credential.
- Confirm `RLS_READ_DATABASE_URL` is provisioned separately for the reviewed non-owner runtime credential, does not exactly equal `DATABASE_URL`, and is not printed or copied into review evidence.
- Confirm an enabled route flag with a missing, malformed, non-PostgreSQL, database-name-less, equal-to-default, unreachable, or unsafe-posture RLS URL fails startup and readiness without falling back to the default client.
- Confirm the SQL files are outside `backend/prisma/migrations`.
- Confirm no hardcoded user IDs, licensee IDs, org IDs, batch IDs, printer IDs, emails, tokens, hostnames, secrets, or production references were added.
- Confirm the migration/owner role and runtime role are different exact PostgreSQL roles.
- Confirm reviewer approval for both `mscqr_app_role` and `mscqr_rls_read_role`; they must be the exact distinct reviewed application and SELECT-only roles.
- Confirm reviewer approval for `mscqr_auth_owner_role`. The templates require `-v mscqr_auth_owner_role=<dedicated_nologin_auth_function_owner_role>` and the role must be distinct from the runtime and migration roles.
- Confirm both LOGIN roles are `NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`, own none of the protected tables, cannot create in `public` or `app_auth`, and inherit no role.
- Confirm the auth owner is `NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT`, has no memberships, and cannot be assumed by the runtime role.
- Confirm `PUBLIC` is not used as the helper grant target. `PUBLIC` is forbidden for this validation because staging may already have unrelated `app_rls` helpers.
- Confirm staging backend is healthy before any SQL apply window.
- Confirm rollback SQL has been reviewed in the same review session as the candidate SQL.

## Backup And Snapshot Checklist

- Take or verify a fresh staging database snapshot before applying SQL.
- Record the snapshot identifier in the private operator notes, not in this repository.
- Confirm the operator can restore staging from the snapshot if rollback is insufficient.
- Confirm the rollback template is locally available in the same terminal session.
- Confirm CloudWatch access is available for application logs and proof events.

## Dry-Run And Review Checklist

- Review the candidate template section by section before execution:
  - shared context helpers
  - non-recursive access helpers
  - shared tenant tables
  - batch and allocation-map tables
  - raw SQL summary tables
  - printer local-agent/profile/status tables
- Confirm `ManufacturerLicenseeLink` policy does not call `app_rls.can_access_licensee`.
- Confirm `PrinterRegistration` policy is a non-recursive parent policy and does not depend on `Printer`.
- Confirm `Printer` may depend on `PrinterRegistration`, but `PrinterRegistration` does not depend back on `Printer`.
- Confirm `PrinterProfileSnapshot` depends through `PrinterProfile` and visible `Printer`.
- Confirm no policy includes `Printer.isActive`; inactive behavior must stay in the application query filter.
- Confirm `PrintItem`, `PrintSession`, and `PrintJob` visibility preserves QR reservable-summary left-join count correctness.
- Confirm the only application-role write policy added is `rls_candidate_user_auth_update`, scoped to the authenticated actor. Candidate apply does not revoke or reconstruct application table privileges.

## Required Database Role Model

The migration/owner role applies Prisma migrations and owns schemas and tables. `mscqr_staging_app` retains its pre-candidate reviewed operational baseline and alone receives EXECUTE on the two `app_auth` functions. `mscqr_staging_rls_read` remains SELECT-only on the 16 candidate tables and can execute only the exact `app_rls` helpers. A third dedicated NOLOGIN role owns `app_auth` and its two functions and receives only their required `User` columns. Neither LOGIN role is a member of the owner role, and neither may create objects in `public` or `app_auth`.

The application must preserve `DATABASE_URL` for the existing default Prisma read/write client and use `RLS_READ_DATABASE_URL` only for the staged RLS read client. The RLS URL must authenticate as the reviewed runtime role, must not exactly equal `DATABASE_URL`, and must never be derived from or fall back to either the migration/owner URL or `DATABASE_URL`. PostgreSQL table owners normally bypass RLS; `FORCE ROW LEVEL SECURITY` narrows that risk, but a dedicated non-owner remains mandatory because it makes the runtime trust boundary independently testable and prevents an owner/admin connection from becoming the staged RLS data plane.

Only these routes may use the separate client, and only when their exact flag is enabled:

| Route | Flag |
| --- | --- |
| `GET /api/qr/batches` | `MSCQR_STAGING_RLS_BATCHES_READ_ENABLED` |
| `GET /api/qr/batches/:id/allocation-map` | `MSCQR_STAGING_RLS_BATCH_ALLOCATION_MAP_ENABLED` |
| `GET /api/manufacturer/printers` | `MSCQR_STAGING_RLS_MANUFACTURER_PRINTERS_READ_ENABLED` |

The default client continues to serve every mutation and all non-staged reads except the reviewed password-login `User` state update. The RLS role has no INSERT, DELETE, or sequence privileges and no other candidate write policy. Switching the global client without completing the pre-authentication flow inventory would break authentication recovery, invitations, verification, administration, batch/QR lifecycle, printing, printer management, rollups, and manufacturer-licensee link writes.

## Exact Pre-Apply Staging Checks

Run these read-only catalog checks through approved private operator tooling. Do not paste connection strings or results containing private infrastructure values into the repository.

```sql
SELECT session_user, current_user, current_role, current_setting('row_security');

SELECT rolname, rolsuper, rolcreatedb, rolcreaterole, rolreplication,
       rolbypassrls, rolcanlogin
FROM pg_roles
WHERE rolname IN ('<migration_owner_role>', '<runtime_role>');

SELECT c.relname, owner.rolname AS table_owner,
       c.relrowsecurity, c.relforcerowsecurity,
       pg_has_role('<runtime_role>', c.relowner, 'USAGE') AS runtime_owns_or_inherits_owner,
       has_table_privilege('<runtime_role>', c.oid, 'SELECT') AS runtime_has_select
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
JOIN pg_roles owner ON owner.oid = c.relowner
WHERE n.nspname = 'public'
  AND c.relname = ANY(ARRAY[
    'Organization', 'Licensee', 'User', 'ManufacturerLicenseeLink',
    'Batch', 'InventoryStatusRollup', 'QRCode', 'PrintJob', 'PrintSession',
    'PrintItem', 'PrinterRegistration', 'Printer', 'PrinterAttestation',
    'PrinterAgentSession', 'PrinterProfile', 'PrinterProfileSnapshot'
  ])
ORDER BY c.relname;

WITH RECURSIVE inherited(role_oid, role_name) AS (
  SELECT granted.oid, granted.rolname
  FROM pg_auth_members m
  JOIN pg_roles member ON member.oid = m.member
  JOIN pg_roles granted ON granted.oid = m.roleid
  WHERE member.rolname = '<runtime_role>'
  UNION ALL
  SELECT granted.oid, granted.rolname
  FROM inherited
  JOIN pg_auth_members m ON m.member = inherited.role_oid
  JOIN pg_roles granted ON granted.oid = m.roleid
)
SELECT DISTINCT role_name FROM inherited ORDER BY role_name;
```

Gate: the runtime role must have no elevated attributes, no transitive memberships, and no ownership result. The auth owner must have no login, elevated attributes, or memberships and must be distinct from the runtime and migration roles. Do not reapply in staging until the disposable harness, password-login forced-RLS regression, backend typecheck, changed-file lint, and document guards all pass and the runtime connection secret is independently reviewed.

The pre-apply identity evidence must come from the same private runtime credential and session shape that the backend will use. Capture only secret-free booleans/counts proving `session_user`, `current_user`, `current_role`, `row_security`, safe direct attributes, no inherited roles, no protected-table ownership, and the intended narrow grants. After apply, the first startup probe must prove only the table families selected by the three phase variables are forced, the expected phase policies exist, both LOGIN roles retain their reviewed grants, only the application role can execute `app_auth`, and neither `PUBLIC` nor the read role can cross the pre-auth boundary. Do not retain a URL, password, hostname, token, hash, or raw connection diagnostics in repository evidence.

When any staged flag is enabled, startup connects the lazy, process-level RLS Prisma client and refuses to serve if configuration, connectivity, or the runtime posture check fails. `/health/ready` and `/health/db` treat that connection as required and report a secret-free degraded result on failure. With every flag disabled, `RLS_READ_DATABASE_URL` is optional, the second client/pool is not created, and readiness behaves as before. Graceful shutdown drains and disconnects both cached clients; requests never create or disconnect a Prisma client.

## Disposable Harness Gate

Before manual staging apply, the disposable SQL harness must pass against a local disposable database.

Non-mutating guard/unit check:

```bash
npm run check:rls:disposable-sql-harness
```

Separate-client configuration, lifecycle, readiness, and route-wiring check:

```bash
npm --prefix backend run test:rls:read-client
```

Full disposable apply/rollback proof placeholder:

```bash
npm run test:p2:db:up
createdb -h 127.0.0.1 -p 55432 -U mscqr_p2_test mscqr_rls_harness_runtime_role_test

env -u DATABASE_URL -u TEST_DATABASE_URL -u P2_TEST_DATABASE_URL \
MSCQR_DISPOSABLE_RLS_HARNESS_CONFIRM=MSCQR_RUN_DISPOSABLE_RLS_HARNESS \
MSCQR_DISPOSABLE_RLS_DATABASE_URL="postgresql://mscqr_p2_test@127.0.0.1:55432/mscqr_rls_harness_runtime_role_test" \
MSCQR_DISPOSABLE_RLS_RUNTIME_ROLE="mscqr_rls_harness_runtime_$(date +%s)" \
npm run test:rls:disposable-sql-harness

dropdb -h 127.0.0.1 -p 55432 -U mscqr_p2_test mscqr_rls_harness_runtime_role_test
```

The disposable database URL must be local-only and the database name must include `rls_harness`, `disposable`, `test`, or `ci`. The harness refuses staging, production, RDS, AWS, Supabase, Neon, Render, Railway, public-host, and non-local/shared-looking database URLs. It also refuses a missing runtime role, `PUBLIC`, reuse of the URL owner as runtime, unsafe runtime attributes, runtime table ownership, inherited roles, and candidate SQL under Prisma migrations. It prints sanitized connection metadata only, never a full database URL or password.

The harness proves:
- candidate SQL applies cleanly to the disposable schema
- expected `app_rls` helpers exist after apply
- both exact `app_auth` functions exist with `SECURITY DEFINER`, `pg_catalog` search paths, schema-qualified application objects, dedicated ownership, application-role-only EXECUTE, and no read-role/PUBLIC execution
- expected candidate SELECT policies exist after apply
- candidate tables have RLS and FORCE RLS enabled after apply
- `session_user` remains the owner while `current_user` and `current_role` are the explicit non-owner runtime role for every RLS assertion
- all 17 helpers fail closed with missing context and are not executable by `PUBLIC`
- empty pre-authentication context cannot enumerate `User`, unrelated roles cannot execute `app_auth`, and manipulated RLS variables cannot redirect the exact email lookup
- valid password login, generic wrong/unknown failures, lockout, successful reset/last-login mutation, and manufacturer MFA bootstrap pass under forced RLS
- exact IDs match for platform, licensee, manufacturer, organization, unrelated-tenant, missing, malformed, empty-string, and tenant-A-to-tenant-B cases
- INSERT and DELETE are denied on all 16 tables; UPDATE is denied except for the authenticated actor's five password-login columns on `User`
- optional route-specific runtime tests pass in disposable P2 databases when `--run-route-tests` is used
- first apply succeeds; second apply fails before mutation with a clear rollback-first message
- missing and wrong psql variables exit nonzero before candidate objects exist
- rollback removes policies, helpers, auth functions/schema/owner role, candidate grants, and table RLS settings
- representative baseline queries pass before apply and after rollback, and schema/table/sequence/function privileges, memberships and role attributes have an empty grant diff
- a second rollback fails clearly and transactionally without changing the restored baseline

The harness does not replace manual SQL review, baseline capture, staging snapshot approval, or CloudWatch proof-event validation.

Do not claim readiness unless the full disposable route run uses a separate runtime connection URL, executes all three real route/service query graphs inside one transaction each, detects any nested fallback to the default client, proves concurrent tenant context isolation and transaction-local cleanup, and confirms runtime writes are still denied.

## Manual psql Command Placeholders

Use placeholders only. Do not write real secrets or hostnames into repository files or PR comments.

Review-only parse in a safe disposable environment:

```bash
psql "$STAGING_REVIEW_DATABASE_URL" \
  -v ON_ERROR_STOP=1 \
  -v mscqr_app_role="mscqr_staging_app" \
  -v mscqr_rls_read_role="mscqr_staging_rls_read" \
  -v mscqr_auth_owner_role="$REVIEWED_NOLOGIN_STAGING_AUTH_OWNER_ROLE" \
  -v mscqr_enable_shared_force_rls=false \
  -v mscqr_enable_batch_force_rls=true \
  -v mscqr_enable_printer_force_rls=false \
  -f documents/security/mscqr_staging_rls_candidate_templates_2026-07-09.sql
```

Rollback in the same staging validation window if needed:

```bash
psql "$STAGING_REVIEW_DATABASE_URL" \
  -v ON_ERROR_STOP=1 \
  -v mscqr_app_role="mscqr_staging_app" \
  -v mscqr_rls_read_role="mscqr_staging_rls_read" \
  -v mscqr_auth_owner_role="$REVIEWED_NOLOGIN_STAGING_AUTH_OWNER_ROLE" \
  -f documents/security/mscqr_staging_rls_candidate_rollback_2026-07-09.sql
```

The placeholder `STAGING_REVIEW_DATABASE_URL` must be resolved from private operator tooling, not committed or printed.
The two LOGIN role names are exact staging identities. Empty, reserved, quoted, injected or nonexistent role names are refused; unexpected memberships, LOGIN on the owner, BYPASSRLS and unsafe attributes are also refused before candidate objects are created.
The placeholder `REVIEWED_NOLOGIN_STAGING_AUTH_OWNER_ROLE` must be the exact reviewed dedicated function-owner role, distinct from runtime and migration roles. The candidate creates it if absent and refuses unsafe existing attributes or memberships; rollback drops it.

## Apply Order

This is the exact future sequence; it is documentation only and was not executed by this change:

1. Keep all route flags disabled.
2. Provision and privately review a distinct `RLS_READ_DATABASE_URL` credential for the exact non-owner runtime role; keep `DATABASE_URL` unchanged.
3. Prove runtime identity, attributes, membership, ownership, and grants from that credential without printing it.
4. Run the complete local separate-client, route, concurrent-context, write-denial, rollback, and document gates.
5. Run `npm --prefix backend run test:rls:auth-bootstrap` and capture only its pass/fail status; do not retain credentials, password hashes, tokens, or raw database output.
6. Capture baseline outputs for password login, manufacturer MFA bootstrap/completion, and the three candidate endpoints.
7. Confirm staging DB snapshot and rollback readiness.
8. Optional install-only rehearsal: apply with all three phase variables `false`. This installs reviewed helpers but forces no application table. Prove password login and rollback equivalence.
9. For the task-definition `:8` batches-only window, apply with shared=false, batch=true and printer=false. This must not enable RLS on `User`, `Licensee`, `Organization` or `ManufacturerLicenseeLink`.
10. Before any deployment, confirm catalog state matches that phase exactly and re-run password login, MFA challenge/completion, `/api/auth/me`, refresh and recovery smoke tests. Roll back immediately on any deviation.
11. Enable only `MSCQR_STAGING_RLS_BATCHES_READ_ENABLED`, then validate `/api/qr/batches` and inaccessible allocation-map behavior. Keep unrelated route flags false.
12. Disable the batch flag and confirm the separate pool drains before rollback.
13. Printer and shared/User enforcement require later, separately reviewed windows. Do not infer their approval from the batch phase.

**Staging task definition `:8` must not be deployed until candidate-active password login and MFA validation pass and catalog proof confirms `User` FORCE RLS is disabled for the batch-only phase.** This repository change does not authorize SQL apply, task registration, ECS update, or deployment.

Do not enable all three flags together during first validation.

## Rollback Order

1. Disable every staged RLS route flag.
2. Restart the affected backend process and confirm readiness reports the RLS dependency disabled, so the separate pool is drained and no route can use the runtime credential.
3. Run `mscqr_staging_rls_candidate_rollback_2026-07-09.sql` manually in staging.
4. Confirm candidate policies are gone.
5. Confirm candidate helper functions, `app_auth` functions/schema, and the dedicated auth owner role are gone.
6. Confirm table RLS and FORCE RLS are disabled for the candidate table set.
7. Re-run read-only baseline endpoint checks through the unchanged default client.
8. Escalate to staging snapshot restore only if rollback does not restore expected behavior.

Disabling the flags is the application rollback and leaves all writes on `DATABASE_URL`. The private `RLS_READ_DATABASE_URL` value may remain configured while all flags are false because it is optional and unused, but remove or rotate it after rollback according to the approved credential lifecycle. To rotate before a later validation, keep every flag false, provision/review the replacement restricted credential, update only `RLS_READ_DATABASE_URL`, restart, enable one flag so startup probes the replacement, validate, disable it again, then revoke the old login after all old processes and pools are gone.

Rollback is a go/no-go gate, not an afterthought. Before reapply approval, prove the rollback file is byte-for-byte the reviewed companion, receives the same exact three role variables, removes only candidate objects/grants/RLS settings, and leaves an empty pre-apply versus post-rollback grant diff. A second rollback must fail clearly before mutation rather than report false success.

## Validation Order

Validate actor classes:
- platform admin
- licensee admin
- org admin
- manufacturer admin or user
- cross-tenant user
- missing tenant context user

Validate data cases:
- batch owned by licensee A
- batch owned by licensee B
- manufacturer child batch
- parent/root/source allocation lineage
- batch with QR codes
- batch with inventory rollup
- batch with print item, session, and job history
- network printer under scoped licensee
- network printer under another licensee
- local-agent printer assigned to current user
- local-agent printer registered by current user
- local-agent printer with latest attestation
- local-agent printer with connected agent session
- local-agent printer with profile and profile snapshot
- inactive printer with `includeInactive` behavior controlled by the application filter

Compare:
- HTTP status
- response object IDs
- row counts
- QR status summaries
- reservable QR summary counts
- printer connection/status fields
- proof event success fields

## CloudWatch Proof-Event Checks

Expected proof events:
- `staging_rls_manufacturer_printers_read_proof`
- `staging_rls_batches_read_proof`
- `staging_rls_batch_allocation_map_proof`

For each enabled flag, confirm:
- `flagEnabled=true`
- expected `contextClass`
- `success=true`
- row count or result shape matches baseline
- no `rls_context_missing`
- no `rls_context_forbidden`
- no `database_error`
- no `unexpected_error`
- no raw user, licensee, batch, printer, device, token, IP, hostname, or email identifiers appear in proof logs

## Stop And Fail Criteria

Stop immediately and disable the active flag if:
- valid password login fails with candidate-active `User` RLS, wrong and unknown accounts diverge, lockout state does not update, or successful login state is not reset
- manufacturer password login does not reach MFA bootstrap, or MFA setup/challenge completion cannot issue an authenticated session
- startup succeeds when an enabled flag has missing or invalid `RLS_READ_DATABASE_URL`
- `RLS_READ_DATABASE_URL` equals `DATABASE_URL`, or runtime identity/posture cannot be proven
- the RLS client cannot connect or readiness does not become degraded on RLS dependency failure
- an enabled route query or nested helper uses the default Prisma client
- transaction-local context leaks after commit/rollback or between concurrent tenants
- any candidate endpoint returns 500
- cross-tenant data appears
- baseline and RLS-enabled object IDs differ unexpectedly
- baseline and RLS-enabled counts differ unexpectedly
- proof event is missing
- proof event reports failure
- CloudWatch shows database or RLS errors
- missing app context does not fail closed
- platform admin bypass fails
- manufacturer linked-licensee access fails
- local-agent printer status loses registration, attestation, session, profile, or snapshot data
- raw SQL reservable summaries drift from baseline

If disabling the flag is insufficient, run the rollback SQL. If rollback is insufficient, use the staging snapshot restore path.

## Remaining Review Risks

- Enabling table RLS affects staging table access globally, even though the route flags control only the staged application read paths.
- Forgot/reset password, invitation/setup, email verification, refresh bootstrap, and some WebAuthn/step-up paths still need exact trust boundaries before the runtime role can safely serve them with `User` FORCE RLS active.
- The only candidate runtime write is the authenticated actor's five password-login state columns on `User`; all other application writes on these 16 tables remain blocked until separately designed policies and grants exist.
- RLS helper grants are scoped to both exact LOGIN roles; auth-function EXECUTE is scoped only to `mscqr_staging_app`. The functions are owned by the exact reviewed `mscqr_auth_owner_role`; rollback revokes exact candidate signatures/grants and drops the candidate-created auth owner and schemas without reconstructing baseline table grants.
- Raw SQL summaries are sensitive to left-join visibility. Validate IDs and counts, not only HTTP 200.
- Batch allocation-map lineage relies on linked-licensee access to preserve parent/root/source visibility for authorized focus batches.
- Printer local-agent policies depend on the PR #109 transaction-aware read graph; do not validate these SQL templates against older backend revisions.

## Senior Engineering Recommendation

Keep migration/owner, runtime application, staged read-only, and NOLOGIN auth-function-owner identities permanently distinct. Before expanding candidate-active traffic, implement one token-specific SQL boundary for password recovery, invitations, verification, and refresh; do not grow the password-login function into a general user repository. Treat startup/readiness posture, route-scoped transactions, auth-flow regression proof, and pool capacity as release gates. For scalability, add a staging RLS proof dashboard keyed by route, flow, flag, context class, exact-ID delta, failure category, and p95 duration, plus a CI-generated policy-to-table/function coverage manifest so new tables or pre-authentication flows cannot silently escape review.
