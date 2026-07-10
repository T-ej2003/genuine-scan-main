# MSCQR RLS Runtime Role Hardening Decision Record

Date: 2026-07-10
Scope: local backend runtime wiring, local disposable PostgreSQL, and non-applied staging SQL templates only
Cloud/database impact: none; staging remained rolled back

## Outcome

The disposable proof now uses two PostgreSQL identities:

- migration/owner: the explicit local database URL username, which runs Prisma schema setup and owns all 16 protected tables
- runtime: a required fresh `NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS` role that owns no protected table and inherits no role

Candidate DDL is applied as the migration owner. Every RLS diagnostic, helper probe, exact-ID visibility assertion, and write-denial assertion runs after `SET LOCAL ROLE <runtime_role>`. The harness never derives the runtime role from the owner URL.

The backend now preserves its existing read/write Prisma client on `DATABASE_URL` and adds a separate, lazy Prisma client whose datasource is overridden only with `RLS_READ_DATABASE_URL`. The second URL is for a dedicated login credential whose effective PostgreSQL identity is the reviewed non-owner, SELECT-only runtime role. The disposable harness may continue to model that role with a fresh `NOLOGIN` role plus `SET LOCAL ROLE`; the deployed read credential must be able to authenticate without changing the required non-owner, non-bypass posture.

## Phase-One Application Role Matrix

| Prisma `UserRole` | Phase-one staged RLS status | Context behavior |
| --- | --- | --- |
| `SUPER_ADMIN` | active | platform context only when the explicit platform setting is true |
| `PLATFORM_SUPER_ADMIN` | active | platform context only when the explicit platform setting is true |
| `LICENSEE_ADMIN` | active | tenant context; licensee association required |
| `MANUFACTURER` | active | manufacturer context; user ID is the manufacturer ID |
| `ORG_ADMIN` | dormant | denied before a RLS transaction is started |
| `MANUFACTURER_ADMIN` | dormant | denied before a RLS transaction is started |
| `MANUFACTURER_USER` | dormant | denied before a RLS transaction is started |

The dormant values remain in the Prisma enum and pre-RLS compatibility helpers. They do not appear in the candidate SQL and cannot gain phase-one access without a separate activation decision, policy design, static role-matrix update, and route proof.

## Root-Cause Evidence

The previous harness had a concrete identity bug: `--app-role` only populated the psql variable used as the helper grant target. `runPsql`, object inventory, and all other database calls continued to connect with the single database URL. There was no runtime connection and no `SET ROLE`. Consequently it could prove object creation and rollback, but could not prove RLS behavior for a non-owner application identity.

The observed staging row visibility is not evidence that the 17 original helpers returned true without context. The hardened disposable proof called every helper directly with missing settings; identifier helpers returned null, `current_role()` returned the empty string, and every boolean access helper returned false without recursion.

One staging-specific conclusion must remain evidence-bounded: table ownership alone cannot explain visible rows when all of the reported staging facts are simultaneously true. A local PostgreSQL control using a non-superuser, `NOBYPASSRLS` table owner with both ENABLE and FORCE RLS returned zero rows under a false policy, both immediately and in a later transaction. An inherited membership in a `BYPASSRLS` role also did not bypass RLS for the child current role. The local Docker URL owner did expose rows under FORCE because that Docker bootstrap role is a direct superuser; the separated runtime role did not.

The completed staging exercise recorded the connection/URL role but did not preserve the decisive statement-time tuple (`session_user`, `current_user`, `current_role`, direct role attributes, transitive membership, `row_security`, table owner, and RLS flags) in the same session as the unexpected counts. Staging is rolled back and this task forbids reconnecting to it. Therefore the exact statement-time staging bypass path cannot honestly be reconstructed from the retained facts alone. Plausible paths that the new diagnostics will distinguish are a different effective `current_user`, a direct superuser or `BYPASSRLS` effective role, or flags/settings observed in a different transaction/session from the count probe. Reapplying before capturing that tuple is forbidden.

## SQL Hardening

- All helper and table grants target only `mscqr_runtime_role`.
- Candidate SQL rejects `PUBLIC`, a missing role, an elevated runtime role, the current migration role, and runtime ownership/inherited ownership of protected tables.
- PostgreSQL's default `PUBLIC` function execution is revoked for all 17 exact helper signatures before runtime grants.
- Platform access requires both the exact `SUPER_ADMIN` or `PLATFORM_SUPER_ADMIN` application role and the explicit platform-admin flag.
- Licensee, manufacturer, organization, and user-ID branches are limited to the four active phase-one roles. Manufacturer context also requires `app.manufacturer_id = app.user_id`.
- Only explicit SELECT is granted on the 16 tables. No sequence privilege is needed for this SELECT-only candidate, and no INSERT, UPDATE, DELETE, or write policy was added.
- Rollback reverses the exact table, function, and schema grants and removes candidate objects and RLS flags.

## Disposable Test Matrix

Exact visible IDs were asserted across all 16 tables for:

- explicitly controlled platform admin
- licensee admin for tenant A
- manufacturer A linked only to licensee A
- each dormant enum role, which is denied before a RLS transaction
- unrelated tenant B
- missing context
- malformed role/context
- empty-string context
- tenant A querying for tenant B data

The matrix includes a printer with nullable tenant/user/registration foreign keys. It is visible only to the explicit platform context, proving that null comparisons do not create a visibility branch. All 48 runtime write probes (INSERT, UPDATE, and DELETE on 16 tables) were denied.

This denial is an intentional rollout blocker for a global Prisma credential switch. Before the separate read client, the backend used one Prisma `DATABASE_URL`, and repository inspection found active writes across the protected set: auth and account services mutate `User`; licensee administration mutates `Organization` and `Licensee`; QR allocation, lifecycle, incident, and policy services mutate `Batch` and `QRCode`; print creation/confirmation/control services mutate `PrintJob`, `PrintSession`, and `PrintItem`; printer connection/registry/session services mutate `PrinterRegistration`, `Printer`, `PrinterAttestation`, `PrinterAgentSession`, `PrinterProfile`, and `PrinterProfileSnapshot`; analytics refresh mutates `InventoryStatusRollup`; and manufacturer scope administration mutates `ManufacturerLicenseeLink`. An application switched globally to this SELECT-only role would break those paths. No broad DML grant or write policy was added because command-specific authorization requirements have not yet been designed and proven.

## Separate Read-Only Prisma Client

The first rollout boundary is intentionally narrow:

- `DATABASE_URL` continues to back the existing default Prisma singleton and every existing read/write path unless one of the three named route flags selects the RLS path.
- `RLS_READ_DATABASE_URL` backs one separately cached process-level Prisma client. It never falls back to `DATABASE_URL`, must not exactly match `DATABASE_URL`, and is never printed or included in diagnostics.
- The RLS client is created only when at least one staged RLS read flag is enabled. All flags disabled means the URL is optional, no RLS pool is created, and startup/readiness retain their previous dependency behavior.
- The RLS client is exposed to application code only as the transaction runner for the RLS wrapper. The callback receives a narrow read-only transaction-client surface; PostgreSQL SELECT-only privileges remain the authoritative runtime write control.
- Every enabled route builds authenticated context, sets all six established `app.*` values with transaction-local `set_config(..., true)`, and executes its full nested read graph through the same transaction connection. Missing or malformed context fails before the protected read.
- The process keeps one RLS client/pool rather than creating a client per request, and disconnects it alongside the default client during graceful shutdown. Operators must capacity-plan for one additional Prisma pool per backend process whenever any flag is enabled; the pool does not exist while every flag is disabled.

Only these route/flag pairs use this client:

| Route | Flag |
| --- | --- |
| `GET /api/qr/batches` | `MSCQR_STAGING_RLS_BATCHES_READ_ENABLED` |
| `GET /api/qr/batches/:id/allocation-map` | `MSCQR_STAGING_RLS_BATCH_ALLOCATION_MAP_ENABLED` |
| `GET /api/manufacturer/printers` | `MSCQR_STAGING_RLS_MANUFACTURER_PRINTERS_READ_ENABLED` |

Flag-off execution remains on the existing default Prisma path. No other route, authentication hydration, mutation, worker, printer operation, or global client is switched.

## Configuration, Startup, And Readiness Contract

`RLS_READ_DATABASE_URL` is optional only while all three route flags are false. If any one is true, backend startup validates that the value exists, parses as `postgres://` or `postgresql://`, includes a host, runtime username, and database name, and differs exactly from `DATABASE_URL`. It then connects and checks a secret-free runtime posture: `row_security=on`; a login-capable role with no superuser, `CREATEDB`, `CREATEROLE`, replication, or `BYPASSRLS` attributes; no inherited roles; no ownership of a protected table; all 16 tables protected and SELECT-accessible; no table-write, sequence, or schema-creation privileges; all 16 candidate policies present; and all 17 helpers present and executable.

Any configuration, connection, or posture failure aborts startup with a stable, credential-free error. Readiness also reports the RLS dependency as required and not ready and returns a degraded response while a staged flag is enabled and the probe fails. There is no fallback to the default client and no partially enabled route. When all flags are disabled, readiness reports the RLS dependency as disabled/optional and does not initialize the second client.

## Credential Provisioning And Rotation Contract

Provision `RLS_READ_DATABASE_URL` through the approved private runtime-configuration path; never commit, paste, echo, or log it. Its credential must authenticate as the exact reviewed runtime identity, remain distinct from the migration/owner and default application credentials, own no protected table, inherit no role, and retain only the reviewed connection/schema, 16-table SELECT, and 17-helper EXECUTE privileges. `DATABASE_URL` remains required by this phase because all writes and non-staged reads stay on the existing client.

Before any later staging reapply, prove the identity from the same credential and session that will execute route reads: capture `session_user`, `current_user`, `current_role`, `row_security`, direct role attributes, transitive memberships, protected-table ownership, and intended narrow grants. After the candidate is later applied with all flags disabled, the first one-flag startup probe must separately prove protected-table RLS/FORCE flags and SELECT access, the 16 candidate policies, and exact helper EXECUTE privileges before route traffic. Store only redacted boolean/count evidence; never store the URL, username if locally classified as sensitive, password, host, or raw connection diagnostics in the repository.

For rotation, keep all three flags disabled, provision and review a new restricted credential, update only `RLS_READ_DATABASE_URL`, and restart so the old process pool is drained. Then enable one flag and restart so the new startup posture probe runs before validating that route; disable the flag again before proceeding. Revoke the old login only after no process can retain its old pool. Rotation must not change `DATABASE_URL`, broaden grants, or add write policies.

## Validation Gate

Completed local evidence:

- 30 disposable-harness guard/unit tests passed
- full 48-migration disposable candidate apply, diagnostics, 9-context exact-ID matrix, 48 write denials, rollback, grant cleanup, fixture cleanup, and runtime-role cleanup passed
- backend TypeScript build passed
- explicit ESLint on the new client, wrapper, staged services, and related tests passed; the repository's legacy changed files retain pre-existing `no-explicit-any` debt but this change adds no new `any`
- transaction-context, batch-list, allocation-map, and manufacturer-printers RLS P2 tests passed
- document organization, RLS prototype boundaries, and `git diff --check` passed

The separate-client change adds a dedicated configuration/lifecycle/route-wiring gate through `npm --prefix backend run test:rls:read-client`. The full local disposable gate must also exercise the real separate runtime URL and the three real route/service read graphs, including concurrent context isolation and PostgreSQL write denial, before staging readiness can be claimed.

No staging reapply is allowed until:

1. the local disposable harness passes from a clean database;
2. the exact non-owner staging runtime role exists and is used by `RLS_READ_DATABASE_URL`, while `DATABASE_URL` remains the distinct default read/write credential;
3. the read-only pre-apply role/ownership/membership query in the runbook passes;
4. rollback is reviewed and immediately executable with the same exact runtime-role variable;
5. enabled-without-valid-RLS-URL startup failure, readiness failure, singleton lifecycle, clean shutdown, concurrent transaction-context isolation, and no-default-client escape tests pass;
6. route flags remain disabled for initial SQL apply and statement-time diagnostics are captured before policy-result tests.

## CTO Recommendations

1. Keep the startup/readiness posture check limited to safe booleans/counts and stable error codes; never add raw URLs, usernames, hosts, or database exceptions to health or logs.
2. Preserve the three-credential boundary: migration tooling uses the owner credential, `DATABASE_URL` remains the default application read/write credential, and only the staged read wrapper uses `RLS_READ_DATABASE_URL`.
3. Before adding writes, inventory every Prisma mutation on the 16 tables and design command-specific `WITH CHECK` policies plus narrow table/sequence grants. Do not grant broad DML to make existing writes pass.
4. Generate a policy coverage manifest from the Prisma schema and fail CI when a protected relation or newly added tenant foreign key lacks an explicit RLS classification.
5. Add redacted RLS proof telemetry with context class, route, policy version, exact-ID-set hash, denial category, and p95 duration for scalable staging and production monitoring.
