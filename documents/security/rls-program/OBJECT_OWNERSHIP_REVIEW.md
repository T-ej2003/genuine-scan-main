# MSCQR Object Ownership Review

This is the human review of `object-ownership-chain.json`. It changes no database owner, role, grant, policy, RLS state, SQL artifact, or runtime behavior.

## Role and object ownership matrix

| Object class | Enduring owner | Creation identity | Transfer | Verification |
|---|---|---|---|---|
| tables | identity-table-owner | identity-migration | The broker-controlled transfer executor performs explicit, fully qualified per-object ALTER OWNER after the migration creates or alters the object; REASSIGN OWNED is forbidden because it cannot preserve the table-owner/auth-owner split. | Every Prisma table has relowner=environment table owner; all 75 FORCE targets and both migration-only tables are included. |
| table-owned-sequences | identity-table-owner | identity-migration | The broker-controlled transfer executor performs explicit, fully qualified per-object ALTER OWNER after the migration creates or alters the object; REASSIGN OWNED is forbidden because it cannot preserve the table-owner/auth-owner split. | Every identity/serial sequence linked through pg_depend has the same owner as its owning table. |
| standalone-sequences | identity-table-owner | identity-migration | The broker-controlled transfer executor performs explicit, fully qualified per-object ALTER OWNER after the migration creates or alters the object; REASSIGN OWNED is forbidden because it cannot preserve the table-owner/auth-owner split. | Every non-extension application sequence has the table owner; no orphan migration-owned sequence remains. |
| indexes | owning-table-owner | identity-migration | Index ownership follows its owning table and is normalized by the table transfer. | Every application index resolves to a table whose relowner is the table owner. |
| constraints | owning-table-owner | identity-migration | Constraint authority follows the owning table; no independent runtime ownership exists. | Every constraint belongs to a table certified to the table owner; referenced tables are also certified. |
| policies | owning-table-owner | identity-migration | Policies have no independent owner; only the owning table owner may create, alter, or drop them through the reviewed deployment path. | Every policy's table relowner is the table owner and no policy command is installed by startup/runtime. |
| schemas | schema-specific | identity-migration | Explicit ALTER SCHEMA OWNER through the broker path: public and app_rls to table owner; app_auth to auth owner; extension-owned schemas remain extension-managed. | pg_namespace proves exact schema owners and PUBLIC/runtime CREATE is absent on protected schemas. |
| functions | schema-and-function-specific | identity-migration | The broker-controlled transfer executor performs explicit, fully qualified per-object ALTER OWNER after the migration creates or alters the object; REASSIGN OWNED is forbidden because it cannot preserve the table-owner/auth-owner split. | app_auth exact pre-auth signatures have auth owner; approved app_rls worker helpers have table owner and SECURITY INVOKER; no migration/runtime-owned application function remains. |
| procedures | identity-table-owner | identity-migration | The broker-controlled transfer executor performs explicit, fully qualified per-object ALTER OWNER after the migration creates or alters the object; REASSIGN OWNED is forbidden because it cannot preserve the table-owner/auth-owner split. | Every application procedure is owned by the table owner; app_auth procedures are forbidden unless separately added to the exact auth manifest. |
| enum-types | identity-table-owner | identity-migration | The broker-controlled transfer executor performs explicit, fully qualified per-object ALTER OWNER after the migration creates or alters the object; REASSIGN OWNED is forbidden because it cannot preserve the table-owner/auth-owner split. | Every non-extension application enum type has typowner=table owner. |
| composite-types | identity-table-owner | identity-migration | The broker-controlled transfer executor performs explicit, fully qualified per-object ALTER OWNER after the migration creates or alters the object; REASSIGN OWNED is forbidden because it cannot preserve the table-owner/auth-owner split. | Every standalone non-extension composite type has typowner=table owner; table row types follow their table. |
| views | identity-table-owner | identity-migration | The broker-controlled transfer executor performs explicit, fully qualified per-object ALTER OWNER after the migration creates or alters the object; REASSIGN OWNED is forbidden because it cannot preserve the table-owner/auth-owner split. | Every application view has relowner=table owner and uses an explicitly reviewed security option. |
| materialized-views | identity-table-owner | identity-migration | The broker-controlled transfer executor performs explicit, fully qualified per-object ALTER OWNER after the migration creates or alters the object; REASSIGN OWNED is forbidden because it cannot preserve the table-owner/auth-owner split. | Every application materialized view has relowner=table owner and an exact refresh authority. |
| triggers | owning-table-owner | identity-migration | Trigger authority follows the table; its called function is separately certified under the function rule. | Every non-internal trigger is attached to a table-owner table and calls an approved-owner function. |
| publications | external-managed-service-owner | controlled-platform-administration-only | Application migrations may not create publications. If introduced, a separately approved non-runtime administrative owner is required. | No MSCQR application publication is present; future presence fails verification until allowlisted. |
| subscriptions | external-managed-service-owner | controlled-platform-administration-only | Application migrations may not create subscriptions. If introduced, a separately approved non-runtime administrative owner is required. | No MSCQR application subscription is present; future presence fails verification until allowlisted. |
| extensions | managed-service-extension-owner | controlled-platform-administration-only | Extension installation and update are outside Prisma migrations; extension-owned objects/schemas are identified by extension dependencies and excluded from application transfer. | Every extension and extension-owned object is on an explicit platform allowlist and is not owned by a runtime role. |

## Migration lifecycle

1. **authenticate:** identity-migration authenticates with the deployment-only environment credential.
2. **preflight:** Verify expected database/environment, current user, role attributes, owner attributes, schema baseline, clean membership state, and capture an exact object-owner snapshot.
3. **temporary-authority:** Broker obtains only the exact transfer authority; recommended path grants no owner membership to migration.
4. **migrate:** Migration creates/alters only reviewed objects and records the created/changed object set.
5. **transfer:** Broker transfers each object to its class owner using the deterministic object manifest.
6. **normalize-privileges:** Normalize schema privileges, exact grants, routine EXECUTE, and creator-specific default privileges.
7. **revoke-temporary-authority:** Revoke every temporary membership/authority in the success and failure paths.
8. **catalog-verification:** Run the complete catalog contract and compare the created/changed set with expected owners and grants.
9. **completion-gate:** Fail deployment if ownership, membership, grant, security-mode, or verification residue exists.

## Temporary authority model

The approved path separates DDL execution from ownership transfer. `identity-migration` never joins an owner role: an audited broker executor transfers the exact changed objects and may receive one target-owner membership at a time with `ADMIN FALSE`, `INHERIT FALSE`, `SET TRUE`. That membership is itself privileged and is revoked before catalog verification. PostgreSQL 18 `CREATEROLE` is not treated as blanket authority; the grantor must have the exact membership administration authority and the transfer executor must be able to assume the target owner for the transfer.

The fallback allows the migration identity the same non-inheriting, SET-only membership one owner at a time only under a separate reviewed exception. Success is impossible until membership is revoked and both ownership and membership residue are zero.

## Schema, sequence, type, function and policy ownership

`public` and `app_rls` belong to the table owner; `app_auth` belongs to the auth owner. PUBLIC and runtime CREATE are denied. Prisma-created application schemas must be declared and table-owner owned. Extension schemas remain with the allowlisted managed extension owner. Table-owned and standalone application sequences, enums, composite types, views and materialized views use the table owner. Indexes, constraints, policies and triggers follow the owning table; called functions are verified independently.

The seven approved pre-auth functions are auth-owner SECURITY DEFINER functions. The 2 approved worker helpers are table-owner SECURITY INVOKER functions. Policies have no independent PostgreSQL owner: their authority follows the table owner.

## Default privileges

Every possible creator—migration, table owner and auth owner—has explicit future-object defaults. PUBLIC receives no application-object privilege; runtime roles receive no default table, sequence, schema, type or routine access. Exact runtime grants come only from command semantics after transfer. Defaults are not relied on retroactively and inherited-role defaults are not assumed.

## Failure, rollback and catalog verification

Preflight records exact owners and changed objects. Transfer, privilege normalization, revocation and catalog verification are a single fail-closed deployment gate. Transactional DDL rolls back together; nontransactional operations require explicit compensation. Rollback may restore only a previously approved NOLOGIN owner and never restores runtime or migration ownership. Failure handling always attempts revocation and cannot report success with residue.

Catalog certification covers all 77 tables (75 FORCE targets plus two migration-only tables), sequences/dependencies, schemas/CREATE ACLs, exact function owners/security modes/EXECUTE ACLs, types, owner membership closure, default ACLs and optional publications/subscriptions/extensions. Migration, runtime and environment-admin LOGIN ownership must all be zero.

## Environment differences

The contract is identical in development, staging and production; only the `mscqr_dev_*`, `mscqr_staging_*` and `mscqr_prod_*` role names differ. Production uses the same deployment-only migration credential and broker gate, with no standing break-glass ownership path.

## Remaining implementation work

Implement reviewed role/bootstrap and ownership-transfer artifacts later, add disposable PostgreSQL catalog tests for every query contract, capture environment-specific preflight evidence, and rehearse partial-failure compensation before staging activation. This architecture decision does not authorize those changes.

