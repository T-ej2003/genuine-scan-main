# MSCQR Object Ownership Review

This is the human review of `object-ownership-chain.json`. It changes no database owner, role, grant, policy, RLS state, SQL artifact, or runtime behavior.

## Role and object ownership matrix

| Object class | Enduring owner | Creation identity | Transfer | Verification |
|---|---|---|---|---|
| tables | identity-table-owner | identity-migration | After zero-based Prisma migration, the brokered administrator transaction temporarily gives identity-migration SET-only access to one target NOLOGIN owner, SET ROLEs to the migration owner, performs explicit fully qualified ALTER OWNER statements, and revokes the edge before success. REASSIGN OWNED is forbidden. | Every Prisma table has relowner=environment table owner; all 75 FORCE targets and both migration-only tables are included. |
| table-owned-sequences | identity-table-owner | identity-migration | After zero-based Prisma migration, the brokered administrator transaction temporarily gives identity-migration SET-only access to one target NOLOGIN owner, SET ROLEs to the migration owner, performs explicit fully qualified ALTER OWNER statements, and revokes the edge before success. REASSIGN OWNED is forbidden. | Every identity/serial sequence linked through pg_depend has the same owner as its owning table. |
| standalone-sequences | identity-table-owner | identity-migration | After zero-based Prisma migration, the brokered administrator transaction temporarily gives identity-migration SET-only access to one target NOLOGIN owner, SET ROLEs to the migration owner, performs explicit fully qualified ALTER OWNER statements, and revokes the edge before success. REASSIGN OWNED is forbidden. | Every non-extension application sequence has the table owner; no orphan migration-owned sequence remains. |
| indexes | owning-table-owner | identity-migration | Index ownership follows its owning table and is normalized by the table transfer. | Every application index resolves to a table whose relowner is the table owner. |
| constraints | owning-table-owner | identity-migration | Constraint authority follows the owning table; no independent runtime ownership exists. | Every constraint belongs to a table certified to the table owner; referenced tables are also certified. |
| policies | owning-table-owner | identity-migration | Policies have no independent owner; only the owning table owner may create, alter, or drop them through the reviewed deployment path. | Every policy's table relowner is the table owner and no policy command is installed by startup/runtime. |
| schemas | schema-specific | identity-migration | Explicit ALTER SCHEMA OWNER through the broker path: public and app_rls to table owner; app_auth to auth owner; extension-owned schemas remain extension-managed. | pg_namespace proves exact schema owners and PUBLIC/runtime CREATE is absent on protected schemas. |
| functions | schema-and-function-specific | identity-migration | After zero-based Prisma migration, the brokered administrator transaction temporarily gives identity-migration SET-only access to one target NOLOGIN owner, SET ROLEs to the migration owner, performs explicit fully qualified ALTER OWNER statements, and revokes the edge before success. REASSIGN OWNED is forbidden. | app_auth exact pre-auth signatures have auth owner; approved app_rls worker helpers have table owner and SECURITY INVOKER; no migration/runtime-owned application function remains. |
| procedures | identity-table-owner | identity-migration | After zero-based Prisma migration, the brokered administrator transaction temporarily gives identity-migration SET-only access to one target NOLOGIN owner, SET ROLEs to the migration owner, performs explicit fully qualified ALTER OWNER statements, and revokes the edge before success. REASSIGN OWNED is forbidden. | Every application procedure is owned by the table owner; app_auth procedures are forbidden unless separately added to the exact auth manifest. |
| enum-types | identity-table-owner | identity-migration | After zero-based Prisma migration, the brokered administrator transaction temporarily gives identity-migration SET-only access to one target NOLOGIN owner, SET ROLEs to the migration owner, performs explicit fully qualified ALTER OWNER statements, and revokes the edge before success. REASSIGN OWNED is forbidden. | Every non-extension application enum type has typowner=table owner. |
| composite-types | identity-table-owner | identity-migration | After zero-based Prisma migration, the brokered administrator transaction temporarily gives identity-migration SET-only access to one target NOLOGIN owner, SET ROLEs to the migration owner, performs explicit fully qualified ALTER OWNER statements, and revokes the edge before success. REASSIGN OWNED is forbidden. | Every standalone non-extension composite type has typowner=table owner; table row types follow their table. |
| views | identity-table-owner | identity-migration | After zero-based Prisma migration, the brokered administrator transaction temporarily gives identity-migration SET-only access to one target NOLOGIN owner, SET ROLEs to the migration owner, performs explicit fully qualified ALTER OWNER statements, and revokes the edge before success. REASSIGN OWNED is forbidden. | Every application view has relowner=table owner and uses an explicitly reviewed security option. |
| materialized-views | identity-table-owner | identity-migration | After zero-based Prisma migration, the brokered administrator transaction temporarily gives identity-migration SET-only access to one target NOLOGIN owner, SET ROLEs to the migration owner, performs explicit fully qualified ALTER OWNER statements, and revokes the edge before success. REASSIGN OWNED is forbidden. | Every application materialized view has relowner=table owner and an exact refresh authority. |
| triggers | owning-table-owner | identity-migration | Trigger authority follows the table; its called function is separately certified under the function rule. | Every non-internal trigger is attached to a table-owner table and calls an approved-owner function. |
| publications | external-managed-service-owner | controlled-platform-administration-only | Application migrations may not create publications. If introduced, a separately approved non-runtime administrative owner is required. | No MSCQR application publication is present; future presence fails verification until allowlisted. |
| subscriptions | external-managed-service-owner | controlled-platform-administration-only | Application migrations may not create subscriptions. If introduced, a separately approved non-runtime administrative owner is required. | No MSCQR application subscription is present; future presence fails verification until allowlisted. |
| extensions | managed-service-extension-owner | controlled-platform-administration-only | Extension installation and update are outside Prisma migrations; extension-owned objects/schemas are identified by extension dependencies and excluded from application transfer. | Every extension and extension-owned object is on an explicit platform allowlist and is not owned by a runtime role. |

## Migration lifecycle

1. **authenticate:** identity-migration authenticates with the deployment-only environment credential.
2. **preflight:** Verify the exact green database/environment and administrator, require a template0-clean application catalog, zero managed roles, zero unexpected grants/policies/memberships/default ACLs and no traffic.
3. **temporary-authority:** Only after zero-based Prisma migration, the brokered administrator grants the migration owner one SET-only target-owner edge inside the ownership transaction.
4. **migrate:** Migration creates/alters only reviewed objects and records the created/changed object set.
5. **transfer:** Broker transfers each object to its class owner using the deterministic object manifest.
6. **normalize-privileges:** Normalize schema privileges, exact grants, routine EXECUTE, and creator-specific default privileges.
7. **revoke-temporary-authority:** Revoke every temporary membership/authority in the success and failure paths.
8. **catalog-verification:** Run the complete catalog contract and compare the created/changed set with expected owners and grants.
9. **completion-gate:** Fail deployment if ownership, membership, grant, security-mode, or verification residue exists.

## Temporary authority model

The approved clean-room path separates zero-based Prisma DDL from ownership transfer. The restricted migration credential never receives owner membership while migrations run. In the later brokered administrative transaction, the administrator temporarily gives `identity-migration` one target-owner membership with `ADMIN FALSE`, `INHERIT FALSE`, `SET TRUE`, assumes the migration owner of the new objects, transfers the exact allowlisted objects, and revokes the membership before commit. There is no fallback transfer path and success requires zero membership and ownership residue.

## Schema, sequence, type, function and policy ownership

`public` and `app_rls` belong to the table owner; `app_auth` belongs to the auth owner. PUBLIC and runtime CREATE are denied. Prisma-created application schemas must be declared and table-owner owned. Extension schemas remain with the allowlisted managed extension owner. Table-owned and standalone application sequences, enums, composite types, views and materialized views use the table owner. Indexes, constraints, policies and triggers follow the owning table; called functions are verified independently.

The seven approved pre-auth functions are auth-owner SECURITY DEFINER functions. The 2 approved worker helpers are table-owner SECURITY INVOKER functions. Policies have no independent PostgreSQL owner: their authority follows the table owner.

## Default privileges

Every possible creator—migration, table owner and auth owner—has explicit future-object defaults. PUBLIC receives no application-object privilege; runtime roles receive no default table, sequence, schema, type or routine access. Exact runtime grants come only from command semantics after transfer.

## Failure, rollback and catalog verification

Installation is permitted only in a fresh green database on isolated green infrastructure. Preflight refuses any application object, managed role, unexpected grant, policy, membership or default ACL. A failed candidate is not repaired in place: stop and disconnect green consumers, prove no required data was accepted, drop the green database, drop only exact package-marked roles, and keep or restore traffic to the untouched blue database.

Catalog certification covers all 77 tables (75 FORCE targets plus two migration-only tables), sequences/dependencies, schemas/CREATE ACLs, exact function owners/security modes/EXECUTE ACLs, types, owner membership closure, default ACLs and optional publications/subscriptions/extensions. Migration, runtime and environment-admin LOGIN ownership must all be zero.

## Environment differences

The contract is identical in development, staging and production; only the `mscqr_dev_*`, `mscqr_staging_*` and `mscqr_prod_*` role names differ. Green must use a separate PostgreSQL cluster or instance because roles are cluster-wide and all managed names must be absent before apply. The current blue database and its roles are never mutation targets.

## Certification status

The clean-room generator, exact catalog verifier, failure-injection harness and role-marker cleanup package implement this ownership model. Application-path workflow certification and green staging activation remain separate gates.

