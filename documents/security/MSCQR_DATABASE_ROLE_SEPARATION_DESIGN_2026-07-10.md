# Database role separation design

Status: prepared for a later reviewed staging migration. No infrastructure, secret, staging, or production mutation is authorized by this document.

## Target roles

| Role | Login | Membership | Purpose | Privilege boundary |
| --- | --- | --- | --- | --- |
| owner | NOLOGIN | none | Owns application schemas, tables, and sequences | No elevated cluster attributes; never used as application credentials |
| migrator | LOGIN | `SET ROLE owner` only; no inheritance/admin option | Controlled migrations and DDL | No direct DML grants, no CREATEROLE, no CREATEDB, no BYPASSRLS |
| app | LOGIN | none | API, workers, and normal application reads/writes | Exact SELECT plus inventory-derived INSERT/UPDATE/DELETE only |
| rls read | LOGIN | none | Enabled staged RLS read routes only | Exact SELECT on 16 route-graph tables; no DML, sequences, ownership, or schema create |

The migrator must connect with its own credential and run `SET ROLE <owner>` inside the reviewed migration session. This preserves a stable NOLOGIN owner rather than making the login migrator own newly created objects.

## Staging-only migration sequence

1. Capture current staging ownership, ACLs, schema grants, role attributes, memberships, connection consumers, and rollback evidence. Do not put that capture in source control if it contains identifiers that operations considers sensitive.
2. Review the grant inventory and confirm the current schema contains no public sequences. If it does, stop and add exact sequence grants first.
3. Execute `mscqr_staging_database_role_separation_template_2026-07-10.sql` manually against a staging database whose name is not production-like. Supply all five explicit psql variables; the template creates no passwords.
4. Verify role attributes, ownership, memberships, grants, and no PUBLIC relation/function grants. The template does this in its transaction; repeat with independent operator evidence.
5. Provision credentials outside this repository through the approved secret process, configure the normal app and the independent RLS-read connection, and keep all staged read flags off until the separate candidate RLS review is approved.
6. Run the existing RLS read-client, route, and disposable SQL checks. Enable one route flag at a time only in a later change window.

## Rollback sequence

1. Disable all staged RLS read flags and remove the separate runtime connections before changing database roles.
2. Stop application traffic or put staging in the approved maintenance mode; verify no session is using the separation roles.
3. Run `mscqr_staging_database_role_separation_rollback_2026-07-10.sql` manually with the same names and the captured previous owner. It transfers current public relation ownership back, removes the controlled membership and drops the separation roles.
4. Restore the pre-change ACL capture before restoring any former runtime connection. The rollback deliberately does not recreate broad or unknown legacy permissions.
5. Independently verify ownership, memberships, ACLs, active connections, and application health before ending the maintenance window.

## Local proof boundary

`scripts/run-disposable-role-separation-harness.mjs` creates a fresh database only on local disposable PostgreSQL, applies the repository migrations, applies the role template, proves migrator ownership, normal app writes, no app CREATEROLE/CREATEDB, all 48 RLS-read DML privilege probes denied, and template rollback. It then drops the temporary database. It rejects cloud, staging, and production-looking URLs and requires an exact confirmation environment value.

The local proof is not production readiness evidence. It does not prove a live provider's managed-role restrictions, existing ACL restoration, credential distribution, application deployment, or route-runtime behavior in staging.
