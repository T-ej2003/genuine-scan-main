-- MSCQR STAGING-ONLY DATABASE ROLE SEPARATION ROLLBACK TEMPLATE.
--
-- DO NOT RUN IN PRODUCTION. This is a manual, reviewed staging rollback only.
-- It contains no credentials and is never invoked automatically. Restore the
-- pre-change ACL capture separately before using a former runtime role.
--
-- Required psql variables match the apply template:
--   mscqr_previous_owner_role, mscqr_owner_role, mscqr_migrator_role,
--   mscqr_app_role, mscqr_rls_read_role.

\set ON_ERROR_STOP on

\if :{?mscqr_previous_owner_role}
\else
\echo 'Missing -v mscqr_previous_owner_role=<pre-separation-owner-role>'
\quit 3
\endif
\if :{?mscqr_owner_role}
\else
\echo 'Missing -v mscqr_owner_role=<separation-owner-role>'
\quit 3
\endif
\if :{?mscqr_migrator_role}
\else
\echo 'Missing -v mscqr_migrator_role=<separation-migrator-role>'
\quit 3
\endif
\if :{?mscqr_app_role}
\else
\echo 'Missing -v mscqr_app_role=<separation-app-role>'
\quit 3
\endif
\if :{?mscqr_rls_read_role}
\else
\echo 'Missing -v mscqr_rls_read_role=<separation-rls-read-role>'
\quit 3
\endif

BEGIN;

SELECT set_config('mscqr.role.previous_owner', :'mscqr_previous_owner_role', true);
SELECT set_config('mscqr.role.owner', :'mscqr_owner_role', true);
SELECT set_config('mscqr.role.migrator', :'mscqr_migrator_role', true);
SELECT set_config('mscqr.role.app', :'mscqr_app_role', true);
SELECT set_config('mscqr.role.rls_read', :'mscqr_rls_read_role', true);

DO $$
DECLARE
  previous_owner text := current_setting('mscqr.role.previous_owner', true);
  owner_role text := current_setting('mscqr.role.owner', true);
  migrator_role text := current_setting('mscqr.role.migrator', true);
  app_role text := current_setting('mscqr.role.app', true);
  rls_read_role text := current_setting('mscqr.role.rls_read', true);
  names text[] := ARRAY[previous_owner, owner_role, migrator_role, app_role, rls_read_role];
BEGIN
  IF current_database() ~* '(^|[_-])(prod|production|live|primary)([_-]|$)' THEN
    RAISE EXCEPTION 'This staging-only rollback refuses production-like database name %', current_database();
  END IF;
  IF array_length(names, 1) <> (SELECT count(DISTINCT value) FROM unnest(names) AS value)
     OR EXISTS (SELECT 1 FROM unnest(names) AS value WHERE value !~ '^[a-z_][a-z0-9_]{0,62}$') THEN
    RAISE EXCEPTION 'Rollback role variables must be distinct lower-case PostgreSQL identifiers';
  END IF;
  IF current_user <> previous_owner THEN
    RAISE EXCEPTION 'Connected role % must equal mscqr_previous_owner_role %', current_user, previous_owner;
  END IF;
  IF (SELECT count(*) FROM pg_roles WHERE rolname = ANY(ARRAY[owner_role, migrator_role, app_role, rls_read_role])) <> 4 THEN
    RAISE EXCEPTION 'All separation roles must exist before rollback';
  END IF;
END
$$;

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM :"mscqr_app_role", :"mscqr_rls_read_role";
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM :"mscqr_app_role", :"mscqr_rls_read_role";
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM :"mscqr_app_role", :"mscqr_rls_read_role";
REVOKE ALL ON SCHEMA public FROM :"mscqr_app_role", :"mscqr_rls_read_role";

DO $$
DECLARE
  previous_owner text := current_setting('mscqr.role.previous_owner', true);
  owner_role text := current_setting('mscqr.role.owner', true);
  migrator_role text := current_setting('mscqr.role.migrator', true);
  app_role text := current_setting('mscqr.role.app', true);
  rls_read_role text := current_setting('mscqr.role.rls_read', true);
  relation record;
BEGIN
  FOR relation IN
    SELECT c.relname, c.relkind
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'S')
  LOOP
    IF relation.relkind = 'S' THEN
      EXECUTE format('ALTER SEQUENCE public.%I OWNER TO %I', relation.relname, previous_owner);
    ELSE
      EXECUTE format('ALTER TABLE public.%I OWNER TO %I', relation.relname, previous_owner);
    END IF;
  END LOOP;
  EXECUTE format('ALTER SCHEMA public OWNER TO %I', previous_owner);
  IF EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'app_rls') THEN
    EXECUTE format('ALTER SCHEMA app_rls OWNER TO %I', previous_owner);
  END IF;
  EXECUTE format('REVOKE %I FROM %I', owner_role, migrator_role);
  EXECUTE format('REVOKE CONNECT ON DATABASE %I FROM %I, %I, %I', current_database(), migrator_role, app_role, rls_read_role);
  EXECUTE format('DROP OWNED BY %I', rls_read_role);
  EXECUTE format('DROP OWNED BY %I', app_role);
  EXECUTE format('DROP OWNED BY %I', migrator_role);
  EXECUTE format('DROP OWNED BY %I', owner_role);
  EXECUTE format('DROP ROLE %I', rls_read_role);
  EXECUTE format('DROP ROLE %I', app_role);
  EXECUTE format('DROP ROLE %I', migrator_role);
  EXECUTE format('DROP ROLE %I', owner_role);
END
$$;

DO $$
DECLARE
  previous_owner text := current_setting('mscqr.role.previous_owner', true);
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = ANY(ARRAY[
    current_setting('mscqr.role.owner', true), current_setting('mscqr.role.migrator', true),
    current_setting('mscqr.role.app', true), current_setting('mscqr.role.rls_read', true)
  ])) THEN
    RAISE EXCEPTION 'Rollback did not remove all separation roles';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace JOIN pg_roles o ON o.oid = c.relowner
    WHERE n.nspname = 'public' AND c.relkind IN ('r','p','S') AND o.rolname <> previous_owner
  ) THEN
    RAISE EXCEPTION 'Rollback did not restore public table/sequence ownership';
  END IF;
END
$$;

COMMIT;
