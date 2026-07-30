-- Manual, reviewed production provisioning only. Never run by the canary task.
-- Required psql variables: canary_tenant_id, foreign_tenant_id (UUIDs), and canary_credential_rotation (true|false).
-- Run from an administrator-only terminal. psql's hidden \password prompt is deliberate: do not pass a password by CLI, file, Git, Terraform, or logs.
-- The operator enters the one newly generated dedicated-secret value only when creating this role, or when canary_credential_rotation=true.
\set ON_ERROR_STOP on
\if :{?canary_credential_rotation}
\else
  \quit 3
\endif
SELECT CASE WHEN :'canary_credential_rotation' IN ('true', 'false') THEN 1 ELSE 1 / 0 END;
SELECT CASE WHEN EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mscqr_prod_rls_canary_read') THEN 'true' ELSE 'false' END AS canary_role_exists \gset
\if :canary_role_exists
  \if :canary_credential_rotation
    \password mscqr_prod_rls_canary_read
  \else
    \echo 'Existing canary credential preserved; set canary_credential_rotation=true only for an approved rotation.'
  \endif
\else
  \if :canary_credential_rotation
    \quit 3
  \endif
  CREATE ROLE mscqr_prod_rls_canary_read LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  \password mscqr_prod_rls_canary_read
\endif
BEGIN;
REVOKE ALL ON DATABASE mscqr_production FROM mscqr_prod_rls_canary_read;
GRANT CONNECT ON DATABASE mscqr_production TO mscqr_prod_rls_canary_read;
REVOKE ALL ON SCHEMA public, app_rls FROM mscqr_prod_rls_canary_read;
GRANT USAGE ON SCHEMA app_rls TO mscqr_prod_rls_canary_read;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM mscqr_prod_rls_canary_read;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA app_rls FROM mscqr_prod_rls_canary_read;
ALTER ROLE mscqr_prod_rls_canary_read SET statement_timeout = '5s';
ALTER ROLE mscqr_prod_rls_canary_read SET lock_timeout = '1s';
ALTER ROLE mscqr_prod_rls_canary_read SET idle_in_transaction_session_timeout = '10s';
ALTER ROLE mscqr_prod_rls_canary_read SET default_transaction_read_only = on;
ALTER ROLE mscqr_prod_rls_canary_read SET mscqr.rls_canary_tenant = :'canary_tenant_id';
ALTER ROLE mscqr_prod_rls_canary_read SET mscqr.rls_canary_foreign_tenant = :'foreign_tenant_id';
SET ROLE mscqr_prod_auth_owner;
CREATE OR REPLACE FUNCTION app_rls.production_read_only_canary_probe()
RETURNS TABLE(same_tenant_visible boolean, foreign_tenant_invisible boolean)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, public, app_rls AS $$
DECLARE own_tenant text := current_setting('mscqr.rls_canary_tenant', true); foreign_tenant text := current_setting('mscqr.rls_canary_foreign_tenant', true);
BEGIN
  IF session_user <> 'mscqr_prod_rls_canary_read' OR own_tenant !~* '^[0-9a-f-]{36}$' OR foreign_tenant !~* '^[0-9a-f-]{36}$' OR own_tenant = foreign_tenant THEN RAISE EXCEPTION 'read-only canary binding is invalid'; END IF;
  RETURN QUERY SELECT EXISTS (SELECT 1 FROM public."Batch" WHERE "licenseeId" = own_tenant), NOT EXISTS (SELECT 1 FROM public."Batch" WHERE "licenseeId" = foreign_tenant);
END $$;
REVOKE ALL ON FUNCTION app_rls.production_read_only_canary_probe() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_rls.production_read_only_canary_probe() TO mscqr_prod_rls_canary_read;
DROP POLICY IF EXISTS production_read_only_canary_batch_select ON public."Batch";
CREATE POLICY production_read_only_canary_batch_select ON public."Batch" FOR SELECT TO mscqr_prod_auth_owner
  USING (current_user = 'mscqr_prod_auth_owner' AND session_user = 'mscqr_prod_rls_canary_read' AND "licenseeId" = current_setting('mscqr.rls_canary_tenant', true));
RESET ROLE;
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mscqr_prod_rls_canary_read' AND (rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolinherit))
     OR EXISTS (SELECT 1 FROM pg_auth_members m JOIN pg_roles parent ON parent.oid=m.roleid JOIN pg_roles member ON member.oid=m.member WHERE member.rolname='mscqr_prod_rls_canary_read')
     OR has_table_privilege('mscqr_prod_rls_canary_read','public."Batch"','INSERT,UPDATE,DELETE,TRUNCATE') THEN RAISE EXCEPTION 'canary privilege verification failed'; END IF;
END $$;
COMMIT;

-- Rollback never prints or changes the credential: REVOKE EXECUTE ON FUNCTION app_rls.production_read_only_canary_probe() FROM mscqr_prod_rls_canary_read; DROP POLICY IF EXISTS production_read_only_canary_batch_select ON public."Batch"; DROP FUNCTION IF EXISTS app_rls.production_read_only_canary_probe(); REVOKE USAGE ON SCHEMA app_rls FROM mscqr_prod_rls_canary_read; REVOKE CONNECT ON DATABASE mscqr_production FROM mscqr_prod_rls_canary_read; DROP ROLE IF EXISTS mscqr_prod_rls_canary_read;
