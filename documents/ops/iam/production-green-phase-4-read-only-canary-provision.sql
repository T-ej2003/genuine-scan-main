-- Manual, reviewed production provisioning only. Never run by the canary task.
-- Required psql variable: canary_credential_rotation (true|false). Scope IDs come only from the initializer-owned control object.
-- Run from an administrator-only terminal. psql's hidden \password prompt is deliberate: do not pass a password by CLI, file, Git, Terraform, or logs.
-- The operator enters the one newly generated dedicated-secret value only when creating this role, or when canary_credential_rotation=true.
\set ON_ERROR_STOP on
\if :{?canary_credential_rotation}
\else
  \quit 3
\endif
SELECT set_config('mscqr.canary_credential_rotation', :'canary_credential_rotation', false);
DO $$ BEGIN
  IF current_setting('mscqr.canary_credential_rotation') NOT IN ('true', 'false') THEN
    RAISE EXCEPTION 'canary_credential_rotation must be true or false';
  END IF;
END $$;
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
DO $subscription_observer_role$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='mscqr_prod_subscription_observer') THEN
    EXECUTE 'CREATE ROLE mscqr_prod_subscription_observer NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='mscqr_prod_subscription_observer'
      AND (rolcanlogin OR rolsuper OR rolinherit OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls))
     OR EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles member ON member.oid=m.member
       WHERE member.rolname='mscqr_prod_subscription_observer') THEN
    RAISE EXCEPTION 'subscription observer role is not the exact isolated NOLOGIN principal';
  END IF;
END $subscription_observer_role$;
REVOKE ALL ON DATABASE mscqr_production_rls_green_phase2 FROM mscqr_prod_rls_canary_read;
GRANT CONNECT ON DATABASE mscqr_production_rls_green_phase2 TO mscqr_prod_rls_canary_read;
REVOKE ALL ON SCHEMA public, app_rls FROM mscqr_prod_rls_canary_read;
GRANT USAGE ON SCHEMA app_rls TO mscqr_prod_rls_canary_read;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM mscqr_prod_rls_canary_read;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA app_rls FROM mscqr_prod_rls_canary_read;
GRANT SELECT (subconninfo) ON pg_catalog.pg_subscription TO mscqr_prod_subscription_observer;
GRANT USAGE, CREATE ON SCHEMA app_rls TO mscqr_prod_subscription_observer;
SET ROLE mscqr_prod_subscription_observer;
CREATE OR REPLACE FUNCTION app_rls.production_security_subscription_inventory()
RETURNS TABLE(subscription_name text,subscription_owner text,enabled boolean,binary boolean,streaming text,two_phase text,
  disable_on_error boolean,password_required boolean,run_as_owner boolean,failover boolean,slot_name text,
  synchronous_commit text,publications text[],origin text,connection_info_sha256 text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $subscription_inventory$
  SELECT s.subname::text,o.rolname::text,s.subenabled,s.subbinary,s.substream::text,s.subtwophasestate::text,
    s.subdisableonerr,s.subpasswordrequired,s.subrunasowner,s.subfailover,s.subslotname::text,s.subsynccommit,
    ARRAY(SELECT publication FROM pg_catalog.unnest(s.subpublications) publication ORDER BY publication),s.suborigin,
    pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
      pg_catalog.jsonb_build_array('mscqr-security-subscription-connection-v1',s.subname,s.subconninfo)::text,'UTF8')),'hex')
  FROM pg_catalog.pg_subscription s JOIN pg_catalog.pg_roles o ON o.oid=s.subowner
$subscription_inventory$;
REVOKE ALL ON FUNCTION app_rls.production_security_subscription_inventory() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_rls.production_security_subscription_inventory() TO mscqr_prod_rls_canary_read;
RESET ROLE;
REVOKE USAGE, CREATE ON SCHEMA app_rls FROM mscqr_prod_subscription_observer;
ALTER ROLE mscqr_prod_rls_canary_read SET statement_timeout = '5s';
ALTER ROLE mscqr_prod_rls_canary_read SET lock_timeout = '1s';
ALTER ROLE mscqr_prod_rls_canary_read SET idle_in_transaction_session_timeout = '10s';
ALTER ROLE mscqr_prod_rls_canary_read SET default_transaction_read_only = on;
SET ROLE mscqr_prd_rls_phase2_auth_owner;
SELECT COALESCE((SELECT scope_id FROM app_rls.production_read_only_canary_control WHERE scope_name='canary'), '') AS canary_scope \gset
SELECT set_config('mscqr.canary_scope_candidate', :'canary_scope', false);
DO $$ BEGIN
  IF current_setting('mscqr.canary_scope_candidate') !~* '^[0-9a-f-]{36}$' THEN
    RAISE EXCEPTION 'production read-only canary control did not provide a valid canary scope';
  END IF;
END $$;
RESET ROLE;
SELECT set_config('mscqr.predecessor_app_rls_acl', COALESCE(nspacl::text, ''), true) FROM pg_namespace WHERE nspname='app_rls';
SELECT set_config('mscqr.auth_owner_had_schema_create', has_schema_privilege('mscqr_prd_rls_phase2_auth_owner', 'app_rls', 'CREATE')::text, true);
DO $$ BEGIN
  IF current_setting('mscqr.auth_owner_had_schema_create') = 'false' THEN EXECUTE 'GRANT CREATE ON SCHEMA app_rls TO mscqr_prd_rls_phase2_auth_owner'; END IF;
END $$;
SET ROLE mscqr_prd_rls_phase2_auth_owner;
CREATE OR REPLACE FUNCTION app_rls.production_read_only_canary_probe()
RETURNS TABLE(same_tenant_visible boolean, foreign_tenant_invisible boolean)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, public, app_rls AS $$
BEGIN
  IF session_user <> 'mscqr_prod_rls_canary_read' OR COALESCE(current_setting('mscqr.rls_canary_scope', true), '') !~* '^[0-9a-f-]{36}$' THEN RAISE EXCEPTION 'read-only canary binding is invalid'; END IF;
  RETURN QUERY SELECT EXISTS (SELECT 1 FROM app_rls.production_read_only_canary_control WHERE scope_name='canary'), NOT EXISTS (SELECT 1 FROM app_rls.production_read_only_canary_control WHERE scope_name='isolation');
END $$;
REVOKE ALL ON FUNCTION app_rls.production_read_only_canary_probe() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_rls.production_read_only_canary_probe() TO mscqr_prod_rls_canary_read;
RESET ROLE;
DO $$ BEGIN
  IF current_setting('mscqr.auth_owner_had_schema_create') = 'false' THEN EXECUTE 'REVOKE CREATE ON SCHEMA app_rls FROM mscqr_prd_rls_phase2_auth_owner'; END IF;
END $$;
DO $$ BEGIN
  IF has_schema_privilege('mscqr_prd_rls_phase2_auth_owner', 'app_rls', 'CREATE')::text <> current_setting('mscqr.auth_owner_had_schema_create')
     OR (SELECT COALESCE(nspacl::text, '') <> current_setting('mscqr.predecessor_app_rls_acl') FROM pg_namespace WHERE nspname='app_rls')
     OR EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mscqr_prod_rls_canary_read' AND (rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolinherit))
     OR EXISTS (SELECT 1 FROM pg_auth_members m JOIN pg_roles parent ON parent.oid=m.roleid JOIN pg_roles member ON member.oid=m.member WHERE member.rolname='mscqr_prod_rls_canary_read')
     OR EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='mscqr_prod_subscription_observer' AND
       (rolcanlogin OR rolsuper OR rolinherit OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls))
     OR EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles member ON member.oid=m.member WHERE member.rolname='mscqr_prod_subscription_observer')
     OR has_table_privilege('mscqr_prod_subscription_observer','pg_catalog.pg_subscription','SELECT')
     OR (SELECT count(*)<>1 FROM pg_catalog.pg_attribute a CROSS JOIN LATERAL pg_catalog.aclexplode(a.attacl) acl
       WHERE a.attrelid='pg_catalog.pg_subscription'::pg_catalog.regclass AND a.attname='subconninfo' AND acl.grantee='mscqr_prod_subscription_observer'::pg_catalog.regrole)
     OR (SELECT count(*)<>1 FROM pg_catalog.pg_attribute a CROSS JOIN LATERAL pg_catalog.aclexplode(a.attacl) acl
       WHERE a.attrelid='pg_catalog.pg_subscription'::pg_catalog.regclass AND a.attname='subconninfo')
     OR EXISTS (SELECT 1 FROM pg_catalog.pg_attribute a CROSS JOIN LATERAL pg_catalog.aclexplode(a.attacl) acl
       WHERE a.attrelid='pg_catalog.pg_subscription'::pg_catalog.regclass AND a.attname='subconninfo'
         AND (acl.grantee<>'mscqr_prod_subscription_observer'::pg_catalog.regrole OR acl.privilege_type<>'SELECT' OR acl.is_grantable))
     OR EXISTS (SELECT 1 FROM pg_catalog.pg_attribute a CROSS JOIN LATERAL pg_catalog.aclexplode(a.attacl) acl
       WHERE a.attrelid='pg_catalog.pg_subscription'::pg_catalog.regclass AND acl.grantee='mscqr_prod_subscription_observer'::pg_catalog.regrole
         AND (a.attname<>'subconninfo' OR acl.privilege_type<>'SELECT' OR acl.is_grantable))
     OR pg_catalog.has_column_privilege('mscqr_prod_rls_canary_read','pg_catalog.pg_subscription','subconninfo','SELECT')
     OR NOT pg_catalog.has_function_privilege('mscqr_prod_rls_canary_read','app_rls.production_security_subscription_inventory()','EXECUTE')
     OR pg_catalog.has_schema_privilege('mscqr_prod_subscription_observer','app_rls','CREATE')
     OR EXISTS (SELECT 1 FROM information_schema.role_table_grants WHERE grantee='mscqr_prod_rls_canary_read') THEN RAISE EXCEPTION 'canary privilege verification failed'; END IF;
END $$;
COMMIT;

-- Rollback never prints or changes credentials: REVOKE EXECUTE ON FUNCTION app_rls.production_security_subscription_inventory() FROM mscqr_prod_rls_canary_read; DROP FUNCTION IF EXISTS app_rls.production_security_subscription_inventory(); REVOKE SELECT (subconninfo) ON pg_catalog.pg_subscription FROM mscqr_prod_subscription_observer; DROP ROLE IF EXISTS mscqr_prod_subscription_observer; REVOKE EXECUTE ON FUNCTION app_rls.production_read_only_canary_probe() FROM mscqr_prod_rls_canary_read; DROP FUNCTION IF EXISTS app_rls.production_read_only_canary_probe(); REVOKE USAGE ON SCHEMA app_rls FROM mscqr_prod_rls_canary_read; REVOKE CONNECT ON DATABASE mscqr_production_rls_green_phase2 FROM mscqr_prod_rls_canary_read; DROP ROLE IF EXISTS mscqr_prod_rls_canary_read;
