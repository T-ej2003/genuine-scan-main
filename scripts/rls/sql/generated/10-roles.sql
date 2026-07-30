\set ON_ERROR_STOP on
BEGIN;
DO $$ DECLARE database_owner text; BEGIN

  IF current_user<>'certification-administrator' THEN RAISE EXCEPTION 'Expected certification-administrator brokered administrative executor'; END IF;

  IF current_setting('server_version_num')::integer / 10000 <> 18 THEN RAISE EXCEPTION 'Full RLS package requires PostgreSQL 18 catalog semantics'; END IF;
  IF current_database() !~ '^mscqr_full_rls_cert_[a-z0-9_]+$' THEN RAISE EXCEPTION 'clean-room package is bound to a green database name matching ^mscqr_full_rls_cert_[a-z0-9_]+$'; END IF;
  SELECT owner_role.rolname INTO STRICT database_owner FROM pg_database d JOIN pg_roles owner_role ON owner_role.oid=d.datdba WHERE d.datname=current_database();
  IF database_owner<>current_user THEN RAISE EXCEPTION 'clean-room executor must own the green candidate database'; END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname=current_user AND (NOT rolcreaterole OR NOT rolcreatedb)) THEN RAISE EXCEPTION 'clean-room executor requires CREATEROLE and CREATEDB without runtime use'; END IF;
  IF current_user IN ('mscqr_rls_cert_owner', 'mscqr_rls_cert_auth_owner', 'mscqr_rls_cert_app', 'mscqr_rls_cert_read', 'mscqr_rls_cert_preauth', 'mscqr_rls_cert_worker', 'mscqr_rls_cert_scheduled', 'mscqr_rls_cert_operator', 'mscqr_rls_cert_migration') THEN RAISE EXCEPTION 'administrative executor may not be a managed identity'; END IF;
  IF EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid()) THEN
    PERFORM pg_sleep(1);
    IF EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid()) THEN RAISE EXCEPTION 'clean-room preflight refuses another green database session'; END IF;
  END IF;

  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname IN ('mscqr_rls_cert_owner', 'mscqr_rls_cert_auth_owner', 'mscqr_rls_cert_app', 'mscqr_rls_cert_read', 'mscqr_rls_cert_preauth', 'mscqr_rls_cert_worker', 'mscqr_rls_cert_scheduled', 'mscqr_rls_cert_operator', 'mscqr_rls_cert_migration')) THEN RAISE EXCEPTION 'clean-room preflight refuses a pre-existing managed role'; END IF;

  IF EXISTS (SELECT 1 FROM pg_namespace WHERE nspname !~ '^pg_' AND nspname<>'information_schema' AND nspname<>'public') THEN RAISE EXCEPTION 'clean-room preflight refuses an unexpected user schema'; END IF;
  IF EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public')
     OR EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public')
     OR EXISTS (SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname='public')
  THEN RAISE EXCEPTION 'clean-room preflight refuses pre-existing application objects'; END IF;
  IF EXISTS (SELECT 1 FROM pg_policies) THEN RAISE EXCEPTION 'clean-room preflight refuses pre-existing policies'; END IF;
  IF EXISTS (SELECT 1 FROM pg_default_acl) THEN RAISE EXCEPTION 'clean-room preflight refuses pre-existing default ACLs'; END IF;
  IF EXISTS (SELECT 1 FROM pg_publication) OR EXISTS (SELECT 1 FROM pg_subscription) THEN RAISE EXCEPTION 'clean-room preflight refuses publications or subscriptions'; END IF;

  IF EXISTS (SELECT 1 FROM pg_database WHERE datname=current_database() AND datacl IS NOT NULL) THEN RAISE EXCEPTION 'clean-room preflight refuses pre-existing database grants'; END IF;
  IF (SELECT count(*) FROM pg_namespace n CROSS JOIN LATERAL aclexplode(COALESCE(n.nspacl,acldefault('n',n.nspowner))) acl WHERE n.nspname='public')<>3
     OR NOT has_schema_privilege('public','public','USAGE') OR has_schema_privilege('public','public','CREATE')
     OR EXISTS (
       SELECT 1 FROM pg_namespace n CROSS JOIN LATERAL aclexplode(COALESCE(n.nspacl,acldefault('n',n.nspowner))) acl
       WHERE n.nspname='public' AND NOT (
         (acl.grantee=n.nspowner AND acl.grantor=n.nspowner AND acl.privilege_type IN ('USAGE','CREATE') AND NOT acl.is_grantable)
         OR (acl.grantee=0 AND acl.grantor=n.nspowner AND acl.privilege_type='USAGE' AND NOT acl.is_grantable)
       )
     )
  THEN RAISE EXCEPTION 'clean-room preflight refuses non-baseline public schema grants'; END IF;
  IF EXISTS (SELECT 1 FROM pg_extension e JOIN pg_namespace n ON n.oid=e.extnamespace WHERE e.extname<>'plpgsql' OR n.nspname<>'pg_catalog') THEN RAISE EXCEPTION 'clean-room preflight refuses non-baseline extensions'; END IF;
  EXECUTE 'CREATE ROLE "mscqr_rls_cert_owner" NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS';
  EXECUTE 'CREATE ROLE "mscqr_rls_cert_auth_owner" NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS';
  EXECUTE 'CREATE ROLE "mscqr_rls_cert_app" LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS';
  EXECUTE 'CREATE ROLE "mscqr_rls_cert_read" LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS';
  EXECUTE 'CREATE ROLE "mscqr_rls_cert_preauth" LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS';
  EXECUTE 'CREATE ROLE "mscqr_rls_cert_worker" LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS';
  EXECUTE 'CREATE ROLE "mscqr_rls_cert_scheduled" LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS';
  EXECUTE 'CREATE ROLE "mscqr_rls_cert_operator" LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS';
  EXECUTE 'CREATE ROLE "mscqr_rls_cert_migration" LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS';
END $$;
GRANT "mscqr_rls_cert_owner" TO "certification-administrator" WITH ADMIN FALSE, INHERIT FALSE, SET TRUE;
COMMENT ON ROLE "mscqr_rls_cert_owner" IS 'mscqr-full-rls-clean-room:certification:92bde76db3f1062e50a9873c99ce9c78455c17875e9b42cef2f2bc9e01e0f643';
GRANT "mscqr_rls_cert_auth_owner" TO "certification-administrator" WITH ADMIN FALSE, INHERIT FALSE, SET TRUE;
COMMENT ON ROLE "mscqr_rls_cert_auth_owner" IS 'mscqr-full-rls-clean-room:certification:92bde76db3f1062e50a9873c99ce9c78455c17875e9b42cef2f2bc9e01e0f643';
GRANT "mscqr_rls_cert_app" TO "certification-administrator" WITH ADMIN FALSE, INHERIT FALSE, SET TRUE;
COMMENT ON ROLE "mscqr_rls_cert_app" IS 'mscqr-full-rls-clean-room:certification:92bde76db3f1062e50a9873c99ce9c78455c17875e9b42cef2f2bc9e01e0f643';
GRANT "mscqr_rls_cert_read" TO "certification-administrator" WITH ADMIN FALSE, INHERIT FALSE, SET TRUE;
COMMENT ON ROLE "mscqr_rls_cert_read" IS 'mscqr-full-rls-clean-room:certification:92bde76db3f1062e50a9873c99ce9c78455c17875e9b42cef2f2bc9e01e0f643';
GRANT "mscqr_rls_cert_preauth" TO "certification-administrator" WITH ADMIN FALSE, INHERIT FALSE, SET TRUE;
COMMENT ON ROLE "mscqr_rls_cert_preauth" IS 'mscqr-full-rls-clean-room:certification:92bde76db3f1062e50a9873c99ce9c78455c17875e9b42cef2f2bc9e01e0f643';
GRANT "mscqr_rls_cert_worker" TO "certification-administrator" WITH ADMIN FALSE, INHERIT FALSE, SET TRUE;
COMMENT ON ROLE "mscqr_rls_cert_worker" IS 'mscqr-full-rls-clean-room:certification:92bde76db3f1062e50a9873c99ce9c78455c17875e9b42cef2f2bc9e01e0f643';
GRANT "mscqr_rls_cert_scheduled" TO "certification-administrator" WITH ADMIN FALSE, INHERIT FALSE, SET TRUE;
COMMENT ON ROLE "mscqr_rls_cert_scheduled" IS 'mscqr-full-rls-clean-room:certification:92bde76db3f1062e50a9873c99ce9c78455c17875e9b42cef2f2bc9e01e0f643';
GRANT "mscqr_rls_cert_operator" TO "certification-administrator" WITH ADMIN FALSE, INHERIT FALSE, SET TRUE;
COMMENT ON ROLE "mscqr_rls_cert_operator" IS 'mscqr-full-rls-clean-room:certification:92bde76db3f1062e50a9873c99ce9c78455c17875e9b42cef2f2bc9e01e0f643';
GRANT "mscqr_rls_cert_migration" TO "certification-administrator" WITH ADMIN FALSE, INHERIT FALSE, SET TRUE;
COMMENT ON ROLE "mscqr_rls_cert_migration" IS 'mscqr-full-rls-clean-room:certification:92bde76db3f1062e50a9873c99ce9c78455c17875e9b42cef2f2bc9e01e0f643';
CREATE SCHEMA mscqr_rls_install AUTHORIZATION "certification-administrator";
REVOKE ALL ON SCHEMA mscqr_rls_install FROM PUBLIC;
CREATE TABLE mscqr_rls_install.state (
  singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
  target_environment text NOT NULL,
  deployment_id text NOT NULL,
  green_database text NOT NULL,
  source_contract_sha256 text NOT NULL,
  package_role_marker text NOT NULL,
  administrator_role text NOT NULL,
  release_sha text,
  migration_set_digest text,
  approval_contract_sha256 text,
  approval_id text,
  ticket_id text,
  independent_checker_identity text,
  approval_expires_at timestamptz,
  phase text NOT NULL,
  traffic_enabled boolean NOT NULL DEFAULT false
);
CREATE TABLE mscqr_rls_install.expected_policy (
  schema_name text NOT NULL,
  table_name text NOT NULL,
  policy_name text NOT NULL,
  permissive boolean NOT NULL,
  command_name text NOT NULL,
  role_names text[] NOT NULL,
  using_tree text,
  with_check_tree text,
  policy_comment text NOT NULL,
  PRIMARY KEY(schema_name,table_name,policy_name)
);
CREATE TABLE mscqr_rls_install.expected_routine (
  schema_name text NOT NULL,
  routine_name text NOT NULL,
  identity_arguments text NOT NULL,
  result_type text NOT NULL,
  routine_kind text NOT NULL,
  owner_name text NOT NULL,
  language_name text NOT NULL,
  volatility text NOT NULL,
  security_definer boolean NOT NULL,
  leakproof boolean NOT NULL,
  strict boolean NOT NULL,
  parallel_mode text NOT NULL,
  configuration text[],
  source_body text NOT NULL,
  acl_rows jsonb NOT NULL,
  PRIMARY KEY(schema_name,routine_name,identity_arguments)
);
REVOKE ALL ON ALL TABLES IN SCHEMA mscqr_rls_install FROM PUBLIC;
INSERT INTO mscqr_rls_install.state(
  target_environment,deployment_id,green_database,source_contract_sha256,package_role_marker,administrator_role,
  release_sha,migration_set_digest,approval_contract_sha256,approval_id,ticket_id,independent_checker_identity,approval_expires_at,phase
)
VALUES (
  'certification','cert',current_database(),'92bde76db3f1062e50a9873c99ce9c78455c17875e9b42cef2f2bc9e01e0f643','mscqr-full-rls-clean-room:certification:92bde76db3f1062e50a9873c99ce9c78455c17875e9b42cef2f2bc9e01e0f643',current_user,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  'roles-created'
);
DO $$ BEGIN
  EXECUTE format('REVOKE CONNECT,TEMPORARY ON DATABASE %I FROM PUBLIC',current_database());
  EXECUTE format('GRANT CONNECT ON DATABASE %I TO %I',current_database(),'mscqr_rls_cert_app');
  EXECUTE format('GRANT CONNECT ON DATABASE %I TO %I',current_database(),'mscqr_rls_cert_read');
  EXECUTE format('GRANT CONNECT ON DATABASE %I TO %I',current_database(),'mscqr_rls_cert_preauth');
  EXECUTE format('GRANT CONNECT ON DATABASE %I TO %I',current_database(),'mscqr_rls_cert_worker');
  EXECUTE format('GRANT CONNECT ON DATABASE %I TO %I',current_database(),'mscqr_rls_cert_scheduled');
  EXECUTE format('GRANT CONNECT ON DATABASE %I TO %I',current_database(),'mscqr_rls_cert_operator');
  EXECUTE format('GRANT CONNECT ON DATABASE %I TO %I',current_database(),'mscqr_rls_cert_migration');
  EXECUTE format('GRANT TEMPORARY ON DATABASE %I TO %I',current_database(),'mscqr_rls_cert_migration');
END $$;
GRANT USAGE,CREATE ON SCHEMA public TO "mscqr_rls_cert_migration";
GRANT USAGE ON SCHEMA mscqr_rls_install TO "mscqr_rls_cert_migration";
GRANT SELECT ON TABLE mscqr_rls_install.state TO "mscqr_rls_cert_migration";
DO $$ BEGIN
  IF NOT pg_has_role(session_user,'mscqr_rls_cert_migration','SET') THEN RAISE EXCEPTION 'administrative executor lacks SET authority for mscqr_rls_cert_migration'; END IF;
END $$;
SET ROLE "mscqr_rls_cert_migration";
ALTER DEFAULT PRIVILEGES FOR ROLE "mscqr_rls_cert_migration" REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE "mscqr_rls_cert_migration" REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE "mscqr_rls_cert_migration" REVOKE ALL ON ROUTINES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE "mscqr_rls_cert_migration" REVOKE ALL ON TYPES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE "mscqr_rls_cert_migration" REVOKE ALL ON SCHEMAS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE "mscqr_rls_cert_migration" REVOKE ALL ON LARGE OBJECTS FROM PUBLIC;
RESET ROLE;
COMMIT;
