\set ON_ERROR_STOP on
BEGIN;
SELECT current_database() AS green_database, current_user AS executor;
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
END $$;
COMMIT;
