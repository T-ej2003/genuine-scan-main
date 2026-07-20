\set ON_ERROR_STOP on
BEGIN;
DO $$ BEGIN

  IF current_user<>'certification-administrator' THEN RAISE EXCEPTION 'context helpers requires the reviewed brokered administrator'; END IF;
  IF current_database() !~ '^mscqr_full_rls_cert_[a-z0-9_]+$' THEN RAISE EXCEPTION 'context helpers is bound to the reviewed green database'; END IF;
  IF NOT EXISTS (SELECT 1 FROM mscqr_rls_install.state WHERE singleton
    AND target_environment='certification'
    AND deployment_id='cert'
    AND green_database=current_database()
    AND source_contract_sha256='31314331260d1ce2f31399e33eb04cb87fcad6450368f99e3c7ea303efd74e3f'
    AND package_role_marker='mscqr-full-rls-clean-room:certification:31314331260d1ce2f31399e33eb04cb87fcad6450368f99e3c7ea303efd74e3f'
    AND administrator_role='certification-administrator'
    AND phase='ownership-installed'
    AND NOT traffic_enabled) THEN RAISE EXCEPTION 'context helpers lacks the exact clean-room package marker'; END IF;

  IF (SELECT count(*) FROM pg_roles WHERE rolname IN ('mscqr_rls_cert_owner', 'mscqr_rls_cert_auth_owner', 'mscqr_rls_cert_app', 'mscqr_rls_cert_read', 'mscqr_rls_cert_preauth', 'mscqr_rls_cert_worker', 'mscqr_rls_cert_scheduled', 'mscqr_rls_cert_operator', 'mscqr_rls_cert_migration'))<>9
     OR EXISTS (SELECT 1 FROM pg_roles r JOIN (VALUES ('mscqr_rls_cert_owner', false),
    ('mscqr_rls_cert_auth_owner', false),
    ('mscqr_rls_cert_app', true),
    ('mscqr_rls_cert_read', true),
    ('mscqr_rls_cert_preauth', true),
    ('mscqr_rls_cert_worker', true),
    ('mscqr_rls_cert_scheduled', true),
    ('mscqr_rls_cert_operator', true),
    ('mscqr_rls_cert_migration', true)) spec(role_name,expected_login) ON spec.role_name=r.rolname WHERE r.rolcanlogin IS DISTINCT FROM spec.expected_login OR r.rolinherit OR r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls OR obj_description(r.oid,'pg_authid')<>'mscqr-full-rls-clean-room:certification:31314331260d1ce2f31399e33eb04cb87fcad6450368f99e3c7ea303efd74e3f')
  THEN RAISE EXCEPTION 'managed role attributes or package markers drifted'; END IF;

  IF (SELECT count(*) FROM pg_auth_members m JOIN pg_roles parent ON parent.oid=m.roleid WHERE parent.rolname IN ('mscqr_rls_cert_owner', 'mscqr_rls_cert_auth_owner', 'mscqr_rls_cert_app', 'mscqr_rls_cert_read', 'mscqr_rls_cert_preauth', 'mscqr_rls_cert_worker', 'mscqr_rls_cert_scheduled', 'mscqr_rls_cert_operator', 'mscqr_rls_cert_migration'))<>18
     OR EXISTS (SELECT 1 FROM pg_auth_members m JOIN pg_roles parent ON parent.oid=m.roleid JOIN pg_roles member ON member.oid=m.member WHERE parent.rolname IN ('mscqr_rls_cert_owner', 'mscqr_rls_cert_auth_owner', 'mscqr_rls_cert_app', 'mscqr_rls_cert_read', 'mscqr_rls_cert_preauth', 'mscqr_rls_cert_worker', 'mscqr_rls_cert_scheduled', 'mscqr_rls_cert_operator', 'mscqr_rls_cert_migration') AND (member.rolname<>'certification-administrator' OR m.inherit_option OR (m.admin_option=m.set_option)))
     OR EXISTS (SELECT 1 FROM pg_roles parent WHERE parent.rolname IN ('mscqr_rls_cert_owner', 'mscqr_rls_cert_auth_owner', 'mscqr_rls_cert_app', 'mscqr_rls_cert_read', 'mscqr_rls_cert_preauth', 'mscqr_rls_cert_worker', 'mscqr_rls_cert_scheduled', 'mscqr_rls_cert_operator', 'mscqr_rls_cert_migration') AND ((SELECT count(*) FROM pg_auth_members m JOIN pg_roles member ON member.oid=m.member WHERE m.roleid=parent.oid AND member.rolname='certification-administrator' AND m.admin_option AND NOT m.inherit_option AND NOT m.set_option)<>1 OR (SELECT count(*) FROM pg_auth_members m JOIN pg_roles member ON member.oid=m.member JOIN pg_roles grantor ON grantor.oid=m.grantor WHERE m.roleid=parent.oid AND member.rolname='certification-administrator' AND grantor.rolname='certification-administrator' AND NOT m.admin_option AND NOT m.inherit_option AND m.set_option)<>1))
     OR EXISTS (SELECT 1 FROM pg_auth_members m JOIN pg_roles member ON member.oid=m.member WHERE member.rolname IN ('mscqr_rls_cert_owner', 'mscqr_rls_cert_auth_owner', 'mscqr_rls_cert_app', 'mscqr_rls_cert_read', 'mscqr_rls_cert_preauth', 'mscqr_rls_cert_worker', 'mscqr_rls_cert_scheduled', 'mscqr_rls_cert_operator', 'mscqr_rls_cert_migration'))
  THEN RAISE EXCEPTION 'managed role membership topology drifted'; END IF;
END $$;
DO $$ BEGIN
  IF NOT pg_has_role(session_user,'mscqr_rls_cert_owner','SET') THEN RAISE EXCEPTION 'administrative executor lacks SET authority for mscqr_rls_cert_owner'; END IF;
  EXECUTE format('SET LOCAL ROLE %I','mscqr_rls_cert_owner');
END $$;
CREATE FUNCTION app_rls.setting(setting_name text) RETURNS text LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$ SELECT NULLIF(btrim(current_setting(setting_name,true)),'') $$;
CREATE FUNCTION app_rls.uuid_setting(setting_name text) RETURNS text LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$ SELECT CASE WHEN app_rls.setting(setting_name) ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' THEN lower(app_rls.setting(setting_name)) ELSE NULL END $$;
CREATE FUNCTION app_rls.current_user_id() RETURNS text LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$ SELECT app_rls.uuid_setting('app.user_id') $$;
CREATE FUNCTION app_rls.current_organization_id() RETURNS text LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$ SELECT app_rls.uuid_setting('app.organization_id') $$;
CREATE FUNCTION app_rls.current_licensee_id() RETURNS text LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$ SELECT app_rls.uuid_setting('app.licensee_id') $$;
CREATE FUNCTION app_rls.current_manufacturer_id() RETURNS text LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$ SELECT app_rls.uuid_setting('app.manufacturer_id') $$;
CREATE FUNCTION app_rls.current_role() RETURNS text LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$ SELECT app_rls.setting('app.role') $$;
CREATE FUNCTION app_rls.current_assurance() RETURNS text LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$ SELECT app_rls.setting('app.auth_assurance') $$;
CREATE FUNCTION app_rls.current_request_id() RETURNS text LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$ SELECT app_rls.setting('app.request_id') $$;
CREATE FUNCTION app_rls.current_purpose() RETURNS text LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$ SELECT app_rls.setting('app.purpose') $$;
CREATE FUNCTION app_rls.attributed_request() RETURNS boolean LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$ SELECT app_rls.current_request_id() IS NOT NULL AND app_rls.current_purpose() IS NOT NULL $$;
CREATE FUNCTION app_rls.install_actor_context(user_id text,actor_role text,organization_id text,licensee_id text,manufacturer_id text,assurance text,request_id text,purpose_code text) RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
  IF current_setting('app.context_installed',true)='1' OR app_rls.uuid_setting('app.user_id') IS NOT NULL THEN RAISE EXCEPTION 'canonical context already installed in this transaction'; END IF;
  IF user_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' THEN RAISE EXCEPTION 'invalid actor identifier'; END IF;
  IF actor_role !~ '^[A-Z][A-Z0-9_]{1,63}$' THEN RAISE EXCEPTION 'invalid actor role'; END IF;
  IF assurance NOT IN ('password-verified','mfa-bootstrap','mfa-verified','step-up-verified','system-verified','operator-approved','dual-approved-break-glass') THEN RAISE EXCEPTION 'invalid assurance'; END IF;
  IF request_id IS NULL OR btrim(request_id)='' OR purpose_code IS NULL OR btrim(purpose_code)='' THEN RAISE EXCEPTION 'request attribution is required'; END IF;
  IF organization_id<>'' AND organization_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' THEN RAISE EXCEPTION 'invalid organization identifier'; END IF;
  IF licensee_id<>'' AND licensee_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' THEN RAISE EXCEPTION 'invalid licensee identifier'; END IF;
  IF manufacturer_id<>'' AND manufacturer_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' THEN RAISE EXCEPTION 'invalid manufacturer identifier'; END IF;
  PERFORM set_config('app.user_id',lower(user_id),true),set_config('app.role',actor_role,true),set_config('app.organization_id',lower(coalesce(organization_id,'')),true),set_config('app.licensee_id',lower(coalesce(licensee_id,'')),true),set_config('app.manufacturer_id',lower(coalesce(manufacturer_id,'')),true),set_config('app.auth_assurance',assurance,true),set_config('app.request_id',request_id,true),set_config('app.purpose',purpose_code,true),set_config('app.context_installed','1',true);
END $$;
CREATE FUNCTION app_rls.manufacturer_scope_valid(target_manufacturer_id text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,app_rls AS $$
  SELECT target_manufacturer_id IS NOT NULL AND target_manufacturer_id ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    AND app_rls.current_licensee_id() IS NOT NULL
    AND ((app_rls.current_role() IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') AND target_manufacturer_id=app_rls.current_user_id() AND app_rls.current_purpose() IN ('audit-log-read','trace-timeline-read')) OR ((app_rls.current_role() IN ('LICENSEE_ADMIN','ORG_ADMIN') OR app_rls.current_role() IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')) AND app_rls.current_purpose()='tenant-risk-analytics'))
    AND EXISTS (SELECT 1 FROM public."User" u JOIN public."ManufacturerLicenseeLink" ml ON ml."manufacturerId"=u."id" JOIN public."Licensee" l ON l."id"=ml."licenseeId" JOIN public."Organization" o ON o."id"=l."orgId" WHERE u."id"=target_manufacturer_id AND u."role" IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') AND u."isActive"=TRUE AND u."status"='ACTIVE' AND u."deletedAt" IS NULL AND u."disabledAt" IS NULL AND ml."licenseeId"=app_rls.current_licensee_id() AND l."isActive"=TRUE AND l."suspendedAt" IS NULL AND (app_rls.current_organization_id() IS NULL OR l."orgId"=app_rls.current_organization_id()) AND o."isActive"=TRUE)
$$;
CREATE FUNCTION app_rls.actor_scope_valid() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,app_rls AS $$
  SELECT CASE
    WHEN app_rls.current_role() IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') THEN
      app_rls.current_manufacturer_id()=app_rls.current_user_id()
      AND EXISTS (SELECT 1 FROM public."User" u WHERE u."id"=app_rls.current_user_id() AND u."role"::text=app_rls.current_role() AND u."isActive"=TRUE AND u."status"='ACTIVE' AND u."deletedAt" IS NULL AND u."disabledAt" IS NULL)
      AND app_rls.manufacturer_scope_valid(app_rls.current_user_id())
    WHEN app_rls.current_role() IN ('LICENSEE_ADMIN','ORG_ADMIN') THEN
      EXISTS (SELECT 1 FROM public."User" u JOIN public."Licensee" l ON l."id"=u."licenseeId" JOIN public."Organization" o ON o."id"=u."orgId" AND o."id"=l."orgId" WHERE u."id"=app_rls.current_user_id() AND u."role"::text=app_rls.current_role() AND u."isActive"=TRUE AND u."status"='ACTIVE' AND u."deletedAt" IS NULL AND u."disabledAt" IS NULL AND u."licenseeId"=app_rls.current_licensee_id() AND u."orgId"=app_rls.current_organization_id() AND l."isActive"=TRUE AND l."suspendedAt" IS NULL AND o."isActive"=TRUE)
    WHEN app_rls.current_role() IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') THEN
      app_rls.current_assurance() IN ('mfa-verified','step-up-verified','dual-approved-break-glass')
      AND EXISTS (SELECT 1 FROM public."User" u WHERE u."id"=app_rls.current_user_id() AND u."role"::text=app_rls.current_role() AND u."isActive"=TRUE AND u."status"='ACTIVE' AND u."deletedAt" IS NULL AND u."disabledAt" IS NULL)
      AND EXISTS (SELECT 1 FROM public."Licensee" l JOIN public."Organization" o ON o."id"=l."orgId" WHERE l."id"=app_rls.current_licensee_id() AND (app_rls.current_organization_id() IS NULL OR l."orgId"=app_rls.current_organization_id()) AND l."isActive"=TRUE AND l."suspendedAt" IS NULL AND o."isActive"=TRUE)
    ELSE FALSE
  END
$$;
CREATE FUNCTION app_rls.platform_audit_log_details(log_ids text[]) RETURNS TABLE(id text,ip_address text,user_agent text,user_id text,user_name text) LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,app_rls AS $$
  SELECT a."id",a."ipAddress",a."userAgent",a."userId",u."name"
  FROM public."AuditLog" a LEFT JOIN public."User" u ON u."id"=a."userId"
  WHERE app_rls.attributed_request() AND app_rls.actor_scope_valid()
    AND app_rls.current_role() IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') AND app_rls.current_assurance() IN ('mfa-verified','step-up-verified','dual-approved-break-glass')
    AND app_rls.current_purpose()='platform-audit-log-read' AND cardinality(log_ids) BETWEEN 1 AND 500
    AND a."licenseeId"=app_rls.current_licensee_id() AND a."id"=ANY(log_ids)
$$;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA app_rls FROM PUBLIC;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA app_rls TO "mscqr_rls_cert_app";
RESET ROLE;
INSERT INTO mscqr_rls_install.expected_routine(
  schema_name,routine_name,identity_arguments,result_type,routine_kind,owner_name,language_name,volatility,
  security_definer,leakproof,strict,parallel_mode,configuration,source_body,acl_rows
)
SELECT n.nspname,p.proname,pg_get_function_identity_arguments(p.oid),pg_get_function_result(p.oid),p.prokind::text,
  owner_role.rolname,l.lanname,p.provolatile::text,p.prosecdef,p.proleakproof,p.proisstrict,p.proparallel::text,
  p.proconfig,p.prosrc,
  COALESCE((
    SELECT jsonb_agg(jsonb_build_array(COALESCE(grantee.rolname,'PUBLIC'),grantor.rolname,acl.privilege_type,acl.is_grantable)
      ORDER BY COALESCE(grantee.rolname,'PUBLIC'),grantor.rolname,acl.privilege_type,acl.is_grantable)
    FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) acl
    LEFT JOIN pg_roles grantee ON grantee.oid=acl.grantee
    JOIN pg_roles grantor ON grantor.oid=acl.grantor
  ),'[]'::jsonb)
FROM pg_proc p
JOIN pg_namespace n ON n.oid=p.pronamespace
JOIN pg_roles owner_role ON owner_role.oid=p.proowner
JOIN pg_language l ON l.oid=p.prolang
WHERE n.nspname IN ('app_rls','app_auth');
UPDATE mscqr_rls_install.state SET phase='context-helpers-installed' WHERE singleton;
COMMIT;
