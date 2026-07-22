\set ON_ERROR_STOP on
BEGIN;
DO $$ BEGIN

  IF current_user<>'certification-administrator' THEN RAISE EXCEPTION 'context helpers requires the reviewed brokered administrator'; END IF;
  IF current_database() !~ '^mscqr_full_rls_cert_[a-z0-9_]+$' THEN RAISE EXCEPTION 'context helpers is bound to the reviewed green database'; END IF;
  IF NOT EXISTS (SELECT 1 FROM mscqr_rls_install.state WHERE singleton
    AND target_environment='certification'
    AND deployment_id='cert'
    AND green_database=current_database()
    AND source_contract_sha256='4b26861c6ae1e37033afaa11f0e6f6c46ac7fd4961f0bdba0366075305734148'
    AND package_role_marker='mscqr-full-rls-clean-room:certification:4b26861c6ae1e37033afaa11f0e6f6c46ac7fd4961f0bdba0366075305734148'
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
    ('mscqr_rls_cert_migration', true)) spec(role_name,expected_login) ON spec.role_name=r.rolname WHERE r.rolcanlogin IS DISTINCT FROM spec.expected_login OR r.rolinherit OR r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls OR obj_description(r.oid,'pg_authid')<>'mscqr-full-rls-clean-room:certification:4b26861c6ae1e37033afaa11f0e6f6c46ac7fd4961f0bdba0366075305734148')
  THEN RAISE EXCEPTION 'managed role attributes or package markers drifted'; END IF;

  IF (SELECT count(*) FROM pg_auth_members m JOIN pg_roles parent ON parent.oid=m.roleid WHERE parent.rolname IN ('mscqr_rls_cert_owner', 'mscqr_rls_cert_auth_owner', 'mscqr_rls_cert_app', 'mscqr_rls_cert_read', 'mscqr_rls_cert_preauth', 'mscqr_rls_cert_worker', 'mscqr_rls_cert_scheduled', 'mscqr_rls_cert_operator', 'mscqr_rls_cert_migration'))<>18
     OR EXISTS (SELECT 1 FROM pg_auth_members m JOIN pg_roles parent ON parent.oid=m.roleid JOIN pg_roles member ON member.oid=m.member WHERE parent.rolname IN ('mscqr_rls_cert_owner', 'mscqr_rls_cert_auth_owner', 'mscqr_rls_cert_app', 'mscqr_rls_cert_read', 'mscqr_rls_cert_preauth', 'mscqr_rls_cert_worker', 'mscqr_rls_cert_scheduled', 'mscqr_rls_cert_operator', 'mscqr_rls_cert_migration') AND (member.rolname<>'certification-administrator' OR m.inherit_option OR (m.admin_option=m.set_option)))
     OR EXISTS (SELECT 1 FROM pg_roles parent WHERE parent.rolname IN ('mscqr_rls_cert_owner', 'mscqr_rls_cert_auth_owner', 'mscqr_rls_cert_app', 'mscqr_rls_cert_read', 'mscqr_rls_cert_preauth', 'mscqr_rls_cert_worker', 'mscqr_rls_cert_scheduled', 'mscqr_rls_cert_operator', 'mscqr_rls_cert_migration') AND ((SELECT count(*) FROM pg_auth_members m JOIN pg_roles member ON member.oid=m.member WHERE m.roleid=parent.oid AND member.rolname='certification-administrator' AND m.admin_option AND NOT m.inherit_option AND NOT m.set_option)<>1 OR (SELECT count(*) FROM pg_auth_members m JOIN pg_roles member ON member.oid=m.member JOIN pg_roles grantor ON grantor.oid=m.grantor WHERE m.roleid=parent.oid AND member.rolname='certification-administrator' AND grantor.rolname='certification-administrator' AND NOT m.admin_option AND NOT m.inherit_option AND m.set_option)<>1))
     OR EXISTS (SELECT 1 FROM pg_auth_members m JOIN pg_roles member ON member.oid=m.member WHERE member.rolname IN ('mscqr_rls_cert_owner', 'mscqr_rls_cert_auth_owner', 'mscqr_rls_cert_app', 'mscqr_rls_cert_read', 'mscqr_rls_cert_preauth', 'mscqr_rls_cert_worker', 'mscqr_rls_cert_scheduled', 'mscqr_rls_cert_operator', 'mscqr_rls_cert_migration'))
  THEN RAISE EXCEPTION 'managed role membership topology drifted'; END IF;
END $$;
DO $$ BEGIN
  IF NOT pg_has_role(session_user,'mscqr_rls_cert_owner','SET') THEN RAISE EXCEPTION 'administrative executor lacks SET authority for mscqr_rls_cert_owner'; END IF;
END $$;
SET ROLE "mscqr_rls_cert_owner";
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

CREATE FUNCTION app_rls.dashboard_scope_fingerprint(requested_licensee_id text) RETURNS text
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,app_rls AS $function$
DECLARE
  selector text := NULLIF(btrim(requested_licensee_id),'');
  actor_licensee_id text;
  actor_organization_id text;
  membership_count bigint;
  primary_count bigint;
  membership_fingerprint text;
BEGIN
  IF NOT app_rls.attributed_request()
     OR app_rls.current_purpose()<>'dashboard-snapshot-read'
     OR app_rls.current_user_id() IS NULL
     OR app_rls.current_role() IS NULL
     OR app_rls.current_request_id() !~ '^[A-Za-z0-9._:-]{1,128}$'
  THEN RAISE EXCEPTION 'dashboard access denied'; END IF;
  IF selector IS NOT NULL AND selector !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  THEN RAISE EXCEPTION 'dashboard access denied'; END IF;
  IF ((app_rls.current_role() IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') OR app_rls.current_role() IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER')) AND app_rls.current_assurance() NOT IN ('mfa-verified','step-up-verified','dual-approved-break-glass'))
     OR (app_rls.current_role() IN ('LICENSEE_ADMIN','ORG_ADMIN') AND app_rls.current_assurance() NOT IN ('password-verified','mfa-verified','step-up-verified','dual-approved-break-glass'))
     OR NOT (app_rls.current_role() IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') OR app_rls.current_role() IN ('LICENSEE_ADMIN','ORG_ADMIN') OR app_rls.current_role() IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER'))
  THEN RAISE EXCEPTION 'dashboard access denied'; END IF;

  SELECT u."licenseeId",u."orgId" INTO actor_licensee_id,actor_organization_id
  FROM public."User" u
  WHERE u."id"=app_rls.current_user_id()
    AND u."role"::text=app_rls.current_role()
    AND u."isActive"=TRUE AND u."status"='ACTIVE'
    AND u."deletedAt" IS NULL AND u."disabledAt" IS NULL;
  IF NOT FOUND THEN RAISE EXCEPTION 'dashboard access denied'; END IF;

  IF app_rls.current_role() IN ('LICENSEE_ADMIN','ORG_ADMIN') THEN
    IF app_rls.current_licensee_id() IS NULL OR app_rls.current_organization_id() IS NULL
       OR app_rls.current_manufacturer_id() IS NOT NULL
       OR actor_licensee_id IS DISTINCT FROM app_rls.current_licensee_id()
       OR actor_organization_id IS DISTINCT FROM app_rls.current_organization_id()
       OR (selector IS NOT NULL AND selector IS DISTINCT FROM app_rls.current_licensee_id())
       OR NOT EXISTS (
         SELECT 1 FROM public."Licensee" l JOIN public."Organization" o ON o."id"=l."orgId"
         WHERE l."id"=app_rls.current_licensee_id() AND l."orgId"=app_rls.current_organization_id()
           AND l."isActive"=TRUE AND l."suspendedAt" IS NULL AND o."isActive"=TRUE
       )
    THEN RAISE EXCEPTION 'dashboard access denied'; END IF;
    RETURN md5(concat_ws('|','tenant',app_rls.current_user_id(),app_rls.current_role(),app_rls.current_licensee_id(),app_rls.current_organization_id()));
  END IF;

  IF app_rls.current_role() IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') THEN
    IF app_rls.current_manufacturer_id() IS DISTINCT FROM app_rls.current_user_id()
       OR app_rls.current_organization_id() IS NOT NULL
       OR app_rls.current_licensee_id() IS DISTINCT FROM selector
    THEN RAISE EXCEPTION 'dashboard access denied'; END IF;
    SELECT count(*),count(*) FILTER (WHERE ml."isPrimary"),string_agg(ml."licenseeId"||':'||ml."isPrimary"::text||':'||extract(epoch FROM ml."updatedAt")::text,',' ORDER BY ml."licenseeId")
      INTO membership_count,primary_count,membership_fingerprint
    FROM public."ManufacturerLicenseeLink" ml
    JOIN public."Licensee" l ON l."id"=ml."licenseeId"
    JOIN public."Organization" o ON o."id"=l."orgId"
    WHERE ml."manufacturerId"=app_rls.current_user_id()
      AND l."isActive"=TRUE AND l."suspendedAt" IS NULL AND o."isActive"=TRUE;
    IF membership_count NOT BETWEEN 1 AND 100 OR primary_count>1
       OR (actor_licensee_id IS NOT NULL AND NOT EXISTS (
         SELECT 1 FROM public."ManufacturerLicenseeLink" ml
         JOIN public."Licensee" l ON l."id"=ml."licenseeId"
         JOIN public."Organization" o ON o."id"=l."orgId"
         WHERE ml."manufacturerId"=app_rls.current_user_id() AND ml."licenseeId"=actor_licensee_id
           AND l."isActive"=TRUE AND l."suspendedAt" IS NULL AND o."isActive"=TRUE
       ))
       OR (actor_organization_id IS NOT NULL AND NOT EXISTS (
         SELECT 1 FROM public."ManufacturerLicenseeLink" ml
         JOIN public."Licensee" l ON l."id"=ml."licenseeId"
         JOIN public."Organization" o ON o."id"=l."orgId"
         WHERE ml."manufacturerId"=app_rls.current_user_id() AND l."orgId"=actor_organization_id
           AND l."isActive"=TRUE AND l."suspendedAt" IS NULL AND o."isActive"=TRUE
       ))
       OR (selector IS NOT NULL AND NOT EXISTS (
         SELECT 1 FROM public."ManufacturerLicenseeLink" ml
         JOIN public."Licensee" l ON l."id"=ml."licenseeId"
         JOIN public."Organization" o ON o."id"=l."orgId"
         WHERE ml."manufacturerId"=app_rls.current_user_id() AND ml."licenseeId"=selector
           AND l."isActive"=TRUE AND l."suspendedAt" IS NULL AND o."isActive"=TRUE
       ))
    THEN RAISE EXCEPTION 'dashboard access denied'; END IF;
    RETURN md5(concat_ws('|','manufacturer',app_rls.current_user_id(),app_rls.current_role(),coalesce(selector,'all'),membership_fingerprint));
  END IF;

  IF app_rls.current_manufacturer_id() IS NOT NULL OR app_rls.current_organization_id() IS NOT NULL
     OR app_rls.current_licensee_id() IS DISTINCT FROM selector
     OR (selector IS NOT NULL AND NOT EXISTS (
       SELECT 1 FROM public."Licensee" l JOIN public."Organization" o ON o."id"=l."orgId"
       WHERE l."id"=selector AND l."isActive"=TRUE AND l."suspendedAt" IS NULL AND o."isActive"=TRUE
     ))
  THEN RAISE EXCEPTION 'dashboard access denied'; END IF;
  RETURN md5(concat_ws('|','platform',app_rls.current_user_id(),app_rls.current_role(),coalesce(selector,'global')));
END
$function$;

CREATE FUNCTION app_rls.authorize_dashboard_snapshot(audit_id text,requested_licensee_id text,route_surface text) RETURNS text
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,app_rls AS $function$
DECLARE
  fingerprint text;
  audit_organization_id text := app_rls.current_organization_id();
BEGIN
  IF audit_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
     OR route_surface NOT IN ('GET /api/dashboard/stats','GET /api/events/dashboard')
  THEN RAISE EXCEPTION 'dashboard access denied'; END IF;
  fingerprint := app_rls.dashboard_scope_fingerprint(requested_licensee_id);
  IF app_rls.current_licensee_id() IS NOT NULL AND audit_organization_id IS NULL THEN
    SELECT l."orgId" INTO audit_organization_id
    FROM public."Licensee" l JOIN public."Organization" o ON o."id"=l."orgId"
    WHERE l."id"=app_rls.current_licensee_id()
      AND l."isActive"=TRUE AND l."suspendedAt" IS NULL AND o."isActive"=TRUE;
    IF NOT FOUND THEN RAISE EXCEPTION 'dashboard access denied'; END IF;
  END IF;
  INSERT INTO public."AuditLog"
    ("id","userId","orgId","licenseeId","action","entityType","entityId","details")
  VALUES (
    lower(audit_id),app_rls.current_user_id(),audit_organization_id,app_rls.current_licensee_id(),
    'DASHBOARD_SNAPSHOT_READ','DashboardSnapshot',coalesce(app_rls.current_licensee_id(),app_rls.current_user_id()),
    jsonb_build_object(
      'actorId',app_rls.current_user_id(),'role',app_rls.current_role(),'assurance',app_rls.current_assurance(),
      'requestId',app_rls.current_request_id(),'purposeCode',app_rls.current_purpose(),'route',route_surface,
      'scopeFingerprint',fingerprint,'outcome','SUCCESS','workflowIds',jsonb_build_array(
        'workflow-internal-backend-src-services-dashboard-snapshot-service-ts-compute-dashboard-snapshot',
        'workflow-internal-backend-src-services-dashboard-snapshot-service-ts-load-inventory-aggregate'
      )
    )
  ) ON CONFLICT ("id") DO NOTHING;
  IF NOT EXISTS (
    SELECT 1 FROM public."AuditLog" a
    WHERE a."id"=lower(audit_id) AND a."userId"=app_rls.current_user_id()
      AND a."orgId" IS NOT DISTINCT FROM audit_organization_id
      AND a."licenseeId" IS NOT DISTINCT FROM app_rls.current_licensee_id()
      AND a."action"='DASHBOARD_SNAPSHOT_READ' AND a."entityType"='DashboardSnapshot'
      AND a."entityId"=coalesce(app_rls.current_licensee_id(),app_rls.current_user_id())
      AND a."details"->>'actorId'=app_rls.current_user_id()
      AND a."details"->>'role'=app_rls.current_role()
      AND a."details"->>'assurance'=app_rls.current_assurance()
      AND a."details"->>'requestId'=app_rls.current_request_id()
      AND a."details"->>'purposeCode'='dashboard-snapshot-read'
      AND a."details"->>'route'=route_surface
      AND a."details"->>'scopeFingerprint'=fingerprint
      AND a."details"->>'outcome'='SUCCESS'
      AND a."details"->'workflowIds'=jsonb_build_array(
        'workflow-internal-backend-src-services-dashboard-snapshot-service-ts-compute-dashboard-snapshot',
        'workflow-internal-backend-src-services-dashboard-snapshot-service-ts-load-inventory-aggregate'
      )
  ) THEN RAISE EXCEPTION 'dashboard access denied'; END IF;
  RETURN fingerprint;
END
$function$;

CREATE FUNCTION app_rls.dashboard_snapshot_scope(audit_id text,requested_licensee_id text,route_surface text)
RETURNS TABLE(scope_fingerprint text) LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,app_rls AS $function$
  SELECT app_rls.authorize_dashboard_snapshot(audit_id,requested_licensee_id,route_surface)
$function$;

CREATE FUNCTION app_rls.dashboard_snapshot_data(audit_id text,requested_licensee_id text,route_surface text,expected_scope_fingerprint text)
RETURNS TABLE(
  total_qr_codes bigint,active_licensees bigint,manufacturers bigint,total_batches bigint,
  dormant bigint,active bigint,activated bigint,allocated bigint,printed bigint,redeemed bigint,blocked bigint,scanned bigint,
  rollup_authoritative boolean
) LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,app_rls AS $function$
DECLARE
  fingerprint text;
  rollup_total bigint;
  rollup_dormant bigint;
  rollup_active bigint;
  rollup_activated bigint;
  rollup_allocated bigint;
  rollup_printed bigint;
  rollup_redeemed bigint;
  rollup_blocked bigint;
  rollup_scanned bigint;
BEGIN
  fingerprint := app_rls.authorize_dashboard_snapshot(audit_id,requested_licensee_id,route_surface);
  IF expected_scope_fingerprint IS DISTINCT FROM fingerprint THEN RAISE EXCEPTION 'dashboard access denied'; END IF;

  IF app_rls.current_role() IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') THEN
    SELECT count(*) INTO active_licensees
    FROM public."Licensee" l
    JOIN public."Organization" o ON o."id"=l."orgId"
    WHERE EXISTS (
      SELECT 1 FROM public."ManufacturerLicenseeLink" ml
      WHERE ml."manufacturerId"=app_rls.current_user_id() AND ml."licenseeId"=l."id"
    ) AND l."isActive"=TRUE AND l."suspendedAt" IS NULL AND o."isActive"=TRUE;
  ELSIF app_rls.current_role() IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') AND app_rls.current_licensee_id() IS NULL THEN
    SELECT count(*) INTO active_licensees
    FROM public."Licensee" l
    WHERE l."isActive"=TRUE;
  ELSE
    SELECT count(*) INTO active_licensees
    FROM public."Licensee" l
    JOIN public."Organization" o ON o."id"=l."orgId"
    WHERE l."id"=app_rls.current_licensee_id()
      AND l."isActive"=TRUE AND l."suspendedAt" IS NULL AND o."isActive"=TRUE;
  END IF;

  SELECT count(*) INTO manufacturers
  FROM public."User" u
  WHERE u."role" IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') AND u."isActive"=TRUE
    AND (
      (app_rls.current_role() IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') AND u."id"=app_rls.current_user_id())
      OR (app_rls.current_role() IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') AND app_rls.current_licensee_id() IS NULL)
      OR ((app_rls.current_role() IN ('LICENSEE_ADMIN','ORG_ADMIN') OR app_rls.current_role() IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')) AND app_rls.current_licensee_id() IS NOT NULL AND (
        u."licenseeId"=app_rls.current_licensee_id()
        OR EXISTS (SELECT 1 FROM public."ManufacturerLicenseeLink" ml WHERE ml."manufacturerId"=u."id" AND ml."licenseeId"=app_rls.current_licensee_id())
      ))
    );

  SELECT count(*) INTO total_batches
  FROM public."Batch" b
  WHERE (
    (app_rls.current_role() IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') AND b."manufacturerId"=app_rls.current_user_id() AND EXISTS (
      SELECT 1 FROM public."ManufacturerLicenseeLink" ml
      JOIN public."Licensee" l ON l."id"=ml."licenseeId"
      JOIN public."Organization" o ON o."id"=l."orgId"
      WHERE ml."manufacturerId"=app_rls.current_user_id() AND ml."licenseeId"=b."licenseeId"
        AND l."isActive"=TRUE AND l."suspendedAt" IS NULL AND o."isActive"=TRUE
        AND (app_rls.current_licensee_id() IS NULL OR ml."licenseeId"=app_rls.current_licensee_id())
    ))
    OR (app_rls.current_role() IN ('LICENSEE_ADMIN','ORG_ADMIN') AND b."licenseeId"=app_rls.current_licensee_id())
    OR (app_rls.current_role() IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') AND (app_rls.current_licensee_id() IS NULL OR b."licenseeId"=app_rls.current_licensee_id()))
  );

  SELECT coalesce(sum(r."totalCodes"),0),coalesce(sum(r."dormant"),0),coalesce(sum(r."active"),0),
         coalesce(sum(r."activated"),0),coalesce(sum(r."allocated"),0),coalesce(sum(r."printed"),0),
         coalesce(sum(r."redeemed"),0),coalesce(sum(r."blocked"),0),coalesce(sum(r."scanned"),0)
    INTO rollup_total,rollup_dormant,rollup_active,rollup_activated,rollup_allocated,rollup_printed,rollup_redeemed,rollup_blocked,rollup_scanned
  FROM public."InventoryStatusRollup" r
  WHERE (
    (app_rls.current_role() IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') AND r."manufacturerId"=app_rls.current_user_id() AND EXISTS (
      SELECT 1 FROM public."ManufacturerLicenseeLink" ml
      JOIN public."Licensee" l ON l."id"=ml."licenseeId"
      JOIN public."Organization" o ON o."id"=l."orgId"
      WHERE ml."manufacturerId"=app_rls.current_user_id() AND ml."licenseeId"=r."licenseeId"
        AND l."isActive"=TRUE AND l."suspendedAt" IS NULL AND o."isActive"=TRUE
        AND (app_rls.current_licensee_id() IS NULL OR ml."licenseeId"=app_rls.current_licensee_id())
    ))
    OR (app_rls.current_role() IN ('LICENSEE_ADMIN','ORG_ADMIN') AND r."licenseeId"=app_rls.current_licensee_id())
    OR (app_rls.current_role() IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') AND (app_rls.current_licensee_id() IS NULL OR r."licenseeId"=app_rls.current_licensee_id()))
  );

  IF rollup_total>0 OR rollup_dormant>0 OR rollup_active>0 OR rollup_activated>0 OR rollup_allocated>0
     OR rollup_printed>0 OR rollup_redeemed>0 OR rollup_blocked>0 OR rollup_scanned>0
  THEN
    rollup_authoritative:=TRUE;
    total_qr_codes:=rollup_total; dormant:=rollup_dormant; active:=rollup_active; activated:=rollup_activated;
    allocated:=rollup_allocated; printed:=rollup_printed; redeemed:=rollup_redeemed; blocked:=rollup_blocked; scanned:=rollup_scanned;
  ELSE
    rollup_authoritative:=FALSE;
    SELECT count(*),count(*) FILTER (WHERE qcode."status"='DORMANT'),count(*) FILTER (WHERE qcode."status"='ACTIVE'),
           count(*) FILTER (WHERE qcode."status"='ACTIVATED'),count(*) FILTER (WHERE qcode."status"='ALLOCATED'),
           count(*) FILTER (WHERE qcode."status"='PRINTED'),count(*) FILTER (WHERE qcode."status"='REDEEMED'),
           count(*) FILTER (WHERE qcode."status"='BLOCKED'),count(*) FILTER (WHERE qcode."status"='SCANNED')
      INTO total_qr_codes,dormant,active,activated,allocated,printed,redeemed,blocked,scanned
    FROM public."QRCode" qcode
    WHERE (
      (app_rls.current_role() IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') AND EXISTS (
        SELECT 1 FROM public."Batch" b WHERE b."id"=qcode."batchId" AND b."manufacturerId"=app_rls.current_user_id()
      ) AND EXISTS (
        SELECT 1 FROM public."ManufacturerLicenseeLink" ml
        JOIN public."Licensee" l ON l."id"=ml."licenseeId"
        JOIN public."Organization" o ON o."id"=l."orgId"
        WHERE ml."manufacturerId"=app_rls.current_user_id() AND ml."licenseeId"=qcode."licenseeId"
          AND l."isActive"=TRUE AND l."suspendedAt" IS NULL AND o."isActive"=TRUE
          AND (app_rls.current_licensee_id() IS NULL OR ml."licenseeId"=app_rls.current_licensee_id())
      ))
      OR (app_rls.current_role() IN ('LICENSEE_ADMIN','ORG_ADMIN') AND qcode."licenseeId"=app_rls.current_licensee_id())
      OR (app_rls.current_role() IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') AND (app_rls.current_licensee_id() IS NULL OR qcode."licenseeId"=app_rls.current_licensee_id()))
    );
  END IF;
  RETURN NEXT;
END
$function$;

CREATE FUNCTION app_rls.batch_scope_fingerprint(requested_licensee_id text,route_surface text,focus_batch_id text) RETURNS text
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,app_rls AS $function$
DECLARE
  selector text := NULLIF(btrim(requested_licensee_id),'');
  focus_id text := NULLIF(btrim(focus_batch_id),'');
  actor_licensee_id text;
  actor_organization_id text;
  membership_count bigint;
  primary_count bigint;
  membership_fingerprint text;
BEGIN
  IF NOT (app_rls.attributed_request() AND app_rls.current_purpose()='batch-operational-read' AND app_rls.current_request_id() ~ '^[A-Za-z0-9._:-]{1,128}$' AND ((app_rls.current_role() IN ('LICENSEE_ADMIN','ORG_ADMIN') AND app_rls.current_assurance() IN ('password-verified','mfa-verified','step-up-verified','dual-approved-break-glass')) OR ((app_rls.current_role() IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') OR app_rls.current_role() IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')) AND app_rls.current_assurance() IN ('mfa-verified','step-up-verified','dual-approved-break-glass'))))
     OR app_rls.current_user_id() IS NULL OR app_rls.current_role() IS NULL
     OR route_surface IS NULL
     OR (requested_licensee_id IS NOT NULL AND btrim(requested_licensee_id)='')
     OR (focus_batch_id IS NOT NULL AND btrim(focus_batch_id)='')
     OR route_surface NOT IN ('GET /api/qr/batches','GET /api/qr/batches/:id/allocation-map')
     OR (route_surface='GET /api/qr/batches' AND focus_id IS NOT NULL)
     OR (route_surface='GET /api/qr/batches/:id/allocation-map' AND focus_id IS NULL)
  THEN RAISE EXCEPTION 'batch operational access denied'; END IF;
  IF (selector IS NOT NULL AND selector !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$')
     OR (focus_id IS NOT NULL AND focus_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$')
  THEN RAISE EXCEPTION 'batch operational access denied'; END IF;

  SELECT u."licenseeId",u."orgId" INTO actor_licensee_id,actor_organization_id
  FROM public."User" u
  WHERE u."id"=app_rls.current_user_id() AND u."role"::text=app_rls.current_role()
    AND u."isActive"=TRUE AND u."status"='ACTIVE'
    AND u."deletedAt" IS NULL AND u."disabledAt" IS NULL;
  IF NOT FOUND THEN RAISE EXCEPTION 'batch operational access denied'; END IF;

  IF app_rls.current_role() IN ('LICENSEE_ADMIN','ORG_ADMIN') THEN
    IF app_rls.current_licensee_id() IS NULL OR app_rls.current_organization_id() IS NULL
       OR app_rls.current_manufacturer_id() IS NOT NULL
       OR actor_licensee_id IS DISTINCT FROM app_rls.current_licensee_id()
       OR actor_organization_id IS DISTINCT FROM app_rls.current_organization_id()
       OR (selector IS NOT NULL AND selector IS DISTINCT FROM app_rls.current_licensee_id())
       OR NOT EXISTS (
         SELECT 1 FROM public."Licensee" l JOIN public."Organization" o ON o."id"=l."orgId"
         WHERE l."id"=app_rls.current_licensee_id() AND l."orgId"=app_rls.current_organization_id()
           AND l."isActive"=TRUE AND l."suspendedAt" IS NULL AND o."isActive"=TRUE
       )
    THEN RAISE EXCEPTION 'batch operational access denied'; END IF;
    RETURN md5(concat_ws('|','tenant',app_rls.current_user_id(),app_rls.current_role(),app_rls.current_licensee_id(),app_rls.current_organization_id(),route_surface,coalesce(focus_id,'list')));
  END IF;

  IF app_rls.current_role() IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') THEN
    IF app_rls.current_manufacturer_id() IS DISTINCT FROM app_rls.current_user_id()
       OR app_rls.current_organization_id() IS NOT NULL
       OR app_rls.current_licensee_id() IS DISTINCT FROM selector
    THEN RAISE EXCEPTION 'batch operational access denied'; END IF;
    SELECT count(*),count(*) FILTER (WHERE ml."isPrimary"),string_agg(ml."licenseeId"||':'||ml."isPrimary"::text||':'||extract(epoch FROM ml."updatedAt")::text,',' ORDER BY ml."licenseeId")
      INTO membership_count,primary_count,membership_fingerprint
    FROM public."ManufacturerLicenseeLink" ml
    JOIN public."Licensee" l ON l."id"=ml."licenseeId"
    JOIN public."Organization" o ON o."id"=l."orgId"
    WHERE ml."manufacturerId"=app_rls.current_user_id()
      AND l."isActive"=TRUE AND l."suspendedAt" IS NULL AND o."isActive"=TRUE;
    IF membership_count NOT BETWEEN 1 AND 100 OR primary_count>1
       OR (actor_licensee_id IS NOT NULL AND NOT EXISTS (
         SELECT 1 FROM public."ManufacturerLicenseeLink" ml
         JOIN public."Licensee" l ON l."id"=ml."licenseeId"
         JOIN public."Organization" o ON o."id"=l."orgId"
         WHERE ml."manufacturerId"=app_rls.current_user_id() AND ml."licenseeId"=actor_licensee_id
           AND l."isActive"=TRUE AND l."suspendedAt" IS NULL AND o."isActive"=TRUE
       ))
       OR (actor_organization_id IS NOT NULL AND NOT EXISTS (
         SELECT 1 FROM public."ManufacturerLicenseeLink" ml
         JOIN public."Licensee" l ON l."id"=ml."licenseeId"
         JOIN public."Organization" o ON o."id"=l."orgId"
         WHERE ml."manufacturerId"=app_rls.current_user_id() AND l."orgId"=actor_organization_id
           AND l."isActive"=TRUE AND l."suspendedAt" IS NULL AND o."isActive"=TRUE
       ))
       OR (selector IS NOT NULL AND NOT EXISTS (
         SELECT 1 FROM public."ManufacturerLicenseeLink" ml
         JOIN public."Licensee" l ON l."id"=ml."licenseeId"
         JOIN public."Organization" o ON o."id"=l."orgId"
         WHERE ml."manufacturerId"=app_rls.current_user_id() AND ml."licenseeId"=selector
           AND l."isActive"=TRUE AND l."suspendedAt" IS NULL AND o."isActive"=TRUE
       ))
    THEN RAISE EXCEPTION 'batch operational access denied'; END IF;
    RETURN md5(concat_ws('|','manufacturer',app_rls.current_user_id(),app_rls.current_role(),coalesce(selector,'all'),membership_fingerprint,route_surface,coalesce(focus_id,'list')));
  END IF;

  IF NOT app_rls.current_role() IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') OR selector IS NULL OR app_rls.current_licensee_id() IS DISTINCT FROM selector
     OR app_rls.current_manufacturer_id() IS NOT NULL OR app_rls.current_organization_id() IS NOT NULL
     OR NOT EXISTS (
       SELECT 1 FROM public."Licensee" l JOIN public."Organization" o ON o."id"=l."orgId"
       WHERE l."id"=selector AND l."isActive"=TRUE AND l."suspendedAt" IS NULL AND o."isActive"=TRUE
     )
  THEN RAISE EXCEPTION 'batch operational access denied'; END IF;
  RETURN md5(concat_ws('|','platform',app_rls.current_user_id(),app_rls.current_role(),selector,route_surface,coalesce(focus_id,'list')));
END
$function$;

CREATE FUNCTION app_rls.batch_operational_batch_allowed(candidate_batch_id text,focus_batch_id text) RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,app_rls AS $function$
DECLARE focus_id text := NULLIF(btrim(focus_batch_id),''); focus_licensee_id text; source_batch_id text;
BEGIN
  IF candidate_batch_id IS NULL OR candidate_batch_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' THEN RETURN FALSE; END IF;
  IF focus_id IS NULL THEN
    RETURN EXISTS (SELECT 1 FROM public."Batch" b WHERE b."id"=candidate_batch_id AND (
      ((app_rls.current_role() IN ('LICENSEE_ADMIN','ORG_ADMIN') OR app_rls.current_role() IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')) AND b."licenseeId"=app_rls.current_licensee_id())
      OR (app_rls.current_role() IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') AND b."manufacturerId"=app_rls.current_user_id() AND EXISTS (
  SELECT 1 FROM public."ManufacturerLicenseeLink" scope_ml
  JOIN public."Licensee" scope_l ON scope_l."id"=scope_ml."licenseeId"
  JOIN public."Organization" scope_o ON scope_o."id"=scope_l."orgId"
  WHERE scope_ml."manufacturerId"=app_rls.current_user_id()
    AND scope_ml."licenseeId"=b."licenseeId"
    AND scope_l."isActive"=TRUE AND scope_l."suspendedAt" IS NULL AND scope_o."isActive"=TRUE
    AND (app_rls.current_licensee_id() IS NULL OR scope_ml."licenseeId"=app_rls.current_licensee_id())
))
    ));
  END IF;
  SELECT f."licenseeId",coalesce(f."rootBatchId",f."parentBatchId",f."id") INTO focus_licensee_id,source_batch_id
  FROM public."Batch" f WHERE f."id"=focus_id AND (
    ((app_rls.current_role() IN ('LICENSEE_ADMIN','ORG_ADMIN') OR app_rls.current_role() IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')) AND f."licenseeId"=app_rls.current_licensee_id())
    OR (app_rls.current_role() IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') AND f."manufacturerId"=app_rls.current_user_id() AND EXISTS (
  SELECT 1 FROM public."ManufacturerLicenseeLink" scope_ml
  JOIN public."Licensee" scope_l ON scope_l."id"=scope_ml."licenseeId"
  JOIN public."Organization" scope_o ON scope_o."id"=scope_l."orgId"
  WHERE scope_ml."manufacturerId"=app_rls.current_user_id()
    AND scope_ml."licenseeId"=f."licenseeId"
    AND scope_l."isActive"=TRUE AND scope_l."suspendedAt" IS NULL AND scope_o."isActive"=TRUE
    AND (app_rls.current_licensee_id() IS NULL OR scope_ml."licenseeId"=app_rls.current_licensee_id())
))
  );
  IF NOT FOUND THEN RETURN FALSE; END IF;
  RETURN EXISTS (SELECT 1 FROM public."Batch" b WHERE b."id"=candidate_batch_id AND b."licenseeId"=focus_licensee_id
    AND (b."id"=source_batch_id OR b."parentBatchId"=source_batch_id OR b."rootBatchId"=source_batch_id));
END
$function$;

CREATE FUNCTION app_rls.authorize_batch_operational_read(audit_id text,requested_licensee_id text,route_surface text,focus_batch_id text) RETURNS text
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,app_rls AS $function$
DECLARE fingerprint text; audit_organization_id text := app_rls.current_organization_id(); focus_id text := NULLIF(btrim(focus_batch_id),'');
BEGIN
  IF audit_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' THEN RAISE EXCEPTION 'batch operational access denied'; END IF;
  fingerprint := app_rls.batch_scope_fingerprint(requested_licensee_id,route_surface,focus_id);
  IF focus_id IS NOT NULL AND NOT app_rls.batch_operational_batch_allowed(focus_id,focus_id) THEN
    RAISE EXCEPTION 'batch operational access denied';
  END IF;
  IF app_rls.current_licensee_id() IS NOT NULL AND audit_organization_id IS NULL THEN
    SELECT l."orgId" INTO audit_organization_id FROM public."Licensee" l JOIN public."Organization" o ON o."id"=l."orgId"
    WHERE l."id"=app_rls.current_licensee_id() AND l."isActive"=TRUE AND l."suspendedAt" IS NULL AND o."isActive"=TRUE;
    IF NOT FOUND THEN RAISE EXCEPTION 'batch operational access denied'; END IF;
  END IF;
  INSERT INTO public."AuditLog" ("id","userId","orgId","licenseeId","action","entityType","entityId","details")
  VALUES (lower(audit_id),app_rls.current_user_id(),audit_organization_id,app_rls.current_licensee_id(),'BATCH_OPERATIONAL_READ','BatchOperationalRead',coalesce(focus_id,app_rls.current_licensee_id(),app_rls.current_user_id()),
    jsonb_build_object('actorId',app_rls.current_user_id(),'role',app_rls.current_role(),'assurance',app_rls.current_assurance(),'requestId',app_rls.current_request_id(),'purposeCode',app_rls.current_purpose(),'route',route_surface,'focusBatchId',focus_id,'scopeFingerprint',fingerprint,'outcome','SUCCESS','workflowIds',jsonb_build_array('workflow-internal-backend-src-services-batch-allocation-service-ts-build-count-maps','workflow-internal-backend-src-services-batch-allocation-service-ts-get-batch-allocation-map','workflow-internal-backend-src-services-batch-allocation-service-ts-read-batches','workflow-internal-backend-src-services-batch-allocation-service-ts-read-rollups','workflow-internal-backend-src-services-batch-allocation-service-ts-read-total','workflow-internal-backend-src-services-batch-allocation-service-ts-read-unassigned-ranges','workflow-internal-backend-src-services-print-reservation-service-ts-list-reservable-qr-code-summaries')))
  ON CONFLICT ("id") DO NOTHING;
  IF NOT EXISTS (SELECT 1 FROM public."AuditLog" a WHERE a."id"=lower(audit_id) AND a."userId"=app_rls.current_user_id()
    AND a."orgId" IS NOT DISTINCT FROM audit_organization_id AND a."licenseeId" IS NOT DISTINCT FROM app_rls.current_licensee_id()
    AND a."action"='BATCH_OPERATIONAL_READ' AND a."entityType"='BatchOperationalRead'
    AND a."entityId"=coalesce(focus_id,app_rls.current_licensee_id(),app_rls.current_user_id())
    AND a."details"->>'requestId'=app_rls.current_request_id() AND a."details"->>'purposeCode'='batch-operational-read'
    AND a."details"->>'route'=route_surface AND a."details"->>'focusBatchId' IS NOT DISTINCT FROM focus_id
    AND a."details"->>'scopeFingerprint'=fingerprint AND a."details"->>'outcome'='SUCCESS'
    AND a."details"->'workflowIds'=jsonb_build_array('workflow-internal-backend-src-services-batch-allocation-service-ts-build-count-maps','workflow-internal-backend-src-services-batch-allocation-service-ts-get-batch-allocation-map','workflow-internal-backend-src-services-batch-allocation-service-ts-read-batches','workflow-internal-backend-src-services-batch-allocation-service-ts-read-rollups','workflow-internal-backend-src-services-batch-allocation-service-ts-read-total','workflow-internal-backend-src-services-batch-allocation-service-ts-read-unassigned-ranges','workflow-internal-backend-src-services-print-reservation-service-ts-list-reservable-qr-code-summaries'))
  THEN RAISE EXCEPTION 'batch operational access denied'; END IF;
  RETURN fingerprint;
END
$function$;

CREATE FUNCTION app_rls.batch_operational_scope(audit_id text,requested_licensee_id text,route_surface text,focus_batch_id text)
RETURNS TABLE(scope_fingerprint text) LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,app_rls AS $function$
  SELECT app_rls.authorize_batch_operational_read(audit_id,requested_licensee_id,route_surface,focus_batch_id)
$function$;

CREATE FUNCTION app_rls.batch_operational_rows(audit_id text,requested_licensee_id text,route_surface text,focus_batch_id text,expected_scope_fingerprint text,page_limit integer,page_offset integer)
RETURNS TABLE(row_data jsonb) LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,app_rls AS $function$
DECLARE fingerprint text; focus_licensee_id text; source_batch_id text;
BEGIN
  fingerprint := app_rls.authorize_batch_operational_read(audit_id,requested_licensee_id,route_surface,focus_batch_id);
  IF expected_scope_fingerprint IS DISTINCT FROM fingerprint OR page_limit IS NULL OR page_offset IS NULL
     OR page_limit NOT BETWEEN 0 AND 500 OR page_offset<0
     OR (focus_batch_id IS NULL AND page_limit=0)
  THEN RAISE EXCEPTION 'batch operational access denied'; END IF;
  IF focus_batch_id IS NOT NULL THEN
    SELECT f."licenseeId",coalesce(f."rootBatchId",f."parentBatchId",f."id")
      INTO focus_licensee_id,source_batch_id
    FROM public."Batch" f WHERE f."id"=focus_batch_id;
    IF NOT FOUND THEN RAISE EXCEPTION 'batch operational access denied'; END IF;
  END IF;
  RETURN QUERY
  SELECT to_jsonb(b) || jsonb_build_object(
    'licensee',jsonb_build_object('id',l."id",'name',l."name",'prefix',l."prefix"),
    'manufacturer',CASE WHEN m."id" IS NULL THEN 'null'::jsonb ELSE jsonb_build_object('id',m."id",'name',m."name",'email',m."email") END,
    '_count',jsonb_build_object('qrCodes',(SELECT count(*) FROM public."QRCode" qcode WHERE qcode."batchId"=b."id"))
  ) || CASE WHEN focus_batch_id IS NULL THEN jsonb_build_object(
    'parentBatch',CASE WHEN parent_b."id" IS NULL THEN 'null'::jsonb ELSE jsonb_build_object('id',parent_b."id",'name',parent_b."name") END,
    'rootBatch',CASE WHEN root_b."id" IS NULL THEN 'null'::jsonb ELSE jsonb_build_object('id',root_b."id",'name',root_b."name") END
  ) ELSE '{}'::jsonb END
  FROM public."Batch" b
  JOIN public."Licensee" l ON l."id"=b."licenseeId"
  LEFT JOIN public."User" m ON m."id"=b."manufacturerId"
  LEFT JOIN public."Batch" parent_b ON parent_b."id"=b."parentBatchId"
  LEFT JOIN public."Batch" root_b ON root_b."id"=b."rootBatchId"
  WHERE (focus_batch_id IS NULL AND (((app_rls.current_role() IN ('LICENSEE_ADMIN','ORG_ADMIN') OR app_rls.current_role() IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')) AND b."licenseeId"=app_rls.current_licensee_id()) OR (app_rls.current_role() IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') AND b."manufacturerId"=app_rls.current_user_id() AND EXISTS (
  SELECT 1 FROM public."ManufacturerLicenseeLink" scope_ml
  JOIN public."Licensee" scope_l ON scope_l."id"=scope_ml."licenseeId"
  JOIN public."Organization" scope_o ON scope_o."id"=scope_l."orgId"
  WHERE scope_ml."manufacturerId"=app_rls.current_user_id()
    AND scope_ml."licenseeId"=b."licenseeId"
    AND scope_l."isActive"=TRUE AND scope_l."suspendedAt" IS NULL AND scope_o."isActive"=TRUE
    AND (app_rls.current_licensee_id() IS NULL OR scope_ml."licenseeId"=app_rls.current_licensee_id())
))))
     OR (focus_batch_id IS NOT NULL AND b."licenseeId"=focus_licensee_id
       AND (b."id"=source_batch_id OR b."parentBatchId"=source_batch_id OR b."rootBatchId"=source_batch_id))
  ORDER BY CASE WHEN focus_batch_id IS NULL THEN b."updatedAt" END DESC,
           CASE WHEN focus_batch_id IS NULL THEN b."createdAt" END DESC,
           CASE WHEN focus_batch_id IS NOT NULL THEN b."createdAt" END ASC,
           CASE WHEN focus_batch_id IS NOT NULL THEN b."id" END ASC
  LIMIT CASE WHEN focus_batch_id IS NULL THEN page_limit ELSE 2147483647 END
  OFFSET CASE WHEN focus_batch_id IS NULL THEN page_offset ELSE 0 END;
END
$function$;

CREATE FUNCTION app_rls.batch_operational_total(audit_id text,requested_licensee_id text,route_surface text,focus_batch_id text,expected_scope_fingerprint text)
RETURNS TABLE(total bigint) LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,app_rls AS $function$
DECLARE fingerprint text; focus_licensee_id text; source_batch_id text;
BEGIN
  fingerprint := app_rls.authorize_batch_operational_read(audit_id,requested_licensee_id,route_surface,focus_batch_id);
  IF expected_scope_fingerprint IS DISTINCT FROM fingerprint THEN RAISE EXCEPTION 'batch operational access denied'; END IF;
  IF focus_batch_id IS NOT NULL THEN
    SELECT f."licenseeId",coalesce(f."rootBatchId",f."parentBatchId",f."id")
      INTO focus_licensee_id,source_batch_id
    FROM public."Batch" f WHERE f."id"=focus_batch_id;
    IF NOT FOUND THEN RAISE EXCEPTION 'batch operational access denied'; END IF;
  END IF;
  RETURN QUERY SELECT count(*) FROM public."Batch" b
  WHERE (focus_batch_id IS NULL AND (((app_rls.current_role() IN ('LICENSEE_ADMIN','ORG_ADMIN') OR app_rls.current_role() IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')) AND b."licenseeId"=app_rls.current_licensee_id()) OR (app_rls.current_role() IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') AND b."manufacturerId"=app_rls.current_user_id() AND EXISTS (
  SELECT 1 FROM public."ManufacturerLicenseeLink" scope_ml
  JOIN public."Licensee" scope_l ON scope_l."id"=scope_ml."licenseeId"
  JOIN public."Organization" scope_o ON scope_o."id"=scope_l."orgId"
  WHERE scope_ml."manufacturerId"=app_rls.current_user_id()
    AND scope_ml."licenseeId"=b."licenseeId"
    AND scope_l."isActive"=TRUE AND scope_l."suspendedAt" IS NULL AND scope_o."isActive"=TRUE
    AND (app_rls.current_licensee_id() IS NULL OR scope_ml."licenseeId"=app_rls.current_licensee_id())
))))
     OR (focus_batch_id IS NOT NULL AND b."licenseeId"=focus_licensee_id
       AND (b."id"=source_batch_id OR b."parentBatchId"=source_batch_id OR b."rootBatchId"=source_batch_id));
END
$function$;

CREATE FUNCTION app_rls.batch_inventory_rollups(audit_id text,requested_licensee_id text,route_surface text,focus_batch_id text,expected_scope_fingerprint text,batch_ids text[])
RETURNS TABLE(batch_id text,dormant integer,active integer,activated integer,allocated integer,printed integer,redeemed integer,blocked integer,scanned integer)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,app_rls AS $function$
DECLARE fingerprint text;
BEGIN
  fingerprint := app_rls.authorize_batch_operational_read(audit_id,requested_licensee_id,route_surface,focus_batch_id);
  IF expected_scope_fingerprint IS DISTINCT FROM fingerprint OR batch_ids IS NULL OR cardinality(batch_ids) NOT BETWEEN 1 AND 500
     OR cardinality(batch_ids)<>(SELECT count(DISTINCT id) FROM unnest(batch_ids) id)
     OR EXISTS (SELECT 1 FROM unnest(batch_ids) id WHERE id IS NULL OR NOT app_rls.batch_operational_batch_allowed(id,focus_batch_id)) THEN RAISE EXCEPTION 'batch operational access denied'; END IF;
  RETURN QUERY SELECT r."batchId",r."dormant",r."active",r."activated",r."allocated",r."printed",r."redeemed",r."blocked",r."scanned"
  FROM public."InventoryStatusRollup" r WHERE r."batchId"=ANY(batch_ids);
END
$function$;

CREATE FUNCTION app_rls.batch_unassigned_ranges(audit_id text,requested_licensee_id text,route_surface text,focus_batch_id text,expected_scope_fingerprint text,batch_ids text[])
RETURNS TABLE(batch_id text,item_count bigint,start_code text,end_code text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,app_rls AS $function$
DECLARE fingerprint text;
BEGIN
  fingerprint := app_rls.authorize_batch_operational_read(audit_id,requested_licensee_id,route_surface,focus_batch_id);
  IF expected_scope_fingerprint IS DISTINCT FROM fingerprint OR batch_ids IS NULL OR cardinality(batch_ids) NOT BETWEEN 1 AND 500
     OR cardinality(batch_ids)<>(SELECT count(DISTINCT id) FROM unnest(batch_ids) id)
     OR EXISTS (SELECT 1 FROM unnest(batch_ids) id WHERE id IS NULL OR NOT app_rls.batch_operational_batch_allowed(id,focus_batch_id)) THEN RAISE EXCEPTION 'batch operational access denied'; END IF;
  RETURN QUERY SELECT qcode."batchId",count(*),coalesce(min(qcode."displayCode"),min(qcode."code")),coalesce(max(qcode."displayCode"),max(qcode."code"))
  FROM public."QRCode" qcode WHERE qcode."batchId"=ANY(batch_ids) AND qcode."status" IN ('DORMANT','ACTIVE')
  GROUP BY qcode."batchId";
END
$function$;

CREATE FUNCTION app_rls.batch_status_fallback(audit_id text,requested_licensee_id text,route_surface text,focus_batch_id text,expected_scope_fingerprint text,batch_ids text[])
RETURNS TABLE(batch_id text,status text,item_count bigint)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,app_rls AS $function$
DECLARE fingerprint text;
BEGIN
  fingerprint := app_rls.authorize_batch_operational_read(audit_id,requested_licensee_id,route_surface,focus_batch_id);
  IF expected_scope_fingerprint IS DISTINCT FROM fingerprint OR batch_ids IS NULL OR cardinality(batch_ids) NOT BETWEEN 1 AND 500
     OR cardinality(batch_ids)<>(SELECT count(DISTINCT id) FROM unnest(batch_ids) id)
     OR EXISTS (SELECT 1 FROM unnest(batch_ids) id WHERE id IS NULL OR NOT app_rls.batch_operational_batch_allowed(id,focus_batch_id)) THEN RAISE EXCEPTION 'batch operational access denied'; END IF;
  RETURN QUERY SELECT qcode."batchId",qcode."status"::text,count(*) FROM public."QRCode" qcode
  WHERE qcode."batchId"=ANY(batch_ids) GROUP BY qcode."batchId",qcode."status";
END
$function$;

CREATE FUNCTION app_rls.batch_reservable_qr_summaries(audit_id text,requested_licensee_id text,route_surface text,focus_batch_id text,expected_scope_fingerprint text,batch_ids text[])
RETURNS TABLE(batch_id text,item_count bigint,start_code text,end_code text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,app_rls AS $function$
DECLARE fingerprint text;
BEGIN
  fingerprint := app_rls.authorize_batch_operational_read(audit_id,requested_licensee_id,route_surface,focus_batch_id);
  IF expected_scope_fingerprint IS DISTINCT FROM fingerprint OR batch_ids IS NULL OR cardinality(batch_ids) NOT BETWEEN 1 AND 500
     OR cardinality(batch_ids)<>(SELECT count(DISTINCT id) FROM unnest(batch_ids) id)
     OR EXISTS (SELECT 1 FROM unnest(batch_ids) id WHERE id IS NULL OR NOT app_rls.batch_operational_batch_allowed(id,focus_batch_id)) THEN RAISE EXCEPTION 'batch operational access denied'; END IF;
  RETURN QUERY
  SELECT qcode."batchId",count(*),min(coalesce(qcode."displayCode",qcode."code")),max(coalesce(qcode."displayCode",qcode."code"))
  FROM public."QRCode" qcode
  LEFT JOIN public."PrintItem" pi ON pi."qrCodeId"=qcode."id"
  LEFT JOIN public."PrintSession" ps ON ps."id"=pi."printSessionId"
  LEFT JOIN public."PrintJob" pj ON pj."id"=ps."printJobId"
  WHERE qcode."batchId"=ANY(batch_ids) AND qcode."status"='ALLOCATED' AND qcode."printJobId" IS NULL
    AND (pi."id" IS NULL OR (pi."printConfirmedAt" IS NULL
      AND (pi."confirmationEvidence" IS NULL OR pi."confirmationEvidence"::text IN ('null','{}'))
      AND ((pi."state"::text IN ('FAILED','FROZEN') AND pi."agentAckedAt" IS NULL AND pi."dispatchedAt" IS NULL AND pi."deviceJobRef" IS NULL
        AND (pi."deadLetterReason" IN ('operator_abandoned_unconfirmed_run','pre_dispatch_failure','connector_payload_validation_failed_before_dispatch','printer_agent_payload_failed_before_dispatch')
          OR pi."failureReason" ILIKE '%operator closed unconfirmed failed print run%' OR pi."failureReason" ILIKE '%operator abandoned unconfirmed print run%'
          OR pi."failureReason" ILIKE '%before any printer acknowledgement%' OR pi."failureReason" ILIKE '%pre-dispatch%' OR pi."failureReason" ILIKE '%pre dispatch%')
        AND ps."status"::text IN ('CANCELLED','FAILED') AND pj."status"::text IN ('CANCELLED','FAILED'))
      OR (pi."state"::text='CANCELLED' AND ps."status"::text='STOPPED' AND pj."status"::text IN ('STOPPED','PARTIALLY_COMPLETED')))))
  GROUP BY qcode."batchId";
END
$function$;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA app_rls FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA app_rls FROM "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.setting(text) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.uuid_setting(text) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.current_user_id() TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.current_organization_id() TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.current_licensee_id() TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.current_manufacturer_id() TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.current_role() TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.current_assurance() TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.current_request_id() TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.current_purpose() TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.attributed_request() TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.manufacturer_scope_valid(text) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.actor_scope_valid() TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.dashboard_snapshot_scope(text,text,text) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.dashboard_snapshot_data(text,text,text,text) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.batch_operational_scope(text,text,text,text) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.batch_operational_rows(text,text,text,text,text,integer,integer) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.batch_operational_total(text,text,text,text,text) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.batch_inventory_rollups(text,text,text,text,text,text[]) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.batch_unassigned_ranges(text,text,text,text,text,text[]) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.batch_status_fallback(text,text,text,text,text,text[]) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.batch_reservable_qr_summaries(text,text,text,text,text,text[]) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.platform_audit_log_details(text[]) TO "mscqr_rls_cert_app";
RESET ROLE;
DO $$ BEGIN
  IF NOT pg_has_role(session_user,'mscqr_rls_cert_auth_owner','SET') THEN RAISE EXCEPTION 'administrative executor lacks SET authority for mscqr_rls_cert_auth_owner'; END IF;
END $$;
SET ROLE "mscqr_rls_cert_auth_owner";
-- Reviewed production B01 refresh boundary.  The caller only supplies bearer
-- hash candidates; every other scope is derived from the locked predecessor.
-- "mscqr_rls_cert_auth_owner" is substituted by the clean-room package generator.

CREATE OR REPLACE FUNCTION app_auth.b01_bind_bearer(p_hashes text[], p_request_id text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER VOLATILE SET search_path=pg_catalog,public AS $fn$
BEGIN
  IF coalesce(array_length(p_hashes, 1), 0) NOT BETWEEN 1 AND 3
     OR EXISTS (SELECT 1 FROM unnest(p_hashes) AS h WHERE h !~ '^([0-9a-f]{12}:)?[a-f0-9]{64}$')
     OR (SELECT count(DISTINCT h) FROM unnest(p_hashes) AS h) <> array_length(p_hashes, 1)
     OR p_request_id IS NULL OR length(p_request_id) NOT BETWEEN 1 AND 128 OR p_request_id !~ '^[!-~]+$' THEN
    RAISE EXCEPTION 'B01_REFRESH_INPUT_DENIED' USING ERRCODE='22023';
  END IF;
  -- Reset all derived values before the first protected read.  A pre-auth
  -- caller can set arbitrary custom GUCs, but cannot retain them across this
  -- reviewed function boundary.
  PERFORM set_config('app.b01_user_id','',true),
          set_config('app.b01_organization_id','',true),
          set_config('app.b01_predecessor_id','',true),
          set_config('app.b01_successor_id','',true),
          set_config('app.b01_operation','',true),
          set_config('app.b01_token_hashes', array_to_string(p_hashes, ','), true),
          set_config('app.b01_request_id', p_request_id, true);
END
$fn$;

CREATE OR REPLACE FUNCTION app_auth.b01_bind_predecessor(
  p_token_id text, p_user_id text, p_organization_id text, p_operation text
) RETURNS void LANGUAGE plpgsql SECURITY DEFINER VOLATILE SET search_path=pg_catalog,public AS $fn$
BEGIN
  IF p_token_id IS NULL THEN RAISE EXCEPTION 'B01_REFRESH_TOKEN_CONTEXT_DENIED' USING ERRCODE='42501'; END IF;
  IF p_user_id IS NULL THEN RAISE EXCEPTION 'B01_REFRESH_USER_CONTEXT_DENIED' USING ERRCODE='42501'; END IF;
  IF p_operation NOT IN ('claim','load-state','create-mfa','revoke-scope','complete-rotation','reuse-revoke','account-unavailable','stale-membership') THEN
    RAISE EXCEPTION 'B01_REFRESH_OPERATION_DENIED' USING ERRCODE='42501';
  END IF;
  PERFORM set_config('app.b01_predecessor_id',p_token_id,true),
          set_config('app.b01_user_id',p_user_id,true),
          set_config('app.b01_organization_id',coalesce(p_organization_id,''),true),
          set_config('app.b01_operation',p_operation,true);
END
$fn$;

CREATE OR REPLACE FUNCTION app_auth.b01_audit(p_action text, p_token_id text, p_at timestamp without time zone)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER VOLATILE SET search_path=pg_catalog,public AS $fn$
BEGIN
  INSERT INTO public."AuditLogOutbox" ("id",payload,"updatedAt") VALUES (
    gen_random_uuid()::text,
    jsonb_build_object('userId',current_setting('app.b01_user_id',true),'action',p_action,
      'entityType','RefreshToken','entityId',p_token_id,'details',jsonb_build_object(
        'requestId',current_setting('app.b01_request_id',true),'boundary','b01-refresh-rotation')),
    p_at
  );
END
$fn$;

CREATE OR REPLACE FUNCTION app_auth.claim_refresh_token_rotation(
  p_hashes text[], p_checked_at timestamp without time zone, p_request_id text
) RETURNS TABLE("disposition" text,"tokenId" text,"userId" text,"role" text,"organizationId" text,
  "licenseeId" text,"manufacturerId" text,"authAssurance" text,"expiresAt" timestamp without time zone,
  "authenticatedAt" timestamp without time zone,"mfaVerifiedAt" timestamp without time zone)
LANGUAGE plpgsql SECURITY DEFINER VOLATILE SET search_path=pg_catalog,public AS $fn$
DECLARE t public."RefreshToken"%ROWTYPE; u record; selected_licensee text; selected_manufacturer text; candidate_count integer;
BEGIN
  PERFORM app_auth.b01_bind_bearer(p_hashes,p_request_id);
  IF p_checked_at IS NULL OR abs(extract(epoch FROM p_checked_at-clock_timestamp())) > 300 THEN
    RAISE EXCEPTION 'B01_REFRESH_INPUT_DENIED' USING ERRCODE='22023';
  END IF;
  SELECT count(*) INTO candidate_count FROM public."RefreshToken" rt WHERE rt."tokenHash"=ANY(p_hashes);
  IF candidate_count=0 THEN RETURN; END IF;
  IF candidate_count<>1 THEN RAISE EXCEPTION 'B01_REFRESH_CLAIM_AMBIGUOUS' USING ERRCODE='42501'; END IF;
  SELECT rt.* INTO t FROM public."RefreshToken" rt WHERE rt."tokenHash"=ANY(p_hashes) FOR UPDATE;
  PERFORM app_auth.b01_bind_predecessor(t.id,t."userId",t."orgId",'claim');
  SELECT usr.id,usr.email,usr.name,usr.role,usr."orgId",usr."licenseeId",usr.status,usr."isActive",usr."disabledAt",usr."deletedAt",usr."emailVerifiedAt" INTO u FROM public."User" usr WHERE usr.id=t."userId";
  IF NOT FOUND OR NOT u."isActive" OR u."status"::text<>'ACTIVE' OR u."disabledAt" IS NOT NULL OR u."deletedAt" IS NOT NULL THEN
    PERFORM set_config('app.b01_operation','account-unavailable',true);
    UPDATE public."RefreshToken" rt SET "revokedAt"=p_checked_at,"revokedReason"='ACCOUNT_UNAVAILABLE',"lastUsedAt"=p_checked_at
      WHERE rt."userId"=t."userId" AND rt."revokedAt" IS NULL;
    PERFORM app_auth.b01_audit('AUTH_REFRESH_DISABLED_DENIED',t.id,p_checked_at);
    RETURN QUERY SELECT 'REVOKED',t.id,t."userId",NULL,NULL,NULL,NULL,NULL,t."expiresAt",t."authenticatedAt",t."mfaVerifiedAt"; RETURN;
  END IF;
  IF t."revokedAt" IS NOT NULL THEN
    IF t."replacedByTokenHash" IS NOT NULL THEN
      PERFORM set_config('app.b01_operation','reuse-revoke',true);
      UPDATE public."RefreshToken" rt SET "revokedAt"=p_checked_at,"revokedReason"='REUSE_DETECTED',"lastUsedAt"=p_checked_at
        WHERE rt."userId"=t."userId" AND rt."revokedAt" IS NULL;
      PERFORM app_auth.b01_audit('AUTH_REFRESH_REUSE_DETECTED',t.id,p_checked_at);
      RETURN QUERY SELECT 'REUSE_DETECTED',t.id,t."userId",NULL,NULL,NULL,NULL,NULL,t."expiresAt",t."authenticatedAt",t."mfaVerifiedAt";
    ELSE RETURN QUERY SELECT 'REVOKED',t.id,t."userId",NULL,NULL,NULL,NULL,NULL,t."expiresAt",t."authenticatedAt",t."mfaVerifiedAt"; END IF;
    RETURN;
  END IF;
  IF t."expiresAt"<=p_checked_at THEN
    UPDATE public."RefreshToken" rt SET "revokedAt"=p_checked_at,"revokedReason"='EXPIRED',"lastUsedAt"=p_checked_at WHERE rt.id=t.id;
    PERFORM app_auth.b01_audit('AUTH_REFRESH_EXPIRED',t.id,p_checked_at);
    RETURN QUERY SELECT 'EXPIRED',t.id,t."userId",NULL,NULL,NULL,NULL,NULL,t."expiresAt",t."authenticatedAt",t."mfaVerifiedAt"; RETURN;
  END IF;
  IF t."rotationRequestId" IS NOT NULL AND t."rotationRequestId" IS DISTINCT FROM p_request_id THEN
    RETURN QUERY SELECT 'REVOKED',t.id,t."userId",NULL,NULL,NULL,NULL,NULL,t."expiresAt",t."authenticatedAt",t."mfaVerifiedAt"; RETURN;
  END IF;
  IF u.role::text IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') THEN
    SELECT l.id INTO selected_licensee FROM public."ManufacturerLicenseeLink" ml JOIN public."Licensee" l ON l.id=ml."licenseeId" JOIN public."Organization" o ON o.id=l."orgId"
      WHERE ml."manufacturerId"=u.id AND l."isActive" AND l."suspendedAt" IS NULL AND o."isActive" ORDER BY ml."isPrimary" DESC,ml."createdAt",ml."licenseeId" LIMIT 1;
    IF selected_licensee IS NULL THEN
      PERFORM set_config('app.b01_operation','stale-membership',true);
      UPDATE public."RefreshToken" rt SET "revokedAt"=p_checked_at,"revokedReason"='STALE_MEMBERSHIP',"lastUsedAt"=p_checked_at WHERE rt."userId"=u.id AND rt."revokedAt" IS NULL;
      PERFORM app_auth.b01_audit('AUTH_REFRESH_STALE_MEMBERSHIP_DENIED',t.id,p_checked_at);
      RETURN QUERY SELECT 'REVOKED',t.id,t."userId",NULL,NULL,NULL,NULL,NULL,t."expiresAt",t."authenticatedAt",t."mfaVerifiedAt"; RETURN;
    END IF;
    selected_manufacturer:=u.id;
  ELSIF u.role::text IN ('LICENSEE_ADMIN','ORG_ADMIN') THEN
    SELECT l.id INTO selected_licensee FROM public."Licensee" l JOIN public."Organization" o ON o.id=l."orgId"
      WHERE l.id=u."licenseeId" AND l."orgId" IS NOT DISTINCT FROM t."orgId" AND l."isActive" AND l."suspendedAt" IS NULL AND o."isActive";
    IF selected_licensee IS NULL THEN RAISE EXCEPTION 'B01_REFRESH_BEARER_DENIED' USING ERRCODE='42501'; END IF;
  ELSIF u."orgId" IS DISTINCT FROM t."orgId" THEN RAISE EXCEPTION 'B01_REFRESH_BEARER_DENIED' USING ERRCODE='42501';
  ELSE selected_licensee:=u."licenseeId"; selected_manufacturer:=NULL; END IF;
  UPDATE public."RefreshToken" rt SET "rotationRequestId"=p_request_id,"rotationClaimedAt"=coalesce(rt."rotationClaimedAt",p_checked_at) WHERE rt.id=t.id;
  RETURN QUERY SELECT 'ACTIVE',t.id,u.id,u.role::text,t."orgId",selected_licensee,selected_manufacturer,
    CASE WHEN t."mfaVerifiedAt" IS NULL THEN 'password-verified' ELSE 'mfa-verified' END,t."expiresAt",t."authenticatedAt",t."mfaVerifiedAt";
END
$fn$;

CREATE OR REPLACE FUNCTION app_auth.load_refresh_session_state(
  p_token_id text,p_hashes text[],p_requested_licensee_id text,p_requested_scope_version text,p_checked_at timestamp without time zone,p_request_id text
) RETURNS TABLE("userId" text,"email" text,"name" text,"role" text,"legacyLicenseeId" text,"legacyOrganizationId" text,"emailVerifiedAt" timestamp without time zone,"sessionLicenseeId" text,"sessionOrganizationId" text,"scopeVersion" text,"selectedLicenseeId" text,"selectedLicenseeName" text,"selectedLicenseePrefix" text,"selectedLicenseeBrandName" text,"selectedLicenseeOrganizationId" text,"linkedLicensees" jsonb,"mfaRequired" boolean,"mfaEnabled" boolean,"mfaEnrolled" boolean,"mfaLastUsedAt" timestamp without time zone,"mfaMethods" text[],"mfaPreferredMethod" text)
LANGUAGE plpgsql SECURITY DEFINER VOLATILE SET search_path=pg_catalog,public AS $fn$
DECLARE t public."RefreshToken"%ROWTYPE; u record; selected record; links jsonb; mfa_enabled boolean; mfa_last timestamp without time zone; methods text[];
BEGIN
  PERFORM app_auth.b01_bind_bearer(p_hashes,p_request_id);
  SELECT rt.* INTO t FROM public."RefreshToken" rt WHERE rt.id=p_token_id AND rt."tokenHash"=ANY(p_hashes) FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'B01_REFRESH_BEARER_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM app_auth.b01_bind_predecessor(t.id,t."userId",t."orgId",'load-state');
  IF t."revokedAt" IS NOT NULL OR t."expiresAt"<=p_checked_at OR t."rotationRequestId" IS DISTINCT FROM p_request_id THEN RAISE EXCEPTION 'B01_REFRESH_BEARER_DENIED' USING ERRCODE='42501'; END IF;
  SELECT usr.id,usr.email,usr.name,usr.role,usr."orgId",usr."licenseeId",usr.status,usr."isActive",usr."disabledAt",usr."deletedAt",usr."emailVerifiedAt" INTO u FROM public."User" usr WHERE usr.id=t."userId" AND usr."isActive" AND usr."status"::text='ACTIVE' AND usr."disabledAt" IS NULL AND usr."deletedAt" IS NULL;
  IF NOT FOUND THEN RAISE EXCEPTION 'B01_REFRESH_BEARER_DENIED' USING ERRCODE='42501'; END IF;
  SELECT coalesce(bool_or(x.enabled),false),max(x."lastUsedAt"),coalesce(array_agg(DISTINCT x.method) FILTER (WHERE x.enabled),'{}'::text[]) INTO mfa_enabled,mfa_last,methods FROM (
    SELECT "isEnabled" AS enabled,"lastUsedAt",'TOTP'::text AS method FROM public."AdminMfaCredential" WHERE "userId"=u.id
    UNION ALL SELECT TRUE,"lastUsedAt",'WEBAUTHN' FROM public."AdminWebAuthnCredential" WHERE "userId"=u.id
    UNION ALL SELECT TRUE,"lastUsedAt",type FROM public."UserMfaFactor" WHERE "userId"=u.id AND "disabledAt" IS NULL AND type IN ('TOTP','WEBAUTHN')
  ) x;
  IF EXISTS (SELECT 1 FROM public."UserBackupCode" WHERE "userId"=u.id AND "usedAt" IS NULL) AND 'TOTP'=ANY(methods) THEN methods:=array_append(methods,'BACKUP_CODE'); END IF;
  IF u.role::text IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') THEN
    SELECT l.id,l.name,l.prefix,l."brandName",l."orgId",ml."isPrimary",ml."updatedAt" INTO selected FROM public."ManufacturerLicenseeLink" ml JOIN public."Licensee" l ON l.id=ml."licenseeId" JOIN public."Organization" o ON o.id=l."orgId"
      WHERE ml."manufacturerId"=u.id AND l."isActive" AND l."suspendedAt" IS NULL AND o."isActive" AND (p_requested_licensee_id IS NULL OR l.id=p_requested_licensee_id) ORDER BY ml."isPrimary" DESC,ml."createdAt",ml."licenseeId" LIMIT 1;
    IF NOT FOUND THEN RAISE EXCEPTION 'MANUFACTURER_SCOPE_DENIED' USING ERRCODE='42501'; END IF;
    IF p_requested_licensee_id IS NOT NULL AND (p_requested_scope_version IS NULL OR to_char(selected."updatedAt" AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')<>p_requested_scope_version) THEN RAISE EXCEPTION 'MANUFACTURER_SCOPE_STALE' USING ERRCODE='42501'; END IF;
    SELECT coalesce(jsonb_agg(jsonb_build_object('id',l.id,'name',l.name,'prefix',l.prefix,'brandName',l."brandName",'orgId',l."orgId",'isPrimary',ml."isPrimary",'scopeVersion',to_char(ml."updatedAt" AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')) ORDER BY ml."isPrimary" DESC,ml."createdAt",ml."licenseeId"),'[]'::jsonb) INTO links FROM public."ManufacturerLicenseeLink" ml JOIN public."Licensee" l ON l.id=ml."licenseeId" JOIN public."Organization" o ON o.id=l."orgId" WHERE ml."manufacturerId"=u.id AND l."isActive" AND l."suspendedAt" IS NULL AND o."isActive";
    IF p_requested_licensee_id IS NOT NULL THEN PERFORM app_auth.b01_audit('MANUFACTURER_SCOPE_SWITCH',t.id,p_checked_at); END IF;
    RETURN QUERY SELECT u.id,u.email,u.name,u.role::text,u."licenseeId",u."orgId",u."emailVerifiedAt",selected.id,selected."orgId",to_char(selected."updatedAt" AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),selected.id,selected.name,selected.prefix,selected."brandName",selected."orgId",links,TRUE,mfa_enabled,mfa_enabled,mfa_last,methods,CASE WHEN 'WEBAUTHN'=ANY(methods) THEN 'WEBAUTHN' WHEN 'TOTP'=ANY(methods) THEN 'TOTP' ELSE NULL END;
  ELSE
    IF p_requested_licensee_id IS NOT NULL OR p_requested_scope_version IS NOT NULL THEN RAISE EXCEPTION 'B01_SCOPE_SWITCH_ROLE_DENIED' USING ERRCODE='42501'; END IF;
    RETURN QUERY SELECT u.id,u.email,u.name,u.role::text,u."licenseeId",u."orgId",u."emailVerifiedAt",u."licenseeId",u."orgId",NULL,NULL,NULL,NULL,NULL,NULL,'[]'::jsonb,(u.role::text IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN','LICENSEE_ADMIN','ORG_ADMIN')),mfa_enabled,mfa_enabled,mfa_last,methods,CASE WHEN 'WEBAUTHN'=ANY(methods) THEN 'WEBAUTHN' WHEN 'TOTP'=ANY(methods) THEN 'TOTP' ELSE NULL END;
  END IF;
END
$fn$;

CREATE OR REPLACE FUNCTION app_auth.create_refresh_mfa_challenge(p_token_id text,p_hashes text[],p_user_id text,p_ticket_hash text,p_session_binding_hash text,p_risk_score integer,p_risk_level text,p_reasons text[],p_ip_hash text,p_user_agent_hash text,p_max_attempts integer,p_expires_at timestamp without time zone,p_created_at timestamp without time zone,p_request_id text)
RETURNS TABLE("challengeId" text,"created" boolean) LANGUAGE plpgsql SECURITY DEFINER VOLATILE SET search_path=pg_catalog,public AS $fn$
DECLARE t public."RefreshToken"%ROWTYPE; challenge_id text;
BEGIN
  PERFORM app_auth.b01_bind_bearer(p_hashes,p_request_id);
  SELECT rt.* INTO t FROM public."RefreshToken" rt WHERE rt.id=p_token_id AND rt."tokenHash"=ANY(p_hashes) FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'B01_REFRESH_MFA_CHALLENGE_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM app_auth.b01_bind_predecessor(t.id,t."userId",t."orgId",'create-mfa');
  IF t."userId" IS DISTINCT FROM p_user_id OR t."revokedAt" IS NOT NULL OR t."expiresAt"<=p_created_at OR t."rotationRequestId" IS DISTINCT FROM p_request_id OR p_max_attempts NOT BETWEEN 1 AND 10 OR p_risk_score NOT BETWEEN 0 AND 100 OR p_risk_level NOT IN ('LOW','MEDIUM','HIGH','CRITICAL') OR coalesce(array_length(p_reasons,1),0) NOT BETWEEN 1 AND 12 OR p_ticket_hash !~ '^([0-9a-f]{12}:)?[a-f0-9]{64}$' OR p_session_binding_hash !~ '^([0-9a-f]{12}:)?[a-f0-9]{64}$' OR p_expires_at<=p_created_at OR p_expires_at>p_created_at+interval '15 minutes' THEN RAISE EXCEPTION 'B01_REFRESH_MFA_CHALLENGE_DENIED' USING ERRCODE='42501'; END IF;
  challenge_id:=gen_random_uuid()::text;
  INSERT INTO public."AuthMfaChallenge" (id,"userId","ticketHash","sessionBindingHash",purpose,"riskScore","riskLevel",reasons,"createdIpHash","createdUserAgentHash","maxAttempts","createdAt","updatedAt","expiresAt") VALUES (challenge_id,t."userId",p_ticket_hash,p_session_binding_hash,'admin_login',p_risk_score,p_risk_level::public."AuthRiskLevel",p_reasons,p_ip_hash,p_user_agent_hash,p_max_attempts,p_created_at,p_created_at,p_expires_at);
  PERFORM app_auth.b01_audit('AUTH_REFRESH_MFA_CHALLENGE_REQUIRED',t.id,p_created_at);
  RETURN QUERY SELECT challenge_id,TRUE;
END
$fn$;

CREATE OR REPLACE FUNCTION app_auth.revoke_refresh_token_scope(p_token_id text,p_hashes text[],p_user_id text,p_scope text,p_reason text,p_revoked_at timestamp without time zone,p_request_id text)
RETURNS TABLE("revokedCount" integer) LANGUAGE plpgsql SECURITY DEFINER VOLATILE SET search_path=pg_catalog,public AS $fn$
DECLARE t public."RefreshToken"%ROWTYPE; changed integer;
BEGIN
  PERFORM app_auth.b01_bind_bearer(p_hashes,p_request_id);
  SELECT rt.* INTO t FROM public."RefreshToken" rt WHERE rt.id=p_token_id AND rt."tokenHash"=ANY(p_hashes) FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'B01_REFRESH_REVOCATION_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM app_auth.b01_bind_predecessor(t.id,t."userId",t."orgId",'revoke-scope');
  IF t."userId" IS DISTINCT FROM p_user_id OR t."revokedAt" IS NOT NULL OR t."rotationRequestId" IS DISTINCT FROM p_request_id OR t."rotationCompletedAt" IS NOT NULL OR p_scope NOT IN ('token','password-only','all') OR p_reason NOT IN ('ACCOUNT_UNAVAILABLE','MFA_STATE_CHANGED','MFA_REQUIRED_AFTER_POLICY_CHANGE') THEN RAISE EXCEPTION 'B01_REFRESH_REVOCATION_DENIED' USING ERRCODE='42501'; END IF;
  UPDATE public."RefreshToken" rt SET "revokedAt"=p_revoked_at,"revokedReason"=p_reason,"lastUsedAt"=p_revoked_at WHERE rt."userId"=t."userId" AND rt."revokedAt" IS NULL AND (p_scope<>'token' OR rt.id=p_token_id) AND (p_scope<>'password-only' OR rt."mfaVerifiedAt" IS NULL);
  GET DIAGNOSTICS changed=ROW_COUNT; PERFORM app_auth.b01_audit('AUTH_REFRESH_REVOKED',t.id,p_revoked_at); RETURN QUERY SELECT changed;
END
$fn$;

CREATE OR REPLACE FUNCTION app_auth.complete_refresh_token_rotation(p_token_id text,p_hashes text[],p_user_id text,p_organization_id text,p_token_hash text,p_expires_at timestamp without time zone,p_ip_hash text,p_user_agent text,p_authenticated_at timestamp without time zone,p_mfa_verified_at timestamp without time zone,p_rotated_at timestamp without time zone,p_request_id text)
RETURNS TABLE("id" text,"expiresAt" timestamp without time zone) LANGUAGE plpgsql SECURITY DEFINER VOLATILE SET search_path=pg_catalog,public AS $fn$
DECLARE t public."RefreshToken"%ROWTYPE; successor_id text; changed integer;
BEGIN
  PERFORM app_auth.b01_bind_bearer(p_hashes,p_request_id);
  SELECT rt.* INTO t FROM public."RefreshToken" rt WHERE rt.id=p_token_id AND rt."tokenHash"=ANY(p_hashes) FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'B01_REFRESH_ROTATION_CLAIM_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM app_auth.b01_bind_predecessor(t.id,t."userId",t."orgId",'complete-rotation');
  IF p_rotated_at IS NULL OR abs(extract(epoch FROM p_rotated_at-clock_timestamp())) > 300
     OR p_token_hash !~ '^([0-9a-f]{12}:)?[a-f0-9]{64}$' OR p_token_hash=ANY(p_hashes)
     OR p_expires_at<=p_rotated_at OR p_expires_at>p_rotated_at+interval '31 days'
     OR t."userId" IS DISTINCT FROM p_user_id OR t."revokedAt" IS NOT NULL OR t."expiresAt"<=p_rotated_at
     OR t."rotationRequestId" IS DISTINCT FROM p_request_id OR t."rotationCompletedAt" IS NOT NULL
     OR (t."authenticatedAt" IS NOT NULL AND p_authenticated_at IS DISTINCT FROM t."authenticatedAt")
     OR p_mfa_verified_at IS DISTINCT FROM t."mfaVerifiedAt" OR p_organization_id IS DISTINCT FROM t."orgId"
  THEN RAISE EXCEPTION 'B01_REFRESH_ROTATION_CONTEXT_DENIED' USING ERRCODE='42501'; END IF;
  successor_id:=gen_random_uuid()::text;
  PERFORM set_config('app.b01_successor_id',successor_id,true);
  INSERT INTO public."RefreshToken" (id,"orgId","userId","tokenHash","expiresAt","createdAt","createdIpHash","createdUserAgent","authenticatedAt","mfaVerifiedAt","lastUsedAt") VALUES (successor_id,t."orgId",t."userId",p_token_hash,p_expires_at,p_rotated_at,p_ip_hash,p_user_agent,coalesce(t."authenticatedAt",p_rotated_at),t."mfaVerifiedAt",p_rotated_at);
  -- The refresh predecessor and its database-verifiable authenticated session
  -- are one security lineage.  Revoking both here keeps rotation atomic and
  -- avoids a runtime-side capability mutation between predecessor and
  -- successor writes.
  UPDATE public."RefreshToken" rt SET "revokedAt"=p_rotated_at,"revokedReason"='ROTATED',"replacedByTokenHash"=p_token_hash,"rotationCompletedAt"=p_rotated_at,"lastUsedAt"=p_rotated_at,
    "sessionCapabilityRevokedAt"=CASE WHEN rt."sessionCapabilityHash" IS NULL THEN rt."sessionCapabilityRevokedAt" ELSE p_rotated_at END,
    "sessionCapabilityRevokedReason"=CASE WHEN rt."sessionCapabilityHash" IS NULL THEN rt."sessionCapabilityRevokedReason" ELSE 'REFRESH_ROTATED' END
    WHERE rt.id=t.id AND rt."revokedAt" IS NULL;
  GET DIAGNOSTICS changed=ROW_COUNT; IF changed<>1 THEN RAISE EXCEPTION 'REFRESH_TOKEN_ROTATION_LOST' USING ERRCODE='40001'; END IF;
  PERFORM app_auth.b01_audit('AUTH_REFRESH_ROTATED',t.id,p_rotated_at); RETURN QUERY SELECT successor_id,p_expires_at;
END
$fn$;

REVOKE ALL ON FUNCTION app_auth.b01_bind_bearer(text[],text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_auth.b01_bind_predecessor(text,text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_auth.b01_audit(text,text,timestamp without time zone) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_auth.claim_refresh_token_rotation(text[],timestamp without time zone,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_auth.load_refresh_session_state(text,text[],text,text,timestamp without time zone,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_auth.create_refresh_mfa_challenge(text,text[],text,text,text,integer,text,text[],text,text,integer,timestamp without time zone,timestamp without time zone,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_auth.revoke_refresh_token_scope(text,text[],text,text,text,timestamp without time zone,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_auth.complete_refresh_token_rotation(text,text[],text,text,text,timestamp without time zone,text,text,timestamp without time zone,timestamp without time zone,timestamp without time zone,text) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION app_auth.claim_refresh_token_rotation(text[],timestamp without time zone,text) TO "mscqr_rls_cert_preauth";
GRANT EXECUTE ON FUNCTION app_auth.complete_refresh_token_rotation(text,text[],text,text,text,timestamp without time zone,text,text,timestamp without time zone,timestamp without time zone,timestamp without time zone,text) TO "mscqr_rls_cert_preauth";
GRANT EXECUTE ON FUNCTION app_auth.create_refresh_mfa_challenge(text,text[],text,text,text,integer,text,text[],text,text,integer,timestamp without time zone,timestamp without time zone,text) TO "mscqr_rls_cert_preauth";
GRANT EXECUTE ON FUNCTION app_auth.load_refresh_session_state(text,text[],text,text,timestamp without time zone,text) TO "mscqr_rls_cert_preauth";
GRANT EXECUTE ON FUNCTION app_auth.revoke_refresh_token_scope(text,text[],text,text,text,timestamp without time zone,text) TO "mscqr_rls_cert_preauth";
RESET ROLE;
DO $$ BEGIN
  IF NOT pg_has_role(session_user,'mscqr_rls_cert_auth_owner','SET') THEN RAISE EXCEPTION 'administrative executor lacks SET authority for mscqr_rls_cert_auth_owner'; END IF;
END $$;
SET ROLE "mscqr_rls_cert_auth_owner";
-- Database-verifiable authenticated session capability. "mscqr_rls_cert_auth_owner" is
-- substituted only by the clean-room generator. Raw capabilities are accepted
-- only by the exact issue/verify/revocation boundaries and are never persisted
-- or returned by PostgreSQL.

CREATE OR REPLACE FUNCTION app_auth.auth_session_prepare(
  p_capability text,
  p_purpose text,
  p_request_id text
) RETURNS text
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE capability_hash text;
BEGIN
  IF p_capability !~ '^[A-Za-z0-9_-]{43}$'
     OR p_purpose IS NULL OR length(btrim(p_purpose)) NOT BETWEEN 1 AND 240
     OR p_request_id IS NULL OR length(btrim(p_request_id)) NOT BETWEEN 1 AND 128
  THEN RAISE EXCEPTION 'AUTH_SESSION_CAPABILITY_DENIED' USING ERRCODE='42501'; END IF;

  -- This deliberately overwrites all values that can influence an authenticated
  -- policy before the first protected read. Runtime callers may set app.* but
  -- cannot retain it through this reviewed function boundary.
  capability_hash := encode(sha256(convert_to(p_capability,'UTF8')),'hex');
  PERFORM set_config('app.auth_session_hash',capability_hash,true),
          set_config('app.auth_session_id','',true),
          set_config('app.user_id','',true), set_config('app.role','',true),
          set_config('app.organization_id','',true), set_config('app.licensee_id','',true),
          set_config('app.manufacturer_id','',true), set_config('app.auth_assurance','',true),
          set_config('app.request_id',p_request_id,true), set_config('app.purpose',p_purpose,true),
          set_config('app.auth_session_verified','',true), set_config('app.auth_session_operation','verify',true),
          set_config('app.auth_session_target_id','',true);
  RETURN capability_hash;
END
$fn$;

CREATE OR REPLACE FUNCTION app_auth.issue_authenticated_session_capability(
  p_refresh_token_id text,
  p_refresh_token_hash text,
  p_capability text,
  p_assurance text,
  p_expires_at timestamp without time zone
) RETURNS TABLE("id" text,"expiresAt" timestamp without time zone)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE session_row public."RefreshToken"%ROWTYPE; capability_hash text;
BEGIN
  IF p_refresh_token_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
     OR p_refresh_token_hash !~ '^([0-9a-f]{12}:)?[a-f0-9]{64}$'
     OR p_capability !~ '^[A-Za-z0-9_-]{43}$' OR p_assurance NOT IN ('PASSWORD','ADMIN_MFA')
     OR p_expires_at IS NULL THEN RAISE EXCEPTION 'AUTH_SESSION_CAPABILITY_DENIED' USING ERRCODE='42501'; END IF;
  -- Reuse the reviewed B01 bearer binder before the first protected read.
  -- The identifier stays a selector; the existing refresh bearer hash is the
  -- only pre-auth proof that can make that selector visible.
  PERFORM app_auth.b01_bind_bearer(ARRAY[p_refresh_token_hash], 'auth-session-issue');
  capability_hash := encode(sha256(convert_to(p_capability,'UTF8')),'hex');
  PERFORM set_config('app.auth_session_hash',capability_hash,true), set_config('app.auth_session_id',p_refresh_token_id,true),
          set_config('app.auth_session_refresh_hash',p_refresh_token_hash,true), set_config('app.b01_token_hashes',p_refresh_token_hash,true),
          set_config('app.auth_session_operation','issue',true), set_config('app.auth_session_verified','',true);
  -- Lock the bearer-bound refresh row using an innocuous, reviewed lifecycle
  -- update.  The lock lives for this transaction; validation failures roll it
  -- back.  This avoids a second, user-scoped lookup and serializes competing
  -- issuers for the same refresh credential.
  UPDATE public."RefreshToken" rt
     SET "sessionCapabilityLastUsedAt"=clock_timestamp()
   WHERE rt.id=p_refresh_token_id
     AND rt."tokenHash"=p_refresh_token_hash
     AND rt."revokedAt" IS NULL
     AND rt."expiresAt">clock_timestamp()
  RETURNING rt.* INTO session_row;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'AUTH_SESSION_CAPABILITY_DENIED_SESSION' USING ERRCODE='42501';
  END IF;
  IF session_row."sessionCapabilityHash" IS NOT NULL
     OR p_expires_at<=clock_timestamp() OR p_expires_at>session_row."expiresAt"
     OR (p_assurance='ADMIN_MFA') IS DISTINCT FROM (session_row."mfaVerifiedAt" IS NOT NULL) THEN
    RAISE EXCEPTION 'AUTH_SESSION_CAPABILITY_DENIED_LIFECYCLE' USING ERRCODE='42501';
  END IF;
  UPDATE public."RefreshToken" rt SET "sessionCapabilityHash"=capability_hash,
    "sessionCapabilityHashVersion"='sha256-v1',"sessionCapabilityAssurance"=p_assurance,
    "sessionCapabilityExpiresAt"=p_expires_at,"sessionCapabilityLastUsedAt"=clock_timestamp(),
    "sessionCapabilityRevokedAt"=NULL,"sessionCapabilityRevokedReason"=NULL
    WHERE rt.id=session_row.id AND rt."sessionCapabilityHash" IS NULL;
  IF NOT FOUND THEN RAISE EXCEPTION 'AUTH_SESSION_CAPABILITY_DENIED_SESSION' USING ERRCODE='42501'; END IF;
  RETURN QUERY SELECT session_row.id::text,session_row."expiresAt";
END
$fn$;

CREATE OR REPLACE FUNCTION app_auth.require_authenticated_session(
  p_capability text,
  p_purpose text,
  p_request_id text
) RETURNS TABLE("sessionId" text,"userId" text,"role" text,"organizationId" text,"licenseeId" text,"assurance" text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE session_row record; actor_row record; capability_hash text;
BEGIN
  -- auth_session_prepare performs input validation.  Its SET LOCAL values are
  -- intentionally not relied on across a nested SECURITY DEFINER boundary;
  -- install every security-relevant setting again in this outer boundary so
  -- the protected query below is bound to this exact invocation.
  capability_hash := app_auth.auth_session_prepare(p_capability,p_purpose,p_request_id);
  PERFORM set_config('app.auth_session_hash',capability_hash,true),
          set_config('app.auth_session_id','',true),
          set_config('app.user_id','',true), set_config('app.role','',true),
          set_config('app.organization_id','',true), set_config('app.licensee_id','',true),
          set_config('app.manufacturer_id','',true), set_config('app.auth_assurance','',true),
          set_config('app.request_id',p_request_id,true), set_config('app.purpose',p_purpose,true),
          set_config('app.auth_session_verified','',true), set_config('app.auth_session_operation','verify',true),
          set_config('app.auth_session_target_id','',true);
  SELECT s.id,s."userId",s."sessionCapabilityAssurance" AS assurance
    INTO session_row
    FROM public."RefreshToken" s
   WHERE s."sessionCapabilityHash"=current_setting('app.auth_session_hash',true)
     AND s."sessionCapabilityHashVersion"='sha256-v1'
     AND s."sessionCapabilityRevokedAt" IS NULL AND s."sessionCapabilityExpiresAt">clock_timestamp()
     AND s."revokedAt" IS NULL AND s."expiresAt">clock_timestamp()
   FOR UPDATE OF s;
  IF NOT FOUND THEN RAISE EXCEPTION 'AUTH_SESSION_CAPABILITY_DENIED' USING ERRCODE='42501'; END IF;

  -- The user selector is derived from the locked, capability-bound refresh
  -- row.  It is never a caller-provided authority value.
  PERFORM set_config('app.user_id',session_row."userId",true);
  SELECT u.id,u.role::text AS role,u."orgId",u."licenseeId"
    INTO actor_row
    FROM public."User" u
   WHERE u.id=session_row."userId" AND u."isActive"
     AND u.status='ACTIVE'::public."UserStatus"
     AND u."disabledAt" IS NULL AND u."deletedAt" IS NULL;
  IF NOT FOUND THEN RAISE EXCEPTION 'AUTH_SESSION_CAPABILITY_DENIED' USING ERRCODE='42501'; END IF;

  UPDATE public."RefreshToken" SET "sessionCapabilityLastUsedAt"=clock_timestamp() WHERE id=session_row.id;
  PERFORM set_config('app.auth_session_id',session_row.id,true),
          set_config('app.user_id',actor_row.id,true), set_config('app.role',actor_row.role,true),
          set_config('app.organization_id',coalesce(actor_row."orgId",''),true),
          set_config('app.licensee_id',coalesce(actor_row."licenseeId",''),true),
          set_config('app.auth_assurance',CASE session_row.assurance WHEN 'ADMIN_MFA' THEN 'mfa-verified' WHEN 'PASSWORD' THEN 'password-verified' ELSE '' END,true),
          set_config('app.auth_session_verified','1',true);
  IF current_setting('app.auth_assurance',true)='' THEN RAISE EXCEPTION 'AUTH_SESSION_CAPABILITY_DENIED' USING ERRCODE='42501'; END IF;
  RETURN QUERY SELECT session_row.id::text,actor_row.id::text,actor_row.role::text,
    actor_row."orgId"::text,actor_row."licenseeId"::text,session_row.assurance::text;
END
$fn$;

CREATE OR REPLACE FUNCTION app_auth.revoke_authenticated_session_capability(
  p_capability text,
  p_target_refresh_token_id text,
  p_reason text,
  p_request_id text
) RETURNS TABLE("revoked" boolean)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor_row record; changed integer;
BEGIN
  IF p_target_refresh_token_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
     OR p_reason !~ '^[A-Z0-9_:-]{1,128}$' THEN
    RAISE EXCEPTION 'AUTH_SESSION_CAPABILITY_DENIED' USING ERRCODE='42501';
  END IF;
  SELECT * INTO actor_row FROM app_auth.require_authenticated_session(p_capability,'auth-session-revoke',p_request_id);
  IF NOT FOUND THEN RAISE EXCEPTION 'AUTH_SESSION_CAPABILITY_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM set_config('app.auth_session_operation','revoke-one',true), set_config('app.auth_session_target_id',p_target_refresh_token_id,true);
  UPDATE public."RefreshToken" rt
     SET "sessionCapabilityRevokedAt"=clock_timestamp(),"sessionCapabilityRevokedReason"=p_reason
   WHERE rt.id=p_target_refresh_token_id AND rt."userId"=actor_row."userId"
     AND rt."sessionCapabilityHash" IS NOT NULL AND rt."sessionCapabilityRevokedAt" IS NULL;
  GET DIAGNOSTICS changed=ROW_COUNT;
  RETURN QUERY SELECT changed=1;
END
$fn$;

CREATE OR REPLACE FUNCTION app_auth.revoke_all_authenticated_session_capabilities(
  p_capability text,
  p_reason text,
  p_request_id text
) RETURNS TABLE("revokedCount" integer)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor_row record; changed integer;
BEGIN
  IF p_reason !~ '^[A-Z0-9_:-]{1,128}$' THEN
    RAISE EXCEPTION 'AUTH_SESSION_CAPABILITY_DENIED' USING ERRCODE='42501';
  END IF;
  SELECT * INTO actor_row FROM app_auth.require_authenticated_session(p_capability,'auth-session-revoke-all',p_request_id);
  IF NOT FOUND THEN RAISE EXCEPTION 'AUTH_SESSION_CAPABILITY_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM set_config('app.auth_session_operation','revoke-user',true);
  UPDATE public."RefreshToken" rt
     SET "sessionCapabilityRevokedAt"=clock_timestamp(),"sessionCapabilityRevokedReason"=p_reason
   WHERE rt."userId"=actor_row."userId" AND rt."sessionCapabilityHash" IS NOT NULL
     AND rt."sessionCapabilityRevokedAt" IS NULL;
  GET DIAGNOSTICS changed=ROW_COUNT;
  RETURN QUERY SELECT changed;
END
$fn$;

REVOKE ALL ON FUNCTION app_auth.auth_session_prepare(text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_auth.issue_authenticated_session_capability(text,text,text,text,timestamp without time zone) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_auth.require_authenticated_session(text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_auth.revoke_authenticated_session_capability(text,text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_auth.revoke_all_authenticated_session_capabilities(text,text,text) FROM PUBLIC;

GRANT USAGE ON SCHEMA app_auth TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_auth.issue_authenticated_session_capability(text,text,text,text,timestamp without time zone) TO "mscqr_rls_cert_preauth";
GRANT EXECUTE ON FUNCTION app_auth.require_authenticated_session(text,text,text) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_auth.revoke_all_authenticated_session_capabilities(text,text,text) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_auth.revoke_authenticated_session_capability(text,text,text,text) TO "mscqr_rls_cert_app";
RESET ROLE;
DO $$ BEGIN
  IF NOT pg_has_role(session_user,'mscqr_rls_cert_owner','SET') THEN RAISE EXCEPTION 'administrative executor lacks SET authority for mscqr_rls_cert_owner'; END IF;
END $$;
SET ROLE "mscqr_rls_cert_owner";
GRANT USAGE,CREATE ON SCHEMA app_rls TO "mscqr_rls_cert_auth_owner";
RESET ROLE;
DO $$ BEGIN
  IF NOT pg_has_role(session_user,'mscqr_rls_cert_auth_owner','SET') THEN RAISE EXCEPTION 'administrative executor lacks SET authority for mscqr_rls_cert_auth_owner'; END IF;
END $$;
SET ROLE "mscqr_rls_cert_auth_owner";
-- Capability-verified C03 compliance and incident-evidence boundaries.
-- "mscqr_rls_cert_auth_owner" is replaced by the reviewed clean-room generator. Runtime
-- callers receive EXECUTE only on the seven public signatures at the end.

CREATE OR REPLACE FUNCTION app_rls.c03_require_authenticated_actor(
  p_capability text,
  p_purpose text,
  p_request_id text
) RETURNS TABLE(
  session_id text,
  user_id text,
  role text,
  organization_id text,
  licensee_id text,
  assurance text
)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record;
BEGIN
  SELECT * INTO actor
    FROM app_auth.require_authenticated_session(p_capability,p_purpose,p_request_id);
  IF NOT FOUND THEN RAISE EXCEPTION 'C03_AUTHENTICATED_SESSION_DENIED' USING ERRCODE='42501'; END IF;

  PERFORM set_config('app.c03_session_id',actor."sessionId",true),
          set_config('app.c03_user_id',actor."userId",true),
          set_config('app.c03_role',actor.role,true),
          set_config('app.c03_actor_organization_id',coalesce(actor."organizationId",''),true),
          set_config('app.c03_actor_licensee_id',coalesce(actor."licenseeId",''),true),
          set_config('app.c03_assurance',actor.assurance,true),
          set_config('app.c03_operation','',true),
          set_config('app.c03_licensee_id','',true),
          set_config('app.c03_job_id','',true),
          set_config('app.c03_incident_id','',true),
          set_config('app.c03_storage_key','',true);
  RETURN QUERY SELECT actor."sessionId"::text,actor."userId"::text,actor.role::text,
    actor."organizationId"::text,actor."licenseeId"::text,actor.assurance::text;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.c03_assert_live_licensee_scope(
  p_selector text,
  p_actor_role text,
  p_actor_organization_id text,
  p_actor_licensee_id text
) RETURNS TABLE(licensee_id text,organization_id text)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
BEGIN
  IF p_selector !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
     OR p_actor_role NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN','LICENSEE_ADMIN','ORG_ADMIN','MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER')
     OR (p_actor_role NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') AND p_selector IS DISTINCT FROM p_actor_licensee_id)
  THEN RAISE EXCEPTION 'C03_SCOPE_DENIED' USING ERRCODE='42501'; END IF;

  RETURN QUERY
  SELECT l.id::text,l."orgId"::text
    FROM public."Licensee" l
    JOIN public."Organization" o ON o.id=l."orgId"
   WHERE l.id=p_selector AND l."isActive" AND l."suspendedAt" IS NULL AND o."isActive"
     AND (p_actor_role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')
          OR (l."orgId"=p_actor_organization_id AND l.id=p_actor_licensee_id));
  IF NOT FOUND THEN RAISE EXCEPTION 'C03_SCOPE_DENIED' USING ERRCODE='42501'; END IF;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.c03_bind_operation(
  p_operation text,
  p_licensee_id text,
  p_job_id text DEFAULT '',
  p_incident_id text DEFAULT '',
  p_storage_key text DEFAULT ''
) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
BEGIN
  IF p_operation !~ '^[a-z0-9-]{1,80}$' THEN RAISE EXCEPTION 'C03_OPERATION_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM set_config('app.c03_operation',p_operation,true),
          set_config('app.c03_licensee_id',coalesce(p_licensee_id,''),true),
          set_config('app.c03_job_id',coalesce(p_job_id,''),true),
          set_config('app.c03_incident_id',coalesce(p_incident_id,''),true),
          set_config('app.c03_storage_key',coalesce(p_storage_key,''),true);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.c03_compliance_job_projection(p_job_id text)
RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
  SELECT jsonb_build_object(
    'id',j.id,'licenseeId',j."licenseeId",'status',j.status::text,
    'triggerType',j."triggerType",'periodFrom',j."periodFrom",'periodTo',j."periodTo",
    'fileName',j."fileName",'storageKey',j."storageKey",'integrityHash',j."integrityHash",
    'signatureAlgorithm',j."signatureAlgorithm",'summary',j.summary,'errorMessage',j."errorMessage",
    'startedByUserId',j."startedByUserId",'startedAt',j."startedAt",'finishedAt',j."finishedAt",
    'createdAt',j."createdAt",'updatedAt',j."updatedAt")
  FROM public."CompliancePackJob" j WHERE j.id=p_job_id
$fn$;

CREATE OR REPLACE FUNCTION app_rls.c03_validate_compliance_result(p_result jsonb)
RETURNS void
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $fn$
BEGIN
  IF jsonb_typeof(p_result)<>'object'
     OR EXISTS (SELECT 1 FROM jsonb_object_keys(p_result) k
                WHERE k NOT IN ('fileName','storageKey','integrityHash','signatureAlgorithm','controls','generatedAt','storageMode'))
     OR length(p_result->>'fileName') NOT BETWEEN 1 AND 240 OR p_result->>'fileName' LIKE '%/%'
     OR length(p_result->>'storageKey') NOT BETWEEN 1 AND 1000 OR p_result->>'storageKey' LIKE '%..%'
     OR p_result->>'integrityHash' !~ '^[0-9a-f]{64}$'
     OR p_result->>'signatureAlgorithm' NOT IN ('ed25519','hmac-sha256')
     OR p_result->>'storageMode' NOT IN ('object-storage','local-disk')
     OR (p_result ? 'controls' AND jsonb_typeof(p_result->'controls')<>'number')
  THEN RAISE EXCEPTION 'C03_COMPLIANCE_RESULT_INVALID' USING ERRCODE='22023'; END IF;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.c03_queue_audit(
  p_action text,
  p_entity_type text,
  p_entity_id text,
  p_details jsonb
) RETURNS void
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
  INSERT INTO public."AuditLogOutbox" (id,payload,"updatedAt")
  VALUES (gen_random_uuid()::text,jsonb_build_object(
    'userId',current_setting('app.c03_user_id',true),
    'orgId',NULLIF(current_setting('app.c03_actor_organization_id',true),''),
    'licenseeId',NULLIF(current_setting('app.c03_licensee_id',true),''),
    'action',p_action,'entityType',p_entity_type,'entityId',p_entity_id,
    'details',coalesce(p_details,'{}'::jsonb) || jsonb_build_object(
      'requestId',current_setting('app.request_id',true),
      'purpose',current_setting('app.purpose',true),
      'authenticatedSessionId',current_setting('app.c03_session_id',true))),transaction_timestamp())
$fn$;

CREATE OR REPLACE FUNCTION app_rls.c03_build_compliance_report(
  p_licensee_id text,
  p_from timestamptz,
  p_to timestamptz
) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE total_incidents integer; resolved_incidents integer; breached_incidents integer;
DECLARE audit_events integer; failed_logins integer; retention_days integer; handoff jsonb;
BEGIN
  IF (p_from IS NOT NULL AND p_to IS NOT NULL AND p_from>p_to)
     OR (p_from IS NOT NULL AND p_to IS NOT NULL AND p_to-p_from>interval '366 days')
  THEN RAISE EXCEPTION 'C03_COMPLIANCE_RANGE_INVALID' USING ERRCODE='22023'; END IF;
  SELECT count(*),count(*) FILTER (WHERE status::text IN ('RESOLVED','CLOSED')),
         count(*) FILTER (WHERE "slaDueAt"<transaction_timestamp() AND status::text NOT IN ('RESOLVED','CLOSED'))
    INTO total_incidents,resolved_incidents,breached_incidents
    FROM public."Incident" WHERE "licenseeId"=p_licensee_id
      AND (p_from IS NULL OR "createdAt">=p_from) AND (p_to IS NULL OR "createdAt"<=p_to);
  SELECT count(*),count(*) FILTER (WHERE action LIKE '%LOGIN_FAILED%') INTO audit_events,failed_logins
    FROM public."AuditLog" WHERE "licenseeId"=p_licensee_id
      AND (p_from IS NULL OR "createdAt">=p_from) AND (p_to IS NULL OR "createdAt"<=p_to);
  SELECT coalesce("retentionDays",180) INTO retention_days
    FROM public."EvidenceRetentionPolicy" WHERE "licenseeId"=p_licensee_id;
  retention_days:=coalesce(retention_days,180);
  SELECT coalesce(jsonb_object_agg(stage,row_count),'{}'::jsonb) INTO handoff FROM (
    SELECT h."currentStage"::text stage,count(*) row_count FROM public."IncidentHandoff" h
    JOIN public."Incident" i ON i.id=h."incidentId" WHERE i."licenseeId"=p_licensee_id GROUP BY h."currentStage"
  ) grouped;
  RETURN jsonb_build_object(
    'generatedAt',transaction_timestamp(),'appName','MSCQR',
    'scope',jsonb_build_object('licenseeId',p_licensee_id,'from',p_from,'to',p_to),
    'compliance',jsonb_build_object('auditRetentionDays',retention_days),
    'metrics',jsonb_build_object('incidents',jsonb_build_object('total',total_incidents,'resolved',resolved_incidents,'slaBreachedOpen',breached_incidents,'handoff',handoff),'auditEvents',audit_events,'failedLogins',failed_logins),
    'controls',jsonb_build_array(
      jsonb_build_object('controlId','SOC2-CC7.2','framework','SOC2','status',CASE WHEN breached_incidents>5 THEN 'ATTENTION' ELSE 'EFFECTIVE' END,'evidenceRefs',jsonb_build_array('metrics.incidents.slaBreachedOpen')),
      jsonb_build_object('controlId','SOC2-CC6.1','framework','SOC2','status',CASE WHEN failed_logins>=20 THEN 'ATTENTION' WHEN failed_logins>=5 THEN 'MONITOR' ELSE 'EFFECTIVE' END,'evidenceRefs',jsonb_build_array('metrics.failedLogins')),
      jsonb_build_object('controlId','ISO27001-A.5.23','framework','ISO27001','status',CASE WHEN audit_events>0 THEN 'EFFECTIVE' ELSE 'ATTENTION' END,'evidenceRefs',jsonb_build_array('metrics.auditEvents')),
      jsonb_build_object('controlId','ISO27001-A.8.10','framework','ISO27001','status',CASE WHEN retention_days>=180 THEN 'EFFECTIVE' ELSE 'MONITOR' END,'evidenceRefs',jsonb_build_array('compliance.auditRetentionDays'))));
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.c03_revalidate_compliance_pack_job_actor_scope(
  p_capability text,p_purpose text,p_request_id text,p_job_id text
) RETURNS TABLE(user_id text,role text,organization_id text,licensee_id text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; job public."CompliancePackJob"%ROWTYPE; scope record;
BEGIN
  IF p_job_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  THEN RAISE EXCEPTION 'C03_COMPLIANCE_JOB_DENIED' USING ERRCODE='42501'; END IF;
  SELECT * INTO actor FROM app_rls.c03_require_authenticated_actor(p_capability,p_purpose,p_request_id);
  IF actor.assurance<>'ADMIN_MFA' THEN RAISE EXCEPTION 'C03_COMPLIANCE_MFA_REQUIRED' USING ERRCODE='42501'; END IF;
  PERFORM app_rls.c03_bind_operation('compliance-pack-revalidate','',p_job_id);
  SELECT * INTO job FROM public."CompliancePackJob" WHERE id=p_job_id;
  IF NOT FOUND OR job."licenseeId" IS NULL THEN RAISE EXCEPTION 'C03_COMPLIANCE_JOB_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM app_rls.c03_bind_operation('compliance-pack-revalidate',job."licenseeId",p_job_id);
  SELECT * INTO scope FROM app_rls.c03_assert_live_licensee_scope(job."licenseeId",actor.role,actor.organization_id,actor.licensee_id);
  PERFORM app_rls.c03_bind_operation('compliance-pack-revalidate',scope.licensee_id,p_job_id);
  RETURN QUERY SELECT actor.user_id::text,actor.role::text,scope.organization_id::text,scope.licensee_id::text;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.c03_start_compliance_pack_job(
  p_capability text,p_purpose text,p_request_id text,p_licensee_id text,
  p_trigger_type text,p_from timestamptz,p_to timestamptz
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; scope record; job public."CompliancePackJob"%ROWTYPE; report jsonb;
DECLARE replay_key text; request_hash text; prior public."ActionIdempotencyKey"%ROWTYPE;
BEGIN
  IF p_purpose<>'compliance-pack-start' OR p_trigger_type<>'MANUAL'
  THEN RAISE EXCEPTION 'C03_COMPLIANCE_START_DENIED' USING ERRCODE='42501'; END IF;
  SELECT * INTO actor FROM app_rls.c03_require_authenticated_actor(p_capability,p_purpose,p_request_id);
  IF actor.assurance<>'ADMIN_MFA' THEN RAISE EXCEPTION 'C03_COMPLIANCE_MFA_REQUIRED' USING ERRCODE='42501'; END IF;
  PERFORM app_rls.c03_bind_operation('compliance-pack-start',p_licensee_id);
  SELECT * INTO scope FROM app_rls.c03_assert_live_licensee_scope(p_licensee_id,actor.role,actor.organization_id,actor.licensee_id);
  PERFORM app_rls.c03_bind_operation('compliance-pack-start',scope.licensee_id);
  replay_key:=encode(sha256(convert_to('c03-compliance-start|'||actor.session_id||'|'||p_request_id,'UTF8')),'hex');
  request_hash:=encode(sha256(convert_to(jsonb_build_object('licenseeId',scope.licensee_id,'triggerType',p_trigger_type,'from',p_from,'to',p_to)::text,'UTF8')),'hex');
  INSERT INTO public."ActionIdempotencyKey" (id,"keyHash",action,scope,"requestHash","expiresAt")
  VALUES (gen_random_uuid()::text,replay_key,'c03-compliance-start',scope.licensee_id,request_hash,transaction_timestamp()+interval '24 hours')
  ON CONFLICT ("keyHash") DO NOTHING;
  IF NOT FOUND THEN
    SELECT * INTO prior FROM public."ActionIdempotencyKey" WHERE "keyHash"=replay_key FOR UPDATE;
    IF prior."requestHash" IS DISTINCT FROM request_hash OR prior."completedAt" IS NULL OR prior."responsePayload" IS NULL
    THEN RAISE EXCEPTION 'C03_COMPLIANCE_REPLAY_CONFLICT' USING ERRCODE='40001'; END IF;
    RETURN prior."responsePayload";
  END IF;
  job.id:=gen_random_uuid()::text;
  PERFORM app_rls.c03_bind_operation('compliance-pack-start',scope.licensee_id,job.id);
  INSERT INTO public."CompliancePackJob" (id,"licenseeId",status,"triggerType","periodFrom","periodTo","startedByUserId","startedAt","updatedAt")
  VALUES (job.id,scope.licensee_id,'RUNNING',p_trigger_type,p_from,p_to,actor.user_id,transaction_timestamp(),transaction_timestamp())
  RETURNING * INTO job;
  report:=app_rls.c03_build_compliance_report(scope.licensee_id,p_from,p_to);
  PERFORM app_rls.c03_queue_audit('COMPLIANCE_PACK_STARTED','CompliancePackJob',job.id,jsonb_build_object('triggerType',p_trigger_type,'periodFrom',p_from,'periodTo',p_to));
  UPDATE public."ActionIdempotencyKey" SET "statusCode"=200,"responsePayload"=jsonb_build_object('job',to_jsonb(job),'report',report),"completedAt"=transaction_timestamp()
   WHERE "keyHash"=replay_key;
  RETURN jsonb_build_object('job',to_jsonb(job),'report',report);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.c03_complete_compliance_pack_job(
  p_capability text,p_purpose text,p_request_id text,p_job_id text,p_result jsonb
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; job public."CompliancePackJob"%ROWTYPE; scope record; projected jsonb;
BEGIN
  IF p_purpose<>'compliance-pack-complete' THEN RAISE EXCEPTION 'C03_COMPLIANCE_COMPLETE_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM app_rls.c03_validate_compliance_result(p_result);
  SELECT * INTO actor FROM app_rls.c03_require_authenticated_actor(p_capability,p_purpose,p_request_id);
  IF actor.assurance<>'ADMIN_MFA' THEN RAISE EXCEPTION 'C03_COMPLIANCE_MFA_REQUIRED' USING ERRCODE='42501'; END IF;
  PERFORM app_rls.c03_bind_operation('compliance-pack-complete','',p_job_id);
  SELECT * INTO job FROM public."CompliancePackJob" WHERE id=p_job_id;
  IF NOT FOUND OR job."licenseeId" IS NULL THEN RAISE EXCEPTION 'C03_COMPLIANCE_JOB_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM app_rls.c03_bind_operation('compliance-pack-complete',job."licenseeId",p_job_id);
  SELECT * INTO scope FROM app_rls.c03_assert_live_licensee_scope(job."licenseeId",actor.role,actor.organization_id,actor.licensee_id);
  PERFORM app_rls.c03_bind_operation('compliance-pack-complete',scope.licensee_id,p_job_id);
  SELECT * INTO job FROM public."CompliancePackJob" WHERE id=p_job_id AND "licenseeId"=scope.licensee_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'C03_COMPLIANCE_JOB_DENIED' USING ERRCODE='42501'; END IF;
  IF job.status='COMPLETED' AND job."storageKey"=p_result->>'storageKey' AND job."integrityHash"=p_result->>'integrityHash' THEN RETURN app_rls.c03_compliance_job_projection(p_job_id); END IF;
  IF job.status<>'RUNNING' THEN RAISE EXCEPTION 'C03_COMPLIANCE_TRANSITION_DENIED' USING ERRCODE='40001'; END IF;
  UPDATE public."CompliancePackJob" SET status='COMPLETED',"fileName"=p_result->>'fileName',"storageKey"=p_result->>'storageKey',
    "integrityHash"=p_result->>'integrityHash',"signatureAlgorithm"=p_result->>'signatureAlgorithm',summary=p_result,
    "errorMessage"=NULL,"finishedAt"=transaction_timestamp(),"updatedAt"=transaction_timestamp() WHERE id=p_job_id;
  projected:=app_rls.c03_compliance_job_projection(p_job_id);
  PERFORM app_rls.c03_queue_audit('COMPLIANCE_PACK_COMPLETED','CompliancePackJob',p_job_id,jsonb_build_object('storageKey',p_result->>'storageKey','integrityHash',p_result->>'integrityHash'));
  RETURN projected;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.c03_fail_compliance_pack_job(
  p_capability text,p_purpose text,p_request_id text,p_job_id text,p_error_code text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; job public."CompliancePackJob"%ROWTYPE; scope record; projected jsonb;
BEGIN
  IF p_purpose<>'compliance-pack-fail' OR p_error_code !~ '^[A-Z0-9_:-]{1,160}$'
  THEN RAISE EXCEPTION 'C03_COMPLIANCE_FAIL_DENIED' USING ERRCODE='42501'; END IF;
  SELECT * INTO actor FROM app_rls.c03_require_authenticated_actor(p_capability,p_purpose,p_request_id);
  IF actor.assurance<>'ADMIN_MFA' THEN RAISE EXCEPTION 'C03_COMPLIANCE_MFA_REQUIRED' USING ERRCODE='42501'; END IF;
  PERFORM app_rls.c03_bind_operation('compliance-pack-fail','',p_job_id);
  SELECT * INTO job FROM public."CompliancePackJob" WHERE id=p_job_id;
  IF NOT FOUND OR job."licenseeId" IS NULL THEN RAISE EXCEPTION 'C03_COMPLIANCE_JOB_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM app_rls.c03_bind_operation('compliance-pack-fail',job."licenseeId",p_job_id);
  SELECT * INTO scope FROM app_rls.c03_assert_live_licensee_scope(job."licenseeId",actor.role,actor.organization_id,actor.licensee_id);
  PERFORM app_rls.c03_bind_operation('compliance-pack-fail',scope.licensee_id,p_job_id);
  SELECT * INTO job FROM public."CompliancePackJob" WHERE id=p_job_id AND "licenseeId"=scope.licensee_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'C03_COMPLIANCE_JOB_DENIED' USING ERRCODE='42501'; END IF;
  IF job.status='FAILED' AND job."errorMessage"=p_error_code THEN RETURN app_rls.c03_compliance_job_projection(p_job_id); END IF;
  IF job.status<>'RUNNING' THEN RAISE EXCEPTION 'C03_COMPLIANCE_TRANSITION_DENIED' USING ERRCODE='40001'; END IF;
  UPDATE public."CompliancePackJob" SET status='FAILED',"errorMessage"=p_error_code,"finishedAt"=transaction_timestamp(),"updatedAt"=transaction_timestamp() WHERE id=p_job_id;
  projected:=app_rls.c03_compliance_job_projection(p_job_id);
  PERFORM app_rls.c03_queue_audit('COMPLIANCE_PACK_FAILED','CompliancePackJob',p_job_id,jsonb_build_object('errorCode',p_error_code));
  RETURN projected;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.c03_get_compliance_pack_job(
  p_capability text,p_purpose text,p_request_id text,p_job_id text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; job public."CompliancePackJob"%ROWTYPE; scope record; report jsonb;
BEGIN
  IF p_purpose NOT IN ('compliance-pack-download','compliance-pack-rebuild-read')
  THEN RAISE EXCEPTION 'C03_COMPLIANCE_READ_DENIED' USING ERRCODE='42501'; END IF;
  SELECT * INTO actor FROM app_rls.c03_require_authenticated_actor(p_capability,p_purpose,p_request_id);
  IF actor.assurance<>'ADMIN_MFA' THEN RAISE EXCEPTION 'C03_COMPLIANCE_MFA_REQUIRED' USING ERRCODE='42501'; END IF;
  PERFORM app_rls.c03_bind_operation('compliance-pack-get','',p_job_id);
  SELECT * INTO job FROM public."CompliancePackJob" WHERE id=p_job_id;
  IF NOT FOUND OR job."licenseeId" IS NULL THEN RAISE EXCEPTION 'C03_COMPLIANCE_JOB_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM app_rls.c03_bind_operation('compliance-pack-get',job."licenseeId",p_job_id);
  SELECT * INTO scope FROM app_rls.c03_assert_live_licensee_scope(job."licenseeId",actor.role,actor.organization_id,actor.licensee_id);
  PERFORM app_rls.c03_bind_operation('compliance-pack-get',scope.licensee_id,p_job_id);
  report:=app_rls.c03_build_compliance_report(scope.licensee_id,job."periodFrom",job."periodTo");
  RETURN jsonb_build_object('job',app_rls.c03_compliance_job_projection(p_job_id),'report',report);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.c03_complete_compliance_pack_rebuild(
  p_capability text,p_purpose text,p_request_id text,p_job_id text,p_result jsonb
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; job public."CompliancePackJob"%ROWTYPE; scope record; projected jsonb;
BEGIN
  IF p_purpose<>'compliance-pack-rebuild-complete' THEN RAISE EXCEPTION 'C03_COMPLIANCE_REBUILD_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM app_rls.c03_validate_compliance_result(p_result);
  SELECT * INTO actor FROM app_rls.c03_require_authenticated_actor(p_capability,p_purpose,p_request_id);
  IF actor.assurance<>'ADMIN_MFA' THEN RAISE EXCEPTION 'C03_COMPLIANCE_MFA_REQUIRED' USING ERRCODE='42501'; END IF;
  PERFORM app_rls.c03_bind_operation('compliance-pack-rebuild','',p_job_id);
  SELECT * INTO job FROM public."CompliancePackJob" WHERE id=p_job_id;
  IF NOT FOUND OR job."licenseeId" IS NULL THEN RAISE EXCEPTION 'C03_COMPLIANCE_JOB_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM app_rls.c03_bind_operation('compliance-pack-rebuild',job."licenseeId",p_job_id);
  SELECT * INTO scope FROM app_rls.c03_assert_live_licensee_scope(job."licenseeId",actor.role,actor.organization_id,actor.licensee_id);
  PERFORM app_rls.c03_bind_operation('compliance-pack-rebuild',scope.licensee_id,p_job_id);
  SELECT * INTO job FROM public."CompliancePackJob" WHERE id=p_job_id AND "licenseeId"=scope.licensee_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'C03_COMPLIANCE_JOB_DENIED' USING ERRCODE='42501'; END IF;
  IF job.status<>'COMPLETED' THEN RAISE EXCEPTION 'C03_COMPLIANCE_TRANSITION_DENIED' USING ERRCODE='40001'; END IF;
  IF job."storageKey"=p_result->>'storageKey' AND job."integrityHash"=p_result->>'integrityHash' THEN RETURN app_rls.c03_compliance_job_projection(p_job_id); END IF;
  UPDATE public."CompliancePackJob" SET "fileName"=p_result->>'fileName',"storageKey"=p_result->>'storageKey',
    "integrityHash"=p_result->>'integrityHash',"signatureAlgorithm"=p_result->>'signatureAlgorithm',summary=p_result,
    "updatedAt"=transaction_timestamp() WHERE id=p_job_id;
  projected:=app_rls.c03_compliance_job_projection(p_job_id);
  PERFORM app_rls.c03_queue_audit('COMPLIANCE_PACK_REBUILT','CompliancePackJob',p_job_id,jsonb_build_object('storageKey',p_result->>'storageKey','integrityHash',p_result->>'integrityHash'));
  RETURN projected;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.c03_get_incident_evidence_file_by_storage_key(
  p_capability text,p_purpose text,p_request_id text,p_storage_key text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; evidence record; scope record; candidate_count integer;
DECLARE evidence_id text; incident_id text; incident_licensee_id text;
BEGIN
  IF p_purpose<>'incident-evidence-file-read' OR p_storage_key IS NULL OR length(p_storage_key) NOT BETWEEN 1 AND 1000 OR p_storage_key ~ '[[:cntrl:]]'
  THEN RAISE EXCEPTION 'C03_INCIDENT_EVIDENCE_DENIED' USING ERRCODE='42501'; END IF;
  SELECT * INTO actor FROM app_rls.c03_require_authenticated_actor(p_capability,p_purpose,p_request_id);
  IF actor.role NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN','LICENSEE_ADMIN','ORG_ADMIN') OR actor.assurance<>'ADMIN_MFA'
  THEN RAISE EXCEPTION 'C03_INCIDENT_EVIDENCE_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM app_rls.c03_bind_operation('incident-evidence-read','','','',p_storage_key);
  SELECT count(*),min(e.id),min(e."incidentId") INTO candidate_count,evidence_id,incident_id
    FROM public."IncidentEvidence" e WHERE e."storageKey"=p_storage_key;
  IF candidate_count<>1 THEN RAISE EXCEPTION 'C03_INCIDENT_EVIDENCE_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM app_rls.c03_bind_operation('incident-evidence-read','','',incident_id,p_storage_key);
  SELECT i."licenseeId" INTO incident_licensee_id FROM public."Incident" i WHERE i.id=incident_id;
  IF NOT FOUND OR incident_licensee_id IS NULL THEN RAISE EXCEPTION 'C03_INCIDENT_EVIDENCE_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM app_rls.c03_bind_operation('incident-evidence-read',incident_licensee_id,'',incident_id,p_storage_key);
  SELECT * INTO scope FROM app_rls.c03_assert_live_licensee_scope(incident_licensee_id,actor.role,actor.organization_id,actor.licensee_id);
  PERFORM app_rls.c03_bind_operation('incident-evidence-read',scope.licensee_id,'',incident_id,p_storage_key);
  SELECT e.id,e."incidentId",e."fileUrl",e."storageKey",e."fileType",e."uploadedByUserId",e."uploadedBy"::text,e."createdAt"
    INTO evidence FROM public."IncidentEvidence" e WHERE e.id=evidence_id AND e."storageKey"=p_storage_key;
  IF NOT FOUND THEN RAISE EXCEPTION 'C03_INCIDENT_EVIDENCE_DENIED' USING ERRCODE='42501'; END IF;
  RETURN jsonb_build_object('id',evidence.id,'incidentId',evidence."incidentId",'fileUrl',evidence."fileUrl",
    'storageKey',evidence."storageKey",'fileType',evidence."fileType",'uploadedByUserId',evidence."uploadedByUserId",
    'uploadedBy',evidence."uploadedBy",'createdAt',evidence."createdAt");
END
$fn$;

REVOKE ALL ON FUNCTION app_rls.c03_require_authenticated_actor(text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_assert_live_licensee_scope(text,text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_bind_operation(text,text,text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_compliance_job_projection(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_validate_compliance_result(jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_queue_audit(text,text,text,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_build_compliance_report(text,timestamp with time zone,timestamp with time zone) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_revalidate_compliance_pack_job_actor_scope(text,text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_start_compliance_pack_job(text,text,text,text,text,timestamp with time zone,timestamp with time zone) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_complete_compliance_pack_job(text,text,text,text,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_fail_compliance_pack_job(text,text,text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_get_compliance_pack_job(text,text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_complete_compliance_pack_rebuild(text,text,text,text,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_get_incident_evidence_file_by_storage_key(text,text,text,text) FROM PUBLIC;

ALTER FUNCTION app_rls.c03_require_authenticated_actor(text,text,text) OWNER TO "mscqr_rls_cert_auth_owner";
ALTER FUNCTION app_rls.c03_assert_live_licensee_scope(text,text,text,text) OWNER TO "mscqr_rls_cert_auth_owner";
ALTER FUNCTION app_rls.c03_bind_operation(text,text,text,text,text) OWNER TO "mscqr_rls_cert_auth_owner";
ALTER FUNCTION app_rls.c03_compliance_job_projection(text) OWNER TO "mscqr_rls_cert_auth_owner";
ALTER FUNCTION app_rls.c03_validate_compliance_result(jsonb) OWNER TO "mscqr_rls_cert_auth_owner";
ALTER FUNCTION app_rls.c03_queue_audit(text,text,text,jsonb) OWNER TO "mscqr_rls_cert_auth_owner";
ALTER FUNCTION app_rls.c03_build_compliance_report(text,timestamp with time zone,timestamp with time zone) OWNER TO "mscqr_rls_cert_auth_owner";
ALTER FUNCTION app_rls.c03_revalidate_compliance_pack_job_actor_scope(text,text,text,text) OWNER TO "mscqr_rls_cert_auth_owner";
ALTER FUNCTION app_rls.c03_start_compliance_pack_job(text,text,text,text,text,timestamp with time zone,timestamp with time zone) OWNER TO "mscqr_rls_cert_auth_owner";
ALTER FUNCTION app_rls.c03_complete_compliance_pack_job(text,text,text,text,jsonb) OWNER TO "mscqr_rls_cert_auth_owner";
ALTER FUNCTION app_rls.c03_fail_compliance_pack_job(text,text,text,text,text) OWNER TO "mscqr_rls_cert_auth_owner";
ALTER FUNCTION app_rls.c03_get_compliance_pack_job(text,text,text,text) OWNER TO "mscqr_rls_cert_auth_owner";
ALTER FUNCTION app_rls.c03_complete_compliance_pack_rebuild(text,text,text,text,jsonb) OWNER TO "mscqr_rls_cert_auth_owner";
ALTER FUNCTION app_rls.c03_get_incident_evidence_file_by_storage_key(text,text,text,text) OWNER TO "mscqr_rls_cert_auth_owner";

GRANT EXECUTE ON FUNCTION app_rls.c03_complete_compliance_pack_job(text,text,text,text,jsonb) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.c03_complete_compliance_pack_rebuild(text,text,text,text,jsonb) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.c03_fail_compliance_pack_job(text,text,text,text,text) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.c03_get_compliance_pack_job(text,text,text,text) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.c03_get_incident_evidence_file_by_storage_key(text,text,text,text) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.c03_revalidate_compliance_pack_job_actor_scope(text,text,text,text) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.c03_start_compliance_pack_job(text,text,text,text,text,timestamp with time zone,timestamp with time zone) TO "mscqr_rls_cert_app";
RESET ROLE;
DO $$ BEGIN
  IF NOT pg_has_role(session_user,'mscqr_rls_cert_owner','SET') THEN RAISE EXCEPTION 'administrative executor lacks SET authority for mscqr_rls_cert_owner'; END IF;
END $$;
SET ROLE "mscqr_rls_cert_owner";
REVOKE CREATE ON SCHEMA app_rls FROM "mscqr_rls_cert_auth_owner";
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
