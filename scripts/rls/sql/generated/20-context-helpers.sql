\set ON_ERROR_STOP on
BEGIN;
DO $$ BEGIN

  IF current_user<>'certification-administrator' THEN RAISE EXCEPTION 'context helpers requires the reviewed brokered administrator'; END IF;
  IF current_database() !~ '^mscqr_full_rls_cert_[a-z0-9_]+$' THEN RAISE EXCEPTION 'context helpers is bound to the reviewed green database'; END IF;
  IF NOT EXISTS (SELECT 1 FROM mscqr_rls_install.state WHERE singleton
    AND target_environment='certification'
    AND deployment_id='cert'
    AND green_database=current_database()
    AND source_contract_sha256='40c6c8cee5cba8ae7f912ee3eae289420d40219366e44c921ae8d4e0601d86cd'
    AND package_role_marker='mscqr-full-rls-clean-room:certification:40c6c8cee5cba8ae7f912ee3eae289420d40219366e44c921ae8d4e0601d86cd'
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
    ('mscqr_rls_cert_migration', true)) spec(role_name,expected_login) ON spec.role_name=r.rolname WHERE r.rolcanlogin IS DISTINCT FROM spec.expected_login OR r.rolinherit OR r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls OR obj_description(r.oid,'pg_authid')<>'mscqr-full-rls-clean-room:certification:40c6c8cee5cba8ae7f912ee3eae289420d40219366e44c921ae8d4e0601d86cd')
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
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA app_rls FROM PUBLIC;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA app_rls TO "mscqr_rls_cert_app";
REVOKE EXECUTE ON FUNCTION app_rls.dashboard_scope_fingerprint(text) FROM "mscqr_rls_cert_app";
REVOKE EXECUTE ON FUNCTION app_rls.authorize_dashboard_snapshot(text,text,text) FROM "mscqr_rls_cert_app";
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
