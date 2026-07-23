\set ON_ERROR_STOP on
BEGIN;
DO $$ BEGIN

  IF current_user<>'certification-administrator' THEN RAISE EXCEPTION 'context helpers requires the reviewed brokered administrator'; END IF;
  IF current_database() !~ '^mscqr_full_rls_cert_[a-z0-9_]+$' THEN RAISE EXCEPTION 'context helpers is bound to the reviewed green database'; END IF;
  IF NOT EXISTS (SELECT 1 FROM mscqr_rls_install.state WHERE singleton
    AND target_environment='certification'
    AND deployment_id='cert'
    AND green_database=current_database()
    AND source_contract_sha256='aa29cb02f424c6fe58d9acad32dd3dfc7b218f5953c1f90134f342b886726168'
    AND package_role_marker='mscqr-full-rls-clean-room:certification:aa29cb02f424c6fe58d9acad32dd3dfc7b218f5953c1f90134f342b886726168'
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
    ('mscqr_rls_cert_migration', true)) spec(role_name,expected_login) ON spec.role_name=r.rolname WHERE r.rolcanlogin IS DISTINCT FROM spec.expected_login OR r.rolinherit OR r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls OR obj_description(r.oid,'pg_authid')<>'mscqr-full-rls-clean-room:certification:aa29cb02f424c6fe58d9acad32dd3dfc7b218f5953c1f90134f342b886726168')
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
LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog,app_rls AS $function$
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
  THEN RAISE EXCEPTION 'dashboard access denied: missing verified request context'; END IF;
  IF selector IS NOT NULL AND selector !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  THEN RAISE EXCEPTION 'dashboard access denied: invalid licensee selector'; END IF;
  IF ((app_rls.current_role() IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') OR app_rls.current_role() IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER')) AND app_rls.current_assurance() NOT IN ('mfa-verified','step-up-verified','dual-approved-break-glass'))
     OR (app_rls.current_role() IN ('LICENSEE_ADMIN','ORG_ADMIN') AND app_rls.current_assurance() NOT IN ('password-verified','mfa-verified','step-up-verified','dual-approved-break-glass'))
     OR NOT (app_rls.current_role() IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') OR app_rls.current_role() IN ('LICENSEE_ADMIN','ORG_ADMIN') OR app_rls.current_role() IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER'))
  THEN RAISE EXCEPTION 'dashboard access denied: actor role or assurance'; END IF;

  SELECT u."licenseeId",u."orgId" INTO actor_licensee_id,actor_organization_id
  FROM public."User" u
  WHERE u."id"=app_rls.current_user_id()
    AND u."role"::text=app_rls.current_role()
    AND u."isActive"=TRUE AND u."status"='ACTIVE'
    AND u."deletedAt" IS NULL AND u."disabledAt" IS NULL;
  IF NOT FOUND THEN RAISE EXCEPTION 'dashboard access denied: actor row'; END IF;

  IF app_rls.current_role() IN ('LICENSEE_ADMIN','ORG_ADMIN') THEN
    IF app_rls.current_licensee_id() IS NULL OR app_rls.current_organization_id() IS NULL
       OR app_rls.current_manufacturer_id() IS NOT NULL
    THEN RAISE EXCEPTION 'dashboard access denied: tenant derived context'; END IF;
    IF actor_licensee_id IS DISTINCT FROM app_rls.current_licensee_id()
       OR actor_organization_id IS DISTINCT FROM app_rls.current_organization_id()
    THEN RAISE EXCEPTION 'dashboard access denied: tenant actor relationship'; END IF;
    IF selector IS NOT NULL AND selector IS DISTINCT FROM app_rls.current_licensee_id()
    THEN RAISE EXCEPTION 'dashboard access denied: tenant selector'; END IF;
    IF NOT EXISTS (
         SELECT 1 FROM public."Licensee" l
         WHERE l."id"=app_rls.current_licensee_id() AND l."orgId"=app_rls.current_organization_id()
           AND l."isActive"=TRUE AND l."suspendedAt" IS NULL
       )
    THEN RAISE EXCEPTION 'dashboard access denied: tenant live licensee'; END IF;
    IF NOT EXISTS (
         SELECT 1 FROM public."Organization" o
         WHERE o."id"=app_rls.current_organization_id() AND o."isActive"=TRUE
       )
    THEN RAISE EXCEPTION 'dashboard access denied: tenant live organization'; END IF;
    RETURN md5(concat_ws('|','tenant',app_rls.current_user_id(),app_rls.current_role(),app_rls.current_licensee_id(),app_rls.current_organization_id()));
  END IF;

  IF app_rls.current_role() IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') THEN
    IF app_rls.current_manufacturer_id() IS DISTINCT FROM app_rls.current_user_id()
       OR app_rls.current_organization_id() IS NOT NULL
       OR app_rls.current_licensee_id() IS DISTINCT FROM selector
    THEN RAISE EXCEPTION 'dashboard access denied: manufacturer scope'; END IF;
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
  THEN RAISE EXCEPTION 'dashboard access denied: platform scope'; END IF;
  RETURN md5(concat_ws('|','platform',app_rls.current_user_id(),app_rls.current_role(),coalesce(selector,'global')));
END
$function$;

CREATE FUNCTION app_rls.authorize_dashboard_snapshot(audit_id text,requested_licensee_id text,route_surface text) RETURNS text
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,app_rls AS $function$
DECLARE
  fingerprint text;
  audit_organization_id text := app_rls.current_organization_id();
BEGIN
  IF audit_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
     OR route_surface NOT IN ('GET /api/dashboard/stats','GET /api/events/dashboard')
  THEN RAISE EXCEPTION 'dashboard access denied: request attribution'; END IF;
  fingerprint := app_rls.dashboard_scope_fingerprint(requested_licensee_id);
  IF app_rls.current_licensee_id() IS NOT NULL AND audit_organization_id IS NULL THEN
    SELECT l."orgId" INTO audit_organization_id
    FROM public."Licensee" l JOIN public."Organization" o ON o."id"=l."orgId"
    WHERE l."id"=app_rls.current_licensee_id()
      AND l."isActive"=TRUE AND l."suspendedAt" IS NULL AND o."isActive"=TRUE;
    IF NOT FOUND THEN RAISE EXCEPTION 'dashboard access denied: audit organization'; END IF;
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
  ) THEN RAISE EXCEPTION 'dashboard access denied: audit persistence'; END IF;
  RETURN fingerprint;
END
$function$;

CREATE FUNCTION app_rls.dashboard_snapshot_scope(audit_id text,requested_licensee_id text,route_surface text)
RETURNS TABLE(scope_fingerprint text) LANGUAGE sql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,app_rls AS $function$
  SELECT app_rls.authorize_dashboard_snapshot(audit_id,requested_licensee_id,route_surface)
$function$;

CREATE FUNCTION app_rls.dashboard_snapshot_data(audit_id text,requested_licensee_id text,route_surface text,expected_scope_fingerprint text)
RETURNS TABLE(
  total_qr_codes bigint,active_licensees bigint,manufacturers bigint,total_batches bigint,
  dormant bigint,active bigint,activated bigint,allocated bigint,printed bigint,redeemed bigint,blocked bigint,scanned bigint,
  rollup_authoritative boolean
) LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,app_rls AS $function$
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
  IF expected_scope_fingerprint IS DISTINCT FROM fingerprint THEN RAISE EXCEPTION 'dashboard access denied: scope fingerprint'; END IF;

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
LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog,app_rls AS $function$
DECLARE
  selector text := NULLIF(btrim(requested_licensee_id),'');
  focus_id text := NULLIF(btrim(focus_batch_id),'');
  actor_licensee_id text;
  actor_organization_id text;
  membership_count bigint;
  primary_count bigint;
  membership_fingerprint text;
BEGIN
  IF NOT ((current_user='mscqr_rls_cert_auth_owner' AND current_setting('app.auth_session_verified',true)='1' AND EXISTS (SELECT 1 FROM public."RefreshToken" operational_session WHERE operational_session."id"=current_setting('app.auth_session_id',true) AND operational_session."userId"=app_rls.current_user_id() AND operational_session."sessionCapabilityHash"=current_setting('app.auth_session_hash',true) AND operational_session."sessionCapabilityHashVersion"='sha256-v1' AND operational_session."sessionCapabilityRevokedAt" IS NULL AND operational_session."sessionCapabilityExpiresAt">clock_timestamp() AND operational_session."revokedAt" IS NULL AND operational_session."expiresAt">clock_timestamp())) AND app_rls.attributed_request() AND app_rls.current_purpose()='batch-operational-read' AND app_rls.current_request_id() ~ '^[A-Za-z0-9._:-]{1,128}$' AND ((app_rls.current_role() IN ('LICENSEE_ADMIN','ORG_ADMIN') AND app_rls.current_assurance() IN ('password-verified','mfa-verified','step-up-verified','dual-approved-break-glass')) OR ((app_rls.current_role() IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') OR app_rls.current_role() IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')) AND app_rls.current_assurance() IN ('mfa-verified','step-up-verified','dual-approved-break-glass'))))
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
LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog,app_rls AS $function$
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
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,app_rls AS $function$
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
RETURNS TABLE(scope_fingerprint text) LANGUAGE sql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,app_rls AS $function$
  SELECT app_rls.authorize_batch_operational_read(audit_id,requested_licensee_id,route_surface,focus_batch_id)
$function$;

CREATE FUNCTION app_rls.batch_operational_rows(audit_id text,requested_licensee_id text,route_surface text,focus_batch_id text,expected_scope_fingerprint text,page_limit integer,page_offset integer)
RETURNS TABLE(row_data jsonb) LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,app_rls AS $function$
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
RETURNS TABLE(total bigint) LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,app_rls AS $function$
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
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,app_rls AS $function$
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
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,app_rls AS $function$
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
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,app_rls AS $function$
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
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,app_rls AS $function$
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
GRANT EXECUTE ON FUNCTION app_rls.platform_audit_log_details(text[]) TO "mscqr_rls_cert_app";
GRANT USAGE,CREATE ON SCHEMA app_rls TO "mscqr_rls_cert_auth_owner";
GRANT EXECUTE ON FUNCTION app_rls.setting(text) TO "mscqr_rls_cert_auth_owner";
GRANT EXECUTE ON FUNCTION app_rls.uuid_setting(text) TO "mscqr_rls_cert_auth_owner";
GRANT EXECUTE ON FUNCTION app_rls.current_user_id() TO "mscqr_rls_cert_auth_owner";
GRANT EXECUTE ON FUNCTION app_rls.current_organization_id() TO "mscqr_rls_cert_auth_owner";
GRANT EXECUTE ON FUNCTION app_rls.current_licensee_id() TO "mscqr_rls_cert_auth_owner";
GRANT EXECUTE ON FUNCTION app_rls.current_manufacturer_id() TO "mscqr_rls_cert_auth_owner";
GRANT EXECUTE ON FUNCTION app_rls.current_role() TO "mscqr_rls_cert_auth_owner";
GRANT EXECUTE ON FUNCTION app_rls.current_assurance() TO "mscqr_rls_cert_auth_owner";
GRANT EXECUTE ON FUNCTION app_rls.current_request_id() TO "mscqr_rls_cert_auth_owner";
GRANT EXECUTE ON FUNCTION app_rls.current_purpose() TO "mscqr_rls_cert_auth_owner";
GRANT EXECUTE ON FUNCTION app_rls.attributed_request() TO "mscqr_rls_cert_auth_owner";
GRANT EXECUTE ON FUNCTION app_rls.dashboard_scope_fingerprint(text) TO "mscqr_rls_cert_auth_owner";
GRANT EXECUTE ON FUNCTION app_rls.authorize_dashboard_snapshot(text,text,text) TO "mscqr_rls_cert_auth_owner";
GRANT EXECUTE ON FUNCTION app_rls.dashboard_snapshot_scope(text,text,text) TO "mscqr_rls_cert_auth_owner";
GRANT EXECUTE ON FUNCTION app_rls.dashboard_snapshot_data(text,text,text,text) TO "mscqr_rls_cert_auth_owner";
GRANT EXECUTE ON FUNCTION app_rls.batch_scope_fingerprint(text,text,text) TO "mscqr_rls_cert_auth_owner";
GRANT EXECUTE ON FUNCTION app_rls.batch_operational_batch_allowed(text,text) TO "mscqr_rls_cert_auth_owner";
GRANT EXECUTE ON FUNCTION app_rls.authorize_batch_operational_read(text,text,text,text) TO "mscqr_rls_cert_auth_owner";
GRANT EXECUTE ON FUNCTION app_rls.batch_operational_scope(text,text,text,text) TO "mscqr_rls_cert_auth_owner";
GRANT EXECUTE ON FUNCTION app_rls.batch_operational_rows(text,text,text,text,text,integer,integer) TO "mscqr_rls_cert_auth_owner";
GRANT EXECUTE ON FUNCTION app_rls.batch_operational_total(text,text,text,text,text) TO "mscqr_rls_cert_auth_owner";
GRANT EXECUTE ON FUNCTION app_rls.batch_inventory_rollups(text,text,text,text,text,text[]) TO "mscqr_rls_cert_auth_owner";
GRANT EXECUTE ON FUNCTION app_rls.batch_unassigned_ranges(text,text,text,text,text,text[]) TO "mscqr_rls_cert_auth_owner";
GRANT EXECUTE ON FUNCTION app_rls.batch_status_fallback(text,text,text,text,text,text[]) TO "mscqr_rls_cert_auth_owner";
GRANT EXECUTE ON FUNCTION app_rls.batch_reservable_qr_summaries(text,text,text,text,text,text[]) TO "mscqr_rls_cert_auth_owner";
RESET ROLE;
DO $$ BEGIN
  IF NOT pg_has_role(session_user,'mscqr_rls_cert_auth_owner','SET') THEN RAISE EXCEPTION 'administrative executor lacks SET authority for mscqr_rls_cert_auth_owner'; END IF;
END $$;
SET ROLE "mscqr_rls_cert_auth_owner";
-- Capability-bearing public wrappers for the mature dashboard and batch-read
-- implementations emitted by the clean-room package.  The implementation
-- overloads are SECURITY INVOKER and are never granted to a runtime role.
-- These wrappers are owned by identity-auth-function-owner and re-derive all
-- actor context from the durable authenticated-session capability.

CREATE OR REPLACE FUNCTION app_rls.operational_read_bind_actor(
  p_capability text,
  p_purpose text,
  p_request_id text,
  p_requested_licensee_id text
) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $fn$
DECLARE actor record; selected_licensee text := NULLIF(btrim(p_requested_licensee_id),'');
BEGIN
  IF p_purpose NOT IN ('dashboard-snapshot-read','batch-operational-read') THEN
    RAISE EXCEPTION 'operational read access denied' USING ERRCODE='42501';
  END IF;
  SELECT * INTO actor FROM app_auth.require_authenticated_session(p_capability,p_purpose,p_request_id);
  PERFORM set_config(
    'app.auth_session_hash',
    encode(sha256(convert_to(p_capability, 'UTF8')), 'hex'),
    true
  ),
          set_config('app.auth_session_id',actor."sessionId",true),
          set_config('app.auth_session_verified','1',true),
          set_config('app.user_id',actor."userId",true),
          set_config('app.role',actor.role,true),
          set_config('app.organization_id',coalesce(actor."organizationId",''),true),
          set_config('app.licensee_id',coalesce(actor."licenseeId",''),true),
          set_config('app.manufacturer_id','',true),
          set_config('app.auth_assurance',CASE actor.assurance WHEN 'ADMIN_MFA' THEN 'mfa-verified' WHEN 'PASSWORD' THEN 'password-verified' ELSE '' END,true),
          set_config('app.request_id',p_request_id,true),
          set_config('app.purpose',p_purpose,true);
  IF current_setting('app.auth_assurance',true)='' THEN
    RAISE EXCEPTION 'operational read access denied' USING ERRCODE='42501';
  END IF;
  IF actor.role IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') THEN
    PERFORM set_config('app.manufacturer_id',actor."userId",true),
            set_config('app.organization_id','',true),
            set_config('app.licensee_id',coalesce(selected_licensee,''),true);
  ELSIF actor.role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') THEN
    PERFORM set_config('app.manufacturer_id','',true),
            set_config('app.organization_id','',true),
            set_config('app.licensee_id',coalesce(selected_licensee,''),true);
  ELSIF actor.role IN ('LICENSEE_ADMIN','ORG_ADMIN') THEN
    IF selected_licensee IS NOT NULL AND selected_licensee IS DISTINCT FROM actor."licenseeId" THEN
      RAISE EXCEPTION 'operational read access denied' USING ERRCODE='42501';
    END IF;
    PERFORM set_config('app.manufacturer_id','',true);
  ELSE
    RAISE EXCEPTION 'operational read access denied' USING ERRCODE='42501';
  END IF;
END
$fn$;

REVOKE ALL ON FUNCTION app_rls.operational_read_bind_actor(text,text,text,text) FROM PUBLIC;

CREATE OR REPLACE FUNCTION app_rls.dashboard_snapshot_scope(
  p_capability text,p_purpose text,p_request_id text,
  audit_id text,requested_licensee_id text,route_surface text
) RETURNS TABLE(scope_fingerprint text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
BEGIN
  PERFORM app_rls.operational_read_bind_actor(p_capability,p_purpose,p_request_id,requested_licensee_id);
  RETURN QUERY SELECT * FROM app_rls.dashboard_snapshot_scope(audit_id,requested_licensee_id,route_surface);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.dashboard_snapshot_data(
  p_capability text,p_purpose text,p_request_id text,
  audit_id text,requested_licensee_id text,route_surface text,expected_scope_fingerprint text
) RETURNS TABLE(
  total_qr_codes bigint,active_licensees bigint,manufacturers bigint,total_batches bigint,
  dormant bigint,active bigint,activated bigint,allocated bigint,printed bigint,redeemed bigint,blocked bigint,scanned bigint,
  rollup_authoritative boolean
)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
BEGIN
  PERFORM app_rls.operational_read_bind_actor(p_capability,p_purpose,p_request_id,requested_licensee_id);
  RETURN QUERY SELECT * FROM app_rls.dashboard_snapshot_data(audit_id,requested_licensee_id,route_surface,expected_scope_fingerprint);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.batch_operational_scope(
  p_capability text,p_purpose text,p_request_id text,
  audit_id text,requested_licensee_id text,route_surface text,focus_batch_id text
) RETURNS TABLE(scope_fingerprint text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
BEGIN
  PERFORM app_rls.operational_read_bind_actor(p_capability,p_purpose,p_request_id,requested_licensee_id);
  RETURN QUERY SELECT * FROM app_rls.batch_operational_scope(audit_id,requested_licensee_id,route_surface,focus_batch_id);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.batch_operational_rows(
  p_capability text,p_purpose text,p_request_id text,
  audit_id text,requested_licensee_id text,route_surface text,focus_batch_id text,expected_scope_fingerprint text,
  page_limit integer,page_offset integer
) RETURNS TABLE(row_data jsonb)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
BEGIN
  PERFORM app_rls.operational_read_bind_actor(p_capability,p_purpose,p_request_id,requested_licensee_id);
  RETURN QUERY SELECT * FROM app_rls.batch_operational_rows(audit_id,requested_licensee_id,route_surface,focus_batch_id,expected_scope_fingerprint,page_limit,page_offset);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.batch_operational_total(
  p_capability text,p_purpose text,p_request_id text,
  audit_id text,requested_licensee_id text,route_surface text,focus_batch_id text,expected_scope_fingerprint text
) RETURNS TABLE(total bigint)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
BEGIN
  PERFORM app_rls.operational_read_bind_actor(p_capability,p_purpose,p_request_id,requested_licensee_id);
  RETURN QUERY SELECT * FROM app_rls.batch_operational_total(audit_id,requested_licensee_id,route_surface,focus_batch_id,expected_scope_fingerprint);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.batch_inventory_rollups(
  p_capability text,p_purpose text,p_request_id text,
  audit_id text,requested_licensee_id text,route_surface text,focus_batch_id text,expected_scope_fingerprint text,batch_ids text[]
) RETURNS TABLE(batch_id text,dormant integer,active integer,activated integer,allocated integer,printed integer,redeemed integer,blocked integer,scanned integer)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
BEGIN
  PERFORM app_rls.operational_read_bind_actor(p_capability,p_purpose,p_request_id,requested_licensee_id);
  RETURN QUERY SELECT * FROM app_rls.batch_inventory_rollups(audit_id,requested_licensee_id,route_surface,focus_batch_id,expected_scope_fingerprint,batch_ids);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.batch_unassigned_ranges(
  p_capability text,p_purpose text,p_request_id text,
  audit_id text,requested_licensee_id text,route_surface text,focus_batch_id text,expected_scope_fingerprint text,batch_ids text[]
) RETURNS TABLE(batch_id text,item_count bigint,start_code text,end_code text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
BEGIN
  PERFORM app_rls.operational_read_bind_actor(p_capability,p_purpose,p_request_id,requested_licensee_id);
  RETURN QUERY SELECT * FROM app_rls.batch_unassigned_ranges(audit_id,requested_licensee_id,route_surface,focus_batch_id,expected_scope_fingerprint,batch_ids);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.batch_status_fallback(
  p_capability text,p_purpose text,p_request_id text,
  audit_id text,requested_licensee_id text,route_surface text,focus_batch_id text,expected_scope_fingerprint text,batch_ids text[]
) RETURNS TABLE(batch_id text,status text,item_count bigint)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
BEGIN
  PERFORM app_rls.operational_read_bind_actor(p_capability,p_purpose,p_request_id,requested_licensee_id);
  RETURN QUERY SELECT * FROM app_rls.batch_status_fallback(audit_id,requested_licensee_id,route_surface,focus_batch_id,expected_scope_fingerprint,batch_ids);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.batch_reservable_qr_summaries(
  p_capability text,p_purpose text,p_request_id text,
  audit_id text,requested_licensee_id text,route_surface text,focus_batch_id text,expected_scope_fingerprint text,batch_ids text[]
) RETURNS TABLE(batch_id text,item_count bigint,start_code text,end_code text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
BEGIN
  PERFORM app_rls.operational_read_bind_actor(p_capability,p_purpose,p_request_id,requested_licensee_id);
  RETURN QUERY SELECT * FROM app_rls.batch_reservable_qr_summaries(audit_id,requested_licensee_id,route_surface,focus_batch_id,expected_scope_fingerprint,batch_ids);
END
$fn$;

REVOKE ALL ON FUNCTION app_rls.dashboard_snapshot_scope(text,text,text,text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.dashboard_snapshot_data(text,text,text,text,text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.batch_operational_scope(text,text,text,text,text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.batch_operational_rows(text,text,text,text,text,text,text,text,integer,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.batch_operational_total(text,text,text,text,text,text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.batch_inventory_rollups(text,text,text,text,text,text,text,text,text[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.batch_unassigned_ranges(text,text,text,text,text,text,text,text,text[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.batch_status_fallback(text,text,text,text,text,text,text,text,text[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.batch_reservable_qr_summaries(text,text,text,text,text,text,text,text,text[]) FROM PUBLIC;

-- Release Fix 2: exact tenant-directory projections.  The capability is the
-- sole authentication input; every selector is narrowed against live rows.
CREATE OR REPLACE FUNCTION app_rls.read_licensee_directory(
  p_capability text,
  p_purpose text,
  p_request_id text,
  p_requested_licensee_id text,
  p_detail boolean
) RETURNS TABLE(payload jsonb)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE
  actor record;
  selector text := NULLIF(btrim(p_requested_licensee_id),'');
  scope_ids text := '';
  scope_org_ids text := '';
  scope_user_ids text := '';
BEGIN
  IF p_purpose<>'tenant-directory-licensees'
     OR p_detail IS NULL
     OR (selector IS NOT NULL AND selector !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$')
     OR (p_detail AND selector IS NULL) THEN
    RAISE EXCEPTION 'TENANT_DIRECTORY_DENIED' USING ERRCODE='42501';
  END IF;

  SELECT * INTO actor FROM app_auth.require_authenticated_session(p_capability,p_purpose,p_request_id);
  IF actor.role NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN','LICENSEE_ADMIN','MANUFACTURER_ADMIN') THEN
    RAISE EXCEPTION 'TENANT_DIRECTORY_DENIED' USING ERRCODE='42501';
  END IF;
  scope_ids := CASE
    WHEN actor.role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') THEN coalesce(selector,'')
    WHEN actor.role='LICENSEE_ADMIN' THEN coalesce(actor."licenseeId",'')
    ELSE ''
  END;
  scope_org_ids := CASE WHEN actor.role='LICENSEE_ADMIN' THEN coalesce(actor."organizationId",'') ELSE '' END;
  PERFORM set_config('app.tenant_directory_session_id',actor."sessionId",true),
          set_config('app.tenant_directory_user_id',actor."userId",true),
          set_config('app.tenant_directory_role',actor.role,true),
          set_config('app.tenant_directory_organization_id',coalesce(actor."organizationId",''),true),
          set_config('app.tenant_directory_licensee_id',coalesce(actor."licenseeId",''),true),
          set_config('app.tenant_directory_requested_licensee_id',coalesce(selector,''),true),
          set_config('app.tenant_directory_scope_licensee_ids',scope_ids,true),
          set_config('app.tenant_directory_scope_organization_ids',scope_org_ids,true),
          set_config('app.tenant_directory_scope_user_ids','',true),
          set_config('app.tenant_directory_operation','licensees',true);

  IF actor.role='LICENSEE_ADMIN' AND NOT EXISTS (
    SELECT 1 FROM public."Licensee" l JOIN public."Organization" o ON o.id=l."orgId"
     WHERE l.id=actor."licenseeId" AND l."orgId"=actor."organizationId"
       AND l."isActive" AND l."suspendedAt" IS NULL AND o."isActive"
  ) THEN RAISE EXCEPTION 'TENANT_DIRECTORY_DENIED' USING ERRCODE='42501'; END IF;
  IF actor.role='LICENSEE_ADMIN' AND selector IS NOT NULL AND selector IS DISTINCT FROM actor."licenseeId" THEN
    RAISE EXCEPTION 'TENANT_DIRECTORY_DENIED' USING ERRCODE='42501';
  END IF;
  IF actor.role='MANUFACTURER_ADMIN' THEN
    SELECT string_agg(ml."licenseeId",',' ORDER BY ml."licenseeId") INTO scope_ids
      FROM public."ManufacturerLicenseeLink" ml
     WHERE ml."manufacturerId"=actor."userId" AND (selector IS NULL OR ml."licenseeId"=selector);
    IF coalesce(scope_ids,'')='' THEN RAISE EXCEPTION 'TENANT_DIRECTORY_DENIED' USING ERRCODE='42501'; END IF;
    PERFORM set_config('app.tenant_directory_scope_licensee_ids',scope_ids,true);
    SELECT string_agg(DISTINCT l."orgId",',' ORDER BY l."orgId") INTO scope_org_ids
      FROM public."Licensee" l WHERE l.id=ANY(string_to_array(scope_ids,','));
    PERFORM set_config('app.tenant_directory_scope_organization_ids',coalesce(scope_org_ids,''),true);
    SELECT string_agg(l.id,',' ORDER BY l.id) INTO scope_ids
      FROM public."Licensee" l JOIN public."Organization" o ON o.id=l."orgId"
     WHERE l.id=ANY(string_to_array(scope_ids,',')) AND l."isActive" AND l."suspendedAt" IS NULL AND o."isActive";
    IF coalesce(scope_ids,'')='' THEN RAISE EXCEPTION 'TENANT_DIRECTORY_DENIED' USING ERRCODE='42501'; END IF;
  END IF;
  PERFORM set_config('app.tenant_directory_scope_licensee_ids',coalesce(scope_ids,''),true);
  IF coalesce(scope_ids,'')<>'' THEN
    SELECT string_agg(DISTINCT ml."manufacturerId",',' ORDER BY ml."manufacturerId") INTO scope_user_ids
      FROM public."ManufacturerLicenseeLink" ml WHERE ml."licenseeId"=ANY(string_to_array(scope_ids,','));
  END IF;
  PERFORM set_config('app.tenant_directory_scope_user_ids',coalesce(scope_user_ids,''),true);

  RETURN QUERY
  WITH visible AS MATERIALIZED (
    SELECT l.*
    FROM public."Licensee" l
    JOIN public."Organization" o ON o.id=l."orgId"
    WHERE (selector IS NULL OR l.id=selector)
      AND (
        actor.role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')
        OR (actor.role='LICENSEE_ADMIN' AND l.id=actor."licenseeId" AND l."orgId"=actor."organizationId")
        OR (actor.role='MANUFACTURER_ADMIN' AND EXISTS (
          SELECT 1 FROM public."ManufacturerLicenseeLink" ml WHERE ml."manufacturerId"=actor."userId" AND ml."licenseeId"=l.id
        ))
      )
      AND (actor.role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') OR (l."isActive" AND l."suspendedAt" IS NULL AND o."isActive"))
  ), rows AS (
    SELECT l.id,l."createdAt",
      jsonb_build_object(
        'id',l.id,'orgId',l."orgId",'name',l.name,'prefix',l.prefix,
        'description',l.description,'brandName',l."brandName",'location',l.location,
        'website',l.website,'supportEmail',l."supportEmail",'supportPhone',l."supportPhone",
        'metadata',l.metadata,'isActive',l."isActive",'suspendedAt',CASE WHEN l."suspendedAt" IS NULL THEN NULL ELSE to_char(l."suspendedAt",'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') END,
        'suspendedReason',l."suspendedReason",'createdAt',to_char(l."createdAt",'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
        'updatedAt',to_char(l."updatedAt",'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
        '_count',jsonb_build_object(
          'users',(SELECT count(*) FROM public."User" u WHERE u."licenseeId"=l.id),
          'qrCodes',(SELECT count(*) FROM public."QRCode" q WHERE q."licenseeId"=l.id),
          'batches',(SELECT count(*) FROM public."Batch" b WHERE b."licenseeId"=l.id)
        )
      ) || CASE WHEN p_detail THEN jsonb_build_object(
        'qrRanges',COALESCE((SELECT jsonb_agg(jsonb_build_object(
          'id',r.id,'licenseeId',r."licenseeId",'startCode',r."startCode",'endCode',r."endCode",
          'totalCodes',r."totalCodes",'usedCodes',r."usedCodes",
          'createdAt',to_char(r."createdAt",'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
          'updatedAt',to_char(r."updatedAt",'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
        ) ORDER BY r."createdAt" DESC) FROM public."QRRange" r WHERE r."licenseeId"=l.id),'[]'::jsonb),
        'users',COALESCE((SELECT jsonb_agg(jsonb_build_object(
          'id',u.id,'name',u.name,'email',u.email,'role',u.role::text,'isActive',u."isActive",
          'createdAt',to_char(u."createdAt",'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
        ) ORDER BY u."createdAt",u.id) FROM public."User" u WHERE u."licenseeId"=l.id),'[]'::jsonb)
      ) ELSE jsonb_build_object(
        'latestRange',(SELECT jsonb_build_object(
          'id',r.id,'startCode',r."startCode",'endCode',r."endCode",'totalCodes',r."totalCodes",
          'createdAt',to_char(r."createdAt",'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
        ) FROM public."QRRange" r WHERE r."licenseeId"=l.id ORDER BY r."createdAt" DESC LIMIT 1),
        'adminOnboarding',jsonb_build_object(
          'state',CASE
            WHEN EXISTS (SELECT 1 FROM public."Invite" i WHERE i."licenseeId"=l.id AND i.role='LICENSEE_ADMIN' AND i."usedAt" IS NULL AND i."expiresAt">clock_timestamp()) THEN 'PENDING'
            WHEN EXISTS (SELECT 1 FROM public."User" u WHERE u."licenseeId"=l.id AND u.role='LICENSEE_ADMIN' AND u."deletedAt" IS NULL) THEN 'ACTIVE'
            ELSE 'UNASSIGNED' END,
          'adminUser',(SELECT jsonb_build_object(
            'id',u.id,'name',u.name,'email',u.email,'role',u.role::text,'status',u.status::text,
            'isActive',u."isActive",'createdAt',to_char(u."createdAt",'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
          ) FROM public."User" u WHERE u."licenseeId"=l.id AND u.role='LICENSEE_ADMIN' AND u."deletedAt" IS NULL ORDER BY u."createdAt",u.id LIMIT 1),
          'pendingInvite',(SELECT jsonb_build_object(
            'id',i.id,'email',i.email,'expiresAt',to_char(i."expiresAt",'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
            'createdAt',to_char(i."createdAt",'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
          ) FROM public."Invite" i WHERE i."licenseeId"=l.id AND i.role='LICENSEE_ADMIN' AND i."usedAt" IS NULL AND i."expiresAt">clock_timestamp() ORDER BY i."createdAt" DESC LIMIT 1)
        )
      ) END AS row_data
    FROM visible l
  )
  SELECT CASE WHEN p_detail THEN (SELECT row_data FROM rows LIMIT 1)
              ELSE COALESCE((SELECT jsonb_agg(row_data ORDER BY "createdAt" DESC,id) FROM rows),'[]'::jsonb) END;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.read_user_directory(
  p_capability text,
  p_purpose text,
  p_request_id text,
  p_requested_licensee_id text,
  p_include_inactive boolean,
  p_role_filter text,
  p_limit integer,
  p_offset integer
) RETURNS TABLE(payload jsonb,total bigint)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE
  actor record;
  selector text := NULLIF(btrim(p_requested_licensee_id),'');
  role_filter text := NULLIF(btrim(p_role_filter),'');
  scope_ids text := '';
  scope_org_ids text := '';
  scope_user_ids text := '';
BEGIN
  IF p_purpose<>'tenant-directory-users' OR p_include_inactive IS NULL
     OR p_limit NOT BETWEEN 1 AND 500 OR p_offset NOT BETWEEN 0 AND 1000000
     OR (selector IS NOT NULL AND selector !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$')
     OR (role_filter IS NOT NULL AND role_filter NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN','LICENSEE_ADMIN','MANUFACTURER_ADMIN')) THEN
    RAISE EXCEPTION 'TENANT_DIRECTORY_DENIED' USING ERRCODE='42501';
  END IF;

  SELECT * INTO actor FROM app_auth.require_authenticated_session(p_capability,p_purpose,p_request_id);
  IF actor.role NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN','LICENSEE_ADMIN','MANUFACTURER_ADMIN') THEN
    RAISE EXCEPTION 'TENANT_DIRECTORY_DENIED' USING ERRCODE='42501';
  END IF;
  scope_ids := CASE
    WHEN actor.role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') THEN coalesce(selector,'')
    WHEN actor.role='LICENSEE_ADMIN' THEN coalesce(actor."licenseeId",'')
    ELSE ''
  END;
  scope_org_ids := CASE WHEN actor.role='LICENSEE_ADMIN' THEN coalesce(actor."organizationId",'') ELSE '' END;
  PERFORM set_config('app.tenant_directory_session_id',actor."sessionId",true),
          set_config('app.tenant_directory_user_id',actor."userId",true),
          set_config('app.tenant_directory_role',actor.role,true),
          set_config('app.tenant_directory_organization_id',coalesce(actor."organizationId",''),true),
          set_config('app.tenant_directory_licensee_id',coalesce(actor."licenseeId",''),true),
          set_config('app.tenant_directory_requested_licensee_id',coalesce(selector,''),true),
          set_config('app.tenant_directory_scope_licensee_ids',scope_ids,true),
          set_config('app.tenant_directory_scope_organization_ids',scope_org_ids,true),
          set_config('app.tenant_directory_scope_user_ids','',true),
          set_config('app.tenant_directory_operation','users',true);

  IF actor.role='LICENSEE_ADMIN' AND (selector IS NOT NULL AND selector IS DISTINCT FROM actor."licenseeId" OR NOT EXISTS (
    SELECT 1 FROM public."Licensee" l JOIN public."Organization" o ON o.id=l."orgId"
     WHERE l.id=actor."licenseeId" AND l."orgId"=actor."organizationId"
       AND l."isActive" AND l."suspendedAt" IS NULL AND o."isActive"
  )) THEN RAISE EXCEPTION 'TENANT_DIRECTORY_DENIED' USING ERRCODE='42501'; END IF;
  IF actor.role='MANUFACTURER_ADMIN' THEN
    SELECT string_agg(ml."licenseeId",',' ORDER BY ml."licenseeId") INTO scope_ids
      FROM public."ManufacturerLicenseeLink" ml
     WHERE ml."manufacturerId"=actor."userId" AND (selector IS NULL OR ml."licenseeId"=selector);
    IF coalesce(scope_ids,'')='' THEN RAISE EXCEPTION 'TENANT_DIRECTORY_DENIED' USING ERRCODE='42501'; END IF;
    PERFORM set_config('app.tenant_directory_scope_licensee_ids',scope_ids,true);
    SELECT string_agg(DISTINCT l."orgId",',' ORDER BY l."orgId") INTO scope_org_ids
      FROM public."Licensee" l WHERE l.id=ANY(string_to_array(scope_ids,','));
    PERFORM set_config('app.tenant_directory_scope_organization_ids',coalesce(scope_org_ids,''),true);
    SELECT string_agg(l.id,',' ORDER BY l.id) INTO scope_ids
      FROM public."Licensee" l JOIN public."Organization" o ON o.id=l."orgId"
     WHERE l.id=ANY(string_to_array(scope_ids,',')) AND l."isActive" AND l."suspendedAt" IS NULL AND o."isActive";
    IF coalesce(scope_ids,'')='' THEN RAISE EXCEPTION 'TENANT_DIRECTORY_DENIED' USING ERRCODE='42501'; END IF;
  END IF;
  PERFORM set_config('app.tenant_directory_scope_licensee_ids',coalesce(scope_ids,''),true);
  IF coalesce(scope_ids,'')<>'' THEN
    SELECT string_agg(DISTINCT ml."manufacturerId",',' ORDER BY ml."manufacturerId") INTO scope_user_ids
      FROM public."ManufacturerLicenseeLink" ml WHERE ml."licenseeId"=ANY(string_to_array(scope_ids,','));
  END IF;
  PERFORM set_config('app.tenant_directory_scope_user_ids',coalesce(scope_user_ids,''),true);

  RETURN QUERY
  WITH eligible AS MATERIALIZED (
    SELECT u.id,u.email,u.name,u.role,u."licenseeId",u."isActive",u."deletedAt",u."createdAt",u.location,u.website
    FROM public."User" u
    WHERE (p_include_inactive OR (u."isActive" AND u."deletedAt" IS NULL))
      AND (role_filter IS NULL OR u.role::text=role_filter)
      AND (
        actor.role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') AND (selector IS NULL OR u."licenseeId"=selector OR EXISTS (SELECT 1 FROM public."ManufacturerLicenseeLink" ml WHERE ml."manufacturerId"=u.id AND ml."licenseeId"=selector))
        OR actor.role='LICENSEE_ADMIN' AND (u."licenseeId"=actor."licenseeId" OR EXISTS (SELECT 1 FROM public."ManufacturerLicenseeLink" ml WHERE ml."manufacturerId"=u.id AND ml."licenseeId"=actor."licenseeId"))
        OR actor.role='MANUFACTURER_ADMIN' AND (
          u."licenseeId"=ANY(string_to_array(scope_ids,','))
          OR EXISTS (SELECT 1 FROM public."ManufacturerLicenseeLink" target_link
            WHERE target_link."manufacturerId"=u.id AND target_link."licenseeId"=ANY(string_to_array(scope_ids,',')))
        )
      )
  ), page AS (
    SELECT * FROM eligible ORDER BY "createdAt" DESC,id LIMIT p_limit OFFSET p_offset
  ), projected AS (
    SELECT u.id,u."createdAt",
      jsonb_build_object(
        'id',u.id,'email',u.email,'name',u.name,'role',u.role::text,'licenseeId',COALESCE(scoped.licensee->>'id',u."licenseeId"),
        'isActive',u."isActive",'deletedAt',CASE WHEN u."deletedAt" IS NULL THEN NULL ELSE to_char(u."deletedAt",'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') END,
        'createdAt',to_char(u."createdAt",'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),'location',u.location,'website',u.website,
        'licensee',scoped.licensee
      ) || CASE WHEN jsonb_array_length(links.items)>0 THEN jsonb_build_object('linkedLicensees',links.items) ELSE '{}'::jsonb END AS row_data
    FROM page u
    LEFT JOIN public."Licensee" direct_licensee ON direct_licensee.id=u."licenseeId"
    LEFT JOIN LATERAL (
      SELECT COALESCE(jsonb_agg(jsonb_build_object(
        'id',l.id,'name',l.name,'prefix',l.prefix,'brandName',l."brandName",'orgId',l."orgId",
        'isPrimary',ml."isPrimary",'scopeVersion',to_char(ml."updatedAt",'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
      ) ORDER BY ml."isPrimary" DESC,ml."createdAt",l.id),'[]'::jsonb) AS items
      FROM public."ManufacturerLicenseeLink" ml JOIN public."Licensee" l ON l.id=ml."licenseeId"
      WHERE ml."manufacturerId"=u.id AND (
        actor.role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') AND (selector IS NULL OR ml."licenseeId"=selector)
        OR actor.role NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') AND ml."licenseeId"=ANY(string_to_array(scope_ids,','))
      )
    ) links ON true
    LEFT JOIN LATERAL (
      SELECT value AS licensee FROM jsonb_array_elements(links.items) value
      ORDER BY (value->>'id'=selector) DESC,(value->>'isPrimary')::boolean DESC,value->>'id' LIMIT 1
    ) linked_scope ON true
    LEFT JOIN LATERAL (
      SELECT COALESCE(linked_scope.licensee,CASE WHEN direct_licensee.id IS NULL THEN NULL ELSE jsonb_build_object(
        'id',direct_licensee.id,'name',direct_licensee.name,'prefix',direct_licensee.prefix,'brandName',direct_licensee."brandName"
      ) END) AS licensee
    ) scoped ON true
  )
  SELECT COALESCE((SELECT jsonb_agg(row_data ORDER BY "createdAt" DESC,id) FROM projected),'[]'::jsonb),
         (SELECT count(*) FROM eligible);
END
$fn$;

REVOKE ALL ON FUNCTION app_rls.read_licensee_directory(text,text,text,text,boolean) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.read_user_directory(text,text,text,text,boolean,text,integer,integer) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION app_rls.batch_inventory_rollups(text,text,text,text,text,text,text,text,text[]) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.batch_operational_rows(text,text,text,text,text,text,text,text,integer,integer) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.batch_operational_scope(text,text,text,text,text,text,text) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.batch_operational_total(text,text,text,text,text,text,text,text) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.batch_reservable_qr_summaries(text,text,text,text,text,text,text,text,text[]) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.batch_status_fallback(text,text,text,text,text,text,text,text,text[]) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.batch_unassigned_ranges(text,text,text,text,text,text,text,text,text[]) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.dashboard_snapshot_data(text,text,text,text,text,text,text) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.dashboard_snapshot_scope(text,text,text,text,text,text) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.read_licensee_directory(text,text,text,text,boolean) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.read_user_directory(text,text,text,text,boolean,text,integer,integer) TO "mscqr_rls_cert_app";
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
-- Reviewed production B01 pre-authentication boundaries. Bearer hashes and
-- normalized email addresses are selectors only; the locked token/account
-- relationship is the sole authority for every mutation.

CREATE OR REPLACE FUNCTION app_auth.b01_preauth_audit(
  p_action text, p_entity_type text, p_entity_id text, p_at timestamp without time zone, p_details jsonb DEFAULT '{}'::jsonb
) RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
BEGIN
  IF p_action NOT IN ('AUTH_PASSWORD_RESET_REQUESTED','AUTH_PASSWORD_RESET_COMPLETED','AUTH_EMAIL_VERIFIED','AUTH_EMAIL_CHANGE_CONFIRMED','AUTH_INVITE_ACCEPTED')
     OR current_setting('app.b01_preauth_user_id',true)='' THEN
    RAISE EXCEPTION 'B01_PREAUTH_AUDIT_DENIED' USING ERRCODE='42501';
  END IF;
  INSERT INTO public."AuditLogOutbox" (id,payload,"updatedAt") VALUES (
    gen_random_uuid()::text,
    jsonb_build_object(
      'userId',current_setting('app.b01_preauth_user_id',true),
      'orgId',nullif(current_setting('app.b01_preauth_org_id',true),''),
      'licenseeId',nullif(current_setting('app.b01_preauth_licensee_id',true),''),
      'action',p_action,'entityType',p_entity_type,'entityId',p_entity_id,
      'details',coalesce(p_details,'{}'::jsonb)
    ), p_at
  );
END
$fn$;

CREATE OR REPLACE FUNCTION app_auth.lookup_password_user(p_requested_email text)
RETURNS TABLE(
  "id" text,"email" text,"passwordHash" text,"name" text,"role" text,"licenseeId" text,"orgId" text,
  "status" text,"isActive" boolean,"disabledAt" timestamp without time zone,"deletedAt" timestamp without time zone,
  "failedLoginAttempts" integer,"lockedUntil" timestamp without time zone,"lastLoginAt" timestamp without time zone,
  "emailVerifiedAt" timestamp without time zone
) LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE candidate_count integer; candidate_user_id text;
BEGIN
  IF p_requested_email IS NULL OR length(p_requested_email) NOT BETWEEN 3 AND 320
     OR p_requested_email IS DISTINCT FROM lower(btrim(p_requested_email))
     OR p_requested_email !~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$' THEN
    RAISE EXCEPTION 'B01_PASSWORD_LOOKUP_DENIED' USING ERRCODE='22023';
  END IF;
  PERFORM set_config('app.b01_preauth_operation','password-lookup',true),
          set_config('app.b01_preauth_email',p_requested_email,true),
          set_config('app.b01_preauth_hashes','',true),set_config('app.b01_preauth_token_id','',true),
          set_config('app.b01_preauth_user_id','',true),set_config('app.b01_preauth_org_id','',true),
          set_config('app.b01_preauth_licensee_id','',true),set_config('app.b01_preauth_pending_email','',true);
  SELECT count(*)::integer INTO candidate_count FROM public."User" u WHERE lower(u.email)=p_requested_email;
  IF candidate_count<>1 THEN RETURN; END IF;
  SELECT u.id INTO STRICT candidate_user_id FROM public."User" u WHERE lower(u.email)=p_requested_email;
  PERFORM set_config('app.b01_preauth_user_id',candidate_user_id,true);
  RETURN QUERY SELECT u.id,u.email,u."passwordHash",u.name,u.role::text,u."licenseeId",u."orgId",u.status::text,
    u."isActive",u."disabledAt",u."deletedAt",u."failedLoginAttempts",u."lockedUntil",u."lastLoginAt",u."emailVerifiedAt"
    FROM public."User" u WHERE lower(u.email)=p_requested_email;
END
$fn$;

CREATE OR REPLACE FUNCTION app_auth.record_password_failure(
  p_requested_email text,p_attempted_at timestamp without time zone,p_max_attempts integer,p_lockout_minutes integer
) RETURNS TABLE("failedLoginAttempts" integer,"lockedUntil" timestamp without time zone)
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE candidate_count integer;
BEGIN
  IF p_requested_email IS NULL OR length(p_requested_email) NOT BETWEEN 3 AND 320
     OR p_requested_email IS DISTINCT FROM lower(btrim(p_requested_email))
     OR p_requested_email !~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$'
     OR p_attempted_at IS NULL OR abs(extract(epoch FROM (p_attempted_at-(clock_timestamp() AT TIME ZONE 'UTC'))))>300
     OR p_max_attempts NOT BETWEEN 1 AND 100 OR p_lockout_minutes NOT BETWEEN 1 AND 1440 THEN
    RAISE EXCEPTION 'B01_PASSWORD_FAILURE_DENIED' USING ERRCODE='22023';
  END IF;
  PERFORM set_config('app.b01_preauth_operation','password-failure',true),
          set_config('app.b01_preauth_email',p_requested_email,true),
          set_config('app.b01_preauth_hashes','',true),set_config('app.b01_preauth_token_id','',true),
          set_config('app.b01_preauth_user_id','',true),set_config('app.b01_preauth_org_id','',true),
          set_config('app.b01_preauth_licensee_id','',true),set_config('app.b01_preauth_pending_email','',true);
  SELECT count(*)::integer INTO candidate_count FROM public."User" u WHERE lower(u.email)=p_requested_email;
  IF candidate_count<>1 THEN RETURN; END IF;
  RETURN QUERY
  UPDATE public."User" u SET
    "failedLoginAttempts"=u."failedLoginAttempts"+1,
    "lockedUntil"=CASE WHEN u."failedLoginAttempts"+1>=p_max_attempts
      THEN greatest(coalesce(u."lockedUntil",p_attempted_at),p_attempted_at+make_interval(mins=>p_lockout_minutes))
      ELSE u."lockedUntil" END,
    "updatedAt"=p_attempted_at
  WHERE lower(u.email)=p_requested_email
  RETURNING u."failedLoginAttempts",u."lockedUntil";
END
$fn$;

CREATE OR REPLACE FUNCTION app_auth.request_password_reset(
  p_requested_email text,p_reset_token_hash text,p_expires_at timestamp without time zone,
  p_requested_at timestamp without time zone,p_created_ip_hash text,p_user_agent_hash text
) RETURNS TABLE("accepted" boolean,"deliveryRequired" boolean,"userId" text,"email" text,"licenseeId" text,"orgId" text,"expiresAt" timestamp without time zone)
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE candidate_count integer; actor_row record; reset_id text;
BEGIN
  IF p_requested_email IS NULL OR length(p_requested_email) NOT BETWEEN 3 AND 320
     OR p_requested_email IS DISTINCT FROM lower(btrim(p_requested_email))
     OR p_requested_email !~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$'
     OR p_reset_token_hash !~ '^([0-9a-f]{12}:)?[0-9a-f]{64}$'
     OR (p_created_ip_hash IS NOT NULL AND p_created_ip_hash !~ '^([0-9a-f]{12}:)?[0-9a-f]{64}$')
     OR (p_user_agent_hash IS NOT NULL AND p_user_agent_hash !~ '^([0-9a-f]{12}:)?[0-9a-f]{64}$')
     OR p_requested_at IS NULL OR abs(extract(epoch FROM (p_requested_at-(clock_timestamp() AT TIME ZONE 'UTC'))))>300
     OR p_expires_at<=p_requested_at OR p_expires_at>p_requested_at+interval '24 hours' THEN
    RAISE EXCEPTION 'B01_PASSWORD_RESET_REQUEST_DENIED' USING ERRCODE='22023';
  END IF;
  PERFORM set_config('app.b01_preauth_operation','reset-request',true),
          set_config('app.b01_preauth_email',p_requested_email,true),
          set_config('app.b01_preauth_hashes',p_reset_token_hash,true),set_config('app.b01_preauth_token_id','',true),
          set_config('app.b01_preauth_user_id','',true),set_config('app.b01_preauth_org_id','',true),
          set_config('app.b01_preauth_licensee_id','',true),set_config('app.b01_preauth_pending_email','',true);
  SELECT count(*)::integer INTO candidate_count FROM public."User" u WHERE lower(u.email)=p_requested_email;
  IF candidate_count<>1 THEN RETURN QUERY SELECT true,false,NULL::text,NULL::text,NULL::text,NULL::text,NULL::timestamp; RETURN; END IF;
  SELECT u.id,u.email,u."licenseeId",u."orgId" INTO actor_row FROM public."User" u
    WHERE lower(u.email)=p_requested_email AND u."isActive" AND u."disabledAt" IS NULL AND u."deletedAt" IS NULL AND u.status<>'DISABLED'::public."UserStatus";
  IF NOT FOUND THEN RETURN QUERY SELECT true,false,NULL::text,NULL::text,NULL::text,NULL::text,NULL::timestamp; RETURN; END IF;
  PERFORM set_config('app.b01_preauth_user_id',actor_row.id,true),
          set_config('app.b01_preauth_org_id',coalesce(actor_row."orgId",''),true),
          set_config('app.b01_preauth_licensee_id',coalesce(actor_row."licenseeId",''),true);
  reset_id:=gen_random_uuid()::text;
  INSERT INTO public."PasswordReset" (id,"orgId","userId","tokenHash","expiresAt","createdAt","createdIpHash","userAgentHash")
    VALUES (reset_id,actor_row."orgId",actor_row.id,p_reset_token_hash,p_expires_at,p_requested_at,p_created_ip_hash,p_user_agent_hash);
  PERFORM app_auth.b01_preauth_audit('AUTH_PASSWORD_RESET_REQUESTED','PasswordReset',reset_id,p_requested_at,jsonb_build_object('expiresAt',p_expires_at));
  RETURN QUERY SELECT true,true,actor_row.id::text,actor_row.email::text,actor_row."licenseeId"::text,actor_row."orgId"::text,p_expires_at;
END
$fn$;

CREATE OR REPLACE FUNCTION app_auth.consume_password_reset_token(
  p_token_hash_candidates text[],p_new_password_hash text,p_consumed_at timestamp without time zone
) RETURNS TABLE("id" text,"email" text,"name" text,"role" text,"licenseeId" text,"orgId" text)
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE token_row record; actor_row record; candidate_ids text[]; changed integer;
BEGIN
  IF coalesce(array_length(p_token_hash_candidates,1),0) NOT BETWEEN 1 AND 3
     OR EXISTS (SELECT 1 FROM unnest(p_token_hash_candidates) h WHERE h IS NULL OR h !~ '^([0-9a-f]{12}:)?[0-9a-f]{64}$')
     OR (SELECT count(DISTINCT h) FROM unnest(p_token_hash_candidates) h)<>array_length(p_token_hash_candidates,1)
     OR p_new_password_hash IS NULL OR p_new_password_hash NOT LIKE '$argon2id$%' OR length(p_new_password_hash)>512
     OR p_consumed_at IS NULL OR abs(extract(epoch FROM (p_consumed_at-(clock_timestamp() AT TIME ZONE 'UTC'))))>300 THEN
    RAISE EXCEPTION 'B01_PASSWORD_RESET_CONSUME_DENIED' USING ERRCODE='22023';
  END IF;
  PERFORM set_config('app.b01_preauth_operation','reset-consume',true),set_config('app.b01_preauth_email','',true),
          set_config('app.b01_preauth_hashes',array_to_string(p_token_hash_candidates,','),true),set_config('app.b01_preauth_token_id','',true),
          set_config('app.b01_preauth_user_id','',true),set_config('app.b01_preauth_org_id','',true),
          set_config('app.b01_preauth_licensee_id','',true),set_config('app.b01_preauth_pending_email','',true);
  SELECT array_agg(r.id ORDER BY r.id) INTO candidate_ids FROM public."PasswordReset" r
    WHERE r."tokenHash"=ANY(p_token_hash_candidates) AND r."usedAt" IS NULL AND r."expiresAt">p_consumed_at;
  IF coalesce(array_length(candidate_ids,1),0)<>1 THEN RETURN; END IF;
  SELECT r.id,r."orgId",r."userId",r."tokenHash",r."expiresAt",r."usedAt" INTO token_row
    FROM public."PasswordReset" r WHERE r.id=candidate_ids[1];
  PERFORM set_config('app.b01_preauth_token_id',token_row.id,true),set_config('app.b01_preauth_user_id',token_row."userId",true);
  SELECT u.id,u.email,u.name,u.role,u."orgId",u."licenseeId",u.status,u."isActive",u."disabledAt",u."deletedAt",u."emailVerifiedAt"
    INTO actor_row FROM public."User" u WHERE u.id=token_row."userId" FOR UPDATE;
  IF NOT FOUND OR NOT actor_row."isActive" OR actor_row."disabledAt" IS NOT NULL OR actor_row."deletedAt" IS NOT NULL OR actor_row.status='DISABLED'::public."UserStatus" THEN RETURN; END IF;
  SELECT r.id,r."orgId",r."userId",r."tokenHash",r."expiresAt",r."usedAt" INTO token_row
    FROM public."PasswordReset" r WHERE r.id=candidate_ids[1];
  IF NOT FOUND OR token_row."userId"<>actor_row.id OR token_row."usedAt" IS NOT NULL OR token_row."expiresAt"<=p_consumed_at THEN RETURN; END IF;
  PERFORM set_config('app.b01_preauth_org_id',coalesce(actor_row."orgId",''),true),
          set_config('app.b01_preauth_licensee_id',coalesce(actor_row."licenseeId",''),true);
  UPDATE public."User" u SET "passwordHash"=p_new_password_hash,status='ACTIVE'::public."UserStatus",
    "emailVerifiedAt"=coalesce(u."emailVerifiedAt",p_consumed_at),"failedLoginAttempts"=0,"lockedUntil"=NULL,"updatedAt"=p_consumed_at
    WHERE u.id=actor_row.id;
  UPDATE public."PasswordReset" r SET "usedAt"=p_consumed_at WHERE r.id=token_row.id AND r."usedAt" IS NULL;
  GET DIAGNOSTICS changed=ROW_COUNT; IF changed<>1 THEN RAISE EXCEPTION 'B01_PASSWORD_RESET_REPLAY' USING ERRCODE='40001'; END IF;
  UPDATE public."RefreshToken" r SET "revokedAt"=coalesce(r."revokedAt",p_consumed_at),
    "revokedReason"=coalesce(r."revokedReason",'PASSWORD_RESET'),"lastUsedAt"=p_consumed_at,
    "sessionCapabilityRevokedAt"=coalesce(r."sessionCapabilityRevokedAt",p_consumed_at),
    "sessionCapabilityRevokedReason"=coalesce(r."sessionCapabilityRevokedReason",'PASSWORD_RESET')
    WHERE r."userId"=actor_row.id AND (r."revokedAt" IS NULL OR r."sessionCapabilityRevokedAt" IS NULL);
  PERFORM app_auth.b01_preauth_audit('AUTH_PASSWORD_RESET_COMPLETED','User',actor_row.id,p_consumed_at,'{}'::jsonb);
  RETURN QUERY SELECT actor_row.id,actor_row.email,actor_row.name,actor_row.role::text,actor_row."licenseeId",actor_row."orgId";
END
$fn$;

CREATE OR REPLACE FUNCTION app_auth.lookup_invitation_token(p_token_hash_candidates text[],p_checked_at timestamp without time zone)
RETURNS TABLE("email" text,"role" text,"expiresAt" timestamp without time zone,"licenseeName" text,"requiresConnector" boolean)
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE invite_row record; actor_row record; candidate_ids text[]; candidate_user_ids text[]; licensee_name text;
BEGIN
  IF coalesce(array_length(p_token_hash_candidates,1),0) NOT BETWEEN 1 AND 3
     OR EXISTS (SELECT 1 FROM unnest(p_token_hash_candidates) h WHERE h IS NULL OR h !~ '^([0-9a-f]{12}:)?[0-9a-f]{64}$')
     OR (SELECT count(DISTINCT h) FROM unnest(p_token_hash_candidates) h)<>array_length(p_token_hash_candidates,1)
     OR p_checked_at IS NULL OR abs(extract(epoch FROM (p_checked_at-(clock_timestamp() AT TIME ZONE 'UTC'))))>300 THEN
    RAISE EXCEPTION 'B01_INVITE_LOOKUP_DENIED' USING ERRCODE='22023';
  END IF;
  PERFORM set_config('app.b01_preauth_operation','invite-lookup',true),set_config('app.b01_preauth_email','',true),
          set_config('app.b01_preauth_hashes',array_to_string(p_token_hash_candidates,','),true),set_config('app.b01_preauth_token_id','',true),
          set_config('app.b01_preauth_user_id','',true),set_config('app.b01_preauth_org_id','',true),
          set_config('app.b01_preauth_licensee_id','',true),set_config('app.b01_preauth_pending_email','',true);
  SELECT array_agg(i.id ORDER BY i.id) INTO candidate_ids FROM public."Invite" i
    WHERE i."tokenHash"=ANY(p_token_hash_candidates) AND i."usedAt" IS NULL AND i."expiresAt">p_checked_at;
  IF coalesce(array_length(candidate_ids,1),0)<>1 THEN RETURN; END IF;
  SELECT i.id,i."orgId",i."licenseeId",i.email,i.role,i."manufacturerId",i."tokenHash",i."expiresAt",i."usedAt"
    INTO invite_row FROM public."Invite" i WHERE i.id=candidate_ids[1];
  PERFORM set_config('app.b01_preauth_token_id',invite_row.id,true),set_config('app.b01_preauth_email',invite_row.email,true),
          set_config('app.b01_preauth_org_id',invite_row."orgId",true),set_config('app.b01_preauth_licensee_id',coalesce(invite_row."licenseeId",''),true);
  SELECT array_agg(u.id ORDER BY u.id) INTO candidate_user_ids FROM public."User" u WHERE lower(u.email)=invite_row.email;
  IF coalesce(array_length(candidate_user_ids,1),0)<>1 THEN RETURN; END IF;
  SELECT u.id,u.email,u.role,u."orgId",u."licenseeId",u.status,u."isActive",u."disabledAt",u."deletedAt",u."passwordHash"
    INTO actor_row FROM public."User" u WHERE u.id=candidate_user_ids[1];
  IF NOT FOUND OR actor_row.email<>invite_row.email OR NOT actor_row."isActive" OR actor_row.status<>'INVITED'::public."UserStatus"
     OR actor_row."disabledAt" IS NOT NULL OR actor_row."deletedAt" IS NOT NULL OR actor_row."passwordHash" IS NOT NULL
     OR (CASE WHEN actor_row.role::text IN ('LICENSEE_ADMIN','ORG_ADMIN') THEN 'LICENSEE_ADMIN' WHEN actor_row.role::text IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') THEN 'MANUFACTURER' ELSE actor_row.role::text END)
        IS DISTINCT FROM (CASE WHEN invite_row.role::text IN ('LICENSEE_ADMIN','ORG_ADMIN') THEN 'LICENSEE_ADMIN' WHEN invite_row.role::text IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') THEN 'MANUFACTURER' ELSE invite_row.role::text END)
     OR (invite_row.role::text IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') AND (actor_row."orgId" IS NOT NULL OR actor_row."licenseeId" IS NOT NULL))
     OR (invite_row.role::text NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') AND (actor_row."orgId" IS DISTINCT FROM invite_row."orgId" OR actor_row."licenseeId" IS DISTINCT FROM invite_row."licenseeId"))
     OR (invite_row."manufacturerId" IS NOT NULL AND actor_row.id IS DISTINCT FROM invite_row."manufacturerId") THEN RETURN; END IF;
  PERFORM set_config('app.b01_preauth_user_id',actor_row.id,true);
  IF NOT EXISTS (SELECT 1 FROM public."Organization" o WHERE o.id=invite_row."orgId" AND o."isActive") THEN RETURN; END IF;
  IF invite_row."licenseeId" IS NOT NULL THEN
    SELECT l.name INTO licensee_name FROM public."Licensee" l WHERE l.id=invite_row."licenseeId" AND l."orgId"=invite_row."orgId" AND l."isActive" AND l."suspendedAt" IS NULL;
    IF NOT FOUND THEN RETURN; END IF;
  END IF;
  RETURN QUERY SELECT invite_row.email,invite_row.role::text,invite_row."expiresAt",licensee_name,
    invite_row.role::text IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER');
END
$fn$;

CREATE OR REPLACE FUNCTION app_auth.consume_invitation_token(
  p_token_hash_candidates text[],p_new_password_hash text,p_requested_name text,p_consumed_at timestamp without time zone,
  p_request_id text,p_ip_hash text,p_user_agent text
) RETURNS TABLE("inviteId" text,"id" text,"email" text,"name" text,"role" text,"licenseeId" text,"orgId" text,"status" text)
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE invite_row record; actor_row record; candidate_ids text[]; candidate_user_ids text[]; requested_name text:=nullif(btrim(coalesce(p_requested_name,'')),''); changed integer;
BEGIN
  IF coalesce(array_length(p_token_hash_candidates,1),0) NOT BETWEEN 1 AND 3
     OR EXISTS (SELECT 1 FROM unnest(p_token_hash_candidates) h WHERE h IS NULL OR h !~ '^([0-9a-f]{12}:)?[0-9a-f]{64}$')
     OR (SELECT count(DISTINCT h) FROM unnest(p_token_hash_candidates) h)<>array_length(p_token_hash_candidates,1)
     OR p_new_password_hash IS NULL OR p_new_password_hash NOT LIKE '$argon2id$%' OR length(p_new_password_hash)>512
     OR (requested_name IS NOT NULL AND (length(requested_name)>120 OR requested_name~'[[:cntrl:]]'))
     OR p_consumed_at IS NULL OR abs(extract(epoch FROM (p_consumed_at-(clock_timestamp() AT TIME ZONE 'UTC'))))>300
     OR p_request_id IS NULL OR length(p_request_id) NOT BETWEEN 1 AND 128 OR p_request_id !~ '^[!-~]+$'
     OR (p_ip_hash IS NOT NULL AND p_ip_hash !~ '^([0-9a-f]{12}:)?[0-9a-f]{64}$')
     OR length(coalesce(p_user_agent,''))>512 OR coalesce(p_user_agent,'')~'[[:cntrl:]]' THEN
    RAISE EXCEPTION 'B01_INVITE_CONSUME_DENIED' USING ERRCODE='22023';
  END IF;
  PERFORM set_config('app.b01_preauth_operation','invite-consume',true),set_config('app.b01_preauth_email','',true),
          set_config('app.b01_preauth_hashes',array_to_string(p_token_hash_candidates,','),true),set_config('app.b01_preauth_token_id','',true),
          set_config('app.b01_preauth_user_id','',true),set_config('app.b01_preauth_org_id','',true),
          set_config('app.b01_preauth_licensee_id','',true),set_config('app.b01_preauth_pending_email','',true);
  SELECT array_agg(i.id ORDER BY i.id) INTO candidate_ids FROM public."Invite" i
    WHERE i."tokenHash"=ANY(p_token_hash_candidates) AND i."usedAt" IS NULL AND i."expiresAt">p_consumed_at;
  IF coalesce(array_length(candidate_ids,1),0)<>1 THEN RETURN; END IF;
  SELECT i.id,i."orgId",i."licenseeId",i.email,i.role,i."manufacturerId",i."tokenHash",i."expiresAt",i."usedAt"
    INTO invite_row FROM public."Invite" i WHERE i.id=candidate_ids[1];
  PERFORM set_config('app.b01_preauth_token_id',invite_row.id,true),set_config('app.b01_preauth_email',invite_row.email,true),
          set_config('app.b01_preauth_org_id',invite_row."orgId",true),set_config('app.b01_preauth_licensee_id',coalesce(invite_row."licenseeId",''),true);
  SELECT array_agg(u.id ORDER BY u.id) INTO candidate_user_ids FROM public."User" u WHERE lower(u.email)=invite_row.email;
  IF coalesce(array_length(candidate_user_ids,1),0)<>1 THEN RETURN; END IF;
  SELECT u.id,u.email,u."passwordHash",u.name,u.role,u."orgId",u."licenseeId",u.status,u."isActive",u."disabledAt",u."deletedAt"
    INTO actor_row FROM public."User" u WHERE u.id=candidate_user_ids[1];
  PERFORM set_config('app.b01_preauth_user_id',actor_row.id,true);
  SELECT u.id,u.email,u."passwordHash",u.name,u.role,u."orgId",u."licenseeId",u.status,u."isActive",u."disabledAt",u."deletedAt"
    INTO actor_row FROM public."User" u WHERE u.id=candidate_user_ids[1] FOR UPDATE;
  IF NOT FOUND THEN RETURN; END IF;
  SELECT i.id,i."orgId",i."licenseeId",i.email,i.role,i."manufacturerId",i."tokenHash",i."expiresAt",i."usedAt"
    INTO invite_row FROM public."Invite" i WHERE i.id=candidate_ids[1];
  IF NOT FOUND OR invite_row.email<>actor_row.email OR invite_row."usedAt" IS NOT NULL OR invite_row."expiresAt"<=p_consumed_at THEN RETURN; END IF;
  IF NOT FOUND OR actor_row.email<>invite_row.email OR NOT actor_row."isActive" OR actor_row.status<>'INVITED'::public."UserStatus"
     OR actor_row."disabledAt" IS NOT NULL OR actor_row."deletedAt" IS NOT NULL OR actor_row."passwordHash" IS NOT NULL
     OR (CASE WHEN actor_row.role::text IN ('LICENSEE_ADMIN','ORG_ADMIN') THEN 'LICENSEE_ADMIN' WHEN actor_row.role::text IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') THEN 'MANUFACTURER' ELSE actor_row.role::text END)
        IS DISTINCT FROM (CASE WHEN invite_row.role::text IN ('LICENSEE_ADMIN','ORG_ADMIN') THEN 'LICENSEE_ADMIN' WHEN invite_row.role::text IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') THEN 'MANUFACTURER' ELSE invite_row.role::text END)
     OR (invite_row.role::text IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') AND (actor_row."orgId" IS NOT NULL OR actor_row."licenseeId" IS NOT NULL))
     OR (invite_row.role::text NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') AND (actor_row."orgId" IS DISTINCT FROM invite_row."orgId" OR actor_row."licenseeId" IS DISTINCT FROM invite_row."licenseeId"))
     OR (invite_row."manufacturerId" IS NOT NULL AND actor_row.id IS DISTINCT FROM invite_row."manufacturerId") THEN RETURN; END IF;
  PERFORM set_config('app.b01_preauth_user_id',actor_row.id,true);
  IF NOT EXISTS (SELECT 1 FROM public."Organization" o WHERE o.id=invite_row."orgId" AND o."isActive")
     OR (invite_row."licenseeId" IS NOT NULL AND NOT EXISTS (SELECT 1 FROM public."Licensee" l WHERE l.id=invite_row."licenseeId" AND l."orgId"=invite_row."orgId" AND l."isActive" AND l."suspendedAt" IS NULL)) THEN RETURN; END IF;
  UPDATE public."User" u SET "passwordHash"=p_new_password_hash,name=coalesce(requested_name,u.name),status='ACTIVE'::public."UserStatus",
    "emailVerifiedAt"=p_consumed_at,"failedLoginAttempts"=0,"lockedUntil"=NULL,"updatedAt"=p_consumed_at WHERE u.id=actor_row.id;
  UPDATE public."Invite" i SET "usedAt"=p_consumed_at,"acceptedByUserId"=actor_row.id WHERE i.id=invite_row.id AND i."usedAt" IS NULL;
  GET DIAGNOSTICS changed=ROW_COUNT; IF changed<>1 THEN RAISE EXCEPTION 'B01_INVITE_REPLAY' USING ERRCODE='40001'; END IF;
  PERFORM app_auth.b01_preauth_audit('AUTH_INVITE_ACCEPTED','Invite',invite_row.id,p_consumed_at,
    jsonb_build_object('requestId',p_request_id,'targetUserId',actor_row.id,'email',actor_row.email,'role',actor_row.role::text,'ipHash',p_ip_hash,'userAgent',p_user_agent));
  RETURN QUERY SELECT invite_row.id,actor_row.id,actor_row.email,coalesce(requested_name,actor_row.name),actor_row.role::text,
    actor_row."licenseeId",actor_row."orgId",'ACTIVE'::text;
END
$fn$;

CREATE OR REPLACE FUNCTION app_auth.consume_email_verification_token(
  p_token_hash_candidates text[],p_consumed_at timestamp without time zone
) RETURNS TABLE("verified" boolean,"purpose" text,"userId" text,"email" text)
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE token_row record; actor_row record; candidate_ids text[]; changed integer; result_email text; audit_action text;
BEGIN
  IF coalesce(array_length(p_token_hash_candidates,1),0) NOT BETWEEN 1 AND 3
     OR EXISTS (SELECT 1 FROM unnest(p_token_hash_candidates) h WHERE h IS NULL OR h !~ '^([0-9a-f]{12}:)?[0-9a-f]{64}$')
     OR (SELECT count(DISTINCT h) FROM unnest(p_token_hash_candidates) h)<>array_length(p_token_hash_candidates,1)
     OR p_consumed_at IS NULL OR abs(extract(epoch FROM (p_consumed_at-(clock_timestamp() AT TIME ZONE 'UTC'))))>300 THEN
    RAISE EXCEPTION 'B01_EMAIL_VERIFICATION_DENIED' USING ERRCODE='22023';
  END IF;
  PERFORM set_config('app.b01_preauth_operation','email-consume',true),set_config('app.b01_preauth_email','',true),
          set_config('app.b01_preauth_hashes',array_to_string(p_token_hash_candidates,','),true),set_config('app.b01_preauth_token_id','',true),
          set_config('app.b01_preauth_user_id','',true),set_config('app.b01_preauth_org_id','',true),
          set_config('app.b01_preauth_licensee_id','',true),set_config('app.b01_preauth_pending_email','',true);
  SELECT array_agg(e.id ORDER BY e.id) INTO candidate_ids FROM public."EmailVerificationToken" e
    WHERE e."tokenHash"=ANY(p_token_hash_candidates) AND e."usedAt" IS NULL AND e."expiresAt">p_consumed_at;
  IF coalesce(array_length(candidate_ids,1),0)<>1 THEN RETURN; END IF;
  SELECT e.id,e."userId",e.email,e."pendingEmail",e.purpose,e."tokenHash",e."expiresAt",e."usedAt"
    INTO token_row FROM public."EmailVerificationToken" e WHERE e.id=candidate_ids[1];
  PERFORM set_config('app.b01_preauth_token_id',token_row.id,true),set_config('app.b01_preauth_user_id',token_row."userId",true),
          set_config('app.b01_preauth_pending_email',coalesce(token_row."pendingEmail",''),true);
  SELECT u.id,u.email,u."pendingEmail",u."orgId",u."licenseeId",u.status,u."isActive",u."disabledAt",u."deletedAt",u."emailVerifiedAt"
    INTO actor_row FROM public."User" u WHERE u.id=token_row."userId" FOR UPDATE;
  IF NOT FOUND OR NOT actor_row."isActive" OR actor_row.status='DISABLED'::public."UserStatus" OR actor_row."disabledAt" IS NOT NULL OR actor_row."deletedAt" IS NOT NULL THEN RETURN; END IF;
  SELECT e.id,e."userId",e.email,e."pendingEmail",e.purpose,e."tokenHash",e."expiresAt",e."usedAt"
    INTO token_row FROM public."EmailVerificationToken" e WHERE e.id=candidate_ids[1];
  IF NOT FOUND OR token_row."userId"<>actor_row.id OR token_row."usedAt" IS NOT NULL OR token_row."expiresAt"<=p_consumed_at
     OR token_row.purpose NOT IN ('EMAIL_CHANGE','EMAIL_VERIFICATION') THEN RETURN; END IF;
  PERFORM set_config('app.b01_preauth_org_id',coalesce(actor_row."orgId",''),true),set_config('app.b01_preauth_licensee_id',coalesce(actor_row."licenseeId",''),true);
  IF token_row.purpose='EMAIL_CHANGE' THEN
    IF token_row."pendingEmail" IS NULL OR lower(token_row."pendingEmail")<>token_row."pendingEmail"
       OR actor_row."pendingEmail" IS DISTINCT FROM token_row."pendingEmail"
       OR EXISTS (SELECT 1 FROM public."User" u WHERE lower(u.email)=token_row."pendingEmail" AND u.id<>actor_row.id) THEN RETURN; END IF;
    UPDATE public."User" u SET email=token_row."pendingEmail","pendingEmail"=NULL,"pendingEmailRequestedAt"=NULL,
      "emailVerifiedAt"=p_consumed_at,status='ACTIVE'::public."UserStatus","updatedAt"=p_consumed_at WHERE u.id=actor_row.id;
    UPDATE public."RefreshToken" r SET "revokedAt"=coalesce(r."revokedAt",p_consumed_at),"revokedReason"=coalesce(r."revokedReason",'EMAIL_CHANGE'),"lastUsedAt"=p_consumed_at,
      "sessionCapabilityRevokedAt"=coalesce(r."sessionCapabilityRevokedAt",p_consumed_at),"sessionCapabilityRevokedReason"=coalesce(r."sessionCapabilityRevokedReason",'EMAIL_CHANGE')
      WHERE r."userId"=actor_row.id AND (r."revokedAt" IS NULL OR r."sessionCapabilityRevokedAt" IS NULL);
    result_email:=token_row."pendingEmail"; audit_action:='AUTH_EMAIL_CHANGE_CONFIRMED';
  ELSE
    IF lower(token_row.email)<>lower(actor_row.email) THEN RETURN; END IF;
    UPDATE public."User" u SET "emailVerifiedAt"=coalesce(u."emailVerifiedAt",p_consumed_at),status='ACTIVE'::public."UserStatus","updatedAt"=p_consumed_at WHERE u.id=actor_row.id;
    result_email:=actor_row.email; audit_action:='AUTH_EMAIL_VERIFIED';
  END IF;
  UPDATE public."EmailVerificationToken" e SET "usedAt"=p_consumed_at WHERE e.id=token_row.id AND e."usedAt" IS NULL;
  GET DIAGNOSTICS changed=ROW_COUNT; IF changed<>1 THEN RAISE EXCEPTION 'B01_EMAIL_VERIFICATION_REPLAY' USING ERRCODE='40001'; END IF;
  PERFORM app_auth.b01_preauth_audit(audit_action,'User',actor_row.id,p_consumed_at,jsonb_build_object('email',result_email,'purpose',token_row.purpose));
  RETURN QUERY SELECT true,token_row.purpose,actor_row.id,result_email;
END
$fn$;

REVOKE ALL ON FUNCTION app_auth.b01_preauth_audit(text,text,text,timestamp without time zone,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_auth.lookup_password_user(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_auth.record_password_failure(text,timestamp without time zone,integer,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_auth.request_password_reset(text,text,timestamp without time zone,timestamp without time zone,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_auth.consume_password_reset_token(text[],text,timestamp without time zone) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_auth.lookup_invitation_token(text[],timestamp without time zone) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_auth.consume_invitation_token(text[],text,text,timestamp without time zone,text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_auth.consume_email_verification_token(text[],timestamp without time zone) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION app_auth.consume_email_verification_token(text[],timestamp without time zone) TO "mscqr_rls_cert_preauth";
GRANT EXECUTE ON FUNCTION app_auth.consume_invitation_token(text[],text,text,timestamp without time zone,text,text,text) TO "mscqr_rls_cert_preauth";
GRANT EXECUTE ON FUNCTION app_auth.consume_password_reset_token(text[],text,timestamp without time zone) TO "mscqr_rls_cert_preauth";
GRANT EXECUTE ON FUNCTION app_auth.lookup_invitation_token(text[],timestamp without time zone) TO "mscqr_rls_cert_preauth";
GRANT EXECUTE ON FUNCTION app_auth.lookup_password_user(text) TO "mscqr_rls_cert_preauth";
GRANT EXECUTE ON FUNCTION app_auth.record_password_failure(text,timestamp without time zone,integer,integer) TO "mscqr_rls_cert_preauth";
GRANT EXECUTE ON FUNCTION app_auth.request_password_reset(text,text,timestamp without time zone,timestamp without time zone,text,text) TO "mscqr_rls_cert_preauth";
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
-- Release Fix 1: exact login, logout, /auth/me, recent-MFA and risk boundaries.
-- Authenticated functions consume only context installed by the reviewed
-- app_auth.require_authenticated_session boundary in the same transaction.
-- Login functions consume the subject bound by app_auth.lookup_password_user;
-- they never inspect caller-selected tenant/user context.

CREATE OR REPLACE FUNCTION app_rls.b01_authenticated_actor(
  p_expected_user_id text,p_expected_session_id text,p_request_id text
) RETURNS TABLE(
  "sessionId" text,"userId" text,"role" text,"organizationId" text,
  "licenseeId" text,"manufacturerId" text,"authAssurance" text
)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record;
BEGIN
  IF current_setting('app.auth_session_verified',true)<>'1'
     OR current_setting('app.auth_session_id',true) IS DISTINCT FROM p_expected_session_id
     OR current_setting('app.user_id',true) IS DISTINCT FROM p_expected_user_id
     OR current_setting('app.request_id',true) IS DISTINCT FROM p_request_id THEN
    RAISE EXCEPTION 'AUTH_SESSION_CAPABILITY_DENIED' USING ERRCODE='42501';
  END IF;
  SELECT u.id,u.role::text AS role,u."orgId",u."licenseeId",rt.id AS session_id,
         rt."sessionCapabilityAssurance" AS assurance
    INTO actor
    FROM public."RefreshToken" rt JOIN public."User" u ON u.id=rt."userId"
   WHERE rt.id=p_expected_session_id AND rt."userId"=p_expected_user_id
     AND rt."sessionCapabilityHash"=current_setting('app.auth_session_hash',true)
     AND rt."sessionCapabilityHashVersion"='sha256-v1'
     AND rt."sessionCapabilityRevokedAt" IS NULL AND rt."sessionCapabilityExpiresAt">clock_timestamp()
     AND rt."revokedAt" IS NULL AND rt."expiresAt">clock_timestamp()
     AND u."isActive" AND u.status='ACTIVE'::public."UserStatus"
     AND u."disabledAt" IS NULL AND u."deletedAt" IS NULL;
  IF NOT FOUND THEN RAISE EXCEPTION 'AUTH_SESSION_CAPABILITY_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM set_config('app.auth_closure_operation','actor',true),
          set_config('app.auth_closure_session_id',actor.session_id,true),
          set_config('app.auth_closure_user_id',actor.id,true),
          set_config('app.auth_closure_role',actor.role,true),
          set_config('app.auth_closure_organization_id',coalesce(actor."orgId",''),true),
          set_config('app.auth_closure_licensee_id',coalesce(actor."licenseeId",''),true);
  RETURN QUERY SELECT actor.session_id::text,actor.id::text,actor.role::text,actor."orgId"::text,
    actor."licenseeId"::text,CASE WHEN actor.role IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') THEN actor.id::text END,
    CASE actor.assurance WHEN 'ADMIN_MFA' THEN 'mfa-verified' ELSE 'password-verified' END;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.revalidate_authenticated_actor(
  p_user_id text,p_session_id text,p_requested_licensee_id text,p_requested_organization_id text,
  p_checked_at timestamp without time zone,p_request_id text
) RETURNS TABLE("userId" text,"role" text,"organizationId" text,"licenseeId" text,"manufacturerId" text,"authAssurance" text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record;
BEGIN
  IF p_checked_at IS NULL OR abs(extract(epoch FROM (p_checked_at-clock_timestamp())))>300 THEN
    RAISE EXCEPTION 'AUTH_SESSION_CAPABILITY_DENIED' USING ERRCODE='42501';
  END IF;
  SELECT * INTO actor FROM app_rls.b01_authenticated_actor(p_user_id,p_session_id,p_request_id);
  IF actor.role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') THEN
    IF p_requested_licensee_id IS NOT NULL OR p_requested_organization_id IS NOT NULL THEN RETURN; END IF;
  ELSIF actor.role IN ('LICENSEE_ADMIN','ORG_ADMIN') THEN
    IF p_requested_licensee_id IS DISTINCT FROM actor."licenseeId" OR p_requested_organization_id IS DISTINCT FROM actor."organizationId"
       OR NOT EXISTS (SELECT 1 FROM public."Licensee" l JOIN public."Organization" o ON o.id=l."orgId"
         WHERE l.id=actor."licenseeId" AND l."orgId"=actor."organizationId" AND l."isActive" AND l."suspendedAt" IS NULL AND o."isActive") THEN RETURN; END IF;
  ELSIF actor.role IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') THEN
    IF p_requested_licensee_id IS NULL OR p_requested_organization_id IS NULL OR NOT EXISTS (
      SELECT 1 FROM public."ManufacturerLicenseeLink" ml JOIN public."Licensee" l ON l.id=ml."licenseeId"
      JOIN public."Organization" o ON o.id=l."orgId" WHERE ml."manufacturerId"=actor."userId"
        AND ml."licenseeId"=p_requested_licensee_id AND l."orgId"=p_requested_organization_id
        AND l."isActive" AND l."suspendedAt" IS NULL AND o."isActive") THEN RETURN; END IF;
  END IF;
  RETURN QUERY SELECT actor."userId"::text,actor.role::text,actor."organizationId"::text,
    CASE WHEN actor.role IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') THEN p_requested_licensee_id ELSE actor."licenseeId" END,
    actor."manufacturerId"::text,actor."authAssurance"::text;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.load_authenticated_actor()
RETURNS TABLE(
  "id" text,"email" text,"name" text,"role" text,"licenseeId" text,"orgId" text,
  "emailVerifiedAt" timestamp without time zone,"pendingEmail" text,"pendingEmailRequestedAt" timestamp without time zone,
  "isActive" boolean,"status" text,"deletedAt" timestamp without time zone,"disabledAt" timestamp without time zone,
  "createdAt" timestamp without time zone,"licenseeRecordId" text,"licenseeName" text,
  "licenseePrefix" text,"licenseeBrandName" text,"licenseeOrgId" text
)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record;
BEGIN
  SELECT * INTO actor FROM app_rls.b01_authenticated_actor(current_setting('app.user_id',true),current_setting('app.auth_session_id',true),current_setting('app.request_id',true));
  RETURN QUERY SELECT u.id::text,u.email::text,u.name::text,u.role::text,u."licenseeId"::text,u."orgId"::text,
    u."emailVerifiedAt",u."pendingEmail"::text,u."pendingEmailRequestedAt",u."isActive",u.status::text,u."deletedAt",u."disabledAt",u."createdAt",
    l.id::text,l.name::text,l.prefix::text,l."brandName"::text,l."orgId"::text
  FROM public."User" u LEFT JOIN public."Licensee" l ON l.id=u."licenseeId"
  WHERE u.id=actor."userId" AND u."isActive" AND u.status='ACTIVE'::public."UserStatus" AND u."disabledAt" IS NULL AND u."deletedAt" IS NULL;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.find_refresh_token_by_id(p_session_id text,p_user_id text)
RETURNS TABLE("id" text,"userId" text,"orgId" text,"expiresAt" timestamp without time zone,"createdAt" timestamp without time zone,
  "createdIpHash" text,"createdUserAgent" text,"authenticatedAt" timestamp without time zone,"mfaVerifiedAt" timestamp without time zone,
  "lastUsedAt" timestamp without time zone,"revokedAt" timestamp without time zone,"revokedReason" text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
BEGIN
  PERFORM app_rls.b01_authenticated_actor(p_user_id,p_session_id,current_setting('app.request_id',true));
  RETURN QUERY SELECT rt.id::text,rt."userId"::text,rt."orgId"::text,rt."expiresAt",rt."createdAt",rt."createdIpHash"::text,
    rt."createdUserAgent"::text,rt."authenticatedAt",rt."mfaVerifiedAt",rt."lastUsedAt",rt."revokedAt",rt."revokedReason"::text
  FROM public."RefreshToken" rt WHERE rt.id=p_session_id AND rt."userId"=p_user_id;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.revoke_refresh_token_by_id(
  p_session_id text,p_user_id text,p_reason text,p_revoked_at timestamp without time zone
) RETURNS TABLE("revoked" boolean)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE changed integer;
BEGIN
  IF p_reason NOT IN ('SESSION_REVOKED_BY_USER','LOGOUT','STEP_UP_REPLACED') OR p_revoked_at IS NULL
     OR abs(extract(epoch FROM (p_revoked_at-clock_timestamp())))>300 THEN
    RAISE EXCEPTION 'AUTH_SESSION_REVOCATION_DENIED' USING ERRCODE='42501';
  END IF;
  PERFORM app_rls.b01_authenticated_actor(p_user_id,p_session_id,current_setting('app.request_id',true));
  PERFORM set_config('app.auth_session_operation','revoke-one',true),set_config('app.auth_session_target_id',p_session_id,true);
  UPDATE public."RefreshToken" rt SET "revokedAt"=clock_timestamp(),"revokedReason"=p_reason,"lastUsedAt"=clock_timestamp(),
    "sessionCapabilityRevokedAt"=clock_timestamp(),"sessionCapabilityRevokedReason"=p_reason
  WHERE rt.id=p_session_id AND rt."userId"=p_user_id AND rt."revokedAt" IS NULL;
  GET DIAGNOSTICS changed=ROW_COUNT;
  RETURN QUERY SELECT changed=1;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.require_recent_mfa_session(
  p_session_id text,p_checked_at timestamp without time zone,p_max_age_minutes integer
) RETURNS TABLE("verifiedAt" timestamp without time zone)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record;
BEGIN
  IF p_checked_at IS NULL OR abs(extract(epoch FROM (p_checked_at-clock_timestamp())))>300 OR p_max_age_minutes NOT BETWEEN 1 AND 1440 THEN
    RAISE EXCEPTION 'RECENT_MFA_DENIED' USING ERRCODE='42501';
  END IF;
  SELECT * INTO actor FROM app_rls.b01_authenticated_actor(current_setting('app.user_id',true),p_session_id,current_setting('app.request_id',true));
  IF actor."authAssurance" NOT IN ('mfa-verified','step-up-verified') THEN RETURN; END IF;
  RETURN QUERY SELECT rt."mfaVerifiedAt" FROM public."RefreshToken" rt WHERE rt.id=p_session_id AND rt."userId"=actor."userId"
    AND rt."revokedAt" IS NULL AND rt."expiresAt">p_checked_at
    AND rt."mfaVerifiedAt" BETWEEN p_checked_at-(p_max_age_minutes*interval '1 minute') AND p_checked_at+interval '5 minutes';
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.load_recent_auth_session_risk_inputs(p_limit integer)
RETURNS TABLE("createdIpHash" text,"createdUserAgent" text,"createdAt" timestamp without time zone,"actorState" jsonb)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE user_id text := current_setting('app.b01_preauth_user_id',true); actor record; selected record; links jsonb; methods text[]; mfa_enabled boolean; mfa_last timestamp without time zone; actor_state jsonb;
BEGIN
  IF user_id='' OR p_limit NOT BETWEEN 1 AND 5 THEN RAISE EXCEPTION 'AUTH_LOGIN_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;
  SELECT NULL::text AS id,NULL::text AS name,NULL::text AS prefix,NULL::text AS "brandName",NULL::text AS "orgId",NULL::timestamp AS "updatedAt" INTO selected;
  PERFORM set_config('app.auth_closure_operation','login-risk-read',true),set_config('app.auth_closure_user_id',user_id,true);
  SELECT u.id,u.email,u.name,u.role::text AS role,u."orgId",u."licenseeId",u."emailVerifiedAt"
    INTO actor FROM public."User" u WHERE u.id=user_id AND u."isActive" AND u.status='ACTIVE'::public."UserStatus"
      AND u."disabledAt" IS NULL AND u."deletedAt" IS NULL AND u."emailVerifiedAt" IS NOT NULL;
  IF NOT FOUND THEN RAISE EXCEPTION 'AUTH_LOGIN_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM set_config('app.auth_closure_organization_id',coalesce(actor."orgId",''),true),
          set_config('app.auth_closure_licensee_id',coalesce(actor."licenseeId",''),true);
  SELECT coalesce(bool_or(x.enabled),false),max(x."lastUsedAt"),coalesce(array_agg(DISTINCT x.method) FILTER (WHERE x.enabled),'{}'::text[])
    INTO mfa_enabled,mfa_last,methods FROM (
      SELECT "isEnabled" AS enabled,"lastUsedAt",'TOTP'::text AS method FROM public."AdminMfaCredential" WHERE "userId"=user_id
      UNION ALL SELECT TRUE,"lastUsedAt",'WEBAUTHN' FROM public."AdminWebAuthnCredential" WHERE "userId"=user_id
      UNION ALL SELECT TRUE,"lastUsedAt",type FROM public."UserMfaFactor" WHERE "userId"=user_id AND "disabledAt" IS NULL AND type IN ('TOTP','WEBAUTHN')
    ) x;
  IF EXISTS (SELECT 1 FROM public."UserBackupCode" WHERE "userId"=user_id AND "usedAt" IS NULL) AND 'TOTP'=ANY(methods) THEN methods:=array_append(methods,'BACKUP_CODE'); END IF;
  IF actor.role IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') THEN
    SELECT l.id,l.name,l.prefix,l."brandName",l."orgId",ml."updatedAt" INTO selected
      FROM public."ManufacturerLicenseeLink" ml JOIN public."Licensee" l ON l.id=ml."licenseeId" JOIN public."Organization" o ON o.id=l."orgId"
      WHERE ml."manufacturerId"=user_id AND l."isActive" AND l."suspendedAt" IS NULL AND o."isActive"
      ORDER BY ml."isPrimary" DESC,ml."createdAt",ml."licenseeId" LIMIT 1;
    SELECT coalesce(jsonb_agg(jsonb_build_object('id',l.id,'name',l.name,'prefix',l.prefix,'brandName',l."brandName",'orgId',l."orgId",'isPrimary',ml."isPrimary",'scopeVersion',to_char(ml."updatedAt" AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')) ORDER BY ml."isPrimary" DESC,ml."createdAt",ml."licenseeId"),'[]'::jsonb)
      INTO links FROM public."ManufacturerLicenseeLink" ml JOIN public."Licensee" l ON l.id=ml."licenseeId" JOIN public."Organization" o ON o.id=l."orgId"
      WHERE ml."manufacturerId"=user_id AND l."isActive" AND l."suspendedAt" IS NULL AND o."isActive";
  ELSE
    IF actor."licenseeId" IS NOT NULL THEN
      SELECT l.id,l.name,l.prefix,l."brandName",l."orgId",NULL::timestamp AS "updatedAt" INTO selected
        FROM public."Licensee" l JOIN public."Organization" o ON o.id=l."orgId"
        WHERE l.id=actor."licenseeId" AND l."orgId"=actor."orgId" AND l."isActive" AND l."suspendedAt" IS NULL AND o."isActive";
      IF NOT FOUND THEN RAISE EXCEPTION 'AUTH_LOGIN_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;
    END IF;
    links:='[]'::jsonb;
  END IF;
  actor_state:=jsonb_build_object(
    'userId',actor.id,'email',actor.email,'name',actor.name,'role',actor.role,'legacyLicenseeId',actor."licenseeId",'legacyOrganizationId',actor."orgId",
    'emailVerifiedAt',actor."emailVerifiedAt",'sessionLicenseeId',selected.id,'sessionOrganizationId',CASE WHEN selected.id IS NULL THEN actor."orgId" ELSE selected."orgId" END,
    'scopeVersion',CASE WHEN actor.role IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') THEN to_char(selected."updatedAt" AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') END,
    'selectedLicenseeId',selected.id,'selectedLicenseeName',selected.name,'selectedLicenseePrefix',selected.prefix,'selectedLicenseeBrandName',selected."brandName",'selectedLicenseeOrganizationId',selected."orgId",
    'linkedLicensees',links,'mfaRequired',actor.role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN','LICENSEE_ADMIN','ORG_ADMIN','MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER'),
    'mfaEnabled',mfa_enabled,'mfaEnrolled',mfa_enabled,'mfaLastUsedAt',mfa_last,'mfaMethods',methods,
    'mfaPreferredMethod',CASE WHEN 'WEBAUTHN'=ANY(methods) THEN 'WEBAUTHN' WHEN 'TOTP'=ANY(methods) THEN 'TOTP' ELSE NULL END);
  RETURN QUERY SELECT recent."createdIpHash",recent."createdUserAgent",recent."createdAt",actor_state FROM (
    SELECT rt."createdIpHash"::text,rt."createdUserAgent"::text,rt."createdAt" FROM public."RefreshToken" rt
      WHERE rt."userId"=user_id ORDER BY rt."createdAt" DESC,rt.id LIMIT p_limit
  ) recent;
  IF NOT FOUND THEN RETURN QUERY SELECT NULL::text,NULL::text,NULL::timestamp,actor_state; END IF;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.record_auth_session_risk_signal(
  p_risk_score integer,p_risk_level text,p_reasons text[],p_ip_hash text,p_user_agent_hash text,p_recorded_at timestamp without time zone,
  p_password_hash text,p_challenge_ticket_hash text,p_challenge_session_hash text,p_challenge_expires_at timestamp without time zone,
  p_challenge_max_attempts integer,p_request_id text
) RETURNS TABLE("recorded" boolean,"challengeCreated" boolean)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE user_id text := current_setting('app.b01_preauth_user_id',true); challenge_id text; wants_challenge boolean := p_challenge_ticket_hash IS NOT NULL;
BEGIN
  IF user_id='' OR p_risk_score NOT BETWEEN 0 AND 100 OR p_risk_level NOT IN ('LOW','MEDIUM','HIGH','CRITICAL')
     OR cardinality(p_reasons)>12 OR p_recorded_at IS NULL OR abs(extract(epoch FROM (p_recorded_at-clock_timestamp())))>300
     OR p_request_id IS NULL OR length(p_request_id) NOT BETWEEN 1 AND 128
     OR (p_password_hash IS NOT NULL AND p_password_hash !~ '^\$argon2(id|i|d)\$')
     OR wants_challenge IS DISTINCT FROM (p_challenge_session_hash IS NOT NULL AND p_challenge_expires_at IS NOT NULL AND p_challenge_max_attempts IS NOT NULL)
     OR (wants_challenge AND (p_challenge_ticket_hash !~ '^([0-9a-f]{12}:)?[a-f0-9]{64}$' OR p_challenge_session_hash !~ '^([0-9a-f]{12}:)?[a-f0-9]{64}$'
       OR p_challenge_max_attempts NOT BETWEEN 1 AND 10 OR p_challenge_expires_at<=p_recorded_at OR p_challenge_expires_at>p_recorded_at+interval '15 minutes')) THEN
    RAISE EXCEPTION 'AUTH_LOGIN_RISK_DENIED' USING ERRCODE='42501';
  END IF;
  PERFORM set_config('app.auth_closure_operation','login-risk-write',true),set_config('app.auth_closure_user_id',user_id,true);
  PERFORM set_config('app.auth_closure_request_id',p_request_id,true);
  UPDATE public."User" u SET "failedLoginAttempts"=0,"lockedUntil"=NULL,"lastLoginAt"=p_recorded_at,"updatedAt"=p_recorded_at,
    "passwordHash"=coalesce(p_password_hash,u."passwordHash")
    WHERE u.id=user_id AND u."isActive" AND u.status='ACTIVE'::public."UserStatus" AND u."disabledAt" IS NULL AND u."deletedAt" IS NULL;
  IF NOT FOUND THEN RAISE EXCEPTION 'AUTH_LOGIN_RISK_DENIED' USING ERRCODE='42501'; END IF;
  INSERT INTO public."AuthSessionRiskSignal"(id,"userId","riskScore","riskLevel",reasons,"ipHash","userAgentHash","createdAt")
  VALUES (gen_random_uuid()::text,user_id,p_risk_score,p_risk_level::public."AuthRiskLevel",p_reasons,p_ip_hash,p_user_agent_hash,p_recorded_at);
  IF wants_challenge THEN
    challenge_id:=gen_random_uuid()::text;
    PERFORM set_config('app.auth_closure_operation','login-mfa-challenge',true),set_config('app.auth_closure_challenge_id',challenge_id,true),
            set_config('app.auth_closure_challenge_hash',p_challenge_ticket_hash,true);
    INSERT INTO public."MfaLoginChallenge"(id,"userId","ticketHash",purpose,"riskScore","riskLevel",reasons,"createdIpHash","createdUserAgentHash",attempts,"maxAttempts","createdAt","updatedAt","expiresAt")
      VALUES (challenge_id,user_id,p_challenge_ticket_hash,'admin_login',p_risk_score,p_risk_level::public."AuthRiskLevel",p_reasons,p_ip_hash,p_user_agent_hash,0,p_challenge_max_attempts,p_recorded_at,p_recorded_at,p_challenge_expires_at);
    INSERT INTO public."AuditLogOutbox"(id,payload,"requestId","initiatingUserId","expiresAt","updatedAt") VALUES (
      gen_random_uuid()::text,jsonb_build_object('userId',user_id,'action','AUTH_MFA_CHALLENGE_ISSUED','entityType','MfaLoginChallenge','entityId',challenge_id,'details',jsonb_build_object('purpose','admin_login','riskScore',p_risk_score,'riskLevel',p_risk_level)),
      p_request_id,user_id,p_recorded_at+interval '1 day',p_recorded_at);
  END IF;
  RETURN QUERY SELECT true,wants_challenge;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.create_refresh_token(
  p_user_id text,p_organization_id text,p_token_hash text,p_expires_at timestamp without time zone,p_ip_hash text,p_user_agent text,
  p_authenticated_at timestamp without time zone,p_mfa_verified_at timestamp without time zone,p_created_at timestamp without time zone
) RETURNS TABLE("id" text,"expiresAt" timestamp without time zone)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE token_id text := gen_random_uuid()::text; actor record;
BEGIN
  IF p_user_id IS DISTINCT FROM current_setting('app.b01_preauth_user_id',true)
     OR p_token_hash !~ '^([0-9a-f]{12}:)?[a-f0-9]{64}$' OR p_expires_at<=p_created_at
     OR p_expires_at>p_created_at+interval '31 days' THEN RAISE EXCEPTION 'AUTH_LOGIN_SESSION_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM set_config('app.auth_closure_operation','login-session-create',true),set_config('app.auth_closure_user_id',p_user_id,true),
          set_config('app.auth_closure_organization_id',coalesce(p_organization_id,''),true),set_config('app.auth_closure_token_id',token_id,true),
          set_config('app.auth_closure_token_hash',p_token_hash,true);
  SELECT u.id,u.role::text AS role,u."orgId",u."licenseeId" INTO actor FROM public."User" u WHERE u.id=p_user_id AND u."isActive"
    AND u.status='ACTIVE'::public."UserStatus" AND u."disabledAt" IS NULL AND u."deletedAt" IS NULL AND u."emailVerifiedAt" IS NOT NULL;
  IF NOT FOUND THEN RAISE EXCEPTION 'AUTH_LOGIN_SESSION_DENIED' USING ERRCODE='42501'; END IF;
  IF actor.role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') AND p_organization_id IS NOT NULL THEN RAISE EXCEPTION 'AUTH_LOGIN_SESSION_DENIED' USING ERRCODE='42501';
  ELSIF actor.role IN ('LICENSEE_ADMIN','ORG_ADMIN') AND p_organization_id IS DISTINCT FROM actor."orgId" THEN RAISE EXCEPTION 'AUTH_LOGIN_SESSION_DENIED' USING ERRCODE='42501';
  ELSIF actor.role IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') AND NOT EXISTS (
    SELECT 1 FROM public."ManufacturerLicenseeLink" ml JOIN public."Licensee" l ON l.id=ml."licenseeId" JOIN public."Organization" o ON o.id=l."orgId"
    WHERE ml."manufacturerId"=actor.id AND l."orgId"=p_organization_id AND l."isActive" AND l."suspendedAt" IS NULL AND o."isActive")
  THEN RAISE EXCEPTION 'AUTH_LOGIN_SESSION_DENIED' USING ERRCODE='42501'; END IF;
  INSERT INTO public."RefreshToken"(id,"orgId","userId","tokenHash","expiresAt","createdAt","createdIpHash","createdUserAgent","authenticatedAt","mfaVerifiedAt","lastUsedAt")
  VALUES (token_id,p_organization_id,p_user_id,p_token_hash,p_expires_at,p_created_at,p_ip_hash,p_user_agent,p_authenticated_at,p_mfa_verified_at,p_created_at);
  INSERT INTO public."AuditLogOutbox"(id,payload,"requestId","organizationId","initiatingUserId","initiatingActorRoleSnapshot","expiresAt","updatedAt") VALUES (
    gen_random_uuid()::text,jsonb_build_object('userId',p_user_id,'orgId',p_organization_id,'action',CASE WHEN p_mfa_verified_at IS NULL THEN 'AUTH_LOGIN_SUCCESS' ELSE 'AUTH_LOGIN_SUCCESS_RECENT_ADMIN_MFA' END,'entityType','User','entityId',p_user_id),
    nullif(current_setting('app.auth_closure_request_id',true),''),p_organization_id,p_user_id,actor.role,p_created_at+interval '1 day',p_created_at);
  RETURN QUERY SELECT token_id,p_expires_at;
END
$fn$;

REVOKE ALL ON FUNCTION app_rls.b01_authenticated_actor(text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.revalidate_authenticated_actor(text,text,text,text,timestamp without time zone,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.load_authenticated_actor() FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.find_refresh_token_by_id(text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.revoke_refresh_token_by_id(text,text,text,timestamp without time zone) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.require_recent_mfa_session(text,timestamp without time zone,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.load_recent_auth_session_risk_inputs(integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.record_auth_session_risk_signal(integer,text,text[],text,text,timestamp without time zone,text,text,text,timestamp without time zone,integer,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.create_refresh_token(text,text,text,timestamp without time zone,text,text,timestamp without time zone,timestamp without time zone,timestamp without time zone) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION app_rls.create_refresh_token(text,text,text,timestamp without time zone,text,text,timestamp without time zone,timestamp without time zone,timestamp without time zone) TO "mscqr_rls_cert_preauth";
GRANT EXECUTE ON FUNCTION app_rls.load_recent_auth_session_risk_inputs(integer) TO "mscqr_rls_cert_preauth";
GRANT EXECUTE ON FUNCTION app_rls.record_auth_session_risk_signal(integer,text,text[],text,text,timestamp without time zone,text,text,text,timestamp without time zone,integer,text) TO "mscqr_rls_cert_preauth";
GRANT EXECUTE ON FUNCTION app_rls.find_refresh_token_by_id(text,text) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.load_authenticated_actor() TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.require_recent_mfa_session(text,timestamp without time zone,integer) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.revalidate_authenticated_actor(text,text,text,text,timestamp without time zone,text) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.revoke_refresh_token_by_id(text,text,text,timestamp without time zone) TO "mscqr_rls_cert_app";
RESET ROLE;
DO $$ BEGIN
  IF NOT pg_has_role(session_user,'mscqr_rls_cert_owner','SET') THEN RAISE EXCEPTION 'administrative executor lacks SET authority for mscqr_rls_cert_owner'; END IF;
END $$;
SET ROLE "mscqr_rls_cert_owner";
REVOKE CREATE ON SCHEMA app_rls FROM "mscqr_rls_cert_auth_owner";
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
CREATE OR REPLACE FUNCTION app_rls.session_c_bind_admin(
  p_capability text,p_purpose text,p_request_id text,p_allow_tenant boolean
) RETURNS TABLE("sessionId" text,"userId" text,"role" text,"organizationId" text,"licenseeId" text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record;
BEGIN
  IF p_purpose NOT IN (
    'administration-create-licensee','administration-update-licensee','administration-delete-licensee',
    'administration-create-user','administration-update-user','administration-delete-user',
    'administration-restore-manufacturer','auth-invite-create','licensee-admin-invite-resend'
  ) OR p_request_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' THEN
    RAISE EXCEPTION 'SESSION_C_INVALID_CONTEXT' USING ERRCODE='42501';
  END IF;
  SELECT * INTO actor FROM app_auth.require_authenticated_session(p_capability,p_purpose,p_request_id);
  IF actor.assurance<>'ADMIN_MFA' OR actor.role NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN','LICENSEE_ADMIN')
     OR (NOT p_allow_tenant AND actor.role='LICENSEE_ADMIN') THEN
    RAISE EXCEPTION 'SESSION_C_WRONG_ROLE' USING ERRCODE='42501';
  END IF;
  IF actor.role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') AND (actor."organizationId" IS NOT NULL OR actor."licenseeId" IS NOT NULL) THEN
    RAISE EXCEPTION 'SESSION_C_STALE_PLATFORM_SCOPE' USING ERRCODE='42501';
  END IF;
  PERFORM set_config('app.admin_mutation_session_id',actor."sessionId",true),
          set_config('app.admin_mutation_user_id',actor."userId",true),
          set_config('app.admin_mutation_role',actor.role,true),
          set_config('app.admin_mutation_organization_id',coalesce(actor."organizationId",''),true),
          set_config('app.admin_mutation_licensee_id',coalesce(actor."licenseeId",''),true),
          set_config('app.admin_mutation_operation',p_purpose,true),
          set_config('app.admin_mutation_target_user_id','',true),
          set_config('app.admin_mutation_target_licensee_id','',true),
          set_config('app.admin_mutation_target_organization_id','',true),
          set_config('app.admin_mutation_target_email','',true),
          set_config('app.admin_mutation_target_prefix','',true),
          set_config('app.admin_mutation_audit_id','',true),
          set_config('app.admin_mutation_outbox_id','',true),
          set_config('app.admin_mutation_invite_id','',true),
          set_config('app.admin_mutation_idempotency_hash','',true);
  PERFORM app_rls.session_c_set_target(actor."licenseeId",actor."organizationId",NULL,NULL,NULL);
  IF actor.role='LICENSEE_ADMIN' AND NOT EXISTS (
    SELECT 1 FROM public."Licensee" l JOIN public."Organization" o ON o.id=l."orgId"
     WHERE l.id=actor."licenseeId" AND l."orgId"=actor."organizationId"
       AND l."isActive" AND l."suspendedAt" IS NULL AND o."isActive"
  ) THEN RAISE EXCEPTION 'SESSION_C_FOREIGN_SCOPE' USING ERRCODE='42501'; END IF;
  RETURN QUERY SELECT actor."sessionId"::text,actor."userId"::text,actor.role::text,
    actor."organizationId"::text,actor."licenseeId"::text;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.session_c_set_target(
  p_licensee_id text,p_organization_id text,p_user_id text,p_email text,p_prefix text
) RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
BEGIN
  PERFORM set_config('app.admin_mutation_target_licensee_id',coalesce(p_licensee_id,''),true),
          set_config('app.admin_mutation_target_organization_id',coalesce(p_organization_id,''),true),
          set_config('app.admin_mutation_target_user_id',coalesce(p_user_id,''),true),
          set_config('app.admin_mutation_target_email',coalesce(p_email,''),true),
          set_config('app.admin_mutation_target_prefix',coalesce(p_prefix,''),true);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.session_c_user_projection(p_target_id text)
RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
  SELECT jsonb_build_object(
    'id',u.id,'email',u.email,'name',u.name,'role',u.role::text,'licenseeId',u."licenseeId",
    'isActive',u."isActive",'deletedAt',u."deletedAt",'createdAt',u."createdAt",
    'location',u.location,'website',u.website,
    'licensee',CASE WHEN l.id IS NULL THEN NULL ELSE jsonb_build_object(
      'id',l.id,'name',l.name,'prefix',l.prefix,'brandName',l."brandName") END,
    'manufacturerLicenseeLinks',COALESCE((SELECT jsonb_agg(jsonb_build_object(
      'licenseeId',ml."licenseeId",'isPrimary',ml."isPrimary",'licensee',jsonb_build_object(
        'id',ll.id,'name',ll.name,'prefix',ll.prefix,'brandName',ll."brandName",'orgId',ll."orgId")
      ) ORDER BY ml."isPrimary" DESC,ml."createdAt")
      FROM public."ManufacturerLicenseeLink" ml JOIN public."Licensee" ll ON ll.id=ml."licenseeId"
      WHERE ml."manufacturerId"=u.id),'[]'::jsonb)
  ) FROM public."User" u LEFT JOIN public."Licensee" l ON l.id=u."licenseeId" WHERE u.id=p_target_id
$fn$;

CREATE OR REPLACE FUNCTION app_rls.session_c_write_audit(
  p_actor_id text,p_organization_id text,p_licensee_id text,p_action text,p_entity_type text,
  p_entity_id text,p_details jsonb,p_ip_hash text,p_user_agent text
) RETURNS text LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE audit_id text:=gen_random_uuid()::text; outbox_id text:=gen_random_uuid()::text; created_at timestamp without time zone:=transaction_timestamp();
BEGIN
  IF p_action !~ '^[A-Z0-9_]{1,120}$' OR p_entity_type NOT IN ('Licensee','User','Invite')
     OR (p_ip_hash IS NOT NULL AND p_ip_hash !~ '^([0-9a-f]{12}:)?[a-f0-9]{64}$')
     OR length(coalesce(p_user_agent,''))>512 THEN RAISE EXCEPTION 'SESSION_C_INVALID_AUDIT'; END IF;
  PERFORM set_config('app.admin_mutation_audit_id',audit_id,true),set_config('app.admin_mutation_outbox_id',outbox_id,true);
  INSERT INTO public."AuditLog" (id,"userId","orgId","licenseeId",action,"entityType","entityId",details,"ipHash","userAgent","createdAt")
  VALUES (audit_id,p_actor_id,p_organization_id,p_licensee_id,p_action,p_entity_type,p_entity_id,p_details,p_ip_hash,p_user_agent,created_at);
  INSERT INTO public."SecurityEventOutbox" (id,"eventType",payload,"requestId","organizationId","licenseeId","initiatingUserId","updatedAt")
  VALUES (outbox_id,'AUDIT_LOG',jsonb_build_object(
    'id',audit_id,'action',p_action,'entityType',p_entity_type,'entityId',p_entity_id,
    'userId',p_actor_id,'orgId',p_organization_id,'licenseeId',p_licensee_id,
    'details',p_details,'createdAt',created_at
  ),current_setting('app.request_id',true),p_organization_id,p_licensee_id,p_actor_id,created_at);
  RETURN audit_id;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.session_c_admin_command(
  p_capability text,p_purpose text,p_request_id text,p_command text,payload jsonb
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE
  actor record; target text; target_licensee text; target_org text; target_role text; new_user_id text;
  result jsonb; patch jsonb; hard_delete boolean; remaining record; affected integer:=0;
  idempotency_key text; key_hash text; request_hash text; prior record;
  audit_details jsonb:=coalesce(payload->'audit','{}'::jsonb); audit_action text; audit_entity text; audit_licensee text;
BEGIN
  IF jsonb_typeof(payload)<>'object' OR p_purpose IS DISTINCT FROM 'administration-'||p_command
     OR p_command NOT IN ('create-licensee','update-licensee','delete-licensee','create-user','update-user','delete-user','restore-manufacturer') THEN
    RAISE EXCEPTION 'SESSION_C_UNKNOWN_COMMAND' USING ERRCODE='42501';
  END IF;
  SELECT * INTO STRICT actor FROM app_rls.session_c_bind_admin(p_capability,p_purpose,p_request_id,p_command NOT LIKE '%licensee');

  IF p_command='create-licensee' THEN
    target:=payload->>'id'; idempotency_key:=NULLIF(btrim(payload->>'idempotencyKey'),'');
    IF target !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
       OR length(btrim(coalesce(payload->'licensee'->>'name',''))) NOT BETWEEN 2 AND 200
       OR upper(coalesce(payload->'licensee'->>'prefix','')) !~ '^[A-Z0-9]{1,5}$'
       OR lower(coalesce(payload->'admin'->>'email','')) !~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$'
       OR length(btrim(coalesce(payload->'admin'->>'name',''))) NOT BETWEEN 2 AND 120
       OR (NOT coalesce((payload->'admin'->>'sendInvite')::boolean,false) AND coalesce(payload->'admin'->>'passwordHash','') NOT LIKE '$argon2%') THEN
      RAISE EXCEPTION 'SESSION_C_INVALID_INPUT';
    END IF;
    PERFORM app_rls.session_c_set_target(target,target,NULL,lower(payload->'admin'->>'email'),upper(payload->'licensee'->>'prefix'));
    IF idempotency_key IS NOT NULL THEN
      key_hash:=encode(sha256(convert_to(actor."userId"||'|'||p_purpose||'|'||idempotency_key,'UTF8')),'hex');
      request_hash:=encode(sha256(convert_to((payload-'idempotencyKey'-'id'-'audit')::text,'UTF8')),'hex');
      PERFORM set_config('app.admin_mutation_idempotency_hash',key_hash,true),pg_advisory_xact_lock(hashtextextended(key_hash,0));
      SELECT "requestHash","completedAt","responsePayload" INTO prior FROM public."ActionIdempotencyKey" WHERE "keyHash"=key_hash FOR UPDATE;
      IF FOUND THEN
        IF prior."requestHash" IS DISTINCT FROM request_hash THEN RAISE EXCEPTION 'SESSION_C_IDEMPOTENCY_CONFLICT'; END IF;
        IF prior."completedAt" IS NULL THEN RAISE EXCEPTION 'SESSION_C_IDEMPOTENCY_IN_PROGRESS'; END IF;
        RETURN coalesce(prior."responsePayload",'{}'::jsonb)||'{"replayed":true}'::jsonb;
      END IF;
      INSERT INTO public."ActionIdempotencyKey" (id,"keyHash",action,scope,"requestHash","expiresAt")
      VALUES (gen_random_uuid()::text,key_hash,'licensee.create',actor."userId",request_hash,transaction_timestamp()+interval '30 minutes');
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(upper(payload->'licensee'->>'prefix'),0));
    IF EXISTS (SELECT 1 FROM public."Licensee" WHERE prefix=upper(payload->'licensee'->>'prefix'))
       OR EXISTS (SELECT 1 FROM public."User" WHERE email=lower(payload->'admin'->>'email')) THEN
      RAISE EXCEPTION 'SESSION_C_DUPLICATE_LICENSEE_OR_ADMIN';
    END IF;
    INSERT INTO public."Organization" (id,name,"isActive","updatedAt") VALUES
      (target,payload->'licensee'->>'name',coalesce((payload->'licensee'->>'isActive')::boolean,true),transaction_timestamp());
    INSERT INTO public."Licensee" (id,"orgId",name,prefix,description,"brandName",location,website,"supportEmail","supportPhone","isActive","updatedAt") VALUES
      (target,target,payload->'licensee'->>'name',upper(payload->'licensee'->>'prefix'),payload->'licensee'->>'description',payload->'licensee'->>'brandName',
       payload->'licensee'->>'location',payload->'licensee'->>'website',payload->'licensee'->>'supportEmail',payload->'licensee'->>'supportPhone',
       coalesce((payload->'licensee'->>'isActive')::boolean,true),transaction_timestamp());
    IF NOT coalesce((payload->'admin'->>'sendInvite')::boolean,false) THEN
      new_user_id:=gen_random_uuid()::text; PERFORM app_rls.session_c_set_target(target,target,new_user_id,lower(payload->'admin'->>'email'),upper(payload->'licensee'->>'prefix'));
      INSERT INTO public."User" (id,email,"passwordHash",name,role,"orgId","licenseeId",status,"isActive","emailVerifiedAt","updatedAt") VALUES
        (new_user_id,lower(payload->'admin'->>'email'),payload->'admin'->>'passwordHash',payload->'admin'->>'name','LICENSEE_ADMIN'::public."UserRole",
         target,target,'ACTIVE'::public."UserStatus",true,transaction_timestamp(),transaction_timestamp());
    END IF;
    SELECT jsonb_build_object('licensee',to_jsonb(l),'adminUser',(
      SELECT app_rls.session_c_user_projection(u.id) FROM public."User" u WHERE u."licenseeId"=target AND u.role='LICENSEE_ADMIN'::public."UserRole" LIMIT 1
    ),'replayed',false) INTO result FROM public."Licensee" l WHERE l.id=target;
    PERFORM app_rls.session_c_write_audit(actor."userId",target,target,
      CASE WHEN coalesce((payload->'admin'->>'sendInvite')::boolean,false) THEN 'CREATE_LICENSEE_WITH_ADMIN_INVITE' ELSE 'CREATE_LICENSEE_WITH_ADMIN' END,
      'Licensee',target,jsonb_build_object('workflowId','workflow-http-backend-src-controllers-licensee-controller-ts-create-licensee','requestId',p_request_id,
        'purposeCode',p_purpose,'licenseeName',payload->'licensee'->>'name','prefix',upper(payload->'licensee'->>'prefix'),
        'adminEmail',audit_details->>'adminEmail','sendInvite',coalesce((payload->'admin'->>'sendInvite')::boolean,false)),
      audit_details->>'ipHash',audit_details->>'userAgent');
    IF key_hash IS NOT NULL THEN UPDATE public."ActionIdempotencyKey" SET "statusCode"=201,"responsePayload"=result,"completedAt"=transaction_timestamp() WHERE "keyHash"=key_hash; END IF;
    RETURN result;
  END IF;

  target:=payload->>'id';
  IF target !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' THEN RAISE EXCEPTION 'SESSION_C_INVALID_INPUT'; END IF;
  PERFORM app_rls.session_c_set_target(NULL,NULL,target,NULL,NULL),pg_advisory_xact_lock(hashtextextended(target,0));

  IF p_command IN ('update-licensee','delete-licensee') THEN
    SELECT id,"orgId" INTO target_licensee,target_org FROM public."Licensee" WHERE id=target FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'SESSION_C_LICENSEE_NOT_FOUND'; END IF;
    PERFORM app_rls.session_c_set_target(target_licensee,target_org,NULL,NULL,NULL);
    IF p_command='update-licensee' THEN
      patch:=coalesce(payload->'patch','{}'::jsonb);
      IF jsonb_typeof(patch)<>'object' OR EXISTS (SELECT 1 FROM jsonb_object_keys(patch) k WHERE k NOT IN ('name','description','brandName','location','website','supportEmail','supportPhone','isActive')) THEN RAISE EXCEPTION 'SESSION_C_INVALID_INPUT'; END IF;
      UPDATE public."Licensee" SET
        name=CASE WHEN patch?'name' THEN patch->>'name' ELSE name END,
        description=CASE WHEN patch?'description' THEN patch->>'description' ELSE description END,
        "brandName"=CASE WHEN patch?'brandName' THEN patch->>'brandName' ELSE "brandName" END,
        location=CASE WHEN patch?'location' THEN patch->>'location' ELSE location END,
        website=CASE WHEN patch?'website' THEN patch->>'website' ELSE website END,
        "supportEmail"=CASE WHEN patch?'supportEmail' THEN patch->>'supportEmail' ELSE "supportEmail" END,
        "supportPhone"=CASE WHEN patch?'supportPhone' THEN patch->>'supportPhone' ELSE "supportPhone" END,
        "isActive"=CASE WHEN patch?'isActive' THEN (patch->>'isActive')::boolean ELSE "isActive" END,"updatedAt"=transaction_timestamp()
      WHERE id=target;
      SELECT jsonb_build_object('licensee',to_jsonb(l)) INTO result FROM public."Licensee" l WHERE l.id=target;
      PERFORM app_rls.session_c_write_audit(actor."userId",target_org,target,'UPDATE_LICENSEE','Licensee',target,
        jsonb_build_object('workflowId','workflow-http-backend-src-controllers-licensee-controller-ts-update-licensee','requestId',p_request_id,'purposeCode',p_purpose,'changed',coalesce(audit_details->'changed','[]'::jsonb)),audit_details->>'ipHash',audit_details->>'userAgent');
      RETURN result;
    END IF;
    IF EXISTS (SELECT 1 FROM public."User" WHERE "licenseeId"=target) OR EXISTS (SELECT 1 FROM public."Batch" WHERE "licenseeId"=target)
       OR EXISTS (SELECT 1 FROM public."QRRange" WHERE "licenseeId"=target) OR EXISTS (SELECT 1 FROM public."QRCode" WHERE "licenseeId"=target) THEN
      RAISE EXCEPTION 'SESSION_C_LICENSEE_LINKED_DATA';
    END IF;
    DELETE FROM public."Licensee" WHERE id=target;
    PERFORM app_rls.session_c_write_audit(actor."userId",target_org,NULL,'HARD_DELETE_LICENSEE','Licensee',target,
      jsonb_build_object('workflowId','workflow-http-backend-src-controllers-licensee-controller-ts-delete-licensee','requestId',p_request_id,'purposeCode',p_purpose),audit_details->>'ipHash',audit_details->>'userAgent');
    RETURN jsonb_build_object('licenseeId',target_licensee,'organizationId',target_org);
  END IF;

  IF p_command='create-user' THEN
    target_licensee:=payload->>'licenseeId'; target_role:=payload->>'role'; new_user_id:=gen_random_uuid()::text;
    IF target_licensee !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
       OR target_role NOT IN ('LICENSEE_ADMIN','MANUFACTURER_ADMIN') OR lower(coalesce(payload->>'email','')) !~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$'
       OR coalesce(payload->>'passwordHash','') NOT LIKE '$argon2%' THEN RAISE EXCEPTION 'SESSION_C_INVALID_INPUT'; END IF;
    IF actor.role='LICENSEE_ADMIN' AND (actor."licenseeId" IS DISTINCT FROM target_licensee OR target_role<>'MANUFACTURER_ADMIN') THEN RAISE EXCEPTION 'SESSION_C_FOREIGN_SCOPE'; END IF;
    PERFORM app_rls.session_c_set_target(target_licensee,NULL,new_user_id,lower(payload->>'email'),NULL),
            pg_advisory_xact_lock(hashtextextended(target_licensee,0));
    SELECT l."orgId" INTO target_org FROM public."Licensee" l
      WHERE l.id=target_licensee AND l."isActive" AND l."suspendedAt" IS NULL;
    IF NOT FOUND THEN RAISE EXCEPTION 'SESSION_C_LICENSEE_NOT_FOUND'; END IF;
    IF actor.role='LICENSEE_ADMIN' AND actor."organizationId" IS DISTINCT FROM target_org THEN RAISE EXCEPTION 'SESSION_C_FOREIGN_SCOPE'; END IF;
    PERFORM app_rls.session_c_set_target(target_licensee,target_org,new_user_id,lower(payload->>'email'),NULL);
    IF NOT EXISTS (SELECT 1 FROM public."Organization" o WHERE o.id=target_org AND o."isActive") THEN
      RAISE EXCEPTION 'SESSION_C_LICENSEE_NOT_FOUND';
    END IF;
    BEGIN
      INSERT INTO public."User" (id,email,"passwordHash",name,role,"orgId","licenseeId",location,website,status,"isActive","emailVerifiedAt","updatedAt") VALUES
        (new_user_id,lower(payload->>'email'),payload->>'passwordHash',payload->>'name',target_role::public."UserRole",target_org,target_licensee,
         payload->>'location',payload->>'website','ACTIVE'::public."UserStatus",true,transaction_timestamp(),transaction_timestamp());
    EXCEPTION WHEN unique_violation THEN RAISE EXCEPTION 'SESSION_C_DUPLICATE_USER'; END;
    IF target_role='MANUFACTURER_ADMIN' THEN INSERT INTO public."ManufacturerLicenseeLink" ("manufacturerId","licenseeId","isPrimary","updatedAt") VALUES (new_user_id,target_licensee,true,transaction_timestamp()); END IF;
    result:=jsonb_build_object('user',app_rls.session_c_user_projection(new_user_id),'licenseeId',target_licensee,'organizationId',target_org);
    PERFORM app_rls.session_c_write_audit(actor."userId",target_org,target_licensee,'CREATE_USER','User',new_user_id,
      jsonb_build_object('workflowId','workflow-http-backend-src-controllers-user-controller-ts-create-user','requestId',p_request_id,'purposeCode',p_purpose,'role',target_role),audit_details->>'ipHash',audit_details->>'userAgent');
    RETURN result;
  END IF;

  SELECT u."licenseeId",u."orgId",u.role::text INTO target_licensee,target_org,target_role FROM public."User" u WHERE u.id=target FOR UPDATE;
  IF NOT FOUND OR target_role<>'MANUFACTURER_ADMIN' OR target=actor."userId" THEN RAISE EXCEPTION 'SESSION_C_USER_NOT_FOUND'; END IF;
  PERFORM app_rls.session_c_set_target(target_licensee,target_org,target,NULL,NULL);
  IF actor.role='LICENSEE_ADMIN' AND NOT EXISTS (SELECT 1 FROM public."ManufacturerLicenseeLink" ml WHERE ml."manufacturerId"=target AND ml."licenseeId"=actor."licenseeId") THEN RAISE EXCEPTION 'SESSION_C_FOREIGN_SCOPE'; END IF;

  IF p_command='update-user' THEN
    patch:=coalesce(payload->'patch','{}'::jsonb);
    IF jsonb_typeof(patch)<>'object' OR EXISTS (SELECT 1 FROM jsonb_object_keys(patch) k WHERE k NOT IN ('name','email','passwordHash','isActive','licenseeId','location','website'))
       OR (patch?'passwordHash' AND patch->>'passwordHash' NOT LIKE '$argon2%') THEN RAISE EXCEPTION 'SESSION_C_INVALID_INPUT'; END IF;
    IF patch?'licenseeId' THEN
      IF actor.role NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') THEN RAISE EXCEPTION 'SESSION_C_WRONG_ROLE'; END IF;
      target_licensee:=patch->>'licenseeId'; PERFORM app_rls.session_c_set_target(target_licensee,NULL,target,NULL,NULL);
      SELECT l."orgId" INTO target_org FROM public."Licensee" l JOIN public."Organization" o ON o.id=l."orgId" WHERE l.id=target_licensee AND l."isActive" AND l."suspendedAt" IS NULL AND o."isActive";
      IF NOT FOUND THEN RAISE EXCEPTION 'SESSION_C_LICENSEE_NOT_FOUND'; END IF;
      PERFORM app_rls.session_c_set_target(target_licensee,target_org,target,NULL,NULL);
      UPDATE public."ManufacturerLicenseeLink" SET "isPrimary"=false,"updatedAt"=transaction_timestamp() WHERE "manufacturerId"=target AND "isPrimary";
      INSERT INTO public."ManufacturerLicenseeLink" ("manufacturerId","licenseeId","isPrimary","updatedAt") VALUES (target,target_licensee,true,transaction_timestamp())
      ON CONFLICT ("manufacturerId","licenseeId") DO UPDATE SET "isPrimary"=true,"updatedAt"=transaction_timestamp();
    END IF;
    UPDATE public."User" SET name=CASE WHEN patch?'name' THEN patch->>'name' ELSE name END,email=CASE WHEN patch?'email' THEN lower(patch->>'email') ELSE email END,
      "passwordHash"=CASE WHEN patch?'passwordHash' THEN patch->>'passwordHash' ELSE "passwordHash" END,location=CASE WHEN patch?'location' THEN patch->>'location' ELSE location END,
      website=CASE WHEN patch?'website' THEN patch->>'website' ELSE website END,"licenseeId"=target_licensee,"orgId"=target_org,
      "isActive"=CASE WHEN patch?'isActive' THEN (patch->>'isActive')::boolean ELSE "isActive" END,
      status=CASE WHEN patch?'isActive' AND NOT (patch->>'isActive')::boolean THEN 'DISABLED'::public."UserStatus" WHEN patch?'isActive' THEN 'ACTIVE'::public."UserStatus" ELSE status END,
      "deletedAt"=CASE WHEN patch?'isActive' AND NOT (patch->>'isActive')::boolean THEN transaction_timestamp() WHEN patch?'isActive' THEN NULL ELSE "deletedAt" END,
      "disabledAt"=CASE WHEN patch?'isActive' AND NOT (patch->>'isActive')::boolean THEN transaction_timestamp() WHEN patch?'isActive' THEN NULL ELSE "disabledAt" END,"updatedAt"=transaction_timestamp() WHERE id=target;
    IF (patch?'isActive' AND NOT (patch->>'isActive')::boolean) OR patch?'passwordHash' THEN
      UPDATE public."RefreshToken" SET "revokedAt"=transaction_timestamp(),"revokedReason"='ACCOUNT_SECURITY_CHANGE',
        "sessionCapabilityRevokedAt"=coalesce("sessionCapabilityRevokedAt",transaction_timestamp()),"sessionCapabilityRevokedReason"=coalesce("sessionCapabilityRevokedReason",'ACCOUNT_SECURITY_CHANGE')
      WHERE "userId"=target AND "revokedAt" IS NULL;
    END IF;
    result:=jsonb_build_object('user',app_rls.session_c_user_projection(target),'licenseeId',target_licensee,'organizationId',target_org,'scopedLicenseeId',CASE WHEN actor.role='LICENSEE_ADMIN' THEN actor."licenseeId" ELSE target_licensee END);
    PERFORM app_rls.session_c_write_audit(actor."userId",target_org,target_licensee,'UPDATE_USER','User',target,
      jsonb_build_object('workflowId','workflow-http-backend-src-controllers-user-controller-ts-update-user','requestId',p_request_id,'purposeCode',p_purpose,'changed',coalesce(audit_details->'changed','[]'::jsonb)),audit_details->>'ipHash',audit_details->>'userAgent');
    RETURN result;
  END IF;

  IF p_command='delete-user' THEN
    hard_delete:=coalesce((payload->>'hard')::boolean,false);
    IF hard_delete THEN
      IF actor.role NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') THEN RAISE EXCEPTION 'SESSION_C_WRONG_ROLE'; END IF;
      UPDATE public."Batch" SET "manufacturerId"=NULL,"updatedAt"=transaction_timestamp() WHERE "manufacturerId"=target; GET DIAGNOSTICS affected=ROW_COUNT;
      DELETE FROM public."User" WHERE id=target; audit_action:='HARD_DELETE_MANUFACTURER'; audit_licensee:=target_licensee;
      result:=jsonb_build_object('deletedId',target,'hard',true,'unassignedBatches',affected);
    ELSIF actor.role='LICENSEE_ADMIN' THEN
      target_licensee:=actor."licenseeId"; target_org:=actor."organizationId"; PERFORM app_rls.session_c_set_target(target_licensee,target_org,target,NULL,NULL);
      IF EXISTS (SELECT 1 FROM public."Batch" WHERE "manufacturerId"=target AND "licenseeId"=target_licensee) THEN RAISE EXCEPTION 'SESSION_C_ASSIGNED_BATCHES'; END IF;
      DELETE FROM public."ManufacturerLicenseeLink" WHERE "manufacturerId"=target AND "licenseeId"=target_licensee;
      SELECT "licenseeId","isPrimary" INTO remaining FROM public."ManufacturerLicenseeLink" WHERE "manufacturerId"=target ORDER BY "isPrimary" DESC,"createdAt" LIMIT 1 FOR UPDATE;
      IF NOT FOUND THEN
        UPDATE public."User" SET "isActive"=false,status='DISABLED'::public."UserStatus","deletedAt"=transaction_timestamp(),"disabledAt"=transaction_timestamp(),"licenseeId"=NULL,"orgId"=NULL,"updatedAt"=transaction_timestamp() WHERE id=target;
        UPDATE public."RefreshToken" SET "revokedAt"=transaction_timestamp(),"revokedReason"='ACCOUNT_DISABLED',"sessionCapabilityRevokedAt"=coalesce("sessionCapabilityRevokedAt",transaction_timestamp()),"sessionCapabilityRevokedReason"=coalesce("sessionCapabilityRevokedReason",'ACCOUNT_DISABLED') WHERE "userId"=target AND "revokedAt" IS NULL;
      ELSE
        UPDATE public."ManufacturerLicenseeLink" SET "isPrimary"=("licenseeId"=remaining."licenseeId"),"updatedAt"=transaction_timestamp() WHERE "manufacturerId"=target;
        UPDATE public."User" SET "licenseeId"=remaining."licenseeId","orgId"=(SELECT "orgId" FROM public."Licensee" WHERE id=remaining."licenseeId"),"updatedAt"=transaction_timestamp() WHERE id=target;
      END IF;
      audit_action:='UNLINK_MANUFACTURER_FROM_LICENSEE'; audit_licensee:=target_licensee;
      result:=jsonb_build_object('deletedId',target,'hard',false,'unlinkedLicenseeId',target_licensee);
    ELSE
      UPDATE public."User" SET "isActive"=false,status='DISABLED'::public."UserStatus","deletedAt"=transaction_timestamp(),"disabledAt"=transaction_timestamp(),"updatedAt"=transaction_timestamp() WHERE id=target;
      UPDATE public."RefreshToken" SET "revokedAt"=transaction_timestamp(),"revokedReason"='ACCOUNT_DISABLED',"sessionCapabilityRevokedAt"=coalesce("sessionCapabilityRevokedAt",transaction_timestamp()),"sessionCapabilityRevokedReason"=coalesce("sessionCapabilityRevokedReason",'ACCOUNT_DISABLED') WHERE "userId"=target AND "revokedAt" IS NULL;
      audit_action:='SOFT_DELETE_MANUFACTURER'; audit_licensee:=target_licensee;
      result:=jsonb_build_object('deletedId',target,'hard',false,'id',target,'isActive',false,'deletedAt',transaction_timestamp());
    END IF;
    PERFORM app_rls.session_c_write_audit(actor."userId",target_org,audit_licensee,audit_action,'User',target,
      jsonb_build_object('workflowId','workflow-http-backend-src-controllers-user-controller-ts-delete-user','requestId',p_request_id,'purposeCode',p_purpose,'hard',hard_delete),audit_details->>'ipHash',audit_details->>'userAgent');
    RETURN jsonb_build_object('licenseeId',audit_licensee,'organizationId',target_org,'auditAction',audit_action,'response',result);
  END IF;

  IF p_command='restore-manufacturer' THEN
    IF actor.role='LICENSEE_ADMIN' THEN target_licensee:=actor."licenseeId"; target_org:=actor."organizationId"; END IF;
    IF target_licensee IS NULL OR NOT EXISTS (SELECT 1 FROM public."Licensee" l JOIN public."Organization" o ON o.id=l."orgId" WHERE l.id=target_licensee AND l."orgId"=target_org AND l."isActive" AND l."suspendedAt" IS NULL AND o."isActive") THEN RAISE EXCEPTION 'SESSION_C_FOREIGN_SCOPE'; END IF;
    PERFORM app_rls.session_c_set_target(target_licensee,target_org,target,NULL,NULL);
    INSERT INTO public."ManufacturerLicenseeLink" ("manufacturerId","licenseeId","isPrimary","updatedAt")
    SELECT target,target_licensee,NOT EXISTS (
      SELECT 1 FROM public."ManufacturerLicenseeLink" ml WHERE ml."manufacturerId"=target AND ml."isPrimary"
    ),transaction_timestamp()
    ON CONFLICT ("manufacturerId","licenseeId") DO UPDATE SET "updatedAt"=transaction_timestamp();
    UPDATE public."User" SET "isActive"=true,status='ACTIVE'::public."UserStatus","deletedAt"=NULL,"disabledAt"=NULL,"licenseeId"=target_licensee,"orgId"=target_org,"updatedAt"=transaction_timestamp() WHERE id=target;
    result:=jsonb_build_object('id',target,'isActive',true,'deletedAt',NULL);
    PERFORM app_rls.session_c_write_audit(actor."userId",target_org,target_licensee,'RESTORE_MANUFACTURER','User',target,
      jsonb_build_object('workflowId','workflow-http-backend-src-controllers-user-controller-ts-restore-manufacturer','requestId',p_request_id,'purposeCode',p_purpose,'licenseeId',target_licensee),audit_details->>'ipHash',audit_details->>'userAgent');
    RETURN jsonb_build_object('licenseeId',target_licensee,'organizationId',target_org,'auditAction','RESTORE_MANUFACTURER','response',result);
  END IF;
  RAISE EXCEPTION 'SESSION_C_UNKNOWN_COMMAND';
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.prepare_invitation(
  p_capability text,p_actor_user_id text,p_actor_session_id text,p_request_id text,p_purpose text,
  p_requested_email text,p_requested_name text,p_requested_role text,p_requested_licensee_id text,
  p_requested_manufacturer_id text,p_allow_existing_invited_user boolean,p_require_existing_user boolean,
  p_token_hash text,p_created_at timestamp without time zone,p_expires_at timestamp without time zone,
  p_ip_hash text,p_user_agent text
) RETURNS TABLE(
  "actorDisplayName" text,"actorEmail" text,"actorUserId" text,"inviteEmail" text,
  "inviteExpiresAt" timestamp without time zone,"inviteId" text,"inviteRole" text,
  "licenseeName" text,"linkAction" text,"userEmail" text,"userId" text,
  "userLicenseeId" text,"userName" text,"userOrganizationId" text,"userRole" text,
  "userStatus" text,"workspaceOrganizationId" text
) LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE
  actor record; target_user record; target_licensee record; prior record;
  requested_email text:=lower(btrim(coalesce(p_requested_email,'')));
  user_name text:=btrim(coalesce(p_requested_name,''));
  organization_id text; invite_id text; target_user_id text; link_action text; licensee_name text;
  key_hash text; request_hash text; response jsonb; inserted integer;
BEGIN
  SELECT * INTO actor FROM app_rls.session_c_bind_admin(p_capability,p_purpose,p_request_id,true);
  IF actor."userId" IS DISTINCT FROM p_actor_user_id OR actor."sessionId" IS DISTINCT FROM p_actor_session_id
     OR p_requested_role NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN','LICENSEE_ADMIN','MANUFACTURER_ADMIN')
     OR user_name='' OR length(user_name)>120 OR user_name~'[[:cntrl:]]'
     OR (requested_email<>'' AND (length(requested_email)>320 OR requested_email!~'^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$'))
     OR (NOT p_require_existing_user AND requested_email='')
     OR p_token_hash!~'^([0-9a-f]{12}:)?[0-9a-f]{64}$'
     OR p_created_at IS NULL OR abs(extract(epoch FROM (p_created_at-(clock_timestamp() AT TIME ZONE 'UTC'))))>300
     OR p_expires_at<=p_created_at OR p_expires_at>p_created_at+interval '24 hours'
     OR (p_ip_hash IS NOT NULL AND p_ip_hash!~'^([0-9a-f]{12}:)?[0-9a-f]{64}$')
     OR length(coalesce(p_user_agent,''))>512 OR coalesce(p_user_agent,'')~'[[:cntrl:]]'
  THEN RAISE EXCEPTION 'SESSION_C_INVITE_INPUT_DENIED' USING ERRCODE='42501'; END IF;

  IF p_requested_licensee_id IS NULL THEN
    IF p_requested_role NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') OR p_requested_manufacturer_id IS NOT NULL THEN
      RAISE EXCEPTION 'SESSION_C_INVITE_SCOPE_DENIED' USING ERRCODE='42501';
    END IF;
    organization_id:='00000000-0000-0000-0000-000000000000';
    PERFORM app_rls.session_c_set_target(NULL,organization_id,NULL,requested_email,NULL);
    INSERT INTO public."Organization" (id,name,"isActive","updatedAt") VALUES
      (organization_id,'Platform',true,transaction_timestamp()) ON CONFLICT (id) DO NOTHING;
    IF NOT EXISTS (SELECT 1 FROM public."Organization" WHERE id=organization_id AND "isActive") THEN
      RAISE EXCEPTION 'SESSION_C_INVITE_SCOPE_DENIED' USING ERRCODE='42501';
    END IF;
  ELSE
    PERFORM app_rls.session_c_set_target(p_requested_licensee_id,NULL,NULL,requested_email,NULL),
            pg_advisory_xact_lock(hashtextextended(p_requested_licensee_id,0));
    SELECT l.id,l."orgId",l.name INTO target_licensee FROM public."Licensee" l
      WHERE l.id=p_requested_licensee_id AND l."isActive" AND l."suspendedAt" IS NULL;
    IF NOT FOUND THEN RAISE EXCEPTION 'SESSION_C_INVITE_SCOPE_DENIED' USING ERRCODE='42501'; END IF;
    organization_id:=target_licensee."orgId";
    licensee_name:=target_licensee.name;
    PERFORM app_rls.session_c_set_target(p_requested_licensee_id,organization_id,NULL,requested_email,NULL);
    IF NOT EXISTS (SELECT 1 FROM public."Organization" o WHERE o.id=organization_id AND o."isActive") THEN
      RAISE EXCEPTION 'SESSION_C_INVITE_SCOPE_DENIED' USING ERRCODE='42501';
    END IF;
  END IF;

  IF p_purpose='licensee-admin-invite-resend' THEN
    IF actor.role NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') OR NOT p_allow_existing_invited_user
       OR NOT p_require_existing_user OR p_requested_licensee_id IS NULL
       OR p_requested_role<>'LICENSEE_ADMIN' OR p_requested_manufacturer_id IS NOT NULL THEN
      RAISE EXCEPTION 'SESSION_C_INVITE_SCOPE_DENIED' USING ERRCODE='42501';
    END IF;
  ELSIF actor.role='LICENSEE_ADMIN' THEN
    IF actor."licenseeId" IS DISTINCT FROM p_requested_licensee_id
       OR actor."organizationId" IS DISTINCT FROM organization_id OR p_requested_role<>'MANUFACTURER_ADMIN' THEN
      RAISE EXCEPTION 'SESSION_C_INVITE_SCOPE_DENIED' USING ERRCODE='42501';
    END IF;
  END IF;
  IF p_requested_manufacturer_id IS NOT NULL AND (p_requested_role<>'MANUFACTURER_ADMIN' OR NOT p_allow_existing_invited_user) THEN
    RAISE EXCEPTION 'SESSION_C_INVITE_SCOPE_DENIED' USING ERRCODE='42501';
  END IF;

  PERFORM pg_advisory_xact_lock(hashtextextended(coalesce(p_requested_licensee_id,'platform')||':'||coalesce(nullif(requested_email,''),p_requested_role),0));
  key_hash:=encode(sha256(convert_to('invite:'||actor."userId"||':'||p_request_id,'UTF8')),'hex');
  request_hash:=encode(sha256(convert_to(concat_ws('|',p_purpose,requested_email,user_name,p_requested_role,coalesce(p_requested_licensee_id,''),coalesce(p_requested_manufacturer_id,''),p_token_hash),'UTF8')),'hex');
  PERFORM set_config('app.admin_mutation_idempotency_hash',key_hash,true);
  SELECT "requestHash","completedAt","responsePayload" INTO prior FROM public."ActionIdempotencyKey" WHERE "keyHash"=key_hash FOR UPDATE;
  IF FOUND THEN
    IF prior."requestHash" IS DISTINCT FROM request_hash OR prior."completedAt" IS NULL THEN
      RAISE EXCEPTION 'SESSION_C_INVITE_REPLAY_DENIED' USING ERRCODE='42501';
    END IF;
    response:=prior."responsePayload";
    RETURN QUERY SELECT response->>'actorDisplayName',response->>'actorEmail',response->>'actorUserId',response->>'inviteEmail',
      (response->>'inviteExpiresAt')::timestamp,response->>'inviteId',response->>'inviteRole',response->>'licenseeName',
      response->>'linkAction',response->>'userEmail',response->>'userId',response->>'userLicenseeId',response->>'userName',
      response->>'userOrganizationId',response->>'userRole',response->>'userStatus',response->>'workspaceOrganizationId';
    RETURN;
  END IF;
  INSERT INTO public."ActionIdempotencyKey" (id,"keyHash",action,scope,"requestHash","expiresAt") VALUES
    (gen_random_uuid()::text,key_hash,'invitation.prepare',actor."userId",request_hash,transaction_timestamp()+interval '24 hours');

  IF p_require_existing_user THEN
    SELECT u.id,u.email,u.name,u.role,u."orgId",u."licenseeId",u.status,u."isActive",u."disabledAt",u."deletedAt",u."passwordHash"
      INTO target_user FROM public."User" u WHERE u."licenseeId"=p_requested_licensee_id
      AND u.role='LICENSEE_ADMIN'::public."UserRole" AND (requested_email='' OR u.email=requested_email);
    IF NOT FOUND OR target_user.status<>'INVITED'::public."UserStatus" OR NOT target_user."isActive"
       OR target_user."passwordHash" IS NOT NULL OR target_user."disabledAt" IS NOT NULL OR target_user."deletedAt" IS NOT NULL THEN
      RAISE EXCEPTION 'SESSION_C_INVITE_TARGET_DENIED' USING ERRCODE='42501';
    END IF;
    requested_email:=target_user.email;
  ELSIF p_requested_manufacturer_id IS NOT NULL THEN
    PERFORM app_rls.session_c_set_target(p_requested_licensee_id,organization_id,p_requested_manufacturer_id,requested_email,NULL);
    SELECT u.id,u.email,u.name,u.role,u."orgId",u."licenseeId",u.status,u."isActive",u."disabledAt",u."deletedAt",u."passwordHash"
      INTO target_user FROM public."User" u WHERE u.id=p_requested_manufacturer_id AND u.email=requested_email
      AND u.role='MANUFACTURER_ADMIN'::public."UserRole" AND u.status='ACTIVE'::public."UserStatus"
      AND u."isActive" AND u."disabledAt" IS NULL AND u."deletedAt" IS NULL;
    IF NOT FOUND THEN RAISE EXCEPTION 'SESSION_C_INVITE_TARGET_DENIED' USING ERRCODE='42501'; END IF;
  ELSE
    SELECT u.id,u.email,u.name,u.role,u."orgId",u."licenseeId",u.status,u."isActive",u."disabledAt",u."deletedAt",u."passwordHash"
      INTO target_user FROM public."User" u WHERE u.email=requested_email;
    IF FOUND THEN
      IF NOT p_allow_existing_invited_user THEN RAISE EXCEPTION 'SESSION_C_INVITE_ACCOUNT_EXISTS' USING ERRCODE='23505'; END IF;
      IF target_user.role='MANUFACTURER_ADMIN'::public."UserRole" AND p_requested_role='MANUFACTURER_ADMIN'
         AND target_user.status='ACTIVE'::public."UserStatus" AND target_user."isActive"
         AND target_user."disabledAt" IS NULL AND target_user."deletedAt" IS NULL THEN NULL;
      ELSIF target_user.role::text IS DISTINCT FROM p_requested_role OR target_user.status<>'INVITED'::public."UserStatus"
         OR NOT target_user."isActive" OR target_user."passwordHash" IS NOT NULL OR target_user."disabledAt" IS NOT NULL
         OR target_user."deletedAt" IS NOT NULL OR target_user."licenseeId" IS DISTINCT FROM p_requested_licensee_id
         OR target_user."orgId" IS DISTINCT FROM (CASE WHEN p_requested_role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') THEN NULL ELSE organization_id END) THEN
        RAISE EXCEPTION 'SESSION_C_INVITE_ACCOUNT_EXISTS' USING ERRCODE='23505';
      END IF;
    ELSE
      target_user_id:=gen_random_uuid()::text;
      PERFORM app_rls.session_c_set_target(p_requested_licensee_id,organization_id,target_user_id,requested_email,NULL);
      INSERT INTO public."User" (id,email,name,role,"orgId","licenseeId",status,"isActive","updatedAt") VALUES
        (target_user_id,requested_email,user_name,p_requested_role::public."UserRole",
         CASE WHEN p_requested_role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') THEN NULL ELSE organization_id END,
         p_requested_licensee_id,'INVITED'::public."UserStatus",true,transaction_timestamp());
      SELECT u.id,u.email,u.name,u.role,u."orgId",u."licenseeId",u.status,u."isActive",u."disabledAt",u."deletedAt",u."passwordHash"
        INTO STRICT target_user FROM public."User" u WHERE u.id=target_user_id;
    END IF;
  END IF;
  target_user_id:=target_user.id;
  PERFORM app_rls.session_c_set_target(p_requested_licensee_id,organization_id,target_user_id,requested_email,NULL);

  IF target_user.role='MANUFACTURER_ADMIN'::public."UserRole" THEN
    INSERT INTO public."ManufacturerLicenseeLink" ("manufacturerId","licenseeId","isPrimary","updatedAt")
      SELECT target_user.id,p_requested_licensee_id,NOT EXISTS (SELECT 1 FROM public."ManufacturerLicenseeLink" WHERE "manufacturerId"=target_user.id AND "isPrimary"),transaction_timestamp()
      ON CONFLICT ("manufacturerId","licenseeId") DO NOTHING;
    GET DIAGNOSTICS inserted=ROW_COUNT;
    IF target_user.status='ACTIVE'::public."UserStatus" THEN link_action:=CASE WHEN inserted=1 THEN 'LINKED_EXISTING' ELSE 'ALREADY_LINKED' END; END IF;
  END IF;

  IF link_action IS NULL THEN
    UPDATE public."Invite" invite SET "usedAt"=transaction_timestamp() WHERE invite.email=target_user.email AND invite."licenseeId" IS NOT DISTINCT FROM p_requested_licensee_id AND invite."usedAt" IS NULL;
    invite_id:=gen_random_uuid()::text;
    PERFORM set_config('app.admin_mutation_invite_id',invite_id,true);
    INSERT INTO public."Invite" (id,"orgId","licenseeId",email,role,"manufacturerId","tokenHash","expiresAt","createdByUserId","createdAt") VALUES
      (invite_id,organization_id,p_requested_licensee_id,requested_email,p_requested_role::public."UserRole",p_requested_manufacturer_id,p_token_hash,p_expires_at,actor."userId",p_created_at);
  END IF;
  response:=jsonb_build_object('actorDisplayName',actor_user.name,'actorEmail',actor_user.email,'actorUserId',actor."userId",
    'inviteEmail',requested_email,'inviteExpiresAt',CASE WHEN invite_id IS NULL THEN NULL ELSE p_expires_at END,'inviteId',invite_id,
    'inviteRole',p_requested_role,'licenseeName',licensee_name,'linkAction',link_action,'userEmail',target_user.email,
    'userId',target_user.id,'userLicenseeId',target_user."licenseeId",'userName',target_user.name,
    'userOrganizationId',target_user."orgId",'userRole',target_user.role::text,'userStatus',target_user.status::text,
    'workspaceOrganizationId',organization_id)
  FROM public."User" actor_user WHERE actor_user.id=actor."userId";
  PERFORM app_rls.session_c_write_audit(actor."userId",organization_id,p_requested_licensee_id,
    CASE WHEN link_action IS NULL THEN 'AUTH_INVITE_CREATED' ELSE 'MANUFACTURER_LICENSEE_LINKED' END,
    CASE WHEN link_action IS NULL THEN 'Invite' ELSE 'User' END,coalesce(invite_id,target_user.id),
    jsonb_build_object('workflowId',CASE WHEN p_purpose='licensee-admin-invite-resend' THEN 'workflow-http-backend-src-controllers-licensee-invite-controller-ts-resend-licensee-admin-invite' ELSE 'workflow-http-backend-src-controllers-auth-controller-ts-invite' END,
      'requestId',p_request_id,'purposeCode',p_purpose,'targetUserId',target_user.id,'role',p_requested_role,'linkAction',link_action),p_ip_hash,p_user_agent);
  UPDATE public."ActionIdempotencyKey" SET "statusCode"=201,"responsePayload"=response,"completedAt"=transaction_timestamp() WHERE "keyHash"=key_hash;
  RETURN QUERY SELECT response->>'actorDisplayName',response->>'actorEmail',response->>'actorUserId',response->>'inviteEmail',
    (response->>'inviteExpiresAt')::timestamp,response->>'inviteId',response->>'inviteRole',response->>'licenseeName',
    response->>'linkAction',response->>'userEmail',response->>'userId',response->>'userLicenseeId',response->>'userName',
    response->>'userOrganizationId',response->>'userRole',response->>'userStatus',response->>'workspaceOrganizationId';
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.session_c_create_licensee(p_capability text,p_purpose text,p_request_id text,payload jsonb) RETURNS jsonb LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$ SELECT app_rls.session_c_admin_command($1,$2,$3,'create-licensee',$4) $fn$;
CREATE OR REPLACE FUNCTION app_rls.session_c_update_licensee(p_capability text,p_purpose text,p_request_id text,payload jsonb) RETURNS jsonb LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$ SELECT app_rls.session_c_admin_command($1,$2,$3,'update-licensee',$4) $fn$;
CREATE OR REPLACE FUNCTION app_rls.session_c_delete_licensee(p_capability text,p_purpose text,p_request_id text,payload jsonb) RETURNS jsonb LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$ SELECT app_rls.session_c_admin_command($1,$2,$3,'delete-licensee',$4) $fn$;
CREATE OR REPLACE FUNCTION app_rls.session_c_create_user(p_capability text,p_purpose text,p_request_id text,payload jsonb) RETURNS jsonb LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$ SELECT app_rls.session_c_admin_command($1,$2,$3,'create-user',$4) $fn$;
CREATE OR REPLACE FUNCTION app_rls.session_c_update_user(p_capability text,p_purpose text,p_request_id text,payload jsonb) RETURNS jsonb LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$ SELECT app_rls.session_c_admin_command($1,$2,$3,'update-user',$4) $fn$;
CREATE OR REPLACE FUNCTION app_rls.session_c_delete_user(p_capability text,p_purpose text,p_request_id text,payload jsonb) RETURNS jsonb LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$ SELECT app_rls.session_c_admin_command($1,$2,$3,'delete-user',$4) $fn$;
CREATE OR REPLACE FUNCTION app_rls.session_c_restore_manufacturer(p_capability text,p_purpose text,p_request_id text,payload jsonb) RETURNS jsonb LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$ SELECT app_rls.session_c_admin_command($1,$2,$3,'restore-manufacturer',$4) $fn$;

REVOKE ALL ON FUNCTION app_rls.session_c_bind_admin(text,text,text,boolean) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.session_c_set_target(text,text,text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.session_c_user_projection(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.session_c_write_audit(text,text,text,text,text,text,jsonb,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.session_c_admin_command(text,text,text,text,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.prepare_invitation(text,text,text,text,text,text,text,text,text,text,boolean,boolean,text,timestamp without time zone,timestamp without time zone,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.session_c_create_licensee(text,text,text,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.session_c_update_licensee(text,text,text,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.session_c_delete_licensee(text,text,text,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.session_c_create_user(text,text,text,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.session_c_update_user(text,text,text,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.session_c_delete_user(text,text,text,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.session_c_restore_manufacturer(text,text,text,jsonb) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION app_rls.prepare_invitation(text,text,text,text,text,text,text,text,text,text,boolean,boolean,text,timestamp without time zone,timestamp without time zone,text,text) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.session_c_create_licensee(text,text,text,jsonb) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.session_c_create_user(text,text,text,jsonb) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.session_c_delete_licensee(text,text,text,jsonb) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.session_c_delete_user(text,text,text,jsonb) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.session_c_restore_manufacturer(text,text,text,jsonb) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.session_c_update_licensee(text,text,text,jsonb) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.session_c_update_user(text,text,text,jsonb) TO "mscqr_rls_cert_app";
RESET ROLE;
DO $$ BEGIN
  IF NOT pg_has_role(session_user,'mscqr_rls_cert_owner','SET') THEN RAISE EXCEPTION 'administrative executor lacks SET authority for mscqr_rls_cert_owner'; END IF;
END $$;
SET ROLE "mscqr_rls_cert_owner";
REVOKE CREATE ON SCHEMA app_rls FROM "mscqr_rls_cert_auth_owner";
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
CREATE OR REPLACE FUNCTION app_rls.qr_bind_actor(
  p_capability text,p_purpose text,p_request_id text,p_target_licensee_id text
) RETURNS TABLE("userId" text,"role" text,"organizationId" text,"licenseeId" text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; target_org text; scope_ids text;
BEGIN
  IF p_purpose NOT IN ('qr-range-allocate','qr-code-read','qr-code-stats','qr-code-delete','qr-code-token-bind','qr-code-scope','qr-batch-command','qr-allocation-request-approve','qr-inventory-read','qr-audit-export')
     OR p_request_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
     OR (p_target_licensee_id IS NOT NULL AND p_target_licensee_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$')
  THEN RAISE EXCEPTION 'QR_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;

  SELECT * INTO STRICT actor FROM app_auth.require_authenticated_session(p_capability,p_purpose,p_request_id);
  IF actor.role NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN','LICENSEE_ADMIN','MANUFACTURER_ADMIN') THEN
    RAISE EXCEPTION 'QR_BOUNDARY_DENIED' USING ERRCODE='42501';
  END IF;
  PERFORM set_config('app.qr_session_id',actor."sessionId",true),
          set_config('app.qr_user_id',actor."userId",true),
          set_config('app.qr_role',actor.role,true),
          set_config('app.qr_organization_id',coalesce(actor."organizationId",''),true),
          set_config('app.qr_licensee_id',coalesce(actor."licenseeId",''),true),
          set_config('app.qr_target_licensee_id',coalesce(p_target_licensee_id,''),true),
          set_config('app.qr_target_organization_id','',true),
          set_config('app.qr_scope_licensee_ids','',true),
          set_config('app.qr_target_batch_id','',true),
          set_config('app.qr_source_batch_id','',true),
          set_config('app.qr_target_batch_ids','',true),
          set_config('app.qr_target_manufacturer_id','',true),
          set_config('app.qr_target_request_id','',true),
          set_config('app.qr_batch_action','',true),
          set_config('app.qr_target_code_ids','',true),
          set_config('app.qr_target_user_ids','',true),
          set_config('app.qr_operation',p_purpose,true),
          set_config('app.qr_audit_id','',true),
          set_config('app.qr_outbox_id','',true);
  IF actor.role='MANUFACTURER_ADMIN' THEN
    SELECT coalesce(string_agg(ml."licenseeId",',' ORDER BY ml."licenseeId"),'') INTO scope_ids
      FROM public."ManufacturerLicenseeLink" ml WHERE ml."manufacturerId"=actor."userId";
    PERFORM set_config('app.qr_scope_licensee_ids',scope_ids,true);
  END IF;

  IF p_target_licensee_id IS NOT NULL THEN
    SELECT l."orgId" INTO target_org FROM public."Licensee" l
      WHERE l.id=p_target_licensee_id AND l."isActive" AND l."suspendedAt" IS NULL;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'QR_BOUNDARY_DENIED' USING ERRCODE='42501';
    END IF;
    PERFORM set_config('app.qr_target_organization_id',target_org,true);
    IF NOT EXISTS (SELECT 1 FROM public."Organization" o WHERE o.id=target_org AND o."isActive") THEN
      RAISE EXCEPTION 'QR_BOUNDARY_DENIED' USING ERRCODE='42501';
    END IF;
    IF actor.role='LICENSEE_ADMIN' AND
       (actor."licenseeId" IS DISTINCT FROM p_target_licensee_id OR actor."organizationId" IS DISTINCT FROM target_org) THEN
      RAISE EXCEPTION 'QR_BOUNDARY_DENIED' USING ERRCODE='42501';
    END IF;
    IF actor.role='MANUFACTURER_ADMIN' AND NOT EXISTS (
      SELECT 1 FROM public."ManufacturerLicenseeLink" ml
       WHERE ml."manufacturerId"=actor."userId" AND ml."licenseeId"=p_target_licensee_id
    ) THEN RAISE EXCEPTION 'QR_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;
  END IF;
  RETURN QUERY SELECT actor."userId"::text,actor.role::text,actor."organizationId"::text,actor."licenseeId"::text;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.qr_approve_allocation_request(
  p_capability text,p_purpose text,p_request_id text,p_allocation_request_id text,p_decision_note text
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; request_row record; allocation jsonb; requested_quantity integer; updated jsonb;
BEGIN
  IF p_purpose<>'qr-allocation-request-approve'
     OR p_allocation_request_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
     OR length(coalesce(p_decision_note,''))>500 THEN
    RAISE EXCEPTION 'QR_BOUNDARY_DENIED' USING ERRCODE='42501';
  END IF;
  SELECT * INTO STRICT actor FROM app_rls.qr_bind_actor(p_capability,p_purpose,p_request_id,NULL);
  IF actor.role NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') THEN
    RAISE EXCEPTION 'QR_BOUNDARY_DENIED' USING ERRCODE='42501';
  END IF;
  PERFORM set_config('app.qr_target_request_id',p_allocation_request_id,true);
  SELECT r.id,r."licenseeId",r."requestedByUserId",r.quantity,r."startNumber",r."endNumber",r."batchName",r.status
    INTO request_row FROM public."QrAllocationRequest" r
    WHERE r.id=p_allocation_request_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'QR_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;
  IF request_row.status<>'PENDING'::public."QrAllocationRequestStatus" THEN
    RAISE EXCEPTION 'QR_REQUEST_ALREADY_PROCESSED';
  END IF;
  requested_quantity:=coalesce(request_row.quantity,
    CASE WHEN request_row."startNumber" IS NOT NULL AND request_row."endNumber" IS NOT NULL
      THEN request_row."endNumber"-request_row."startNumber"+1 END);
  IF requested_quantity NOT BETWEEN 1 AND 200000 THEN RAISE EXCEPTION 'QR_INVALID_INPUT'; END IF;

  SELECT app_rls.qr_allocate_range(
    p_capability,'qr-range-allocate',request_row.id,request_row."licenseeId",0,requested_quantity,
    request_row."batchName",'REQUEST_APPROVAL'
  ) INTO allocation;

  SELECT * INTO STRICT actor FROM app_rls.qr_bind_actor(
    p_capability,p_purpose,p_request_id,request_row."licenseeId"
  );
  PERFORM set_config('app.qr_target_request_id',request_row.id,true);
  UPDATE public."QrAllocationRequest" r SET
    status='APPROVED'::public."QrAllocationRequestStatus",
    "approvedByUserId"=actor."userId","approvedAt"=transaction_timestamp(),
    "decisionNote"=nullif(btrim(p_decision_note),''),
    "startNumber"=substring(allocation->>'startCode' FROM '[0-9]+$')::integer,
    "endNumber"=substring(allocation->>'endCode' FROM '[0-9]+$')::integer,
    quantity=requested_quantity,"updatedAt"=transaction_timestamp()
    WHERE r.id=request_row.id AND r.status='PENDING'::public."QrAllocationRequestStatus"
    RETURNING jsonb_build_object(
      'id',r.id,'licenseeId',r."licenseeId",'requestedByUserId',r."requestedByUserId",
      'quantity',r.quantity,'batchName',r."batchName",'status',r.status,
      'startNumber',r."startNumber",'endNumber',r."endNumber"
    ) INTO updated;
  IF updated IS NULL THEN RAISE EXCEPTION 'QR_REQUEST_ALREADY_PROCESSED'; END IF;
  PERFORM app_rls.qr_write_audit(
    actor."userId",actor."organizationId",request_row."licenseeId",
    'APPROVE_QR_ALLOCATION_REQUEST','QrAllocationRequest',request_row.id,
    jsonb_build_object('rangeId',allocation->'range'->>'id','startCode',allocation->>'startCode',
      'endCode',allocation->>'endCode','quantity',requested_quantity,'receivedBatchId',allocation->>'receivedBatchId')
  );
  RETURN jsonb_build_object('request',updated,'allocation',allocation);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.qr_write_audit(
  p_actor_id text,p_org_id text,p_licensee_id text,p_action text,p_entity_type text,p_entity_id text,p_details jsonb
) RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE audit_id text:=gen_random_uuid()::text; outbox_id text:=gen_random_uuid()::text; now_at timestamp without time zone:=transaction_timestamp();
BEGIN
  IF p_action !~ '^[A-Z0-9_]{1,120}$' OR p_entity_type NOT IN ('QRRange','QRCode','Batch','QrAllocationRequest') THEN
    RAISE EXCEPTION 'QR_INVALID_AUDIT';
  END IF;
  PERFORM set_config('app.qr_audit_id',audit_id,true),set_config('app.qr_outbox_id',outbox_id,true);
  INSERT INTO public."AuditLog"(id,"userId","orgId","licenseeId",action,"entityType","entityId",details,"createdAt")
  VALUES(audit_id,p_actor_id,p_org_id,p_licensee_id,p_action,p_entity_type,p_entity_id,p_details,now_at);
  INSERT INTO public."SecurityEventOutbox"(id,"eventType",payload,"requestId","organizationId","licenseeId","initiatingUserId","updatedAt")
  VALUES(outbox_id,'AUDIT_LOG',jsonb_build_object('id',audit_id,'action',p_action,'entityType',p_entity_type,
    'entityId',p_entity_id,'userId',p_actor_id,'orgId',p_org_id,'licenseeId',p_licensee_id,'details',p_details,'createdAt',now_at),
    current_setting('app.request_id',true),p_org_id,p_licensee_id,p_actor_id,now_at);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.qr_batch_command(
  p_capability text,p_purpose text,p_request_id text,p_operation text,p_payload jsonb
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; source_batch record; target_licensee text; target_org text;
  target_manufacturer text; batch_id text; quantity integer; batch_name text;
  ids text[]; selected_ids text[]; selected_count integer; affected integer;
  start_code text; end_code text; remaining_count integer; remaining_start text; remaining_end text;
  result jsonb;
BEGIN
  IF p_purpose<>'qr-batch-command' OR p_operation NOT IN ('CREATE_BATCH','DELETE_BATCH','BULK_DELETE_BATCHES','ASSIGN_MANUFACTURER')
     OR jsonb_typeof(p_payload)<>'object' THEN
    RAISE EXCEPTION 'QR_BOUNDARY_DENIED' USING ERRCODE='42501';
  END IF;
  SELECT * INTO STRICT actor FROM app_rls.qr_bind_actor(p_capability,p_purpose,p_request_id,NULL);

  IF p_operation='CREATE_BATCH' THEN
    IF actor.role<>'LICENSEE_ADMIN' OR actor."licenseeId" IS NULL THEN
      RAISE EXCEPTION 'QR_BOUNDARY_DENIED' USING ERRCODE='42501';
    END IF;
    target_licensee:=actor."licenseeId";
    quantity:=NULLIF(p_payload->>'quantity','')::integer;
    batch_name:=btrim(p_payload->>'name');
    target_manufacturer:=NULLIF(p_payload->>'manufacturerId','');
    IF quantity NOT BETWEEN 1 AND 500000 OR length(batch_name) NOT BETWEEN 2 AND 120
       OR (target_manufacturer IS NOT NULL AND target_manufacturer !~* '^[0-9a-f-]{36}$') THEN
      RAISE EXCEPTION 'QR_INVALID_INPUT';
    END IF;
    SELECT * INTO STRICT actor FROM app_rls.qr_bind_actor(p_capability,p_purpose,p_request_id,target_licensee);
    PERFORM set_config('app.qr_batch_action',p_operation,true);
    IF target_manufacturer IS NOT NULL THEN
      PERFORM set_config('app.qr_target_manufacturer_id',target_manufacturer,true);
      IF NOT EXISTS (
        SELECT 1 FROM public."User" u
        JOIN public."ManufacturerLicenseeLink" ml ON ml."manufacturerId"=u.id AND ml."licenseeId"=target_licensee
        WHERE u.id=target_manufacturer AND u.role='MANUFACTURER_ADMIN'::public."UserRole"
          AND u."isActive" AND u.status='ACTIVE'::public."UserStatus"
          AND u."disabledAt" IS NULL AND u."deletedAt" IS NULL
      ) THEN RAISE EXCEPTION 'QR_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('qr_batch_'||target_licensee,0));
    SELECT array_agg(q.id ORDER BY q."displayCode",q."createdAt"),count(*),
           min(q."displayCode"),max(q."displayCode")
      INTO selected_ids,selected_count,start_code,end_code
      FROM (SELECT q.id,q."displayCode",q."createdAt" FROM public."QRCode" q
            WHERE q."licenseeId"=target_licensee AND q."batchId" IS NULL
              AND q.status='DORMANT'::public."QRStatus" AND q."displayCode" IS NOT NULL
            ORDER BY q."displayCode",q."createdAt" FOR UPDATE SKIP LOCKED LIMIT quantity) q;
    IF selected_count<>quantity THEN RAISE EXCEPTION 'QR_CAPACITY_EXHAUSTED'; END IF;
    batch_id:=gen_random_uuid()::text;
    PERFORM set_config('app.qr_target_batch_id',batch_id,true),
            set_config('app.qr_target_code_ids',array_to_string(selected_ids,','),true);
    INSERT INTO public."Batch"(id,name,"licenseeId","manufacturerId","startCode","endCode","totalCodes","lifecycleState","updatedAt")
    VALUES(batch_id,batch_name,target_licensee,target_manufacturer,start_code,end_code,quantity,'CODES_GENERATED'::public."BatchLifecycleState",transaction_timestamp());
    UPDATE public."QRCode" SET "batchId"=batch_id,status='ALLOCATED'::public."QRStatus",
      "printJobId"=NULL,"tokenNonce"=NULL,"tokenIssuedAt"=NULL,"tokenExpiresAt"=NULL,"tokenHash"=NULL,
      "printedAt"=NULL,"printedByUserId"=NULL,"redeemedAt"=NULL,"redeemedDeviceFingerprint"=NULL,
      "updatedAt"=transaction_timestamp()
      WHERE id=ANY(selected_ids) AND "licenseeId"=target_licensee AND "batchId" IS NULL AND status='DORMANT'::public."QRStatus";
    GET DIAGNOSTICS affected=ROW_COUNT;
    IF affected<>quantity THEN RAISE EXCEPTION 'BATCH_BUSY'; END IF;
    SELECT l."orgId" INTO STRICT target_org FROM public."Licensee" l WHERE l.id=target_licensee;
    PERFORM app_rls.qr_write_audit(actor."userId",target_org,target_licensee,'ALLOCATED','Batch',batch_id,
      jsonb_build_object('context','CREATE_BATCH','quantity',quantity,'manufacturerId',target_manufacturer));
    RETURN jsonb_build_object('id',batch_id,'name',batch_name,'licenseeId',target_licensee,
      'manufacturerId',target_manufacturer,'startCode',start_code,'endCode',end_code,
      'totalCodes',quantity,'lifecycleState','CODES_GENERATED');
  END IF;

  IF p_operation IN ('DELETE_BATCH','ASSIGN_MANUFACTURER') THEN
    IF p_payload->>'batchId' !~* '^[0-9a-f-]{36}$' THEN RAISE EXCEPTION 'QR_INVALID_INPUT'; END IF;
    PERFORM set_config('app.qr_source_batch_id',p_payload->>'batchId',true);
    SELECT b.* INTO source_batch FROM public."Batch" b WHERE b.id=p_payload->>'batchId' FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'QR_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;
    target_licensee:=source_batch."licenseeId";
    SELECT * INTO STRICT actor FROM app_rls.qr_bind_actor(p_capability,p_purpose,p_request_id,target_licensee);
    PERFORM set_config('app.qr_batch_action',p_operation,true);
    PERFORM set_config('app.qr_source_batch_id',source_batch.id,true);
  END IF;

  IF p_operation='DELETE_BATCH' THEN
    IF actor.role NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN','LICENSEE_ADMIN')
       OR source_batch."printedAt" IS NOT NULL OR source_batch."releasedAt" IS NOT NULL
       OR EXISTS (SELECT 1 FROM public."Batch" b WHERE b."parentBatchId"=source_batch.id OR b."rootBatchId"=source_batch.id)
    THEN RAISE EXCEPTION 'INVALID_STATE_TRANSITION'; END IF;
    PERFORM set_config('app.qr_target_batch_ids',source_batch.id,true);
    UPDATE public."QRCode" SET "batchId"=NULL,status='DORMANT'::public."QRStatus",
      "printJobId"=NULL,"tokenNonce"=NULL,"tokenIssuedAt"=NULL,"tokenExpiresAt"=NULL,"tokenHash"=NULL,
      "printedAt"=NULL,"printedByUserId"=NULL,"redeemedAt"=NULL,"redeemedDeviceFingerprint"=NULL,
      "updatedAt"=transaction_timestamp()
      WHERE "batchId"=source_batch.id AND "licenseeId"=target_licensee
        AND status NOT IN ('PRINTED'::public."QRStatus",'REDEEMED'::public."QRStatus",'SCANNED'::public."QRStatus");
    GET DIAGNOSTICS affected=ROW_COUNT;
    DELETE FROM public."Batch" WHERE id=source_batch.id AND "printedAt" IS NULL AND "releasedAt" IS NULL;
    IF NOT FOUND THEN RAISE EXCEPTION 'INVALID_STATE_TRANSITION'; END IF;
    SELECT l."orgId" INTO STRICT target_org FROM public."Licensee" l WHERE l.id=target_licensee;
    PERFORM app_rls.qr_write_audit(actor."userId",target_org,target_licensee,'DELETE_BATCH','Batch',source_batch.id,
      jsonb_build_object('unassignedCount',affected));
    RETURN jsonb_build_object('deletedBatchId',source_batch.id,'unassignedCount',affected);
  END IF;

  IF p_operation='BULK_DELETE_BATCHES' THEN
    IF actor.role NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN','LICENSEE_ADMIN')
       OR jsonb_typeof(p_payload->'batchIds')<>'array' THEN RAISE EXCEPTION 'QR_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;
    SELECT array_agg(DISTINCT value) INTO ids FROM jsonb_array_elements_text(p_payload->'batchIds');
    IF coalesce(cardinality(ids),0) NOT BETWEEN 1 AND 500 OR EXISTS (SELECT 1 FROM unnest(ids) id WHERE id !~* '^[0-9a-f-]{36}$')
    THEN RAISE EXCEPTION 'QR_INVALID_INPUT'; END IF;
    PERFORM set_config('app.qr_target_batch_ids',array_to_string(ids,','),true);
    SELECT count(DISTINCT b."licenseeId"),min(b."licenseeId") INTO selected_count,target_licensee
      FROM public."Batch" b WHERE b.id=ANY(ids);
    IF selected_count<>1 THEN RAISE EXCEPTION 'QR_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;
    SELECT * INTO STRICT actor FROM app_rls.qr_bind_actor(p_capability,p_purpose,p_request_id,target_licensee);
    PERFORM set_config('app.qr_batch_action',p_operation,true);
    PERFORM set_config('app.qr_target_batch_ids',array_to_string(ids,','),true);
    IF (SELECT count(*) FROM public."Batch" b WHERE b.id=ANY(ids))<>cardinality(ids)
       OR EXISTS (SELECT 1 FROM public."Batch" b WHERE b.id=ANY(ids) AND (b."printedAt" IS NOT NULL OR b."releasedAt" IS NOT NULL))
       OR EXISTS (SELECT 1 FROM public."Batch" b WHERE b."parentBatchId"=ANY(ids) OR b."rootBatchId"=ANY(ids))
    THEN RAISE EXCEPTION 'INVALID_STATE_TRANSITION'; END IF;
    UPDATE public."QRCode" SET "batchId"=NULL,status='DORMANT'::public."QRStatus",
      "printJobId"=NULL,"tokenNonce"=NULL,"tokenIssuedAt"=NULL,"tokenExpiresAt"=NULL,"tokenHash"=NULL,
      "printedAt"=NULL,"printedByUserId"=NULL,"redeemedAt"=NULL,"redeemedDeviceFingerprint"=NULL,
      "updatedAt"=transaction_timestamp()
      WHERE "batchId"=ANY(ids) AND "licenseeId"=target_licensee
        AND status NOT IN ('PRINTED'::public."QRStatus",'REDEEMED'::public."QRStatus",'SCANNED'::public."QRStatus");
    GET DIAGNOSTICS affected=ROW_COUNT;
    DELETE FROM public."Batch" WHERE id=ANY(ids);
    GET DIAGNOSTICS selected_count=ROW_COUNT;
    IF selected_count<>cardinality(ids) THEN RAISE EXCEPTION 'BATCH_BUSY'; END IF;
    SELECT l."orgId" INTO STRICT target_org FROM public."Licensee" l WHERE l.id=target_licensee;
    PERFORM app_rls.qr_write_audit(actor."userId",target_org,target_licensee,'BULK_DELETE_BATCHES','Batch',ids[1],
      jsonb_build_object('batchIds',ids,'deletedCount',selected_count,'unassignedCount',affected));
    RETURN jsonb_build_object('deletedCount',selected_count,'unassignedCount',affected);
  END IF;

  IF p_operation='ASSIGN_MANUFACTURER' THEN
    target_manufacturer:=p_payload->>'manufacturerId';
    quantity:=NULLIF(p_payload->>'quantity','')::integer;
    batch_name:=NULLIF(btrim(p_payload->>'name'),'');
    IF actor.role<>'LICENSEE_ADMIN' OR target_manufacturer !~* '^[0-9a-f-]{36}$'
       OR quantity NOT BETWEEN 1 AND 500000 OR source_batch."printedAt" IS NOT NULL
       OR source_batch."releasedAt" IS NOT NULL OR source_batch."manufacturerId" IS NOT NULL
    THEN RAISE EXCEPTION 'QR_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;
    PERFORM set_config('app.qr_target_manufacturer_id',target_manufacturer,true);
    IF NOT EXISTS (
      SELECT 1 FROM public."User" u JOIN public."ManufacturerLicenseeLink" ml
        ON ml."manufacturerId"=u.id AND ml."licenseeId"=target_licensee
      WHERE u.id=target_manufacturer AND u.role='MANUFACTURER_ADMIN'::public."UserRole"
        AND u."isActive" AND u.status='ACTIVE'::public."UserStatus"
        AND u."disabledAt" IS NULL AND u."deletedAt" IS NULL
    ) THEN RAISE EXCEPTION 'QR_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('qr_batch_'||source_batch.id,0));
    SELECT array_agg(q.id ORDER BY q."displayCode",q."createdAt"),count(*),min(q."displayCode"),max(q."displayCode")
      INTO selected_ids,selected_count,start_code,end_code FROM (
        SELECT q.id,q."displayCode",q."createdAt" FROM public."QRCode" q
        WHERE q."batchId"=source_batch.id AND q.status IN ('DORMANT','ACTIVE','ALLOCATED')
          AND q."printJobId" IS NULL AND q."displayCode" IS NOT NULL
        ORDER BY q."displayCode",q."createdAt" FOR UPDATE SKIP LOCKED LIMIT quantity
      ) q;
    IF selected_count<>quantity THEN RAISE EXCEPTION 'QR_CAPACITY_EXHAUSTED'; END IF;
    batch_id:=gen_random_uuid()::text;
    batch_name:=coalesce(batch_name,source_batch.name||' allocation');
    IF length(batch_name) NOT BETWEEN 2 AND 120 THEN RAISE EXCEPTION 'QR_INVALID_INPUT'; END IF;
    PERFORM set_config('app.qr_target_batch_id',batch_id,true),
            set_config('app.qr_source_batch_id',source_batch.id,true),
            set_config('app.qr_target_code_ids',array_to_string(selected_ids,','),true);
    INSERT INTO public."Batch"(id,name,"licenseeId","manufacturerId","parentBatchId","rootBatchId","startCode","endCode","totalCodes","lifecycleState","updatedAt")
    VALUES(batch_id,batch_name,target_licensee,target_manufacturer,source_batch.id,coalesce(source_batch."rootBatchId",source_batch.id),
      start_code,end_code,quantity,'CODES_GENERATED'::public."BatchLifecycleState",transaction_timestamp());
    UPDATE public."QRCode" SET "batchId"=batch_id,status='ALLOCATED'::public."QRStatus",
      "printJobId"=NULL,"tokenNonce"=NULL,"tokenIssuedAt"=NULL,"tokenExpiresAt"=NULL,"tokenHash"=NULL,
      "printedAt"=NULL,"printedByUserId"=NULL,"redeemedAt"=NULL,"redeemedDeviceFingerprint"=NULL,
      "updatedAt"=transaction_timestamp() WHERE id=ANY(selected_ids) AND "batchId"=source_batch.id;
    GET DIAGNOSTICS affected=ROW_COUNT;
    IF affected<>quantity THEN RAISE EXCEPTION 'BATCH_BUSY'; END IF;
    SELECT count(*),min("displayCode"),max("displayCode") INTO remaining_count,remaining_start,remaining_end
      FROM public."QRCode" WHERE "batchId"=source_batch.id;
    UPDATE public."Batch" SET "totalCodes"=remaining_count,
      "startCode"=coalesce(remaining_start,"startCode"),"endCode"=coalesce(remaining_end,"endCode"),
      "updatedAt"=transaction_timestamp() WHERE id=source_batch.id;
    SELECT l."orgId" INTO STRICT target_org FROM public."Licensee" l WHERE l.id=target_licensee;
    PERFORM app_rls.qr_write_audit(actor."userId",target_org,target_licensee,'ALLOCATED','Batch',batch_id,
      jsonb_build_object('context','ASSIGN_MANUFACTURER','sourceBatchId',source_batch.id,
        'manufacturerId',target_manufacturer,'quantity',quantity));
    RETURN jsonb_build_object('newBatchId',batch_id,'newBatchName',batch_name,'allocated',quantity,
      'startCode',start_code,'endCode',end_code,'sourceBatchId',source_batch.id,'sourceBatchName',source_batch.name,
      'sourceRemainingCodes',remaining_count,'sourceRemainingStartCode',remaining_start,'sourceRemainingEndCode',remaining_end,
      'manufacturerId',target_manufacturer,'licenseeId',target_licensee);
  END IF;
  RAISE EXCEPTION 'QR_BOUNDARY_DENIED' USING ERRCODE='42501';
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.qr_allocate_range(
  p_capability text,p_purpose text,p_request_id text,p_licensee_id text,
  p_start_number integer,p_end_number integer,p_received_batch_name text,p_source text
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; l record; range_id text:=gen_random_uuid()::text; batch_id text:=gen_random_uuid()::text;
  start_code text; end_code text; total integer; result jsonb;
BEGIN
  SELECT * INTO STRICT actor FROM app_rls.qr_bind_actor(p_capability,p_purpose,p_request_id,p_licensee_id);
  IF actor.role NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') OR p_purpose<>'qr-range-allocate'
     OR p_start_number<0 OR p_end_number<1 OR (p_start_number>0 AND p_end_number<p_start_number)
     OR p_source NOT IN ('ADMIN_TOPUP','ADMIN_GENERATE','REQUEST_APPROVAL') THEN
    RAISE EXCEPTION 'QR_BOUNDARY_DENIED' USING ERRCODE='42501';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('qr_alloc_'||p_licensee_id,0));
  SELECT id,"orgId",prefix INTO STRICT l FROM public."Licensee" WHERE id=p_licensee_id;
  IF p_start_number=0 THEN
    total:=p_end_number;
    IF total>200000 THEN RAISE EXCEPTION 'QR_INVALID_INPUT'; END IF;
    SELECT coalesce(max(substring(q."displayCode" FROM length(l.prefix)+1)::integer),0)+1
      INTO p_start_number FROM public."QRCode" q
      WHERE q."licenseeId"=p_licensee_id AND q."displayCode" ~ ('^'||l.prefix||'[0-9]{10}$');
    p_end_number:=p_start_number+total-1;
  END IF;
  IF p_end_number-p_start_number+1>200000 THEN RAISE EXCEPTION 'QR_INVALID_INPUT'; END IF;
  start_code:=l.prefix||lpad(p_start_number::text,10,'0');
  end_code:=l.prefix||lpad(p_end_number::text,10,'0');
  total:=p_end_number-p_start_number+1;
  PERFORM set_config('app.qr_target_batch_id',batch_id,true);
  IF EXISTS (SELECT 1 FROM public."QRCode" q WHERE q."licenseeId"=p_licensee_id AND q."displayCode">=start_code AND q."displayCode"<=end_code)
     OR EXISTS (SELECT 1 FROM public."QRRange" r WHERE r."licenseeId"=p_licensee_id AND NOT (r."endCode"<start_code OR r."startCode">end_code)) THEN
    RAISE EXCEPTION 'QR_RANGE_OVERLAP' USING ERRCODE='23505';
  END IF;
  INSERT INTO public."QRRange"(id,"licenseeId","startCode","endCode","totalCodes","usedCodes","updatedAt")
  VALUES(range_id,p_licensee_id,start_code,end_code,total,0,transaction_timestamp());
  INSERT INTO public."Batch"(id,name,"licenseeId","startCode","endCode","totalCodes","lifecycleState","updatedAt")
  VALUES(batch_id,left(coalesce(nullif(btrim(p_received_batch_name),''),'Received '||start_code||' -> '||end_code),120),
    p_licensee_id,start_code,end_code,total,'DRAFT'::public."BatchLifecycleState",transaction_timestamp());
  INSERT INTO public."QRCode"(id,code,"displayCode","licenseeId","batchId",status,"tokenNonce","updatedAt")
  SELECT gen_random_uuid()::text,
    'c_'||encode(sha256(convert_to('qr-code:'||gen_random_uuid()::text||gen_random_uuid()::text,'UTF8')),'hex'),
    l.prefix||lpad(n::text,10,'0'),p_licensee_id,batch_id,'DORMANT'::public."QRStatus",
    encode(sha256(convert_to('qr-nonce:'||gen_random_uuid()::text||gen_random_uuid()::text,'UTF8')),'hex'),transaction_timestamp()
  FROM generate_series(p_start_number,p_end_number) n;
  INSERT INTO public."AllocationEvent"(id,"licenseeId","createdByUserId","requestId",source,"startCode","endCode","totalCodes")
  VALUES(gen_random_uuid()::text,p_licensee_id,actor."userId",
    CASE WHEN p_source='REQUEST_APPROVAL' THEN p_request_id ELSE NULL END,
    p_source,start_code,end_code,total);
  PERFORM app_rls.qr_write_audit(actor."userId",l."orgId",p_licensee_id,'ALLOCATED','QRRange',range_id,
    jsonb_build_object('requestId',p_request_id,'source',p_source,'startCode',start_code,'endCode',end_code,'created',total,'receivedBatchId',batch_id));
  SELECT jsonb_build_object('range',to_jsonb(r),'startCode',start_code,'endCode',end_code,'totalCodes',total,
    'receivedBatchId',batch_id,'receivedBatchName',b.name,'codes',COALESCE((SELECT jsonb_agg(jsonb_build_object(
      'id',q.id,'licenseeId',q."licenseeId",'batchId',q."batchId",'replayEpoch',q."replayEpoch",'tokenNonce',q."tokenNonce",
      'tokenIssuedAt',q."tokenIssuedAt",'tokenExpiresAt',q."tokenExpiresAt") ORDER BY q."displayCode")
      FROM public."QRCode" q WHERE q."batchId"=batch_id),'[]'::jsonb))
    INTO result FROM public."QRRange" r JOIN public."Batch" b ON b.id=batch_id WHERE r.id=range_id;
  RETURN result;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.qr_read_codes(
  p_capability text,p_purpose text,p_request_id text,p_licensee_id text,p_status text,p_query text,p_limit integer,p_offset integer
) RETURNS TABLE(payload jsonb,total bigint)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record;
BEGIN
  SELECT * INTO STRICT actor FROM app_rls.qr_bind_actor(p_capability,p_purpose,p_request_id,p_licensee_id);
  IF p_purpose<>'qr-code-read' OR p_limit NOT BETWEEN 1 AND 500000 OR p_offset<0
     OR (p_status IS NOT NULL AND p_status NOT IN ('DORMANT','ACTIVE','ALLOCATED','ACTIVATED','PRINTED','REDEEMED','BLOCKED','SCANNED'))
  THEN RAISE EXCEPTION 'QR_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;
  RETURN QUERY WITH visible AS (
    SELECT q.id,q.code,q."displayCode",q."licenseeId",q."batchId",q.status,
      q."scanCount",q."createdAt",q."scannedAt",q."printedAt",
      l.name AS licensee_name,l.prefix,b.name AS batch_name,b."printedAt" AS batch_printed_at
    FROM public."QRCode" q JOIN public."Licensee" l ON l.id=q."licenseeId" LEFT JOIN public."Batch" b ON b.id=q."batchId"
    WHERE (p_licensee_id IS NULL OR q."licenseeId"=p_licensee_id)
      AND (p_status IS NULL OR q.status::text=p_status)
      AND (nullif(btrim(p_query),'') IS NULL OR q.code ILIKE '%'||btrim(p_query)||'%' OR q."displayCode" ILIKE '%'||btrim(p_query)||'%')
  ), page AS (SELECT * FROM visible ORDER BY "displayCode" NULLS LAST,"createdAt",id LIMIT p_limit OFFSET p_offset)
  SELECT COALESCE(jsonb_agg(jsonb_build_object(
    'id',id,'code',code,'displayCode',"displayCode",'licenseeId',"licenseeId",'batchId',"batchId",'status',status,
    'scanCount',"scanCount",'createdAt',"createdAt",'scannedAt',"scannedAt",'printedAt',"printedAt",
    'licensee',jsonb_build_object('name',licensee_name,'prefix',prefix),
    'batch',CASE WHEN "batchId" IS NULL THEN NULL ELSE jsonb_build_object('id',"batchId",'name',batch_name,'printedAt',batch_printed_at) END
  ) ORDER BY "displayCode" NULLS LAST,"createdAt",id),'[]'::jsonb),(SELECT count(*) FROM visible) FROM page;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.qr_stats(
  p_capability text,p_purpose text,p_request_id text,p_licensee_id text
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; result jsonb;
BEGIN
  SELECT * INTO STRICT actor FROM app_rls.qr_bind_actor(p_capability,p_purpose,p_request_id,p_licensee_id);
  IF p_purpose<>'qr-code-stats' THEN RAISE EXCEPTION 'QR_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;
  SELECT jsonb_build_object('total',COALESCE(sum(cnt),0),'byStatus',COALESCE(jsonb_object_agg(status,cnt),'{}'::jsonb))
    INTO result FROM (SELECT status::text AS status,count(*) AS cnt FROM public."QRCode"
      WHERE p_licensee_id IS NULL OR "licenseeId"=p_licensee_id GROUP BY status) s;
  RETURN result;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.qr_inventory_projection(
  p_capability text,p_purpose text,p_request_id text,p_licensee_id text,
  p_manufacturer_id text,p_batch_query text,p_code_query text,p_status text,p_limit integer,p_offset integer
) RETURNS TABLE(payload jsonb,total bigint)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record;
BEGIN
  IF p_purpose<>'qr-inventory-read'
     OR (p_manufacturer_id IS NOT NULL AND p_manufacturer_id !~* '^[0-9a-f-]{36}$')
     OR length(coalesce(p_batch_query,''))>120 OR length(coalesce(p_code_query,''))>160
     OR p_limit NOT BETWEEN 1 AND 500 OR p_offset<0
     OR (p_status IS NOT NULL AND p_status NOT IN ('DORMANT','ACTIVE','ALLOCATED','ACTIVATED','PRINTED','REDEEMED','BLOCKED','SCANNED'))
  THEN RAISE EXCEPTION 'QR_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;
  SELECT * INTO STRICT actor FROM app_rls.qr_bind_actor(p_capability,p_purpose,p_request_id,p_licensee_id);
  IF actor.role='MANUFACTURER_ADMIN' AND p_manufacturer_id IS DISTINCT FROM actor."userId" THEN
    RAISE EXCEPTION 'QR_BOUNDARY_DENIED' USING ERRCODE='42501';
  END IF;
  RETURN QUERY WITH matching_batches AS MATERIALIZED (
    SELECT b.id,b.name,b."licenseeId",b."manufacturerId",b."startCode",b."endCode",b."totalCodes",b."createdAt"
    FROM public."Batch" b
    WHERE (p_licensee_id IS NULL OR b."licenseeId"=p_licensee_id)
      AND (p_manufacturer_id IS NULL OR b."manufacturerId"=p_manufacturer_id)
      AND (nullif(btrim(p_batch_query),'') IS NULL OR b.id ILIKE '%'||btrim(p_batch_query)||'%' OR b.name ILIKE '%'||btrim(p_batch_query)||'%')
      AND ((nullif(btrim(p_code_query),'') IS NULL AND p_status IS NULL) OR EXISTS (
        SELECT 1 FROM public."QRCode" matching_q
        WHERE matching_q."batchId"=b.id
          AND (nullif(btrim(p_code_query),'') IS NULL OR matching_q.code ILIKE '%'||btrim(p_code_query)||'%')
          AND (p_status IS NULL OR matching_q.status::text=p_status)
      ))
  ), page AS MATERIALIZED (
    SELECT * FROM matching_batches ORDER BY "createdAt" DESC,id LIMIT p_limit OFFSET p_offset
  ), scope_grouped AS MATERIALIZED (
    SELECT b.id,b."createdAt",q.status::text AS status,count(q.id)::integer AS count
    FROM matching_batches b LEFT JOIN public."QRCode" q ON q."batchId"=b.id
      AND (nullif(btrim(p_code_query),'') IS NULL OR q.code ILIKE '%'||btrim(p_code_query)||'%')
      AND (p_status IS NULL OR q.status::text=p_status)
    GROUP BY b.id,b."createdAt",q.status
  ), scope_days AS (
    SELECT date_trunc('day',"createdAt") AS day,
      sum(count)::bigint AS total,
      sum(count) FILTER (WHERE status IN ('DORMANT','ACTIVE'))::bigint AS dormant,
      sum(count) FILTER (WHERE status IN ('ALLOCATED','ACTIVATED'))::bigint AS allocated,
      sum(count) FILTER (WHERE status='PRINTED')::bigint AS printed,
      sum(count) FILTER (WHERE status IN ('REDEEMED','SCANNED'))::bigint AS redeemed,
      sum(count) FILTER (WHERE status='BLOCKED')::bigint AS blocked
    FROM scope_grouped GROUP BY date_trunc('day',"createdAt")
  ), scope AS (
    SELECT jsonb_build_object(
      'totals',jsonb_build_object(
        'total',COALESCE(sum(sg.count),0),
        'dormant',COALESCE(sum(sg.count) FILTER (WHERE sg.status IN ('DORMANT','ACTIVE')),0),
        'allocated',COALESCE(sum(sg.count) FILTER (WHERE sg.status IN ('ALLOCATED','ACTIVATED')),0),
        'printed',COALESCE(sum(sg.count) FILTER (WHERE sg.status='PRINTED'),0),
        'redeemed',COALESCE(sum(sg.count) FILTER (WHERE sg.status IN ('REDEEMED','SCANNED')),0),
        'blocked',COALESCE(sum(sg.count) FILTER (WHERE sg.status='BLOCKED'),0),
        'created',(SELECT count(*) FROM matching_batches)
      ),
      'trend',COALESCE((
        SELECT jsonb_agg(jsonb_build_object(
          'label',to_char(d.day,'Mon DD'),'total',d.total,'dormant',COALESCE(d.dormant,0),
          'allocated',COALESCE(d.allocated,0),'printed',COALESCE(d.printed,0),
          'redeemed',COALESCE(d.redeemed,0),'blocked',COALESCE(d.blocked,0),'scanEvents',0
        ) ORDER BY d.day) FROM scope_days d
      ),'[]'::jsonb)
    ) AS aggregate
    FROM scope_grouped sg
  ), grouped AS (
    SELECT b.id,b.name,b."licenseeId",b."manufacturerId",b."startCode",b."endCode",b."totalCodes",b."createdAt",
      q.status::text AS status,count(q.id)::integer AS count
    FROM page b LEFT JOIN public."QRCode" q ON q."batchId"=b.id
      AND (nullif(btrim(p_code_query),'') IS NULL OR q.code ILIKE '%'||btrim(p_code_query)||'%')
      AND (p_status IS NULL OR q.status::text=p_status)
    GROUP BY b.id,b.name,b."licenseeId",b."manufacturerId",b."startCode",b."endCode",b."totalCodes",b."createdAt",q.status
  ), tally AS (SELECT count(*)::bigint AS total FROM matching_batches)
  SELECT ordered.payload,ordered.total FROM (
    SELECT jsonb_build_object(
      'batchId',g.id,'name',g.name,'licenseeId',g."licenseeId",'manufacturerId',g."manufacturerId",
      'startCode',g."startCode",'endCode',g."endCode",'totalCodes',g."totalCodes",'createdAt',g."createdAt"
    ) || CASE WHEN g.status IS NULL THEN '{}'::jsonb ELSE jsonb_build_object('status',g.status,'count',g.count) END
      || jsonb_build_object('_scope',scope.aggregate),
    tally.total
    FROM grouped g CROSS JOIN tally CROSS JOIN scope
    UNION ALL
    SELECT jsonb_build_object('_scope',scope.aggregate),tally.total
    FROM tally CROSS JOIN scope WHERE NOT EXISTS (SELECT 1 FROM page)
  ) AS ordered(payload,total)
  ORDER BY ordered.payload->>'createdAt' DESC NULLS LAST,ordered.payload->>'batchId',ordered.payload->>'status';
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.qr_export_codes(
  p_capability text,p_purpose text,p_request_id text,p_batch_id text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; target_batch record; result jsonb; target_user_ids text;
BEGIN
  IF p_purpose<>'qr-audit-export' OR p_batch_id !~* '^[0-9a-f-]{36}$' THEN
    RAISE EXCEPTION 'QR_BOUNDARY_DENIED' USING ERRCODE='42501';
  END IF;
  SELECT * INTO STRICT actor FROM app_rls.qr_bind_actor(p_capability,p_purpose,p_request_id,NULL);
  IF actor.role NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN','LICENSEE_ADMIN') THEN
    RAISE EXCEPTION 'QR_BOUNDARY_DENIED' USING ERRCODE='42501';
  END IF;
  PERFORM set_config('app.qr_source_batch_id',p_batch_id,true);
  SELECT b.id,b.name,b."licenseeId",b."manufacturerId",b."startCode",b."endCode",b."totalCodes",
         b."printedAt",b."createdAt",b."updatedAt"
    INTO target_batch FROM public."Batch" b WHERE b.id=p_batch_id;
  IF NOT FOUND THEN RAISE EXCEPTION 'QR_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;
  SELECT * INTO STRICT actor FROM app_rls.qr_bind_actor(
    p_capability,p_purpose,p_request_id,target_batch."licenseeId"
  );
  PERFORM set_config('app.qr_source_batch_id',p_batch_id,true),
          set_config('app.qr_target_manufacturer_id',coalesce(target_batch."manufacturerId",''),true);
  SELECT string_agg(DISTINCT id,',' ORDER BY id) INTO target_user_ids FROM (
    SELECT t."userId" AS id FROM public."TraceEvent" t
      WHERE t."batchId"=p_batch_id AND t."licenseeId"=target_batch."licenseeId"
    UNION SELECT t."manufacturerId" FROM public."TraceEvent" t
      WHERE t."batchId"=p_batch_id AND t."licenseeId"=target_batch."licenseeId"
    UNION SELECT a."manufacturerId" FROM public."PolicyAlert" a
      WHERE a."batchId"=p_batch_id AND a."licenseeId"=target_batch."licenseeId"
    UNION SELECT a."acknowledgedByUserId" FROM public."PolicyAlert" a
      WHERE a."batchId"=p_batch_id AND a."licenseeId"=target_batch."licenseeId"
  ) scoped_users WHERE id IS NOT NULL;
  PERFORM set_config('app.qr_target_user_ids',coalesce(target_user_ids,''),true);
  SELECT jsonb_build_object(
    'batch',jsonb_build_object(
      'id',target_batch.id,'name',target_batch.name,'licenseeId',target_batch."licenseeId",
      'manufacturerId',target_batch."manufacturerId",'startCode',target_batch."startCode",
      'endCode',target_batch."endCode",'totalCodes',target_batch."totalCodes",
      'printedAt',target_batch."printedAt",'createdAt',target_batch."createdAt",'updatedAt',target_batch."updatedAt",
      'licensee',(SELECT jsonb_build_object('id',l.id,'name',l.name,'prefix',l.prefix)
        FROM public."Licensee" l WHERE l.id=target_batch."licenseeId"),
      'manufacturer',(SELECT jsonb_build_object('id',u.id,'name',u.name,'email',u.email)
        FROM public."User" u WHERE u.id=target_batch."manufacturerId")
    ),
    'qrCodes',(SELECT coalesce(jsonb_agg(jsonb_build_object(
        'id',q.id,'code',q.code,'status',q.status::text,'scanCount',q."scanCount",
        'printedAt',q."printedAt",'redeemedAt',q."redeemedAt",'blockedAt',q."blockedAt",
        'tokenHash',q."tokenHash",'tokenIssuedAt',q."tokenIssuedAt",'tokenExpiresAt',q."tokenExpiresAt",
        'createdAt',q."createdAt",'updatedAt',q."updatedAt"
      ) ORDER BY q.code),'[]'::jsonb) FROM public."QRCode" q WHERE q."batchId"=p_batch_id),
    'traceEvents',(SELECT coalesce(jsonb_agg(jsonb_build_object(
        'id',t.id,'eventType',t."eventType"::text,'licenseeId',t."licenseeId",'batchId',t."batchId",
        'qrCodeId',t."qrCodeId",'manufacturerId',t."manufacturerId",'userId',t."userId",
        'sourceAction',t."sourceAction",'details',t.details,'createdAt',t."createdAt",
        'user',(SELECT jsonb_build_object('id',u.id,'name',u.name,'email',u.email) FROM public."User" u WHERE u.id=t."userId"),
        'manufacturer',(SELECT jsonb_build_object('id',u.id,'name',u.name,'email',u.email) FROM public."User" u WHERE u.id=t."manufacturerId"),
        'qrCode',(SELECT jsonb_build_object('id',q.id,'code',q.code) FROM public."QRCode" q WHERE q.id=t."qrCodeId")
      ) ORDER BY t."createdAt",t.id),'[]'::jsonb)
      FROM public."TraceEvent" t WHERE t."batchId"=p_batch_id AND t."licenseeId"=target_batch."licenseeId"),
    'policyAlerts',(SELECT coalesce(jsonb_agg(jsonb_build_object(
        'id',a.id,'alertType',a."alertType"::text,'severity',a.severity::text,'score',a.score,
        'message',a.message,'licenseeId',a."licenseeId",'batchId',a."batchId",'qrCodeId',a."qrCodeId",
        'manufacturerId',a."manufacturerId",'acknowledgedAt',a."acknowledgedAt",
        'acknowledgedByUserId',a."acknowledgedByUserId",'details',a.details,'createdAt',a."createdAt",
        'acknowledgedByUser',(SELECT jsonb_build_object('id',u.id,'name',u.name,'email',u.email)
          FROM public."User" u WHERE u.id=a."acknowledgedByUserId")
      ) ORDER BY a."createdAt",a.id),'[]'::jsonb)
      FROM public."PolicyAlert" a WHERE a."batchId"=p_batch_id AND a."licenseeId"=target_batch."licenseeId")
  ) INTO result;
  RETURN result;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.qr_delete_codes(
  p_capability text,p_purpose text,p_request_id text,p_ids text[],p_codes text[]
) RETURNS integer LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; target_licensee text; affected integer;
BEGIN
  IF coalesce(cardinality(p_ids),0)+coalesce(cardinality(p_codes),0)<1 THEN RAISE EXCEPTION 'QR_INVALID_INPUT'; END IF;
  SELECT * INTO STRICT actor FROM app_rls.qr_bind_actor(p_capability,p_purpose,p_request_id,NULL);
  IF p_purpose<>'qr-code-delete' OR actor.role NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN','LICENSEE_ADMIN') THEN
    RAISE EXCEPTION 'QR_BOUNDARY_DENIED' USING ERRCODE='42501';
  END IF;
  SELECT q."licenseeId" INTO target_licensee FROM public."QRCode" q
    WHERE q.id=ANY(coalesce(p_ids,'{}'::text[])) OR q.code=ANY(coalesce(p_codes,'{}'::text[]))
    GROUP BY q."licenseeId";
  IF NOT FOUND OR EXISTS (SELECT 1 FROM public."QRCode" q WHERE (q.id=ANY(coalesce(p_ids,'{}'::text[])) OR q.code=ANY(coalesce(p_codes,'{}'::text[]))) AND q."licenseeId"<>target_licensee)
  THEN RAISE EXCEPTION 'QR_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;
  SELECT * INTO STRICT actor FROM app_rls.qr_bind_actor(p_capability,p_purpose,p_request_id,target_licensee);
  IF actor.role NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN','LICENSEE_ADMIN') THEN
    RAISE EXCEPTION 'QR_BOUNDARY_DENIED' USING ERRCODE='42501';
  END IF;
  DELETE FROM public."QRCode" q
    WHERE (q.id=ANY(coalesce(p_ids,'{}'::text[])) OR q.code=ANY(coalesce(p_codes,'{}'::text[])))
      AND q."batchId" IS NULL AND q.status IN ('DORMANT'::public."QRStatus",'ACTIVE'::public."QRStatus");
  GET DIAGNOSTICS affected=ROW_COUNT;
  PERFORM app_rls.qr_write_audit(actor."userId",actor."organizationId",target_licensee,'BULK_DELETE_QR_CODES','QRCode',NULL,
    jsonb_build_object('requestId',p_request_id,'deleted',affected));
  RETURN affected;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.qr_get_code_scope(
  p_capability text,p_purpose text,p_request_id text,p_qr_id text
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE target_licensee text; actor record; result jsonb;
BEGIN
  IF p_qr_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' THEN
    RAISE EXCEPTION 'QR_INVALID_INPUT';
  END IF;
  SELECT * INTO STRICT actor FROM app_rls.qr_bind_actor(p_capability,p_purpose,p_request_id,NULL);
  IF p_purpose<>'qr-code-scope' THEN RAISE EXCEPTION 'QR_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;
  SELECT "licenseeId" INTO target_licensee FROM public."QRCode" WHERE id=p_qr_id;
  IF NOT FOUND THEN RETURN NULL; END IF;
  SELECT * INTO STRICT actor FROM app_rls.qr_bind_actor(p_capability,p_purpose,p_request_id,target_licensee);
  SELECT jsonb_build_object('id',id,'licenseeId',"licenseeId",'batchId',"batchId") INTO result FROM public."QRCode" WHERE id=p_qr_id;
  RETURN result;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.qr_bind_break_glass_tokens(
  p_capability text,p_purpose text,p_request_id text,p_licensee_id text,p_tokens jsonb
) RETURNS integer LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; item jsonb; affected integer:=0; changed integer;
BEGIN
  SELECT * INTO STRICT actor FROM app_rls.qr_bind_actor(p_capability,p_purpose,p_request_id,p_licensee_id);
  IF actor.role NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') OR p_purpose<>'qr-code-token-bind' OR jsonb_typeof(p_tokens)<>'array'
     OR jsonb_array_length(p_tokens)>200000 THEN RAISE EXCEPTION 'QR_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;
  FOR item IN SELECT value FROM jsonb_array_elements(p_tokens) LOOP
    IF item->>'id' !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
       OR item->>'nonce' !~ '^(?:[a-f0-9]{64}|[A-Za-z0-9_-]{22})$'
       OR item->>'hash' !~ '^([0-9a-f]{12}:)?[a-f0-9]{64}$' THEN
      RAISE EXCEPTION 'QR_INVALID_INPUT';
    END IF;
    UPDATE public."QRCode" SET "tokenNonce"=item->>'nonce',"tokenIssuedAt"=(item->>'issuedAt')::timestamp,
      "tokenExpiresAt"=(item->>'expiresAt')::timestamp,"tokenHash"=item->>'hash',
      "issuanceMode"='BREAK_GLASS_DIRECT',"customerVerifiableAt"=NULL,"updatedAt"=transaction_timestamp()
    WHERE id=item->>'id' AND "licenseeId"=p_licensee_id AND status='DORMANT'::public."QRStatus"
      AND "tokenHash" IS NULL AND "tokenExpiresAt" IS NULL;
    GET DIAGNOSTICS changed=ROW_COUNT; affected:=affected+changed;
  END LOOP;
  IF affected<>jsonb_array_length(p_tokens) THEN RAISE EXCEPTION 'QR_TOKEN_BIND_CONFLICT'; END IF;
  RETURN affected;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.refresh_inventory_status_rollups(
  p_request_id text
) RETURNS integer LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE checkpoint_at timestamp; refreshed_at timestamp:=transaction_timestamp(); affected integer;
BEGIN
  IF session_user<>'mscqr_rls_cert_worker' OR p_request_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' THEN
    RAISE EXCEPTION 'ANALYTICS_ROLLUP_DENIED' USING ERRCODE='42501';
  END IF;
  PERFORM set_config('app.analytics_rollup_operation','inventory',true);
  PERFORM set_config('app.analytics_rollup_request_id',lower(p_request_id),true);
  PERFORM pg_advisory_xact_lock(hashtextextended('analytics-inventory-rollup',0));

  INSERT INTO public."SystemCheckpoint" ("key","value","createdAt","updatedAt")
  VALUES ('rollup:inventory-status','{}'::jsonb,refreshed_at,refreshed_at)
  ON CONFLICT ("key") DO NOTHING;
  SELECT CASE WHEN c."value"->>'cursor' ~ '^[0-9]{4}-' THEN (c."value"->>'cursor')::timestamp END
    INTO checkpoint_at
    FROM public."SystemCheckpoint" c
   WHERE c."key"='rollup:inventory-status'
   FOR UPDATE;

  WITH changed_batches AS (
    SELECT b.id
      FROM public."Batch" b
     WHERE checkpoint_at IS NULL
    UNION
    SELECT DISTINCT q."batchId"
      FROM public."QRCode" q
     WHERE checkpoint_at IS NOT NULL
       AND q."batchId" IS NOT NULL
       AND q."updatedAt">=checkpoint_at-interval '10 minutes'
  ), counts AS (
    SELECT b.id AS "batchId",b."licenseeId",b."manufacturerId",b."totalCodes",
      count(q.id) FILTER (WHERE q.status='DORMANT'::public."QRStatus")::integer AS dormant,
      count(q.id) FILTER (WHERE q.status='ACTIVE'::public."QRStatus")::integer AS active,
      count(q.id) FILTER (WHERE q.status='ACTIVATED'::public."QRStatus")::integer AS activated,
      count(q.id) FILTER (WHERE q.status='ALLOCATED'::public."QRStatus")::integer AS allocated,
      count(q.id) FILTER (WHERE q.status='PRINTED'::public."QRStatus")::integer AS printed,
      count(q.id) FILTER (WHERE q.status='REDEEMED'::public."QRStatus")::integer AS redeemed,
      count(q.id) FILTER (WHERE q.status='BLOCKED'::public."QRStatus")::integer AS blocked,
      count(q.id) FILTER (WHERE q.status='SCANNED'::public."QRStatus")::integer AS scanned
    FROM changed_batches changed
    JOIN public."Batch" b ON b.id=changed.id
    LEFT JOIN public."QRCode" q ON q."batchId"=b.id
    GROUP BY b.id,b."licenseeId",b."manufacturerId",b."totalCodes"
  )
  INSERT INTO public."InventoryStatusRollup"
    ("batchId","licenseeId","manufacturerId","totalCodes",dormant,active,activated,allocated,printed,redeemed,blocked,scanned,"refreshedAt","createdAt","updatedAt")
  SELECT "batchId","licenseeId","manufacturerId","totalCodes",dormant,active,activated,allocated,printed,redeemed,blocked,scanned,
         refreshed_at,refreshed_at,refreshed_at
    FROM counts
  ON CONFLICT ("batchId") DO UPDATE SET
    "licenseeId"=excluded."licenseeId","manufacturerId"=excluded."manufacturerId","totalCodes"=excluded."totalCodes",
    dormant=excluded.dormant,active=excluded.active,activated=excluded.activated,allocated=excluded.allocated,
    printed=excluded.printed,redeemed=excluded.redeemed,blocked=excluded.blocked,scanned=excluded.scanned,
    "refreshedAt"=excluded."refreshedAt","updatedAt"=excluded."updatedAt";
  GET DIAGNOSTICS affected=ROW_COUNT;

  UPDATE public."SystemCheckpoint"
     SET "value"=jsonb_build_object('cursor',to_char(refreshed_at,'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')),
         "updatedAt"=refreshed_at
   WHERE "key"='rollup:inventory-status';
  RETURN affected;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.refresh_scan_metrics_hourly_rollups(
  p_request_id text
) RETURNS integer LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE checkpoint_at timestamp; refreshed_at timestamp:=transaction_timestamp(); affected integer;
BEGIN
  IF session_user<>'mscqr_rls_cert_worker' OR p_request_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' THEN
    RAISE EXCEPTION 'ANALYTICS_ROLLUP_DENIED' USING ERRCODE='42501';
  END IF;
  PERFORM set_config('app.analytics_rollup_operation','scan-hourly',true);
  PERFORM set_config('app.analytics_rollup_request_id',lower(p_request_id),true);
  PERFORM pg_advisory_xact_lock(hashtextextended('analytics-scan-hourly-rollup',0));

  INSERT INTO public."SystemCheckpoint" ("key","value","createdAt","updatedAt")
  VALUES ('rollup:scan-metrics-hourly','{}'::jsonb,refreshed_at,refreshed_at)
  ON CONFLICT ("key") DO NOTHING;
  SELECT CASE WHEN c."value"->>'cursor' ~ '^[0-9]{4}-' THEN (c."value"->>'cursor')::timestamp END
    INTO checkpoint_at
    FROM public."SystemCheckpoint" c
   WHERE c."key"='rollup:scan-metrics-hourly'
   FOR UPDATE;

  WITH rows AS (
    SELECT date_trunc('hour',s."scannedAt") AS hour_bucket,s."licenseeId",s."batchId",b."manufacturerId",
      count(*)::integer AS total_scan_events,
      count(*) FILTER (WHERE s."isFirstScan")::integer AS first_scan_events,
      count(*) FILTER (WHERE NOT s."isFirstScan")::integer AS repeat_scan_events,
      count(*) FILTER (WHERE s.status='BLOCKED'::public."QRStatus")::integer AS blocked_events,
      count(*) FILTER (WHERE s."isTrustedOwnerContext")::integer AS trusted_owner_events,
      count(*) FILTER (WHERE NOT s."isTrustedOwnerContext")::integer AS external_events,
      count(*) FILTER (WHERE coalesce(nullif(s."locationName",''),nullif(s."locationCity",''),nullif(s."locationCountry",'')) IS NOT NULL)::integer AS named_location_events,
      count(*) FILTER (WHERE nullif(s.device,'') IS NOT NULL)::integer AS known_device_events,
      count(DISTINCT s."qrCodeId")::integer AS unique_qr_codes,
      min(s."scannedAt") AS first_scanned_at,max(s."scannedAt") AS last_scanned_at
    FROM public."QrScanLog" s
    LEFT JOIN public."Batch" b ON b.id=s."batchId"
    WHERE s."scannedAt">=coalesce(checkpoint_at-interval '2 hours',refreshed_at-interval '7 days')
    GROUP BY 1,2,3,4
  )
  INSERT INTO public."ScanMetricsHourlyRollup"
    (id,"bucketKey","hourBucket","licenseeId","batchId","manufacturerId","totalScanEvents","firstScanEvents",
     "repeatScanEvents","blockedEvents","trustedOwnerEvents","externalEvents","namedLocationEvents",
     "knownDeviceEvents","uniqueQrCodes","firstScannedAt","lastScannedAt","createdAt","updatedAt")
  SELECT gen_random_uuid()::text,
    concat(to_char(hour_bucket,'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),'|',"licenseeId",'|',coalesce("batchId",'__none__'),'|',coalesce("manufacturerId",'__none__')),
    hour_bucket,"licenseeId","batchId","manufacturerId",total_scan_events,first_scan_events,repeat_scan_events,
    blocked_events,trusted_owner_events,external_events,named_location_events,known_device_events,unique_qr_codes,
    first_scanned_at,last_scanned_at,refreshed_at,refreshed_at
  FROM rows
  ON CONFLICT ("bucketKey") DO UPDATE SET
    "totalScanEvents"=excluded."totalScanEvents","firstScanEvents"=excluded."firstScanEvents",
    "repeatScanEvents"=excluded."repeatScanEvents","blockedEvents"=excluded."blockedEvents",
    "trustedOwnerEvents"=excluded."trustedOwnerEvents","externalEvents"=excluded."externalEvents",
    "namedLocationEvents"=excluded."namedLocationEvents","knownDeviceEvents"=excluded."knownDeviceEvents",
    "uniqueQrCodes"=excluded."uniqueQrCodes","firstScannedAt"=excluded."firstScannedAt",
    "lastScannedAt"=excluded."lastScannedAt","updatedAt"=excluded."updatedAt";
  GET DIAGNOSTICS affected=ROW_COUNT;

  UPDATE public."SystemCheckpoint"
     SET "value"=jsonb_build_object('cursor',to_char(refreshed_at,'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')),
         "updatedAt"=refreshed_at
   WHERE "key"='rollup:scan-metrics-hourly';
  RETURN affected;
END
$fn$;

GRANT EXECUTE ON FUNCTION app_rls.qr_allocate_range(text,text,text,text,integer,integer,text,text) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.qr_approve_allocation_request(text,text,text,text,text) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.qr_batch_command(text,text,text,text,jsonb) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.qr_bind_break_glass_tokens(text,text,text,text,jsonb) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.qr_delete_codes(text,text,text,text[],text[]) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.qr_export_codes(text,text,text,text) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.qr_get_code_scope(text,text,text,text) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.qr_inventory_projection(text,text,text,text,text,text,text,text,integer,integer) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.qr_read_codes(text,text,text,text,text,text,integer,integer) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.qr_stats(text,text,text,text) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.refresh_inventory_status_rollups(text) TO "mscqr_rls_cert_worker";
GRANT EXECUTE ON FUNCTION app_rls.refresh_scan_metrics_hourly_rollups(text) TO "mscqr_rls_cert_worker";
RESET ROLE;
DO $$ BEGIN
  IF NOT pg_has_role(session_user,'mscqr_rls_cert_owner','SET') THEN RAISE EXCEPTION 'administrative executor lacks SET authority for mscqr_rls_cert_owner'; END IF;
END $$;
SET ROLE "mscqr_rls_cert_owner";
REVOKE CREATE ON SCHEMA app_rls FROM "mscqr_rls_cert_auth_owner";
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
-- Database-verifiable scheduled compliance identity. Template role names are
-- replaced only by the clean-room package generator.

CREATE OR REPLACE FUNCTION app_rls.scheduled_job_prepare(
  p_capability text,
  p_schedule_id text,
  p_operation text,
  p_request_id text
) RETURNS text
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE capability_hash text; credential public."ScheduledJobCredential"%ROWTYPE;
BEGIN
  IF session_user <> 'mscqr_rls_cert_scheduled'
     OR p_capability !~ '^[A-Za-z0-9_-]{43}$'
     OR p_schedule_id !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
     OR p_operation NOT IN ('claim','get','complete','fail')
     OR p_request_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  THEN RAISE EXCEPTION 'SCHEDULED_JOB_IDENTITY_DENIED' USING ERRCODE='42501'; END IF;

  capability_hash:=encode(sha256(convert_to(p_capability,'UTF8')),'hex');
  PERFORM set_config('app.scheduled_verified','',true),
          set_config('app.scheduled_credential_id','',true),
          set_config('app.scheduled_capability_hash',capability_hash,true),
          set_config('app.scheduled_family','compliance-pack',true),
          set_config('app.scheduled_schedule_id',p_schedule_id,true),
          set_config('app.scheduled_operation',p_operation,true),
          set_config('app.scheduled_request_id',lower(p_request_id),true),
          set_config('app.scheduled_licensee_id','',true),
          set_config('app.scheduled_job_id','',true),
          set_config('app.system_identity','identity-scheduled-job',true),
          set_config('app.user_id','',true),
          set_config('app.role','',true),
          set_config('app.organization_id','',true),
          set_config('app.licensee_id','',true),
          set_config('app.manufacturer_id','',true),
          set_config('app.auth_assurance','system-verified',true),
          set_config('app.request_id',lower(p_request_id),true);

  UPDATE public."ScheduledJobCredential" c
     SET "lastUsedAt"=transaction_timestamp(),"updatedAt"=transaction_timestamp()
   WHERE c."capabilityHash"=capability_hash
     AND c."capabilityHashVersion"='sha256-v1'
     AND c."identityName"='identity-scheduled-job'
     AND c."jobFamily"='compliance-pack'
     AND c."scheduleId"=p_schedule_id
     AND c."revokedAt" IS NULL
     AND c."expiresAt">clock_timestamp()
   RETURNING c.* INTO credential;
  IF NOT FOUND THEN RAISE EXCEPTION 'SCHEDULED_JOB_IDENTITY_DENIED' USING ERRCODE='42501'; END IF;

  PERFORM set_config('app.scheduled_credential_id',credential.id,true),
          set_config('app.scheduled_verified','1',true);
  RETURN credential.id;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.provision_scheduled_job_credential(
  p_credential_id text,
  p_schedule_id text,
  p_capability_hash text,
  p_expires_at timestamptz,
  p_rotated_from_credential_id text,
  p_request_id text
) RETURNS text
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
BEGIN
  IF session_user <> 'mscqr_rls_cert_operator'
     OR p_credential_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
     OR p_schedule_id !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
     OR p_capability_hash !~ '^[0-9a-f]{64}$'
     OR p_expires_at<=transaction_timestamp()+interval '5 minutes'
     OR p_expires_at>transaction_timestamp()+interval '370 days'
     OR p_request_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  THEN RAISE EXCEPTION 'SCHEDULED_JOB_PROVISION_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM set_config('app.scheduled_admin_operation','provision',true),
          set_config('app.scheduled_capability_hash',p_capability_hash,true),
          set_config('app.scheduled_schedule_id',p_schedule_id,true),
          set_config('app.scheduled_request_id',lower(p_request_id),true);
  IF p_rotated_from_credential_id IS NOT NULL THEN
    UPDATE public."ScheduledJobCredential"
       SET "revokedAt"=transaction_timestamp(),"revokedReason"='ROTATED',"updatedAt"=transaction_timestamp()
     WHERE id=p_rotated_from_credential_id AND "identityName"='identity-scheduled-job'
       AND "jobFamily"='compliance-pack' AND "scheduleId"=p_schedule_id AND "revokedAt" IS NULL;
    IF NOT FOUND THEN RAISE EXCEPTION 'SCHEDULED_JOB_ROTATION_DENIED' USING ERRCODE='42501'; END IF;
  END IF;
  INSERT INTO public."ScheduledJobCredential"
    (id,"identityName","jobFamily","scheduleId","capabilityHash","capabilityHashVersion","expiresAt","rotatedFromCredentialId","updatedAt")
  VALUES (p_credential_id,'identity-scheduled-job','compliance-pack',p_schedule_id,p_capability_hash,'sha256-v1',p_expires_at,p_rotated_from_credential_id,transaction_timestamp());
  RETURN p_credential_id;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.revoke_scheduled_job_credential(
  p_credential_id text,p_reason text,p_request_id text
) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
BEGIN
  IF session_user <> 'mscqr_rls_cert_operator'
     OR p_credential_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
     OR p_reason !~ '^[A-Z][A-Z0-9_]{2,63}$'
     OR p_request_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  THEN RAISE EXCEPTION 'SCHEDULED_JOB_REVOKE_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM set_config('app.scheduled_admin_operation','revoke',true),
          set_config('app.scheduled_request_id',lower(p_request_id),true);
  UPDATE public."ScheduledJobCredential"
     SET "revokedAt"=coalesce("revokedAt",transaction_timestamp()),
         "revokedReason"=coalesce("revokedReason",p_reason),"updatedAt"=transaction_timestamp()
   WHERE id=p_credential_id AND "identityName"='identity-scheduled-job';
  RETURN FOUND;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.scheduled_job_queue_audit(
  p_action text,p_job_id text,p_licensee_id text,p_details jsonb
) RETURNS void
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
  INSERT INTO public."AuditLogOutbox" (id,payload,"updatedAt") VALUES (
    gen_random_uuid()::text,
    jsonb_build_object('userId',NULL,'orgId',NULL,'licenseeId',p_licensee_id,
      'action',p_action,'entityType','CompliancePackJob','entityId',p_job_id,
      'details',coalesce(p_details,'{}'::jsonb)||jsonb_build_object(
        'requestId',current_setting('app.scheduled_request_id',true),
        'systemIdentity','identity-scheduled-job',
        'scheduleId',current_setting('app.scheduled_schedule_id',true),
        'credentialId',current_setting('app.scheduled_credential_id',true))),
    transaction_timestamp())
$fn$;

CREATE OR REPLACE FUNCTION app_rls.claim_compliance_pack_slice(
  p_capability text,p_schedule_id text,p_due_at timestamp without time zone,p_batch_size integer
) RETURNS TABLE("jobId" text,"requestId" text,"organizationId" text,"licenseeId" text,
  "scheduleScopeVersion" text,"expiresAt" timestamp without time zone,"attempt" integer,"report" jsonb)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE licensee record; job_id text; request_id text; replay_key text; inserted integer; report_value jsonb;
BEGIN
  IF p_batch_size<1 OR p_batch_size>100 OR p_due_at>transaction_timestamp()+interval '5 minutes'
     OR p_due_at<transaction_timestamp()-interval '24 hours'
  THEN RAISE EXCEPTION 'SCHEDULED_COMPLIANCE_CLAIM_INVALID' USING ERRCODE='22023'; END IF;
  request_id:=gen_random_uuid()::text;
  PERFORM app_rls.scheduled_job_prepare(p_capability,p_schedule_id,'claim',request_id);
  FOR licensee IN
    SELECT l.id,l."orgId" FROM public."Licensee" l
    JOIN public."Organization" o ON o.id=l."orgId"
    WHERE l."isActive" AND l."suspendedAt" IS NULL AND o."isActive"
    ORDER BY l.id LIMIT p_batch_size
  LOOP
    PERFORM set_config('app.scheduled_licensee_id',licensee.id,true),
            set_config('app.licensee_id',licensee.id,true),
            set_config('app.organization_id',licensee."orgId",true);
    replay_key:=encode(sha256(convert_to('scheduled-compliance|'||p_schedule_id||'|'||date_trunc('day',p_due_at)::text||'|'||licensee.id,'UTF8')),'hex');
    INSERT INTO public."ActionIdempotencyKey" (id,"keyHash",action,scope,"requestHash","expiresAt")
    VALUES (gen_random_uuid()::text,replay_key,'scheduled-compliance-pack',licensee.id,
      encode(sha256(convert_to(p_schedule_id||'|'||date_trunc('day',p_due_at)::text,'UTF8')),'hex'),p_due_at+interval '48 hours')
    ON CONFLICT ("keyHash") DO NOTHING;
    GET DIAGNOSTICS inserted=ROW_COUNT;
    IF inserted=0 THEN CONTINUE; END IF;
    job_id:=gen_random_uuid()::text;
    request_id:=gen_random_uuid()::text;
    PERFORM set_config('app.scheduled_job_id',job_id,true),set_config('app.scheduled_request_id',request_id,true);
    INSERT INTO public."CompliancePackJob"
      (id,"licenseeId",status,"triggerType","scheduledScheduleId","periodFrom","periodTo","startedByUserId","startedAt","updatedAt")
    VALUES (job_id,licensee.id,'RUNNING','SCHEDULED',p_schedule_id,p_due_at-interval '24 hours',p_due_at,NULL,transaction_timestamp(),transaction_timestamp());
    report_value:=app_rls.c03_build_compliance_report(licensee.id,p_due_at-interval '24 hours',p_due_at);
    UPDATE public."ActionIdempotencyKey" SET "statusCode"=200,
      "responsePayload"=jsonb_build_object('jobId',job_id,'requestId',request_id),"completedAt"=transaction_timestamp()
      WHERE "keyHash"=replay_key;
    PERFORM app_rls.scheduled_job_queue_audit('COMPLIANCE_PACK_STARTED',job_id,licensee.id,jsonb_build_object('triggerType','SCHEDULED'));
    "jobId":=job_id; "requestId":=request_id; "organizationId":=licensee."orgId"; "licenseeId":=licensee.id;
    "scheduleScopeVersion":=encode(sha256(convert_to(licensee.id||'|'||licensee."orgId"||'|active','UTF8')),'hex');
    "expiresAt":=p_due_at+interval '24 hours'; "attempt":=1; "report":=report_value;
    RETURN NEXT;
  END LOOP;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.scheduled_get_compliance_pack_job(
  p_capability text,p_schedule_id text,p_request_id text,p_job_id text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE job public."CompliancePackJob"%ROWTYPE; report_value jsonb;
BEGIN
  PERFORM app_rls.scheduled_job_prepare(p_capability,p_schedule_id,'get',p_request_id);
  PERFORM set_config('app.scheduled_job_id',p_job_id,true);
  SELECT * INTO job FROM public."CompliancePackJob" WHERE id=p_job_id AND "triggerType"='SCHEDULED' AND "scheduledScheduleId"=p_schedule_id;
  IF NOT FOUND OR job."licenseeId" IS NULL THEN RAISE EXCEPTION 'SCHEDULED_COMPLIANCE_JOB_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM set_config('app.scheduled_licensee_id',job."licenseeId",true),set_config('app.licensee_id',job."licenseeId",true);
  report_value:=app_rls.c03_build_compliance_report(job."licenseeId",job."periodFrom",job."periodTo");
  RETURN jsonb_build_object('job',to_jsonb(job),'report',report_value);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.scheduled_complete_compliance_pack_job(
  p_capability text,p_schedule_id text,p_request_id text,p_job_id text,p_result jsonb
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE job public."CompliancePackJob"%ROWTYPE;
BEGIN
  IF jsonb_typeof(p_result)<>'object' OR p_result->>'fileName' IS NULL OR p_result->>'storageKey' IS NULL
     OR p_result->>'integrityHash' !~ '^[0-9a-f]{64}$' OR octet_length(p_result::text)>65536
  THEN RAISE EXCEPTION 'SCHEDULED_COMPLIANCE_RESULT_INVALID' USING ERRCODE='22023'; END IF;
  PERFORM app_rls.scheduled_job_prepare(p_capability,p_schedule_id,'complete',p_request_id);
  PERFORM set_config('app.scheduled_job_id',p_job_id,true);
  UPDATE public."CompliancePackJob" SET status='COMPLETED',"fileName"=p_result->>'fileName',"storageKey"=p_result->>'storageKey',
    "integrityHash"=p_result->>'integrityHash',"signatureAlgorithm"=p_result->>'signatureAlgorithm',summary=p_result,
    "finishedAt"=transaction_timestamp(),"updatedAt"=transaction_timestamp()
    WHERE id=p_job_id AND "triggerType"='SCHEDULED' AND "scheduledScheduleId"=p_schedule_id AND status='RUNNING' RETURNING * INTO job;
  IF NOT FOUND THEN RAISE EXCEPTION 'SCHEDULED_COMPLIANCE_TRANSITION_DENIED' USING ERRCODE='40001'; END IF;
  PERFORM set_config('app.scheduled_licensee_id',job."licenseeId",true),set_config('app.licensee_id',job."licenseeId",true);
  PERFORM app_rls.scheduled_job_queue_audit('COMPLIANCE_PACK_COMPLETED',job.id,job."licenseeId",jsonb_build_object('storageKey',job."storageKey"));
  RETURN to_jsonb(job);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.scheduled_fail_compliance_pack_job(
  p_capability text,p_schedule_id text,p_request_id text,p_job_id text,p_error_code text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE job public."CompliancePackJob"%ROWTYPE;
BEGIN
  IF p_error_code !~ '^[A-Z][A-Z0-9_]{2,127}$' THEN RAISE EXCEPTION 'SCHEDULED_COMPLIANCE_ERROR_INVALID' USING ERRCODE='22023'; END IF;
  PERFORM app_rls.scheduled_job_prepare(p_capability,p_schedule_id,'fail',p_request_id);
  PERFORM set_config('app.scheduled_job_id',p_job_id,true);
  UPDATE public."CompliancePackJob" SET status='FAILED',"errorMessage"=p_error_code,"finishedAt"=transaction_timestamp(),"updatedAt"=transaction_timestamp()
    WHERE id=p_job_id AND "triggerType"='SCHEDULED' AND "scheduledScheduleId"=p_schedule_id AND status='RUNNING' RETURNING * INTO job;
  IF NOT FOUND THEN RAISE EXCEPTION 'SCHEDULED_COMPLIANCE_TRANSITION_DENIED' USING ERRCODE='40001'; END IF;
  PERFORM set_config('app.scheduled_licensee_id',job."licenseeId",true),set_config('app.licensee_id',job."licenseeId",true);
  PERFORM app_rls.scheduled_job_queue_audit('COMPLIANCE_PACK_FAILED',job.id,job."licenseeId",jsonb_build_object('errorCode',p_error_code));
  RETURN to_jsonb(job);
END
$fn$;

REVOKE ALL ON FUNCTION app_rls.scheduled_job_prepare(text,text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.provision_scheduled_job_credential(text,text,text,timestamp with time zone,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.revoke_scheduled_job_credential(text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.scheduled_job_queue_audit(text,text,text,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.claim_compliance_pack_slice(text,text,timestamp without time zone,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.scheduled_get_compliance_pack_job(text,text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.scheduled_complete_compliance_pack_job(text,text,text,text,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.scheduled_fail_compliance_pack_job(text,text,text,text,text) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION app_rls.claim_compliance_pack_slice(text,text,timestamp without time zone,integer) TO "mscqr_rls_cert_scheduled";
GRANT EXECUTE ON FUNCTION app_rls.scheduled_complete_compliance_pack_job(text,text,text,text,jsonb) TO "mscqr_rls_cert_scheduled";
GRANT EXECUTE ON FUNCTION app_rls.scheduled_fail_compliance_pack_job(text,text,text,text,text) TO "mscqr_rls_cert_scheduled";
GRANT EXECUTE ON FUNCTION app_rls.scheduled_get_compliance_pack_job(text,text,text,text) TO "mscqr_rls_cert_scheduled";
GRANT EXECUTE ON FUNCTION app_rls.provision_scheduled_job_credential(text,text,text,timestamp with time zone,text,text) TO "mscqr_rls_cert_operator";
GRANT EXECUTE ON FUNCTION app_rls.revoke_scheduled_job_credential(text,text,text) TO "mscqr_rls_cert_operator";
RESET ROLE;
DO $$ BEGIN
  IF NOT pg_has_role(session_user,'mscqr_rls_cert_owner','SET') THEN RAISE EXCEPTION 'administrative executor lacks SET authority for mscqr_rls_cert_owner'; END IF;
END $$;
SET ROLE "mscqr_rls_cert_owner";
REVOKE CREATE ON SCHEMA app_rls FROM "mscqr_rls_cert_auth_owner";
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
CREATE OR REPLACE FUNCTION app_rls.b03_bind_outbox_operation(p_operation text,p_row_id text,p_payload_digest text)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
BEGIN
  IF p_operation NOT IN ('audit-enqueue','audit-claim','audit-consume','audit-fail','security-enqueue','security-claim','security-complete','security-fail')
     OR p_payload_digest IS NOT NULL AND p_payload_digest !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'B03_OUTBOX_DENIED' USING ERRCODE='42501';
  END IF;
  PERFORM set_config('app.b03_outbox_operation',p_operation,true),
          set_config('app.b03_outbox_id',coalesce(p_row_id,''),true),
          set_config('app.b03_outbox_digest',coalesce(p_payload_digest,''),true),
          set_config('app.b03_outbox_idempotency_key','',true),
          set_config('app.b03_audit_user_id','',true),
          set_config('app.b03_audit_organization_id','',true),
          set_config('app.b03_audit_licensee_id','',true),
          set_config('app.b03_security_outbox_id','',true),
          set_config('app.b03_security_outbox_digest','',true);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.enqueue_audit_log_outbox(
  p_payload jsonb,p_payload_digest text,p_idempotency_key text,p_request_id text,
  p_organization_id text,p_licensee_id text,p_manufacturer_id text,p_initiating_user_id text,
  p_initiating_actor_role text,p_expires_at timestamp without time zone,p_initial_error_code text
) RETURNS TABLE("id" text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE v_id text := gen_random_uuid()::text;
BEGIN
  PERFORM app_rls.b03_bind_outbox_operation('audit-enqueue',v_id,p_payload_digest);
  PERFORM set_config('app.b03_outbox_idempotency_key',coalesce(p_idempotency_key,''),true);
  IF session_user <> 'mscqr_rls_cert_app' OR current_setting('app.auth_session_verified',true)<>'1'
     OR jsonb_typeof(p_payload)<>'object' OR p_payload_digest !~ '^[0-9a-f]{64}$'
     OR p_idempotency_key !~ '^[0-9a-f]{64}$' OR p_request_id !~* '^[0-9a-f-]{36}$'
     OR p_initiating_user_id IS DISTINCT FROM current_setting('app.user_id',true)
     OR p_initiating_actor_role IS DISTINCT FROM current_setting('app.role',true)
     OR p_organization_id IS DISTINCT FROM NULLIF(current_setting('app.organization_id',true),'')
     OR p_licensee_id IS DISTINCT FROM NULLIF(current_setting('app.licensee_id',true),'')
     OR p_expires_at<=transaction_timestamp() OR p_expires_at>transaction_timestamp()+interval '2 days'
  THEN RAISE EXCEPTION 'B03_OUTBOX_DENIED' USING ERRCODE='42501'; END IF;
  INSERT INTO public."AuditLogOutbox" AS o
    (id,payload,"jobType","requestId","payloadDigest","idempotencyKey","organizationId","licenseeId","manufacturerId","initiatingUserId","initiatingActorRoleSnapshot","expiresAt","lastError","updatedAt")
  VALUES (v_id,p_payload,'AUDIT_LOG_RECOVERY',p_request_id,p_payload_digest,p_idempotency_key,p_organization_id,p_licensee_id,p_manufacturer_id,p_initiating_user_id,p_initiating_actor_role,p_expires_at,p_initial_error_code,transaction_timestamp())
  ON CONFLICT ("idempotencyKey") DO NOTHING RETURNING o.id INTO v_id;
  IF v_id IS NULL THEN
    SELECT o.id INTO v_id FROM public."AuditLogOutbox" o
     WHERE o."idempotencyKey"=p_idempotency_key AND o."payloadDigest"=p_payload_digest;
    IF NOT FOUND THEN RAISE EXCEPTION 'B03_OUTBOX_REPLAY_MISMATCH' USING ERRCODE='23505'; END IF;
  END IF;
  RETURN QUERY SELECT v_id;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.claim_audit_log_outbox_slice(p_attempted_at timestamp without time zone,p_batch_size integer)
RETURNS TABLE("id" text,"jobType" text,"requestId" text,"payloadDigest" text,"idempotencyKey" text,"organizationId" text,"licenseeId" text,"manufacturerId" text,"initiatingUserId" text,"expiresAt" timestamp without time zone,"attempt" integer)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
BEGIN
  PERFORM app_rls.b03_bind_outbox_operation('audit-claim','',repeat('0',64));
  IF session_user<>'mscqr_rls_cert_worker' OR p_batch_size NOT BETWEEN 1 AND 250 OR abs(extract(epoch FROM (clock_timestamp()-p_attempted_at)))>60
  THEN RAISE EXCEPTION 'B03_OUTBOX_DENIED' USING ERRCODE='42501'; END IF;
  RETURN QUERY WITH candidates AS (
    SELECT o.id FROM public."AuditLogOutbox" o
     WHERE o."jobType"='AUDIT_LOG_RECOVERY' AND o.status IN ('QUEUED','FAILED')
       AND o."nextAttemptAt"<=p_attempted_at AND o."expiresAt">p_attempted_at AND o.attempts<10
       AND (o."claimLeaseExpiresAt" IS NULL OR o."claimLeaseExpiresAt"<=p_attempted_at)
     ORDER BY o."createdAt",o.id FOR UPDATE SKIP LOCKED LIMIT p_batch_size
  ), claimed AS (
    UPDATE public."AuditLogOutbox" o SET attempts=o.attempts+1,"claimedAt"=p_attempted_at,
      "claimLeaseExpiresAt"=p_attempted_at+interval '5 minutes',"updatedAt"=transaction_timestamp()
    FROM candidates c WHERE o.id=c.id RETURNING o.*
  ) SELECT c.id,c."jobType",c."requestId",c."payloadDigest",c."idempotencyKey",c."organizationId",c."licenseeId",c."manufacturerId",c."initiatingUserId",c."expiresAt",c.attempts FROM claimed c;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.consume_audit_log_outbox(p_job_id text,p_payload_digest text,p_attempted_at timestamp without time zone)
RETURNS TABLE("auditLogId" text,"replayed" boolean)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE o record; v_audit_id text; v_security_id text; v_security_payload jsonb; v_security_digest text;
BEGIN
  PERFORM app_rls.b03_bind_outbox_operation('audit-consume',p_job_id,p_payload_digest);
  IF session_user<>'mscqr_rls_cert_worker' THEN RAISE EXCEPTION 'B03_OUTBOX_DENIED' USING ERRCODE='42501'; END IF;
  SELECT q.* INTO o FROM public."AuditLogOutbox" q WHERE q.id=p_job_id AND q."payloadDigest"=p_payload_digest FOR UPDATE;
  IF NOT FOUND OR o."expiresAt"<=p_attempted_at OR abs(extract(epoch FROM (clock_timestamp()-p_attempted_at)))>60
  THEN RAISE EXCEPTION 'B03_OUTBOX_DENIED' USING ERRCODE='42501'; END IF;
  IF o.status='SENT' THEN RETURN QUERY SELECT o."flushedAuditLogId",true; RETURN; END IF;
  IF o."claimLeaseExpiresAt" IS NULL OR o."claimLeaseExpiresAt"<p_attempted_at OR jsonb_typeof(o.payload)<>'object'
     OR coalesce(o.payload->>'action','')='' OR coalesce(o.payload->>'entityType','')=''
  THEN RAISE EXCEPTION 'B03_OUTBOX_DENIED' USING ERRCODE='42501'; END IF;
  v_audit_id:=gen_random_uuid()::text;
  PERFORM set_config('app.b03_audit_user_id',coalesce(o."initiatingUserId",''),true),
          set_config('app.b03_audit_organization_id',coalesce(o."organizationId",''),true),
          set_config('app.b03_audit_licensee_id',coalesce(o."licenseeId",''),true);
  INSERT INTO public."AuditLog" (id,"userId","orgId","licenseeId",action,"entityType","entityId",details,"ipAddress","ipHash","userAgent")
  VALUES (v_audit_id,o."initiatingUserId",o."organizationId",o."licenseeId",o.payload->>'action',o.payload->>'entityType',NULLIF(o.payload->>'entityId',''),o.payload->'details',NULLIF(o.payload->>'ipAddress',''),NULLIF(o.payload->>'ipHash',''),NULLIF(o.payload->>'userAgent',''));
  v_security_id:=gen_random_uuid()::text;
  v_security_payload:=jsonb_build_object(
    'id',v_audit_id,'action',o.payload->>'action','entityType',o.payload->>'entityType',
    'entityId',NULLIF(o.payload->>'entityId',''),'userId',o."initiatingUserId",
    'orgId',o."organizationId",'licenseeId',o."licenseeId",'details',o.payload->'details',
    'createdAt',transaction_timestamp()
  );
  v_security_digest:=encode(sha256(convert_to(v_security_payload::text,'UTF8')),'hex');
  PERFORM set_config('app.b03_security_outbox_id',v_security_id,true),
          set_config('app.b03_security_outbox_digest',v_security_digest,true);
  INSERT INTO public."SecurityEventOutbox"
    (id,"eventType",payload,"jobType","requestId","payloadDigest","idempotencyKey","organizationId","licenseeId","manufacturerId","initiatingUserId","expiresAt","updatedAt")
  VALUES
    (v_security_id,'AUDIT_LOG',v_security_payload,'AUDIT_LOG',o."requestId",v_security_digest,
     encode(sha256(convert_to('AUDIT_LOG:'||v_audit_id,'UTF8')),'hex'),o."organizationId",o."licenseeId",
     o."manufacturerId",o."initiatingUserId",least(o."expiresAt",transaction_timestamp()+interval '1 day'),transaction_timestamp());
  UPDATE public."AuditLogOutbox" SET status='SENT',"flushedAuditLogId"=v_audit_id,"lastError"=NULL,"claimLeaseExpiresAt"=NULL,"updatedAt"=transaction_timestamp() WHERE id=p_job_id;
  RETURN QUERY SELECT v_audit_id,false;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.fail_audit_log_outbox(p_job_id text,p_payload_digest text,p_attempted_at timestamp without time zone,p_attempt integer,p_error_code text)
RETURNS TABLE("terminal" boolean,"nextAttemptAt" timestamp without time zone)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE v_terminal boolean; v_next timestamp without time zone;
BEGIN
  PERFORM app_rls.b03_bind_outbox_operation('audit-fail',p_job_id,p_payload_digest);
  IF session_user<>'mscqr_rls_cert_worker' OR p_attempt NOT BETWEEN 1 AND 10 OR p_error_code!~'^[A-Z0-9_]{1,128}$'
     OR abs(extract(epoch FROM (clock_timestamp()-p_attempted_at)))>60
  THEN RAISE EXCEPTION 'B03_OUTBOX_DENIED' USING ERRCODE='42501'; END IF;
  v_terminal:=p_attempt>=10; v_next:=CASE WHEN v_terminal THEN p_attempted_at ELSE p_attempted_at+make_interval(secs=>least(300,greatest(10,power(2,p_attempt)::integer))) END;
  UPDATE public."AuditLogOutbox" SET status='FAILED',"lastError"=p_error_code,"nextAttemptAt"=v_next,"claimLeaseExpiresAt"=NULL,"updatedAt"=transaction_timestamp()
   WHERE id=p_job_id AND "payloadDigest"=p_payload_digest AND status<>'SENT' AND attempts=p_attempt;
  IF NOT FOUND THEN RAISE EXCEPTION 'B03_OUTBOX_DENIED' USING ERRCODE='42501'; END IF;
  RETURN QUERY SELECT v_terminal,v_next;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.enqueue_security_event_outbox(p_event_type text,p_payload jsonb,p_payload_digest text,p_idempotency_key text,p_request_id text,p_organization_id text,p_licensee_id text,p_manufacturer_id text,p_initiating_user_id text,p_expires_at timestamp without time zone)
RETURNS TABLE("id" text) LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE v_id text:=gen_random_uuid()::text;
BEGIN
  PERFORM app_rls.b03_bind_outbox_operation('security-enqueue',v_id,p_payload_digest);
  PERFORM set_config('app.b03_outbox_idempotency_key',coalesce(p_idempotency_key,''),true);
  IF session_user<>'mscqr_rls_cert_app' OR current_setting('app.auth_session_verified',true)<>'1' OR p_event_type NOT IN ('AUDIT_LOG','CSP_VIOLATION')
     OR jsonb_typeof(p_payload)<>'object' OR p_payload_digest!~'^[0-9a-f]{64}$' OR p_idempotency_key!~'^[0-9a-f]{64}$'
     OR p_initiating_user_id IS DISTINCT FROM current_setting('app.user_id',true) OR p_expires_at<=transaction_timestamp() OR p_expires_at>transaction_timestamp()+interval '2 days'
  THEN RAISE EXCEPTION 'B03_OUTBOX_DENIED' USING ERRCODE='42501'; END IF;
  INSERT INTO public."SecurityEventOutbox" AS o (id,"eventType",payload,"jobType","requestId","payloadDigest","idempotencyKey","organizationId","licenseeId","manufacturerId","initiatingUserId","expiresAt","updatedAt")
  VALUES(v_id,p_event_type,p_payload,p_event_type,p_request_id,p_payload_digest,p_idempotency_key,p_organization_id,p_licensee_id,p_manufacturer_id,p_initiating_user_id,p_expires_at,transaction_timestamp())
  ON CONFLICT ("idempotencyKey") DO NOTHING RETURNING o.id INTO v_id;
  IF v_id IS NULL THEN SELECT o.id INTO v_id FROM public."SecurityEventOutbox" o WHERE o."idempotencyKey"=p_idempotency_key AND o."payloadDigest"=p_payload_digest AND o."eventType"=p_event_type; IF NOT FOUND THEN RAISE EXCEPTION 'B03_OUTBOX_REPLAY_MISMATCH' USING ERRCODE='23505'; END IF; END IF;
  RETURN QUERY SELECT v_id;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.claim_security_event_outbox_slice(p_attempted_at timestamp without time zone,p_batch_size integer,p_job_type text)
RETURNS TABLE("id" text,"jobType" text,"requestId" text,"payloadDigest" text,"idempotencyKey" text,"organizationId" text,"licenseeId" text,"manufacturerId" text,"initiatingUserId" text,"expiresAt" timestamp without time zone,"attempt" integer,"eventType" text,"eventPayload" jsonb,"createdAt" timestamp without time zone)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
BEGIN
  PERFORM app_rls.b03_bind_outbox_operation('security-claim','',repeat('0',64));
  IF session_user<>'mscqr_rls_cert_worker' OR p_job_type NOT IN ('AUDIT_LOG','CSP_VIOLATION') OR p_batch_size NOT BETWEEN 1 AND 200
     OR abs(extract(epoch FROM (clock_timestamp()-p_attempted_at)))>60
  THEN RAISE EXCEPTION 'B03_OUTBOX_DENIED' USING ERRCODE='42501'; END IF;
  RETURN QUERY WITH candidates AS (SELECT o.id FROM public."SecurityEventOutbox" o WHERE o."jobType"=p_job_type AND o.status IN ('QUEUED','FAILED') AND o."nextAttemptAt"<=p_attempted_at AND o."expiresAt">p_attempted_at AND o.attempts<10 AND (o."claimLeaseExpiresAt" IS NULL OR o."claimLeaseExpiresAt"<=p_attempted_at) ORDER BY o."createdAt",o.id FOR UPDATE SKIP LOCKED LIMIT p_batch_size), claimed AS (UPDATE public."SecurityEventOutbox" o SET attempts=o.attempts+1,"claimedAt"=p_attempted_at,"claimLeaseExpiresAt"=p_attempted_at+interval '5 minutes',"updatedAt"=transaction_timestamp() FROM candidates c WHERE o.id=c.id RETURNING o.*) SELECT c.id,c."jobType",c."requestId",c."payloadDigest",c."idempotencyKey",c."organizationId",c."licenseeId",c."manufacturerId",c."initiatingUserId",c."expiresAt",c.attempts,c."eventType",c.payload,c."createdAt" FROM claimed c;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.complete_security_event_outbox(p_job_id text,p_payload_digest text,p_attempted_at timestamp without time zone,p_sink_event_id text)
RETURNS TABLE("completed" boolean,"replayed" boolean) LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE o record;
BEGIN
  PERFORM app_rls.b03_bind_outbox_operation('security-complete',p_job_id,p_payload_digest);
  IF session_user<>'mscqr_rls_cert_worker' OR length(p_sink_event_id) NOT BETWEEN 1 AND 191
     OR abs(extract(epoch FROM (clock_timestamp()-p_attempted_at)))>60
  THEN RAISE EXCEPTION 'B03_OUTBOX_DENIED' USING ERRCODE='42501'; END IF;
  SELECT q.* INTO o FROM public."SecurityEventOutbox" q WHERE q.id=p_job_id AND q."payloadDigest"=p_payload_digest FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'B03_OUTBOX_DENIED' USING ERRCODE='42501'; END IF;
  IF o.status='SENT' THEN
    IF o."sinkEventId" IS DISTINCT FROM p_sink_event_id THEN RAISE EXCEPTION 'B03_OUTBOX_REPLAY_MISMATCH' USING ERRCODE='23505'; END IF;
    RETURN QUERY SELECT true,true; RETURN;
  END IF;
  IF o."claimLeaseExpiresAt" IS NULL OR o."claimLeaseExpiresAt"<p_attempted_at THEN RAISE EXCEPTION 'B03_OUTBOX_DENIED' USING ERRCODE='42501'; END IF;
  UPDATE public."SecurityEventOutbox" SET status='SENT',"sentAt"=p_attempted_at,"sinkEventId"=p_sink_event_id,"lastError"=NULL,"claimLeaseExpiresAt"=NULL,"updatedAt"=transaction_timestamp() WHERE id=p_job_id;
  RETURN QUERY SELECT true,false;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.fail_security_event_outbox(p_job_id text,p_payload_digest text,p_attempted_at timestamp without time zone,p_attempt integer,p_error_code text)
RETURNS TABLE("terminal" boolean,"nextAttemptAt" timestamp without time zone) LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE v_terminal boolean; v_next timestamp without time zone;
BEGIN
  PERFORM app_rls.b03_bind_outbox_operation('security-fail',p_job_id,p_payload_digest);
  IF session_user<>'mscqr_rls_cert_worker' OR p_attempt NOT BETWEEN 1 AND 10 OR p_error_code!~'^[A-Z0-9_]{1,128}$'
     OR abs(extract(epoch FROM (clock_timestamp()-p_attempted_at)))>60
  THEN RAISE EXCEPTION 'B03_OUTBOX_DENIED' USING ERRCODE='42501'; END IF;
  v_terminal:=p_attempt>=10; v_next:=CASE WHEN v_terminal THEN p_attempted_at ELSE p_attempted_at+make_interval(secs=>least(300,greatest(5,power(2,p_attempt)::integer))) END;
  UPDATE public."SecurityEventOutbox" SET status='FAILED',"lastError"=p_error_code,"nextAttemptAt"=v_next,"claimLeaseExpiresAt"=NULL,"updatedAt"=transaction_timestamp() WHERE id=p_job_id AND "payloadDigest"=p_payload_digest AND status<>'SENT' AND attempts=p_attempt;
  IF NOT FOUND THEN RAISE EXCEPTION 'B03_OUTBOX_DENIED' USING ERRCODE='42501'; END IF;
  RETURN QUERY SELECT v_terminal,v_next;
END
$fn$;

REVOKE ALL ON FUNCTION app_rls.b03_bind_outbox_operation(text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.enqueue_audit_log_outbox(jsonb,text,text,text,text,text,text,text,text,timestamp without time zone,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.claim_audit_log_outbox_slice(timestamp without time zone,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.consume_audit_log_outbox(text,text,timestamp without time zone) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.fail_audit_log_outbox(text,text,timestamp without time zone,integer,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.enqueue_security_event_outbox(text,jsonb,text,text,text,text,text,text,text,timestamp without time zone) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.claim_security_event_outbox_slice(timestamp without time zone,integer,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.complete_security_event_outbox(text,text,timestamp without time zone,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.fail_security_event_outbox(text,text,timestamp without time zone,integer,text) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION app_rls.enqueue_audit_log_outbox(jsonb,text,text,text,text,text,text,text,text,timestamp without time zone,text) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.enqueue_security_event_outbox(text,jsonb,text,text,text,text,text,text,text,timestamp without time zone) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.claim_audit_log_outbox_slice(timestamp without time zone,integer) TO "mscqr_rls_cert_worker";
GRANT EXECUTE ON FUNCTION app_rls.claim_security_event_outbox_slice(timestamp without time zone,integer,text) TO "mscqr_rls_cert_worker";
GRANT EXECUTE ON FUNCTION app_rls.complete_security_event_outbox(text,text,timestamp without time zone,text) TO "mscqr_rls_cert_worker";
GRANT EXECUTE ON FUNCTION app_rls.consume_audit_log_outbox(text,text,timestamp without time zone) TO "mscqr_rls_cert_worker";
GRANT EXECUTE ON FUNCTION app_rls.fail_audit_log_outbox(text,text,timestamp without time zone,integer,text) TO "mscqr_rls_cert_worker";
GRANT EXECUTE ON FUNCTION app_rls.fail_security_event_outbox(text,text,timestamp without time zone,integer,text) TO "mscqr_rls_cert_worker";
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
