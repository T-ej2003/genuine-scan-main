\set ON_ERROR_STOP on
BEGIN;
DO $$ BEGIN

  IF current_user<>'certification-administrator' THEN RAISE EXCEPTION 'context helpers requires the reviewed brokered administrator'; END IF;
  IF current_database() !~ '^mscqr_full_rls_cert_[a-z0-9_]+$' THEN RAISE EXCEPTION 'context helpers is bound to the reviewed green database'; END IF;
  IF NOT EXISTS (SELECT 1 FROM mscqr_rls_install.state WHERE singleton
    AND target_environment='certification'
    AND deployment_id='cert'
    AND green_database=current_database()
    AND source_contract_sha256='68be98736423be84c0eb0baa9423a78109abe61835d8479dd61b656a68c423dc'
    AND package_role_marker='mscqr-full-rls-clean-room:certification:68be98736423be84c0eb0baa9423a78109abe61835d8479dd61b656a68c423dc'
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
    ('mscqr_rls_cert_migration', true)) spec(role_name,expected_login) ON spec.role_name=r.rolname WHERE r.rolcanlogin IS DISTINCT FROM spec.expected_login OR r.rolinherit OR r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls OR obj_description(r.oid,'pg_authid')<>'mscqr-full-rls-clean-room:certification:68be98736423be84c0eb0baa9423a78109abe61835d8479dd61b656a68c423dc')
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
  IF NOT ((current_user='mscqr_rls_cert_auth_owner' AND app_rls.operational_read_session_valid()) AND app_rls.attributed_request() AND app_rls.current_purpose()='batch-operational-read' AND app_rls.current_request_id() ~ '^[A-Za-z0-9._:-]{1,128}$' AND ((app_rls.current_role() IN ('LICENSEE_ADMIN','ORG_ADMIN') AND app_rls.current_assurance() IN ('password-verified','mfa-verified','step-up-verified','dual-approved-break-glass')) OR ((app_rls.current_role() IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') OR app_rls.current_role() IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')) AND app_rls.current_assurance() IN ('mfa-verified','step-up-verified','dual-approved-break-glass'))))
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

CREATE OR REPLACE FUNCTION app_rls.operational_read_session_valid()
RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
BEGIN
  IF session_user <> 'mscqr_rls_cert_app'
     OR current_setting('app.auth_session_verified',true) <> '1'
  THEN RETURN false; END IF;
  RETURN EXISTS (
    SELECT 1 FROM public."RefreshToken" s
     WHERE s.id=current_setting('app.auth_session_id',true)
       AND s."userId"=current_setting('app.user_id',true)
       AND s."sessionCapabilityHash"=current_setting('app.auth_session_hash',true)
       AND s."sessionCapabilityHashVersion"='sha256-v1'
       AND s."sessionCapabilityRevokedAt" IS NULL
       AND s."sessionCapabilityExpiresAt">clock_timestamp()
       AND s."revokedAt" IS NULL
       AND s."expiresAt">clock_timestamp()
  );
END
$fn$;

REVOKE ALL ON FUNCTION app_rls.operational_read_session_valid() FROM PUBLIC;

CREATE OR REPLACE FUNCTION app_rls.operational_read_bind_actor(
  p_capability text,
  p_purpose text,
  p_request_id text,
  p_requested_licensee_id text
) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $fn$
DECLARE
  actor record;
  selected_licensee text := NULLIF(btrim(p_requested_licensee_id),'');
  scope_licensee_ids text := '';
  scope_organization_ids text := '';
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
          set_config('app.purpose',p_purpose,true),
          set_config('app.operational_scope_loading','1',true),
          set_config('app.operational_scope_licensee_ids','',true),
          set_config('app.operational_scope_organization_ids','',true);
  IF current_setting('app.auth_assurance',true)='' THEN
    RAISE EXCEPTION 'operational read access denied' USING ERRCODE='42501';
  END IF;
  IF actor.role IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') THEN
    SELECT string_agg(l.id::text,',' ORDER BY l.id),string_agg(DISTINCT o.id::text,',' ORDER BY o.id::text)
      INTO scope_licensee_ids,scope_organization_ids
      FROM public."ManufacturerLicenseeLink" ml
      JOIN public."Licensee" l ON l.id=ml."licenseeId"
      JOIN public."Organization" o ON o.id=l."orgId"
     WHERE ml."manufacturerId"=actor."userId"
       AND l."isActive" AND l."suspendedAt" IS NULL AND o."isActive"
       AND (selected_licensee IS NULL OR l.id=selected_licensee);
    IF scope_licensee_ids IS NULL THEN
      RAISE EXCEPTION 'operational read access denied' USING ERRCODE='42501';
    END IF;
    PERFORM set_config('app.manufacturer_id',actor."userId",true),
            set_config('app.organization_id','',true),
            set_config('app.licensee_id',coalesce(selected_licensee,''),true);
  ELSIF actor.role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') THEN
    IF selected_licensee IS NOT NULL THEN
      SELECT l.id::text,o.id::text INTO scope_licensee_ids,scope_organization_ids
        FROM public."Licensee" l JOIN public."Organization" o ON o.id=l."orgId"
       WHERE l.id=selected_licensee AND l."isActive" AND l."suspendedAt" IS NULL AND o."isActive";
      IF NOT FOUND THEN RAISE EXCEPTION 'operational read access denied' USING ERRCODE='42501'; END IF;
    END IF;
    PERFORM set_config('app.manufacturer_id','',true),
            set_config('app.organization_id','',true),
            set_config('app.licensee_id',coalesce(selected_licensee,''),true);
  ELSIF actor.role IN ('LICENSEE_ADMIN','ORG_ADMIN') THEN
    IF selected_licensee IS NOT NULL AND selected_licensee IS DISTINCT FROM actor."licenseeId" THEN
      RAISE EXCEPTION 'operational read access denied' USING ERRCODE='42501';
    END IF;
    SELECT l.id::text,o.id::text INTO scope_licensee_ids,scope_organization_ids
      FROM public."Licensee" l JOIN public."Organization" o ON o.id=l."orgId"
     WHERE l.id=actor."licenseeId" AND l."orgId"=actor."organizationId"
       AND l."isActive" AND l."suspendedAt" IS NULL AND o."isActive";
    IF NOT FOUND THEN RAISE EXCEPTION 'operational read access denied' USING ERRCODE='42501'; END IF;
    PERFORM set_config('app.manufacturer_id','',true);
  ELSE
    RAISE EXCEPTION 'operational read access denied' USING ERRCODE='42501';
  END IF;
  PERFORM set_config('app.operational_scope_licensee_ids',coalesce(scope_licensee_ids,''),true),
          set_config('app.operational_scope_organization_ids',coalesce(scope_organization_ids,''),true),
          set_config('app.operational_scope_loading','',true);
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
    SELECT l.id,l."orgId",l.name,l.prefix,l.description,l."brandName",l.location,l.website,
           l."supportEmail",l."supportPhone",l.metadata,l."isActive",l."suspendedAt",
           l."suspendedReason",l."createdAt",l."updatedAt"
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
DECLARE t record; u record; selected_licensee text; selected_manufacturer text; candidate_count integer;
BEGIN
  PERFORM app_auth.b01_bind_bearer(p_hashes,p_request_id);
  IF p_checked_at IS NULL OR abs(extract(epoch FROM p_checked_at-clock_timestamp())) > 300 THEN
    RAISE EXCEPTION 'B01_REFRESH_INPUT_DENIED' USING ERRCODE='22023';
  END IF;
  SELECT count(*) INTO candidate_count FROM public."RefreshToken" rt WHERE rt."tokenHash"=ANY(p_hashes);
  IF candidate_count=0 THEN RETURN; END IF;
  IF candidate_count<>1 THEN RAISE EXCEPTION 'B01_REFRESH_CLAIM_AMBIGUOUS' USING ERRCODE='42501'; END IF;
  SELECT rt.id,rt."userId",rt."orgId",rt."revokedAt",rt."replacedByTokenHash",rt."expiresAt",
    rt."authenticatedAt",rt."mfaVerifiedAt",rt."rotationRequestId"
    INTO t FROM public."RefreshToken" rt WHERE rt."tokenHash"=ANY(p_hashes) FOR UPDATE;
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
DECLARE t record; u record; selected record; links jsonb; mfa_enabled boolean; mfa_last timestamp without time zone; methods text[];
BEGIN
  PERFORM app_auth.b01_bind_bearer(p_hashes,p_request_id);
  SELECT rt.id,rt."userId",rt."orgId",rt."revokedAt",rt."expiresAt",rt."rotationRequestId"
    INTO t FROM public."RefreshToken" rt WHERE rt.id=p_token_id AND rt."tokenHash"=ANY(p_hashes) FOR UPDATE;
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
DECLARE t record; challenge_id text;
BEGIN
  PERFORM app_auth.b01_bind_bearer(p_hashes,p_request_id);
  SELECT rt.id,rt."userId",rt."orgId",rt."revokedAt",rt."expiresAt",rt."rotationRequestId"
    INTO t FROM public."RefreshToken" rt WHERE rt.id=p_token_id AND rt."tokenHash"=ANY(p_hashes) FOR UPDATE;
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
DECLARE t record; changed integer;
BEGIN
  PERFORM app_auth.b01_bind_bearer(p_hashes,p_request_id);
  SELECT rt.id,rt."userId",rt."orgId",rt."revokedAt",rt."rotationRequestId",rt."rotationCompletedAt"
    INTO t FROM public."RefreshToken" rt WHERE rt.id=p_token_id AND rt."tokenHash"=ANY(p_hashes) FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'B01_REFRESH_REVOCATION_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM app_auth.b01_bind_predecessor(t.id,t."userId",t."orgId",'revoke-scope');
  IF t."userId" IS DISTINCT FROM p_user_id OR t."revokedAt" IS NOT NULL OR t."rotationRequestId" IS DISTINCT FROM p_request_id OR t."rotationCompletedAt" IS NOT NULL OR p_scope NOT IN ('token','password-only','all') OR p_reason NOT IN ('ACCOUNT_UNAVAILABLE','MFA_STATE_CHANGED','MFA_REQUIRED_AFTER_POLICY_CHANGE') THEN RAISE EXCEPTION 'B01_REFRESH_REVOCATION_DENIED' USING ERRCODE='42501'; END IF;
  UPDATE public."RefreshToken" rt SET "revokedAt"=p_revoked_at,"revokedReason"=p_reason,"lastUsedAt"=p_revoked_at WHERE rt."userId"=t."userId" AND rt."revokedAt" IS NULL AND (p_scope<>'token' OR rt.id=p_token_id) AND (p_scope<>'password-only' OR rt."mfaVerifiedAt" IS NULL);
  GET DIAGNOSTICS changed=ROW_COUNT; PERFORM app_auth.b01_audit('AUTH_REFRESH_REVOKED',t.id,p_revoked_at); RETURN QUERY SELECT changed;
END
$fn$;

CREATE OR REPLACE FUNCTION app_auth.complete_refresh_token_rotation(p_token_id text,p_hashes text[],p_user_id text,p_organization_id text,p_token_hash text,p_expires_at timestamp without time zone,p_ip_hash text,p_user_agent text,p_authenticated_at timestamp without time zone,p_mfa_verified_at timestamp without time zone,p_rotated_at timestamp without time zone,p_request_id text)
RETURNS TABLE("id" text,"expiresAt" timestamp without time zone) LANGUAGE plpgsql SECURITY DEFINER VOLATILE SET search_path=pg_catalog,public AS $fn$
DECLARE t record; successor_id text; changed integer;
BEGIN
  PERFORM app_auth.b01_bind_bearer(p_hashes,p_request_id);
  SELECT rt.id,rt."userId",rt."orgId",rt."revokedAt",rt."expiresAt",rt."rotationRequestId",
    rt."rotationCompletedAt",rt."authenticatedAt",rt."mfaVerifiedAt"
    INTO t FROM public."RefreshToken" rt WHERE rt.id=p_token_id AND rt."tokenHash"=ANY(p_hashes) FOR UPDATE;
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
  IF p_action NOT IN ('AUTH_LOGIN_FAIL','AUTH_LOGIN_LOCKED','AUTH_PASSWORD_RESET_REQUESTED','AUTH_PASSWORD_RESET_COMPLETED','AUTH_EMAIL_VERIFIED','AUTH_EMAIL_CHANGE_CONFIRMED','AUTH_INVITE_ACCEPTED')
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
DECLARE candidate_count integer; actor_row record;
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
  SELECT u.id,u."orgId",u."licenseeId",u."failedLoginAttempts",u."lockedUntil"
    INTO STRICT actor_row FROM public."User" u WHERE lower(u.email)=p_requested_email FOR UPDATE;
  PERFORM set_config('app.b01_preauth_user_id',actor_row.id,true),
          set_config('app.b01_preauth_org_id',coalesce(actor_row."orgId",''),true),
          set_config('app.b01_preauth_licensee_id',coalesce(actor_row."licenseeId",''),true);
  IF actor_row."lockedUntil" IS NOT NULL AND actor_row."lockedUntil">p_attempted_at THEN
    PERFORM app_auth.b01_preauth_audit('AUTH_LOGIN_LOCKED','User',actor_row.id,p_attempted_at,
      jsonb_build_object('lockedUntil',actor_row."lockedUntil"));
    RETURN QUERY SELECT actor_row."failedLoginAttempts"::integer,actor_row."lockedUntil"::timestamp;
    RETURN;
  END IF;
  RETURN QUERY
  UPDATE public."User" u SET
    "failedLoginAttempts"=u."failedLoginAttempts"+1,
    "lockedUntil"=CASE WHEN u."failedLoginAttempts"+1>=p_max_attempts
      THEN greatest(coalesce(u."lockedUntil",p_attempted_at),p_attempted_at+make_interval(mins=>p_lockout_minutes))
      ELSE u."lockedUntil" END,
    "updatedAt"=p_attempted_at
  WHERE lower(u.email)=p_requested_email
  RETURNING u."failedLoginAttempts",u."lockedUntil";
  PERFORM app_auth.b01_preauth_audit('AUTH_LOGIN_FAIL','User',actor_row.id,p_attempted_at,
    jsonb_build_object('reason','INVALID_CREDENTIALS'));
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
DECLARE session_row record; capability_hash text;
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
  RETURNING rt.id,rt."expiresAt",rt."mfaVerifiedAt",rt."sessionCapabilityHash" INTO session_row;
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
   FOR SHARE OF s;
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

CREATE OR REPLACE FUNCTION app_rls.load_authenticated_manufacturer_scope(
  p_requested_licensee_id text,p_requested_org_id text,p_requested_scope_version text,
  p_purpose text,p_write_audit boolean
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; selected record; link_count integer; primary_count integer; links jsonb; audit_id text;
BEGIN
  SELECT * INTO actor FROM app_rls.b01_authenticated_actor(
    current_setting('app.user_id',true),
    current_setting('app.auth_session_id',true),
    current_setting('app.request_id',true)
  );
  IF actor.role <> 'MANUFACTURER_ADMIN'
     OR p_purpose NOT IN ('manufacturer-bootstrap','manufacturer-scope-switch')
     OR (p_requested_licensee_id IS NOT NULL AND p_requested_licensee_id !~* '^[0-9a-f-]{36}$')
     OR (p_requested_org_id IS NOT NULL AND p_requested_org_id !~* '^[0-9a-f-]{36}$')
     OR (p_requested_licensee_id IS NOT NULL AND p_requested_scope_version IS NULL)
  THEN RAISE EXCEPTION 'MANUFACTURER_SCOPE_DENIED' USING ERRCODE='42501'; END IF;

  PERFORM set_config('app.auth_closure_operation','manufacturer-scope-read',true),
          set_config('app.auth_closure_user_id',actor."userId",true);
  SELECT count(*) INTO link_count
  FROM public."ManufacturerLicenseeLink" ml
  JOIN public."Licensee" l ON l.id=ml."licenseeId"
  JOIN public."Organization" o ON o.id=l."orgId"
  WHERE ml."manufacturerId"=actor."userId" AND l."isActive"
    AND l."suspendedAt" IS NULL AND o."isActive";
  IF link_count=0 THEN RAISE EXCEPTION 'MANUFACTURER_MEMBERSHIP_REQUIRED' USING ERRCODE='42501'; END IF;
  IF link_count>100 THEN RAISE EXCEPTION 'MANUFACTURER_MEMBERSHIP_SET_TOO_LARGE' USING ERRCODE='54000'; END IF;
  SELECT count(*) INTO primary_count
  FROM public."ManufacturerLicenseeLink" ml
  JOIN public."Licensee" l ON l.id=ml."licenseeId"
  JOIN public."Organization" o ON o.id=l."orgId"
  WHERE ml."manufacturerId"=actor."userId" AND ml."isPrimary"
    AND l."isActive" AND l."suspendedAt" IS NULL AND o."isActive";
  IF primary_count>1 THEN RAISE EXCEPTION 'MANUFACTURER_MEMBERSHIP_AMBIGUOUS' USING ERRCODE='42501'; END IF;

  SELECT ml."licenseeId",ml."isPrimary",ml."updatedAt",l.id,l.name,l.prefix,l."brandName",l."orgId"
  INTO selected
  FROM public."ManufacturerLicenseeLink" ml
  JOIN public."Licensee" l ON l.id=ml."licenseeId"
  JOIN public."Organization" o ON o.id=l."orgId"
  WHERE ml."manufacturerId"=actor."userId" AND l."isActive"
    AND l."suspendedAt" IS NULL AND o."isActive"
    AND (p_requested_licensee_id IS NULL OR ml."licenseeId"=p_requested_licensee_id)
    AND (p_requested_org_id IS NULL OR l."orgId"=p_requested_org_id)
  ORDER BY
    CASE WHEN p_requested_licensee_id IS NOT NULL OR p_requested_org_id IS NOT NULL THEN 0 ELSE 1 END,
    ml."isPrimary" DESC,ml."createdAt",ml."licenseeId"
  LIMIT 1;
  IF NOT FOUND AND (p_requested_licensee_id IS NOT NULL OR p_requested_org_id IS NOT NULL) THEN
    RAISE EXCEPTION 'MANUFACTURER_SCOPE_DENIED' USING ERRCODE='42501';
  END IF;
  IF p_requested_scope_version IS NOT NULL
     AND to_char(selected."updatedAt" AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') IS DISTINCT FROM p_requested_scope_version
  THEN RAISE EXCEPTION 'MANUFACTURER_SCOPE_STALE' USING ERRCODE='42501'; END IF;
  IF p_requested_licensee_id IS NULL AND p_requested_org_id IS NULL
     AND link_count>1
     AND NOT EXISTS (
       SELECT 1 FROM public."ManufacturerLicenseeLink" ml
       WHERE ml."manufacturerId"=actor."userId" AND ml."isPrimary"
     )
  THEN selected:=NULL; END IF;

  SELECT coalesce(jsonb_agg(jsonb_build_object(
    'id',l.id,'name',l.name,'prefix',l.prefix,'brandName',l."brandName",
    'orgId',l."orgId",'isPrimary',ml."isPrimary",
    'scopeVersion',to_char(ml."updatedAt" AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
  ) ORDER BY ml."isPrimary" DESC,ml."createdAt",ml."licenseeId"),'[]'::jsonb)
  INTO links
  FROM public."ManufacturerLicenseeLink" ml
  JOIN public."Licensee" l ON l.id=ml."licenseeId"
  JOIN public."Organization" o ON o.id=l."orgId"
  WHERE ml."manufacturerId"=actor."userId" AND l."isActive"
    AND l."suspendedAt" IS NULL AND o."isActive";

  IF p_write_audit THEN
    audit_id:=gen_random_uuid()::text;
    PERFORM set_config('app.auth_closure_audit_id',audit_id,true);
    INSERT INTO public."AuditLogOutbox"(
      id,payload,"requestId","organizationId","licenseeId","initiatingUserId",
      "initiatingActorRoleSnapshot","expiresAt","updatedAt"
    ) VALUES (
      audit_id,jsonb_build_object(
        'userId',actor."userId",'orgId',selected."orgId",'licenseeId',selected.id,
        'action',CASE WHEN p_purpose='manufacturer-scope-switch' THEN 'MANUFACTURER_SCOPE_SWITCH' ELSE 'MANUFACTURER_BOOTSTRAP_READ' END,
        'entityType','ManufacturerLicenseeLink',
        'entityId',CASE WHEN selected.id IS NULL THEN actor."userId" ELSE actor."userId"||':'||selected.id END,
        'details',jsonb_build_object('requestId',current_setting('app.request_id',true),
          'selectedLicenseeId',selected.id,'selectedOrganizationId',selected."orgId",
          'scopeVersion',CASE WHEN selected.id IS NULL THEN NULL ELSE to_char(selected."updatedAt" AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') END,
          'assurance',actor."authAssurance",'purpose',p_purpose,
          'outcome',CASE WHEN selected.id IS NULL THEN 'SCOPE_SELECTION_REQUIRED' ELSE 'SELECTED' END)
      ),current_setting('app.request_id',true),selected."orgId",selected.id,actor."userId",actor.role,
      clock_timestamp()+interval '1 day',clock_timestamp()
    );
  END IF;

  RETURN jsonb_build_object(
    'manufacturerId',actor."userId",
    'selectedLicensee',CASE WHEN selected.id IS NULL THEN NULL ELSE jsonb_build_object(
      'id',selected.id,'name',selected.name,'prefix',selected.prefix,'brandName',selected."brandName",
      'orgId',selected."orgId",'isPrimary',selected."isPrimary",
      'scopeVersion',to_char(selected."updatedAt" AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
    ) END,
    'linkedLicensees',links
  );
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

CREATE OR REPLACE FUNCTION app_rls.load_authenticated_password_actor()
RETURNS TABLE(
  "id" text,"passwordHash" text,"role" text,"status" text,"isActive" boolean,
  "disabledAt" timestamp without time zone,"deletedAt" timestamp without time zone
)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record;
BEGIN
  SELECT * INTO actor FROM app_rls.b01_authenticated_actor(
    current_setting('app.user_id',true),
    current_setting('app.auth_session_id',true),
    current_setting('app.request_id',true)
  );
  PERFORM set_config('app.auth_closure_operation','password-actor-read',true);
  RETURN QUERY
  SELECT u.id::text,u."passwordHash"::text,u.role::text,u.status::text,u."isActive",u."disabledAt",u."deletedAt"
    FROM public."User" u
   WHERE u.id=actor."userId"
     AND u."isActive" AND u.status='ACTIVE'::public."UserStatus"
     AND u."disabledAt" IS NULL AND u."deletedAt" IS NULL;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.list_active_refresh_tokens(
  p_user_id text,p_checked_at timestamp without time zone
) RETURNS TABLE(
  "id" text,"userId" text,"orgId" text,"expiresAt" timestamp without time zone,
  "createdAt" timestamp without time zone,"createdIpHash" text,"createdUserAgent" text,
  "authenticatedAt" timestamp without time zone,"mfaVerifiedAt" timestamp without time zone,
  "lastUsedAt" timestamp without time zone,"revokedAt" timestamp without time zone,"revokedReason" text
)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record;
BEGIN
  IF p_checked_at IS NULL OR abs(extract(epoch FROM (p_checked_at-clock_timestamp())))>300 THEN
    RAISE EXCEPTION 'AUTH_SESSION_LIST_DENIED' USING ERRCODE='42501';
  END IF;
  SELECT * INTO actor FROM app_rls.b01_authenticated_actor(
    current_setting('app.user_id',true),
    current_setting('app.auth_session_id',true),
    current_setting('app.request_id',true)
  );
  IF actor."userId" IS DISTINCT FROM p_user_id THEN
    RAISE EXCEPTION 'AUTH_SESSION_LIST_DENIED' USING ERRCODE='42501';
  END IF;
  PERFORM set_config('app.auth_closure_operation','session-list',true);
  RETURN QUERY
  SELECT rt.id::text,rt."userId"::text,rt."orgId"::text,rt."expiresAt",rt."createdAt",
    rt."createdIpHash"::text,rt."createdUserAgent"::text,rt."authenticatedAt",rt."mfaVerifiedAt",
    rt."lastUsedAt",rt."revokedAt",rt."revokedReason"::text
    FROM public."RefreshToken" rt
   WHERE rt."userId"=actor."userId" AND rt."revokedAt" IS NULL AND rt."expiresAt">p_checked_at
   ORDER BY coalesce(rt."lastUsedAt",rt."createdAt") DESC,rt.id
   LIMIT 200;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.revoke_all_refresh_tokens(
  p_user_id text,p_reason text,p_revoked_at timestamp without time zone
) RETURNS TABLE("revokedCount" integer)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; changed integer;
BEGIN
  IF p_reason NOT IN ('ALL_SESSIONS_REVOKED_BY_USER','PASSWORD_CHANGED','MFA_DISABLED')
     OR p_revoked_at IS NULL OR abs(extract(epoch FROM (p_revoked_at-clock_timestamp())))>300 THEN
    RAISE EXCEPTION 'AUTH_SESSION_REVOCATION_DENIED' USING ERRCODE='42501';
  END IF;
  SELECT * INTO actor FROM app_rls.b01_authenticated_actor(
    current_setting('app.user_id',true),
    current_setting('app.auth_session_id',true),
    current_setting('app.request_id',true)
  );
  IF actor."userId" IS DISTINCT FROM p_user_id THEN
    RAISE EXCEPTION 'AUTH_SESSION_REVOCATION_DENIED' USING ERRCODE='42501';
  END IF;
  PERFORM set_config('app.auth_closure_operation','session-revoke-all',true);
  UPDATE public."RefreshToken" rt
     SET "revokedAt"=p_revoked_at,"revokedReason"=p_reason,"lastUsedAt"=p_revoked_at,
         "sessionCapabilityRevokedAt"=p_revoked_at,"sessionCapabilityRevokedReason"=p_reason
   WHERE rt."userId"=actor."userId" AND rt."revokedAt" IS NULL;
  GET DIAGNOSTICS changed=ROW_COUNT;
  RETURN QUERY SELECT changed;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.prove_authenticated_password_step_up(
  p_session_id text,p_expected_password_hash text,p_verified_at timestamp without time zone
) RETURNS TABLE("authorized" boolean)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record;
BEGIN
  IF p_expected_password_hash IS NULL OR p_verified_at IS NULL
     OR abs(extract(epoch FROM (p_verified_at-clock_timestamp())))>300 THEN
    RAISE EXCEPTION 'AUTH_PASSWORD_STEP_UP_DENIED' USING ERRCODE='42501';
  END IF;
  SELECT * INTO actor FROM app_rls.b01_authenticated_actor(
    current_setting('app.user_id',true),p_session_id,current_setting('app.request_id',true)
  );
  PERFORM set_config('app.auth_closure_operation','password-step-up',true);
  IF NOT EXISTS (
    SELECT 1 FROM public."User" u
     WHERE u.id=actor."userId" AND u."passwordHash"=p_expected_password_hash
       AND u."isActive" AND u.status='ACTIVE'::public."UserStatus"
       AND u."disabledAt" IS NULL AND u."deletedAt" IS NULL
  ) THEN RETURN QUERY SELECT false; RETURN; END IF;
  UPDATE public."RefreshToken" rt SET "authenticatedAt"=p_verified_at,"lastUsedAt"=p_verified_at
   WHERE rt.id=p_session_id AND rt."userId"=actor."userId" AND rt."revokedAt" IS NULL;
  RETURN QUERY SELECT FOUND;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.require_recent_sensitive_session(
  p_session_id text,p_checked_at timestamp without time zone,
  p_max_password_age_minutes integer,p_max_mfa_age_minutes integer
) RETURNS TABLE("authorized" boolean)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; session_row record;
BEGIN
  IF p_checked_at IS NULL OR abs(extract(epoch FROM (p_checked_at-clock_timestamp())))>300
     OR p_max_password_age_minutes NOT BETWEEN 1 AND 1440
     OR p_max_mfa_age_minutes NOT BETWEEN 1 AND 1440 THEN
    RAISE EXCEPTION 'AUTH_SENSITIVE_SESSION_DENIED' USING ERRCODE='42501';
  END IF;
  SELECT * INTO actor FROM app_rls.b01_authenticated_actor(
    current_setting('app.user_id',true),p_session_id,current_setting('app.request_id',true)
  );
  PERFORM set_config('app.auth_closure_operation','sensitive-session-read',true);
  SELECT rt."authenticatedAt",rt."mfaVerifiedAt" INTO session_row
    FROM public."RefreshToken" rt
   WHERE rt.id=p_session_id AND rt."userId"=actor."userId"
     AND rt."revokedAt" IS NULL AND rt."expiresAt">p_checked_at;
  RETURN QUERY SELECT FOUND
    AND session_row."authenticatedAt">=p_checked_at-(p_max_password_age_minutes*interval '1 minute')
    AND (
      actor.role NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN','LICENSEE_ADMIN','MANUFACTURER_ADMIN')
      OR session_row."mfaVerifiedAt">=p_checked_at-(p_max_mfa_age_minutes*interval '1 minute')
    );
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.request_authenticated_email_change(
  p_next_email text,p_token_hash text,p_secret_version text,
  p_expires_at timestamp without time zone,p_requested_at timestamp without time zone,
  p_ip_hash text,p_user_agent_hash text
) RETURNS TABLE(
  "changed" boolean,"verificationRequired" boolean,"userId" text,"currentEmail" text,
  "pendingEmail" text,"orgId" text,"licenseeId" text,"expiresAt" timestamp without time zone
)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; user_row record; token_id text := gen_random_uuid()::text; normalized_email text := lower(btrim(p_next_email));
BEGIN
  IF normalized_email !~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$'
     OR length(normalized_email)>320
     OR p_token_hash !~ '^([0-9a-f]{12}:)?[a-f0-9]{64}$'
     OR p_secret_version IS NULL OR length(p_secret_version) NOT BETWEEN 1 AND 64
     OR p_requested_at IS NULL OR abs(extract(epoch FROM (p_requested_at-clock_timestamp())))>300
     OR p_expires_at<=p_requested_at OR p_expires_at>p_requested_at+interval '48 hours' THEN
    RAISE EXCEPTION 'AUTH_EMAIL_CHANGE_DENIED' USING ERRCODE='42501';
  END IF;
  SELECT * INTO actor FROM app_rls.b01_authenticated_actor(
    current_setting('app.user_id',true),
    current_setting('app.auth_session_id',true),
    current_setting('app.request_id',true)
  );
  PERFORM set_config('app.auth_closure_operation','email-change',true),
          set_config('app.auth_closure_pending_email',normalized_email,true),
          set_config('app.auth_closure_token_hash',p_token_hash,true);
  SELECT u.id,u.email,u."orgId",u."licenseeId" INTO user_row
    FROM public."User" u WHERE u.id=actor."userId" FOR UPDATE;
  IF lower(user_row.email)=normalized_email THEN
    RETURN QUERY SELECT false,false,user_row.id::text,user_row.email::text,NULL::text,
      user_row."orgId"::text,user_row."licenseeId"::text,NULL::timestamp;
    RETURN;
  END IF;
  IF EXISTS (SELECT 1 FROM public."User" u WHERE lower(u.email)=normalized_email AND u.id<>actor."userId") THEN
    RAISE EXCEPTION 'AUTH_EMAIL_CHANGE_CONFLICT' USING ERRCODE='23505';
  END IF;
  UPDATE public."EmailVerificationToken" t SET "usedAt"=p_requested_at
   WHERE t."userId"=actor."userId" AND t.purpose='EMAIL_CHANGE' AND t."usedAt" IS NULL;
  INSERT INTO public."EmailVerificationToken"(
    id,"userId",email,"pendingEmail",purpose,"tokenHash","secretVersion","expiresAt","createdAt","createdIpHash","userAgentHash"
  ) VALUES (
    token_id,actor."userId",user_row.email,normalized_email,'EMAIL_CHANGE',p_token_hash,p_secret_version,
    p_expires_at,p_requested_at,p_ip_hash,p_user_agent_hash
  );
  UPDATE public."User" u SET "pendingEmail"=normalized_email,"pendingEmailRequestedAt"=p_requested_at,"updatedAt"=p_requested_at
   WHERE u.id=actor."userId";
  PERFORM set_config('app.auth_closure_pending_email',normalized_email,true);
  RETURN QUERY SELECT false,true,user_row.id::text,user_row.email::text,normalized_email,
    user_row."orgId"::text,user_row."licenseeId"::text,p_expires_at;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.update_authenticated_profile(
  p_name text,p_email_change_requested boolean,p_audit_pending_email text,
  p_changed_at timestamp without time zone
) RETURNS TABLE(
  "id" text,"email" text,"name" text,"role" text,"licenseeId" text,"orgId" text,
  "emailVerifiedAt" timestamp without time zone,"pendingEmail" text,"pendingEmailRequestedAt" timestamp without time zone,
  "isActive" boolean,"status" text,"deletedAt" timestamp without time zone,"disabledAt" timestamp without time zone,
  "createdAt" timestamp without time zone,"licenseeRecordId" text,"licenseeName" text,
  "licenseePrefix" text,"licenseeBrandName" text,"licenseeOrgId" text
)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; audit_id text := gen_random_uuid()::text;
BEGIN
  IF p_changed_at IS NULL OR abs(extract(epoch FROM (p_changed_at-clock_timestamp())))>300
     OR (p_name IS NOT NULL AND length(btrim(p_name)) NOT BETWEEN 2 AND 80)
     OR (p_email_change_requested AND NOT EXISTS (
       SELECT 1 FROM public."User" pending_actor
        WHERE pending_actor.id=current_setting('app.user_id',true)
          AND lower(pending_actor."pendingEmail")=lower(btrim(coalesce(p_audit_pending_email,'')))
     )) THEN
    RAISE EXCEPTION 'AUTH_PROFILE_UPDATE_DENIED' USING ERRCODE='42501';
  END IF;
  SELECT * INTO actor FROM app_rls.b01_authenticated_actor(
    current_setting('app.user_id',true),
    current_setting('app.auth_session_id',true),
    current_setting('app.request_id',true)
  );
  PERFORM set_config('app.auth_closure_operation','profile-update',true);
  UPDATE public."User" u SET name=coalesce(btrim(p_name),u.name),"updatedAt"=p_changed_at
   WHERE u.id=actor."userId";
  IF NOT FOUND THEN RAISE EXCEPTION 'AUTH_PROFILE_UPDATE_DENIED' USING ERRCODE='42501'; END IF;
  INSERT INTO public."AuditLogOutbox"(id,payload,"requestId","organizationId","licenseeId","initiatingUserId","initiatingActorRoleSnapshot","expiresAt","updatedAt")
  VALUES (
    audit_id,
    jsonb_build_object('userId',actor."userId",'action','AUTH_PROFILE_UPDATED','entityType','User','entityId',actor."userId",
      'details',jsonb_build_object('nameChanged',p_name IS NOT NULL,'emailChangeRequested',p_email_change_requested)),
    current_setting('app.request_id',true),nullif(actor."organizationId",''),nullif(actor."licenseeId",''),
    actor."userId",actor.role,p_changed_at+interval '1 day',p_changed_at
  );
  RETURN QUERY SELECT a.* FROM app_rls.load_authenticated_actor() a;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.change_authenticated_password(
  p_expected_password_hash text,p_password_hash text,p_changed_at timestamp without time zone
) RETURNS TABLE("changed" boolean)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; changed integer;
BEGIN
  IF p_expected_password_hash IS NULL OR p_password_hash !~ '^\$argon2(id|i|d)\$'
     OR p_changed_at IS NULL OR abs(extract(epoch FROM (p_changed_at-clock_timestamp())))>300 THEN
    RAISE EXCEPTION 'AUTH_PASSWORD_CHANGE_DENIED' USING ERRCODE='42501';
  END IF;
  SELECT * INTO actor FROM app_rls.b01_authenticated_actor(
    current_setting('app.user_id',true),
    current_setting('app.auth_session_id',true),
    current_setting('app.request_id',true)
  );
  PERFORM set_config('app.auth_closure_operation','password-change',true);
  UPDATE public."User" u SET "passwordHash"=p_password_hash,"updatedAt"=p_changed_at
   WHERE u.id=actor."userId" AND u."passwordHash"=p_expected_password_hash;
  GET DIAGNOSTICS changed=ROW_COUNT;
  IF changed<>1 THEN RETURN QUERY SELECT false; RETURN; END IF;
  UPDATE public."RefreshToken" rt
     SET "revokedAt"=p_changed_at,"revokedReason"='PASSWORD_CHANGED',
         "sessionCapabilityRevokedAt"=p_changed_at,"sessionCapabilityRevokedReason"='PASSWORD_CHANGED'
   WHERE rt."userId"=actor."userId" AND rt."revokedAt" IS NULL;
  INSERT INTO public."AuditLogOutbox"(id,payload,"requestId","organizationId","licenseeId","initiatingUserId","initiatingActorRoleSnapshot","expiresAt","updatedAt")
  VALUES (
    gen_random_uuid()::text,
    jsonb_build_object('userId',actor."userId",'action','AUTH_PASSWORD_CHANGED','entityType','User','entityId',actor."userId"),
    current_setting('app.request_id',true),nullif(actor."organizationId",''),nullif(actor."licenseeId",''),
    actor."userId",actor.role,p_changed_at+interval '1 day',p_changed_at
  );
  RETURN QUERY SELECT true;
END
$fn$;

-- RF7 compatibility closure: admin MFA persistence remains application-crypto
-- driven, while every protected row is selected or mutated by an actor-bound
-- capability. Raw MFA secrets and bearer material are never written to audit.
CREATE OR REPLACE FUNCTION app_rls.b01_admin_mfa_actor()
RETURNS TABLE("userId" text,"role" text,"organizationId" text,"licenseeId" text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record;
BEGIN
  SELECT * INTO actor FROM app_rls.b01_authenticated_actor(
    current_setting('app.user_id',true),
    current_setting('app.auth_session_id',true),
    current_setting('app.request_id',true)
  );
  IF actor.role NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN','LICENSEE_ADMIN','MANUFACTURER_ADMIN') THEN
    RAISE EXCEPTION 'AUTH_MFA_ROLE_DENIED' USING ERRCODE='42501';
  END IF;
  RETURN QUERY SELECT actor."userId"::text,actor.role::text,actor."organizationId"::text,actor."licenseeId"::text;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.load_admin_mfa_state()
RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; result jsonb;
BEGIN
  SELECT * INTO actor FROM app_rls.b01_admin_mfa_actor();
  PERFORM set_config('app.auth_closure_operation','mfa-state-read',true);
  SELECT jsonb_build_object(
    'legacyTotp',(SELECT to_jsonb(x) FROM (
      SELECT c.id,c."isEnabled",c."verifiedAt",c."lastUsedAt",c."backupCodesHash",c."createdAt",c."updatedAt"
      FROM public."AdminMfaCredential" c WHERE c."userId"=actor."userId"
    ) x),
    'legacyWebAuthn',coalesce((SELECT jsonb_agg(to_jsonb(x) ORDER BY x."lastUsedAt" DESC NULLS LAST,x."createdAt" DESC) FROM (
      SELECT c.id,c.label,c."credentialId",c.transports,c."lastUsedAt",c."createdAt",c."updatedAt"
      FROM public."AdminWebAuthnCredential" c WHERE c."userId"=actor."userId"
    ) x),'[]'::jsonb),
    'factors',coalesce((SELECT jsonb_agg(to_jsonb(x) ORDER BY x."lastUsedAt" DESC NULLS LAST,x."createdAt" DESC) FROM (
      SELECT f.id,f.type,f.label,f."credentialId",f.transports,f."legacySource",f."lastUsedAt",f."createdAt",f."updatedAt"
      FROM public."UserMfaFactor" f WHERE f."userId"=actor."userId" AND f."disabledAt" IS NULL
    ) x),'[]'::jsonb),
    'backupCodesRemaining',(SELECT count(*) FROM public."UserBackupCode" b WHERE b."userId"=actor."userId" AND b."usedAt" IS NULL)
  ) INTO result;
  RETURN result;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.begin_admin_totp_enrollment(
  p_mode text,p_secret_ciphertext text,p_secret_iv text,p_secret_tag text,p_backup_hashes text[],
  p_pending_cutoff timestamp without time zone,p_created_at timestamp without time zone
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; enrolled boolean; pending_count integer; credential_id text; factor_id text;
BEGIN
  IF p_mode NOT IN ('FIRST_ENROLLMENT','REPLACEMENT') OR p_secret_ciphertext IS NULL OR p_secret_iv IS NULL
     OR p_secret_tag IS NULL OR cardinality(p_backup_hashes) NOT BETWEEN 1 AND 20
     OR p_pending_cutoff IS NULL OR p_created_at IS NULL
     OR abs(extract(epoch FROM (p_created_at-clock_timestamp())))>300
     OR p_pending_cutoff>p_created_at OR p_pending_cutoff<p_created_at-interval '30 minutes' THEN
    RAISE EXCEPTION 'MFA_ENROLLMENT_INPUT_DENIED' USING ERRCODE='22023';
  END IF;
  SELECT * INTO actor FROM app_rls.b01_admin_mfa_actor();
  PERFORM pg_advisory_xact_lock(hashtextextended('mfa_state:'||actor."userId",0));
  PERFORM set_config('app.auth_closure_operation','mfa-enrollment-begin',true);

  SELECT coalesce(bool_or(v),false) INTO enrolled FROM (
    SELECT c."isEnabled" OR c."verifiedAt" IS NOT NULL AS v FROM public."AdminMfaCredential" c WHERE c."userId"=actor."userId"
    UNION ALL SELECT true FROM public."AdminWebAuthnCredential" w WHERE w."userId"=actor."userId"
    UNION ALL SELECT true FROM public."UserMfaFactor" f WHERE f."userId"=actor."userId" AND f."disabledAt" IS NULL
      AND f."legacySource" IS DISTINCT FROM 'MFA_ENROLLMENT_PENDING'
      AND (f.type='WEBAUTHN' OR (f.type='TOTP' AND (f."lastUsedAt" IS NOT NULL OR f."legacySource"='AdminMfaCredential')))
  ) q;
  IF p_mode='FIRST_ENROLLMENT' AND enrolled THEN RAISE EXCEPTION 'MFA_ALREADY_ENROLLED' USING ERRCODE='23505'; END IF;
  IF p_mode='REPLACEMENT' AND NOT enrolled THEN RAISE EXCEPTION 'MFA_REPLACEMENT_REQUIRES_ENROLLED_FACTOR' USING ERRCODE='23514'; END IF;

  SELECT count(*) INTO pending_count FROM public."UserMfaFactor" f
   WHERE f."userId"=actor."userId" AND f.type='TOTP' AND f."disabledAt" IS NULL
     AND f."legacySource"='MFA_ENROLLMENT_PENDING' AND f."createdAt">p_pending_cutoff;
  IF pending_count>0 THEN RAISE EXCEPTION 'MFA_SETUP_ALREADY_STARTED' USING ERRCODE='23505'; END IF;
  DELETE FROM public."UserMfaFactor" f WHERE f."userId"=actor."userId" AND f.type='TOTP'
    AND f."legacySource"='MFA_ENROLLMENT_PENDING';

  IF p_mode='REPLACEMENT' THEN
    INSERT INTO public."UserMfaFactor"(id,"userId",type,label,"secretCiphertext","secretIv","secretTag","legacySource","legacyCredentialId","lastUsedAt","createdAt","updatedAt")
    SELECT 'legacy-totp-'||actor."userId",actor."userId",'TOTP','Authenticator app',c."secretCiphertext",c."secretIv",c."secretTag",
           'AdminMfaCredential',actor."userId",coalesce(c."lastUsedAt",c."verifiedAt"),p_created_at,p_created_at
      FROM public."AdminMfaCredential" c
     WHERE c."userId"=actor."userId" AND c."isEnabled"
       AND NOT EXISTS (SELECT 1 FROM public."UserMfaFactor" f WHERE f."userId"=actor."userId" AND f.type='TOTP'
         AND f."disabledAt" IS NULL AND f."legacySource" IS DISTINCT FROM 'MFA_ENROLLMENT_PENDING')
    ON CONFLICT (id) DO UPDATE SET "disabledAt"=NULL,"lastUsedAt"=excluded."lastUsedAt","updatedAt"=p_created_at;
    INSERT INTO public."UserBackupCode"(id,"userId","codeHash","createdAt")
    SELECT gen_random_uuid()::text,actor."userId",h,p_created_at
      FROM public."AdminMfaCredential" c,unnest(c."backupCodesHash") h
     WHERE c."userId"=actor."userId" AND c."isEnabled"
    ON CONFLICT ("codeHash") DO NOTHING;
  END IF;

  SELECT c.id INTO credential_id FROM public."AdminMfaCredential" c WHERE c."userId"=actor."userId" FOR UPDATE;
  IF credential_id IS NULL THEN
    credential_id:=gen_random_uuid()::text;
    INSERT INTO public."AdminMfaCredential"(id,"userId","secretCiphertext","secretIv","secretTag","backupCodesHash","isEnabled","verifiedAt","lastUsedAt","createdAt","updatedAt")
    VALUES (credential_id,actor."userId",p_secret_ciphertext,p_secret_iv,p_secret_tag,p_backup_hashes,false,NULL,NULL,p_created_at,p_created_at);
  ELSE
    UPDATE public."AdminMfaCredential" SET "secretCiphertext"=p_secret_ciphertext,"secretIv"=p_secret_iv,"secretTag"=p_secret_tag,
      "backupCodesHash"=p_backup_hashes,"isEnabled"=false,"verifiedAt"=NULL,"lastUsedAt"=NULL,"updatedAt"=p_created_at
      WHERE id=credential_id;
  END IF;
  factor_id:=gen_random_uuid()::text;
  INSERT INTO public."UserMfaFactor"(id,"userId",type,label,"secretCiphertext","secretIv","secretTag","legacySource","legacyCredentialId","createdAt","updatedAt")
  VALUES (factor_id,actor."userId",'TOTP','Authenticator app',p_secret_ciphertext,p_secret_iv,p_secret_tag,
          'MFA_ENROLLMENT_PENDING',actor."userId",p_created_at,p_created_at);
  RETURN jsonb_build_object('factorId',factor_id);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.load_admin_totp_enrollment(
  p_mode text,p_pending_cutoff timestamp without time zone
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; result jsonb; enrolled boolean;
BEGIN
  IF p_mode NOT IN ('FIRST_ENROLLMENT','REPLACEMENT') OR p_pending_cutoff IS NULL THEN
    RAISE EXCEPTION 'MFA_ENROLLMENT_INPUT_DENIED' USING ERRCODE='22023';
  END IF;
  SELECT * INTO actor FROM app_rls.b01_admin_mfa_actor();
  PERFORM pg_advisory_xact_lock(hashtextextended('mfa_state:'||actor."userId",0));
  PERFORM set_config('app.auth_closure_operation','mfa-enrollment-load',true);
  SELECT coalesce(bool_or(v),false) INTO enrolled FROM (
    SELECT c."isEnabled" OR c."verifiedAt" IS NOT NULL AS v FROM public."AdminMfaCredential" c WHERE c."userId"=actor."userId"
    UNION ALL SELECT true FROM public."AdminWebAuthnCredential" w WHERE w."userId"=actor."userId"
    UNION ALL SELECT true FROM public."UserMfaFactor" f WHERE f."userId"=actor."userId" AND f."disabledAt" IS NULL
      AND f."legacySource" IS DISTINCT FROM 'MFA_ENROLLMENT_PENDING'
      AND (f.type='WEBAUTHN' OR (f.type='TOTP' AND (f."lastUsedAt" IS NOT NULL OR f."legacySource"='AdminMfaCredential')))
  ) q;
  IF p_mode='FIRST_ENROLLMENT' AND enrolled THEN RAISE EXCEPTION 'MFA_ALREADY_ENROLLED' USING ERRCODE='23505'; END IF;
  IF p_mode='REPLACEMENT' AND NOT enrolled THEN RAISE EXCEPTION 'MFA_REPLACEMENT_REQUIRES_ENROLLED_FACTOR' USING ERRCODE='23514'; END IF;
  SELECT jsonb_build_object(
    'credential',(SELECT to_jsonb(x) FROM (
      SELECT c.id,c."secretCiphertext",c."secretIv",c."secretTag",c."backupCodesHash",c."isEnabled",c."verifiedAt"
      FROM public."AdminMfaCredential" c WHERE c."userId"=actor."userId"
    ) x),
    'pending',coalesce((SELECT jsonb_agg(to_jsonb(x)) FROM (
      SELECT f.id,f."secretCiphertext",f."secretIv",f."secretTag",f."createdAt"
      FROM public."UserMfaFactor" f WHERE f."userId"=actor."userId" AND f.type='TOTP'
        AND f."disabledAt" IS NULL AND f."legacySource"='MFA_ENROLLMENT_PENDING' AND f."createdAt">p_pending_cutoff
    ) x),'[]'::jsonb)
  ) INTO result;
  RETURN result;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.complete_admin_totp_enrollment(
  p_mode text,p_factor_id text,p_secret_ciphertext text,p_secret_iv text,p_secret_tag text,
  p_completed_at timestamp without time zone,p_ip_hash text,p_user_agent text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; hashes text[]; changed integer;
BEGIN
  IF p_mode NOT IN ('FIRST_ENROLLMENT','REPLACEMENT') OR p_factor_id IS NULL OR p_secret_ciphertext IS NULL
     OR p_secret_iv IS NULL OR p_secret_tag IS NULL OR p_completed_at IS NULL
     OR abs(extract(epoch FROM (p_completed_at-clock_timestamp())))>300 THEN
    RAISE EXCEPTION 'MFA_ENROLLMENT_INPUT_DENIED' USING ERRCODE='22023';
  END IF;
  SELECT * INTO actor FROM app_rls.b01_admin_mfa_actor();
  PERFORM pg_advisory_xact_lock(hashtextextended('mfa_state:'||actor."userId",0));
  PERFORM set_config('app.auth_closure_operation','mfa-enrollment-complete',true);
  SELECT c."backupCodesHash" INTO hashes FROM public."AdminMfaCredential" c
   WHERE c."userId"=actor."userId" AND NOT c."isEnabled" AND c."verifiedAt" IS NULL
     AND c."secretCiphertext"=p_secret_ciphertext AND c."secretIv"=p_secret_iv AND c."secretTag"=p_secret_tag FOR UPDATE;
  IF NOT FOUND OR NOT EXISTS (
    SELECT 1 FROM public."UserMfaFactor" f WHERE f.id=p_factor_id AND f."userId"=actor."userId"
      AND f.type='TOTP' AND f."disabledAt" IS NULL AND f."legacySource"='MFA_ENROLLMENT_PENDING'
      AND f."secretCiphertext"=p_secret_ciphertext AND f."secretIv"=p_secret_iv AND f."secretTag"=p_secret_tag
  ) THEN RAISE EXCEPTION 'MFA_SETUP_NOT_STARTED' USING ERRCODE='23514'; END IF;
  UPDATE public."UserMfaFactor" SET "disabledAt"=p_completed_at,"updatedAt"=p_completed_at
    WHERE "userId"=actor."userId" AND type='TOTP' AND "disabledAt" IS NULL AND id<>p_factor_id;
  UPDATE public."UserMfaFactor" SET "legacySource"=NULL,"legacyCredentialId"=NULL,"lastUsedAt"=p_completed_at,
    "disabledAt"=NULL,"updatedAt"=p_completed_at WHERE id=p_factor_id AND "userId"=actor."userId";
  UPDATE public."AdminMfaCredential" SET "isEnabled"=true,"verifiedAt"=p_completed_at,"lastUsedAt"=p_completed_at,"updatedAt"=p_completed_at
    WHERE "userId"=actor."userId" AND NOT "isEnabled" AND "verifiedAt" IS NULL;
  GET DIAGNOSTICS changed=ROW_COUNT;
  IF changed<>1 THEN RAISE EXCEPTION 'MFA_SETUP_NOT_STARTED' USING ERRCODE='23514'; END IF;
  DELETE FROM public."UserBackupCode" WHERE "userId"=actor."userId" AND "usedAt" IS NULL;
  INSERT INTO public."UserBackupCode"(id,"userId","codeHash","createdAt")
    SELECT gen_random_uuid()::text,actor."userId",h,p_completed_at FROM unnest(hashes) h;
  INSERT INTO public."AuditLogOutbox"(id,payload,"requestId","organizationId","licenseeId","initiatingUserId","initiatingActorRoleSnapshot","expiresAt","updatedAt")
  VALUES (gen_random_uuid()::text,jsonb_build_object('userId',actor."userId",'action',
    CASE WHEN p_mode='REPLACEMENT' THEN 'AUTH_MFA_REPLACED' ELSE 'AUTH_MFA_ENROLLED' END,
    'entityType','User','entityId',actor."userId",'details',jsonb_build_object('source',
    CASE WHEN p_mode='REPLACEMENT' THEN 'ACTIVE_SESSION' ELSE 'LOGIN_BOOTSTRAP' END),
    'ipHash',p_ip_hash,'userAgent',p_user_agent),current_setting('app.request_id',true),
    nullif(actor."organizationId",''),nullif(actor."licenseeId",''),actor."userId",actor.role,p_completed_at+interval '1 day',p_completed_at);
  RETURN jsonb_build_object('enabled',true);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.load_admin_mfa_verifiers()
RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; result jsonb;
BEGIN
  SELECT * INTO actor FROM app_rls.b01_admin_mfa_actor();
  PERFORM pg_advisory_xact_lock(hashtextextended('mfa_state:'||actor."userId",0));
  PERFORM set_config('app.auth_closure_operation','mfa-verifier-read',true);
  SELECT jsonb_build_object(
    'factors',coalesce((SELECT jsonb_agg(to_jsonb(x) ORDER BY x."createdAt" DESC) FROM (
      SELECT f.id,f."secretCiphertext",f."secretIv",f."secretTag",f."legacySource",f."lastUsedAt",f."createdAt"
      FROM public."UserMfaFactor" f WHERE f."userId"=actor."userId" AND f.type='TOTP'
        AND f."disabledAt" IS NULL AND f."secretCiphertext" IS NOT NULL
    ) x),'[]'::jsonb),
    'backupCodes',coalesce((SELECT jsonb_agg(jsonb_build_object('id',b.id,'codeHash',b."codeHash")) FROM public."UserBackupCode" b
      WHERE b."userId"=actor."userId" AND b."usedAt" IS NULL),'[]'::jsonb),
    'legacy',(SELECT to_jsonb(x) FROM (
      SELECT c."isEnabled",c."secretCiphertext",c."secretIv",c."secretTag",c."backupCodesHash"
      FROM public."AdminMfaCredential" c WHERE c."userId"=actor."userId"
    ) x)
  ) INTO result;
  RETURN result;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.consume_admin_mfa_verifier(
  p_method text,p_record_id text,p_expected_legacy_hashes text[],p_next_legacy_hashes text[],
  p_used_at timestamp without time zone
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; changed integer;
BEGIN
  IF p_method NOT IN ('TOTP_FACTOR','TOTP_LEGACY','BACKUP_CODE','BACKUP_LEGACY') OR p_used_at IS NULL
     OR abs(extract(epoch FROM (p_used_at-clock_timestamp())))>300 THEN
    RAISE EXCEPTION 'MFA_VERIFIER_INPUT_DENIED' USING ERRCODE='22023';
  END IF;
  SELECT * INTO actor FROM app_rls.b01_admin_mfa_actor();
  PERFORM pg_advisory_xact_lock(hashtextextended('mfa_state:'||actor."userId",0));
  PERFORM set_config('app.auth_closure_operation','mfa-verifier-consume',true);
  changed:=0;
  IF p_method='TOTP_FACTOR' THEN
    UPDATE public."UserMfaFactor" SET "lastUsedAt"=p_used_at,"updatedAt"=p_used_at
     WHERE id=p_record_id AND "userId"=actor."userId" AND type='TOTP' AND "disabledAt" IS NULL;
    GET DIAGNOSTICS changed=ROW_COUNT;
  ELSIF p_method='TOTP_LEGACY' THEN
    UPDATE public."AdminMfaCredential" SET "lastUsedAt"=p_used_at,"updatedAt"=p_used_at
     WHERE "userId"=actor."userId" AND "isEnabled";
    GET DIAGNOSTICS changed=ROW_COUNT;
    IF changed=1 THEN
      INSERT INTO public."UserMfaFactor"(id,"userId",type,label,"secretCiphertext","secretIv","secretTag",
        "legacySource","legacyCredentialId","lastUsedAt","createdAt","updatedAt")
      SELECT 'legacy-totp-'||actor."userId",actor."userId",'TOTP','Authenticator app',
        c."secretCiphertext",c."secretIv",c."secretTag",'AdminMfaCredential',actor."userId",
        p_used_at,p_used_at,p_used_at
      FROM public."AdminMfaCredential" c WHERE c."userId"=actor."userId" AND c."isEnabled"
      ON CONFLICT (id) DO UPDATE SET "disabledAt"=NULL,"lastUsedAt"=p_used_at,"updatedAt"=p_used_at;
    END IF;
  ELSIF p_method='BACKUP_CODE' THEN
    UPDATE public."UserBackupCode" SET "usedAt"=p_used_at
     WHERE id=p_record_id AND "userId"=actor."userId" AND "usedAt" IS NULL;
    GET DIAGNOSTICS changed=ROW_COUNT;
  ELSE
    UPDATE public."AdminMfaCredential" SET "backupCodesHash"=p_next_legacy_hashes,"lastUsedAt"=p_used_at,"updatedAt"=p_used_at
     WHERE "userId"=actor."userId" AND "isEnabled" AND "backupCodesHash"=p_expected_legacy_hashes;
    GET DIAGNOSTICS changed=ROW_COUNT;
  END IF;
  RETURN jsonb_build_object('consumed',changed=1);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.replace_admin_backup_codes(
  p_hashes text[],p_replaced_at timestamp without time zone
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record;
BEGIN
  IF cardinality(p_hashes) NOT BETWEEN 1 AND 20 OR p_replaced_at IS NULL
     OR abs(extract(epoch FROM (p_replaced_at-clock_timestamp())))>300 THEN
    RAISE EXCEPTION 'MFA_BACKUP_INPUT_DENIED' USING ERRCODE='22023';
  END IF;
  SELECT * INTO actor FROM app_rls.b01_admin_mfa_actor();
  PERFORM pg_advisory_xact_lock(hashtextextended('mfa_state:'||actor."userId",0));
  PERFORM set_config('app.auth_closure_operation','mfa-backup-replace',true);
  DELETE FROM public."UserBackupCode" WHERE "userId"=actor."userId" AND "usedAt" IS NULL;
  INSERT INTO public."UserBackupCode"(id,"userId","codeHash","createdAt")
    SELECT gen_random_uuid()::text,actor."userId",h,p_replaced_at FROM unnest(p_hashes) h;
  UPDATE public."AdminMfaCredential" SET "backupCodesHash"=p_hashes,"lastUsedAt"=p_replaced_at,"updatedAt"=p_replaced_at
    WHERE "userId"=actor."userId";
  RETURN jsonb_build_object('replaced',true);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.disable_admin_mfa(
  p_disabled_at timestamp without time zone,p_ip_hash text,p_user_agent text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record;
BEGIN
  IF p_disabled_at IS NULL OR abs(extract(epoch FROM (p_disabled_at-clock_timestamp())))>300 THEN
    RAISE EXCEPTION 'MFA_DISABLE_INPUT_DENIED' USING ERRCODE='22023';
  END IF;
  SELECT * INTO actor FROM app_rls.b01_admin_mfa_actor();
  PERFORM pg_advisory_xact_lock(hashtextextended('mfa_state:'||actor."userId",0));
  PERFORM set_config('app.auth_closure_operation','mfa-disable',true);
  UPDATE public."AdminMfaCredential" SET "backupCodesHash"='{}',"isEnabled"=false,"verifiedAt"=NULL,"lastUsedAt"=NULL,"updatedAt"=p_disabled_at
    WHERE "userId"=actor."userId";
  UPDATE public."UserMfaFactor" SET "disabledAt"=p_disabled_at,"updatedAt"=p_disabled_at
    WHERE "userId"=actor."userId" AND "disabledAt" IS NULL;
  DELETE FROM public."AdminWebAuthnCredential" WHERE "userId"=actor."userId";
  DELETE FROM public."UserBackupCode" WHERE "userId"=actor."userId" AND "usedAt" IS NULL;
  UPDATE public."RefreshToken" SET "revokedAt"=p_disabled_at,"revokedReason"='MFA_DISABLED',"lastUsedAt"=p_disabled_at,
    "sessionCapabilityRevokedAt"=p_disabled_at,"sessionCapabilityRevokedReason"='MFA_DISABLED'
    WHERE "userId"=actor."userId" AND "revokedAt" IS NULL;
  INSERT INTO public."AuditLogOutbox"(id,payload,"requestId","organizationId","licenseeId","initiatingUserId","initiatingActorRoleSnapshot","expiresAt","updatedAt")
  VALUES (gen_random_uuid()::text,jsonb_build_object('userId',actor."userId",'action','AUTH_MFA_DISABLED','entityType','User',
    'entityId',actor."userId",'details',jsonb_build_object('actorUserId',actor."userId"),'ipHash',p_ip_hash,'userAgent',p_user_agent),
    current_setting('app.request_id',true),nullif(actor."organizationId",''),nullif(actor."licenseeId",''),
    actor."userId",actor.role,p_disabled_at+interval '1 day',p_disabled_at);
  RETURN jsonb_build_object('enabled',false);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.create_admin_mfa_challenge(
  p_kind text,p_ticket_hash text,p_session_binding_hash text,p_purpose text,p_risk_score integer,p_risk_level text,
  p_reasons text[],p_ip_hash text,p_user_agent_hash text,p_max_attempts integer,
  p_created_at timestamp without time zone,p_expires_at timestamp without time zone
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; challenge_id text:=gen_random_uuid()::text;
BEGIN
  IF p_kind NOT IN ('LOGIN','SESSION') OR p_ticket_hash !~ '^([0-9a-f]{12}:)?[a-f0-9]{64}$'
     OR p_purpose NOT IN ('admin_login','high_risk_action')
     OR (p_kind='LOGIN') IS DISTINCT FROM (p_purpose='admin_login')
     OR (p_kind='SESSION') IS DISTINCT FROM (p_session_binding_hash IS NOT NULL)
     OR (p_session_binding_hash IS NOT NULL AND p_session_binding_hash !~ '^([0-9a-f]{12}:)?[a-f0-9]{64}$')
     OR p_risk_score NOT BETWEEN 0 AND 100 OR p_risk_level NOT IN ('LOW','MEDIUM','HIGH','CRITICAL')
     OR cardinality(p_reasons)>12 OR p_max_attempts NOT BETWEEN 1 AND 10 OR p_created_at IS NULL
     OR p_expires_at<=p_created_at OR p_expires_at>p_created_at+interval '15 minutes'
     OR abs(extract(epoch FROM (p_created_at-clock_timestamp())))>300 THEN
    RAISE EXCEPTION 'MFA_CHALLENGE_INPUT_DENIED' USING ERRCODE='22023';
  END IF;
  SELECT * INTO actor FROM app_rls.b01_admin_mfa_actor();
  PERFORM set_config('app.auth_closure_operation','mfa-challenge-create',true),
          set_config('app.auth_closure_challenge_id',challenge_id,true),
          set_config('app.auth_closure_challenge_hash',p_ticket_hash,true);
  IF p_kind='LOGIN' THEN
    INSERT INTO public."MfaLoginChallenge"(id,"userId","ticketHash",purpose,"riskScore","riskLevel",reasons,
      "createdIpHash","createdUserAgentHash",attempts,"maxAttempts","createdAt","updatedAt","expiresAt")
    VALUES (challenge_id,actor."userId",p_ticket_hash,p_purpose,p_risk_score,p_risk_level::public."AuthRiskLevel",
      p_reasons,p_ip_hash,p_user_agent_hash,0,p_max_attempts,p_created_at,p_created_at,p_expires_at);
  ELSE
    UPDATE public."AuthMfaChallenge" SET "supersededAt"=p_created_at,"updatedAt"=p_created_at
     WHERE "userId"=actor."userId" AND purpose=p_purpose AND "sessionBindingHash"=p_session_binding_hash
       AND "consumedAt" IS NULL AND "supersededAt" IS NULL AND "expiresAt">p_created_at;
    INSERT INTO public."AuthMfaChallenge"(id,"userId","ticketHash","sessionBindingHash",purpose,"riskScore","riskLevel",reasons,
      "createdIpHash","createdUserAgentHash",attempts,"maxAttempts","createdAt","updatedAt","expiresAt")
    VALUES (challenge_id,actor."userId",p_ticket_hash,p_session_binding_hash,p_purpose,p_risk_score,p_risk_level::public."AuthRiskLevel",
      p_reasons,p_ip_hash,p_user_agent_hash,0,p_max_attempts,p_created_at,p_created_at,p_expires_at);
  END IF;
  INSERT INTO public."AuditLogOutbox"(id,payload,"requestId","organizationId","licenseeId","initiatingUserId","initiatingActorRoleSnapshot","expiresAt","updatedAt")
  VALUES (gen_random_uuid()::text,jsonb_build_object('userId',actor."userId",'action','AUTH_MFA_CHALLENGE_ISSUED',
    'entityType','MfaChallenge','entityId',challenge_id,'details',jsonb_build_object('purpose',p_purpose,
    'riskScore',p_risk_score,'riskLevel',p_risk_level,'sessionBound',p_kind='SESSION',
    'ttlMs',round(extract(epoch FROM (p_expires_at-p_created_at))*1000),
    'ttlMinutes',round(extract(epoch FROM (p_expires_at-p_created_at))/60))),
    current_setting('app.request_id',true),nullif(actor."organizationId",''),nullif(actor."licenseeId",''),
    actor."userId",actor.role,p_created_at+interval '1 day',p_created_at);
  RETURN jsonb_build_object('challengeId',challenge_id);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.load_admin_mfa_challenge(
  p_ticket_hashes text[],p_session_binding_hashes text[],p_checked_at timestamp without time zone
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; result jsonb;
BEGIN
  IF cardinality(p_ticket_hashes) NOT BETWEEN 1 AND 3 OR p_checked_at IS NULL
     OR abs(extract(epoch FROM (p_checked_at-clock_timestamp())))>300 THEN
    RAISE EXCEPTION 'MFA_CHALLENGE_INPUT_DENIED' USING ERRCODE='22023';
  END IF;
  SELECT * INTO actor FROM app_rls.b01_admin_mfa_actor();
  PERFORM pg_advisory_xact_lock(hashtextextended('mfa_state:'||actor."userId",0));
  PERFORM set_config('app.auth_closure_operation','mfa-challenge-read',true);
  SELECT to_jsonb(x) INTO result FROM (
    SELECT 'LOGIN'::text AS kind,c.id,c."userId",c.purpose,c."riskScore",c."riskLevel"::text AS "riskLevel",
      c.reasons,c.attempts,c."maxAttempts",c."createdIpHash",c."createdUserAgentHash",
      c."expiresAt",c."consumedAt",NULL::timestamp without time zone AS "supersededAt"
    FROM public."MfaLoginChallenge" c WHERE c."userId"=actor."userId" AND c."ticketHash"=ANY(p_ticket_hashes)
    UNION ALL
    SELECT 'SESSION',c.id,c."userId",c.purpose,c."riskScore",c."riskLevel"::text,c.reasons,c.attempts,c."maxAttempts",
      c."createdIpHash",c."createdUserAgentHash",c."expiresAt",c."consumedAt",c."supersededAt"
    FROM public."AuthMfaChallenge" c WHERE c."userId"=actor."userId" AND c."ticketHash"=ANY(p_ticket_hashes)
      AND c."sessionBindingHash"=ANY(p_session_binding_hashes)
  ) x LIMIT 1;
  RETURN result;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.record_admin_mfa_challenge_failure(
  p_kind text,p_challenge_id text,p_action text,p_expected_attempts integer,p_failed_at timestamp without time zone,
  p_ip_hash text,p_user_agent text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; changed integer; next_attempts integer:=p_expected_attempts;
BEGIN
  IF p_kind NOT IN ('LOGIN','SESSION') OR p_action NOT IN ('AUTH_MFA_CHALLENGE_EXPIRED','AUTH_MFA_FAILURE','AUTH_MFA_TOO_MANY_ATTEMPTS')
     OR p_expected_attempts NOT BETWEEN 0 AND 10 OR p_failed_at IS NULL
     OR abs(extract(epoch FROM (p_failed_at-clock_timestamp())))>300 THEN
    RAISE EXCEPTION 'MFA_CHALLENGE_INPUT_DENIED' USING ERRCODE='22023';
  END IF;
  SELECT * INTO actor FROM app_rls.b01_admin_mfa_actor();
  PERFORM set_config('app.auth_closure_operation','mfa-challenge-fail',true);
  IF p_kind='LOGIN' THEN
    UPDATE public."MfaLoginChallenge" SET attempts=p_expected_attempts,"updatedAt"=p_failed_at
     WHERE id=p_challenge_id AND "userId"=actor."userId" AND "consumedAt" IS NULL AND attempts<=p_expected_attempts;
  ELSE
    UPDATE public."AuthMfaChallenge" SET attempts=p_expected_attempts,"updatedAt"=p_failed_at
     WHERE id=p_challenge_id AND "userId"=actor."userId" AND "consumedAt" IS NULL AND "supersededAt" IS NULL AND attempts<=p_expected_attempts;
  END IF;
  GET DIAGNOSTICS changed=ROW_COUNT;
  IF changed<>1 THEN RAISE EXCEPTION 'MFA_CHALLENGE_NOT_FOUND' USING ERRCODE='P0002'; END IF;
  INSERT INTO public."AuditLogOutbox"(id,payload,"requestId","organizationId","licenseeId","initiatingUserId","initiatingActorRoleSnapshot","expiresAt","updatedAt")
  VALUES (gen_random_uuid()::text,jsonb_build_object('userId',actor."userId",'action',p_action,'entityType','MfaChallenge',
    'entityId',p_challenge_id,'details',jsonb_build_object('attempts',next_attempts),'ipHash',p_ip_hash,'userAgent',p_user_agent),
    current_setting('app.request_id',true),nullif(actor."organizationId",''),nullif(actor."licenseeId",''),
    actor."userId",actor.role,p_failed_at+interval '1 day',p_failed_at);
  RETURN jsonb_build_object('recorded',true,'attempts',next_attempts);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.complete_admin_mfa_challenge(
  p_kind text,p_challenge_id text,p_method text,p_completed_at timestamp without time zone,p_ip_hash text,p_user_agent text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; challenge record;
BEGIN
  IF p_kind NOT IN ('LOGIN','SESSION') OR p_method NOT IN ('TOTP','BACKUP_CODE') OR p_completed_at IS NULL
     OR abs(extract(epoch FROM (p_completed_at-clock_timestamp())))>300 THEN
    RAISE EXCEPTION 'MFA_CHALLENGE_INPUT_DENIED' USING ERRCODE='22023';
  END IF;
  SELECT * INTO actor FROM app_rls.b01_admin_mfa_actor();
  PERFORM set_config('app.auth_closure_operation','mfa-challenge-complete',true);
  IF p_kind='LOGIN' THEN
    UPDATE public."MfaLoginChallenge" SET "consumedAt"=p_completed_at,"updatedAt"=p_completed_at
     WHERE id=p_challenge_id AND "userId"=actor."userId" AND "consumedAt" IS NULL AND "expiresAt">p_completed_at
    RETURNING "riskScore","riskLevel",reasons INTO challenge;
  ELSE
    UPDATE public."AuthMfaChallenge" SET "consumedAt"=p_completed_at,"updatedAt"=p_completed_at
     WHERE id=p_challenge_id AND "userId"=actor."userId" AND "consumedAt" IS NULL AND "supersededAt" IS NULL AND "expiresAt">p_completed_at
    RETURNING "riskScore","riskLevel",reasons INTO challenge;
  END IF;
  IF NOT FOUND THEN RAISE EXCEPTION 'MFA_CHALLENGE_NOT_FOUND' USING ERRCODE='P0002'; END IF;
  INSERT INTO public."AuditLogOutbox"(id,payload,"requestId","organizationId","licenseeId","initiatingUserId","initiatingActorRoleSnapshot","expiresAt","updatedAt")
  VALUES (gen_random_uuid()::text,jsonb_build_object('userId',actor."userId",'action',
    CASE WHEN p_method='BACKUP_CODE' THEN 'AUTH_MFA_BACKUP_CODE_USED' ELSE 'AUTH_MFA_SUCCESS' END,
    'entityType','MfaChallenge','entityId',p_challenge_id,'details',jsonb_build_object('method',p_method),
    'ipHash',p_ip_hash,'userAgent',p_user_agent),current_setting('app.request_id',true),
    nullif(actor."organizationId",''),nullif(actor."licenseeId",''),actor."userId",actor.role,p_completed_at+interval '1 day',p_completed_at);
  INSERT INTO public."AuditLogOutbox"(id,payload,"requestId","organizationId","licenseeId","initiatingUserId","initiatingActorRoleSnapshot","expiresAt","updatedAt")
  VALUES (gen_random_uuid()::text,jsonb_build_object('userId',actor."userId",'action','AUTH_MFA_LOGIN_COMPLETE',
    'entityType','User','entityId',actor."userId",'details',jsonb_build_object('riskScore',challenge."riskScore",
    'riskLevel',challenge."riskLevel",'reasons',challenge.reasons),'ipHash',p_ip_hash,'userAgent',p_user_agent),
    current_setting('app.request_id',true),nullif(actor."organizationId",''),nullif(actor."licenseeId",''),
    actor."userId",actor.role,p_completed_at+interval '1 day',p_completed_at);
  RETURN jsonb_build_object('completed',true);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.load_admin_webauthn_credentials()
RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; result jsonb;
BEGIN
  SELECT * INTO actor FROM app_rls.b01_admin_mfa_actor();
  PERFORM set_config('app.auth_closure_operation','mfa-webauthn-read',true);
  SELECT jsonb_build_object(
    'factors',coalesce((SELECT jsonb_agg(to_jsonb(x) ORDER BY x."lastUsedAt" DESC NULLS LAST,x."createdAt" DESC) FROM (
      SELECT f.id,f.label,f."credentialId",f."publicKey",f.counter,f.transports,f."lastUsedAt",f."createdAt",f."updatedAt"
      FROM public."UserMfaFactor" f WHERE f."userId"=actor."userId" AND f.type='WEBAUTHN'
        AND f."disabledAt" IS NULL AND f."credentialId" IS NOT NULL AND f."publicKey" IS NOT NULL
    ) x),'[]'::jsonb),
    'legacy',coalesce((SELECT jsonb_agg(to_jsonb(x) ORDER BY x."lastUsedAt" DESC NULLS LAST,x."createdAt" DESC) FROM (
      SELECT c.id,c.label,c."credentialId",c."publicKeySpki",c."publicKeyAlgorithm",c.counter,c.transports,
        c."lastUsedAt",c."createdAt",c."updatedAt"
      FROM public."AdminWebAuthnCredential" c WHERE c."userId"=actor."userId"
    ) x),'[]'::jsonb)
  ) INTO result;
  RETURN result;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.create_admin_webauthn_challenge(
  p_purpose text,p_ticket_hash text,p_challenge_hash text,p_ip_hash text,p_user_agent_hash text,
  p_origin text,p_rp_id text,p_created_at timestamp without time zone,p_expires_at timestamp without time zone
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; challenge_id text:=gen_random_uuid()::text; credential_ids text[];
BEGIN
  IF p_purpose NOT IN ('ENROLLMENT','LOGIN','STEP_UP') OR p_ticket_hash !~ '^([0-9a-f]{12}:)?[a-f0-9]{64}$'
     OR p_challenge_hash !~ '^([0-9a-f]{12}:)?[a-f0-9]{64}$' OR length(coalesce(p_origin,''))>512
     OR length(coalesce(p_rp_id,'')) NOT BETWEEN 1 AND 253 OR p_created_at IS NULL
     OR p_expires_at<=p_created_at OR p_expires_at>p_created_at+interval '15 minutes'
     OR abs(extract(epoch FROM (p_created_at-clock_timestamp())))>300 THEN
    RAISE EXCEPTION 'WEBAUTHN_CHALLENGE_INPUT_DENIED' USING ERRCODE='22023';
  END IF;
  SELECT * INTO actor FROM app_rls.b01_admin_mfa_actor();
  PERFORM set_config('app.auth_closure_operation','mfa-webauthn-challenge-create',true),
          set_config('app.auth_closure_challenge_id',challenge_id,true),
          set_config('app.auth_closure_challenge_hash',p_ticket_hash,true);
  SELECT coalesce(array_agg(id ORDER BY id),'{}'::text[]) INTO credential_ids FROM (
    SELECT f."credentialId" AS id FROM public."UserMfaFactor" f WHERE f."userId"=actor."userId"
      AND f.type='WEBAUTHN' AND f."disabledAt" IS NULL AND f."credentialId" IS NOT NULL AND f."publicKey" IS NOT NULL
    UNION SELECT c."credentialId" FROM public."AdminWebAuthnCredential" c WHERE c."userId"=actor."userId"
  ) q;
  IF p_purpose IN ('LOGIN','STEP_UP') AND cardinality(credential_ids)=0 THEN
    RAISE EXCEPTION 'WEBAUTHN_NOT_ENROLLED' USING ERRCODE='P0002';
  END IF;
  INSERT INTO public."AuthWebAuthnChallenge"(id,"userId",purpose,"ticketHash","challengeHash","credentialIds",
    "createdIpHash","createdUserAgentHash",origin,"rpId","createdAt","expiresAt")
  VALUES (challenge_id,actor."userId",p_purpose,p_ticket_hash,p_challenge_hash,credential_ids,
    p_ip_hash,p_user_agent_hash,p_origin,p_rp_id,p_created_at,p_expires_at);
  RETURN jsonb_build_object('challengeId',challenge_id,'credentialIds',to_jsonb(credential_ids));
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.load_admin_webauthn_challenge(
  p_ticket_hashes text[],p_purpose text,p_credential_id text,p_checked_at timestamp without time zone
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; result jsonb;
BEGIN
  IF cardinality(p_ticket_hashes) NOT BETWEEN 1 AND 3 OR p_purpose NOT IN ('ENROLLMENT','LOGIN','STEP_UP')
     OR p_checked_at IS NULL OR abs(extract(epoch FROM (p_checked_at-clock_timestamp())))>300 THEN
    RAISE EXCEPTION 'WEBAUTHN_CHALLENGE_INPUT_DENIED' USING ERRCODE='22023';
  END IF;
  SELECT * INTO actor FROM app_rls.b01_admin_mfa_actor();
  PERFORM pg_advisory_xact_lock(hashtextextended('mfa_state:'||actor."userId",0));
  PERFORM set_config('app.auth_closure_operation','mfa-webauthn-challenge-read',true);
  SELECT jsonb_build_object(
    'challenge',jsonb_build_object(
      'id',c.id,'userId',c."userId",'challengeHash',c."challengeHash",
      'origin',c.origin,'rpId',c."rpId"
    ),
    'factor',(SELECT to_jsonb(x) FROM (
      SELECT f.id,f."credentialId",f."publicKey",f.counter,f.transports
      FROM public."UserMfaFactor" f WHERE f."userId"=actor."userId" AND f.type='WEBAUTHN'
        AND f."disabledAt" IS NULL AND f."credentialId"=p_credential_id
    ) x),
    'legacy',(SELECT to_jsonb(x) FROM (
      SELECT w.id,w."credentialId",w."publicKeySpki",w."publicKeyAlgorithm",w.counter,w.transports
      FROM public."AdminWebAuthnCredential" w WHERE w."userId"=actor."userId" AND w."credentialId"=p_credential_id
    ) x)
  ) INTO result
  FROM public."AuthWebAuthnChallenge" c WHERE c."userId"=actor."userId" AND c."ticketHash"=ANY(p_ticket_hashes)
    AND c.purpose=p_purpose AND c."consumedAt" IS NULL AND c."expiresAt">p_checked_at;
  RETURN result;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.complete_admin_webauthn_registration(
  p_challenge_id text,p_credential_id text,p_label text,p_public_key text,p_counter integer,p_transports text[],
  p_device_type text,p_backed_up boolean,p_completed_at timestamp without time zone
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; factor_id text;
BEGIN
  IF p_credential_id IS NULL OR length(p_credential_id)>1024 OR p_public_key IS NULL OR length(p_public_key)>16384
     OR length(coalesce(p_label,''))>128 OR p_counter<0 OR cardinality(p_transports)>16 OR p_completed_at IS NULL
     OR abs(extract(epoch FROM (p_completed_at-clock_timestamp())))>300 THEN
    RAISE EXCEPTION 'WEBAUTHN_REGISTRATION_INPUT_DENIED' USING ERRCODE='22023';
  END IF;
  SELECT * INTO actor FROM app_rls.b01_admin_mfa_actor();
  PERFORM pg_advisory_xact_lock(hashtextextended('mfa_state:'||actor."userId",0));
  PERFORM set_config('app.auth_closure_operation','mfa-webauthn-registration-complete',true);
  IF NOT EXISTS (SELECT 1 FROM public."AuthWebAuthnChallenge" c WHERE c.id=p_challenge_id AND c."userId"=actor."userId"
    AND c.purpose='ENROLLMENT' AND c."consumedAt" IS NULL AND c."expiresAt">p_completed_at) THEN
    RAISE EXCEPTION 'WEBAUTHN_CHALLENGE_NOT_FOUND' USING ERRCODE='P0002';
  END IF;
  IF EXISTS (SELECT 1 FROM public."UserMfaFactor" f WHERE f."credentialId"=p_credential_id AND f."userId"<>actor."userId")
     OR EXISTS (SELECT 1 FROM public."AdminWebAuthnCredential" w WHERE w."credentialId"=p_credential_id AND w."userId"<>actor."userId") THEN
    RAISE EXCEPTION 'WEBAUTHN_CREDENTIAL_CONFLICT' USING ERRCODE='23505';
  END IF;
  SELECT f.id INTO factor_id FROM public."UserMfaFactor" f WHERE f."credentialId"=p_credential_id FOR UPDATE;
  IF factor_id IS NULL THEN
    factor_id:=gen_random_uuid()::text;
    INSERT INTO public."UserMfaFactor"(id,"userId",type,label,"credentialId","publicKey",counter,transports,
      "credentialDeviceType","credentialBackedUp","lastUsedAt","createdAt","updatedAt")
    VALUES (factor_id,actor."userId",'WEBAUTHN',coalesce(nullif(trim(p_label),''),'Passkey'),p_credential_id,p_public_key,
      p_counter,p_transports,p_device_type,p_backed_up,p_completed_at,p_completed_at,p_completed_at);
  ELSE
    UPDATE public."UserMfaFactor" SET "userId"=actor."userId",type='WEBAUTHN',label=coalesce(nullif(trim(p_label),''),'Passkey'),
      "publicKey"=p_public_key,counter=p_counter,transports=p_transports,"credentialDeviceType"=p_device_type,
      "credentialBackedUp"=p_backed_up,"lastUsedAt"=p_completed_at,"disabledAt"=NULL,"updatedAt"=p_completed_at
      WHERE id=factor_id AND "userId"=actor."userId";
  END IF;
  UPDATE public."AuthWebAuthnChallenge" SET "consumedAt"=p_completed_at
   WHERE id=p_challenge_id AND "userId"=actor."userId" AND "consumedAt" IS NULL AND "expiresAt">p_completed_at;
  IF NOT FOUND THEN RAISE EXCEPTION 'WEBAUTHN_CHALLENGE_NOT_FOUND' USING ERRCODE='P0002'; END IF;
  INSERT INTO public."AuditLogOutbox"(id,payload,"requestId","organizationId","licenseeId","initiatingUserId","initiatingActorRoleSnapshot","expiresAt","updatedAt")
  VALUES (gen_random_uuid()::text,jsonb_build_object('userId',actor."userId",'action','AUTH_WEBAUTHN_ENROLLED',
    'entityType','User','entityId',actor."userId",'details',jsonb_build_object('label',coalesce(nullif(trim(p_label),''),'Passkey'))),
    current_setting('app.request_id',true),nullif(actor."organizationId",''),nullif(actor."licenseeId",''),
    actor."userId",actor.role,p_completed_at+interval '1 day',p_completed_at);
  RETURN jsonb_build_object('ok',true,'credentialId',p_credential_id);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.complete_admin_webauthn_authentication(
  p_challenge_id text,p_credential_kind text,p_credential_row_id text,p_expected_counter integer,p_next_counter integer,
  p_device_type text,p_backed_up boolean,p_completed_at timestamp without time zone
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; changed integer; purpose text;
BEGIN
  IF p_credential_kind NOT IN ('FACTOR','LEGACY') OR p_expected_counter<0 OR p_next_counter<0
     OR (p_next_counter>0 AND p_expected_counter>0 AND p_next_counter<=p_expected_counter)
     OR p_completed_at IS NULL OR abs(extract(epoch FROM (p_completed_at-clock_timestamp())))>300 THEN
    RAISE EXCEPTION 'WEBAUTHN_AUTHENTICATION_INPUT_DENIED' USING ERRCODE='22023';
  END IF;
  SELECT * INTO actor FROM app_rls.b01_admin_mfa_actor();
  PERFORM pg_advisory_xact_lock(hashtextextended('mfa_state:'||actor."userId",0));
  PERFORM set_config('app.auth_closure_operation','mfa-webauthn-authentication-complete',true);
  SELECT c.purpose INTO purpose FROM public."AuthWebAuthnChallenge" c WHERE c.id=p_challenge_id AND c."userId"=actor."userId"
    AND c.purpose IN ('LOGIN','STEP_UP') AND c."consumedAt" IS NULL AND c."expiresAt">p_completed_at FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'WEBAUTHN_CHALLENGE_NOT_FOUND' USING ERRCODE='P0002'; END IF;
  IF p_credential_kind='FACTOR' THEN
    UPDATE public."UserMfaFactor" SET counter=greatest(counter,p_next_counter),"credentialDeviceType"=p_device_type,
      "credentialBackedUp"=p_backed_up,"lastUsedAt"=p_completed_at,"updatedAt"=p_completed_at
      WHERE id=p_credential_row_id AND "userId"=actor."userId" AND type='WEBAUTHN' AND "disabledAt" IS NULL
        AND counter=p_expected_counter;
  ELSE
    UPDATE public."AdminWebAuthnCredential" SET counter=greatest(counter,p_next_counter),"lastUsedAt"=p_completed_at,"updatedAt"=p_completed_at
      WHERE id=p_credential_row_id AND "userId"=actor."userId" AND counter=p_expected_counter;
  END IF;
  GET DIAGNOSTICS changed=ROW_COUNT;
  IF changed<>1 THEN RAISE EXCEPTION 'WEBAUTHN_COUNTER_REPLAY' USING ERRCODE='40001'; END IF;
  UPDATE public."AuthWebAuthnChallenge" SET "consumedAt"=p_completed_at
    WHERE id=p_challenge_id AND "userId"=actor."userId" AND "consumedAt" IS NULL AND "expiresAt">p_completed_at;
  IF NOT FOUND THEN RAISE EXCEPTION 'WEBAUTHN_CHALLENGE_NOT_FOUND' USING ERRCODE='P0002'; END IF;
  RETURN jsonb_build_object('ok',true,'purpose',purpose);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.delete_admin_webauthn_credential(
  p_credential_row_id text,p_deleted_at timestamp without time zone
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; changed integer:=0; delta integer;
BEGIN
  IF p_credential_row_id IS NULL OR p_deleted_at IS NULL
     OR abs(extract(epoch FROM (p_deleted_at-clock_timestamp())))>300 THEN
    RAISE EXCEPTION 'WEBAUTHN_DELETE_INPUT_DENIED' USING ERRCODE='22023';
  END IF;
  SELECT * INTO actor FROM app_rls.b01_admin_mfa_actor();
  PERFORM pg_advisory_xact_lock(hashtextextended('mfa_state:'||actor."userId",0));
  PERFORM set_config('app.auth_closure_operation','mfa-webauthn-delete',true);
  UPDATE public."UserMfaFactor" SET "disabledAt"=p_deleted_at,"updatedAt"=p_deleted_at
    WHERE id=p_credential_row_id AND "userId"=actor."userId" AND type='WEBAUTHN' AND "disabledAt" IS NULL;
  GET DIAGNOSTICS changed=ROW_COUNT;
  DELETE FROM public."AdminWebAuthnCredential" WHERE id=p_credential_row_id AND "userId"=actor."userId";
  GET DIAGNOSTICS delta=ROW_COUNT;
  IF changed+delta>0 THEN
    INSERT INTO public."AuditLogOutbox"(id,payload,"requestId","organizationId","licenseeId","initiatingUserId","initiatingActorRoleSnapshot","expiresAt","updatedAt")
    VALUES (gen_random_uuid()::text,jsonb_build_object('userId',actor."userId",'action','AUTH_WEBAUTHN_CREDENTIAL_REMOVED',
      'entityType','User','entityId',actor."userId",'details',jsonb_build_object('credentialId',p_credential_row_id)),
      current_setting('app.request_id',true),nullif(actor."organizationId",''),nullif(actor."licenseeId",''),
      actor."userId",actor.role,p_deleted_at+interval '1 day',p_deleted_at);
  END IF;
  RETURN jsonb_build_object('deleted',changed+delta>0);
END
$fn$;

REVOKE ALL ON FUNCTION app_rls.b01_authenticated_actor(text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.revalidate_authenticated_actor(text,text,text,text,timestamp without time zone,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.load_authenticated_actor() FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.load_authenticated_manufacturer_scope(text,text,text,text,boolean) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.find_refresh_token_by_id(text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.revoke_refresh_token_by_id(text,text,text,timestamp without time zone) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.require_recent_mfa_session(text,timestamp without time zone,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.load_recent_auth_session_risk_inputs(integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.record_auth_session_risk_signal(integer,text,text[],text,text,timestamp without time zone,text,text,text,timestamp without time zone,integer,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.create_refresh_token(text,text,text,timestamp without time zone,text,text,timestamp without time zone,timestamp without time zone,timestamp without time zone) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.load_authenticated_password_actor() FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.list_active_refresh_tokens(text,timestamp without time zone) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.revoke_all_refresh_tokens(text,text,timestamp without time zone) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.prove_authenticated_password_step_up(text,text,timestamp without time zone) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.require_recent_sensitive_session(text,timestamp without time zone,integer,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.request_authenticated_email_change(text,text,text,timestamp without time zone,timestamp without time zone,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.update_authenticated_profile(text,boolean,text,timestamp without time zone) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.change_authenticated_password(text,text,timestamp without time zone) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.b01_admin_mfa_actor() FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.load_admin_mfa_state() FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.begin_admin_totp_enrollment(text,text,text,text,text[],timestamp without time zone,timestamp without time zone) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.load_admin_totp_enrollment(text,timestamp without time zone) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.complete_admin_totp_enrollment(text,text,text,text,text,timestamp without time zone,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.load_admin_mfa_verifiers() FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.consume_admin_mfa_verifier(text,text,text[],text[],timestamp without time zone) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.replace_admin_backup_codes(text[],timestamp without time zone) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.disable_admin_mfa(timestamp without time zone,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.create_admin_mfa_challenge(text,text,text,text,integer,text,text[],text,text,integer,timestamp without time zone,timestamp without time zone) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.load_admin_mfa_challenge(text[],text[],timestamp without time zone) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.record_admin_mfa_challenge_failure(text,text,text,integer,timestamp without time zone,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.complete_admin_mfa_challenge(text,text,text,timestamp without time zone,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.load_admin_webauthn_credentials() FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.create_admin_webauthn_challenge(text,text,text,text,text,text,text,timestamp without time zone,timestamp without time zone) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.load_admin_webauthn_challenge(text[],text,text,timestamp without time zone) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.complete_admin_webauthn_registration(text,text,text,text,integer,text[],text,boolean,timestamp without time zone) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.complete_admin_webauthn_authentication(text,text,text,integer,integer,text,boolean,timestamp without time zone) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.delete_admin_webauthn_credential(text,timestamp without time zone) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION app_rls.create_refresh_token(text,text,text,timestamp without time zone,text,text,timestamp without time zone,timestamp without time zone,timestamp without time zone) TO "mscqr_rls_cert_preauth";
GRANT EXECUTE ON FUNCTION app_rls.load_recent_auth_session_risk_inputs(integer) TO "mscqr_rls_cert_preauth";
GRANT EXECUTE ON FUNCTION app_rls.record_auth_session_risk_signal(integer,text,text[],text,text,timestamp without time zone,text,text,text,timestamp without time zone,integer,text) TO "mscqr_rls_cert_preauth";
GRANT EXECUTE ON FUNCTION app_rls.begin_admin_totp_enrollment(text,text,text,text,text[],timestamp without time zone,timestamp without time zone) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.change_authenticated_password(text,text,timestamp without time zone) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.complete_admin_mfa_challenge(text,text,text,timestamp without time zone,text,text) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.complete_admin_totp_enrollment(text,text,text,text,text,timestamp without time zone,text,text) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.complete_admin_webauthn_authentication(text,text,text,integer,integer,text,boolean,timestamp without time zone) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.complete_admin_webauthn_registration(text,text,text,text,integer,text[],text,boolean,timestamp without time zone) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.consume_admin_mfa_verifier(text,text,text[],text[],timestamp without time zone) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.create_admin_mfa_challenge(text,text,text,text,integer,text,text[],text,text,integer,timestamp without time zone,timestamp without time zone) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.create_admin_webauthn_challenge(text,text,text,text,text,text,text,timestamp without time zone,timestamp without time zone) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.delete_admin_webauthn_credential(text,timestamp without time zone) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.disable_admin_mfa(timestamp without time zone,text,text) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.find_refresh_token_by_id(text,text) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.list_active_refresh_tokens(text,timestamp without time zone) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.load_admin_mfa_challenge(text[],text[],timestamp without time zone) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.load_admin_mfa_state() TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.load_admin_mfa_verifiers() TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.load_admin_totp_enrollment(text,timestamp without time zone) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.load_admin_webauthn_challenge(text[],text,text,timestamp without time zone) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.load_admin_webauthn_credentials() TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.load_authenticated_actor() TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.load_authenticated_manufacturer_scope(text,text,text,text,boolean) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.load_authenticated_password_actor() TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.prove_authenticated_password_step_up(text,text,timestamp without time zone) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.record_admin_mfa_challenge_failure(text,text,text,integer,timestamp without time zone,text,text) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.replace_admin_backup_codes(text[],timestamp without time zone) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.request_authenticated_email_change(text,text,text,timestamp without time zone,timestamp without time zone,text,text) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.require_recent_mfa_session(text,timestamp without time zone,integer) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.require_recent_sensitive_session(text,timestamp without time zone,integer,integer) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.revalidate_authenticated_actor(text,text,text,text,timestamp without time zone,text) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.revoke_all_refresh_tokens(text,text,timestamp without time zone) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.revoke_refresh_token_by_id(text,text,text,timestamp without time zone) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.update_authenticated_profile(text,boolean,text,timestamp without time zone) TO "mscqr_rls_cert_app";
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
CREATE OR REPLACE FUNCTION app_rls.c03_revalidate_actor_scope(
  target_licensee_id text,
  allowed_roles_json jsonb,
  minimum_assurance text,
  purpose_code text
)
RETURNS TABLE(user_id text, role text, organization_id text, licensee_id text)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  actor record;
  target_org_id text;
  installed_licensee_id text := NULLIF(current_setting('app.licensee_id', true), '');
  installed_org_id text := NULLIF(current_setting('app.organization_id', true), '');
  installed_manufacturer_id text := NULLIF(current_setting('app.manufacturer_id', true), '');
  installed_assurance text := current_setting('app.auth_assurance', true);
BEGIN
  IF current_setting('app.user_id', true) !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
     OR current_setting('app.request_id', true) !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
     OR target_licensee_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
     OR current_setting('app.purpose', true) IS DISTINCT FROM purpose_code
     OR jsonb_typeof(allowed_roles_json) IS DISTINCT FROM 'array'
     OR NOT (allowed_roles_json ? current_setting('app.role', true))
     OR minimum_assurance NOT IN ('password-verified', 'mfa-verified', 'step-up-verified')
     OR (CASE minimum_assurance
          WHEN 'password-verified' THEN installed_assurance NOT IN ('password-verified','mfa-verified','step-up-verified')
          WHEN 'mfa-verified' THEN installed_assurance NOT IN ('mfa-verified','step-up-verified')
          ELSE installed_assurance <> 'step-up-verified'
        END) THEN
    RETURN;
  END IF;

  SELECT u.id, u.role::text AS role, u."orgId", u."licenseeId"
    INTO actor
    FROM public."User" u
   WHERE u.id = current_setting('app.user_id', true)
     AND u.role::text = current_setting('app.role', true)
     AND u."isActive"
     AND u.status = 'ACTIVE'::public."UserStatus"
     AND u."deletedAt" IS NULL
     AND u."disabledAt" IS NULL;
  IF NOT FOUND THEN RETURN; END IF;

  SELECT l."orgId" INTO target_org_id
    FROM public."Licensee" l
    JOIN public."Organization" o ON o.id = l."orgId"
   WHERE l.id = target_licensee_id
     AND l."isActive"
     AND l."suspendedAt" IS NULL
     AND o."isActive";
  IF NOT FOUND THEN RETURN; END IF;

  IF actor.role IN ('SUPER_ADMIN', 'PLATFORM_SUPER_ADMIN') THEN
    IF actor."orgId" IS NOT NULL OR actor."licenseeId" IS NOT NULL OR installed_org_id IS NOT NULL OR installed_manufacturer_id IS NOT NULL THEN
      RETURN;
    END IF;
  ELSIF actor.role = 'MANUFACTURER_ADMIN' THEN
    IF installed_licensee_id IS DISTINCT FROM target_licensee_id
       OR installed_manufacturer_id IS DISTINCT FROM actor.id
       OR NOT EXISTS (
         SELECT 1 FROM public."ManufacturerLicenseeLink" ml
          WHERE ml."manufacturerId" = actor.id AND ml."licenseeId" = target_licensee_id
       ) THEN
      RETURN;
    END IF;
  ELSIF actor.role <> 'LICENSEE_ADMIN'
        OR actor."licenseeId" IS DISTINCT FROM target_licensee_id
        OR actor."orgId" IS DISTINCT FROM target_org_id
        OR installed_licensee_id IS DISTINCT FROM target_licensee_id
        OR installed_org_id IS DISTINCT FROM target_org_id
        OR installed_manufacturer_id IS NOT NULL THEN
    RETURN;
  END IF;

  RETURN QUERY SELECT actor.id::text, actor.role::text, target_org_id, target_licensee_id;
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_revalidate_platform_actor_scope(
  allowed_roles_json jsonb,
  minimum_assurance text,
  purpose_code text
)
RETURNS TABLE(user_id text, role text)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
  SELECT actor.id::text, actor.role::text
    FROM public."User" actor
   WHERE actor.id = current_setting('app.user_id', true)
     AND actor.role::text = current_setting('app.role', true)
     AND actor.role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')
     AND actor."orgId" IS NULL AND actor."licenseeId" IS NULL
     AND actor."isActive" AND actor.status = 'ACTIVE'::public."UserStatus"
     AND actor."deletedAt" IS NULL AND actor."disabledAt" IS NULL
     AND NULLIF(current_setting('app.organization_id', true), '') IS NULL
     AND NULLIF(current_setting('app.licensee_id', true), '') IS NULL
     AND NULLIF(current_setting('app.manufacturer_id', true), '') IS NULL
     AND current_setting('app.request_id', true) ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
     AND current_setting('app.purpose', true) = purpose_code
     AND jsonb_typeof(allowed_roles_json) = 'array'
     AND allowed_roles_json ? actor.role::text
     AND CASE minimum_assurance
           WHEN 'password-verified' THEN current_setting('app.auth_assurance', true) IN ('password-verified','mfa-verified','step-up-verified')
           WHEN 'mfa-verified' THEN current_setting('app.auth_assurance', true) IN ('mfa-verified','step-up-verified')
           WHEN 'step-up-verified' THEN current_setting('app.auth_assurance', true) = 'step-up-verified'
           ELSE false
         END
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_revalidate_incident_actor_scope(
  incident_id text, allowed_roles_json jsonb, minimum_assurance text, purpose_code text
)
RETURNS TABLE(user_id text, role text, organization_id text, licensee_id text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
  SELECT actor.* FROM public."Incident" resource
  CROSS JOIN LATERAL app_rls.c03_revalidate_actor_scope(resource."licenseeId", allowed_roles_json, minimum_assurance, purpose_code) actor
  WHERE resource.id = incident_id AND resource."licenseeId" IS NOT NULL
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_revalidate_policy_rule_actor_scope(
  policy_rule_id text, allowed_roles_json jsonb, minimum_assurance text, purpose_code text
)
RETURNS TABLE(user_id text, role text, organization_id text, licensee_id text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
  SELECT actor.* FROM public."PolicyRule" resource
  CROSS JOIN LATERAL app_rls.c03_revalidate_actor_scope(resource."licenseeId", allowed_roles_json, minimum_assurance, purpose_code) actor
  WHERE resource.id = policy_rule_id AND resource."licenseeId" IS NOT NULL
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_revalidate_compliance_pack_job_actor_scope(
  compliance_pack_job_id text, allowed_roles_json jsonb, minimum_assurance text, purpose_code text
)
RETURNS TABLE(user_id text, role text, organization_id text, licensee_id text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
  SELECT actor.* FROM public."CompliancePackJob" resource
  CROSS JOIN LATERAL app_rls.c03_revalidate_actor_scope(resource."licenseeId", allowed_roles_json, minimum_assurance, purpose_code) actor
  WHERE resource.id = compliance_pack_job_id AND resource."licenseeId" IS NOT NULL
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_revalidate_incident_evidence_actor_scope(
  incident_evidence_id text, allowed_roles_json jsonb, minimum_assurance text, purpose_code text
)
RETURNS TABLE(user_id text, role text, organization_id text, licensee_id text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
  SELECT actor.* FROM public."IncidentEvidence" evidence
  JOIN public."Incident" resource ON resource.id = evidence."incidentId"
  CROSS JOIN LATERAL app_rls.c03_revalidate_actor_scope(resource."licenseeId", allowed_roles_json, minimum_assurance, purpose_code) actor
  WHERE evidence.id = incident_evidence_id AND resource."licenseeId" IS NOT NULL
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_revalidate_incident_evidence_storage_actor_scope(
  storage_key text, allowed_roles_json jsonb, minimum_assurance text, purpose_code text
)
RETURNS TABLE(user_id text, role text, organization_id text, licensee_id text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
  SELECT actor.* FROM public."IncidentEvidence" evidence
  JOIN public."Incident" resource ON resource.id = evidence."incidentId"
  CROSS JOIN LATERAL app_rls.c03_revalidate_actor_scope(resource."licenseeId", allowed_roles_json, minimum_assurance, purpose_code) actor
  WHERE evidence."storageKey" = storage_key AND resource."licenseeId" IS NOT NULL
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_revalidate_sensitive_approval_actor_scope(
  approval_id text, allowed_roles_json jsonb, minimum_assurance text, purpose_code text
)
RETURNS TABLE(user_id text, role text, organization_id text, licensee_id text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
  SELECT actor.* FROM public."SensitiveActionApproval" resource
  CROSS JOIN LATERAL app_rls.c03_revalidate_actor_scope(resource."licenseeId", allowed_roles_json, minimum_assurance, purpose_code) actor
  WHERE resource.id = approval_id AND resource."licenseeId" IS NOT NULL
$$;

REVOKE ALL ON FUNCTION app_rls.c03_revalidate_actor_scope(text,jsonb,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_revalidate_platform_actor_scope(jsonb,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_revalidate_incident_actor_scope(text,jsonb,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_revalidate_policy_rule_actor_scope(text,jsonb,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_revalidate_compliance_pack_job_actor_scope(text,jsonb,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_revalidate_incident_evidence_actor_scope(text,jsonb,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_revalidate_incident_evidence_storage_actor_scope(text,jsonb,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_revalidate_sensitive_approval_actor_scope(text,jsonb,text,text) FROM PUBLIC;

CREATE OR REPLACE FUNCTION app_rls.c02_audit_trace_session_valid()
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF session_user <> 'mscqr_rls_cert_app'
     OR current_setting('app.auth_session_verified', true) <> '1'
  THEN RETURN false; END IF;

  RETURN EXISTS (
    SELECT 1 FROM public."RefreshToken" session_row
     WHERE session_row.id = current_setting('app.auth_session_id', true)
       AND session_row."userId" = current_setting('app.user_id', true)
       AND session_row."sessionCapabilityHash" = current_setting('app.auth_session_hash', true)
       AND session_row."sessionCapabilityHashVersion" = 'sha256-v1'
       AND session_row."sessionCapabilityRevokedAt" IS NULL
       AND session_row."sessionCapabilityExpiresAt" > clock_timestamp()
       AND session_row."revokedAt" IS NULL
       AND session_row."expiresAt" > clock_timestamp()
  );
END;
$$;

REVOKE ALL ON FUNCTION app_rls.c02_audit_trace_session_valid() FROM PUBLIC;

CREATE OR REPLACE FUNCTION app_rls.c02_audit_trace_actor_valid(target_licensee_id text)
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  actor record;
  target_org_id text;
  actor_id text := current_setting('app.user_id', true);
  actor_role text := current_setting('app.role', true);
  actor_org_id text := NULLIF(current_setting('app.organization_id', true), '');
  actor_licensee_id text := NULLIF(current_setting('app.licensee_id', true), '');
  actor_manufacturer_id text := NULLIF(current_setting('app.manufacturer_id', true), '');
  assurance text := current_setting('app.auth_assurance', true);
  purpose_code text := current_setting('app.purpose', true);
BEGIN
  IF actor_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
     OR current_setting('app.request_id', true) !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
     OR target_licensee_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
     OR actor_licensee_id IS DISTINCT FROM target_licensee_id
     OR purpose_code NOT IN (
       'platform-audit-log-read', 'audit-log-read',
       'platform-audit-csv-export', 'tenant-audit-csv-export', 'manufacturer-audit-csv-export',
       'platform-fraud-report-read',
       'platform-trace-timeline-read', 'tenant-trace-timeline-read', 'manufacturer-trace-timeline-read'
     ) THEN
    RETURN false;
  END IF;

  SELECT u.id, u.role::text AS role, u."orgId", u."licenseeId"
    INTO actor
    FROM public."User" u
   WHERE u.id = actor_id
     AND u.role::text = actor_role
     AND u."isActive"
     AND u.status = 'ACTIVE'::public."UserStatus"
     AND u."deletedAt" IS NULL
     AND u."disabledAt" IS NULL;
  IF NOT FOUND THEN RETURN false; END IF;

  SELECT l."orgId" INTO target_org_id
    FROM public."Licensee" l
    JOIN public."Organization" o ON o.id = l."orgId"
   WHERE l.id = target_licensee_id
     AND l."isActive"
     AND l."suspendedAt" IS NULL
     AND o."isActive";
  IF NOT FOUND THEN RETURN false; END IF;

  IF actor_role IN ('SUPER_ADMIN', 'PLATFORM_SUPER_ADMIN') THEN
    RETURN assurance = 'mfa-verified'
       AND actor."orgId" IS NULL
       AND actor."licenseeId" IS NULL
       AND actor_org_id IS NULL
       AND actor_manufacturer_id IS NULL;
  END IF;

  IF actor_role = 'LICENSEE_ADMIN' THEN
    RETURN assurance IN ('password-verified', 'mfa-verified', 'step-up-verified')
       AND actor."licenseeId" = target_licensee_id
       AND actor."orgId" = target_org_id
       AND actor_org_id = target_org_id
       AND actor_manufacturer_id IS NULL
       AND (purpose_code <> 'audit-log-read' OR assurance IN ('mfa-verified', 'step-up-verified'));
  END IF;

  IF actor_role = 'MANUFACTURER_ADMIN' THEN
    RETURN assurance IN ('password-verified', 'mfa-verified', 'step-up-verified')
       AND actor_manufacturer_id = actor_id
       AND EXISTS (
         SELECT 1
           FROM public."ManufacturerLicenseeLink" ml
          WHERE ml."manufacturerId" = actor_id
            AND ml."licenseeId" = target_licensee_id
       );
  END IF;

  RETURN false;
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.platform_audit_log_details(audit_ids text[])
RETURNS TABLE(id text, ip_address text, user_agent text, user_id text, user_name text)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  target_licensee_id text := NULLIF(current_setting('app.licensee_id', true), '');
BEGIN
  IF current_setting('app.role', true) NOT IN ('SUPER_ADMIN', 'PLATFORM_SUPER_ADMIN')
     OR current_setting('app.purpose', true) <> 'platform-audit-log-read'
     OR NOT app_rls.c02_audit_trace_actor_valid(target_licensee_id)
     OR COALESCE(cardinality(audit_ids), 0) > 500
     OR EXISTS (
       SELECT 1 FROM unnest(COALESCE(audit_ids, ARRAY[]::text[])) requested(id)
       LEFT JOIN public."AuditLog" a ON a.id = requested.id AND a."licenseeId" = target_licensee_id
       WHERE a.id IS NULL
     ) THEN
    RAISE EXCEPTION 'SESSION_C_AUDIT_DETAIL_SCOPE_DENIED';
  END IF;

  RETURN QUERY
  SELECT a.id, a."ipAddress", a."userAgent", a."userId", u.name
    FROM public."AuditLog" a
    LEFT JOIN public."User" u ON u.id = a."userId"
   WHERE a.id = ANY(COALESCE(audit_ids, ARRAY[]::text[]))
     AND a."licenseeId" = target_licensee_id;
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c02_fraud_report_network_details(report_ids text[])
RETURNS TABLE(id text, ip_address text)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  target_licensee_id text := NULLIF(current_setting('app.licensee_id', true), '');
BEGIN
  IF current_setting('app.role', true) NOT IN ('SUPER_ADMIN', 'PLATFORM_SUPER_ADMIN')
     OR current_setting('app.purpose', true) <> 'platform-fraud-report-read'
     OR NOT app_rls.c02_audit_trace_actor_valid(target_licensee_id)
     OR COALESCE(cardinality(report_ids), 0) > 500
     OR EXISTS (
       SELECT 1 FROM unnest(COALESCE(report_ids, ARRAY[]::text[])) requested(id)
       LEFT JOIN public."AuditLog" a
         ON a.id = requested.id
        AND a."licenseeId" = target_licensee_id
        AND a.action = 'CUSTOMER_FRAUD_REPORT'
       WHERE a.id IS NULL
     ) THEN
    RAISE EXCEPTION 'SESSION_C_FRAUD_DETAIL_SCOPE_DENIED';
  END IF;

  RETURN QUERY
  SELECT a.id, a."ipAddress"
    FROM public."AuditLog" a
   WHERE a.id = ANY(COALESCE(report_ids, ARRAY[]::text[]))
     AND a."licenseeId" = target_licensee_id
     AND a.action = 'CUSTOMER_FRAUD_REPORT';
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c02_respond_fraud_report(
  report_id text,
  response_status text,
  requested_message text,
  notify_customer boolean
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  actor record;
  report record;
  target_org_id text;
  response_id text := gen_random_uuid()::text;
  normalized_code text;
  recipient_email text;
  response_message text;
  delivery jsonb;
  response_details jsonb;
BEGIN
  IF current_setting('app.purpose', true) <> 'platform-fraud-report-response'
     OR current_setting('app.auth_assurance', true) <> 'mfa-verified'
     OR current_setting('app.request_id', true) !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
     OR report_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
     OR response_status NOT IN ('REVIEWED', 'RESOLVED', 'DISMISSED') THEN
    RAISE EXCEPTION 'SESSION_C_INVALID_CONTEXT';
  END IF;

  SELECT u.id, u.role::text AS role
    INTO actor
    FROM public."User" u
   WHERE u.id = current_setting('app.user_id', true)
     AND u.role::text = current_setting('app.role', true)
     AND u.role IN ('SUPER_ADMIN', 'PLATFORM_SUPER_ADMIN')
     AND u."orgId" IS NULL
     AND u."licenseeId" IS NULL
     AND u."isActive"
     AND u.status = 'ACTIVE'::public."UserStatus"
     AND u."deletedAt" IS NULL
     AND u."disabledAt" IS NULL
   FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'SESSION_C_DISABLED_OR_STALE_ACTOR'; END IF;

  PERFORM pg_advisory_xact_lock(hashtextextended(report_id, 0));
  SELECT a.id, a."licenseeId", a."entityId", a.details
    INTO report
    FROM public."AuditLog" a
   WHERE a.id = report_id
     AND a.action = 'CUSTOMER_FRAUD_REPORT'
     AND a."licenseeId" IS NOT NULL
   FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'SESSION_C_FRAUD_REPORT_NOT_FOUND'; END IF;

  SELECT l."orgId" INTO target_org_id
    FROM public."Licensee" l
    JOIN public."Organization" o ON o.id = l."orgId"
   WHERE l.id = report."licenseeId"
     AND l."isActive"
     AND l."suspendedAt" IS NULL
     AND o."isActive";
  IF NOT FOUND THEN RAISE EXCEPTION 'SESSION_C_FRAUD_REPORT_NOT_FOUND'; END IF;

  normalized_code := COALESCE(NULLIF(report.details->>'code', ''), NULLIF(report."entityId", ''), 'UNKNOWN');
  recipient_email := NULLIF(btrim(report.details->>'contactEmail'), '');
  response_message := NULLIF(btrim(requested_message), '');
  IF response_message IS NULL THEN
    response_message := CASE response_status
      WHEN 'RESOLVED' THEN 'Thanks for reporting code ' || normalized_code || '. Our security team reviewed it and completed corrective action.'
      WHEN 'DISMISSED' THEN 'Thanks for reporting code ' || normalized_code || '. We reviewed the case and found no actionable fraud signal from current evidence.'
      ELSE 'Thanks for reporting code ' || normalized_code || '. Our security team has started investigating your report.'
    END;
  END IF;
  response_message := left(response_message, 1000);
  delivery := jsonb_build_object(
    'attempted', notify_customer,
    'delivered', notify_customer AND recipient_email IS NOT NULL,
    'transport', CASE WHEN notify_customer THEN 'simulated' ELSE 'none' END,
    'recipientEmail', CASE WHEN notify_customer THEN recipient_email ELSE NULL END,
    'reason', CASE WHEN notify_customer AND recipient_email IS NULL THEN 'Customer did not provide a contact email in the report.' ELSE NULL END,
    'deliveredAt', CASE WHEN notify_customer AND recipient_email IS NOT NULL THEN transaction_timestamp() ELSE NULL END
  );
  response_details := jsonb_build_object(
    'reportId', report.id,
    'status', response_status,
    'message', response_message,
    'notifyCustomer', notify_customer,
    'recipientEmail', recipient_email,
    'delivery', delivery,
    'sourceCode', normalized_code,
    'respondedAt', transaction_timestamp(),
    'requestId', current_setting('app.request_id', true),
    'purposeCode', current_setting('app.purpose', true)
  );

  INSERT INTO public."AuditLog"
    (id, "userId", "orgId", "licenseeId", action, "entityType", "entityId", details)
  VALUES
    (response_id, actor.id, target_org_id, report."licenseeId", 'CUSTOMER_FRAUD_REPORT_RESPONSE', 'FraudReport', report.id, response_details);
  INSERT INTO public."SecurityEventOutbox" (id, "eventType", payload, "updatedAt")
  VALUES (
    gen_random_uuid()::text,
    'AUDIT_LOG',
    jsonb_build_object(
      'id', response_id,
      'action', 'CUSTOMER_FRAUD_REPORT_RESPONSE',
      'entityType', 'FraudReport',
      'entityId', report.id,
      'userId', actor.id,
      'orgId', target_org_id,
      'licenseeId', report."licenseeId",
      'details', response_details,
      'createdAt', transaction_timestamp()
    ),
    transaction_timestamp()
  );

  RETURN jsonb_build_object(
    'responseId', response_id,
    'reportId', report.id,
    'status', response_status,
    'message', response_message,
    'notifyCustomer', notify_customer,
    'delivery', delivery
  );
END;
$$;

REVOKE ALL ON FUNCTION app_rls.c02_audit_trace_actor_valid(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.platform_audit_log_details(text[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c02_fraud_report_network_details(text[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c02_respond_fraud_report(text,text,text,boolean) FROM PUBLIC;

CREATE OR REPLACE FUNCTION app_rls.c03_assert_restricted_identity(expected_identity text)
RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog
AS $$
BEGIN
  IF expected_identity NOT IN ('preauth','worker')
     OR session_user::text IS DISTINCT FROM (CASE expected_identity
       WHEN 'preauth' THEN 'mscqr_rls_cert_preauth'
       ELSE 'mscqr_rls_cert_worker'
     END) THEN
    RAISE EXCEPTION 'C03_RESTRICTED_IDENTITY_DENIED' USING ERRCODE='42501';
  END IF;
  RETURN true;
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_public_incident_qr(qr_proof text)
RETURNS TABLE(qr_id text, licensee_id text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
DECLARE candidate record;
BEGIN
  IF session_user::text<>'mscqr_rls_cert_preauth' OR current_setting('app.purpose',true)<>'public-incident-intake'
     OR qr_proof IS NULL OR length(qr_proof) NOT BETWEEN 2 AND 128 OR qr_proof<>btrim(qr_proof) THEN
    RAISE EXCEPTION 'C03_PUBLIC_INCIDENT_DENIED' USING ERRCODE='42501';
  END IF;
  PERFORM set_config('app.c03_public_operation','incident-qr-read',true);
  PERFORM set_config('app.c03_public_code',qr_proof,true);
  SELECT q.id,q."licenseeId" INTO candidate FROM public."QRCode" q WHERE q.code=qr_proof;
  IF NOT FOUND THEN RAISE EXCEPTION 'C03_PUBLIC_INCIDENT_NOT_FOUND' USING ERRCODE='02000'; END IF;
  PERFORM set_config('app.c03_public_licensee_id',candidate."licenseeId",true);
  RETURN QUERY
  SELECT candidate.id,candidate."licenseeId" FROM public."Licensee" l
   JOIN public."Organization" o ON o.id=l."orgId"
  WHERE l.id=candidate."licenseeId" AND l."isActive" AND l."suspendedAt" IS NULL AND o."isActive";
  IF NOT FOUND THEN RAISE EXCEPTION 'C03_PUBLIC_INCIDENT_NOT_FOUND' USING ERRCODE='02000'; END IF;
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_compute_incident_spam_signal(qr_proof text, contact_hashes jsonb)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
DECLARE qr record; recent_count integer;
BEGIN
  IF jsonb_typeof(contact_hashes)<>'object'
     OR EXISTS (SELECT 1 FROM jsonb_object_keys(contact_hashes) k WHERE k NOT IN ('emailHash','phoneHash'))
     OR length(COALESCE(contact_hashes->>'emailHash',''))>64
     OR length(COALESCE(contact_hashes->>'phoneHash',''))>64 THEN
    RAISE EXCEPTION 'C03_PUBLIC_INCIDENT_INVALID' USING ERRCODE='22023';
  END IF;
  SELECT * INTO qr FROM app_rls.c03_public_incident_qr(qr_proof);
  PERFORM set_config('app.c03_public_operation','incident-history-read',true);
  PERFORM set_config('app.c03_public_qr_id',qr.qr_id,true);
  SELECT count(*) INTO recent_count FROM public."Incident" i
   WHERE i."qrCodeId"=qr.qr_id AND i."createdAt">transaction_timestamp()-interval '24 hours';
  RETURN recent_count>=5;
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_compute_incident_severity(qr_proof text, input jsonb)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
DECLARE qr record; kind text := input->>'incidentType';
BEGIN
  IF jsonb_typeof(input)<>'object' OR kind NOT IN ('COUNTERFEIT_SUSPECTED','DUPLICATE_SCAN','TAMPERED_LABEL','WRONG_PRODUCT','OTHER') THEN
    RAISE EXCEPTION 'C03_PUBLIC_INCIDENT_INVALID' USING ERRCODE='22023';
  END IF;
  SELECT * INTO qr FROM app_rls.c03_public_incident_qr(qr_proof);
  RETURN CASE kind
    WHEN 'COUNTERFEIT_SUSPECTED' THEN 'HIGH'
    WHEN 'TAMPERED_LABEL' THEN 'HIGH'
    WHEN 'DUPLICATE_SCAN' THEN 'MEDIUM'
    ELSE 'LOW'
  END;
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_create_public_incident_report(
  qr_proof text, report jsonb, uploads jsonb, idempotency_key text
)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
DECLARE qr record; prior record; incident record;
DECLARE request_hash text; response jsonb; upload jsonb; evidence_id text;
BEGIN
  IF jsonb_typeof(report)<>'object' OR jsonb_typeof(uploads)<>'array'
     OR jsonb_array_length(uploads)>8 OR length(idempotency_key) NOT BETWEEN 8 AND 200
     OR report->>'incidentType' NOT IN ('COUNTERFEIT_SUSPECTED','DUPLICATE_SCAN','TAMPERED_LABEL','WRONG_PRODUCT','OTHER')
     OR report->>'severity' NOT IN ('LOW','MEDIUM','HIGH','CRITICAL')
     OR length(COALESCE(report->>'description','')) NOT BETWEEN 5 AND 2000 THEN
    RAISE EXCEPTION 'C03_PUBLIC_INCIDENT_INVALID' USING ERRCODE='22023';
  END IF;
  SELECT * INTO qr FROM app_rls.c03_public_incident_qr(qr_proof);
  request_hash:=encode(sha256(convert_to(report::text||uploads::text,'UTF8')),'hex');
  PERFORM set_config('app.c03_public_operation','incident-create',true);
  PERFORM set_config('app.c03_public_qr_id',qr.qr_id,true);
  PERFORM set_config('app.c03_public_licensee_id',qr.licensee_id,true);
  INSERT INTO public."ActionIdempotencyKey"(id,"keyHash",action,scope,"requestHash","expiresAt")
  VALUES(gen_random_uuid()::text,encode(sha256(convert_to('public-incident|'||idempotency_key,'UTF8')),'hex'),
    'c03-public-incident',qr.licensee_id,request_hash,transaction_timestamp()+interval '24 hours')
  ON CONFLICT("keyHash") DO NOTHING;
  IF NOT FOUND THEN
    SELECT k."requestHash",k."responsePayload" INTO prior FROM public."ActionIdempotencyKey" k
     WHERE k."keyHash"=encode(sha256(convert_to('public-incident|'||idempotency_key,'UTF8')),'hex') FOR UPDATE;
    IF prior."requestHash" IS DISTINCT FROM request_hash THEN RAISE EXCEPTION 'C03_PUBLIC_INCIDENT_REPLAY_CONFLICT' USING ERRCODE='40001'; END IF;
    IF prior."responsePayload" IS NULL THEN RAISE EXCEPTION 'C03_PUBLIC_INCIDENT_REPLAY_IN_PROGRESS' USING ERRCODE='40001'; END IF;
    RETURN prior."responsePayload";
  END IF;
  INSERT INTO public."Incident"(
    id,"qrCodeId","qrCodeValue","licenseeId","reportedBy","customerName","customerEmail","customerPhone",
    "customerCountry","preferredContactMethod","consentToContact","incidentType",severity,description,photos,
    "purchasePlace","purchaseDate","productBatchNo","locationLat","locationLng","locationName","locationCountry",
    "locationRegion","locationCity","ipHash","userAgentHash","deviceFingerprintHash",status,priority,"slaDueAt",tags
  ) VALUES (
    gen_random_uuid()::text,qr.qr_id,qr_proof,qr.licensee_id,'CUSTOMER',
    NULLIF(report->>'customerName',''),NULLIF(report->>'customerEmail',''),NULLIF(report->>'customerPhone',''),
    NULLIF(report->>'customerCountry',''),COALESCE(NULLIF(report->>'preferredContactMethod',''),'NONE')::public."IncidentContactMethod",
    COALESCE((report->>'consentToContact')::boolean,false),(report->>'incidentType')::public."IncidentType",
    (report->>'severity')::public."IncidentSeverity",report->>'description',
    ARRAY(SELECT jsonb_array_elements_text(COALESCE(report->'photos','[]'::jsonb))),
    NULLIF(report->>'purchasePlace',''),NULLIF(report->>'purchaseDate','')::timestamptz,NULLIF(report->>'productBatchNo',''),
    NULLIF(report->>'locationLat','')::double precision,NULLIF(report->>'locationLng','')::double precision,
    NULLIF(report->>'locationName',''),NULLIF(report->>'locationCountry',''),NULLIF(report->>'locationRegion',''),
    NULLIF(report->>'locationCity',''),NULLIF(report->>'ipHash',''),NULLIF(report->>'userAgentHash',''),
    NULLIF(report->>'deviceFingerprintHash',''),'NEW','P3',
    transaction_timestamp()+CASE report->>'severity' WHEN 'CRITICAL' THEN interval '4 hours' WHEN 'HIGH' THEN interval '24 hours' WHEN 'MEDIUM' THEN interval '72 hours' ELSE interval '168 hours' END,
    ARRAY(SELECT jsonb_array_elements_text(COALESCE(report->'tags','[]'::jsonb)))
  ) RETURNING id,status,severity,"createdAt","qrCodeValue" INTO incident;
  PERFORM set_config('app.c03_public_incident_id',incident.id,true);
  INSERT INTO public."IncidentEvent"(id,"incidentId","actorType","eventType","eventPayload")
  VALUES(gen_random_uuid()::text,incident.id,'CUSTOMER','CREATED',jsonb_build_object('source','public_report'));
  FOR upload IN SELECT * FROM jsonb_array_elements(uploads) LOOP
    IF length(COALESCE(upload->>'fileUrl',''))>1000 OR length(COALESCE(upload->>'storageKey',''))>1000
       OR length(COALESCE(upload->>'fileType',''))>160 THEN RAISE EXCEPTION 'C03_PUBLIC_INCIDENT_INVALID' USING ERRCODE='22023'; END IF;
    evidence_id:=gen_random_uuid()::text;
    INSERT INTO public."IncidentEvidence"(id,"incidentId","fileUrl","storageKey","fileType","uploadedBy")
    VALUES(evidence_id,incident.id,NULLIF(upload->>'fileUrl',''),NULLIF(upload->>'storageKey',''),NULLIF(upload->>'fileType',''),'CUSTOMER');
  END LOOP;
  response:=jsonb_build_object('id',incident.id,'status',incident.status,'severity',incident.severity,
    'createdAt',incident."createdAt",'qrCodeValue',incident."qrCodeValue");
  UPDATE public."ActionIdempotencyKey" SET "statusCode"=201,"responsePayload"=response,"completedAt"=transaction_timestamp()
   WHERE action='c03-public-incident' AND scope=qr.licensee_id AND "requestHash"=request_hash AND "responsePayload" IS NULL;
  RETURN response;
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_require_incident_actor(p_incident_id text, p_purpose text, p_assurance text DEFAULT 'password-verified')
RETURNS TABLE(user_id text, licensee_id text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
BEGIN
  PERFORM set_config('app.c03_incident_id',p_incident_id,true);
  RETURN QUERY
  SELECT actor.user_id,actor.licensee_id
    FROM public."Incident" i
    CROSS JOIN LATERAL app_rls.c03_revalidate_actor_scope(
      i."licenseeId",'["SUPER_ADMIN","PLATFORM_SUPER_ADMIN","LICENSEE_ADMIN","MANUFACTURER_ADMIN"]'::jsonb,p_assurance,p_purpose
    ) actor
   WHERE i.id=p_incident_id;
  IF NOT FOUND THEN RAISE EXCEPTION 'C03_INCIDENT_DENIED' USING ERRCODE='42501'; END IF;
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_get_incident_detail(incident_id text)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
DECLARE actor record; result jsonb;
BEGIN
  SELECT * INTO actor FROM app_rls.c03_require_incident_actor(incident_id,current_setting('app.purpose',true));
  SELECT to_jsonb(i)||jsonb_build_object(
    'events',COALESCE((SELECT jsonb_agg(to_jsonb(e) ORDER BY e."createdAt",e.id) FROM (
      SELECT event.id,event."incidentId",event."actorType",event."actorUserId",event."eventType",
        event."eventPayload",event."createdAt" FROM public."IncidentEvent" event WHERE event."incidentId"=i.id
    ) e),'[]'::jsonb),
    'communications',COALESCE((SELECT jsonb_agg(to_jsonb(c) ORDER BY c."createdAt" DESC,c.id DESC) FROM (
      SELECT comm.id,comm."incidentId",comm.direction,comm.channel,comm."toAddress",comm.subject,
        comm."bodyPreview",comm."attemptedFrom",comm."usedFrom",comm."replyTo",comm."providerMessageId",
        comm."errorMessage",comm.status,comm."createdAt"
      FROM public."IncidentCommunication" comm WHERE comm."incidentId"=i.id
    ) c),'[]'::jsonb),
    'evidence',COALESCE((SELECT jsonb_agg(to_jsonb(v) ORDER BY v."createdAt" DESC,v.id DESC) FROM (
      SELECT evidence.id,evidence."incidentId",evidence."fileUrl",evidence."storageKey",evidence."fileType",
        evidence."uploadedByUserId",evidence."uploadedBy",evidence."createdAt"
      FROM public."IncidentEvidence" evidence WHERE evidence."incidentId"=i.id
    ) v),'[]'::jsonb)
  ) INTO result FROM (
    SELECT incident.id,incident."qrCodeId",incident."qrCodeValue",incident."scanEventId",incident."licenseeId",
      incident."reportedBy",incident."customerName",incident."customerEmail",incident."customerPhone",
      incident."customerCountry",incident."preferredContactMethod",incident."consentToContact",
      incident."incidentType",incident.severity,incident."severityOverridden",incident.description,
      incident.photos,incident."purchasePlace",incident."purchaseDate",incident."productBatchNo",
      incident."locationLat",incident."locationLng",incident."locationName",incident."locationCountry",
      incident."locationRegion",incident."locationCity",incident."ipHash",incident."userAgentHash",
      incident."deviceFingerprintHash",incident.status,incident.priority,incident."assignedToUserId",
      incident."slaDueAt",incident.tags,incident."internalNotes",incident."resolutionSummary",
      incident."resolutionOutcome",incident."createdAt",incident."updatedAt"
    FROM public."Incident" incident
    WHERE incident.id=incident_id AND incident."licenseeId"=actor.licensee_id
  ) i;
  RETURN result;
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_list_incidents(filters jsonb, row_limit integer, row_offset integer)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
DECLARE actor record; result jsonb;
BEGIN
  IF jsonb_typeof(filters)<>'object' OR row_limit NOT BETWEEN 1 AND 200 OR row_offset NOT BETWEEN 0 AND 20000
     OR EXISTS(SELECT 1 FROM jsonb_object_keys(filters) k WHERE k NOT IN ('status','severity','qr','search','dateFrom','dateTo','assignedTo')) THEN
    RAISE EXCEPTION 'C03_INCIDENT_LIST_INVALID' USING ERRCODE='22023';
  END IF;
  SELECT * INTO actor FROM app_rls.c03_revalidate_actor_scope(
    current_setting('app.licensee_id',true),'["SUPER_ADMIN","PLATFORM_SUPER_ADMIN","LICENSEE_ADMIN","ORG_ADMIN"]'::jsonb,
    'password-verified','incident-list');
  IF NOT FOUND THEN RAISE EXCEPTION 'C03_INCIDENT_DENIED' USING ERRCODE='42501'; END IF;
  SELECT jsonb_build_object(
    'rows',COALESCE(jsonb_agg(to_jsonb(page) ORDER BY page."createdAt" DESC,page.id DESC),'[]'::jsonb),
    'total',(SELECT count(*) FROM public."Incident" i WHERE i."licenseeId"=actor.licensee_id
      AND (NOT filters?'status' OR i.status::text=filters->>'status')
      AND (NOT filters?'severity' OR i.severity::text=filters->>'severity')
      AND (NOT filters?'assignedTo' OR i."assignedToUserId"=filters->>'assignedTo')
      AND (NOT filters?'qr' OR i."qrCodeValue" ILIKE '%'||(filters->>'qr')||'%')
      AND (NOT filters?'search' OR i.description ILIKE '%'||(filters->>'search')||'%' OR i."qrCodeValue" ILIKE '%'||(filters->>'search')||'%')
      AND (NOT filters?'dateFrom' OR i."createdAt">=(filters->>'dateFrom')::timestamptz)
      AND (NOT filters?'dateTo' OR i."createdAt"<=(filters->>'dateTo')::timestamptz))
  ) INTO result FROM (
    SELECT i.id,i."qrCodeId",i."qrCodeValue",i."scanEventId",i."licenseeId",i."reportedBy",
      i."customerName",i."customerEmail",i."customerPhone",i."customerCountry",i."preferredContactMethod",
      i."consentToContact",i."incidentType",i.severity,i."severityOverridden",i.description,i.photos,
      i."purchasePlace",i."purchaseDate",i."productBatchNo",i."locationLat",i."locationLng",
      i."locationName",i."locationCountry",i."locationRegion",i."locationCity",i."ipHash",
      i."userAgentHash",i."deviceFingerprintHash",i.status,i.priority,i."assignedToUserId",
      i."slaDueAt",i.tags,i."internalNotes",i."resolutionSummary",i."resolutionOutcome",
      i."createdAt",i."updatedAt"
    FROM public."Incident" i WHERE i."licenseeId"=actor.licensee_id
      AND (NOT filters?'status' OR i.status::text=filters->>'status')
      AND (NOT filters?'severity' OR i.severity::text=filters->>'severity')
      AND (NOT filters?'assignedTo' OR i."assignedToUserId"=filters->>'assignedTo')
      AND (NOT filters?'qr' OR i."qrCodeValue" ILIKE '%'||(filters->>'qr')||'%')
      AND (NOT filters?'search' OR i.description ILIKE '%'||(filters->>'search')||'%' OR i."qrCodeValue" ILIKE '%'||(filters->>'search')||'%')
      AND (NOT filters?'dateFrom' OR i."createdAt">=(filters->>'dateFrom')::timestamptz)
      AND (NOT filters?'dateTo' OR i."createdAt"<=(filters->>'dateTo')::timestamptz)
    ORDER BY i."createdAt" DESC,i.id DESC LIMIT row_limit OFFSET row_offset
  ) page;
  RETURN result;
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_patch_incident(incident_id text, patch jsonb)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
DECLARE actor record; changed text[]:=ARRAY[]::text[]; updated record;
BEGIN
  IF jsonb_typeof(patch)<>'object' OR patch='{}'::jsonb OR EXISTS(SELECT 1 FROM jsonb_object_keys(patch) k
    WHERE k NOT IN ('status','assignedToUserId','internalNotes','tags','severity','priority','resolutionSummary','resolutionOutcome')) THEN
    RAISE EXCEPTION 'C03_INCIDENT_PATCH_INVALID' USING ERRCODE='22023';
  END IF;
  SELECT * INTO actor FROM app_rls.c03_require_incident_actor(incident_id,'incident-update','mfa-verified');
  PERFORM 1 FROM public."Incident" WHERE id=incident_id AND "licenseeId"=actor.licensee_id FOR UPDATE;
  UPDATE public."Incident" i SET
    status=CASE WHEN patch?'status' THEN (patch->>'status')::public."IncidentStatus" ELSE i.status END,
    "assignedToUserId"=CASE WHEN patch?'assignedToUserId' THEN NULLIF(patch->>'assignedToUserId','') ELSE i."assignedToUserId" END,
    "internalNotes"=CASE WHEN patch?'internalNotes' THEN NULLIF(patch->>'internalNotes','') ELSE i."internalNotes" END,
    tags=CASE WHEN patch?'tags' THEN ARRAY(SELECT jsonb_array_elements_text(patch->'tags')) ELSE i.tags END,
    severity=CASE WHEN patch?'severity' THEN (patch->>'severity')::public."IncidentSeverity" ELSE i.severity END,
    "severityOverridden"=CASE WHEN patch?'severity' THEN true ELSE i."severityOverridden" END,
    priority=CASE WHEN patch?'priority' THEN (patch->>'priority')::public."IncidentPriority" ELSE i.priority END,
    "resolutionSummary"=CASE WHEN patch?'resolutionSummary' THEN NULLIF(patch->>'resolutionSummary','') ELSE i."resolutionSummary" END,
    "resolutionOutcome"=CASE WHEN patch?'resolutionOutcome' THEN NULLIF(patch->>'resolutionOutcome','')::public."IncidentResolutionOutcome" ELSE i."resolutionOutcome" END,
    "updatedAt"=transaction_timestamp()
   WHERE i.id=incident_id
   RETURNING id,"qrCodeId","qrCodeValue","scanEventId","licenseeId","reportedBy","customerName",
     "customerEmail","customerPhone","customerCountry","preferredContactMethod","consentToContact",
     "incidentType",severity,"severityOverridden",description,photos,"purchasePlace","purchaseDate",
     "productBatchNo","locationLat","locationLng","locationName","locationCountry","locationRegion",
     "locationCity","ipHash","userAgentHash","deviceFingerprintHash",status,priority,"assignedToUserId",
     "slaDueAt",tags,"internalNotes","resolutionSummary","resolutionOutcome","createdAt","updatedAt"
   INTO updated;
  SELECT array_agg(k) INTO changed FROM jsonb_object_keys(patch) k;
  INSERT INTO public."IncidentEvent"(id,"incidentId","actorType","actorUserId","eventType","eventPayload")
  VALUES(gen_random_uuid()::text,incident_id,'ADMIN',actor.user_id,'UPDATED_FIELDS',jsonb_build_object('changedFields',changed));
  RETURN jsonb_build_object('incident',to_jsonb(updated),'changedFields',to_jsonb(changed));
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_record_incident_event(incident_id text, event_type text, event_payload jsonb)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
DECLARE actor record; created record; purpose text:=current_setting('app.purpose',true);
BEGIN
  SELECT * INTO actor FROM app_rls.c03_require_incident_actor(incident_id,purpose,
    CASE WHEN purpose IN ('incident-note-add','incident-update','incident-pdf-export') THEN 'mfa-verified' ELSE 'password-verified' END);
  IF event_type NOT IN ('CREATED','NOTE_ADDED','STATUS_CHANGED','ASSIGNED','UPDATED_FIELDS','EXPORTED','EMAIL_SENT') OR octet_length(COALESCE(event_payload,'{}'::jsonb)::text)>16384 THEN
    RAISE EXCEPTION 'C03_INCIDENT_EVENT_INVALID' USING ERRCODE='22023';
  END IF;
  INSERT INTO public."IncidentEvent"(id,"incidentId","actorType","actorUserId","eventType","eventPayload")
  VALUES(gen_random_uuid()::text,incident_id,'ADMIN',actor.user_id,event_type::public."IncidentEventType",event_payload)
  RETURNING id,"incidentId","actorType","actorUserId","eventType","eventPayload","createdAt" INTO created;
  RETURN to_jsonb(created);
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_add_incident_evidence(incident_id text, evidence jsonb, idempotency_key text)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
DECLARE actor record; created record; key_hash text;
BEGIN
  IF jsonb_typeof(evidence)<>'object' OR length(idempotency_key) NOT BETWEEN 8 AND 200
     OR length(COALESCE(evidence->>'fileUrl',''))>1000 OR length(COALESCE(evidence->>'storageKey',''))>1000
     OR length(COALESCE(evidence->>'fileType',''))>160 THEN
    RAISE EXCEPTION 'C03_INCIDENT_EVIDENCE_INVALID' USING ERRCODE='22023';
  END IF;
  SELECT * INTO actor FROM app_rls.c03_require_incident_actor(incident_id,'incident-evidence-add','mfa-verified');
  key_hash:=encode(sha256(convert_to('incident-evidence|'||incident_id||'|'||idempotency_key,'UTF8')),'hex');
  INSERT INTO public."ActionIdempotencyKey"(id,"keyHash",action,scope,"requestHash","expiresAt")
  VALUES(gen_random_uuid()::text,key_hash,'c03-incident-evidence',incident_id,
    encode(sha256(convert_to(evidence::text,'UTF8')),'hex'),transaction_timestamp()+interval '24 hours')
  ON CONFLICT("keyHash") DO NOTHING;
  IF NOT FOUND THEN
    RETURN (SELECT "responsePayload" FROM public."ActionIdempotencyKey" WHERE "keyHash"=key_hash AND "responsePayload" IS NOT NULL);
  END IF;
  INSERT INTO public."IncidentEvidence"(id,"incidentId","fileUrl","storageKey","fileType","uploadedByUserId","uploadedBy")
  VALUES(gen_random_uuid()::text,incident_id,NULLIF(evidence->>'fileUrl',''),NULLIF(evidence->>'storageKey',''),
    NULLIF(evidence->>'fileType',''),actor.user_id,'ADMIN')
  RETURNING id,"incidentId","fileUrl","storageKey","fileType","uploadedByUserId","uploadedBy","createdAt"
  INTO created;
  UPDATE public."ActionIdempotencyKey" SET "statusCode"=201,"responsePayload"=jsonb_build_object('evidence',to_jsonb(created)),
    "completedAt"=transaction_timestamp() WHERE "keyHash"=key_hash;
  RETURN jsonb_build_object('evidence',to_jsonb(created),'tamperChecks',NULL);
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_build_incident_evidence_audit_snapshot(incident_id text)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
DECLARE actor record;
BEGIN
  SELECT * INTO actor FROM app_rls.c03_require_incident_actor(incident_id,current_setting('app.purpose',true),'mfa-verified');
  RETURN jsonb_build_object(
    'incident',(SELECT to_jsonb(i) FROM (
      SELECT incident.id,incident."qrCodeId",incident."qrCodeValue",incident."scanEventId",incident."licenseeId",
        incident."reportedBy",incident."customerName",incident."customerEmail",incident."customerPhone",
        incident."customerCountry",incident."preferredContactMethod",incident."consentToContact",
        incident."incidentType",incident.severity,incident."severityOverridden",incident.description,
        incident.photos,incident."purchasePlace",incident."purchaseDate",incident."productBatchNo",
        incident."locationLat",incident."locationLng",incident."locationName",incident."locationCountry",
        incident."locationRegion",incident."locationCity",incident."ipHash",incident."userAgentHash",
        incident."deviceFingerprintHash",incident.status,incident.priority,incident."assignedToUserId",
        incident."slaDueAt",incident.tags,incident."internalNotes",incident."resolutionSummary",
        incident."resolutionOutcome",incident."createdAt",incident."updatedAt"
      FROM public."Incident" incident WHERE incident.id=incident_id
    ) i),
    'evidence',COALESCE((SELECT jsonb_agg(to_jsonb(e) ORDER BY e."createdAt",e.id) FROM (
      SELECT evidence.id,evidence."incidentId",evidence."fileUrl",evidence."storageKey",evidence."fileType",
        evidence."uploadedByUserId",evidence."uploadedBy",evidence."createdAt"
      FROM public."IncidentEvidence" evidence WHERE evidence."incidentId"=incident_id
    ) e),'[]'::jsonb),
    'events',COALESCE((SELECT jsonb_agg(to_jsonb(e) ORDER BY e."createdAt",e.id) FROM (
      SELECT event.id,event."incidentId",event."actorType",event."actorUserId",event."eventType",
        event."eventPayload",event."createdAt"
      FROM public."IncidentEvent" event WHERE event."incidentId"=incident_id
    ) e),'[]'::jsonb)
  );
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_list_ir_alerts(
  p_incident_authorization_id text, p_incident_id text, p_licensee_id text, p_filters jsonb, p_row_limit integer, p_row_offset integer
)
RETURNS TABLE(id text,licensee_id text,alert_type text,severity text,message text,score integer,policy_rule_id text,
  incident_id text,batch_id text,qr_code_id text,manufacturer_id text,acknowledged_at timestamptz,created_at timestamptz,total_count bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
DECLARE actor record;
BEGIN
  IF p_incident_authorization_id !~* '^[0-9a-f-]{36}$' OR jsonb_typeof(p_filters)<>'object'
     OR p_row_limit NOT BETWEEN 1 AND 100 OR p_row_offset NOT BETWEEN 0 AND 20000 THEN
    RAISE EXCEPTION 'C03_IR_ALERT_INVALID' USING ERRCODE='22023';
  END IF;
  SELECT * INTO actor FROM app_rls.c03_require_incident_actor(p_incident_id,'incident-response-alert-triage','step-up-verified');
  IF actor.licensee_id<>p_licensee_id THEN RAISE EXCEPTION 'C03_IR_ALERT_DENIED' USING ERRCODE='42501'; END IF;
  RETURN QUERY SELECT a.id,a."licenseeId",a."alertType"::text,a.severity::text,a.message,a.score,a."policyRuleId",
    a."incidentId",a."batchId",a."qrCodeId",a."manufacturerId",a."acknowledgedAt",a."createdAt",count(*) OVER()
    FROM public."PolicyAlert" a WHERE a."licenseeId"=actor.licensee_id AND a."incidentId"=p_incident_id
      AND (NOT p_filters?'alertType' OR a."alertType"::text=p_filters->>'alertType')
      AND (NOT p_filters?'severity' OR a.severity::text=p_filters->>'severity')
      AND (NOT p_filters?'acknowledged' OR (a."acknowledgedAt" IS NOT NULL)=(p_filters->>'acknowledged')::boolean)
      AND (NOT p_filters?'policyRuleId' OR a."policyRuleId"=p_filters->>'policyRuleId')
      AND (NOT p_filters?'qrCodeId' OR a."qrCodeId"=p_filters->>'qrCodeId')
      AND (NOT p_filters?'batchId' OR a."batchId"=p_filters->>'batchId')
      AND (NOT p_filters?'manufacturerId' OR a."manufacturerId"=p_filters->>'manufacturerId')
    ORDER BY a."createdAt" DESC,a.id DESC LIMIT p_row_limit OFFSET p_row_offset;
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_link_ir_alert_incident(
  incident_authorization_id text, alert_id text, incident_id text, reason text, idempotency_key text
)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
DECLARE actor record; alert record; key_hash text;
BEGIN
  IF incident_authorization_id !~* '^[0-9a-f-]{36}$' OR length(reason) NOT BETWEEN 3 AND 600
     OR length(idempotency_key) NOT BETWEEN 8 AND 200 THEN RAISE EXCEPTION 'C03_IR_ALERT_INVALID' USING ERRCODE='22023'; END IF;
  SELECT * INTO actor FROM app_rls.c03_require_incident_actor(incident_id,'alert-escalation','step-up-verified');
  key_hash:=encode(sha256(convert_to('alert-link|'||alert_id||'|'||idempotency_key,'UTF8')),'hex');
  INSERT INTO public."ActionIdempotencyKey"(id,"keyHash",action,scope,"requestHash","expiresAt")
  VALUES(gen_random_uuid()::text,key_hash,'c03-alert-link',actor.licensee_id,
    encode(sha256(convert_to(incident_id||'|'||reason,'UTF8')),'hex'),transaction_timestamp()+interval '24 hours')
  ON CONFLICT("keyHash") DO NOTHING;
  IF NOT FOUND THEN RETURN (SELECT "responsePayload" FROM public."ActionIdempotencyKey" WHERE "keyHash"=key_hash); END IF;
  UPDATE public."PolicyAlert" SET "incidentId"=incident_id WHERE id=alert_id AND "licenseeId"=actor.licensee_id
   RETURNING id,"licenseeId","alertType",severity,message,score,"policyRuleId","incidentId",
     "batchId","qrCodeId","manufacturerId","acknowledgedAt","acknowledgedByUserId",details,"createdAt"
   INTO alert;
  IF NOT FOUND THEN RAISE EXCEPTION 'C03_IR_ALERT_DENIED' USING ERRCODE='42501'; END IF;
  UPDATE public."ActionIdempotencyKey" SET "statusCode"=200,"responsePayload"=to_jsonb(alert),"completedAt"=transaction_timestamp()
   WHERE "keyHash"=key_hash;
  RETURN to_jsonb(alert);
END;
$$;

REVOKE ALL ON FUNCTION app_rls.c03_assert_restricted_identity(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_public_incident_qr(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_compute_incident_spam_signal(text,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_compute_incident_severity(text,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_create_public_incident_report(text,jsonb,jsonb,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_require_incident_actor(text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_get_incident_detail(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_list_incidents(jsonb,integer,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_patch_incident(text,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_record_incident_event(text,text,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_add_incident_evidence(text,jsonb,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_build_incident_evidence_audit_snapshot(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_list_ir_alerts(text,text,text,jsonb,integer,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_link_ir_alert_incident(text,text,text,text,text) FROM PUBLIC;

CREATE OR REPLACE FUNCTION app_rls.c03_require_approval_actor(p_purpose text)
RETURNS TABLE(user_id text, licensee_id text)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
BEGIN
  IF current_setting('app.purpose', true) IS DISTINCT FROM p_purpose
     OR current_setting('app.role', true) NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN','LICENSEE_ADMIN','MANUFACTURER_ADMIN') THEN
    RAISE EXCEPTION 'C03_APPROVAL_DENIED' USING ERRCODE='42501';
  END IF;
  RETURN QUERY
  SELECT actor.user_id, actor.licensee_id
    FROM app_rls.c03_revalidate_actor_scope(
      current_setting('app.licensee_id', true),
      '["SUPER_ADMIN","PLATFORM_SUPER_ADMIN","LICENSEE_ADMIN","MANUFACTURER_ADMIN"]'::jsonb,
      CASE WHEN p_purpose IN ('sensitive-action-approval-approve','sensitive-action-approval-reject') THEN 'mfa-verified' ELSE 'password-verified' END,
      p_purpose
    ) actor;
  IF NOT FOUND THEN RAISE EXCEPTION 'C03_APPROVAL_DENIED' USING ERRCODE='42501'; END IF;
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_create_sensitive_action_approval(input jsonb)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
DECLARE actor record; created record;
DECLARE action_key text := input->>'actionKey';
BEGIN
  SELECT * INTO actor FROM app_rls.c03_require_approval_actor('sensitive-action-approval-request');
  IF jsonb_typeof(input)<>'object'
     OR action_key NOT IN ('FEATURE_FLAG_UPSERT','RETENTION_POLICY_PATCH','RETENTION_APPLY','QR_BLOCK','BATCH_BLOCK','BATCH_RELEASE','PRINTER_GATEWAY_SECRET_ROTATION')
     OR jsonb_typeof(input->'payload')<>'object'
     OR octet_length((input->'payload')::text)>65536
     OR (input ? 'summary' AND input->'summary' IS NOT NULL AND jsonb_typeof(input->'summary')<>'object')
     OR length(COALESCE(input->>'entityType',''))>120
     OR length(COALESCE(input->>'entityId',''))>160 THEN
    RAISE EXCEPTION 'C03_APPROVAL_INVALID' USING ERRCODE='22023';
  END IF;
  INSERT INTO public."SensitiveActionApproval" (
    id,"actionKey",status,"requestedByUserId","licenseeId","entityType","entityId",
    payload,summary,"requestIpHash","requestUserAgentHash","expiresAt","updatedAt"
  ) VALUES (
    gen_random_uuid()::text,action_key,'PENDING',actor.user_id,actor.licensee_id,
    NULLIF(input->>'entityType',''),NULLIF(input->>'entityId',''),input->'payload',
    input->'summary',NULLIF(input->>'requestIpHash',''),NULLIF(input->>'requestUserAgentHash',''),
    transaction_timestamp()+interval '30 minutes',transaction_timestamp()
  ) RETURNING
    id,"actionKey",status,"requestedByUserId","reviewedByUserId","executedByUserId",
    "licenseeId","entityType","entityId",payload,summary,"expiresAt","createdAt","executedAt"
    INTO created;
  PERFORM app_rls.c03_governance_audit('SENSITIVE_ACTION_APPROVAL_REQUESTED','SensitiveActionApproval',created.id,
    jsonb_build_object('actionKey',action_key,'requestedByUserId',actor.user_id));
  RETURN to_jsonb(created);
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_list_sensitive_action_approvals(status_filter text, row_limit integer, row_offset integer)
RETURNS TABLE(result jsonb)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
DECLARE actor record;
BEGIN
  SELECT * INTO actor FROM app_rls.c03_require_approval_actor('sensitive-action-approval-list');
  IF row_limit NOT BETWEEN 1 AND 200 OR row_offset NOT BETWEEN 0 AND 20000
     OR (status_filter IS NOT NULL AND status_filter NOT IN ('PENDING','APPROVED','REJECTED','EXECUTED','FAILED','EXPIRED')) THEN
    RAISE EXCEPTION 'C03_APPROVAL_LIST_INVALID' USING ERRCODE='22023';
  END IF;
  RETURN QUERY
  SELECT jsonb_build_object(
      'id',a.id,'actionKey',a."actionKey",'status',a.status,
      'requestedByUserId',a."requestedByUserId",'reviewedByUserId',a."reviewedByUserId",
      'executedByUserId',a."executedByUserId",'licenseeId',a."licenseeId",
      'entityType',a."entityType",'entityId',a."entityId",'payload',a.payload,
      'summary',a.summary,'expiresAt',a."expiresAt",'createdAt',a."createdAt",
      'executedAt',a."executedAt"
    )
    FROM public."SensitiveActionApproval" a
   WHERE a."licenseeId"=actor.licensee_id
     AND (status_filter IS NULL OR a.status=status_filter)
   ORDER BY a."createdAt" DESC,a.id DESC
   LIMIT row_limit OFFSET row_offset;
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_review_sensitive_action_approval(
  p_approval_id text, p_decision text, p_review_note text
)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
DECLARE actor record; approval record;
BEGIN
  IF p_decision NOT IN ('APPROVED','REJECTED') OR length(COALESCE(p_review_note,''))>500 THEN
    RAISE EXCEPTION 'C03_APPROVAL_REVIEW_INVALID' USING ERRCODE='22023';
  END IF;
  SELECT * INTO actor FROM app_rls.c03_require_approval_actor(
    CASE p_decision WHEN 'APPROVED' THEN 'sensitive-action-approval-approve' ELSE 'sensitive-action-approval-reject' END
  );
  SELECT id,"actionKey",status,"requestedByUserId","expiresAt"
    INTO approval FROM public."SensitiveActionApproval"
   WHERE id=p_approval_id AND "licenseeId"=actor.licensee_id FOR UPDATE;
  IF NOT FOUND OR approval.status<>'PENDING' OR approval."expiresAt"<=transaction_timestamp()
     OR approval."requestedByUserId"=actor.user_id THEN
    RAISE EXCEPTION 'C03_APPROVAL_DENIED' USING ERRCODE='42501';
  END IF;
  UPDATE public."SensitiveActionApproval"
     SET status=p_decision,"reviewedByUserId"=actor.user_id,"reviewNote"=NULLIF(p_review_note,''),
         "reviewedAt"=transaction_timestamp(),"updatedAt"=transaction_timestamp()
   WHERE id=p_approval_id
   RETURNING
     id,"actionKey",status,"requestedByUserId","reviewedByUserId","executedByUserId",
     "licenseeId","entityType","entityId",payload,summary,"expiresAt","createdAt","executedAt"
     INTO approval;
  PERFORM app_rls.c03_governance_audit('SENSITIVE_ACTION_APPROVAL_'||p_decision,'SensitiveActionApproval',approval.id,
    jsonb_build_object('actionKey',approval."actionKey",'requestedByUserId',approval."requestedByUserId",'reviewedByUserId',actor.user_id));
  RETURN to_jsonb(approval);
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_approve_sensitive_action_approval(approval_id text, review_note text)
RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public
AS $$ SELECT app_rls.c03_review_sensitive_action_approval(approval_id,'APPROVED',review_note) $$;

CREATE OR REPLACE FUNCTION app_rls.c03_reject_sensitive_action_approval(approval_id text, review_note text)
RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public
AS $$ SELECT app_rls.c03_review_sensitive_action_approval(approval_id,'REJECTED',review_note) $$;

REVOKE ALL ON FUNCTION app_rls.c03_require_approval_actor(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_create_sensitive_action_approval(jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_list_sensitive_action_approvals(text,integer,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_review_sensitive_action_approval(text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_approve_sensitive_action_approval(text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_reject_sensitive_action_approval(text,text) FROM PUBLIC;

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
          set_config('app.c03_approval_id','',true),
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
DECLARE actor record; job record; scope record;
BEGIN
  IF p_job_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  THEN RAISE EXCEPTION 'C03_COMPLIANCE_JOB_DENIED' USING ERRCODE='42501'; END IF;
  SELECT * INTO actor FROM app_rls.c03_require_authenticated_actor(p_capability,p_purpose,p_request_id);
  IF actor.assurance<>'ADMIN_MFA' THEN RAISE EXCEPTION 'C03_COMPLIANCE_MFA_REQUIRED' USING ERRCODE='42501'; END IF;
  PERFORM app_rls.c03_bind_operation('compliance-pack-revalidate','',p_job_id);
  SELECT j."licenseeId" INTO job FROM public."CompliancePackJob" j WHERE j.id=p_job_id;
  IF NOT FOUND OR job."licenseeId" IS NULL THEN RAISE EXCEPTION 'C03_COMPLIANCE_JOB_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM app_rls.c03_bind_operation('compliance-pack-revalidate',job."licenseeId",p_job_id);
  SELECT * INTO scope FROM app_rls.c03_assert_live_licensee_scope(job."licenseeId",actor.role,actor.organization_id,actor.licensee_id);
  PERFORM app_rls.c03_bind_operation('compliance-pack-revalidate',scope.licensee_id,p_job_id);
  RETURN QUERY SELECT actor.user_id::text,actor.role::text,scope.organization_id::text,scope.licensee_id::text;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.c03_bind_sensitive_approval_actor(
  p_capability text,p_purpose text,p_request_id text,p_approval_id text
) RETURNS TABLE(user_id text,role text,organization_id text,licensee_id text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; approval_licensee_id text; scope record;
BEGIN
  IF p_purpose NOT IN ('sensitive-action-approval-approve','sensitive-action-approval-reject')
     OR p_approval_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  THEN RAISE EXCEPTION 'C03_APPROVAL_DENIED' USING ERRCODE='42501'; END IF;

  SELECT * INTO actor FROM app_rls.c03_require_authenticated_actor(p_capability,p_purpose,p_request_id);
  IF actor.role NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN','LICENSEE_ADMIN','MANUFACTURER_ADMIN')
     OR actor.assurance<>'ADMIN_MFA'
  THEN RAISE EXCEPTION 'C03_APPROVAL_DENIED' USING ERRCODE='42501'; END IF;

  PERFORM set_config('app.c03_operation','sensitive-action-approval-revalidate',true),
          set_config('app.c03_approval_id',p_approval_id,true);
  SELECT "licenseeId" INTO approval_licensee_id
    FROM public."SensitiveActionApproval"
   WHERE id=p_approval_id;
  IF NOT FOUND OR approval_licensee_id IS NULL
  THEN RAISE EXCEPTION 'C03_APPROVAL_DENIED' USING ERRCODE='42501'; END IF;

  PERFORM set_config('app.c03_licensee_id',approval_licensee_id,true);
  SELECT * INTO scope FROM app_rls.c03_assert_live_licensee_scope(
    approval_licensee_id,actor.role,actor.organization_id,actor.licensee_id
  );
  PERFORM set_config('app.licensee_id',scope.licensee_id,true),
          set_config('app.c03_licensee_id',scope.licensee_id,true),
          set_config('app.c03_operation','sensitive-action-approval-review',true);
  RETURN QUERY SELECT actor.user_id::text,actor.role::text,scope.organization_id::text,scope.licensee_id::text;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.c03_start_compliance_pack_job(
  p_capability text,p_purpose text,p_request_id text,p_licensee_id text,
  p_trigger_type text,p_from timestamptz,p_to timestamptz
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; scope record; report jsonb; job_id text;
DECLARE replay_key text; request_hash text; prior record;
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
    SELECT k."requestHash",k."completedAt",k."responsePayload" INTO prior
      FROM public."ActionIdempotencyKey" k WHERE k."keyHash"=replay_key FOR UPDATE;
    IF prior."requestHash" IS DISTINCT FROM request_hash OR prior."completedAt" IS NULL OR prior."responsePayload" IS NULL
    THEN RAISE EXCEPTION 'C03_COMPLIANCE_REPLAY_CONFLICT' USING ERRCODE='40001'; END IF;
    RETURN prior."responsePayload";
  END IF;
  job_id:=gen_random_uuid()::text;
  PERFORM app_rls.c03_bind_operation('compliance-pack-start',scope.licensee_id,job_id);
  INSERT INTO public."CompliancePackJob" (id,"licenseeId",status,"triggerType","periodFrom","periodTo","startedByUserId","startedAt","updatedAt")
  VALUES (job_id,scope.licensee_id,'RUNNING',p_trigger_type,p_from,p_to,actor.user_id,transaction_timestamp(),transaction_timestamp());
  report:=app_rls.c03_build_compliance_report(scope.licensee_id,p_from,p_to);
  PERFORM app_rls.c03_queue_audit('COMPLIANCE_PACK_STARTED','CompliancePackJob',job_id,jsonb_build_object('triggerType',p_trigger_type,'periodFrom',p_from,'periodTo',p_to));
  UPDATE public."ActionIdempotencyKey" SET "statusCode"=200,"responsePayload"=jsonb_build_object(
    'job',app_rls.c03_compliance_job_projection(job_id),'report',report),"completedAt"=transaction_timestamp()
   WHERE "keyHash"=replay_key;
  RETURN jsonb_build_object('job',app_rls.c03_compliance_job_projection(job_id),'report',report);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.c03_complete_compliance_pack_job(
  p_capability text,p_purpose text,p_request_id text,p_job_id text,p_result jsonb
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; job record; scope record; projected jsonb;
BEGIN
  IF p_purpose<>'compliance-pack-complete' THEN RAISE EXCEPTION 'C03_COMPLIANCE_COMPLETE_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM app_rls.c03_validate_compliance_result(p_result);
  SELECT * INTO actor FROM app_rls.c03_require_authenticated_actor(p_capability,p_purpose,p_request_id);
  IF actor.assurance<>'ADMIN_MFA' THEN RAISE EXCEPTION 'C03_COMPLIANCE_MFA_REQUIRED' USING ERRCODE='42501'; END IF;
  PERFORM app_rls.c03_bind_operation('compliance-pack-complete','',p_job_id);
  SELECT j."licenseeId" INTO job FROM public."CompliancePackJob" j WHERE j.id=p_job_id;
  IF NOT FOUND OR job."licenseeId" IS NULL THEN RAISE EXCEPTION 'C03_COMPLIANCE_JOB_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM app_rls.c03_bind_operation('compliance-pack-complete',job."licenseeId",p_job_id);
  SELECT * INTO scope FROM app_rls.c03_assert_live_licensee_scope(job."licenseeId",actor.role,actor.organization_id,actor.licensee_id);
  PERFORM app_rls.c03_bind_operation('compliance-pack-complete',scope.licensee_id,p_job_id);
  SELECT j.status,j."storageKey",j."integrityHash" INTO job FROM public."CompliancePackJob" j
    WHERE j.id=p_job_id AND j."licenseeId"=scope.licensee_id FOR UPDATE;
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
DECLARE actor record; job record; scope record; projected jsonb;
BEGIN
  IF p_purpose<>'compliance-pack-fail' OR p_error_code !~ '^[A-Z0-9_:-]{1,160}$'
  THEN RAISE EXCEPTION 'C03_COMPLIANCE_FAIL_DENIED' USING ERRCODE='42501'; END IF;
  SELECT * INTO actor FROM app_rls.c03_require_authenticated_actor(p_capability,p_purpose,p_request_id);
  IF actor.assurance<>'ADMIN_MFA' THEN RAISE EXCEPTION 'C03_COMPLIANCE_MFA_REQUIRED' USING ERRCODE='42501'; END IF;
  PERFORM app_rls.c03_bind_operation('compliance-pack-fail','',p_job_id);
  SELECT j."licenseeId" INTO job FROM public."CompliancePackJob" j WHERE j.id=p_job_id;
  IF NOT FOUND OR job."licenseeId" IS NULL THEN RAISE EXCEPTION 'C03_COMPLIANCE_JOB_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM app_rls.c03_bind_operation('compliance-pack-fail',job."licenseeId",p_job_id);
  SELECT * INTO scope FROM app_rls.c03_assert_live_licensee_scope(job."licenseeId",actor.role,actor.organization_id,actor.licensee_id);
  PERFORM app_rls.c03_bind_operation('compliance-pack-fail',scope.licensee_id,p_job_id);
  SELECT j.status,j."errorMessage" INTO job FROM public."CompliancePackJob" j
    WHERE j.id=p_job_id AND j."licenseeId"=scope.licensee_id FOR UPDATE;
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
DECLARE actor record; job record; scope record; report jsonb;
BEGIN
  IF p_purpose NOT IN ('compliance-pack-download','compliance-pack-rebuild-read')
  THEN RAISE EXCEPTION 'C03_COMPLIANCE_READ_DENIED' USING ERRCODE='42501'; END IF;
  SELECT * INTO actor FROM app_rls.c03_require_authenticated_actor(p_capability,p_purpose,p_request_id);
  IF actor.assurance<>'ADMIN_MFA' THEN RAISE EXCEPTION 'C03_COMPLIANCE_MFA_REQUIRED' USING ERRCODE='42501'; END IF;
  PERFORM app_rls.c03_bind_operation('compliance-pack-get','',p_job_id);
  SELECT j."licenseeId",j."periodFrom",j."periodTo" INTO job
    FROM public."CompliancePackJob" j WHERE j.id=p_job_id;
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
DECLARE actor record; job record; scope record; projected jsonb;
BEGIN
  IF p_purpose<>'compliance-pack-rebuild-complete' THEN RAISE EXCEPTION 'C03_COMPLIANCE_REBUILD_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM app_rls.c03_validate_compliance_result(p_result);
  SELECT * INTO actor FROM app_rls.c03_require_authenticated_actor(p_capability,p_purpose,p_request_id);
  IF actor.assurance<>'ADMIN_MFA' THEN RAISE EXCEPTION 'C03_COMPLIANCE_MFA_REQUIRED' USING ERRCODE='42501'; END IF;
  PERFORM app_rls.c03_bind_operation('compliance-pack-rebuild','',p_job_id);
  SELECT j."licenseeId" INTO job FROM public."CompliancePackJob" j WHERE j.id=p_job_id;
  IF NOT FOUND OR job."licenseeId" IS NULL THEN RAISE EXCEPTION 'C03_COMPLIANCE_JOB_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM app_rls.c03_bind_operation('compliance-pack-rebuild',job."licenseeId",p_job_id);
  SELECT * INTO scope FROM app_rls.c03_assert_live_licensee_scope(job."licenseeId",actor.role,actor.organization_id,actor.licensee_id);
  PERFORM app_rls.c03_bind_operation('compliance-pack-rebuild',scope.licensee_id,p_job_id);
  SELECT j.status,j."storageKey",j."integrityHash" INTO job FROM public."CompliancePackJob" j
    WHERE j.id=p_job_id AND j."licenseeId"=scope.licensee_id FOR UPDATE;
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
REVOKE ALL ON FUNCTION app_rls.c03_bind_sensitive_approval_actor(text,text,text,text) FROM PUBLIC;
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
ALTER FUNCTION app_rls.c03_bind_sensitive_approval_actor(text,text,text,text) OWNER TO "mscqr_rls_cert_auth_owner";
ALTER FUNCTION app_rls.c03_start_compliance_pack_job(text,text,text,text,text,timestamp with time zone,timestamp with time zone) OWNER TO "mscqr_rls_cert_auth_owner";
ALTER FUNCTION app_rls.c03_complete_compliance_pack_job(text,text,text,text,jsonb) OWNER TO "mscqr_rls_cert_auth_owner";
ALTER FUNCTION app_rls.c03_fail_compliance_pack_job(text,text,text,text,text) OWNER TO "mscqr_rls_cert_auth_owner";
ALTER FUNCTION app_rls.c03_get_compliance_pack_job(text,text,text,text) OWNER TO "mscqr_rls_cert_auth_owner";
ALTER FUNCTION app_rls.c03_complete_compliance_pack_rebuild(text,text,text,text,jsonb) OWNER TO "mscqr_rls_cert_auth_owner";
ALTER FUNCTION app_rls.c03_get_incident_evidence_file_by_storage_key(text,text,text,text) OWNER TO "mscqr_rls_cert_auth_owner";

CREATE OR REPLACE FUNCTION app_rls.c03_require_policy_actor(
  target_licensee_id text,
  purpose_code text
)
RETURNS TABLE(user_id text, organization_id text, licensee_id text)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  RETURN QUERY
  SELECT actor.id::text, organization.id::text, licensee.id::text
    FROM public."User" actor
    JOIN public."Licensee" licensee ON licensee.id = target_licensee_id
    JOIN public."Organization" organization ON organization.id = licensee."orgId"
   WHERE actor.id = current_setting('app.user_id', true)
     AND actor.role::text = current_setting('app.role', true)
     AND actor.role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')
     AND actor."orgId" IS NULL AND actor."licenseeId" IS NULL
     AND actor."isActive" AND actor.status = 'ACTIVE'::public."UserStatus"
     AND actor."deletedAt" IS NULL AND actor."disabledAt" IS NULL
     AND licensee."isActive" AND licensee."suspendedAt" IS NULL AND organization."isActive"
     AND current_setting('app.organization_id', true) = organization.id
     AND current_setting('app.licensee_id', true) = licensee.id
     AND current_setting('app.auth_assurance', true) IN ('mfa-verified','step-up-verified')
     AND current_setting('app.purpose', true) = purpose_code
     AND current_setting('app.request_id', true) ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$';
  IF NOT FOUND THEN
    RAISE EXCEPTION 'C03_POLICY_DENIED' USING ERRCODE = '42501';
  END IF;
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_require_platform_policy_actor(purpose_code text)
RETURNS text
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  actor_id text;
BEGIN
  SELECT actor.id INTO actor_id
    FROM public."User" actor
   WHERE actor.id = current_setting('app.user_id', true)
     AND actor.role::text = current_setting('app.role', true)
     AND actor.role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')
     AND actor."orgId" IS NULL AND actor."licenseeId" IS NULL
     AND actor."isActive" AND actor.status = 'ACTIVE'::public."UserStatus"
     AND actor."deletedAt" IS NULL AND actor."disabledAt" IS NULL
     AND NULLIF(current_setting('app.organization_id', true), '') IS NULL
     AND NULLIF(current_setting('app.licensee_id', true), '') IS NULL
     AND NULLIF(current_setting('app.manufacturer_id', true), '') IS NULL
     AND current_setting('app.auth_assurance', true) IN ('mfa-verified','step-up-verified')
     AND current_setting('app.purpose', true) = purpose_code
     AND current_setting('app.request_id', true) ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$';
  IF actor_id IS NULL THEN
    RAISE EXCEPTION 'C03_POLICY_DENIED' USING ERRCODE = '42501';
  END IF;
  RETURN actor_id;
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_policy_context_valid()
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
  SELECT current_setting('app.purpose', true) LIKE 'incident-response-policy-%'
     AND (
       EXISTS (
       SELECT 1
         FROM public."User" actor
         JOIN public."Licensee" licensee ON licensee.id = current_setting('app.licensee_id', true)
         JOIN public."Organization" organization ON organization.id = licensee."orgId"
        WHERE actor.id = current_setting('app.user_id', true)
          AND actor.role::text = current_setting('app.role', true)
          AND actor.role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')
          AND actor."orgId" IS NULL AND actor."licenseeId" IS NULL
          AND actor."isActive" AND actor.status = 'ACTIVE'::public."UserStatus"
          AND actor."deletedAt" IS NULL AND actor."disabledAt" IS NULL
          AND licensee."isActive" AND licensee."suspendedAt" IS NULL AND organization."isActive"
          AND current_setting('app.organization_id', true) = organization.id
          AND current_setting('app.auth_assurance', true) IN ('mfa-verified','step-up-verified')
       )
       OR EXISTS (
         SELECT 1 FROM public."User" actor
          WHERE actor.id = current_setting('app.user_id', true)
            AND actor.role::text = current_setting('app.role', true)
            AND actor.role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')
            AND actor."orgId" IS NULL AND actor."licenseeId" IS NULL
            AND actor."isActive" AND actor.status = 'ACTIVE'::public."UserStatus"
            AND actor."deletedAt" IS NULL AND actor."disabledAt" IS NULL
            AND NULLIF(current_setting('app.organization_id', true), '') IS NULL
            AND NULLIF(current_setting('app.licensee_id', true), '') IS NULL
            AND NULLIF(current_setting('app.manufacturer_id', true), '') IS NULL
            AND current_setting('app.auth_assurance', true) IN ('mfa-verified','step-up-verified')
       )
     )
     AND current_setting('app.request_id', true) ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_session_valid()
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF session_user <> 'mscqr_rls_cert_app'
     OR current_setting('app.auth_session_verified', true) <> '1'
     OR current_setting('app.c03_session_id', true) IS DISTINCT FROM current_setting('app.auth_session_id', true)
     OR current_setting('app.c03_user_id', true) IS DISTINCT FROM current_setting('app.user_id', true)
  THEN RETURN false; END IF;

  RETURN EXISTS (
    SELECT 1 FROM public."RefreshToken" session_row
     WHERE session_row.id = current_setting('app.c03_session_id', true)
       AND session_row."userId" = current_setting('app.c03_user_id', true)
       AND session_row."sessionCapabilityHash" = current_setting('app.auth_session_hash', true)
       AND session_row."sessionCapabilityHashVersion" = 'sha256-v1'
       AND session_row."sessionCapabilityRevokedAt" IS NULL
       AND session_row."sessionCapabilityExpiresAt" > clock_timestamp()
       AND session_row."revokedAt" IS NULL
       AND session_row."expiresAt" > clock_timestamp()
  );
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_policy_replay(
  command_name text,
  command_payload jsonb
)
RETURNS TABLE(replayed boolean, result jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  key_value text := 'c03-policy:' || current_setting('app.licensee_id', true) || ':' || current_setting('app.user_id', true) || ':' || command_name || ':' || current_setting('app.request_id', true);
  request_hash text := encode(sha256(convert_to(command_payload::text, 'UTF8')), 'hex');
  inserted integer;
  existing record;
BEGIN
  INSERT INTO public."ActionIdempotencyKey"
    (id, "keyHash", action, scope, "requestHash", "expiresAt")
  VALUES
    (gen_random_uuid()::text, key_value, 'c03-policy-' || command_name,
     current_setting('app.licensee_id', true), request_hash, transaction_timestamp() + interval '24 hours')
  ON CONFLICT ("keyHash") DO NOTHING;
  GET DIAGNOSTICS inserted = ROW_COUNT;

  IF inserted = 1 THEN
    RETURN QUERY SELECT false, NULL::jsonb;
    RETURN;
  END IF;

  SELECT idem."requestHash", idem."responsePayload"
    INTO existing
    FROM public."ActionIdempotencyKey" idem
   WHERE idem."keyHash" = key_value
   FOR UPDATE;
  IF existing."requestHash" IS DISTINCT FROM request_hash THEN
    RAISE EXCEPTION 'C03_POLICY_REPLAY_CONFLICT' USING ERRCODE = '40001';
  END IF;
  IF existing."responsePayload" IS NULL THEN
    RAISE EXCEPTION 'C03_POLICY_REPLAY_IN_PROGRESS' USING ERRCODE = '40001';
  END IF;
  RETURN QUERY SELECT true, existing."responsePayload";
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_complete_policy_command(
  command_name text,
  command_result jsonb
)
RETURNS void
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
  UPDATE public."ActionIdempotencyKey"
     SET "statusCode" = 200,
         "responsePayload" = command_result,
         "completedAt" = transaction_timestamp()
   WHERE "keyHash" = 'c03-policy:' || current_setting('app.licensee_id', true) || ':' || current_setting('app.user_id', true) || ':' || command_name || ':' || current_setting('app.request_id', true)
     AND "responsePayload" IS NULL
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_list_policy_rules(
  rule_type_filter text,
  active_filter boolean,
  row_limit integer,
  row_offset integer
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  licensee_id text := current_setting('app.licensee_id', true);
  result jsonb;
BEGIN
  PERFORM 1 FROM app_rls.c03_require_policy_actor(licensee_id, 'incident-response-policy-list');
  IF row_limit < 1 OR row_limit > 200 OR row_offset < 0
     OR (rule_type_filter IS NOT NULL AND rule_type_filter NOT IN (
       'DISTINCT_DEVICES','MULTI_COUNTRY','BURST_SCANS','TOO_MANY_REPORTS'
     )) THEN
    RAISE EXCEPTION 'C03_POLICY_LIST_INVALID' USING ERRCODE = '22023';
  END IF;

  SELECT jsonb_build_object(
    'rules', COALESCE(jsonb_agg(to_jsonb(selected) ORDER BY selected."updatedAt" DESC, selected.id DESC), '[]'::jsonb),
    'total', (SELECT count(*) FROM public."PolicyRule" p
               WHERE p."licenseeId" = licensee_id
                 AND (rule_type_filter IS NULL OR p."ruleType"::text = rule_type_filter)
                 AND (active_filter IS NULL OR p."isActive" = active_filter))
  )
    INTO result
    FROM (
      SELECT p.id, p."orgId", p."licenseeId", p."manufacturerId", p."createdByUserId",
             p.name, p.description, p."ruleType", p."isActive", p.threshold, p."windowMinutes",
             p.severity, p."autoCreateIncident", p."incidentSeverity", p."incidentPriority",
             p."actionConfig", p."createdAt", p."updatedAt",
             CASE WHEN organization.id IS NULL THEN NULL ELSE jsonb_build_object(
               'id', organization.id, 'name', organization.name) END AS organization,
             CASE WHEN licensee.id IS NULL THEN NULL ELSE jsonb_build_object(
               'id', licensee.id, 'name', licensee.name, 'prefix', licensee.prefix) END AS licensee,
             CASE WHEN creator.id IS NULL THEN NULL ELSE jsonb_build_object(
               'id', creator.id, 'email', creator.email, 'name', creator.name) END AS "createdByUser"
        FROM public."PolicyRule" p
        LEFT JOIN public."Organization" organization ON organization.id = p."orgId"
        LEFT JOIN public."Licensee" licensee ON licensee.id = p."licenseeId"
        LEFT JOIN public."User" creator ON creator.id = p."createdByUserId"
       WHERE p."licenseeId" = licensee_id
         AND (rule_type_filter IS NULL OR p."ruleType"::text = rule_type_filter)
         AND (active_filter IS NULL OR p."isActive" = active_filter)
       ORDER BY p."updatedAt" DESC, p.id DESC
       LIMIT row_limit OFFSET row_offset
    ) selected;
  RETURN result;
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_list_platform_policy_rules(
  rule_type_filter text,
  active_filter boolean,
  row_limit integer,
  row_offset integer
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  result jsonb;
BEGIN
  PERFORM app_rls.c03_require_platform_policy_actor('incident-response-policy-list');
  IF row_limit < 1 OR row_limit > 200 OR row_offset < 0
     OR (rule_type_filter IS NOT NULL AND rule_type_filter NOT IN (
       'DISTINCT_DEVICES','MULTI_COUNTRY','BURST_SCANS','TOO_MANY_REPORTS'
     )) THEN
    RAISE EXCEPTION 'C03_POLICY_LIST_INVALID' USING ERRCODE = '22023';
  END IF;

  SELECT jsonb_build_object(
    'rules', COALESCE(jsonb_agg(to_jsonb(selected) ORDER BY selected."updatedAt" DESC, selected.id DESC), '[]'::jsonb),
    'total', (SELECT count(*) FROM public."PolicyRule" p
               WHERE (rule_type_filter IS NULL OR p."ruleType"::text = rule_type_filter)
                 AND (active_filter IS NULL OR p."isActive" = active_filter))
  )
    INTO result
    FROM (
      SELECT p.id, p."orgId", p."licenseeId", p."manufacturerId", p."createdByUserId",
             p.name, p.description, p."ruleType", p."isActive", p.threshold, p."windowMinutes",
             p.severity, p."autoCreateIncident", p."incidentSeverity", p."incidentPriority",
             p."actionConfig", p."createdAt", p."updatedAt",
             CASE WHEN organization.id IS NULL THEN NULL ELSE jsonb_build_object(
               'id', organization.id, 'name', organization.name) END AS organization,
             CASE WHEN licensee.id IS NULL THEN NULL ELSE jsonb_build_object(
               'id', licensee.id, 'name', licensee.name, 'prefix', licensee.prefix) END AS licensee,
             CASE WHEN creator.id IS NULL THEN NULL ELSE jsonb_build_object(
               'id', creator.id, 'email', creator.email, 'name', creator.name) END AS "createdByUser"
        FROM public."PolicyRule" p
        LEFT JOIN public."Organization" organization ON organization.id = p."orgId"
        LEFT JOIN public."Licensee" licensee ON licensee.id = p."licenseeId"
        LEFT JOIN public."User" creator ON creator.id = p."createdByUserId"
       WHERE (rule_type_filter IS NULL OR p."ruleType"::text = rule_type_filter)
         AND (active_filter IS NULL OR p."isActive" = active_filter)
       ORDER BY p."updatedAt" DESC, p.id DESC
       LIMIT row_limit OFFSET row_offset
    ) selected;
  RETURN result;
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_create_policy_rule(input jsonb)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  actor record;
  replay record;
  created record;
  result jsonb;
BEGIN
  IF jsonb_typeof(input) IS DISTINCT FROM 'object'
     OR EXISTS (
       SELECT 1 FROM jsonb_object_keys(input) AS keys(value)
        WHERE value NOT IN ('name','description','ruleType','isActive','threshold','windowMinutes',
                            'severity','autoCreateIncident','incidentSeverity','incidentPriority','actionConfig')
     )
     OR length(btrim(COALESCE(input->>'name',''))) NOT BETWEEN 3 AND 120
     OR (input->>'threshold')::integer NOT BETWEEN 1 AND 100000
     OR (input->>'windowMinutes')::integer NOT BETWEEN 1 AND 43200
     OR input->>'ruleType' NOT IN ('DISTINCT_DEVICES','MULTI_COUNTRY','BURST_SCANS','TOO_MANY_REPORTS')
     OR COALESCE(input->>'severity','MEDIUM') NOT IN ('LOW','MEDIUM','HIGH','CRITICAL')
     OR (input ? 'incidentSeverity' AND input->>'incidentSeverity' IS NOT NULL
         AND input->>'incidentSeverity' NOT IN ('LOW','MEDIUM','HIGH','CRITICAL'))
     OR (input ? 'incidentPriority' AND input->>'incidentPriority' IS NOT NULL
         AND input->>'incidentPriority' NOT IN ('P1','P2','P3','P4')) THEN
    RAISE EXCEPTION 'C03_POLICY_CREATE_INVALID' USING ERRCODE = '22023';
  END IF;

  SELECT * INTO actor
    FROM app_rls.c03_require_policy_actor(
      current_setting('app.licensee_id', true),
      'incident-response-policy-create'
    );
  SELECT * INTO replay FROM app_rls.c03_policy_replay('create', input);
  IF replay.replayed THEN
    RETURN replay.result || '{"__c03Replay":true}'::jsonb;
  END IF;

  INSERT INTO public."PolicyRule"
    (id, "orgId", "licenseeId", "createdByUserId", name, description, "ruleType", "isActive",
     threshold, "windowMinutes", severity, "autoCreateIncident", "incidentSeverity",
     "incidentPriority", "actionConfig", "updatedAt")
  VALUES
    (gen_random_uuid()::text, actor.organization_id, actor.licensee_id, actor.user_id,
     btrim(input->>'name'), NULLIF(input->>'description',''), (input->>'ruleType')::public."PolicyRuleType",
     COALESCE((input->>'isActive')::boolean, true), (input->>'threshold')::integer,
     (input->>'windowMinutes')::integer, COALESCE(input->>'severity','MEDIUM')::public."AlertSeverity",
     COALESCE((input->>'autoCreateIncident')::boolean, false),
     NULLIF(input->>'incidentSeverity','')::public."IncidentSeverity",
     NULLIF(input->>'incidentPriority','')::public."IncidentPriority",
     CASE WHEN input ? 'actionConfig' THEN input->'actionConfig' ELSE NULL END,
     transaction_timestamp())
  RETURNING id, "orgId", "licenseeId", "manufacturerId", "createdByUserId",
    name, description, "ruleType", "isActive", threshold, "windowMinutes",
    severity, "autoCreateIncident", "incidentSeverity", "incidentPriority",
    "actionConfig", "createdAt", "updatedAt" INTO created;
  result := to_jsonb(created);
  PERFORM app_rls.c03_complete_policy_command('create', result);
  RETURN result || '{"__c03Replay":false}'::jsonb;
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_update_policy_rule(policy_rule_id text, patch jsonb)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  replay record;
  updated record;
  result jsonb;
BEGIN
  IF policy_rule_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
     OR jsonb_typeof(patch) IS DISTINCT FROM 'object' OR patch = '{}'::jsonb
     OR EXISTS (
       SELECT 1 FROM jsonb_object_keys(patch) AS keys(value)
        WHERE value NOT IN ('name','description','ruleType','isActive','threshold','windowMinutes',
                            'severity','autoCreateIncident','incidentSeverity','incidentPriority','actionConfig')
     ) THEN
    RAISE EXCEPTION 'C03_POLICY_UPDATE_INVALID' USING ERRCODE = '22023';
  END IF;

  PERFORM 1 FROM app_rls.c03_require_policy_actor(
    current_setting('app.licensee_id', true),
    'incident-response-policy-update'
  );
  PERFORM 1
    FROM public."PolicyRule"
   WHERE id = policy_rule_id
     AND "licenseeId" = current_setting('app.licensee_id', true)
   FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'C03_POLICY_DENIED' USING ERRCODE = '42501'; END IF;
  SELECT * INTO replay FROM app_rls.c03_policy_replay('update:' || policy_rule_id, patch);
  IF replay.replayed THEN
    RETURN replay.result || '{"__c03Replay":true}'::jsonb;
  END IF;

  UPDATE public."PolicyRule" p
     SET name = CASE WHEN patch ? 'name' THEN btrim(patch->>'name') ELSE p.name END,
         description = CASE WHEN patch ? 'description' THEN patch->>'description' ELSE p.description END,
         "ruleType" = CASE WHEN patch ? 'ruleType' THEN (patch->>'ruleType')::public."PolicyRuleType" ELSE p."ruleType" END,
         "isActive" = CASE WHEN patch ? 'isActive' THEN (patch->>'isActive')::boolean ELSE p."isActive" END,
         threshold = CASE WHEN patch ? 'threshold' THEN (patch->>'threshold')::integer ELSE p.threshold END,
         "windowMinutes" = CASE WHEN patch ? 'windowMinutes' THEN (patch->>'windowMinutes')::integer ELSE p."windowMinutes" END,
         severity = CASE WHEN patch ? 'severity' THEN (patch->>'severity')::public."AlertSeverity" ELSE p.severity END,
         "autoCreateIncident" = CASE WHEN patch ? 'autoCreateIncident' THEN (patch->>'autoCreateIncident')::boolean ELSE p."autoCreateIncident" END,
         "incidentSeverity" = CASE WHEN patch ? 'incidentSeverity' THEN NULLIF(patch->>'incidentSeverity','')::public."IncidentSeverity" ELSE p."incidentSeverity" END,
         "incidentPriority" = CASE WHEN patch ? 'incidentPriority' THEN NULLIF(patch->>'incidentPriority','')::public."IncidentPriority" ELSE p."incidentPriority" END,
         "actionConfig" = CASE WHEN patch ? 'actionConfig' THEN patch->'actionConfig' ELSE p."actionConfig" END,
         "updatedAt" = transaction_timestamp()
   WHERE p.id = policy_rule_id
  RETURNING id, "orgId", "licenseeId", "manufacturerId", "createdByUserId",
    name, description, "ruleType", "isActive", threshold, "windowMinutes",
    severity, "autoCreateIncident", "incidentSeverity", "incidentPriority",
    "actionConfig", "createdAt", "updatedAt" INTO updated;
  IF length(updated.name) NOT BETWEEN 3 AND 120 OR updated.threshold NOT BETWEEN 1 AND 100000
     OR updated."windowMinutes" NOT BETWEEN 1 AND 43200 THEN
    RAISE EXCEPTION 'C03_POLICY_UPDATE_INVALID' USING ERRCODE = '22023';
  END IF;
  result := to_jsonb(updated);
  PERFORM app_rls.c03_complete_policy_command('update:' || policy_rule_id, result);
  RETURN result || '{"__c03Replay":false}'::jsonb;
END;
$$;

REVOKE ALL ON FUNCTION app_rls.c03_require_policy_actor(text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_require_platform_policy_actor(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_policy_context_valid() FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_session_valid() FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_policy_replay(text,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_complete_policy_command(text,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_list_policy_rules(text,boolean,integer,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_list_platform_policy_rules(text,boolean,integer,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_create_policy_rule(jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_update_policy_rule(text,jsonb) FROM PUBLIC;

CREATE OR REPLACE FUNCTION app_rls.c03_require_governance_actor(allowed_purposes text[])
RETURNS TABLE(user_id text, organization_id text, licensee_id text)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
DECLARE purpose_code text := current_setting('app.purpose', true);
BEGIN
  IF purpose_code IS NULL OR NOT purpose_code = ANY(allowed_purposes) THEN
    RAISE EXCEPTION 'C03_GOVERNANCE_PURPOSE_DENIED' USING ERRCODE = '42501';
  END IF;
  RETURN QUERY
  SELECT actor.user_id, actor.organization_id, actor.licensee_id
    FROM app_rls.c03_revalidate_actor_scope(
      current_setting('app.licensee_id', true),
      '["SUPER_ADMIN","PLATFORM_SUPER_ADMIN"]'::jsonb,
      'mfa-verified', purpose_code
    ) actor;
  IF NOT FOUND THEN RAISE EXCEPTION 'C03_GOVERNANCE_ACTOR_DENIED' USING ERRCODE = '42501'; END IF;
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_governance_row_visible(target_licensee_id text, allowed_purposes text[])
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
  SELECT current_setting('app.purpose', true) = ANY(allowed_purposes)
     AND EXISTS (
       SELECT 1 FROM app_rls.c03_revalidate_actor_scope(
         target_licensee_id,
         '["SUPER_ADMIN","PLATFORM_SUPER_ADMIN"]'::jsonb,
         'mfa-verified', current_setting('app.purpose', true)
       )
     )
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_governance_replay(command_name text, payload jsonb)
RETURNS TABLE(replayed boolean, result jsonb)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
DECLARE
  key_value text := encode(sha256(convert_to(
    'c03-governance|' || current_setting('app.licensee_id', true) || '|' ||
    current_setting('app.user_id', true) || '|' || command_name || '|' ||
    current_setting('app.request_id', true), 'UTF8')), 'hex');
  request_hash text := encode(sha256(convert_to(COALESCE(payload, '{}'::jsonb)::text, 'UTF8')), 'hex');
  inserted integer;
  prior record;
BEGIN
  INSERT INTO public."ActionIdempotencyKey" (id,"keyHash",action,scope,"requestHash","expiresAt")
  VALUES (gen_random_uuid()::text,key_value,'c03-governance-' || command_name,
          current_setting('app.licensee_id',true),request_hash,transaction_timestamp()+interval '24 hours')
  ON CONFLICT ("keyHash") DO NOTHING;
  GET DIAGNOSTICS inserted = ROW_COUNT;
  IF inserted = 1 THEN RETURN QUERY SELECT false,NULL::jsonb; RETURN; END IF;
  SELECT k."requestHash",k."completedAt",k."responsePayload" INTO prior
    FROM public."ActionIdempotencyKey" k WHERE k."keyHash"=key_value FOR UPDATE;
  IF prior."requestHash" IS DISTINCT FROM request_hash THEN
    RAISE EXCEPTION 'C03_GOVERNANCE_REPLAY_CONFLICT' USING ERRCODE='40001';
  END IF;
  IF prior."completedAt" IS NULL OR prior."responsePayload" IS NULL THEN
    RAISE EXCEPTION 'C03_GOVERNANCE_REPLAY_IN_PROGRESS' USING ERRCODE='40001';
  END IF;
  RETURN QUERY SELECT true,prior."responsePayload";
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_complete_governance_command(command_name text, response jsonb)
RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
  UPDATE public."ActionIdempotencyKey"
     SET "statusCode"=200,"responsePayload"=response,"completedAt"=transaction_timestamp()
   WHERE "keyHash"=encode(sha256(convert_to(
     'c03-governance|' || current_setting('app.licensee_id', true) || '|' ||
     current_setting('app.user_id', true) || '|' || command_name || '|' ||
     current_setting('app.request_id', true), 'UTF8')), 'hex')
     AND "completedAt" IS NULL
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_governance_audit(action_name text, entity_type text, entity_id text, details jsonb)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
DECLARE audit_id text := gen_random_uuid()::text;
BEGIN
  INSERT INTO public."AuditLog" (id,"userId","orgId","licenseeId",action,"entityType","entityId",details)
  VALUES (audit_id,current_setting('app.user_id',true),NULLIF(current_setting('app.organization_id',true),''),
          NULLIF(current_setting('app.licensee_id',true),''),action_name,entity_type,entity_id,
          COALESCE(details,'{}'::jsonb) || jsonb_build_object(
            'requestId',current_setting('app.request_id',true),'purpose',current_setting('app.purpose',true),
            'immutableAttribution',true));
  INSERT INTO public."SecurityEventOutbox" (id,"eventType",payload,"updatedAt")
  VALUES (gen_random_uuid()::text,'C03_GOVERNANCE_AUDIT',jsonb_build_object(
    'auditEventId',audit_id,'action',action_name,'entityType',entity_type,'entityId',entity_id,
    'licenseeId',NULLIF(current_setting('app.licensee_id',true),'')),transaction_timestamp());
  RETURN audit_id;
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_require_governance_approval(action_key text, expected_payload jsonb)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
DECLARE approval record;
DECLARE approval_id text := current_setting('app.c03_approval_id', true);
BEGIN
  IF approval_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' THEN
    RAISE EXCEPTION 'C03_GOVERNANCE_APPROVAL_REQUIRED' USING ERRCODE='42501';
  END IF;
  SELECT a."actionKey",a.status,a."expiresAt",a."licenseeId",a."reviewedByUserId",
    a."requestedByUserId",a."executedAt",a.payload INTO approval
    FROM public."SensitiveActionApproval" a WHERE a.id=approval_id FOR UPDATE;
  IF NOT FOUND OR approval."actionKey" IS DISTINCT FROM action_key
     OR approval.status IS DISTINCT FROM 'APPROVED' OR approval."expiresAt"<=transaction_timestamp()
     OR approval."licenseeId" IS DISTINCT FROM current_setting('app.licensee_id',true)
     OR approval."reviewedByUserId" IS DISTINCT FROM current_setting('app.user_id',true)
     OR approval."requestedByUserId"=approval."reviewedByUserId"
     OR approval."executedAt" IS NOT NULL
     OR jsonb_strip_nulls(approval.payload) IS DISTINCT FROM jsonb_strip_nulls(expected_payload) THEN
    RAISE EXCEPTION 'C03_GOVERNANCE_APPROVAL_INVALID' USING ERRCODE='42501';
  END IF;
  RETURN approval_id;
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_mark_governance_approval_executed(approval_id text)
RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
  UPDATE public."SensitiveActionApproval"
     SET status='EXECUTED',"executedByUserId"=current_setting('app.user_id',true),
         "executedAt"=transaction_timestamp(),"updatedAt"=transaction_timestamp()
   WHERE id=approval_id AND status='APPROVED' AND "executedAt" IS NULL
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_list_tenant_feature_flags(target_licensee_id text)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
DECLARE scope record;
BEGIN
  IF current_setting('app.purpose', true) IS DISTINCT FROM 'governance-feature-flag-list'
     OR current_setting('app.c03_role', true) NOT IN ('SUPER_ADMIN', 'PLATFORM_SUPER_ADMIN')
     OR current_setting('app.c03_assurance', true) IS DISTINCT FROM 'ADMIN_MFA' THEN
    RAISE EXCEPTION 'C03_GOVERNANCE_ACTOR_DENIED' USING ERRCODE = '42501';
  END IF;
  PERFORM app_rls.c03_bind_operation('governance-feature-flag-list', target_licensee_id);
  SELECT * INTO scope FROM app_rls.c03_assert_live_licensee_scope(
    target_licensee_id,
    current_setting('app.c03_role', true),
    NULLIF(current_setting('app.c03_actor_organization_id', true), ''),
    NULLIF(current_setting('app.c03_actor_licensee_id', true), '')
  );
  IF NOT FOUND THEN
    RAISE EXCEPTION 'C03_GOVERNANCE_ACTOR_DENIED' USING ERRCODE = '42501';
  END IF;
  RETURN COALESCE((
    SELECT jsonb_agg(jsonb_build_object(
      'id', f.id,
      'licenseeId', f."licenseeId",
      'key', f.key,
      'enabled', f.enabled,
      'updatedAt', f."updatedAt"
    ) ORDER BY f.key, f.id)
      FROM public."TenantFeatureFlag" f
     WHERE f."licenseeId" = scope.licensee_id
  ), '[]'::jsonb);
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_upsert_tenant_feature_flag(key text, enabled boolean, config jsonb)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
DECLARE actor record; replay record; row record; response jsonb; approval_id text;
DECLARE payload jsonb;
BEGIN
  SELECT * INTO actor FROM app_rls.c03_require_governance_actor(ARRAY['sensitive-action-approval-approve']);
  IF key !~ '^[a-z0-9][a-z0-9_.-]{1,119}$' OR (config IS NOT NULL AND jsonb_typeof(config)<>'object')
     OR octet_length(COALESCE(config,'{}'::jsonb)::text)>65536 THEN
    RAISE EXCEPTION 'C03_FEATURE_FLAG_INVALID' USING ERRCODE='22023';
  END IF;
  payload := jsonb_build_object('licenseeId',actor.licensee_id,'key',key,'enabled',enabled,'config',config);
  SELECT * INTO replay FROM app_rls.c03_governance_replay('feature-flag:'||key,payload);
  IF replay.replayed THEN RETURN replay.result || '{"__c03Replay":true}'::jsonb; END IF;
  approval_id := app_rls.c03_require_governance_approval('FEATURE_FLAG_UPSERT',payload);
  INSERT INTO public."TenantFeatureFlag" (id,"licenseeId",key,enabled,config,"updatedByUserId","updatedAt")
  VALUES (gen_random_uuid()::text,actor.licensee_id,key,enabled,config,actor.user_id,transaction_timestamp())
  ON CONFLICT ("licenseeId",key) DO UPDATE SET enabled=EXCLUDED.enabled,config=EXCLUDED.config,
    "updatedByUserId"=EXCLUDED."updatedByUserId","updatedAt"=transaction_timestamp()
  RETURNING id,"licenseeId",key,enabled,config,"updatedByUserId","createdAt","updatedAt" INTO row;
  response := to_jsonb(row);
  PERFORM app_rls.c03_governance_audit('TENANT_FEATURE_FLAG_UPSERTED','TenantFeatureFlag',row.id,
    jsonb_build_object('key',key,'enabled',enabled,'approvalId',approval_id));
  PERFORM app_rls.c03_mark_governance_approval_executed(approval_id);
  PERFORM app_rls.c03_complete_governance_command('feature-flag:'||key,response);
  RETURN response || '{"__c03Replay":false}'::jsonb;
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_get_or_create_retention_policy()
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
DECLARE actor record; row record; inserted boolean := false;
BEGIN
  SELECT * INTO actor FROM app_rls.c03_require_governance_actor(ARRAY[
    'governance-retention-policy-read','governance-retention-preview','governance-compliance-report',
    'compliance-pack-start','compliance-pack-download','compliance-pack-rebuild-read',
    'sensitive-action-approval-approve'
  ]);
  SELECT p.id,p."licenseeId",p."retentionDays",p."purgeEnabled",p."exportBeforePurge",
    p."legalHoldTags",p."updatedByUserId",p."createdAt",p."updatedAt" INTO row
    FROM public."EvidenceRetentionPolicy" p WHERE p."licenseeId"=actor.licensee_id FOR UPDATE;
  IF NOT FOUND THEN
    INSERT INTO public."EvidenceRetentionPolicy"
      (id,"licenseeId","retentionDays","purgeEnabled","exportBeforePurge","legalHoldTags","updatedAt")
    VALUES (gen_random_uuid()::text,actor.licensee_id,180,false,true,ARRAY['legal_hold','compliance_hold'],transaction_timestamp())
    RETURNING id,"licenseeId","retentionDays","purgeEnabled","exportBeforePurge",
      "legalHoldTags","updatedByUserId","createdAt","updatedAt" INTO row;
    inserted := true;
  END IF;
  IF inserted THEN
    PERFORM app_rls.c03_governance_audit('EVIDENCE_RETENTION_POLICY_CREATED','EvidenceRetentionPolicy',row.id,'{}'::jsonb);
  END IF;
  RETURN to_jsonb(row);
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_run_retention_lifecycle(mode text, approval_id text)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
DECLARE actor record; replay record; policy record;
DECLARE job record; cutoff_at timestamptz; evaluated integer; eligible integer; response jsonb;
BEGIN
  IF mode NOT IN ('PREVIEW','APPLY') THEN RAISE EXCEPTION 'C03_RETENTION_MODE_INVALID' USING ERRCODE='22023'; END IF;
  IF mode='APPLY' THEN
    RAISE EXCEPTION 'C03_RETENTION_APPLY_REQUIRES_MAKER_CHECKER_EXECUTOR' USING ERRCODE='42501';
  END IF;
  IF approval_id IS NOT NULL THEN RAISE EXCEPTION 'C03_RETENTION_PREVIEW_APPROVAL_FORBIDDEN' USING ERRCODE='22023'; END IF;
  SELECT * INTO actor FROM app_rls.c03_require_governance_actor(ARRAY['governance-retention-preview']);
  SELECT * INTO replay FROM app_rls.c03_governance_replay('retention-preview','{"mode":"PREVIEW"}'::jsonb);
  IF replay.replayed THEN RETURN replay.result || '{"__c03Replay":true}'::jsonb; END IF;
  PERFORM app_rls.c03_get_or_create_retention_policy();
  SELECT p.id,p."licenseeId",p."retentionDays",p."purgeEnabled",p."exportBeforePurge",
    p."legalHoldTags",p."updatedByUserId",p."createdAt",p."updatedAt" INTO policy
    FROM public."EvidenceRetentionPolicy" p WHERE p."licenseeId"=actor.licensee_id FOR UPDATE;
  cutoff_at := transaction_timestamp()-make_interval(days=>policy."retentionDays");
  SELECT count(*),count(*) FILTER (WHERE NOT (COALESCE(incident.tags,ARRAY[]::text[]) && policy."legalHoldTags"))
    INTO evaluated,eligible
    FROM public."IncidentEvidence" evidence JOIN public."Incident" incident ON incident.id=evidence."incidentId"
   WHERE incident."licenseeId"=actor.licensee_id AND evidence."createdAt"<cutoff_at;
  INSERT INTO public."EvidenceRetentionJob"
    (id,"licenseeId",status,mode,"cutoffAt","recordsEvaluated","recordsPurged","recordsExported",summary,
     "startedByUserId","startedAt","finishedAt")
  VALUES (gen_random_uuid()::text,actor.licensee_id,'PREVIEW','PREVIEW',cutoff_at,evaluated,0,0,
    jsonb_build_object('eligibleCount',eligible,'skippedDueToLegalHold',evaluated-eligible,
      'purgeEnabled',policy."purgeEnabled"),actor.user_id,transaction_timestamp(),transaction_timestamp())
  RETURNING id,"licenseeId",status,mode,"cutoffAt","recordsEvaluated","recordsPurged",
    "recordsExported",summary,"startedByUserId","startedAt","finishedAt","createdAt" INTO job;
  response := jsonb_build_object('job',to_jsonb(job),'policy',to_jsonb(policy),'cutoffAt',cutoff_at,
    'evaluated',evaluated,'eligible',eligible,'purged',0,'exported',0);
  PERFORM app_rls.c03_governance_audit('EVIDENCE_RETENTION_JOB_PREVIEWED','EvidenceRetentionJob',job.id,
    jsonb_build_object('evaluated',evaluated,'eligible',eligible));
  PERFORM app_rls.c03_complete_governance_command('retention-preview',response);
  RETURN response || '{"__c03Replay":false}'::jsonb;
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_generate_compliance_report(from_at timestamptz, to_at timestamptz)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
DECLARE actor record; replay record; policy record; response jsonb;
DECLARE total_incidents integer; resolved_incidents integer; breached_incidents integer; fraud_reports integer;
DECLARE audit_events integer; failed_logins integer; handoff jsonb; payload jsonb;
BEGIN
  IF (from_at IS NOT NULL AND to_at IS NOT NULL AND from_at>to_at)
     OR (from_at IS NOT NULL AND to_at IS NOT NULL AND to_at-from_at>interval '366 days') THEN
    RAISE EXCEPTION 'C03_COMPLIANCE_RANGE_INVALID' USING ERRCODE='22023';
  END IF;
  SELECT * INTO actor FROM app_rls.c03_require_governance_actor(ARRAY[
    'governance-compliance-report','compliance-pack-start','compliance-pack-download','compliance-pack-rebuild-read']);
  payload := jsonb_build_object('from',from_at,'to',to_at);
  SELECT * INTO replay FROM app_rls.c03_governance_replay('compliance-report',payload);
  IF replay.replayed THEN RETURN replay.result || '{"__c03Replay":true}'::jsonb; END IF;
  PERFORM app_rls.c03_get_or_create_retention_policy();
  SELECT p."retentionDays",p."purgeEnabled",p."exportBeforePurge",p."legalHoldTags" INTO policy
    FROM public."EvidenceRetentionPolicy" p WHERE p."licenseeId"=actor.licensee_id;
  SELECT count(*),count(*) FILTER (WHERE status::text IN ('RESOLVED','CLOSED')),
         count(*) FILTER (WHERE "slaDueAt"<transaction_timestamp() AND status::text NOT IN ('RESOLVED','CLOSED')),
         count(*) FILTER (WHERE "reportedBy"='CUSTOMER')
    INTO total_incidents,resolved_incidents,breached_incidents,fraud_reports
    FROM public."Incident" WHERE "licenseeId"=actor.licensee_id
      AND (from_at IS NULL OR "createdAt">=from_at) AND (to_at IS NULL OR "createdAt"<=to_at);
  SELECT count(*),count(*) FILTER (WHERE action LIKE '%LOGIN_FAILED%') INTO audit_events,failed_logins
    FROM public."AuditLog" WHERE "licenseeId"=actor.licensee_id
      AND (from_at IS NULL OR "createdAt">=from_at) AND (to_at IS NULL OR "createdAt"<=to_at);
  SELECT COALESCE(jsonb_object_agg(stage,row_count),'{}'::jsonb) INTO handoff FROM (
    SELECT h."currentStage"::text stage,count(*) row_count FROM public."IncidentHandoff" h
    JOIN public."Incident" i ON i.id=h."incidentId" WHERE i."licenseeId"=actor.licensee_id GROUP BY h."currentStage"
  ) grouped;
  response := jsonb_build_object(
    'generatedAt',transaction_timestamp(),'appName','MSCQR',
    'scope',jsonb_build_object('licenseeId',actor.licensee_id,'from',from_at,'to',to_at),
    'compliance',jsonb_build_object(
      'ukGdpr',jsonb_build_object('statement','Personal data is processed in accordance with UK GDPR and the Data Protection Act 2018.','contact','support@mscqr.local'),
      'securityAccess',jsonb_build_object('roleBasedAccess',jsonb_build_array('Super Admin','Licensee','Manufacturer'),'httpsEncrypted',true,'passwordHandling','Secure password hashing and OTP controls are enforced.','auditLogging',true),
      'incidentResponse',jsonb_build_object('workflow',jsonb_build_array('report intake','review','containment','documentation','resolution')),
      'qrUsagePolicy',jsonb_build_object('uniqueTraceable',true,'singleUseWhereApplicable',true,'nonDuplicationRule',true),
      'auditRetentionDays',policy."retentionDays",
      'hosting',jsonb_build_object('provider','Cloud provider not set','disclaimer','Service is provided on a best-effort basis with reasonable security controls.')),
    'metrics',jsonb_build_object(
      'incidents',jsonb_build_object('total',total_incidents,'resolved',resolved_incidents,'slaBreachedOpen',breached_incidents,'handoff',handoff),
      'fraudReports',fraud_reports,'auditEvents',audit_events,'failedLogins',failed_logins,
      'retention',jsonb_build_object('retentionDays',policy."retentionDays",'purgeEnabled',policy."purgeEnabled",
        'exportBeforePurge',policy."exportBeforePurge",'legalHoldTags',policy."legalHoldTags")),
    'controls',jsonb_build_array(
      jsonb_build_object('controlId','SOC2-CC7.2','framework','SOC2','title','Security event detection and response','status',CASE WHEN breached_incidents>5 THEN 'ATTENTION' ELSE 'EFFECTIVE' END,'evidenceRefs',jsonb_build_array('metrics.incidents.slaBreachedOpen','metrics.incidents.total','metrics.incidents.resolved')),
      jsonb_build_object('controlId','SOC2-CC6.1','framework','SOC2','title','Logical access and authentication controls','status',CASE WHEN failed_logins>=20 THEN 'ATTENTION' WHEN failed_logins>=5 THEN 'MONITOR' ELSE 'EFFECTIVE' END,'evidenceRefs',jsonb_build_array('metrics.failedLogins','compliance.securityAccess')),
      jsonb_build_object('controlId','ISO27001-A.5.23','framework','ISO27001','title','Information security for cloud services and logging','status',CASE WHEN audit_events>0 THEN 'EFFECTIVE' ELSE 'ATTENTION' END,'evidenceRefs',jsonb_build_array('metrics.auditEvents','scope.licenseeId','generatedAt')),
      jsonb_build_object('controlId','ISO27001-A.8.10','framework','ISO27001','title','Information retention and deletion','status',CASE WHEN policy."retentionDays">=180 THEN 'EFFECTIVE' ELSE 'MONITOR' END,'evidenceRefs',jsonb_build_array('compliance.auditRetentionDays','metrics.retention'))),
    'controlSummary',jsonb_build_object('EFFECTIVE',0,'MONITOR',0,'ATTENTION',0));
  PERFORM app_rls.c03_governance_audit('COMPLIANCE_REPORT_SNAPSHOT','ComplianceReport',actor.licensee_id,
    jsonb_build_object('from',from_at,'to',to_at,'incidents',total_incidents));
  PERFORM app_rls.c03_complete_governance_command('compliance-report',response);
  RETURN response || '{"__c03Replay":false}'::jsonb;
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_update_retention_policy(patch jsonb)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
DECLARE actor record; replay record; row record; response jsonb; approval_id text; payload jsonb;
BEGIN
  SELECT * INTO actor FROM app_rls.c03_require_governance_actor(ARRAY['sensitive-action-approval-approve']);
  IF jsonb_typeof(patch)<>'object' OR patch='{}'::jsonb OR EXISTS (
    SELECT 1 FROM jsonb_object_keys(patch) k WHERE k NOT IN ('retentionDays','purgeEnabled','exportBeforePurge','legalHoldTags'))
     OR (patch ? 'retentionDays' AND (patch->>'retentionDays')::integer NOT BETWEEN 1 AND 3650)
     OR (patch ? 'legalHoldTags' AND (jsonb_typeof(patch->'legalHoldTags')<>'array' OR jsonb_array_length(patch->'legalHoldTags')>64)) THEN
    RAISE EXCEPTION 'C03_RETENTION_POLICY_INVALID' USING ERRCODE='22023';
  END IF;
  payload := jsonb_build_object('licenseeId',actor.licensee_id) || patch;
  SELECT * INTO replay FROM app_rls.c03_governance_replay('retention-policy-update',payload);
  IF replay.replayed THEN RETURN replay.result || '{"__c03Replay":true}'::jsonb; END IF;
  approval_id := app_rls.c03_require_governance_approval('RETENTION_POLICY_PATCH',payload);
  PERFORM app_rls.c03_get_or_create_retention_policy();
  UPDATE public."EvidenceRetentionPolicy" p SET
    "retentionDays"=CASE WHEN patch?'retentionDays' THEN (patch->>'retentionDays')::integer ELSE p."retentionDays" END,
    "purgeEnabled"=CASE WHEN patch?'purgeEnabled' THEN (patch->>'purgeEnabled')::boolean ELSE p."purgeEnabled" END,
    "exportBeforePurge"=CASE WHEN patch?'exportBeforePurge' THEN (patch->>'exportBeforePurge')::boolean ELSE p."exportBeforePurge" END,
    "legalHoldTags"=CASE WHEN patch?'legalHoldTags' THEN ARRAY(SELECT jsonb_array_elements_text(patch->'legalHoldTags')) ELSE p."legalHoldTags" END,
    "updatedByUserId"=actor.user_id,"updatedAt"=transaction_timestamp()
  WHERE p."licenseeId"=actor.licensee_id
  RETURNING id,"licenseeId","retentionDays","purgeEnabled","exportBeforePurge",
    "legalHoldTags","updatedByUserId","createdAt","updatedAt" INTO row;
  response := to_jsonb(row);
  PERFORM app_rls.c03_governance_audit('EVIDENCE_RETENTION_POLICY_UPDATED','EvidenceRetentionPolicy',row.id,
    jsonb_build_object('approvalId',approval_id,'changedFields',(SELECT jsonb_agg(k) FROM jsonb_object_keys(patch) k)));
  PERFORM app_rls.c03_mark_governance_approval_executed(approval_id);
  PERFORM app_rls.c03_complete_governance_command('retention-policy-update',response);
  RETURN response || '{"__c03Replay":false}'::jsonb;
END;
$$;

REVOKE ALL ON FUNCTION app_rls.c03_require_governance_actor(text[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_governance_row_visible(text,text[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_governance_replay(text,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_complete_governance_command(text,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_governance_audit(text,text,text,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_require_governance_approval(text,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_mark_governance_approval_executed(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_list_tenant_feature_flags(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_upsert_tenant_feature_flag(text,boolean,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_get_or_create_retention_policy() FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_run_retention_lifecycle(text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_generate_compliance_report(timestamptz,timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_update_retention_policy(jsonb) FROM PUBLIC;

CREATE OR REPLACE FUNCTION app_rls.risk_analytics_session_valid()
RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $fn$
BEGIN
  IF session_user <> 'mscqr_rls_cert_app'
     OR current_setting('app.auth_session_verified',true) <> '1'
     OR current_setting('app.risk_analytics_operation',true) <> 'snapshot'
  THEN RETURN false; END IF;

  RETURN EXISTS (
    SELECT 1
      FROM public."RefreshToken" s
     WHERE s.id=current_setting('app.auth_session_id',true)
       AND s."userId"=current_setting('app.user_id',true)
       AND s."sessionCapabilityHash"=current_setting('app.auth_session_hash',true)
       AND s."sessionCapabilityHashVersion"='sha256-v1'
       AND s."sessionCapabilityRevokedAt" IS NULL
       AND s."sessionCapabilityExpiresAt">clock_timestamp()
       AND s."revokedAt" IS NULL
       AND s."expiresAt">clock_timestamp()
  );
END
$fn$;

REVOKE ALL ON FUNCTION app_rls.risk_analytics_session_valid() FROM PUBLIC;

CREATE OR REPLACE FUNCTION app_rls.risk_analytics_snapshot(
  p_capability text,
  p_purpose text,
  p_request_id text,
  p_licensee_id text,
  p_expected_user_id text,
  p_lookback_hours integer,
  p_limit integer,
  p_checked_at timestamp without time zone
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $fn$
DECLARE
  actor record;
  tenant record;
  result jsonb;
  policy_payload jsonb;
  batches_payload jsonb;
  scans_payload jsonb;
  alerts_payload jsonb;
  qrs_payload jsonb;
  manufacturers_payload jsonb;
  manufacturer_links_payload jsonb;
  incidents_payload jsonb;
  policy_rules_payload jsonb;
  audit_id text := gen_random_uuid()::text;
  scan_count integer;
  batch_count integer;
  alert_count integer;
BEGIN
  IF p_purpose <> 'tenant-risk-analytics'
     OR p_request_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
     OR p_licensee_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
     OR p_expected_user_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
     OR p_lookback_hours NOT BETWEEN 1 AND 720
     OR p_limit NOT BETWEEN 1 AND 200
     OR p_checked_at IS NULL
  THEN RAISE EXCEPTION 'RISK_ANALYTICS_DENIED' USING ERRCODE='42501'; END IF;

  SELECT * INTO STRICT actor
    FROM app_auth.require_authenticated_session(p_capability,p_purpose,p_request_id);
  IF actor."userId" IS DISTINCT FROM p_expected_user_id
     OR actor.role NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN','LICENSEE_ADMIN')
     OR (actor.role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') AND
         (actor."organizationId" IS NOT NULL OR actor."licenseeId" IS NOT NULL OR actor.assurance <> 'ADMIN_MFA'))
     OR (actor.role='LICENSEE_ADMIN' AND actor."licenseeId" IS DISTINCT FROM p_licensee_id)
  THEN RAISE EXCEPTION 'RISK_ANALYTICS_DENIED' USING ERRCODE='42501'; END IF;

  PERFORM set_config('app.risk_analytics_operation','snapshot',true),
          set_config('app.risk_analytics_user_id',actor."userId",true),
          set_config('app.risk_analytics_licensee_id',p_licensee_id,true),
          set_config('app.risk_analytics_organization_id','',true),
          set_config('app.risk_analytics_audit_id',audit_id,true);

  SELECT l.id,l."orgId" INTO tenant
    FROM public."Licensee" l
   WHERE l.id=p_licensee_id AND l."isActive" AND l."suspendedAt" IS NULL;
  IF NOT FOUND THEN RAISE EXCEPTION 'RISK_ANALYTICS_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM set_config('app.risk_analytics_organization_id',tenant."orgId",true);
  IF NOT EXISTS (SELECT 1 FROM public."Organization" o WHERE o.id=tenant."orgId" AND o."isActive")
     OR (actor.role='LICENSEE_ADMIN' AND actor."organizationId" IS DISTINCT FROM tenant."orgId")
  THEN RAISE EXCEPTION 'RISK_ANALYTICS_DENIED' USING ERRCODE='42501'; END IF;

  SELECT count(*) INTO batch_count FROM public."Batch" b WHERE b."licenseeId"=p_licensee_id;
  SELECT count(*) INTO scan_count FROM public."QrScanLog" s
   WHERE s."licenseeId"=p_licensee_id AND s."batchId" IS NOT NULL
     AND s."scannedAt" BETWEEN p_checked_at-(p_lookback_hours||' hours')::interval AND p_checked_at;
  SELECT count(*) INTO alert_count FROM public."PolicyAlert" a
   WHERE a."licenseeId"=p_licensee_id AND a."batchId" IS NOT NULL AND a."acknowledgedAt" IS NULL;
  IF batch_count>5000 OR scan_count>50000 OR alert_count>50000 THEN
    RAISE EXCEPTION 'RISK_ANALYTICS_DIMENSION_LIMIT' USING ERRCODE='22023';
  END IF;

  SELECT COALESCE(jsonb_build_object(
      'multiScanThreshold',p."multiScanThreshold",
      'geoDriftThresholdKm',p."geoDriftThresholdKm",
      'velocitySpikeThresholdPerMin',p."velocitySpikeThresholdPerMin"
    ),'{"multiScanThreshold":2,"geoDriftThresholdKm":300,"velocitySpikeThresholdPerMin":80}'::jsonb)
    INTO policy_payload
    FROM public."SecurityPolicy" p WHERE p."licenseeId"=p_licensee_id LIMIT 1;
  policy_payload := COALESCE(policy_payload,'{"multiScanThreshold":2,"geoDriftThresholdKm":300,"velocitySpikeThresholdPerMin":80}'::jsonb);

  SELECT COALESCE(jsonb_agg(jsonb_build_object(
      'id',b.id,'name',b.name,'licenseeId',b."licenseeId",'manufacturerId',b."manufacturerId"
    ) ORDER BY b.id),'[]'::jsonb)
    INTO batches_payload FROM public."Batch" b WHERE b."licenseeId"=p_licensee_id;

  SELECT COALESCE(jsonb_agg(jsonb_build_object(
      'id',s.id,'licenseeId',s."licenseeId",'qrCodeId',s."qrCodeId",'batchId',s."batchId",
      'latitude',s.latitude,'longitude',s.longitude,'scannedAt',s."scannedAt",
      'qrCode',CASE WHEN q.id IS NULL THEN NULL ELSE jsonb_build_object('id',q.id,'licenseeId',q."licenseeId",'batchId',q."batchId") END,
      'batch',CASE WHEN b.id IS NULL THEN NULL ELSE jsonb_build_object('id',b.id,'licenseeId',b."licenseeId") END
    ) ORDER BY s."batchId",s."qrCodeId",s."scannedAt",s.id),'[]'::jsonb)
    INTO scans_payload
    FROM public."QrScanLog" s
    LEFT JOIN public."QRCode" q ON q.id=s."qrCodeId"
    LEFT JOIN public."Batch" b ON b.id=s."batchId"
   WHERE s."licenseeId"=p_licensee_id AND s."batchId" IS NOT NULL
     AND s."scannedAt" BETWEEN p_checked_at-(p_lookback_hours||' hours')::interval AND p_checked_at;

  SELECT COALESCE(jsonb_agg(jsonb_build_object(
      'id',a.id,'licenseeId',a."licenseeId",'batchId',a."batchId",'qrCodeId',a."qrCodeId",
      'manufacturerId',a."manufacturerId",'incidentId',a."incidentId",
      'policyRuleId',a."policyRuleId",'acknowledgedAt',a."acknowledgedAt"
    ) ORDER BY a."batchId",a.id),'[]'::jsonb)
    INTO alerts_payload FROM public."PolicyAlert" a
   WHERE a."licenseeId"=p_licensee_id AND a."batchId" IS NOT NULL AND a."acknowledgedAt" IS NULL;

  SELECT COALESCE(jsonb_agg(jsonb_build_object(
      'id',q.id,'licenseeId',q."licenseeId",'batchId',q."batchId",'scanCount',q."scanCount"
    ) ORDER BY q.id),'[]'::jsonb)
    INTO qrs_payload FROM public."QRCode" q WHERE q."licenseeId"=p_licensee_id;

  SELECT COALESCE(jsonb_agg(jsonb_build_object('id',u.id,'name',u.name) ORDER BY u.id),'[]'::jsonb)
    INTO manufacturers_payload
    FROM public."User" u
   WHERE u.role IN (
       'MANUFACTURER_ADMIN'::public."UserRole",
       'MANUFACTURER'::public."UserRole",
       'MANUFACTURER_USER'::public."UserRole"
     )
     AND u."isActive" AND u.status='ACTIVE'::public."UserStatus"
     AND u."deletedAt" IS NULL AND u."disabledAt" IS NULL
     AND EXISTS (SELECT 1 FROM public."ManufacturerLicenseeLink" ml
       WHERE ml."manufacturerId"=u.id AND ml."licenseeId"=p_licensee_id);

  SELECT COALESCE(jsonb_agg(jsonb_build_object(
      'manufacturerId',ml."manufacturerId",'licenseeId',ml."licenseeId"
    ) ORDER BY ml."manufacturerId"),'[]'::jsonb)
    INTO manufacturer_links_payload
    FROM public."ManufacturerLicenseeLink" ml WHERE ml."licenseeId"=p_licensee_id;

  SELECT COALESCE(jsonb_agg(jsonb_build_object('id',i.id,'licenseeId',i."licenseeId") ORDER BY i.id),'[]'::jsonb)
    INTO incidents_payload FROM public."Incident" i WHERE i."licenseeId"=p_licensee_id;

  SELECT COALESCE(jsonb_agg(jsonb_build_object(
      'id',r.id,'licenseeId',r."licenseeId",'orgId',r."orgId",
      'manufacturerId',r."manufacturerId",'isActive',r."isActive"
    ) ORDER BY r.id),'[]'::jsonb)
    INTO policy_rules_payload
    FROM public."PolicyRule" r
   WHERE r."licenseeId"=p_licensee_id OR r."orgId"=tenant."orgId"
      OR EXISTS (SELECT 1 FROM public."ManufacturerLicenseeLink" ml
        WHERE ml."licenseeId"=p_licensee_id AND ml."manufacturerId"=r."manufacturerId");

  result := jsonb_build_object(
    'organizationId',tenant."orgId",
    'policy',policy_payload,
    'batches',batches_payload,
    'scanLogs',scans_payload,
    'alerts',alerts_payload,
    'qrs',qrs_payload,
    'manufacturers',manufacturers_payload,
    'manufacturerLinks',manufacturer_links_payload,
    'incidents',incidents_payload,
    'policyRules',policy_rules_payload
  );

  INSERT INTO public."AuditLog"
    (id,"userId","orgId","licenseeId",action,"entityType","entityId",details)
  VALUES (audit_id,actor."userId",tenant."orgId",p_licensee_id,'RISK_ANALYTICS_READ','Licensee',p_licensee_id,
    jsonb_build_object('requestId',p_request_id,'purposeCode',p_purpose,'lookbackHours',p_lookback_hours,
      'limit',p_limit,'analyzedBatchCount',batch_count,'scanRows',scan_count,'openAlertRows',alert_count,
      'workflowId','workflow-internal-backend-src-services-analytics-service-ts-get-risk-analytics',
      'route','GET /api/analytics/risk-scores'));

  RETURN result;
END
$fn$;

REVOKE ALL ON FUNCTION app_rls.risk_analytics_snapshot(text,text,text,text,text,integer,integer,timestamp without time zone) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_rls.c02_fraud_report_network_details(text[]) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.c02_respond_fraud_report(text,text,text,boolean) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.c03_add_incident_evidence(text,jsonb,text) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.c03_approve_sensitive_action_approval(text,text) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.c03_bind_sensitive_approval_actor(text,text,text,text) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.c03_build_incident_evidence_audit_snapshot(text) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.c03_complete_compliance_pack_job(text,text,text,text,jsonb) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.c03_complete_compliance_pack_rebuild(text,text,text,text,jsonb) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.c03_create_policy_rule(jsonb) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.c03_create_sensitive_action_approval(jsonb) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.c03_fail_compliance_pack_job(text,text,text,text,text) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.c03_generate_compliance_report(timestamp with time zone,timestamp with time zone) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.c03_get_compliance_pack_job(text,text,text,text) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.c03_get_incident_detail(text) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.c03_get_incident_evidence_file_by_storage_key(text,text,text,text) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.c03_get_or_create_retention_policy() TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.c03_link_ir_alert_incident(text,text,text,text,text) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.c03_list_incidents(jsonb,integer,integer) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.c03_list_ir_alerts(text,text,text,jsonb,integer,integer) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.c03_list_platform_policy_rules(text,boolean,integer,integer) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.c03_list_policy_rules(text,boolean,integer,integer) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.c03_list_sensitive_action_approvals(text,integer,integer) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.c03_list_tenant_feature_flags(text) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.c03_patch_incident(text,jsonb) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.c03_record_incident_event(text,text,jsonb) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.c03_reject_sensitive_action_approval(text,text) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.c03_require_authenticated_actor(text,text,text) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.c03_revalidate_compliance_pack_job_actor_scope(text,text,text,text) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.c03_run_retention_lifecycle(text,text) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.c03_start_compliance_pack_job(text,text,text,text,text,timestamp with time zone,timestamp with time zone) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.c03_update_policy_rule(text,jsonb) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.c03_update_retention_policy(jsonb) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.c03_upsert_tenant_feature_flag(text,boolean,jsonb) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.platform_audit_log_details(text[]) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.risk_analytics_snapshot(text,text,text,text,text,integer,integer,timestamp without time zone) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.c03_assert_restricted_identity(text) TO "mscqr_rls_cert_preauth";
GRANT EXECUTE ON FUNCTION app_rls.c03_compute_incident_severity(text,jsonb) TO "mscqr_rls_cert_preauth";
GRANT EXECUTE ON FUNCTION app_rls.c03_compute_incident_spam_signal(text,jsonb) TO "mscqr_rls_cert_preauth";
GRANT EXECUTE ON FUNCTION app_rls.c03_create_public_incident_report(text,jsonb,jsonb,text) TO "mscqr_rls_cert_preauth";
GRANT EXECUTE ON FUNCTION app_rls.c03_assert_restricted_identity(text) TO "mscqr_rls_cert_worker";
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
    SELECT jsonb_build_object('licensee',jsonb_build_object(
      'id',l.id,'orgId',l."orgId",'name',l.name,'prefix',l.prefix,'description',l.description,
      'brandName',l."brandName",'location',l.location,'website',l.website,'supportEmail',l."supportEmail",
      'supportPhone',l."supportPhone",'metadata',l.metadata,'isActive',l."isActive",
      'suspendedAt',l."suspendedAt",'suspendedReason',l."suspendedReason",
      'createdAt',l."createdAt",'updatedAt',l."updatedAt"
    ),'adminUser',(
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
      SELECT jsonb_build_object('licensee',jsonb_build_object(
        'id',l.id,'orgId',l."orgId",'name',l.name,'prefix',l.prefix,'description',l.description,
        'brandName',l."brandName",'location',l.location,'website',l.website,'supportEmail',l."supportEmail",
        'supportPhone',l."supportPhone",'metadata',l.metadata,'isActive',l."isActive",
        'suspendedAt',l."suspendedAt",'suspendedReason',l."suspendedReason",
        'createdAt',l."createdAt",'updatedAt',l."updatedAt"
      )) INTO result FROM public."Licensee" l WHERE l.id=target;
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
  exported_count bigint; export_status text; export_query text; result jsonb;
BEGIN
  IF p_purpose<>'qr-batch-command' OR p_operation NOT IN ('CREATE_BATCH','DELETE_BATCH','BULK_DELETE_BATCHES','ASSIGN_MANUFACTURER','RENAME_BATCH','AUDIT_CODE_EXPORT')
     OR jsonb_typeof(p_payload)<>'object' THEN
    RAISE EXCEPTION 'QR_BOUNDARY_DENIED' USING ERRCODE='42501';
  END IF;
  SELECT * INTO STRICT actor FROM app_rls.qr_bind_actor(p_capability,p_purpose,p_request_id,NULL);

  IF p_operation='AUDIT_CODE_EXPORT' THEN
    target_licensee:=NULLIF(p_payload->>'licenseeId','');
    export_status:=NULLIF(p_payload->>'status','');
    export_query:=NULLIF(p_payload->>'query','');
    IF actor.role NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')
       OR p_payload->>'count' !~ '^(0|[1-9][0-9]*)$'
       OR (target_licensee IS NOT NULL AND target_licensee !~* '^[0-9a-f-]{36}$')
       OR (export_status IS NOT NULL AND export_status NOT IN ('DORMANT','ACTIVE','ALLOCATED','ACTIVATED','PRINTED','REDEEMED','BLOCKED','SCANNED'))
       OR length(coalesce(export_query,''))>500
    THEN RAISE EXCEPTION 'QR_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;
    exported_count:=(p_payload->>'count')::bigint;
    IF target_licensee IS NOT NULL THEN
      SELECT * INTO STRICT actor FROM app_rls.qr_bind_actor(
        p_capability,p_purpose,p_request_id,target_licensee
      );
      SELECT l."orgId" INTO STRICT target_org FROM public."Licensee" l WHERE l.id=target_licensee;
    END IF;
    PERFORM set_config('app.qr_batch_action',p_operation,true);
    PERFORM app_rls.qr_write_audit(
      actor."userId",target_org,target_licensee,'EXPORT_QR_CODES','QRCode',NULL,
      jsonb_build_object('status',export_status,'query',export_query,'count',exported_count)
    );
    RETURN jsonb_build_object('exportedCount',exported_count);
  END IF;

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

  IF p_operation IN ('DELETE_BATCH','ASSIGN_MANUFACTURER','RENAME_BATCH') THEN
    IF p_payload->>'batchId' !~* '^[0-9a-f-]{36}$' THEN RAISE EXCEPTION 'QR_INVALID_INPUT'; END IF;
    PERFORM set_config('app.qr_source_batch_id',p_payload->>'batchId',true);
    SELECT b.id,b.name,b."licenseeId",b."manufacturerId",b."rootBatchId",b."printedAt",b."releasedAt"
      INTO source_batch FROM public."Batch" b WHERE b.id=p_payload->>'batchId' FOR UPDATE;
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

  IF p_operation='RENAME_BATCH' THEN
    batch_name:=btrim(p_payload->>'name');
    IF actor.role NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN','LICENSEE_ADMIN')
       OR length(batch_name) NOT BETWEEN 2 AND 120 THEN
      RAISE EXCEPTION 'QR_BOUNDARY_DENIED' USING ERRCODE='42501';
    END IF;
    IF batch_name=source_batch.name THEN
      RETURN jsonb_build_object('id',source_batch.id,'name',source_batch.name,'licenseeId',target_licensee);
    END IF;
    UPDATE public."Batch" SET name=batch_name,"updatedAt"=transaction_timestamp() WHERE id=source_batch.id;
    IF NOT FOUND THEN RAISE EXCEPTION 'QR_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;
    SELECT l."orgId" INTO STRICT target_org FROM public."Licensee" l WHERE l.id=target_licensee;
    PERFORM app_rls.qr_write_audit(actor."userId",target_org,target_licensee,'RENAME_BATCH','Batch',source_batch.id,
      jsonb_build_object('from',source_batch.name,'to',batch_name));
    RETURN jsonb_build_object('id',source_batch.id,'name',batch_name,'licenseeId',target_licensee);
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
  SELECT jsonb_build_object('range',jsonb_build_object(
      'id',r.id,'licenseeId',r."licenseeId",'startCode',r."startCode",'endCode',r."endCode",
      'totalCodes',r."totalCodes",'usedCodes',r."usedCodes",'createdAt',r."createdAt",'updatedAt',r."updatedAt"
    ),'startCode',start_code,'endCode',end_code,'totalCodes',total,
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
-- Release Fix 5: capability-bound printing lifecycle.
-- Caller GUCs are never authority. Every public application function verifies
-- aq_db_session before reading a protected printing table.

CREATE OR REPLACE FUNCTION app_rls.printing_bind_actor(
  p_capability text,
  p_purpose text,
  p_request_id text,
  p_batch_id text DEFAULT NULL
) RETURNS TABLE(
  "userId" text,
  "role" text,
  "organizationId" text,
  "licenseeId" text,
  "batchLicenseeId" text,
  "batchManufacturerId" text
)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public
AS $fn$
DECLARE
  actor record;
  batch_row record;
  target_org text;
BEGIN
  IF p_purpose NOT IN (
    'printing-readiness','printing-create-job','printing-job-control',
    'printing-sample-scan','printing-release','printing-reissue',
    'printing-printer-read','printing-printer-admin','printing-connector-registration',
    'printing-audit-export','printing-test-label','printing-idempotency'
  ) OR p_request_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
     OR (p_batch_id IS NOT NULL AND p_batch_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$')
  THEN
    RAISE EXCEPTION 'PRINTING_BOUNDARY_DENIED' USING ERRCODE='42501';
  END IF;

  SELECT * INTO STRICT actor
    FROM app_auth.require_authenticated_session(p_capability,p_purpose,p_request_id);
  IF actor.role NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN','LICENSEE_ADMIN','MANUFACTURER_ADMIN') THEN
    RAISE EXCEPTION 'PRINTING_BOUNDARY_DENIED' USING ERRCODE='42501';
  END IF;

  PERFORM
    set_config('app.printing_session_id',actor."sessionId",true),
    set_config('app.printing_user_id',actor."userId",true),
    set_config('app.printing_role',actor.role,true),
    set_config('app.printing_organization_id',coalesce(actor."organizationId",''),true),
    set_config('app.printing_licensee_id',coalesce(actor."licenseeId",''),true),
    set_config('app.printing_batch_id',coalesce(p_batch_id,''),true),
    set_config('app.printing_job_id','',true),
    set_config('app.printing_session_row_id','',true),
    set_config('app.printing_item_id','',true),
    set_config('app.printing_printer_id','',true),
    set_config('app.printing_registration_id','',true),
    set_config('app.printing_reissue_id','',true),
    set_config('app.printing_idempotency_key_hash','',true),
    set_config('app.printing_original_session_id','',true),
    set_config('app.printing_released_user_id','',true),
    set_config('app.printing_approved_user_id','',true),
    set_config('app.printing_operation',p_purpose,true),
    set_config('app.printing_request_id',p_request_id,true),
    set_config('app.printing_audit_id','',true),
    set_config('app.printing_outbox_id','',true);

  IF p_batch_id IS NULL THEN
    RETURN QUERY SELECT actor."userId"::text,actor.role::text,
      actor."organizationId"::text,actor."licenseeId"::text,NULL::text,NULL::text;
    RETURN;
  END IF;

  SELECT b.id,b."licenseeId",b."manufacturerId",l."orgId"
    INTO batch_row
    FROM public."Batch" b
    JOIN public."Licensee" l ON l.id=b."licenseeId"
    JOIN public."Organization" o ON o.id=l."orgId"
   WHERE b.id=p_batch_id AND l."isActive" AND l."suspendedAt" IS NULL AND o."isActive";
  IF NOT FOUND THEN
    RAISE EXCEPTION 'PRINTING_BOUNDARY_DENIED' USING ERRCODE='42501';
  END IF;

  target_org:=batch_row."orgId";
  IF actor.role='LICENSEE_ADMIN' AND (
    actor."licenseeId" IS DISTINCT FROM batch_row."licenseeId"
    OR actor."organizationId" IS DISTINCT FROM target_org
  ) THEN
    RAISE EXCEPTION 'PRINTING_BOUNDARY_DENIED' USING ERRCODE='42501';
  END IF;
  IF actor.role='MANUFACTURER_ADMIN' AND (
    batch_row."manufacturerId" IS DISTINCT FROM actor."userId"
    OR NOT EXISTS (
      SELECT 1 FROM public."ManufacturerLicenseeLink" ml
       WHERE ml."manufacturerId"=actor."userId"
         AND ml."licenseeId"=batch_row."licenseeId"
    )
  ) THEN
    RAISE EXCEPTION 'PRINTING_BOUNDARY_DENIED' USING ERRCODE='42501';
  END IF;

  PERFORM
    set_config('app.printing_organization_id',target_org,true),
    set_config('app.printing_licensee_id',batch_row."licenseeId",true);
  RETURN QUERY SELECT actor."userId"::text,actor.role::text,target_org,
    batch_row."licenseeId"::text,batch_row."licenseeId"::text,
    batch_row."manufacturerId"::text;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.printing_write_audit(
  p_actor_id text,
  p_actor_role text,
  p_org_id text,
  p_licensee_id text,
  p_action text,
  p_entity_type text,
  p_entity_id text,
  p_details jsonb
) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public
AS $fn$
DECLARE
  audit_id text:=gen_random_uuid()::text;
  outbox_id text:=gen_random_uuid()::text;
  now_at timestamp without time zone:=transaction_timestamp();
BEGIN
  IF p_action !~ '^[A-Z0-9_]{1,120}$'
     OR p_entity_type NOT IN ('PrintJob','PrintSession','PrintItem','PrintReissueRequest','Batch','Printer')
     OR jsonb_typeof(coalesce(p_details,'{}'::jsonb))<>'object'
  THEN RAISE EXCEPTION 'PRINTING_INVALID_AUDIT'; END IF;
  PERFORM set_config('app.printing_audit_id',audit_id,true),
          set_config('app.printing_outbox_id',outbox_id,true);
  INSERT INTO public."AuditLog"(
    id,"userId","orgId","licenseeId",action,"entityType","entityId",details,"createdAt"
  ) VALUES (
    audit_id,p_actor_id,p_org_id,p_licensee_id,p_action,p_entity_type,p_entity_id,
    coalesce(p_details,'{}'::jsonb)||jsonb_build_object('actorRole',p_actor_role),now_at
  );
  INSERT INTO public."SecurityEventOutbox"(
    id,"eventType",payload,"requestId","organizationId","licenseeId","initiatingUserId","updatedAt"
  ) VALUES (
    outbox_id,'AUDIT_LOG',
    jsonb_build_object(
      'id',audit_id,'action',p_action,'entityType',p_entity_type,'entityId',p_entity_id,
      'userId',p_actor_id,'orgId',p_org_id,'licenseeId',p_licensee_id,
      'details',coalesce(p_details,'{}'::jsonb)||jsonb_build_object('actorRole',p_actor_role),
      'createdAt',now_at
    ),
    current_setting('app.printing_request_id',true),p_org_id,p_licensee_id,p_actor_id,now_at
  );
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.printing_readiness(
  p_capability text,
  p_purpose text,
  p_request_id text,
  p_operation text,
  p_subject_id text,
  p_options jsonb DEFAULT '{}'::jsonb
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public
AS $fn$
DECLARE
  actor record;
  batch_row record;
  job_row record;
  result jsonb;
  page_limit integer;
  target_batch_id text;
  target_job_id text;
  released_user_id text;
  approved_user_id text;
BEGIN
  IF p_purpose<>'printing-readiness'
     OR p_operation NOT IN ('BATCH','JOB','JOB_LIST','ATTENTION_QUEUE','RELEASE','REISSUE','REISSUE_REQUEST','REISSUE_LIST','PRINTABLE_ITEMS','PRINTER','PRINTER_LIST','PRINTER_STATUS','VALIDATION_EVIDENCE')
     OR p_subject_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
     OR jsonb_typeof(coalesce(p_options,'{}'::jsonb))<>'object'
  THEN RAISE EXCEPTION 'PRINTING_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;

  SELECT * INTO STRICT actor FROM app_rls.printing_bind_actor(
    p_capability,p_purpose,p_request_id,NULL
  );
  target_job_id:=CASE WHEN p_operation IN ('JOB','REISSUE') THEN p_subject_id END;
  IF target_job_id IS NOT NULL THEN
    PERFORM set_config('app.printing_job_id',target_job_id,true);
    SELECT j."batchId" INTO STRICT target_batch_id FROM public."PrintJob" j WHERE j.id=target_job_id;
  ELSIF p_operation='REISSUE_REQUEST' THEN
    PERFORM set_config('app.printing_reissue_id',p_subject_id,true);
    SELECT r."batchId" INTO STRICT target_batch_id FROM public."PrintReissueRequest" r WHERE r.id=p_subject_id;
  ELSIF p_operation IN ('PRINTER','PRINTER_LIST','PRINTER_STATUS') THEN
    target_batch_id:=p_options->>'batchId';
  ELSIF p_operation NOT IN ('JOB_LIST','ATTENTION_QUEUE') THEN
    target_batch_id:=p_subject_id;
  END IF;
  IF target_batch_id IS NOT NULL THEN
    SELECT * INTO STRICT actor FROM app_rls.printing_bind_actor(
      p_capability,p_purpose,p_request_id,target_batch_id
    );
  END IF;

  IF p_operation IN ('BATCH','RELEASE','PRINTABLE_ITEMS') THEN
    SELECT b.id,b.name,b."licenseeId",b."manufacturerId",b."lifecycleState",
      b."sampleScanPolicy",b."totalCodes",b."printedAt",b."releasedAt"
      INTO STRICT batch_row FROM public."Batch" b WHERE b.id=target_batch_id;
    RETURN jsonb_build_object(
      'batch',jsonb_build_object(
        'id',batch_row.id,'name',batch_row.name,'licenseeId',batch_row."licenseeId",
        'manufacturerId',batch_row."manufacturerId",'lifecycleState',batch_row."lifecycleState",
        'sampleScanPolicy',batch_row."sampleScanPolicy",'totalCodes',batch_row."totalCodes",
        'printedAt',batch_row."printedAt",'releasedAt',batch_row."releasedAt"
      ),
      'printableItems',coalesce((
        SELECT jsonb_agg(jsonb_build_object(
          'id',q.id,'code',q.code,'displayCode',q."displayCode",'batchId',q."batchId",
          'licenseeId',q."licenseeId",'status',q.status,'replayEpoch',q."replayEpoch"
        ) ORDER BY q."displayCode",q.id)
        FROM (
          SELECT q.id,q.code,q."displayCode",q."licenseeId",q."batchId",
            q.status,q."replayEpoch",q."printJobId"
          FROM public."QRCode" q
           WHERE q."batchId"=batch_row.id
             AND q.status IN ('ALLOCATED'::public."QRStatus",'ACTIVATED'::public."QRStatus")
             AND (nullif(p_options->>'rangeStart','') IS NULL OR q."displayCode">=p_options->>'rangeStart')
             AND (nullif(p_options->>'rangeEnd','') IS NULL OR q."displayCode"<=p_options->>'rangeEnd')
             AND (q."printJobId" IS NULL OR NOT EXISTS (
               SELECT 1 FROM public."PrintItem" pi
               WHERE pi."qrCodeId"=q.id AND (
                 pi."printConfirmedAt" IS NOT NULL
                 OR pi.state NOT IN ('FAILED'::public."PrintItemState",'FROZEN'::public."PrintItemState",'CANCELLED'::public."PrintItemState")
               )
             ))
           ORDER BY q."displayCode",q.id
           LIMIT LEAST(GREATEST(coalesce(NULLIF(p_options->>'limit','')::integer,500),1),200000)
        ) q
      ),'[]'::jsonb),
      'qrCount',(SELECT count(*) FROM public."QRCode" q WHERE q."batchId"=batch_row.id),
      'confirmedItemCount',(SELECT count(*) FROM public."PrintItem" pi
        JOIN public."PrintSession" ps ON ps.id=pi."printSessionId"
        WHERE ps."batchId"=batch_row.id AND pi."printConfirmedAt" IS NOT NULL),
      'sampleCount',(SELECT count(DISTINCT pa."qrCodeId") FROM public."PrintAuditEvent" pa
        WHERE pa."batchId"=batch_row.id AND pa."eventType"='SAMPLE_SCAN_PASSED'),
      'sampleRequired',CASE coalesce(batch_row."sampleScanPolicy"->>'type',batch_row."sampleScanPolicy"->>'mode','ONE_PER_PRINT_JOB')
        WHEN 'ONE_PER_PRINT_JOB' THEN 1
        WHEN 'ONE_PER_ROLL' THEN 1
        WHEN 'ONE_PER_N_LABELS' THEN GREATEST(1,ceil(batch_row."totalCodes"::numeric/GREATEST(coalesce((batch_row."sampleScanPolicy"->>'n')::integer,batch_row."totalCodes"),1))::integer)
        WHEN 'PERCENTAGE' THEN GREATEST(
          GREATEST(coalesce((batch_row."sampleScanPolicy"->>'min')::integer,1),1),
          ceil(batch_row."totalCodes"*GREATEST(coalesce((batch_row."sampleScanPolicy"->>'percentage')::numeric,1),0.01)/100)::integer
        )
        ELSE 1 END,
      'latestJob',(SELECT to_jsonb(j) FROM (
        SELECT job.id,job."jobNumber",job."batchId",job."manufacturerId",job."printerId",
          job.status,job."printMode",job."pipelineState",job."payloadType",job."payloadHash",
          job.quantity,job."itemCount",job."rangeStart",job."rangeEnd",job."sentAt",
          job."completedAt",job."failureReason",job."reprintOfJobId",job."approvedByUserId",
          job."reprintReason",job."confirmedAt",job."createdAt",job."updatedAt"
        FROM public."PrintJob" job WHERE job."batchId"=batch_row.id
        ORDER BY job."createdAt" DESC LIMIT 1
      ) j)
    );
  END IF;

  IF p_operation='VALIDATION_EVIDENCE' THEN
    SELECT j.id,j."approvedByUserId",j.status,j."pipelineState",j."itemCount",j.quantity,
      j."payloadHash",j."sentAt",j."confirmedAt",j."printerId" INTO STRICT job_row
      FROM public."PrintJob" j
      WHERE j."batchId"=target_batch_id
        AND (nullif(p_options->>'printJobId','') IS NULL OR j.id=p_options->>'printJobId')
      ORDER BY j."createdAt" DESC,j.id DESC
      LIMIT 1;
    PERFORM set_config('app.printing_job_id',job_row.id,true);
    SELECT b."releasedByUserId" INTO released_user_id
      FROM public."Batch" b WHERE b.id=target_batch_id;
    approved_user_id:=job_row."approvedByUserId";
    PERFORM set_config('app.printing_released_user_id',coalesce(released_user_id,''),true),
            set_config('app.printing_approved_user_id',coalesce(approved_user_id,''),true);
    RETURN (
      WITH selected_sample AS (
        SELECT q.id,q.code,q.status,q."printedAt",q."createdAt",q."batchId",q."printJobId"
        FROM public."QRCode" q
        WHERE q."batchId"=target_batch_id AND q."printJobId"=job_row.id
          AND (
            NOT EXISTS (
              SELECT 1 FROM public."PrintAuditEvent" pae
              WHERE pae."batchId"=target_batch_id AND pae."printJobId"=job_row.id
                AND pae."eventType" IN ('SAMPLE_SCAN_PASSED','sample_scan_verified')
            )
            OR q.id=(
              SELECT pae."qrCodeId" FROM public."PrintAuditEvent" pae
              WHERE pae."batchId"=target_batch_id AND pae."printJobId"=job_row.id
                AND pae."eventType" IN ('SAMPLE_SCAN_PASSED','sample_scan_verified')
              ORDER BY pae."createdAt" DESC,pae.id DESC LIMIT 1
            )
          )
        ORDER BY q."printedAt" NULLS LAST,q."createdAt",q.id LIMIT 1
      )
      SELECT jsonb_build_object(
        'generatedAt',transaction_timestamp(),
        'batch',jsonb_build_object(
          'id',b.id,'displayCode',coalesce(b.name,b."startCode"),
          'lifecycleState',b."lifecycleState",
          'brand',jsonb_build_object('id',l.id,'name',l.name,'prefix',l.prefix)
        ),
        'printJob',jsonb_build_object('id',job_row.id,'status',job_row.status,'pipelineState',job_row."pipelineState"),
        'printer',jsonb_build_object(
          'id',p.id,'name',p.name,'profileName',p.model,
          'model',p.model,'transport',
            CASE p."connectionType"
              WHEN 'NETWORK_IPP'::public."PrinterConnectionType" THEN 'ipp'
              WHEN 'LOCAL_AGENT'::public."PrinterConnectionType" THEN 'local-agent'
              ELSE 'tcp-raw' END,
          'host',coalesce(p.host,p."ipAddress"),'port',p.port
        ),
        'labelCount',coalesce(job_row."itemCount",job_row.quantity,b."totalCodes"),
        'payloadHash',job_row."payloadHash",'sentAt',job_row."sentAt",
        'physicalPrintConfirmedAt',job_row."confirmedAt",
        'sampleScanVerifiedAt',(
          SELECT pae."createdAt" FROM public."PrintAuditEvent" pae
          WHERE pae."batchId"=b.id AND pae."printJobId"=job_row.id
            AND pae."eventType" IN ('SAMPLE_SCAN_PASSED','sample_scan_verified')
          ORDER BY pae."createdAt" DESC,pae.id DESC LIMIT 1
        ),
        'releasedAt',b."releasedAt",
        'releasedBy',CASE WHEN released_by.id IS NULL THEN NULL ELSE jsonb_build_object(
          'id',released_by.id,'displayName',coalesce(released_by.name,released_by.email),'role',released_by.role) END,
        'checker',CASE WHEN checker.id IS NULL THEN NULL ELSE jsonb_build_object(
          'id',checker.id,'displayName',coalesce(checker.name,checker.email),'role',checker.role) END,
        'sampleQr',jsonb_build_object(
          'id',sample.id,
          'publicCode',CASE WHEN coalesce((p_options->>'includePublicCode')::boolean,false) THEN sample.code END,
          'maskedPublicCode',CASE WHEN sample.code IS NULL THEN NULL
            WHEN length(sample.code)<=12 THEN left(sample.code,3)||'...'||right(sample.code,2)
            ELSE left(sample.code,6)||'...'||right(sample.code,6) END,
          'verifyUrl',NULL
        ),
        'verify',jsonb_build_object(
          'result',CASE
            WHEN sample.id IS NULL THEN 'not_found'
            WHEN sample.status='BLOCKED'::public."QRStatus" THEN 'blocked'
            WHEN b."lifecycleState"='RELEASED'::public."BatchLifecycleState" THEN 'authentic_released'
            WHEN sample.status IN ('PRINTED'::public."QRStatus",'ACTIVATED'::public."QRStatus") THEN 'authentic_not_released'
            ELSE 'not_ready' END,
          'routeUsesExactPublicCode',coalesce(sample.code LIKE 'c\_%' ESCAPE '\',false)
        ),
        'auditEventIds',coalesce((
          SELECT jsonb_agg(pae.id ORDER BY pae."createdAt",pae.id)
          FROM public."PrintAuditEvent" pae
          WHERE pae."batchId"=b.id
            AND (pae."printJobId"=job_row.id OR pae."eventType" LIKE 'batch_release%')
        ),'[]'::jsonb),
        'auditEvents',jsonb_build_object(
          'sampleScanVerifiedId',(SELECT pae.id FROM public."PrintAuditEvent" pae
            WHERE pae."batchId"=b.id AND pae."printJobId"=job_row.id
              AND pae."eventType" IN ('SAMPLE_SCAN_PASSED','sample_scan_verified')
            ORDER BY pae."createdAt" DESC,pae.id DESC LIMIT 1),
          'batchReleasedId',(SELECT pae.id FROM public."PrintAuditEvent" pae
            WHERE pae."batchId"=b.id AND pae."printJobId"=job_row.id
              AND pae."eventType" IN ('BATCH_RELEASED','batch_released')
            ORDER BY pae."createdAt" DESC,pae.id DESC LIMIT 1),
          'approvalGrantedId',(SELECT pae.id FROM public."PrintAuditEvent" pae
            WHERE pae."batchId"=b.id AND pae."printJobId"=job_row.id
              AND pae."eventType" IN ('RELEASE_APPROVED','batch_release_approval_granted')
            ORDER BY pae."createdAt" DESC,pae.id DESC LIMIT 1)
        ),
        'legacyRisk',jsonb_build_object(
          'status',CASE
            WHEN legacy.total=0 THEN 'no_legacy_public_codes_in_batch'
            WHEN legacy.unsafe>0 THEN 'legacy_codes_locked'
            ELSE 'legacy_codes_review_required' END,
          'totalLegacyCodes',legacy.total,'unsafeLegacyCodes',legacy.unsafe
        )
      )
      FROM public."Batch" b
      JOIN public."Licensee" l ON l.id=b."licenseeId"
      LEFT JOIN public."Printer" p ON p.id=job_row."printerId"
      LEFT JOIN public."User" released_by ON released_by.id=b."releasedByUserId"
      LEFT JOIN public."User" approved_by ON approved_by.id=job_row."approvedByUserId"
      LEFT JOIN public."User" checker ON checker.id=coalesce(approved_by.id,released_by.id)
      LEFT JOIN selected_sample sample ON true
      CROSS JOIN LATERAL (
        SELECT count(*) FILTER (WHERE q.code NOT LIKE 'c\_%' ESCAPE '\') AS total,
          count(*) FILTER (WHERE q.code NOT LIKE 'c\_%' ESCAPE '\' AND (
            q."printedAt" IS NOT NULL OR q."scannedAt" IS NOT NULL OR q."scanCount">0
            OR q.status IN ('PRINTED'::public."QRStatus",'SCANNED'::public."QRStatus",
              'REDEEMED'::public."QRStatus",'BLOCKED'::public."QRStatus")
          )) AS unsafe
        FROM public."QRCode" q WHERE q."batchId"=b.id
      ) legacy
      WHERE b.id=target_batch_id
    );
  END IF;

  IF p_operation='PRINTER_LIST' THEN
    RETURN coalesce((
      SELECT jsonb_agg(to_jsonb(p) ORDER BY p."isDefault" DESC,p.name,p.id)
      FROM (
        SELECT printer.id,printer.name,printer.vendor,printer.model,printer."connectionType",
          printer."commandLanguage",printer."ipAddress",printer.host,printer.port,printer."resourcePath",
          printer."tlsEnabled",printer."printerUri",printer."deliveryMode",printer."gatewayId",
          printer."gatewayLastSeenAt",printer."gatewayStatus",printer."gatewayLastError",
          printer."nativePrinterId",printer."agentId",printer."deviceFingerprint",
          printer."printerRegistrationId",printer."orgId",printer."licenseeId",
          printer."assignedUserId",printer."createdByUserId",printer."isActive",printer."isDefault",
          printer."lastSeenAt",printer."lastValidatedAt",printer."lastValidationStatus",
          printer."lastValidationMessage",printer."capabilitySummary",printer."calibrationProfile",
          printer.metadata,printer."createdAt",printer."updatedAt"
        FROM public."Printer" printer
        WHERE (coalesce((p_options->>'includeInactive')::boolean,false) OR printer."isActive")
        AND (
          actor.role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')
          OR (actor.role='LICENSEE_ADMIN'
            AND printer."licenseeId"=actor."licenseeId" AND printer."orgId"=actor."organizationId")
          OR (actor.role='MANUFACTURER_ADMIN' AND (
            printer."assignedUserId"=actor."userId"
            OR EXISTS (
              SELECT 1 FROM public."PrinterRegistration" pr
              WHERE pr.id=printer."printerRegistrationId" AND pr."userId"=actor."userId"
                AND pr."trustStatus"='TRUSTED' AND pr."revokedAt" IS NULL
            )
            OR EXISTS (
              SELECT 1 FROM public."ManufacturerLicenseeLink" ml
              WHERE ml."manufacturerId"=actor."userId" AND ml."licenseeId"=printer."licenseeId"
            )
          ))
        )
      ) p
    ),'[]'::jsonb);
  END IF;

  IF p_operation='PRINTER' THEN
    RETURN (
      SELECT to_jsonb(p)
      FROM (
        SELECT printer.id,printer.name,printer.vendor,printer.model,printer."connectionType",
          printer."commandLanguage",printer."ipAddress",printer.host,printer.port,printer."resourcePath",
          printer."tlsEnabled",printer."printerUri",printer."deliveryMode",printer."gatewayId",
          printer."gatewayLastSeenAt",printer."gatewayStatus",printer."gatewayLastError",
          printer."nativePrinterId",printer."agentId",printer."deviceFingerprint",
          printer."printerRegistrationId",printer."orgId",printer."licenseeId",
          printer."assignedUserId",printer."createdByUserId",printer."isActive",printer."isDefault",
          printer."lastSeenAt",printer."lastValidatedAt",printer."lastValidationStatus",
          printer."lastValidationMessage",printer."capabilitySummary",printer."calibrationProfile",
          printer.metadata,printer."createdAt",printer."updatedAt"
        FROM public."Printer" printer
        WHERE printer.id=p_subject_id AND (
        actor.role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')
        OR (actor.role='LICENSEE_ADMIN'
          AND printer."licenseeId"=actor."licenseeId" AND printer."orgId"=actor."organizationId")
        OR printer."assignedUserId"=actor."userId"
        OR EXISTS (
          SELECT 1 FROM public."PrinterRegistration" pr
          WHERE pr.id=printer."printerRegistrationId" AND pr."userId"=actor."userId"
            AND pr."trustStatus"='TRUSTED' AND pr."revokedAt" IS NULL
        )
      )
      ) p
    );
  END IF;

  IF p_operation='PRINTER_STATUS' THEN
    IF p_subject_id IS DISTINCT FROM actor."userId" THEN
      RAISE EXCEPTION 'PRINTING_BOUNDARY_DENIED' USING ERRCODE='42501';
    END IF;
    RETURN (
      WITH registration AS (
        SELECT pr.id,pr."agentId",pr."deviceFingerprint",pr."trustStatus",pr."trustReason",
          pr."approvedAt",pr."lastSeenAt",pr."updatedAt"
        FROM public."PrinterRegistration" pr
        WHERE pr."userId"=actor."userId" AND pr."revokedAt" IS NULL
          AND pr."trustStatus"<>'REVOKED'::public."PrinterTrustStatus"
        ORDER BY pr."approvedAt" DESC NULLS LAST,pr."lastSeenAt" DESC NULLS LAST,pr."updatedAt" DESC
        LIMIT 1
      ), attestation AS (
        SELECT pa.id,pa."printerRegistrationId",pa.metadata,pa."expiresAt",pa."trustValid",
          pa."signatureValid",pa."attestedAt",pa."rejectionReason",pa."createdAt"
        FROM public."PrinterAttestation" pa
        JOIN registration pr ON pr.id=pa."printerRegistrationId"
        ORDER BY pa."createdAt" DESC,pa.id DESC LIMIT 1
      )
      SELECT CASE WHEN pr.id IS NULL THEN jsonb_build_object(
        'connected',false,'trusted',false,'compatibilityMode',false,
        'eligibleForPrinting',false,'connectionClass','BLOCKED','stale',true,
        'securePrinterSession',false,'freshHelperHeartbeat',false,
        'helperConnection',false,'eligiblePrinter',false,
        'missingFields',jsonb_build_array('printerRegistration','freshHelperHeartbeat',
          'helperConnection','eligiblePrinter','securePrinterSession','selectedPrinter'),
        'registrationId',NULL,'error','No printer registration'
      ) ELSE (
        coalesce(pa.metadata,'{}'::jsonb)
        ||jsonb_build_object(
          'connected',coalesce((pa.metadata->>'connected')::boolean,false)
            AND pa."expiresAt">transaction_timestamp() AND pa."trustValid",
          'trusted',pr."trustStatus"='TRUSTED'::public."PrinterTrustStatus"
            AND pa."expiresAt">transaction_timestamp() AND pa."trustValid" AND pa."signatureValid",
          'compatibilityMode',false,
          'eligibleForPrinting',pr."trustStatus"='TRUSTED'::public."PrinterTrustStatus"
            AND pa."expiresAt">transaction_timestamp() AND pa."trustValid" AND pa."signatureValid"
            AND coalesce((pa.metadata->>'connected')::boolean,false)
            AND coalesce(pa.metadata->>'selectedPrinterId',pa.metadata->>'printerId','')<>'',
          'connectionClass',CASE WHEN pr."trustStatus"='TRUSTED'::public."PrinterTrustStatus"
            AND pa."expiresAt">transaction_timestamp() AND pa."trustValid" AND pa."signatureValid"
            THEN 'TRUSTED' ELSE 'BLOCKED' END,
          'stale',pa."expiresAt"<=transaction_timestamp(),
          'securePrinterSession',pr."trustStatus"='TRUSTED'::public."PrinterTrustStatus"
            AND pa."expiresAt">transaction_timestamp() AND pa."trustValid" AND pa."signatureValid",
          'freshHelperHeartbeat',pa."expiresAt">transaction_timestamp(),
          'helperConnection',coalesce((pa.metadata->>'connected')::boolean,false)
            AND pa."expiresAt">transaction_timestamp(),
          'eligiblePrinter',coalesce(pa.metadata->>'selectedPrinterId',pa.metadata->>'printerId','')<>'',
          'missingFields','[]'::jsonb,
          'registrationId',pr.id,'agentId',pr."agentId",
          'deviceFingerprint',pr."deviceFingerprint",'trustStatus',pr."trustStatus",
          'trustReason',pr."trustReason",'lastHeartbeatAt',pa."attestedAt",
          'ageSeconds',greatest(0,extract(epoch FROM transaction_timestamp()-pa."attestedAt")::integer),
          'signedAttestation',jsonb_build_object(
            'required',true,'present',true,'signatureValid',pa."signatureValid",
            'fresh',pa."expiresAt">transaction_timestamp() AND pa."trustValid",
            'issuedAt',pa.metadata->>'heartbeatIssuedAt','rejectReason',pa."rejectionReason"
          ),
          'error',CASE WHEN pa."trustValid" AND pa."expiresAt">transaction_timestamp()
            THEN NULL ELSE coalesce(pa."rejectionReason",pr."trustReason",'Printer attestation stale') END
        )
      ) END
      FROM (SELECT 1) seed
      LEFT JOIN registration pr ON true
      LEFT JOIN attestation pa ON true
    );
  END IF;

  IF p_operation IN ('JOB','REISSUE') THEN
    SELECT j.id,j."jobNumber",j."batchId",j."manufacturerId",j."printerId",j.status,
      j."printMode",j."pipelineState",j."payloadType",j."payloadHash",j.quantity,j."itemCount",
      j."rangeStart",j."rangeEnd",j."sentAt",j."completedAt",j."failureReason",
      j."reprintOfJobId",j."approvedByUserId",j."reprintReason",j."confirmedAt",
      j."createdAt",j."updatedAt" INTO STRICT job_row
      FROM public."PrintJob" j WHERE j.id=target_job_id;
    RETURN jsonb_build_object(
      'job',to_jsonb(job_row),
      'session',(SELECT to_jsonb(ps) FROM (
        SELECT session.id,session."printJobId",session."batchId",session."manufacturerId",
          session."printerRegistrationId",session."printerId",session.status,session."totalItems",
          session."issuedItems",session."confirmedItems",session."frozenItems",session."failedReason",
          session."startedAt",session."completedAt",session."createdAt",session."updatedAt"
        FROM public."PrintSession" session WHERE session."printJobId"=job_row.id
      ) ps),
      'items',coalesce((SELECT jsonb_agg(
        jsonb_build_object(
          'id',pi.id,'printSessionId',pi."printSessionId",'qrCodeId',pi."qrCodeId",'code',pi.code,
          'state',pi.state,'pipelineState',pi."pipelineState",'issueSequence',pi."issueSequence",
          'attemptCount',pi."attemptCount",'deviceJobRef',pi."deviceJobRef",
          'dispatchMetadata',pi."dispatchMetadata",'confirmationEvidence',pi."confirmationEvidence",
          'issuedAt',pi."issuedAt",'dispatchedAt',pi."dispatchedAt",'agentAckedAt',pi."agentAckedAt",
          'confirmationDeadlineAt',pi."confirmationDeadlineAt",'printConfirmedAt',pi."printConfirmedAt",
          'closedAt',pi."closedAt",'frozenAt',pi."frozenAt",'failedAt',pi."failedAt",
          'failureReason',pi."failureReason",'deadLetterReason',pi."deadLetterReason",
          'createdAt',pi."createdAt",'updatedAt',pi."updatedAt",
          'qrCode',jsonb_build_object('id',q.id,'code',q.code,'displayCode',q."displayCode",'status',q.status)
        ) ORDER BY pi."issueSequence" NULLS LAST,pi.id
      ) FROM public."PrintItem" pi
        JOIN public."PrintSession" ps ON ps.id=pi."printSessionId"
        JOIN public."QRCode" q ON q.id=pi."qrCodeId"
        WHERE ps."printJobId"=job_row.id),'[]'::jsonb)
    );
  END IF;

  IF p_operation='REISSUE_REQUEST' THEN
    PERFORM set_config('app.printing_reissue_id',p_subject_id,true);
    RETURN (
      SELECT to_jsonb(r)||jsonb_build_object(
        'originalPrintJob',jsonb_build_object(
          'id',j.id,'jobNumber',j."jobNumber",'status',j.status,'quantity',j.quantity,
          'itemCount',j."itemCount",'rangeStart',j."rangeStart",'rangeEnd',j."rangeEnd",
          'printMode',j."printMode",'pipelineState',j."pipelineState",
          'batch',jsonb_build_object('id',b.id,'name',b.name,'licenseeId',b."licenseeId"),
          'printer',jsonb_build_object('id',p.id,'name',p.name)
        )
      )
      FROM (
        SELECT request.id,request."originalPrintJobId",request."replacementPrintJobId",
          request."requestedByUserId",request."approvedByUserId",request."licenseeId",
          request."manufacturerId",request."batchId",request."requestedByRole",
          request."targetApproverRole",request.quantity,request."affectedRangeStart",
          request."affectedRangeEnd",request."decisionNote",request."approvalReferenceId",
          request.status,request.reason,request."rejectionReason",request."approvedAt",
          request."rejectedAt",request."executedAt",request."createdAt",request."updatedAt"
        FROM public."PrintReissueRequest" request WHERE request.id=p_subject_id
      ) r
      JOIN public."PrintJob" j ON j.id=r."originalPrintJobId"
      JOIN public."Batch" b ON b.id=j."batchId"
      JOIN public."Printer" p ON p.id=j."printerId"
    );
  END IF;

  IF p_operation='REISSUE_LIST' THEN
    RETURN coalesce((
      SELECT jsonb_agg(to_jsonb(x) ORDER BY x."createdAt" DESC,x.id DESC)
      FROM (
        SELECT r.id,r."originalPrintJobId",r."replacementPrintJobId",r."requestedByUserId",
          r."approvedByUserId",r."licenseeId",r."manufacturerId",r."batchId",r."requestedByRole",
          r."targetApproverRole",r.quantity,r."affectedRangeStart",r."affectedRangeEnd",
          r."decisionNote",r."approvalReferenceId",r.status,r.reason,r."rejectionReason",
          r."approvedAt",r."rejectedAt",r."executedAt",r."createdAt",r."updatedAt",
          jsonb_build_object(
          'id',j.id,'jobNumber',j."jobNumber",'status',j.status,'quantity',j.quantity,
          'itemCount',j."itemCount",'rangeStart',j."rangeStart",'rangeEnd',j."rangeEnd",
          'batch',jsonb_build_object('id',b.id,'name',b.name,'licenseeId',b."licenseeId"),
          'printer',jsonb_build_object('id',p.id,'name',p.name)
        ) AS "originalPrintJob"
        FROM public."PrintReissueRequest" r
        JOIN public."PrintJob" j ON j.id=r."originalPrintJobId"
        JOIN public."Batch" b ON b.id=j."batchId"
        JOIN public."Printer" p ON p.id=j."printerId"
        WHERE (nullif(p_options->>'status','') IS NULL OR r.status::text=p_options->>'status')
          AND (
            actor.role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')
            OR (actor.role='LICENSEE_ADMIN' AND r."licenseeId"=actor."licenseeId")
            OR (actor.role='MANUFACTURER_ADMIN' AND r."requestedByUserId"=actor."userId")
          )
        ORDER BY r."createdAt" DESC,r.id DESC
        LIMIT LEAST(GREATEST(coalesce(NULLIF(p_options->>'limit','')::integer,50),1),200)
      ) x
    ),'[]'::jsonb);
  END IF;

  IF p_operation='ATTENTION_QUEUE' THEN
    RETURN (
      WITH scoped AS (
        SELECT j.id,j."jobNumber",j.status,j."pipelineState",j."updatedAt"
        FROM public."PrintJob" j
        JOIN public."Batch" b ON b.id=j."batchId"
        WHERE (
          j.status IN ('PENDING'::public."PrintJobStatus",'SENT'::public."PrintJobStatus")
          OR j."pipelineState" IN (
            'QUEUED'::public."PrintPipelineState",'PREFLIGHT_OK'::public."PrintPipelineState",
            'SENT_TO_PRINTER'::public."PrintPipelineState",'PRINTER_ACKNOWLEDGED'::public."PrintPipelineState",
            'NEEDS_OPERATOR_ACTION'::public."PrintPipelineState"
          )
        )
        AND (
          (actor.role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')
            AND (nullif(p_options->>'licenseeId','') IS NULL OR b."licenseeId"=p_options->>'licenseeId'))
          OR (actor.role='LICENSEE_ADMIN' AND b."licenseeId"=actor."licenseeId")
          OR (actor.role='MANUFACTURER_ADMIN' AND j."manufacturerId"=actor."userId" AND EXISTS (
            SELECT 1 FROM public."ManufacturerLicenseeLink" ml
            WHERE ml."manufacturerId"=actor."userId" AND ml."licenseeId"=b."licenseeId"
          ))
        )
      )
      SELECT jsonb_build_object(
        'count',(SELECT count(*) FROM scoped),
        'latest',(SELECT to_jsonb(x) FROM scoped x ORDER BY x."updatedAt" DESC,x.id DESC LIMIT 1)
      )
    );
  END IF;

  page_limit:=LEAST(GREATEST(coalesce(NULLIF(p_options->>'limit','')::integer,100),1),500);
  RETURN coalesce((
    SELECT jsonb_agg(to_jsonb(x) ORDER BY x."createdAt" DESC,x.id DESC)
    FROM (
      SELECT j.id,j."jobNumber",j."batchId",j."manufacturerId",j."printerId",
        j.status,j."printMode",j."pipelineState",j.quantity,j."itemCount",
        j."rangeStart",j."rangeEnd",j."sentAt",j."completedAt",j."failureReason",
        j."reprintOfJobId",j."approvedByUserId",j."reprintReason",j."confirmedAt",
        j."createdAt",j."updatedAt"
      FROM public."PrintJob" j
      JOIN public."Batch" b ON b.id=j."batchId"
      WHERE (nullif(p_options->>'batchId','') IS NULL OR j."batchId"=p_options->>'batchId')
        AND (
        actor.role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')
        OR (actor.role='LICENSEE_ADMIN' AND b."licenseeId"=actor."licenseeId")
        OR (actor.role='MANUFACTURER_ADMIN' AND j."manufacturerId"=actor."userId" AND EXISTS (
          SELECT 1 FROM public."ManufacturerLicenseeLink" ml
          WHERE ml."manufacturerId"=actor."userId" AND ml."licenseeId"=b."licenseeId"
        ))
      )
      ORDER BY j."createdAt" DESC,j.id DESC LIMIT page_limit
    ) x
  ),'[]'::jsonb);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.printing_printer_administration(
  p_capability text,
  p_purpose text,
  p_request_id text,
  p_operation text,
  p_printer_id text,
  p_payload jsonb
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public
AS $fn$
DECLARE
  actor record;
  printer_row record;
  scope_licensee text;
  scope_org text;
  now_at timestamp without time zone:=transaction_timestamp();
  new_id text:=coalesce(nullif(p_printer_id,''),gen_random_uuid()::text);
  audit_action text;
BEGIN
  IF p_purpose<>'printing-printer-admin'
     OR p_operation NOT IN (
       'CREATE','UPDATE','DELETE','RELINK',
       'AUDIT_TEST','AUDIT_TEST_LABEL_ATTENTION','AUDIT_TEST_LABEL_CONFIRMED',
       'AUDIT_TEST_LABEL_QUEUED','AUDIT_DISCOVERY'
     )
     OR (p_operation<>'CREATE' AND p_printer_id !~* '^[0-9a-f-]{36}$')
     OR jsonb_typeof(coalesce(p_payload,'{}'::jsonb))<>'object'
  THEN RAISE EXCEPTION 'PRINTING_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;

  SELECT * INTO STRICT actor
    FROM app_rls.printing_bind_actor(p_capability,p_purpose,p_request_id,NULL);
  PERFORM set_config('app.printing_operation','printing-printer-admin-'||lower(p_operation),true),
          set_config('app.printing_printer_id',new_id,true);

  IF p_operation='CREATE' THEN
    IF actor.role NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN','LICENSEE_ADMIN')
    THEN RAISE EXCEPTION 'PRINTING_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;
    scope_licensee:=CASE WHEN actor.role='LICENSEE_ADMIN' THEN actor."licenseeId"
      ELSE nullif(p_payload->>'licenseeId','') END;
    SELECT l."orgId" INTO STRICT scope_org FROM public."Licensee" l
      JOIN public."Organization" o ON o.id=l."orgId"
      WHERE l.id=scope_licensee AND l."isActive" AND l."suspendedAt" IS NULL AND o."isActive";
    IF actor.role='LICENSEE_ADMIN' AND (
      actor."organizationId" IS DISTINCT FROM scope_org
      OR actor."licenseeId" IS DISTINCT FROM scope_licensee
    ) THEN RAISE EXCEPTION 'PRINTING_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;
  ELSE
    SELECT p.id,p.name,p.vendor,p.model,p."connectionType",p."commandLanguage",p."ipAddress",p.host,p.port,
      p."resourcePath",p."tlsEnabled",p."printerUri",p."deliveryMode",p."gatewayId",p."gatewayLastSeenAt",
      p."gatewayStatus",p."gatewayLastError",p."nativePrinterId",p."agentId",p."deviceFingerprint",
      p."printerRegistrationId",p."orgId",p."licenseeId",p."assignedUserId",p."createdByUserId",
      p."isActive",p."isDefault",p."lastSeenAt",p."lastValidatedAt",p."lastValidationStatus",
      p."lastValidationMessage",p."capabilitySummary",p."calibrationProfile",p.metadata,p."createdAt",p."updatedAt"
      INTO STRICT printer_row FROM public."Printer" p WHERE p.id=p_printer_id FOR UPDATE;
    scope_licensee:=printer_row."licenseeId";
    scope_org:=printer_row."orgId";
    IF actor.role='LICENSEE_ADMIN' AND (
      actor."licenseeId" IS DISTINCT FROM scope_licensee
      OR actor."organizationId" IS DISTINCT FROM scope_org
    ) THEN RAISE EXCEPTION 'PRINTING_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;
    IF actor.role='MANUFACTURER_ADMIN' AND NOT (
      (
        p_operation='RELINK' AND printer_row."connectionType"='LOCAL_AGENT'
        AND (printer_row."assignedUserId"=actor."userId" OR EXISTS (
          SELECT 1 FROM public."PrinterRegistration" pr
          WHERE pr.id=printer_row."printerRegistrationId" AND pr."userId"=actor."userId"
            AND pr."trustStatus"='TRUSTED' AND pr."revokedAt" IS NULL
        ))
      )
      OR (
        p_operation LIKE 'AUDIT_%' AND printer_row."assignedUserId"=actor."userId"
        AND EXISTS (
          SELECT 1 FROM public."ManufacturerLicenseeLink" ml
          WHERE ml."manufacturerId"=actor."userId" AND ml."licenseeId"=printer_row."licenseeId"
        )
      )
    ) THEN RAISE EXCEPTION 'PRINTING_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;
    IF actor.role NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN','LICENSEE_ADMIN','MANUFACTURER_ADMIN')
    THEN RAISE EXCEPTION 'PRINTING_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;
  END IF;

  PERFORM set_config('app.printing_licensee_id',coalesce(scope_licensee,''),true),
          set_config('app.printing_organization_id',coalesce(scope_org,''),true);

  IF p_operation='CREATE' THEN
    IF p_payload->>'connectionType' NOT IN ('NETWORK_DIRECT','NETWORK_IPP')
       OR length(btrim(coalesce(p_payload->>'name',''))) NOT BETWEEN 2 AND 180
       OR nullif(p_payload->>'gatewaySecretHash','') IS NOT NULL
          AND p_payload->>'gatewaySecretHash' !~ '^[0-9a-f]{64}$'
    THEN RAISE EXCEPTION 'PRINTING_INVALID_INPUT'; END IF;
    INSERT INTO public."Printer"(
      id,name,vendor,model,"connectionType","commandLanguage","ipAddress",host,port,
      "resourcePath","tlsEnabled","printerUri","deliveryMode","gatewayId","gatewaySecretHash",
      "gatewayStatus","gatewayLastError","orgId","licenseeId","createdByUserId","isActive",
      "isDefault","capabilitySummary","calibrationProfile","createdAt","updatedAt"
    ) VALUES (
      new_id,btrim(p_payload->>'name'),nullif(btrim(p_payload->>'vendor'),''),
      nullif(btrim(p_payload->>'model'),''),
      (p_payload->>'connectionType')::public."PrinterConnectionType",
      coalesce(nullif(p_payload->>'commandLanguage',''),'AUTO')::public."PrinterCommandLanguage",
      nullif(btrim(p_payload->>'ipAddress'),''),nullif(btrim(p_payload->>'host'),''),
      coalesce((p_payload->>'port')::integer,
        CASE WHEN p_payload->>'connectionType'='NETWORK_IPP' THEN 631 ELSE 9100 END),
      nullif(btrim(p_payload->>'resourcePath'),''),
      coalesce((p_payload->>'tlsEnabled')::boolean,false),nullif(btrim(p_payload->>'printerUri'),''),
      coalesce(nullif(p_payload->>'deliveryMode',''),'DIRECT')::public."PrinterDeliveryMode",
      nullif(p_payload->>'gatewayId',''),nullif(p_payload->>'gatewaySecretHash',''),
      CASE WHEN p_payload->>'deliveryMode'='SITE_GATEWAY' THEN 'PENDING' END,
      CASE WHEN p_payload->>'deliveryMode'='SITE_GATEWAY' THEN 'Gateway has not checked in yet.' END,
      scope_org,scope_licensee,actor."userId",coalesce((p_payload->>'isActive')::boolean,true),
      coalesce((p_payload->>'isDefault')::boolean,false),p_payload->'capabilitySummary',
      p_payload->'calibrationProfile',now_at,now_at
    ) RETURNING id,name,vendor,model,"connectionType","commandLanguage","ipAddress",host,port,
      "resourcePath","tlsEnabled","printerUri","deliveryMode","gatewayId","gatewayLastSeenAt",
      "gatewayStatus","gatewayLastError","nativePrinterId","agentId","deviceFingerprint",
      "printerRegistrationId","orgId","licenseeId","assignedUserId","createdByUserId","isActive",
      "isDefault","lastSeenAt","lastValidatedAt","lastValidationStatus","lastValidationMessage",
      "capabilitySummary","calibrationProfile",metadata,"createdAt","updatedAt" INTO printer_row;
  ELSIF p_operation='UPDATE' THEN
    IF printer_row."connectionType"='LOCAL_AGENT'
       AND p_payload - ARRAY['lastValidationStatus','lastValidationMessage','metadata']::text[] <> '{}'::jsonb
    THEN RAISE EXCEPTION 'PRINTING_INVALID_INPUT'; END IF;
    UPDATE public."Printer" SET
      name=coalesce(nullif(btrim(p_payload->>'name'),''),name),
      vendor=CASE WHEN p_payload ? 'vendor' THEN nullif(btrim(p_payload->>'vendor'),'') ELSE vendor END,
      model=CASE WHEN p_payload ? 'model' THEN nullif(btrim(p_payload->>'model'),'') ELSE model END,
      "commandLanguage"=coalesce(nullif(p_payload->>'commandLanguage','')::public."PrinterCommandLanguage","commandLanguage"),
      "ipAddress"=CASE WHEN p_payload ? 'ipAddress' THEN nullif(btrim(p_payload->>'ipAddress'),'') ELSE "ipAddress" END,
      host=CASE WHEN p_payload ? 'host' THEN nullif(btrim(p_payload->>'host'),'') ELSE host END,
      port=coalesce((p_payload->>'port')::integer,port),
      "resourcePath"=CASE WHEN p_payload ? 'resourcePath' THEN nullif(btrim(p_payload->>'resourcePath'),'') ELSE "resourcePath" END,
      "tlsEnabled"=coalesce((p_payload->>'tlsEnabled')::boolean,"tlsEnabled"),
      "printerUri"=CASE WHEN p_payload ? 'printerUri' THEN nullif(btrim(p_payload->>'printerUri'),'') ELSE "printerUri" END,
      "deliveryMode"=coalesce(nullif(p_payload->>'deliveryMode','')::public."PrinterDeliveryMode","deliveryMode"),
      "gatewayId"=coalesce(nullif(p_payload->>'gatewayId',''),"gatewayId"),
      "gatewaySecretHash"=coalesce(nullif(p_payload->>'gatewaySecretHash',''),"gatewaySecretHash"),
      "gatewayStatus"=CASE WHEN p_payload ? 'gatewaySecretHash' THEN 'PENDING' ELSE "gatewayStatus" END,
      "gatewayLastError"=CASE WHEN p_payload ? 'gatewaySecretHash' THEN 'Gateway has not checked in yet.' ELSE "gatewayLastError" END,
      "isActive"=coalesce((p_payload->>'isActive')::boolean,"isActive"),
      "isDefault"=coalesce((p_payload->>'isDefault')::boolean,"isDefault"),
      "capabilitySummary"=coalesce(p_payload->'capabilitySummary',"capabilitySummary"),
      "calibrationProfile"=coalesce(p_payload->'calibrationProfile',"calibrationProfile"),
      metadata=coalesce(p_payload->'metadata',metadata),
      "lastValidatedAt"=CASE WHEN p_payload ? 'lastValidationStatus' THEN now_at ELSE "lastValidatedAt" END,
      "lastValidationStatus"=coalesce(nullif(left(p_payload->>'lastValidationStatus',80),''),"lastValidationStatus"),
      "lastValidationMessage"=CASE WHEN p_payload ? 'lastValidationMessage'
        THEN nullif(left(p_payload->>'lastValidationMessage',500),'') ELSE "lastValidationMessage" END,
      "updatedAt"=now_at
      WHERE id=p_printer_id
      RETURNING id,name,vendor,model,"connectionType","commandLanguage","ipAddress",host,port,
        "resourcePath","tlsEnabled","printerUri","deliveryMode","gatewayId","gatewayLastSeenAt",
        "gatewayStatus","gatewayLastError","nativePrinterId","agentId","deviceFingerprint",
        "printerRegistrationId","orgId","licenseeId","assignedUserId","createdByUserId","isActive",
        "isDefault","lastSeenAt","lastValidatedAt","lastValidationStatus","lastValidationMessage",
        "capabilitySummary","calibrationProfile",metadata,"createdAt","updatedAt" INTO printer_row;
  ELSIF p_operation='RELINK' THEN
    IF NOT EXISTS (
      SELECT 1 FROM public."PrinterRegistration" pr
      WHERE pr.id=nullif(p_payload->>'printerRegistrationId','')
        AND pr."userId"=actor."userId" AND pr."trustStatus"='TRUSTED'
        AND pr."revokedAt" IS NULL
    ) OR NOT EXISTS (
      SELECT 1 FROM public."PrinterAttestation" pa
      WHERE pa."printerRegistrationId"=nullif(p_payload->>'printerRegistrationId','')
        AND pa."trustValid" AND pa."signatureValid" AND pa."expiresAt">now_at
        AND EXISTS (
          SELECT 1 FROM jsonb_array_elements(coalesce(pa.metadata->'printers','[]'::jsonb)) inventory
          WHERE coalesce(inventory->>'printerId',inventory->>'id')=nullif(p_payload->>'nativePrinterId','')
        )
    ) THEN RAISE EXCEPTION 'CONNECTOR_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;
    UPDATE public."Printer" SET "isDefault"=false,"updatedAt"=now_at
      WHERE "assignedUserId"=actor."userId" AND "connectionType"='LOCAL_AGENT'
        AND id<>p_printer_id;
    UPDATE public."Printer" SET
      "printerRegistrationId"=nullif(p_payload->>'printerRegistrationId',''),
      "nativePrinterId"=nullif(p_payload->>'nativePrinterId',''),
      "agentId"=nullif(p_payload->>'agentId',''),
      "deviceFingerprint"=nullif(p_payload->>'deviceFingerprint',''),
      "assignedUserId"=actor."userId","isActive"=true,"isDefault"=true,
      "lastSeenAt"=now_at,"lastValidatedAt"=now_at,"lastValidationStatus"='READY',
      "lastValidationMessage"=NULL,"updatedAt"=now_at
      WHERE id=p_printer_id
      RETURNING id,name,vendor,model,"connectionType","commandLanguage","ipAddress",host,port,
        "resourcePath","tlsEnabled","printerUri","deliveryMode","gatewayId","gatewayLastSeenAt",
        "gatewayStatus","gatewayLastError","nativePrinterId","agentId","deviceFingerprint",
        "printerRegistrationId","orgId","licenseeId","assignedUserId","createdByUserId","isActive",
        "isDefault","lastSeenAt","lastValidatedAt","lastValidationStatus","lastValidationMessage",
        "capabilitySummary","calibrationProfile",metadata,"createdAt","updatedAt" INTO printer_row;
  ELSIF p_operation='DELETE' THEN
    IF printer_row."connectionType"='LOCAL_AGENT'
       OR EXISTS (SELECT 1 FROM public."PrintJob" j
         WHERE j."printerId"=printer_row.id AND j.status IN ('PENDING','SENT','PAUSED'))
    THEN RAISE EXCEPTION 'INVALID_STATE_TRANSITION'; END IF;
    DELETE FROM public."Printer" p WHERE p.id=p_printer_id
    RETURNING id,name,vendor,model,"connectionType","commandLanguage","ipAddress",host,port,
      "resourcePath","tlsEnabled","printerUri","deliveryMode","gatewayId","gatewayLastSeenAt",
      "gatewayStatus","gatewayLastError","nativePrinterId","agentId","deviceFingerprint",
      "printerRegistrationId","orgId","licenseeId","assignedUserId","createdByUserId","isActive",
      "isDefault","lastSeenAt","lastValidatedAt","lastValidationStatus","lastValidationMessage",
      "capabilitySummary","calibrationProfile",metadata,"createdAt","updatedAt" INTO printer_row;
  END IF;

  audit_action:=CASE p_operation
    WHEN 'AUDIT_TEST' THEN 'PRINTER_TESTED'
    WHEN 'AUDIT_TEST_LABEL_ATTENTION' THEN 'PRINTER_TEST_LABEL_ATTENTION'
    WHEN 'AUDIT_TEST_LABEL_CONFIRMED' THEN 'PRINTER_TEST_LABEL_CONFIRMED'
    WHEN 'AUDIT_TEST_LABEL_QUEUED' THEN 'PRINTER_TEST_LABEL_QUEUED'
    WHEN 'AUDIT_DISCOVERY' THEN 'PRINTER_DISCOVERED'
    ELSE 'PRINTER_'||p_operation END;
  PERFORM app_rls.printing_write_audit(
    actor."userId",actor.role,scope_org,scope_licensee,
    audit_action,'Printer',printer_row.id,
    jsonb_build_object('connectionType',printer_row."connectionType",
      'deliveryMode',printer_row."deliveryMode",
      'evidence',coalesce(p_payload->'evidence','{}'::jsonb))
  );
  RETURN to_jsonb(printer_row)||jsonb_build_object('removed',p_operation='DELETE');
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.printing_idempotency(
  p_capability text,
  p_purpose text,
  p_request_id text,
  p_operation text,
  p_action text,
  p_key_hash text,
  p_request_hash text,
  p_status_code integer,
  p_response jsonb
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public
AS $fn$
DECLARE
  actor record;
  row_value record;
  inserted boolean:=false;
  expected_scope text;
  now_at timestamp without time zone:=transaction_timestamp();
BEGIN
  IF p_purpose<>'printing-idempotency'
     OR p_operation NOT IN ('BEGIN','COMPLETE','ABORT')
     OR p_action NOT IN ('PRINT_JOB_CREATE','PRINTER_TEST_LABEL')
     OR p_key_hash !~ '^[0-9a-f]{64}$'
     OR p_request_hash !~ '^[0-9a-f]{64}$'
     OR (p_operation='COMPLETE' AND p_status_code NOT BETWEEN 100 AND 599)
     OR jsonb_typeof(coalesce(p_response,'{}'::jsonb))<>'object'
  THEN RAISE EXCEPTION 'PRINTING_IDEMPOTENCY_DENIED' USING ERRCODE='42501'; END IF;

  SELECT * INTO STRICT actor
    FROM app_rls.printing_bind_actor(p_capability,p_purpose,p_request_id,NULL);
  expected_scope:='printing:'||p_action||':actor:'||actor."userId";
  PERFORM set_config('app.printing_operation','printing-idempotency-'||lower(p_operation),true),
          set_config('app.printing_idempotency_key_hash',p_key_hash,true);

  SELECT k.id,k."keyHash",k.action,k.scope,k."requestHash",k."statusCode",k."responsePayload",
    k."completedAt",k."expiresAt" INTO row_value FROM public."ActionIdempotencyKey" k
    WHERE "keyHash"=p_key_hash FOR UPDATE;
  IF p_operation='ABORT' THEN
    IF NOT FOUND THEN RETURN jsonb_build_object('aborted',true,'idempotent',true); END IF;
    IF row_value.action IS DISTINCT FROM p_action
       OR row_value.scope IS DISTINCT FROM expected_scope
       OR row_value."requestHash" IS DISTINCT FROM p_request_hash
    THEN RAISE EXCEPTION 'IDEMPOTENCY_KEY_PAYLOAD_MISMATCH'; END IF;
    IF row_value."completedAt" IS NOT NULL
    THEN RETURN jsonb_build_object('aborted',false,'idempotent',true); END IF;
    UPDATE public."ActionIdempotencyKey" SET "expiresAt"=now_at-interval '1 microsecond'
      WHERE "keyHash"=p_key_hash;
    RETURN jsonb_build_object('aborted',true,'idempotent',false);
  END IF;
  IF FOUND AND row_value."expiresAt"<=now_at THEN
    UPDATE public."ActionIdempotencyKey" SET
      action=p_action,scope=expected_scope,"requestHash"=p_request_hash,
      "statusCode"=NULL,"responsePayload"=NULL,"completedAt"=NULL,
      "createdAt"=now_at,"expiresAt"=now_at+interval '10 minutes'
      WHERE "keyHash"=p_key_hash
      RETURNING id,"keyHash",action,scope,"requestHash","statusCode","responsePayload","completedAt","expiresAt"
      INTO row_value;
    inserted:=true;
  ELSIF NOT FOUND THEN
    BEGIN
      INSERT INTO public."ActionIdempotencyKey"(
        id,"keyHash",action,scope,"requestHash","createdAt","expiresAt"
      ) VALUES (
        gen_random_uuid()::text,p_key_hash,p_action,expected_scope,p_request_hash,
        now_at,now_at+interval '10 minutes'
      ) RETURNING id,"keyHash",action,scope,"requestHash","statusCode","responsePayload","completedAt","expiresAt"
      INTO row_value;
      inserted:=true;
    EXCEPTION WHEN unique_violation THEN
      SELECT k.id,k."keyHash",k.action,k.scope,k."requestHash",k."statusCode",k."responsePayload",
        k."completedAt",k."expiresAt" INTO STRICT row_value FROM public."ActionIdempotencyKey" k
        WHERE "keyHash"=p_key_hash FOR UPDATE;
    END;
  END IF;

  IF row_value.action IS DISTINCT FROM p_action
     OR row_value.scope IS DISTINCT FROM expected_scope
     OR row_value."requestHash" IS DISTINCT FROM p_request_hash
  THEN RAISE EXCEPTION 'IDEMPOTENCY_KEY_PAYLOAD_MISMATCH'; END IF;

  IF p_operation='BEGIN' THEN
    IF row_value."completedAt" IS NOT NULL THEN
      RETURN jsonb_build_object(
        'replayed',true,'keyHash',row_value."keyHash",
        'statusCode',coalesce(row_value."statusCode",200),
        'responsePayload',coalesce(row_value."responsePayload",'{}'::jsonb)
      );
    END IF;
    IF NOT inserted THEN RAISE EXCEPTION 'IDEMPOTENCY_KEY_IN_PROGRESS'; END IF;
    RETURN jsonb_build_object('replayed',false,'keyHash',row_value."keyHash");
  END IF;

  IF row_value."completedAt" IS NOT NULL THEN
    RETURN jsonb_build_object('completed',true,'idempotent',true);
  END IF;
  UPDATE public."ActionIdempotencyKey" SET
    "statusCode"=p_status_code,"responsePayload"=p_response,
    "completedAt"=now_at
    WHERE "keyHash"=p_key_hash;
  RETURN jsonb_build_object('completed',true,'idempotent',false);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.printing_connector_registration(
  p_capability text,
  p_purpose text,
  p_request_id text,
  p_operation text,
  p_payload jsonb
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public
AS $fn$
DECLARE
  actor record;
  registration record;
  printer_input jsonb;
  printer_id text;
  native_id text;
  printer_name text;
  now_at timestamp without time zone:=transaction_timestamp();
  expires_at timestamp without time zone;
  trust_valid boolean;
BEGIN
  IF p_purpose<>'printing-connector-registration'
     OR p_operation NOT IN ('LOOKUP','HEARTBEAT')
     OR jsonb_typeof(coalesce(p_payload,'{}'::jsonb))<>'object'
  THEN RAISE EXCEPTION 'PRINTING_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;
  SELECT * INTO STRICT actor
    FROM app_rls.printing_bind_actor(p_capability,p_purpose,p_request_id,NULL);
  IF actor.role<>'MANUFACTURER_ADMIN'
  THEN RAISE EXCEPTION 'PRINTING_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM set_config('app.printing_operation','printing-connector-registration-'||lower(p_operation),true),
          set_config('app.printing_user_id',actor."userId",true);

  IF p_operation='LOOKUP' THEN
    SELECT pr.id,pr."userId",pr."orgId",pr."licenseeId",pr."deviceFingerprint",pr."agentId",
      pr."publicKeyPem",pr."trustStatus",pr."revokedAt",pr."approvedAt",pr."lastSeenAt",pr."updatedAt"
      INTO registration
      FROM public."PrinterRegistration" pr
      WHERE pr."userId"=actor."userId" AND pr."revokedAt" IS NULL
        AND (
          nullif(p_payload->>'deviceFingerprint','') IS NULL
          OR pr."deviceFingerprint"=p_payload->>'deviceFingerprint'
        )
      ORDER BY pr."approvedAt" DESC NULLS LAST,pr."lastSeenAt" DESC NULLS LAST,pr."updatedAt" DESC
      LIMIT 1;
    RETURN CASE WHEN registration.id IS NULL THEN NULL ELSE jsonb_build_object(
      'id',registration.id,'agentId',registration."agentId",
      'deviceFingerprint',registration."deviceFingerprint",
      'publicKeyPem',registration."publicKeyPem",'trustStatus',registration."trustStatus",
      'revokedAt',registration."revokedAt"
    ) END;
  END IF;

  trust_valid:=coalesce((p_payload->>'signatureValid')::boolean,false)
    AND coalesce((p_payload->>'connected')::boolean,false);
  expires_at:=nullif(p_payload->>'expiresAt','')::timestamp without time zone;
  IF length(btrim(coalesce(p_payload->>'agentId',''))) NOT BETWEEN 1 AND 180
     OR length(btrim(coalesce(p_payload->>'deviceFingerprint',''))) NOT BETWEEN 8 AND 256
     OR p_payload->>'publicKeyPem' NOT LIKE '%BEGIN%PUBLIC KEY%'
     OR length(p_payload->>'publicKeyPem')>8000
     OR p_payload->>'signedPayloadHash' !~ '^[0-9a-f]{64}$'
     OR length(btrim(coalesce(p_payload->>'heartbeatNonce',''))) NOT BETWEEN 12 AND 180
     OR expires_at<=now_at OR expires_at>now_at+interval '15 minutes'
     OR jsonb_typeof(coalesce(p_payload->'metadata','{}'::jsonb))<>'object'
     OR jsonb_typeof(coalesce(p_payload->'printers','[]'::jsonb))<>'array'
     OR jsonb_array_length(coalesce(p_payload->'printers','[]'::jsonb))>50
  THEN RAISE EXCEPTION 'CONNECTOR_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;

  SELECT pr.id,pr."userId",pr."orgId",pr."licenseeId",pr."deviceFingerprint",pr."agentId",
    pr."publicKeyPem",pr."trustStatus",pr."revokedAt",pr."approvedAt",pr."lastSeenAt",pr."updatedAt"
    INTO registration
    FROM public."PrinterRegistration" pr
    WHERE pr."userId"=actor."userId"
      AND pr."deviceFingerprint"=btrim(p_payload->>'deviceFingerprint')
    FOR UPDATE;
  IF registration.id IS NULL THEN
    registration.id:=gen_random_uuid()::text;
    PERFORM set_config('app.printing_registration_id',registration.id,true);
    INSERT INTO public."PrinterRegistration"(
      id,"userId","orgId","licenseeId","deviceFingerprint","agentId","publicKeyPem",
      "certFingerprint","trustStatus","trustReason","approvedAt","lastSeenAt","createdAt","updatedAt"
    ) VALUES (
      registration.id,actor."userId",actor."organizationId",actor."licenseeId",
      btrim(p_payload->>'deviceFingerprint'),btrim(p_payload->>'agentId'),
      p_payload->>'publicKeyPem',nullif(p_payload->>'certFingerprint',''),
      CASE WHEN trust_valid THEN 'TRUSTED' ELSE 'FAILED' END::public."PrinterTrustStatus",
      CASE WHEN trust_valid THEN NULL ELSE left(coalesce(p_payload->>'rejectionReason','Signature verification failed'),500) END,
      CASE WHEN trust_valid THEN now_at END,now_at,now_at,now_at
    ) RETURNING id,"userId","orgId","licenseeId","deviceFingerprint","agentId","publicKeyPem",
      "trustStatus","revokedAt","approvedAt","lastSeenAt","updatedAt" INTO registration;
  ELSE
    PERFORM set_config('app.printing_registration_id',registration.id,true);
    IF registration."revokedAt" IS NOT NULL
       OR registration."trustStatus"='REVOKED'::public."PrinterTrustStatus"
    THEN RAISE EXCEPTION 'CONNECTOR_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;
    UPDATE public."PrinterRegistration" SET
      "orgId"=actor."organizationId","licenseeId"=actor."licenseeId",
      "agentId"=btrim(p_payload->>'agentId'),
      "publicKeyPem"=CASE WHEN trust_valid THEN p_payload->>'publicKeyPem' ELSE "publicKeyPem" END,
      "certFingerprint"=coalesce("certFingerprint",nullif(p_payload->>'certFingerprint','')),
      "trustStatus"=CASE WHEN trust_valid THEN 'TRUSTED' ELSE 'FAILED' END::public."PrinterTrustStatus",
      "trustReason"=CASE WHEN trust_valid THEN NULL ELSE left(coalesce(p_payload->>'rejectionReason','Signature verification failed'),500) END,
      "approvedAt"=CASE WHEN trust_valid THEN coalesce("approvedAt",now_at) ELSE "approvedAt" END,
      "lastSeenAt"=now_at,"updatedAt"=now_at
      WHERE id=registration.id
      RETURNING id,"userId","orgId","licenseeId","deviceFingerprint","agentId","publicKeyPem",
        "trustStatus","revokedAt","approvedAt","lastSeenAt","updatedAt" INTO registration;
  END IF;

  IF trust_valid THEN
    UPDATE public."PrinterRegistration"
      SET "trustStatus"='REVOKED',"trustReason"='Replaced by a newer signed connector registration',
          "revokedAt"=now_at,"updatedAt"=now_at
      WHERE "userId"=actor."userId" AND id<>registration.id AND "revokedAt" IS NULL;
  END IF;

  INSERT INTO public."PrinterAttestation"(
    id,"printerRegistrationId","signedPayloadHash","heartbeatNonce","attestedAt","expiresAt",
    "sourceIpHash","userAgentHash","mtlsFingerprint","signatureValid","trustValid",
    "rejectionReason",metadata,"createdAt"
  ) VALUES (
    gen_random_uuid()::text,registration.id,p_payload->>'signedPayloadHash',
    btrim(p_payload->>'heartbeatNonce'),now_at,expires_at,
    nullif(p_payload->>'sourceIpHash',''),nullif(p_payload->>'userAgentHash',''),
    nullif(p_payload->>'certFingerprint',''),coalesce((p_payload->>'signatureValid')::boolean,false),
    trust_valid,nullif(left(p_payload->>'rejectionReason',500),''),
    coalesce(p_payload->'metadata','{}'::jsonb),now_at
  ) ON CONFLICT ("printerRegistrationId","heartbeatNonce") DO NOTHING;

  IF trust_valid THEN
    FOR printer_input IN SELECT value FROM jsonb_array_elements(coalesce(p_payload->'printers','[]'::jsonb))
    LOOP
      native_id:=left(btrim(coalesce(printer_input->>'printerId',printer_input->>'id','')),180);
      printer_name:=left(btrim(coalesce(printer_input->>'printerName',printer_input->>'name','')),180);
      IF native_id='' OR printer_name='' THEN CONTINUE; END IF;
      SELECT p.id INTO printer_id FROM public."Printer" p
        WHERE p."printerRegistrationId"=registration.id AND p."nativePrinterId"=native_id
        FOR UPDATE;
      printer_id:=coalesce(printer_id,gen_random_uuid()::text);
      PERFORM set_config('app.printing_printer_id',printer_id,true);
      INSERT INTO public."Printer"(
        id,name,vendor,model,"connectionType","commandLanguage","nativePrinterId","agentId",
        "deviceFingerprint","printerRegistrationId","orgId","licenseeId","assignedUserId",
        "createdByUserId","isActive","isDefault","lastSeenAt","lastValidatedAt",
        "lastValidationStatus","capabilitySummary","calibrationProfile",metadata,"createdAt","updatedAt"
      ) VALUES (
        printer_id,printer_name,nullif(left(printer_input->>'vendor',180),''),
        nullif(left(printer_input->>'model',180),''),
        'LOCAL_AGENT'::public."PrinterConnectionType",
        coalesce(nullif(upper(printer_input->>'commandLanguage'),'')::public."PrinterCommandLanguage",
          'AUTO'::public."PrinterCommandLanguage"),
        native_id,registration."agentId",registration."deviceFingerprint",registration.id,
        actor."organizationId",actor."licenseeId",actor."userId",actor."userId",true,
        native_id=coalesce(p_payload->'metadata'->>'selectedPrinterId',p_payload->'metadata'->>'printerId'),
        now_at,now_at,'READY',printer_input->'capabilitySummary',
        p_payload->'metadata'->'calibrationProfile',
        jsonb_build_object('online',coalesce((printer_input->>'online')::boolean,true)),now_at,now_at
      )
      ON CONFLICT ("printerRegistrationId","nativePrinterId") DO UPDATE SET
        name=excluded.name,model=excluded.model,"agentId"=excluded."agentId",
        "deviceFingerprint"=excluded."deviceFingerprint","orgId"=excluded."orgId",
        "licenseeId"=excluded."licenseeId","assignedUserId"=excluded."assignedUserId",
        "isActive"=true,"isDefault"=excluded."isDefault","lastSeenAt"=now_at,
        "lastValidatedAt"=now_at,"lastValidationStatus"='READY',
        "capabilitySummary"=excluded."capabilitySummary",
        "calibrationProfile"=excluded."calibrationProfile",metadata=excluded.metadata,"updatedAt"=now_at;
    END LOOP;
  END IF;
  RETURN jsonb_build_object('registrationId',registration.id,'trusted',trust_valid,
    'trustStatus',registration."trustStatus",'idempotent',false);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.printing_test_label_job(
  p_capability text,
  p_request_id text,
  p_operation text,
  p_printer_id text,
  p_connector jsonb,
  p_job jsonb
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public
AS $fn$
DECLARE
  actor record;
  connector_actor record;
  registration record;
  printer_row record;
  current_job jsonb;
  next_job jsonb;
  now_at timestamp without time zone:=transaction_timestamp();
  issued_at timestamp without time zone;
  expires_at timestamp without time zone;
  fingerprint jsonb;
BEGIN
  IF p_operation NOT IN ('QUEUE','CLAIM','ACK','CONFIRM','FAIL')
     OR p_request_id !~* '^[0-9a-f-]{36}$'
     OR p_printer_id !~* '^[0-9a-f-]{36}$'
     OR jsonb_typeof(coalesce(p_connector,'{}'::jsonb))<>'object'
     OR jsonb_typeof(coalesce(p_job,'{}'::jsonb))<>'object'
  THEN RAISE EXCEPTION 'PRINTING_TEST_LABEL_DENIED' USING ERRCODE='42501'; END IF;

  IF p_operation='QUEUE' THEN
    SELECT * INTO STRICT actor
      FROM app_rls.printing_bind_actor(p_capability,'printing-test-label',p_request_id,NULL);
    IF actor.role<>'MANUFACTURER_ADMIN'
    THEN RAISE EXCEPTION 'PRINTING_TEST_LABEL_DENIED' USING ERRCODE='42501'; END IF;
    PERFORM set_config('app.printing_operation','printing-test-label-queue',true),
            set_config('app.printing_printer_id',p_printer_id,true);
    SELECT p.id,p.metadata,p."orgId",p."licenseeId",p."connectionType",p."deliveryMode",
      p."nativePrinterId",p."ipAddress",p.host,p.port INTO STRICT printer_row FROM public."Printer" p
      WHERE p.id=p_printer_id AND p."connectionType"='LOCAL_AGENT' AND p."isActive"
        AND p."assignedUserId"=actor."userId"
        AND EXISTS (
          SELECT 1 FROM public."ManufacturerLicenseeLink" ml
          JOIN public."Licensee" l ON l.id=ml."licenseeId"
          JOIN public."Organization" o ON o.id=l."orgId"
          WHERE ml."manufacturerId"=actor."userId" AND ml."licenseeId"=p."licenseeId"
            AND l."isActive" AND l."suspendedAt" IS NULL AND o."isActive"
        )
      FOR UPDATE;
    current_job:=printer_row.metadata->'pendingLocalAgentTestLabel';
    IF current_job IS NOT NULL
       AND coalesce(current_job->>'status','') NOT IN ('CONFIRMED','FAILED','EXPIRED')
       AND nullif(current_job->>'expiresAt','')::timestamp without time zone>now_at
    THEN RETURN current_job||jsonb_build_object('idempotent',true); END IF;
    expires_at:=nullif(p_job->>'expiresAt','')::timestamp without time zone;
    IF p_job->>'testJobId' !~* '^[0-9a-f-]{36}$'
       OR p_job->>'status'<>'PENDING'
       OR p_job->>'payloadHash' !~ '^[0-9a-f]{64}$'
       OR length(coalesce(p_job->>'payloadContent','')) NOT BETWEEN 1 AND 65536
       OR length(coalesce(p_job->>'code','')) NOT BETWEEN 1 AND 80
       OR expires_at<=now_at OR expires_at>now_at+interval '5 minutes'
    THEN RAISE EXCEPTION 'PRINTING_TEST_LABEL_DENIED' USING ERRCODE='42501'; END IF;
    UPDATE public."Printer" SET
      metadata=jsonb_set(coalesce(metadata,'{}'::jsonb),'{pendingLocalAgentTestLabel}',p_job,true),
      "updatedAt"=now_at
      WHERE id=printer_row.id
      RETURNING id,metadata,"orgId","licenseeId","connectionType","deliveryMode",
        "nativePrinterId","ipAddress",host,port INTO printer_row;
    PERFORM app_rls.printing_write_audit(
      actor."userId",actor.role,printer_row."orgId",printer_row."licenseeId",
      'PRINTER_TEST_LABEL_QUEUED','Printer',printer_row.id,
      jsonb_build_object('testJobId',p_job->>'testJobId')
    );
    RETURN p_job||jsonb_build_object('idempotent',false);
  END IF;

  IF session_user<>'mscqr_rls_cert_app'
  THEN RAISE EXCEPTION 'PRINTING_TEST_LABEL_DENIED' USING ERRCODE='42501'; END IF;
  issued_at:=nullif(p_connector->>'issuedAt','')::timestamp without time zone;
  IF p_connector->>'registrationId' !~* '^[0-9a-f-]{36}$'
     OR length(btrim(coalesce(p_connector->>'agentId',''))) NOT BETWEEN 1 AND 180
     OR length(btrim(coalesce(p_connector->>'deviceFingerprint',''))) NOT BETWEEN 8 AND 256
     OR p_connector->>'nonce' !~ '^[A-Za-z0-9_-]{16,160}$'
     OR issued_at IS NULL OR abs(extract(epoch FROM (now_at-issued_at)))>120
  THEN RAISE EXCEPTION 'PRINTING_TEST_LABEL_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM set_config('app.printing_operation','printing-connector-test-label-'||lower(p_operation),true),
          set_config('app.printing_request_id',p_request_id,true),
          set_config('app.printing_registration_id',p_connector->>'registrationId',true),
          set_config('app.printing_printer_id',p_printer_id,true);
  SELECT pr.id,pr."userId",pr."orgId",pr."licenseeId" INTO STRICT registration
    FROM public."PrinterRegistration" pr
    WHERE pr.id=p_connector->>'registrationId'
      AND pr."agentId"=p_connector->>'agentId'
      AND pr."deviceFingerprint"=p_connector->>'deviceFingerprint'
      AND pr."trustStatus"='TRUSTED' AND pr."revokedAt" IS NULL;
  PERFORM set_config('app.printing_user_id',registration."userId",true),
          set_config('app.printing_organization_id',coalesce(registration."orgId",''),true),
          set_config('app.printing_licensee_id',coalesce(registration."licenseeId",''),true);
  SELECT u.id,u.role::text AS role INTO STRICT connector_actor
    FROM public."User" u
    WHERE u.id=registration."userId" AND u."isActive" AND u."deletedAt" IS NULL;
  IF NOT EXISTS (
    SELECT 1 FROM public."PrinterAttestation" pa
    WHERE pa."printerRegistrationId"=registration.id
      AND pa."signatureValid" AND pa."trustValid" AND pa."expiresAt">now_at
  ) THEN RAISE EXCEPTION 'PRINTER_ATTESTATION_STALE'; END IF;
  SELECT p.id,p.metadata,p."orgId",p."licenseeId",p."connectionType",p."deliveryMode",
    p."nativePrinterId",p."ipAddress",p.host,p.port,p."printerUri",p."commandLanguage"
    INTO STRICT printer_row FROM public."Printer" p
    WHERE p.id=p_printer_id AND p."printerRegistrationId"=registration.id
      AND p."isActive" AND p."connectionType"='LOCAL_AGENT'
    FOR UPDATE;
  current_job:=printer_row.metadata->'pendingLocalAgentTestLabel';
  IF current_job IS NULL THEN RETURN jsonb_build_object('available',false); END IF;
  expires_at:=nullif(current_job->>'expiresAt','')::timestamp without time zone;
  IF expires_at IS NULL OR expires_at<=now_at THEN
    next_job:=current_job||jsonb_build_object(
      'status','EXPIRED','failedAt',now_at,
      'failedReason','The connector did not complete the printer test before expiry'
    );
    UPDATE public."Printer" SET
      metadata=jsonb_set(coalesce(metadata,'{}'::jsonb),'{pendingLocalAgentTestLabel}',next_job,true),
      "updatedAt"=now_at WHERE id=printer_row.id;
    RETURN jsonb_build_object('available',false);
  END IF;

  IF p_operation='CLAIM' THEN
    IF current_job->>'status'<>'PENDING' THEN RETURN jsonb_build_object('available',false); END IF;
    next_job:=current_job||jsonb_build_object('status','CLAIMED','claimedAt',now_at);
  ELSE
    IF p_job->>'testJobId' IS DISTINCT FROM current_job->>'testJobId'
    THEN RETURN jsonb_build_object('matched',false); END IF;
    IF p_operation='ACK' THEN
      IF current_job->>'status'='ACKED' THEN RETURN jsonb_build_object('matched',true,'idempotent',true); END IF;
      IF current_job->>'status'<>'CLAIMED' THEN RAISE EXCEPTION 'INVALID_STATE_TRANSITION'; END IF;
      next_job:=current_job||jsonb_build_object('status','ACKED','ackedAt',now_at,'ackMetadata',coalesce(p_job->'metadata','{}'::jsonb));
    ELSIF p_operation='CONFIRM' THEN
      IF current_job->>'status'='CONFIRMED' THEN RETURN jsonb_build_object('matched',true,'idempotent',true); END IF;
      IF current_job->>'status' NOT IN ('CLAIMED','ACKED') THEN RAISE EXCEPTION 'INVALID_STATE_TRANSITION'; END IF;
      next_job:=current_job||jsonb_build_object(
        'status','CONFIRMED','confirmedAt',now_at,
        'payloadType',p_job->>'payloadType','deviceJobRef',p_job->>'deviceJobRef',
        'confirmationMode',coalesce(p_job->>'confirmationMode','LOCAL_QUEUE'),
        'confirmMetadata',coalesce(p_job->'metadata','{}'::jsonb)
      );
    ELSE
      IF current_job->>'status' IN ('CONFIRMED','FAILED','EXPIRED')
      THEN RETURN jsonb_build_object('matched',true,'idempotent',true); END IF;
      next_job:=current_job||jsonb_build_object(
        'status','FAILED','failedAt',now_at,
        'failedReason',left(coalesce(p_job->>'reason','Connector reported test-label failure'),500)
      );
    END IF;
  END IF;

  fingerprint:=jsonb_build_object(
    'connectionType',printer_row."connectionType",
    'deliveryMode',coalesce(printer_row."deliveryMode",'DIRECT'),
    'nativePrinterId',printer_row."nativePrinterId",
    'ipAddress',printer_row."ipAddress",'host',printer_row.host,'port',printer_row.port,
    'printerUri',printer_row."printerUri",'commandLanguage',printer_row."commandLanguage"
  );
  UPDATE public."Printer" SET metadata=
    CASE WHEN p_operation='CONFIRM' THEN
      jsonb_set(
        jsonb_set(
          jsonb_set(
            jsonb_set(coalesce(metadata,'{}'::jsonb),'{pendingLocalAgentTestLabel}',next_job,true),
            '{lastTestLabelConfirmedAt}',to_jsonb(now_at),true
          ),
          '{lastTestLabelConnectionType}',to_jsonb('LOCAL_AGENT'::text),true
        ),
        '{lastTestLabelFingerprint}',fingerprint,true
      )||jsonb_build_object('lastTestLabelDeviceJobRef',p_job->>'deviceJobRef')
    ELSE jsonb_set(coalesce(metadata,'{}'::jsonb),'{pendingLocalAgentTestLabel}',next_job,true) END,
    "updatedAt"=now_at
    WHERE id=printer_row.id;
  IF p_operation IN ('ACK','CONFIRM','FAIL') THEN
    PERFORM app_rls.printing_write_audit(
      connector_actor.id,connector_actor.role,registration."orgId",registration."licenseeId",
      'PRINTER_TEST_LABEL_'||p_operation,'Printer',printer_row.id,
      jsonb_build_object(
        'testJobId',current_job->>'testJobId',
        'deviceJobRef',nullif(p_job->>'deviceJobRef','')
      )
    );
  END IF;
  RETURN CASE WHEN p_operation='CLAIM'
    THEN next_job||jsonb_build_object('available',true)
    ELSE jsonb_build_object('matched',true,'idempotent',false,'status',next_job->>'status') END;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.printing_create_job(
  p_capability text,
  p_purpose text,
  p_request_id text,
  p_batch_id text,
  p_printer_id text,
  p_quantity integer,
  p_range_start text,
  p_range_end text,
  p_print_mode text,
  p_payload_type text,
  p_print_lock_token_hash text,
  p_items jsonb
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public
AS $fn$
DECLARE
  actor record;
  batch_row record;
  printer_row record;
  job_id text:=gen_random_uuid()::text;
  session_id text:=gen_random_uuid()::text;
  now_at timestamp without time zone:=transaction_timestamp();
  item record;
  affected integer;
BEGIN
  IF p_purpose<>'printing-create-job'
     OR p_quantity NOT BETWEEN 1 AND 200000
     OR p_printer_id !~* '^[0-9a-f-]{36}$'
     OR p_print_mode NOT IN ('LOCAL_AGENT','NETWORK_DIRECT','NETWORK_IPP')
     OR p_payload_type NOT IN ('PDF','ZPL','TSPL','SBPL','EPL','DPL','HONEYWELL_DP','HONEYWELL_FINGERPRINT','IPL','CPCL','ESC_POS','JSON','OTHER')
     OR jsonb_typeof(p_items)<>'array' OR jsonb_array_length(p_items)<>p_quantity
     OR (p_print_lock_token_hash IS NOT NULL AND p_print_lock_token_hash !~ '^[0-9a-f]{64}$')
  THEN RAISE EXCEPTION 'PRINTING_INVALID_INPUT'; END IF;

  SELECT * INTO STRICT actor FROM app_rls.printing_bind_actor(
    p_capability,p_purpose,p_request_id,p_batch_id
  );
  IF actor.role<>'MANUFACTURER_ADMIN' OR actor."batchManufacturerId" IS DISTINCT FROM actor."userId" THEN
    RAISE EXCEPTION 'PRINTING_BOUNDARY_DENIED' USING ERRCODE='42501';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('printing_batch_'||p_batch_id,0));
  SELECT b.id,b."licenseeId",b."lifecycleState",b."releasedAt",b."suspendedAt"
    INTO STRICT batch_row FROM public."Batch" b WHERE b.id=p_batch_id FOR UPDATE;
  IF batch_row."lifecycleState" NOT IN ('CODES_GENERATED'::public."BatchLifecycleState",'PRINT_ACKNOWLEDGED'::public."BatchLifecycleState")
     OR batch_row."releasedAt" IS NOT NULL OR batch_row."suspendedAt" IS NOT NULL
  THEN RAISE EXCEPTION 'INVALID_STATE_TRANSITION'; END IF;
  IF EXISTS (
    SELECT 1 FROM public."PrintJob" j JOIN public."PrintSession" ps ON ps."printJobId"=j.id
     WHERE j."batchId"=p_batch_id AND j."manufacturerId"=actor."userId"
       AND j.status IN ('PENDING','SENT','PAUSED') AND ps.status IN ('ACTIVE','PAUSED','RESUME_PENDING')
  ) THEN RAISE EXCEPTION 'ACTIVE_PRINT_JOB_EXISTS'; END IF;

  SELECT p.id,p."connectionType",p."commandLanguage",p."printerRegistrationId",p."nativePrinterId"
    INTO printer_row FROM public."Printer" p
   WHERE p.id=p_printer_id AND p."isActive"
     AND p."licenseeId"=batch_row."licenseeId"
     AND (
       p."assignedUserId"=actor."userId"
       OR EXISTS (
         SELECT 1 FROM public."PrinterRegistration" pr
          WHERE pr.id=p."printerRegistrationId" AND pr."userId"=actor."userId"
            AND pr."trustStatus"='TRUSTED'::public."PrinterTrustStatus" AND pr."revokedAt" IS NULL
       )
     );
  IF NOT FOUND THEN
    RAISE EXCEPTION 'PRINTING_BOUNDARY_DENIED' USING ERRCODE='42501';
  END IF;
  IF printer_row."connectionType"::text<>p_print_mode AND NOT (
    printer_row."connectionType"='LOCAL_AGENT'::public."PrinterConnectionType" AND p_print_mode='LOCAL_AGENT'
  ) THEN RAISE EXCEPTION 'PRINTER_NOT_READY'; END IF;
  IF (
    printer_row."connectionType"='NETWORK_IPP'::public."PrinterConnectionType"
    AND p_payload_type<>'PDF'
  ) OR (
    printer_row."connectionType"<>'NETWORK_IPP'::public."PrinterConnectionType"
    AND p_payload_type<>CASE
      WHEN printer_row."commandLanguage"::text IN (
        'ZPL','TSPL','SBPL','EPL','DPL','HONEYWELL_DP','HONEYWELL_FINGERPRINT',
        'IPL','CPCL'
      ) THEN printer_row."commandLanguage"::text
      ELSE 'ZPL' END
  ) THEN RAISE EXCEPTION 'PRINTER_PAYLOAD_MISMATCH'; END IF;
  IF printer_row."connectionType"='LOCAL_AGENT'::public."PrinterConnectionType" THEN
    IF printer_row."printerRegistrationId" IS NULL THEN RAISE EXCEPTION 'PRINTER_ATTESTATION_STALE'; END IF;
    PERFORM set_config('app.printing_registration_id',printer_row."printerRegistrationId",true);
    IF NOT EXISTS (
      SELECT 1 FROM public."PrinterAttestation" pa
      WHERE pa."printerRegistrationId"=printer_row."printerRegistrationId"
        AND pa."signatureValid" AND pa."trustValid" AND pa."expiresAt">now_at
        AND coalesce((pa.metadata->>'connected')::boolean,false)
        AND coalesce(pa.metadata->>'selectedPrinterId',pa.metadata->>'printerId','')
          IN (printer_row.id,coalesce(printer_row."nativePrinterId",''))
    ) THEN RAISE EXCEPTION 'PRINTER_ATTESTATION_STALE'; END IF;
  END IF;

  PERFORM set_config('app.printing_job_id',job_id,true),
          set_config('app.printing_session_row_id',session_id,true),
          set_config('app.printing_printer_id',p_printer_id,true);
  INSERT INTO public."PrintJob"(
    id,"jobNumber","batchId","manufacturerId","printerId",status,"printMode","pipelineState",
    "payloadType",quantity,"itemCount","rangeStart","rangeEnd","printLockTokenHash","createdAt","updatedAt"
  ) VALUES (
    job_id,'PJ-'||to_char(now_at,'YYYYMMDD')||'-'||upper(substr(replace(job_id,'-',''),1,8)),
    p_batch_id,actor."userId",p_printer_id,'PENDING',p_print_mode::public."PrintDispatchMode",
    CASE WHEN p_print_mode='LOCAL_AGENT' THEN 'QUEUED' ELSE 'PREFLIGHT_OK' END::public."PrintPipelineState",
    p_payload_type::public."PrintPayloadType",p_quantity,p_quantity,p_range_start,p_range_end,
    p_print_lock_token_hash,now_at,now_at
  );
  INSERT INTO public."PrintSession"(
    id,"printJobId","batchId","manufacturerId","printerRegistrationId","printerId",
    status,"totalItems","createdAt","updatedAt"
  ) VALUES (
    session_id,job_id,p_batch_id,actor."userId",printer_row."printerRegistrationId",p_printer_id,
    'ACTIVE',p_quantity,now_at,now_at
  );

  FOR item IN SELECT value,row_number() OVER () AS seq FROM jsonb_array_elements(p_items)
  LOOP
    IF item.value->>'qrCodeId' !~* '^[0-9a-f-]{36}$'
       OR item.value->>'tokenNonce' !~ '^(?:[0-9a-f]{64}|[A-Za-z0-9_-]{22})$'
       OR item.value->>'tokenHash' !~ '^[0-9a-f]{64}$'
       OR (item.value->>'tokenExpiresAt')::timestamp without time zone<=now_at
    THEN RAISE EXCEPTION 'PRINTING_INVALID_INPUT'; END IF;
    UPDATE public."QRCode" q SET
      status='ACTIVATED', "tokenNonce"=item.value->>'tokenNonce',
      "tokenIssuedAt"=now_at,"tokenExpiresAt"=(item.value->>'tokenExpiresAt')::timestamp without time zone,
      "tokenHash"=item.value->>'tokenHash',"printJobId"=job_id,
      "issuanceMode"='GOVERNED_PRINT',"updatedAt"=now_at
     WHERE q.id=item.value->>'qrCodeId' AND q."batchId"=p_batch_id
       AND q."licenseeId"=batch_row."licenseeId"
       AND q.status='ALLOCATED' AND q."printJobId" IS NULL
       AND (p_range_start IS NULL OR q."displayCode">=p_range_start)
       AND (p_range_end IS NULL OR q."displayCode"<=p_range_end);
    GET DIAGNOSTICS affected=ROW_COUNT;
    IF affected<>1 THEN RAISE EXCEPTION 'BATCH_BUSY'; END IF;
    INSERT INTO public."PrintItem"(
      id,"printSessionId","qrCodeId",code,state,"pipelineState","issueSequence","createdAt","updatedAt"
    ) SELECT gen_random_uuid()::text,session_id,q.id,q.code,'RESERVED','QUEUED',item.seq,now_at,now_at
      FROM public."QRCode" q WHERE q.id=item.value->>'qrCodeId';
  END LOOP;
  PERFORM app_rls.printing_write_audit(
    actor."userId",actor.role,actor."organizationId",actor."batchLicenseeId",
    'PRINT_JOB_CREATED','PrintJob',job_id,
    jsonb_build_object('batchId',p_batch_id,'printerId',p_printer_id,'quantity',p_quantity,'printSessionId',session_id)
  );
  RETURN jsonb_build_object(
    'job',jsonb_build_object('id',job_id,'batchId',p_batch_id,'manufacturerId',actor."userId",
      'printerId',p_printer_id,'status','PENDING','printMode',p_print_mode,'pipelineState',
      CASE WHEN p_print_mode='LOCAL_AGENT' THEN 'QUEUED' ELSE 'PREFLIGHT_OK' END,'quantity',p_quantity,'createdAt',now_at),
    'session',jsonb_build_object('id',session_id,'printJobId',job_id,'batchId',p_batch_id,
      'manufacturerId',actor."userId",'printerId',p_printer_id,'status','ACTIVE','totalItems',p_quantity),
    'preparedCount',p_quantity
  );
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.printing_control_job(
  p_capability text,
  p_purpose text,
  p_request_id text,
  p_job_id text,
  p_operation text,
  p_reason text DEFAULT NULL
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public
AS $fn$
DECLARE actor record; job_row record; session_row record; now_at timestamp without time zone:=transaction_timestamp();
  target_job_status public."PrintJobStatus"; target_pipeline public."PrintPipelineState"; target_session public."PrintSessionStatus";
BEGIN
  IF p_purpose<>'printing-job-control' OR p_operation NOT IN ('PAUSE','RESUME','STOP','ABANDON')
     OR p_job_id !~* '^[0-9a-f-]{36}$' OR length(coalesce(p_reason,''))>500
  THEN RAISE EXCEPTION 'PRINTING_INVALID_INPUT'; END IF;
  SELECT * INTO STRICT actor FROM app_rls.printing_bind_actor(
    p_capability,p_purpose,p_request_id,NULL
  );
  PERFORM set_config('app.printing_job_id',p_job_id,true);
  SELECT j.id,j."batchId",j."manufacturerId",j.status
    INTO STRICT job_row FROM public."PrintJob" j WHERE j.id=p_job_id FOR UPDATE;
  SELECT * INTO STRICT actor FROM app_rls.printing_bind_actor(
    p_capability,p_purpose,p_request_id,job_row."batchId"
  );
  IF actor.role='MANUFACTURER_ADMIN' AND job_row."manufacturerId"<>actor."userId" THEN
    RAISE EXCEPTION 'PRINTING_BOUNDARY_DENIED' USING ERRCODE='42501';
  END IF;
  SELECT ps.id,ps.status INTO STRICT session_row
    FROM public."PrintSession" ps WHERE ps."printJobId"=p_job_id FOR UPDATE;
  PERFORM set_config('app.printing_job_id',p_job_id,true),
          set_config('app.printing_session_row_id',session_row.id,true);

  IF p_operation='PAUSE' THEN
    IF job_row.status NOT IN ('PENDING','SENT') OR session_row.status<>'ACTIVE' THEN RAISE EXCEPTION 'INVALID_STATE_TRANSITION'; END IF;
    target_job_status:='PAUSED'; target_pipeline:='PAUSED'; target_session:='PAUSED';
  ELSIF p_operation='RESUME' THEN
    IF job_row.status<>'PAUSED' OR session_row.status NOT IN ('PAUSED','RESUME_PENDING') THEN RAISE EXCEPTION 'INVALID_STATE_TRANSITION'; END IF;
    target_job_status:='SENT'; target_pipeline:='RESUME_PENDING'; target_session:='RESUME_PENDING';
  ELSE
    IF job_row.status IN ('CONFIRMED','CANCELLED','STOPPED') THEN
      RETURN jsonb_build_object('jobId',p_job_id,'status',job_row.status,'idempotent',true);
    END IF;
    IF p_operation='ABANDON' AND EXISTS (
      SELECT 1 FROM public."PrintItem" pi WHERE pi."printSessionId"=session_row.id AND pi."printConfirmedAt" IS NOT NULL
    ) THEN RAISE EXCEPTION 'PHYSICAL_CONFIRMATION_PRESENT'; END IF;
    target_job_status:=CASE WHEN p_operation='ABANDON' THEN 'CANCELLED' ELSE 'STOPPED' END;
    target_pipeline:=CASE WHEN p_operation='ABANDON' THEN 'STOPPED' ELSE 'STOPPED' END;
    target_session:=CASE WHEN p_operation='ABANDON' THEN 'CANCELLED' ELSE 'STOPPED' END;
    UPDATE public."PrintItem" SET state='CANCELLED', "pipelineState"='STOPPED',
      "failureReason"=nullif(btrim(p_reason),''),"updatedAt"=now_at
      WHERE "printSessionId"=session_row.id AND state NOT IN ('PRINT_CONFIRMED','CLOSED','CANCELLED');
  END IF;
  UPDATE public."PrintSession" SET status=target_session,
    "failedReason"=CASE WHEN p_operation IN ('STOP','ABANDON') THEN nullif(btrim(p_reason),'') ELSE "failedReason" END,
    "completedAt"=CASE WHEN p_operation IN ('STOP','ABANDON') THEN now_at ELSE "completedAt" END,
    "updatedAt"=now_at WHERE id=session_row.id;
  UPDATE public."PrintJob" SET status=target_job_status,"pipelineState"=target_pipeline,
    "failureReason"=CASE WHEN p_operation IN ('STOP','ABANDON') THEN nullif(btrim(p_reason),'') ELSE "failureReason" END,
    "completedAt"=CASE WHEN p_operation IN ('STOP','ABANDON') THEN now_at ELSE "completedAt" END,
    "updatedAt"=now_at WHERE id=p_job_id;
  PERFORM app_rls.printing_write_audit(actor."userId",actor.role,actor."organizationId",actor."batchLicenseeId",
    'PRINT_JOB_'||p_operation,'PrintJob',p_job_id,jsonb_build_object('reason',nullif(btrim(p_reason),'')));
  RETURN jsonb_build_object('jobId',p_job_id,'status',target_job_status,'pipelineState',target_pipeline,
    'sessionStatus',target_session,'idempotent',false);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.printing_connector_event(
  p_registration_id text,
  p_agent_id text,
  p_device_fingerprint text,
  p_nonce text,
  p_issued_at timestamp without time zone,
  p_request_id text,
  p_operation text,
  p_job_id text,
  p_item_id text,
  p_printer_id text,
  p_payload_hash text,
  p_device_job_ref text,
  p_details jsonb DEFAULT '{}'::jsonb
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public
AS $fn$
DECLARE registration record; printer_row record; job_row record; session_row record; item_row record;
  now_at timestamp without time zone:=transaction_timestamp(); remaining integer; audit_actor text;
BEGIN
  IF p_operation NOT IN ('CLAIM','ACK','CONFIRM','FAIL')
     OR p_request_id !~* '^[0-9a-f-]{36}$' OR p_registration_id !~* '^[0-9a-f-]{36}$'
     OR (p_operation<>'CLAIM' AND p_job_id !~* '^[0-9a-f-]{36}$')
     OR (p_item_id IS NOT NULL AND p_item_id !~* '^[0-9a-f-]{36}$')
     OR p_nonce !~ '^[A-Za-z0-9_-]{16,160}$'
     OR abs(extract(epoch FROM (now_at-p_issued_at)))>120
     OR jsonb_typeof(coalesce(p_details,'{}'::jsonb))<>'object'
  THEN RAISE EXCEPTION 'CONNECTOR_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;
  IF session_user<>'mscqr_rls_cert_app' THEN RAISE EXCEPTION 'CONNECTOR_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;

  PERFORM set_config('app.printing_operation','printing-connector-'||lower(p_operation),true),
          set_config('app.printing_request_id',p_request_id,true),
          set_config('app.printing_registration_id',p_registration_id,true),
          set_config('app.printing_job_id',coalesce(p_job_id,''),true),
          set_config('app.printing_item_id',coalesce(p_item_id,''),true);
  SELECT pr."userId" INTO STRICT registration FROM public."PrinterRegistration" pr
   WHERE pr.id=p_registration_id AND pr."agentId"=p_agent_id
     AND pr."deviceFingerprint"=p_device_fingerprint
     AND pr."trustStatus"='TRUSTED' AND pr."revokedAt" IS NULL;
  INSERT INTO public."PrinterAttestation"(
    id,"printerRegistrationId","signedPayloadHash","heartbeatNonce","attestedAt","expiresAt",
    "signatureValid","trustValid",metadata,"createdAt"
  ) VALUES (
    gen_random_uuid()::text,p_registration_id,coalesce(p_payload_hash,repeat('0',64)),p_nonce,
    p_issued_at,p_issued_at+interval '2 minutes',true,true,
    jsonb_build_object('operation',p_operation,'requestId',p_request_id),now_at
  );
  SELECT p.id,p.name,p."connectionType",p."commandLanguage",p."nativePrinterId",
    p."ipAddress",p.port,p."calibrationProfile",p."capabilitySummary",p.metadata
    INTO STRICT printer_row FROM public."Printer" p
   WHERE (p.id=p_printer_id OR p."nativePrinterId"=p_printer_id)
     AND p."printerRegistrationId"=p_registration_id AND p."isActive"
   ORDER BY (p.id=p_printer_id) DESC,p."isDefault" DESC,p."updatedAt" DESC LIMIT 1;
  PERFORM set_config('app.printing_printer_id',printer_row.id,true);
  IF p_operation='CLAIM' THEN
    SELECT j.id,j."batchId",j."manufacturerId",j."jobNumber",j."reprintOfJobId"
      INTO job_row FROM public."PrintJob" j
     WHERE j."printerId"=printer_row.id AND j."manufacturerId"=registration."userId"
       AND j."printMode"='LOCAL_AGENT' AND j.status IN ('PENDING','SENT')
     ORDER BY j."createdAt",j.id FOR UPDATE OF j SKIP LOCKED LIMIT 1;
    IF NOT FOUND THEN RETURN jsonb_build_object('available',false); END IF;
  ELSE
    SELECT j.id,j."batchId",j."manufacturerId",j."jobNumber",j."reprintOfJobId"
      INTO STRICT job_row FROM public."PrintJob" j
     WHERE j.id=p_job_id AND j."printerId"=printer_row.id AND j."manufacturerId"=registration."userId"
       AND j."printMode"='LOCAL_AGENT' FOR UPDATE;
  END IF;
  PERFORM set_config('app.printing_job_id',job_row.id,true),
          set_config('app.printing_batch_id',job_row."batchId",true),
          set_config('app.printing_user_id',registration."userId",true);
  PERFORM set_config('app.printing_licensee_id',(
    SELECT b."licenseeId" FROM public."Batch" b WHERE b.id=job_row."batchId"
  ),true);
  SELECT ps.id,ps."issuedItems" INTO STRICT session_row FROM public."PrintSession" ps
   WHERE ps."printJobId"=job_row.id AND ps."printerRegistrationId"=p_registration_id
     AND ps.status='ACTIVE' FOR UPDATE;
  audit_actor:=registration."userId";
  PERFORM set_config('app.printing_session_row_id',session_row.id,true),
          set_config('app.printing_printer_id',printer_row.id,true);

  IF p_operation='CLAIM' THEN
    SELECT pi.id,pi."qrCodeId",pi.code,pi.state,pi."issueSequence"
      INTO item_row FROM public."PrintItem" pi
     WHERE pi."printSessionId"=session_row.id AND pi.state='RESERVED'
     ORDER BY pi."issueSequence" NULLS LAST,pi.id FOR UPDATE SKIP LOCKED LIMIT 1;
    IF NOT FOUND THEN RETURN jsonb_build_object('available',false); END IF;
    PERFORM set_config('app.printing_item_id',item_row.id,true);
    UPDATE public."PrintItem" SET state='ISSUED',"pipelineState"='SENT_TO_PRINTER',
      "issuedAt"=now_at,"dispatchedAt"=now_at,"issueSequence"=session_row."issuedItems"+1,
      "attemptCount"="attemptCount"+1,"updatedAt"=now_at
      WHERE id=item_row.id;
    item_row."issueSequence":=session_row."issuedItems"+1;
    UPDATE public."PrintSession" SET "issuedItems"="issuedItems"+1,"updatedAt"=now_at WHERE id=session_row.id;
    UPDATE public."PrintJob" SET status='SENT',"pipelineState"='SENT_TO_PRINTER',
      "sentAt"=coalesce("sentAt",now_at),"updatedAt"=now_at WHERE id=job_row.id;
    UPDATE public."Batch" SET "lifecycleState"='PRINT_ACKNOWLEDGED',"updatedAt"=now_at
      WHERE id=job_row."batchId" AND "lifecycleState"='CODES_GENERATED';
    INSERT INTO public."PrintItemEvent"(id,"printItemId","eventType","previousState","nextState",details,"actorUserId","createdAt")
    VALUES(gen_random_uuid()::text,item_row.id,'ISSUED','RESERVED','ISSUED',
      jsonb_build_object('dispatchMode','LOCAL_AGENT','registrationId',p_registration_id),audit_actor,now_at);
    RETURN (
      SELECT jsonb_build_object(
        'available',true,'printJobId',job_row.id,'printSessionId',session_row.id,
        'printItemId',item_row.id,'qrCodeId',item_row."qrCodeId",'code',item_row.code,
        'issueSequence',item_row."issueSequence",'issuedAt',now_at,
        'jobNumber',job_row."jobNumber",'manufacturerId',job_row."manufacturerId",
        'reprintOfJobId',job_row."reprintOfJobId",
        'qrCode',jsonb_build_object(
          'id',q.id,'code',q.code,'displayCode',q."displayCode",'batchId',q."batchId",
          'licenseeId',q."licenseeId",'tokenNonce',q."tokenNonce",'tokenIssuedAt',q."tokenIssuedAt",
          'tokenExpiresAt',q."tokenExpiresAt",'tokenHash',q."tokenHash",'replayEpoch',q."replayEpoch",
          'status',q.status
        ),
        'batch',jsonb_build_object(
          'id',b.id,'name',b.name,'licenseeId',b."licenseeId",'metadata',b.metadata,
          'licensee',jsonb_build_object('id',l.id,'name',l.name,'prefix',l.prefix,'location',l.location,'metadata',l.metadata)
        ),
        'manufacturer',jsonb_build_object('id',u.id,'name',u.name,'location',u.location,'metadata',u.metadata),
        'printer',jsonb_build_object(
          'id',printer_row.id,'name',printer_row.name,'connectionType',printer_row."connectionType",
          'commandLanguage',printer_row."commandLanguage",'nativePrinterId',printer_row."nativePrinterId",
          'ipAddress',printer_row."ipAddress",'port',printer_row.port,
          'calibrationProfile',printer_row."calibrationProfile",
          'capabilitySummary',printer_row."capabilitySummary",'metadata',printer_row.metadata
        )
      )
      FROM public."QRCode" q
      JOIN public."Batch" b ON b.id=job_row."batchId"
      JOIN public."Licensee" l ON l.id=b."licenseeId"
      JOIN public."User" u ON u.id=job_row."manufacturerId"
      WHERE q.id=item_row."qrCodeId"
    );
  END IF;

  SELECT pi.id,pi."qrCodeId",pi.state INTO STRICT item_row FROM public."PrintItem" pi
   WHERE pi.id=p_item_id AND pi."printSessionId"=session_row.id FOR UPDATE;
  IF p_operation='ACK' THEN
    IF item_row.state='AGENT_ACKED' THEN
      RETURN jsonb_build_object('printItemId',item_row.id,'acknowledged',true,'idempotent',true);
    END IF;
    IF item_row.state<>'ISSUED' THEN RAISE EXCEPTION 'INVALID_STATE_TRANSITION'; END IF;
    UPDATE public."PrintItem" SET state='AGENT_ACKED',"pipelineState"='PRINTER_ACKNOWLEDGED',
      "agentAckedAt"=now_at,"deviceJobRef"=nullif(p_device_job_ref,''),
      "dispatchMetadata"=p_details,"updatedAt"=now_at WHERE id=item_row.id;
  ELSIF p_operation='CONFIRM' THEN
    IF item_row.state IN ('PRINT_CONFIRMED','CLOSED') THEN
      RETURN jsonb_build_object('printItemId',item_row.id,'confirmed',true,'idempotent',true);
    END IF;
    IF item_row.state<>'AGENT_ACKED' THEN RAISE EXCEPTION 'PRINT_ACK_REQUIRED'; END IF;
    UPDATE public."PrintItem" SET state='PRINT_CONFIRMED',"pipelineState"='PRINT_CONFIRMED',
      "printConfirmedAt"=now_at,"confirmationEvidence"=p_details,
      "deviceJobRef"=coalesce(nullif(p_device_job_ref,''),"deviceJobRef"),"updatedAt"=now_at
      WHERE id=item_row.id;
    UPDATE public."QRCode" SET status='PRINTED',"printedAt"=now_at,"printedByUserId"=audit_actor,
      "updatedAt"=now_at WHERE id=item_row."qrCodeId" AND "printJobId"=job_row.id;
    UPDATE public."PrintSession" SET "confirmedItems"="confirmedItems"+1,"updatedAt"=now_at
      WHERE id=session_row.id;
    SELECT count(*) INTO remaining FROM public."PrintItem" pi
      WHERE pi."printSessionId"=session_row.id AND pi.state NOT IN ('PRINT_CONFIRMED','CLOSED');
    IF remaining=0 THEN
      UPDATE public."PrintSession" SET status='COMPLETED',"completedAt"=now_at,"updatedAt"=now_at WHERE id=session_row.id;
      UPDATE public."PrintJob" SET status='CONFIRMED',"pipelineState"='PRINT_CONFIRMED',
        "confirmedAt"=now_at,"completedAt"=now_at,"updatedAt"=now_at WHERE id=job_row.id;
      UPDATE public."Batch" SET "lifecycleState"='PRINT_CONFIRMED',"printedAt"=now_at,"updatedAt"=now_at
        WHERE id=job_row."batchId" AND "lifecycleState"='PRINT_ACKNOWLEDGED';
    END IF;
  ELSE
    IF item_row.state IN ('FAILED','FROZEN') THEN
      RETURN jsonb_build_object('printItemId',item_row.id,'failed',true,'idempotent',true);
    END IF;
    UPDATE public."PrintItem" SET state='FAILED',"pipelineState"='FAILED',"failedAt"=now_at,
      "failureReason"=left(coalesce(p_details->>'reason','connector_failure'),500),"updatedAt"=now_at
      WHERE id=item_row.id;
    UPDATE public."PrintSession" SET status='FAILED',"failedReason"=left(coalesce(p_details->>'reason','connector_failure'),500),
      "updatedAt"=now_at WHERE id=session_row.id;
    UPDATE public."PrintJob" SET status='FAILED',"pipelineState"='FAILED',
      "failureReason"=left(coalesce(p_details->>'reason','connector_failure'),500),"updatedAt"=now_at WHERE id=job_row.id;
  END IF;
  INSERT INTO public."PrintItemEvent"(id,"printItemId","eventType","previousState","nextState",details,"actorUserId","createdAt")
  VALUES(gen_random_uuid()::text,item_row.id,
    CASE p_operation WHEN 'ACK' THEN 'AGENT_ACKED' WHEN 'CONFIRM' THEN 'PRINT_CONFIRMED' ELSE 'FAILED' END::public."PrintItemEventType",
    item_row.state,
    CASE p_operation WHEN 'ACK' THEN 'AGENT_ACKED' WHEN 'CONFIRM' THEN 'PRINT_CONFIRMED' ELSE 'FAILED' END::public."PrintItemState",
    p_details,audit_actor,now_at);
  INSERT INTO public."PrintAuditEvent"(id,"batchId","printJobId","qrCodeId","eventType","actorId",metadata,"createdAt")
  VALUES(gen_random_uuid()::text,job_row."batchId",job_row.id,item_row."qrCodeId",
    'CONNECTOR_'||p_operation,audit_actor,
    jsonb_build_object('registrationId',p_registration_id,'printerId',p_printer_id,'deviceJobRef',p_device_job_ref),now_at);
  RETURN jsonb_build_object('printJobId',job_row.id,'printSessionId',session_row.id,
    'printItemId',item_row.id,'operation',p_operation,'idempotent',false,
    'remainingToPrint',CASE WHEN p_operation='CONFIRM' THEN remaining ELSE NULL END);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.printing_connector_identity(
  p_kind text,p_agent_id text,p_device_fingerprint text,p_printer_selector text,
  p_gateway_id text,p_gateway_secret_hash text,p_operation text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE registration record; printer_row record; attestation_row record;
  now_at timestamp without time zone:=transaction_timestamp();
BEGIN
  IF session_user<>'mscqr_rls_cert_app' OR p_kind NOT IN ('LOCAL_AGENT','SITE_GATEWAY')
     OR p_operation NOT IN ('VERIFY','HEARTBEAT')
     OR length(coalesce(p_agent_id,''))>180 OR length(coalesce(p_device_fingerprint,''))>256
     OR length(coalesce(p_printer_selector,''))>180 OR length(coalesce(p_gateway_id,''))>180
     OR (p_gateway_secret_hash IS NOT NULL AND p_gateway_secret_hash !~ '^[0-9a-f]{64}$')
  THEN RAISE EXCEPTION 'CONNECTOR_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM set_config('app.printing_operation','printing-connector-identity',true),
          set_config('app.printing_agent_id',coalesce(p_agent_id,''),true),
          set_config('app.printing_device_fingerprint',coalesce(p_device_fingerprint,''),true),
          set_config('app.printing_gateway_id',coalesce(p_gateway_id,''),true),
          set_config('app.printing_gateway_secret_hash',coalesce(p_gateway_secret_hash,''),true);
  IF p_kind='LOCAL_AGENT' THEN
    SELECT pr.id,pr."userId",pr."orgId",pr."licenseeId",pr."agentId",pr."deviceFingerprint",
      pr."publicKeyPem",pr."trustStatus",pr."approvedAt",pr."revokedAt",pr."lastSeenAt"
      INTO STRICT registration FROM public."PrinterRegistration" pr
      WHERE pr."agentId"=p_agent_id AND pr."deviceFingerprint"=p_device_fingerprint
        AND pr."trustStatus"='TRUSTED' AND pr."revokedAt" IS NULL
      ORDER BY pr."lastSeenAt" DESC NULLS LAST,pr."updatedAt" DESC LIMIT 1;
    PERFORM set_config('app.printing_registration_id',registration.id,true),
            set_config('app.printing_user_id',registration."userId",true);
    SELECT p.id,p.name,p.vendor,p.model,p."connectionType",p."commandLanguage",p."ipAddress",p.host,p.port,
      p."resourcePath",p."tlsEnabled",p."printerUri",p."deliveryMode",p."gatewayId",p."gatewayLastSeenAt",
      p."gatewayStatus",p."gatewayLastError",p."nativePrinterId",p."agentId",p."deviceFingerprint",
      p."printerRegistrationId",p."orgId",p."licenseeId",p."assignedUserId",p."createdByUserId",
      p."isActive",p."isDefault",p."lastSeenAt",p."lastValidatedAt",p."lastValidationStatus",
      p."lastValidationMessage",p."capabilitySummary",p."calibrationProfile",p.metadata,p."createdAt",p."updatedAt"
      INTO STRICT printer_row FROM public."Printer" p
      WHERE p."printerRegistrationId"=registration.id AND p."isActive"
        AND (p.id=p_printer_selector OR p."nativePrinterId"=p_printer_selector)
      ORDER BY (p.id=p_printer_selector) DESC,p."isDefault" DESC,p."updatedAt" DESC LIMIT 1;
    PERFORM set_config('app.printing_printer_id',printer_row.id,true);
    SELECT pa."signatureValid",pa."trustValid",pa."expiresAt",pa.metadata
      INTO attestation_row FROM public."PrinterAttestation" pa
      WHERE pa."printerRegistrationId"=registration.id
      ORDER BY pa."createdAt" DESC,pa.id DESC LIMIT 1;
    IF p_operation='HEARTBEAT' THEN
      UPDATE public."PrinterRegistration" SET "lastSeenAt"=now_at,"updatedAt"=now_at WHERE id=registration.id;
      UPDATE public."Printer" SET "lastSeenAt"=now_at,"updatedAt"=now_at WHERE id=printer_row.id;
    END IF;
    RETURN jsonb_build_object(
      'registration',jsonb_build_object(
        'id',registration.id,'userId',registration."userId",'orgId',registration."orgId",
        'licenseeId',registration."licenseeId",'agentId',registration."agentId",
        'deviceFingerprint',registration."deviceFingerprint",'publicKeyPem',registration."publicKeyPem",
        'trustStatus',registration."trustStatus",'approvedAt',registration."approvedAt",
        'revokedAt',registration."revokedAt",'lastSeenAt',registration."lastSeenAt"
      ),
      'printer',to_jsonb(printer_row),
      'eligibleForPrinting',registration."publicKeyPem" LIKE '%BEGIN%' AND printer_row."isActive"
        AND attestation_row."signatureValid" AND attestation_row."trustValid"
        AND attestation_row."expiresAt">now_at
        AND coalesce((attestation_row.metadata->>'connected')::boolean,false)
        AND coalesce(attestation_row.metadata->>'selectedPrinterId',attestation_row.metadata->>'printerId','')
          IN (printer_row.id,coalesce(printer_row."nativePrinterId",''))
    );
  END IF;
  SELECT p.id,p.name,p.vendor,p.model,p."connectionType",p."commandLanguage",p."ipAddress",p.host,p.port,
    p."resourcePath",p."tlsEnabled",p."printerUri",p."deliveryMode",p."gatewayId",p."gatewayLastSeenAt",
    p."gatewayStatus",p."gatewayLastError",p."nativePrinterId",p."agentId",p."deviceFingerprint",
    p."printerRegistrationId",p."orgId",p."licenseeId",p."assignedUserId",p."createdByUserId",
    p."isActive",p."isDefault",p."lastSeenAt",p."lastValidatedAt",p."lastValidationStatus",
    p."lastValidationMessage",p."capabilitySummary",p."calibrationProfile",p.metadata,p."createdAt",p."updatedAt"
    INTO STRICT printer_row FROM public."Printer" p
    WHERE p."gatewayId"=p_gateway_id AND p."gatewaySecretHash"=p_gateway_secret_hash
      AND p."deliveryMode"='SITE_GATEWAY' AND p."isActive"
      AND (p_printer_selector IS NULL OR p_printer_selector='' OR p.id=p_printer_selector);
  PERFORM set_config('app.printing_printer_id',printer_row.id,true);
  IF p_operation='HEARTBEAT' THEN
    UPDATE public."Printer" SET "gatewayLastSeenAt"=now_at,"gatewayStatus"='ONLINE',
      "gatewayLastError"=NULL,"updatedAt"=now_at WHERE id=printer_row.id;
  END IF;
  RETURN jsonb_build_object('printer',to_jsonb(printer_row),'eligibleForPrinting',true);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.printing_gateway_job(
  p_gateway_id text,p_gateway_secret_hash text,p_request_id text,p_operation text,p_mode text,
  p_job_id text,p_item_id text,p_details jsonb
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE printer_row record; job_row record; session_row record; item_row record;
  now_at timestamp without time zone:=transaction_timestamp(); remaining integer;
BEGIN
  IF session_user<>'mscqr_rls_cert_app' OR p_operation NOT IN ('CLAIM','ACK','CONFIRM','FAIL')
     OR p_mode NOT IN ('NETWORK_DIRECT','NETWORK_IPP')
     OR p_request_id !~* '^[0-9a-f-]{36}$' OR p_gateway_secret_hash !~ '^[0-9a-f]{64}$'
     OR (p_operation<>'CLAIM' AND (p_job_id !~* '^[0-9a-f-]{36}$' OR p_item_id !~* '^[0-9a-f-]{36}$'))
     OR jsonb_typeof(coalesce(p_details,'{}'::jsonb))<>'object'
  THEN RAISE EXCEPTION 'CONNECTOR_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM set_config('app.printing_operation','printing-connector-gateway-'||lower(p_operation),true),
          set_config('app.printing_request_id',p_request_id,true),
          set_config('app.printing_gateway_id',p_gateway_id,true),
          set_config('app.printing_gateway_secret_hash',p_gateway_secret_hash,true),
          set_config('app.printing_job_id',coalesce(p_job_id,''),true),
          set_config('app.printing_item_id',coalesce(p_item_id,''),true);
  SELECT p.id,p.name,p.vendor,p.model,p."connectionType",p."commandLanguage",p."ipAddress",p.host,p.port,
    p."resourcePath",p."tlsEnabled",p."printerUri",p."deliveryMode",p."gatewayId",p."gatewayLastSeenAt",
    p."gatewayStatus",p."gatewayLastError",p."nativePrinterId",p."agentId",p."deviceFingerprint",
    p."printerRegistrationId",p."orgId",p."licenseeId",p."assignedUserId",p."createdByUserId",
    p."isActive",p."isDefault",p."lastSeenAt",p."lastValidatedAt",p."lastValidationStatus",
    p."lastValidationMessage",p."capabilitySummary",p."calibrationProfile",p.metadata,p."createdAt",p."updatedAt"
    INTO STRICT printer_row FROM public."Printer" p
    WHERE p."gatewayId"=p_gateway_id AND p."gatewaySecretHash"=p_gateway_secret_hash
      AND p."deliveryMode"='SITE_GATEWAY'
      AND p."connectionType"=p_mode::public."PrinterConnectionType" AND p."isActive"
    FOR UPDATE;
  PERFORM set_config('app.printing_printer_id',printer_row.id,true);
  UPDATE public."Printer" SET "gatewayLastSeenAt"=now_at,"gatewayStatus"='ONLINE',
    "gatewayLastError"=NULL,"updatedAt"=now_at WHERE id=printer_row.id;
  IF p_operation='CLAIM' THEN
    SELECT j.id,j."jobNumber",j."batchId",j."manufacturerId",j."printerId",j.status,j."printMode",
      j."pipelineState",j."payloadType",j."payloadHash",j.quantity,j."itemCount",j."rangeStart",
      j."rangeEnd",j."sentAt",j."completedAt",j."failureReason",j."reprintOfJobId",
      j."approvedByUserId",j."reprintReason",j."confirmedAt",j."createdAt",j."updatedAt"
      INTO job_row FROM public."PrintJob" j
      WHERE j."printerId"=printer_row.id
        AND j."printMode"=p_mode::public."PrintDispatchMode"
        AND j.status IN ('PENDING','SENT')
      ORDER BY j."createdAt",j.id FOR UPDATE SKIP LOCKED LIMIT 1;
    IF NOT FOUND THEN RETURN jsonb_build_object('available',false); END IF;
  ELSE
    SELECT j.id,j."jobNumber",j."batchId",j."manufacturerId",j."printerId",j.status,j."printMode",
      j."pipelineState",j."payloadType",j."payloadHash",j.quantity,j."itemCount",j."rangeStart",
      j."rangeEnd",j."sentAt",j."completedAt",j."failureReason",j."reprintOfJobId",
      j."approvedByUserId",j."reprintReason",j."confirmedAt",j."createdAt",j."updatedAt"
      INTO STRICT job_row FROM public."PrintJob" j
      WHERE j.id=p_job_id AND j."printerId"=printer_row.id
        AND j."printMode"=p_mode::public."PrintDispatchMode" FOR UPDATE;
  END IF;
  PERFORM set_config('app.printing_job_id',job_row.id,true),
          set_config('app.printing_batch_id',job_row."batchId",true);
  SELECT ps.id,ps."printJobId",ps."batchId",ps."manufacturerId",ps."printerRegistrationId",
    ps."printerId",ps.status,ps."totalItems",ps."issuedItems",ps."confirmedItems",ps."frozenItems",
    ps."failedReason",ps."startedAt",ps."completedAt",ps."createdAt",ps."updatedAt"
    INTO STRICT session_row FROM public."PrintSession" ps WHERE ps."printJobId"=job_row.id FOR UPDATE;
  PERFORM set_config('app.printing_session_row_id',session_row.id,true);
  IF p_operation='CLAIM' THEN
    SELECT pi.id,pi."qrCodeId",pi.state INTO item_row FROM public."PrintItem" pi
      WHERE pi."printSessionId"=session_row.id AND pi.state='RESERVED'
      ORDER BY pi."issueSequence" NULLS LAST,pi.id FOR UPDATE SKIP LOCKED LIMIT 1;
    IF NOT FOUND THEN RETURN jsonb_build_object('available',false,'printJobId',job_row.id); END IF;
    PERFORM set_config('app.printing_item_id',item_row.id,true);
    UPDATE public."PrintItem" SET state='ISSUED',"pipelineState"='SENT_TO_PRINTER',
      "attemptCount"="attemptCount"+1,"issuedAt"=coalesce("issuedAt",now_at),"updatedAt"=now_at WHERE id=item_row.id;
    UPDATE public."PrintSession" SET "issuedItems"="issuedItems"+1,"updatedAt"=now_at WHERE id=session_row.id;
    UPDATE public."PrintJob" SET status='SENT',"pipelineState"='SENT_TO_PRINTER',
      "sentAt"=coalesce("sentAt",now_at),"updatedAt"=now_at WHERE id=job_row.id;
    UPDATE public."Batch" SET "lifecycleState"='PRINT_ACKNOWLEDGED',"updatedAt"=now_at
      WHERE id=job_row."batchId" AND "lifecycleState"='CODES_GENERATED';
    RETURN jsonb_build_object('available',true,'job',to_jsonb(job_row),
      'session',to_jsonb(session_row),'printer',to_jsonb(printer_row),
      'item',(SELECT jsonb_build_object(
        'id',pi.id,'qrCodeId',q.id,'code',q.code,'displayCode',q."displayCode",
        'batchId',q."batchId",'licenseeId',q."licenseeId",'tokenNonce',q."tokenNonce",
        'tokenIssuedAt',q."tokenIssuedAt",'tokenExpiresAt',q."tokenExpiresAt",
        'tokenHash',q."tokenHash",'replayEpoch',q."replayEpoch"
      ) FROM public."PrintItem" pi JOIN public."QRCode" q ON q.id=pi."qrCodeId" WHERE pi.id=item_row.id));
  END IF;
  SELECT pi.id,pi."qrCodeId",pi.state INTO STRICT item_row FROM public."PrintItem" pi
    WHERE pi.id=p_item_id AND pi."printSessionId"=session_row.id FOR UPDATE;
  PERFORM set_config('app.printing_item_id',item_row.id,true);
  IF p_operation='ACK' THEN
    IF item_row.state='AGENT_ACKED' THEN RETURN jsonb_build_object('idempotent',true,'printItemId',item_row.id); END IF;
    IF item_row.state<>'ISSUED' THEN RAISE EXCEPTION 'INVALID_STATE_TRANSITION'; END IF;
    UPDATE public."PrintItem" SET state='AGENT_ACKED',"pipelineState"='PRINTER_ACKNOWLEDGED',
      "agentAckedAt"=now_at,"confirmationDeadlineAt"=now_at+interval '10 minutes',
      "deviceJobRef"=nullif(p_details->>'deviceJobRef',''),"dispatchMetadata"=p_details,"updatedAt"=now_at
      WHERE id=item_row.id;
  ELSIF p_operation='CONFIRM' THEN
    IF item_row.state IN ('PRINT_CONFIRMED','CLOSED') THEN RETURN jsonb_build_object('idempotent',true,'printItemId',item_row.id); END IF;
    IF item_row.state<>'AGENT_ACKED' THEN RAISE EXCEPTION 'PRINT_ACK_REQUIRED'; END IF;
    UPDATE public."PrintItem" SET state='PRINT_CONFIRMED',"pipelineState"='PRINT_CONFIRMED',
      "printConfirmedAt"=now_at,"confirmationEvidence"=p_details,"updatedAt"=now_at WHERE id=item_row.id;
    UPDATE public."QRCode" SET status='PRINTED',"printedAt"=coalesce("printedAt",now_at),
      "printedByUserId"=job_row."manufacturerId","updatedAt"=now_at WHERE id=item_row."qrCodeId";
    SELECT count(*) INTO remaining FROM public."PrintItem" pi
      WHERE pi."printSessionId"=session_row.id AND pi.state NOT IN ('PRINT_CONFIRMED','CLOSED','FAILED','CANCELLED');
    IF remaining=0 THEN
      UPDATE public."PrintSession" SET status='COMPLETED',"confirmedItems"="totalItems",
        "completedAt"=now_at,"updatedAt"=now_at WHERE id=session_row.id;
      UPDATE public."PrintJob" SET status='CONFIRMED',"pipelineState"='PRINT_CONFIRMED',
        "confirmedAt"=now_at,"completedAt"=now_at,"updatedAt"=now_at WHERE id=job_row.id;
      UPDATE public."Batch" SET "lifecycleState"='PRINT_CONFIRMED',"printedAt"=now_at,"updatedAt"=now_at
        WHERE id=job_row."batchId" AND "lifecycleState"='PRINT_ACKNOWLEDGED';
    END IF;
  ELSE
    UPDATE public."PrintItem" SET state='FAILED',"pipelineState"='FAILED',"failedAt"=now_at,
      "failureReason"=left(coalesce(p_details->>'reason','gateway_failure'),500),"updatedAt"=now_at WHERE id=item_row.id;
    UPDATE public."PrintSession" SET status='FAILED',"failedReason"=left(coalesce(p_details->>'reason','gateway_failure'),500),
      "updatedAt"=now_at WHERE id=session_row.id;
    UPDATE public."PrintJob" SET status='FAILED',"pipelineState"='FAILED',
      "failureReason"=left(coalesce(p_details->>'reason','gateway_failure'),500),"updatedAt"=now_at WHERE id=job_row.id;
    UPDATE public."Printer" SET "gatewayStatus"='ERROR',"gatewayLastError"=left(p_details->>'reason',500),
      "updatedAt"=now_at WHERE id=printer_row.id;
  END IF;
  INSERT INTO public."PrintItemEvent"(id,"printItemId","eventType","previousState","nextState",details,"actorUserId","createdAt")
  VALUES(gen_random_uuid()::text,item_row.id,
    CASE p_operation WHEN 'ACK' THEN 'AGENT_ACKED' WHEN 'CONFIRM' THEN 'PRINT_CONFIRMED' ELSE 'FAILED' END,
    item_row.state,CASE p_operation WHEN 'ACK' THEN 'AGENT_ACKED' WHEN 'CONFIRM' THEN 'PRINT_CONFIRMED' ELSE 'FAILED' END,
    p_details,job_row."manufacturerId",now_at);
  INSERT INTO public."PrintAuditEvent"(id,"batchId","printJobId","qrCodeId","eventType","actorId",metadata,"createdAt")
  VALUES(gen_random_uuid()::text,job_row."batchId",job_row.id,item_row."qrCodeId",
    'GATEWAY_'||p_operation,job_row."manufacturerId",
    jsonb_build_object('gatewayId',p_gateway_id,'printerId',printer_row.id),now_at);
  RETURN jsonb_build_object('printJobId',job_row.id,'printItemId',item_row.id,
    'operation',p_operation,'remainingToPrint',remaining,'idempotent',false);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.printing_record_sample(
  p_capability text,p_purpose text,p_request_id text,p_job_id text,p_qr_code text,p_evidence jsonb
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; job_row record; qr_row record; policy jsonb; required_count integer; actual_count integer;
  event_id text:=gen_random_uuid()::text; now_at timestamp without time zone:=transaction_timestamp();
BEGIN
  SELECT * INTO STRICT actor FROM app_rls.printing_bind_actor(p_capability,p_purpose,p_request_id,NULL);
  PERFORM set_config('app.printing_job_id',p_job_id,true);
  SELECT j.id,j."batchId",j.status,j.quantity
    INTO STRICT job_row FROM public."PrintJob" j WHERE j.id=p_job_id FOR UPDATE;
  SELECT * INTO STRICT actor FROM app_rls.printing_bind_actor(p_capability,p_purpose,p_request_id,job_row."batchId");
  PERFORM set_config('app.printing_job_id',p_job_id,true);
  IF p_purpose<>'printing-sample-scan' OR job_row.status<>'CONFIRMED' THEN RAISE EXCEPTION 'PHYSICAL_CONFIRMATION_REQUIRED'; END IF;
  BEGIN
    SELECT q.id INTO STRICT qr_row FROM public."QRCode" q
     WHERE q.code=btrim(p_qr_code) AND q."batchId"=job_row."batchId" AND q."printJobId"=job_row.id
       AND q.status='PRINTED';
  EXCEPTION WHEN NO_DATA_FOUND THEN
    RAISE EXCEPTION 'QR_NOT_IN_PRINT_JOB';
  END;
  IF EXISTS (SELECT 1 FROM public."PrintAuditEvent" e WHERE e."printJobId"=job_row.id
    AND e."qrCodeId"=qr_row.id AND e."eventType"='SAMPLE_SCAN_PASSED')
  THEN RETURN jsonb_build_object('idempotent',true,'qrCodeId',qr_row.id); END IF;
  SELECT b."sampleScanPolicy" INTO policy FROM public."Batch" b WHERE b.id=job_row."batchId";
  required_count:=CASE coalesce(policy->>'type',policy->>'mode','ONE_PER_PRINT_JOB')
    WHEN 'ONE_PER_PRINT_JOB' THEN 1
    WHEN 'ONE_PER_ROLL' THEN 1
    WHEN 'ONE_PER_N_LABELS' THEN GREATEST(1,ceil(job_row.quantity::numeric/GREATEST(coalesce((policy->>'n')::integer,job_row.quantity),1))::integer)
    WHEN 'PERCENTAGE' THEN GREATEST(
      GREATEST(coalesce((policy->>'min')::integer,1),1),
      ceil(job_row.quantity*GREATEST(coalesce((policy->>'percentage')::numeric,1),0.01)/100)::integer
    )
    ELSE 1 END;
  PERFORM set_config('app.printing_job_id',job_row.id,true),set_config('app.printing_item_id',qr_row.id,true);
  INSERT INTO public."PrintAuditEvent"(id,"batchId","printJobId","qrCodeId","eventType","actorId",metadata,"createdAt")
  VALUES(event_id,job_row."batchId",job_row.id,qr_row.id,'SAMPLE_SCAN_PASSED',actor."userId",
    coalesce(p_evidence,'{}'::jsonb)||jsonb_build_object('requestId',p_request_id),now_at);
  SELECT count(DISTINCT e."qrCodeId") INTO actual_count FROM public."PrintAuditEvent" e
    WHERE e."printJobId"=job_row.id AND e."eventType"='SAMPLE_SCAN_PASSED';
  IF actual_count>=required_count THEN
    UPDATE public."Batch" SET "lifecycleState"='SAMPLE_VERIFIED',"updatedAt"=now_at
      WHERE id=job_row."batchId" AND "lifecycleState"='PRINT_CONFIRMED';
  END IF;
  PERFORM app_rls.printing_write_audit(actor."userId",actor.role,actor."organizationId",actor."batchLicenseeId",
    'PRINT_SAMPLE_RECORDED','PrintJob',job_row.id,
    jsonb_build_object('qrCodeId',qr_row.id,'required',required_count,'actual',actual_count));
  RETURN jsonb_build_object('idempotent',false,'qrCodeId',qr_row.id,'required',required_count,
    'actual',actual_count,'satisfied',actual_count>=required_count);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.printing_release_batch(
  p_capability text,p_purpose text,p_request_id text,p_batch_id text,p_decision text,p_reason text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; batch_row record; maker_id text; now_at timestamp without time zone:=transaction_timestamp();
  released_count integer; approval_id text; approval_requested_by text; approval_status text;
  approval_expires_at timestamp without time zone;
  effective_decision text:=p_decision;
BEGIN
  IF p_purpose<>'printing-release' OR p_decision NOT IN ('REQUEST','APPROVE','REJECT')
     OR length(coalesce(p_reason,''))>500 THEN RAISE EXCEPTION 'PRINTING_INVALID_INPUT'; END IF;
  SELECT * INTO STRICT actor FROM app_rls.printing_bind_actor(p_capability,p_purpose,p_request_id,p_batch_id);
  IF actor.role NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN','LICENSEE_ADMIN','MANUFACTURER_ADMIN') THEN
    RAISE EXCEPTION 'PRINTING_BOUNDARY_DENIED' USING ERRCODE='42501';
  END IF;
  SELECT b.id,b."lifecycleState",b."releasedAt",b."totalCodes"
    INTO STRICT batch_row FROM public."Batch" b WHERE b.id=p_batch_id FOR UPDATE;
  SELECT j."manufacturerId" INTO maker_id FROM public."PrintJob" j WHERE j."batchId"=p_batch_id
    AND j.status='CONFIRMED' ORDER BY j."confirmedAt" DESC NULLS LAST,j."createdAt" DESC LIMIT 1;
  IF maker_id IS NULL THEN RAISE EXCEPTION 'PHYSICAL_CONFIRMATION_REQUIRED'; END IF;
  IF p_decision='REQUEST' THEN
    SELECT a.id,a."requestedByUserId",a.status,a."expiresAt"
      INTO approval_id,approval_requested_by,approval_status,approval_expires_at
      FROM public."SensitiveActionApproval" a
     WHERE a."actionKey"='BATCH_RELEASE' AND a."entityType"='Batch' AND a."entityId"=p_batch_id
       AND a.status='PENDING' AND a."expiresAt">now_at
     ORDER BY a."createdAt" DESC,a.id DESC LIMIT 1 FOR UPDATE;
    IF NOT FOUND THEN
      IF actor.role<>'MANUFACTURER_ADMIN' OR maker_id<>actor."userId" THEN
        RAISE EXCEPTION 'PRINTING_RELEASE_REQUEST_DENIED' USING ERRCODE='42501';
      END IF;
      INSERT INTO public."SensitiveActionApproval"(
        id,"actionKey","requestedByUserId","licenseeId","entityType","entityId",payload,summary,status,
        "expiresAt","createdAt","updatedAt"
      ) VALUES (
        gen_random_uuid()::text,'BATCH_RELEASE',actor."userId",actor."batchLicenseeId",'Batch',p_batch_id,
        jsonb_build_object('batchId',p_batch_id,'printJobId',(
          SELECT j.id FROM public."PrintJob" j WHERE j."batchId"=p_batch_id AND j.status='CONFIRMED'
          ORDER BY j."confirmedAt" DESC NULLS LAST,j."createdAt" DESC LIMIT 1
        ),'requestedByUserId',actor."userId",'releaseBoundary','supply_chain'),
        jsonb_build_object('reason',nullif(btrim(p_reason),''),'totalCodes',batch_row."totalCodes"),
        'PENDING',now_at+interval '30 minutes',now_at,now_at
      ) RETURNING id,"requestedByUserId",status,"expiresAt"
        INTO approval_id,approval_requested_by,approval_status,approval_expires_at;
      PERFORM app_rls.printing_write_audit(actor."userId",actor.role,actor."organizationId",actor."batchLicenseeId",
        'BATCH_RELEASE_REQUESTED','Batch',p_batch_id,jsonb_build_object('approvalId',approval_id));
      RETURN jsonb_build_object('batchId',p_batch_id,'approvalRequired',true,'approvalId',approval_id,
        'status',approval_status,'expiresAt',approval_expires_at,'idempotent',false);
    END IF;
    IF approval_requested_by=actor."userId" THEN
      RETURN jsonb_build_object('batchId',p_batch_id,'approvalRequired',true,'approvalId',approval_id,
        'status',approval_status,'expiresAt',approval_expires_at,'idempotent',true);
    END IF;
    IF actor.role NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN','LICENSEE_ADMIN') THEN
      RAISE EXCEPTION 'CHECKER_REQUIRED' USING ERRCODE='42501';
    END IF;
    UPDATE public."SensitiveActionApproval" SET status='EXECUTED',"reviewedByUserId"=actor."userId",
      "reviewedAt"=now_at,"executedByUserId"=actor."userId","executedAt"=now_at,"updatedAt"=now_at
      WHERE id=approval_id;
    effective_decision:='APPROVE';
  END IF;
  IF maker_id=actor."userId" THEN RAISE EXCEPTION 'MAKER_CANNOT_APPROVE' USING ERRCODE='42501'; END IF;
  IF effective_decision='REJECT' THEN
    UPDATE public."Batch" SET "lifecycleState"='FAILED',"updatedAt"=now_at WHERE id=p_batch_id
      AND "lifecycleState" IN ('PRINT_CONFIRMED','SAMPLE_VERIFIED');
    IF NOT FOUND THEN RAISE EXCEPTION 'INVALID_STATE_TRANSITION'; END IF;
  ELSE
    IF batch_row."releasedAt" IS NOT NULL OR batch_row."lifecycleState"='RELEASED' THEN RAISE EXCEPTION 'BATCH_ALREADY_RELEASED'; END IF;
    IF batch_row."lifecycleState"<>'SAMPLE_VERIFIED' THEN RAISE EXCEPTION 'SAMPLE_SCAN_REQUIRED'; END IF;
    IF EXISTS (SELECT 1 FROM public."PrintItem" pi JOIN public."PrintSession" ps ON ps.id=pi."printSessionId"
      WHERE ps."batchId"=p_batch_id AND pi.state NOT IN ('PRINT_CONFIRMED','CLOSED','CANCELLED','FAILED'))
    THEN RAISE EXCEPTION 'PHYSICAL_CONFIRMATION_REQUIRED'; END IF;
    UPDATE public."QRCode" SET "customerVerifiableAt"=now_at,"updatedAt"=now_at
      WHERE "batchId"=p_batch_id AND status='PRINTED';
    GET DIAGNOSTICS released_count=ROW_COUNT;
    IF released_count=0 THEN RAISE EXCEPTION 'QR_CODES_REQUIRED'; END IF;
    UPDATE public."Batch" SET "lifecycleState"='RELEASED',"releasedAt"=now_at,
      "releasedByUserId"=actor."userId","updatedAt"=now_at WHERE id=p_batch_id;
  END IF;
  PERFORM app_rls.printing_write_audit(actor."userId",actor.role,actor."organizationId",actor."batchLicenseeId",
    'BATCH_RELEASE_'||effective_decision,'Batch',p_batch_id,
    jsonb_build_object('makerId',maker_id,'approvalId',approval_id,
      'reason',nullif(btrim(p_reason),''),'releasedCodes',coalesce(released_count,0)));
  RETURN jsonb_build_object('batchId',p_batch_id,'decision',effective_decision,'lifecycleState',
    CASE WHEN effective_decision='APPROVE' THEN 'RELEASED' ELSE 'FAILED' END,
    'releasedCodes',coalesce(released_count,0),'approvalRequired',approval_id IS NOT NULL,
    'approvalId',approval_id);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.printing_reissue_request(
  p_capability text,p_purpose text,p_request_id text,p_operation text,p_reissue_id text,
  p_original_job_id text,p_quantity integer,p_range_start text,p_range_end text,p_reason text,p_decision_note text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; job_row record; request_row record; request_id text; replacement_job_id text;
  target_batch_id text;
  replacement_session_id text; original_session_id text; moved_count integer;
  now_at timestamp without time zone:=transaction_timestamp();
BEGIN
  IF p_purpose<>'printing-reissue' OR p_operation NOT IN ('CREATE','FORWARD','APPROVE','REJECT','CANCEL','EXECUTE')
     OR length(coalesce(p_reason,''))>500 OR length(coalesce(p_decision_note,''))>500
     OR (p_operation='CREATE' AND p_quantity NOT BETWEEN 1 AND 200000)
     OR (p_range_start IS NOT NULL AND p_range_end IS NOT NULL AND p_range_start>p_range_end)
  THEN RAISE EXCEPTION 'PRINTING_INVALID_INPUT'; END IF;
  IF p_operation='CREATE' THEN
    SELECT * INTO STRICT actor FROM app_rls.printing_bind_actor(p_capability,p_purpose,p_request_id,NULL);
    PERFORM set_config('app.printing_job_id',p_original_job_id,true);
    SELECT j.id,j."batchId",j."manufacturerId",j.status
      INTO STRICT job_row FROM public."PrintJob" j WHERE j.id=p_original_job_id FOR UPDATE;
    SELECT * INTO STRICT actor FROM app_rls.printing_bind_actor(p_capability,p_purpose,p_request_id,job_row."batchId");
    PERFORM set_config('app.printing_job_id',p_original_job_id,true);
    IF actor.role<>'MANUFACTURER_ADMIN' OR job_row."manufacturerId"<>actor."userId"
       OR job_row.status NOT IN ('FAILED','PARTIALLY_COMPLETED','CONFIRMED')
    THEN RAISE EXCEPTION 'PRINTING_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;
    SELECT r.id INTO request_id FROM public."PrintReissueRequest" r
      WHERE r."originalPrintJobId"=job_row.id AND r.status IN ('PENDING','APPROVED') FOR UPDATE;
    IF request_id IS NOT NULL THEN
      RETURN (SELECT to_jsonb(r)||jsonb_build_object('idempotent',true) FROM (
        SELECT request.id,request."originalPrintJobId",request."replacementPrintJobId",
          request."requestedByUserId",request."approvedByUserId",request."licenseeId",
          request."manufacturerId",request."batchId",request."requestedByRole",
          request."targetApproverRole",request.quantity,request."affectedRangeStart",
          request."affectedRangeEnd",request."decisionNote",request."approvalReferenceId",
          request.status,request.reason,request."rejectionReason",request."approvedAt",
          request."rejectedAt",request."executedAt",request."createdAt",request."updatedAt"
        FROM public."PrintReissueRequest" request WHERE request.id=request_id
      ) r);
    END IF;
    request_id:=gen_random_uuid()::text;
    PERFORM set_config('app.printing_reissue_id',request_id,true);
    INSERT INTO public."PrintReissueRequest"(
      id,"originalPrintJobId","requestedByUserId","licenseeId","manufacturerId","batchId",
      "requestedByRole","targetApproverRole",quantity,"affectedRangeStart","affectedRangeEnd",
      status,reason,"createdAt","updatedAt"
    ) VALUES (
      request_id,job_row.id,actor."userId",actor."batchLicenseeId",job_row."manufacturerId",job_row."batchId",
      actor.role,'LICENSEE_ADMIN',p_quantity,p_range_start,p_range_end,'PENDING',btrim(p_reason),now_at,now_at
    ) RETURNING id,"originalPrintJobId","replacementPrintJobId","requestedByUserId",
      "approvedByUserId","licenseeId","manufacturerId","batchId","requestedByRole",
      "targetApproverRole",quantity,"affectedRangeStart","affectedRangeEnd","decisionNote",
      "approvalReferenceId",status,reason,"rejectionReason","approvedAt","rejectedAt",
      "executedAt","createdAt","updatedAt" INTO request_row;
  ELSE
    SELECT * INTO STRICT actor FROM app_rls.printing_bind_actor(p_capability,p_purpose,p_request_id,NULL);
    PERFORM set_config('app.printing_reissue_id',p_reissue_id,true);
    SELECT r.id,r."originalPrintJobId",r."replacementPrintJobId",r."requestedByUserId",
      r."approvedByUserId",r."licenseeId",r."manufacturerId",r."batchId",r."requestedByRole",
      r."targetApproverRole",r.quantity,r."affectedRangeStart",r."affectedRangeEnd",r."decisionNote",
      r."approvalReferenceId",r.status,r.reason,r."rejectionReason",r."approvedAt",r."rejectedAt",
      r."executedAt",r."createdAt",r."updatedAt" INTO STRICT request_row
      FROM public."PrintReissueRequest" r
      WHERE r.id=p_reissue_id FOR UPDATE;
    PERFORM set_config('app.printing_job_id',request_row."originalPrintJobId",true);
    SELECT j."batchId" INTO STRICT target_batch_id FROM public."PrintJob" j
      WHERE j.id=request_row."originalPrintJobId";
    SELECT * INTO STRICT actor FROM app_rls.printing_bind_actor(p_capability,p_purpose,p_request_id,target_batch_id);
    PERFORM set_config('app.printing_reissue_id',p_reissue_id,true),
            set_config('app.printing_job_id',request_row."originalPrintJobId",true);
    IF p_operation='EXECUTE' THEN
      IF actor.role<>'MANUFACTURER_ADMIN' OR request_row."requestedByUserId"<>actor."userId"
         OR request_row.status::text NOT IN ('APPROVED','EXECUTED')
      THEN RAISE EXCEPTION 'PRINTING_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;
      IF request_row.status::text='EXECUTED' THEN
        RETURN to_jsonb(request_row)||jsonb_build_object('idempotent',true);
      END IF;
      SELECT j.id,j."batchId",j."manufacturerId",j."printerId",j.status,j."printMode",
        j."payloadType",j.quantity,j."itemCount",
        ps.id AS original_session_id,ps."printerRegistrationId" AS original_registration_id
        INTO STRICT job_row
        FROM public."PrintJob" j JOIN public."PrintSession" ps ON ps."printJobId"=j.id
        WHERE j.id=request_row."originalPrintJobId" FOR UPDATE OF j,ps;
      IF job_row.status NOT IN ('FAILED','PARTIALLY_COMPLETED','CONFIRMED','STOPPED','CANCELLED')
      THEN RAISE EXCEPTION 'INVALID_STATE_TRANSITION'; END IF;
      original_session_id:=job_row.original_session_id;
      IF job_row."printMode"='LOCAL_AGENT'::public."PrintDispatchMode" THEN
        IF job_row.original_registration_id IS NULL THEN RAISE EXCEPTION 'PRINTER_ATTESTATION_STALE'; END IF;
        PERFORM set_config('app.printing_registration_id',job_row.original_registration_id,true);
        IF NOT EXISTS (
          SELECT 1 FROM public."PrinterAttestation" pa
          JOIN public."Printer" p ON p.id=job_row."printerId"
          WHERE pa."printerRegistrationId"=job_row.original_registration_id
            AND pa."signatureValid" AND pa."trustValid" AND pa."expiresAt">now_at
            AND coalesce((pa.metadata->>'connected')::boolean,false)
            AND coalesce(pa.metadata->>'selectedPrinterId',pa.metadata->>'printerId','')
              IN (p.id,coalesce(p."nativePrinterId",''))
        ) THEN RAISE EXCEPTION 'PRINTER_ATTESTATION_STALE'; END IF;
      END IF;
      replacement_job_id:=gen_random_uuid()::text;
      replacement_session_id:=gen_random_uuid()::text;
      PERFORM set_config('app.printing_job_id',replacement_job_id,true),
              set_config('app.printing_session_row_id',replacement_session_id,true),
              set_config('app.printing_original_session_id',original_session_id,true);
      INSERT INTO public."PrintJob"(
        id,"jobNumber","batchId","manufacturerId","printerId",status,"printMode","pipelineState",
        "payloadType",quantity,"itemCount","rangeStart","rangeEnd","reprintOfJobId","approvedByUserId",
        "reprintReason","createdAt","updatedAt"
      ) VALUES (
        replacement_job_id,'RJ-'||to_char(now_at,'YYYYMMDDHH24MISS')||'-'||upper(substr(replacement_job_id,1,6)),
        job_row."batchId",job_row."manufacturerId",job_row."printerId",'PENDING',job_row."printMode",
        'QUEUED',job_row."payloadType",coalesce(request_row.quantity,job_row.quantity),
        coalesce(request_row.quantity,job_row."itemCount"),request_row."affectedRangeStart",
        request_row."affectedRangeEnd",job_row.id,request_row."approvedByUserId",request_row.reason,now_at,now_at
      );
      INSERT INTO public."PrintSession"(
        id,"printJobId","batchId","manufacturerId","printerRegistrationId","printerId",status,"totalItems","createdAt","updatedAt"
      ) VALUES (
        replacement_session_id,replacement_job_id,job_row."batchId",job_row."manufacturerId",
        job_row.original_registration_id,job_row."printerId",'ACTIVE',
        coalesce(request_row.quantity,job_row."itemCount"),now_at,now_at
      );
      WITH eligible AS (
        SELECT pi.id,pi."qrCodeId"
        FROM public."PrintItem" pi
        JOIN public."QRCode" q ON q.id=pi."qrCodeId"
        WHERE pi."printSessionId"=original_session_id
          AND pi."printConfirmedAt" IS NULL
          AND pi.state IN ('FAILED','FROZEN','CANCELLED','RESERVED','ISSUED')
          AND q."batchId"=job_row."batchId"
          AND (request_row."affectedRangeStart" IS NULL OR q."displayCode">=request_row."affectedRangeStart")
          AND (request_row."affectedRangeEnd" IS NULL OR q."displayCode"<=request_row."affectedRangeEnd")
        ORDER BY pi."issueSequence" NULLS LAST,pi.id
        FOR UPDATE
        LIMIT coalesce(request_row.quantity,job_row."itemCount")
      ), moved AS (
        UPDATE public."PrintItem" pi SET
          "printSessionId"=replacement_session_id,state='RESERVED', "pipelineState"='QUEUED',
          "attemptCount"=0,"deviceJobRef"=NULL,"dispatchMetadata"=NULL,"confirmationEvidence"=NULL,
          "issuedAt"=NULL,"dispatchedAt"=NULL,"agentAckedAt"=NULL,"printConfirmedAt"=NULL,
          "failedAt"=NULL,"failureReason"=NULL,"updatedAt"=now_at
        FROM eligible e WHERE pi.id=e.id RETURNING pi."qrCodeId"
      )
      UPDATE public."QRCode" q SET "printJobId"=replacement_job_id,"updatedAt"=now_at
        FROM moved m WHERE q.id=m."qrCodeId";
      GET DIAGNOSTICS moved_count = ROW_COUNT;
      IF moved_count<>coalesce(request_row.quantity,job_row."itemCount")
      THEN RAISE EXCEPTION 'NOT_ENOUGH_CODES'; END IF;
      UPDATE public."PrintReissueRequest" SET status='EXECUTED',
        "replacementPrintJobId"=replacement_job_id,"executedAt"=now_at,"updatedAt"=now_at
        WHERE id=request_row.id
        RETURNING id,"originalPrintJobId","replacementPrintJobId","requestedByUserId",
          "approvedByUserId","licenseeId","manufacturerId","batchId","requestedByRole",
          "targetApproverRole",quantity,"affectedRangeStart","affectedRangeEnd","decisionNote",
          "approvalReferenceId",status,reason,"rejectionReason","approvedAt","rejectedAt",
          "executedAt","createdAt","updatedAt" INTO request_row;
      request_id:=request_row.id;
    ELSE
      IF p_operation='CANCEL' THEN
        IF request_row."requestedByUserId"<>actor."userId" THEN
          RAISE EXCEPTION 'PRINTING_BOUNDARY_DENIED' USING ERRCODE='42501';
        END IF;
      ELSIF request_row."requestedByUserId"=actor."userId" THEN
        RAISE EXCEPTION 'MAKER_CANNOT_APPROVE' USING ERRCODE='42501';
      ELSIF p_operation='FORWARD' THEN
        IF actor.role<>'LICENSEE_ADMIN' OR request_row."targetApproverRole"<>'LICENSEE_ADMIN'
        THEN RAISE EXCEPTION 'PRINTING_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;
      ELSIF p_operation='APPROVE' THEN
        IF actor.role NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') OR request_row."targetApproverRole"<>'SUPER_ADMIN'
        THEN RAISE EXCEPTION 'PRINTING_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;
      ELSIF p_operation='REJECT' AND NOT (
        (actor.role='LICENSEE_ADMIN' AND request_row."targetApproverRole"='LICENSEE_ADMIN')
        OR (actor.role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') AND request_row."targetApproverRole"='SUPER_ADMIN')
      ) THEN RAISE EXCEPTION 'PRINTING_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;
      IF request_row.status::text<>'PENDING' THEN RAISE EXCEPTION 'INVALID_STATE_TRANSITION'; END IF;
      IF p_operation='FORWARD' THEN
        UPDATE public."PrintReissueRequest" SET "targetApproverRole"='SUPER_ADMIN',
          "decisionNote"=nullif(btrim(p_decision_note),''),"updatedAt"=now_at
          WHERE id=request_row.id
          RETURNING id,"originalPrintJobId","replacementPrintJobId","requestedByUserId",
            "approvedByUserId","licenseeId","manufacturerId","batchId","requestedByRole",
            "targetApproverRole",quantity,"affectedRangeStart","affectedRangeEnd","decisionNote",
            "approvalReferenceId",status,reason,"rejectionReason","approvedAt","rejectedAt",
            "executedAt","createdAt","updatedAt" INTO request_row;
      ELSE
    UPDATE public."PrintReissueRequest" SET
      status=CASE p_operation WHEN 'APPROVE' THEN 'APPROVED' WHEN 'REJECT' THEN 'REJECTED' ELSE 'CANCELLED' END::public."ReissueRequestStatus",
      "approvedByUserId"=CASE WHEN p_operation='APPROVE' THEN actor."userId" ELSE "approvedByUserId" END,
      "approvedAt"=CASE WHEN p_operation='APPROVE' THEN now_at ELSE "approvedAt" END,
      "rejectedAt"=CASE WHEN p_operation='REJECT' THEN now_at ELSE "rejectedAt" END,
      "decisionNote"=nullif(btrim(p_decision_note),''),
      "rejectionReason"=CASE WHEN p_operation='REJECT' THEN nullif(btrim(p_reason),'') ELSE "rejectionReason" END,
      "updatedAt"=now_at WHERE id=request_row.id
      RETURNING id,"originalPrintJobId","replacementPrintJobId","requestedByUserId",
        "approvedByUserId","licenseeId","manufacturerId","batchId","requestedByRole",
        "targetApproverRole",quantity,"affectedRangeStart","affectedRangeEnd","decisionNote",
        "approvalReferenceId",status,reason,"rejectionReason","approvedAt","rejectedAt",
        "executedAt","createdAt","updatedAt" INTO request_row;
      END IF;
    request_id:=request_row.id;
    END IF;
  END IF;
  PERFORM app_rls.printing_write_audit(actor."userId",actor.role,actor."organizationId",actor."batchLicenseeId",
    'PRINT_REISSUE_'||p_operation,'PrintReissueRequest',request_id,
    jsonb_build_object('originalPrintJobId',coalesce(request_row."originalPrintJobId",p_original_job_id),'quantity',p_quantity));
  RETURN to_jsonb(request_row)||jsonb_build_object('idempotent',false);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.printing_worker_reconcile(
  p_operation text,p_request_id text,p_limit integer
) RETURNS integer
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE affected integer:=0; now_at timestamp without time zone:=transaction_timestamp();
BEGIN
  IF session_user<>'mscqr_rls_cert_worker' OR p_operation NOT IN ('EXPIRE_CONFIRMATIONS','RECONCILE_BATCHES')
     OR p_request_id !~* '^[0-9a-f-]{36}$' OR p_limit NOT BETWEEN 1 AND 1000
  THEN RAISE EXCEPTION 'PRINTING_WORKER_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM set_config('app.printing_operation','printing-worker-'||lower(p_operation),true),
          set_config('app.printing_request_id',p_request_id,true);
  IF p_operation='EXPIRE_CONFIRMATIONS' THEN
    WITH target AS (
      SELECT pi.id FROM public."PrintItem" pi
       WHERE pi.state='AGENT_ACKED' AND pi."confirmationDeadlineAt"<now_at
       ORDER BY pi."confirmationDeadlineAt",pi.id FOR UPDATE SKIP LOCKED LIMIT p_limit
    )
    UPDATE public."PrintItem" pi SET state='FAILED',"pipelineState"='FAILED',"failedAt"=now_at,
      "failureReason"='confirmation_deadline_expired',"updatedAt"=now_at
      FROM target t WHERE pi.id=t.id;
    GET DIAGNOSTICS affected=ROW_COUNT;
  ELSE
    WITH target AS (
      SELECT b.id FROM public."Batch" b
       WHERE b."lifecycleState" IN ('CODES_GENERATED','PRINT_ACKNOWLEDGED','PRINT_CONFIRMED')
       ORDER BY b."updatedAt",b.id FOR UPDATE SKIP LOCKED LIMIT p_limit
    ), state AS (
      SELECT t.id,
        bool_or(j.status='CONFIRMED') AS confirmed_job,
        bool_or(j.status IN ('PENDING','SENT','PAUSED')) AS active_job
      FROM target t LEFT JOIN public."PrintJob" j ON j."batchId"=t.id GROUP BY t.id
    )
    UPDATE public."Batch" b SET "lifecycleState"=CASE
      WHEN s.confirmed_job THEN 'PRINT_CONFIRMED'::public."BatchLifecycleState"
      WHEN s.active_job THEN 'PRINT_ACKNOWLEDGED'::public."BatchLifecycleState"
      ELSE b."lifecycleState" END,"updatedAt"=now_at
      FROM state s WHERE b.id=s.id AND b."lifecycleState" IS DISTINCT FROM CASE
      WHEN s.confirmed_job THEN 'PRINT_CONFIRMED'::public."BatchLifecycleState"
      WHEN s.active_job THEN 'PRINT_ACKNOWLEDGED'::public."BatchLifecycleState"
      ELSE b."lifecycleState" END;
    GET DIAGNOSTICS affected=ROW_COUNT;
  END IF;
  RETURN affected;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.printing_worker_network_job(
  p_operation text,p_request_id text,p_job_id text,p_details jsonb
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE job_row record; session_row record; now_at timestamp without time zone:=transaction_timestamp();
  mode_value public."PrintDispatchMode"; item_ids text[]; remaining integer; page_limit integer;
BEGIN
  IF session_user<>'mscqr_rls_cert_worker'
     OR p_operation NOT IN ('CLAIM_DIRECT','CLAIM_IPP','CONFIRM','FAIL')
     OR p_request_id !~* '^[0-9a-f-]{36}$'
     OR (p_job_id IS NOT NULL AND p_job_id !~* '^[0-9a-f-]{36}$')
     OR jsonb_typeof(coalesce(p_details,'{}'::jsonb))<>'object'
  THEN RAISE EXCEPTION 'PRINTING_WORKER_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM set_config('app.printing_operation','printing-worker-network',true),
          set_config('app.printing_request_id',p_request_id,true);
  IF p_operation IN ('CLAIM_DIRECT','CLAIM_IPP') THEN
    mode_value:=CASE p_operation WHEN 'CLAIM_DIRECT' THEN 'NETWORK_DIRECT' ELSE 'NETWORK_IPP' END;
    page_limit:=LEAST(GREATEST(coalesce(NULLIF(p_details->>'limit','')::integer,25),1),250);
    SELECT j.id,j."jobNumber",j."batchId",j."manufacturerId",j."printerId",j.status,j."printMode",
      j."pipelineState",j."payloadType",j."payloadHash",j.quantity,j."itemCount",j."rangeStart",
      j."rangeEnd",j."sentAt",j."completedAt",j."failureReason",j."reprintOfJobId",
      j."approvedByUserId",j."reprintReason",j."confirmedAt",j."createdAt",j."updatedAt"
      INTO job_row FROM public."PrintJob" j
      WHERE (p_job_id IS NULL OR j.id=p_job_id) AND j."printMode"=mode_value
        AND j.status IN ('PENDING','SENT') AND EXISTS (
          SELECT 1 FROM public."PrintSession" ps JOIN public."PrintItem" pi ON pi."printSessionId"=ps.id
          WHERE ps."printJobId"=j.id AND pi.state='RESERVED'
        )
      ORDER BY j."createdAt",j.id FOR UPDATE SKIP LOCKED LIMIT 1;
    IF NOT FOUND THEN RETURN jsonb_build_object('available',false); END IF;
    PERFORM set_config('app.printing_job_id',job_row.id,true),
            set_config('app.printing_batch_id',job_row."batchId",true),
            set_config('app.printing_printer_id',job_row."printerId",true);
    SELECT ps.id,ps."printJobId",ps."batchId",ps."manufacturerId",ps."printerRegistrationId",
      ps."printerId",ps.status,ps."totalItems",ps."issuedItems",ps."confirmedItems",ps."frozenItems",
      ps."failedReason",ps."startedAt",ps."completedAt",ps."createdAt",ps."updatedAt"
      INTO STRICT session_row FROM public."PrintSession" ps
      WHERE ps."printJobId"=job_row.id FOR UPDATE;
    PERFORM set_config('app.printing_session_row_id',session_row.id,true);
    WITH selected AS (
      SELECT pi.id FROM public."PrintItem" pi
      WHERE pi."printSessionId"=session_row.id AND pi.state='RESERVED'
      ORDER BY pi."issueSequence" NULLS LAST,pi.id FOR UPDATE SKIP LOCKED LIMIT page_limit
    ), issued AS (
      UPDATE public."PrintItem" pi SET state='AGENT_ACKED',"pipelineState"='SENT_TO_PRINTER',
        "attemptCount"=pi."attemptCount"+1,"issuedAt"=coalesce(pi."issuedAt",now_at),
        "dispatchedAt"=now_at,"agentAckedAt"=now_at,
        "confirmationDeadlineAt"=now_at+interval '10 minutes',"updatedAt"=now_at
      FROM selected s WHERE pi.id=s.id RETURNING pi.id
    )
    SELECT array_agg(id ORDER BY id) INTO item_ids FROM issued;
    UPDATE public."PrintJob" SET status='SENT',"pipelineState"='SENT_TO_PRINTER',
      "sentAt"=coalesce("sentAt",now_at),"updatedAt"=now_at WHERE id=job_row.id;
    UPDATE public."Batch" SET "lifecycleState"='PRINT_ACKNOWLEDGED',"updatedAt"=now_at
      WHERE id=job_row."batchId" AND "lifecycleState"='CODES_GENERATED';
    RETURN jsonb_build_object(
      'available',true,'job',to_jsonb(job_row),
      'session',to_jsonb(session_row),
      'printer',(SELECT to_jsonb(p) FROM (
        SELECT printer.id,printer.name,printer.vendor,printer.model,printer."connectionType",
          printer."commandLanguage",printer."ipAddress",printer.host,printer.port,printer."resourcePath",
          printer."tlsEnabled",printer."printerUri",printer."deliveryMode",printer."gatewayId",
          printer."gatewayLastSeenAt",printer."gatewayStatus",printer."gatewayLastError",
          printer."nativePrinterId",printer."agentId",printer."deviceFingerprint",
          printer."printerRegistrationId",printer."orgId",printer."licenseeId",
          printer."assignedUserId",printer."createdByUserId",printer."isActive",printer."isDefault",
          printer."lastSeenAt",printer."lastValidatedAt",printer."lastValidationStatus",
          printer."lastValidationMessage",printer."capabilitySummary",printer."calibrationProfile",
          printer.metadata,printer."createdAt",printer."updatedAt"
        FROM public."Printer" printer WHERE printer.id=job_row."printerId"
      ) p),
      'batch',(SELECT jsonb_build_object('id',b.id,'name',b.name,'licenseeId',b."licenseeId",
        'manufacturerId',b."manufacturerId") FROM public."Batch" b WHERE b.id=job_row."batchId"),
      'items',coalesce((SELECT jsonb_agg(jsonb_build_object(
        'id',pi.id,'qrCodeId',q.id,'code',q.code,'displayCode',q."displayCode",
        'batchId',q."batchId",'licenseeId',q."licenseeId",'tokenNonce',q."tokenNonce",
        'tokenIssuedAt',q."tokenIssuedAt",'tokenExpiresAt',q."tokenExpiresAt",
        'tokenHash',q."tokenHash",'replayEpoch',q."replayEpoch"
      ) ORDER BY pi."issueSequence" NULLS LAST,pi.id)
      FROM public."PrintItem" pi JOIN public."QRCode" q ON q.id=pi."qrCodeId"
      WHERE pi.id=ANY(item_ids)),'[]'::jsonb)
    );
  END IF;

  SELECT j.id,j."batchId",j."manufacturerId",j."printerId",j."printMode"
    INTO STRICT job_row FROM public."PrintJob" j WHERE j.id=p_job_id FOR UPDATE;
  PERFORM set_config('app.printing_job_id',job_row.id,true),
          set_config('app.printing_batch_id',job_row."batchId",true),
          set_config('app.printing_printer_id',job_row."printerId",true);
  SELECT ps.id INTO STRICT session_row FROM public."PrintSession" ps
    WHERE ps."printJobId"=job_row.id FOR UPDATE;
  PERFORM set_config('app.printing_session_row_id',session_row.id,true);
  SELECT coalesce(array_agg(value #>> '{}'),'{}'::text[]) INTO item_ids
    FROM jsonb_array_elements(coalesce(p_details->'itemIds','[]'::jsonb));
  IF cardinality(item_ids)=0 THEN RAISE EXCEPTION 'PRINTING_INVALID_INPUT'; END IF;
  IF p_operation='CONFIRM' THEN
    UPDATE public."PrintItem" SET state='PRINT_CONFIRMED',"pipelineState"='PRINT_CONFIRMED',
      "printConfirmedAt"=now_at,"confirmationEvidence"=jsonb_build_object(
        'runtimeIdentity','identity-background-worker','transport',job_row."printMode",
        'transportReference',p_details->>'transportReference'
      ),"updatedAt"=now_at
      WHERE id=ANY(item_ids) AND "printSessionId"=session_row.id AND state='AGENT_ACKED';
    IF NOT FOUND AND EXISTS (
      SELECT 1 FROM public."PrintItem" pi WHERE pi.id=ANY(item_ids)
        AND pi."printSessionId"=session_row.id AND pi.state NOT IN ('PRINT_CONFIRMED','CLOSED')
    ) THEN RAISE EXCEPTION 'INVALID_STATE_TRANSITION'; END IF;
    UPDATE public."QRCode" q SET status='PRINTED',"printedAt"=coalesce(q."printedAt",now_at),
      "printedByUserId"=job_row."manufacturerId","updatedAt"=now_at
      WHERE q.id IN (SELECT pi."qrCodeId" FROM public."PrintItem" pi WHERE pi.id=ANY(item_ids));
    SELECT count(*) INTO remaining FROM public."PrintItem" pi
      WHERE pi."printSessionId"=session_row.id AND pi.state NOT IN ('PRINT_CONFIRMED','CLOSED','FAILED','CANCELLED');
    IF remaining=0 THEN
      UPDATE public."PrintSession" SET status='COMPLETED',"confirmedItems"="totalItems",
        "completedAt"=now_at,"updatedAt"=now_at WHERE id=session_row.id;
      UPDATE public."PrintJob" SET status='CONFIRMED',"pipelineState"='PRINT_CONFIRMED',
        "confirmedAt"=now_at,"completedAt"=now_at,"updatedAt"=now_at WHERE id=job_row.id;
      UPDATE public."Batch" SET "lifecycleState"='PRINT_CONFIRMED',"printedAt"=now_at,"updatedAt"=now_at
        WHERE id=job_row."batchId" AND "lifecycleState"='PRINT_ACKNOWLEDGED';
    END IF;
  ELSE
    UPDATE public."PrintItem" SET state='FAILED',"pipelineState"='FAILED',"failedAt"=now_at,
      "failureReason"=left(coalesce(p_details->>'reason','network_transport_failed'),500),"updatedAt"=now_at
      WHERE id=ANY(item_ids) AND "printSessionId"=session_row.id
        AND state NOT IN ('PRINT_CONFIRMED','CLOSED');
    UPDATE public."PrintSession" SET status='FAILED',
      "failedReason"=left(coalesce(p_details->>'reason','network_transport_failed'),500),"updatedAt"=now_at
      WHERE id=session_row.id;
    UPDATE public."PrintJob" SET status='FAILED',"pipelineState"='FAILED',
      "failureReason"=left(coalesce(p_details->>'reason','network_transport_failed'),500),"updatedAt"=now_at
      WHERE id=job_row.id;
  END IF;
  INSERT INTO public."PrintAuditEvent"(id,"batchId","printJobId","eventType",actorId,metadata,"createdAt")
  VALUES(gen_random_uuid()::text,job_row."batchId",job_row.id,'WORKER_NETWORK_'||p_operation,
    job_row."manufacturerId",jsonb_build_object('runtimeIdentity','identity-background-worker',
      'itemCount',cardinality(item_ids),'transportReference',p_details->>'transportReference'),now_at);
  RETURN jsonb_build_object('printJobId',job_row.id,'operation',p_operation,
    'itemCount',cardinality(item_ids),'remaining',remaining,'idempotent',false);
END
$fn$;

GRANT EXECUTE ON FUNCTION app_rls.printing_connector_event(text,text,text,text,timestamp without time zone,text,text,text,text,text,text,text,jsonb) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.printing_connector_identity(text,text,text,text,text,text,text) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.printing_connector_registration(text,text,text,text,jsonb) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.printing_control_job(text,text,text,text,text,text) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.printing_create_job(text,text,text,text,text,integer,text,text,text,text,text,jsonb) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.printing_gateway_job(text,text,text,text,text,text,text,jsonb) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.printing_idempotency(text,text,text,text,text,text,text,integer,jsonb) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.printing_printer_administration(text,text,text,text,text,jsonb) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.printing_readiness(text,text,text,text,text,jsonb) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.printing_record_sample(text,text,text,text,text,jsonb) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.printing_reissue_request(text,text,text,text,text,text,integer,text,text,text,text) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.printing_release_batch(text,text,text,text,text,text) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.printing_test_label_job(text,text,text,text,jsonb,jsonb) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.printing_worker_network_job(text,text,text,jsonb) TO "mscqr_rls_cert_worker";
GRANT EXECUTE ON FUNCTION app_rls.printing_worker_reconcile(text,text,integer) TO "mscqr_rls_cert_worker";
RESET ROLE;
DO $$ BEGIN
  IF NOT pg_has_role(session_user,'mscqr_rls_cert_owner','SET') THEN RAISE EXCEPTION 'administrative executor lacks SET authority for mscqr_rls_cert_owner'; END IF;
END $$;
SET ROLE "mscqr_rls_cert_owner";
REVOKE CREATE ON SCHEMA app_rls FROM "mscqr_rls_cert_auth_owner";
RESET ROLE;
DO $$ BEGIN
  IF NOT pg_has_role(session_user,'mscqr_rls_cert_auth_owner','SET') THEN RAISE EXCEPTION 'administrative executor lacks SET authority for mscqr_rls_cert_auth_owner'; END IF;
END $$;
SET ROLE "mscqr_rls_cert_auth_owner";
CREATE OR REPLACE FUNCTION app_public.public_verify_bind(
  p_operation text,
  p_request_id text,
  p_qr_id text DEFAULT NULL,
  p_code text DEFAULT NULL,
  p_decision_id text DEFAULT NULL,
  p_session_id text DEFAULT NULL,
  p_idempotency_hash text DEFAULT NULL
) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public
AS $$
BEGIN
  IF p_operation !~ '^public-verification-[a-z0-9-]{1,64}$'
     OR p_request_id !~ '^[!-~]{1,128}$' THEN
    RAISE EXCEPTION 'PUBLIC_VERIFICATION_INVALID_INPUT' USING ERRCODE='22023';
  END IF;
  PERFORM set_config('app.public_verification_operation',p_operation,true);
  PERFORM set_config('app.public_verification_request_id',p_request_id,true);
  PERFORM set_config('app.public_verification_qr_id',coalesce(p_qr_id,''),true);
  PERFORM set_config('app.public_verification_code',coalesce(p_code,''),true);
  PERFORM set_config('app.public_verification_decision_id',coalesce(p_decision_id,''),true);
  PERFORM set_config('app.public_verification_session_id',coalesce(p_session_id,''),true);
  PERFORM set_config('app.public_verification_idempotency_hash',coalesce(p_idempotency_hash,''),true);
  PERFORM set_config('app.public_verification_target_id','',true);
  PERFORM set_config('app.public_verification_support_id','',true);
  PERFORM set_config('app.public_verification_audit_id','',true);
  PERFORM set_config('app.public_verification_outbox_id','',true);
  PERFORM set_config('app.public_verification_organization_id','',true);
  PERFORM set_config('app.public_verification_licensee_id','',true);
  PERFORM set_config('app.public_verification_batch_id','',true);
  PERFORM set_config('app.public_verification_manufacturer_id','',true);
  PERFORM set_config('app.public_verification_customer_session_hash','',true);
  PERFORM set_config('app.public_verification_transfer_token_hash','',true);
  PERFORM set_config('app.public_verification_passkey_ticket_hashes','',true);
  PERFORM set_config('app.public_verification_customer_user_id','',true);
END
$$;

CREATE OR REPLACE FUNCTION app_public.issue_customer_auth_session(
  p_capability text,
  p_customer_user_id text,
  p_customer_email text,
  p_auth_strength text,
  p_auth_provider text,
  p_issued_at timestamp without time zone,
  p_expires_at timestamp without time zone,
  p_request_id text
) RETURNS TABLE("accepted" boolean)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public
AS $$
DECLARE session_id text:=gen_random_uuid()::text;
BEGIN
  IF length(p_capability)<32 OR length(p_capability)>4096
     OR p_customer_user_id !~ '^cust_[a-f0-9]{32}$'
     OR p_customer_email !~ '^[^[:space:]@]+@[^[:space:]@]+[.][^[:space:]@]+$'
     OR p_auth_strength NOT IN ('EMAIL_OTP','PASSKEY','SOCIAL')
     OR p_auth_provider NOT IN ('EMAIL_OTP','GOOGLE')
     OR p_issued_at IS NULL OR p_expires_at<=p_issued_at
     OR p_expires_at>p_issued_at+interval '31 days' THEN
    RAISE EXCEPTION 'PUBLIC_CUSTOMER_SESSION_INVALID' USING ERRCODE='22023';
  END IF;
  PERFORM app_public.public_verify_bind('public-verification-customer-session-issue',p_request_id,NULL,NULL,NULL,NULL,NULL);
  PERFORM set_config('app.public_verification_target_id',session_id,true);
  INSERT INTO public."CustomerAuthSession"(
    id,"tokenHash","customerUserId","customerEmail","authStrength","authProvider",
    "issuedAt","expiresAt","lastSeenAt","revokedAt","createdAt","updatedAt"
  ) VALUES (
    session_id,encode(sha256(convert_to(p_capability,'UTF8')),'hex'),p_customer_user_id,lower(p_customer_email),
    p_auth_strength,p_auth_provider,p_issued_at,p_expires_at,p_issued_at,NULL,p_issued_at,p_issued_at
  );
  RETURN QUERY SELECT true;
END
$$;

CREATE OR REPLACE FUNCTION app_public.require_customer_auth_session(
  p_capability text,
  p_checked_at timestamp without time zone,
  p_request_id text,
  p_operation text
) RETURNS TABLE(
  "sessionId" text,
  "customerUserId" text,
  "customerEmail" text,
  "authStrength" text,
  "authProvider" text
)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public
AS $$
DECLARE session_row record;
BEGIN
  IF length(p_capability)<32 OR length(p_capability)>4096
     OR p_checked_at IS NULL
     OR p_operation !~ '^customer-[a-z0-9-]{1,64}$' THEN
    RAISE EXCEPTION 'PUBLIC_CUSTOMER_SESSION_DENIED' USING ERRCODE='42501';
  END IF;
  PERFORM app_public.public_verify_bind('public-verification-'||p_operation,p_request_id,NULL,NULL,NULL,NULL,NULL);
  PERFORM set_config('app.public_verification_customer_session_hash',encode(sha256(convert_to(p_capability,'UTF8')),'hex'),true);
  SELECT s.id,s."customerUserId",s."customerEmail",s."authStrength",s."authProvider",
    s."expiresAt",s."revokedAt" INTO session_row
  FROM public."CustomerAuthSession" s
  WHERE s."tokenHash"=encode(sha256(convert_to(p_capability,'UTF8')),'hex');
  IF session_row.id IS NULL OR session_row."revokedAt" IS NOT NULL OR session_row."expiresAt"<=p_checked_at THEN
    RAISE EXCEPTION 'PUBLIC_CUSTOMER_SESSION_DENIED' USING ERRCODE='42501';
  END IF;
  PERFORM set_config('app.public_verification_target_id',session_row.id,true);
  UPDATE public."CustomerAuthSession" AS s SET "lastSeenAt"=p_checked_at,"updatedAt"=p_checked_at
  WHERE s.id=session_row.id AND s."revokedAt" IS NULL AND s."expiresAt">p_checked_at
  RETURNING s.id,s."customerUserId",s."customerEmail",s."authStrength",s."authProvider",s."expiresAt",s."revokedAt"
  INTO session_row;
  IF session_row.id IS NULL THEN
    RAISE EXCEPTION 'PUBLIC_CUSTOMER_SESSION_DENIED' USING ERRCODE='42501';
  END IF;
  RETURN QUERY SELECT session_row.id,session_row."customerUserId",session_row."customerEmail",
    session_row."authStrength",session_row."authProvider";
END
$$;

CREATE OR REPLACE FUNCTION app_public.read_customer_auth_session(
  p_capability text,
  p_checked_at timestamp without time zone,
  p_request_id text
) RETURNS TABLE(
  "customerUserId" text,
  "customerEmail" text,
  "authStrength" text,
  "authProvider" text
)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public
AS $$
DECLARE session_row record;
BEGIN
  SELECT * INTO session_row FROM app_public.require_customer_auth_session(
    p_capability,p_checked_at,p_request_id,'customer-session-read'
  );
  RETURN QUERY SELECT session_row."customerUserId",session_row."customerEmail",
    session_row."authStrength",session_row."authProvider";
END
$$;

CREATE OR REPLACE FUNCTION app_public.revoke_customer_auth_session(
  p_capability text,
  p_revoked_at timestamp without time zone,
  p_request_id text
) RETURNS TABLE("revoked" boolean)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public
AS $$
DECLARE session_row record;
BEGIN
  IF length(p_capability)<32 OR length(p_capability)>4096 OR p_revoked_at IS NULL THEN
    RAISE EXCEPTION 'PUBLIC_CUSTOMER_SESSION_DENIED' USING ERRCODE='42501';
  END IF;
  PERFORM app_public.public_verify_bind(
    'public-verification-customer-session-revoke',p_request_id,NULL,NULL,NULL,NULL,NULL
  );
  PERFORM set_config(
    'app.public_verification_customer_session_hash',
    encode(sha256(convert_to(p_capability,'UTF8')),'hex'),true
  );
  SELECT s.id INTO session_row FROM public."CustomerAuthSession" s
  WHERE s."tokenHash"=encode(sha256(convert_to(p_capability,'UTF8')),'hex');
  IF session_row.id IS NULL THEN
    RAISE EXCEPTION 'PUBLIC_CUSTOMER_SESSION_DENIED' USING ERRCODE='42501';
  END IF;
  PERFORM set_config('app.public_verification_target_id',session_row.id,true);
  UPDATE public."CustomerAuthSession"
    SET "revokedAt"=coalesce("revokedAt",p_revoked_at),"updatedAt"=p_revoked_at
  WHERE id=session_row.id;
  RETURN QUERY SELECT true;
END
$$;

CREATE OR REPLACE FUNCTION app_public.public_verify_execute(
  p_qr_id text,
  p_proof_source text,
  p_checked_at timestamp without time zone,
  p_request_id text,
  p_actor_ip_hash text,
  p_actor_device_hash text,
  p_session_start_token_hash text,
  p_signed_token_digest text DEFAULT NULL
) RETURNS TABLE(
  "result" text,
  "messageKey" text,
  "nextAction" text,
  "maskedCode" text,
  "brandName" text,
  "brandWebsite" text,
  "brandSupportEmail" text,
  "brandSupportPhone" text,
  "manufacturerName" text,
  "manufacturerWebsite" text,
  "printedAt" timestamp without time zone,
  "firstVerifiedAt" timestamp without time zone,
  "latestVerifiedAt" timestamp without time zone,
  "ownershipClaimAvailable" boolean,
  "sessionStartToken" text
)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public
AS $$
DECLARE
  qr record;
  batch record;
  brand record;
  organization record;
  manufacturer record;
  previous_scan record;
  replacement_status text := 'NONE';
  classification text;
  outcome public."VerificationDecisionOutcome";
  risk_band public."VerificationRiskBand";
  public_result text;
  message_key text;
  next_action text;
  decision_id text := gen_random_uuid()::text;
  evidence_id text := gen_random_uuid()::text;
  scan_id text := gen_random_uuid()::text;
  audit_id text := gen_random_uuid()::text;
  outbox_id text := gen_random_uuid()::text;
  next_scan_count integer;
  first_at timestamp without time zone;
  ready boolean;
  same_context boolean;
  claim_available boolean;
  scan_history_eligible boolean;
  safe_code text;
BEGIN
  IF p_proof_source NOT IN ('SIGNED_LABEL','MANUAL_CODE_LOOKUP')
     OR p_qr_id !~ '^[0-9a-fA-F-]{36}$'
     OR p_checked_at IS NULL
     OR p_session_start_token_hash !~ '^(?:[A-Za-z0-9._-]{1,32}:)?[a-f0-9]{64}$'
     OR (p_actor_ip_hash IS NOT NULL AND p_actor_ip_hash !~ '^(?:[A-Za-z0-9._-]{1,32}:)?[a-f0-9]{64}$')
     OR (p_actor_device_hash IS NOT NULL AND p_actor_device_hash !~ '^(?:[A-Za-z0-9._-]{1,32}:)?[a-f0-9]{64}$')
     OR (p_signed_token_digest IS NOT NULL AND p_signed_token_digest !~ '^(?:[A-Za-z0-9._-]{1,32}:)?[a-f0-9]{64}$') THEN
    RAISE EXCEPTION 'PUBLIC_VERIFICATION_INVALID_INPUT' USING ERRCODE='22023';
  END IF;
  SELECT NULL::text AS id,NULL::text AS "licenseeId",NULL::text AS "manufacturerId",
    NULL::text AS "lifecycleState",NULL::timestamp AS "printedAt",NULL::timestamp AS "suspendedAt" INTO batch;
  SELECT NULL::text AS id,NULL::text AS name,NULL::text AS website INTO manufacturer;
  SELECT NULL::text AS id,NULL::timestamp AS "scannedAt",NULL::text AS "ipAddress",NULL::text AS device INTO previous_scan;

  PERFORM app_public.public_verify_bind(
    'public-verification-execute',p_request_id,p_qr_id,NULL,decision_id,NULL,NULL
  );
  PERFORM set_config('app.public_verification_audit_id',audit_id,true);
  PERFORM set_config('app.public_verification_outbox_id',outbox_id,true);
  SELECT q.id,q.code,q."licenseeId",q."batchId",q.status,q."scanCount",q."scannedAt",q."printedAt",
    q."issuanceMode",q."customerVerifiableAt",q."signedFirstSeenAt",q."lastSignedVerificationAt",
    q."lastSignedVerificationIpHash",q."lastSignedVerificationDeviceHash"
  INTO STRICT qr
  FROM public."QRCode" q WHERE q.id=p_qr_id FOR UPDATE;
  PERFORM set_config('app.public_verification_licensee_id',qr."licenseeId",true);
  PERFORM set_config('app.public_verification_batch_id',coalesce(qr."batchId",''),true);
  SELECT l.id,l."orgId",l.name,l."brandName",l.website,l."supportEmail",l."supportPhone",
    l."isActive",l."suspendedAt"
  INTO brand
  FROM public."Licensee" l WHERE l.id=qr."licenseeId";
  IF brand.id IS NULL THEN RAISE EXCEPTION 'PUBLIC_VERIFICATION_SCOPE_INVALID' USING ERRCODE='42501'; END IF;
  PERFORM set_config('app.public_verification_organization_id',brand."orgId",true);
  SELECT o.id,o."isActive" INTO organization
  FROM public."Organization" o WHERE o.id=brand."orgId";
  IF organization.id IS NULL THEN
    RAISE EXCEPTION 'PUBLIC_VERIFICATION_SCOPE_INVALID' USING ERRCODE='42501';
  END IF;
  IF NOT brand."isActive" OR brand."suspendedAt" IS NOT NULL OR NOT organization."isActive" THEN
    RAISE EXCEPTION 'PUBLIC_VERIFICATION_SCOPE_INVALID' USING ERRCODE='42501';
  END IF;
  IF qr."batchId" IS NOT NULL THEN
    SELECT b.id,b."licenseeId",b."manufacturerId",b."lifecycleState",b."printedAt",b."suspendedAt"
    INTO batch
    FROM public."Batch" b WHERE b.id=qr."batchId";
    IF batch.id IS NULL OR batch."licenseeId"<>qr."licenseeId" THEN
      RAISE EXCEPTION 'PUBLIC_VERIFICATION_SCOPE_INVALID' USING ERRCODE='42501';
    END IF;
    IF batch.id IS NOT NULL AND batch."manufacturerId" IS NOT NULL THEN
      PERFORM set_config('app.public_verification_manufacturer_id',batch."manufacturerId",true);
      SELECT u.id,u.name,u.website INTO manufacturer
      FROM public."User" u WHERE u.id=batch."manufacturerId";
    END IF;
  END IF;
  SELECT s.id,s."scannedAt",s."ipAddress",s.device
  INTO previous_scan
  FROM public."QrScanLog" s
  WHERE s."qrCodeId"=qr.id
  ORDER BY s."scannedAt" DESC,s.id DESC LIMIT 1;
  SELECT min(s."scannedAt") INTO first_at
  FROM public."QrScanLog" s
  WHERE s."qrCodeId"=qr.id;
  SELECT CASE
    WHEN rc."originalQrCodeId"=qr.id THEN 'REPLACED_LABEL'
    ELSE 'ACTIVE_REPLACEMENT'
  END INTO replacement_status
  FROM public."ReplacementChain" rc
  WHERE rc.status='ACTIVE'
    AND (rc."originalQrCodeId"=qr.id OR rc."replacementQrCodeId"=qr.id)
  ORDER BY rc."createdAt" DESC LIMIT 1;
  replacement_status:=coalesce(replacement_status,'NONE');

  ready := qr.status IN ('PRINTED','SCANNED','REDEEMED')
    AND batch.id IS NOT NULL
    AND batch."lifecycleState"::text='RELEASED'
    AND batch."suspendedAt" IS NULL
    AND (qr."issuanceMode"<>'GOVERNED_PRINT' OR qr."customerVerifiableAt" IS NOT NULL);
  same_context := previous_scan.id IS NOT NULL
    AND p_actor_device_hash IS NOT NULL
    AND p_actor_ip_hash IS NOT NULL
    AND previous_scan.device=p_actor_device_hash
    AND previous_scan."ipAddress"=p_actor_ip_hash;
  IF qr.status='BLOCKED' OR replacement_status='REPLACED_LABEL' THEN
    classification:='BLOCKED_BY_SECURITY'; outcome:='BLOCKED'; risk_band:='CRITICAL';
    public_result:='BLOCKED'; message_key:='verification.blocked'; next_action:='REPORT_CONCERN';
  ELSIF NOT ready THEN
    classification:='NOT_READY_FOR_CUSTOMER_USE'; outcome:='NOT_READY'; risk_band:='ELEVATED';
    public_result:='NOT_READY'; message_key:='verification.not_ready'; next_action:='TRY_LATER';
  ELSIF previous_scan.id IS NULL THEN
    classification:='FIRST_SCAN'; outcome:='AUTHENTIC'; risk_band:='LOW';
    public_result:='AUTHENTIC'; message_key:='verification.first_scan'; next_action:='SAVE_OR_REPORT';
  ELSIF same_context THEN
    classification:='LEGIT_REPEAT'; outcome:='AUTHENTIC'; risk_band:='LOW';
    public_result:='AUTHENTIC_REPEAT'; message_key:='verification.repeat'; next_action:='SAVE_OR_REPORT';
  ELSE
    classification:='SUSPICIOUS_DUPLICATE'; outcome:='SUSPICIOUS_DUPLICATE'; risk_band:='HIGH';
    public_result:='REVIEW'; message_key:='verification.changed_context'; next_action:='REPORT_CONCERN';
  END IF;

  safe_code:=CASE WHEN length(qr.code)<=4 THEN repeat('*',length(qr.code))
    ELSE repeat('*',length(qr.code)-4)||right(qr.code,4) END;
  scan_history_eligible:=classification IN ('FIRST_SCAN','LEGIT_REPEAT','SUSPICIOUS_DUPLICATE');
  next_scan_count:=coalesce(qr."scanCount",0);
  IF scan_history_eligible THEN
    next_scan_count:=next_scan_count+1;
    INSERT INTO public."QrScanLog"(
      id,code,"qrCodeId","licenseeId","batchId",status,"scannedAt","isFirstScan","scanCount",
      "customerUserId","ownershipId","ownershipMatchMethod","isTrustedOwnerContext",
      "ipAddress","userAgent",device,latitude,longitude,accuracy,
      "locationName","locationCountry","locationRegion","locationCity"
    ) VALUES (
      scan_id,qr.code,qr.id,qr."licenseeId",qr."batchId",qr.status,p_checked_at,
      classification='FIRST_SCAN',next_scan_count,NULL,NULL,NULL,false,
      p_actor_ip_hash,NULL,p_actor_device_hash,NULL,NULL,NULL,NULL,NULL,NULL,NULL
    );
    UPDATE public."QRCode" SET
      "scanCount"=next_scan_count,"scannedAt"=p_checked_at,
      "lastScanIp"=p_actor_ip_hash,"lastScanDevice"=p_actor_device_hash,"lastScanUserAgent"=NULL,
      "signedFirstSeenAt"=CASE WHEN p_proof_source='SIGNED_LABEL' THEN coalesce("signedFirstSeenAt",p_checked_at) ELSE "signedFirstSeenAt" END,
      "lastSignedVerificationAt"=CASE WHEN p_proof_source='SIGNED_LABEL' AND classification<>'SUSPICIOUS_DUPLICATE' THEN p_checked_at ELSE "lastSignedVerificationAt" END,
      "lastSignedVerificationIpHash"=CASE WHEN p_proof_source='SIGNED_LABEL' AND classification<>'SUSPICIOUS_DUPLICATE' THEN p_actor_ip_hash ELSE "lastSignedVerificationIpHash" END,
      "lastSignedVerificationDeviceHash"=CASE WHEN p_proof_source='SIGNED_LABEL' AND classification<>'SUSPICIOUS_DUPLICATE' THEN p_actor_device_hash ELSE "lastSignedVerificationDeviceHash" END,
      "updatedAt"=transaction_timestamp()
    WHERE id=qr.id;
  END IF;
  INSERT INTO public."VerificationDecision"(
    id,"decisionVersion","qrCodeId",code,"licenseeId","batchId","proofSource","proofTier",
    outcome,classification,"reasonCodes","riskBand","replacementStatus","degradationMode",
    "customerTrustLevel","isAuthentic","scanCount","riskScore","actorIpHash","actorDeviceHash",metadata,"createdAt"
  ) VALUES (
    decision_id,1,qr.id,qr.code,qr."licenseeId",qr."batchId",p_proof_source,
    (CASE WHEN p_proof_source='SIGNED_LABEL' THEN 'SIGNED_LABEL' ELSE 'MANUAL_REGISTRY_LOOKUP' END)::public."VerificationProofTier",
    outcome,classification,ARRAY[classification,p_proof_source],risk_band,
    replacement_status::public."VerificationReplacementStatus",'NORMAL'::public."VerificationDegradationMode",
    'ANONYMOUS'::public."CustomerTrustLevel",outcome='AUTHENTIC',next_scan_count,
    CASE risk_band WHEN 'CRITICAL' THEN 100 WHEN 'HIGH' THEN 80 WHEN 'ELEVATED' THEN 50 ELSE 10 END,
    p_actor_ip_hash,p_actor_device_hash,
    jsonb_build_object(
      'publicOutcome',public_result,'messageKey',message_key,'nextActionKey',next_action,
      'requestId',p_request_id,'signedTokenDigestPresent',p_signed_token_digest IS NOT NULL
    ),p_checked_at
  );
  INSERT INTO public."VerificationEvidenceSnapshot"(
    id,"verificationDecisionId","scanSummary","ownershipSnapshot","riskSignals","policySnapshot",
    "lifecycleSnapshot",metadata,"createdAt"
  ) VALUES (
    evidence_id,decision_id,
    jsonb_build_object('totalScans',next_scan_count,'firstScan',scan_history_eligible AND classification='FIRST_SCAN',
      'firstVerifiedAt',CASE WHEN scan_history_eligible THEN coalesce(first_at,p_checked_at) ELSE first_at END,
      'latestVerifiedAt',CASE WHEN scan_history_eligible THEN p_checked_at ELSE qr."scannedAt" END),
    jsonb_build_object('claimAvailable',ready AND qr.status<>'BLOCKED'),
    jsonb_build_object('contextChanged',scan_history_eligible AND previous_scan.id IS NOT NULL AND NOT same_context),
    NULL,
    jsonb_build_object('qrStatus',qr.status,'batchLifecycle',batch."lifecycleState",
      'customerVerifiableAt',qr."customerVerifiableAt",'replacementStatus',replacement_status),
    jsonb_build_object(
      'publicSessionStart',jsonb_build_object('tokenHash',p_session_start_token_hash,'issuedAt',p_checked_at,
        'expiresAt',p_checked_at+interval '15 minutes'),
      'presentationSnapshot',jsonb_build_object(
        'publicOutcome',public_result,'messageKey',message_key,'nextActionKey',next_action,
        'maskedCode',safe_code,'brandName',coalesce(brand."brandName",brand.name),
        'brandWebsite',CASE WHEN brand.website ~ '^https?://' THEN brand.website ELSE NULL END,
        'brandSupportEmail',brand."supportEmail",'brandSupportPhone',brand."supportPhone",
        'manufacturerName',manufacturer.name,'manufacturerWebsite',
          CASE WHEN manufacturer.website ~ '^https?://' THEN manufacturer.website ELSE NULL END,
        'printedAt',coalesce(qr."printedAt",batch."printedAt"),
        'firstVerifiedAt',CASE WHEN scan_history_eligible THEN coalesce(first_at,p_checked_at) ELSE first_at END,
        'latestVerifiedAt',CASE WHEN scan_history_eligible THEN p_checked_at ELSE qr."scannedAt" END,
        'ownershipClaimAvailable',ready AND qr.status<>'BLOCKED',
        'proofSource',p_proof_source)
    ),
    p_checked_at
  );
  INSERT INTO public."AuditLog"(
    id,"userId","orgId","licenseeId",action,"entityType","entityId",details,
    "ipAddress","ipHash","userAgent","createdAt"
  ) VALUES (
    audit_id,NULL,NULL,qr."licenseeId",'PUBLIC_VERIFICATION_RECORDED','VerificationDecision',decision_id,
    jsonb_build_object('classification',classification,'proofSource',p_proof_source,
      'scanCount',next_scan_count,'requestId',p_request_id),
    NULL,NULL,NULL,p_checked_at
  );
  INSERT INTO public."SecurityEventOutbox"(
    id,"eventType",payload,"jobType","requestId","payloadDigest","idempotencyKey",
    "organizationId","licenseeId","manufacturerId","initiatingUserId","expiresAt",
    "claimedAt","claimLeaseExpiresAt","sinkEventId",status,attempts,"nextAttemptAt","lastError","sentAt",
    "createdAt","updatedAt"
  ) VALUES (
    outbox_id,'PUBLIC_VERIFICATION_DECISION',
    jsonb_build_object('decisionId',decision_id,'classification',classification,
      'proofSource',p_proof_source,'requestId',p_request_id),
    NULL,p_request_id,NULL,
    encode(sha256(convert_to('public-verification:'||decision_id,'UTF8')),'hex'),
    NULL,qr."licenseeId",batch."manufacturerId",NULL,p_checked_at+interval '30 days',
    NULL,NULL,NULL,'QUEUED',0,p_checked_at,NULL,NULL,p_checked_at,p_checked_at
  );

  claim_available:=ready AND qr.status<>'BLOCKED' AND replacement_status<>'REPLACED_LABEL';
  RETURN QUERY SELECT
    public_result,message_key,next_action,safe_code,
    coalesce(brand."brandName",brand.name),
    CASE WHEN brand.website ~ '^https?://' THEN brand.website ELSE NULL END,
    brand."supportEmail",brand."supportPhone",manufacturer.name,
    CASE WHEN manufacturer.website ~ '^https?://' THEN manufacturer.website ELSE NULL END,
    coalesce(qr."printedAt",batch."printedAt"),
    CASE WHEN scan_history_eligible THEN coalesce(first_at,p_checked_at) ELSE first_at END,
    CASE WHEN scan_history_eligible THEN p_checked_at ELSE qr."scannedAt" END,
    claim_available,NULL::text;
END
$$;

CREATE OR REPLACE FUNCTION app_public.verify_raw_qr(
  p_requested_code text,
  p_checked_at timestamp without time zone,
  p_request_id text,
  p_actor_ip_hash text,
  p_actor_device_hash text,
  p_session_start_token_hash text
) RETURNS TABLE(
  "result" text,"messageKey" text,"nextAction" text,"maskedCode" text,
  "brandName" text,"brandWebsite" text,"brandSupportEmail" text,"brandSupportPhone" text,
  "manufacturerName" text,"manufacturerWebsite" text,
  "printedAt" timestamp without time zone,"firstVerifiedAt" timestamp without time zone,
  "latestVerifiedAt" timestamp without time zone,"ownershipClaimAvailable" boolean,
  "sessionStartToken" text
)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public
AS $$
DECLARE qr_id text;
BEGIN
  IF p_requested_code IS NULL OR p_requested_code<>btrim(p_requested_code)
     OR length(p_requested_code)<8 OR length(p_requested_code)>128
     OR p_requested_code !~ '^[A-Za-z0-9][A-Za-z0-9_-]{7,127}$' THEN
    RAISE EXCEPTION 'PUBLIC_VERIFICATION_INVALID_INPUT' USING ERRCODE='22023';
  END IF;
  PERFORM app_public.public_verify_bind(
    'public-verification-raw-resolve',p_request_id,NULL,p_requested_code,NULL,NULL,NULL
  );
  SELECT q.id INTO qr_id FROM public."QRCode" q WHERE q.code=p_requested_code;
  IF qr_id IS NULL THEN
    -- Bounded PostgreSQL jitter reduces the unknown-code timing oracle without
    -- holding a QR row lock or allowing caller-controlled delay.
    PERFORM pg_sleep(0.015 + random()*0.010);
    RETURN QUERY SELECT 'NOT_FOUND','verification.not_found','TRY_AGAIN',
      CASE WHEN length(p_requested_code)<=4 THEN repeat('*',length(p_requested_code))
        ELSE repeat('*',length(p_requested_code)-4)||right(p_requested_code,4) END,
      NULL::text,NULL::text,NULL::text,NULL::text,NULL::text,NULL::text,
      NULL::timestamp,NULL::timestamp,NULL::timestamp,false,NULL::text;
    RETURN;
  END IF;
  RETURN QUERY SELECT * FROM app_public.public_verify_execute(
    qr_id,'MANUAL_CODE_LOOKUP',p_checked_at,p_request_id,p_actor_ip_hash,p_actor_device_hash,
    p_session_start_token_hash,NULL
  );
END
$$;

CREATE OR REPLACE FUNCTION app_public.verify_signed_qr(
  p_token_digest text,
  p_qr_id text,
  p_licensee_id text,
  p_batch_id text,
  p_manufacturer_id text,
  p_nonce text,
  p_replay_epoch integer,
  p_key_version text,
  p_issued_at timestamp without time zone,
  p_expires_at timestamp without time zone,
  p_checked_at timestamp without time zone,
  p_request_id text,
  p_actor_ip_hash text,
  p_actor_device_hash text,
  p_session_start_token_hash text
) RETURNS TABLE(
  "result" text,"messageKey" text,"nextAction" text,"verificationMethod" text,
  "maskedCode" text,"brandName" text,"brandWebsite" text,"brandSupportEmail" text,
  "brandSupportPhone" text,"manufacturerName" text,"manufacturerWebsite" text,
  "printedAt" timestamp without time zone,"firstVerifiedAt" timestamp without time zone,
  "latestVerifiedAt" timestamp without time zone,"ownershipClaimAvailable" boolean,
  "sessionStartToken" text
)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public
AS $$
DECLARE qr record; batch record;
BEGIN
  IF p_token_digest !~ '^(?:[A-Za-z0-9._-]{1,32}:)?[a-f0-9]{64}$'
     OR length(coalesce(p_nonce,'')) NOT BETWEEN 8 AND 256
     OR p_nonce !~ '^[A-Za-z0-9_-]+$'
     OR p_replay_epoch<1 OR p_key_version !~ '^[A-Za-z0-9._-]{1,64}$'
     OR p_issued_at>p_checked_at OR p_checked_at>=p_expires_at THEN
    RAISE EXCEPTION 'PUBLIC_SIGNED_TOKEN_INVALID' USING ERRCODE='22023';
  END IF;
  PERFORM app_public.public_verify_bind(
    'public-verification-signed-resolve',p_request_id,p_qr_id,NULL,NULL,NULL,NULL
  );
  SELECT q.id,q."licenseeId",q."batchId",q."tokenHash",q."tokenNonce",q."replayEpoch",
    q."tokenIssuedAt",q."tokenExpiresAt"
  INTO qr
  FROM public."QRCode" q WHERE q.id=p_qr_id;
  IF qr.id IS NULL OR qr."licenseeId"<>p_licensee_id
     OR qr."batchId" IS DISTINCT FROM p_batch_id
     OR qr."tokenHash" IS DISTINCT FROM p_token_digest
     OR qr."tokenNonce" IS DISTINCT FROM p_nonce
     OR qr."replayEpoch"<>p_replay_epoch
     OR qr."tokenIssuedAt" IS NULL
     OR abs(extract(epoch FROM (qr."tokenIssuedAt"-p_issued_at)))>1
     OR qr."tokenExpiresAt" IS NULL
     OR abs(extract(epoch FROM (qr."tokenExpiresAt"-p_expires_at)))>1
     OR qr."tokenExpiresAt"<=p_checked_at THEN
    RAISE EXCEPTION 'PUBLIC_SIGNED_TOKEN_INVALID' USING ERRCODE='42501';
  END IF;
  PERFORM set_config('app.public_verification_batch_id',coalesce(qr."batchId",''),true);
  IF qr."batchId" IS NOT NULL THEN
    SELECT b.id,b."manufacturerId" INTO batch
    FROM public."Batch" b WHERE b.id=qr."batchId";
    IF batch."manufacturerId" IS DISTINCT FROM p_manufacturer_id THEN
      RAISE EXCEPTION 'PUBLIC_SIGNED_TOKEN_INVALID' USING ERRCODE='42501';
    END IF;
  ELSIF p_manufacturer_id IS NOT NULL THEN
    RAISE EXCEPTION 'PUBLIC_SIGNED_TOKEN_INVALID' USING ERRCODE='42501';
  END IF;
  RETURN QUERY SELECT v."result",v."messageKey",v."nextAction",'SIGNED_LABEL'::text,
    v."maskedCode",v."brandName",v."brandWebsite",v."brandSupportEmail",v."brandSupportPhone",
    v."manufacturerName",v."manufacturerWebsite",
    v."printedAt",v."firstVerifiedAt",v."latestVerifiedAt",v."ownershipClaimAvailable",v."sessionStartToken"
  FROM app_public.public_verify_execute(
    p_qr_id,'SIGNED_LABEL',p_checked_at,p_request_id,p_actor_ip_hash,p_actor_device_hash,
    p_session_start_token_hash,p_token_digest
  ) v;
END
$$;

CREATE OR REPLACE FUNCTION app_public.record_qr_verification(
  p_qr_id text,p_proof_class text,p_outcome_code text,p_scanned_at timestamp without time zone,
  p_request_id text,p_actor_ip_hash text,p_actor_device_hash text
) RETURNS TABLE("decisionKey" text,"recorded" boolean)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public
AS $$
BEGIN
  RAISE EXCEPTION 'PUBLIC_VERIFICATION_INTERNAL_ONLY' USING ERRCODE='42501';
END
$$;

CREATE OR REPLACE FUNCTION app_public.start_verification_session(
  p_session_start_token_hash text,
  p_entry_method text,
  p_customer_capability text,
  p_checked_at timestamp without time zone,
  p_request_id text,
  p_session_proof_hash text
) RETURNS TABLE(
  "sessionId" text,"sessionProofToken" text,"maskedCode" text,"customerFacingState" text,
  "entryMethod" text,"authState" text,"startedAt" timestamp without time zone,
  "expiresAt" timestamp without time zone,"proofBindingExpiresAt" timestamp without time zone,
  "brandName" text
)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public
AS $$
DECLARE evidence record;
  decision record;
  customer record;
  session_id text:=gen_random_uuid()::text;
  expires_at timestamp without time zone:=p_checked_at+interval '24 hours';
  updated_metadata jsonb; token_state jsonb; brand_name text;
BEGIN
  SELECT NULL::text AS "customerUserId",NULL::text AS "customerEmail" INTO customer;
  IF p_entry_method NOT IN ('SIGNED_SCAN','MANUAL_CODE')
     OR p_session_start_token_hash !~ '^(?:[A-Za-z0-9._-]{1,32}:)?[a-f0-9]{64}$'
     OR p_session_proof_hash !~ '^(?:[A-Za-z0-9._-]{1,32}:)?[a-f0-9]{64}$' THEN
    RAISE EXCEPTION 'PUBLIC_VERIFICATION_SESSION_INVALID' USING ERRCODE='22023';
  END IF;
  IF p_customer_capability IS NOT NULL THEN
    SELECT * INTO customer FROM app_public.require_customer_auth_session(
      p_customer_capability,p_checked_at,p_request_id,'customer-verification-session-start'
    );
  END IF;
  PERFORM app_public.public_verify_bind(
    'public-verification-session-start',p_request_id,NULL,NULL,NULL,session_id,NULL
  );
  SELECT e.id,e."verificationDecisionId",e.metadata
  INTO evidence
  FROM public."VerificationEvidenceSnapshot" e
  WHERE e.metadata#>>'{publicSessionStart,tokenHash}'=p_session_start_token_hash
  ORDER BY e."createdAt" DESC LIMIT 1 FOR UPDATE;
  token_state:=coalesce(evidence.metadata->'publicSessionStart','{}'::jsonb);
  IF evidence.id IS NULL OR token_state ? 'consumedAt'
     OR (token_state->>'expiresAt')::timestamp without time zone<=p_checked_at THEN
    RAISE EXCEPTION 'PUBLIC_VERIFICATION_SESSION_INVALID' USING ERRCODE='42501';
  END IF;
  PERFORM set_config('app.public_verification_decision_id',evidence."verificationDecisionId",true);
  SELECT d.id,d."qrCodeId",d.code,d."licenseeId"
  INTO STRICT decision
  FROM public."VerificationDecision" d
  WHERE d.id=evidence."verificationDecisionId";
  IF decision."licenseeId" IS NOT NULL THEN
    PERFORM set_config('app.public_verification_licensee_id',decision."licenseeId",true);
    SELECT coalesce(l."brandName",l.name) INTO brand_name
    FROM public."Licensee" l WHERE l.id=decision."licenseeId";
  END IF;
  updated_metadata:=jsonb_set(evidence.metadata,'{publicSessionStart,consumedAt}',to_jsonb(p_checked_at),true);
  UPDATE public."VerificationEvidenceSnapshot" SET metadata=updated_metadata WHERE id=evidence.id;
  INSERT INTO public."CustomerVerificationSession"(
    id,"verificationDecisionId","qrCodeId",code,"entryMethod","authState",
    "customerUserId","customerEmail","intakeCompletedAt","revealedAt","expiresAt",
    "proofBindingTokenHash","proofBindingIssuedAt","proofBindingExpiresAt","proofBindingReplayEpoch",
    metadata,"createdAt","updatedAt"
  ) VALUES (
    session_id,decision.id,decision."qrCodeId",decision.code,
    p_entry_method::public."CustomerVerificationEntryMethod",
    (CASE WHEN customer."customerUserId" IS NULL THEN 'PENDING' ELSE 'VERIFIED' END)::public."CustomerVerificationAuthState",
    customer."customerUserId",customer."customerEmail",NULL,NULL,expires_at,p_session_proof_hash,p_checked_at,
    p_checked_at+interval '30 minutes',NULL,
    jsonb_build_object('boundCustomerUserId',customer."customerUserId"),p_checked_at,p_checked_at
  );
  RETURN QUERY SELECT session_id,NULL::text,
    CASE WHEN decision.code IS NULL THEN '' WHEN length(decision.code)<=4 THEN repeat('*',length(decision.code))
      ELSE repeat('*',length(decision.code)-4)||right(decision.code,4) END,
    CASE WHEN customer."customerUserId" IS NULL THEN 'AUTHENTICATION_REQUIRED' ELSE 'INTAKE_REQUIRED' END,
    p_entry_method,CASE WHEN customer."customerUserId" IS NULL THEN 'PENDING' ELSE 'VERIFIED' END,
    p_checked_at,expires_at,p_checked_at+interval '30 minutes',brand_name;
END
$$;

CREATE OR REPLACE FUNCTION app_public.read_verification_session(
  p_session_id text,p_session_proof_hash text,p_customer_capability text,
  p_checked_at timestamp without time zone,p_request_id text
) RETURNS TABLE(
  "sessionId" text,"maskedCode" text,"customerFacingState" text,"startedAt" timestamp without time zone,
  "expiresAt" timestamp without time zone,"proofBindingExpiresAt" timestamp without time zone,
  "entryMethod" text,"authState" text,"intakeCompleted" boolean,"revealed" boolean,
  "brandName" text,"verification" jsonb
)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public
AS $$
DECLARE s record; d record;
  evidence record; brand_name text;
  customer record;
BEGIN
  SELECT NULL::text AS "customerUserId",NULL::text AS "customerEmail" INTO customer;
  IF p_customer_capability IS NOT NULL THEN
    SELECT * INTO customer FROM app_public.require_customer_auth_session(
      p_customer_capability,p_checked_at,p_request_id,'customer-verification-session-read'
    );
  END IF;
  PERFORM app_public.public_verify_bind(
    'public-verification-session-read',p_request_id,NULL,NULL,NULL,p_session_id,NULL
  );
  SELECT cs.id,cs."verificationDecisionId",cs.code,cs."entryMethod",cs."authState",cs."customerUserId",
    cs."intakeCompletedAt",cs."revealedAt",cs."expiresAt",cs."proofBindingTokenHash",
    cs."proofBindingExpiresAt",cs."createdAt"
  INTO s
  FROM public."CustomerVerificationSession" cs WHERE cs.id=p_session_id;
  IF s.id IS NULL OR s."expiresAt"<=p_checked_at OR s."proofBindingExpiresAt"<=p_checked_at
     OR s."proofBindingTokenHash" IS DISTINCT FROM p_session_proof_hash
     OR (s."customerUserId" IS NOT NULL AND s."customerUserId" IS DISTINCT FROM customer."customerUserId") THEN
    RAISE EXCEPTION 'PUBLIC_VERIFICATION_SESSION_INVALID' USING ERRCODE='42501';
  END IF;
  PERFORM set_config('app.public_verification_decision_id',s."verificationDecisionId",true);
  SELECT vd.id,vd."licenseeId" INTO STRICT d
  FROM public."VerificationDecision" vd WHERE vd.id=s."verificationDecisionId";
  SELECT e.id,e.metadata INTO evidence
  FROM public."VerificationEvidenceSnapshot" e
  WHERE e."verificationDecisionId"=d.id ORDER BY e."createdAt" DESC LIMIT 1;
  PERFORM set_config('app.public_verification_licensee_id',coalesce(d."licenseeId",''),true);
  SELECT coalesce(l."brandName",l.name) INTO brand_name FROM public."Licensee" l WHERE l.id=d."licenseeId";
  RETURN QUERY SELECT s.id,
    CASE WHEN s.code IS NULL THEN '' WHEN length(s.code)<=4 THEN repeat('*',length(s.code))
      ELSE repeat('*',length(s.code)-4)||right(s.code,4) END,
    CASE WHEN s."revealedAt" IS NOT NULL THEN 'REVEALED'
      WHEN s."intakeCompletedAt" IS NOT NULL THEN 'READY_TO_REVEAL'
      WHEN s."customerUserId" IS NOT NULL THEN 'INTAKE_REQUIRED'
      ELSE 'AUTHENTICATION_REQUIRED' END,
    s."createdAt",s."expiresAt",s."proofBindingExpiresAt",s."entryMethod"::text,s."authState"::text,
    s."intakeCompletedAt" IS NOT NULL,s."revealedAt" IS NOT NULL,brand_name,
    CASE WHEN s."revealedAt" IS NOT NULL THEN evidence.metadata->'presentationSnapshot' ELSE NULL END;
END
$$;

CREATE OR REPLACE FUNCTION app_public.write_verification_session(
  p_session_id text,p_session_proof_hash text,p_customer_capability text,
  p_operation text,p_payload jsonb,p_checked_at timestamp without time zone,p_request_id text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public
AS $$
DECLARE s record; intake_id text; customer record;
BEGIN
  IF p_operation NOT IN ('INTAKE','REVEAL') THEN
    RAISE EXCEPTION 'PUBLIC_VERIFICATION_SESSION_INVALID' USING ERRCODE='22023';
  END IF;
  SELECT * INTO customer FROM app_public.require_customer_auth_session(
    p_customer_capability,p_checked_at,p_request_id,'customer-verification-session-write'
  );
  PERFORM app_public.public_verify_bind(
    'public-verification-session-write',p_request_id,NULL,NULL,NULL,p_session_id,NULL
  );
  SELECT cs.id,cs."customerUserId",cs."expiresAt",cs."proofBindingTokenHash",cs."proofBindingExpiresAt"
  INTO s
  FROM public."CustomerVerificationSession" cs WHERE cs.id=p_session_id FOR UPDATE;
  IF s.id IS NULL OR s."expiresAt"<=p_checked_at OR s."proofBindingExpiresAt"<=p_checked_at
     OR s."proofBindingTokenHash"<>p_session_proof_hash
     OR (s."customerUserId" IS NOT NULL AND s."customerUserId"<>customer."customerUserId") THEN
    RAISE EXCEPTION 'PUBLIC_VERIFICATION_SESSION_INVALID' USING ERRCODE='42501';
  END IF;
  IF p_operation='INTAKE' THEN
    IF p_payload->>'purchaseChannel' NOT IN ('online','offline','gifted','unknown')
       OR p_payload->>'scanReason' NOT IN ('routine_check','new_seller','pricing_concern','packaging_concern','authenticity_concern')
       OR p_payload->>'ownershipIntent' NOT IN ('verify_only','claim_ownership','report_concern','contact_support')
       OR length(coalesce(p_payload->>'notes',''))>2000 THEN
      RAISE EXCEPTION 'PUBLIC_VERIFICATION_INTAKE_INVALID' USING ERRCODE='22023';
    END IF;
    SELECT i.id INTO intake_id FROM public."CustomerTrustIntake" i WHERE i."sessionId"=s.id;
    IF intake_id IS NULL THEN
      intake_id:=gen_random_uuid()::text;
      INSERT INTO public."CustomerTrustIntake"(
        id,"sessionId","customerUserId","customerEmail","purchaseChannel","sourceCategory",
        "platformName","sellerName","listingUrl","orderReference","storeName","purchaseCity",
        "purchaseCountry","purchaseDate","packagingState","packagingConcern","scanReason",
        "ownershipIntent",notes,answers,"createdAt","updatedAt"
      ) VALUES (
        intake_id,s.id,customer."customerUserId",customer."customerEmail",p_payload->>'purchaseChannel',
        nullif(p_payload->>'sourceCategory',''),nullif(p_payload->>'platformName',''),
        nullif(p_payload->>'sellerName',''),nullif(p_payload->>'listingUrl',''),
        nullif(p_payload->>'orderReference',''),nullif(p_payload->>'storeName',''),
        nullif(p_payload->>'purchaseCity',''),nullif(p_payload->>'purchaseCountry',''),
        CASE WHEN nullif(p_payload->>'purchaseDate','') IS NULL THEN NULL ELSE (p_payload->>'purchaseDate')::timestamp END,
        nullif(p_payload->>'packagingState',''),nullif(p_payload->>'packagingConcern',''),
        p_payload->>'scanReason',p_payload->>'ownershipIntent',nullif(p_payload->>'notes',''),
        p_payload,p_checked_at,p_checked_at
      );
    ELSE
      UPDATE public."CustomerTrustIntake" SET
        "customerUserId"=customer."customerUserId","customerEmail"=customer."customerEmail",
        "purchaseChannel"=p_payload->>'purchaseChannel',"sourceCategory"=nullif(p_payload->>'sourceCategory',''),
        "platformName"=nullif(p_payload->>'platformName',''),"sellerName"=nullif(p_payload->>'sellerName',''),
        "listingUrl"=nullif(p_payload->>'listingUrl',''),"orderReference"=nullif(p_payload->>'orderReference',''),
        "storeName"=nullif(p_payload->>'storeName',''),"purchaseCity"=nullif(p_payload->>'purchaseCity',''),
        "purchaseCountry"=nullif(p_payload->>'purchaseCountry',''),
        "purchaseDate"=CASE WHEN nullif(p_payload->>'purchaseDate','') IS NULL THEN NULL ELSE (p_payload->>'purchaseDate')::timestamp END,
        "packagingState"=nullif(p_payload->>'packagingState',''),
        "packagingConcern"=nullif(p_payload->>'packagingConcern',''),
        "scanReason"=p_payload->>'scanReason',"ownershipIntent"=p_payload->>'ownershipIntent',
        notes=nullif(p_payload->>'notes',''),answers=p_payload,"updatedAt"=p_checked_at
      WHERE id=intake_id;
    END IF;
    UPDATE public."CustomerVerificationSession" SET "authState"='VERIFIED',
      "customerUserId"=customer."customerUserId","customerEmail"=customer."customerEmail",
      "intakeCompletedAt"=coalesce("intakeCompletedAt",p_checked_at),"updatedAt"=p_checked_at
    WHERE id=s.id;
    RETURN jsonb_build_object('intakeSaved',true);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM public."CustomerTrustIntake" WHERE "sessionId"=s.id) THEN
    RAISE EXCEPTION 'PUBLIC_VERIFICATION_INTAKE_REQUIRED' USING ERRCODE='22023';
  END IF;
  UPDATE public."CustomerVerificationSession" SET "authState"='VERIFIED',
    "customerUserId"=customer."customerUserId","customerEmail"=customer."customerEmail",
    "revealedAt"=coalesce("revealedAt",p_checked_at),"updatedAt"=p_checked_at WHERE id=s.id;
  RETURN jsonb_build_object('revealed',true,'sessionId',s.id);
END
$$;

CREATE OR REPLACE FUNCTION app_public.public_verify_write_evidence(
  p_action text,p_entity_type text,p_entity_id text,p_licensee_id text,
  p_details jsonb,p_recorded_at timestamp without time zone,p_request_id text
) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public
AS $$
DECLARE audit_id text:=gen_random_uuid()::text; outbox_id text:=gen_random_uuid()::text;
  safe_details jsonb:=coalesce(p_details,'{}'::jsonb);
BEGIN
  IF p_action !~ '^VERIFY_[A-Z0-9_]{1,96}$' OR p_entity_type !~ '^[A-Za-z][A-Za-z0-9]{1,63}$'
     OR p_entity_id IS NULL OR p_recorded_at IS NULL THEN
    RAISE EXCEPTION 'PUBLIC_VERIFICATION_EVIDENCE_INVALID' USING ERRCODE='22023';
  END IF;
  PERFORM set_config('app.public_verification_audit_id',audit_id,true);
  PERFORM set_config('app.public_verification_outbox_id',outbox_id,true);
  INSERT INTO public."AuditLog"(
    id,"userId","orgId","licenseeId",action,"entityType","entityId",details,
    "ipAddress","ipHash","userAgent","createdAt"
  ) VALUES (
    audit_id,NULL,NULL,p_licensee_id,p_action,p_entity_type,p_entity_id,
    safe_details||jsonb_build_object('requestId',p_request_id),NULL,NULL,NULL,p_recorded_at
  );
  INSERT INTO public."SecurityEventOutbox"(
    id,"eventType",payload,"jobType","requestId","payloadDigest","idempotencyKey",
    "organizationId","licenseeId","manufacturerId","initiatingUserId","expiresAt",
    "claimedAt","claimLeaseExpiresAt","sinkEventId",status,attempts,"nextAttemptAt",
    "lastError","sentAt","createdAt","updatedAt"
  ) VALUES (
    outbox_id,p_action,safe_details,NULL,p_request_id,
    encode(sha256(convert_to(safe_details::text,'UTF8')),'hex'),
    encode(sha256(convert_to(p_action||':'||p_entity_id,'UTF8')),'hex'),
    NULL,p_licensee_id,NULL,NULL,p_recorded_at+interval '7 days',
    NULL,NULL,NULL,'QUEUED',0,p_recorded_at,NULL,NULL,p_recorded_at,p_recorded_at
  );
END
$$;

CREATE OR REPLACE FUNCTION app_public.claim_customer_ownership(
  p_customer_capability text,p_session_id text,p_session_proof_hash text,
  p_device_token_hash text,p_ip_hash text,p_user_agent_hash text,p_link_only boolean,
  p_checked_at timestamp without time zone,p_request_id text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public
AS $$
DECLARE customer record; session_row record;
  qr record; batch_state text; ownership record; claim_available boolean;
  ownership_id text:=gen_random_uuid()::text; action text; result text;
BEGIN
  SELECT NULL::text AS "customerUserId",NULL::text AS "customerEmail" INTO customer;
  IF p_customer_capability IS NOT NULL THEN
    SELECT * INTO customer FROM app_public.require_customer_auth_session(
      p_customer_capability,p_checked_at,p_request_id,'customer-ownership'
    );
  END IF;
  IF p_link_only AND customer."customerUserId" IS NULL THEN
    RAISE EXCEPTION 'PUBLIC_CUSTOMER_SESSION_DENIED' USING ERRCODE='42501';
  END IF;
  IF p_session_id !~ '^[0-9a-fA-F-]{36}$'
     OR p_session_proof_hash !~ '^(?:[A-Za-z0-9._-]{1,32}:)?[a-f0-9]{64}$'
     OR (customer."customerUserId" IS NULL AND p_device_token_hash IS NULL)
     OR (p_device_token_hash IS NOT NULL AND p_device_token_hash !~ '^(?:[A-Za-z0-9._-]{1,32}:)?[a-f0-9]{64}$') THEN
    RAISE EXCEPTION 'PUBLIC_OWNERSHIP_INVALID' USING ERRCODE='22023';
  END IF;
  PERFORM app_public.public_verify_bind(
    'public-verification-ownership-claim',p_request_id,NULL,NULL,NULL,p_session_id,NULL
  );
  SELECT s.id,s."customerUserId",s."qrCodeId",s."verificationDecisionId"
  INTO session_row FROM public."CustomerVerificationSession" s
  WHERE s.id=p_session_id AND s."proofBindingTokenHash"=p_session_proof_hash
    AND s."proofBindingExpiresAt">p_checked_at AND s."expiresAt">p_checked_at;
  IF session_row.id IS NULL OR
     (session_row."customerUserId" IS NOT NULL
       AND session_row."customerUserId" IS DISTINCT FROM customer."customerUserId") THEN
    RAISE EXCEPTION 'PUBLIC_OWNERSHIP_SESSION_DENIED' USING ERRCODE='42501';
  END IF;
  PERFORM set_config('app.public_verification_decision_id',session_row."verificationDecisionId",true);
  SELECT coalesce((e.metadata#>>'{presentationSnapshot,ownershipClaimAvailable}')::boolean,false)
  INTO claim_available
  FROM public."VerificationEvidenceSnapshot" e
  WHERE e."verificationDecisionId"=session_row."verificationDecisionId"
  ORDER BY e."createdAt" DESC,e.id DESC LIMIT 1;
  IF NOT coalesce(claim_available,false) THEN
    RAISE EXCEPTION 'PUBLIC_OWNERSHIP_NOT_READY' USING ERRCODE='55000';
  END IF;
  PERFORM set_config('app.public_verification_qr_id',session_row."qrCodeId",true);
  SELECT q.id,q.code,q."licenseeId",q."batchId",q.status,q."issuanceMode",q."customerVerifiableAt"
  INTO qr
  FROM public."QRCode" q WHERE q.id=session_row."qrCodeId";
  IF qr.id IS NULL THEN RAISE EXCEPTION 'PUBLIC_OWNERSHIP_TARGET_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM set_config('app.public_verification_licensee_id',qr."licenseeId",true);
  IF qr."batchId" IS NOT NULL THEN
    PERFORM set_config('app.public_verification_batch_id',qr."batchId",true);
    SELECT b."lifecycleState"::text INTO batch_state FROM public."Batch" b WHERE b.id=qr."batchId";
  END IF;
  IF qr.status NOT IN ('PRINTED','SCANNED','REDEEMED')
     OR coalesce(batch_state,'RELEASED')<>'RELEASED'
     OR (qr."issuanceMode"='GOVERNED_PRINT' AND qr."customerVerifiableAt" IS NULL) THEN
    RAISE EXCEPTION 'PUBLIC_OWNERSHIP_NOT_READY' USING ERRCODE='55000';
  END IF;
  SELECT o.id,o."userId",o."deviceTokenHash",o."claimedAt" INTO ownership
    FROM public."Ownership" o WHERE o."qrCodeId"=qr.id FOR UPDATE;
  IF ownership.id IS NULL THEN
    IF p_link_only THEN RAISE EXCEPTION 'PUBLIC_OWNERSHIP_NOT_FOUND' USING ERRCODE='42501'; END IF;
    PERFORM set_config('app.public_verification_target_id',ownership_id,true);
    INSERT INTO public."Ownership"(
      id,"qrCodeId","userId","deviceTokenHash","ipHash","userAgentHash","claimSource","linkedAt","claimedAt"
    ) VALUES (
      ownership_id,qr.id,customer."customerUserId",p_device_token_hash,p_ip_hash,p_user_agent_hash,
      CASE WHEN customer."customerUserId" IS NULL THEN 'DEVICE' ELSE 'USER' END,
      CASE WHEN customer."customerUserId" IS NULL THEN NULL ELSE p_checked_at END,p_checked_at
    ) RETURNING id,"userId","deviceTokenHash","claimedAt" INTO ownership;
    result:=CASE WHEN customer."customerUserId" IS NULL THEN 'CLAIMED_DEVICE' ELSE 'CLAIMED_USER' END;
    action:='VERIFY_CLAIM_SUCCESS';
  ELSIF ownership."userId"=customer."customerUserId"
     OR (ownership."userId" IS NULL AND ownership."deviceTokenHash"=p_device_token_hash) THEN
    PERFORM set_config('app.public_verification_target_id',ownership.id,true);
    IF customer."customerUserId" IS NOT NULL AND ownership."userId" IS NULL THEN
      UPDATE public."Ownership" SET "userId"=customer."customerUserId","linkedAt"=p_checked_at,
        "claimSource"='DEVICE_AND_USER' WHERE id=ownership.id
      RETURNING id,"userId","deviceTokenHash","claimedAt" INTO ownership;
      result:='LINKED_TO_SIGNED_IN_ACCOUNT'; action:='VERIFY_CLAIM_LINKED_TO_USER';
    ELSE
      result:='ALREADY_OWNED_BY_YOU'; action:='VERIFY_CLAIM_IDEMPOTENT';
    END IF;
  ELSE
    result:='OWNED_BY_ANOTHER_USER'; action:='VERIFY_CLAIM_CONFLICT';
  END IF;
  PERFORM app_public.public_verify_write_evidence(
    action,'Ownership',qr.id,qr."licenseeId",
    jsonb_build_object('claimResult',result,'customerBound',customer."customerUserId" IS NOT NULL),
    p_checked_at,p_request_id
  );
  RETURN jsonb_build_object(
    'claimResult',result,'message',CASE
      WHEN result='OWNED_BY_ANOTHER_USER' THEN 'Ownership is already claimed by another account or device.'
      WHEN result='ALREADY_OWNED_BY_YOU' THEN 'This product is already owned by you on this device/account.'
      WHEN result='LINKED_TO_SIGNED_IN_ACCOUNT' THEN 'Device claim linked to your signed-in account.'
      ELSE 'Product ownership claimed.' END,
    'conflict',result='OWNED_BY_ANOTHER_USER','claimTimestamp',ownership."claimedAt",
    'ownershipStatus',jsonb_build_object(
      'isClaimed',true,'claimedAt',ownership."claimedAt",
      'isOwnedByRequester',result<>'OWNED_BY_ANOTHER_USER',
      'isClaimedByAnother',result='OWNED_BY_ANOTHER_USER','canClaim',false
    )
  );
END
$$;

CREATE OR REPLACE FUNCTION app_public.create_customer_ownership_transfer(
  p_customer_capability text,p_requested_code text,p_recipient_email text,p_token_hash text,
  p_expires_at timestamp without time zone,p_checked_at timestamp without time zone,p_request_id text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public
AS $$
DECLARE customer record; qr record; ownership record;
  transfer_id text:=gen_random_uuid()::text;
BEGIN
  SELECT * INTO customer FROM app_public.require_customer_auth_session(
    p_customer_capability,p_checked_at,p_request_id,'customer-ownership'
  );
  IF p_token_hash !~ '^(?:[A-Za-z0-9._-]{1,32}:)?[a-f0-9]{64}$'
     OR p_expires_at<=p_checked_at OR p_expires_at>p_checked_at+interval '8 days'
     OR (p_recipient_email IS NOT NULL AND length(p_recipient_email)>160) THEN
    RAISE EXCEPTION 'PUBLIC_OWNERSHIP_TRANSFER_INVALID' USING ERRCODE='22023';
  END IF;
  PERFORM app_public.public_verify_bind(
    'public-verification-ownership-transfer-create',p_request_id,NULL,p_requested_code,NULL,NULL,NULL
  );
  SELECT q.id,q.code,q."licenseeId" INTO qr
  FROM public."QRCode" q WHERE q.code=p_requested_code;
  IF qr.id IS NULL THEN RAISE EXCEPTION 'PUBLIC_OWNERSHIP_TARGET_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM set_config('app.public_verification_qr_id',qr.id,true);
  PERFORM set_config('app.public_verification_licensee_id',qr."licenseeId",true);
  SELECT o.id INTO ownership FROM public."Ownership" o
  WHERE o."qrCodeId"=qr.id AND o."userId"=customer."customerUserId" FOR UPDATE;
  IF ownership.id IS NULL THEN RAISE EXCEPTION 'PUBLIC_OWNERSHIP_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM set_config('app.public_verification_target_id',ownership.id,true);
  UPDATE public."OwnershipTransfer" SET status='CANCELLED',"cancelledAt"=p_checked_at,"updatedAt"=p_checked_at
  WHERE "qrCodeId"=qr.id AND "initiatedByCustomerId"=customer."customerUserId" AND status='PENDING';
  PERFORM set_config('app.public_verification_support_id',transfer_id,true);
  PERFORM set_config('app.public_verification_transfer_token_hash',p_token_hash,true);
  INSERT INTO public."OwnershipTransfer"(
    id,"qrCodeId","ownershipId","initiatedByCustomerId","initiatedByEmail","recipientEmail",
    "tokenHash",status,"expiresAt","acceptedAt","cancelledAt","lastViewedAt",metadata,"createdAt","updatedAt"
  ) VALUES (
    transfer_id,qr.id,ownership.id,customer."customerUserId",customer."customerEmail",
    CASE WHEN p_recipient_email IS NULL THEN NULL ELSE lower(p_recipient_email) END,
    p_token_hash,'PENDING',p_expires_at,NULL,NULL,NULL,
    jsonb_build_object('source','public_verification'),p_checked_at,p_checked_at
  );
  PERFORM app_public.public_verify_write_evidence(
    'VERIFY_OWNERSHIP_TRANSFER_CREATED','OwnershipTransfer',transfer_id,qr."licenseeId",
    jsonb_build_object('qrCodeId',qr.id,'recipientBound',p_recipient_email IS NOT NULL),
    p_checked_at,p_request_id
  );
  RETURN jsonb_build_object(
    'transferId',transfer_id,'status','PENDING','expiresAt',p_expires_at,
    'notificationEmails',jsonb_build_array(customer."customerEmail",lower(p_recipient_email))
  );
END
$$;

CREATE OR REPLACE FUNCTION app_public.cancel_customer_ownership_transfer(
  p_customer_capability text,p_requested_code text,p_transfer_id text,
  p_checked_at timestamp without time zone,p_request_id text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public
AS $$
DECLARE customer record; qr record; changed integer;
  transfer record;
BEGIN
  SELECT * INTO customer FROM app_public.require_customer_auth_session(
    p_customer_capability,p_checked_at,p_request_id,'customer-ownership'
  );
  PERFORM app_public.public_verify_bind(
    'public-verification-ownership-transfer-cancel',p_request_id,NULL,p_requested_code,NULL,NULL,NULL
  );
  SELECT q.id,q.code,q."licenseeId" INTO qr
  FROM public."QRCode" q WHERE q.code=p_requested_code;
  IF qr.id IS NULL THEN RAISE EXCEPTION 'PUBLIC_OWNERSHIP_TARGET_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM set_config('app.public_verification_qr_id',qr.id,true);
  PERFORM set_config('app.public_verification_licensee_id',qr."licenseeId",true);
  SELECT t.id,t."initiatedByEmail",t."recipientEmail" INTO transfer FROM public."OwnershipTransfer" t
  WHERE t."qrCodeId"=qr.id AND t."initiatedByCustomerId"=customer."customerUserId"
    AND t.status='PENDING' AND (p_transfer_id IS NULL OR t.id=p_transfer_id)
  ORDER BY t."createdAt" DESC,t.id DESC LIMIT 1 FOR UPDATE;
  IF transfer.id IS NULL THEN RAISE EXCEPTION 'PUBLIC_OWNERSHIP_TRANSFER_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM set_config('app.public_verification_support_id',transfer.id,true);
  UPDATE public."OwnershipTransfer" SET status='CANCELLED',"cancelledAt"=p_checked_at,"updatedAt"=p_checked_at
  WHERE id=transfer.id AND "qrCodeId"=qr.id AND "initiatedByCustomerId"=customer."customerUserId"
    AND status='PENDING';
  GET DIAGNOSTICS changed=ROW_COUNT;
  IF changed<>1 THEN RAISE EXCEPTION 'PUBLIC_OWNERSHIP_TRANSFER_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM app_public.public_verify_write_evidence(
    'VERIFY_OWNERSHIP_TRANSFER_CANCELLED','OwnershipTransfer',transfer.id,qr."licenseeId",
    jsonb_build_object('qrCodeId',qr.id),p_checked_at,p_request_id
  );
  RETURN jsonb_build_object(
    'transferId',transfer.id,'status','CANCELLED',
    'notificationEmails',jsonb_build_array(transfer."initiatedByEmail",transfer."recipientEmail")
  );
END
$$;

CREATE OR REPLACE FUNCTION app_public.accept_customer_ownership_transfer(
  p_customer_capability text,p_token_hash text,p_ip_hash text,p_user_agent_hash text,
  p_checked_at timestamp without time zone,p_request_id text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public
AS $$
DECLARE customer record; transfer record; qr record;
  ownership record;
BEGIN
  SELECT * INTO customer FROM app_public.require_customer_auth_session(
    p_customer_capability,p_checked_at,p_request_id,'customer-ownership'
  );
  IF p_token_hash !~ '^(?:[A-Za-z0-9._-]{1,32}:)?[a-f0-9]{64}$' THEN
    RAISE EXCEPTION 'PUBLIC_OWNERSHIP_TRANSFER_INVALID' USING ERRCODE='22023';
  END IF;
  PERFORM app_public.public_verify_bind(
    'public-verification-ownership-transfer-accept',p_request_id,NULL,NULL,NULL,NULL,NULL
  );
  PERFORM set_config('app.public_verification_transfer_token_hash',p_token_hash,true);
  SELECT t.id,t.status,t."expiresAt",t."initiatedByCustomerId",t."recipientEmail",
    t."qrCodeId",t."ownershipId",t."initiatedByEmail" INTO transfer FROM public."OwnershipTransfer" t
  WHERE t."tokenHash"=p_token_hash FOR UPDATE;
  IF transfer.id IS NULL OR transfer.status<>'PENDING' OR transfer."expiresAt"<=p_checked_at
     OR transfer."initiatedByCustomerId"=customer."customerUserId"
     OR (transfer."recipientEmail" IS NOT NULL
       AND lower(transfer."recipientEmail")<>lower(customer."customerEmail")) THEN
    RAISE EXCEPTION 'PUBLIC_OWNERSHIP_TRANSFER_DENIED' USING ERRCODE='42501';
  END IF;
  PERFORM set_config('app.public_verification_qr_id',transfer."qrCodeId",true);
  PERFORM set_config('app.public_verification_support_id',transfer.id,true);
  SELECT q.id,q.code,q."licenseeId" INTO STRICT qr
  FROM public."QRCode" q WHERE q.id=transfer."qrCodeId";
  PERFORM set_config('app.public_verification_licensee_id',qr."licenseeId",true);
  PERFORM set_config('app.public_verification_target_id',transfer."ownershipId",true);
  SELECT o.id INTO STRICT ownership FROM public."Ownership" o
  WHERE o.id=transfer."ownershipId" AND o."qrCodeId"=qr.id FOR UPDATE;
  UPDATE public."OwnershipTransfer" SET status='ACCEPTED',"acceptedAt"=p_checked_at,
    "lastViewedAt"=p_checked_at,"updatedAt"=p_checked_at WHERE id=transfer.id;
  UPDATE public."Ownership" SET "userId"=customer."customerUserId","linkedAt"=p_checked_at,
    "claimedAt"=p_checked_at,"ipHash"=p_ip_hash,"userAgentHash"=p_user_agent_hash,
    "claimSource"='USER_TRANSFERRED' WHERE id=ownership.id;
  UPDATE public."OwnershipTransfer" SET status='CANCELLED',"cancelledAt"=p_checked_at,"updatedAt"=p_checked_at
  WHERE "qrCodeId"=qr.id AND status='PENDING' AND id<>transfer.id;
  PERFORM app_public.public_verify_write_evidence(
    'VERIFY_OWNERSHIP_TRANSFER_ACCEPTED','OwnershipTransfer',transfer.id,qr."licenseeId",
    jsonb_build_object('qrCodeId',qr.id),p_checked_at,p_request_id
  );
  RETURN jsonb_build_object('transferId',transfer.id,'status','ACCEPTED','code',qr.code,
    'notificationEmails',jsonb_build_array(transfer."initiatedByEmail",customer."customerEmail",transfer."recipientEmail"),
    'ownershipStatus',jsonb_build_object('isClaimed',true,'claimedAt',p_checked_at,
      'isOwnedByRequester',true,'isClaimedByAnother',false,'canClaim',false));
END
$$;

CREATE OR REPLACE FUNCTION app_public.begin_customer_passkey(
  p_customer_capability text,p_customer_user_id text,p_customer_email text,p_purpose text,
  p_ticket_hash text,p_challenge_hash text,p_ip_hash text,p_user_agent_hash text,
  p_origin text,p_rp_id text,p_expires_at timestamp without time zone,
  p_checked_at timestamp without time zone,p_request_id text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public
AS $$
DECLARE customer record; challenge_id text:=gen_random_uuid()::text; credentials jsonb;
BEGIN
  SELECT NULL::text AS "customerUserId",NULL::text AS "customerEmail" INTO customer;
  IF p_purpose NOT IN ('ENROLLMENT','LOGIN','STEP_UP')
     OR p_customer_user_id !~ '^cust_[a-f0-9]{32}$'
     OR p_customer_email !~ '^[^[:space:]@]+@[^[:space:]@]+[.][^[:space:]@]+$'
     OR p_ticket_hash !~ '^(?:[A-Za-z0-9._-]{1,32}:)?[a-f0-9]{64}$'
     OR p_challenge_hash !~ '^(?:[A-Za-z0-9._-]{1,32}:)?[a-f0-9]{64}$'
     OR p_expires_at<=p_checked_at OR p_expires_at>p_checked_at+interval '15 minutes'
     OR length(coalesce(p_origin,''))>512 OR length(coalesce(p_rp_id,''))>253 THEN
    RAISE EXCEPTION 'PUBLIC_PASSKEY_INVALID' USING ERRCODE='22023';
  END IF;
  IF p_purpose<>'LOGIN' THEN
    SELECT * INTO customer FROM app_public.require_customer_auth_session(
      p_customer_capability,p_checked_at,p_request_id,'customer-passkey'
    );
    IF customer."customerUserId"<>p_customer_user_id
       OR lower(customer."customerEmail")<>lower(p_customer_email) THEN
      RAISE EXCEPTION 'PUBLIC_PASSKEY_DENIED' USING ERRCODE='42501';
    END IF;
  ELSE
    PERFORM app_public.public_verify_bind('public-verification-customer-passkey',p_request_id);
  END IF;
  PERFORM set_config('app.public_verification_customer_user_id',p_customer_user_id,true);
  SELECT coalesce(jsonb_agg(jsonb_build_object(
    'credentialId',c."credentialId",'transports',to_jsonb(c.transports)
  ) ORDER BY c."createdAt",c.id),'[]'::jsonb)
  INTO credentials
  FROM public."CustomerWebAuthnCredential" c
  WHERE c."customerUserId"=p_customer_user_id;
  IF p_purpose IN ('LOGIN','STEP_UP') AND jsonb_array_length(credentials)=0 THEN
    RAISE EXCEPTION 'WEBAUTHN_NOT_ENROLLED' USING ERRCODE='02000';
  END IF;
  PERFORM set_config('app.public_verification_target_id',challenge_id,true);
  INSERT INTO public."CustomerWebAuthnChallenge"(
    id,"customerUserId","customerEmail",purpose,"ticketHash","challengeHash","credentialIds",
    "createdIpHash","createdUserAgentHash",origin,"rpId","createdAt","expiresAt","consumedAt"
  ) VALUES (
    challenge_id,p_customer_user_id,lower(p_customer_email),p_purpose,p_ticket_hash,p_challenge_hash,
    ARRAY(SELECT value->>'credentialId' FROM jsonb_array_elements(credentials)),
    p_ip_hash,p_user_agent_hash,p_origin,p_rp_id,p_checked_at,p_expires_at,NULL
  );
  RETURN jsonb_build_object('challengeId',challenge_id,'credentials',credentials);
END
$$;

CREATE OR REPLACE FUNCTION app_public.load_customer_passkey(
  p_ticket_hashes text[],p_purpose text,p_credential_id text,
  p_checked_at timestamp without time zone,p_request_id text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public
AS $$
DECLARE challenge record;
  credential record;
BEGIN
  IF coalesce(array_length(p_ticket_hashes,1),0)<1 OR array_length(p_ticket_hashes,1)>4
     OR EXISTS (SELECT 1 FROM unnest(p_ticket_hashes) h
       WHERE h !~ '^(?:[A-Za-z0-9._-]{1,32}:)?[a-f0-9]{64}$')
     OR (p_purpose IS NOT NULL AND p_purpose NOT IN ('ENROLLMENT','LOGIN','STEP_UP')) THEN
    RAISE EXCEPTION 'PUBLIC_PASSKEY_INVALID' USING ERRCODE='22023';
  END IF;
  PERFORM app_public.public_verify_bind('public-verification-customer-passkey',p_request_id);
  PERFORM set_config('app.public_verification_passkey_ticket_hashes',array_to_string(p_ticket_hashes,','),true);
  SELECT c.id,c."customerUserId",c."customerEmail",c.purpose,c."challengeHash",
    c."credentialIds",c."expiresAt",c.origin,c."rpId" INTO challenge
    FROM public."CustomerWebAuthnChallenge" c
  WHERE c."ticketHash"=ANY(p_ticket_hashes)
    AND (p_purpose IS NULL OR c.purpose=p_purpose)
    AND c."consumedAt" IS NULL AND c."expiresAt">p_checked_at
  ORDER BY c."createdAt" DESC LIMIT 1;
  IF challenge.id IS NULL THEN RAISE EXCEPTION 'WEBAUTHN_CHALLENGE_NOT_FOUND' USING ERRCODE='02000'; END IF;
  PERFORM set_config('app.public_verification_target_id',challenge.id,true);
  IF p_credential_id IS NOT NULL THEN
    PERFORM set_config('app.public_verification_support_id',p_credential_id,true);
    SELECT c.id,c."customerUserId",c."customerEmail",c."credentialId",c."publicKeySpki",c.counter
      INTO credential FROM public."CustomerWebAuthnCredential" c
    WHERE c."customerUserId"=challenge."customerUserId" AND c."credentialId"=p_credential_id;
    IF credential.id IS NULL OR NOT p_credential_id=ANY(challenge."credentialIds") THEN
      RAISE EXCEPTION 'WEBAUTHN_CREDENTIAL_NOT_FOUND' USING ERRCODE='02000';
    END IF;
  END IF;
  RETURN jsonb_build_object(
    'id',challenge.id,'customerUserId',challenge."customerUserId",
    'customerEmail',challenge."customerEmail",'purpose',challenge.purpose,
    'challengeHash',challenge."challengeHash",'expiresAt',challenge."expiresAt",
    'credentialIds',to_jsonb(challenge."credentialIds"),'origin',challenge.origin,'rpId',challenge."rpId",
    'credential',CASE WHEN credential.id IS NULL THEN NULL ELSE jsonb_build_object(
      'id',credential.id,'customerUserId',credential."customerUserId",
      'customerEmail',credential."customerEmail",'credentialId',credential."credentialId",
      'publicKeySpki',credential."publicKeySpki",'counter',credential.counter
    ) END
  );
END
$$;

CREATE OR REPLACE FUNCTION app_public.finish_customer_passkey(
  p_customer_capability text,p_ticket_hashes text[],p_purpose text,p_payload jsonb,
  p_checked_at timestamp without time zone,p_request_id text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public
AS $$
DECLARE challenge record;
  credential record; customer record;
  credential_id text:=p_payload->>'credentialId'; next_counter integer;
BEGIN
  IF p_purpose NOT IN ('ENROLLMENT','LOGIN','STEP_UP')
     OR coalesce(array_length(p_ticket_hashes,1),0)<1 OR array_length(p_ticket_hashes,1)>4
     OR EXISTS (SELECT 1 FROM unnest(p_ticket_hashes) h
       WHERE h !~ '^(?:[A-Za-z0-9._-]{1,32}:)?[a-f0-9]{64}$')
     OR credential_id IS NULL OR length(credential_id)>1024 THEN
    RAISE EXCEPTION 'PUBLIC_PASSKEY_INVALID' USING ERRCODE='22023';
  END IF;
  IF p_customer_capability IS NOT NULL THEN
    SELECT * INTO customer FROM app_public.require_customer_auth_session(
      p_customer_capability,p_checked_at,p_request_id,'customer-passkey'
    );
  ELSE
    PERFORM app_public.public_verify_bind('public-verification-customer-passkey',p_request_id);
  END IF;
  PERFORM set_config('app.public_verification_passkey_ticket_hashes',array_to_string(p_ticket_hashes,','),true);
  SELECT c.id,c."customerUserId",c."customerEmail",c.purpose,c."credentialIds",c."expiresAt"
    INTO challenge FROM public."CustomerWebAuthnChallenge" c
  WHERE c."ticketHash"=ANY(p_ticket_hashes) AND c.purpose=p_purpose
    AND c."consumedAt" IS NULL AND c."expiresAt">p_checked_at
  ORDER BY c."createdAt" DESC LIMIT 1;
  IF challenge.id IS NULL THEN RAISE EXCEPTION 'WEBAUTHN_CHALLENGE_NOT_FOUND' USING ERRCODE='02000'; END IF;
  PERFORM set_config('app.public_verification_target_id',challenge.id,true);
  UPDATE public."CustomerWebAuthnChallenge"
  SET "consumedAt"=p_checked_at
  WHERE id=challenge.id AND "consumedAt" IS NULL AND "expiresAt">p_checked_at
  RETURNING id,"customerUserId","customerEmail",purpose,"credentialIds","expiresAt" INTO challenge;
  IF challenge.id IS NULL THEN RAISE EXCEPTION 'WEBAUTHN_CHALLENGE_NOT_FOUND' USING ERRCODE='02000'; END IF;
  PERFORM set_config('app.public_verification_customer_user_id',challenge."customerUserId",true);
  IF p_purpose IN ('ENROLLMENT','STEP_UP')
     AND (customer."customerUserId" IS NULL OR customer."customerUserId"<>challenge."customerUserId") THEN
    RAISE EXCEPTION 'PUBLIC_PASSKEY_DENIED' USING ERRCODE='42501';
  END IF;
  IF p_purpose='ENROLLMENT' THEN
    IF length(coalesce(p_payload->>'publicKeySpki',''))<16
       OR coalesce(jsonb_array_length(p_payload->'transports'),0)>16
       OR length(coalesce(p_payload->>'label',''))>120 THEN
      RAISE EXCEPTION 'PUBLIC_PASSKEY_INVALID' USING ERRCODE='22023';
    END IF;
    PERFORM set_config('app.public_verification_support_id',credential_id,true);
    SELECT c.id,c."customerUserId",c."credentialId",c.counter INTO credential
      FROM public."CustomerWebAuthnCredential" c
    WHERE c."credentialId"=credential_id;
    IF credential.id IS NOT NULL AND credential."customerUserId"<>challenge."customerUserId" THEN
      RAISE EXCEPTION 'PUBLIC_PASSKEY_DENIED' USING ERRCODE='42501';
    END IF;
    IF credential.id IS NULL THEN
      PERFORM set_config('app.public_verification_support_id',gen_random_uuid()::text,true);
      INSERT INTO public."CustomerWebAuthnCredential"(
        id,"customerUserId","customerEmail",label,"credentialId","publicKeySpki",
        "publicKeyAlgorithm",counter,transports,"lastUsedAt","createdAt","updatedAt"
      ) VALUES (
        current_setting('app.public_verification_support_id'),challenge."customerUserId",
        challenge."customerEmail",coalesce(nullif(p_payload->>'label',''),'Passkey'),credential_id,
        p_payload->>'publicKeySpki',(p_payload->>'publicKeyAlgorithm')::integer,
        (p_payload->>'counter')::integer,
        ARRAY(SELECT jsonb_array_elements_text(coalesce(p_payload->'transports','[]'::jsonb))),
        p_checked_at,p_checked_at,p_checked_at
      ) RETURNING id,"customerUserId","credentialId",counter INTO credential;
    ELSE
      PERFORM set_config('app.public_verification_support_id',credential.id,true);
      UPDATE public."CustomerWebAuthnCredential" SET
        label=coalesce(nullif(p_payload->>'label',''),'Passkey'),
        "publicKeySpki"=p_payload->>'publicKeySpki',
        "publicKeyAlgorithm"=(p_payload->>'publicKeyAlgorithm')::integer,
        counter=(p_payload->>'counter')::integer,
        transports=ARRAY(SELECT jsonb_array_elements_text(coalesce(p_payload->'transports','[]'::jsonb))),
        "lastUsedAt"=p_checked_at,"updatedAt"=p_checked_at
      WHERE id=credential.id RETURNING id,"customerUserId","credentialId",counter INTO credential;
    END IF;
  ELSE
    PERFORM set_config('app.public_verification_support_id',credential_id,true);
    SELECT c.id,c."customerUserId",c."credentialId",c.counter INTO credential
      FROM public."CustomerWebAuthnCredential" c
    WHERE c."customerUserId"=challenge."customerUserId" AND c."credentialId"=credential_id;
    IF credential.id IS NULL OR NOT credential_id=ANY(challenge."credentialIds") THEN
      RAISE EXCEPTION 'WEBAUTHN_CREDENTIAL_NOT_FOUND' USING ERRCODE='02000';
    END IF;
    PERFORM set_config('app.public_verification_support_id',credential.id,true);
    SELECT c.id,c."customerUserId",c."credentialId",c.counter INTO credential
      FROM public."CustomerWebAuthnCredential" c
    WHERE c.id=credential.id FOR UPDATE;
    next_counter:=(p_payload->>'nextCounter')::integer;
    IF next_counter<credential.counter OR (next_counter>0 AND credential.counter>0 AND next_counter<=credential.counter) THEN
      RAISE EXCEPTION 'WEBAUTHN_COUNTER_REPLAY' USING ERRCODE='55000';
    END IF;
    UPDATE public."CustomerWebAuthnCredential"
    SET counter=greatest(counter,next_counter),"lastUsedAt"=p_checked_at,"updatedAt"=p_checked_at
    WHERE id=credential.id;
  END IF;
  RETURN jsonb_build_object(
    'credentialId',credential."credentialId",'customerUserId',challenge."customerUserId",
    'customerEmail',challenge."customerEmail",'purpose',challenge.purpose,'assertedAt',p_checked_at
  );
END
$$;

CREATE OR REPLACE FUNCTION app_public.list_customer_passkeys(
  p_customer_capability text,p_checked_at timestamp without time zone,p_request_id text
) RETURNS TABLE(payload jsonb)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public
AS $$
DECLARE customer record;
BEGIN
  SELECT * INTO customer FROM app_public.require_customer_auth_session(
    p_customer_capability,p_checked_at,p_request_id,'customer-passkey'
  );
  PERFORM set_config('app.public_verification_customer_user_id',customer."customerUserId",true);
  RETURN QUERY SELECT jsonb_build_object(
    'id',c.id,'label',coalesce(c.label,'Passkey'),'credentialId',c."credentialId",
    'transports',to_jsonb(c.transports),'lastUsedAt',c."lastUsedAt",
    'createdAt',c."createdAt",'updatedAt',c."updatedAt"
  ) FROM public."CustomerWebAuthnCredential" c
  WHERE c."customerUserId"=customer."customerUserId"
  ORDER BY c."lastUsedAt" DESC NULLS LAST,c."createdAt" DESC,c.id DESC LIMIT 20;
END
$$;

CREATE OR REPLACE FUNCTION app_public.delete_customer_passkey(
  p_customer_capability text,p_credential_row_id text,
  p_checked_at timestamp without time zone,p_request_id text
) RETURNS TABLE(deleted boolean)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public
AS $$
DECLARE customer record; changed integer;
BEGIN
  SELECT * INTO customer FROM app_public.require_customer_auth_session(
    p_customer_capability,p_checked_at,p_request_id,'customer-passkey'
  );
  PERFORM set_config('app.public_verification_customer_user_id',customer."customerUserId",true);
  PERFORM set_config('app.public_verification_support_id',p_credential_row_id,true);
  DELETE FROM public."CustomerWebAuthnCredential"
  WHERE id=p_credential_row_id AND "customerUserId"=customer."customerUserId";
  GET DIAGNOSTICS changed=ROW_COUNT;
  RETURN QUERY SELECT changed=1;
END
$$;

CREATE OR REPLACE FUNCTION app_public.submit_product_feedback(
  p_requested_code text,p_rating integer,p_satisfaction text,p_notes text,p_observed_status text,
  p_observed_outcome text,p_page_url text,p_submitted_at timestamp without time zone,
  p_request_id text,p_actor_ip_hash text,p_idempotency_digest text
) RETURNS TABLE("accepted" boolean,"publicReference" text,"message" text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public
AS $$
DECLARE qr record; key_row record;
  reference text:='FB-'||upper(substr(replace(gen_random_uuid()::text,'-',''),1,12)); audit_id text;
BEGIN
  IF p_rating<1 OR p_rating>5 OR p_satisfaction NOT IN
    ('very_satisfied','satisfied','neutral','disappointed','very_disappointed')
    OR length(coalesce(p_notes,''))>1000 THEN
    RAISE EXCEPTION 'PUBLIC_FEEDBACK_INVALID' USING ERRCODE='22023';
  END IF;
  PERFORM app_public.public_verify_bind(
    'public-verification-feedback',p_request_id,NULL,p_requested_code,NULL,NULL,p_idempotency_digest
  );
  SELECT q.id,q."licenseeId" INTO qr
  FROM public."QRCode" q WHERE q.code=p_requested_code;
  IF qr.id IS NULL THEN RAISE EXCEPTION 'PUBLIC_FEEDBACK_TARGET_INVALID' USING ERRCODE='42501'; END IF;
  SELECT k.id,k."responsePayload" INTO key_row
  FROM public."ActionIdempotencyKey" k WHERE k."keyHash"=p_idempotency_digest;
  IF key_row.id IS NOT NULL THEN
    RETURN QUERY SELECT true,coalesce(key_row."responsePayload"->>'reference',reference),
      'Feedback submitted successfully.'; RETURN;
  END IF;
  INSERT INTO public."ActionIdempotencyKey"(
    id,"keyHash",action,scope,"requestHash","statusCode","responsePayload","createdAt","completedAt","expiresAt"
  ) VALUES (
    gen_random_uuid()::text,p_idempotency_digest,'PUBLIC_PRODUCT_FEEDBACK',qr.id,p_idempotency_digest,201,
    jsonb_build_object('reference',reference),p_submitted_at,p_submitted_at,p_submitted_at+interval '24 hours'
  );
  audit_id:=gen_random_uuid()::text;
  PERFORM set_config('app.public_verification_audit_id',audit_id,true);
  INSERT INTO public."AuditLog"(
    id,"userId","orgId","licenseeId",action,"entityType","entityId",details,
    "ipAddress","ipHash","userAgent","createdAt"
  ) VALUES (
    audit_id,NULL,NULL,qr."licenseeId",'CUSTOMER_PRODUCT_FEEDBACK','CustomerFeedback',qr.id,
    jsonb_build_object('reference',reference,'rating',p_rating,'satisfaction',p_satisfaction,
      'notesPresent',length(coalesce(p_notes,''))>0,'observedStatus',nullif(p_observed_status,''),
      'observedOutcome',nullif(p_observed_outcome,''),'requestId',p_request_id),
    NULL,NULL,NULL,p_submitted_at
  );
  RETURN QUERY SELECT true,reference,'Feedback submitted successfully.';
END
$$;

CREATE OR REPLACE FUNCTION app_public.submit_public_incident(
  p_session_id text,p_session_proof_hash text,p_incident_type text,p_description text,p_contact_email text,
  p_consent_to_contact boolean,p_evidence jsonb,p_submitted_at timestamp without time zone,p_request_id text,
  p_actor_ip_hash text,p_actor_device_hash text,p_idempotency_digest text
) RETURNS TABLE("accepted" boolean,"publicReference" text,"message" text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public
AS $$
DECLARE qr record; session_row record;
  key_row record;
  incident_id text:=gen_random_uuid()::text; ticket_id text:=gen_random_uuid()::text;
  outbox_id text:=gen_random_uuid()::text;
  reference text:='INC-'||upper(substr(replace(gen_random_uuid()::text,'-',''),1,12));
BEGIN
  IF p_session_id !~ '^[0-9a-fA-F-]{36}$'
     OR p_session_proof_hash !~ '^(?:[A-Za-z0-9._-]{1,32}:)?[a-f0-9]{64}$'
     OR p_incident_type NOT IN ('counterfeit_suspected','duplicate_scan','tampered_label','wrong_product','other')
     OR length(btrim(p_description))<3 OR length(p_description)>2000
     OR jsonb_typeof(coalesce(p_evidence,'[]'::jsonb))<>'array'
     OR jsonb_array_length(coalesce(p_evidence,'[]'::jsonb))>4
     OR (p_consent_to_contact AND (p_contact_email IS NULL OR length(p_contact_email)>160)) THEN
    RAISE EXCEPTION 'PUBLIC_INCIDENT_INVALID' USING ERRCODE='22023';
  END IF;
  PERFORM app_public.public_verify_bind(
    'public-verification-incident',p_request_id,NULL,NULL,NULL,p_session_id,p_idempotency_digest
  );
  SELECT s.id,s."qrCodeId" INTO session_row FROM public."CustomerVerificationSession" s
  WHERE s.id=p_session_id AND s."proofBindingTokenHash"=p_session_proof_hash
    AND s."proofBindingExpiresAt">p_submitted_at AND s."expiresAt">p_submitted_at;
  IF session_row.id IS NULL THEN
    RAISE EXCEPTION 'PUBLIC_INCIDENT_SESSION_DENIED' USING ERRCODE='42501';
  END IF;
  PERFORM set_config('app.public_verification_qr_id',session_row."qrCodeId",true);
  SELECT q.id,q.code,q."licenseeId" INTO qr
  FROM public."QRCode" q WHERE q.id=session_row."qrCodeId";
  IF qr.id IS NULL THEN RAISE EXCEPTION 'PUBLIC_INCIDENT_TARGET_INVALID' USING ERRCODE='42501'; END IF;
  PERFORM set_config('app.public_verification_qr_id',qr.id,true);
  PERFORM set_config('app.public_verification_target_id',incident_id,true);
  PERFORM set_config('app.public_verification_support_id',ticket_id,true);
  PERFORM set_config('app.public_verification_outbox_id',outbox_id,true);
  SELECT k.id,k."responsePayload" INTO key_row
  FROM public."ActionIdempotencyKey" k WHERE k."keyHash"=p_idempotency_digest;
  IF key_row.id IS NOT NULL THEN
    RETURN QUERY SELECT true,key_row."responsePayload"->>'reference','Concern submitted successfully.'; RETURN;
  END IF;
  INSERT INTO public."Incident"(
    id,"qrCodeId","qrCodeValue","scanEventId","licenseeId","reportedBy","customerName",
    "customerEmail","customerPhone","customerCountry","preferredContactMethod","consentToContact",
    "incidentType",severity,"severityOverridden",description,photos,"purchasePlace","purchaseDate",
    "productBatchNo","locationLat","locationLng","locationName","locationCountry","locationRegion",
    "locationCity","ipHash","userAgentHash","deviceFingerprintHash",status,priority,
    "assignedToUserId","slaDueAt",tags,"internalNotes","resolutionSummary","resolutionOutcome",
    "createdAt","updatedAt"
  ) VALUES (
    incident_id,qr.id,qr.code,NULL,qr."licenseeId",'CUSTOMER',NULL,
    CASE WHEN p_consent_to_contact THEN lower(p_contact_email) ELSE NULL END,NULL,NULL,
    (CASE WHEN p_consent_to_contact THEN 'EMAIL' ELSE 'NONE' END)::public."IncidentContactMethod",
    p_consent_to_contact,
    upper(p_incident_type)::public."IncidentType",'MEDIUM',false,p_description,ARRAY[]::text[],
    NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,p_actor_ip_hash,NULL,p_actor_device_hash,
    'NEW','P3',NULL,p_submitted_at+interval '24 hours',
    ARRAY['public_verification_concern'],NULL,NULL,NULL,p_submitted_at,p_submitted_at
  );
  INSERT INTO public."IncidentEvent"(
    id,"incidentId","actorType","actorUserId","eventType","eventPayload","createdAt"
  ) VALUES (
    gen_random_uuid()::text,incident_id,'CUSTOMER',NULL,'CREATED',
    jsonb_build_object('requestId',p_request_id,'source','public_verification'),p_submitted_at
  );
  IF EXISTS (
    SELECT 1 FROM jsonb_array_elements(coalesce(p_evidence,'[]'::jsonb)) e
    WHERE e->>'storageKey' !~ '^[A-Za-z0-9._-]{1,255}$'
       OR length(coalesce(e->>'fileUrl','')) NOT BETWEEN 31 AND 300
       OR e->>'fileUrl' !~ '^/api/incidents/evidence-files/[A-Za-z0-9._%-]+$'
       OR e->>'fileType' NOT IN ('image/jpeg','image/png','image/webp','application/pdf')
  ) THEN
    RAISE EXCEPTION 'PUBLIC_INCIDENT_EVIDENCE_INVALID' USING ERRCODE='22023';
  END IF;
  INSERT INTO public."IncidentEvidence"(
    id,"incidentId","fileUrl","storageKey","fileType","uploadedByUserId","uploadedBy","createdAt"
  )
  SELECT gen_random_uuid()::text,incident_id,e->>'fileUrl',e->>'storageKey',e->>'fileType',
    NULL,'CUSTOMER',p_submitted_at
  FROM jsonb_array_elements(coalesce(p_evidence,'[]'::jsonb)) e;
  INSERT INTO public."SupportTicket"(
    id,"incidentId","referenceCode","licenseeId","customerEmail",subject,status,priority,
    "assignedToUserId","slaDueAt","firstResponseAt","resolvedAt","createdAt","updatedAt"
  ) VALUES (
    ticket_id,incident_id,reference,qr."licenseeId",
    CASE WHEN p_consent_to_contact THEN lower(p_contact_email) ELSE NULL END,
    'Public verification concern','OPEN','P3',NULL,p_submitted_at+interval '24 hours',
    NULL,NULL,p_submitted_at,p_submitted_at
  );
  INSERT INTO public."ActionIdempotencyKey"(
    id,"keyHash",action,scope,"requestHash","statusCode","responsePayload","createdAt","completedAt","expiresAt"
  ) VALUES (
    gen_random_uuid()::text,p_idempotency_digest,'PUBLIC_VERIFICATION_INCIDENT',qr.id,
    p_idempotency_digest,201,jsonb_build_object('reference',reference),
    p_submitted_at,p_submitted_at,p_submitted_at+interval '24 hours'
  );
  INSERT INTO public."SecurityEventOutbox"(
    id,"eventType",payload,"jobType","requestId","payloadDigest","idempotencyKey",
    "organizationId","licenseeId","manufacturerId","initiatingUserId","expiresAt",
    "claimedAt","claimLeaseExpiresAt","sinkEventId",status,attempts,"nextAttemptAt",
    "lastError","sentAt","createdAt","updatedAt"
  ) VALUES (
    outbox_id,'PUBLIC_VERIFICATION_CONCERN',
    jsonb_build_object('incidentId',incident_id,'reference',reference,'requestId',p_request_id),
    NULL,p_request_id,NULL,
    encode(sha256(convert_to('public-incident:'||p_idempotency_digest,'UTF8')),'hex'),
    NULL,qr."licenseeId",NULL,NULL,p_submitted_at+interval '30 days',NULL,NULL,NULL,
    'QUEUED',0,p_submitted_at,NULL,NULL,p_submitted_at,p_submitted_at
  );
  RETURN QUERY SELECT true,reference,'Concern submitted successfully.';
END
$$;

CREATE OR REPLACE FUNCTION app_public.submit_request_access(
  p_full_name text,p_work_email text,p_company_name text,p_role_title text,p_country text,
  p_monthly_volume text,p_message text,p_source_page text,p_referrer text,
  p_submitted_at timestamp without time zone,p_request_id text,p_idempotency_digest text
) RETURNS TABLE("accepted" boolean,"publicReference" text,"message" text,"deliveryRequired" boolean)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public
AS $$
DECLARE
  existing record;
  row_id text:=gen_random_uuid()::text;
  reference text:='RA-'||upper(substr(replace(gen_random_uuid()::text,'-',''),1,12));
BEGIN
  IF length(btrim(p_full_name)) NOT BETWEEN 2 AND 120
     OR length(btrim(p_work_email)) NOT BETWEEN 3 AND 160
     OR p_work_email !~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$'
     OR length(btrim(p_company_name)) NOT BETWEEN 2 AND 160
     OR length(btrim(p_role_title)) NOT BETWEEN 2 AND 120
     OR length(btrim(p_country)) NOT BETWEEN 2 AND 120
     OR length(btrim(p_monthly_volume)) NOT BETWEEN 1 AND 80
     OR length(btrim(p_message)) NOT BETWEEN 10 AND 3000 THEN
    RAISE EXCEPTION 'PUBLIC_REQUEST_ACCESS_INVALID' USING ERRCODE='22023';
  END IF;
  PERFORM app_public.public_verify_bind(
    'public-verification-request-access',p_request_id,NULL,NULL,NULL,NULL,p_idempotency_digest
  );
  SELECT k.id,k."responsePayload" INTO existing
  FROM public."ActionIdempotencyKey" k WHERE k."keyHash"=p_idempotency_digest;
  IF existing.id IS NOT NULL THEN
    RETURN QUERY SELECT true,existing."responsePayload"->>'reference',
      'Request received. MSCQR will review your access request.',false;
    RETURN;
  END IF;
  PERFORM set_config('app.public_verification_target_id',row_id,true);
  INSERT INTO public."RequestAccess"(
    id,"referenceCode","fullName","workEmail","companyName","roleTitle",country,
    "monthlyGarmentVolume",message,"sourcePage",referrer,status,"internalNote",
    "assignedToUserId","reviewedByUserId","reviewedAt","adminEmailDeliveryStatus",
    "adminEmailErrorCode","acknowledgementEmailDeliveryStatus","acknowledgementEmailErrorCode",
    "createdAt","updatedAt"
  ) VALUES (
    row_id,reference,btrim(p_full_name),lower(btrim(p_work_email)),btrim(p_company_name),
    btrim(p_role_title),btrim(p_country),btrim(p_monthly_volume),btrim(p_message),
    nullif(btrim(p_source_page),''),nullif(btrim(p_referrer),''),'NEW',NULL,NULL,NULL,NULL,
    'QUEUED',NULL,'QUEUED',NULL,p_submitted_at,p_submitted_at
  );
  INSERT INTO public."ActionIdempotencyKey"(
    id,"keyHash",action,scope,"requestHash","statusCode","responsePayload",
    "createdAt","completedAt","expiresAt"
  ) VALUES (
    gen_random_uuid()::text,p_idempotency_digest,'PUBLIC_REQUEST_ACCESS',row_id,
    p_idempotency_digest,201,jsonb_build_object('reference',reference),
    p_submitted_at,p_submitted_at,p_submitted_at+interval '24 hours'
  );
  RETURN QUERY SELECT true,reference,'Request received. MSCQR will review your access request.',true;
END
$$;

CREATE OR REPLACE FUNCTION app_public.submit_public_support(
  p_public_name text,p_public_email text,p_issue_type text,p_title text,p_description text,
  p_verified_code text,p_product_reference text,p_source_path text,p_page_url text,
  p_submitted_at timestamp without time zone,p_request_id text,p_idempotency_digest text
) RETURNS TABLE("accepted" boolean,"publicReference" text,"message" text,"deliveryRequired" boolean)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public
AS $$
DECLARE
  existing record;
  qr record;
  row_id text:=gen_random_uuid()::text;
  reference text:='SUP-'||upper(substr(replace(gen_random_uuid()::text,'-',''),1,12));
BEGIN
  IF length(btrim(p_public_name)) NOT BETWEEN 2 AND 120
     OR length(btrim(p_public_email)) NOT BETWEEN 3 AND 160
     OR p_public_email !~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$'
     OR p_issue_type NOT IN ('verification_result','scan_problem','product_concern','platform_access','privacy','other')
     OR length(btrim(p_title)) NOT BETWEEN 5 AND 160
     OR length(btrim(p_description)) NOT BETWEEN 10 AND 4000
     OR (p_source_path IS NOT NULL AND (left(p_source_path,1)<>'/' OR position('..' in p_source_path)>0)) THEN
    RAISE EXCEPTION 'PUBLIC_SUPPORT_INVALID' USING ERRCODE='22023';
  END IF;
  PERFORM app_public.public_verify_bind(
    'public-verification-support',p_request_id,NULL,p_verified_code,NULL,NULL,p_idempotency_digest
  );
  IF p_verified_code IS NOT NULL THEN
    SELECT q.id,q.code,q."licenseeId" INTO qr
    FROM public."QRCode" q WHERE q.code=p_verified_code;
    IF qr.id IS NULL THEN RAISE EXCEPTION 'PUBLIC_SUPPORT_TARGET_INVALID' USING ERRCODE='42501'; END IF;
    PERFORM set_config('app.public_verification_qr_id',qr.id,true);
  END IF;
  SELECT k.id,k."responsePayload" INTO existing
  FROM public."ActionIdempotencyKey" k WHERE k."keyHash"=p_idempotency_digest;
  IF existing.id IS NOT NULL THEN
    RETURN QUERY SELECT true,existing."responsePayload"->>'reference',
      'Support request received.',false;
    RETURN;
  END IF;
  PERFORM set_config('app.public_verification_target_id',row_id,true);
  INSERT INTO public."SupportIssueReport"(
    id,"reporterUserId","reporterRole","licenseeId","referenceCode","publicName","publicEmail",
    "issueType","verificationCode","productReference",priority,title,description,status,
    "internalNote","responseMessage","respondedAt","respondedByUserId","emailDeliveryStatus",
    "emailErrorCode","acknowledgementEmailDeliveryStatus","acknowledgementEmailErrorCode",
    "sourcePath","pageUrl","autoDetected","screenshotPath","screenshotMime","screenshotSize",
    diagnostics,"createdAt","updatedAt"
  ) VALUES (
    row_id,NULL,NULL,qr."licenseeId",reference,btrim(p_public_name),lower(btrim(p_public_email)),
    p_issue_type,qr.code,nullif(btrim(p_product_reference),''),
    CASE WHEN p_issue_type IN ('verification_result','product_concern') THEN 'P2' ELSE 'P3' END,
    btrim(p_title),btrim(p_description),
    'OPEN',NULL,NULL,NULL,NULL,'QUEUED',NULL,'QUEUED',NULL,nullif(btrim(p_source_path),''),
    nullif(btrim(p_page_url),''),false,NULL,NULL,NULL,
    jsonb_build_object('verifiedQrBound',qr.id IS NOT NULL,'requestId',p_request_id),
    p_submitted_at,p_submitted_at
  );
  INSERT INTO public."ActionIdempotencyKey"(
    id,"keyHash",action,scope,"requestHash","statusCode","responsePayload",
    "createdAt","completedAt","expiresAt"
  ) VALUES (
    gen_random_uuid()::text,p_idempotency_digest,'PUBLIC_SUPPORT',row_id,
    p_idempotency_digest,201,jsonb_build_object('reference',reference),
    p_submitted_at,p_submitted_at,p_submitted_at+interval '24 hours'
  );
  RETURN QUERY SELECT true,reference,'Support request received.',true;
END
$$;

CREATE OR REPLACE FUNCTION app_public.complete_request_access_delivery(
  p_idempotency_digest text,p_admin_status text,p_admin_error text,
  p_ack_status text,p_ack_error text,p_completed_at timestamp without time zone,p_request_id text
) RETURNS TABLE("updated" boolean)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public
AS $$
DECLARE key_row record;
BEGIN
  IF p_idempotency_digest !~ '^(?:[A-Za-z0-9._-]{1,32}:)?[a-f0-9]{64}$'
     OR p_admin_status NOT IN ('SENT','DRY_RUN','DISABLED','FAILED','SKIPPED')
     OR p_ack_status NOT IN ('SENT','DRY_RUN','DISABLED','FAILED','SKIPPED')
     OR length(coalesce(p_admin_error,''))>80 OR length(coalesce(p_ack_error,''))>80
     OR p_completed_at IS NULL THEN
    RAISE EXCEPTION 'PUBLIC_REQUEST_ACCESS_DELIVERY_INVALID' USING ERRCODE='22023';
  END IF;
  PERFORM app_public.public_verify_bind(
    'public-verification-request-access-delivery',p_request_id,NULL,NULL,NULL,NULL,p_idempotency_digest
  );
  SELECT k.id,k.scope INTO key_row FROM public."ActionIdempotencyKey" k
  WHERE k."keyHash"=p_idempotency_digest AND k.action='PUBLIC_REQUEST_ACCESS';
  IF key_row.id IS NULL THEN
    RAISE EXCEPTION 'PUBLIC_REQUEST_ACCESS_DELIVERY_DENIED' USING ERRCODE='42501';
  END IF;
  PERFORM set_config('app.public_verification_target_id',key_row.scope,true);
  UPDATE public."RequestAccess" SET
    "adminEmailDeliveryStatus"=p_admin_status,
    "adminEmailErrorCode"=nullif(p_admin_error,''),
    "acknowledgementEmailDeliveryStatus"=p_ack_status,
    "acknowledgementEmailErrorCode"=nullif(p_ack_error,''),
    "updatedAt"=p_completed_at
  WHERE id=key_row.scope;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'PUBLIC_REQUEST_ACCESS_DELIVERY_DENIED' USING ERRCODE='42501';
  END IF;
  RETURN QUERY SELECT true;
END
$$;

CREATE OR REPLACE FUNCTION app_public.complete_public_support_delivery(
  p_idempotency_digest text,p_admin_status text,p_admin_error text,
  p_ack_status text,p_ack_error text,p_completed_at timestamp without time zone,p_request_id text
) RETURNS TABLE("updated" boolean)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public
AS $$
DECLARE key_row record;
BEGIN
  IF p_idempotency_digest !~ '^(?:[A-Za-z0-9._-]{1,32}:)?[a-f0-9]{64}$'
     OR p_admin_status NOT IN ('SENT','DRY_RUN','DISABLED','FAILED','SKIPPED')
     OR p_ack_status NOT IN ('SENT','DRY_RUN','DISABLED','FAILED','SKIPPED')
     OR length(coalesce(p_admin_error,''))>80 OR length(coalesce(p_ack_error,''))>80
     OR p_completed_at IS NULL THEN
    RAISE EXCEPTION 'PUBLIC_SUPPORT_DELIVERY_INVALID' USING ERRCODE='22023';
  END IF;
  PERFORM app_public.public_verify_bind(
    'public-verification-support-delivery',p_request_id,NULL,NULL,NULL,NULL,p_idempotency_digest
  );
  SELECT k.id,k.scope INTO key_row FROM public."ActionIdempotencyKey" k
  WHERE k."keyHash"=p_idempotency_digest AND k.action='PUBLIC_SUPPORT';
  IF key_row.id IS NULL THEN
    RAISE EXCEPTION 'PUBLIC_SUPPORT_DELIVERY_DENIED' USING ERRCODE='42501';
  END IF;
  PERFORM set_config('app.public_verification_target_id',key_row.scope,true);
  UPDATE public."SupportIssueReport" SET
    "emailDeliveryStatus"=p_admin_status,
    "emailErrorCode"=nullif(p_admin_error,''),
    "acknowledgementEmailDeliveryStatus"=p_ack_status,
    "acknowledgementEmailErrorCode"=nullif(p_ack_error,''),
    "updatedAt"=p_completed_at
  WHERE id=key_row.scope;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'PUBLIC_SUPPORT_DELIVERY_DENIED' USING ERRCODE='42501';
  END IF;
  RETURN QUERY SELECT true;
END
$$;

CREATE OR REPLACE FUNCTION app_public.track_support_status(
  p_reference_code text,p_proof_digest text,p_proof_version integer,
  p_checked_at timestamp without time zone,p_request_id text
) RETURNS TABLE(
  "referenceCode" text,"customerFacingStatus" text,"priority" text,
  "updatedAt" timestamp without time zone,"handoffStage" text,
  "slaDueAt" timestamp without time zone
)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public
AS $$
DECLARE
  ticket record;
  handoff record;
  expected_digest text;
BEGIN
  IF p_reference_code !~ '^[A-Z0-9][A-Z0-9_-]{3,63}$'
     OR p_proof_digest !~ '^sha256-v1:[a-f0-9]{64}$'
     OR p_proof_version<>1 OR p_checked_at IS NULL THEN
    RAISE EXCEPTION 'PUBLIC_SUPPORT_TRACK_INVALID' USING ERRCODE='22023';
  END IF;
  expected_digest:=substr(p_proof_digest,11);
  PERFORM app_public.public_verify_bind(
    'public-verification-support-track',p_request_id,NULL,p_reference_code,NULL,NULL,p_proof_digest
  );
  SELECT t.id,t."incidentId",t."referenceCode",t.status::text AS status,t.priority::text AS priority,
         t."updatedAt",t."slaDueAt"
    INTO ticket
    FROM public."SupportTicket" t
   WHERE t."referenceCode"=p_reference_code
     AND t."customerEmail" IS NOT NULL
     AND encode(sha256(convert_to(lower(t."customerEmail"),'UTF8')),'hex')=expected_digest;
  IF ticket.id IS NULL THEN RETURN; END IF;
  PERFORM set_config('app.public_verification_target_id',ticket."incidentId",true);
  SELECT h."currentStage"::text AS stage,h."slaDueAt"
    INTO handoff
    FROM public."IncidentHandoff" h
   WHERE h."incidentId"=ticket."incidentId";
  RETURN QUERY SELECT ticket."referenceCode",ticket.status,ticket.priority,ticket."updatedAt",
    handoff.stage,coalesce(handoff."slaDueAt",ticket."slaDueAt");
END
$$;

REVOKE ALL ON FUNCTION app_public.public_verify_bind(text,text,text,text,text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_public.issue_customer_auth_session(text,text,text,text,text,timestamp without time zone,timestamp without time zone,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_public.require_customer_auth_session(text,timestamp without time zone,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_public.revoke_customer_auth_session(text,timestamp without time zone,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_public.public_verify_execute(text,text,timestamp without time zone,text,text,text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_public.verify_raw_qr(text,timestamp without time zone,text,text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_public.verify_signed_qr(text,text,text,text,text,text,integer,text,timestamp without time zone,timestamp without time zone,timestamp without time zone,text,text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_public.record_qr_verification(text,text,text,timestamp without time zone,text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_public.start_verification_session(text,text,text,timestamp without time zone,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_public.read_verification_session(text,text,text,timestamp without time zone,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_public.write_verification_session(text,text,text,text,jsonb,timestamp without time zone,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_public.public_verify_write_evidence(text,text,text,text,jsonb,timestamp without time zone,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_public.claim_customer_ownership(text,text,text,text,text,text,boolean,timestamp without time zone,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_public.create_customer_ownership_transfer(text,text,text,text,timestamp without time zone,timestamp without time zone,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_public.cancel_customer_ownership_transfer(text,text,text,timestamp without time zone,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_public.accept_customer_ownership_transfer(text,text,text,text,timestamp without time zone,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_public.begin_customer_passkey(text,text,text,text,text,text,text,text,text,text,timestamp without time zone,timestamp without time zone,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_public.load_customer_passkey(text[],text,text,timestamp without time zone,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_public.finish_customer_passkey(text,text[],text,jsonb,timestamp without time zone,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_public.list_customer_passkeys(text,timestamp without time zone,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_public.delete_customer_passkey(text,text,timestamp without time zone,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_public.submit_product_feedback(text,integer,text,text,text,text,text,timestamp without time zone,text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_public.submit_public_incident(text,text,text,text,text,boolean,jsonb,timestamp without time zone,text,text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_public.submit_request_access(text,text,text,text,text,text,text,text,text,timestamp without time zone,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_public.submit_public_support(text,text,text,text,text,text,text,text,text,timestamp without time zone,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_public.complete_request_access_delivery(text,text,text,text,text,timestamp without time zone,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_public.complete_public_support_delivery(text,text,text,text,text,timestamp without time zone,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_public.track_support_status(text,text,integer,timestamp without time zone,text) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION app_public.accept_customer_ownership_transfer(text,text,text,text,timestamp without time zone,text) TO "mscqr_rls_cert_preauth";
GRANT EXECUTE ON FUNCTION app_public.begin_customer_passkey(text,text,text,text,text,text,text,text,text,text,timestamp without time zone,timestamp without time zone,text) TO "mscqr_rls_cert_preauth";
GRANT EXECUTE ON FUNCTION app_public.cancel_customer_ownership_transfer(text,text,text,timestamp without time zone,text) TO "mscqr_rls_cert_preauth";
GRANT EXECUTE ON FUNCTION app_public.claim_customer_ownership(text,text,text,text,text,text,boolean,timestamp without time zone,text) TO "mscqr_rls_cert_preauth";
GRANT EXECUTE ON FUNCTION app_public.complete_public_support_delivery(text,text,text,text,text,timestamp without time zone,text) TO "mscqr_rls_cert_preauth";
GRANT EXECUTE ON FUNCTION app_public.complete_request_access_delivery(text,text,text,text,text,timestamp without time zone,text) TO "mscqr_rls_cert_preauth";
GRANT EXECUTE ON FUNCTION app_public.create_customer_ownership_transfer(text,text,text,text,timestamp without time zone,timestamp without time zone,text) TO "mscqr_rls_cert_preauth";
GRANT EXECUTE ON FUNCTION app_public.delete_customer_passkey(text,text,timestamp without time zone,text) TO "mscqr_rls_cert_preauth";
GRANT EXECUTE ON FUNCTION app_public.finish_customer_passkey(text,text[],text,jsonb,timestamp without time zone,text) TO "mscqr_rls_cert_preauth";
GRANT EXECUTE ON FUNCTION app_public.issue_customer_auth_session(text,text,text,text,text,timestamp without time zone,timestamp without time zone,text) TO "mscqr_rls_cert_preauth";
GRANT EXECUTE ON FUNCTION app_public.list_customer_passkeys(text,timestamp without time zone,text) TO "mscqr_rls_cert_preauth";
GRANT EXECUTE ON FUNCTION app_public.load_customer_passkey(text[],text,text,timestamp without time zone,text) TO "mscqr_rls_cert_preauth";
GRANT EXECUTE ON FUNCTION app_public.read_customer_auth_session(text,timestamp without time zone,text) TO "mscqr_rls_cert_preauth";
GRANT EXECUTE ON FUNCTION app_public.read_verification_session(text,text,text,timestamp without time zone,text) TO "mscqr_rls_cert_preauth";
GRANT EXECUTE ON FUNCTION app_public.revoke_customer_auth_session(text,timestamp without time zone,text) TO "mscqr_rls_cert_preauth";
GRANT EXECUTE ON FUNCTION app_public.start_verification_session(text,text,text,timestamp without time zone,text,text) TO "mscqr_rls_cert_preauth";
GRANT EXECUTE ON FUNCTION app_public.submit_product_feedback(text,integer,text,text,text,text,text,timestamp without time zone,text,text,text) TO "mscqr_rls_cert_preauth";
GRANT EXECUTE ON FUNCTION app_public.submit_public_incident(text,text,text,text,text,boolean,jsonb,timestamp without time zone,text,text,text,text) TO "mscqr_rls_cert_preauth";
GRANT EXECUTE ON FUNCTION app_public.submit_public_support(text,text,text,text,text,text,text,text,text,timestamp without time zone,text,text) TO "mscqr_rls_cert_preauth";
GRANT EXECUTE ON FUNCTION app_public.submit_request_access(text,text,text,text,text,text,text,text,text,timestamp without time zone,text,text) TO "mscqr_rls_cert_preauth";
GRANT EXECUTE ON FUNCTION app_public.track_support_status(text,text,integer,timestamp without time zone,text) TO "mscqr_rls_cert_preauth";
GRANT EXECUTE ON FUNCTION app_public.verify_raw_qr(text,timestamp without time zone,text,text,text,text) TO "mscqr_rls_cert_preauth";
GRANT EXECUTE ON FUNCTION app_public.verify_signed_qr(text,text,text,text,text,text,integer,text,timestamp without time zone,timestamp without time zone,timestamp without time zone,text,text,text,text) TO "mscqr_rls_cert_preauth";
GRANT EXECUTE ON FUNCTION app_public.write_verification_session(text,text,text,text,jsonb,timestamp without time zone,text) TO "mscqr_rls_cert_preauth";
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
DECLARE capability_hash text; credential record;
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
   RETURNING c.id INTO credential;
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
DECLARE job record; report_value jsonb;
BEGIN
  PERFORM app_rls.scheduled_job_prepare(p_capability,p_schedule_id,'get',p_request_id);
  PERFORM set_config('app.scheduled_job_id',p_job_id,true);
  SELECT j."licenseeId",j."periodFrom",j."periodTo" INTO job
    FROM public."CompliancePackJob" j
    WHERE j.id=p_job_id AND j."triggerType"='SCHEDULED' AND j."scheduledScheduleId"=p_schedule_id;
  IF NOT FOUND OR job."licenseeId" IS NULL THEN RAISE EXCEPTION 'SCHEDULED_COMPLIANCE_JOB_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM set_config('app.scheduled_licensee_id',job."licenseeId",true),set_config('app.licensee_id',job."licenseeId",true);
  report_value:=app_rls.c03_build_compliance_report(job."licenseeId",job."periodFrom",job."periodTo");
  RETURN jsonb_build_object('job',app_rls.c03_compliance_job_projection(p_job_id),'report',report_value);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.scheduled_complete_compliance_pack_job(
  p_capability text,p_schedule_id text,p_request_id text,p_job_id text,p_result jsonb
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE job record;
BEGIN
  IF jsonb_typeof(p_result)<>'object' OR p_result->>'fileName' IS NULL OR p_result->>'storageKey' IS NULL
     OR p_result->>'integrityHash' !~ '^[0-9a-f]{64}$' OR octet_length(p_result::text)>65536
  THEN RAISE EXCEPTION 'SCHEDULED_COMPLIANCE_RESULT_INVALID' USING ERRCODE='22023'; END IF;
  PERFORM app_rls.scheduled_job_prepare(p_capability,p_schedule_id,'complete',p_request_id);
  PERFORM set_config('app.scheduled_job_id',p_job_id,true);
  UPDATE public."CompliancePackJob" SET status='COMPLETED',"fileName"=p_result->>'fileName',"storageKey"=p_result->>'storageKey',
    "integrityHash"=p_result->>'integrityHash',"signatureAlgorithm"=p_result->>'signatureAlgorithm',summary=p_result,
    "finishedAt"=transaction_timestamp(),"updatedAt"=transaction_timestamp()
    WHERE id=p_job_id AND "triggerType"='SCHEDULED' AND "scheduledScheduleId"=p_schedule_id AND status='RUNNING'
    RETURNING id,"licenseeId","storageKey" INTO job;
  IF NOT FOUND THEN RAISE EXCEPTION 'SCHEDULED_COMPLIANCE_TRANSITION_DENIED' USING ERRCODE='40001'; END IF;
  PERFORM set_config('app.scheduled_licensee_id',job."licenseeId",true),set_config('app.licensee_id',job."licenseeId",true);
  PERFORM app_rls.scheduled_job_queue_audit('COMPLIANCE_PACK_COMPLETED',job.id,job."licenseeId",jsonb_build_object('storageKey',job."storageKey"));
  RETURN app_rls.c03_compliance_job_projection(p_job_id);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.scheduled_fail_compliance_pack_job(
  p_capability text,p_schedule_id text,p_request_id text,p_job_id text,p_error_code text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE job record;
BEGIN
  IF p_error_code !~ '^[A-Z][A-Z0-9_]{2,127}$' THEN RAISE EXCEPTION 'SCHEDULED_COMPLIANCE_ERROR_INVALID' USING ERRCODE='22023'; END IF;
  PERFORM app_rls.scheduled_job_prepare(p_capability,p_schedule_id,'fail',p_request_id);
  PERFORM set_config('app.scheduled_job_id',p_job_id,true);
  UPDATE public."CompliancePackJob" SET status='FAILED',"errorMessage"=p_error_code,"finishedAt"=transaction_timestamp(),"updatedAt"=transaction_timestamp()
    WHERE id=p_job_id AND "triggerType"='SCHEDULED' AND "scheduledScheduleId"=p_schedule_id AND status='RUNNING'
    RETURNING id,"licenseeId" INTO job;
  IF NOT FOUND THEN RAISE EXCEPTION 'SCHEDULED_COMPLIANCE_TRANSITION_DENIED' USING ERRCODE='40001'; END IF;
  PERFORM set_config('app.scheduled_licensee_id',job."licenseeId",true),set_config('app.licensee_id',job."licenseeId",true);
  PERFORM app_rls.scheduled_job_queue_audit('COMPLIANCE_PACK_FAILED',job.id,job."licenseeId",jsonb_build_object('errorCode',p_error_code));
  RETURN app_rls.c03_compliance_job_projection(p_job_id);
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
    FROM candidates c WHERE o.id=c.id
    RETURNING o.id,o."jobType",o."requestId",o."payloadDigest",o."idempotencyKey",
      o."organizationId",o."licenseeId",o."manufacturerId",o."initiatingUserId",
      o."expiresAt",o.attempts
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
  SELECT q.id,q.payload,q."requestId",q."organizationId",q."licenseeId",q."manufacturerId",
    q."initiatingUserId",q."expiresAt",q."claimLeaseExpiresAt",q.status,q."flushedAuditLogId"
    INTO o FROM public."AuditLogOutbox" q
    WHERE q.id=p_job_id AND q."payloadDigest"=p_payload_digest FOR UPDATE;
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
  RETURN QUERY WITH candidates AS (
    SELECT o.id FROM public."SecurityEventOutbox" o
    WHERE o."jobType"=p_job_type AND o.status IN ('QUEUED','FAILED')
      AND o."nextAttemptAt"<=p_attempted_at AND o."expiresAt">p_attempted_at
      AND o.attempts<10 AND (o."claimLeaseExpiresAt" IS NULL OR o."claimLeaseExpiresAt"<=p_attempted_at)
    ORDER BY o."createdAt",o.id FOR UPDATE SKIP LOCKED LIMIT p_batch_size
  ), claimed AS (
    UPDATE public."SecurityEventOutbox" o
    SET attempts=o.attempts+1,"claimedAt"=p_attempted_at,
      "claimLeaseExpiresAt"=p_attempted_at+interval '5 minutes',"updatedAt"=transaction_timestamp()
    FROM candidates c WHERE o.id=c.id
    RETURNING o.id,o."jobType",o."requestId",o."payloadDigest",o."idempotencyKey",
      o."organizationId",o."licenseeId",o."manufacturerId",o."initiatingUserId",
      o."expiresAt",o.attempts,o."eventType",o.payload,o."createdAt"
  )
  SELECT c.id,c."jobType",c."requestId",c."payloadDigest",c."idempotencyKey",
    c."organizationId",c."licenseeId",c."manufacturerId",c."initiatingUserId",
    c."expiresAt",c.attempts,c."eventType",c.payload,c."createdAt"
  FROM claimed c;
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
  SELECT q.id,q.status,q."sinkEventId",q."claimLeaseExpiresAt"
    INTO o FROM public."SecurityEventOutbox" q
    WHERE q.id=p_job_id AND q."payloadDigest"=p_payload_digest FOR UPDATE;
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
-- Capability-bound notification and incident-email persistence.
-- "mscqr_rls_cert_auth_owner" owns these functions; runtime roles receive exact EXECUTE only.

CREATE OR REPLACE FUNCTION app_rls.b03_authenticated_context_valid()
RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $fn$
BEGIN
  IF session_user <> 'mscqr_rls_cert_app'
     OR current_setting('app.auth_session_verified',true) <> '1'
     OR current_setting('app.b03_actor_id',true) IS DISTINCT FROM current_setting('app.user_id',true)
  THEN RETURN false; END IF;

  RETURN EXISTS (
    SELECT 1 FROM public."RefreshToken" session_row
     WHERE session_row.id=current_setting('app.auth_session_id',true)
       AND session_row."userId"=current_setting('app.b03_actor_id',true)
       AND session_row."sessionCapabilityHash"=current_setting('app.auth_session_hash',true)
       AND session_row."sessionCapabilityHashVersion"='sha256-v1'
       AND session_row."sessionCapabilityRevokedAt" IS NULL
       AND session_row."sessionCapabilityExpiresAt">clock_timestamp()
       AND session_row."revokedAt" IS NULL
       AND session_row."expiresAt">clock_timestamp()
  );
END
$fn$;

REVOKE ALL ON FUNCTION app_rls.b03_authenticated_context_valid() FROM PUBLIC;

CREATE OR REPLACE FUNCTION app_rls.b03_require_authenticated_actor(p_request_id text)
RETURNS TABLE(user_id text, role text, organization_id text, licensee_id text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $fn$
DECLARE actor record;
BEGIN
  IF p_request_id IS NULL OR length(p_request_id) NOT BETWEEN 1 AND 128
     OR p_request_id !~ '^[!-~]+$'
     OR p_request_id IS DISTINCT FROM current_setting('app.request_id', true) THEN
    RAISE EXCEPTION 'B03_AUTHENTICATED_BOUNDARY_DENIED' USING ERRCODE='42501';
  END IF;

  SELECT * INTO actor
  FROM app_rls.b01_authenticated_actor(
    current_setting('app.user_id', true),
    current_setting('app.auth_session_id', true),
    p_request_id
  );

  IF actor.role NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN','LICENSEE_ADMIN','MANUFACTURER_ADMIN') THEN
    RAISE EXCEPTION 'B03_AUTHENTICATED_BOUNDARY_DENIED' USING ERRCODE='42501';
  END IF;

  PERFORM set_config('app.b03_actor_id', actor."userId", true),
          set_config('app.b03_actor_role', actor.role, true),
          set_config('app.b03_actor_org_id', coalesce(actor."organizationId", ''), true),
          set_config('app.b03_actor_licensee_id', coalesce(actor."licenseeId", ''), true);

  RETURN QUERY SELECT actor."userId"::text, actor.role::text,
    actor."organizationId"::text, actor."licenseeId"::text;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.b03_assert_requested_scope(
  p_licensee_id text,
  p_organization_id text
) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $fn$
DECLARE actor_role text := current_setting('app.b03_actor_role', true);
DECLARE actor_id text := current_setting('app.b03_actor_id', true);
DECLARE actor_licensee text := nullif(current_setting('app.b03_actor_licensee_id', true), '');
DECLARE actor_org text := nullif(current_setting('app.b03_actor_org_id', true), '');
BEGIN
  IF actor_role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') THEN
    IF p_licensee_id IS NOT NULL AND NOT EXISTS (
      SELECT 1 FROM public."Licensee" l
      JOIN public."Organization" o ON o.id=l."orgId"
      WHERE l.id=p_licensee_id
        AND (p_organization_id IS NULL OR o.id=p_organization_id)
        AND l."isActive" AND l."suspendedAt" IS NULL AND o."isActive"
    ) THEN
      RAISE EXCEPTION 'B03_TENANT_SCOPE_DENIED' USING ERRCODE='42501';
    END IF;
  ELSIF actor_role='LICENSEE_ADMIN' THEN
    IF p_licensee_id IS DISTINCT FROM actor_licensee
       OR (p_organization_id IS NOT NULL AND p_organization_id IS DISTINCT FROM actor_org) THEN
      RAISE EXCEPTION 'B03_TENANT_SCOPE_DENIED' USING ERRCODE='42501';
    END IF;
  ELSIF actor_role='MANUFACTURER_ADMIN' THEN
    IF p_licensee_id IS NULL OR NOT EXISTS (
      SELECT 1 FROM public."ManufacturerLicenseeLink" ml
      JOIN public."Licensee" l ON l.id=ml."licenseeId"
      JOIN public."Organization" o ON o.id=l."orgId"
      WHERE ml."manufacturerId"=actor_id AND ml."licenseeId"=p_licensee_id
        AND (p_organization_id IS NULL OR p_organization_id=actor_org)
        AND l."isActive" AND l."suspendedAt" IS NULL AND o."isActive"
    ) THEN
      RAISE EXCEPTION 'B03_TENANT_SCOPE_DENIED' USING ERRCODE='42501';
    END IF;
  ELSE
    RAISE EXCEPTION 'B03_AUTHENTICATED_BOUNDARY_DENIED' USING ERRCODE='42501';
  END IF;

  PERFORM set_config('app.b03_licensee_id', coalesce(p_licensee_id, ''), true),
          set_config('app.b03_organization_id', coalesce(p_organization_id, ''), true);
  RETURN true;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.b03_primary_superadmin_email()
RETURNS TABLE(email text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $fn$
BEGIN
  PERFORM app_rls.b03_require_authenticated_actor(current_setting('app.request_id', true));
  PERFORM set_config('app.b03_operation','superadmin-read',true);
  RETURN QUERY
  SELECT u.email::text
  FROM public."User" u
  WHERE u.role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')
    AND u."isActive" AND u.status='ACTIVE' AND u."deletedAt" IS NULL
  ORDER BY u."createdAt",u.id
  LIMIT 1;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.b03_superadmin_alert_emails()
RETURNS TABLE(email text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $fn$
BEGIN
  PERFORM app_rls.b03_require_authenticated_actor(current_setting('app.request_id', true));
  PERFORM set_config('app.b03_operation','superadmin-read',true);
  RETURN QUERY
  SELECT u.email::text
  FROM public."User" u
  WHERE u.role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')
    AND u."isActive" AND u.status='ACTIVE' AND u."deletedAt" IS NULL
  ORDER BY u."createdAt",u.id
  LIMIT 100;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.b03_resolve_incident_email_actor(p_actor_user_id text)
RETURNS TABLE(id text,email text,name text,role text,active boolean)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $fn$
DECLARE actor record;
BEGIN
  SELECT * INTO actor
  FROM app_rls.b03_require_authenticated_actor(current_setting('app.request_id', true));
  IF p_actor_user_id IS DISTINCT FROM actor.user_id THEN
    RAISE EXCEPTION 'B03_INCIDENT_EMAIL_ACTOR_DENIED' USING ERRCODE='42501';
  END IF;
  PERFORM set_config('app.b03_operation','actor-read',true);
  RETURN QUERY
  SELECT u.id::text,u.email::text,u.name::text,u.role::text,
    (u."isActive" AND u.status='ACTIVE' AND u."deletedAt" IS NULL AND u."disabledAt" IS NULL)
  FROM public."User" u WHERE u.id=actor.user_id;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.b03_create_role_notifications(
  p_audience text,p_title text,p_body text,p_type text,p_licensee_id text,p_organization_id text,
  p_incident_id text,p_data jsonb,p_channels text[],p_request_id text
) RETURNS TABLE(
  "notificationId" text,"userId" text,"userEmail" text,"userRole" text,
  "userLicenseeId" text,"userOrganizationId" text,"channel" text,
  "writeResult" jsonb,"sideEffectRequired" boolean
)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $fn$
DECLARE actor record;
DECLARE channel_value text;
DECLARE recipient record;
DECLARE notification_id text;
DECLARE audience_roles text[];
BEGIN
  SELECT * INTO actor FROM app_rls.b03_require_authenticated_actor(p_request_id);
  IF p_audience NOT IN ('SUPER_ADMIN','LICENSEE_ADMIN','MANUFACTURER','ALL')
     OR p_title IS NULL OR length(p_title) NOT BETWEEN 1 AND 255
     OR p_body IS NULL OR length(p_body) NOT BETWEEN 1 AND 10000
     OR p_type IS NULL OR length(p_type) NOT BETWEEN 1 AND 128
     OR p_channels IS NULL OR cardinality(p_channels) NOT BETWEEN 1 AND 2
     OR EXISTS (SELECT 1 FROM unnest(p_channels) c WHERE c NOT IN ('WEB','EMAIL'))
     OR cardinality(p_channels)<>(SELECT count(DISTINCT c) FROM unnest(p_channels) c)
     OR octet_length(coalesce(p_data,'null'::jsonb)::text)>65536 THEN
    RAISE EXCEPTION 'B03_NOTIFICATION_INPUT_DENIED' USING ERRCODE='22023';
  END IF;
  PERFORM app_rls.b03_assert_requested_scope(p_licensee_id,p_organization_id);
  IF actor.role='LICENSEE_ADMIN' AND p_audience NOT IN ('LICENSEE_ADMIN','ALL') THEN
    RAISE EXCEPTION 'B03_NOTIFICATION_AUDIENCE_DENIED' USING ERRCODE='42501';
  END IF;
  IF actor.role='MANUFACTURER_ADMIN' AND p_audience NOT IN ('MANUFACTURER','ALL') THEN
    RAISE EXCEPTION 'B03_NOTIFICATION_AUDIENCE_DENIED' USING ERRCODE='42501';
  END IF;
  IF p_incident_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM public."Incident" i
    WHERE i.id=p_incident_id AND (p_licensee_id IS NULL OR i."licenseeId"=p_licensee_id)
  ) THEN
    RAISE EXCEPTION 'B03_INCIDENT_SCOPE_DENIED' USING ERRCODE='42501';
  END IF;

  audience_roles := CASE p_audience
    WHEN 'SUPER_ADMIN' THEN ARRAY['SUPER_ADMIN','PLATFORM_SUPER_ADMIN']
    WHEN 'LICENSEE_ADMIN' THEN ARRAY['LICENSEE_ADMIN']
    WHEN 'MANUFACTURER' THEN ARRAY['MANUFACTURER_ADMIN']
    ELSE ARRAY['SUPER_ADMIN','PLATFORM_SUPER_ADMIN','LICENSEE_ADMIN','MANUFACTURER_ADMIN']
  END;
  PERFORM set_config('app.b03_operation','notification-write',true);

  FOR recipient IN
    SELECT u.id,u.email,u.role::text AS role,u."licenseeId",u."orgId"
    FROM public."User" u
    WHERE u.role::text=ANY(audience_roles)
      AND u."isActive" AND u.status='ACTIVE' AND u."deletedAt" IS NULL AND u."disabledAt" IS NULL
      AND (p_licensee_id IS NULL OR u."licenseeId"=p_licensee_id OR (
        u.role='MANUFACTURER_ADMIN' AND EXISTS (
          SELECT 1 FROM public."ManufacturerLicenseeLink" ml
          WHERE ml."manufacturerId"=u.id AND ml."licenseeId"=p_licensee_id
        )
      ))
      AND (p_organization_id IS NULL OR u."orgId"=p_organization_id)
    ORDER BY u.id
  LOOP
    FOREACH channel_value IN ARRAY p_channels LOOP
      notification_id:=gen_random_uuid()::text;
      INSERT INTO public."Notification"(
        id,"userId","orgId","licenseeId","incidentId",audience,channel,type,title,body,data,"updatedAt"
      ) VALUES (
        notification_id,recipient.id,coalesce(p_organization_id,recipient."orgId"),
        coalesce(p_licensee_id,recipient."licenseeId"),p_incident_id,
        p_audience::public."NotificationAudience",channel_value::public."NotificationChannel",
        p_type,p_title,p_body,p_data,clock_timestamp()
      );
      RETURN QUERY SELECT notification_id,recipient.id::text,recipient.email::text,recipient.role,
        recipient."licenseeId"::text,recipient."orgId"::text,channel_value,
        jsonb_build_object('count',1),true;
    END LOOP;
  END LOOP;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.b03_create_user_notification(
  p_user_id text,p_title text,p_body text,p_type text,p_licensee_id text,p_organization_id text,
  p_incident_id text,p_data jsonb,p_channel text,p_request_id text
) RETURNS TABLE(
  "notificationId" text,"userId" text,"userEmail" text,"userRole" text,
  "userLicenseeId" text,"userOrganizationId" text,"channel" text,
  "writeResult" jsonb,"sideEffectRequired" boolean,"notification" jsonb
)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $fn$
DECLARE actor record;
DECLARE recipient record;
DECLARE notification_id text := gen_random_uuid()::text;
DECLARE projection jsonb;
BEGIN
  SELECT * INTO actor FROM app_rls.b03_require_authenticated_actor(p_request_id);
  IF p_channel NOT IN ('WEB','EMAIL') OR p_title IS NULL OR length(p_title) NOT BETWEEN 1 AND 255
     OR p_body IS NULL OR length(p_body) NOT BETWEEN 1 AND 10000
     OR p_type IS NULL OR length(p_type) NOT BETWEEN 1 AND 128
     OR octet_length(coalesce(p_data,'null'::jsonb)::text)>65536 THEN
    RAISE EXCEPTION 'B03_NOTIFICATION_INPUT_DENIED' USING ERRCODE='22023';
  END IF;
  PERFORM app_rls.b03_assert_requested_scope(p_licensee_id,p_organization_id);
  PERFORM set_config('app.b03_operation','notification-write',true),
          set_config('app.b03_target_user_id',p_user_id,true);
  SELECT u.id,u.email,u.role::text AS role,u."licenseeId",u."orgId" INTO recipient
  FROM public."User" u
  WHERE u.id=p_user_id AND u."isActive" AND u.status='ACTIVE'
    AND u."deletedAt" IS NULL AND u."disabledAt" IS NULL;
  IF NOT FOUND
     OR (actor.role='LICENSEE_ADMIN' AND recipient."licenseeId" IS DISTINCT FROM actor.licensee_id)
     OR (actor.role='MANUFACTURER_ADMIN' AND NOT EXISTS (
       SELECT 1 FROM public."ManufacturerLicenseeLink" ml
       WHERE ml."manufacturerId"=actor.user_id AND ml."licenseeId"=recipient."licenseeId"
     )) THEN
    RAISE EXCEPTION 'B03_NOTIFICATION_TARGET_DENIED' USING ERRCODE='42501';
  END IF;
  IF p_licensee_id IS NOT NULL AND recipient."licenseeId" IS DISTINCT FROM p_licensee_id THEN
    RAISE EXCEPTION 'B03_NOTIFICATION_TARGET_DENIED' USING ERRCODE='42501';
  END IF;

  INSERT INTO public."Notification"(
    id,"userId","orgId","licenseeId","incidentId",audience,channel,type,title,body,data,"updatedAt"
  ) VALUES (
    notification_id,recipient.id,coalesce(p_organization_id,recipient."orgId"),
    coalesce(p_licensee_id,recipient."licenseeId"),p_incident_id,'ALL',
    p_channel::public."NotificationChannel",p_type,p_title,p_body,p_data,clock_timestamp()
  );
  SELECT jsonb_build_object(
    'id',notification_id,'userId',recipient.id,'orgId',coalesce(p_organization_id,recipient."orgId"),
    'licenseeId',coalesce(p_licensee_id,recipient."licenseeId"),'incidentId',p_incident_id,
    'audience','ALL','channel',p_channel,'type',p_type,'title',p_title,'body',p_body,
    'data',p_data,'readAt',NULL,'emailedAt',NULL,'createdAt',clock_timestamp(),'updatedAt',clock_timestamp()
  ) INTO projection;
  RETURN QUERY SELECT notification_id,recipient.id::text,recipient.email::text,recipient.role,
    recipient."licenseeId"::text,recipient."orgId"::text,p_channel,
    jsonb_build_object('count',1),true,projection;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.b03_mark_notification_emailed(
  p_notification_id text,p_emailed_at timestamp without time zone,p_request_id text
) RETURNS TABLE(updated boolean)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $fn$
DECLARE actor record;
DECLARE changed integer;
BEGIN
  SELECT * INTO actor FROM app_rls.b03_require_authenticated_actor(p_request_id);
  IF p_emailed_at IS NULL OR abs(extract(epoch FROM (p_emailed_at-clock_timestamp())))>300 THEN
    RAISE EXCEPTION 'B03_NOTIFICATION_INPUT_DENIED' USING ERRCODE='22023';
  END IF;
  PERFORM set_config('app.b03_operation','notification-email-update',true),
          set_config('app.b03_notification_id',p_notification_id,true);
  UPDATE public."Notification" n SET "emailedAt"=coalesce(n."emailedAt",p_emailed_at),"updatedAt"=clock_timestamp()
  WHERE n.id=p_notification_id AND (
    actor.role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')
    OR n."userId"=actor.user_id
    OR (actor.role='LICENSEE_ADMIN' AND n."licenseeId"=actor.licensee_id)
    OR (actor.role='MANUFACTURER_ADMIN' AND EXISTS (
      SELECT 1 FROM public."ManufacturerLicenseeLink" ml
      WHERE ml."manufacturerId"=actor.user_id AND ml."licenseeId"=n."licenseeId"
    ))
  );
  GET DIAGNOSTICS changed=ROW_COUNT;
  RETURN QUERY SELECT changed=1;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.b03_list_notifications_for_user(
  p_user_id text,p_limit integer,p_offset integer,p_unread_only boolean,
  p_cursor_created_at timestamp without time zone,p_cursor_id text,p_request_id text
) RETURNS TABLE(notifications jsonb,total integer,unread integer)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $fn$
DECLARE actor record;
DECLARE audience_value text;
DECLARE rows_json jsonb;
DECLARE total_count integer;
DECLARE unread_count integer;
BEGIN
  SELECT * INTO actor FROM app_rls.b03_require_authenticated_actor(p_request_id);
  IF p_user_id IS DISTINCT FROM actor.user_id OR p_limit NOT BETWEEN 1 AND 100
     OR p_offset NOT BETWEEN 0 AND 1000000 THEN
    RAISE EXCEPTION 'B03_NOTIFICATION_READ_DENIED' USING ERRCODE='42501';
  END IF;
  audience_value:=CASE actor.role
    WHEN 'SUPER_ADMIN' THEN 'SUPER_ADMIN'
    WHEN 'PLATFORM_SUPER_ADMIN' THEN 'SUPER_ADMIN'
    WHEN 'LICENSEE_ADMIN' THEN 'LICENSEE_ADMIN'
    ELSE 'MANUFACTURER'
  END;
  PERFORM set_config('app.b03_operation','notification-read',true);

  WITH visible AS (
    SELECT n.id,n."userId",n."orgId",n."licenseeId",n."incidentId",n.audience,n.channel,
      n.type,n.title,n.body,n.data,n."readAt",n."emailedAt",n."createdAt",n."updatedAt"
    FROM public."Notification" n
    WHERE n.channel='WEB'
      AND (n."userId"=actor.user_id OR (
        n."userId" IS NULL AND n.audience::text IN ('ALL',audience_value)
        AND (
          actor.role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')
          OR n."licenseeId" IS NULL
          OR (actor.role='LICENSEE_ADMIN' AND n."licenseeId"=actor.licensee_id)
          OR (actor.role='MANUFACTURER_ADMIN' AND EXISTS (
            SELECT 1 FROM public."ManufacturerLicenseeLink" ml
            WHERE ml."manufacturerId"=actor.user_id AND ml."licenseeId"=n."licenseeId"
          ))
        )
      ))
      AND NOT (actor.role='LICENSEE_ADMIN' AND lower(n.type)=ANY(ARRAY[
        'manufacturer_batch_assigned','manufacturer_print_job_created','manufacturer_print_job_confirmed',
        'system_print_job_created','system_print_job_completed','system_print_job_failed','system_printer_status_changed'
      ]))
  ), page AS (
    SELECT * FROM visible
    WHERE (NOT p_unread_only OR "readAt" IS NULL)
      AND (p_cursor_created_at IS NULL OR ("createdAt",id)<(p_cursor_created_at,p_cursor_id))
    ORDER BY "createdAt" DESC,id DESC
    LIMIT p_limit OFFSET CASE WHEN p_cursor_created_at IS NULL THEN p_offset ELSE 0 END
  )
  SELECT coalesce(jsonb_agg(to_jsonb(page) ORDER BY "createdAt" DESC,id DESC),'[]'::jsonb)
    INTO rows_json FROM page;
  SELECT count(*)::integer INTO total_count FROM visible
    WHERE (NOT p_unread_only OR "readAt" IS NULL);
  SELECT count(*)::integer INTO unread_count FROM visible WHERE "readAt" IS NULL;
  RETURN QUERY SELECT rows_json,
    CASE WHEN p_cursor_created_at IS NULL THEN total_count ELSE NULL END,
    unread_count;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.b03_mark_notification_read(
  p_notification_id text,p_user_id text,p_read_at timestamp without time zone,p_request_id text
) RETURNS TABLE(notification jsonb)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $fn$
DECLARE actor record;
DECLARE selected record;
BEGIN
  SELECT * INTO actor FROM app_rls.b03_require_authenticated_actor(p_request_id);
  IF p_user_id IS DISTINCT FROM actor.user_id OR p_read_at IS NULL
     OR abs(extract(epoch FROM (p_read_at-clock_timestamp())))>300 THEN
    RAISE EXCEPTION 'B03_NOTIFICATION_READ_DENIED' USING ERRCODE='42501';
  END IF;
  PERFORM set_config('app.b03_operation','notification-read-update',true),
          set_config('app.b03_notification_id',p_notification_id,true);
  SELECT n.id,n."userId",n."orgId",n."licenseeId",n."incidentId",n.audience,n.channel,
    n.type,n.title,n.body,n.data,n."readAt",n."emailedAt",n."createdAt",n."updatedAt"
    INTO selected FROM public."Notification" n
  WHERE n.id=p_notification_id AND n.channel='WEB' AND n."userId"=actor.user_id
  FOR UPDATE;
  IF NOT FOUND THEN RETURN QUERY SELECT NULL::jsonb; RETURN; END IF;
  UPDATE public."Notification" n
  SET "readAt"=coalesce(n."readAt",p_read_at),"updatedAt"=clock_timestamp()
  WHERE n.id=selected.id
  RETURNING n.id,n."userId",n."orgId",n."licenseeId",n."incidentId",n.audience,n.channel,
    n.type,n.title,n.body,n.data,n."readAt",n."emailedAt",n."createdAt",n."updatedAt"
    INTO selected;
  RETURN QUERY SELECT to_jsonb(selected);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.b03_mark_all_notifications_read(
  p_user_id text,p_read_at timestamp without time zone,p_request_id text
) RETURNS TABLE(count integer)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $fn$
DECLARE actor record;
DECLARE changed integer;
BEGIN
  SELECT * INTO actor FROM app_rls.b03_require_authenticated_actor(p_request_id);
  IF p_user_id IS DISTINCT FROM actor.user_id OR p_read_at IS NULL
     OR abs(extract(epoch FROM (p_read_at-clock_timestamp())))>300 THEN
    RAISE EXCEPTION 'B03_NOTIFICATION_READ_DENIED' USING ERRCODE='42501';
  END IF;
  PERFORM set_config('app.b03_operation','notification-read-update',true);
  UPDATE public."Notification" n
  SET "readAt"=p_read_at,"updatedAt"=clock_timestamp()
  WHERE n."userId"=actor.user_id AND n.channel='WEB' AND n."readAt" IS NULL;
  GET DIAGNOSTICS changed=ROW_COUNT;
  RETURN QUERY SELECT changed;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.b03_resolve_incident_notification_scope(p_incident_id text)
RETURNS TABLE("incidentId" text,"licenseeId" text,"manufacturerOrganizationId" text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $fn$
DECLARE actor record;
DECLARE incident_scope record;
BEGIN
  SELECT * INTO actor
  FROM app_rls.b03_require_authenticated_actor(current_setting('app.request_id', true));
  PERFORM set_config('app.b03_operation','incident-scope-read',true),
          set_config('app.b03_incident_id',p_incident_id,true);
  SELECT i.id,i."licenseeId",manufacturer."orgId" INTO incident_scope
  FROM public."Incident" i
  LEFT JOIN public."QRCode" qr ON qr.id=i."qrCodeId"
  LEFT JOIN public."Batch" b ON b.id=qr."batchId"
  LEFT JOIN public."User" manufacturer ON manufacturer.id=b."manufacturerId"
  WHERE i.id=p_incident_id;
  IF NOT FOUND
     OR (actor.role='LICENSEE_ADMIN' AND incident_scope."licenseeId" IS DISTINCT FROM actor.licensee_id)
     OR (actor.role='MANUFACTURER_ADMIN' AND NOT EXISTS (
       SELECT 1 FROM public."ManufacturerLicenseeLink" ml
       WHERE ml."manufacturerId"=actor.user_id AND ml."licenseeId"=incident_scope."licenseeId"
     )) THEN
    RAISE EXCEPTION 'B03_INCIDENT_SCOPE_DENIED' USING ERRCODE='42501';
  END IF;
  RETURN QUERY SELECT incident_scope.id::text,incident_scope."licenseeId"::text,
    incident_scope."orgId"::text;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.b03_claim_incident_email_delivery(
  p_incident_id text,p_licensee_id text,p_actor_user_id text,p_sender_mode text,
  p_to_address text,p_subject text,p_body_preview text,p_attempted_from text,p_used_from text,
  p_reply_to text,p_template text,p_request_id text,p_idempotency_key text,p_payload_digest text
) RETURNS TABLE(
  "deliveryId" text,"disposition" text,"delivered" boolean,"providerMessageId" text,
  "emailErrorCode" text,"attemptedFrom" text,"usedFrom" text,"replyTo" text
)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $fn$
DECLARE actor record;
DECLARE incident_scope record;
DECLARE existing record;
DECLARE delivery_id text := gen_random_uuid()::text;
BEGIN
  SELECT * INTO actor FROM app_rls.b03_require_authenticated_actor(p_request_id);
  IF p_sender_mode NOT IN ('actor','system') OR p_to_address IS NULL OR length(p_to_address) NOT BETWEEN 3 AND 320
     OR p_to_address !~ '^[^[:space:]@]+@[^[:space:]@]+$'
     OR p_subject IS NULL OR length(p_subject) NOT BETWEEN 1 AND 998
     OR length(coalesce(p_body_preview,''))>500
     OR p_idempotency_key !~ '^[0-9a-f]{64}$' OR p_payload_digest !~ '^[0-9a-f]{64}$'
     OR (p_sender_mode='actor' AND p_actor_user_id IS DISTINCT FROM actor.user_id) THEN
    RAISE EXCEPTION 'B03_INCIDENT_EMAIL_INPUT_DENIED' USING ERRCODE='22023';
  END IF;
  PERFORM set_config('app.b03_operation','incident-email-write',true),
          set_config('app.b03_incident_id',p_incident_id,true);
  SELECT i.id,i."licenseeId" INTO incident_scope
  FROM public."Incident" i WHERE i.id=p_incident_id;
  IF NOT FOUND OR (p_licensee_id IS NOT NULL AND p_licensee_id IS DISTINCT FROM incident_scope."licenseeId")
     OR (actor.role='LICENSEE_ADMIN' AND actor.licensee_id IS DISTINCT FROM incident_scope."licenseeId")
     OR (actor.role='MANUFACTURER_ADMIN' AND NOT EXISTS (
       SELECT 1 FROM public."ManufacturerLicenseeLink" ml
       WHERE ml."manufacturerId"=actor.user_id AND ml."licenseeId"=incident_scope."licenseeId"
     )) THEN
    RAISE EXCEPTION 'B03_INCIDENT_SCOPE_DENIED' USING ERRCODE='42501';
  END IF;

  PERFORM set_config('app.b03_licensee_id',coalesce(incident_scope."licenseeId",''),true);
  SELECT k.id,k."requestHash",k."statusCode",k."responsePayload",k."completedAt"
    INTO existing FROM public."ActionIdempotencyKey" k
  WHERE k."keyHash"=p_idempotency_key FOR UPDATE;
  IF FOUND THEN
    IF existing."requestHash" IS DISTINCT FROM p_payload_digest THEN
      RAISE EXCEPTION 'B03_IDEMPOTENCY_CONFLICT' USING ERRCODE='23505';
    END IF;
    RETURN QUERY SELECT existing."responsePayload"->>'deliveryId',
      CASE
        WHEN existing."completedAt" IS NULL THEN 'IN_FLIGHT'
        WHEN existing."statusCode"=200 THEN 'REPLAY_SENT'
        ELSE 'REPLAY_FAILED'
      END,
      existing."statusCode"=200,
      existing."responsePayload"->>'providerMessageId',
      existing."responsePayload"->>'emailErrorCode',
      existing."responsePayload"->>'attemptedFrom',
      existing."responsePayload"->>'usedFrom',
      existing."responsePayload"->>'replyTo';
    RETURN;
  END IF;

  INSERT INTO public."ActionIdempotencyKey"(
    id,"keyHash",action,scope,"requestHash","responsePayload","expiresAt"
  ) VALUES (
    gen_random_uuid()::text,p_idempotency_key,'b03-incident-email',p_incident_id,
    p_payload_digest,jsonb_build_object('deliveryId',delivery_id),clock_timestamp()+interval '1 day'
  );
  INSERT INTO public."IncidentCommunication"(
    id,"incidentId",direction,channel,"toAddress",subject,"bodyPreview","attemptedFrom",
    "usedFrom","replyTo",status
  ) VALUES (
    delivery_id,p_incident_id,'OUTBOUND','EMAIL',lower(p_to_address),p_subject,p_body_preview,
    p_attempted_from,p_used_from,p_reply_to,'QUEUED'
  );
  RETURN QUERY SELECT delivery_id,'CLAIMED',false,NULL::text,NULL::text,
    p_attempted_from,p_used_from,p_reply_to;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.b03_complete_incident_email_delivery(
  p_delivery_id text,p_idempotency_key text,p_provider_message_id text,p_email_error_code text,
  p_status text,p_smtp_config_source text,p_used_from text,p_completed_at timestamp without time zone
) RETURNS TABLE("communicationId" text,"eventId" text,"auditLogId" text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $fn$
DECLARE actor record;
DECLARE delivery record;
DECLARE idem record;
DECLARE event_id text := gen_random_uuid()::text;
DECLARE audit_id text := gen_random_uuid()::text;
DECLARE delivery_licensee_id text;
BEGIN
  SELECT * INTO actor
  FROM app_rls.b03_require_authenticated_actor(current_setting('app.request_id', true));
  IF p_status NOT IN ('QUEUED','SENT','FAILED')
     OR p_idempotency_key !~ '^[0-9a-f]{64}$'
     OR p_completed_at IS NULL OR abs(extract(epoch FROM (p_completed_at-clock_timestamp())))>300 THEN
    RAISE EXCEPTION 'B03_INCIDENT_EMAIL_INPUT_DENIED' USING ERRCODE='22023';
  END IF;
  PERFORM set_config('app.b03_operation','incident-email-complete',true);
  PERFORM set_config('app.b03_delivery_id',p_delivery_id,true);
  SELECT k.id,k."responsePayload",k."completedAt"
    INTO idem FROM public."ActionIdempotencyKey" k
  WHERE k."keyHash"=p_idempotency_key AND k.action='b03-incident-email' FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'B03_INCIDENT_EMAIL_CLAIM_REQUIRED' USING ERRCODE='42501'; END IF;
  IF idem."completedAt" IS NOT NULL THEN
    RETURN QUERY SELECT idem."responsePayload"->>'deliveryId',
      idem."responsePayload"->>'eventId',idem."responsePayload"->>'auditLogId';
    RETURN;
  END IF;
  SELECT c.id,c."incidentId",c."attemptedFrom",c."replyTo"
    INTO delivery FROM public."IncidentCommunication" c
  WHERE c.id=p_delivery_id AND c.id=(idem."responsePayload"->>'deliveryId') FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'B03_INCIDENT_EMAIL_CLAIM_REQUIRED' USING ERRCODE='42501'; END IF;
  PERFORM set_config('app.b03_incident_id',delivery."incidentId",true);
  SELECT i."licenseeId" INTO STRICT delivery_licensee_id
  FROM public."Incident" i WHERE i.id=delivery."incidentId";
  PERFORM set_config('app.b03_licensee_id',coalesce(delivery_licensee_id,''),true);
  UPDATE public."IncidentCommunication" c SET
    "providerMessageId"=p_provider_message_id,"errorMessage"=p_email_error_code,
    "usedFrom"=p_used_from,status=p_status::public."IncidentCommStatus"
  WHERE c.id=p_delivery_id;
  INSERT INTO public."IncidentEvent"(id,"incidentId","actorType","actorUserId","eventType","eventPayload")
  VALUES (
    event_id,delivery."incidentId",'ADMIN',actor.user_id,'EMAIL_SENT',
    jsonb_build_object('delivered',p_status='SENT','providerMessageId',p_provider_message_id,
      'emailErrorCode',p_email_error_code,'smtpConfigSource',p_smtp_config_source)
  );
  INSERT INTO public."AuditLog"(id,"userId","orgId","licenseeId",action,"entityType","entityId",details)
  SELECT audit_id,actor.user_id,actor.organization_id,i."licenseeId",'INCIDENT_EMAIL_SENT',
    'Incident',i.id,jsonb_build_object('status',p_status,'delivered',p_status='SENT',
      'providerMessageId',p_provider_message_id,'emailErrorCode',p_email_error_code,
      'smtpConfigSource',p_smtp_config_source,'usedFrom',p_used_from)
  FROM public."Incident" i WHERE i.id=delivery."incidentId";
  UPDATE public."ActionIdempotencyKey" k SET
    "statusCode"=CASE WHEN p_status='SENT' THEN 200 ELSE 502 END,
    "responsePayload"=jsonb_build_object(
      'deliveryId',p_delivery_id,'eventId',event_id,'auditLogId',audit_id,
      'providerMessageId',p_provider_message_id,'emailErrorCode',p_email_error_code,
      'attemptedFrom',delivery."attemptedFrom",'usedFrom',p_used_from,'replyTo',delivery."replyTo"
    ),
    "completedAt"=p_completed_at
  WHERE k.id=idem.id;
  RETURN QUERY SELECT p_delivery_id,event_id,audit_id;
END
$fn$;

REVOKE ALL ON FUNCTION app_rls.b03_require_authenticated_actor(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.b03_assert_requested_scope(text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.b03_primary_superadmin_email() FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.b03_superadmin_alert_emails() FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.b03_resolve_incident_email_actor(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.b03_create_role_notifications(text,text,text,text,text,text,text,jsonb,text[],text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.b03_create_user_notification(text,text,text,text,text,text,text,jsonb,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.b03_mark_notification_emailed(text,timestamp without time zone,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.b03_list_notifications_for_user(text,integer,integer,boolean,timestamp without time zone,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.b03_mark_notification_read(text,text,timestamp without time zone,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.b03_mark_all_notifications_read(text,timestamp without time zone,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.b03_resolve_incident_notification_scope(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.b03_claim_incident_email_delivery(text,text,text,text,text,text,text,text,text,text,text,text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.b03_complete_incident_email_delivery(text,text,text,text,text,text,text,timestamp without time zone) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_rls.b03_claim_incident_email_delivery(text,text,text,text,text,text,text,text,text,text,text,text,text,text) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.b03_complete_incident_email_delivery(text,text,text,text,text,text,text,timestamp without time zone) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.b03_create_role_notifications(text,text,text,text,text,text,text,jsonb,text[],text) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.b03_create_user_notification(text,text,text,text,text,text,text,jsonb,text,text) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.b03_list_notifications_for_user(text,integer,integer,boolean,timestamp without time zone,text,text) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.b03_mark_all_notifications_read(text,timestamp without time zone,text) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.b03_mark_notification_emailed(text,timestamp without time zone,text) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.b03_mark_notification_read(text,text,timestamp without time zone,text) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.b03_primary_superadmin_email() TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.b03_resolve_incident_email_actor(text) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.b03_resolve_incident_notification_scope(text) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.b03_superadmin_alert_emails() TO "mscqr_rls_cert_app";
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
WHERE n.nspname IN ('app_rls','app_auth','app_public');
UPDATE mscqr_rls_install.state SET phase='context-helpers-installed' WHERE singleton;
COMMIT;
