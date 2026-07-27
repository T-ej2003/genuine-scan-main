-- Capability-bearing public wrappers for the mature dashboard and batch-read
-- implementations emitted by the clean-room package.  The implementation
-- overloads are SECURITY INVOKER and are never granted to a runtime role.
-- These wrappers are owned by identity-auth-function-owner and re-derive all
-- actor context from the durable authenticated-session capability.

CREATE OR REPLACE FUNCTION app_rls.operational_read_session_valid()
RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
BEGIN
  IF session_user <> {{APP_ROLE}}
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
