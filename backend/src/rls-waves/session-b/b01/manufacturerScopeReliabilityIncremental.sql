\set ON_ERROR_STOP on
BEGIN;

CREATE OR REPLACE FUNCTION app_rls.load_authenticated_manufacturer_scope(
  p_requested_licensee_id text,p_requested_org_id text,p_requested_scope_version text,
  p_purpose text,p_write_audit boolean
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; selected record; scope_link record; selected_found boolean:=false;
  link_count integer:=0; primary_count integer:=0; links jsonb:='[]'::jsonb; audit_id text;
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
  FOR scope_link IN
    SELECT ml."licenseeId",ml."isPrimary",ml."updatedAt",l.id,l.name,l.prefix,l."brandName",l."orgId"
    FROM public."ManufacturerLicenseeLink" ml
    JOIN public."Licensee" l ON l.id=ml."licenseeId"
    JOIN public."Organization" o ON o.id=l."orgId"
    WHERE ml."manufacturerId"=actor."userId" AND l."isActive"
      AND l."suspendedAt" IS NULL AND o."isActive"
    ORDER BY ml."isPrimary" DESC,ml."createdAt",ml."licenseeId"
  LOOP
    link_count:=link_count+1;
    IF link_count>100 THEN RAISE EXCEPTION 'MANUFACTURER_MEMBERSHIP_SET_TOO_LARGE' USING ERRCODE='54000'; END IF;
    IF scope_link."isPrimary" THEN primary_count:=primary_count+1; END IF;
    IF NOT selected_found
       AND (p_requested_licensee_id IS NULL OR scope_link."licenseeId"=p_requested_licensee_id)
       AND (p_requested_org_id IS NULL OR scope_link."orgId"=p_requested_org_id)
    THEN selected:=scope_link; selected_found:=true; END IF;
    links:=links||jsonb_build_array(jsonb_build_object(
      'id',scope_link.id,'name',scope_link.name,'prefix',scope_link.prefix,'brandName',scope_link."brandName",
      'orgId',scope_link."orgId",'isPrimary',scope_link."isPrimary",
      'scopeVersion',to_char(scope_link."updatedAt" AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
    ));
  END LOOP;
  IF link_count=0 THEN RAISE EXCEPTION 'MANUFACTURER_MEMBERSHIP_REQUIRED' USING ERRCODE='42501'; END IF;
  IF primary_count>1 THEN RAISE EXCEPTION 'MANUFACTURER_MEMBERSHIP_AMBIGUOUS' USING ERRCODE='42501'; END IF;
  IF NOT selected_found AND (p_requested_licensee_id IS NOT NULL OR p_requested_org_id IS NOT NULL) THEN
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

COMMIT;
