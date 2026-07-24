CREATE OR REPLACE FUNCTION app_rls.risk_analytics_session_valid()
RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $fn$
BEGIN
  IF session_user <> {{APP_ROLE}}
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

  SELECT COALESCE(jsonb_agg(to_jsonb(a) ORDER BY a."batchId",a.id),'[]'::jsonb)
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
