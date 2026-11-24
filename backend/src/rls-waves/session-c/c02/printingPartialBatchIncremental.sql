\set ON_ERROR_STOP on
BEGIN;

DO $preflight$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_proc p
    WHERE p.oid=to_regprocedure('app_rls.printing_create_job(text,text,text,text,text,integer,text,text,text,text,text,jsonb)')
      AND p.proowner=current_user::regrole AND p.prosecdef
      AND p.provolatile='v' AND p.proconfig=ARRAY['search_path=pg_catalog, public']
      AND current_user IN ('mscqr_prd_rls_phase2_auth_owner','mscqr_rls_cert_auth_owner')
      AND (SELECT count(*)=2
             AND count(*) FILTER (WHERE a.grantee=p.proowner AND a.grantor=p.proowner
               AND a.privilege_type='EXECUTE' AND NOT a.is_grantable)=1
             AND count(*) FILTER (WHERE a.grantee=(CASE current_user
               WHEN 'mscqr_prd_rls_phase2_auth_owner' THEN 'mscqr_prd_rls_phase2_app'
               ELSE 'mscqr_rls_cert_app' END)::regrole AND a.grantor=p.proowner
               AND a.privilege_type='EXECUTE' AND NOT a.is_grantable)=1
           FROM pg_catalog.aclexplode(coalesce(p.proacl,pg_catalog.acldefault('f',p.proowner))) a)
      AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')='1bbabb75f6d8bed10140569fff834b1c8cee0872f84393dd98cc79bd59fac222'
      AND encode(sha256(convert_to(pg_get_functiondef(p.oid),'UTF8')),'hex')='7cbe6b908ba9118f1cb2785b030be28cb708168be9db5ccfcfe7c4e6e6f4edcd'
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_proc p
    WHERE p.oid=to_regprocedure('app_rls.printing_record_sample(text,text,text,text,text,jsonb)')
      AND p.proowner=current_user::regrole AND p.prosecdef
      AND p.provolatile='v' AND p.proconfig=ARRAY['search_path=pg_catalog, public']
      AND current_user IN ('mscqr_prd_rls_phase2_auth_owner','mscqr_rls_cert_auth_owner')
      AND (SELECT count(*)=2
             AND count(*) FILTER (WHERE a.grantee=p.proowner AND a.grantor=p.proowner
               AND a.privilege_type='EXECUTE' AND NOT a.is_grantable)=1
             AND count(*) FILTER (WHERE a.grantee=(CASE current_user
               WHEN 'mscqr_prd_rls_phase2_auth_owner' THEN 'mscqr_prd_rls_phase2_app'
               ELSE 'mscqr_rls_cert_app' END)::regrole AND a.grantor=p.proowner
               AND a.privilege_type='EXECUTE' AND NOT a.is_grantable)=1
           FROM pg_catalog.aclexplode(coalesce(p.proacl,pg_catalog.acldefault('f',p.proowner))) a)
      AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')='c873ef11234a13cc1a61f6c08689c8bdd2fc255ca666a15fde727910d69efa00'
      AND encode(sha256(convert_to(pg_get_functiondef(p.oid),'UTF8')),'hex')='ccc2e0db775df537bfa93eb0a358d322e8e8a041ec37022fc451863b6f81486e'
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_proc p
    WHERE p.oid=to_regprocedure('app_rls.printing_release_batch(text,text,text,text,text,text)')
      AND p.proowner=current_user::regrole AND p.prosecdef
      AND p.provolatile='v' AND p.proconfig=ARRAY['search_path=pg_catalog, public']
      AND current_user IN ('mscqr_prd_rls_phase2_auth_owner','mscqr_rls_cert_auth_owner')
      AND (SELECT count(*)=2
             AND count(*) FILTER (WHERE a.grantee=p.proowner AND a.grantor=p.proowner
               AND a.privilege_type='EXECUTE' AND NOT a.is_grantable)=1
             AND count(*) FILTER (WHERE a.grantee=(CASE current_user
               WHEN 'mscqr_prd_rls_phase2_auth_owner' THEN 'mscqr_prd_rls_phase2_app'
               ELSE 'mscqr_rls_cert_app' END)::regrole AND a.grantor=p.proowner
               AND a.privilege_type='EXECUTE' AND NOT a.is_grantable)=1
           FROM pg_catalog.aclexplode(coalesce(p.proacl,pg_catalog.acldefault('f',p.proowner))) a)
      AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')='e508e171562a9f8431bb725b9d88d78d55cca670a4828bc49163eb0e271cd922'
      AND encode(sha256(convert_to(pg_get_functiondef(p.oid),'UTF8')),'hex')='1244b25c4beedde1475fa83fd8ac9cc7daf4c0effa74a0434e0a42687c87c059'
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_proc p
    WHERE p.oid=to_regprocedure('app_rls.printing_readiness(text,text,text,text,text,jsonb)')
      AND p.proowner=current_user::regrole AND p.prosecdef
      AND p.provolatile='v' AND p.proconfig=ARRAY['search_path=pg_catalog, public']
      AND current_user IN ('mscqr_prd_rls_phase2_auth_owner','mscqr_rls_cert_auth_owner')
      AND (SELECT count(*)=2
             AND count(*) FILTER (WHERE a.grantee=p.proowner AND a.grantor=p.proowner
               AND a.privilege_type='EXECUTE' AND NOT a.is_grantable)=1
             AND count(*) FILTER (WHERE a.grantee=(CASE current_user
               WHEN 'mscqr_prd_rls_phase2_auth_owner' THEN 'mscqr_prd_rls_phase2_app'
               ELSE 'mscqr_rls_cert_app' END)::regrole AND a.grantor=p.proowner
               AND a.privilege_type='EXECUTE' AND NOT a.is_grantable)=1
           FROM pg_catalog.aclexplode(coalesce(p.proacl,pg_catalog.acldefault('f',p.proowner))) a)
      AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')='047f5f3264d667ac308d2ed43df381284adc4a951e0961ba5ab146a6753429cf'
      AND encode(sha256(convert_to(pg_get_functiondef(p.oid),'UTF8')),'hex')='b294ad8736d7c4ddfa05ee54ead70706830c01af8e228d825024f84dbb617fef'
  ) OR NOT has_schema_privilege(current_user,'app_rls','CREATE')
  THEN RAISE EXCEPTION 'PRINT_JOB_MIGRATION_IDENTITY_INVALID' USING ERRCODE='42501'; END IF;
END
$preflight$;

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
  IF batch_row."lifecycleState" NOT IN ('CODES_GENERATED','PRINT_ACKNOWLEDGED','PRINT_CONFIRMED')
     OR batch_row."releasedAt" IS NOT NULL OR batch_row."suspendedAt" IS NOT NULL
  THEN RAISE EXCEPTION 'INVALID_STATE_TRANSITION'; END IF;
  IF EXISTS (
    SELECT 1 FROM public."PrintJob" j JOIN public."PrintSession" ps ON ps."printJobId"=j.id
     WHERE j."batchId"=p_batch_id AND j."manufacturerId"=actor."userId"
       AND j.status IN ('PENDING','SENT','PAUSED') AND ps.status IN ('ACTIVE','PAUSED','RESUME_PENDING')
  ) THEN RAISE EXCEPTION 'ACTIVE_PRINT_JOB_EXISTS'; END IF;

  SELECT p.id,p."connectionType",p."commandLanguage",p."printerRegistrationId",p."nativePrinterId",
    p."assignedUserId",p."orgId",p."licenseeId"
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
        AND pa."signatureValid" AND pa."trustValid"
        AND pa."expiresAt">(clock_timestamp() AT TIME ZONE 'UTC')
        AND coalesce((pa.metadata->>'connected')::boolean,false)
        AND (pa.metadata->>'source' IS DISTINCT FROM 'PERSISTENT_SESSION'
          OR pa.metadata->'printerHealth'->>'healthVersion'='1')
        AND NOT EXISTS (SELECT 1 FROM public."PrinterAttestation" newer
          WHERE newer."printerRegistrationId"=pa."printerRegistrationId"
            AND newer.metadata->>'source'='PERSISTENT_SESSION'
            AND (newer."createdAt",newer.id)>(pa."createdAt",pa.id))
        AND coalesce(pa.metadata->>'selectedPrinterId',pa.metadata->>'printerId','')
          IN (printer_row.id,coalesce(printer_row."nativePrinterId",''))
        AND ((pa.metadata->>'source' IS DISTINCT FROM 'PERSISTENT_SESSION' AND NOT EXISTS (
          SELECT 1 FROM public."PrinterAgentSession" prior
          WHERE prior."registrationId"=pa."printerRegistrationId"
        )) OR EXISTS (
          SELECT 1 FROM public."PrinterAgentSession" s
          WHERE s.id=pa.metadata->>'sessionId' AND s."registrationId"=pa."printerRegistrationId"
            AND s."connectionState"='CONNECTED' AND s."revokedAt" IS NULL
            AND s."expiresAt">clock_timestamp() AND s."lastSignedHeartbeatAt">clock_timestamp()-interval '35 seconds'
            AND s."selectedPrinterId"=pa.metadata->>'selectedPrinterId'
            AND s.metadata->>'printerId'=printer_row.id
            AND s.metadata->>'manufacturerId'=printer_row."assignedUserId"
            AND s.metadata->>'orgId' IS NOT DISTINCT FROM printer_row."orgId"
            AND s.metadata->>'licenseeId' IS NOT DISTINCT FROM printer_row."licenseeId"
        ))
    ) THEN RAISE EXCEPTION 'PRINTER_ATTESTATION_STALE'; END IF;
  END IF;

  -- Lock registration before the printer FK, including non-key trust updates.
  IF printer_row."printerRegistrationId" IS NOT NULL THEN
    PERFORM 1 FROM public."PrinterRegistration" pr
      WHERE pr.id=printer_row."printerRegistrationId" AND pr."userId"=actor."userId"
        AND pr."orgId" IS NOT DISTINCT FROM printer_row."orgId"
        AND pr."licenseeId" IS NOT DISTINCT FROM printer_row."licenseeId"
        AND pr."trustStatus"='TRUSTED' AND pr."revokedAt" IS NULL
      FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION 'PRINTER_ATTESTATION_STALE'; END IF;
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
       OR item.value->>'tokenIssuedAt' IS NULL
       OR NOT isfinite((item.value->>'tokenIssuedAt')::timestamp without time zone)
       OR (item.value->>'tokenIssuedAt')::timestamp without time zone>now_at
       OR (item.value->>'tokenExpiresAt')::timestamp without time zone<=(item.value->>'tokenIssuedAt')::timestamp without time zone
       OR (item.value->>'tokenExpiresAt')::timestamp without time zone<=now_at
    THEN RAISE EXCEPTION 'PRINTING_INVALID_INPUT'; END IF;
    UPDATE public."QRCode" q SET
      status='ACTIVATED', "tokenNonce"=item.value->>'tokenNonce',
      "tokenIssuedAt"=(item.value->>'tokenIssuedAt')::timestamp without time zone,
      "tokenExpiresAt"=(item.value->>'tokenExpiresAt')::timestamp without time zone,
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
  SELECT b."sampleScanPolicy" INTO policy FROM public."Batch" b WHERE b.id=job_row."batchId" FOR UPDATE;
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
    WHERE e."printJobId"=job_row.id AND e."eventType" IN ('SAMPLE_SCAN_PASSED','sample_scan_verified');
  IF actual_count>=required_count AND NOT EXISTS (
    SELECT 1 FROM public."QRCode" q WHERE q."batchId"=job_row."batchId"
      AND q.status='ALLOCATED' AND q."printJobId" IS NULL
      AND NOT EXISTS (SELECT 1 FROM public."PrintItem" pi WHERE pi."qrCodeId"=q.id)
  ) AND NOT EXISTS (
    SELECT 1 FROM public."PrintJob" j WHERE j."batchId"=job_row."batchId" AND j.status='CONFIRMED'
      AND (SELECT count(DISTINCT e."qrCodeId") FROM public."PrintAuditEvent" e
        WHERE e."printJobId"=j.id AND e."eventType" IN ('SAMPLE_SCAN_PASSED','sample_scan_verified'))
        < CASE coalesce(policy->>'type',policy->>'mode','ONE_PER_PRINT_JOB')
            WHEN 'ONE_PER_N_LABELS' THEN GREATEST(1,ceil(j.quantity::numeric/GREATEST(coalesce((policy->>'n')::integer,j.quantity),1))::integer)
            WHEN 'PERCENTAGE' THEN GREATEST(GREATEST(coalesce((policy->>'min')::integer,1),1),
              ceil(j.quantity*GREATEST(coalesce((policy->>'percentage')::numeric,1),0.01)/100)::integer)
            ELSE 1 END
  ) THEN
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
  SELECT b.id,b."lifecycleState",b."releasedAt",b."totalCodes",b."sampleScanPolicy"
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
    IF EXISTS (SELECT 1 FROM public."PrintJob" j JOIN public."QRCode" q ON q."printJobId"=j.id
      WHERE j."batchId"=p_batch_id AND j.status<>'CONFIRMED' AND q.status='PRINTED')
    THEN RAISE EXCEPTION 'PHYSICAL_CONFIRMATION_REQUIRED'; END IF;
    IF EXISTS (
      SELECT 1 FROM public."PrintJob" j WHERE j."batchId"=p_batch_id AND j.status='CONFIRMED'
        AND (SELECT count(DISTINCT e."qrCodeId") FROM public."PrintAuditEvent" e
          WHERE e."printJobId"=j.id AND e."eventType" IN ('SAMPLE_SCAN_PASSED','sample_scan_verified'))
          < CASE coalesce(batch_row."sampleScanPolicy"->>'type',batch_row."sampleScanPolicy"->>'mode','ONE_PER_PRINT_JOB')
              WHEN 'ONE_PER_N_LABELS' THEN GREATEST(1,ceil(j.quantity::numeric/GREATEST(coalesce((batch_row."sampleScanPolicy"->>'n')::integer,j.quantity),1))::integer)
              WHEN 'PERCENTAGE' THEN GREATEST(GREATEST(coalesce((batch_row."sampleScanPolicy"->>'min')::integer,1),1),
                ceil(j.quantity*GREATEST(coalesce((batch_row."sampleScanPolicy"->>'percentage')::numeric,1),0.01)/100)::integer)
              ELSE 1 END
    ) THEN RAISE EXCEPTION 'SAMPLE_SCAN_REQUIRED'; END IF;
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
  target_registration_id text;
  released_user_id text;
  approved_user_id text;
BEGIN
  IF p_purpose<>'printing-readiness'
     OR p_operation NOT IN ('BATCH','JOB','JOB_LIST','ATTENTION_QUEUE','RELEASE','REISSUE','REISSUE_REQUEST','REISSUE_LIST','PRINTABLE_ITEMS','PRINTER','PRINTER_LIST','PRINTER_STATUS','VALIDATION_EVIDENCE')
     OR (p_operation<>'REISSUE_LIST' AND (p_subject_id IS NULL OR p_subject_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'))
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
  ELSIF p_operation NOT IN ('JOB_LIST','ATTENTION_QUEUE','REISSUE_LIST') THEN
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
             AND q.status='ALLOCATED'::public."QRStatus" AND q."printJobId" IS NULL
             AND (nullif(p_options->>'rangeStart','') IS NULL OR q."displayCode">=p_options->>'rangeStart')
             AND (nullif(p_options->>'rangeEnd','') IS NULL OR q."displayCode"<=p_options->>'rangeEnd')
             AND NOT EXISTS (SELECT 1 FROM public."PrintItem" pi WHERE pi."qrCodeId"=q.id)
           ORDER BY q."displayCode",q.id
           LIMIT LEAST(GREATEST(coalesce(NULLIF(p_options->>'limit','')::integer,500),1),200000)
        ) q
      ),'[]'::jsonb),
      'qrCount',(SELECT count(*) FROM public."QRCode" q WHERE q."batchId"=batch_row.id),
      'confirmedItemCount',(SELECT count(*) FROM public."PrintItem" pi
        JOIN public."PrintSession" ps ON ps.id=pi."printSessionId"
        WHERE ps."batchId"=batch_row.id AND pi."printConfirmedAt" IS NOT NULL),
      'sampleCount',(SELECT count(DISTINCT pa."qrCodeId") FROM public."PrintAuditEvent" pa
        WHERE pa."batchId"=batch_row.id AND pa."eventType" IN ('SAMPLE_SCAN_PASSED','sample_scan_verified')),
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
    SELECT pr.id INTO target_registration_id
      FROM public."PrinterRegistration" pr
      WHERE pr."userId"=actor."userId" AND pr."revokedAt" IS NULL
        AND pr."trustStatus"<>'REVOKED'::public."PrinterTrustStatus"
      ORDER BY pr."approvedAt" DESC NULLS LAST,pr."lastSeenAt" DESC NULLS LAST,pr."updatedAt" DESC
      LIMIT 1;
    PERFORM set_config('app.printing_registration_id',coalesce(target_registration_id,''),true);
    RETURN (
      WITH registration AS (
        SELECT pr.id,pr."userId",pr."orgId",pr."licenseeId",
          pr."agentId",pr."deviceFingerprint",pr."trustStatus",pr."trustReason",
          pr."approvedAt",pr."lastSeenAt",pr."updatedAt"
        FROM public."PrinterRegistration" pr
        WHERE pr.id=target_registration_id
      ), attestation AS (
        SELECT pa.id,pa."printerRegistrationId",pa.metadata,pa."expiresAt",pa."trustValid",
          pa."signatureValid",pa."attestedAt",pa."rejectionReason",pa."createdAt",
          ((pa.metadata->>'source' IS DISTINCT FROM 'PERSISTENT_SESSION' AND NOT EXISTS (
            SELECT 1 FROM public."PrinterAgentSession" prior
            WHERE prior."registrationId"=pa."printerRegistrationId"
          )) OR EXISTS (
            SELECT 1 FROM public."PrinterAgentSession" s
            WHERE s.id=pa.metadata->>'sessionId' AND s."registrationId"=pa."printerRegistrationId"
              AND s."connectionState"='CONNECTED' AND s."revokedAt" IS NULL
              AND s."expiresAt">transaction_timestamp()
              AND s."lastSignedHeartbeatAt">transaction_timestamp()-interval '35 seconds'
              AND s."selectedPrinterId"=pa.metadata->>'selectedPrinterId'
              AND s.metadata->>'printerId'=pa.metadata->>'printerId'
              AND s.metadata->>'manufacturerId'=pr."userId"
              AND s.metadata->>'orgId' IS NOT DISTINCT FROM pr."orgId"
              AND s.metadata->>'licenseeId' IS NOT DISTINCT FROM pr."licenseeId"
          )) AS session_authorized
        FROM public."PrinterAttestation" pa
        JOIN registration pr ON pr.id=pa."printerRegistrationId"
        WHERE NOT (pa.metadata ? 'operation')
          AND (pa.metadata->>'source'='PERSISTENT_SESSION' OR NOT EXISTS (
            SELECT 1 FROM public."PrinterAgentSession" prior
            WHERE prior."registrationId"=pa."printerRegistrationId"
          ))
        ORDER BY pa."createdAt" DESC,pa.id DESC LIMIT 1
      )
      SELECT CASE WHEN pr.id IS NULL THEN jsonb_build_object(
        'connected',false,'trusted',false,'compatibilityMode',false,
        'eligibleForPrinting',false,'requiredForPrinting',true,
        'connectionClass','BLOCKED','stale',true,
        'securePrinterSession',false,'freshHelperHeartbeat',false,
        'helperConnection',false,'eligiblePrinter',false,
        'missingFields',jsonb_build_array('printerRegistration','freshHelperHeartbeat',
          'helperConnection','eligiblePrinter','securePrinterSession','selectedPrinter'),
        'registrationId',NULL,'lastHeartbeatAt',NULL,'ageSeconds',NULL,
        'error','No printer registration'
      ) ELSE (
        coalesce(pa.metadata,'{}'::jsonb)
        ||jsonb_build_object(
          'connected',CASE WHEN pa.metadata->>'source'='PERSISTENT_SESSION' THEN pa.session_authorized
            ELSE coalesce((pa.metadata->>'connected')::boolean,false)
              AND pa."expiresAt">transaction_timestamp() AND pa."trustValid" AND pa.session_authorized END,
          'printerAvailable',coalesce((pa.metadata->>'connected')::boolean,false) AND pa."expiresAt">transaction_timestamp(),
          'trusted',pr."trustStatus"='TRUSTED'::public."PrinterTrustStatus"
            AND pa."expiresAt">transaction_timestamp() AND pa."trustValid" AND pa."signatureValid" AND pa.session_authorized,
          'compatibilityMode',false,
          'requiredForPrinting',true,
          'eligibleForPrinting',pr."trustStatus"='TRUSTED'::public."PrinterTrustStatus"
            AND pa."expiresAt">transaction_timestamp() AND pa."trustValid" AND pa."signatureValid" AND pa.session_authorized
            AND coalesce((pa.metadata->>'connected')::boolean,false)
        AND (pa.metadata->>'source' IS DISTINCT FROM 'PERSISTENT_SESSION'
          OR pa.metadata->'printerHealth'->>'healthVersion'='1')
        AND NOT EXISTS (SELECT 1 FROM public."PrinterAttestation" newer
          WHERE newer."printerRegistrationId"=pa."printerRegistrationId"
            AND newer.metadata->>'source'='PERSISTENT_SESSION'
            AND (newer."createdAt",newer.id)>(pa."createdAt",pa.id))
            AND coalesce(pa.metadata->>'selectedPrinterId',pa.metadata->>'printerId','')<>'',
          'connectionClass',CASE WHEN pr."trustStatus"='TRUSTED'::public."PrinterTrustStatus"
            AND pa."expiresAt">transaction_timestamp() AND pa."trustValid" AND pa."signatureValid" AND pa.session_authorized
            THEN 'TRUSTED' ELSE 'BLOCKED' END,
          'stale',pa."expiresAt"<=transaction_timestamp() OR NOT pa.session_authorized,
          'securePrinterSession',pr."trustStatus"='TRUSTED'::public."PrinterTrustStatus"
            AND pa."expiresAt">transaction_timestamp() AND pa."trustValid" AND pa."signatureValid" AND pa.session_authorized,
          'freshHelperHeartbeat',pa."expiresAt">transaction_timestamp() AND pa.session_authorized,
          'helperConnection',CASE WHEN pa.metadata->>'source'='PERSISTENT_SESSION' THEN pa.session_authorized
            ELSE coalesce((pa.metadata->>'connected')::boolean,false)
              AND pa."expiresAt">transaction_timestamp() AND pa.session_authorized END,
          'eligiblePrinter',coalesce(pa.metadata->>'selectedPrinterId',pa.metadata->>'printerId','')<>'',
          'missingFields','[]'::jsonb,
          'registrationId',pr.id,'agentId',pr."agentId",
          'deviceFingerprint',pr."deviceFingerprint",'trustStatus',pr."trustStatus",
          'trustReason',CASE WHEN pa.session_authorized AND NOT coalesce((pa.metadata->>'connected')::boolean,false)
            THEN 'Selected printer health is unavailable or stale' ELSE pr."trustReason" END,'lastHeartbeatAt',pa."attestedAt",
          'ageSeconds',greatest(0,extract(epoch FROM transaction_timestamp()-pa."attestedAt")::integer),
          'signedAttestation',jsonb_build_object(
            'required',true,'present',true,'signatureValid',pa."signatureValid",
            'fresh',pa."expiresAt">transaction_timestamp() AND pa."trustValid" AND pa.session_authorized,
            'issuedAt',pa.metadata->>'heartbeatIssuedAt','rejectReason',pa."rejectionReason"
          ),
          'error',CASE WHEN pa.session_authorized AND NOT coalesce((pa.metadata->>'connected')::boolean,false)
            THEN 'Selected printer health is unavailable or stale'
            WHEN pa."trustValid" AND pa."expiresAt">transaction_timestamp() AND pa.session_authorized
            THEN NULL WHEN NOT pa.session_authorized THEN 'Persistent printer session disconnected'
            ELSE coalesce(pa."rejectionReason",pr."trustReason",'Printer attestation stale') END
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
        JOIN public."Batch" b ON b.id=j."batchId" AND b.id=r."batchId" AND b."licenseeId"=r."licenseeId"
        JOIN public."Licensee" l ON l.id=b."licenseeId" AND l."isActive" AND l."suspendedAt" IS NULL
        JOIN public."Organization" o ON o.id=l."orgId" AND o."isActive"
        JOIN public."Printer" p ON p.id=j."printerId"
        WHERE (nullif(p_options->>'status','') IS NULL OR r.status::text=p_options->>'status')
          AND (
            actor.role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')
            OR (actor.role='LICENSEE_ADMIN' AND r."licenseeId"=actor."licenseeId" AND l."orgId"=actor."organizationId")
            OR (actor.role='MANUFACTURER_ADMIN' AND r."requestedByUserId"=actor."userId"
              AND b."manufacturerId"=actor."userId" AND EXISTS (
                SELECT 1 FROM public."ManufacturerLicenseeLink" ml
                WHERE ml."manufacturerId"=actor."userId" AND ml."licenseeId"=b."licenseeId"
              ))
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

DO $postflight$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_proc p
    WHERE p.oid=to_regprocedure('app_rls.printing_create_job(text,text,text,text,text,integer,text,text,text,text,text,jsonb)')
      AND p.proowner=current_user::regrole AND p.prosecdef
      AND p.provolatile='v' AND p.proconfig=ARRAY['search_path=pg_catalog, public']
      AND current_user IN ('mscqr_prd_rls_phase2_auth_owner','mscqr_rls_cert_auth_owner')
      AND (SELECT count(*)=2
             AND count(*) FILTER (WHERE a.grantee=p.proowner AND a.grantor=p.proowner
               AND a.privilege_type='EXECUTE' AND NOT a.is_grantable)=1
             AND count(*) FILTER (WHERE a.grantee=(CASE current_user
               WHEN 'mscqr_prd_rls_phase2_auth_owner' THEN 'mscqr_prd_rls_phase2_app'
               ELSE 'mscqr_rls_cert_app' END)::regrole AND a.grantor=p.proowner
               AND a.privilege_type='EXECUTE' AND NOT a.is_grantable)=1
           FROM pg_catalog.aclexplode(coalesce(p.proacl,pg_catalog.acldefault('f',p.proowner))) a)
      AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')='c67095e4bd432af37b51a1a544923d056a3f3b790daaa0ea1c43321059a5a03a'
      AND encode(sha256(convert_to(pg_get_functiondef(p.oid),'UTF8')),'hex')='0f4d77a96f718d902a343ec991639ea05a04e5ce566beb80c5305616db3d9c60'
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_proc p
    WHERE p.oid=to_regprocedure('app_rls.printing_record_sample(text,text,text,text,text,jsonb)')
      AND p.proowner=current_user::regrole AND p.prosecdef
      AND p.provolatile='v' AND p.proconfig=ARRAY['search_path=pg_catalog, public']
      AND current_user IN ('mscqr_prd_rls_phase2_auth_owner','mscqr_rls_cert_auth_owner')
      AND (SELECT count(*)=2
             AND count(*) FILTER (WHERE a.grantee=p.proowner AND a.grantor=p.proowner
               AND a.privilege_type='EXECUTE' AND NOT a.is_grantable)=1
             AND count(*) FILTER (WHERE a.grantee=(CASE current_user
               WHEN 'mscqr_prd_rls_phase2_auth_owner' THEN 'mscqr_prd_rls_phase2_app'
               ELSE 'mscqr_rls_cert_app' END)::regrole AND a.grantor=p.proowner
               AND a.privilege_type='EXECUTE' AND NOT a.is_grantable)=1
           FROM pg_catalog.aclexplode(coalesce(p.proacl,pg_catalog.acldefault('f',p.proowner))) a)
      AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')='cca7c9eeaca4aabbcd4f8212bf0d18935ce2c9019137f2a3160863e153795dbc'
      AND encode(sha256(convert_to(pg_get_functiondef(p.oid),'UTF8')),'hex')='35f2c48107f58f0730401b0ca782726deaa2708a6246acd2aa960f1503ff2a27'
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_proc p
    WHERE p.oid=to_regprocedure('app_rls.printing_release_batch(text,text,text,text,text,text)')
      AND p.proowner=current_user::regrole AND p.prosecdef
      AND p.provolatile='v' AND p.proconfig=ARRAY['search_path=pg_catalog, public']
      AND current_user IN ('mscqr_prd_rls_phase2_auth_owner','mscqr_rls_cert_auth_owner')
      AND (SELECT count(*)=2
             AND count(*) FILTER (WHERE a.grantee=p.proowner AND a.grantor=p.proowner
               AND a.privilege_type='EXECUTE' AND NOT a.is_grantable)=1
             AND count(*) FILTER (WHERE a.grantee=(CASE current_user
               WHEN 'mscqr_prd_rls_phase2_auth_owner' THEN 'mscqr_prd_rls_phase2_app'
               ELSE 'mscqr_rls_cert_app' END)::regrole AND a.grantor=p.proowner
               AND a.privilege_type='EXECUTE' AND NOT a.is_grantable)=1
           FROM pg_catalog.aclexplode(coalesce(p.proacl,pg_catalog.acldefault('f',p.proowner))) a)
      AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')='09096b1fdaa91bd790d7ca41272848244a234fffa9fbfe01f9276b798f0e82ab'
      AND encode(sha256(convert_to(pg_get_functiondef(p.oid),'UTF8')),'hex')='3d6154abac6e5ddad3c4252b85e17359c1458e4eb46b8f767bae9242b2edf430'
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_proc p
    WHERE p.oid=to_regprocedure('app_rls.printing_readiness(text,text,text,text,text,jsonb)')
      AND p.proowner=current_user::regrole AND p.prosecdef
      AND p.provolatile='v' AND p.proconfig=ARRAY['search_path=pg_catalog, public']
      AND current_user IN ('mscqr_prd_rls_phase2_auth_owner','mscqr_rls_cert_auth_owner')
      AND (SELECT count(*)=2
             AND count(*) FILTER (WHERE a.grantee=p.proowner AND a.grantor=p.proowner
               AND a.privilege_type='EXECUTE' AND NOT a.is_grantable)=1
             AND count(*) FILTER (WHERE a.grantee=(CASE current_user
               WHEN 'mscqr_prd_rls_phase2_auth_owner' THEN 'mscqr_prd_rls_phase2_app'
               ELSE 'mscqr_rls_cert_app' END)::regrole AND a.grantor=p.proowner
               AND a.privilege_type='EXECUTE' AND NOT a.is_grantable)=1
           FROM pg_catalog.aclexplode(coalesce(p.proacl,pg_catalog.acldefault('f',p.proowner))) a)
      AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')='5acf5031c74368da3e26aa3d801411a1b31b409e2782e40f237777ddb8492266'
      AND encode(sha256(convert_to(pg_get_functiondef(p.oid),'UTF8')),'hex')='2413d9c3b14b933170ae19b03214291932ca9b4a7d5b1f689129c020f2abe5f1'
  ) THEN RAISE EXCEPTION 'PRINT_JOB_MIGRATION_SUCCESSOR_INVALID' USING ERRCODE='42501'; END IF;
END
$postflight$;

COMMIT;
