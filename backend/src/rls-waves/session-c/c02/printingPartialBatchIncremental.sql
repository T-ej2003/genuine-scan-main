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
      AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')='41a94c32bc9eda53bb975560b62cd7e98eb98cc3c8fb5593dd6dbda90ad96884'
      AND encode(sha256(convert_to(pg_get_functiondef(p.oid),'UTF8')),'hex')='b8c528c3fa290d74e21417172668646e0b1f0e4e5d412ca312d54d6b89c31996'
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
      AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')='e004b27f2771512fcbb32eef3e2df65f624088c7b010669c4b63dfd0ab794a53'
      AND encode(sha256(convert_to(pg_get_functiondef(p.oid),'UTF8')),'hex')='63d3d14a35547cad3bb37baa8830a5c56122e557d5a06a70926a26ea5fe0d576'
  ) THEN RAISE EXCEPTION 'PRINT_JOB_MIGRATION_SUCCESSOR_INVALID' USING ERRCODE='42501'; END IF;
END
$postflight$;

COMMIT;
