\set ON_ERROR_STOP on
BEGIN;

DO $preflight$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_proc p
    WHERE p.oid=to_regprocedure('app_rls.printing_create_job(text,text,text,text,text,integer,text,text,text,text,text,jsonb)')
      AND p.proowner=current_user::regrole AND p.prosecdef
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

COMMIT;
