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
  IF session_user<>{{WORKER_ROLE}} OR p_request_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' THEN
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
  IF session_user<>{{WORKER_ROLE}} OR p_request_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' THEN
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
