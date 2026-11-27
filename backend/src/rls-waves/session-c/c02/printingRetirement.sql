-- One approval owns one committed original attempt. Retirement never releases the device fence.
CREATE OR REPLACE FUNCTION app_rls.printing_retirement(
  p_capability text,p_request_id text,p_operation text,p_job_id text,p_item_id text,p_reason text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public
AS $fn$
DECLARE
  actor record; job_row record; item_row record; approval record;
  device_id text; registration_id text; attempt_id text; proof jsonb; approval_id text;
  now_at timestamp:=transaction_timestamp();
BEGIN
  IF p_operation NOT IN ('LIST','REQUEST','APPROVE','REJECT')
    OR p_job_id IS NULL OR p_job_id !~* '^[0-9a-f-]{36}$'
    OR (p_operation<>'LIST' AND (p_item_id IS NULL OR p_item_id !~* '^[0-9a-f-]{36}$'
      OR length(coalesce(btrim(p_reason),'')) NOT BETWEEN 8 AND 500))
  THEN RAISE EXCEPTION 'PRINTING_INVALID_INPUT'; END IF;

  SELECT * INTO STRICT actor FROM app_rls.printing_bind_actor(p_capability,'printing-job-control',p_request_id,NULL);
  PERFORM set_config('app.printing_job_id',p_job_id,true);
  SELECT j."printerId",j."batchId",j."manufacturerId" INTO job_row FROM public."PrintJob" j WHERE j.id=p_job_id;
  IF NOT FOUND THEN RAISE EXCEPTION 'PRINTING_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;
  SELECT * INTO STRICT actor FROM app_rls.printing_bind_actor(p_capability,'printing-job-control',p_request_id,job_row."batchId");
  IF actor.role NOT IN ('MANUFACTURER_ADMIN','LICENSEE_ADMIN')
    OR (actor.role='MANUFACTURER_ADMIN' AND job_row."manufacturerId"<>actor."userId")
    OR (p_operation='REQUEST' AND actor.role<>'MANUFACTURER_ADMIN')
    OR (p_operation IN ('APPROVE','REJECT') AND actor.role<>'LICENSEE_ADMIN')
  THEN RAISE EXCEPTION 'PRINTING_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;

  device_id:=job_row."printerId";
  IF p_operation<>'LIST' THEN
    IF device_id IS NULL THEN RAISE EXCEPTION 'PHYSICAL_OUTCOME_UNCONFIRMED'; END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('printing_printer_'||device_id,0));
  END IF;
  PERFORM set_config('app.printing_job_id',p_job_id,true),
    set_config('app.printing_operation','printing-qr-retirement',true);
  SELECT j.status,j."pipelineState",j."printMode",j."batchId",j."manufacturerId",j."printerId"
    INTO STRICT job_row FROM public."PrintJob" j WHERE j.id=p_job_id;
  IF job_row."printerId" IS DISTINCT FROM device_id
    OR job_row."manufacturerId" IS DISTINCT FROM actor."batchManufacturerId"
  THEN RAISE EXCEPTION 'PRINTING_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;

  SELECT ps.id INTO STRICT approval FROM public."PrintSession" ps WHERE ps."printJobId"=p_job_id;
  PERFORM set_config('app.printing_session_row_id',approval.id,true);
  SELECT ps.id,ps."printerRegistrationId" INTO STRICT approval FROM public."PrintSession" ps
    WHERE ps.id=approval.id AND ps."batchId"=job_row."batchId"
      AND ps."manufacturerId"=job_row."manufacturerId" AND ps."printerId"=device_id
      AND ps."printerRegistrationId" IS NOT NULL;
  registration_id:=approval."printerRegistrationId";

  IF p_operation='LIST' THEN
    RETURN (SELECT coalesce(jsonb_agg(entry ORDER BY entry->>'itemId'),'[]'::jsonb)
      FROM (
        SELECT jsonb_build_object('itemId',pi.id,'serial',q."displayCode",'status',coalesce(a.status,'UNREQUESTED'),
          'requestReason',a.reason,'canRequest',a.id IS NULL AND actor.role='MANUFACTURER_ADMIN' AND eligibility.allowed,
          'canReject',coalesce(a.status='PENDING' AND actor.role='LICENSEE_ADMIN' AND a."requestedByUserId"<>actor."userId",false),
          'canApprove',coalesce(a.status='PENDING' AND actor.role='LICENSEE_ADMIN'
            AND a."requestedByUserId"<>actor."userId" AND eligibility.allowed,false)) AS entry
        FROM public."PrintItem" pi JOIN public."QRCode" q ON q.id=pi."qrCodeId"
        LEFT JOIN LATERAL (
          SELECT sa.id,sa.status,sa."requestedByUserId",sa.payload->>'reason' AS reason
          FROM public."SensitiveActionApproval" sa WHERE sa."actionKey"='PRINT_QR_RETIREMENT'
            AND sa."entityType"='PrintItem' AND sa."entityId"=pi.id AND sa."licenseeId"=actor."batchLicenseeId"
            AND sa.payload->'binding'=jsonb_build_object('jobId',p_job_id,'sessionId',approval.id,'qrId',q.id,
              'printerId',device_id,'registrationId',registration_id,'attemptId',pi."dispatchMetadata"->>'attemptId',
              'payloadHash',pi."dispatchMetadata"->>'payloadHash')
            AND (sa.status IN ('REJECTED','EXECUTED') OR sa."expiresAt">now_at)
          ORDER BY sa."createdAt" DESC,sa.id DESC LIMIT 1
        ) a ON TRUE
        CROSS JOIN LATERAL (SELECT coalesce(job_row.status IN ('PAUSED','STOPPED')
          AND job_row."pipelineState"='NEEDS_OPERATOR_ACTION' AND job_row."printMode"='LOCAL_AGENT'
          AND pi.state IN ('ISSUED','AGENT_ACKED','FROZEN') AND pi."dispatchedAt" IS NOT NULL
          AND pi."printConfirmedAt" IS NULL AND q.status='ACTIVATED' AND q."printedAt" IS NULL
          AND q."customerVerifiableAt" IS NULL
          AND coalesce(pi."confirmationEvidence",'null'::jsonb) IN ('null'::jsonb,'{}'::jsonb)
          AND pi."dispatchMetadata"->>'dispatchEvidenceVersion'='1'
          AND pi."dispatchMetadata"->>'attemptId' IS NOT NULL
          AND pi."dispatchMetadata"->>'payloadHash' ~ '^[a-f0-9]{64}$',false) AS allowed) eligibility
        WHERE pi."printSessionId"=approval.id AND (p_item_id IS NULL OR pi.id>p_item_id)
          AND q."printJobId"=p_job_id AND q."batchId"=job_row."batchId" AND q."licenseeId"=actor."batchLicenseeId"
          AND (a.id IS NOT NULL OR (actor.role='MANUFACTURER_ADMIN' AND eligibility.allowed))
        ORDER BY pi.id LIMIT 50
      ) candidates);
  END IF;

  PERFORM 1 FROM public."PrintJob" j WHERE j.id=p_job_id FOR UPDATE;
  PERFORM 1 FROM public."PrintSession" ps WHERE ps.id=approval.id FOR UPDATE;
  PERFORM set_config('app.printing_item_id',p_item_id,true);
  SELECT pi.id,pi.state,pi."qrCodeId",pi."dispatchedAt",pi."printConfirmedAt",pi."dispatchMetadata",pi."confirmationEvidence",
    q.status AS qr_status,q."printedAt",q."customerVerifiableAt"
    INTO item_row FROM public."PrintItem" pi JOIN public."QRCode" q ON q.id=pi."qrCodeId"
    WHERE pi.id=p_item_id AND pi."printSessionId"=approval.id
      AND q."printJobId"=p_job_id AND q."batchId"=job_row."batchId" AND q."licenseeId"=actor."batchLicenseeId"
    FOR UPDATE OF pi,q;
  IF NOT FOUND THEN RAISE EXCEPTION 'PRINTING_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;
  attempt_id:=item_row."dispatchMetadata"->>'attemptId';
  proof:=jsonb_build_object('jobId',p_job_id,'sessionId',approval.id,'qrId',item_row."qrCodeId",
     'printerId',device_id,'registrationId',registration_id,'attemptId',attempt_id,'payloadHash',item_row."dispatchMetadata"->>'payloadHash');
  SELECT sa.id,sa.status,sa."requestedByUserId",sa.payload INTO approval
    FROM public."SensitiveActionApproval" sa WHERE sa."actionKey"='PRINT_QR_RETIREMENT'
      AND sa."entityType"='PrintItem' AND sa."entityId"=p_item_id AND sa."licenseeId"=actor."batchLicenseeId"
      AND sa.payload->'binding'=proof
      AND (sa.status IN ('REJECTED','EXECUTED') OR sa."expiresAt">now_at)
    ORDER BY sa."createdAt" DESC,sa.id DESC LIMIT 1 FOR UPDATE;

  IF p_operation='REQUEST' AND approval.id IS NOT NULL
     OR (p_operation='APPROVE' AND approval.status='EXECUTED')
     OR (p_operation='REJECT' AND approval.status='REJECTED')
  THEN RETURN jsonb_build_object('id',approval.id,'status',approval.status,'idempotent',true); END IF;
  IF p_operation<>'REQUEST' AND (approval.id IS NULL OR approval.status<>'PENDING'
    OR approval."requestedByUserId"=actor."userId") THEN RAISE EXCEPTION 'INVALID_STATE_TRANSITION'; END IF;
  IF p_operation<>'REJECT' AND (
    job_row.status NOT IN ('PAUSED','STOPPED') OR job_row."pipelineState"<>'NEEDS_OPERATOR_ACTION'
    OR job_row."printMode"<>'LOCAL_AGENT' OR item_row.state NOT IN ('ISSUED','AGENT_ACKED','FROZEN')
    OR item_row."dispatchedAt" IS NULL OR item_row."printConfirmedAt" IS NOT NULL
    OR coalesce(item_row."confirmationEvidence",'null'::jsonb) NOT IN ('null'::jsonb,'{}'::jsonb)
    OR item_row.qr_status<>'ACTIVATED' OR item_row."printedAt" IS NOT NULL OR item_row."customerVerifiableAt" IS NOT NULL
    OR item_row."dispatchMetadata"->>'dispatchEvidenceVersion' IS DISTINCT FROM '1'
    OR attempt_id IS NULL OR item_row."dispatchMetadata"->>'payloadHash' IS NULL
    OR item_row."dispatchMetadata"->>'payloadHash' !~ '^[a-f0-9]{64}$'
  ) THEN RAISE EXCEPTION 'PHYSICAL_OUTCOME_UNCONFIRMED'; END IF;

  approval_id:=coalesce(approval.id,gen_random_uuid()::text);
  PERFORM set_config('app.printing_retirement_approval_id',approval_id,true);
  IF p_operation='REQUEST' THEN
    INSERT INTO public."SensitiveActionApproval"(
      id,"actionKey",status,"requestedByUserId","licenseeId","entityType","entityId",payload,"expiresAt","createdAt","updatedAt"
    ) VALUES (approval_id,'PRINT_QR_RETIREMENT','PENDING',actor."userId",actor."batchLicenseeId",'PrintItem',p_item_id,
      jsonb_build_object('binding',proof,'attemptId',attempt_id,'reason',btrim(p_reason)),now_at+interval '7 days',now_at,now_at);
  ELSE
    IF p_operation='APPROVE' THEN
      UPDATE public."QRCode" SET status='BLOCKED',"blockedAt"=now_at,"updatedAt"=now_at WHERE id=item_row."qrCodeId";
      UPDATE public."PrintItem" SET state='CANCELLED',"pipelineState"='NEEDS_OPERATOR_ACTION',
        "failureReason"='historical_physical_outcome_unknown_qr_retired',"updatedAt"=now_at WHERE id=p_item_id;
    END IF;
    UPDATE public."SensitiveActionApproval" SET status=CASE WHEN p_operation='APPROVE' THEN 'EXECUTED' ELSE 'REJECTED' END,
      "reviewedByUserId"=actor."userId","reviewedAt"=now_at,
      "executedByUserId"=CASE WHEN p_operation='APPROVE' THEN actor."userId" END,
      "executedAt"=CASE WHEN p_operation='APPROVE' THEN now_at END,"updatedAt"=now_at WHERE id=approval_id;
  END IF;
  PERFORM app_rls.printing_write_audit(actor."userId",actor.role,actor."organizationId",actor."batchLicenseeId",
    'PRINT_QR_RETIREMENT_'||p_operation,'PrintJob',p_job_id,
    jsonb_build_object('approvalId',approval_id,'binding',proof,'historicalPhysicalOutcome','UNKNOWN','reason',btrim(p_reason)));
  IF p_operation='APPROVE' THEN
    INSERT INTO public."Notification"(id,"userId",audience,channel,type,title,body,data,"updatedAt")
      SELECT gen_random_uuid()::text,u.id,'SUPER_ADMIN','WEB','print_qr_retired',
        'QR label retired','The licensee approved retirement of a label with unknown physical output.',
        jsonb_build_object('approvalId',approval_id,'jobId',p_job_id,'batchId',job_row."batchId"),now_at
      FROM public."User" u WHERE u.role='SUPER_ADMIN' AND u."isActive" AND u.status='ACTIVE'
        AND u."disabledAt" IS NULL AND u."deletedAt" IS NULL;
  END IF;
  RETURN jsonb_build_object('id',approval_id,
    'status',CASE p_operation WHEN 'APPROVE' THEN 'EXECUTED' WHEN 'REJECT' THEN 'REJECTED' ELSE 'PENDING' END,
    'idempotent',false);
END
$fn$;
