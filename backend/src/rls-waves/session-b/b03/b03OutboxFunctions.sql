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
  IF session_user <> {{APP_ROLE}} OR current_setting('app.auth_session_verified',true)<>'1'
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
  IF session_user<>{{WORKER_ROLE}} OR p_batch_size NOT BETWEEN 1 AND 250 OR abs(extract(epoch FROM (clock_timestamp()-p_attempted_at)))>60
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
  IF session_user<>{{WORKER_ROLE}} THEN RAISE EXCEPTION 'B03_OUTBOX_DENIED' USING ERRCODE='42501'; END IF;
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
  IF session_user<>{{WORKER_ROLE}} OR p_attempt NOT BETWEEN 1 AND 10 OR p_error_code!~'^[A-Z0-9_]{1,128}$'
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
  IF session_user<>{{APP_ROLE}} OR current_setting('app.auth_session_verified',true)<>'1' OR p_event_type NOT IN ('AUDIT_LOG','CSP_VIOLATION')
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
  IF session_user<>{{WORKER_ROLE}} OR p_job_type NOT IN ('AUDIT_LOG','CSP_VIOLATION') OR p_batch_size NOT BETWEEN 1 AND 200
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
  IF session_user<>{{WORKER_ROLE}} OR length(p_sink_event_id) NOT BETWEEN 1 AND 191
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
  IF session_user<>{{WORKER_ROLE}} OR p_attempt NOT BETWEEN 1 AND 10 OR p_error_code!~'^[A-Z0-9_]{1,128}$'
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
