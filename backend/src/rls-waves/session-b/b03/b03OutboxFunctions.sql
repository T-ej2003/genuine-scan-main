-- Historical TypeScript B03 stable JSON encoding. Private; no runtime grants.
CREATE OR REPLACE FUNCTION app_rls.b03_stable_json(p_value jsonb)
RETURNS text LANGUAGE plpgsql IMMUTABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE result text; value text; digits text; exponent integer; magnitude numeric;
BEGIN
  CASE jsonb_typeof(p_value)
  WHEN 'object' THEN
    SELECT '{'||coalesce(string_agg(to_json(k)::text||':'||app_rls.b03_stable_json(v),',' ORDER BY
      ARRAY(SELECT unnest(CASE WHEN ascii(c)>65535 THEN ARRAY[55296+(ascii(c)-65536)/1024,56320+(ascii(c)-65536)%1024] ELSE ARRAY[ascii(c)] END)
        FROM regexp_split_to_table(k,'') WITH ORDINALITY AS chars(c,n) ORDER BY n)), '')||'}'
    INTO result FROM jsonb_each(p_value) AS entries(k,v);
  WHEN 'array' THEN
    SELECT '['||coalesce(string_agg(app_rls.b03_stable_json(v),',' ORDER BY n),'')||']'
    INTO result FROM jsonb_array_elements(p_value) WITH ORDINALITY AS entries(v,n);
  WHEN 'number' THEN
    magnitude:=abs(p_value::text::numeric);
    IF magnitude=0 THEN RETURN '0'; END IF;
    value:=magnitude::text;
    IF magnitude>=0.000001 AND magnitude<1e21 THEN
      result:=CASE WHEN position('.' IN value)>0 THEN rtrim(rtrim(value,'0'),'.') ELSE value END;
    ELSE
      exponent:=floor(log(10,magnitude));
      digits:=rtrim(replace((magnitude/power(10::numeric,exponent))::text,'.',''),'0');
      result:=left(digits,1)||CASE WHEN length(digits)>1 THEN '.'||substr(digits,2) ELSE '' END||'e'||CASE WHEN exponent>=0 THEN '+' ELSE '' END||exponent::text;
    END IF;
    IF p_value::text::numeric<0 THEN result:='-'||result; END IF;
  ELSE result:=p_value::text;
  END CASE;
  RETURN result;
END
$fn$;

-- All producer bodies retain their existing RLS/actor checks. This trigger
-- only completes NEW, never reads or writes another row and grants no access.
CREATE OR REPLACE FUNCTION app_rls.b03_complete_audit_record()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE original_request text; expected_digest text; encoding text;
BEGIN
  IF TG_OP<>'INSERT' OR TG_TABLE_SCHEMA<>'public' OR TG_TABLE_NAME<>'AuditLogOutbox'
     OR NEW."authorityProvenance" IS NOT NULL OR NEW.payload->'details' ? 'auditRecovery' OR jsonb_typeof(NEW.payload) IS DISTINCT FROM 'object'
  THEN RAISE EXCEPTION 'B03_AUDIT_RECORD_DENIED' USING ERRCODE='42501'; END IF;
  original_request:=coalesce(NEW."requestId",nullif(current_setting('app.request_id',true),''),
    nullif(current_setting('app.b01_request_id',true),''),nullif(current_setting('app.scheduled_request_id',true),''));
  IF original_request IS NOT NULL AND (length(original_request) NOT BETWEEN 1 AND 128 OR original_request !~ '^[!-~]+$')
  THEN RAISE EXCEPTION 'B03_AUDIT_REQUEST_DENIED' USING ERRCODE='42501'; END IF;
  -- Bare SQL INSERT producers emit distinct events, not replay-aware requests.
  -- Use their immutable row ID; retain the original request only as provenance.
  NEW."requestId":=CASE WHEN (NEW."payloadDigest" IS NOT NULL OR NEW."idempotencyKey" IS NOT NULL) AND original_request ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    THEN lower(original_request) ELSE NEW.id END;
  encoding:=CASE WHEN current_setting('app.b03_outbox_operation',true)='audit-enqueue' AND current_setting('app.b03_outbox_id',true)=NEW.id THEN 'stable-json-v1' ELSE 'jsonb-text-v1' END;
  expected_digest:=encode(sha256(convert_to(CASE WHEN encoding='stable-json-v1' THEN app_rls.b03_stable_json(NEW.payload) ELSE NEW.payload::text END,'UTF8')),'hex');
  IF NEW."payloadDigest" IS NOT NULL AND NEW."payloadDigest" IS DISTINCT FROM expected_digest
  THEN RAISE EXCEPTION 'B03_AUDIT_DIGEST_MISMATCH' USING ERRCODE='23505'; END IF;
  NEW."payloadDigest":=expected_digest;
  expected_digest:=encode(sha256(convert_to('AUDIT_LOG_RECOVERY:'||NEW."requestId"||':'||NEW."payloadDigest",'UTF8')),'hex');
  IF NEW."idempotencyKey" IS NOT NULL AND NEW."idempotencyKey" IS DISTINCT FROM expected_digest
  THEN RAISE EXCEPTION 'B03_OUTBOX_REPLAY_MISMATCH' USING ERRCODE='23505'; END IF;
  NEW."idempotencyKey":=expected_digest;
  NEW."initiatingUserId":=coalesce(NEW."initiatingUserId",nullif(NEW.payload->>'userId',''));
  NEW."organizationId":=coalesce(NEW."organizationId",nullif(NEW.payload->>'orgId',''));
  NEW."licenseeId":=coalesce(NEW."licenseeId",nullif(NEW.payload->>'licenseeId',''));
  NEW."expiresAt":=coalesce(NEW."expiresAt",NEW."createdAt"+interval '1 day');
  IF NEW."jobType" IS DISTINCT FROM 'AUDIT_LOG_RECOVERY'
     OR NEW."requestId" !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
     OR (NEW."initiatingUserId" IS NULL AND NEW.payload->'details'->>'systemIdentity' IS DISTINCT FROM 'identity-scheduled-job')
     OR octet_length(NEW.payload::text)>65536 OR NEW."expiresAt"<=NEW."createdAt" OR coalesce(NEW.payload->>'action','')='' OR coalesce(NEW.payload->>'entityType','')=''
     OR (NEW.payload ? 'userId' AND NEW."initiatingUserId" IS DISTINCT FROM nullif(NEW.payload->>'userId',''))
     OR (NEW.payload ? 'orgId' AND NEW."organizationId" IS DISTINCT FROM nullif(NEW.payload->>'orgId',''))
     OR (NEW.payload ? 'licenseeId' AND NEW."licenseeId" IS DISTINCT FROM nullif(NEW.payload->>'licenseeId',''))
  THEN RAISE EXCEPTION 'B03_AUDIT_RECORD_DENIED' USING ERRCODE='42501'; END IF;
  NEW."authorityProvenance":=jsonb_build_object('version',1,'origin','producer','digestEncoding',encoding,
    'requestIdSource',CASE WHEN NEW."requestId"=lower(original_request) THEN 'original-request' ELSE 'new-event-id' END,
    'originalRequestId',original_request);
  RETURN NEW;
END
$fn$;

-- Exact persisted legacy shape. No request, actor, tenant or expiry is invented.
CREATE OR REPLACE FUNCTION app_rls.b03_audit_record_valid(p_record public."AuditLogOutbox")
RETURNS boolean LANGUAGE sql IMMUTABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
  SELECT coalesce(p_record."jobType"='AUDIT_LOG_RECOVERY'
    AND p_record."requestId" ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    AND jsonb_typeof(p_record.payload)='object' AND octet_length(p_record.payload::text)<=65536
    AND coalesce(p_record.payload->>'action','')<>'' AND coalesce(p_record.payload->>'entityType','')<>''
    AND (NOT p_record.payload ? 'userId' OR p_record."initiatingUserId" IS NOT DISTINCT FROM nullif(p_record.payload->>'userId',''))
    AND (NOT p_record.payload ? 'orgId' OR p_record."organizationId" IS NOT DISTINCT FROM nullif(p_record.payload->>'orgId',''))
    AND (NOT p_record.payload ? 'licenseeId' OR p_record."licenseeId" IS NOT DISTINCT FROM nullif(p_record.payload->>'licenseeId',''))
    AND (p_record."initiatingUserId" IS NOT NULL OR p_record.payload->'details'->>'systemIdentity'='identity-scheduled-job')
    AND p_record."expiresAt" IS NOT NULL
    AND CASE WHEN p_record."authorityProvenance" IS NULL THEN
      (p_record."payloadDigest" IS NULL AND p_record."idempotencyKey" IS NULL AND p_record."flushedAuditLogId" IS NULL AND p_record.attempts=0)
      OR (p_record."payloadDigest" IN (encode(sha256(convert_to(p_record.payload::text,'UTF8')),'hex'),
          encode(sha256(convert_to(app_rls.b03_stable_json(p_record.payload),'UTF8')),'hex'))
        AND p_record."idempotencyKey"=encode(sha256(convert_to('AUDIT_LOG_RECOVERY:'||p_record."requestId"||':'||p_record."payloadDigest",'UTF8')),'hex'))
    ELSE jsonb_typeof(p_record."authorityProvenance")='object'
      AND p_record."authorityProvenance"->'version'='1'::jsonb
      AND CASE WHEN p_record."authorityProvenance"->>'origin'='legacy-recovery' THEN
        (SELECT count(*) FROM jsonb_object_keys(CASE WHEN jsonb_typeof(p_record."authorityProvenance")='object' THEN p_record."authorityProvenance" ELSE '{}'::jsonb END))=8
        AND p_record."authorityProvenance"->'originalDigestPresent'='false'::jsonb
        AND p_record."authorityProvenance"->'recoveryDigestDerived'='true'::jsonb
        AND p_record."authorityProvenance"->'originalIdentityPresent'='false'::jsonb
        AND p_record."authorityProvenance"->>'recordId'=p_record.id
        AND jsonb_typeof(p_record."authorityProvenance"->'recoveredAt')='string'
      ELSE (SELECT count(*) FROM jsonb_object_keys(CASE WHEN jsonb_typeof(p_record."authorityProvenance")='object' THEN p_record."authorityProvenance" ELSE '{}'::jsonb END))=5
        AND CASE WHEN p_record."authorityProvenance"->>'requestIdSource'='original-request' THEN
          lower(p_record."authorityProvenance"->>'originalRequestId')=p_record."requestId"
        ELSE p_record."authorityProvenance"->>'requestIdSource'='new-event-id' AND p_record."requestId"=p_record.id END END
      AND p_record."authorityProvenance"->>'origin' IN ('producer','legacy-recovery')
      AND p_record."authorityProvenance"->>'digestEncoding' IN ('stable-json-v1','jsonb-text-v1')
      AND p_record."payloadDigest"=encode(sha256(convert_to(CASE WHEN p_record."authorityProvenance"->>'digestEncoding'='stable-json-v1'
        THEN app_rls.b03_stable_json(p_record.payload) ELSE p_record.payload::text END,'UTF8')),'hex')
      AND p_record."idempotencyKey"=encode(sha256(convert_to('AUDIT_LOG_RECOVERY:'||p_record."requestId"||':'||p_record."payloadDigest",'UTF8')),'hex') END,false)
$fn$;

REVOKE ALL ON FUNCTION app_rls.b03_stable_json(jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.b03_complete_audit_record() FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.b03_audit_record_valid(public."AuditLogOutbox") FROM PUBLIC;

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
     WHERE o."idempotencyKey"=p_idempotency_key AND o."payloadDigest"=p_payload_digest
       AND o."requestId"=p_request_id AND o."initiatingUserId" IS NOT DISTINCT FROM p_initiating_user_id
       AND o."organizationId" IS NOT DISTINCT FROM p_organization_id AND o."licenseeId" IS NOT DISTINCT FROM p_licensee_id
       AND o."manufacturerId" IS NOT DISTINCT FROM p_manufacturer_id
       AND o."initiatingActorRoleSnapshot" IS NOT DISTINCT FROM p_initiating_actor_role;
    IF NOT FOUND THEN RAISE EXCEPTION 'B03_OUTBOX_REPLAY_MISMATCH' USING ERRCODE='23505'; END IF;
  END IF;
  RETURN QUERY SELECT v_id;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.claim_audit_log_outbox_slice(p_attempted_at timestamp without time zone,p_batch_size integer)
RETURNS TABLE("id" text,"jobType" text,"requestId" text,"payloadDigest" text,"idempotencyKey" text,"organizationId" text,"licenseeId" text,"manufacturerId" text,"initiatingUserId" text,"expiresAt" timestamp without time zone,"attempt" integer)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE legacy_record record; recovered_digest text; recovered_key text;
BEGIN
  PERFORM app_rls.b03_bind_outbox_operation('audit-claim','',repeat('0',64));
  IF session_user<>{{WORKER_ROLE}} OR p_batch_size NOT BETWEEN 1 AND 250 OR abs(extract(epoch FROM (clock_timestamp()-p_attempted_at)))>60
  THEN RAISE EXCEPTION 'B03_OUTBOX_DENIED' USING ERRCODE='42501'; END IF;
  -- Each normalised row remains the same durable record. SKIP LOCKED and
  -- the surrounding worker transaction make concurrent recovery/claim atomic.
  FOR legacy_record IN
    SELECT q.id,q.payload,q."requestId",q."initiatingUserId",q."organizationId",q."licenseeId",q."manufacturerId",q."initiatingActorRoleSnapshot" FROM public."AuditLogOutbox" q
    WHERE q.status IN ('QUEUED','FAILED') AND q."authorityProvenance" IS NULL
      AND q."payloadDigest" IS NULL AND q."idempotencyKey" IS NULL
      AND coalesce(q."lastError",'') NOT IN ('B03_AUDIT_RECORD_DUPLICATE','B03_AUDIT_IDENTITY_COLLISION','B03_AUDIT_RECORD_UNRECONSTRUCTABLE')
      AND q."expiresAt">p_attempted_at AND app_rls.b03_audit_record_valid(q)
    ORDER BY q."createdAt",q.id FOR UPDATE SKIP LOCKED LIMIT p_batch_size
  LOOP
    recovered_digest:=encode(sha256(convert_to(legacy_record.payload::text,'UTF8')),'hex');
    recovered_key:=encode(sha256(convert_to('AUDIT_LOG_RECOVERY:'||legacy_record."requestId"||':'||recovered_digest,'UTF8')),'hex');
    -- Serialize only this identity. Hash collisions delay a retry, never merge records.
    IF NOT pg_try_advisory_xact_lock(hashtextextended(recovered_key,0)) THEN CONTINUE; END IF;
    IF EXISTS (SELECT 1 FROM public."AuditLogOutbox" q WHERE q."idempotencyKey"=recovered_key) THEN
      UPDATE public."AuditLogOutbox" AS q SET "lastError"=CASE WHEN EXISTS (
        SELECT 1 FROM public."AuditLogOutbox" existing WHERE existing."idempotencyKey"=recovered_key
          AND existing."initiatingUserId" IS NOT DISTINCT FROM legacy_record."initiatingUserId"
          AND existing."organizationId" IS NOT DISTINCT FROM legacy_record."organizationId"
          AND existing."licenseeId" IS NOT DISTINCT FROM legacy_record."licenseeId"
          AND existing."manufacturerId" IS NOT DISTINCT FROM legacy_record."manufacturerId"
          AND existing."initiatingActorRoleSnapshot" IS NOT DISTINCT FROM legacy_record."initiatingActorRoleSnapshot")
        THEN 'B03_AUDIT_RECORD_DUPLICATE' ELSE 'B03_AUDIT_IDENTITY_COLLISION' END WHERE q.id=legacy_record.id;
      CONTINUE;
    END IF;
    BEGIN
    UPDATE public."AuditLogOutbox" AS q SET "payloadDigest"=recovered_digest,"idempotencyKey"=recovered_key,
      "authorityProvenance"=jsonb_build_object('version',1,'origin','legacy-recovery','digestEncoding','jsonb-text-v1',
        'originalDigestPresent',false,'recoveryDigestDerived',true,'originalIdentityPresent',false,
        'recordId',legacy_record.id,'recoveredAt',p_attempted_at),"updatedAt"=transaction_timestamp()
      WHERE q.id=legacy_record.id;
    EXCEPTION WHEN unique_violation THEN
      UPDATE public."AuditLogOutbox" AS q SET "lastError"=CASE WHEN EXISTS (
        SELECT 1 FROM public."AuditLogOutbox" existing WHERE existing."idempotencyKey"=recovered_key
          AND existing."initiatingUserId" IS NOT DISTINCT FROM legacy_record."initiatingUserId"
          AND existing."organizationId" IS NOT DISTINCT FROM legacy_record."organizationId"
          AND existing."licenseeId" IS NOT DISTINCT FROM legacy_record."licenseeId"
          AND existing."manufacturerId" IS NOT DISTINCT FROM legacy_record."manufacturerId"
          AND existing."initiatingActorRoleSnapshot" IS NOT DISTINCT FROM legacy_record."initiatingActorRoleSnapshot")
        THEN 'B03_AUDIT_RECORD_DUPLICATE' ELSE 'B03_AUDIT_IDENTITY_COLLISION' END WHERE q.id=legacy_record.id;
    END;
  END LOOP;
  -- Invalid/expired records remain durable and visible; never mark SENT.
  WITH invalid AS (
    SELECT q.id FROM public."AuditLogOutbox" q WHERE q.status IN ('QUEUED','FAILED')
      AND (NOT app_rls.b03_audit_record_valid(q) OR q."expiresAt"<=p_attempted_at)
      AND q."lastError" IS DISTINCT FROM 'B03_AUDIT_RECORD_UNRECONSTRUCTABLE'
    ORDER BY q."createdAt",q.id FOR UPDATE SKIP LOCKED LIMIT p_batch_size
  ) UPDATE public."AuditLogOutbox" q SET "lastError"='B03_AUDIT_RECORD_UNRECONSTRUCTABLE'
    FROM invalid i WHERE q.id=i.id;
  RETURN QUERY WITH candidates AS (
    SELECT o.id FROM public."AuditLogOutbox" o
     WHERE o."payloadDigest" IS NOT NULL AND o."idempotencyKey" IS NOT NULL
       AND coalesce(o."lastError",'') NOT IN ('B03_AUDIT_RECORD_DUPLICATE','B03_AUDIT_IDENTITY_COLLISION','B03_AUDIT_RECORD_UNRECONSTRUCTABLE')
       AND app_rls.b03_audit_record_valid(o) AND o."jobType"='AUDIT_LOG_RECOVERY' AND o.status IN ('QUEUED','FAILED')
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
    q."initiatingUserId",q."expiresAt",q."claimLeaseExpiresAt",q.status,q."flushedAuditLogId",q."authorityProvenance", app_rls.b03_audit_record_valid(q) AS valid
    INTO o FROM public."AuditLogOutbox" q
    WHERE q.id=p_job_id AND q."payloadDigest"=p_payload_digest FOR UPDATE;
  IF NOT FOUND OR NOT o.valid OR o."expiresAt"<=p_attempted_at OR abs(extract(epoch FROM (clock_timestamp()-p_attempted_at)))>60
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
  VALUES (v_audit_id,o."initiatingUserId",o."organizationId",o."licenseeId",o.payload->>'action',o.payload->>'entityType',NULLIF(o.payload->>'entityId',''),CASE WHEN o."authorityProvenance"->>'origin'='legacy-recovery' THEN coalesce(o.payload->'details','{}'::jsonb)||jsonb_build_object('auditRecovery',o."authorityProvenance") ELSE o.payload->'details' END,NULLIF(o.payload->>'ipAddress',''),NULLIF(o.payload->>'ipHash',''),NULLIF(o.payload->>'userAgent',''));
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
RETURNS TABLE("id" text,"jobType" text,"requestId" text,"payloadDigest" text,"idempotencyKey" text,"organizationId" text,"licenseeId" text,"manufacturerId" text,"initiatingUserId" text,"expiresAt" timestamp without time zone,"attempt" integer,"eventType" text,"eventPayload" jsonb,"createdAt" timestamp without time zone,"projectionCompleted" boolean)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
BEGIN
  PERFORM app_rls.b03_bind_outbox_operation('security-claim','',repeat('0',64));
  IF session_user<>{{WORKER_ROLE}} OR p_job_type NOT IN ('AUDIT_LOG','CSP_VIOLATION') OR p_batch_size NOT BETWEEN 1 AND 200
     OR abs(extract(epoch FROM (clock_timestamp()-p_attempted_at)))>60
  THEN RAISE EXCEPTION 'B03_OUTBOX_DENIED' USING ERRCODE='42501'; END IF;
  RETURN QUERY WITH candidates AS (
    SELECT o.id FROM public."SecurityEventOutbox" o
    WHERE o."jobType"=p_job_type AND o.status IN ('QUEUED','FAILED')
      AND o."lastError" IS DISTINCT FROM 'SIEM_SINK_DISABLED'
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
      o."expiresAt",o.attempts,o."eventType",o.payload,o."createdAt",o."sinkEventId"='projection:'||o.id AS "projectionCompleted"
  )
  SELECT c.id,c."jobType",c."requestId",c."payloadDigest",c."idempotencyKey",
    c."organizationId",c."licenseeId",c."manufacturerId",c."initiatingUserId",
    c."expiresAt",c.attempts,c."eventType",c.payload,c."createdAt",coalesce(c."projectionCompleted",false)
  FROM claimed c;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.complete_security_event_outbox(p_job_id text,p_payload_digest text,p_attempted_at timestamp without time zone,p_sink_event_id text)
RETURNS TABLE("completed" boolean,"replayed" boolean) LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE o record;
BEGIN
  PERFORM app_rls.b03_bind_outbox_operation('security-complete',p_job_id,p_payload_digest);
  IF session_user<>{{WORKER_ROLE}} OR p_sink_event_id IS NULL OR length(p_sink_event_id) NOT BETWEEN 1 AND 191
     OR abs(extract(epoch FROM (clock_timestamp()-p_attempted_at)))>60
  THEN RAISE EXCEPTION 'B03_OUTBOX_DENIED' USING ERRCODE='42501'; END IF;
  SELECT q.id,q.status,q."sinkEventId",q."claimLeaseExpiresAt",q."lastError",q."eventType",q.payload
    INTO o FROM public."SecurityEventOutbox" q
    WHERE q.id=p_job_id AND q."payloadDigest"=p_payload_digest FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'B03_OUTBOX_DENIED' USING ERRCODE='42501'; END IF;
  IF o.status='SENT' OR o."lastError"='SIEM_SINK_DISABLED' THEN
    IF o."sinkEventId" IS DISTINCT FROM p_sink_event_id THEN RAISE EXCEPTION 'B03_OUTBOX_REPLAY_MISMATCH' USING ERRCODE='23505'; END IF;
    RETURN QUERY SELECT true,true; RETURN;
  END IF;
  IF o."claimLeaseExpiresAt" IS NULL OR o."claimLeaseExpiresAt"<p_attempted_at THEN RAISE EXCEPTION 'B03_OUTBOX_DENIED' USING ERRCODE='42501'; END IF;
  -- Existing fields distinguish internal completion from actual external delivery.
  IF p_sink_event_id='projection:'||p_job_id THEN
    IF o."eventType" IS DISTINCT FROM 'AUDIT_LOG' OR o.payload->>'entityType' IS DISTINCT FROM 'QrAllocationRequest'
       OR coalesce(o.payload->>'action','') NOT IN ('CREATE_QR_ALLOCATION_REQUEST','REJECT_QR_ALLOCATION_REQUEST')
    THEN RAISE EXCEPTION 'B03_OUTBOX_DENIED' USING ERRCODE='42501'; END IF;
    UPDATE public."SecurityEventOutbox" SET "sinkEventId"=p_sink_event_id,"updatedAt"=transaction_timestamp() WHERE id=p_job_id;
    RETURN QUERY SELECT true,coalesce(o."sinkEventId"=p_sink_event_id,false); RETURN;
  END IF;
  IF p_sink_event_id='disabled:'||p_job_id THEN
    IF o.payload->>'action' IN ('CREATE_QR_ALLOCATION_REQUEST','REJECT_QR_ALLOCATION_REQUEST')
       AND o."sinkEventId" IS DISTINCT FROM 'projection:'||p_job_id
    THEN RAISE EXCEPTION 'B03_OUTBOX_DENIED' USING ERRCODE='42501'; END IF;
    UPDATE public."SecurityEventOutbox" SET status='FAILED',"sentAt"=NULL,"sinkEventId"=p_sink_event_id,
      "lastError"='SIEM_SINK_DISABLED',"claimLeaseExpiresAt"=NULL,"updatedAt"=transaction_timestamp() WHERE id=p_job_id;
    RETURN QUERY SELECT true,false; RETURN;
  END IF;
  IF p_sink_event_id LIKE 'projection:%' OR p_sink_event_id LIKE 'disabled:%' THEN
    RAISE EXCEPTION 'B03_OUTBOX_DENIED' USING ERRCODE='42501';
  END IF;
  IF o.payload->>'action' IN ('CREATE_QR_ALLOCATION_REQUEST','REJECT_QR_ALLOCATION_REQUEST')
     AND o."sinkEventId" IS DISTINCT FROM 'projection:'||p_job_id
  THEN RAISE EXCEPTION 'B03_OUTBOX_DENIED' USING ERRCODE='42501'; END IF;
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
  UPDATE public."SecurityEventOutbox" SET status='FAILED',"lastError"=p_error_code,"nextAttemptAt"=v_next,"claimLeaseExpiresAt"=NULL,"updatedAt"=transaction_timestamp() WHERE id=p_job_id AND "payloadDigest"=p_payload_digest AND status<>'SENT' AND "lastError" IS DISTINCT FROM 'SIEM_SINK_DISABLED' AND attempts=p_attempt;
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
