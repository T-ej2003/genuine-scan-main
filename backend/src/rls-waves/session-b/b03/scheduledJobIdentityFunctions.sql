-- Database-verifiable scheduled compliance identity. Template role names are
-- replaced only by the clean-room package generator.

CREATE OR REPLACE FUNCTION app_rls.scheduled_job_prepare(
  p_capability text,
  p_schedule_id text,
  p_operation text,
  p_request_id text
) RETURNS text
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE capability_hash text; credential record;
BEGIN
  IF session_user <> {{SCHEDULED_ROLE}}
     OR p_capability !~ '^[A-Za-z0-9_-]{43}$'
     OR p_schedule_id !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
     OR p_operation NOT IN ('claim','get','complete','fail')
     OR p_request_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  THEN RAISE EXCEPTION 'SCHEDULED_JOB_IDENTITY_DENIED' USING ERRCODE='42501'; END IF;

  capability_hash:=encode(sha256(convert_to(p_capability,'UTF8')),'hex');
  PERFORM set_config('app.scheduled_verified','',true),
          set_config('app.scheduled_credential_id','',true),
          set_config('app.scheduled_capability_hash',capability_hash,true),
          set_config('app.scheduled_family','compliance-pack',true),
          set_config('app.scheduled_schedule_id',p_schedule_id,true),
          set_config('app.scheduled_operation',p_operation,true),
          set_config('app.scheduled_request_id',lower(p_request_id),true),
          set_config('app.scheduled_licensee_id','',true),
          set_config('app.scheduled_job_id','',true),
          set_config('app.system_identity','identity-scheduled-job',true),
          set_config('app.user_id','',true),
          set_config('app.role','',true),
          set_config('app.organization_id','',true),
          set_config('app.licensee_id','',true),
          set_config('app.manufacturer_id','',true),
          set_config('app.auth_assurance','system-verified',true),
          set_config('app.request_id',lower(p_request_id),true);

  UPDATE public."ScheduledJobCredential" c
     SET "lastUsedAt"=transaction_timestamp(),"updatedAt"=transaction_timestamp()
   WHERE c."capabilityHash"=capability_hash
     AND c."capabilityHashVersion"='sha256-v1'
     AND c."identityName"='identity-scheduled-job'
     AND c."jobFamily"='compliance-pack'
     AND c."scheduleId"=p_schedule_id
     AND c."revokedAt" IS NULL
     AND c."expiresAt">clock_timestamp()
   RETURNING c.id INTO credential;
  IF NOT FOUND THEN RAISE EXCEPTION 'SCHEDULED_JOB_IDENTITY_DENIED' USING ERRCODE='42501'; END IF;

  PERFORM set_config('app.scheduled_credential_id',credential.id,true),
          set_config('app.scheduled_verified','1',true);
  RETURN credential.id;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.provision_scheduled_job_credential(
  p_credential_id text,
  p_schedule_id text,
  p_capability_hash text,
  p_expires_at timestamptz,
  p_rotated_from_credential_id text,
  p_request_id text
) RETURNS text
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
BEGIN
  IF session_user <> {{OPERATOR_ROLE}}
     OR p_credential_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
     OR p_schedule_id !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
     OR p_capability_hash !~ '^[0-9a-f]{64}$'
     OR p_expires_at<=transaction_timestamp()+interval '5 minutes'
     OR p_expires_at>transaction_timestamp()+interval '370 days'
     OR p_request_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  THEN RAISE EXCEPTION 'SCHEDULED_JOB_PROVISION_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM set_config('app.scheduled_admin_operation','provision',true),
          set_config('app.scheduled_capability_hash',p_capability_hash,true),
          set_config('app.scheduled_schedule_id',p_schedule_id,true),
          set_config('app.scheduled_request_id',lower(p_request_id),true);
  IF p_rotated_from_credential_id IS NOT NULL THEN
    UPDATE public."ScheduledJobCredential"
       SET "revokedAt"=transaction_timestamp(),"revokedReason"='ROTATED',"updatedAt"=transaction_timestamp()
     WHERE id=p_rotated_from_credential_id AND "identityName"='identity-scheduled-job'
       AND "jobFamily"='compliance-pack' AND "scheduleId"=p_schedule_id AND "revokedAt" IS NULL;
    IF NOT FOUND THEN RAISE EXCEPTION 'SCHEDULED_JOB_ROTATION_DENIED' USING ERRCODE='42501'; END IF;
  END IF;
  INSERT INTO public."ScheduledJobCredential"
    (id,"identityName","jobFamily","scheduleId","capabilityHash","capabilityHashVersion","expiresAt","rotatedFromCredentialId","updatedAt")
  VALUES (p_credential_id,'identity-scheduled-job','compliance-pack',p_schedule_id,p_capability_hash,'sha256-v1',p_expires_at,p_rotated_from_credential_id,transaction_timestamp());
  RETURN p_credential_id;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.revoke_scheduled_job_credential(
  p_credential_id text,p_reason text,p_request_id text
) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
BEGIN
  IF session_user <> {{OPERATOR_ROLE}}
     OR p_credential_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
     OR p_reason !~ '^[A-Z][A-Z0-9_]{2,63}$'
     OR p_request_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  THEN RAISE EXCEPTION 'SCHEDULED_JOB_REVOKE_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM set_config('app.scheduled_admin_operation','revoke',true),
          set_config('app.scheduled_request_id',lower(p_request_id),true);
  UPDATE public."ScheduledJobCredential"
     SET "revokedAt"=coalesce("revokedAt",transaction_timestamp()),
         "revokedReason"=coalesce("revokedReason",p_reason),"updatedAt"=transaction_timestamp()
   WHERE id=p_credential_id AND "identityName"='identity-scheduled-job';
  RETURN FOUND;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.scheduled_job_queue_audit(
  p_action text,p_job_id text,p_licensee_id text,p_details jsonb
) RETURNS void
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
  INSERT INTO public."AuditLogOutbox" (id,payload,"updatedAt") VALUES (
    gen_random_uuid()::text,
    jsonb_build_object('userId',NULL,'orgId',NULL,'licenseeId',p_licensee_id,
      'action',p_action,'entityType','CompliancePackJob','entityId',p_job_id,
      'details',coalesce(p_details,'{}'::jsonb)||jsonb_build_object(
        'requestId',current_setting('app.scheduled_request_id',true),
        'systemIdentity','identity-scheduled-job',
        'scheduleId',current_setting('app.scheduled_schedule_id',true),
        'credentialId',current_setting('app.scheduled_credential_id',true))),
    transaction_timestamp())
$fn$;

CREATE OR REPLACE FUNCTION app_rls.claim_compliance_pack_slice(
  p_capability text,p_schedule_id text,p_due_at timestamp without time zone,p_batch_size integer
) RETURNS TABLE("jobId" text,"requestId" text,"organizationId" text,"licenseeId" text,
  "scheduleScopeVersion" text,"expiresAt" timestamp without time zone,"attempt" integer,"report" jsonb)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE licensee record; job_id text; request_id text; replay_key text; inserted integer; report_value jsonb;
BEGIN
  IF p_batch_size<1 OR p_batch_size>100 OR p_due_at>transaction_timestamp()+interval '5 minutes'
     OR p_due_at<transaction_timestamp()-interval '24 hours'
  THEN RAISE EXCEPTION 'SCHEDULED_COMPLIANCE_CLAIM_INVALID' USING ERRCODE='22023'; END IF;
  request_id:=gen_random_uuid()::text;
  PERFORM app_rls.scheduled_job_prepare(p_capability,p_schedule_id,'claim',request_id);
  FOR licensee IN
    SELECT l.id,l."orgId" FROM public."Licensee" l
    JOIN public."Organization" o ON o.id=l."orgId"
    WHERE l."isActive" AND l."suspendedAt" IS NULL AND o."isActive"
    ORDER BY l.id LIMIT p_batch_size
  LOOP
    PERFORM set_config('app.scheduled_licensee_id',licensee.id,true),
            set_config('app.licensee_id',licensee.id,true),
            set_config('app.organization_id',licensee."orgId",true);
    replay_key:=encode(sha256(convert_to('scheduled-compliance|'||p_schedule_id||'|'||date_trunc('day',p_due_at)::text||'|'||licensee.id,'UTF8')),'hex');
    INSERT INTO public."ActionIdempotencyKey" (id,"keyHash",action,scope,"requestHash","expiresAt")
    VALUES (gen_random_uuid()::text,replay_key,'scheduled-compliance-pack',licensee.id,
      encode(sha256(convert_to(p_schedule_id||'|'||date_trunc('day',p_due_at)::text,'UTF8')),'hex'),p_due_at+interval '48 hours')
    ON CONFLICT ("keyHash") DO NOTHING;
    GET DIAGNOSTICS inserted=ROW_COUNT;
    IF inserted=0 THEN CONTINUE; END IF;
    job_id:=gen_random_uuid()::text;
    request_id:=gen_random_uuid()::text;
    PERFORM set_config('app.scheduled_job_id',job_id,true),set_config('app.scheduled_request_id',request_id,true);
    INSERT INTO public."CompliancePackJob"
      (id,"licenseeId",status,"triggerType","scheduledScheduleId","periodFrom","periodTo","startedByUserId","startedAt","updatedAt")
    VALUES (job_id,licensee.id,'RUNNING','SCHEDULED',p_schedule_id,p_due_at-interval '24 hours',p_due_at,NULL,transaction_timestamp(),transaction_timestamp());
    report_value:=app_rls.c03_build_compliance_report(licensee.id,p_due_at-interval '24 hours',p_due_at);
    UPDATE public."ActionIdempotencyKey" SET "statusCode"=200,
      "responsePayload"=jsonb_build_object('jobId',job_id,'requestId',request_id),"completedAt"=transaction_timestamp()
      WHERE "keyHash"=replay_key;
    PERFORM app_rls.scheduled_job_queue_audit('COMPLIANCE_PACK_STARTED',job_id,licensee.id,jsonb_build_object('triggerType','SCHEDULED'));
    "jobId":=job_id; "requestId":=request_id; "organizationId":=licensee."orgId"; "licenseeId":=licensee.id;
    "scheduleScopeVersion":=encode(sha256(convert_to(licensee.id||'|'||licensee."orgId"||'|active','UTF8')),'hex');
    "expiresAt":=p_due_at+interval '24 hours'; "attempt":=1; "report":=report_value;
    RETURN NEXT;
  END LOOP;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.scheduled_get_compliance_pack_job(
  p_capability text,p_schedule_id text,p_request_id text,p_job_id text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE job record; report_value jsonb;
BEGIN
  PERFORM app_rls.scheduled_job_prepare(p_capability,p_schedule_id,'get',p_request_id);
  PERFORM set_config('app.scheduled_job_id',p_job_id,true);
  SELECT j."licenseeId",j."periodFrom",j."periodTo" INTO job
    FROM public."CompliancePackJob" j
    WHERE j.id=p_job_id AND j."triggerType"='SCHEDULED' AND j."scheduledScheduleId"=p_schedule_id;
  IF NOT FOUND OR job."licenseeId" IS NULL THEN RAISE EXCEPTION 'SCHEDULED_COMPLIANCE_JOB_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM set_config('app.scheduled_licensee_id',job."licenseeId",true),set_config('app.licensee_id',job."licenseeId",true);
  report_value:=app_rls.c03_build_compliance_report(job."licenseeId",job."periodFrom",job."periodTo");
  RETURN jsonb_build_object('job',app_rls.c03_compliance_job_projection(p_job_id),'report',report_value);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.scheduled_complete_compliance_pack_job(
  p_capability text,p_schedule_id text,p_request_id text,p_job_id text,p_result jsonb
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE job record;
BEGIN
  IF jsonb_typeof(p_result)<>'object' OR p_result->>'fileName' IS NULL OR p_result->>'storageKey' IS NULL
     OR p_result->>'integrityHash' !~ '^[0-9a-f]{64}$' OR octet_length(p_result::text)>65536
  THEN RAISE EXCEPTION 'SCHEDULED_COMPLIANCE_RESULT_INVALID' USING ERRCODE='22023'; END IF;
  PERFORM app_rls.scheduled_job_prepare(p_capability,p_schedule_id,'complete',p_request_id);
  PERFORM set_config('app.scheduled_job_id',p_job_id,true);
  UPDATE public."CompliancePackJob" SET status='COMPLETED',"fileName"=p_result->>'fileName',"storageKey"=p_result->>'storageKey',
    "integrityHash"=p_result->>'integrityHash',"signatureAlgorithm"=p_result->>'signatureAlgorithm',summary=p_result,
    "finishedAt"=transaction_timestamp(),"updatedAt"=transaction_timestamp()
    WHERE id=p_job_id AND "triggerType"='SCHEDULED' AND "scheduledScheduleId"=p_schedule_id AND status='RUNNING'
    RETURNING id,"licenseeId","storageKey" INTO job;
  IF NOT FOUND THEN RAISE EXCEPTION 'SCHEDULED_COMPLIANCE_TRANSITION_DENIED' USING ERRCODE='40001'; END IF;
  PERFORM set_config('app.scheduled_licensee_id',job."licenseeId",true),set_config('app.licensee_id',job."licenseeId",true);
  PERFORM app_rls.scheduled_job_queue_audit('COMPLIANCE_PACK_COMPLETED',job.id,job."licenseeId",jsonb_build_object('storageKey',job."storageKey"));
  RETURN app_rls.c03_compliance_job_projection(p_job_id);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.scheduled_fail_compliance_pack_job(
  p_capability text,p_schedule_id text,p_request_id text,p_job_id text,p_error_code text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE job record;
BEGIN
  IF p_error_code !~ '^[A-Z][A-Z0-9_]{2,127}$' THEN RAISE EXCEPTION 'SCHEDULED_COMPLIANCE_ERROR_INVALID' USING ERRCODE='22023'; END IF;
  PERFORM app_rls.scheduled_job_prepare(p_capability,p_schedule_id,'fail',p_request_id);
  PERFORM set_config('app.scheduled_job_id',p_job_id,true);
  UPDATE public."CompliancePackJob" SET status='FAILED',"errorMessage"=p_error_code,"finishedAt"=transaction_timestamp(),"updatedAt"=transaction_timestamp()
    WHERE id=p_job_id AND "triggerType"='SCHEDULED' AND "scheduledScheduleId"=p_schedule_id AND status='RUNNING'
    RETURNING id,"licenseeId" INTO job;
  IF NOT FOUND THEN RAISE EXCEPTION 'SCHEDULED_COMPLIANCE_TRANSITION_DENIED' USING ERRCODE='40001'; END IF;
  PERFORM set_config('app.scheduled_licensee_id',job."licenseeId",true),set_config('app.licensee_id',job."licenseeId",true);
  PERFORM app_rls.scheduled_job_queue_audit('COMPLIANCE_PACK_FAILED',job.id,job."licenseeId",jsonb_build_object('errorCode',p_error_code));
  RETURN app_rls.c03_compliance_job_projection(p_job_id);
END
$fn$;

REVOKE ALL ON FUNCTION app_rls.scheduled_job_prepare(text,text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.provision_scheduled_job_credential(text,text,text,timestamp with time zone,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.revoke_scheduled_job_credential(text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.scheduled_job_queue_audit(text,text,text,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.claim_compliance_pack_slice(text,text,timestamp without time zone,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.scheduled_get_compliance_pack_job(text,text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.scheduled_complete_compliance_pack_job(text,text,text,text,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.scheduled_fail_compliance_pack_job(text,text,text,text,text) FROM PUBLIC;
