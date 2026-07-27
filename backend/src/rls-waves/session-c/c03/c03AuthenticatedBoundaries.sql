-- Capability-verified C03 compliance and incident-evidence boundaries.
-- {{AUTH_OWNER}} is replaced by the reviewed clean-room generator. Runtime
-- callers receive EXECUTE only on the seven public signatures at the end.

CREATE OR REPLACE FUNCTION app_rls.c03_require_authenticated_actor(
  p_capability text,
  p_purpose text,
  p_request_id text
) RETURNS TABLE(
  session_id text,
  user_id text,
  role text,
  organization_id text,
  licensee_id text,
  assurance text
)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record;
BEGIN
  SELECT * INTO actor
    FROM app_auth.require_authenticated_session(p_capability,p_purpose,p_request_id);
  IF NOT FOUND THEN RAISE EXCEPTION 'C03_AUTHENTICATED_SESSION_DENIED' USING ERRCODE='42501'; END IF;

  PERFORM set_config('app.c03_session_id',actor."sessionId",true),
          set_config('app.c03_user_id',actor."userId",true),
          set_config('app.c03_role',actor.role,true),
          set_config('app.c03_actor_organization_id',coalesce(actor."organizationId",''),true),
          set_config('app.c03_actor_licensee_id',coalesce(actor."licenseeId",''),true),
          set_config('app.c03_assurance',actor.assurance,true),
          set_config('app.c03_operation','',true),
          set_config('app.c03_licensee_id','',true),
          set_config('app.c03_job_id','',true),
          set_config('app.c03_incident_id','',true),
          set_config('app.c03_approval_id','',true),
          set_config('app.c03_storage_key','',true);
  RETURN QUERY SELECT actor."sessionId"::text,actor."userId"::text,actor.role::text,
    actor."organizationId"::text,actor."licenseeId"::text,actor.assurance::text;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.c03_assert_live_licensee_scope(
  p_selector text,
  p_actor_role text,
  p_actor_organization_id text,
  p_actor_licensee_id text
) RETURNS TABLE(licensee_id text,organization_id text)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
BEGIN
  IF p_selector !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
     OR p_actor_role NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN','LICENSEE_ADMIN','ORG_ADMIN','MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER')
     OR (p_actor_role NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') AND p_selector IS DISTINCT FROM p_actor_licensee_id)
  THEN RAISE EXCEPTION 'C03_SCOPE_DENIED' USING ERRCODE='42501'; END IF;

  RETURN QUERY
  SELECT l.id::text,l."orgId"::text
    FROM public."Licensee" l
    JOIN public."Organization" o ON o.id=l."orgId"
   WHERE l.id=p_selector AND l."isActive" AND l."suspendedAt" IS NULL AND o."isActive"
     AND (p_actor_role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')
          OR (l."orgId"=p_actor_organization_id AND l.id=p_actor_licensee_id));
  IF NOT FOUND THEN RAISE EXCEPTION 'C03_SCOPE_DENIED' USING ERRCODE='42501'; END IF;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.c03_bind_operation(
  p_operation text,
  p_licensee_id text,
  p_job_id text DEFAULT '',
  p_incident_id text DEFAULT '',
  p_storage_key text DEFAULT ''
) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
BEGIN
  IF p_operation !~ '^[a-z0-9-]{1,80}$' THEN RAISE EXCEPTION 'C03_OPERATION_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM set_config('app.c03_operation',p_operation,true),
          set_config('app.c03_licensee_id',coalesce(p_licensee_id,''),true),
          set_config('app.c03_job_id',coalesce(p_job_id,''),true),
          set_config('app.c03_incident_id',coalesce(p_incident_id,''),true),
          set_config('app.c03_storage_key',coalesce(p_storage_key,''),true);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.c03_compliance_job_projection(p_job_id text)
RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
  SELECT jsonb_build_object(
    'id',j.id,'licenseeId',j."licenseeId",'status',j.status::text,
    'triggerType',j."triggerType",'periodFrom',j."periodFrom",'periodTo',j."periodTo",
    'fileName',j."fileName",'storageKey',j."storageKey",'integrityHash',j."integrityHash",
    'signatureAlgorithm',j."signatureAlgorithm",'summary',j.summary,'errorMessage',j."errorMessage",
    'startedByUserId',j."startedByUserId",'startedAt',j."startedAt",'finishedAt',j."finishedAt",
    'createdAt',j."createdAt",'updatedAt',j."updatedAt")
  FROM public."CompliancePackJob" j WHERE j.id=p_job_id
$fn$;

CREATE OR REPLACE FUNCTION app_rls.c03_validate_compliance_result(p_result jsonb)
RETURNS void
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $fn$
BEGIN
  IF jsonb_typeof(p_result)<>'object'
     OR EXISTS (SELECT 1 FROM jsonb_object_keys(p_result) k
                WHERE k NOT IN ('fileName','storageKey','integrityHash','signatureAlgorithm','controls','generatedAt','storageMode'))
     OR length(p_result->>'fileName') NOT BETWEEN 1 AND 240 OR p_result->>'fileName' LIKE '%/%'
     OR length(p_result->>'storageKey') NOT BETWEEN 1 AND 1000 OR p_result->>'storageKey' LIKE '%..%'
     OR p_result->>'integrityHash' !~ '^[0-9a-f]{64}$'
     OR p_result->>'signatureAlgorithm' NOT IN ('ed25519','hmac-sha256')
     OR p_result->>'storageMode' NOT IN ('object-storage','local-disk')
     OR (p_result ? 'controls' AND jsonb_typeof(p_result->'controls')<>'number')
  THEN RAISE EXCEPTION 'C03_COMPLIANCE_RESULT_INVALID' USING ERRCODE='22023'; END IF;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.c03_queue_audit(
  p_action text,
  p_entity_type text,
  p_entity_id text,
  p_details jsonb
) RETURNS void
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
  INSERT INTO public."AuditLogOutbox" (id,payload,"updatedAt")
  VALUES (gen_random_uuid()::text,jsonb_build_object(
    'userId',current_setting('app.c03_user_id',true),
    'orgId',NULLIF(current_setting('app.c03_actor_organization_id',true),''),
    'licenseeId',NULLIF(current_setting('app.c03_licensee_id',true),''),
    'action',p_action,'entityType',p_entity_type,'entityId',p_entity_id,
    'details',coalesce(p_details,'{}'::jsonb) || jsonb_build_object(
      'requestId',current_setting('app.request_id',true),
      'purpose',current_setting('app.purpose',true),
      'authenticatedSessionId',current_setting('app.c03_session_id',true))),transaction_timestamp())
$fn$;

CREATE OR REPLACE FUNCTION app_rls.c03_build_compliance_report(
  p_licensee_id text,
  p_from timestamptz,
  p_to timestamptz
) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE total_incidents integer; resolved_incidents integer; breached_incidents integer;
DECLARE audit_events integer; failed_logins integer; retention_days integer; handoff jsonb;
BEGIN
  IF (p_from IS NOT NULL AND p_to IS NOT NULL AND p_from>p_to)
     OR (p_from IS NOT NULL AND p_to IS NOT NULL AND p_to-p_from>interval '366 days')
  THEN RAISE EXCEPTION 'C03_COMPLIANCE_RANGE_INVALID' USING ERRCODE='22023'; END IF;
  SELECT count(*),count(*) FILTER (WHERE status::text IN ('RESOLVED','CLOSED')),
         count(*) FILTER (WHERE "slaDueAt"<transaction_timestamp() AND status::text NOT IN ('RESOLVED','CLOSED'))
    INTO total_incidents,resolved_incidents,breached_incidents
    FROM public."Incident" WHERE "licenseeId"=p_licensee_id
      AND (p_from IS NULL OR "createdAt">=p_from) AND (p_to IS NULL OR "createdAt"<=p_to);
  SELECT count(*),count(*) FILTER (WHERE action LIKE '%LOGIN_FAILED%') INTO audit_events,failed_logins
    FROM public."AuditLog" WHERE "licenseeId"=p_licensee_id
      AND (p_from IS NULL OR "createdAt">=p_from) AND (p_to IS NULL OR "createdAt"<=p_to);
  SELECT coalesce("retentionDays",180) INTO retention_days
    FROM public."EvidenceRetentionPolicy" WHERE "licenseeId"=p_licensee_id;
  retention_days:=coalesce(retention_days,180);
  SELECT coalesce(jsonb_object_agg(stage,row_count),'{}'::jsonb) INTO handoff FROM (
    SELECT h."currentStage"::text stage,count(*) row_count FROM public."IncidentHandoff" h
    JOIN public."Incident" i ON i.id=h."incidentId" WHERE i."licenseeId"=p_licensee_id GROUP BY h."currentStage"
  ) grouped;
  RETURN jsonb_build_object(
    'generatedAt',transaction_timestamp(),'appName','MSCQR',
    'scope',jsonb_build_object('licenseeId',p_licensee_id,'from',p_from,'to',p_to),
    'compliance',jsonb_build_object('auditRetentionDays',retention_days),
    'metrics',jsonb_build_object('incidents',jsonb_build_object('total',total_incidents,'resolved',resolved_incidents,'slaBreachedOpen',breached_incidents,'handoff',handoff),'auditEvents',audit_events,'failedLogins',failed_logins),
    'controls',jsonb_build_array(
      jsonb_build_object('controlId','SOC2-CC7.2','framework','SOC2','status',CASE WHEN breached_incidents>5 THEN 'ATTENTION' ELSE 'EFFECTIVE' END,'evidenceRefs',jsonb_build_array('metrics.incidents.slaBreachedOpen')),
      jsonb_build_object('controlId','SOC2-CC6.1','framework','SOC2','status',CASE WHEN failed_logins>=20 THEN 'ATTENTION' WHEN failed_logins>=5 THEN 'MONITOR' ELSE 'EFFECTIVE' END,'evidenceRefs',jsonb_build_array('metrics.failedLogins')),
      jsonb_build_object('controlId','ISO27001-A.5.23','framework','ISO27001','status',CASE WHEN audit_events>0 THEN 'EFFECTIVE' ELSE 'ATTENTION' END,'evidenceRefs',jsonb_build_array('metrics.auditEvents')),
      jsonb_build_object('controlId','ISO27001-A.8.10','framework','ISO27001','status',CASE WHEN retention_days>=180 THEN 'EFFECTIVE' ELSE 'MONITOR' END,'evidenceRefs',jsonb_build_array('compliance.auditRetentionDays'))));
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.c03_revalidate_compliance_pack_job_actor_scope(
  p_capability text,p_purpose text,p_request_id text,p_job_id text
) RETURNS TABLE(user_id text,role text,organization_id text,licensee_id text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; job record; scope record;
BEGIN
  IF p_job_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  THEN RAISE EXCEPTION 'C03_COMPLIANCE_JOB_DENIED' USING ERRCODE='42501'; END IF;
  SELECT * INTO actor FROM app_rls.c03_require_authenticated_actor(p_capability,p_purpose,p_request_id);
  IF actor.assurance<>'ADMIN_MFA' THEN RAISE EXCEPTION 'C03_COMPLIANCE_MFA_REQUIRED' USING ERRCODE='42501'; END IF;
  PERFORM app_rls.c03_bind_operation('compliance-pack-revalidate','',p_job_id);
  SELECT j."licenseeId" INTO job FROM public."CompliancePackJob" j WHERE j.id=p_job_id;
  IF NOT FOUND OR job."licenseeId" IS NULL THEN RAISE EXCEPTION 'C03_COMPLIANCE_JOB_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM app_rls.c03_bind_operation('compliance-pack-revalidate',job."licenseeId",p_job_id);
  SELECT * INTO scope FROM app_rls.c03_assert_live_licensee_scope(job."licenseeId",actor.role,actor.organization_id,actor.licensee_id);
  PERFORM app_rls.c03_bind_operation('compliance-pack-revalidate',scope.licensee_id,p_job_id);
  RETURN QUERY SELECT actor.user_id::text,actor.role::text,scope.organization_id::text,scope.licensee_id::text;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.c03_bind_sensitive_approval_actor(
  p_capability text,p_purpose text,p_request_id text,p_approval_id text
) RETURNS TABLE(user_id text,role text,organization_id text,licensee_id text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; approval_licensee_id text; scope record;
BEGIN
  IF p_purpose NOT IN ('sensitive-action-approval-approve','sensitive-action-approval-reject')
     OR p_approval_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  THEN RAISE EXCEPTION 'C03_APPROVAL_DENIED' USING ERRCODE='42501'; END IF;

  SELECT * INTO actor FROM app_rls.c03_require_authenticated_actor(p_capability,p_purpose,p_request_id);
  IF actor.role NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN','LICENSEE_ADMIN','MANUFACTURER_ADMIN')
     OR actor.assurance<>'ADMIN_MFA'
  THEN RAISE EXCEPTION 'C03_APPROVAL_DENIED' USING ERRCODE='42501'; END IF;

  PERFORM set_config('app.c03_operation','sensitive-action-approval-revalidate',true),
          set_config('app.c03_approval_id',p_approval_id,true);
  SELECT "licenseeId" INTO approval_licensee_id
    FROM public."SensitiveActionApproval"
   WHERE id=p_approval_id;
  IF NOT FOUND OR approval_licensee_id IS NULL
  THEN RAISE EXCEPTION 'C03_APPROVAL_DENIED' USING ERRCODE='42501'; END IF;

  PERFORM set_config('app.c03_licensee_id',approval_licensee_id,true);
  SELECT * INTO scope FROM app_rls.c03_assert_live_licensee_scope(
    approval_licensee_id,actor.role,actor.organization_id,actor.licensee_id
  );
  PERFORM set_config('app.licensee_id',scope.licensee_id,true),
          set_config('app.c03_licensee_id',scope.licensee_id,true),
          set_config('app.c03_operation','sensitive-action-approval-review',true);
  RETURN QUERY SELECT actor.user_id::text,actor.role::text,scope.organization_id::text,scope.licensee_id::text;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.c03_start_compliance_pack_job(
  p_capability text,p_purpose text,p_request_id text,p_licensee_id text,
  p_trigger_type text,p_from timestamptz,p_to timestamptz
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; scope record; report jsonb; job_id text;
DECLARE replay_key text; request_hash text; prior record;
BEGIN
  IF p_purpose<>'compliance-pack-start' OR p_trigger_type<>'MANUAL'
  THEN RAISE EXCEPTION 'C03_COMPLIANCE_START_DENIED' USING ERRCODE='42501'; END IF;
  SELECT * INTO actor FROM app_rls.c03_require_authenticated_actor(p_capability,p_purpose,p_request_id);
  IF actor.assurance<>'ADMIN_MFA' THEN RAISE EXCEPTION 'C03_COMPLIANCE_MFA_REQUIRED' USING ERRCODE='42501'; END IF;
  PERFORM app_rls.c03_bind_operation('compliance-pack-start',p_licensee_id);
  SELECT * INTO scope FROM app_rls.c03_assert_live_licensee_scope(p_licensee_id,actor.role,actor.organization_id,actor.licensee_id);
  PERFORM app_rls.c03_bind_operation('compliance-pack-start',scope.licensee_id);
  replay_key:=encode(sha256(convert_to('c03-compliance-start|'||actor.session_id||'|'||p_request_id,'UTF8')),'hex');
  request_hash:=encode(sha256(convert_to(jsonb_build_object('licenseeId',scope.licensee_id,'triggerType',p_trigger_type,'from',p_from,'to',p_to)::text,'UTF8')),'hex');
  INSERT INTO public."ActionIdempotencyKey" (id,"keyHash",action,scope,"requestHash","expiresAt")
  VALUES (gen_random_uuid()::text,replay_key,'c03-compliance-start',scope.licensee_id,request_hash,transaction_timestamp()+interval '24 hours')
  ON CONFLICT ("keyHash") DO NOTHING;
  IF NOT FOUND THEN
    SELECT k."requestHash",k."completedAt",k."responsePayload" INTO prior
      FROM public."ActionIdempotencyKey" k WHERE k."keyHash"=replay_key FOR UPDATE;
    IF prior."requestHash" IS DISTINCT FROM request_hash OR prior."completedAt" IS NULL OR prior."responsePayload" IS NULL
    THEN RAISE EXCEPTION 'C03_COMPLIANCE_REPLAY_CONFLICT' USING ERRCODE='40001'; END IF;
    RETURN prior."responsePayload";
  END IF;
  job_id:=gen_random_uuid()::text;
  PERFORM app_rls.c03_bind_operation('compliance-pack-start',scope.licensee_id,job_id);
  INSERT INTO public."CompliancePackJob" (id,"licenseeId",status,"triggerType","periodFrom","periodTo","startedByUserId","startedAt","updatedAt")
  VALUES (job_id,scope.licensee_id,'RUNNING',p_trigger_type,p_from,p_to,actor.user_id,transaction_timestamp(),transaction_timestamp());
  report:=app_rls.c03_build_compliance_report(scope.licensee_id,p_from,p_to);
  PERFORM app_rls.c03_queue_audit('COMPLIANCE_PACK_STARTED','CompliancePackJob',job_id,jsonb_build_object('triggerType',p_trigger_type,'periodFrom',p_from,'periodTo',p_to));
  UPDATE public."ActionIdempotencyKey" SET "statusCode"=200,"responsePayload"=jsonb_build_object(
    'job',app_rls.c03_compliance_job_projection(job_id),'report',report),"completedAt"=transaction_timestamp()
   WHERE "keyHash"=replay_key;
  RETURN jsonb_build_object('job',app_rls.c03_compliance_job_projection(job_id),'report',report);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.c03_complete_compliance_pack_job(
  p_capability text,p_purpose text,p_request_id text,p_job_id text,p_result jsonb
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; job record; scope record; projected jsonb;
BEGIN
  IF p_purpose<>'compliance-pack-complete' THEN RAISE EXCEPTION 'C03_COMPLIANCE_COMPLETE_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM app_rls.c03_validate_compliance_result(p_result);
  SELECT * INTO actor FROM app_rls.c03_require_authenticated_actor(p_capability,p_purpose,p_request_id);
  IF actor.assurance<>'ADMIN_MFA' THEN RAISE EXCEPTION 'C03_COMPLIANCE_MFA_REQUIRED' USING ERRCODE='42501'; END IF;
  PERFORM app_rls.c03_bind_operation('compliance-pack-complete','',p_job_id);
  SELECT j."licenseeId" INTO job FROM public."CompliancePackJob" j WHERE j.id=p_job_id;
  IF NOT FOUND OR job."licenseeId" IS NULL THEN RAISE EXCEPTION 'C03_COMPLIANCE_JOB_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM app_rls.c03_bind_operation('compliance-pack-complete',job."licenseeId",p_job_id);
  SELECT * INTO scope FROM app_rls.c03_assert_live_licensee_scope(job."licenseeId",actor.role,actor.organization_id,actor.licensee_id);
  PERFORM app_rls.c03_bind_operation('compliance-pack-complete',scope.licensee_id,p_job_id);
  SELECT j.status,j."storageKey",j."integrityHash" INTO job FROM public."CompliancePackJob" j
    WHERE j.id=p_job_id AND j."licenseeId"=scope.licensee_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'C03_COMPLIANCE_JOB_DENIED' USING ERRCODE='42501'; END IF;
  IF job.status='COMPLETED' AND job."storageKey"=p_result->>'storageKey' AND job."integrityHash"=p_result->>'integrityHash' THEN RETURN app_rls.c03_compliance_job_projection(p_job_id); END IF;
  IF job.status<>'RUNNING' THEN RAISE EXCEPTION 'C03_COMPLIANCE_TRANSITION_DENIED' USING ERRCODE='40001'; END IF;
  UPDATE public."CompliancePackJob" SET status='COMPLETED',"fileName"=p_result->>'fileName',"storageKey"=p_result->>'storageKey',
    "integrityHash"=p_result->>'integrityHash',"signatureAlgorithm"=p_result->>'signatureAlgorithm',summary=p_result,
    "errorMessage"=NULL,"finishedAt"=transaction_timestamp(),"updatedAt"=transaction_timestamp() WHERE id=p_job_id;
  projected:=app_rls.c03_compliance_job_projection(p_job_id);
  PERFORM app_rls.c03_queue_audit('COMPLIANCE_PACK_COMPLETED','CompliancePackJob',p_job_id,jsonb_build_object('storageKey',p_result->>'storageKey','integrityHash',p_result->>'integrityHash'));
  RETURN projected;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.c03_fail_compliance_pack_job(
  p_capability text,p_purpose text,p_request_id text,p_job_id text,p_error_code text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; job record; scope record; projected jsonb;
BEGIN
  IF p_purpose<>'compliance-pack-fail' OR p_error_code !~ '^[A-Z0-9_:-]{1,160}$'
  THEN RAISE EXCEPTION 'C03_COMPLIANCE_FAIL_DENIED' USING ERRCODE='42501'; END IF;
  SELECT * INTO actor FROM app_rls.c03_require_authenticated_actor(p_capability,p_purpose,p_request_id);
  IF actor.assurance<>'ADMIN_MFA' THEN RAISE EXCEPTION 'C03_COMPLIANCE_MFA_REQUIRED' USING ERRCODE='42501'; END IF;
  PERFORM app_rls.c03_bind_operation('compliance-pack-fail','',p_job_id);
  SELECT j."licenseeId" INTO job FROM public."CompliancePackJob" j WHERE j.id=p_job_id;
  IF NOT FOUND OR job."licenseeId" IS NULL THEN RAISE EXCEPTION 'C03_COMPLIANCE_JOB_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM app_rls.c03_bind_operation('compliance-pack-fail',job."licenseeId",p_job_id);
  SELECT * INTO scope FROM app_rls.c03_assert_live_licensee_scope(job."licenseeId",actor.role,actor.organization_id,actor.licensee_id);
  PERFORM app_rls.c03_bind_operation('compliance-pack-fail',scope.licensee_id,p_job_id);
  SELECT j.status,j."errorMessage" INTO job FROM public."CompliancePackJob" j
    WHERE j.id=p_job_id AND j."licenseeId"=scope.licensee_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'C03_COMPLIANCE_JOB_DENIED' USING ERRCODE='42501'; END IF;
  IF job.status='FAILED' AND job."errorMessage"=p_error_code THEN RETURN app_rls.c03_compliance_job_projection(p_job_id); END IF;
  IF job.status<>'RUNNING' THEN RAISE EXCEPTION 'C03_COMPLIANCE_TRANSITION_DENIED' USING ERRCODE='40001'; END IF;
  UPDATE public."CompliancePackJob" SET status='FAILED',"errorMessage"=p_error_code,"finishedAt"=transaction_timestamp(),"updatedAt"=transaction_timestamp() WHERE id=p_job_id;
  projected:=app_rls.c03_compliance_job_projection(p_job_id);
  PERFORM app_rls.c03_queue_audit('COMPLIANCE_PACK_FAILED','CompliancePackJob',p_job_id,jsonb_build_object('errorCode',p_error_code));
  RETURN projected;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.c03_get_compliance_pack_job(
  p_capability text,p_purpose text,p_request_id text,p_job_id text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; job record; scope record; report jsonb;
BEGIN
  IF p_purpose NOT IN ('compliance-pack-download','compliance-pack-rebuild-read')
  THEN RAISE EXCEPTION 'C03_COMPLIANCE_READ_DENIED' USING ERRCODE='42501'; END IF;
  SELECT * INTO actor FROM app_rls.c03_require_authenticated_actor(p_capability,p_purpose,p_request_id);
  IF actor.assurance<>'ADMIN_MFA' THEN RAISE EXCEPTION 'C03_COMPLIANCE_MFA_REQUIRED' USING ERRCODE='42501'; END IF;
  PERFORM app_rls.c03_bind_operation('compliance-pack-get','',p_job_id);
  SELECT j."licenseeId",j."periodFrom",j."periodTo" INTO job
    FROM public."CompliancePackJob" j WHERE j.id=p_job_id;
  IF NOT FOUND OR job."licenseeId" IS NULL THEN RAISE EXCEPTION 'C03_COMPLIANCE_JOB_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM app_rls.c03_bind_operation('compliance-pack-get',job."licenseeId",p_job_id);
  SELECT * INTO scope FROM app_rls.c03_assert_live_licensee_scope(job."licenseeId",actor.role,actor.organization_id,actor.licensee_id);
  PERFORM app_rls.c03_bind_operation('compliance-pack-get',scope.licensee_id,p_job_id);
  report:=app_rls.c03_build_compliance_report(scope.licensee_id,job."periodFrom",job."periodTo");
  RETURN jsonb_build_object('job',app_rls.c03_compliance_job_projection(p_job_id),'report',report);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.c03_complete_compliance_pack_rebuild(
  p_capability text,p_purpose text,p_request_id text,p_job_id text,p_result jsonb
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; job record; scope record; projected jsonb;
BEGIN
  IF p_purpose<>'compliance-pack-rebuild-complete' THEN RAISE EXCEPTION 'C03_COMPLIANCE_REBUILD_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM app_rls.c03_validate_compliance_result(p_result);
  SELECT * INTO actor FROM app_rls.c03_require_authenticated_actor(p_capability,p_purpose,p_request_id);
  IF actor.assurance<>'ADMIN_MFA' THEN RAISE EXCEPTION 'C03_COMPLIANCE_MFA_REQUIRED' USING ERRCODE='42501'; END IF;
  PERFORM app_rls.c03_bind_operation('compliance-pack-rebuild','',p_job_id);
  SELECT j."licenseeId" INTO job FROM public."CompliancePackJob" j WHERE j.id=p_job_id;
  IF NOT FOUND OR job."licenseeId" IS NULL THEN RAISE EXCEPTION 'C03_COMPLIANCE_JOB_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM app_rls.c03_bind_operation('compliance-pack-rebuild',job."licenseeId",p_job_id);
  SELECT * INTO scope FROM app_rls.c03_assert_live_licensee_scope(job."licenseeId",actor.role,actor.organization_id,actor.licensee_id);
  PERFORM app_rls.c03_bind_operation('compliance-pack-rebuild',scope.licensee_id,p_job_id);
  SELECT j.status,j."storageKey",j."integrityHash" INTO job FROM public."CompliancePackJob" j
    WHERE j.id=p_job_id AND j."licenseeId"=scope.licensee_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'C03_COMPLIANCE_JOB_DENIED' USING ERRCODE='42501'; END IF;
  IF job.status<>'COMPLETED' THEN RAISE EXCEPTION 'C03_COMPLIANCE_TRANSITION_DENIED' USING ERRCODE='40001'; END IF;
  IF job."storageKey"=p_result->>'storageKey' AND job."integrityHash"=p_result->>'integrityHash' THEN RETURN app_rls.c03_compliance_job_projection(p_job_id); END IF;
  UPDATE public."CompliancePackJob" SET "fileName"=p_result->>'fileName',"storageKey"=p_result->>'storageKey',
    "integrityHash"=p_result->>'integrityHash',"signatureAlgorithm"=p_result->>'signatureAlgorithm',summary=p_result,
    "updatedAt"=transaction_timestamp() WHERE id=p_job_id;
  projected:=app_rls.c03_compliance_job_projection(p_job_id);
  PERFORM app_rls.c03_queue_audit('COMPLIANCE_PACK_REBUILT','CompliancePackJob',p_job_id,jsonb_build_object('storageKey',p_result->>'storageKey','integrityHash',p_result->>'integrityHash'));
  RETURN projected;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.c03_get_incident_evidence_file_by_storage_key(
  p_capability text,p_purpose text,p_request_id text,p_storage_key text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; evidence record; scope record; candidate_count integer;
DECLARE evidence_id text; incident_id text; incident_licensee_id text;
BEGIN
  IF p_purpose<>'incident-evidence-file-read' OR p_storage_key IS NULL OR length(p_storage_key) NOT BETWEEN 1 AND 1000 OR p_storage_key ~ '[[:cntrl:]]'
  THEN RAISE EXCEPTION 'C03_INCIDENT_EVIDENCE_DENIED' USING ERRCODE='42501'; END IF;
  SELECT * INTO actor FROM app_rls.c03_require_authenticated_actor(p_capability,p_purpose,p_request_id);
  IF actor.role NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN','LICENSEE_ADMIN','ORG_ADMIN') OR actor.assurance<>'ADMIN_MFA'
  THEN RAISE EXCEPTION 'C03_INCIDENT_EVIDENCE_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM app_rls.c03_bind_operation('incident-evidence-read','','','',p_storage_key);
  SELECT count(*),min(e.id),min(e."incidentId") INTO candidate_count,evidence_id,incident_id
    FROM public."IncidentEvidence" e WHERE e."storageKey"=p_storage_key;
  IF candidate_count<>1 THEN RAISE EXCEPTION 'C03_INCIDENT_EVIDENCE_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM app_rls.c03_bind_operation('incident-evidence-read','','',incident_id,p_storage_key);
  SELECT i."licenseeId" INTO incident_licensee_id FROM public."Incident" i WHERE i.id=incident_id;
  IF NOT FOUND OR incident_licensee_id IS NULL THEN RAISE EXCEPTION 'C03_INCIDENT_EVIDENCE_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM app_rls.c03_bind_operation('incident-evidence-read',incident_licensee_id,'',incident_id,p_storage_key);
  SELECT * INTO scope FROM app_rls.c03_assert_live_licensee_scope(incident_licensee_id,actor.role,actor.organization_id,actor.licensee_id);
  PERFORM app_rls.c03_bind_operation('incident-evidence-read',scope.licensee_id,'',incident_id,p_storage_key);
  SELECT e.id,e."incidentId",e."fileUrl",e."storageKey",e."fileType",e."uploadedByUserId",e."uploadedBy"::text,e."createdAt"
    INTO evidence FROM public."IncidentEvidence" e WHERE e.id=evidence_id AND e."storageKey"=p_storage_key;
  IF NOT FOUND THEN RAISE EXCEPTION 'C03_INCIDENT_EVIDENCE_DENIED' USING ERRCODE='42501'; END IF;
  RETURN jsonb_build_object('id',evidence.id,'incidentId',evidence."incidentId",'fileUrl',evidence."fileUrl",
    'storageKey',evidence."storageKey",'fileType',evidence."fileType",'uploadedByUserId',evidence."uploadedByUserId",
    'uploadedBy',evidence."uploadedBy",'createdAt',evidence."createdAt");
END
$fn$;

REVOKE ALL ON FUNCTION app_rls.c03_require_authenticated_actor(text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_assert_live_licensee_scope(text,text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_bind_operation(text,text,text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_compliance_job_projection(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_validate_compliance_result(jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_queue_audit(text,text,text,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_build_compliance_report(text,timestamp with time zone,timestamp with time zone) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_revalidate_compliance_pack_job_actor_scope(text,text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_bind_sensitive_approval_actor(text,text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_start_compliance_pack_job(text,text,text,text,text,timestamp with time zone,timestamp with time zone) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_complete_compliance_pack_job(text,text,text,text,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_fail_compliance_pack_job(text,text,text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_get_compliance_pack_job(text,text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_complete_compliance_pack_rebuild(text,text,text,text,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_get_incident_evidence_file_by_storage_key(text,text,text,text) FROM PUBLIC;

ALTER FUNCTION app_rls.c03_require_authenticated_actor(text,text,text) OWNER TO {{AUTH_OWNER}};
ALTER FUNCTION app_rls.c03_assert_live_licensee_scope(text,text,text,text) OWNER TO {{AUTH_OWNER}};
ALTER FUNCTION app_rls.c03_bind_operation(text,text,text,text,text) OWNER TO {{AUTH_OWNER}};
ALTER FUNCTION app_rls.c03_compliance_job_projection(text) OWNER TO {{AUTH_OWNER}};
ALTER FUNCTION app_rls.c03_validate_compliance_result(jsonb) OWNER TO {{AUTH_OWNER}};
ALTER FUNCTION app_rls.c03_queue_audit(text,text,text,jsonb) OWNER TO {{AUTH_OWNER}};
ALTER FUNCTION app_rls.c03_build_compliance_report(text,timestamp with time zone,timestamp with time zone) OWNER TO {{AUTH_OWNER}};
ALTER FUNCTION app_rls.c03_revalidate_compliance_pack_job_actor_scope(text,text,text,text) OWNER TO {{AUTH_OWNER}};
ALTER FUNCTION app_rls.c03_bind_sensitive_approval_actor(text,text,text,text) OWNER TO {{AUTH_OWNER}};
ALTER FUNCTION app_rls.c03_start_compliance_pack_job(text,text,text,text,text,timestamp with time zone,timestamp with time zone) OWNER TO {{AUTH_OWNER}};
ALTER FUNCTION app_rls.c03_complete_compliance_pack_job(text,text,text,text,jsonb) OWNER TO {{AUTH_OWNER}};
ALTER FUNCTION app_rls.c03_fail_compliance_pack_job(text,text,text,text,text) OWNER TO {{AUTH_OWNER}};
ALTER FUNCTION app_rls.c03_get_compliance_pack_job(text,text,text,text) OWNER TO {{AUTH_OWNER}};
ALTER FUNCTION app_rls.c03_complete_compliance_pack_rebuild(text,text,text,text,jsonb) OWNER TO {{AUTH_OWNER}};
ALTER FUNCTION app_rls.c03_get_incident_evidence_file_by_storage_key(text,text,text,text) OWNER TO {{AUTH_OWNER}};
