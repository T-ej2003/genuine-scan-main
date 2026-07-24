CREATE OR REPLACE FUNCTION app_rls.c03_require_governance_actor(allowed_purposes text[])
RETURNS TABLE(user_id text, organization_id text, licensee_id text)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
DECLARE purpose_code text := current_setting('app.purpose', true);
BEGIN
  IF purpose_code IS NULL OR NOT purpose_code = ANY(allowed_purposes) THEN
    RAISE EXCEPTION 'C03_GOVERNANCE_PURPOSE_DENIED' USING ERRCODE = '42501';
  END IF;
  RETURN QUERY
  SELECT actor.user_id, actor.organization_id, actor.licensee_id
    FROM app_rls.c03_revalidate_actor_scope(
      current_setting('app.licensee_id', true),
      '["SUPER_ADMIN","PLATFORM_SUPER_ADMIN"]'::jsonb,
      'mfa-verified', purpose_code
    ) actor;
  IF NOT FOUND THEN RAISE EXCEPTION 'C03_GOVERNANCE_ACTOR_DENIED' USING ERRCODE = '42501'; END IF;
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_governance_row_visible(target_licensee_id text, allowed_purposes text[])
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
  SELECT current_setting('app.purpose', true) = ANY(allowed_purposes)
     AND EXISTS (
       SELECT 1 FROM app_rls.c03_revalidate_actor_scope(
         target_licensee_id,
         '["SUPER_ADMIN","PLATFORM_SUPER_ADMIN"]'::jsonb,
         'mfa-verified', current_setting('app.purpose', true)
       )
     )
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_governance_replay(command_name text, payload jsonb)
RETURNS TABLE(replayed boolean, result jsonb)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
DECLARE
  key_value text := encode(sha256(convert_to(
    'c03-governance|' || current_setting('app.licensee_id', true) || '|' ||
    current_setting('app.user_id', true) || '|' || command_name || '|' ||
    current_setting('app.request_id', true), 'UTF8')), 'hex');
  request_hash text := encode(sha256(convert_to(COALESCE(payload, '{}'::jsonb)::text, 'UTF8')), 'hex');
  inserted integer;
  prior public."ActionIdempotencyKey"%ROWTYPE;
BEGIN
  INSERT INTO public."ActionIdempotencyKey" (id,"keyHash",action,scope,"requestHash","expiresAt")
  VALUES (gen_random_uuid()::text,key_value,'c03-governance-' || command_name,
          current_setting('app.licensee_id',true),request_hash,transaction_timestamp()+interval '24 hours')
  ON CONFLICT ("keyHash") DO NOTHING;
  GET DIAGNOSTICS inserted = ROW_COUNT;
  IF inserted = 1 THEN RETURN QUERY SELECT false,NULL::jsonb; RETURN; END IF;
  SELECT * INTO prior FROM public."ActionIdempotencyKey" WHERE "keyHash"=key_value FOR UPDATE;
  IF prior."requestHash" IS DISTINCT FROM request_hash THEN
    RAISE EXCEPTION 'C03_GOVERNANCE_REPLAY_CONFLICT' USING ERRCODE='40001';
  END IF;
  IF prior."completedAt" IS NULL OR prior."responsePayload" IS NULL THEN
    RAISE EXCEPTION 'C03_GOVERNANCE_REPLAY_IN_PROGRESS' USING ERRCODE='40001';
  END IF;
  RETURN QUERY SELECT true,prior."responsePayload";
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_complete_governance_command(command_name text, response jsonb)
RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
  UPDATE public."ActionIdempotencyKey"
     SET "statusCode"=200,"responsePayload"=response,"completedAt"=transaction_timestamp()
   WHERE "keyHash"=encode(sha256(convert_to(
     'c03-governance|' || current_setting('app.licensee_id', true) || '|' ||
     current_setting('app.user_id', true) || '|' || command_name || '|' ||
     current_setting('app.request_id', true), 'UTF8')), 'hex')
     AND "completedAt" IS NULL
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_governance_audit(action_name text, entity_type text, entity_id text, details jsonb)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
DECLARE audit_id text := gen_random_uuid()::text;
BEGIN
  INSERT INTO public."AuditLog" (id,"userId","orgId","licenseeId",action,"entityType","entityId",details)
  VALUES (audit_id,current_setting('app.user_id',true),NULLIF(current_setting('app.organization_id',true),''),
          NULLIF(current_setting('app.licensee_id',true),''),action_name,entity_type,entity_id,
          COALESCE(details,'{}'::jsonb) || jsonb_build_object(
            'requestId',current_setting('app.request_id',true),'purpose',current_setting('app.purpose',true),
            'immutableAttribution',true));
  INSERT INTO public."SecurityEventOutbox" (id,"eventType",payload,"updatedAt")
  VALUES (gen_random_uuid()::text,'C03_GOVERNANCE_AUDIT',jsonb_build_object(
    'auditEventId',audit_id,'action',action_name,'entityType',entity_type,'entityId',entity_id,
    'licenseeId',NULLIF(current_setting('app.licensee_id',true),'')),transaction_timestamp());
  RETURN audit_id;
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_require_governance_approval(action_key text, expected_payload jsonb)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
DECLARE approval public."SensitiveActionApproval"%ROWTYPE;
DECLARE approval_id text := current_setting('app.c03_approval_id', true);
BEGIN
  IF approval_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' THEN
    RAISE EXCEPTION 'C03_GOVERNANCE_APPROVAL_REQUIRED' USING ERRCODE='42501';
  END IF;
  SELECT * INTO approval FROM public."SensitiveActionApproval" WHERE id=approval_id FOR UPDATE;
  IF NOT FOUND OR approval."actionKey" IS DISTINCT FROM action_key
     OR approval.status IS DISTINCT FROM 'APPROVED' OR approval."expiresAt"<=transaction_timestamp()
     OR approval."licenseeId" IS DISTINCT FROM current_setting('app.licensee_id',true)
     OR approval."reviewedByUserId" IS DISTINCT FROM current_setting('app.user_id',true)
     OR approval."requestedByUserId"=approval."reviewedByUserId"
     OR approval."executedAt" IS NOT NULL
     OR jsonb_strip_nulls(approval.payload) IS DISTINCT FROM jsonb_strip_nulls(expected_payload) THEN
    RAISE EXCEPTION 'C03_GOVERNANCE_APPROVAL_INVALID' USING ERRCODE='42501';
  END IF;
  RETURN approval_id;
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_mark_governance_approval_executed(approval_id text)
RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
  UPDATE public."SensitiveActionApproval"
     SET status='EXECUTED',"executedByUserId"=current_setting('app.user_id',true),
         "executedAt"=transaction_timestamp(),"updatedAt"=transaction_timestamp()
   WHERE id=approval_id AND status='APPROVED' AND "executedAt" IS NULL
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_upsert_tenant_feature_flag(key text, enabled boolean, config jsonb)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
DECLARE actor record; replay record; row public."TenantFeatureFlag"%ROWTYPE; response jsonb; approval_id text;
DECLARE payload jsonb;
BEGIN
  SELECT * INTO actor FROM app_rls.c03_require_governance_actor(ARRAY['sensitive-action-approval-approve']);
  IF key !~ '^[a-z0-9][a-z0-9_.-]{1,119}$' OR (config IS NOT NULL AND jsonb_typeof(config)<>'object')
     OR octet_length(COALESCE(config,'{}'::jsonb)::text)>65536 THEN
    RAISE EXCEPTION 'C03_FEATURE_FLAG_INVALID' USING ERRCODE='22023';
  END IF;
  payload := jsonb_build_object('licenseeId',actor.licensee_id,'key',key,'enabled',enabled,'config',config);
  SELECT * INTO replay FROM app_rls.c03_governance_replay('feature-flag:'||key,payload);
  IF replay.replayed THEN RETURN replay.result || '{"__c03Replay":true}'::jsonb; END IF;
  approval_id := app_rls.c03_require_governance_approval('FEATURE_FLAG_UPSERT',payload);
  INSERT INTO public."TenantFeatureFlag" (id,"licenseeId",key,enabled,config,"updatedByUserId","updatedAt")
  VALUES (gen_random_uuid()::text,actor.licensee_id,key,enabled,config,actor.user_id,transaction_timestamp())
  ON CONFLICT ("licenseeId",key) DO UPDATE SET enabled=EXCLUDED.enabled,config=EXCLUDED.config,
    "updatedByUserId"=EXCLUDED."updatedByUserId","updatedAt"=transaction_timestamp()
  RETURNING * INTO row;
  response := to_jsonb(row);
  PERFORM app_rls.c03_governance_audit('TENANT_FEATURE_FLAG_UPSERTED','TenantFeatureFlag',row.id,
    jsonb_build_object('key',key,'enabled',enabled,'approvalId',approval_id));
  PERFORM app_rls.c03_mark_governance_approval_executed(approval_id);
  PERFORM app_rls.c03_complete_governance_command('feature-flag:'||key,response);
  RETURN response || '{"__c03Replay":false}'::jsonb;
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_get_or_create_retention_policy()
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
DECLARE actor record; row public."EvidenceRetentionPolicy"%ROWTYPE; inserted boolean := false;
BEGIN
  SELECT * INTO actor FROM app_rls.c03_require_governance_actor(ARRAY[
    'governance-retention-policy-read','governance-retention-preview','governance-compliance-report',
    'compliance-pack-start','compliance-pack-download','compliance-pack-rebuild-read',
    'sensitive-action-approval-approve'
  ]);
  SELECT * INTO row FROM public."EvidenceRetentionPolicy" WHERE "licenseeId"=actor.licensee_id FOR UPDATE;
  IF NOT FOUND THEN
    INSERT INTO public."EvidenceRetentionPolicy"
      (id,"licenseeId","retentionDays","purgeEnabled","exportBeforePurge","legalHoldTags","updatedAt")
    VALUES (gen_random_uuid()::text,actor.licensee_id,180,false,true,ARRAY['legal_hold','compliance_hold'],transaction_timestamp())
    RETURNING * INTO row;
    inserted := true;
  END IF;
  IF inserted THEN
    PERFORM app_rls.c03_governance_audit('EVIDENCE_RETENTION_POLICY_CREATED','EvidenceRetentionPolicy',row.id,'{}'::jsonb);
  END IF;
  RETURN to_jsonb(row);
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_run_retention_lifecycle(mode text, approval_id text)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
DECLARE actor record; replay record; policy public."EvidenceRetentionPolicy"%ROWTYPE;
DECLARE job public."EvidenceRetentionJob"%ROWTYPE; cutoff_at timestamptz; evaluated integer; eligible integer; response jsonb;
BEGIN
  IF mode NOT IN ('PREVIEW','APPLY') THEN RAISE EXCEPTION 'C03_RETENTION_MODE_INVALID' USING ERRCODE='22023'; END IF;
  IF mode='APPLY' THEN
    RAISE EXCEPTION 'C03_RETENTION_APPLY_REQUIRES_MAKER_CHECKER_EXECUTOR' USING ERRCODE='42501';
  END IF;
  IF approval_id IS NOT NULL THEN RAISE EXCEPTION 'C03_RETENTION_PREVIEW_APPROVAL_FORBIDDEN' USING ERRCODE='22023'; END IF;
  SELECT * INTO actor FROM app_rls.c03_require_governance_actor(ARRAY['governance-retention-preview']);
  SELECT * INTO replay FROM app_rls.c03_governance_replay('retention-preview','{"mode":"PREVIEW"}'::jsonb);
  IF replay.replayed THEN RETURN replay.result || '{"__c03Replay":true}'::jsonb; END IF;
  PERFORM app_rls.c03_get_or_create_retention_policy();
  SELECT * INTO policy FROM public."EvidenceRetentionPolicy" WHERE "licenseeId"=actor.licensee_id FOR UPDATE;
  cutoff_at := transaction_timestamp()-make_interval(days=>policy."retentionDays");
  SELECT count(*),count(*) FILTER (WHERE NOT (COALESCE(incident.tags,ARRAY[]::text[]) && policy."legalHoldTags"))
    INTO evaluated,eligible
    FROM public."IncidentEvidence" evidence JOIN public."Incident" incident ON incident.id=evidence."incidentId"
   WHERE incident."licenseeId"=actor.licensee_id AND evidence."createdAt"<cutoff_at;
  INSERT INTO public."EvidenceRetentionJob"
    (id,"licenseeId",status,mode,"cutoffAt","recordsEvaluated","recordsPurged","recordsExported",summary,
     "startedByUserId","startedAt","finishedAt")
  VALUES (gen_random_uuid()::text,actor.licensee_id,'PREVIEW','PREVIEW',cutoff_at,evaluated,0,0,
    jsonb_build_object('eligibleCount',eligible,'skippedDueToLegalHold',evaluated-eligible,
      'purgeEnabled',policy."purgeEnabled"),actor.user_id,transaction_timestamp(),transaction_timestamp())
  RETURNING * INTO job;
  response := jsonb_build_object('job',to_jsonb(job),'policy',to_jsonb(policy),'cutoffAt',cutoff_at,
    'evaluated',evaluated,'eligible',eligible,'purged',0,'exported',0);
  PERFORM app_rls.c03_governance_audit('EVIDENCE_RETENTION_JOB_PREVIEWED','EvidenceRetentionJob',job.id,
    jsonb_build_object('evaluated',evaluated,'eligible',eligible));
  PERFORM app_rls.c03_complete_governance_command('retention-preview',response);
  RETURN response || '{"__c03Replay":false}'::jsonb;
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_generate_compliance_report(from_at timestamptz, to_at timestamptz)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
DECLARE actor record; replay record; policy public."EvidenceRetentionPolicy"%ROWTYPE; response jsonb;
DECLARE total_incidents integer; resolved_incidents integer; breached_incidents integer; fraud_reports integer;
DECLARE audit_events integer; failed_logins integer; handoff jsonb; payload jsonb;
BEGIN
  IF (from_at IS NOT NULL AND to_at IS NOT NULL AND from_at>to_at)
     OR (from_at IS NOT NULL AND to_at IS NOT NULL AND to_at-from_at>interval '366 days') THEN
    RAISE EXCEPTION 'C03_COMPLIANCE_RANGE_INVALID' USING ERRCODE='22023';
  END IF;
  SELECT * INTO actor FROM app_rls.c03_require_governance_actor(ARRAY[
    'governance-compliance-report','compliance-pack-start','compliance-pack-download','compliance-pack-rebuild-read']);
  payload := jsonb_build_object('from',from_at,'to',to_at);
  SELECT * INTO replay FROM app_rls.c03_governance_replay('compliance-report',payload);
  IF replay.replayed THEN RETURN replay.result || '{"__c03Replay":true}'::jsonb; END IF;
  PERFORM app_rls.c03_get_or_create_retention_policy();
  SELECT * INTO policy FROM public."EvidenceRetentionPolicy" WHERE "licenseeId"=actor.licensee_id;
  SELECT count(*),count(*) FILTER (WHERE status::text IN ('RESOLVED','CLOSED')),
         count(*) FILTER (WHERE "slaDueAt"<transaction_timestamp() AND status::text NOT IN ('RESOLVED','CLOSED')),
         count(*) FILTER (WHERE "reportedBy"='CUSTOMER')
    INTO total_incidents,resolved_incidents,breached_incidents,fraud_reports
    FROM public."Incident" WHERE "licenseeId"=actor.licensee_id
      AND (from_at IS NULL OR "createdAt">=from_at) AND (to_at IS NULL OR "createdAt"<=to_at);
  SELECT count(*),count(*) FILTER (WHERE action LIKE '%LOGIN_FAILED%') INTO audit_events,failed_logins
    FROM public."AuditLog" WHERE "licenseeId"=actor.licensee_id
      AND (from_at IS NULL OR "createdAt">=from_at) AND (to_at IS NULL OR "createdAt"<=to_at);
  SELECT COALESCE(jsonb_object_agg(stage,row_count),'{}'::jsonb) INTO handoff FROM (
    SELECT h."currentStage"::text stage,count(*) row_count FROM public."IncidentHandoff" h
    JOIN public."Incident" i ON i.id=h."incidentId" WHERE i."licenseeId"=actor.licensee_id GROUP BY h."currentStage"
  ) grouped;
  response := jsonb_build_object(
    'generatedAt',transaction_timestamp(),'appName','MSCQR',
    'scope',jsonb_build_object('licenseeId',actor.licensee_id,'from',from_at,'to',to_at),
    'compliance',jsonb_build_object(
      'ukGdpr',jsonb_build_object('statement','Personal data is processed in accordance with UK GDPR and the Data Protection Act 2018.','contact','support@mscqr.local'),
      'securityAccess',jsonb_build_object('roleBasedAccess',jsonb_build_array('Super Admin','Licensee','Manufacturer'),'httpsEncrypted',true,'passwordHandling','Secure password hashing and OTP controls are enforced.','auditLogging',true),
      'incidentResponse',jsonb_build_object('workflow',jsonb_build_array('report intake','review','containment','documentation','resolution')),
      'qrUsagePolicy',jsonb_build_object('uniqueTraceable',true,'singleUseWhereApplicable',true,'nonDuplicationRule',true),
      'auditRetentionDays',policy."retentionDays",
      'hosting',jsonb_build_object('provider','Cloud provider not set','disclaimer','Service is provided on a best-effort basis with reasonable security controls.')),
    'metrics',jsonb_build_object(
      'incidents',jsonb_build_object('total',total_incidents,'resolved',resolved_incidents,'slaBreachedOpen',breached_incidents,'handoff',handoff),
      'fraudReports',fraud_reports,'auditEvents',audit_events,'failedLogins',failed_logins,
      'retention',jsonb_build_object('retentionDays',policy."retentionDays",'purgeEnabled',policy."purgeEnabled",
        'exportBeforePurge',policy."exportBeforePurge",'legalHoldTags',policy."legalHoldTags")),
    'controls',jsonb_build_array(
      jsonb_build_object('controlId','SOC2-CC7.2','framework','SOC2','title','Security event detection and response','status',CASE WHEN breached_incidents>5 THEN 'ATTENTION' ELSE 'EFFECTIVE' END,'evidenceRefs',jsonb_build_array('metrics.incidents.slaBreachedOpen','metrics.incidents.total','metrics.incidents.resolved')),
      jsonb_build_object('controlId','SOC2-CC6.1','framework','SOC2','title','Logical access and authentication controls','status',CASE WHEN failed_logins>=20 THEN 'ATTENTION' WHEN failed_logins>=5 THEN 'MONITOR' ELSE 'EFFECTIVE' END,'evidenceRefs',jsonb_build_array('metrics.failedLogins','compliance.securityAccess')),
      jsonb_build_object('controlId','ISO27001-A.5.23','framework','ISO27001','title','Information security for cloud services and logging','status',CASE WHEN audit_events>0 THEN 'EFFECTIVE' ELSE 'ATTENTION' END,'evidenceRefs',jsonb_build_array('metrics.auditEvents','scope.licenseeId','generatedAt')),
      jsonb_build_object('controlId','ISO27001-A.8.10','framework','ISO27001','title','Information retention and deletion','status',CASE WHEN policy."retentionDays">=180 THEN 'EFFECTIVE' ELSE 'MONITOR' END,'evidenceRefs',jsonb_build_array('compliance.auditRetentionDays','metrics.retention'))),
    'controlSummary',jsonb_build_object('EFFECTIVE',0,'MONITOR',0,'ATTENTION',0));
  PERFORM app_rls.c03_governance_audit('COMPLIANCE_REPORT_SNAPSHOT','ComplianceReport',actor.licensee_id,
    jsonb_build_object('from',from_at,'to',to_at,'incidents',total_incidents));
  PERFORM app_rls.c03_complete_governance_command('compliance-report',response);
  RETURN response || '{"__c03Replay":false}'::jsonb;
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_update_retention_policy(patch jsonb)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
DECLARE actor record; replay record; row public."EvidenceRetentionPolicy"%ROWTYPE; response jsonb; approval_id text; payload jsonb;
BEGIN
  SELECT * INTO actor FROM app_rls.c03_require_governance_actor(ARRAY['sensitive-action-approval-approve']);
  IF jsonb_typeof(patch)<>'object' OR patch='{}'::jsonb OR EXISTS (
    SELECT 1 FROM jsonb_object_keys(patch) k WHERE k NOT IN ('retentionDays','purgeEnabled','exportBeforePurge','legalHoldTags'))
     OR (patch ? 'retentionDays' AND (patch->>'retentionDays')::integer NOT BETWEEN 1 AND 3650)
     OR (patch ? 'legalHoldTags' AND (jsonb_typeof(patch->'legalHoldTags')<>'array' OR jsonb_array_length(patch->'legalHoldTags')>64)) THEN
    RAISE EXCEPTION 'C03_RETENTION_POLICY_INVALID' USING ERRCODE='22023';
  END IF;
  payload := jsonb_build_object('licenseeId',actor.licensee_id) || patch;
  SELECT * INTO replay FROM app_rls.c03_governance_replay('retention-policy-update',payload);
  IF replay.replayed THEN RETURN replay.result || '{"__c03Replay":true}'::jsonb; END IF;
  approval_id := app_rls.c03_require_governance_approval('RETENTION_POLICY_PATCH',payload);
  PERFORM app_rls.c03_get_or_create_retention_policy();
  UPDATE public."EvidenceRetentionPolicy" p SET
    "retentionDays"=CASE WHEN patch?'retentionDays' THEN (patch->>'retentionDays')::integer ELSE p."retentionDays" END,
    "purgeEnabled"=CASE WHEN patch?'purgeEnabled' THEN (patch->>'purgeEnabled')::boolean ELSE p."purgeEnabled" END,
    "exportBeforePurge"=CASE WHEN patch?'exportBeforePurge' THEN (patch->>'exportBeforePurge')::boolean ELSE p."exportBeforePurge" END,
    "legalHoldTags"=CASE WHEN patch?'legalHoldTags' THEN ARRAY(SELECT jsonb_array_elements_text(patch->'legalHoldTags')) ELSE p."legalHoldTags" END,
    "updatedByUserId"=actor.user_id,"updatedAt"=transaction_timestamp()
  WHERE p."licenseeId"=actor.licensee_id RETURNING * INTO row;
  response := to_jsonb(row);
  PERFORM app_rls.c03_governance_audit('EVIDENCE_RETENTION_POLICY_UPDATED','EvidenceRetentionPolicy',row.id,
    jsonb_build_object('approvalId',approval_id,'changedFields',(SELECT jsonb_agg(k) FROM jsonb_object_keys(patch) k)));
  PERFORM app_rls.c03_mark_governance_approval_executed(approval_id);
  PERFORM app_rls.c03_complete_governance_command('retention-policy-update',response);
  RETURN response || '{"__c03Replay":false}'::jsonb;
END;
$$;

REVOKE ALL ON FUNCTION app_rls.c03_require_governance_actor(text[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_governance_row_visible(text,text[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_governance_replay(text,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_complete_governance_command(text,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_governance_audit(text,text,text,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_require_governance_approval(text,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_mark_governance_approval_executed(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_upsert_tenant_feature_flag(text,boolean,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_get_or_create_retention_policy() FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_run_retention_lifecycle(text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_generate_compliance_report(timestamptz,timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_update_retention_policy(jsonb) FROM PUBLIC;
