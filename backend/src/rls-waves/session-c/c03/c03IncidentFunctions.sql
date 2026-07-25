CREATE OR REPLACE FUNCTION app_rls.c03_assert_restricted_identity(expected_identity text)
RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog
AS $$
BEGIN
  IF expected_identity NOT IN ('preauth','worker')
     OR session_user::text IS DISTINCT FROM (CASE expected_identity
       WHEN 'preauth' THEN '{{PREAUTH_ROLE}}'
       ELSE '{{WORKER_ROLE}}'
     END) THEN
    RAISE EXCEPTION 'C03_RESTRICTED_IDENTITY_DENIED' USING ERRCODE='42501';
  END IF;
  RETURN true;
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_public_incident_qr(qr_proof text)
RETURNS TABLE(qr_id text, licensee_id text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
DECLARE candidate record;
BEGIN
  IF session_user::text<>'{{PREAUTH_ROLE}}' OR current_setting('app.purpose',true)<>'public-incident-intake'
     OR qr_proof IS NULL OR length(qr_proof) NOT BETWEEN 2 AND 128 OR qr_proof<>btrim(qr_proof) THEN
    RAISE EXCEPTION 'C03_PUBLIC_INCIDENT_DENIED' USING ERRCODE='42501';
  END IF;
  PERFORM set_config('app.c03_public_operation','incident-qr-read',true);
  PERFORM set_config('app.c03_public_code',qr_proof,true);
  SELECT q.id,q."licenseeId" INTO candidate FROM public."QRCode" q WHERE q.code=qr_proof;
  IF NOT FOUND THEN RAISE EXCEPTION 'C03_PUBLIC_INCIDENT_NOT_FOUND' USING ERRCODE='02000'; END IF;
  PERFORM set_config('app.c03_public_licensee_id',candidate."licenseeId",true);
  RETURN QUERY
  SELECT candidate.id,candidate."licenseeId" FROM public."Licensee" l
   JOIN public."Organization" o ON o.id=l."orgId"
  WHERE l.id=candidate."licenseeId" AND l."isActive" AND l."suspendedAt" IS NULL AND o."isActive";
  IF NOT FOUND THEN RAISE EXCEPTION 'C03_PUBLIC_INCIDENT_NOT_FOUND' USING ERRCODE='02000'; END IF;
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_compute_incident_spam_signal(qr_proof text, contact_hashes jsonb)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
DECLARE qr record; recent_count integer;
BEGIN
  IF jsonb_typeof(contact_hashes)<>'object'
     OR EXISTS (SELECT 1 FROM jsonb_object_keys(contact_hashes) k WHERE k NOT IN ('emailHash','phoneHash'))
     OR length(COALESCE(contact_hashes->>'emailHash',''))>64
     OR length(COALESCE(contact_hashes->>'phoneHash',''))>64 THEN
    RAISE EXCEPTION 'C03_PUBLIC_INCIDENT_INVALID' USING ERRCODE='22023';
  END IF;
  SELECT * INTO qr FROM app_rls.c03_public_incident_qr(qr_proof);
  PERFORM set_config('app.c03_public_operation','incident-history-read',true);
  PERFORM set_config('app.c03_public_qr_id',qr.qr_id,true);
  SELECT count(*) INTO recent_count FROM public."Incident" i
   WHERE i."qrCodeId"=qr.qr_id AND i."createdAt">transaction_timestamp()-interval '24 hours';
  RETURN recent_count>=5;
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_compute_incident_severity(qr_proof text, input jsonb)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
DECLARE qr record; kind text := input->>'incidentType';
BEGIN
  IF jsonb_typeof(input)<>'object' OR kind NOT IN ('COUNTERFEIT_SUSPECTED','DUPLICATE_SCAN','TAMPERED_LABEL','WRONG_PRODUCT','OTHER') THEN
    RAISE EXCEPTION 'C03_PUBLIC_INCIDENT_INVALID' USING ERRCODE='22023';
  END IF;
  SELECT * INTO qr FROM app_rls.c03_public_incident_qr(qr_proof);
  RETURN CASE kind
    WHEN 'COUNTERFEIT_SUSPECTED' THEN 'HIGH'
    WHEN 'TAMPERED_LABEL' THEN 'HIGH'
    WHEN 'DUPLICATE_SCAN' THEN 'MEDIUM'
    ELSE 'LOW'
  END;
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_create_public_incident_report(
  qr_proof text, report jsonb, uploads jsonb, idempotency_key text
)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
DECLARE qr record; prior record; incident record;
DECLARE request_hash text; response jsonb; upload jsonb; evidence_id text;
BEGIN
  IF jsonb_typeof(report)<>'object' OR jsonb_typeof(uploads)<>'array'
     OR jsonb_array_length(uploads)>8 OR length(idempotency_key) NOT BETWEEN 8 AND 200
     OR report->>'incidentType' NOT IN ('COUNTERFEIT_SUSPECTED','DUPLICATE_SCAN','TAMPERED_LABEL','WRONG_PRODUCT','OTHER')
     OR report->>'severity' NOT IN ('LOW','MEDIUM','HIGH','CRITICAL')
     OR length(COALESCE(report->>'description','')) NOT BETWEEN 5 AND 2000 THEN
    RAISE EXCEPTION 'C03_PUBLIC_INCIDENT_INVALID' USING ERRCODE='22023';
  END IF;
  SELECT * INTO qr FROM app_rls.c03_public_incident_qr(qr_proof);
  request_hash:=encode(sha256(convert_to(report::text||uploads::text,'UTF8')),'hex');
  PERFORM set_config('app.c03_public_operation','incident-create',true);
  PERFORM set_config('app.c03_public_qr_id',qr.qr_id,true);
  PERFORM set_config('app.c03_public_licensee_id',qr.licensee_id,true);
  INSERT INTO public."ActionIdempotencyKey"(id,"keyHash",action,scope,"requestHash","expiresAt")
  VALUES(gen_random_uuid()::text,encode(sha256(convert_to('public-incident|'||idempotency_key,'UTF8')),'hex'),
    'c03-public-incident',qr.licensee_id,request_hash,transaction_timestamp()+interval '24 hours')
  ON CONFLICT("keyHash") DO NOTHING;
  IF NOT FOUND THEN
    SELECT k."requestHash",k."responsePayload" INTO prior FROM public."ActionIdempotencyKey" k
     WHERE k."keyHash"=encode(sha256(convert_to('public-incident|'||idempotency_key,'UTF8')),'hex') FOR UPDATE;
    IF prior."requestHash" IS DISTINCT FROM request_hash THEN RAISE EXCEPTION 'C03_PUBLIC_INCIDENT_REPLAY_CONFLICT' USING ERRCODE='40001'; END IF;
    IF prior."responsePayload" IS NULL THEN RAISE EXCEPTION 'C03_PUBLIC_INCIDENT_REPLAY_IN_PROGRESS' USING ERRCODE='40001'; END IF;
    RETURN prior."responsePayload";
  END IF;
  INSERT INTO public."Incident"(
    id,"qrCodeId","qrCodeValue","licenseeId","reportedBy","customerName","customerEmail","customerPhone",
    "customerCountry","preferredContactMethod","consentToContact","incidentType",severity,description,photos,
    "purchasePlace","purchaseDate","productBatchNo","locationLat","locationLng","locationName","locationCountry",
    "locationRegion","locationCity","ipHash","userAgentHash","deviceFingerprintHash",status,priority,"slaDueAt",tags
  ) VALUES (
    gen_random_uuid()::text,qr.qr_id,qr_proof,qr.licensee_id,'CUSTOMER',
    NULLIF(report->>'customerName',''),NULLIF(report->>'customerEmail',''),NULLIF(report->>'customerPhone',''),
    NULLIF(report->>'customerCountry',''),COALESCE(NULLIF(report->>'preferredContactMethod',''),'NONE')::public."IncidentContactMethod",
    COALESCE((report->>'consentToContact')::boolean,false),(report->>'incidentType')::public."IncidentType",
    (report->>'severity')::public."IncidentSeverity",report->>'description',
    ARRAY(SELECT jsonb_array_elements_text(COALESCE(report->'photos','[]'::jsonb))),
    NULLIF(report->>'purchasePlace',''),NULLIF(report->>'purchaseDate','')::timestamptz,NULLIF(report->>'productBatchNo',''),
    NULLIF(report->>'locationLat','')::double precision,NULLIF(report->>'locationLng','')::double precision,
    NULLIF(report->>'locationName',''),NULLIF(report->>'locationCountry',''),NULLIF(report->>'locationRegion',''),
    NULLIF(report->>'locationCity',''),NULLIF(report->>'ipHash',''),NULLIF(report->>'userAgentHash',''),
    NULLIF(report->>'deviceFingerprintHash',''),'NEW','P3',
    transaction_timestamp()+CASE report->>'severity' WHEN 'CRITICAL' THEN interval '4 hours' WHEN 'HIGH' THEN interval '24 hours' WHEN 'MEDIUM' THEN interval '72 hours' ELSE interval '168 hours' END,
    ARRAY(SELECT jsonb_array_elements_text(COALESCE(report->'tags','[]'::jsonb)))
  ) RETURNING id,status,severity,"createdAt","qrCodeValue" INTO incident;
  PERFORM set_config('app.c03_public_incident_id',incident.id,true);
  INSERT INTO public."IncidentEvent"(id,"incidentId","actorType","eventType","eventPayload")
  VALUES(gen_random_uuid()::text,incident.id,'CUSTOMER','CREATED',jsonb_build_object('source','public_report'));
  FOR upload IN SELECT * FROM jsonb_array_elements(uploads) LOOP
    IF length(COALESCE(upload->>'fileUrl',''))>1000 OR length(COALESCE(upload->>'storageKey',''))>1000
       OR length(COALESCE(upload->>'fileType',''))>160 THEN RAISE EXCEPTION 'C03_PUBLIC_INCIDENT_INVALID' USING ERRCODE='22023'; END IF;
    evidence_id:=gen_random_uuid()::text;
    INSERT INTO public."IncidentEvidence"(id,"incidentId","fileUrl","storageKey","fileType","uploadedBy")
    VALUES(evidence_id,incident.id,NULLIF(upload->>'fileUrl',''),NULLIF(upload->>'storageKey',''),NULLIF(upload->>'fileType',''),'CUSTOMER');
  END LOOP;
  response:=jsonb_build_object('id',incident.id,'status',incident.status,'severity',incident.severity,
    'createdAt',incident."createdAt",'qrCodeValue',incident."qrCodeValue");
  UPDATE public."ActionIdempotencyKey" SET "statusCode"=201,"responsePayload"=response,"completedAt"=transaction_timestamp()
   WHERE action='c03-public-incident' AND scope=qr.licensee_id AND "requestHash"=request_hash AND "responsePayload" IS NULL;
  RETURN response;
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_require_incident_actor(p_incident_id text, p_purpose text, p_assurance text DEFAULT 'password-verified')
RETURNS TABLE(user_id text, licensee_id text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
BEGIN
  PERFORM set_config('app.c03_incident_id',p_incident_id,true);
  RETURN QUERY
  SELECT actor.user_id,actor.licensee_id
    FROM public."Incident" i
    CROSS JOIN LATERAL app_rls.c03_revalidate_actor_scope(
      i."licenseeId",'["SUPER_ADMIN","PLATFORM_SUPER_ADMIN","LICENSEE_ADMIN","MANUFACTURER_ADMIN"]'::jsonb,p_assurance,p_purpose
    ) actor
   WHERE i.id=p_incident_id;
  IF NOT FOUND THEN RAISE EXCEPTION 'C03_INCIDENT_DENIED' USING ERRCODE='42501'; END IF;
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_get_incident_detail(incident_id text)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
DECLARE actor record; result jsonb;
BEGIN
  SELECT * INTO actor FROM app_rls.c03_require_incident_actor(incident_id,current_setting('app.purpose',true));
  SELECT to_jsonb(i)||jsonb_build_object(
    'events',COALESCE((SELECT jsonb_agg(to_jsonb(e) ORDER BY e."createdAt",e.id) FROM (
      SELECT event.id,event."incidentId",event."actorType",event."actorUserId",event."eventType",
        event."eventPayload",event."createdAt" FROM public."IncidentEvent" event WHERE event."incidentId"=i.id
    ) e),'[]'::jsonb),
    'communications',COALESCE((SELECT jsonb_agg(to_jsonb(c) ORDER BY c."createdAt" DESC,c.id DESC) FROM (
      SELECT comm.id,comm."incidentId",comm.direction,comm.channel,comm."toAddress",comm.subject,
        comm."bodyPreview",comm."attemptedFrom",comm."usedFrom",comm."replyTo",comm."providerMessageId",
        comm."errorMessage",comm.status,comm."createdAt"
      FROM public."IncidentCommunication" comm WHERE comm."incidentId"=i.id
    ) c),'[]'::jsonb),
    'evidence',COALESCE((SELECT jsonb_agg(to_jsonb(v) ORDER BY v."createdAt" DESC,v.id DESC) FROM (
      SELECT evidence.id,evidence."incidentId",evidence."fileUrl",evidence."storageKey",evidence."fileType",
        evidence."uploadedByUserId",evidence."uploadedBy",evidence."createdAt"
      FROM public."IncidentEvidence" evidence WHERE evidence."incidentId"=i.id
    ) v),'[]'::jsonb)
  ) INTO result FROM (
    SELECT incident.id,incident."qrCodeId",incident."qrCodeValue",incident."scanEventId",incident."licenseeId",
      incident."reportedBy",incident."customerName",incident."customerEmail",incident."customerPhone",
      incident."customerCountry",incident."preferredContactMethod",incident."consentToContact",
      incident."incidentType",incident.severity,incident."severityOverridden",incident.description,
      incident.photos,incident."purchasePlace",incident."purchaseDate",incident."productBatchNo",
      incident."locationLat",incident."locationLng",incident."locationName",incident."locationCountry",
      incident."locationRegion",incident."locationCity",incident."ipHash",incident."userAgentHash",
      incident."deviceFingerprintHash",incident.status,incident.priority,incident."assignedToUserId",
      incident."slaDueAt",incident.tags,incident."internalNotes",incident."resolutionSummary",
      incident."resolutionOutcome",incident."createdAt",incident."updatedAt"
    FROM public."Incident" incident
    WHERE incident.id=incident_id AND incident."licenseeId"=actor.licensee_id
  ) i;
  RETURN result;
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_list_incidents(filters jsonb, row_limit integer, row_offset integer)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
DECLARE actor record; result jsonb;
BEGIN
  IF jsonb_typeof(filters)<>'object' OR row_limit NOT BETWEEN 1 AND 200 OR row_offset NOT BETWEEN 0 AND 20000
     OR EXISTS(SELECT 1 FROM jsonb_object_keys(filters) k WHERE k NOT IN ('status','severity','qr','search','dateFrom','dateTo','assignedTo')) THEN
    RAISE EXCEPTION 'C03_INCIDENT_LIST_INVALID' USING ERRCODE='22023';
  END IF;
  SELECT * INTO actor FROM app_rls.c03_revalidate_actor_scope(
    current_setting('app.licensee_id',true),'["SUPER_ADMIN","PLATFORM_SUPER_ADMIN","LICENSEE_ADMIN","ORG_ADMIN"]'::jsonb,
    'password-verified','incident-list');
  IF NOT FOUND THEN RAISE EXCEPTION 'C03_INCIDENT_DENIED' USING ERRCODE='42501'; END IF;
  SELECT jsonb_build_object(
    'rows',COALESCE(jsonb_agg(to_jsonb(page) ORDER BY page."createdAt" DESC,page.id DESC),'[]'::jsonb),
    'total',(SELECT count(*) FROM public."Incident" i WHERE i."licenseeId"=actor.licensee_id
      AND (NOT filters?'status' OR i.status::text=filters->>'status')
      AND (NOT filters?'severity' OR i.severity::text=filters->>'severity')
      AND (NOT filters?'assignedTo' OR i."assignedToUserId"=filters->>'assignedTo')
      AND (NOT filters?'qr' OR i."qrCodeValue" ILIKE '%'||(filters->>'qr')||'%')
      AND (NOT filters?'search' OR i.description ILIKE '%'||(filters->>'search')||'%' OR i."qrCodeValue" ILIKE '%'||(filters->>'search')||'%')
      AND (NOT filters?'dateFrom' OR i."createdAt">=(filters->>'dateFrom')::timestamptz)
      AND (NOT filters?'dateTo' OR i."createdAt"<=(filters->>'dateTo')::timestamptz))
  ) INTO result FROM (
    SELECT i.id,i."qrCodeId",i."qrCodeValue",i."scanEventId",i."licenseeId",i."reportedBy",
      i."customerName",i."customerEmail",i."customerPhone",i."customerCountry",i."preferredContactMethod",
      i."consentToContact",i."incidentType",i.severity,i."severityOverridden",i.description,i.photos,
      i."purchasePlace",i."purchaseDate",i."productBatchNo",i."locationLat",i."locationLng",
      i."locationName",i."locationCountry",i."locationRegion",i."locationCity",i."ipHash",
      i."userAgentHash",i."deviceFingerprintHash",i.status,i.priority,i."assignedToUserId",
      i."slaDueAt",i.tags,i."internalNotes",i."resolutionSummary",i."resolutionOutcome",
      i."createdAt",i."updatedAt"
    FROM public."Incident" i WHERE i."licenseeId"=actor.licensee_id
      AND (NOT filters?'status' OR i.status::text=filters->>'status')
      AND (NOT filters?'severity' OR i.severity::text=filters->>'severity')
      AND (NOT filters?'assignedTo' OR i."assignedToUserId"=filters->>'assignedTo')
      AND (NOT filters?'qr' OR i."qrCodeValue" ILIKE '%'||(filters->>'qr')||'%')
      AND (NOT filters?'search' OR i.description ILIKE '%'||(filters->>'search')||'%' OR i."qrCodeValue" ILIKE '%'||(filters->>'search')||'%')
      AND (NOT filters?'dateFrom' OR i."createdAt">=(filters->>'dateFrom')::timestamptz)
      AND (NOT filters?'dateTo' OR i."createdAt"<=(filters->>'dateTo')::timestamptz)
    ORDER BY i."createdAt" DESC,i.id DESC LIMIT row_limit OFFSET row_offset
  ) page;
  RETURN result;
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_patch_incident(incident_id text, patch jsonb)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
DECLARE actor record; changed text[]:=ARRAY[]::text[]; updated record;
BEGIN
  IF jsonb_typeof(patch)<>'object' OR patch='{}'::jsonb OR EXISTS(SELECT 1 FROM jsonb_object_keys(patch) k
    WHERE k NOT IN ('status','assignedToUserId','internalNotes','tags','severity','priority','resolutionSummary','resolutionOutcome')) THEN
    RAISE EXCEPTION 'C03_INCIDENT_PATCH_INVALID' USING ERRCODE='22023';
  END IF;
  SELECT * INTO actor FROM app_rls.c03_require_incident_actor(incident_id,'incident-update','mfa-verified');
  PERFORM 1 FROM public."Incident" WHERE id=incident_id AND "licenseeId"=actor.licensee_id FOR UPDATE;
  UPDATE public."Incident" i SET
    status=CASE WHEN patch?'status' THEN (patch->>'status')::public."IncidentStatus" ELSE i.status END,
    "assignedToUserId"=CASE WHEN patch?'assignedToUserId' THEN NULLIF(patch->>'assignedToUserId','') ELSE i."assignedToUserId" END,
    "internalNotes"=CASE WHEN patch?'internalNotes' THEN NULLIF(patch->>'internalNotes','') ELSE i."internalNotes" END,
    tags=CASE WHEN patch?'tags' THEN ARRAY(SELECT jsonb_array_elements_text(patch->'tags')) ELSE i.tags END,
    severity=CASE WHEN patch?'severity' THEN (patch->>'severity')::public."IncidentSeverity" ELSE i.severity END,
    "severityOverridden"=CASE WHEN patch?'severity' THEN true ELSE i."severityOverridden" END,
    priority=CASE WHEN patch?'priority' THEN (patch->>'priority')::public."IncidentPriority" ELSE i.priority END,
    "resolutionSummary"=CASE WHEN patch?'resolutionSummary' THEN NULLIF(patch->>'resolutionSummary','') ELSE i."resolutionSummary" END,
    "resolutionOutcome"=CASE WHEN patch?'resolutionOutcome' THEN NULLIF(patch->>'resolutionOutcome','')::public."IncidentResolutionOutcome" ELSE i."resolutionOutcome" END,
    "updatedAt"=transaction_timestamp()
   WHERE i.id=incident_id
   RETURNING id,"qrCodeId","qrCodeValue","scanEventId","licenseeId","reportedBy","customerName",
     "customerEmail","customerPhone","customerCountry","preferredContactMethod","consentToContact",
     "incidentType",severity,"severityOverridden",description,photos,"purchasePlace","purchaseDate",
     "productBatchNo","locationLat","locationLng","locationName","locationCountry","locationRegion",
     "locationCity","ipHash","userAgentHash","deviceFingerprintHash",status,priority,"assignedToUserId",
     "slaDueAt",tags,"internalNotes","resolutionSummary","resolutionOutcome","createdAt","updatedAt"
   INTO updated;
  SELECT array_agg(k) INTO changed FROM jsonb_object_keys(patch) k;
  INSERT INTO public."IncidentEvent"(id,"incidentId","actorType","actorUserId","eventType","eventPayload")
  VALUES(gen_random_uuid()::text,incident_id,'ADMIN',actor.user_id,'UPDATED_FIELDS',jsonb_build_object('changedFields',changed));
  RETURN jsonb_build_object('incident',to_jsonb(updated),'changedFields',to_jsonb(changed));
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_record_incident_event(incident_id text, event_type text, event_payload jsonb)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
DECLARE actor record; created record; purpose text:=current_setting('app.purpose',true);
BEGIN
  SELECT * INTO actor FROM app_rls.c03_require_incident_actor(incident_id,purpose,
    CASE WHEN purpose IN ('incident-note-add','incident-update','incident-pdf-export') THEN 'mfa-verified' ELSE 'password-verified' END);
  IF event_type NOT IN ('CREATED','NOTE_ADDED','STATUS_CHANGED','ASSIGNED','UPDATED_FIELDS','EXPORTED','EMAIL_SENT') OR octet_length(COALESCE(event_payload,'{}'::jsonb)::text)>16384 THEN
    RAISE EXCEPTION 'C03_INCIDENT_EVENT_INVALID' USING ERRCODE='22023';
  END IF;
  INSERT INTO public."IncidentEvent"(id,"incidentId","actorType","actorUserId","eventType","eventPayload")
  VALUES(gen_random_uuid()::text,incident_id,'ADMIN',actor.user_id,event_type::public."IncidentEventType",event_payload)
  RETURNING id,"incidentId","actorType","actorUserId","eventType","eventPayload","createdAt" INTO created;
  RETURN to_jsonb(created);
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_add_incident_evidence(incident_id text, evidence jsonb, idempotency_key text)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
DECLARE actor record; created record; key_hash text;
BEGIN
  IF jsonb_typeof(evidence)<>'object' OR length(idempotency_key) NOT BETWEEN 8 AND 200
     OR length(COALESCE(evidence->>'fileUrl',''))>1000 OR length(COALESCE(evidence->>'storageKey',''))>1000
     OR length(COALESCE(evidence->>'fileType',''))>160 THEN
    RAISE EXCEPTION 'C03_INCIDENT_EVIDENCE_INVALID' USING ERRCODE='22023';
  END IF;
  SELECT * INTO actor FROM app_rls.c03_require_incident_actor(incident_id,'incident-evidence-add','mfa-verified');
  key_hash:=encode(sha256(convert_to('incident-evidence|'||incident_id||'|'||idempotency_key,'UTF8')),'hex');
  INSERT INTO public."ActionIdempotencyKey"(id,"keyHash",action,scope,"requestHash","expiresAt")
  VALUES(gen_random_uuid()::text,key_hash,'c03-incident-evidence',incident_id,
    encode(sha256(convert_to(evidence::text,'UTF8')),'hex'),transaction_timestamp()+interval '24 hours')
  ON CONFLICT("keyHash") DO NOTHING;
  IF NOT FOUND THEN
    RETURN (SELECT "responsePayload" FROM public."ActionIdempotencyKey" WHERE "keyHash"=key_hash AND "responsePayload" IS NOT NULL);
  END IF;
  INSERT INTO public."IncidentEvidence"(id,"incidentId","fileUrl","storageKey","fileType","uploadedByUserId","uploadedBy")
  VALUES(gen_random_uuid()::text,incident_id,NULLIF(evidence->>'fileUrl',''),NULLIF(evidence->>'storageKey',''),
    NULLIF(evidence->>'fileType',''),actor.user_id,'ADMIN')
  RETURNING id,"incidentId","fileUrl","storageKey","fileType","uploadedByUserId","uploadedBy","createdAt"
  INTO created;
  UPDATE public."ActionIdempotencyKey" SET "statusCode"=201,"responsePayload"=jsonb_build_object('evidence',to_jsonb(created)),
    "completedAt"=transaction_timestamp() WHERE "keyHash"=key_hash;
  RETURN jsonb_build_object('evidence',to_jsonb(created),'tamperChecks',NULL);
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_build_incident_evidence_audit_snapshot(incident_id text)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
DECLARE actor record;
BEGIN
  SELECT * INTO actor FROM app_rls.c03_require_incident_actor(incident_id,current_setting('app.purpose',true),'mfa-verified');
  RETURN jsonb_build_object(
    'incident',(SELECT to_jsonb(i) FROM (
      SELECT incident.id,incident."qrCodeId",incident."qrCodeValue",incident."scanEventId",incident."licenseeId",
        incident."reportedBy",incident."customerName",incident."customerEmail",incident."customerPhone",
        incident."customerCountry",incident."preferredContactMethod",incident."consentToContact",
        incident."incidentType",incident.severity,incident."severityOverridden",incident.description,
        incident.photos,incident."purchasePlace",incident."purchaseDate",incident."productBatchNo",
        incident."locationLat",incident."locationLng",incident."locationName",incident."locationCountry",
        incident."locationRegion",incident."locationCity",incident."ipHash",incident."userAgentHash",
        incident."deviceFingerprintHash",incident.status,incident.priority,incident."assignedToUserId",
        incident."slaDueAt",incident.tags,incident."internalNotes",incident."resolutionSummary",
        incident."resolutionOutcome",incident."createdAt",incident."updatedAt"
      FROM public."Incident" incident WHERE incident.id=incident_id
    ) i),
    'evidence',COALESCE((SELECT jsonb_agg(to_jsonb(e) ORDER BY e."createdAt",e.id) FROM (
      SELECT evidence.id,evidence."incidentId",evidence."fileUrl",evidence."storageKey",evidence."fileType",
        evidence."uploadedByUserId",evidence."uploadedBy",evidence."createdAt"
      FROM public."IncidentEvidence" evidence WHERE evidence."incidentId"=incident_id
    ) e),'[]'::jsonb),
    'events',COALESCE((SELECT jsonb_agg(to_jsonb(e) ORDER BY e."createdAt",e.id) FROM (
      SELECT event.id,event."incidentId",event."actorType",event."actorUserId",event."eventType",
        event."eventPayload",event."createdAt"
      FROM public."IncidentEvent" event WHERE event."incidentId"=incident_id
    ) e),'[]'::jsonb)
  );
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_list_ir_alerts(
  p_incident_authorization_id text, p_incident_id text, p_licensee_id text, p_filters jsonb, p_row_limit integer, p_row_offset integer
)
RETURNS TABLE(id text,licensee_id text,alert_type text,severity text,message text,score integer,policy_rule_id text,
  incident_id text,batch_id text,qr_code_id text,manufacturer_id text,acknowledged_at timestamptz,created_at timestamptz,total_count bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
DECLARE actor record;
BEGIN
  IF p_incident_authorization_id !~* '^[0-9a-f-]{36}$' OR jsonb_typeof(p_filters)<>'object'
     OR p_row_limit NOT BETWEEN 1 AND 100 OR p_row_offset NOT BETWEEN 0 AND 20000 THEN
    RAISE EXCEPTION 'C03_IR_ALERT_INVALID' USING ERRCODE='22023';
  END IF;
  SELECT * INTO actor FROM app_rls.c03_require_incident_actor(p_incident_id,'incident-response-alert-triage','step-up-verified');
  IF actor.licensee_id<>p_licensee_id THEN RAISE EXCEPTION 'C03_IR_ALERT_DENIED' USING ERRCODE='42501'; END IF;
  RETURN QUERY SELECT a.id,a."licenseeId",a."alertType"::text,a.severity::text,a.message,a.score,a."policyRuleId",
    a."incidentId",a."batchId",a."qrCodeId",a."manufacturerId",a."acknowledgedAt",a."createdAt",count(*) OVER()
    FROM public."PolicyAlert" a WHERE a."licenseeId"=actor.licensee_id AND a."incidentId"=p_incident_id
      AND (NOT p_filters?'alertType' OR a."alertType"::text=p_filters->>'alertType')
      AND (NOT p_filters?'severity' OR a.severity::text=p_filters->>'severity')
      AND (NOT p_filters?'acknowledged' OR (a."acknowledgedAt" IS NOT NULL)=(p_filters->>'acknowledged')::boolean)
      AND (NOT p_filters?'policyRuleId' OR a."policyRuleId"=p_filters->>'policyRuleId')
      AND (NOT p_filters?'qrCodeId' OR a."qrCodeId"=p_filters->>'qrCodeId')
      AND (NOT p_filters?'batchId' OR a."batchId"=p_filters->>'batchId')
      AND (NOT p_filters?'manufacturerId' OR a."manufacturerId"=p_filters->>'manufacturerId')
    ORDER BY a."createdAt" DESC,a.id DESC LIMIT p_row_limit OFFSET p_row_offset;
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_link_ir_alert_incident(
  incident_authorization_id text, alert_id text, incident_id text, reason text, idempotency_key text
)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
DECLARE actor record; alert record; key_hash text;
BEGIN
  IF incident_authorization_id !~* '^[0-9a-f-]{36}$' OR length(reason) NOT BETWEEN 3 AND 600
     OR length(idempotency_key) NOT BETWEEN 8 AND 200 THEN RAISE EXCEPTION 'C03_IR_ALERT_INVALID' USING ERRCODE='22023'; END IF;
  SELECT * INTO actor FROM app_rls.c03_require_incident_actor(incident_id,'alert-escalation','step-up-verified');
  key_hash:=encode(sha256(convert_to('alert-link|'||alert_id||'|'||idempotency_key,'UTF8')),'hex');
  INSERT INTO public."ActionIdempotencyKey"(id,"keyHash",action,scope,"requestHash","expiresAt")
  VALUES(gen_random_uuid()::text,key_hash,'c03-alert-link',actor.licensee_id,
    encode(sha256(convert_to(incident_id||'|'||reason,'UTF8')),'hex'),transaction_timestamp()+interval '24 hours')
  ON CONFLICT("keyHash") DO NOTHING;
  IF NOT FOUND THEN RETURN (SELECT "responsePayload" FROM public."ActionIdempotencyKey" WHERE "keyHash"=key_hash); END IF;
  UPDATE public."PolicyAlert" SET "incidentId"=incident_id WHERE id=alert_id AND "licenseeId"=actor.licensee_id
   RETURNING id,"licenseeId","alertType",severity,message,score,"policyRuleId","incidentId",
     "batchId","qrCodeId","manufacturerId","acknowledgedAt","acknowledgedByUserId",details,"createdAt"
   INTO alert;
  IF NOT FOUND THEN RAISE EXCEPTION 'C03_IR_ALERT_DENIED' USING ERRCODE='42501'; END IF;
  UPDATE public."ActionIdempotencyKey" SET "statusCode"=200,"responsePayload"=to_jsonb(alert),"completedAt"=transaction_timestamp()
   WHERE "keyHash"=key_hash;
  RETURN to_jsonb(alert);
END;
$$;

REVOKE ALL ON FUNCTION app_rls.c03_assert_restricted_identity(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_public_incident_qr(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_compute_incident_spam_signal(text,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_compute_incident_severity(text,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_create_public_incident_report(text,jsonb,jsonb,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_require_incident_actor(text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_get_incident_detail(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_list_incidents(jsonb,integer,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_patch_incident(text,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_record_incident_event(text,text,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_add_incident_evidence(text,jsonb,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_build_incident_evidence_audit_snapshot(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_list_ir_alerts(text,text,text,jsonb,integer,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_link_ir_alert_incident(text,text,text,text,text) FROM PUBLIC;
