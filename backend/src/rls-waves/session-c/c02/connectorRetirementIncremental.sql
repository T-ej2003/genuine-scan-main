\set ON_ERROR_STOP on
BEGIN;
DO $preflight$
BEGIN
  IF current_user<>'mscqr_prd_rls_phase2_auth_owner' OR NOT EXISTS (
    SELECT 1 FROM pg_proc p WHERE p.oid=to_regprocedure(
      'app_rls.printing_printer_administration(text,text,text,text,text,jsonb)')
      AND p.proowner=current_user::regrole AND p.prosecdef)
  THEN RAISE EXCEPTION 'CONNECTOR_RETIREMENT_FUNCTION_OWNER_INVALID' USING ERRCODE='42501'; END IF;
END
$preflight$;
CREATE OR REPLACE FUNCTION app_rls.printing_printer_administration(
  p_capability text,
  p_purpose text,
  p_request_id text,
  p_operation text,
  p_printer_id text,
  p_payload jsonb
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public
AS $fn$
DECLARE
  actor record;
  printer_row record;
  scope_licensee text;
  scope_org text;
  now_at timestamp without time zone:=transaction_timestamp();
  new_id text:=coalesce(nullif(p_printer_id,''),gen_random_uuid()::text);
  audit_action text;
  maintenance_scope text;
  maintenance_printers text[];
  maintenance_inventory jsonb;
  maintenance_snapshot jsonb;
  maintenance_binding jsonb;
  maintenance_registration record;
BEGIN
  IF p_purpose<>'printing-printer-admin'
     OR p_operation NOT IN (
       'CREATE','UPDATE','DELETE','RELINK','RETIRE','MAINTENANCE_REQUEST','MAINTENANCE_STATUS','DIAGNOSTIC_LEASE','DIAGNOSTIC_COMPLETE','DIAGNOSTIC_ABORT','MAINTENANCE_INVENTORY','MAINTENANCE_AUTHORIZE','MAINTENANCE_CONSUME','MAINTENANCE_VERIFY','MAINTENANCE_RELEASE',
       'AUDIT_TEST','AUDIT_TEST_LABEL_ATTENTION','AUDIT_TEST_LABEL_CONFIRMED',
       'AUDIT_TEST_LABEL_QUEUED','AUDIT_DISCOVERY'
     )
     OR (p_operation<>'CREATE' AND p_printer_id !~* '^[0-9a-f-]{36}$')
     OR jsonb_typeof(coalesce(p_payload,'{}'::jsonb))<>'object'
  THEN RAISE EXCEPTION 'PRINTING_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;

  SELECT * INTO STRICT actor
    FROM app_rls.printing_bind_actor(p_capability,p_purpose,p_request_id,NULL);
  PERFORM set_config('app.printing_operation','printing-printer-admin-'||lower(p_operation),true),
          set_config('app.printing_printer_id',new_id,true);

  IF p_operation='CREATE' THEN
    IF actor.role NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN','LICENSEE_ADMIN')
    THEN RAISE EXCEPTION 'PRINTING_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;
    scope_licensee:=CASE WHEN actor.role='LICENSEE_ADMIN' THEN actor."licenseeId"
      ELSE nullif(p_payload->>'licenseeId','') END;
    SELECT l."orgId" INTO STRICT scope_org FROM public."Licensee" l
      JOIN public."Organization" o ON o.id=l."orgId"
      WHERE l.id=scope_licensee AND l."isActive" AND l."suspendedAt" IS NULL AND o."isActive";
    IF actor.role='LICENSEE_ADMIN' AND (
      actor."organizationId" IS DISTINCT FROM scope_org
      OR actor."licenseeId" IS DISTINCT FROM scope_licensee
    ) THEN RAISE EXCEPTION 'PRINTING_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;
  ELSE
    SELECT p.id,p.name,p.vendor,p.model,p."connectionType",p."commandLanguage",p."ipAddress",p.host,p.port,
      p."resourcePath",p."tlsEnabled",p."printerUri",p."deliveryMode",p."gatewayId",p."gatewayLastSeenAt",
      p."gatewayStatus",p."gatewayLastError",p."nativePrinterId",p."agentId",p."deviceFingerprint",
      p."printerRegistrationId",p."orgId",p."licenseeId",p."assignedUserId",p."createdByUserId",
      p."isActive",p."isDefault",p."lastSeenAt",p."lastValidatedAt",p."lastValidationStatus",
      p."lastValidationMessage",p."capabilitySummary",p."calibrationProfile",p.metadata,p."createdAt",p."updatedAt"
      INTO printer_row FROM public."Printer" p WHERE p.id=p_printer_id FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'PRINTING_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;
    scope_licensee:=printer_row."licenseeId";
    scope_org:=printer_row."orgId";
    IF actor.role='LICENSEE_ADMIN' AND (
      actor."licenseeId" IS DISTINCT FROM scope_licensee
      OR actor."organizationId" IS DISTINCT FROM scope_org
    ) THEN RAISE EXCEPTION 'PRINTING_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;
    IF actor.role='MANUFACTURER_ADMIN' AND NOT (
      (
        p_operation='RELINK' AND printer_row."connectionType"='LOCAL_AGENT'
        AND (printer_row."assignedUserId"=actor."userId" OR EXISTS (
          SELECT 1 FROM public."PrinterRegistration" pr
          WHERE pr.id=printer_row."printerRegistrationId" AND pr."userId"=actor."userId"
            AND pr."trustStatus"='TRUSTED' AND pr."revokedAt" IS NULL
        ))
      )
      OR (
        (p_operation LIKE 'AUDIT_%' OR p_operation IN ('RETIRE','MAINTENANCE_REQUEST','MAINTENANCE_STATUS','DIAGNOSTIC_LEASE','DIAGNOSTIC_COMPLETE','DIAGNOSTIC_ABORT','MAINTENANCE_INVENTORY','MAINTENANCE_AUTHORIZE','MAINTENANCE_CONSUME','MAINTENANCE_VERIFY','MAINTENANCE_RELEASE')) AND printer_row."assignedUserId"=actor."userId"
        AND EXISTS (
          SELECT 1 FROM public."ManufacturerLicenseeLink" ml
          WHERE ml."manufacturerId"=actor."userId" AND ml."licenseeId"=printer_row."licenseeId"
        )
      )
    ) THEN RAISE EXCEPTION 'PRINTING_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;
    IF actor.role NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN','LICENSEE_ADMIN','MANUFACTURER_ADMIN')
    THEN RAISE EXCEPTION 'PRINTING_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;
  END IF;

  PERFORM set_config('app.printing_licensee_id',coalesce(scope_licensee,''),true),
          set_config('app.printing_organization_id',coalesce(scope_org,''),true);
  IF p_operation IN ('MAINTENANCE_REQUEST','MAINTENANCE_STATUS','DIAGNOSTIC_LEASE','DIAGNOSTIC_COMPLETE','DIAGNOSTIC_ABORT','MAINTENANCE_INVENTORY','MAINTENANCE_AUTHORIZE','MAINTENANCE_CONSUME','MAINTENANCE_VERIFY','MAINTENANCE_RELEASE') THEN
    IF printer_row."printerRegistrationId" IS NOT NULL AND NOT EXISTS (
      SELECT 1 FROM public."PrinterRegistration" pr WHERE pr.id=printer_row."printerRegistrationId"
        AND pr."userId" IS NOT DISTINCT FROM printer_row."assignedUserId"
        AND pr."orgId" IS NOT DISTINCT FROM scope_org AND pr."licenseeId" IS NOT DISTINCT FROM scope_licensee
    ) THEN RAISE EXCEPTION 'PRINTING_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;
    maintenance_scope:=CASE WHEN printer_row."printerRegistrationId" IS NOT NULL THEN jsonb_build_array('local',printer_row."printerRegistrationId")::text WHEN printer_row."gatewayId" IS NOT NULL THEN jsonb_build_array('gateway',printer_row."gatewayId",printer_row."orgId",printer_row."licenseeId",printer_row."assignedUserId")::text ELSE jsonb_build_array('printer',printer_row.id)::text END;
    maintenance_snapshot:=app_rls.printing_maintenance_gate(maintenance_scope,'STATUS',actor."userId",'{}'::jsonb);
    IF p_operation IN ('MAINTENANCE_INVENTORY','MAINTENANCE_AUTHORIZE','MAINTENANCE_CONSUME','MAINTENANCE_VERIFY','MAINTENANCE_RELEASE') THEN
      SELECT array_agg(p.id ORDER BY p.id) INTO maintenance_printers FROM public."Printer" p
        WHERE CASE WHEN printer_row."printerRegistrationId" IS NOT NULL THEN p."printerRegistrationId"=printer_row."printerRegistrationId"
          WHEN printer_row."gatewayId" IS NOT NULL THEN p."gatewayId"=printer_row."gatewayId"
            AND p."orgId" IS NOT DISTINCT FROM scope_org AND p."licenseeId" IS NOT DISTINCT FROM scope_licensee
            AND p."assignedUserId" IS NOT DISTINCT FROM printer_row."assignedUserId"
          ELSE p.id=printer_row.id END;
      PERFORM set_config('app.printing_maintenance_printers',to_json(maintenance_printers)::text,true);
      -- Only PRINT_CONFIRMED/CLOSED with a durable confirmation timestamp are
      -- settled. Legacy backfill also writes that timestamp (without JSON
      -- evidence). FAILED/FROZEN/CANCELLED remain governably reissuable; even a
      -- never-issued RESERVED item is pending work and must be reconciled.
      -- One bounded workset feeds inventory, authorization and consumption.
      WITH unresolved AS MATERIALIZED (
        SELECT pi.id,pi.state,pi."attemptCount",pi."printSessionId",pi."deviceJobRef",pi."failureReason",
          pi."pipelineState",pi."issuedAt",pi."dispatchedAt",pi."agentAckedAt",pi."confirmationDeadlineAt",
          pi."printConfirmedAt",pi."dispatchMetadata",pi."confirmationEvidence",ps."printJobId"
        FROM public."PrintItem" pi JOIN public."PrintSession" ps ON ps.id=pi."printSessionId"
        WHERE ps."printerId"=ANY(maintenance_printers)
          AND NOT (pi.state IN ('PRINT_CONFIRMED','CLOSED') AND pi."printConfirmedAt" IS NOT NULL)
        ORDER BY pi.id LIMIT 513
      )
      SELECT jsonb_build_object(
        'jobs',coalesce((SELECT jsonb_agg(to_jsonb(j) ORDER BY j.id) FROM (
          SELECT id,status,"printerId","pipelineState" FROM public."PrintJob"
          WHERE id IN (SELECT "printJobId" FROM unresolved)) j),'[]'::jsonb),
        'items',coalesce((SELECT jsonb_agg(to_jsonb(i)-'printJobId' ORDER BY i.id) FROM unresolved i),'[]'::jsonb),
        'settledHistory',jsonb_build_object('items',(SELECT count(*) FROM public."PrintItem" pi
          JOIN public."PrintSession" ps ON ps.id=pi."printSessionId"
          WHERE ps."printerId"=ANY(maintenance_printers) AND pi.state IN ('PRINT_CONFIRMED','CLOSED') AND pi."printConfirmedAt" IS NOT NULL)))
        INTO maintenance_inventory;
      -- Completed diagnostic leases remain in the checkpoint audit history;
      -- only ambiguous leases require per-operation reconciliation evidence.
      maintenance_inventory:=maintenance_inventory||jsonb_build_object(
        'diagnostics',(SELECT coalesce(jsonb_object_agg(lease.key,lease.value),'{}'::jsonb)
          FROM jsonb_each(coalesce(maintenance_snapshot->'diagnostics','{}'::jsonb)) lease
          WHERE lease.value->>'state' IS DISTINCT FROM 'CONFIRMED' AND lease.value->>'state' IS DISTINCT FROM 'REJECTED_PRE_DISPATCH'),
        'settledDiagnostics',(SELECT count(*) FROM jsonb_each(coalesce(maintenance_snapshot->'diagnostics','{}'::jsonb)) lease
          WHERE lease.value->>'state' IN ('CONFIRMED','REJECTED_PRE_DISPATCH')),
        'localDiagnostics',coalesce((SELECT jsonb_agg(jsonb_build_object('printerId',p.id,'job',p.metadata->'pendingLocalAgentTestLabel') ORDER BY p.id)
          FROM public."Printer" p WHERE p.id=ANY(maintenance_printers) AND p.metadata ? 'pendingLocalAgentTestLabel'
            AND p.metadata->'pendingLocalAgentTestLabel'->>'status' IS DISTINCT FROM 'CONFIRMED'),'[]'::jsonb));
      -- LIMIT is a detection bound, never a truncated authorizable inventory.
      IF jsonb_array_length(maintenance_inventory->'items')>512 OR octet_length(maintenance_inventory::text)>1000000
      THEN RAISE EXCEPTION 'MAINTENANCE_WORKSET_TOO_LARGE' USING ERRCODE='54000',
        HINT='Keep dispatch fenced. Reconcile accepted work through its authenticated confirmation lifecycle. Do not split evidence, discard records or reset uncertain items; larger unresolved sets require a separately governed bounded reconciliation protocol.';
      END IF;
      IF p_operation='MAINTENANCE_INVENTORY' THEN
        RETURN maintenance_snapshot||jsonb_build_object('inventory',maintenance_inventory,
          'workDigest',encode(sha256(convert_to(maintenance_inventory::text,'UTF8')),'hex'));
      END IF;
      IF p_operation IN ('MAINTENANCE_CONSUME','MAINTENANCE_VERIFY','MAINTENANCE_RELEASE') THEN
        IF p_operation='MAINTENANCE_RELEASE' THEN p_payload:=p_payload||jsonb_build_object('binding',p_payload->'evidence'->'binding'); END IF;
        RETURN app_rls.printing_maintenance_gate(maintenance_scope,
          CASE p_operation WHEN 'MAINTENANCE_CONSUME' THEN 'CONSUME' WHEN 'MAINTENANCE_RELEASE' THEN 'RELEASE' ELSE 'VERIFY' END,actor."userId",
          p_payload||jsonb_build_object('workDigest',encode(sha256(convert_to(maintenance_inventory::text,'UTF8')),'hex')));
      END IF;
      maintenance_binding:=p_payload->'evidence'->'binding';
      IF jsonb_typeof(maintenance_binding) IS DISTINCT FROM 'object' OR
        jsonb_typeof(p_payload->'evidence'->'reconciliations') IS DISTINCT FROM 'array' OR
        printer_row."printerRegistrationId" IS NULL OR maintenance_snapshot->>'state'<>'DISPATCH_FENCED'
        OR p_payload->'evidence'->>'workDigest' IS DISTINCT FROM encode(sha256(convert_to(maintenance_inventory::text,'UTF8')),'hex')
        OR coalesce(p_payload->'evidence'->>'evidenceSha256','') !~ '^[a-f0-9]{64}$'
        OR coalesce((p_payload->'evidence'->>'expiresAt')::timestamptz,'-infinity')<=clock_timestamp()
        OR coalesce((p_payload->'evidence'->>'verifiedAt')::timestamptz,'-infinity')<(maintenance_snapshot->>'requestedAt')::timestamptz
        OR maintenance_binding->>'printerId' IS DISTINCT FROM printer_row.id
        OR maintenance_binding->>'registrationId' IS DISTINCT FROM printer_row."printerRegistrationId"
        OR maintenance_binding->>'tenantId' IS DISTINCT FROM scope_org
        OR maintenance_binding->>'manufacturerId' IS DISTINCT FROM printer_row."assignedUserId"
        OR maintenance_binding->>'fenceRequestId' IS DISTINCT FROM maintenance_snapshot->>'requestId'
        OR coalesce(maintenance_binding->>'attemptId','') !~* '^[0-9a-f-]{36}$'
        OR coalesce(maintenance_binding->>'sourceVersion','') !~ '^[0-9]+[.][0-9]+[.][0-9]+([.][0-9]+)?$'
        OR coalesce(maintenance_binding->>'targetVersion','') !~ '^[0-9]+[.][0-9]+[.][0-9]+([.][0-9]+)?$'
        OR maintenance_binding->>'sourceVersion'=maintenance_binding->>'targetVersion'
        OR string_to_array(maintenance_binding->>'targetVersion','.')::integer[]<=string_to_array(maintenance_binding->>'sourceVersion','.')::integer[]
        OR coalesce(maintenance_binding->>'statePath','')=''
        OR EXISTS(SELECT 1 FROM unnest(ARRAY['sourceSha256','targetSha256','installerSha256','stateSha256','stateDiscoverySha256','configurationSha256','startupSha256','wrapperSha256','payloadSha256','sourcePayloadSha256','uninstallerSha256','uninstallDataSha256','uninstallRegistrationSha256']) field
          WHERE coalesce(maintenance_binding->>field,'') !~ '^[a-f0-9]{64}$')
      THEN RAISE EXCEPTION 'MAINTENANCE_EVIDENCE_MISMATCH' USING ERRCODE='42501'; END IF;
      SELECT pr."agentId",pr."deviceFingerprint",pr."publicKeyPem" INTO STRICT maintenance_registration FROM public."PrinterRegistration" pr
        WHERE pr.id=printer_row."printerRegistrationId" AND pr."userId"=printer_row."assignedUserId" AND pr."trustStatus"='TRUSTED' AND pr."revokedAt" IS NULL;
      IF maintenance_binding->>'publicKeySha256' IS DISTINCT FROM encode(sha256(convert_to(maintenance_registration."publicKeyPem",'UTF8')),'hex') OR
        maintenance_binding->>'agentId' IS DISTINCT FROM maintenance_registration."agentId" OR
        maintenance_binding->>'deviceFingerprint' IS DISTINCT FROM maintenance_registration."deviceFingerprint"
      THEN RAISE EXCEPTION 'MAINTENANCE_IDENTITY_MISMATCH' USING ERRCODE='42501'; END IF;
      -- Reconciliation is an audit record, never a retry/reset instruction or
      -- a claim that the legacy binary supports native drain acknowledgement.
      IF EXISTS(SELECT 1 FROM jsonb_array_elements(maintenance_inventory->'items') item
        WHERE NOT EXISTS(SELECT 1 FROM jsonb_array_elements(p_payload->'evidence'->'reconciliations') r
          WHERE r->>'itemId'=item->>'id' AND (r->>'outcome' IN ('PHYSICAL_CONFIRMED','VOID_NO_REPLAY')
            OR (r->>'outcome'='PROTECTED_UNKNOWN' AND item->>'state'='FROZEN'
              AND item->>'pipelineState'='NEEDS_OPERATOR_ACTION'
              AND item->'dispatchMetadata'->'upgradeNoReplay'->>'entrySha256'=r->>'reference'
              AND EXISTS (SELECT 1 FROM jsonb_array_elements(p_payload->'evidence'->'isolationEvidence') proof
                WHERE proof->>'kind'='connector-work-inventory' AND proof->>'sha256'=
                  item->'dispatchMetadata'->'upgradeNoReplay'->>'journalSha256')))
            AND length(coalesce(r->>'reference',''))>0))
        OR EXISTS(SELECT 1 FROM jsonb_each(maintenance_inventory->'diagnostics') lease
          WHERE NOT EXISTS(SELECT 1 FROM jsonb_array_elements(p_payload->'evidence'->'reconciliations') r
            WHERE r->>'diagnosticId'=lease.key AND r->>'outcome' IN ('PHYSICAL_CONFIRMED','VOID_NO_REPLAY') AND length(coalesce(r->>'reference',''))>0))
      OR EXISTS(SELECT 1 FROM jsonb_array_elements(maintenance_inventory->'localDiagnostics') diagnostic
          WHERE NOT EXISTS(SELECT 1 FROM jsonb_array_elements(p_payload->'evidence'->'reconciliations') r
            WHERE r->>'diagnosticId'=diagnostic->'job'->>'testJobId' AND r->>'outcome' IN ('PHYSICAL_CONFIRMED','VOID_NO_REPLAY') AND length(coalesce(r->>'reference',''))>0))
      THEN RAISE EXCEPTION 'MAINTENANCE_RECONCILIATION_REQUIRED' USING ERRCODE='55000'; END IF;
      RETURN app_rls.printing_maintenance_gate(maintenance_scope,'AUTHORIZE',actor."userId",
        jsonb_build_object('binding',maintenance_binding,'tokenHash',p_payload->>'tokenHash',
          'expiresAt',p_payload->'evidence'->>'expiresAt','evidence',p_payload->'evidence'));
    END IF;
    RETURN app_rls.printing_maintenance_gate(maintenance_scope,
      CASE p_operation WHEN 'MAINTENANCE_REQUEST' THEN 'REQUEST' WHEN 'DIAGNOSTIC_LEASE' THEN 'LEASE' WHEN 'DIAGNOSTIC_COMPLETE' THEN 'COMPLETE' WHEN 'DIAGNOSTIC_ABORT' THEN 'ABORT' ELSE 'STATUS' END,
      actor."userId",p_payload||jsonb_build_object('requestId',p_request_id,'printerId',printer_row.id));
  END IF;
  IF p_operation IN ('UPDATE','DELETE','RELINK') THEN
    PERFORM app_rls.printing_maintenance_gate(CASE WHEN printer_row."printerRegistrationId" IS NOT NULL THEN jsonb_build_array('local',printer_row."printerRegistrationId")::text WHEN printer_row."gatewayId" IS NOT NULL THEN jsonb_build_array('gateway',printer_row."gatewayId",printer_row."orgId",printer_row."licenseeId",printer_row."assignedUserId")::text ELSE jsonb_build_array('printer',printer_row.id)::text END,'CHECK',NULL,jsonb_build_object('printerId',printer_row.id));
  END IF;

  IF p_operation='CREATE' THEN
    IF p_payload->>'connectionType' NOT IN ('NETWORK_DIRECT','NETWORK_IPP')
       OR length(btrim(coalesce(p_payload->>'name',''))) NOT BETWEEN 2 AND 180
       OR nullif(p_payload->>'gatewaySecretHash','') IS NOT NULL
          AND p_payload->>'gatewaySecretHash' !~ '^[0-9a-f]{64}$'
    THEN RAISE EXCEPTION 'PRINTING_INVALID_INPUT'; END IF;
    INSERT INTO public."Printer"(
      id,name,vendor,model,"connectionType","commandLanguage","ipAddress",host,port,
      "resourcePath","tlsEnabled","printerUri","deliveryMode","gatewayId","gatewaySecretHash",
      "gatewayStatus","gatewayLastError","orgId","licenseeId","createdByUserId","isActive",
      "isDefault","capabilitySummary","calibrationProfile","createdAt","updatedAt"
    ) VALUES (
      new_id,btrim(p_payload->>'name'),nullif(btrim(p_payload->>'vendor'),''),
      nullif(btrim(p_payload->>'model'),''),
      (p_payload->>'connectionType')::public."PrinterConnectionType",
      coalesce(nullif(p_payload->>'commandLanguage',''),'AUTO')::public."PrinterCommandLanguage",
      nullif(btrim(p_payload->>'ipAddress'),''),nullif(btrim(p_payload->>'host'),''),
      coalesce((p_payload->>'port')::integer,
        CASE WHEN p_payload->>'connectionType'='NETWORK_IPP' THEN 631 ELSE 9100 END),
      nullif(btrim(p_payload->>'resourcePath'),''),
      coalesce((p_payload->>'tlsEnabled')::boolean,false),nullif(btrim(p_payload->>'printerUri'),''),
      coalesce(nullif(p_payload->>'deliveryMode',''),'DIRECT')::public."PrinterDeliveryMode",
      nullif(p_payload->>'gatewayId',''),nullif(p_payload->>'gatewaySecretHash',''),
      CASE WHEN p_payload->>'deliveryMode'='SITE_GATEWAY' THEN 'PENDING' END,
      CASE WHEN p_payload->>'deliveryMode'='SITE_GATEWAY' THEN 'Gateway has not checked in yet.' END,
      scope_org,scope_licensee,actor."userId",coalesce((p_payload->>'isActive')::boolean,true),
      coalesce((p_payload->>'isDefault')::boolean,false),p_payload->'capabilitySummary',
      p_payload->'calibrationProfile',now_at,now_at
    ) RETURNING id,name,vendor,model,"connectionType","commandLanguage","ipAddress",host,port,
      "resourcePath","tlsEnabled","printerUri","deliveryMode","gatewayId","gatewayLastSeenAt",
      "gatewayStatus","gatewayLastError","nativePrinterId","agentId","deviceFingerprint",
      "printerRegistrationId","orgId","licenseeId","assignedUserId","createdByUserId","isActive",
      "isDefault","lastSeenAt","lastValidatedAt","lastValidationStatus","lastValidationMessage",
      "capabilitySummary","calibrationProfile",metadata,"createdAt","updatedAt" INTO printer_row;
  ELSIF p_operation='UPDATE' THEN
    IF printer_row."connectionType"='LOCAL_AGENT'
       AND p_payload - ARRAY['lastValidationStatus','lastValidationMessage','metadata']::text[] <> '{}'::jsonb
    THEN RAISE EXCEPTION 'PRINTING_INVALID_INPUT'; END IF;
    UPDATE public."Printer" SET
      name=coalesce(nullif(btrim(p_payload->>'name'),''),name),
      vendor=CASE WHEN p_payload ? 'vendor' THEN nullif(btrim(p_payload->>'vendor'),'') ELSE vendor END,
      model=CASE WHEN p_payload ? 'model' THEN nullif(btrim(p_payload->>'model'),'') ELSE model END,
      "commandLanguage"=coalesce(nullif(p_payload->>'commandLanguage','')::public."PrinterCommandLanguage","commandLanguage"),
      "ipAddress"=CASE WHEN p_payload ? 'ipAddress' THEN nullif(btrim(p_payload->>'ipAddress'),'') ELSE "ipAddress" END,
      host=CASE WHEN p_payload ? 'host' THEN nullif(btrim(p_payload->>'host'),'') ELSE host END,
      port=coalesce((p_payload->>'port')::integer,port),
      "resourcePath"=CASE WHEN p_payload ? 'resourcePath' THEN nullif(btrim(p_payload->>'resourcePath'),'') ELSE "resourcePath" END,
      "tlsEnabled"=coalesce((p_payload->>'tlsEnabled')::boolean,"tlsEnabled"),
      "printerUri"=CASE WHEN p_payload ? 'printerUri' THEN nullif(btrim(p_payload->>'printerUri'),'') ELSE "printerUri" END,
      "deliveryMode"=coalesce(nullif(p_payload->>'deliveryMode','')::public."PrinterDeliveryMode","deliveryMode"),
      "gatewayId"=coalesce(nullif(p_payload->>'gatewayId',''),"gatewayId"),
      "gatewaySecretHash"=coalesce(nullif(p_payload->>'gatewaySecretHash',''),"gatewaySecretHash"),
      "gatewayStatus"=CASE WHEN p_payload ? 'gatewaySecretHash' THEN 'PENDING' ELSE "gatewayStatus" END,
      "gatewayLastError"=CASE WHEN p_payload ? 'gatewaySecretHash' THEN 'Gateway has not checked in yet.' ELSE "gatewayLastError" END,
      "isActive"=coalesce((p_payload->>'isActive')::boolean,"isActive"),
      "isDefault"=coalesce((p_payload->>'isDefault')::boolean,"isDefault"),
      "capabilitySummary"=coalesce(p_payload->'capabilitySummary',"capabilitySummary"),
      "calibrationProfile"=coalesce(p_payload->'calibrationProfile',"calibrationProfile"),
      metadata=coalesce(p_payload->'metadata',metadata),
      "lastValidatedAt"=CASE WHEN p_payload ? 'lastValidationStatus' THEN now_at ELSE "lastValidatedAt" END,
      "lastValidationStatus"=coalesce(nullif(left(p_payload->>'lastValidationStatus',80),''),"lastValidationStatus"),
      "lastValidationMessage"=CASE WHEN p_payload ? 'lastValidationMessage'
        THEN nullif(left(p_payload->>'lastValidationMessage',500),'') ELSE "lastValidationMessage" END,
      "updatedAt"=now_at
      WHERE id=p_printer_id
      RETURNING id,name,vendor,model,"connectionType","commandLanguage","ipAddress",host,port,
        "resourcePath","tlsEnabled","printerUri","deliveryMode","gatewayId","gatewayLastSeenAt",
        "gatewayStatus","gatewayLastError","nativePrinterId","agentId","deviceFingerprint",
        "printerRegistrationId","orgId","licenseeId","assignedUserId","createdByUserId","isActive",
        "isDefault","lastSeenAt","lastValidatedAt","lastValidationStatus","lastValidationMessage",
        "capabilitySummary","calibrationProfile",metadata,"createdAt","updatedAt" INTO printer_row;
	  ELSIF p_operation='RELINK' THEN
	    PERFORM set_config(
	      'app.printing_registration_id',
	      coalesce(nullif(p_payload->>'printerRegistrationId',''),''),
	      true
	    );
	    IF NOT EXISTS (
      SELECT 1 FROM public."PrinterRegistration" pr
      WHERE pr.id=nullif(p_payload->>'printerRegistrationId','')
        AND pr."userId"=actor."userId" AND pr."trustStatus"='TRUSTED'
        AND pr."revokedAt" IS NULL
    ) OR NOT EXISTS (
      SELECT 1 FROM public."PrinterAttestation" pa
      WHERE pa."printerRegistrationId"=nullif(p_payload->>'printerRegistrationId','')
        AND pa."trustValid" AND pa."signatureValid" AND pa."expiresAt">now_at
        AND EXISTS (
          SELECT 1 FROM jsonb_array_elements(coalesce(pa.metadata->'printers','[]'::jsonb)) inventory
          WHERE coalesce(inventory->>'printerId',inventory->>'id')=nullif(p_payload->>'nativePrinterId','')
        )
    ) THEN RAISE EXCEPTION 'CONNECTOR_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;
    PERFORM app_rls.printing_maintenance_gate(jsonb_build_array('local',p_payload->>'printerRegistrationId')::text,'CHECK',NULL,'{}'::jsonb);
    UPDATE public."Printer" SET "isDefault"=false,"updatedAt"=now_at
      WHERE "assignedUserId"=actor."userId" AND "connectionType"='LOCAL_AGENT'
        AND id<>p_printer_id;
    UPDATE public."Printer" SET
      "printerRegistrationId"=NULL,"nativePrinterId"=NULL,
      "agentId"=NULL,"deviceFingerprint"=NULL,
      "isActive"=false,"isDefault"=false,
      "lastValidationStatus"='RELINKED',
      "lastValidationMessage"='Superseded by an explicit printer relink',
      "updatedAt"=now_at
      WHERE id<>p_printer_id
        AND "printerRegistrationId"=nullif(p_payload->>'printerRegistrationId','')
        AND "nativePrinterId"=nullif(p_payload->>'nativePrinterId','')
        AND "assignedUserId"=actor."userId"
        AND "orgId" IS NOT DISTINCT FROM scope_org
        AND "licenseeId" IS NOT DISTINCT FROM scope_licensee
        AND "connectionType"='LOCAL_AGENT';
    UPDATE public."Printer" SET
      "printerRegistrationId"=nullif(p_payload->>'printerRegistrationId',''),
      "nativePrinterId"=nullif(p_payload->>'nativePrinterId',''),
      "agentId"=nullif(p_payload->>'agentId',''),
      "deviceFingerprint"=nullif(p_payload->>'deviceFingerprint',''),
      "assignedUserId"=actor."userId","isActive"=true,"isDefault"=true,
      "lastSeenAt"=now_at,"lastValidatedAt"=now_at,"lastValidationStatus"='READY',
      "lastValidationMessage"=NULL,"updatedAt"=now_at
      WHERE id=p_printer_id
      RETURNING id,name,vendor,model,"connectionType","commandLanguage","ipAddress",host,port,
        "resourcePath","tlsEnabled","printerUri","deliveryMode","gatewayId","gatewayLastSeenAt",
        "gatewayStatus","gatewayLastError","nativePrinterId","agentId","deviceFingerprint",
        "printerRegistrationId","orgId","licenseeId","assignedUserId","createdByUserId","isActive",
        "isDefault","lastSeenAt","lastValidatedAt","lastValidationStatus","lastValidationMessage",
        "capabilitySummary","calibrationProfile",metadata,"createdAt","updatedAt" INTO printer_row;
  ELSIF p_operation='RETIRE' THEN
    IF actor.role<>'MANUFACTURER_ADMIN' OR printer_row."connectionType"<>'LOCAL_AGENT'
       OR printer_row."printerRegistrationId" IS NULL OR coalesce(p_payload,'{}'::jsonb)<>'{}'::jsonb
    THEN RAISE EXCEPTION 'PRINTING_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;
    PERFORM set_config('app.printing_registration_id',printer_row."printerRegistrationId",true);
    SELECT pr.id,pr."trustStatus",pr."revokedAt" INTO STRICT maintenance_registration
      FROM public."PrinterRegistration" pr
      WHERE pr.id=printer_row."printerRegistrationId" AND pr."userId"=actor."userId"
        AND pr."orgId" IS NOT DISTINCT FROM scope_org
        AND pr."licenseeId" IS NOT DISTINCT FROM scope_licensee FOR UPDATE;
    maintenance_scope:=jsonb_build_array('local',maintenance_registration.id)::text;
    maintenance_snapshot:=app_rls.printing_maintenance_gate(maintenance_scope,'STATUS',actor."userId",'{}'::jsonb);
    IF maintenance_snapshot->>'state'='DISPATCH_FENCED'
       AND maintenance_registration."trustStatus"='REVOKED'
       AND maintenance_registration."revokedAt" IS NOT NULL
       AND NOT EXISTS (SELECT 1 FROM public."Printer" p
         WHERE p."printerRegistrationId"=maintenance_registration.id AND p."isActive")
    THEN RETURN jsonb_build_object('printerId',printer_row.id,'registrationId',maintenance_registration.id,
      'retired',true,'idempotent',true,'dispatchFenced',true); END IF;
    IF maintenance_snapshot->>'state'<>'ACTIVE'
    THEN RAISE EXCEPTION 'CONNECTOR_MAINTENANCE_FENCED' USING ERRCODE='55000'; END IF;
    PERFORM app_rls.printing_maintenance_gate(maintenance_scope,'REQUEST',actor."userId",
      jsonb_build_object('requestId',p_request_id,'printerId',printer_row.id));
    UPDATE public."PrinterRegistration" SET "trustStatus"='REVOKED',"revokedAt"=coalesce("revokedAt",now_at),
      "trustReason"='Manufacturer retired connector',"updatedAt"=now_at
      WHERE id=maintenance_registration.id;
    UPDATE public."Printer" SET "isActive"=false,"isDefault"=false,
      "lastValidationStatus"='RETIRED',"lastValidationMessage"='Connector registration retired',
      "updatedAt"=now_at WHERE "printerRegistrationId"=maintenance_registration.id
      AND "assignedUserId"=actor."userId" AND "orgId" IS NOT DISTINCT FROM scope_org
      AND "licenseeId" IS NOT DISTINCT FROM scope_licensee;
    PERFORM app_rls.printing_write_audit(actor."userId",actor.role,scope_org,scope_licensee,
      'PRINTER_RETIRED','Printer',printer_row.id,jsonb_build_object('registrationId',maintenance_registration.id));
    RETURN jsonb_build_object('printerId',printer_row.id,'registrationId',maintenance_registration.id,
      'retired',true,'idempotent',false,'dispatchFenced',true);
  ELSIF p_operation='DELETE' THEN
    IF printer_row."connectionType"='LOCAL_AGENT'
       OR EXISTS (SELECT 1 FROM public."PrintJob" j
         WHERE j."printerId"=printer_row.id AND j.status IN ('PENDING','SENT','PAUSED'))
    THEN RAISE EXCEPTION 'INVALID_STATE_TRANSITION'; END IF;
    DELETE FROM public."Printer" p WHERE p.id=p_printer_id
    RETURNING id,name,vendor,model,"connectionType","commandLanguage","ipAddress",host,port,
      "resourcePath","tlsEnabled","printerUri","deliveryMode","gatewayId","gatewayLastSeenAt",
      "gatewayStatus","gatewayLastError","nativePrinterId","agentId","deviceFingerprint",
      "printerRegistrationId","orgId","licenseeId","assignedUserId","createdByUserId","isActive",
      "isDefault","lastSeenAt","lastValidatedAt","lastValidationStatus","lastValidationMessage",
      "capabilitySummary","calibrationProfile",metadata,"createdAt","updatedAt" INTO printer_row;
  END IF;

  audit_action:=CASE p_operation
    WHEN 'AUDIT_TEST' THEN 'PRINTER_TESTED'
    WHEN 'AUDIT_TEST_LABEL_ATTENTION' THEN 'PRINTER_TEST_LABEL_ATTENTION'
    WHEN 'AUDIT_TEST_LABEL_CONFIRMED' THEN 'PRINTER_TEST_LABEL_CONFIRMED'
    WHEN 'AUDIT_TEST_LABEL_QUEUED' THEN 'PRINTER_TEST_LABEL_QUEUED'
    WHEN 'AUDIT_DISCOVERY' THEN 'PRINTER_DISCOVERED'
    ELSE 'PRINTER_'||p_operation END;
  PERFORM app_rls.printing_write_audit(
    actor."userId",actor.role,scope_org,scope_licensee,
    audit_action,'Printer',printer_row.id,
    jsonb_build_object('connectionType',printer_row."connectionType",
      'deliveryMode',printer_row."deliveryMode",
      'evidence',coalesce(p_payload->'evidence','{}'::jsonb))
  );
  RETURN to_jsonb(printer_row)||jsonb_build_object('removed',p_operation='DELETE');
END
$fn$;
REVOKE ALL ON FUNCTION app_rls.printing_printer_administration(text,text,text,text,text,jsonb) FROM PUBLIC;
COMMIT;
