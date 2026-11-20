\set ON_ERROR_STOP on
BEGIN;
DO $$ BEGIN
  IF NOT pg_has_role(session_user,'mscqr_rls_cert_owner','SET') THEN RAISE EXCEPTION 'administrative executor lacks SET authority for mscqr_rls_cert_owner'; END IF;
END $$;
SET ROLE "mscqr_rls_cert_owner";
GRANT USAGE,CREATE ON SCHEMA app_rls TO "mscqr_rls_cert_auth_owner";
RESET ROLE;
DO $$ BEGIN
  IF NOT pg_has_role(session_user,'mscqr_rls_cert_auth_owner','SET') THEN RAISE EXCEPTION 'administrative executor lacks SET authority for mscqr_rls_cert_auth_owner'; END IF;
END $$;
SET ROLE "mscqr_rls_cert_auth_owner";
-- Upgrade-only replacements. The historical C02 package stays unchanged.
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
       'CREATE','UPDATE','DELETE','RELINK','MAINTENANCE_REQUEST','MAINTENANCE_STATUS','DIAGNOSTIC_LEASE','DIAGNOSTIC_COMPLETE','DIAGNOSTIC_ABORT','MAINTENANCE_INVENTORY','MAINTENANCE_AUTHORIZE','MAINTENANCE_CONSUME','MAINTENANCE_VERIFY','MAINTENANCE_RELEASE',
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
      INTO STRICT printer_row FROM public."Printer" p WHERE p.id=p_printer_id FOR UPDATE;
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
        (p_operation LIKE 'AUDIT_%' OR p_operation IN ('MAINTENANCE_REQUEST','MAINTENANCE_STATUS','DIAGNOSTIC_LEASE','DIAGNOSTIC_COMPLETE','DIAGNOSTIC_ABORT','MAINTENANCE_INVENTORY','MAINTENANCE_AUTHORIZE','MAINTENANCE_CONSUME','MAINTENANCE_VERIFY','MAINTENANCE_RELEASE')) AND printer_row."assignedUserId"=actor."userId"
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

CREATE OR REPLACE FUNCTION app_rls.printing_reissue_request(
  p_capability text,p_purpose text,p_request_id text,p_operation text,p_reissue_id text,
  p_original_job_id text,p_quantity integer,p_range_start text,p_range_end text,p_reason text,p_decision_note text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; batch_row record; job_row record; original_session_row record; request_row record; request_id text; replacement_job_id text;
  target_batch_id text; target_original_job_id text;
  replacement_session_id text; original_session_id text; moved_count integer;
  item_count integer; safe_item_count integer;
  now_at timestamp without time zone:=transaction_timestamp();
BEGIN
  IF p_purpose<>'printing-reissue' OR p_operation NOT IN ('CREATE','FORWARD','APPROVE','REJECT','CANCEL','EXECUTE')
     OR length(coalesce(p_reason,''))>500 OR length(coalesce(p_decision_note,''))>500
     OR (p_operation='CREATE' AND p_quantity NOT BETWEEN 1 AND 200000)
     OR (p_range_start IS NOT NULL AND p_range_end IS NOT NULL AND p_range_start>p_range_end)
  THEN RAISE EXCEPTION 'PRINTING_INVALID_INPUT'; END IF;
  IF p_operation='CREATE' THEN
    SELECT * INTO STRICT actor FROM app_rls.printing_bind_actor(p_capability,p_purpose,p_request_id,NULL);
    PERFORM set_config('app.printing_job_id',p_original_job_id,true);
    SELECT j."batchId" INTO STRICT target_batch_id FROM public."PrintJob" j WHERE j.id=p_original_job_id;
    PERFORM pg_advisory_xact_lock(hashtextextended('printing_batch_'||target_batch_id,0));
    SELECT j.id,j."batchId",j."manufacturerId",j."printerId",j.status,j."pipelineState",
      j.quantity,j."itemCount",j."sentAt",j."confirmedAt",j."completedAt"
      INTO STRICT job_row FROM public."PrintJob" j WHERE j.id=p_original_job_id FOR UPDATE;
    IF job_row."batchId" IS DISTINCT FROM target_batch_id THEN RAISE EXCEPTION 'INVALID_STATE_TRANSITION'; END IF;
    SELECT * INTO STRICT actor FROM app_rls.printing_bind_actor(p_capability,p_purpose,p_request_id,job_row."batchId");
    SELECT ps.id,ps.status,ps."totalItems",ps."issuedItems",ps."confirmedItems",
      ps."frozenItems",ps."completedAt" INTO STRICT original_session_row
      FROM public."PrintSession" ps WHERE ps."printJobId"=job_row.id;
    PERFORM set_config('app.printing_job_id',p_original_job_id,true),
            set_config('app.printing_original_session_id',original_session_row.id,true);
    IF actor.role<>'MANUFACTURER_ADMIN' OR job_row."manufacturerId"<>actor."userId"
       OR job_row.status NOT IN ('FAILED','PARTIALLY_COMPLETED','CONFIRMED','STOPPED')
    THEN RAISE EXCEPTION 'PRINTING_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;
    SELECT r.id INTO request_id FROM public."PrintReissueRequest" r
      WHERE r."originalPrintJobId"=job_row.id AND r.status IN ('PENDING','APPROVED');
    IF request_id IS NOT NULL THEN
      RETURN (SELECT to_jsonb(r)||jsonb_build_object('idempotent',true) FROM (
        SELECT request.id,request."originalPrintJobId",request."replacementPrintJobId",
          request."requestedByUserId",request."approvedByUserId",request."licenseeId",
          request."manufacturerId",request."batchId",request."requestedByRole",
          request."targetApproverRole",request.quantity,request."affectedRangeStart",
          request."affectedRangeEnd",request."decisionNote",request."approvalReferenceId",
          request.status,request.reason,request."rejectionReason",request."approvedAt",
          request."rejectedAt",request."executedAt",request."createdAt",request."updatedAt"
        FROM public."PrintReissueRequest" request WHERE request.id=request_id
      ) r);
    END IF;
    SELECT b."lifecycleState",b."releasedAt",b."suspendedAt" INTO STRICT batch_row
      FROM public."Batch" b WHERE b.id=job_row."batchId" FOR SHARE;
    IF batch_row."lifecycleState" IS NULL OR batch_row."lifecycleState"='RELEASED'
       OR (job_row.status='STOPPED' AND batch_row."lifecycleState" NOT IN ('CODES_GENERATED','PRINT_ACKNOWLEDGED'))
       OR batch_row."releasedAt" IS NOT NULL OR batch_row."suspendedAt" IS NOT NULL
    THEN RAISE EXCEPTION 'INVALID_STATE_TRANSITION'; END IF;
    IF job_row.status='STOPPED' THEN
      IF job_row."pipelineState"<>'STOPPED' OR original_session_row.status<>'STOPPED'
         OR job_row."completedAt" IS NULL OR original_session_row."completedAt" IS NULL
         OR job_row."sentAt" IS NOT NULL OR job_row."confirmedAt" IS NOT NULL
         OR original_session_row."issuedItems"<>0 OR original_session_row."confirmedItems"<>0
         OR original_session_row."frozenItems"<>0 OR job_row."itemCount" IS DISTINCT FROM job_row.quantity
         OR original_session_row."totalItems"<>job_row.quantity
         OR coalesce(p_quantity,job_row.quantity)<>job_row.quantity
         OR p_range_start IS NOT NULL OR p_range_end IS NOT NULL
      THEN RAISE EXCEPTION 'PHYSICAL_OUTCOME_UNCONFIRMED'; END IF;
      SELECT count(*),count(*) FILTER (WHERE
        pi.state='CANCELLED' AND pi."pipelineState"='STOPPED' AND pi."attemptCount"=0
        AND pi."currentRenderTokenHash" IS NULL AND pi."deviceJobRef" IS NULL
        AND pi."issuedAt" IS NULL AND pi."dispatchedAt" IS NULL AND pi."agentAckedAt" IS NULL
        AND pi."confirmationDeadlineAt" IS NULL AND pi."printConfirmedAt" IS NULL
        AND pi."closedAt" IS NULL AND pi."frozenAt" IS NULL AND pi."failedAt" IS NULL
        AND coalesce(pi."dispatchMetadata",'null'::jsonb) IN ('null'::jsonb,'{}'::jsonb)
        AND coalesce(pi."confirmationEvidence",'null'::jsonb) IN ('null'::jsonb,'{}'::jsonb)
        AND q."batchId"=job_row."batchId" AND q."licenseeId"=actor."batchLicenseeId"
        AND q."printJobId"=job_row.id AND q.status='ACTIVATED' AND pi.code=q.code
        AND q."printedAt" IS NULL AND q."scannedAt" IS NULL AND q."scanCount"=0
        AND q."tokenNonce" IS NOT NULL AND q."tokenIssuedAt" IS NOT NULL
        AND q."tokenHash" IS NOT NULL AND q."tokenExpiresAt">clock_timestamp()
      ) INTO item_count,safe_item_count FROM public."PrintItem" pi
      JOIN public."QRCode" q ON q.id=pi."qrCodeId" WHERE pi."printSessionId"=original_session_row.id;
      IF item_count<>job_row.quantity OR safe_item_count<>job_row.quantity
         OR EXISTS (SELECT 1 FROM public."PrintItemEvent" e JOIN public."PrintItem" pi ON pi.id=e."printItemId"
           WHERE pi."printSessionId"=original_session_row.id)
         OR EXISTS (SELECT 1 FROM public."PrintJobChunk" c WHERE c."printJobId"=job_row.id
           OR c."printSessionId"=original_session_row.id)
         OR EXISTS (SELECT 1 FROM public."PrintAuditEvent" e WHERE e."printJobId"=job_row.id)
         OR EXISTS (SELECT 1 FROM public."PrintJob" j JOIN public."PrintSession" ps ON ps."printJobId"=j.id
           WHERE j."batchId"=job_row."batchId" AND j.id<>job_row.id
             AND j.status IN ('PENDING','SENT','PAUSED') AND ps.status IN ('ACTIVE','PAUSED','RESUME_PENDING'))
      THEN RAISE EXCEPTION 'PHYSICAL_OUTCOME_UNCONFIRMED'; END IF;
    END IF;
    request_id:=gen_random_uuid()::text;
    PERFORM set_config('app.printing_reissue_id',request_id,true);
    INSERT INTO public."PrintReissueRequest"(
      id,"originalPrintJobId","requestedByUserId","licenseeId","manufacturerId","batchId",
      "requestedByRole","targetApproverRole",quantity,"affectedRangeStart","affectedRangeEnd",
      status,reason,"createdAt","updatedAt"
    ) VALUES (
      request_id,job_row.id,actor."userId",actor."batchLicenseeId",job_row."manufacturerId",job_row."batchId",
      actor.role,'LICENSEE_ADMIN',p_quantity,p_range_start,p_range_end,'PENDING',btrim(p_reason),now_at,now_at
    ) RETURNING id,"originalPrintJobId","replacementPrintJobId","requestedByUserId",
      "approvedByUserId","licenseeId","manufacturerId","batchId","requestedByRole",
      "targetApproverRole",quantity,"affectedRangeStart","affectedRangeEnd","decisionNote",
      "approvalReferenceId",status,reason,"rejectionReason","approvedAt","rejectedAt",
      "executedAt","createdAt","updatedAt" INTO request_row;
  ELSE
    SELECT * INTO STRICT actor FROM app_rls.printing_bind_actor(p_capability,p_purpose,p_request_id,NULL);
    PERFORM set_config('app.printing_reissue_id',p_reissue_id,true);
    IF p_operation='EXECUTE' THEN
      SELECT r."originalPrintJobId" INTO STRICT target_original_job_id
        FROM public."PrintReissueRequest" r WHERE r.id=p_reissue_id;
      PERFORM set_config('app.printing_job_id',target_original_job_id,true);
      SELECT j."batchId" INTO STRICT target_batch_id FROM public."PrintJob" j WHERE j.id=target_original_job_id;
      PERFORM pg_advisory_xact_lock(hashtextextended('printing_batch_'||target_batch_id,0));
    END IF;
    SELECT r.id,r."originalPrintJobId",r."replacementPrintJobId",r."requestedByUserId",
      r."approvedByUserId",r."licenseeId",r."manufacturerId",r."batchId",r."requestedByRole",
      r."targetApproverRole",r.quantity,r."affectedRangeStart",r."affectedRangeEnd",r."decisionNote",
      r."approvalReferenceId",r.status,r.reason,r."rejectionReason",r."approvedAt",r."rejectedAt",
      r."executedAt",r."createdAt",r."updatedAt" INTO STRICT request_row
      FROM public."PrintReissueRequest" r
      WHERE r.id=p_reissue_id FOR UPDATE;
    IF p_operation='EXECUTE' AND request_row."originalPrintJobId" IS DISTINCT FROM target_original_job_id
    THEN RAISE EXCEPTION 'INVALID_STATE_TRANSITION'; END IF;
    PERFORM set_config('app.printing_job_id',request_row."originalPrintJobId",true);
    IF p_operation<>'EXECUTE' THEN
      SELECT j."batchId" INTO STRICT target_batch_id FROM public."PrintJob" j
        WHERE j.id=request_row."originalPrintJobId";
    END IF;
    SELECT * INTO STRICT actor FROM app_rls.printing_bind_actor(p_capability,p_purpose,p_request_id,target_batch_id);
    PERFORM set_config('app.printing_reissue_id',p_reissue_id,true),
            set_config('app.printing_job_id',request_row."originalPrintJobId",true);
    IF p_operation='EXECUTE' THEN
      IF actor.role<>'MANUFACTURER_ADMIN' OR request_row."requestedByUserId"<>actor."userId"
         OR request_row.status::text NOT IN ('APPROVED','EXECUTED')
      THEN RAISE EXCEPTION 'PRINTING_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;
      IF request_row.status::text='EXECUTED' THEN
        RETURN to_jsonb(request_row)||jsonb_build_object('idempotent',true);
      END IF;
      SELECT j.id,j."batchId",j."manufacturerId",j."printerId",j.status,j."pipelineState",j."printMode",
        j."payloadType",j.quantity,j."itemCount",j."sentAt",j."confirmedAt",j."completedAt",
        ps.id AS original_session_id,ps.status AS original_session_status,
        ps."totalItems" AS original_total_items,ps."issuedItems" AS original_issued_items,
        ps."confirmedItems" AS original_confirmed_items,ps."frozenItems" AS original_frozen_items,
        ps."completedAt" AS original_completed_at,ps."printerRegistrationId" AS original_registration_id
        INTO STRICT job_row
        FROM public."PrintJob" j JOIN public."PrintSession" ps ON ps."printJobId"=j.id
        WHERE j.id=request_row."originalPrintJobId" FOR UPDATE OF j;
      IF job_row."batchId" IS DISTINCT FROM target_batch_id THEN RAISE EXCEPTION 'INVALID_STATE_TRANSITION'; END IF;
      SELECT b."lifecycleState",b."releasedAt",b."suspendedAt" INTO STRICT batch_row
        FROM public."Batch" b WHERE b.id=job_row."batchId" FOR SHARE;
      IF batch_row."lifecycleState" IS NULL OR batch_row."lifecycleState"='RELEASED'
         OR (job_row.status='STOPPED' AND batch_row."lifecycleState" NOT IN ('CODES_GENERATED','PRINT_ACKNOWLEDGED'))
         OR batch_row."releasedAt" IS NOT NULL OR batch_row."suspendedAt" IS NOT NULL
      THEN RAISE EXCEPTION 'INVALID_STATE_TRANSITION'; END IF;
      IF job_row.status NOT IN ('FAILED','PARTIALLY_COMPLETED','CONFIRMED','STOPPED','CANCELLED')
      THEN RAISE EXCEPTION 'INVALID_STATE_TRANSITION'; END IF;
      original_session_id:=job_row.original_session_id;
      PERFORM set_config('app.printing_original_session_id',original_session_id,true);
      IF job_row."pipelineState"='NEEDS_OPERATOR_ACTION' OR EXISTS (
        SELECT 1 FROM public."PrintItem" pi WHERE pi."printSessionId"=job_row.original_session_id
          AND pi."dispatchMetadata" ? 'upgradeNoReplay')
      THEN RAISE EXCEPTION 'PHYSICAL_OUTCOME_UNCONFIRMED'; END IF;
      IF job_row.status='STOPPED' THEN
        IF job_row."pipelineState"<>'STOPPED' OR job_row.original_session_status<>'STOPPED'
           OR job_row."completedAt" IS NULL OR job_row.original_completed_at IS NULL
           OR job_row."sentAt" IS NOT NULL OR job_row."confirmedAt" IS NOT NULL
           OR job_row.original_issued_items<>0 OR job_row.original_confirmed_items<>0
           OR job_row.original_frozen_items<>0 OR job_row."itemCount" IS DISTINCT FROM job_row.quantity
           OR job_row.original_total_items<>job_row.quantity
           OR coalesce(request_row.quantity,job_row.quantity)<>job_row.quantity
           OR request_row."affectedRangeStart" IS NOT NULL OR request_row."affectedRangeEnd" IS NOT NULL
        THEN RAISE EXCEPTION 'PHYSICAL_OUTCOME_UNCONFIRMED'; END IF;
        SELECT count(*),count(*) FILTER (WHERE
          pi.state='CANCELLED' AND pi."pipelineState"='STOPPED' AND pi."attemptCount"=0
          AND pi."currentRenderTokenHash" IS NULL AND pi."deviceJobRef" IS NULL
          AND pi."issuedAt" IS NULL AND pi."dispatchedAt" IS NULL AND pi."agentAckedAt" IS NULL
          AND pi."confirmationDeadlineAt" IS NULL AND pi."printConfirmedAt" IS NULL
          AND pi."closedAt" IS NULL AND pi."frozenAt" IS NULL AND pi."failedAt" IS NULL
          AND coalesce(pi."dispatchMetadata",'null'::jsonb) IN ('null'::jsonb,'{}'::jsonb)
          AND coalesce(pi."confirmationEvidence",'null'::jsonb) IN ('null'::jsonb,'{}'::jsonb)
          AND q."batchId"=job_row."batchId" AND q."licenseeId"=actor."batchLicenseeId"
          AND q."printJobId"=job_row.id AND q.status='ACTIVATED' AND pi.code=q.code
          AND q."printedAt" IS NULL AND q."scannedAt" IS NULL AND q."scanCount"=0
          AND q."tokenNonce" IS NOT NULL AND q."tokenIssuedAt" IS NOT NULL
          AND q."tokenHash" IS NOT NULL AND q."tokenExpiresAt">clock_timestamp()
        ) INTO item_count,safe_item_count FROM public."PrintItem" pi
        JOIN public."QRCode" q ON q.id=pi."qrCodeId" WHERE pi."printSessionId"=original_session_id;
        IF item_count<>job_row.quantity OR safe_item_count<>job_row.quantity
           OR EXISTS (SELECT 1 FROM public."PrintItemEvent" e JOIN public."PrintItem" pi ON pi.id=e."printItemId"
             WHERE pi."printSessionId"=original_session_id)
           OR EXISTS (SELECT 1 FROM public."PrintJobChunk" c WHERE c."printJobId"=job_row.id
             OR c."printSessionId"=original_session_id)
           OR EXISTS (SELECT 1 FROM public."PrintAuditEvent" e WHERE e."printJobId"=job_row.id)
           OR EXISTS (SELECT 1 FROM public."PrintJob" j JOIN public."PrintSession" ps ON ps."printJobId"=j.id
             WHERE j."batchId"=job_row."batchId" AND j.id<>job_row.id
               AND j.status IN ('PENDING','SENT','PAUSED') AND ps.status IN ('ACTIVE','PAUSED','RESUME_PENDING'))
        THEN RAISE EXCEPTION 'PHYSICAL_OUTCOME_UNCONFIRMED'; END IF;
      END IF;
      IF job_row."printMode"='LOCAL_AGENT'::public."PrintDispatchMode" THEN
        IF job_row.original_registration_id IS NULL THEN RAISE EXCEPTION 'PRINTER_ATTESTATION_STALE'; END IF;
        PERFORM set_config('app.printing_registration_id',job_row.original_registration_id,true);
        IF NOT EXISTS (
          SELECT 1 FROM public."PrinterAttestation" pa
          JOIN public."Printer" p ON p.id=job_row."printerId"
          WHERE pa."printerRegistrationId"=job_row.original_registration_id
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
              IN (p.id,coalesce(p."nativePrinterId",''))
            AND ((pa.metadata->>'source' IS DISTINCT FROM 'PERSISTENT_SESSION' AND NOT EXISTS (
              SELECT 1 FROM public."PrinterAgentSession" prior
              WHERE prior."registrationId"=pa."printerRegistrationId"
            )) OR EXISTS (
              SELECT 1 FROM public."PrinterAgentSession" s
              WHERE s.id=pa.metadata->>'sessionId' AND s."registrationId"=pa."printerRegistrationId"
                AND s."connectionState"='CONNECTED' AND s."revokedAt" IS NULL
                AND s."expiresAt">clock_timestamp()
                AND s."lastSignedHeartbeatAt">clock_timestamp()-interval '35 seconds'
                AND s."selectedPrinterId"=pa.metadata->>'selectedPrinterId'
                AND s.metadata->>'printerId'=p.id
                AND s.metadata->>'manufacturerId'=p."assignedUserId"
                AND s.metadata->>'orgId' IS NOT DISTINCT FROM p."orgId"
                AND s.metadata->>'licenseeId' IS NOT DISTINCT FROM p."licenseeId"
            ))
        ) THEN RAISE EXCEPTION 'PRINTER_ATTESTATION_STALE'; END IF;
      END IF;
      replacement_job_id:=gen_random_uuid()::text;
      replacement_session_id:=gen_random_uuid()::text;
      PERFORM set_config('app.printing_job_id',replacement_job_id,true),
              set_config('app.printing_session_row_id',replacement_session_id,true),
              set_config('app.printing_original_session_id',original_session_id,true);
      INSERT INTO public."PrintJob"(
        id,"jobNumber","batchId","manufacturerId","printerId",status,"printMode","pipelineState",
        "payloadType",quantity,"itemCount","rangeStart","rangeEnd","reprintOfJobId","approvedByUserId",
        "reprintReason","createdAt","updatedAt"
      ) VALUES (
        replacement_job_id,'RJ-'||to_char(now_at,'YYYYMMDDHH24MISS')||'-'||upper(substr(replacement_job_id,1,6)),
        job_row."batchId",job_row."manufacturerId",job_row."printerId",'PENDING',job_row."printMode",
        'QUEUED',job_row."payloadType",coalesce(request_row.quantity,job_row.quantity),
        coalesce(request_row.quantity,job_row."itemCount"),request_row."affectedRangeStart",
        request_row."affectedRangeEnd",job_row.id,request_row."approvedByUserId",request_row.reason,now_at,now_at
      );
      INSERT INTO public."PrintSession"(
        id,"printJobId","batchId","manufacturerId","printerRegistrationId","printerId",status,"totalItems","createdAt","updatedAt"
      ) VALUES (
        replacement_session_id,replacement_job_id,job_row."batchId",job_row."manufacturerId",
        job_row.original_registration_id,job_row."printerId",'ACTIVE',
        coalesce(request_row.quantity,job_row."itemCount"),now_at,now_at
      );
      WITH eligible AS (
        SELECT pi.id,pi."qrCodeId"
        FROM public."PrintItem" pi
        JOIN public."QRCode" q ON q.id=pi."qrCodeId"
        WHERE pi."printSessionId"=original_session_id
          AND pi."printConfirmedAt" IS NULL
          AND pi.state IN ('FAILED','FROZEN','CANCELLED','RESERVED','ISSUED')
          AND q."batchId"=job_row."batchId"
          AND (request_row."affectedRangeStart" IS NULL OR q."displayCode">=request_row."affectedRangeStart")
          AND (request_row."affectedRangeEnd" IS NULL OR q."displayCode"<=request_row."affectedRangeEnd")
        ORDER BY pi."issueSequence" NULLS LAST,pi.id
        FOR UPDATE
        LIMIT coalesce(request_row.quantity,job_row."itemCount")
      ), moved AS (
        UPDATE public."PrintItem" pi SET
          "printSessionId"=replacement_session_id,state='RESERVED', "pipelineState"='QUEUED',
          "attemptCount"=0,"deviceJobRef"=NULL,"dispatchMetadata"=NULL,"confirmationEvidence"=NULL,
          "issuedAt"=NULL,"dispatchedAt"=NULL,"agentAckedAt"=NULL,"printConfirmedAt"=NULL,
          "failedAt"=NULL,"failureReason"=NULL,"updatedAt"=now_at
        FROM eligible e WHERE pi.id=e.id RETURNING pi."qrCodeId"
      )
      UPDATE public."QRCode" q SET "printJobId"=replacement_job_id,"updatedAt"=now_at
        FROM moved m WHERE q.id=m."qrCodeId";
      GET DIAGNOSTICS moved_count = ROW_COUNT;
      IF moved_count<>coalesce(request_row.quantity,job_row."itemCount")
      THEN RAISE EXCEPTION 'NOT_ENOUGH_CODES'; END IF;
      UPDATE public."PrintReissueRequest" SET status='EXECUTED',
        "replacementPrintJobId"=replacement_job_id,"executedAt"=now_at,"updatedAt"=now_at
        WHERE id=request_row.id
        RETURNING id,"originalPrintJobId","replacementPrintJobId","requestedByUserId",
          "approvedByUserId","licenseeId","manufacturerId","batchId","requestedByRole",
          "targetApproverRole",quantity,"affectedRangeStart","affectedRangeEnd","decisionNote",
          "approvalReferenceId",status,reason,"rejectionReason","approvedAt","rejectedAt",
          "executedAt","createdAt","updatedAt" INTO request_row;
      request_id:=request_row.id;
    ELSE
      IF p_operation='CANCEL' THEN
        IF request_row."requestedByUserId"<>actor."userId" THEN
          RAISE EXCEPTION 'PRINTING_BOUNDARY_DENIED' USING ERRCODE='42501';
        END IF;
      ELSIF request_row."requestedByUserId"=actor."userId" THEN
        RAISE EXCEPTION 'MAKER_CANNOT_APPROVE' USING ERRCODE='42501';
      ELSIF p_operation='FORWARD' THEN
        IF actor.role<>'LICENSEE_ADMIN' OR request_row."targetApproverRole"<>'LICENSEE_ADMIN'
        THEN RAISE EXCEPTION 'PRINTING_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;
      ELSIF p_operation='APPROVE' THEN
        IF actor.role NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') OR request_row."targetApproverRole"<>'SUPER_ADMIN'
        THEN RAISE EXCEPTION 'PRINTING_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;
      ELSIF p_operation='REJECT' AND NOT (
        (actor.role='LICENSEE_ADMIN' AND request_row."targetApproverRole"='LICENSEE_ADMIN')
        OR (actor.role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') AND request_row."targetApproverRole"='SUPER_ADMIN')
      ) THEN RAISE EXCEPTION 'PRINTING_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;
      IF request_row.status::text<>'PENDING' THEN RAISE EXCEPTION 'INVALID_STATE_TRANSITION'; END IF;
      IF p_operation='FORWARD' THEN
        UPDATE public."PrintReissueRequest" SET "targetApproverRole"='SUPER_ADMIN',
          "decisionNote"=nullif(btrim(p_decision_note),''),"updatedAt"=now_at
          WHERE id=request_row.id
          RETURNING id,"originalPrintJobId","replacementPrintJobId","requestedByUserId",
            "approvedByUserId","licenseeId","manufacturerId","batchId","requestedByRole",
            "targetApproverRole",quantity,"affectedRangeStart","affectedRangeEnd","decisionNote",
            "approvalReferenceId",status,reason,"rejectionReason","approvedAt","rejectedAt",
            "executedAt","createdAt","updatedAt" INTO request_row;
      ELSE
    UPDATE public."PrintReissueRequest" SET
      status=CASE p_operation WHEN 'APPROVE' THEN 'APPROVED' WHEN 'REJECT' THEN 'REJECTED' ELSE 'CANCELLED' END::public."ReissueRequestStatus",
      "approvedByUserId"=CASE WHEN p_operation='APPROVE' THEN actor."userId" ELSE "approvedByUserId" END,
      "approvedAt"=CASE WHEN p_operation='APPROVE' THEN now_at ELSE "approvedAt" END,
      "rejectedAt"=CASE WHEN p_operation='REJECT' THEN now_at ELSE "rejectedAt" END,
      "decisionNote"=nullif(btrim(p_decision_note),''),
      "rejectionReason"=CASE WHEN p_operation='REJECT' THEN nullif(btrim(p_reason),'') ELSE "rejectionReason" END,
      "updatedAt"=now_at WHERE id=request_row.id
      RETURNING id,"originalPrintJobId","replacementPrintJobId","requestedByUserId",
        "approvedByUserId","licenseeId","manufacturerId","batchId","requestedByRole",
        "targetApproverRole",quantity,"affectedRangeStart","affectedRangeEnd","decisionNote",
        "approvalReferenceId",status,reason,"rejectionReason","approvedAt","rejectedAt",
        "executedAt","createdAt","updatedAt" INTO request_row;
      END IF;
    request_id:=request_row.id;
    END IF;
  END IF;
  PERFORM app_rls.printing_write_audit(actor."userId",actor.role,actor."organizationId",actor."batchLicenseeId",
    'PRINT_REISSUE_'||p_operation,'PrintReissueRequest',request_id,
    jsonb_build_object('originalPrintJobId',coalesce(request_row."originalPrintJobId",p_original_job_id),'quantity',p_quantity)
      || CASE WHEN p_operation='EXECUTE' THEN jsonb_build_object(
        'replacementPrintJobId',replacement_job_id,'originalPrintSessionId',original_session_id,
        'replacementPrintSessionId',replacement_session_id,'movedCount',moved_count)
        ELSE '{}'::jsonb END);
  RETURN to_jsonb(request_row)||jsonb_build_object('idempotent',false);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.printing_upgrade_protect_unknown(
  p_capability text, p_request_id text, p_printer_id text,
  p_fence_request_id text, p_journal_sha256 text, p_entries jsonb
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public
AS $fn$
DECLARE snapshot jsonb; registration_id text; expected_count integer;
  matches jsonb; entry jsonb; item_row record; marker jsonb; added integer:=0;
BEGIN
  IF session_user <> 'mscqr_rls_cert_app' OR p_journal_sha256 IS NULL OR p_journal_sha256 !~ '^[a-f0-9]{64}$' OR
     p_fence_request_id IS NULL OR p_fence_request_id !~* '^[0-9a-f-]{36}$' OR
     p_entries IS NULL OR jsonb_typeof(p_entries) IS DISTINCT FROM 'array' OR
     jsonb_array_length(p_entries) NOT BETWEEN 1 AND 512
  THEN RAISE EXCEPTION 'UPGRADE_NO_REPLAY_DENIED' USING ERRCODE='42501'; END IF;
  expected_count:=jsonb_array_length(p_entries);
  IF EXISTS (
    SELECT 1 FROM jsonb_to_recordset(p_entries) AS e(name text,sha256 text,"printJobId" text,"printItemId" text,"attemptId" text,state text)
    WHERE e.name IS NULL OR e.sha256 IS NULL OR e.state IS NULL OR
      e.name !~ '^[a-f0-9]{64}(\.gateway-attempt)?\.json$' OR e.sha256 !~ '^[a-f0-9]{64}$' OR
      e.state NOT IN ('ATTEMPT_RESERVED','PREPARING','PRE_DISPATCH_FAILURE','PRE_DISPATCH_REPORTED') OR
      e."printJobId" IS NULL OR e."printItemId" IS NULL OR
      (e."attemptId" IS NOT NULL AND e."attemptId" !~* '^[0-9a-f-]{36}$')
  ) OR (SELECT count(DISTINCT e."printItemId") FROM jsonb_to_recordset(p_entries) AS e("printItemId" text))<>expected_count OR
       (SELECT count(DISTINCT e.name) FROM jsonb_to_recordset(p_entries) AS e(name text))<>expected_count
  THEN RAISE EXCEPTION 'UPGRADE_NO_REPLAY_DENIED' USING ERRCODE='42501'; END IF;

  -- The maintenance gate serializes claims and this write on the same printer.
  snapshot:=app_rls.printing_printer_administration(
    p_capability,'printing-printer-admin',p_request_id,'MAINTENANCE_INVENTORY',p_printer_id,'{}'::jsonb);
  IF current_setting('app.printing_role',true)<>'MANUFACTURER_ADMIN' OR
     snapshot->>'state'<>'DISPATCH_FENCED' OR snapshot->>'requestId' IS DISTINCT FROM p_fence_request_id
  THEN RAISE EXCEPTION 'UPGRADE_NO_REPLAY_DENIED' USING ERRCODE='42501'; END IF;
  SELECT p."printerRegistrationId" INTO STRICT registration_id FROM public."Printer" p
    WHERE p.id=p_printer_id AND p."assignedUserId"=current_setting('app.printing_user_id',true)
      AND p."isActive" AND p."printerRegistrationId" IS NOT NULL;
  SELECT coalesce(jsonb_agg(jsonb_build_object('itemId',pi.id,'sessionId',ps.id,
      'jobId',j.id,'qrCodeId',pi."qrCodeId",'entrySha256',e.sha256,'attemptId',e."attemptId") ORDER BY pi.id),'[]'::jsonb)
    INTO matches FROM jsonb_to_recordset(p_entries)
      AS e(name text,sha256 text,"printJobId" text,"printItemId" text,"attemptId" text,state text)
    JOIN public."PrintItem" pi ON pi.id=e."printItemId"
    JOIN public."PrintSession" ps ON ps.id=pi."printSessionId" AND ps."printJobId"=e."printJobId"
    JOIN public."PrintJob" j ON j.id=ps."printJobId"
    WHERE ps."printerRegistrationId"=registration_id AND
      j."manufacturerId"=current_setting('app.printing_user_id',true) AND
      pi."printConfirmedAt" IS NULL AND pi.state NOT IN ('PRINT_CONFIRMED','CLOSED') AND
      (e."attemptId" IS NOT DISTINCT FROM pi."dispatchMetadata"->>'attemptId');
  IF jsonb_array_length(matches)<>expected_count
  THEN RAISE EXCEPTION 'UPGRADE_NO_REPLAY_MISMATCH' USING ERRCODE='42501'; END IF;

  FOR entry IN SELECT value FROM jsonb_array_elements(matches) ORDER BY value->>'itemId' LOOP
    PERFORM set_config('app.printing_operation','printing-connector-upgrade-protect',true),
      set_config('app.printing_registration_id',registration_id,true),
      set_config('app.printing_session_row_id',entry->>'sessionId',true),
      set_config('app.printing_job_id',entry->>'jobId',true),
      set_config('app.printing_item_id',entry->>'itemId',true);
    SELECT pi.state,pi."dispatchMetadata",pi."printConfirmedAt",pi."printSessionId",pi."qrCodeId"
      INTO STRICT item_row FROM public."PrintItem" pi WHERE pi.id=entry->>'itemId' FOR UPDATE;
    marker:=jsonb_build_object('journalSha256',p_journal_sha256,
      'entrySha256',entry->>'entrySha256','attemptId',entry->>'attemptId');
    IF item_row."printSessionId" IS DISTINCT FROM entry->>'sessionId' OR
       item_row."qrCodeId" IS DISTINCT FROM entry->>'qrCodeId' OR
       item_row."printConfirmedAt" IS NOT NULL OR item_row.state IN ('PRINT_CONFIRMED','CLOSED') OR
       (item_row."dispatchMetadata" ? 'upgradeNoReplay' AND
         item_row."dispatchMetadata"->'upgradeNoReplay' IS DISTINCT FROM marker)
    THEN RAISE EXCEPTION 'UPGRADE_NO_REPLAY_MISMATCH' USING ERRCODE='42501'; END IF;
    IF NOT (item_row."dispatchMetadata" ? 'upgradeNoReplay') THEN
      UPDATE public."PrintItem" pi SET state='FROZEN',"pipelineState"='NEEDS_OPERATOR_ACTION',
        "frozenAt"=coalesce(pi."frozenAt",clock_timestamp()),"failureReason"='physical_outcome_unconfirmed',
        "dispatchMetadata"=coalesce(pi."dispatchMetadata",'{}'::jsonb)||jsonb_build_object('upgradeNoReplay',marker),
        "updatedAt"=clock_timestamp() WHERE pi.id=entry->>'itemId';
      INSERT INTO public."PrintItemEvent"(id,"printItemId","eventType","previousState","nextState",details,"actorUserId","createdAt")
        VALUES(gen_random_uuid()::text,entry->>'itemId','INCIDENT_RAISED',item_row.state,'FROZEN',
          jsonb_build_object('reason','upgrade_unknown_no_replay','journalSha256',p_journal_sha256),
          current_setting('app.printing_user_id',true),clock_timestamp());
      added:=added+1;
    END IF;
    UPDATE public."PrintSession" ps SET status=CASE WHEN ps.status IN ('ACTIVE','RESUME_PENDING') THEN 'PAUSED'::public."PrintSessionStatus" ELSE ps.status END,
      "frozenItems"=(SELECT count(*) FROM public."PrintItem" pi WHERE pi."printSessionId"=ps.id AND pi.state='FROZEN'),
      "failedReason"='physical_outcome_unconfirmed',"updatedAt"=clock_timestamp() WHERE ps.id=entry->>'sessionId';
    UPDATE public."PrintJob" j SET status=CASE WHEN j.status IN ('PENDING','SENT') THEN 'PAUSED'::public."PrintJobStatus" ELSE j.status END,
      "pipelineState"='NEEDS_OPERATOR_ACTION',"failureReason"='physical_outcome_unconfirmed',"updatedAt"=clock_timestamp()
      WHERE j.id=entry->>'jobId';
  END LOOP;
  RETURN jsonb_build_object('protected',expected_count,'newlyProtected',added,'journalSha256',p_journal_sha256);
END
$fn$;

REVOKE ALL ON FUNCTION app_rls.printing_upgrade_protect_unknown(text,text,text,text,text,jsonb) FROM PUBLIC;

-- Installer bearer authorization is distinct from the rotating browser session.
-- AUTHORIZE already bound this token and registration to the durable fence.
CREATE OR REPLACE FUNCTION app_rls.printing_upgrade_handoff(
  p_operation text, p_token_hash text, p_binding jsonb
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public
AS $fn$
DECLARE scope text; checkpoint_key text; checkpoint jsonb; actor_id text;
BEGIN
  IF session_user <> 'mscqr_rls_cert_app' OR p_operation NOT IN ('CONSUME','VERIFY','REVOKE') OR
     coalesce(p_token_hash,'') !~ '^[a-f0-9]{64}$' OR jsonb_typeof(p_binding) IS DISTINCT FROM 'object' OR
     coalesce(p_binding->>'registrationId','') !~* '^[0-9a-f-]{36}$' OR
     coalesce(p_binding->>'attemptId','') !~* '^[0-9a-f-]{36}$' OR
     coalesce(p_binding->>'manufacturerId','')='' OR
     coalesce(p_binding->>'printerId','') !~* '^[0-9a-f-]{36}$'
  THEN RAISE EXCEPTION 'UPGRADE_HANDOFF_DENIED' USING ERRCODE='42501'; END IF;
  actor_id:=p_binding->>'manufacturerId';
  scope:=jsonb_build_array('local',p_binding->>'registrationId')::text;
  checkpoint_key:='connector-maintenance:'||encode(sha256(convert_to(scope,'UTF8')),'hex');
  PERFORM set_config('app.printing_maintenance_key',checkpoint_key,true);
  PERFORM pg_advisory_xact_lock(hashtextextended(checkpoint_key,0));
  SELECT value INTO STRICT checkpoint FROM public."SystemCheckpoint" WHERE key=checkpoint_key FOR UPDATE;
  IF checkpoint->>'state' IS DISTINCT FROM 'DISPATCH_FENCED' OR
     checkpoint->'upgrade'->>'actor' IS DISTINCT FROM actor_id OR
     checkpoint->'upgrade'->>'tokenHash' IS DISTINCT FROM p_token_hash OR
     checkpoint->'upgrade'->'binding' IS DISTINCT FROM p_binding OR
     checkpoint->'upgrade'->'binding'->>'fenceRequestId' IS DISTINCT FROM checkpoint->>'requestId' OR
     coalesce((checkpoint->'upgrade'->>'expiresAt')::timestamptz,'-infinity')<=clock_timestamp() OR
     checkpoint->'upgrade'->>'state' NOT IN ('AUTHORIZED','CONSUMED')
  THEN RAISE EXCEPTION 'UPGRADE_HANDOFF_DENIED' USING ERRCODE='42501'; END IF;
  IF p_operation='REVOKE' THEN
    UPDATE public."SystemCheckpoint" SET value=jsonb_set(checkpoint,'{upgrade,state}',to_jsonb('REVOKED'::text)),
      "updatedAt"=clock_timestamp() WHERE key=checkpoint_key;
    RETURN jsonb_build_object('revoked',true,'dispatchFenced',true);
  END IF;
  RETURN app_rls.printing_maintenance_gate(scope,p_operation,actor_id,
    jsonb_build_object('binding',p_binding,'tokenHash',p_token_hash,
      'workDigest',checkpoint->'upgrade'->'evidence'->>'workDigest'));
END
$fn$;

REVOKE ALL ON FUNCTION app_rls.printing_upgrade_handoff(text,text,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_rls.printing_printer_administration(text,text,text,text,text,jsonb) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.printing_reissue_request(text,text,text,text,text,text,integer,text,text,text,text) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.printing_upgrade_handoff(text,text,jsonb) TO "mscqr_rls_cert_app";
GRANT EXECUTE ON FUNCTION app_rls.printing_upgrade_protect_unknown(text,text,text,text,text,jsonb) TO "mscqr_rls_cert_app";
RESET ROLE;
DO $$ BEGIN
  IF NOT pg_has_role(session_user,'mscqr_rls_cert_owner','SET') THEN RAISE EXCEPTION 'administrative executor lacks SET authority for mscqr_rls_cert_owner'; END IF;
END $$;
SET ROLE "mscqr_rls_cert_owner";
REVOKE CREATE ON SCHEMA app_rls FROM "mscqr_rls_cert_auth_owner";
RESET ROLE;
COMMIT;
