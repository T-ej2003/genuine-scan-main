-- Release Fix 5: capability-bound printing lifecycle.
-- Caller GUCs are never authority. Every public application function verifies
-- aq_db_session before reading a protected printing table.

CREATE OR REPLACE FUNCTION app_rls.printing_bind_actor(
  p_capability text,
  p_purpose text,
  p_request_id text,
  p_batch_id text DEFAULT NULL
) RETURNS TABLE(
  "userId" text,
  "role" text,
  "organizationId" text,
  "licenseeId" text,
  "batchLicenseeId" text,
  "batchManufacturerId" text
)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public
AS $fn$
DECLARE
  actor record;
  batch_row record;
  target_org text;
BEGIN
  IF p_purpose NOT IN (
    'printing-readiness','printing-create-job','printing-job-control',
    'printing-sample-scan','printing-release','printing-reissue',
    'printing-printer-read','printing-printer-admin','printing-connector-registration',
    'printing-audit-export','printing-test-label','printing-idempotency'
  ) OR p_request_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
     OR (p_batch_id IS NOT NULL AND p_batch_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$')
  THEN
    RAISE EXCEPTION 'PRINTING_BOUNDARY_DENIED' USING ERRCODE='42501';
  END IF;

  SELECT * INTO STRICT actor
    FROM app_auth.require_authenticated_session(p_capability,p_purpose,p_request_id);
  IF actor.role NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN','LICENSEE_ADMIN','MANUFACTURER_ADMIN') THEN
    RAISE EXCEPTION 'PRINTING_BOUNDARY_DENIED' USING ERRCODE='42501';
  END IF;

  PERFORM
    set_config('app.printing_session_id',actor."sessionId",true),
    set_config('app.printing_user_id',actor."userId",true),
    set_config('app.printing_role',actor.role,true),
    set_config('app.printing_organization_id',coalesce(actor."organizationId",''),true),
    set_config('app.printing_licensee_id',coalesce(actor."licenseeId",''),true),
    set_config('app.printing_batch_id',coalesce(p_batch_id,''),true),
    set_config('app.printing_job_id','',true),
    set_config('app.printing_session_row_id','',true),
    set_config('app.printing_item_id','',true),
    set_config('app.printing_printer_id','',true),
    set_config('app.printing_registration_id','',true),
    set_config('app.printing_reissue_id','',true),
    set_config('app.printing_idempotency_key_hash','',true),
    set_config('app.printing_original_session_id','',true),
    set_config('app.printing_released_user_id','',true),
    set_config('app.printing_approved_user_id','',true),
    set_config('app.printing_operation',p_purpose,true),
    set_config('app.printing_request_id',p_request_id,true),
    set_config('app.printing_audit_id','',true),
    set_config('app.printing_outbox_id','',true);

  IF p_batch_id IS NULL THEN
    RETURN QUERY SELECT actor."userId"::text,actor.role::text,
      actor."organizationId"::text,actor."licenseeId"::text,NULL::text,NULL::text;
    RETURN;
  END IF;

  SELECT b.id,b."licenseeId",b."manufacturerId",l."orgId"
    INTO batch_row
    FROM public."Batch" b
    JOIN public."Licensee" l ON l.id=b."licenseeId"
    JOIN public."Organization" o ON o.id=l."orgId"
   WHERE b.id=p_batch_id AND l."isActive" AND l."suspendedAt" IS NULL AND o."isActive";
  IF NOT FOUND THEN
    RAISE EXCEPTION 'PRINTING_BOUNDARY_DENIED' USING ERRCODE='42501';
  END IF;

  target_org:=batch_row."orgId";
  IF actor.role='LICENSEE_ADMIN' AND (
    actor."licenseeId" IS DISTINCT FROM batch_row."licenseeId"
    OR actor."organizationId" IS DISTINCT FROM target_org
  ) THEN
    RAISE EXCEPTION 'PRINTING_BOUNDARY_DENIED' USING ERRCODE='42501';
  END IF;
  IF actor.role='MANUFACTURER_ADMIN' AND (
    batch_row."manufacturerId" IS DISTINCT FROM actor."userId"
    OR NOT EXISTS (
      SELECT 1 FROM public."ManufacturerLicenseeLink" ml
       WHERE ml."manufacturerId"=actor."userId"
         AND ml."licenseeId"=batch_row."licenseeId"
    )
  ) THEN
    RAISE EXCEPTION 'PRINTING_BOUNDARY_DENIED' USING ERRCODE='42501';
  END IF;

  PERFORM
    set_config('app.printing_organization_id',target_org,true),
    set_config('app.printing_licensee_id',batch_row."licenseeId",true);
  RETURN QUERY SELECT actor."userId"::text,actor.role::text,target_org,
    batch_row."licenseeId"::text,batch_row."licenseeId"::text,
    batch_row."manufacturerId"::text;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.printing_write_audit(
  p_actor_id text,
  p_actor_role text,
  p_org_id text,
  p_licensee_id text,
  p_action text,
  p_entity_type text,
  p_entity_id text,
  p_details jsonb
) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public
AS $fn$
DECLARE
  audit_id text:=gen_random_uuid()::text;
  outbox_id text:=gen_random_uuid()::text;
  now_at timestamp without time zone:=transaction_timestamp();
BEGIN
  IF p_action !~ '^[A-Z0-9_]{1,120}$'
     OR p_entity_type NOT IN ('PrintJob','PrintSession','PrintItem','PrintReissueRequest','Batch','Printer')
     OR jsonb_typeof(coalesce(p_details,'{}'::jsonb))<>'object'
  THEN RAISE EXCEPTION 'PRINTING_INVALID_AUDIT'; END IF;
  PERFORM set_config('app.printing_audit_id',audit_id,true),
          set_config('app.printing_outbox_id',outbox_id,true);
  INSERT INTO public."AuditLog"(
    id,"userId","orgId","licenseeId",action,"entityType","entityId",details,"createdAt"
  ) VALUES (
    audit_id,p_actor_id,p_org_id,p_licensee_id,p_action,p_entity_type,p_entity_id,
    coalesce(p_details,'{}'::jsonb)||jsonb_build_object('actorRole',p_actor_role),now_at
  );
  INSERT INTO public."SecurityEventOutbox"(
    id,"eventType",payload,"requestId","organizationId","licenseeId","initiatingUserId","updatedAt"
  ) VALUES (
    outbox_id,'AUDIT_LOG',
    jsonb_build_object(
      'id',audit_id,'action',p_action,'entityType',p_entity_type,'entityId',p_entity_id,
      'userId',p_actor_id,'orgId',p_org_id,'licenseeId',p_licensee_id,
      'details',coalesce(p_details,'{}'::jsonb)||jsonb_build_object('actorRole',p_actor_role),
      'createdAt',now_at
    ),
    current_setting('app.printing_request_id',true),p_org_id,p_licensee_id,p_actor_id,now_at
  );
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.printing_readiness(
  p_capability text,
  p_purpose text,
  p_request_id text,
  p_operation text,
  p_subject_id text,
  p_options jsonb DEFAULT '{}'::jsonb
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public
AS $fn$
DECLARE
  actor record;
  batch_row record;
  job_row record;
  result jsonb;
  page_limit integer;
  target_batch_id text;
  target_job_id text;
  released_user_id text;
  approved_user_id text;
BEGIN
  IF p_purpose<>'printing-readiness'
     OR p_operation NOT IN ('BATCH','JOB','JOB_LIST','ATTENTION_QUEUE','RELEASE','REISSUE','REISSUE_REQUEST','REISSUE_LIST','PRINTABLE_ITEMS','PRINTER','PRINTER_LIST','PRINTER_STATUS','VALIDATION_EVIDENCE')
     OR p_subject_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
     OR jsonb_typeof(coalesce(p_options,'{}'::jsonb))<>'object'
  THEN RAISE EXCEPTION 'PRINTING_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;

  SELECT * INTO STRICT actor FROM app_rls.printing_bind_actor(
    p_capability,p_purpose,p_request_id,NULL
  );
  target_job_id:=CASE WHEN p_operation IN ('JOB','REISSUE') THEN p_subject_id END;
  IF target_job_id IS NOT NULL THEN
    PERFORM set_config('app.printing_job_id',target_job_id,true);
    SELECT j."batchId" INTO STRICT target_batch_id FROM public."PrintJob" j WHERE j.id=target_job_id;
  ELSIF p_operation='REISSUE_REQUEST' THEN
    PERFORM set_config('app.printing_reissue_id',p_subject_id,true);
    SELECT r."batchId" INTO STRICT target_batch_id FROM public."PrintReissueRequest" r WHERE r.id=p_subject_id;
  ELSIF p_operation IN ('PRINTER','PRINTER_LIST','PRINTER_STATUS') THEN
    target_batch_id:=p_options->>'batchId';
  ELSIF p_operation NOT IN ('JOB_LIST','ATTENTION_QUEUE') THEN
    target_batch_id:=p_subject_id;
  END IF;
  IF target_batch_id IS NOT NULL THEN
    SELECT * INTO STRICT actor FROM app_rls.printing_bind_actor(
      p_capability,p_purpose,p_request_id,target_batch_id
    );
  END IF;

  IF p_operation IN ('BATCH','RELEASE','PRINTABLE_ITEMS') THEN
    SELECT b.id,b.name,b."licenseeId",b."manufacturerId",b."lifecycleState",
      b."sampleScanPolicy",b."totalCodes",b."printedAt",b."releasedAt"
      INTO STRICT batch_row FROM public."Batch" b WHERE b.id=target_batch_id;
    RETURN jsonb_build_object(
      'batch',jsonb_build_object(
        'id',batch_row.id,'name',batch_row.name,'licenseeId',batch_row."licenseeId",
        'manufacturerId',batch_row."manufacturerId",'lifecycleState',batch_row."lifecycleState",
        'sampleScanPolicy',batch_row."sampleScanPolicy",'totalCodes',batch_row."totalCodes",
        'printedAt',batch_row."printedAt",'releasedAt',batch_row."releasedAt"
      ),
      'printableItems',coalesce((
        SELECT jsonb_agg(jsonb_build_object(
          'id',q.id,'code',q.code,'displayCode',q."displayCode",'batchId',q."batchId",
          'licenseeId',q."licenseeId",'status',q.status,'replayEpoch',q."replayEpoch"
        ) ORDER BY q."displayCode",q.id)
        FROM (
          SELECT q.id,q.code,q."displayCode",q."licenseeId",q."batchId",
            q.status,q."replayEpoch",q."printJobId"
          FROM public."QRCode" q
           WHERE q."batchId"=batch_row.id
             AND q.status IN ('ALLOCATED'::public."QRStatus",'ACTIVATED'::public."QRStatus")
             AND (nullif(p_options->>'rangeStart','') IS NULL OR q."displayCode">=p_options->>'rangeStart')
             AND (nullif(p_options->>'rangeEnd','') IS NULL OR q."displayCode"<=p_options->>'rangeEnd')
             AND (q."printJobId" IS NULL OR NOT EXISTS (
               SELECT 1 FROM public."PrintItem" pi
               WHERE pi."qrCodeId"=q.id AND (
                 pi."printConfirmedAt" IS NOT NULL
                 OR pi.state NOT IN ('FAILED'::public."PrintItemState",'FROZEN'::public."PrintItemState",'CANCELLED'::public."PrintItemState")
               )
             ))
           ORDER BY q."displayCode",q.id
           LIMIT LEAST(GREATEST(coalesce(NULLIF(p_options->>'limit','')::integer,500),1),200000)
        ) q
      ),'[]'::jsonb),
      'qrCount',(SELECT count(*) FROM public."QRCode" q WHERE q."batchId"=batch_row.id),
      'confirmedItemCount',(SELECT count(*) FROM public."PrintItem" pi
        JOIN public."PrintSession" ps ON ps.id=pi."printSessionId"
        WHERE ps."batchId"=batch_row.id AND pi."printConfirmedAt" IS NOT NULL),
      'sampleCount',(SELECT count(DISTINCT pa."qrCodeId") FROM public."PrintAuditEvent" pa
        WHERE pa."batchId"=batch_row.id AND pa."eventType"='SAMPLE_SCAN_PASSED'),
      'sampleRequired',CASE coalesce(batch_row."sampleScanPolicy"->>'type',batch_row."sampleScanPolicy"->>'mode','ONE_PER_PRINT_JOB')
        WHEN 'ONE_PER_PRINT_JOB' THEN 1
        WHEN 'ONE_PER_ROLL' THEN 1
        WHEN 'ONE_PER_N_LABELS' THEN GREATEST(1,ceil(batch_row."totalCodes"::numeric/GREATEST(coalesce((batch_row."sampleScanPolicy"->>'n')::integer,batch_row."totalCodes"),1))::integer)
        WHEN 'PERCENTAGE' THEN GREATEST(
          GREATEST(coalesce((batch_row."sampleScanPolicy"->>'min')::integer,1),1),
          ceil(batch_row."totalCodes"*GREATEST(coalesce((batch_row."sampleScanPolicy"->>'percentage')::numeric,1),0.01)/100)::integer
        )
        ELSE 1 END,
      'latestJob',(SELECT to_jsonb(j) FROM (
        SELECT job.id,job."jobNumber",job."batchId",job."manufacturerId",job."printerId",
          job.status,job."printMode",job."pipelineState",job."payloadType",job."payloadHash",
          job.quantity,job."itemCount",job."rangeStart",job."rangeEnd",job."sentAt",
          job."completedAt",job."failureReason",job."reprintOfJobId",job."approvedByUserId",
          job."reprintReason",job."confirmedAt",job."createdAt",job."updatedAt"
        FROM public."PrintJob" job WHERE job."batchId"=batch_row.id
        ORDER BY job."createdAt" DESC LIMIT 1
      ) j)
    );
  END IF;

  IF p_operation='VALIDATION_EVIDENCE' THEN
    SELECT j.id,j."approvedByUserId",j.status,j."pipelineState",j."itemCount",j.quantity,
      j."payloadHash",j."sentAt",j."confirmedAt",j."printerId" INTO STRICT job_row
      FROM public."PrintJob" j
      WHERE j."batchId"=target_batch_id
        AND (nullif(p_options->>'printJobId','') IS NULL OR j.id=p_options->>'printJobId')
      ORDER BY j."createdAt" DESC,j.id DESC
      LIMIT 1;
    PERFORM set_config('app.printing_job_id',job_row.id,true);
    SELECT b."releasedByUserId" INTO released_user_id
      FROM public."Batch" b WHERE b.id=target_batch_id;
    approved_user_id:=job_row."approvedByUserId";
    PERFORM set_config('app.printing_released_user_id',coalesce(released_user_id,''),true),
            set_config('app.printing_approved_user_id',coalesce(approved_user_id,''),true);
    RETURN (
      WITH selected_sample AS (
        SELECT q.id,q.code,q.status,q."printedAt",q."createdAt",q."batchId",q."printJobId"
        FROM public."QRCode" q
        WHERE q."batchId"=target_batch_id AND q."printJobId"=job_row.id
          AND (
            NOT EXISTS (
              SELECT 1 FROM public."PrintAuditEvent" pae
              WHERE pae."batchId"=target_batch_id AND pae."printJobId"=job_row.id
                AND pae."eventType" IN ('SAMPLE_SCAN_PASSED','sample_scan_verified')
            )
            OR q.id=(
              SELECT pae."qrCodeId" FROM public."PrintAuditEvent" pae
              WHERE pae."batchId"=target_batch_id AND pae."printJobId"=job_row.id
                AND pae."eventType" IN ('SAMPLE_SCAN_PASSED','sample_scan_verified')
              ORDER BY pae."createdAt" DESC,pae.id DESC LIMIT 1
            )
          )
        ORDER BY q."printedAt" NULLS LAST,q."createdAt",q.id LIMIT 1
      )
      SELECT jsonb_build_object(
        'generatedAt',transaction_timestamp(),
        'batch',jsonb_build_object(
          'id',b.id,'displayCode',coalesce(b.name,b."startCode"),
          'lifecycleState',b."lifecycleState",
          'brand',jsonb_build_object('id',l.id,'name',l.name,'prefix',l.prefix)
        ),
        'printJob',jsonb_build_object('id',job_row.id,'status',job_row.status,'pipelineState',job_row."pipelineState"),
        'printer',jsonb_build_object(
          'id',p.id,'name',p.name,'profileName',p.model,
          'model',p.model,'transport',
            CASE p."connectionType"
              WHEN 'NETWORK_IPP'::public."PrinterConnectionType" THEN 'ipp'
              WHEN 'LOCAL_AGENT'::public."PrinterConnectionType" THEN 'local-agent'
              ELSE 'tcp-raw' END,
          'host',coalesce(p.host,p."ipAddress"),'port',p.port
        ),
        'labelCount',coalesce(job_row."itemCount",job_row.quantity,b."totalCodes"),
        'payloadHash',job_row."payloadHash",'sentAt',job_row."sentAt",
        'physicalPrintConfirmedAt',job_row."confirmedAt",
        'sampleScanVerifiedAt',(
          SELECT pae."createdAt" FROM public."PrintAuditEvent" pae
          WHERE pae."batchId"=b.id AND pae."printJobId"=job_row.id
            AND pae."eventType" IN ('SAMPLE_SCAN_PASSED','sample_scan_verified')
          ORDER BY pae."createdAt" DESC,pae.id DESC LIMIT 1
        ),
        'releasedAt',b."releasedAt",
        'releasedBy',CASE WHEN released_by.id IS NULL THEN NULL ELSE jsonb_build_object(
          'id',released_by.id,'displayName',coalesce(released_by.name,released_by.email),'role',released_by.role) END,
        'checker',CASE WHEN checker.id IS NULL THEN NULL ELSE jsonb_build_object(
          'id',checker.id,'displayName',coalesce(checker.name,checker.email),'role',checker.role) END,
        'sampleQr',jsonb_build_object(
          'id',sample.id,
          'publicCode',CASE WHEN coalesce((p_options->>'includePublicCode')::boolean,false) THEN sample.code END,
          'maskedPublicCode',CASE WHEN sample.code IS NULL THEN NULL
            WHEN length(sample.code)<=12 THEN left(sample.code,3)||'...'||right(sample.code,2)
            ELSE left(sample.code,6)||'...'||right(sample.code,6) END,
          'verifyUrl',NULL
        ),
        'verify',jsonb_build_object(
          'result',CASE
            WHEN sample.id IS NULL THEN 'not_found'
            WHEN sample.status='BLOCKED'::public."QRStatus" THEN 'blocked'
            WHEN b."lifecycleState"='RELEASED'::public."BatchLifecycleState" THEN 'authentic_released'
            WHEN sample.status IN ('PRINTED'::public."QRStatus",'ACTIVATED'::public."QRStatus") THEN 'authentic_not_released'
            ELSE 'not_ready' END,
          'routeUsesExactPublicCode',coalesce(sample.code LIKE 'c\_%' ESCAPE '\',false)
        ),
        'auditEventIds',coalesce((
          SELECT jsonb_agg(pae.id ORDER BY pae."createdAt",pae.id)
          FROM public."PrintAuditEvent" pae
          WHERE pae."batchId"=b.id
            AND (pae."printJobId"=job_row.id OR pae."eventType" LIKE 'batch_release%')
        ),'[]'::jsonb),
        'auditEvents',jsonb_build_object(
          'sampleScanVerifiedId',(SELECT pae.id FROM public."PrintAuditEvent" pae
            WHERE pae."batchId"=b.id AND pae."printJobId"=job_row.id
              AND pae."eventType" IN ('SAMPLE_SCAN_PASSED','sample_scan_verified')
            ORDER BY pae."createdAt" DESC,pae.id DESC LIMIT 1),
          'batchReleasedId',(SELECT pae.id FROM public."PrintAuditEvent" pae
            WHERE pae."batchId"=b.id AND pae."printJobId"=job_row.id
              AND pae."eventType" IN ('BATCH_RELEASED','batch_released')
            ORDER BY pae."createdAt" DESC,pae.id DESC LIMIT 1),
          'approvalGrantedId',(SELECT pae.id FROM public."PrintAuditEvent" pae
            WHERE pae."batchId"=b.id AND pae."printJobId"=job_row.id
              AND pae."eventType" IN ('RELEASE_APPROVED','batch_release_approval_granted')
            ORDER BY pae."createdAt" DESC,pae.id DESC LIMIT 1)
        ),
        'legacyRisk',jsonb_build_object(
          'status',CASE
            WHEN legacy.total=0 THEN 'no_legacy_public_codes_in_batch'
            WHEN legacy.unsafe>0 THEN 'legacy_codes_locked'
            ELSE 'legacy_codes_review_required' END,
          'totalLegacyCodes',legacy.total,'unsafeLegacyCodes',legacy.unsafe
        )
      )
      FROM public."Batch" b
      JOIN public."Licensee" l ON l.id=b."licenseeId"
      LEFT JOIN public."Printer" p ON p.id=job_row."printerId"
      LEFT JOIN public."User" released_by ON released_by.id=b."releasedByUserId"
      LEFT JOIN public."User" approved_by ON approved_by.id=job_row."approvedByUserId"
      LEFT JOIN public."User" checker ON checker.id=coalesce(approved_by.id,released_by.id)
      LEFT JOIN selected_sample sample ON true
      CROSS JOIN LATERAL (
        SELECT count(*) FILTER (WHERE q.code NOT LIKE 'c\_%' ESCAPE '\') AS total,
          count(*) FILTER (WHERE q.code NOT LIKE 'c\_%' ESCAPE '\' AND (
            q."printedAt" IS NOT NULL OR q."scannedAt" IS NOT NULL OR q."scanCount">0
            OR q.status IN ('PRINTED'::public."QRStatus",'SCANNED'::public."QRStatus",
              'REDEEMED'::public."QRStatus",'BLOCKED'::public."QRStatus")
          )) AS unsafe
        FROM public."QRCode" q WHERE q."batchId"=b.id
      ) legacy
      WHERE b.id=target_batch_id
    );
  END IF;

  IF p_operation='PRINTER_LIST' THEN
    RETURN coalesce((
      SELECT jsonb_agg(to_jsonb(p) ORDER BY p."isDefault" DESC,p.name,p.id)
      FROM (
        SELECT printer.id,printer.name,printer.vendor,printer.model,printer."connectionType",
          printer."commandLanguage",printer."ipAddress",printer.host,printer.port,printer."resourcePath",
          printer."tlsEnabled",printer."printerUri",printer."deliveryMode",printer."gatewayId",
          printer."gatewayLastSeenAt",printer."gatewayStatus",printer."gatewayLastError",
          printer."nativePrinterId",printer."agentId",printer."deviceFingerprint",
          printer."printerRegistrationId",printer."orgId",printer."licenseeId",
          printer."assignedUserId",printer."createdByUserId",printer."isActive",printer."isDefault",
          printer."lastSeenAt",printer."lastValidatedAt",printer."lastValidationStatus",
          printer."lastValidationMessage",printer."capabilitySummary",printer."calibrationProfile",
          printer.metadata,printer."createdAt",printer."updatedAt"
        FROM public."Printer" printer
        WHERE (coalesce((p_options->>'includeInactive')::boolean,false) OR printer."isActive")
        AND (
          actor.role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')
          OR (actor.role='LICENSEE_ADMIN'
            AND printer."licenseeId"=actor."licenseeId" AND printer."orgId"=actor."organizationId")
          OR (actor.role='MANUFACTURER_ADMIN' AND (
            printer."assignedUserId"=actor."userId"
            OR EXISTS (
              SELECT 1 FROM public."PrinterRegistration" pr
              WHERE pr.id=printer."printerRegistrationId" AND pr."userId"=actor."userId"
                AND pr."trustStatus"='TRUSTED' AND pr."revokedAt" IS NULL
            )
            OR EXISTS (
              SELECT 1 FROM public."ManufacturerLicenseeLink" ml
              WHERE ml."manufacturerId"=actor."userId" AND ml."licenseeId"=printer."licenseeId"
            )
          ))
        )
      ) p
    ),'[]'::jsonb);
  END IF;

  IF p_operation='PRINTER' THEN
    RETURN (
      SELECT to_jsonb(p)
      FROM (
        SELECT printer.id,printer.name,printer.vendor,printer.model,printer."connectionType",
          printer."commandLanguage",printer."ipAddress",printer.host,printer.port,printer."resourcePath",
          printer."tlsEnabled",printer."printerUri",printer."deliveryMode",printer."gatewayId",
          printer."gatewayLastSeenAt",printer."gatewayStatus",printer."gatewayLastError",
          printer."nativePrinterId",printer."agentId",printer."deviceFingerprint",
          printer."printerRegistrationId",printer."orgId",printer."licenseeId",
          printer."assignedUserId",printer."createdByUserId",printer."isActive",printer."isDefault",
          printer."lastSeenAt",printer."lastValidatedAt",printer."lastValidationStatus",
          printer."lastValidationMessage",printer."capabilitySummary",printer."calibrationProfile",
          printer.metadata,printer."createdAt",printer."updatedAt"
        FROM public."Printer" printer
        WHERE printer.id=p_subject_id AND (
        actor.role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')
        OR (actor.role='LICENSEE_ADMIN'
          AND printer."licenseeId"=actor."licenseeId" AND printer."orgId"=actor."organizationId")
        OR printer."assignedUserId"=actor."userId"
        OR EXISTS (
          SELECT 1 FROM public."PrinterRegistration" pr
          WHERE pr.id=printer."printerRegistrationId" AND pr."userId"=actor."userId"
            AND pr."trustStatus"='TRUSTED' AND pr."revokedAt" IS NULL
        )
      )
      ) p
    );
  END IF;

  IF p_operation='PRINTER_STATUS' THEN
    IF p_subject_id IS DISTINCT FROM actor."userId" THEN
      RAISE EXCEPTION 'PRINTING_BOUNDARY_DENIED' USING ERRCODE='42501';
    END IF;
    RETURN (
      WITH registration AS (
        SELECT pr.id,pr."agentId",pr."deviceFingerprint",pr."trustStatus",pr."trustReason",
          pr."approvedAt",pr."lastSeenAt",pr."updatedAt"
        FROM public."PrinterRegistration" pr
        WHERE pr."userId"=actor."userId" AND pr."revokedAt" IS NULL
          AND pr."trustStatus"<>'REVOKED'::public."PrinterTrustStatus"
        ORDER BY pr."approvedAt" DESC NULLS LAST,pr."lastSeenAt" DESC NULLS LAST,pr."updatedAt" DESC
        LIMIT 1
      ), attestation AS (
        SELECT pa.id,pa."printerRegistrationId",pa.metadata,pa."expiresAt",pa."trustValid",
          pa."signatureValid",pa."attestedAt",pa."rejectionReason",pa."createdAt"
        FROM public."PrinterAttestation" pa
        JOIN registration pr ON pr.id=pa."printerRegistrationId"
        ORDER BY pa."createdAt" DESC,pa.id DESC LIMIT 1
      )
      SELECT CASE WHEN pr.id IS NULL THEN jsonb_build_object(
        'connected',false,'trusted',false,'compatibilityMode',false,
        'eligibleForPrinting',false,'connectionClass','BLOCKED','stale',true,
        'securePrinterSession',false,'freshHelperHeartbeat',false,
        'helperConnection',false,'eligiblePrinter',false,
        'missingFields',jsonb_build_array('printerRegistration','freshHelperHeartbeat',
          'helperConnection','eligiblePrinter','securePrinterSession','selectedPrinter'),
        'registrationId',NULL,'error','No printer registration'
      ) ELSE (
        coalesce(pa.metadata,'{}'::jsonb)
        ||jsonb_build_object(
          'connected',coalesce((pa.metadata->>'connected')::boolean,false)
            AND pa."expiresAt">transaction_timestamp() AND pa."trustValid",
          'trusted',pr."trustStatus"='TRUSTED'::public."PrinterTrustStatus"
            AND pa."expiresAt">transaction_timestamp() AND pa."trustValid" AND pa."signatureValid",
          'compatibilityMode',false,
          'eligibleForPrinting',pr."trustStatus"='TRUSTED'::public."PrinterTrustStatus"
            AND pa."expiresAt">transaction_timestamp() AND pa."trustValid" AND pa."signatureValid"
            AND coalesce((pa.metadata->>'connected')::boolean,false)
            AND coalesce(pa.metadata->>'selectedPrinterId',pa.metadata->>'printerId','')<>'',
          'connectionClass',CASE WHEN pr."trustStatus"='TRUSTED'::public."PrinterTrustStatus"
            AND pa."expiresAt">transaction_timestamp() AND pa."trustValid" AND pa."signatureValid"
            THEN 'TRUSTED' ELSE 'BLOCKED' END,
          'stale',pa."expiresAt"<=transaction_timestamp(),
          'securePrinterSession',pr."trustStatus"='TRUSTED'::public."PrinterTrustStatus"
            AND pa."expiresAt">transaction_timestamp() AND pa."trustValid" AND pa."signatureValid",
          'freshHelperHeartbeat',pa."expiresAt">transaction_timestamp(),
          'helperConnection',coalesce((pa.metadata->>'connected')::boolean,false)
            AND pa."expiresAt">transaction_timestamp(),
          'eligiblePrinter',coalesce(pa.metadata->>'selectedPrinterId',pa.metadata->>'printerId','')<>'',
          'missingFields','[]'::jsonb,
          'registrationId',pr.id,'agentId',pr."agentId",
          'deviceFingerprint',pr."deviceFingerprint",'trustStatus',pr."trustStatus",
          'trustReason',pr."trustReason",'lastHeartbeatAt',pa."attestedAt",
          'ageSeconds',greatest(0,extract(epoch FROM transaction_timestamp()-pa."attestedAt")::integer),
          'signedAttestation',jsonb_build_object(
            'required',true,'present',true,'signatureValid',pa."signatureValid",
            'fresh',pa."expiresAt">transaction_timestamp() AND pa."trustValid",
            'issuedAt',pa.metadata->>'heartbeatIssuedAt','rejectReason',pa."rejectionReason"
          ),
          'error',CASE WHEN pa."trustValid" AND pa."expiresAt">transaction_timestamp()
            THEN NULL ELSE coalesce(pa."rejectionReason",pr."trustReason",'Printer attestation stale') END
        )
      ) END
      FROM (SELECT 1) seed
      LEFT JOIN registration pr ON true
      LEFT JOIN attestation pa ON true
    );
  END IF;

  IF p_operation IN ('JOB','REISSUE') THEN
    SELECT j.id,j."jobNumber",j."batchId",j."manufacturerId",j."printerId",j.status,
      j."printMode",j."pipelineState",j."payloadType",j."payloadHash",j.quantity,j."itemCount",
      j."rangeStart",j."rangeEnd",j."sentAt",j."completedAt",j."failureReason",
      j."reprintOfJobId",j."approvedByUserId",j."reprintReason",j."confirmedAt",
      j."createdAt",j."updatedAt" INTO STRICT job_row
      FROM public."PrintJob" j WHERE j.id=target_job_id;
    RETURN jsonb_build_object(
      'job',to_jsonb(job_row),
      'session',(SELECT to_jsonb(ps) FROM (
        SELECT session.id,session."printJobId",session."batchId",session."manufacturerId",
          session."printerRegistrationId",session."printerId",session.status,session."totalItems",
          session."issuedItems",session."confirmedItems",session."frozenItems",session."failedReason",
          session."startedAt",session."completedAt",session."createdAt",session."updatedAt"
        FROM public."PrintSession" session WHERE session."printJobId"=job_row.id
      ) ps),
      'items',coalesce((SELECT jsonb_agg(
        jsonb_build_object(
          'id',pi.id,'printSessionId',pi."printSessionId",'qrCodeId',pi."qrCodeId",'code',pi.code,
          'state',pi.state,'pipelineState',pi."pipelineState",'issueSequence',pi."issueSequence",
          'attemptCount',pi."attemptCount",'deviceJobRef',pi."deviceJobRef",
          'dispatchMetadata',pi."dispatchMetadata",'confirmationEvidence',pi."confirmationEvidence",
          'issuedAt',pi."issuedAt",'dispatchedAt',pi."dispatchedAt",'agentAckedAt',pi."agentAckedAt",
          'confirmationDeadlineAt',pi."confirmationDeadlineAt",'printConfirmedAt',pi."printConfirmedAt",
          'closedAt',pi."closedAt",'frozenAt',pi."frozenAt",'failedAt',pi."failedAt",
          'failureReason',pi."failureReason",'deadLetterReason',pi."deadLetterReason",
          'createdAt',pi."createdAt",'updatedAt',pi."updatedAt",
          'qrCode',jsonb_build_object('id',q.id,'code',q.code,'displayCode',q."displayCode",'status',q.status)
        ) ORDER BY pi."issueSequence" NULLS LAST,pi.id
      ) FROM public."PrintItem" pi
        JOIN public."PrintSession" ps ON ps.id=pi."printSessionId"
        JOIN public."QRCode" q ON q.id=pi."qrCodeId"
        WHERE ps."printJobId"=job_row.id),'[]'::jsonb)
    );
  END IF;

  IF p_operation='REISSUE_REQUEST' THEN
    PERFORM set_config('app.printing_reissue_id',p_subject_id,true);
    RETURN (
      SELECT to_jsonb(r)||jsonb_build_object(
        'originalPrintJob',jsonb_build_object(
          'id',j.id,'jobNumber',j."jobNumber",'status',j.status,'quantity',j.quantity,
          'itemCount',j."itemCount",'rangeStart',j."rangeStart",'rangeEnd',j."rangeEnd",
          'printMode',j."printMode",'pipelineState',j."pipelineState",
          'batch',jsonb_build_object('id',b.id,'name',b.name,'licenseeId',b."licenseeId"),
          'printer',jsonb_build_object('id',p.id,'name',p.name)
        )
      )
      FROM (
        SELECT request.id,request."originalPrintJobId",request."replacementPrintJobId",
          request."requestedByUserId",request."approvedByUserId",request."licenseeId",
          request."manufacturerId",request."batchId",request."requestedByRole",
          request."targetApproverRole",request.quantity,request."affectedRangeStart",
          request."affectedRangeEnd",request."decisionNote",request."approvalReferenceId",
          request.status,request.reason,request."rejectionReason",request."approvedAt",
          request."rejectedAt",request."executedAt",request."createdAt",request."updatedAt"
        FROM public."PrintReissueRequest" request WHERE request.id=p_subject_id
      ) r
      JOIN public."PrintJob" j ON j.id=r."originalPrintJobId"
      JOIN public."Batch" b ON b.id=j."batchId"
      JOIN public."Printer" p ON p.id=j."printerId"
    );
  END IF;

  IF p_operation='REISSUE_LIST' THEN
    RETURN coalesce((
      SELECT jsonb_agg(to_jsonb(x) ORDER BY x."createdAt" DESC,x.id DESC)
      FROM (
        SELECT r.id,r."originalPrintJobId",r."replacementPrintJobId",r."requestedByUserId",
          r."approvedByUserId",r."licenseeId",r."manufacturerId",r."batchId",r."requestedByRole",
          r."targetApproverRole",r.quantity,r."affectedRangeStart",r."affectedRangeEnd",
          r."decisionNote",r."approvalReferenceId",r.status,r.reason,r."rejectionReason",
          r."approvedAt",r."rejectedAt",r."executedAt",r."createdAt",r."updatedAt",
          jsonb_build_object(
          'id',j.id,'jobNumber',j."jobNumber",'status',j.status,'quantity',j.quantity,
          'itemCount',j."itemCount",'rangeStart',j."rangeStart",'rangeEnd',j."rangeEnd",
          'batch',jsonb_build_object('id',b.id,'name',b.name,'licenseeId',b."licenseeId"),
          'printer',jsonb_build_object('id',p.id,'name',p.name)
        ) AS "originalPrintJob"
        FROM public."PrintReissueRequest" r
        JOIN public."PrintJob" j ON j.id=r."originalPrintJobId"
        JOIN public."Batch" b ON b.id=j."batchId"
        JOIN public."Printer" p ON p.id=j."printerId"
        WHERE (nullif(p_options->>'status','') IS NULL OR r.status::text=p_options->>'status')
          AND (
            actor.role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')
            OR (actor.role='LICENSEE_ADMIN' AND r."licenseeId"=actor."licenseeId")
            OR (actor.role='MANUFACTURER_ADMIN' AND r."requestedByUserId"=actor."userId")
          )
        ORDER BY r."createdAt" DESC,r.id DESC
        LIMIT LEAST(GREATEST(coalesce(NULLIF(p_options->>'limit','')::integer,50),1),200)
      ) x
    ),'[]'::jsonb);
  END IF;

  IF p_operation='ATTENTION_QUEUE' THEN
    RETURN (
      WITH scoped AS (
        SELECT j.id,j."jobNumber",j.status,j."pipelineState",j."updatedAt"
        FROM public."PrintJob" j
        JOIN public."Batch" b ON b.id=j."batchId"
        WHERE (
          j.status IN ('PENDING'::public."PrintJobStatus",'SENT'::public."PrintJobStatus")
          OR j."pipelineState" IN (
            'QUEUED'::public."PrintPipelineState",'PREFLIGHT_OK'::public."PrintPipelineState",
            'SENT_TO_PRINTER'::public."PrintPipelineState",'PRINTER_ACKNOWLEDGED'::public."PrintPipelineState",
            'NEEDS_OPERATOR_ACTION'::public."PrintPipelineState"
          )
        )
        AND (
          (actor.role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')
            AND (nullif(p_options->>'licenseeId','') IS NULL OR b."licenseeId"=p_options->>'licenseeId'))
          OR (actor.role='LICENSEE_ADMIN' AND b."licenseeId"=actor."licenseeId")
          OR (actor.role='MANUFACTURER_ADMIN' AND j."manufacturerId"=actor."userId" AND EXISTS (
            SELECT 1 FROM public."ManufacturerLicenseeLink" ml
            WHERE ml."manufacturerId"=actor."userId" AND ml."licenseeId"=b."licenseeId"
          ))
        )
      )
      SELECT jsonb_build_object(
        'count',(SELECT count(*) FROM scoped),
        'latest',(SELECT to_jsonb(x) FROM scoped x ORDER BY x."updatedAt" DESC,x.id DESC LIMIT 1)
      )
    );
  END IF;

  page_limit:=LEAST(GREATEST(coalesce(NULLIF(p_options->>'limit','')::integer,100),1),500);
  RETURN coalesce((
    SELECT jsonb_agg(to_jsonb(x) ORDER BY x."createdAt" DESC,x.id DESC)
    FROM (
      SELECT j.id,j."jobNumber",j."batchId",j."manufacturerId",j."printerId",
        j.status,j."printMode",j."pipelineState",j.quantity,j."itemCount",
        j."rangeStart",j."rangeEnd",j."sentAt",j."completedAt",j."failureReason",
        j."reprintOfJobId",j."approvedByUserId",j."reprintReason",j."confirmedAt",
        j."createdAt",j."updatedAt"
      FROM public."PrintJob" j
      JOIN public."Batch" b ON b.id=j."batchId"
      WHERE (nullif(p_options->>'batchId','') IS NULL OR j."batchId"=p_options->>'batchId')
        AND (
        actor.role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')
        OR (actor.role='LICENSEE_ADMIN' AND b."licenseeId"=actor."licenseeId")
        OR (actor.role='MANUFACTURER_ADMIN' AND j."manufacturerId"=actor."userId" AND EXISTS (
          SELECT 1 FROM public."ManufacturerLicenseeLink" ml
          WHERE ml."manufacturerId"=actor."userId" AND ml."licenseeId"=b."licenseeId"
        ))
      )
      ORDER BY j."createdAt" DESC,j.id DESC LIMIT page_limit
    ) x
  ),'[]'::jsonb);
END
$fn$;

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
BEGIN
  IF p_purpose<>'printing-printer-admin'
     OR p_operation NOT IN (
       'CREATE','UPDATE','DELETE','RELINK',
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
        p_operation LIKE 'AUDIT_%' AND printer_row."assignedUserId"=actor."userId"
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
    UPDATE public."Printer" SET "isDefault"=false,"updatedAt"=now_at
      WHERE "assignedUserId"=actor."userId" AND "connectionType"='LOCAL_AGENT'
        AND id<>p_printer_id;
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

CREATE OR REPLACE FUNCTION app_rls.printing_idempotency(
  p_capability text,
  p_purpose text,
  p_request_id text,
  p_operation text,
  p_action text,
  p_key_hash text,
  p_request_hash text,
  p_status_code integer,
  p_response jsonb
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public
AS $fn$
DECLARE
  actor record;
  row_value record;
  inserted boolean:=false;
  expected_scope text;
  now_at timestamp without time zone:=transaction_timestamp();
BEGIN
  IF p_purpose<>'printing-idempotency'
     OR p_operation NOT IN ('BEGIN','COMPLETE','ABORT')
     OR p_action NOT IN ('PRINT_JOB_CREATE','PRINTER_TEST_LABEL')
     OR p_key_hash !~ '^[0-9a-f]{64}$'
     OR p_request_hash !~ '^[0-9a-f]{64}$'
     OR (p_operation='COMPLETE' AND p_status_code NOT BETWEEN 100 AND 599)
     OR jsonb_typeof(coalesce(p_response,'{}'::jsonb))<>'object'
  THEN RAISE EXCEPTION 'PRINTING_IDEMPOTENCY_DENIED' USING ERRCODE='42501'; END IF;

  SELECT * INTO STRICT actor
    FROM app_rls.printing_bind_actor(p_capability,p_purpose,p_request_id,NULL);
  expected_scope:='printing:'||p_action||':actor:'||actor."userId";
  PERFORM set_config('app.printing_operation','printing-idempotency-'||lower(p_operation),true),
          set_config('app.printing_idempotency_key_hash',p_key_hash,true);

  SELECT k.id,k."keyHash",k.action,k.scope,k."requestHash",k."statusCode",k."responsePayload",
    k."completedAt",k."expiresAt" INTO row_value FROM public."ActionIdempotencyKey" k
    WHERE "keyHash"=p_key_hash FOR UPDATE;
  IF p_operation='ABORT' THEN
    IF NOT FOUND THEN RETURN jsonb_build_object('aborted',true,'idempotent',true); END IF;
    IF row_value.action IS DISTINCT FROM p_action
       OR row_value.scope IS DISTINCT FROM expected_scope
       OR row_value."requestHash" IS DISTINCT FROM p_request_hash
    THEN RAISE EXCEPTION 'IDEMPOTENCY_KEY_PAYLOAD_MISMATCH'; END IF;
    IF row_value."completedAt" IS NOT NULL
    THEN RETURN jsonb_build_object('aborted',false,'idempotent',true); END IF;
    UPDATE public."ActionIdempotencyKey" SET "expiresAt"=now_at-interval '1 microsecond'
      WHERE "keyHash"=p_key_hash;
    RETURN jsonb_build_object('aborted',true,'idempotent',false);
  END IF;
  IF FOUND AND row_value."expiresAt"<=now_at THEN
    UPDATE public."ActionIdempotencyKey" SET
      action=p_action,scope=expected_scope,"requestHash"=p_request_hash,
      "statusCode"=NULL,"responsePayload"=NULL,"completedAt"=NULL,
      "createdAt"=now_at,"expiresAt"=now_at+interval '10 minutes'
      WHERE "keyHash"=p_key_hash
      RETURNING id,"keyHash",action,scope,"requestHash","statusCode","responsePayload","completedAt","expiresAt"
      INTO row_value;
    inserted:=true;
  ELSIF NOT FOUND THEN
    BEGIN
      INSERT INTO public."ActionIdempotencyKey"(
        id,"keyHash",action,scope,"requestHash","createdAt","expiresAt"
      ) VALUES (
        gen_random_uuid()::text,p_key_hash,p_action,expected_scope,p_request_hash,
        now_at,now_at+interval '10 minutes'
      ) RETURNING id,"keyHash",action,scope,"requestHash","statusCode","responsePayload","completedAt","expiresAt"
      INTO row_value;
      inserted:=true;
    EXCEPTION WHEN unique_violation THEN
      SELECT k.id,k."keyHash",k.action,k.scope,k."requestHash",k."statusCode",k."responsePayload",
        k."completedAt",k."expiresAt" INTO STRICT row_value FROM public."ActionIdempotencyKey" k
        WHERE "keyHash"=p_key_hash FOR UPDATE;
    END;
  END IF;

  IF row_value.action IS DISTINCT FROM p_action
     OR row_value.scope IS DISTINCT FROM expected_scope
     OR row_value."requestHash" IS DISTINCT FROM p_request_hash
  THEN RAISE EXCEPTION 'IDEMPOTENCY_KEY_PAYLOAD_MISMATCH'; END IF;

  IF p_operation='BEGIN' THEN
    IF row_value."completedAt" IS NOT NULL THEN
      RETURN jsonb_build_object(
        'replayed',true,'keyHash',row_value."keyHash",
        'statusCode',coalesce(row_value."statusCode",200),
        'responsePayload',coalesce(row_value."responsePayload",'{}'::jsonb)
      );
    END IF;
    IF NOT inserted THEN RAISE EXCEPTION 'IDEMPOTENCY_KEY_IN_PROGRESS'; END IF;
    RETURN jsonb_build_object('replayed',false,'keyHash',row_value."keyHash");
  END IF;

  IF row_value."completedAt" IS NOT NULL THEN
    RETURN jsonb_build_object('completed',true,'idempotent',true);
  END IF;
  UPDATE public."ActionIdempotencyKey" SET
    "statusCode"=p_status_code,"responsePayload"=p_response,
    "completedAt"=now_at
    WHERE "keyHash"=p_key_hash;
  RETURN jsonb_build_object('completed',true,'idempotent',false);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.printing_connector_registration(
  p_capability text,
  p_purpose text,
  p_request_id text,
  p_operation text,
  p_payload jsonb
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public
AS $fn$
DECLARE
  actor record;
  registration record;
  printer_input jsonb;
  printer_id text;
  native_id text;
  printer_name text;
  now_at timestamp without time zone:=transaction_timestamp();
  expires_at timestamp without time zone;
  trust_valid boolean;
BEGIN
  IF p_purpose<>'printing-connector-registration'
     OR p_operation NOT IN ('LOOKUP','HEARTBEAT')
     OR jsonb_typeof(coalesce(p_payload,'{}'::jsonb))<>'object'
  THEN RAISE EXCEPTION 'PRINTING_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;
  SELECT * INTO STRICT actor
    FROM app_rls.printing_bind_actor(p_capability,p_purpose,p_request_id,NULL);
  IF actor.role<>'MANUFACTURER_ADMIN'
  THEN RAISE EXCEPTION 'PRINTING_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM set_config('app.printing_operation','printing-connector-registration-'||lower(p_operation),true),
          set_config('app.printing_user_id',actor."userId",true);

  IF p_operation='LOOKUP' THEN
    SELECT pr.id,pr."userId",pr."orgId",pr."licenseeId",pr."deviceFingerprint",pr."agentId",
      pr."publicKeyPem",pr."trustStatus",pr."revokedAt",pr."approvedAt",pr."lastSeenAt",pr."updatedAt"
      INTO registration
      FROM public."PrinterRegistration" pr
      WHERE pr."userId"=actor."userId" AND pr."revokedAt" IS NULL
        AND (
          nullif(p_payload->>'deviceFingerprint','') IS NULL
          OR pr."deviceFingerprint"=p_payload->>'deviceFingerprint'
        )
      ORDER BY pr."approvedAt" DESC NULLS LAST,pr."lastSeenAt" DESC NULLS LAST,pr."updatedAt" DESC
      LIMIT 1;
    RETURN CASE WHEN registration.id IS NULL THEN NULL ELSE jsonb_build_object(
      'id',registration.id,'agentId',registration."agentId",
      'deviceFingerprint',registration."deviceFingerprint",
      'publicKeyPem',registration."publicKeyPem",'trustStatus',registration."trustStatus",
      'revokedAt',registration."revokedAt"
    ) END;
  END IF;

  trust_valid:=coalesce((p_payload->>'signatureValid')::boolean,false)
    AND coalesce((p_payload->>'connected')::boolean,false);
  expires_at:=nullif(p_payload->>'expiresAt','')::timestamp without time zone;
  IF length(btrim(coalesce(p_payload->>'agentId',''))) NOT BETWEEN 1 AND 180
     OR length(btrim(coalesce(p_payload->>'deviceFingerprint',''))) NOT BETWEEN 8 AND 256
     OR p_payload->>'publicKeyPem' NOT LIKE '%BEGIN%PUBLIC KEY%'
     OR length(p_payload->>'publicKeyPem')>8000
     OR p_payload->>'signedPayloadHash' !~ '^[0-9a-f]{64}$'
     OR length(btrim(coalesce(p_payload->>'heartbeatNonce',''))) NOT BETWEEN 12 AND 180
     OR expires_at<=now_at OR expires_at>now_at+interval '15 minutes'
     OR jsonb_typeof(coalesce(p_payload->'metadata','{}'::jsonb))<>'object'
     OR jsonb_typeof(coalesce(p_payload->'printers','[]'::jsonb))<>'array'
     OR jsonb_array_length(coalesce(p_payload->'printers','[]'::jsonb))>50
  THEN RAISE EXCEPTION 'CONNECTOR_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;

  SELECT pr.id,pr."userId",pr."orgId",pr."licenseeId",pr."deviceFingerprint",pr."agentId",
    pr."publicKeyPem",pr."trustStatus",pr."revokedAt",pr."approvedAt",pr."lastSeenAt",pr."updatedAt"
    INTO registration
    FROM public."PrinterRegistration" pr
    WHERE pr."userId"=actor."userId"
      AND pr."deviceFingerprint"=btrim(p_payload->>'deviceFingerprint')
    FOR UPDATE;
  IF registration.id IS NULL THEN
    registration.id:=gen_random_uuid()::text;
    PERFORM set_config('app.printing_registration_id',registration.id,true);
    INSERT INTO public."PrinterRegistration"(
      id,"userId","orgId","licenseeId","deviceFingerprint","agentId","publicKeyPem",
      "certFingerprint","trustStatus","trustReason","approvedAt","lastSeenAt","createdAt","updatedAt"
    ) VALUES (
      registration.id,actor."userId",actor."organizationId",actor."licenseeId",
      btrim(p_payload->>'deviceFingerprint'),btrim(p_payload->>'agentId'),
      p_payload->>'publicKeyPem',nullif(p_payload->>'certFingerprint',''),
      CASE WHEN trust_valid THEN 'TRUSTED' ELSE 'FAILED' END::public."PrinterTrustStatus",
      CASE WHEN trust_valid THEN NULL ELSE left(coalesce(p_payload->>'rejectionReason','Signature verification failed'),500) END,
      CASE WHEN trust_valid THEN now_at END,now_at,now_at,now_at
    ) RETURNING id,"userId","orgId","licenseeId","deviceFingerprint","agentId","publicKeyPem",
      "trustStatus","revokedAt","approvedAt","lastSeenAt","updatedAt" INTO registration;
  ELSE
    PERFORM set_config('app.printing_registration_id',registration.id,true);
    IF registration."revokedAt" IS NOT NULL
       OR registration."trustStatus"='REVOKED'::public."PrinterTrustStatus"
    THEN RAISE EXCEPTION 'CONNECTOR_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;
    UPDATE public."PrinterRegistration" SET
      "orgId"=actor."organizationId","licenseeId"=actor."licenseeId",
      "agentId"=btrim(p_payload->>'agentId'),
      "publicKeyPem"=CASE WHEN trust_valid THEN p_payload->>'publicKeyPem' ELSE "publicKeyPem" END,
      "certFingerprint"=coalesce("certFingerprint",nullif(p_payload->>'certFingerprint','')),
      "trustStatus"=CASE WHEN trust_valid THEN 'TRUSTED' ELSE 'FAILED' END::public."PrinterTrustStatus",
      "trustReason"=CASE WHEN trust_valid THEN NULL ELSE left(coalesce(p_payload->>'rejectionReason','Signature verification failed'),500) END,
      "approvedAt"=CASE WHEN trust_valid THEN coalesce("approvedAt",now_at) ELSE "approvedAt" END,
      "lastSeenAt"=now_at,"updatedAt"=now_at
      WHERE id=registration.id
      RETURNING id,"userId","orgId","licenseeId","deviceFingerprint","agentId","publicKeyPem",
        "trustStatus","revokedAt","approvedAt","lastSeenAt","updatedAt" INTO registration;
  END IF;

  IF trust_valid THEN
    UPDATE public."PrinterRegistration"
      SET "trustStatus"='REVOKED',"trustReason"='Replaced by a newer signed connector registration',
          "revokedAt"=now_at,"updatedAt"=now_at
      WHERE "userId"=actor."userId" AND id<>registration.id AND "revokedAt" IS NULL;
  END IF;

  INSERT INTO public."PrinterAttestation"(
    id,"printerRegistrationId","signedPayloadHash","heartbeatNonce","attestedAt","expiresAt",
    "sourceIpHash","userAgentHash","mtlsFingerprint","signatureValid","trustValid",
    "rejectionReason",metadata,"createdAt"
  ) VALUES (
    gen_random_uuid()::text,registration.id,p_payload->>'signedPayloadHash',
    btrim(p_payload->>'heartbeatNonce'),now_at,expires_at,
    nullif(p_payload->>'sourceIpHash',''),nullif(p_payload->>'userAgentHash',''),
    nullif(p_payload->>'certFingerprint',''),coalesce((p_payload->>'signatureValid')::boolean,false),
    trust_valid,nullif(left(p_payload->>'rejectionReason',500),''),
    coalesce(p_payload->'metadata','{}'::jsonb),now_at
  ) ON CONFLICT ("printerRegistrationId","heartbeatNonce") DO NOTHING;

  IF trust_valid THEN
    FOR printer_input IN SELECT value FROM jsonb_array_elements(coalesce(p_payload->'printers','[]'::jsonb))
    LOOP
      native_id:=left(btrim(coalesce(printer_input->>'printerId',printer_input->>'id','')),180);
      printer_name:=left(btrim(coalesce(printer_input->>'printerName',printer_input->>'name','')),180);
      IF native_id='' OR printer_name='' THEN CONTINUE; END IF;
      SELECT p.id INTO printer_id FROM public."Printer" p
        WHERE p."printerRegistrationId"=registration.id AND p."nativePrinterId"=native_id
        FOR UPDATE;
      printer_id:=coalesce(printer_id,gen_random_uuid()::text);
      PERFORM set_config('app.printing_printer_id',printer_id,true);
      INSERT INTO public."Printer"(
        id,name,vendor,model,"connectionType","commandLanguage","nativePrinterId","agentId",
        "deviceFingerprint","printerRegistrationId","orgId","licenseeId","assignedUserId",
        "createdByUserId","isActive","isDefault","lastSeenAt","lastValidatedAt",
        "lastValidationStatus","capabilitySummary","calibrationProfile",metadata,"createdAt","updatedAt"
      ) VALUES (
        printer_id,printer_name,nullif(left(printer_input->>'vendor',180),''),
        nullif(left(printer_input->>'model',180),''),
        'LOCAL_AGENT'::public."PrinterConnectionType",
        coalesce(nullif(upper(printer_input->>'commandLanguage'),'')::public."PrinterCommandLanguage",
          'AUTO'::public."PrinterCommandLanguage"),
        native_id,registration."agentId",registration."deviceFingerprint",registration.id,
        actor."organizationId",actor."licenseeId",actor."userId",actor."userId",true,
        native_id=coalesce(p_payload->'metadata'->>'selectedPrinterId',p_payload->'metadata'->>'printerId'),
        now_at,now_at,'READY',printer_input->'capabilitySummary',
        p_payload->'metadata'->'calibrationProfile',
        jsonb_build_object('online',coalesce((printer_input->>'online')::boolean,true)),now_at,now_at
      )
      ON CONFLICT ("printerRegistrationId","nativePrinterId") DO UPDATE SET
        name=excluded.name,model=excluded.model,"agentId"=excluded."agentId",
        "deviceFingerprint"=excluded."deviceFingerprint","orgId"=excluded."orgId",
        "licenseeId"=excluded."licenseeId","assignedUserId"=excluded."assignedUserId",
        "isActive"=true,"isDefault"=excluded."isDefault","lastSeenAt"=now_at,
        "lastValidatedAt"=now_at,"lastValidationStatus"='READY',
        "capabilitySummary"=excluded."capabilitySummary",
        "calibrationProfile"=excluded."calibrationProfile",metadata=excluded.metadata,"updatedAt"=now_at;
    END LOOP;
  END IF;
  RETURN jsonb_build_object('registrationId',registration.id,'trusted',trust_valid,
    'trustStatus',registration."trustStatus",'idempotent',false);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.printing_test_label_job(
  p_capability text,
  p_request_id text,
  p_operation text,
  p_printer_id text,
  p_connector jsonb,
  p_job jsonb
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public
AS $fn$
DECLARE
  actor record;
  connector_actor record;
  registration record;
  printer_row record;
  current_job jsonb;
  next_job jsonb;
  now_at timestamp without time zone:=transaction_timestamp();
  issued_at timestamp without time zone;
  expires_at timestamp without time zone;
  fingerprint jsonb;
BEGIN
  IF p_operation NOT IN ('QUEUE','CLAIM','ACK','CONFIRM','FAIL')
     OR p_request_id !~* '^[0-9a-f-]{36}$'
     OR p_printer_id !~* '^[0-9a-f-]{36}$'
     OR jsonb_typeof(coalesce(p_connector,'{}'::jsonb))<>'object'
     OR jsonb_typeof(coalesce(p_job,'{}'::jsonb))<>'object'
  THEN RAISE EXCEPTION 'PRINTING_TEST_LABEL_DENIED' USING ERRCODE='42501'; END IF;

  IF p_operation='QUEUE' THEN
    SELECT * INTO STRICT actor
      FROM app_rls.printing_bind_actor(p_capability,'printing-test-label',p_request_id,NULL);
    IF actor.role<>'MANUFACTURER_ADMIN'
    THEN RAISE EXCEPTION 'PRINTING_TEST_LABEL_DENIED' USING ERRCODE='42501'; END IF;
    PERFORM set_config('app.printing_operation','printing-test-label-queue',true),
            set_config('app.printing_printer_id',p_printer_id,true);
    SELECT p.id,p.metadata,p."orgId",p."licenseeId",p."connectionType",p."deliveryMode",
      p."nativePrinterId",p."ipAddress",p.host,p.port INTO STRICT printer_row FROM public."Printer" p
      WHERE p.id=p_printer_id AND p."connectionType"='LOCAL_AGENT' AND p."isActive"
        AND p."assignedUserId"=actor."userId"
        AND EXISTS (
          SELECT 1 FROM public."ManufacturerLicenseeLink" ml
          JOIN public."Licensee" l ON l.id=ml."licenseeId"
          JOIN public."Organization" o ON o.id=l."orgId"
          WHERE ml."manufacturerId"=actor."userId" AND ml."licenseeId"=p."licenseeId"
            AND l."isActive" AND l."suspendedAt" IS NULL AND o."isActive"
        )
      FOR UPDATE;
    current_job:=printer_row.metadata->'pendingLocalAgentTestLabel';
    IF current_job IS NOT NULL
       AND coalesce(current_job->>'status','') NOT IN ('CONFIRMED','FAILED','EXPIRED')
       AND nullif(current_job->>'expiresAt','')::timestamp without time zone>now_at
    THEN RETURN current_job||jsonb_build_object('idempotent',true); END IF;
    expires_at:=nullif(p_job->>'expiresAt','')::timestamp without time zone;
    IF p_job->>'testJobId' !~* '^[0-9a-f-]{36}$'
       OR p_job->>'status'<>'PENDING'
       OR p_job->>'payloadHash' !~ '^[0-9a-f]{64}$'
       OR length(coalesce(p_job->>'payloadContent','')) NOT BETWEEN 1 AND 65536
       OR length(coalesce(p_job->>'code','')) NOT BETWEEN 1 AND 80
       OR expires_at<=now_at OR expires_at>now_at+interval '5 minutes'
    THEN RAISE EXCEPTION 'PRINTING_TEST_LABEL_DENIED' USING ERRCODE='42501'; END IF;
    UPDATE public."Printer" SET
      metadata=jsonb_set(coalesce(metadata,'{}'::jsonb),'{pendingLocalAgentTestLabel}',p_job,true),
      "updatedAt"=now_at
      WHERE id=printer_row.id
      RETURNING id,metadata,"orgId","licenseeId","connectionType","deliveryMode",
        "nativePrinterId","ipAddress",host,port INTO printer_row;
    PERFORM app_rls.printing_write_audit(
      actor."userId",actor.role,printer_row."orgId",printer_row."licenseeId",
      'PRINTER_TEST_LABEL_QUEUED','Printer',printer_row.id,
      jsonb_build_object('testJobId',p_job->>'testJobId')
    );
    RETURN p_job||jsonb_build_object('idempotent',false);
  END IF;

  IF session_user<>{{APP_ROLE}}
  THEN RAISE EXCEPTION 'PRINTING_TEST_LABEL_DENIED' USING ERRCODE='42501'; END IF;
  issued_at:=nullif(p_connector->>'issuedAt','')::timestamp without time zone;
  IF p_connector->>'registrationId' !~* '^[0-9a-f-]{36}$'
     OR length(btrim(coalesce(p_connector->>'agentId',''))) NOT BETWEEN 1 AND 180
     OR length(btrim(coalesce(p_connector->>'deviceFingerprint',''))) NOT BETWEEN 8 AND 256
     OR p_connector->>'nonce' !~ '^[A-Za-z0-9_-]{16,160}$'
     OR issued_at IS NULL OR abs(extract(epoch FROM (now_at-issued_at)))>120
  THEN RAISE EXCEPTION 'PRINTING_TEST_LABEL_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM set_config('app.printing_operation','printing-connector-test-label-'||lower(p_operation),true),
          set_config('app.printing_request_id',p_request_id,true),
          set_config('app.printing_registration_id',p_connector->>'registrationId',true),
          set_config('app.printing_printer_id',p_printer_id,true);
  SELECT pr.id,pr."userId",pr."orgId",pr."licenseeId" INTO STRICT registration
    FROM public."PrinterRegistration" pr
    WHERE pr.id=p_connector->>'registrationId'
      AND pr."agentId"=p_connector->>'agentId'
      AND pr."deviceFingerprint"=p_connector->>'deviceFingerprint'
      AND pr."trustStatus"='TRUSTED' AND pr."revokedAt" IS NULL;
  PERFORM set_config('app.printing_user_id',registration."userId",true),
          set_config('app.printing_organization_id',coalesce(registration."orgId",''),true),
          set_config('app.printing_licensee_id',coalesce(registration."licenseeId",''),true);
  SELECT u.id,u.role::text AS role INTO STRICT connector_actor
    FROM public."User" u
    WHERE u.id=registration."userId" AND u."isActive" AND u."deletedAt" IS NULL;
  IF NOT EXISTS (
    SELECT 1 FROM public."PrinterAttestation" pa
    WHERE pa."printerRegistrationId"=registration.id
      AND pa."signatureValid" AND pa."trustValid" AND pa."expiresAt">now_at
  ) THEN RAISE EXCEPTION 'PRINTER_ATTESTATION_STALE'; END IF;
  SELECT p.id,p.metadata,p."orgId",p."licenseeId",p."connectionType",p."deliveryMode",
    p."nativePrinterId",p."ipAddress",p.host,p.port,p."printerUri",p."commandLanguage"
    INTO STRICT printer_row FROM public."Printer" p
    WHERE p.id=p_printer_id AND p."printerRegistrationId"=registration.id
      AND p."isActive" AND p."connectionType"='LOCAL_AGENT'
    FOR UPDATE;
  current_job:=printer_row.metadata->'pendingLocalAgentTestLabel';
  IF current_job IS NULL THEN RETURN jsonb_build_object('available',false); END IF;
  expires_at:=nullif(current_job->>'expiresAt','')::timestamp without time zone;
  IF expires_at IS NULL OR expires_at<=now_at THEN
    next_job:=current_job||jsonb_build_object(
      'status','EXPIRED','failedAt',now_at,
      'failedReason','The connector did not complete the printer test before expiry'
    );
    UPDATE public."Printer" SET
      metadata=jsonb_set(coalesce(metadata,'{}'::jsonb),'{pendingLocalAgentTestLabel}',next_job,true),
      "updatedAt"=now_at WHERE id=printer_row.id;
    RETURN jsonb_build_object('available',false);
  END IF;

  IF p_operation='CLAIM' THEN
    IF current_job->>'status'<>'PENDING' THEN RETURN jsonb_build_object('available',false); END IF;
    next_job:=current_job||jsonb_build_object('status','CLAIMED','claimedAt',now_at);
  ELSE
    IF p_job->>'testJobId' IS DISTINCT FROM current_job->>'testJobId'
    THEN RETURN jsonb_build_object('matched',false); END IF;
    IF p_operation='ACK' THEN
      IF current_job->>'status'='ACKED' THEN RETURN jsonb_build_object('matched',true,'idempotent',true); END IF;
      IF current_job->>'status'<>'CLAIMED' THEN RAISE EXCEPTION 'INVALID_STATE_TRANSITION'; END IF;
      next_job:=current_job||jsonb_build_object('status','ACKED','ackedAt',now_at,'ackMetadata',coalesce(p_job->'metadata','{}'::jsonb));
    ELSIF p_operation='CONFIRM' THEN
      IF current_job->>'status'='CONFIRMED' THEN RETURN jsonb_build_object('matched',true,'idempotent',true); END IF;
      IF current_job->>'status' NOT IN ('CLAIMED','ACKED') THEN RAISE EXCEPTION 'INVALID_STATE_TRANSITION'; END IF;
      next_job:=current_job||jsonb_build_object(
        'status','CONFIRMED','confirmedAt',now_at,
        'payloadType',p_job->>'payloadType','deviceJobRef',p_job->>'deviceJobRef',
        'confirmationMode',coalesce(p_job->>'confirmationMode','LOCAL_QUEUE'),
        'confirmMetadata',coalesce(p_job->'metadata','{}'::jsonb)
      );
    ELSE
      IF current_job->>'status' IN ('CONFIRMED','FAILED','EXPIRED')
      THEN RETURN jsonb_build_object('matched',true,'idempotent',true); END IF;
      next_job:=current_job||jsonb_build_object(
        'status','FAILED','failedAt',now_at,
        'failedReason',left(coalesce(p_job->>'reason','Connector reported test-label failure'),500)
      );
    END IF;
  END IF;

  fingerprint:=jsonb_build_object(
    'connectionType',printer_row."connectionType",
    'deliveryMode',coalesce(printer_row."deliveryMode",'DIRECT'),
    'nativePrinterId',printer_row."nativePrinterId",
    'ipAddress',printer_row."ipAddress",'host',printer_row.host,'port',printer_row.port,
    'printerUri',printer_row."printerUri",'commandLanguage',printer_row."commandLanguage"
  );
  UPDATE public."Printer" SET metadata=
    CASE WHEN p_operation='CONFIRM' THEN
      jsonb_set(
        jsonb_set(
          jsonb_set(
            jsonb_set(coalesce(metadata,'{}'::jsonb),'{pendingLocalAgentTestLabel}',next_job,true),
            '{lastTestLabelConfirmedAt}',to_jsonb(now_at),true
          ),
          '{lastTestLabelConnectionType}',to_jsonb('LOCAL_AGENT'::text),true
        ),
        '{lastTestLabelFingerprint}',fingerprint,true
      )||jsonb_build_object('lastTestLabelDeviceJobRef',p_job->>'deviceJobRef')
    ELSE jsonb_set(coalesce(metadata,'{}'::jsonb),'{pendingLocalAgentTestLabel}',next_job,true) END,
    "updatedAt"=now_at
    WHERE id=printer_row.id;
  IF p_operation IN ('ACK','CONFIRM','FAIL') THEN
    PERFORM app_rls.printing_write_audit(
      connector_actor.id,connector_actor.role,registration."orgId",registration."licenseeId",
      'PRINTER_TEST_LABEL_'||p_operation,'Printer',printer_row.id,
      jsonb_build_object(
        'testJobId',current_job->>'testJobId',
        'deviceJobRef',nullif(p_job->>'deviceJobRef','')
      )
    );
  END IF;
  RETURN CASE WHEN p_operation='CLAIM'
    THEN next_job||jsonb_build_object('available',true)
    ELSE jsonb_build_object('matched',true,'idempotent',false,'status',next_job->>'status') END;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.printing_create_job(
  p_capability text,
  p_purpose text,
  p_request_id text,
  p_batch_id text,
  p_printer_id text,
  p_quantity integer,
  p_range_start text,
  p_range_end text,
  p_print_mode text,
  p_payload_type text,
  p_print_lock_token_hash text,
  p_items jsonb
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public
AS $fn$
DECLARE
  actor record;
  batch_row record;
  printer_row record;
  job_id text:=gen_random_uuid()::text;
  session_id text:=gen_random_uuid()::text;
  now_at timestamp without time zone:=transaction_timestamp();
  item record;
  affected integer;
BEGIN
  IF p_purpose<>'printing-create-job'
     OR p_quantity NOT BETWEEN 1 AND 200000
     OR p_printer_id !~* '^[0-9a-f-]{36}$'
     OR p_print_mode NOT IN ('LOCAL_AGENT','NETWORK_DIRECT','NETWORK_IPP')
     OR p_payload_type NOT IN ('PDF','ZPL','TSPL','SBPL','EPL','DPL','HONEYWELL_DP','HONEYWELL_FINGERPRINT','IPL','CPCL','ESC_POS','JSON','OTHER')
     OR jsonb_typeof(p_items)<>'array' OR jsonb_array_length(p_items)<>p_quantity
     OR (p_print_lock_token_hash IS NOT NULL AND p_print_lock_token_hash !~ '^[0-9a-f]{64}$')
  THEN RAISE EXCEPTION 'PRINTING_INVALID_INPUT'; END IF;

  SELECT * INTO STRICT actor FROM app_rls.printing_bind_actor(
    p_capability,p_purpose,p_request_id,p_batch_id
  );
  IF actor.role<>'MANUFACTURER_ADMIN' OR actor."batchManufacturerId" IS DISTINCT FROM actor."userId" THEN
    RAISE EXCEPTION 'PRINTING_BOUNDARY_DENIED' USING ERRCODE='42501';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('printing_batch_'||p_batch_id,0));
  SELECT b.id,b."licenseeId",b."lifecycleState",b."releasedAt",b."suspendedAt"
    INTO STRICT batch_row FROM public."Batch" b WHERE b.id=p_batch_id FOR UPDATE;
  IF batch_row."lifecycleState" NOT IN ('CODES_GENERATED'::public."BatchLifecycleState",'PRINT_ACKNOWLEDGED'::public."BatchLifecycleState")
     OR batch_row."releasedAt" IS NOT NULL OR batch_row."suspendedAt" IS NOT NULL
  THEN RAISE EXCEPTION 'INVALID_STATE_TRANSITION'; END IF;
  IF EXISTS (
    SELECT 1 FROM public."PrintJob" j JOIN public."PrintSession" ps ON ps."printJobId"=j.id
     WHERE j."batchId"=p_batch_id AND j."manufacturerId"=actor."userId"
       AND j.status IN ('PENDING','SENT','PAUSED') AND ps.status IN ('ACTIVE','PAUSED','RESUME_PENDING')
  ) THEN RAISE EXCEPTION 'ACTIVE_PRINT_JOB_EXISTS'; END IF;

  SELECT p.id,p."connectionType",p."commandLanguage",p."printerRegistrationId",p."nativePrinterId"
    INTO printer_row FROM public."Printer" p
   WHERE p.id=p_printer_id AND p."isActive"
     AND p."licenseeId"=batch_row."licenseeId"
     AND (
       p."assignedUserId"=actor."userId"
       OR EXISTS (
         SELECT 1 FROM public."PrinterRegistration" pr
          WHERE pr.id=p."printerRegistrationId" AND pr."userId"=actor."userId"
            AND pr."trustStatus"='TRUSTED'::public."PrinterTrustStatus" AND pr."revokedAt" IS NULL
       )
     );
  IF NOT FOUND THEN
    RAISE EXCEPTION 'PRINTING_BOUNDARY_DENIED' USING ERRCODE='42501';
  END IF;
  IF printer_row."connectionType"::text<>p_print_mode AND NOT (
    printer_row."connectionType"='LOCAL_AGENT'::public."PrinterConnectionType" AND p_print_mode='LOCAL_AGENT'
  ) THEN RAISE EXCEPTION 'PRINTER_NOT_READY'; END IF;
  IF (
    printer_row."connectionType"='NETWORK_IPP'::public."PrinterConnectionType"
    AND p_payload_type<>'PDF'
  ) OR (
    printer_row."connectionType"<>'NETWORK_IPP'::public."PrinterConnectionType"
    AND p_payload_type<>CASE
      WHEN printer_row."commandLanguage"::text IN (
        'ZPL','TSPL','SBPL','EPL','DPL','HONEYWELL_DP','HONEYWELL_FINGERPRINT',
        'IPL','CPCL'
      ) THEN printer_row."commandLanguage"::text
      ELSE 'ZPL' END
  ) THEN RAISE EXCEPTION 'PRINTER_PAYLOAD_MISMATCH'; END IF;
  IF printer_row."connectionType"='LOCAL_AGENT'::public."PrinterConnectionType" THEN
    IF printer_row."printerRegistrationId" IS NULL THEN RAISE EXCEPTION 'PRINTER_ATTESTATION_STALE'; END IF;
    PERFORM set_config('app.printing_registration_id',printer_row."printerRegistrationId",true);
    IF NOT EXISTS (
      SELECT 1 FROM public."PrinterAttestation" pa
      WHERE pa."printerRegistrationId"=printer_row."printerRegistrationId"
        AND pa."signatureValid" AND pa."trustValid" AND pa."expiresAt">now_at
        AND coalesce((pa.metadata->>'connected')::boolean,false)
        AND coalesce(pa.metadata->>'selectedPrinterId',pa.metadata->>'printerId','')
          IN (printer_row.id,coalesce(printer_row."nativePrinterId",''))
    ) THEN RAISE EXCEPTION 'PRINTER_ATTESTATION_STALE'; END IF;
  END IF;

  PERFORM set_config('app.printing_job_id',job_id,true),
          set_config('app.printing_session_row_id',session_id,true),
          set_config('app.printing_printer_id',p_printer_id,true);
  INSERT INTO public."PrintJob"(
    id,"jobNumber","batchId","manufacturerId","printerId",status,"printMode","pipelineState",
    "payloadType",quantity,"itemCount","rangeStart","rangeEnd","printLockTokenHash","createdAt","updatedAt"
  ) VALUES (
    job_id,'PJ-'||to_char(now_at,'YYYYMMDD')||'-'||upper(substr(replace(job_id,'-',''),1,8)),
    p_batch_id,actor."userId",p_printer_id,'PENDING',p_print_mode::public."PrintDispatchMode",
    CASE WHEN p_print_mode='LOCAL_AGENT' THEN 'QUEUED' ELSE 'PREFLIGHT_OK' END::public."PrintPipelineState",
    p_payload_type::public."PrintPayloadType",p_quantity,p_quantity,p_range_start,p_range_end,
    p_print_lock_token_hash,now_at,now_at
  );
  INSERT INTO public."PrintSession"(
    id,"printJobId","batchId","manufacturerId","printerRegistrationId","printerId",
    status,"totalItems","createdAt","updatedAt"
  ) VALUES (
    session_id,job_id,p_batch_id,actor."userId",printer_row."printerRegistrationId",p_printer_id,
    'ACTIVE',p_quantity,now_at,now_at
  );

  FOR item IN SELECT value,row_number() OVER () AS seq FROM jsonb_array_elements(p_items)
  LOOP
    IF item.value->>'qrCodeId' !~* '^[0-9a-f-]{36}$'
       OR item.value->>'tokenNonce' !~ '^(?:[0-9a-f]{64}|[A-Za-z0-9_-]{22})$'
       OR item.value->>'tokenHash' !~ '^[0-9a-f]{64}$'
       OR (item.value->>'tokenExpiresAt')::timestamp without time zone<=now_at
    THEN RAISE EXCEPTION 'PRINTING_INVALID_INPUT'; END IF;
    UPDATE public."QRCode" q SET
      status='ACTIVATED', "tokenNonce"=item.value->>'tokenNonce',
      "tokenIssuedAt"=now_at,"tokenExpiresAt"=(item.value->>'tokenExpiresAt')::timestamp without time zone,
      "tokenHash"=item.value->>'tokenHash',"printJobId"=job_id,
      "issuanceMode"='GOVERNED_PRINT',"updatedAt"=now_at
     WHERE q.id=item.value->>'qrCodeId' AND q."batchId"=p_batch_id
       AND q."licenseeId"=batch_row."licenseeId"
       AND q.status='ALLOCATED' AND q."printJobId" IS NULL
       AND (p_range_start IS NULL OR q."displayCode">=p_range_start)
       AND (p_range_end IS NULL OR q."displayCode"<=p_range_end);
    GET DIAGNOSTICS affected=ROW_COUNT;
    IF affected<>1 THEN RAISE EXCEPTION 'BATCH_BUSY'; END IF;
    INSERT INTO public."PrintItem"(
      id,"printSessionId","qrCodeId",code,state,"pipelineState","issueSequence","createdAt","updatedAt"
    ) SELECT gen_random_uuid()::text,session_id,q.id,q.code,'RESERVED','QUEUED',item.seq,now_at,now_at
      FROM public."QRCode" q WHERE q.id=item.value->>'qrCodeId';
  END LOOP;
  PERFORM app_rls.printing_write_audit(
    actor."userId",actor.role,actor."organizationId",actor."batchLicenseeId",
    'PRINT_JOB_CREATED','PrintJob',job_id,
    jsonb_build_object('batchId',p_batch_id,'printerId',p_printer_id,'quantity',p_quantity,'printSessionId',session_id)
  );
  RETURN jsonb_build_object(
    'job',jsonb_build_object('id',job_id,'batchId',p_batch_id,'manufacturerId',actor."userId",
      'printerId',p_printer_id,'status','PENDING','printMode',p_print_mode,'pipelineState',
      CASE WHEN p_print_mode='LOCAL_AGENT' THEN 'QUEUED' ELSE 'PREFLIGHT_OK' END,'quantity',p_quantity,'createdAt',now_at),
    'session',jsonb_build_object('id',session_id,'printJobId',job_id,'batchId',p_batch_id,
      'manufacturerId',actor."userId",'printerId',p_printer_id,'status','ACTIVE','totalItems',p_quantity),
    'preparedCount',p_quantity
  );
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.printing_control_job(
  p_capability text,
  p_purpose text,
  p_request_id text,
  p_job_id text,
  p_operation text,
  p_reason text DEFAULT NULL
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public
AS $fn$
DECLARE actor record; job_row record; session_row record; now_at timestamp without time zone:=transaction_timestamp();
  target_job_status public."PrintJobStatus"; target_pipeline public."PrintPipelineState"; target_session public."PrintSessionStatus";
BEGIN
  IF p_purpose<>'printing-job-control' OR p_operation NOT IN ('PAUSE','RESUME','STOP','ABANDON')
     OR p_job_id !~* '^[0-9a-f-]{36}$' OR length(coalesce(p_reason,''))>500
  THEN RAISE EXCEPTION 'PRINTING_INVALID_INPUT'; END IF;
  SELECT * INTO STRICT actor FROM app_rls.printing_bind_actor(
    p_capability,p_purpose,p_request_id,NULL
  );
  PERFORM set_config('app.printing_job_id',p_job_id,true);
  SELECT j.id,j."batchId",j."manufacturerId",j.status
    INTO STRICT job_row FROM public."PrintJob" j WHERE j.id=p_job_id FOR UPDATE;
  SELECT * INTO STRICT actor FROM app_rls.printing_bind_actor(
    p_capability,p_purpose,p_request_id,job_row."batchId"
  );
  IF actor.role='MANUFACTURER_ADMIN' AND job_row."manufacturerId"<>actor."userId" THEN
    RAISE EXCEPTION 'PRINTING_BOUNDARY_DENIED' USING ERRCODE='42501';
  END IF;
  SELECT ps.id,ps.status INTO STRICT session_row
    FROM public."PrintSession" ps WHERE ps."printJobId"=p_job_id FOR UPDATE;
  PERFORM set_config('app.printing_job_id',p_job_id,true),
          set_config('app.printing_session_row_id',session_row.id,true);

  IF p_operation='PAUSE' THEN
    IF job_row.status NOT IN ('PENDING','SENT') OR session_row.status<>'ACTIVE' THEN RAISE EXCEPTION 'INVALID_STATE_TRANSITION'; END IF;
    target_job_status:='PAUSED'; target_pipeline:='PAUSED'; target_session:='PAUSED';
  ELSIF p_operation='RESUME' THEN
    IF job_row.status<>'PAUSED' OR session_row.status NOT IN ('PAUSED','RESUME_PENDING') THEN RAISE EXCEPTION 'INVALID_STATE_TRANSITION'; END IF;
    target_job_status:='SENT'; target_pipeline:='RESUME_PENDING'; target_session:='RESUME_PENDING';
  ELSE
    IF job_row.status IN ('CONFIRMED','CANCELLED','STOPPED') THEN
      RETURN jsonb_build_object('jobId',p_job_id,'status',job_row.status,'idempotent',true);
    END IF;
    IF p_operation='ABANDON' AND EXISTS (
      SELECT 1 FROM public."PrintItem" pi WHERE pi."printSessionId"=session_row.id AND pi."printConfirmedAt" IS NOT NULL
    ) THEN RAISE EXCEPTION 'PHYSICAL_CONFIRMATION_PRESENT'; END IF;
    target_job_status:=CASE WHEN p_operation='ABANDON' THEN 'CANCELLED' ELSE 'STOPPED' END;
    target_pipeline:=CASE WHEN p_operation='ABANDON' THEN 'STOPPED' ELSE 'STOPPED' END;
    target_session:=CASE WHEN p_operation='ABANDON' THEN 'CANCELLED' ELSE 'STOPPED' END;
    UPDATE public."PrintItem" SET state='CANCELLED', "pipelineState"='STOPPED',
      "failureReason"=nullif(btrim(p_reason),''),"updatedAt"=now_at
      WHERE "printSessionId"=session_row.id AND state NOT IN ('PRINT_CONFIRMED','CLOSED','CANCELLED');
  END IF;
  UPDATE public."PrintSession" SET status=target_session,
    "failedReason"=CASE WHEN p_operation IN ('STOP','ABANDON') THEN nullif(btrim(p_reason),'') ELSE "failedReason" END,
    "completedAt"=CASE WHEN p_operation IN ('STOP','ABANDON') THEN now_at ELSE "completedAt" END,
    "updatedAt"=now_at WHERE id=session_row.id;
  UPDATE public."PrintJob" SET status=target_job_status,"pipelineState"=target_pipeline,
    "failureReason"=CASE WHEN p_operation IN ('STOP','ABANDON') THEN nullif(btrim(p_reason),'') ELSE "failureReason" END,
    "completedAt"=CASE WHEN p_operation IN ('STOP','ABANDON') THEN now_at ELSE "completedAt" END,
    "updatedAt"=now_at WHERE id=p_job_id;
  PERFORM app_rls.printing_write_audit(actor."userId",actor.role,actor."organizationId",actor."batchLicenseeId",
    'PRINT_JOB_'||p_operation,'PrintJob',p_job_id,jsonb_build_object('reason',nullif(btrim(p_reason),'')));
  RETURN jsonb_build_object('jobId',p_job_id,'status',target_job_status,'pipelineState',target_pipeline,
    'sessionStatus',target_session,'idempotent',false);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.printing_connector_event(
  p_registration_id text,
  p_agent_id text,
  p_device_fingerprint text,
  p_nonce text,
  p_issued_at timestamp without time zone,
  p_request_id text,
  p_operation text,
  p_job_id text,
  p_item_id text,
  p_printer_id text,
  p_payload_hash text,
  p_device_job_ref text,
  p_details jsonb DEFAULT '{}'::jsonb
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public
AS $fn$
DECLARE registration record; printer_row record; job_row record; session_row record; item_row record;
  now_at timestamp without time zone:=transaction_timestamp(); remaining integer; audit_actor text;
BEGIN
  IF p_operation NOT IN ('CLAIM','ACK','CONFIRM','FAIL')
     OR p_request_id !~* '^[0-9a-f-]{36}$' OR p_registration_id !~* '^[0-9a-f-]{36}$'
     OR (p_operation<>'CLAIM' AND p_job_id !~* '^[0-9a-f-]{36}$')
     OR (p_item_id IS NOT NULL AND p_item_id !~* '^[0-9a-f-]{36}$')
     OR p_nonce !~ '^[A-Za-z0-9_-]{16,160}$'
     OR abs(extract(epoch FROM (now_at-p_issued_at)))>120
     OR jsonb_typeof(coalesce(p_details,'{}'::jsonb))<>'object'
  THEN RAISE EXCEPTION 'CONNECTOR_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;
  IF session_user<>{{APP_ROLE}} THEN RAISE EXCEPTION 'CONNECTOR_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;

  PERFORM set_config('app.printing_operation','printing-connector-'||lower(p_operation),true),
          set_config('app.printing_request_id',p_request_id,true),
          set_config('app.printing_registration_id',p_registration_id,true),
          set_config('app.printing_job_id',coalesce(p_job_id,''),true),
          set_config('app.printing_item_id',coalesce(p_item_id,''),true);
  SELECT pr."userId" INTO STRICT registration FROM public."PrinterRegistration" pr
   WHERE pr.id=p_registration_id AND pr."agentId"=p_agent_id
     AND pr."deviceFingerprint"=p_device_fingerprint
     AND pr."trustStatus"='TRUSTED' AND pr."revokedAt" IS NULL;
  INSERT INTO public."PrinterAttestation"(
    id,"printerRegistrationId","signedPayloadHash","heartbeatNonce","attestedAt","expiresAt",
    "signatureValid","trustValid",metadata,"createdAt"
  ) VALUES (
    gen_random_uuid()::text,p_registration_id,coalesce(p_payload_hash,repeat('0',64)),p_nonce,
    p_issued_at,p_issued_at+interval '2 minutes',true,true,
    jsonb_build_object('operation',p_operation,'requestId',p_request_id),now_at
  );
  SELECT p.id,p.name,p."connectionType",p."commandLanguage",p."nativePrinterId",
    p."ipAddress",p.port,p."calibrationProfile",p."capabilitySummary",p.metadata
    INTO STRICT printer_row FROM public."Printer" p
   WHERE (p.id=p_printer_id OR p."nativePrinterId"=p_printer_id)
     AND p."printerRegistrationId"=p_registration_id AND p."isActive"
   ORDER BY (p.id=p_printer_id) DESC,p."isDefault" DESC,p."updatedAt" DESC LIMIT 1;
  PERFORM set_config('app.printing_printer_id',printer_row.id,true);
  IF p_operation='CLAIM' THEN
    SELECT j.id,j."batchId",j."manufacturerId",j."jobNumber",j."reprintOfJobId"
      INTO job_row FROM public."PrintJob" j
     WHERE j."printerId"=printer_row.id AND j."manufacturerId"=registration."userId"
       AND j."printMode"='LOCAL_AGENT' AND j.status IN ('PENDING','SENT')
     ORDER BY j."createdAt",j.id FOR UPDATE OF j SKIP LOCKED LIMIT 1;
    IF NOT FOUND THEN RETURN jsonb_build_object('available',false); END IF;
  ELSE
    SELECT j.id,j."batchId",j."manufacturerId",j."jobNumber",j."reprintOfJobId"
      INTO STRICT job_row FROM public."PrintJob" j
     WHERE j.id=p_job_id AND j."printerId"=printer_row.id AND j."manufacturerId"=registration."userId"
       AND j."printMode"='LOCAL_AGENT' FOR UPDATE;
  END IF;
  PERFORM set_config('app.printing_job_id',job_row.id,true),
          set_config('app.printing_batch_id',job_row."batchId",true),
          set_config('app.printing_user_id',registration."userId",true);
  PERFORM set_config('app.printing_licensee_id',(
    SELECT b."licenseeId" FROM public."Batch" b WHERE b.id=job_row."batchId"
  ),true);
  SELECT ps.id,ps."issuedItems" INTO STRICT session_row FROM public."PrintSession" ps
   WHERE ps."printJobId"=job_row.id AND ps."printerRegistrationId"=p_registration_id
     AND ps.status='ACTIVE' FOR UPDATE;
  audit_actor:=registration."userId";
  PERFORM set_config('app.printing_session_row_id',session_row.id,true),
          set_config('app.printing_printer_id',printer_row.id,true);

  IF p_operation='CLAIM' THEN
    SELECT pi.id,pi."qrCodeId",pi.code,pi.state,pi."issueSequence"
      INTO item_row FROM public."PrintItem" pi
     WHERE pi."printSessionId"=session_row.id AND pi.state='RESERVED'
     ORDER BY pi."issueSequence" NULLS LAST,pi.id FOR UPDATE SKIP LOCKED LIMIT 1;
    IF NOT FOUND THEN RETURN jsonb_build_object('available',false); END IF;
    PERFORM set_config('app.printing_item_id',item_row.id,true);
    UPDATE public."PrintItem" SET state='ISSUED',"pipelineState"='SENT_TO_PRINTER',
      "issuedAt"=now_at,"dispatchedAt"=now_at,"issueSequence"=session_row."issuedItems"+1,
      "attemptCount"="attemptCount"+1,"updatedAt"=now_at
      WHERE id=item_row.id;
    item_row."issueSequence":=session_row."issuedItems"+1;
    UPDATE public."PrintSession" SET "issuedItems"="issuedItems"+1,"updatedAt"=now_at WHERE id=session_row.id;
    UPDATE public."PrintJob" SET status='SENT',"pipelineState"='SENT_TO_PRINTER',
      "sentAt"=coalesce("sentAt",now_at),"updatedAt"=now_at WHERE id=job_row.id;
    UPDATE public."Batch" SET "lifecycleState"='PRINT_ACKNOWLEDGED',"updatedAt"=now_at
      WHERE id=job_row."batchId" AND "lifecycleState"='CODES_GENERATED';
    INSERT INTO public."PrintItemEvent"(id,"printItemId","eventType","previousState","nextState",details,"actorUserId","createdAt")
    VALUES(gen_random_uuid()::text,item_row.id,'ISSUED','RESERVED','ISSUED',
      jsonb_build_object('dispatchMode','LOCAL_AGENT','registrationId',p_registration_id),audit_actor,now_at);
    RETURN (
      SELECT jsonb_build_object(
        'available',true,'printJobId',job_row.id,'printSessionId',session_row.id,
        'printItemId',item_row.id,'qrCodeId',item_row."qrCodeId",'code',item_row.code,
        'issueSequence',item_row."issueSequence",'issuedAt',now_at,
        'jobNumber',job_row."jobNumber",'manufacturerId',job_row."manufacturerId",
        'reprintOfJobId',job_row."reprintOfJobId",
        'qrCode',jsonb_build_object(
          'id',q.id,'code',q.code,'displayCode',q."displayCode",'batchId',q."batchId",
          'licenseeId',q."licenseeId",'tokenNonce',q."tokenNonce",'tokenIssuedAt',q."tokenIssuedAt",
          'tokenExpiresAt',q."tokenExpiresAt",'tokenHash',q."tokenHash",'replayEpoch',q."replayEpoch",
          'status',q.status
        ),
        'batch',jsonb_build_object(
          'id',b.id,'name',b.name,'licenseeId',b."licenseeId",'metadata',b.metadata,
          'licensee',jsonb_build_object('id',l.id,'name',l.name,'prefix',l.prefix,'location',l.location,'metadata',l.metadata)
        ),
        'manufacturer',jsonb_build_object('id',u.id,'name',u.name,'location',u.location,'metadata',u.metadata),
        'printer',jsonb_build_object(
          'id',printer_row.id,'name',printer_row.name,'connectionType',printer_row."connectionType",
          'commandLanguage',printer_row."commandLanguage",'nativePrinterId',printer_row."nativePrinterId",
          'ipAddress',printer_row."ipAddress",'port',printer_row.port,
          'calibrationProfile',printer_row."calibrationProfile",
          'capabilitySummary',printer_row."capabilitySummary",'metadata',printer_row.metadata
        )
      )
      FROM public."QRCode" q
      JOIN public."Batch" b ON b.id=job_row."batchId"
      JOIN public."Licensee" l ON l.id=b."licenseeId"
      JOIN public."User" u ON u.id=job_row."manufacturerId"
      WHERE q.id=item_row."qrCodeId"
    );
  END IF;

  SELECT pi.id,pi."qrCodeId",pi.state INTO STRICT item_row FROM public."PrintItem" pi
   WHERE pi.id=p_item_id AND pi."printSessionId"=session_row.id FOR UPDATE;
  IF p_operation='ACK' THEN
    IF item_row.state='AGENT_ACKED' THEN
      RETURN jsonb_build_object('printItemId',item_row.id,'acknowledged',true,'idempotent',true);
    END IF;
    IF item_row.state<>'ISSUED' THEN RAISE EXCEPTION 'INVALID_STATE_TRANSITION'; END IF;
    UPDATE public."PrintItem" SET state='AGENT_ACKED',"pipelineState"='PRINTER_ACKNOWLEDGED',
      "agentAckedAt"=now_at,"deviceJobRef"=nullif(p_device_job_ref,''),
      "dispatchMetadata"=p_details,"updatedAt"=now_at WHERE id=item_row.id;
  ELSIF p_operation='CONFIRM' THEN
    IF item_row.state IN ('PRINT_CONFIRMED','CLOSED') THEN
      RETURN jsonb_build_object('printItemId',item_row.id,'confirmed',true,'idempotent',true);
    END IF;
    IF item_row.state<>'AGENT_ACKED' THEN RAISE EXCEPTION 'PRINT_ACK_REQUIRED'; END IF;
    UPDATE public."PrintItem" SET state='PRINT_CONFIRMED',"pipelineState"='PRINT_CONFIRMED',
      "printConfirmedAt"=now_at,"confirmationEvidence"=p_details,
      "deviceJobRef"=coalesce(nullif(p_device_job_ref,''),"deviceJobRef"),"updatedAt"=now_at
      WHERE id=item_row.id;
    UPDATE public."QRCode" SET status='PRINTED',"printedAt"=now_at,"printedByUserId"=audit_actor,
      "updatedAt"=now_at WHERE id=item_row."qrCodeId" AND "printJobId"=job_row.id;
    UPDATE public."PrintSession" SET "confirmedItems"="confirmedItems"+1,"updatedAt"=now_at
      WHERE id=session_row.id;
    SELECT count(*) INTO remaining FROM public."PrintItem" pi
      WHERE pi."printSessionId"=session_row.id AND pi.state NOT IN ('PRINT_CONFIRMED','CLOSED');
    IF remaining=0 THEN
      UPDATE public."PrintSession" SET status='COMPLETED',"completedAt"=now_at,"updatedAt"=now_at WHERE id=session_row.id;
      UPDATE public."PrintJob" SET status='CONFIRMED',"pipelineState"='PRINT_CONFIRMED',
        "confirmedAt"=now_at,"completedAt"=now_at,"updatedAt"=now_at WHERE id=job_row.id;
      UPDATE public."Batch" SET "lifecycleState"='PRINT_CONFIRMED',"printedAt"=now_at,"updatedAt"=now_at
        WHERE id=job_row."batchId" AND "lifecycleState"='PRINT_ACKNOWLEDGED';
    END IF;
  ELSE
    IF item_row.state IN ('FAILED','FROZEN') THEN
      RETURN jsonb_build_object('printItemId',item_row.id,'failed',true,'idempotent',true);
    END IF;
    UPDATE public."PrintItem" SET state='FAILED',"pipelineState"='FAILED',"failedAt"=now_at,
      "failureReason"=left(coalesce(p_details->>'reason','connector_failure'),500),"updatedAt"=now_at
      WHERE id=item_row.id;
    UPDATE public."PrintSession" SET status='FAILED',"failedReason"=left(coalesce(p_details->>'reason','connector_failure'),500),
      "updatedAt"=now_at WHERE id=session_row.id;
    UPDATE public."PrintJob" SET status='FAILED',"pipelineState"='FAILED',
      "failureReason"=left(coalesce(p_details->>'reason','connector_failure'),500),"updatedAt"=now_at WHERE id=job_row.id;
  END IF;
  INSERT INTO public."PrintItemEvent"(id,"printItemId","eventType","previousState","nextState",details,"actorUserId","createdAt")
  VALUES(gen_random_uuid()::text,item_row.id,
    CASE p_operation WHEN 'ACK' THEN 'AGENT_ACKED' WHEN 'CONFIRM' THEN 'PRINT_CONFIRMED' ELSE 'FAILED' END::public."PrintItemEventType",
    item_row.state,
    CASE p_operation WHEN 'ACK' THEN 'AGENT_ACKED' WHEN 'CONFIRM' THEN 'PRINT_CONFIRMED' ELSE 'FAILED' END::public."PrintItemState",
    p_details,audit_actor,now_at);
  INSERT INTO public."PrintAuditEvent"(id,"batchId","printJobId","qrCodeId","eventType","actorId",metadata,"createdAt")
  VALUES(gen_random_uuid()::text,job_row."batchId",job_row.id,item_row."qrCodeId",
    'CONNECTOR_'||p_operation,audit_actor,
    jsonb_build_object('registrationId',p_registration_id,'printerId',p_printer_id,'deviceJobRef',p_device_job_ref),now_at);
  RETURN jsonb_build_object('printJobId',job_row.id,'printSessionId',session_row.id,
    'printItemId',item_row.id,'operation',p_operation,'idempotent',false,
    'remainingToPrint',CASE WHEN p_operation='CONFIRM' THEN remaining ELSE NULL END);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.printing_connector_identity(
  p_kind text,p_agent_id text,p_device_fingerprint text,p_printer_selector text,
  p_gateway_id text,p_gateway_secret_hash text,p_operation text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE registration record; printer_row record; attestation_row record;
  now_at timestamp without time zone:=transaction_timestamp();
BEGIN
  IF session_user<>{{APP_ROLE}} OR p_kind NOT IN ('LOCAL_AGENT','SITE_GATEWAY')
     OR p_operation NOT IN ('VERIFY','HEARTBEAT')
     OR length(coalesce(p_agent_id,''))>180 OR length(coalesce(p_device_fingerprint,''))>256
     OR length(coalesce(p_printer_selector,''))>180 OR length(coalesce(p_gateway_id,''))>180
     OR (p_gateway_secret_hash IS NOT NULL AND p_gateway_secret_hash !~ '^[0-9a-f]{64}$')
  THEN RAISE EXCEPTION 'CONNECTOR_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM set_config('app.printing_operation','printing-connector-identity',true),
          set_config('app.printing_agent_id',coalesce(p_agent_id,''),true),
          set_config('app.printing_device_fingerprint',coalesce(p_device_fingerprint,''),true),
          set_config('app.printing_gateway_id',coalesce(p_gateway_id,''),true),
          set_config('app.printing_gateway_secret_hash',coalesce(p_gateway_secret_hash,''),true);
  IF p_kind='LOCAL_AGENT' THEN
    SELECT pr.id,pr."userId",pr."orgId",pr."licenseeId",pr."agentId",pr."deviceFingerprint",
      pr."publicKeyPem",pr."trustStatus",pr."approvedAt",pr."revokedAt",pr."lastSeenAt"
      INTO STRICT registration FROM public."PrinterRegistration" pr
      WHERE pr."agentId"=p_agent_id AND pr."deviceFingerprint"=p_device_fingerprint
        AND pr."trustStatus"='TRUSTED' AND pr."revokedAt" IS NULL
      ORDER BY pr."lastSeenAt" DESC NULLS LAST,pr."updatedAt" DESC LIMIT 1;
    PERFORM set_config('app.printing_registration_id',registration.id,true),
            set_config('app.printing_user_id',registration."userId",true);
    SELECT p.id,p.name,p.vendor,p.model,p."connectionType",p."commandLanguage",p."ipAddress",p.host,p.port,
      p."resourcePath",p."tlsEnabled",p."printerUri",p."deliveryMode",p."gatewayId",p."gatewayLastSeenAt",
      p."gatewayStatus",p."gatewayLastError",p."nativePrinterId",p."agentId",p."deviceFingerprint",
      p."printerRegistrationId",p."orgId",p."licenseeId",p."assignedUserId",p."createdByUserId",
      p."isActive",p."isDefault",p."lastSeenAt",p."lastValidatedAt",p."lastValidationStatus",
      p."lastValidationMessage",p."capabilitySummary",p."calibrationProfile",p.metadata,p."createdAt",p."updatedAt"
      INTO STRICT printer_row FROM public."Printer" p
      WHERE p."printerRegistrationId"=registration.id AND p."isActive"
        AND (p.id=p_printer_selector OR p."nativePrinterId"=p_printer_selector)
      ORDER BY (p.id=p_printer_selector) DESC,p."isDefault" DESC,p."updatedAt" DESC LIMIT 1;
    PERFORM set_config('app.printing_printer_id',printer_row.id,true);
    SELECT pa."signatureValid",pa."trustValid",pa."expiresAt",pa.metadata
      INTO attestation_row FROM public."PrinterAttestation" pa
      WHERE pa."printerRegistrationId"=registration.id
      ORDER BY pa."createdAt" DESC,pa.id DESC LIMIT 1;
    IF p_operation='HEARTBEAT' THEN
      UPDATE public."PrinterRegistration" SET "lastSeenAt"=now_at,"updatedAt"=now_at WHERE id=registration.id;
      UPDATE public."Printer" SET "lastSeenAt"=now_at,"updatedAt"=now_at WHERE id=printer_row.id;
    END IF;
    RETURN jsonb_build_object(
      'registration',jsonb_build_object(
        'id',registration.id,'userId',registration."userId",'orgId',registration."orgId",
        'licenseeId',registration."licenseeId",'agentId',registration."agentId",
        'deviceFingerprint',registration."deviceFingerprint",'publicKeyPem',registration."publicKeyPem",
        'trustStatus',registration."trustStatus",'approvedAt',registration."approvedAt",
        'revokedAt',registration."revokedAt",'lastSeenAt',registration."lastSeenAt"
      ),
      'printer',to_jsonb(printer_row),
      'eligibleForPrinting',registration."publicKeyPem" LIKE '%BEGIN%' AND printer_row."isActive"
        AND attestation_row."signatureValid" AND attestation_row."trustValid"
        AND attestation_row."expiresAt">now_at
        AND coalesce((attestation_row.metadata->>'connected')::boolean,false)
        AND coalesce(attestation_row.metadata->>'selectedPrinterId',attestation_row.metadata->>'printerId','')
          IN (printer_row.id,coalesce(printer_row."nativePrinterId",''))
    );
  END IF;
  SELECT p.id,p.name,p.vendor,p.model,p."connectionType",p."commandLanguage",p."ipAddress",p.host,p.port,
    p."resourcePath",p."tlsEnabled",p."printerUri",p."deliveryMode",p."gatewayId",p."gatewayLastSeenAt",
    p."gatewayStatus",p."gatewayLastError",p."nativePrinterId",p."agentId",p."deviceFingerprint",
    p."printerRegistrationId",p."orgId",p."licenseeId",p."assignedUserId",p."createdByUserId",
    p."isActive",p."isDefault",p."lastSeenAt",p."lastValidatedAt",p."lastValidationStatus",
    p."lastValidationMessage",p."capabilitySummary",p."calibrationProfile",p.metadata,p."createdAt",p."updatedAt"
    INTO STRICT printer_row FROM public."Printer" p
    WHERE p."gatewayId"=p_gateway_id AND p."gatewaySecretHash"=p_gateway_secret_hash
      AND p."deliveryMode"='SITE_GATEWAY' AND p."isActive"
      AND (p_printer_selector IS NULL OR p_printer_selector='' OR p.id=p_printer_selector);
  PERFORM set_config('app.printing_printer_id',printer_row.id,true);
  IF p_operation='HEARTBEAT' THEN
    UPDATE public."Printer" SET "gatewayLastSeenAt"=now_at,"gatewayStatus"='ONLINE',
      "gatewayLastError"=NULL,"updatedAt"=now_at WHERE id=printer_row.id;
  END IF;
  RETURN jsonb_build_object('printer',to_jsonb(printer_row),'eligibleForPrinting',true);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.printing_gateway_job(
  p_gateway_id text,p_gateway_secret_hash text,p_request_id text,p_operation text,p_mode text,
  p_job_id text,p_item_id text,p_details jsonb
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE printer_row record; job_row record; session_row record; item_row record;
  now_at timestamp without time zone:=transaction_timestamp(); remaining integer;
BEGIN
  IF session_user<>{{APP_ROLE}} OR p_operation NOT IN ('CLAIM','ACK','CONFIRM','FAIL')
     OR p_mode NOT IN ('NETWORK_DIRECT','NETWORK_IPP')
     OR p_request_id !~* '^[0-9a-f-]{36}$' OR p_gateway_secret_hash !~ '^[0-9a-f]{64}$'
     OR (p_operation<>'CLAIM' AND (p_job_id !~* '^[0-9a-f-]{36}$' OR p_item_id !~* '^[0-9a-f-]{36}$'))
     OR jsonb_typeof(coalesce(p_details,'{}'::jsonb))<>'object'
  THEN RAISE EXCEPTION 'CONNECTOR_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM set_config('app.printing_operation','printing-connector-gateway-'||lower(p_operation),true),
          set_config('app.printing_request_id',p_request_id,true),
          set_config('app.printing_gateway_id',p_gateway_id,true),
          set_config('app.printing_gateway_secret_hash',p_gateway_secret_hash,true),
          set_config('app.printing_job_id',coalesce(p_job_id,''),true),
          set_config('app.printing_item_id',coalesce(p_item_id,''),true);
  SELECT p.id,p.name,p.vendor,p.model,p."connectionType",p."commandLanguage",p."ipAddress",p.host,p.port,
    p."resourcePath",p."tlsEnabled",p."printerUri",p."deliveryMode",p."gatewayId",p."gatewayLastSeenAt",
    p."gatewayStatus",p."gatewayLastError",p."nativePrinterId",p."agentId",p."deviceFingerprint",
    p."printerRegistrationId",p."orgId",p."licenseeId",p."assignedUserId",p."createdByUserId",
    p."isActive",p."isDefault",p."lastSeenAt",p."lastValidatedAt",p."lastValidationStatus",
    p."lastValidationMessage",p."capabilitySummary",p."calibrationProfile",p.metadata,p."createdAt",p."updatedAt"
    INTO STRICT printer_row FROM public."Printer" p
    WHERE p."gatewayId"=p_gateway_id AND p."gatewaySecretHash"=p_gateway_secret_hash
      AND p."deliveryMode"='SITE_GATEWAY'
      AND p."connectionType"=p_mode::public."PrinterConnectionType" AND p."isActive"
    FOR UPDATE;
  PERFORM set_config('app.printing_printer_id',printer_row.id,true);
  UPDATE public."Printer" SET "gatewayLastSeenAt"=now_at,"gatewayStatus"='ONLINE',
    "gatewayLastError"=NULL,"updatedAt"=now_at WHERE id=printer_row.id;
  IF p_operation='CLAIM' THEN
    SELECT j.id,j."jobNumber",j."batchId",j."manufacturerId",j."printerId",j.status,j."printMode",
      j."pipelineState",j."payloadType",j."payloadHash",j.quantity,j."itemCount",j."rangeStart",
      j."rangeEnd",j."sentAt",j."completedAt",j."failureReason",j."reprintOfJobId",
      j."approvedByUserId",j."reprintReason",j."confirmedAt",j."createdAt",j."updatedAt"
      INTO job_row FROM public."PrintJob" j
      WHERE j."printerId"=printer_row.id
        AND j."printMode"=p_mode::public."PrintDispatchMode"
        AND j.status IN ('PENDING','SENT')
      ORDER BY j."createdAt",j.id FOR UPDATE SKIP LOCKED LIMIT 1;
    IF NOT FOUND THEN RETURN jsonb_build_object('available',false); END IF;
  ELSE
    SELECT j.id,j."jobNumber",j."batchId",j."manufacturerId",j."printerId",j.status,j."printMode",
      j."pipelineState",j."payloadType",j."payloadHash",j.quantity,j."itemCount",j."rangeStart",
      j."rangeEnd",j."sentAt",j."completedAt",j."failureReason",j."reprintOfJobId",
      j."approvedByUserId",j."reprintReason",j."confirmedAt",j."createdAt",j."updatedAt"
      INTO STRICT job_row FROM public."PrintJob" j
      WHERE j.id=p_job_id AND j."printerId"=printer_row.id
        AND j."printMode"=p_mode::public."PrintDispatchMode" FOR UPDATE;
  END IF;
  PERFORM set_config('app.printing_job_id',job_row.id,true),
          set_config('app.printing_batch_id',job_row."batchId",true);
  SELECT ps.id,ps."printJobId",ps."batchId",ps."manufacturerId",ps."printerRegistrationId",
    ps."printerId",ps.status,ps."totalItems",ps."issuedItems",ps."confirmedItems",ps."frozenItems",
    ps."failedReason",ps."startedAt",ps."completedAt",ps."createdAt",ps."updatedAt"
    INTO STRICT session_row FROM public."PrintSession" ps WHERE ps."printJobId"=job_row.id FOR UPDATE;
  PERFORM set_config('app.printing_session_row_id',session_row.id,true);
  IF p_operation='CLAIM' THEN
    SELECT pi.id,pi."qrCodeId",pi.state INTO item_row FROM public."PrintItem" pi
      WHERE pi."printSessionId"=session_row.id AND pi.state='RESERVED'
      ORDER BY pi."issueSequence" NULLS LAST,pi.id FOR UPDATE SKIP LOCKED LIMIT 1;
    IF NOT FOUND THEN RETURN jsonb_build_object('available',false,'printJobId',job_row.id); END IF;
    PERFORM set_config('app.printing_item_id',item_row.id,true);
    UPDATE public."PrintItem" SET state='ISSUED',"pipelineState"='SENT_TO_PRINTER',
      "attemptCount"="attemptCount"+1,"issuedAt"=coalesce("issuedAt",now_at),"updatedAt"=now_at WHERE id=item_row.id;
    UPDATE public."PrintSession" SET "issuedItems"="issuedItems"+1,"updatedAt"=now_at WHERE id=session_row.id;
    UPDATE public."PrintJob" SET status='SENT',"pipelineState"='SENT_TO_PRINTER',
      "sentAt"=coalesce("sentAt",now_at),"updatedAt"=now_at WHERE id=job_row.id;
    UPDATE public."Batch" SET "lifecycleState"='PRINT_ACKNOWLEDGED',"updatedAt"=now_at
      WHERE id=job_row."batchId" AND "lifecycleState"='CODES_GENERATED';
    RETURN jsonb_build_object('available',true,'job',to_jsonb(job_row),
      'session',to_jsonb(session_row),'printer',to_jsonb(printer_row),
      'item',(SELECT jsonb_build_object(
        'id',pi.id,'qrCodeId',q.id,'code',q.code,'displayCode',q."displayCode",
        'batchId',q."batchId",'licenseeId',q."licenseeId",'tokenNonce',q."tokenNonce",
        'tokenIssuedAt',q."tokenIssuedAt",'tokenExpiresAt',q."tokenExpiresAt",
        'tokenHash',q."tokenHash",'replayEpoch',q."replayEpoch"
      ) FROM public."PrintItem" pi JOIN public."QRCode" q ON q.id=pi."qrCodeId" WHERE pi.id=item_row.id));
  END IF;
  SELECT pi.id,pi."qrCodeId",pi.state INTO STRICT item_row FROM public."PrintItem" pi
    WHERE pi.id=p_item_id AND pi."printSessionId"=session_row.id FOR UPDATE;
  PERFORM set_config('app.printing_item_id',item_row.id,true);
  IF p_operation='ACK' THEN
    IF item_row.state='AGENT_ACKED' THEN RETURN jsonb_build_object('idempotent',true,'printItemId',item_row.id); END IF;
    IF item_row.state<>'ISSUED' THEN RAISE EXCEPTION 'INVALID_STATE_TRANSITION'; END IF;
    UPDATE public."PrintItem" SET state='AGENT_ACKED',"pipelineState"='PRINTER_ACKNOWLEDGED',
      "agentAckedAt"=now_at,"confirmationDeadlineAt"=now_at+interval '10 minutes',
      "deviceJobRef"=nullif(p_details->>'deviceJobRef',''),"dispatchMetadata"=p_details,"updatedAt"=now_at
      WHERE id=item_row.id;
  ELSIF p_operation='CONFIRM' THEN
    IF item_row.state IN ('PRINT_CONFIRMED','CLOSED') THEN RETURN jsonb_build_object('idempotent',true,'printItemId',item_row.id); END IF;
    IF item_row.state<>'AGENT_ACKED' THEN RAISE EXCEPTION 'PRINT_ACK_REQUIRED'; END IF;
    UPDATE public."PrintItem" SET state='PRINT_CONFIRMED',"pipelineState"='PRINT_CONFIRMED',
      "printConfirmedAt"=now_at,"confirmationEvidence"=p_details,"updatedAt"=now_at WHERE id=item_row.id;
    UPDATE public."QRCode" SET status='PRINTED',"printedAt"=coalesce("printedAt",now_at),
      "printedByUserId"=job_row."manufacturerId","updatedAt"=now_at WHERE id=item_row."qrCodeId";
    SELECT count(*) INTO remaining FROM public."PrintItem" pi
      WHERE pi."printSessionId"=session_row.id AND pi.state NOT IN ('PRINT_CONFIRMED','CLOSED','FAILED','CANCELLED');
    IF remaining=0 THEN
      UPDATE public."PrintSession" SET status='COMPLETED',"confirmedItems"="totalItems",
        "completedAt"=now_at,"updatedAt"=now_at WHERE id=session_row.id;
      UPDATE public."PrintJob" SET status='CONFIRMED',"pipelineState"='PRINT_CONFIRMED',
        "confirmedAt"=now_at,"completedAt"=now_at,"updatedAt"=now_at WHERE id=job_row.id;
      UPDATE public."Batch" SET "lifecycleState"='PRINT_CONFIRMED',"printedAt"=now_at,"updatedAt"=now_at
        WHERE id=job_row."batchId" AND "lifecycleState"='PRINT_ACKNOWLEDGED';
    END IF;
  ELSE
    UPDATE public."PrintItem" SET state='FAILED',"pipelineState"='FAILED',"failedAt"=now_at,
      "failureReason"=left(coalesce(p_details->>'reason','gateway_failure'),500),"updatedAt"=now_at WHERE id=item_row.id;
    UPDATE public."PrintSession" SET status='FAILED',"failedReason"=left(coalesce(p_details->>'reason','gateway_failure'),500),
      "updatedAt"=now_at WHERE id=session_row.id;
    UPDATE public."PrintJob" SET status='FAILED',"pipelineState"='FAILED',
      "failureReason"=left(coalesce(p_details->>'reason','gateway_failure'),500),"updatedAt"=now_at WHERE id=job_row.id;
    UPDATE public."Printer" SET "gatewayStatus"='ERROR',"gatewayLastError"=left(p_details->>'reason',500),
      "updatedAt"=now_at WHERE id=printer_row.id;
  END IF;
  INSERT INTO public."PrintItemEvent"(id,"printItemId","eventType","previousState","nextState",details,"actorUserId","createdAt")
  VALUES(gen_random_uuid()::text,item_row.id,
    CASE p_operation WHEN 'ACK' THEN 'AGENT_ACKED' WHEN 'CONFIRM' THEN 'PRINT_CONFIRMED' ELSE 'FAILED' END,
    item_row.state,CASE p_operation WHEN 'ACK' THEN 'AGENT_ACKED' WHEN 'CONFIRM' THEN 'PRINT_CONFIRMED' ELSE 'FAILED' END,
    p_details,job_row."manufacturerId",now_at);
  INSERT INTO public."PrintAuditEvent"(id,"batchId","printJobId","qrCodeId","eventType","actorId",metadata,"createdAt")
  VALUES(gen_random_uuid()::text,job_row."batchId",job_row.id,item_row."qrCodeId",
    'GATEWAY_'||p_operation,job_row."manufacturerId",
    jsonb_build_object('gatewayId',p_gateway_id,'printerId',printer_row.id),now_at);
  RETURN jsonb_build_object('printJobId',job_row.id,'printItemId',item_row.id,
    'operation',p_operation,'remainingToPrint',remaining,'idempotent',false);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.printing_record_sample(
  p_capability text,p_purpose text,p_request_id text,p_job_id text,p_qr_code text,p_evidence jsonb
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; job_row record; qr_row record; policy jsonb; required_count integer; actual_count integer;
  event_id text:=gen_random_uuid()::text; now_at timestamp without time zone:=transaction_timestamp();
BEGIN
  SELECT * INTO STRICT actor FROM app_rls.printing_bind_actor(p_capability,p_purpose,p_request_id,NULL);
  PERFORM set_config('app.printing_job_id',p_job_id,true);
  SELECT j.id,j."batchId",j.status,j.quantity
    INTO STRICT job_row FROM public."PrintJob" j WHERE j.id=p_job_id FOR UPDATE;
  SELECT * INTO STRICT actor FROM app_rls.printing_bind_actor(p_capability,p_purpose,p_request_id,job_row."batchId");
  PERFORM set_config('app.printing_job_id',p_job_id,true);
  IF p_purpose<>'printing-sample-scan' OR job_row.status<>'CONFIRMED' THEN RAISE EXCEPTION 'PHYSICAL_CONFIRMATION_REQUIRED'; END IF;
  BEGIN
    SELECT q.id INTO STRICT qr_row FROM public."QRCode" q
     WHERE q.code=btrim(p_qr_code) AND q."batchId"=job_row."batchId" AND q."printJobId"=job_row.id
       AND q.status='PRINTED';
  EXCEPTION WHEN NO_DATA_FOUND THEN
    RAISE EXCEPTION 'QR_NOT_IN_PRINT_JOB';
  END;
  IF EXISTS (SELECT 1 FROM public."PrintAuditEvent" e WHERE e."printJobId"=job_row.id
    AND e."qrCodeId"=qr_row.id AND e."eventType"='SAMPLE_SCAN_PASSED')
  THEN RETURN jsonb_build_object('idempotent',true,'qrCodeId',qr_row.id); END IF;
  SELECT b."sampleScanPolicy" INTO policy FROM public."Batch" b WHERE b.id=job_row."batchId";
  required_count:=CASE coalesce(policy->>'type',policy->>'mode','ONE_PER_PRINT_JOB')
    WHEN 'ONE_PER_PRINT_JOB' THEN 1
    WHEN 'ONE_PER_ROLL' THEN 1
    WHEN 'ONE_PER_N_LABELS' THEN GREATEST(1,ceil(job_row.quantity::numeric/GREATEST(coalesce((policy->>'n')::integer,job_row.quantity),1))::integer)
    WHEN 'PERCENTAGE' THEN GREATEST(
      GREATEST(coalesce((policy->>'min')::integer,1),1),
      ceil(job_row.quantity*GREATEST(coalesce((policy->>'percentage')::numeric,1),0.01)/100)::integer
    )
    ELSE 1 END;
  PERFORM set_config('app.printing_job_id',job_row.id,true),set_config('app.printing_item_id',qr_row.id,true);
  INSERT INTO public."PrintAuditEvent"(id,"batchId","printJobId","qrCodeId","eventType","actorId",metadata,"createdAt")
  VALUES(event_id,job_row."batchId",job_row.id,qr_row.id,'SAMPLE_SCAN_PASSED',actor."userId",
    coalesce(p_evidence,'{}'::jsonb)||jsonb_build_object('requestId',p_request_id),now_at);
  SELECT count(DISTINCT e."qrCodeId") INTO actual_count FROM public."PrintAuditEvent" e
    WHERE e."printJobId"=job_row.id AND e."eventType"='SAMPLE_SCAN_PASSED';
  IF actual_count>=required_count THEN
    UPDATE public."Batch" SET "lifecycleState"='SAMPLE_VERIFIED',"updatedAt"=now_at
      WHERE id=job_row."batchId" AND "lifecycleState"='PRINT_CONFIRMED';
  END IF;
  PERFORM app_rls.printing_write_audit(actor."userId",actor.role,actor."organizationId",actor."batchLicenseeId",
    'PRINT_SAMPLE_RECORDED','PrintJob',job_row.id,
    jsonb_build_object('qrCodeId',qr_row.id,'required',required_count,'actual',actual_count));
  RETURN jsonb_build_object('idempotent',false,'qrCodeId',qr_row.id,'required',required_count,
    'actual',actual_count,'satisfied',actual_count>=required_count);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.printing_release_batch(
  p_capability text,p_purpose text,p_request_id text,p_batch_id text,p_decision text,p_reason text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; batch_row record; maker_id text; now_at timestamp without time zone:=transaction_timestamp();
  released_count integer; approval_id text; approval_requested_by text; approval_status text;
  approval_expires_at timestamp without time zone;
  effective_decision text:=p_decision;
BEGIN
  IF p_purpose<>'printing-release' OR p_decision NOT IN ('REQUEST','APPROVE','REJECT')
     OR length(coalesce(p_reason,''))>500 THEN RAISE EXCEPTION 'PRINTING_INVALID_INPUT'; END IF;
  SELECT * INTO STRICT actor FROM app_rls.printing_bind_actor(p_capability,p_purpose,p_request_id,p_batch_id);
  IF actor.role NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN','LICENSEE_ADMIN','MANUFACTURER_ADMIN') THEN
    RAISE EXCEPTION 'PRINTING_BOUNDARY_DENIED' USING ERRCODE='42501';
  END IF;
  SELECT b.id,b."lifecycleState",b."releasedAt",b."totalCodes"
    INTO STRICT batch_row FROM public."Batch" b WHERE b.id=p_batch_id FOR UPDATE;
  SELECT j."manufacturerId" INTO maker_id FROM public."PrintJob" j WHERE j."batchId"=p_batch_id
    AND j.status='CONFIRMED' ORDER BY j."confirmedAt" DESC NULLS LAST,j."createdAt" DESC LIMIT 1;
  IF maker_id IS NULL THEN RAISE EXCEPTION 'PHYSICAL_CONFIRMATION_REQUIRED'; END IF;
  IF p_decision='REQUEST' THEN
    SELECT a.id,a."requestedByUserId",a.status,a."expiresAt"
      INTO approval_id,approval_requested_by,approval_status,approval_expires_at
      FROM public."SensitiveActionApproval" a
     WHERE a."actionKey"='BATCH_RELEASE' AND a."entityType"='Batch' AND a."entityId"=p_batch_id
       AND a.status='PENDING' AND a."expiresAt">now_at
     ORDER BY a."createdAt" DESC,a.id DESC LIMIT 1 FOR UPDATE;
    IF NOT FOUND THEN
      IF actor.role<>'MANUFACTURER_ADMIN' OR maker_id<>actor."userId" THEN
        RAISE EXCEPTION 'PRINTING_RELEASE_REQUEST_DENIED' USING ERRCODE='42501';
      END IF;
      INSERT INTO public."SensitiveActionApproval"(
        id,"actionKey","requestedByUserId","licenseeId","entityType","entityId",payload,summary,status,
        "expiresAt","createdAt","updatedAt"
      ) VALUES (
        gen_random_uuid()::text,'BATCH_RELEASE',actor."userId",actor."batchLicenseeId",'Batch',p_batch_id,
        jsonb_build_object('batchId',p_batch_id,'printJobId',(
          SELECT j.id FROM public."PrintJob" j WHERE j."batchId"=p_batch_id AND j.status='CONFIRMED'
          ORDER BY j."confirmedAt" DESC NULLS LAST,j."createdAt" DESC LIMIT 1
        ),'requestedByUserId',actor."userId",'releaseBoundary','supply_chain'),
        jsonb_build_object('reason',nullif(btrim(p_reason),''),'totalCodes',batch_row."totalCodes"),
        'PENDING',now_at+interval '30 minutes',now_at,now_at
      ) RETURNING id,"requestedByUserId",status,"expiresAt"
        INTO approval_id,approval_requested_by,approval_status,approval_expires_at;
      PERFORM app_rls.printing_write_audit(actor."userId",actor.role,actor."organizationId",actor."batchLicenseeId",
        'BATCH_RELEASE_REQUESTED','Batch',p_batch_id,jsonb_build_object('approvalId',approval_id));
      RETURN jsonb_build_object('batchId',p_batch_id,'approvalRequired',true,'approvalId',approval_id,
        'status',approval_status,'expiresAt',approval_expires_at,'idempotent',false);
    END IF;
    IF approval_requested_by=actor."userId" THEN
      RETURN jsonb_build_object('batchId',p_batch_id,'approvalRequired',true,'approvalId',approval_id,
        'status',approval_status,'expiresAt',approval_expires_at,'idempotent',true);
    END IF;
    IF actor.role NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN','LICENSEE_ADMIN') THEN
      RAISE EXCEPTION 'CHECKER_REQUIRED' USING ERRCODE='42501';
    END IF;
    UPDATE public."SensitiveActionApproval" SET status='EXECUTED',"reviewedByUserId"=actor."userId",
      "reviewedAt"=now_at,"executedByUserId"=actor."userId","executedAt"=now_at,"updatedAt"=now_at
      WHERE id=approval_id;
    effective_decision:='APPROVE';
  END IF;
  IF maker_id=actor."userId" THEN RAISE EXCEPTION 'MAKER_CANNOT_APPROVE' USING ERRCODE='42501'; END IF;
  IF effective_decision='REJECT' THEN
    UPDATE public."Batch" SET "lifecycleState"='FAILED',"updatedAt"=now_at WHERE id=p_batch_id
      AND "lifecycleState" IN ('PRINT_CONFIRMED','SAMPLE_VERIFIED');
    IF NOT FOUND THEN RAISE EXCEPTION 'INVALID_STATE_TRANSITION'; END IF;
  ELSE
    IF batch_row."releasedAt" IS NOT NULL OR batch_row."lifecycleState"='RELEASED' THEN RAISE EXCEPTION 'BATCH_ALREADY_RELEASED'; END IF;
    IF batch_row."lifecycleState"<>'SAMPLE_VERIFIED' THEN RAISE EXCEPTION 'SAMPLE_SCAN_REQUIRED'; END IF;
    IF EXISTS (SELECT 1 FROM public."PrintItem" pi JOIN public."PrintSession" ps ON ps.id=pi."printSessionId"
      WHERE ps."batchId"=p_batch_id AND pi.state NOT IN ('PRINT_CONFIRMED','CLOSED','CANCELLED','FAILED'))
    THEN RAISE EXCEPTION 'PHYSICAL_CONFIRMATION_REQUIRED'; END IF;
    UPDATE public."QRCode" SET "customerVerifiableAt"=now_at,"updatedAt"=now_at
      WHERE "batchId"=p_batch_id AND status='PRINTED';
    GET DIAGNOSTICS released_count=ROW_COUNT;
    IF released_count=0 THEN RAISE EXCEPTION 'QR_CODES_REQUIRED'; END IF;
    UPDATE public."Batch" SET "lifecycleState"='RELEASED',"releasedAt"=now_at,
      "releasedByUserId"=actor."userId","updatedAt"=now_at WHERE id=p_batch_id;
  END IF;
  PERFORM app_rls.printing_write_audit(actor."userId",actor.role,actor."organizationId",actor."batchLicenseeId",
    'BATCH_RELEASE_'||effective_decision,'Batch',p_batch_id,
    jsonb_build_object('makerId',maker_id,'approvalId',approval_id,
      'reason',nullif(btrim(p_reason),''),'releasedCodes',coalesce(released_count,0)));
  RETURN jsonb_build_object('batchId',p_batch_id,'decision',effective_decision,'lifecycleState',
    CASE WHEN effective_decision='APPROVE' THEN 'RELEASED' ELSE 'FAILED' END,
    'releasedCodes',coalesce(released_count,0),'approvalRequired',approval_id IS NOT NULL,
    'approvalId',approval_id);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.printing_reissue_request(
  p_capability text,p_purpose text,p_request_id text,p_operation text,p_reissue_id text,
  p_original_job_id text,p_quantity integer,p_range_start text,p_range_end text,p_reason text,p_decision_note text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; job_row record; request_row record; request_id text; replacement_job_id text;
  target_batch_id text;
  replacement_session_id text; original_session_id text; moved_count integer;
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
    SELECT j.id,j."batchId",j."manufacturerId",j.status
      INTO STRICT job_row FROM public."PrintJob" j WHERE j.id=p_original_job_id FOR UPDATE;
    SELECT * INTO STRICT actor FROM app_rls.printing_bind_actor(p_capability,p_purpose,p_request_id,job_row."batchId");
    PERFORM set_config('app.printing_job_id',p_original_job_id,true);
    IF actor.role<>'MANUFACTURER_ADMIN' OR job_row."manufacturerId"<>actor."userId"
       OR job_row.status NOT IN ('FAILED','PARTIALLY_COMPLETED','CONFIRMED')
    THEN RAISE EXCEPTION 'PRINTING_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;
    SELECT r.id INTO request_id FROM public."PrintReissueRequest" r
      WHERE r."originalPrintJobId"=job_row.id AND r.status IN ('PENDING','APPROVED') FOR UPDATE;
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
    SELECT r.id,r."originalPrintJobId",r."replacementPrintJobId",r."requestedByUserId",
      r."approvedByUserId",r."licenseeId",r."manufacturerId",r."batchId",r."requestedByRole",
      r."targetApproverRole",r.quantity,r."affectedRangeStart",r."affectedRangeEnd",r."decisionNote",
      r."approvalReferenceId",r.status,r.reason,r."rejectionReason",r."approvedAt",r."rejectedAt",
      r."executedAt",r."createdAt",r."updatedAt" INTO STRICT request_row
      FROM public."PrintReissueRequest" r
      WHERE r.id=p_reissue_id FOR UPDATE;
    PERFORM set_config('app.printing_job_id',request_row."originalPrintJobId",true);
    SELECT j."batchId" INTO STRICT target_batch_id FROM public."PrintJob" j
      WHERE j.id=request_row."originalPrintJobId";
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
      SELECT j.id,j."batchId",j."manufacturerId",j."printerId",j.status,j."printMode",
        j."payloadType",j.quantity,j."itemCount",
        ps.id AS original_session_id,ps."printerRegistrationId" AS original_registration_id
        INTO STRICT job_row
        FROM public."PrintJob" j JOIN public."PrintSession" ps ON ps."printJobId"=j.id
        WHERE j.id=request_row."originalPrintJobId" FOR UPDATE OF j,ps;
      IF job_row.status NOT IN ('FAILED','PARTIALLY_COMPLETED','CONFIRMED','STOPPED','CANCELLED')
      THEN RAISE EXCEPTION 'INVALID_STATE_TRANSITION'; END IF;
      original_session_id:=job_row.original_session_id;
      IF job_row."printMode"='LOCAL_AGENT'::public."PrintDispatchMode" THEN
        IF job_row.original_registration_id IS NULL THEN RAISE EXCEPTION 'PRINTER_ATTESTATION_STALE'; END IF;
        PERFORM set_config('app.printing_registration_id',job_row.original_registration_id,true);
        IF NOT EXISTS (
          SELECT 1 FROM public."PrinterAttestation" pa
          JOIN public."Printer" p ON p.id=job_row."printerId"
          WHERE pa."printerRegistrationId"=job_row.original_registration_id
            AND pa."signatureValid" AND pa."trustValid" AND pa."expiresAt">now_at
            AND coalesce((pa.metadata->>'connected')::boolean,false)
            AND coalesce(pa.metadata->>'selectedPrinterId',pa.metadata->>'printerId','')
              IN (p.id,coalesce(p."nativePrinterId",''))
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
    jsonb_build_object('originalPrintJobId',coalesce(request_row."originalPrintJobId",p_original_job_id),'quantity',p_quantity));
  RETURN to_jsonb(request_row)||jsonb_build_object('idempotent',false);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.printing_worker_reconcile(
  p_operation text,p_request_id text,p_limit integer
) RETURNS integer
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE affected integer:=0; now_at timestamp without time zone:=transaction_timestamp();
BEGIN
  IF session_user<>{{WORKER_ROLE}} OR p_operation NOT IN ('EXPIRE_CONFIRMATIONS','RECONCILE_BATCHES')
     OR p_request_id !~* '^[0-9a-f-]{36}$' OR p_limit NOT BETWEEN 1 AND 1000
  THEN RAISE EXCEPTION 'PRINTING_WORKER_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM set_config('app.printing_operation','printing-worker-'||lower(p_operation),true),
          set_config('app.printing_request_id',p_request_id,true);
  IF p_operation='EXPIRE_CONFIRMATIONS' THEN
    WITH target AS (
      SELECT pi.id FROM public."PrintItem" pi
       WHERE pi.state='AGENT_ACKED' AND pi."confirmationDeadlineAt"<now_at
       ORDER BY pi."confirmationDeadlineAt",pi.id FOR UPDATE SKIP LOCKED LIMIT p_limit
    )
    UPDATE public."PrintItem" pi SET state='FAILED',"pipelineState"='FAILED',"failedAt"=now_at,
      "failureReason"='confirmation_deadline_expired',"updatedAt"=now_at
      FROM target t WHERE pi.id=t.id;
    GET DIAGNOSTICS affected=ROW_COUNT;
  ELSE
    WITH target AS (
      SELECT b.id FROM public."Batch" b
       WHERE b."lifecycleState" IN ('CODES_GENERATED','PRINT_ACKNOWLEDGED','PRINT_CONFIRMED')
       ORDER BY b."updatedAt",b.id FOR UPDATE SKIP LOCKED LIMIT p_limit
    ), state AS (
      SELECT t.id,
        bool_or(j.status='CONFIRMED') AS confirmed_job,
        bool_or(j.status IN ('PENDING','SENT','PAUSED')) AS active_job
      FROM target t LEFT JOIN public."PrintJob" j ON j."batchId"=t.id GROUP BY t.id
    )
    UPDATE public."Batch" b SET "lifecycleState"=CASE
      WHEN s.confirmed_job THEN 'PRINT_CONFIRMED'::public."BatchLifecycleState"
      WHEN s.active_job THEN 'PRINT_ACKNOWLEDGED'::public."BatchLifecycleState"
      ELSE b."lifecycleState" END,"updatedAt"=now_at
      FROM state s WHERE b.id=s.id AND b."lifecycleState" IS DISTINCT FROM CASE
      WHEN s.confirmed_job THEN 'PRINT_CONFIRMED'::public."BatchLifecycleState"
      WHEN s.active_job THEN 'PRINT_ACKNOWLEDGED'::public."BatchLifecycleState"
      ELSE b."lifecycleState" END;
    GET DIAGNOSTICS affected=ROW_COUNT;
  END IF;
  RETURN affected;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.printing_worker_network_job(
  p_operation text,p_request_id text,p_job_id text,p_details jsonb
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE job_row record; session_row record; now_at timestamp without time zone:=transaction_timestamp();
  mode_value public."PrintDispatchMode"; item_ids text[]; remaining integer; page_limit integer;
BEGIN
  IF session_user<>{{WORKER_ROLE}}
     OR p_operation NOT IN ('CLAIM_DIRECT','CLAIM_IPP','CONFIRM','FAIL')
     OR p_request_id !~* '^[0-9a-f-]{36}$'
     OR (p_job_id IS NOT NULL AND p_job_id !~* '^[0-9a-f-]{36}$')
     OR jsonb_typeof(coalesce(p_details,'{}'::jsonb))<>'object'
  THEN RAISE EXCEPTION 'PRINTING_WORKER_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM set_config('app.printing_operation','printing-worker-network',true),
          set_config('app.printing_request_id',p_request_id,true);
  IF p_operation IN ('CLAIM_DIRECT','CLAIM_IPP') THEN
    mode_value:=CASE p_operation WHEN 'CLAIM_DIRECT' THEN 'NETWORK_DIRECT' ELSE 'NETWORK_IPP' END;
    page_limit:=LEAST(GREATEST(coalesce(NULLIF(p_details->>'limit','')::integer,25),1),250);
    SELECT j.id,j."jobNumber",j."batchId",j."manufacturerId",j."printerId",j.status,j."printMode",
      j."pipelineState",j."payloadType",j."payloadHash",j.quantity,j."itemCount",j."rangeStart",
      j."rangeEnd",j."sentAt",j."completedAt",j."failureReason",j."reprintOfJobId",
      j."approvedByUserId",j."reprintReason",j."confirmedAt",j."createdAt",j."updatedAt"
      INTO job_row FROM public."PrintJob" j
      WHERE (p_job_id IS NULL OR j.id=p_job_id) AND j."printMode"=mode_value
        AND j.status IN ('PENDING','SENT') AND EXISTS (
          SELECT 1 FROM public."PrintSession" ps JOIN public."PrintItem" pi ON pi."printSessionId"=ps.id
          WHERE ps."printJobId"=j.id AND pi.state='RESERVED'
        )
      ORDER BY j."createdAt",j.id FOR UPDATE SKIP LOCKED LIMIT 1;
    IF NOT FOUND THEN RETURN jsonb_build_object('available',false); END IF;
    PERFORM set_config('app.printing_job_id',job_row.id,true),
            set_config('app.printing_batch_id',job_row."batchId",true),
            set_config('app.printing_printer_id',job_row."printerId",true);
    SELECT ps.id,ps."printJobId",ps."batchId",ps."manufacturerId",ps."printerRegistrationId",
      ps."printerId",ps.status,ps."totalItems",ps."issuedItems",ps."confirmedItems",ps."frozenItems",
      ps."failedReason",ps."startedAt",ps."completedAt",ps."createdAt",ps."updatedAt"
      INTO STRICT session_row FROM public."PrintSession" ps
      WHERE ps."printJobId"=job_row.id FOR UPDATE;
    PERFORM set_config('app.printing_session_row_id',session_row.id,true);
    WITH selected AS (
      SELECT pi.id FROM public."PrintItem" pi
      WHERE pi."printSessionId"=session_row.id AND pi.state='RESERVED'
      ORDER BY pi."issueSequence" NULLS LAST,pi.id FOR UPDATE SKIP LOCKED LIMIT page_limit
    ), issued AS (
      UPDATE public."PrintItem" pi SET state='AGENT_ACKED',"pipelineState"='SENT_TO_PRINTER',
        "attemptCount"=pi."attemptCount"+1,"issuedAt"=coalesce(pi."issuedAt",now_at),
        "dispatchedAt"=now_at,"agentAckedAt"=now_at,
        "confirmationDeadlineAt"=now_at+interval '10 minutes',"updatedAt"=now_at
      FROM selected s WHERE pi.id=s.id RETURNING pi.id
    )
    SELECT array_agg(id ORDER BY id) INTO item_ids FROM issued;
    UPDATE public."PrintJob" SET status='SENT',"pipelineState"='SENT_TO_PRINTER',
      "sentAt"=coalesce("sentAt",now_at),"updatedAt"=now_at WHERE id=job_row.id;
    UPDATE public."Batch" SET "lifecycleState"='PRINT_ACKNOWLEDGED',"updatedAt"=now_at
      WHERE id=job_row."batchId" AND "lifecycleState"='CODES_GENERATED';
    RETURN jsonb_build_object(
      'available',true,'job',to_jsonb(job_row),
      'session',to_jsonb(session_row),
      'printer',(SELECT to_jsonb(p) FROM (
        SELECT printer.id,printer.name,printer.vendor,printer.model,printer."connectionType",
          printer."commandLanguage",printer."ipAddress",printer.host,printer.port,printer."resourcePath",
          printer."tlsEnabled",printer."printerUri",printer."deliveryMode",printer."gatewayId",
          printer."gatewayLastSeenAt",printer."gatewayStatus",printer."gatewayLastError",
          printer."nativePrinterId",printer."agentId",printer."deviceFingerprint",
          printer."printerRegistrationId",printer."orgId",printer."licenseeId",
          printer."assignedUserId",printer."createdByUserId",printer."isActive",printer."isDefault",
          printer."lastSeenAt",printer."lastValidatedAt",printer."lastValidationStatus",
          printer."lastValidationMessage",printer."capabilitySummary",printer."calibrationProfile",
          printer.metadata,printer."createdAt",printer."updatedAt"
        FROM public."Printer" printer WHERE printer.id=job_row."printerId"
      ) p),
      'batch',(SELECT jsonb_build_object('id',b.id,'name',b.name,'licenseeId',b."licenseeId",
        'manufacturerId',b."manufacturerId") FROM public."Batch" b WHERE b.id=job_row."batchId"),
      'items',coalesce((SELECT jsonb_agg(jsonb_build_object(
        'id',pi.id,'qrCodeId',q.id,'code',q.code,'displayCode',q."displayCode",
        'batchId',q."batchId",'licenseeId',q."licenseeId",'tokenNonce',q."tokenNonce",
        'tokenIssuedAt',q."tokenIssuedAt",'tokenExpiresAt',q."tokenExpiresAt",
        'tokenHash',q."tokenHash",'replayEpoch',q."replayEpoch"
      ) ORDER BY pi."issueSequence" NULLS LAST,pi.id)
      FROM public."PrintItem" pi JOIN public."QRCode" q ON q.id=pi."qrCodeId"
      WHERE pi.id=ANY(item_ids)),'[]'::jsonb)
    );
  END IF;

  SELECT j.id,j."batchId",j."manufacturerId",j."printerId",j."printMode"
    INTO STRICT job_row FROM public."PrintJob" j WHERE j.id=p_job_id FOR UPDATE;
  PERFORM set_config('app.printing_job_id',job_row.id,true),
          set_config('app.printing_batch_id',job_row."batchId",true),
          set_config('app.printing_printer_id',job_row."printerId",true);
  SELECT ps.id INTO STRICT session_row FROM public."PrintSession" ps
    WHERE ps."printJobId"=job_row.id FOR UPDATE;
  PERFORM set_config('app.printing_session_row_id',session_row.id,true);
  SELECT coalesce(array_agg(value #>> '{}'),'{}'::text[]) INTO item_ids
    FROM jsonb_array_elements(coalesce(p_details->'itemIds','[]'::jsonb));
  IF cardinality(item_ids)=0 THEN RAISE EXCEPTION 'PRINTING_INVALID_INPUT'; END IF;
  IF p_operation='CONFIRM' THEN
    UPDATE public."PrintItem" SET state='PRINT_CONFIRMED',"pipelineState"='PRINT_CONFIRMED',
      "printConfirmedAt"=now_at,"confirmationEvidence"=jsonb_build_object(
        'runtimeIdentity','identity-background-worker','transport',job_row."printMode",
        'transportReference',p_details->>'transportReference'
      ),"updatedAt"=now_at
      WHERE id=ANY(item_ids) AND "printSessionId"=session_row.id AND state='AGENT_ACKED';
    IF NOT FOUND AND EXISTS (
      SELECT 1 FROM public."PrintItem" pi WHERE pi.id=ANY(item_ids)
        AND pi."printSessionId"=session_row.id AND pi.state NOT IN ('PRINT_CONFIRMED','CLOSED')
    ) THEN RAISE EXCEPTION 'INVALID_STATE_TRANSITION'; END IF;
    UPDATE public."QRCode" q SET status='PRINTED',"printedAt"=coalesce(q."printedAt",now_at),
      "printedByUserId"=job_row."manufacturerId","updatedAt"=now_at
      WHERE q.id IN (SELECT pi."qrCodeId" FROM public."PrintItem" pi WHERE pi.id=ANY(item_ids));
    SELECT count(*) INTO remaining FROM public."PrintItem" pi
      WHERE pi."printSessionId"=session_row.id AND pi.state NOT IN ('PRINT_CONFIRMED','CLOSED','FAILED','CANCELLED');
    IF remaining=0 THEN
      UPDATE public."PrintSession" SET status='COMPLETED',"confirmedItems"="totalItems",
        "completedAt"=now_at,"updatedAt"=now_at WHERE id=session_row.id;
      UPDATE public."PrintJob" SET status='CONFIRMED',"pipelineState"='PRINT_CONFIRMED',
        "confirmedAt"=now_at,"completedAt"=now_at,"updatedAt"=now_at WHERE id=job_row.id;
      UPDATE public."Batch" SET "lifecycleState"='PRINT_CONFIRMED',"printedAt"=now_at,"updatedAt"=now_at
        WHERE id=job_row."batchId" AND "lifecycleState"='PRINT_ACKNOWLEDGED';
    END IF;
  ELSE
    UPDATE public."PrintItem" SET state='FAILED',"pipelineState"='FAILED',"failedAt"=now_at,
      "failureReason"=left(coalesce(p_details->>'reason','network_transport_failed'),500),"updatedAt"=now_at
      WHERE id=ANY(item_ids) AND "printSessionId"=session_row.id
        AND state NOT IN ('PRINT_CONFIRMED','CLOSED');
    UPDATE public."PrintSession" SET status='FAILED',
      "failedReason"=left(coalesce(p_details->>'reason','network_transport_failed'),500),"updatedAt"=now_at
      WHERE id=session_row.id;
    UPDATE public."PrintJob" SET status='FAILED',"pipelineState"='FAILED',
      "failureReason"=left(coalesce(p_details->>'reason','network_transport_failed'),500),"updatedAt"=now_at
      WHERE id=job_row.id;
  END IF;
  INSERT INTO public."PrintAuditEvent"(id,"batchId","printJobId","eventType",actorId,metadata,"createdAt")
  VALUES(gen_random_uuid()::text,job_row."batchId",job_row.id,'WORKER_NETWORK_'||p_operation,
    job_row."manufacturerId",jsonb_build_object('runtimeIdentity','identity-background-worker',
      'itemCount',cardinality(item_ids),'transportReference',p_details->>'transportReference'),now_at);
  RETURN jsonb_build_object('printJobId',job_row.id,'operation',p_operation,
    'itemCount',cardinality(item_ids),'remaining',remaining,'idempotent',false);
END
$fn$;
