-- Read-only manufacturer run summary. Lifecycle mutation guards remain in printingLifecycle.sql.
CREATE OR REPLACE FUNCTION app_rls.printing_run_projection(
  p_capability text,p_purpose text,p_request_id text,p_operation text,p_subject_id text,p_options jsonb
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public
AS $fn$
DECLARE
  result jsonb;
  actor_role text;
  actor_id text;
  target_job_id text;
  run_ids jsonb;
  batch_ids jsonb;
  scoped_rows jsonb;
  run_summaries jsonb;
BEGIN
  IF p_operation NOT IN ('JOB','JOB_LIST') OR p_purpose<>'printing-readiness' THEN
    RAISE EXCEPTION 'PRINTING_BOUNDARY_DENIED' USING ERRCODE='42501';
  END IF;
  IF p_operation='JOB' THEN
    result:=app_rls.printing_readiness(p_capability,p_purpose,p_request_id,p_operation,p_subject_id,p_options);
    actor_role:=current_setting('app.printing_role',true);
    actor_id:=current_setting('app.printing_user_id',true);
  ELSE
    SELECT binding.role,binding."userId" INTO STRICT actor_role,actor_id
      FROM app_rls.printing_bind_actor(p_capability,p_purpose,p_request_id,NULL) binding;
    IF actor_role<>'MANUFACTURER_ADMIN' THEN
      RETURN app_rls.printing_readiness(p_capability,p_purpose,p_request_id,p_operation,p_subject_id,p_options);
    END IF;
  END IF;
  target_job_id:=CASE WHEN p_operation='JOB' THEN p_subject_id END;
  IF actor_role='MANUFACTURER_ADMIN' THEN
    SELECT coalesce(jsonb_agg(scoped.id),'[]'::jsonb),
      coalesce(jsonb_agg(DISTINCT scoped."batchId"),'[]'::jsonb),
      coalesce(jsonb_agg(to_jsonb(scoped) ORDER BY scoped."createdAt" DESC,scoped.id DESC),'[]'::jsonb)
      INTO run_ids,batch_ids,scoped_rows FROM (
      SELECT j.id,j."jobNumber",j."batchId",j."manufacturerId",j."printerId",
        j.status,j."printMode",j."pipelineState",j.quantity,j."itemCount",
        j."rangeStart",j."rangeEnd",j."sentAt",j."completedAt",j."failureReason",
        j."reprintOfJobId",j."approvedByUserId",j."reprintReason",j."confirmedAt",
        j."createdAt",j."updatedAt"
      FROM public."PrintJob" j
      JOIN public."Batch" b ON b.id=j."batchId"
      JOIN public."Licensee" l ON l.id=b."licenseeId"
      JOIN public."Organization" o ON o.id=l."orgId"
      WHERE j."manufacturerId"=actor_id AND b."manufacturerId"=actor_id
        AND l."isActive" AND l."suspendedAt" IS NULL AND o."isActive"
        AND (nullif(p_options->>'licenseeId','') IS NULL OR b."licenseeId"=p_options->>'licenseeId')
        AND (target_job_id IS NULL OR j.id=target_job_id)
        AND (nullif(p_options->>'batchId','') IS NULL OR b.id=p_options->>'batchId')
        AND EXISTS (SELECT 1 FROM public."ManufacturerLicenseeLink" ml
          WHERE ml."manufacturerId"=actor_id AND ml."licenseeId"=b."licenseeId")
      ORDER BY j."createdAt" DESC,j.id DESC
      LIMIT LEAST(GREATEST(coalesce(NULLIF(p_options->>'limit','')::integer,100),1),500)
    ) scoped;
    IF p_operation='JOB' AND run_ids='[]'::jsonb THEN
      RAISE EXCEPTION 'PRINTING_BOUNDARY_DENIED' USING ERRCODE='42501';
    END IF;
    PERFORM set_config('app.printing_run_projection_job_ids',run_ids::text,true),
      set_config('app.printing_run_projection_batch_ids',batch_ids::text,true),
      set_config('app.printing_operation','printing-manufacturer-run-projection',true);
    WITH candidates AS (
      SELECT j.id,j."jobNumber",j."batchId",j."printerId",j.status,j."pipelineState",j.quantity,
        j."rangeStart",j."rangeEnd",j."failureReason",j."completedAt",j."sentAt",j."confirmedAt",j."itemCount",
        b."lifecycleState",b."releasedAt",b."suspendedAt",b."licenseeId",
        ps.id AS session_id,ps.status AS session_status,ps."completedAt" AS session_completed,
        ps."totalItems",ps."issuedItems",ps."confirmedItems",ps."frozenItems",
        pr.name AS printer_name
      FROM public."PrintJob" j
      JOIN public."Batch" b ON b.id=j."batchId"
      LEFT JOIN public."PrintSession" ps ON ps."printJobId"=j.id AND ps."batchId"=b.id AND ps."manufacturerId"=j."manufacturerId"
      LEFT JOIN public."Printer" pr ON pr.id=j."printerId" AND pr."licenseeId"=b."licenseeId"
      WHERE j.id IN (SELECT jsonb_array_elements_text(run_ids))
    ), facts AS (
      SELECT j.*, counts.*,
        counts.item_count=j.quantity AND counts.classified_count=j.quantity AS complete
      FROM candidates j
      CROSS JOIN LATERAL (
        SELECT count(*) AS item_count,count(bucket) AS classified_count,
          count(*) FILTER (WHERE bucket='confirmed') AS confirmed,
          count(*) FILTER (WHERE bucket='pending') AS pending,
          count(*) FILTER (WHERE bucket='failed') AS failed,
          count(*) FILTER (WHERE bucket='uncertain') AS uncertain,
          count(*) FILTER (WHERE bucket='cancelled') AS cancelled,
          coalesce(bool_or(resume_fence),false) AS resume_fence,
          coalesce(bool_or(abandon_fence),false) AS abandon_fence,
          count(*) FILTER (WHERE safe_stopped) AS safe_stopped_count
        FROM (
          SELECT CASE
            WHEN pi.state IN ('PRINT_CONFIRMED','CLOSED') AND pi."printConfirmedAt" IS NOT NULL THEN 'confirmed'
            WHEN pi."printConfirmedAt" IS NOT NULL OR pi.state IN ('PRINT_CONFIRMED','CLOSED') THEN NULL
            WHEN pi."failureReason"='historical_physical_outcome_unknown_qr_retired' AND q.status='BLOCKED'
              AND pi.state='CANCELLED' THEN 'cancelled'
            WHEN pi.state='FROZEN' OR pi."pipelineState"='NEEDS_OPERATOR_ACTION'
              OR (pi.state IN ('ISSUED','AGENT_ACKED') AND
                (j."pipelineState"='NEEDS_OPERATOR_ACTION' OR j.session_status IN ('FAILED','STOPPED','CANCELLED')
                  OR pi."confirmationDeadlineAt"<transaction_timestamp()))
              OR (pi.state IN ('FAILED','CANCELLED') AND evidence.present) THEN 'uncertain'
            WHEN pi.state IN ('RESERVED','ISSUED','AGENT_ACKED') THEN 'pending'
            WHEN pi.state='FAILED' THEN 'failed'
            WHEN pi.state='CANCELLED' THEN 'cancelled'
          END AS bucket,
          pi.state IN ('ISSUED','AGENT_ACKED','FROZEN') AS resume_fence,
          (pi.state IN ('ISSUED','AGENT_ACKED','PRINT_CONFIRMED','CLOSED','FROZEN')
            OR pi."printConfirmedAt" IS NOT NULL OR evidence.present) AS abandon_fence,
          (pi.state='CANCELLED' AND pi."pipelineState"='STOPPED' AND pi."attemptCount"=0
            AND pi."currentRenderTokenHash" IS NULL AND NOT evidence.present
            AND pi."confirmationDeadlineAt" IS NULL AND pi."printConfirmedAt" IS NULL
            AND pi."closedAt" IS NULL AND pi."frozenAt" IS NULL AND pi."failedAt" IS NULL
            AND q."licenseeId"=j."licenseeId" AND q.status='ACTIVATED' AND pi.code=q.code
            AND q."printedAt" IS NULL AND q."scannedAt" IS NULL AND q."scanCount"=0
            AND q."tokenNonce" IS NOT NULL AND q."tokenIssuedAt" IS NOT NULL
            AND q."tokenHash" IS NOT NULL AND q."tokenExpiresAt">clock_timestamp()
            AND NOT EXISTS (SELECT 1 FROM public."PrintItemEvent" e WHERE e."printItemId"=pi.id)) AS safe_stopped
          FROM public."PrintItem" pi
          LEFT JOIN public."QRCode" q ON q.id=pi."qrCodeId" AND q."batchId"=j."batchId" AND q."printJobId"=j.id
          CROSS JOIN LATERAL (
            SELECT (pi."issuedAt" IS NOT NULL OR pi."dispatchedAt" IS NOT NULL
              OR pi."agentAckedAt" IS NOT NULL OR pi."deviceJobRef" IS NOT NULL
              OR coalesce(pi."dispatchMetadata",'null'::jsonb) NOT IN ('null'::jsonb,'{}'::jsonb)
              OR coalesce(pi."confirmationEvidence",'null'::jsonb) NOT IN ('null'::jsonb,'{}'::jsonb)) AS present
          ) evidence
          WHERE pi."printSessionId"=j.session_id
        ) items
      ) counts
    )
    SELECT coalesce(jsonb_object_agg(id,jsonb_build_object(
      'jobId',id,'jobNumber',"jobNumber",'batchId',"batchId",'requestedCount',quantity,
      'confirmedCount',CASE WHEN complete THEN confirmed END,'pendingCount',CASE WHEN complete THEN pending END,
      'failedCount',CASE WHEN complete THEN failed END,'uncertainCount',CASE WHEN complete THEN uncertain END,
      'cancelledOrRetiredCount',CASE WHEN complete THEN cancelled END,
      'serialRange',jsonb_build_object('startCode',"rangeStart",'endCode',"rangeEnd"),
      'printer',CASE WHEN "printerId" IS NOT NULL THEN jsonb_build_object('id',"printerId",'name',printer_name) END,
      'operator',NULL::jsonb,
      'operationalStatus',CASE WHEN "pipelineState"='NEEDS_OPERATOR_ACTION' OR uncertain>0 THEN 'NEEDS_OPERATOR_ACTION' ELSE status::text END,
      'recoveryReason',CASE
        WHEN "failureReason"='historical_physical_outcome_unknown_qr_retired' THEN 'QR retired. Historical physical output remains unknown.'
        WHEN "pipelineState"='NEEDS_OPERATOR_ACTION' OR uncertain>0 THEN 'The outcome of a previous print attempt is unresolved.'
        WHEN NOT complete THEN 'Some historical print item details are unavailable.'
      END,
      'allowedActions',to_jsonb(array_remove(ARRAY[
        CASE WHEN complete AND status IN ('PENDING','SENT') AND session_status='ACTIVE' THEN 'pause' END,
        CASE WHEN complete AND status='PAUSED' AND session_status IN ('PAUSED','RESUME_PENDING')
          AND "pipelineState"<>'NEEDS_OPERATOR_ACTION' AND uncertain=0 AND NOT resume_fence THEN 'resume' END,
        CASE WHEN session_id IS NOT NULL AND status IN ('PENDING','SENT','PAUSED') THEN 'stop' END,
        CASE WHEN complete AND status='FAILED' AND "pipelineState"<>'NEEDS_OPERATOR_ACTION'
          AND uncertain=0 AND NOT abandon_fence THEN 'abandon' END,
        CASE WHEN session_id IS NOT NULL
          AND "releasedAt" IS NULL AND "suspendedAt" IS NULL AND "lifecycleState"<>'RELEASED'
          AND NOT EXISTS (SELECT 1 FROM public."PrintReissueRequest" r WHERE r."originalPrintJobId"=facts.id AND r.status IN ('PENDING','APPROVED'))
          -- Request creation and execution have different guards. Execution still verifies label reuse.
          AND (status IN ('FAILED','PARTIALLY_COMPLETED','CONFIRMED')
            OR (status='STOPPED' AND "pipelineState"='STOPPED' AND session_status='STOPPED'
              AND "completedAt" IS NOT NULL AND session_completed IS NOT NULL AND "sentAt" IS NULL AND "confirmedAt" IS NULL
              AND "issuedItems"=0 AND "confirmedItems"=0 AND "frozenItems"=0 AND "itemCount"=quantity
              AND "totalItems"=quantity AND safe_stopped_count=quantity
              AND "lifecycleState" IN ('CODES_GENERATED','PRINT_ACKNOWLEDGED')
              AND NOT EXISTS (SELECT 1 FROM public."PrintJobChunk" c WHERE c."printJobId"=facts.id OR c."printSessionId"=facts.session_id)
              AND NOT EXISTS (SELECT 1 FROM public."PrintAuditEvent" e WHERE e."printJobId"=facts.id)
              AND NOT EXISTS (SELECT 1 FROM public."PrintJob" other
                JOIN public."PrintSession" other_session ON other_session."printJobId"=other.id
                WHERE other."batchId"=facts."batchId" AND other.id<>facts.id
                  AND other.status IN ('PENDING','SENT','PAUSED')
                  AND other_session.status IN ('ACTIVE','PAUSED','RESUME_PENDING'))))
          THEN 'requestReissue' END
      ]::text[],NULL)),
      'complete',complete
    )),'{}'::jsonb) INTO run_summaries FROM facts;
    PERFORM set_config('app.printing_operation','printing-readiness',true),
      set_config('app.printing_run_projection_job_ids','[]',true),
      set_config('app.printing_run_projection_batch_ids','[]',true);
  END IF;

  IF run_summaries IS NULL THEN RETURN result; END IF;
  IF p_operation='JOB' THEN
    RETURN jsonb_set(result,'{job,runSummary}',run_summaries->target_job_id,true);
  END IF;
  RETURN (SELECT coalesce(jsonb_agg(row_data||jsonb_build_object('runSummary',run_summaries->(row_data->>'id'))
    ORDER BY ordinal),'[]'::jsonb) FROM jsonb_array_elements(scoped_rows) WITH ORDINALITY rows(row_data,ordinal)
    WHERE run_ids ? (row_data->>'id'));
END
$fn$;
REVOKE ALL ON FUNCTION app_rls.printing_run_projection(text,text,text,text,text,jsonb) FROM PUBLIC;

-- Batch history has a distinct read scope from the personal audit feed.
CREATE OR REPLACE FUNCTION app_rls.manufacturer_batch_history(
  p_capability text,p_request_id text,p_batch_id text,p_licensee_id text,p_options jsonb
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public
AS $fn$
DECLARE
  actor record;
  root_id text;
  batch_ids text[];
  page_size integer:=least(greatest(coalesce((p_options->>'limit')::integer,50),1),100);
  before_at timestamp:=nullif(p_options->>'beforeAt','')::timestamptz AT TIME ZONE 'UTC';
  before_id text:=p_options->>'beforeId';
  result jsonb;
BEGIN
  SELECT * INTO STRICT actor FROM app_rls.printing_bind_actor(
    p_capability,'printing-readiness',p_request_id,p_batch_id
  );
  IF actor.role<>'MANUFACTURER_ADMIN' OR p_batch_id IS NULL
     OR p_licensee_id IS NULL OR p_licensee_id IS DISTINCT FROM actor."batchLicenseeId" THEN
    RAISE EXCEPTION 'PRINTING_BOUNDARY_DENIED' USING ERRCODE='42501';
  END IF;

  SELECT coalesce(b."rootBatchId",b."parentBatchId",b.id) INTO STRICT root_id
    FROM public."Batch" b WHERE b.id=p_batch_id AND b."manufacturerId"=actor."userId";
  SELECT array_agg(b.id) INTO batch_ids FROM public."Batch" b
    WHERE b."licenseeId"=p_licensee_id AND b."manufacturerId"=actor."userId"
      AND (b.id=root_id OR b."rootBatchId"=root_id OR (b."rootBatchId" IS NULL AND b."parentBatchId"=root_id));
  PERFORM set_config('app.printing_history_batches',coalesce(to_jsonb(batch_ids)::text,'[]'),true),
    set_config('app.printing_operation','printing-manufacturer-batch-history',true);

  WITH audit_rows AS (
    SELECT 'a:'||a.id AS id,a."createdAt",a.action,
      CASE WHEN a."userId"=actor."userId" THEN 'You'
        WHEN a.action='ALLOCATED' THEN 'Licensee'
        ELSE 'Administrator' END AS "actorLabel",
      CASE WHEN a.action='ALLOCATED' AND jsonb_typeof(a.details->'quantity')='number'
        THEN jsonb_build_object('quantity',a.details->'quantity') ELSE '{}'::jsonb END AS details
    FROM public."AuditLog" a
    WHERE a."licenseeId"=p_licensee_id
      AND (
        (a."entityType"='Batch' AND a."entityId"=ANY(batch_ids)
          AND a.action IN ('ALLOCATED','BATCH_RELEASE_REQUESTED','BATCH_RELEASE_APPROVE','BATCH_RELEASE_REJECT'))
        OR (a."entityType"='PrintJob'
          AND a.action IN ('PRINT_JOB_CREATED','PRINT_JOB_PAUSE','PRINT_JOB_RESUME','PRINT_JOB_STOP',
            'PRINT_JOB_ABANDON','PRINT_JOB_RETIRE_UNCERTAIN','PRINT_QR_RETIREMENT_REQUEST',
            'PRINT_QR_RETIREMENT_APPROVE','PRINT_QR_RETIREMENT_REJECT')
          AND EXISTS (SELECT 1 FROM public."PrintJob" j
            WHERE j.id=a."entityId" AND j."batchId"=ANY(batch_ids) AND j."manufacturerId"=actor."userId"))
        OR (a."entityType"='PrintReissueRequest'
          AND a.action IN ('PRINT_REISSUE_CREATE','PRINT_REISSUE_REQUEST','PRINT_REISSUE_FORWARD',
            'PRINT_REISSUE_APPROVE','PRINT_REISSUE_REJECT','PRINT_REISSUE_CANCEL','PRINT_REISSUE_EXECUTE')
          AND EXISTS (SELECT 1 FROM public."PrintReissueRequest" r JOIN public."PrintJob" j ON j.id=r."originalPrintJobId"
            WHERE r.id=a."entityId" AND j."batchId"=ANY(batch_ids) AND j."manufacturerId"=actor."userId"))
      )
      AND (before_at IS NULL OR (a."createdAt",'a:'||a.id)<(before_at,before_id))
    ORDER BY a."createdAt" DESC,a.id DESC LIMIT (page_size+1)
  ), print_rows AS (
    SELECT 'p:'||e.id AS id,e."createdAt",e."eventType" AS action,
      CASE WHEN e."eventType" IN ('SAMPLE_SCAN_PASSED','sample_scan_verified')
        AND e."actorId"=actor."userId" THEN 'You' ELSE 'System' END AS "actorLabel",
      jsonb_build_object('jobNumber',j."jobNumber") AS details
    FROM public."PrintAuditEvent" e
    JOIN public."PrintJob" j ON j.id=e."printJobId" AND j."batchId"=e."batchId"
    WHERE e."batchId"=ANY(batch_ids) AND j."manufacturerId"=actor."userId"
      AND e."eventType" IN ('CONNECTOR_ACK','CONNECTOR_CONFIRM','CONNECTOR_FAIL','CONNECTOR_ABORT',
        'GATEWAY_ACK','GATEWAY_CONFIRM','GATEWAY_FAIL','WORKER_NETWORK_CONFIRM','WORKER_NETWORK_FAIL',
        'WORKER_RECOVER_UNSUBMITTED','WORKER_DISPATCH_OUTCOME_UNCERTAIN','SAMPLE_SCAN_PASSED','sample_scan_verified')
      AND (before_at IS NULL OR (e."createdAt",'p:'||e.id)<(before_at,before_id))
    ORDER BY e."createdAt" DESC,e.id DESC LIMIT (page_size+1)
  ), trace_rows AS (
    SELECT 't:'||t.id AS id,t."createdAt",'ALLOCATED'::text AS action,
      'Licensee'::text AS "actorLabel",
      CASE WHEN jsonb_typeof(t.details->'quantity')='number'
        THEN jsonb_build_object('quantity',t.details->'quantity') ELSE '{}'::jsonb END AS details
    FROM public."TraceEvent" t
    WHERE t."batchId"=ANY(batch_ids) AND t."licenseeId"=p_licensee_id
      AND t."qrCodeId" IS NULL AND t."eventType"='ASSIGNED'
      AND (before_at IS NULL OR (t."createdAt",'t:'||t.id)<(before_at,before_id))
      AND NOT EXISTS (
        SELECT 1 FROM public."AuditLog" a
        WHERE a."licenseeId"=p_licensee_id AND a."entityType"='Batch'
          AND a."entityId"=t."batchId" AND a.action='ALLOCATED'
      )
    ORDER BY t."createdAt" DESC,t.id DESC LIMIT (page_size+1)
  ), page AS (
    SELECT * FROM (
      SELECT * FROM audit_rows UNION ALL SELECT * FROM print_rows UNION ALL SELECT * FROM trace_rows
    ) events ORDER BY "createdAt" DESC,id DESC LIMIT (page_size+1)
  )
  SELECT jsonb_build_object('events',coalesce(jsonb_agg(
      jsonb_build_object('id',id,'createdAt',"createdAt" AT TIME ZONE 'UTC','action',action,
        'actorLabel',"actorLabel",'details',details) ORDER BY "createdAt" DESC,id DESC),'[]'::jsonb),
    'incomplete',EXISTS (
      SELECT 1 FROM unnest(batch_ids) child(id) WHERE NOT EXISTS (
        SELECT 1 FROM public."AuditLog" a WHERE a."licenseeId"=p_licensee_id
          AND a."entityType"='Batch' AND a."entityId"=child.id AND a.action='ALLOCATED'
      ) AND NOT EXISTS (
        SELECT 1 FROM public."TraceEvent" t WHERE t."licenseeId"=p_licensee_id AND t."batchId"=child.id
          AND t."qrCodeId" IS NULL AND t."eventType"='ASSIGNED'
      )
    )) INTO result FROM page;
  RETURN result;
END
$fn$;
