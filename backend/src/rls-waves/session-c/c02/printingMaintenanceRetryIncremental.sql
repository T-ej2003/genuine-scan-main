\set ON_ERROR_STOP on
BEGIN;

DO $preflight$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_proc p
    WHERE p.oid=to_regprocedure('app_rls.printing_maintenance_gate(text,text,text,jsonb)')
      AND p.proowner=current_user::regrole AND p.prosecdef
  ) OR NOT has_schema_privilege(current_user,'app_rls','CREATE')
  THEN RAISE EXCEPTION 'MAINTENANCE_MIGRATION_IDENTITY_INVALID' USING ERRCODE='42501'; END IF;
END
$preflight$;

CREATE OR REPLACE FUNCTION app_rls.printing_maintenance_gate(
  p_scope text, p_operation text, p_actor text, p_details jsonb
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public
AS $fn$
DECLARE checkpoint_key text; current_value jsonb;
BEGIN
  IF session_user NOT IN ('mscqr_prd_rls_phase2_app','mscqr_prd_rls_phase2_worker')
     OR p_operation NOT IN ('CHECK','REQUEST','STATUS','LEASE','COMPLETE','ABORT','AUTHORIZE','CONSUME','VERIFY','RELEASE') OR length(coalesce(p_scope,'')) NOT BETWEEN 1 AND 2048
     OR (p_operation IN ('REQUEST','LEASE','COMPLETE','ABORT','AUTHORIZE','CONSUME','VERIFY','RELEASE') AND nullif(p_actor,'') IS NULL)
  THEN RAISE EXCEPTION 'PRINTING_MAINTENANCE_DENIED' USING ERRCODE='42501'; END IF;
  checkpoint_key:='connector-maintenance:'||encode(sha256(convert_to(p_scope,'UTF8')),'hex');
  PERFORM set_config('app.printing_maintenance_key',checkpoint_key,true);
  PERFORM pg_advisory_xact_lock(hashtextextended(checkpoint_key,0));
  INSERT INTO public."SystemCheckpoint"(key,value,"createdAt","updatedAt")
    VALUES(checkpoint_key,jsonb_build_object('state','ACTIVE','scope',p_scope),clock_timestamp(),clock_timestamp())
    ON CONFLICT(key) DO NOTHING;
  SELECT value INTO STRICT current_value FROM public."SystemCheckpoint" WHERE key=checkpoint_key FOR UPDATE;
  IF current_value->>'scope' IS DISTINCT FROM p_scope OR
     coalesce(current_value->>'state','') NOT IN ('ACTIVE','DISPATCH_FENCED')
  THEN RAISE EXCEPTION 'PRINTING_MAINTENANCE_STATE_INVALID' USING ERRCODE='55000'; END IF;
  IF p_operation='REQUEST' AND current_value->>'state'='ACTIVE' THEN
    current_value:=current_value||jsonb_build_object('state','DISPATCH_FENCED','requestedBy',p_actor,
      'requestId',p_details->>'requestId','requestedAt',clock_timestamp());
    UPDATE public."SystemCheckpoint" SET value=current_value,"updatedAt"=clock_timestamp() WHERE key=checkpoint_key;
  END IF;
  IF p_operation IN ('CHECK','LEASE') AND current_value->>'state'<>'ACTIVE'
  THEN RAISE EXCEPTION 'CONNECTOR_MAINTENANCE_FENCED' USING ERRCODE='55000'; END IF;
  -- The checkpoint row serializes diagnostic leases with automatic claims and
  -- dispatch reservations on this physical printer. An expired client request
  -- is still ambiguous; only a confirmed diagnostic releases its evidence.
  IF p_operation IN ('CHECK','LEASE') AND nullif(p_details->>'printerId','') IS NOT NULL THEN
    IF EXISTS (SELECT 1 FROM jsonb_each(coalesce(current_value->'diagnostics','{}'::jsonb)) lease
      WHERE (lease.value->>'printerId'=p_details->>'printerId' OR lease.value->>'printerId' IS NULL)
        AND lease.value->>'state' IS DISTINCT FROM 'CONFIRMED'
        AND lease.value->>'state' IS DISTINCT FROM 'REJECTED_PRE_DISPATCH'
        AND NOT coalesce(lease.key=p_details->>'diagnosticRequestId' AND
          lease.value->>'printerId'=p_details->>'printerId' AND lease.value->>'state'='ACCEPTED',false))
    THEN RAISE EXCEPTION 'DIAGNOSTIC_RECONCILIATION_REQUIRED' USING ERRCODE='55000'; END IF;
    -- Local diagnostics have a separate durable record on Printer. A connector
    -- ACK is transport evidence, not physical confirmation, and must not let
    -- the next automatic chunk use the same printer before reconciliation.
    IF p_operation='CHECK' AND EXISTS (
      SELECT 1 FROM public."Printer" p
      WHERE p.id=p_details->>'printerId'
        AND p.metadata->'pendingLocalAgentTestLabel' IS NOT NULL
        AND p.metadata->'pendingLocalAgentTestLabel'->>'status' IS DISTINCT FROM 'CONFIRMED'
        AND (p.metadata->'pendingLocalAgentTestLabel' ? 'claimedAt' OR
          p.metadata->'pendingLocalAgentTestLabel'->>'status' IN ('CLAIMED','ACKED'))
    ) THEN RAISE EXCEPTION 'DIAGNOSTIC_RECONCILIATION_REQUIRED' USING ERRCODE='55000'; END IF;
  END IF;
  IF p_operation IN ('LEASE','COMPLETE','ABORT') THEN
    IF coalesce(p_details->>'requestId','') !~* '^[0-9a-f-]{36}$'
    THEN RAISE EXCEPTION 'PRINTING_MAINTENANCE_DENIED' USING ERRCODE='42501'; END IF;
    IF p_operation='LEASE' THEN
      -- A reservation permanently blocks replay of that request, not a fresh,
      -- separately authorized diagnostic intent. All unresolved reservations
      -- remain in the maintenance inventory and require signed reconciliation.
      IF coalesce(current_value->'diagnostics','{}'::jsonb) ? (p_details->>'requestId')
      THEN RAISE EXCEPTION 'DIAGNOSTIC_RECONCILIATION_REQUIRED' USING ERRCODE='55000'; END IF;
      IF nullif(p_details->>'printerId','') IS NULL OR EXISTS (
        SELECT 1 FROM public."PrintItem" pi JOIN public."PrintSession" ps ON ps.id=pi."printSessionId"
        WHERE ps."printerId"=p_details->>'printerId' AND (
          pi.state IN ('ISSUED','AGENT_ACKED','FROZEN') OR
          (pi."printConfirmedAt" IS NULL AND (pi."dispatchedAt" IS NOT NULL OR
            pi."agentAckedAt" IS NOT NULL OR nullif(pi."dispatchMetadata"->>'transportReference','') IS NOT NULL))))
      THEN RAISE EXCEPTION 'DIAGNOSTIC_RECONCILIATION_REQUIRED' USING ERRCODE='55000'; END IF;
      current_value:=jsonb_set(current_value,'{diagnostics}',coalesce(current_value->'diagnostics','{}'::jsonb)||
        jsonb_build_object(p_details->>'requestId',jsonb_build_object('state','ACCEPTED','actor',p_actor,
          'printerId',p_details->>'printerId','acceptedAt',clock_timestamp())),true);
    ELSE
      IF current_value->'diagnostics'->(p_details->>'requestId')->>'actor' IS DISTINCT FROM p_actor OR
         current_value->'diagnostics'->(p_details->>'requestId')->>'printerId' IS DISTINCT FROM p_details->>'printerId' OR
         current_value->'diagnostics'->(p_details->>'requestId')->>'state' IS DISTINCT FROM 'ACCEPTED' OR
         (p_operation='COMPLETE' AND (p_details->>'outcome' IS DISTINCT FROM 'confirmed' OR nullif(p_details->>'deviceJobRef','') IS NULL)) OR
         (p_operation='ABORT' AND (p_details->>'outcome' IS DISTINCT FROM 'pre_dispatch_rejected' OR
           length(btrim(coalesce(p_details->>'reason',''))) NOT BETWEEN 1 AND 500))
      THEN RAISE EXCEPTION 'PRINTING_MAINTENANCE_DENIED' USING ERRCODE='42501'; END IF;
      current_value:=jsonb_set(current_value,ARRAY['diagnostics',p_details->>'requestId'],
        current_value->'diagnostics'->(p_details->>'requestId')||CASE WHEN p_operation='COMPLETE' THEN jsonb_build_object(
          'state','CONFIRMED','deviceJobRef',p_details->>'deviceJobRef','confirmedAt',clock_timestamp()) ELSE jsonb_build_object(
          'state','REJECTED_PRE_DISPATCH','reason',p_details->>'reason','rejectedAt',clock_timestamp()) END,false);
    END IF;
    UPDATE public."SystemCheckpoint" SET value=current_value,"updatedAt"=clock_timestamp() WHERE key=checkpoint_key;
  END IF;
  IF p_operation IN ('AUTHORIZE','CONSUME','VERIFY','RELEASE') THEN
    IF current_value->>'state'<>'DISPATCH_FENCED' OR
       p_details->'binding'->>'fenceRequestId' IS DISTINCT FROM current_value->>'requestId'
    THEN RAISE EXCEPTION 'MAINTENANCE_AUTHORIZATION_DENIED' USING ERRCODE='42501'; END IF;
    IF p_operation='AUTHORIZE' THEN
      -- A lost HTTP response may retry the same signed evidence and token.
      -- A consumed token or different evidence must never be reissued.
      IF current_value->'upgrade'->>'state'='AUTHORIZED' AND
         current_value->'upgrade'->>'actor'=p_actor AND
         current_value->'upgrade'->>'tokenHash'=p_details->>'tokenHash' AND
         current_value->'upgrade'->'binding'=p_details->'binding' AND
         current_value->'upgrade'->'evidence'=p_details->'evidence' AND
         (current_value->'upgrade'->>'expiresAt')::timestamptz>clock_timestamp()
      THEN RETURN jsonb_build_object('authorized',true,'binding',p_details->'binding','dispatchFenced',true); END IF;
      IF coalesce(p_details->>'tokenHash','') !~ '^[a-f0-9]{64}$' OR
         (current_value ? 'upgrade' AND (
           current_value->'upgrade'->'binding' IS DISTINCT FROM p_details->'binding' OR
           (current_value->'upgrade'->>'expiresAt')::timestamptz>clock_timestamp() OR
           coalesce((p_details->'evidence'->>'verifiedAt')::timestamptz,'-infinity')<=(current_value->'upgrade'->>'expiresAt')::timestamptz))
      THEN RAISE EXCEPTION 'MAINTENANCE_ATTEMPT_ALREADY_EXISTS' USING ERRCODE='55000'; END IF;
      IF current_value ? 'upgrade' THEN
        current_value:=jsonb_set(current_value,'{history}',coalesce(current_value->'history','[]'::jsonb)||jsonb_build_array((current_value->'upgrade')-'tokenHash'));
      END IF;
      current_value:=current_value||jsonb_build_object('upgrade',p_details||jsonb_build_object(
        'state','AUTHORIZED','actor',p_actor,'authorizedAt',clock_timestamp()));
    ELSIF p_operation='RELEASE' THEN
      IF current_value->'upgrade'->>'state' IS DISTINCT FROM 'CONSUMED' OR
         current_value->'upgrade'->'binding' IS DISTINCT FROM p_details->'binding' OR
         coalesce(p_details->'evidence'->>'evidenceSha256','') !~ '^[a-f0-9]{64}$' OR
         coalesce((p_details->'evidence'->>'expiresAt')::timestamptz,'-infinity')<=clock_timestamp() OR
         p_details->'evidence'->>'workDigest' IS DISTINCT FROM p_details->>'workDigest' OR
         p_details->'evidence'->'runtime'->>'version' IS DISTINCT FROM p_details->'binding'->>'targetVersion' OR
         p_details->'evidence'->'runtime'->>'sha256' IS DISTINCT FROM p_details->'binding'->>'targetSha256' OR
         p_details->'evidence'->'runtime'->>'agentId' IS DISTINCT FROM p_details->'binding'->>'agentId' OR
         p_details->'evidence'->'runtime'->>'deviceFingerprint' IS DISTINCT FROM p_details->'binding'->>'deviceFingerprint' OR
         p_details->'evidence'->'runtime'->>'processCount' IS DISTINCT FROM '1' OR
         coalesce(p_details->'evidence'->'runtime'->>'verificationSha256','') !~ '^[a-f0-9]{64}$'
      THEN RAISE EXCEPTION 'MAINTENANCE_AUTHORIZATION_DENIED' USING ERRCODE='42501'; END IF;
      current_value:=jsonb_build_object('state','ACTIVE','scope',p_scope,'history',coalesce(current_value->'history','[]'::jsonb)||
        jsonb_build_array(jsonb_build_object('maintenance',current_value-'history','releaseEvidence',p_details->'evidence','releasedBy',p_actor,'releasedAt',clock_timestamp())));
    ELSE
      IF current_value->'upgrade'->>'actor' IS DISTINCT FROM p_actor OR
         current_value->'upgrade'->>'tokenHash' IS DISTINCT FROM p_details->>'tokenHash' OR
         current_value->'upgrade'->'binding' IS DISTINCT FROM p_details->'binding' OR
         current_value->'upgrade'->'evidence'->>'workDigest' IS DISTINCT FROM p_details->>'workDigest' OR
         coalesce((current_value->'upgrade'->>'expiresAt')::timestamptz,'-infinity')<=clock_timestamp() OR
         current_value->'upgrade'->>'state' IS DISTINCT FROM (CASE WHEN p_operation='CONSUME' THEN 'AUTHORIZED' ELSE 'CONSUMED' END)
      THEN RAISE EXCEPTION 'MAINTENANCE_AUTHORIZATION_DENIED' USING ERRCODE='42501'; END IF;
      IF p_operation='CONSUME' THEN
        current_value:=jsonb_set(current_value,'{upgrade,state}',to_jsonb('CONSUMED'::text));
      END IF;
    END IF;
    UPDATE public."SystemCheckpoint" SET value=current_value,"updatedAt"=clock_timestamp() WHERE key=checkpoint_key;
    RETURN jsonb_build_object('authorized',true,'binding',p_details->'binding','dispatchFenced',current_value->>'state'<>'ACTIVE');
  END IF;
  RETURN (current_value-'upgrade')||jsonb_build_object('upgradeAllowed',false,'reconciliationRequired',current_value->>'state'<>'ACTIVE');
END
$fn$;

COMMIT;
