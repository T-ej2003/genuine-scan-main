CREATE OR REPLACE FUNCTION app_rls.c03_require_approval_actor(p_purpose text)
RETURNS TABLE(user_id text, licensee_id text)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
BEGIN
  IF current_setting('app.purpose', true) IS DISTINCT FROM p_purpose
     OR current_setting('app.role', true) NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN','LICENSEE_ADMIN','MANUFACTURER_ADMIN') THEN
    RAISE EXCEPTION 'C03_APPROVAL_DENIED' USING ERRCODE='42501';
  END IF;
  RETURN QUERY
  SELECT actor.user_id, actor.licensee_id
    FROM app_rls.c03_revalidate_actor_scope(
      current_setting('app.licensee_id', true),
      '["SUPER_ADMIN","PLATFORM_SUPER_ADMIN","LICENSEE_ADMIN","MANUFACTURER_ADMIN"]'::jsonb,
      CASE WHEN p_purpose IN ('sensitive-action-approval-approve','sensitive-action-approval-reject') THEN 'mfa-verified' ELSE 'password-verified' END,
      p_purpose
    ) actor;
  IF NOT FOUND THEN RAISE EXCEPTION 'C03_APPROVAL_DENIED' USING ERRCODE='42501'; END IF;
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_create_sensitive_action_approval(input jsonb)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
DECLARE actor record; created record;
DECLARE action_key text := input->>'actionKey';
BEGIN
  SELECT * INTO actor FROM app_rls.c03_require_approval_actor('sensitive-action-approval-request');
  IF jsonb_typeof(input)<>'object'
     OR action_key NOT IN ('FEATURE_FLAG_UPSERT','RETENTION_POLICY_PATCH','RETENTION_APPLY','QR_BLOCK','BATCH_BLOCK','BATCH_RELEASE','PRINTER_GATEWAY_SECRET_ROTATION')
     OR jsonb_typeof(input->'payload')<>'object'
     OR octet_length((input->'payload')::text)>65536
     OR (input ? 'summary' AND input->'summary' IS NOT NULL AND jsonb_typeof(input->'summary')<>'object')
     OR length(COALESCE(input->>'entityType',''))>120
     OR length(COALESCE(input->>'entityId',''))>160 THEN
    RAISE EXCEPTION 'C03_APPROVAL_INVALID' USING ERRCODE='22023';
  END IF;
  INSERT INTO public."SensitiveActionApproval" (
    id,"actionKey",status,"requestedByUserId","licenseeId","entityType","entityId",
    payload,summary,"requestIpHash","requestUserAgentHash","expiresAt","updatedAt"
  ) VALUES (
    gen_random_uuid()::text,action_key,'PENDING',actor.user_id,actor.licensee_id,
    NULLIF(input->>'entityType',''),NULLIF(input->>'entityId',''),input->'payload',
    input->'summary',NULLIF(input->>'requestIpHash',''),NULLIF(input->>'requestUserAgentHash',''),
    transaction_timestamp()+interval '30 minutes',transaction_timestamp()
  ) RETURNING
    id,"actionKey",status,"requestedByUserId","reviewedByUserId","executedByUserId",
    "licenseeId","entityType","entityId",payload,summary,"expiresAt","createdAt","executedAt"
    INTO created;
  PERFORM app_rls.c03_governance_audit('SENSITIVE_ACTION_APPROVAL_REQUESTED','SensitiveActionApproval',created.id,
    jsonb_build_object('actionKey',action_key,'requestedByUserId',actor.user_id));
  RETURN to_jsonb(created);
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_list_sensitive_action_approvals(status_filter text, row_limit integer, row_offset integer)
RETURNS TABLE(result jsonb)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
DECLARE actor record;
BEGIN
  SELECT * INTO actor FROM app_rls.c03_require_approval_actor('sensitive-action-approval-list');
  IF row_limit NOT BETWEEN 1 AND 200 OR row_offset NOT BETWEEN 0 AND 20000
     OR (status_filter IS NOT NULL AND status_filter NOT IN ('PENDING','APPROVED','REJECTED','EXECUTED','FAILED','EXPIRED')) THEN
    RAISE EXCEPTION 'C03_APPROVAL_LIST_INVALID' USING ERRCODE='22023';
  END IF;
  RETURN QUERY
  SELECT jsonb_build_object(
      'id',a.id,'actionKey',a."actionKey",'status',a.status,
      'requestedByUserId',a."requestedByUserId",'reviewedByUserId',a."reviewedByUserId",
      'executedByUserId',a."executedByUserId",'licenseeId',a."licenseeId",
      'entityType',a."entityType",'entityId',a."entityId",'payload',a.payload,
      'summary',a.summary,'expiresAt',a."expiresAt",'createdAt',a."createdAt",
      'executedAt',a."executedAt"
    )
    FROM public."SensitiveActionApproval" a
   WHERE a."licenseeId"=actor.licensee_id
     AND (status_filter IS NULL OR a.status=status_filter)
   ORDER BY a."createdAt" DESC,a.id DESC
   LIMIT row_limit OFFSET row_offset;
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_review_sensitive_action_approval(
  p_approval_id text, p_decision text, p_review_note text
)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
DECLARE actor record; approval record;
BEGIN
  IF p_decision NOT IN ('APPROVED','REJECTED') OR length(COALESCE(p_review_note,''))>500 THEN
    RAISE EXCEPTION 'C03_APPROVAL_REVIEW_INVALID' USING ERRCODE='22023';
  END IF;
  SELECT * INTO actor FROM app_rls.c03_require_approval_actor(
    CASE p_decision WHEN 'APPROVED' THEN 'sensitive-action-approval-approve' ELSE 'sensitive-action-approval-reject' END
  );
  SELECT id,"actionKey",status,"requestedByUserId","expiresAt"
    INTO approval FROM public."SensitiveActionApproval"
   WHERE id=p_approval_id AND "licenseeId"=actor.licensee_id FOR UPDATE;
  IF NOT FOUND OR approval.status<>'PENDING' OR approval."expiresAt"<=transaction_timestamp()
     OR approval."requestedByUserId"=actor.user_id THEN
    RAISE EXCEPTION 'C03_APPROVAL_DENIED' USING ERRCODE='42501';
  END IF;
  UPDATE public."SensitiveActionApproval"
     SET status=p_decision,"reviewedByUserId"=actor.user_id,"reviewNote"=NULLIF(p_review_note,''),
         "reviewedAt"=transaction_timestamp(),"updatedAt"=transaction_timestamp()
   WHERE id=p_approval_id
   RETURNING
     id,"actionKey",status,"requestedByUserId","reviewedByUserId","executedByUserId",
     "licenseeId","entityType","entityId",payload,summary,"expiresAt","createdAt","executedAt"
     INTO approval;
  PERFORM app_rls.c03_governance_audit('SENSITIVE_ACTION_APPROVAL_'||p_decision,'SensitiveActionApproval',approval.id,
    jsonb_build_object('actionKey',approval."actionKey",'requestedByUserId',approval."requestedByUserId",'reviewedByUserId',actor.user_id));
  RETURN to_jsonb(approval);
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_approve_sensitive_action_approval(approval_id text, review_note text)
RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public
AS $$ SELECT app_rls.c03_review_sensitive_action_approval(approval_id,'APPROVED',review_note) $$;

CREATE OR REPLACE FUNCTION app_rls.c03_reject_sensitive_action_approval(approval_id text, review_note text)
RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public
AS $$ SELECT app_rls.c03_review_sensitive_action_approval(approval_id,'REJECTED',review_note) $$;

REVOKE ALL ON FUNCTION app_rls.c03_require_approval_actor(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_create_sensitive_action_approval(jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_list_sensitive_action_approvals(text,integer,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_review_sensitive_action_approval(text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_approve_sensitive_action_approval(text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_reject_sensitive_action_approval(text,text) FROM PUBLIC;
