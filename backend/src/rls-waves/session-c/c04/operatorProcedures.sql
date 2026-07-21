CREATE SCHEMA IF NOT EXISTS app_ops;

CREATE OR REPLACE FUNCTION app_ops.session_c04_assert_context(
  required_purpose text,
  required_assurance text,
  identity_class text,
  allowed_environments text[]
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  login_role text := session_user;
  environment text := current_setting('app.operator_environment', true);
BEGIN
  IF current_setting('app.context_installed', true) IS DISTINCT FROM '1'
     OR current_setting('app.purpose', true) IS DISTINCT FROM required_purpose
     OR current_setting('app.auth_assurance', true) IS DISTINCT FROM required_assurance
     OR current_setting('app.request_id', true) !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
     OR NOT environment = ANY(allowed_environments) THEN
    RAISE EXCEPTION 'SESSION_C04_INVALID_CONTEXT';
  END IF;

  IF identity_class = 'operator' AND login_role !~ '^mscqr_(dev|staging|prod)_operator$'
     AND login_role <> 'mscqr_rls_wave_c_operator' THEN
    RAISE EXCEPTION 'SESSION_C04_WRONG_RUNTIME_IDENTITY';
  ELSIF identity_class = 'breakglass' AND login_role !~ '^mscqr_prod_breakglass_[a-z0-9_]+$'
     AND login_role <> 'mscqr_rls_wave_c_breakglass' THEN
    RAISE EXCEPTION 'SESSION_C04_WRONG_RUNTIME_IDENTITY';
  ELSIF identity_class = 'migration' AND login_role !~ '^mscqr_(dev|staging|prod)_migration$'
     AND login_role <> 'mscqr_rls_wave_c_migration' THEN
    RAISE EXCEPTION 'SESSION_C04_WRONG_RUNTIME_IDENTITY';
  END IF;
  IF (login_role ~ '^mscqr_dev_(operator|migration)$' AND environment <> 'development')
     OR (login_role ~ '^mscqr_staging_(operator|migration)$' AND environment <> 'staging')
     OR (login_role ~ '^mscqr_prod_(operator|migration)$' AND environment <> 'production')
     OR (login_role ~ '^mscqr_prod_breakglass_' AND environment <> 'production') THEN
    RAISE EXCEPTION 'SESSION_C04_WRONG_ENVIRONMENT';
  END IF;
END;
$$;

CREATE OR REPLACE FUNCTION app_ops.session_c04_assert_actor(required_licensee_id text DEFAULT NULL)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE actor jsonb;
BEGIN
  SELECT jsonb_build_object('id',u.id,'role',u.role::text,'licenseeId',u."licenseeId",'orgId',u."orgId")
    INTO actor
    FROM public."User" u
   WHERE u.id = current_setting('app.user_id', true)
     AND u."isActive" AND u.status = 'ACTIVE'::public."UserStatus"
     AND u."deletedAt" IS NULL AND u."disabledAt" IS NULL
     AND u.role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN','LICENSEE_ADMIN','ORG_ADMIN')
   FOR UPDATE;
  IF actor IS NULL THEN RAISE EXCEPTION 'SESSION_C04_DISABLED_OR_STALE_ACTOR'; END IF;
  IF actor->>'role' IN ('LICENSEE_ADMIN','ORG_ADMIN') AND (
       actor->>'licenseeId' IS DISTINCT FROM current_setting('app.licensee_id', true)
       OR required_licensee_id IS NULL
       OR actor->>'licenseeId' IS DISTINCT FROM required_licensee_id
     ) THEN
    RAISE EXCEPTION 'SESSION_C04_FOREIGN_SCOPE';
  END IF;
  RETURN actor;
END;
$$;

CREATE OR REPLACE FUNCTION app_ops.session_c04_assert_approval(
  approval_id uuid,
  required_action text,
  target_id text,
  required_approvers integer
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  approval public."SensitiveActionApproval"%ROWTYPE;
  approver_count integer := 0;
BEGIN
  SELECT * INTO approval FROM public."SensitiveActionApproval"
   WHERE id = approval_id::text FOR UPDATE;
  IF NOT FOUND OR approval."actionKey" IS DISTINCT FROM required_action
     OR approval.status IS DISTINCT FROM 'APPROVED'
     OR approval."expiresAt" <= transaction_timestamp()
     OR approval."entityId" IS DISTINCT FROM target_id THEN
    RAISE EXCEPTION 'SESSION_C04_MISSING_STALE_OR_FOREIGN_APPROVAL';
  END IF;

  IF required_approvers = 1 THEN
    IF approval."reviewedByUserId" IS NULL
       OR approval."reviewedByUserId" = approval."requestedByUserId"
       OR NOT EXISTS (
         SELECT 1 FROM public."User" u WHERE u.id=approval."reviewedByUserId"
           AND u."isActive" AND u.status='ACTIVE'::public."UserStatus"
           AND u."deletedAt" IS NULL AND u."disabledAt" IS NULL
       ) THEN
      RAISE EXCEPTION 'SESSION_C04_APPROVER_INVALID';
    END IF;
  ELSE
    SELECT count(DISTINCT ids.value) INTO approver_count
      FROM jsonb_array_elements_text(COALESCE(approval.payload->'approverIds','[]'::jsonb)) ids(value)
      JOIN public."User" u ON u.id=ids.value
     WHERE ids.value<>approval."requestedByUserId"
       AND ids.value<>current_setting('app.user_id',true)
       AND u."isActive" AND u.status='ACTIVE'::public."UserStatus"
       AND u."deletedAt" IS NULL AND u."disabledAt" IS NULL;
    IF approver_count < required_approvers THEN RAISE EXCEPTION 'SESSION_C04_DUAL_APPROVAL_REQUIRED'; END IF;
  END IF;
  RETURN to_jsonb(approval);
END;
$$;

CREATE OR REPLACE FUNCTION app_ops.session_c04_replay(action_name text, operation_key text, target_id text)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  key_hash text := md5(action_name || '|' || operation_key);
  request_hash text := md5(target_id);
  prior public."ActionIdempotencyKey"%ROWTYPE;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtextextended(key_hash, 0));
  SELECT * INTO prior FROM public."ActionIdempotencyKey" WHERE "keyHash"=key_hash FOR UPDATE;
  IF FOUND THEN
    IF prior."requestHash" IS DISTINCT FROM request_hash THEN RAISE EXCEPTION 'SESSION_C04_REPLAY_CONFLICT'; END IF;
    IF prior."completedAt" IS NULL THEN RAISE EXCEPTION 'SESSION_C04_OPERATION_IN_PROGRESS'; END IF;
    RETURN prior."responsePayload";
  END IF;
  INSERT INTO public."ActionIdempotencyKey" (id,"keyHash",action,scope,"requestHash","expiresAt")
  VALUES (gen_random_uuid()::text,key_hash,action_name,target_id,request_hash,transaction_timestamp()+interval '24 hours');
  RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION app_ops.session_c04_complete(action_name text, operation_key text, response jsonb)
RETURNS void
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
  UPDATE public."ActionIdempotencyKey"
     SET "statusCode"=200,"responsePayload"=response,"completedAt"=transaction_timestamp()
   WHERE "keyHash"=md5(action_name || '|' || operation_key)
$$;

CREATE OR REPLACE FUNCTION app_ops.session_c04_audit(
  actor_id text,
  action_name text,
  entity_type text,
  entity_id text,
  details jsonb
)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE audit_id text := gen_random_uuid()::text;
BEGIN
  INSERT INTO public."AuditLog" (id,"userId",action,"entityType","entityId",details)
  VALUES (
    audit_id,
    CASE WHEN EXISTS (SELECT 1 FROM public."User" WHERE id=actor_id) THEN actor_id ELSE NULL END,
    action_name,entity_type,entity_id,
    COALESCE(details,'{}'::jsonb) || jsonb_build_object(
      'actorId',actor_id,'runtimeIdentity',session_user,'purpose',current_setting('app.purpose',true),
      'requestId',current_setting('app.request_id',true),'immutableAttribution',true
    )
  );
  INSERT INTO public."SecurityEventOutbox" (id,"eventType",payload,"updatedAt")
  VALUES (gen_random_uuid()::text,'OPERATOR_PROCEDURE_AUDIT',jsonb_build_object(
    'auditEventId',audit_id,'action',action_name,'entityType',entity_type,'entityId',entity_id
  ),transaction_timestamp());
  RETURN audit_id;
END;
$$;

CREATE OR REPLACE FUNCTION app_ops.print_diagnostic(p_batch_id uuid)
RETURNS TABLE(batch_id uuid,print_job_id uuid,print_state text,item_counts jsonb,redacted_failure_codes jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  actor jsonb;
  tenant_id text;
  job_id text;
  job_state text;
  counts jsonb;
  failures jsonb;
  audit_id text;
  prior jsonb;
  response jsonb;
  operation_key text := current_setting('app.request_id',true);
BEGIN
  PERFORM app_ops.session_c04_assert_context('operator-print-diagnostic','operator-approved','operator',ARRAY['development','staging']);
  SELECT b."licenseeId" INTO tenant_id FROM public."Batch" b
    JOIN public."Licensee" l ON l.id=b."licenseeId" AND l."isActive" AND l."suspendedAt" IS NULL
    JOIN public."Organization" o ON o.id=l."orgId" AND o."isActive"
   WHERE b.id=p_batch_id::text FOR UPDATE OF b;
  IF NOT FOUND THEN RAISE EXCEPTION 'SESSION_C04_BATCH_NOT_FOUND'; END IF;
  actor := app_ops.session_c04_assert_actor(tenant_id);
  prior := app_ops.session_c04_replay('operator.print-diagnostic',operation_key,p_batch_id::text);
  IF prior IS NOT NULL THEN
    RETURN QUERY SELECT (prior->>'batchId')::uuid,(prior->>'printJobId')::uuid,prior->>'printState',prior->'itemCounts',prior->'redactedFailureCodes';
    RETURN;
  END IF;
  SELECT p.id,p.status::text INTO job_id,job_state FROM public."PrintJob" p
   WHERE p."batchId"=p_batch_id::text ORDER BY p."createdAt" DESC,p.id LIMIT 1;
  SELECT COALESCE(jsonb_object_agg(state,row_count),'{}'::jsonb) INTO counts FROM (
    SELECT i.state::text state,count(*) row_count FROM public."PrintItem" i
    JOIN public."PrintSession" s ON s.id=i."printSessionId" WHERE s."batchId"=p_batch_id::text GROUP BY i.state
  ) grouped;
  SELECT CASE WHEN count(*)=0 THEN '[]'::jsonb ELSE '["PRINT_ITEM_FAILED"]'::jsonb END INTO failures
    FROM public."PrintItem" i JOIN public."PrintSession" s ON s.id=i."printSessionId"
   WHERE s."batchId"=p_batch_id::text AND i.state='FAILED'::public."PrintItemState";
  audit_id := app_ops.session_c04_audit(actor->>'id','OPERATOR_PRINT_DIAGNOSTIC','Batch',p_batch_id::text,jsonb_build_object('licenseeId',tenant_id));
  response := jsonb_build_object('batchId',p_batch_id,'printJobId',job_id,'printState',job_state,'itemCounts',counts,'redactedFailureCodes',failures,'auditEventId',audit_id);
  PERFORM app_ops.session_c04_complete('operator.print-diagnostic',operation_key,response);
  RETURN QUERY SELECT p_batch_id,job_id::uuid,job_state,counts,failures;
END;
$$;

CREATE OR REPLACE FUNCTION app_ops.reissue_account_setup_link(target_user_id uuid,operator_id uuid,reason text,approval_id uuid)
RETURNS TABLE(operation_id uuid,delivery_queued boolean,audit_event_id uuid)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  actor jsonb;
  target public."User"%ROWTYPE;
  prior jsonb;
  response jsonb;
  audit_id text;
  operation text := approval_id::text;
BEGIN
  PERFORM app_ops.session_c04_assert_context('operator-account-setup-link-reissue','operator-approved','operator',ARRAY['development','staging','production']);
  IF current_setting('app.user_id',true) IS DISTINCT FROM operator_id::text OR length(btrim(reason))<8 THEN RAISE EXCEPTION 'SESSION_C04_INVALID_OPERATOR_OR_REASON'; END IF;
  SELECT * INTO target FROM public."User" WHERE id=target_user_id::text FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'SESSION_C04_TARGET_DISABLED_OR_MISSING'; END IF;
  IF target."licenseeId" IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM public."Licensee" l JOIN public."Organization" o ON o.id=l."orgId"
     WHERE l.id=target."licenseeId" AND l."isActive" AND l."suspendedAt" IS NULL AND o."isActive"
  ) THEN RAISE EXCEPTION 'SESSION_C04_INACTIVE_PARENT_SCOPE'; END IF;
  actor := app_ops.session_c04_assert_actor(target."licenseeId");
  prior := app_ops.session_c04_replay('operator.account-setup-link',operation,target_user_id::text);
  IF prior IS NOT NULL THEN
    RETURN QUERY SELECT (prior->>'operationId')::uuid,(prior->>'deliveryQueued')::boolean,(prior->>'auditEventId')::uuid;
    RETURN;
  END IF;
  IF NOT target."isActive" OR target.status='DISABLED'::public."UserStatus" OR target."deletedAt" IS NOT NULL OR target."disabledAt" IS NOT NULL THEN
    RAISE EXCEPTION 'SESSION_C04_TARGET_DISABLED_OR_MISSING';
  END IF;
  IF app_ops.session_c04_assert_approval(approval_id,'OPERATOR_ACCOUNT_SETUP_LINK_REISSUE',target_user_id::text,1)->>'requestedByUserId' IS DISTINCT FROM operator_id::text THEN
    RAISE EXCEPTION 'SESSION_C04_FOREIGN_OPERATOR_APPROVAL';
  END IF;
  UPDATE public."Invite" SET "usedAt"=transaction_timestamp() WHERE email=target.email AND "usedAt" IS NULL AND "expiresAt">transaction_timestamp();
  UPDATE public."PasswordReset" SET "usedAt"=transaction_timestamp() WHERE "userId"=target.id AND "usedAt" IS NULL AND "expiresAt">transaction_timestamp();
  audit_id := app_ops.session_c04_audit(operator_id::text,'OPERATOR_ACCOUNT_SETUP_LINK_REISSUED','User',target.id,
    jsonb_build_object('approvalId',approval_id,'reason',btrim(reason),'deliveryQueued',true));
  INSERT INTO public."SecurityEventOutbox" (id,"eventType",payload,"updatedAt") VALUES (
    gen_random_uuid()::text,'AUTH_SETUP_LINK_REISSUE_REQUESTED',jsonb_build_object(
      'operationId',operation,'targetUserId',target.id,'operatorId',operator_id,'approvalId',approval_id,
      'mode',CASE WHEN target.status='INVITED'::public."UserStatus" AND target."passwordHash" IS NULL THEN 'SETUP' ELSE 'RESET' END
    ),transaction_timestamp()
  );
  response := jsonb_build_object('operationId',operation,'deliveryQueued',true,'auditEventId',audit_id);
  PERFORM app_ops.session_c04_complete('operator.account-setup-link',operation,response);
  RETURN QUERY SELECT approval_id,true,audit_id::uuid;
END;
$$;

CREATE OR REPLACE FUNCTION app_ops.reset_account_mfa(target_user_id uuid,executor_id uuid,reason text,approval_id uuid)
RETURNS TABLE(operation_id uuid,status text,affected_count integer,audit_event_id uuid)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  target public."User"%ROWTYPE;
  approval jsonb;
  prior jsonb;
  response jsonb;
  audit_id text;
  affected integer := 0;
  changed integer;
  operation text := approval_id::text;
BEGIN
  PERFORM app_ops.session_c04_assert_context('dual-approved-break-glass-mfa-reset','dual-approved-break-glass','breakglass',ARRAY['production']);
  IF current_setting('app.user_id',true) IS DISTINCT FROM executor_id::text OR length(btrim(reason))<12 THEN RAISE EXCEPTION 'SESSION_C04_INVALID_EXECUTOR_OR_REASON'; END IF;
  prior := app_ops.session_c04_replay('operator.breakglass-mfa-reset',operation,target_user_id::text);
  IF prior IS NOT NULL THEN
    RETURN QUERY SELECT (prior->>'operationId')::uuid,prior->>'status',(prior->>'affectedCount')::integer,(prior->>'auditEventId')::uuid;
    RETURN;
  END IF;
  approval := app_ops.session_c04_assert_approval(approval_id,'BREAK_GLASS_MFA_RESET',target_user_id::text,2);
  IF approval->'payload'->>'executorId' IS DISTINCT FROM executor_id::text THEN RAISE EXCEPTION 'SESSION_C04_FOREIGN_EXECUTOR'; END IF;
  SELECT * INTO target FROM public."User" WHERE id=target_user_id::text FOR UPDATE;
  IF NOT FOUND OR NOT target."isActive" OR target.status<>'ACTIVE'::public."UserStatus" OR target."deletedAt" IS NOT NULL OR target."disabledAt" IS NOT NULL
     OR target.role NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') THEN RAISE EXCEPTION 'SESSION_C04_TARGET_NOT_ACTIVE_PLATFORM_ADMIN'; END IF;
  UPDATE public."AdminMfaCredential" SET "isEnabled"=false,"verifiedAt"=NULL,"backupCodesHash"=ARRAY[]::text[],"updatedAt"=transaction_timestamp() WHERE "userId"=target.id;
  GET DIAGNOSTICS changed=ROW_COUNT; affected:=affected+changed;
  UPDATE public."UserMfaFactor" SET "disabledAt"=transaction_timestamp(),"updatedAt"=transaction_timestamp() WHERE "userId"=target.id AND "disabledAt" IS NULL;
  GET DIAGNOSTICS changed=ROW_COUNT; affected:=affected+changed;
  DELETE FROM public."AdminWebAuthnCredential" WHERE "userId"=target.id; GET DIAGNOSTICS changed=ROW_COUNT; affected:=affected+changed;
  DELETE FROM public."UserBackupCode" WHERE "userId"=target.id; GET DIAGNOSTICS changed=ROW_COUNT; affected:=affected+changed;
  UPDATE public."RefreshToken" SET "revokedAt"=transaction_timestamp(),"revokedReason"='BREAK_GLASS_MFA_RESET',"lastUsedAt"=transaction_timestamp()
   WHERE "userId"=target.id AND "revokedAt" IS NULL;
  GET DIAGNOSTICS changed=ROW_COUNT; affected:=affected+changed;
  audit_id := app_ops.session_c04_audit(executor_id::text,'AUTH_MFA_BREAK_GLASS_RESET','User',target.id,
    jsonb_build_object('approvalId',approval_id,'reason',btrim(reason),'affectedCount',affected));
  response := jsonb_build_object('operationId',operation,'status','completed','affectedCount',affected,'auditEventId',audit_id);
  PERFORM app_ops.session_c04_complete('operator.breakglass-mfa-reset',operation,response);
  RETURN QUERY SELECT approval_id,'completed',affected,audit_id::uuid;
END;
$$;

CREATE OR REPLACE FUNCTION app_ops.prepare_rls_validation_fixture(fixture_id uuid,tenant_key text,approval_id uuid)
RETURNS TABLE(operation_id uuid,status text,affected_count integer,audit_event_id uuid)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  actor jsonb;
  prior jsonb;
  response jsonb;
  audit_id text;
  licensee_id text := gen_random_uuid()::text;
  admin_id text := gen_random_uuid()::text;
  manufacturer_id text := gen_random_uuid()::text;
  range_id text := gen_random_uuid()::text;
  batch_id text := gen_random_uuid()::text;
  prefix text := upper(substr(md5(lower(tenant_key)),1,8));
  operation text := approval_id::text;
  i integer;
  affected integer := 0;
BEGIN
  PERFORM app_ops.session_c04_assert_context('operator-staging-rls-validation-fixture','operator-approved','operator',ARRAY['staging']);
  IF tenant_key !~ '^[a-z0-9][a-z0-9_-]{2,63}$' THEN RAISE EXCEPTION 'SESSION_C04_INVALID_TENANT_KEY'; END IF;
  actor := app_ops.session_c04_assert_actor(NULL);
  IF actor->>'role' NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') THEN RAISE EXCEPTION 'SESSION_C04_PLATFORM_ACTOR_REQUIRED'; END IF;
  prior := app_ops.session_c04_replay('operator.staging-rls-fixture',operation,fixture_id::text || '|' || tenant_key);
  IF prior IS NOT NULL THEN
    RETURN QUERY SELECT (prior->>'operationId')::uuid,prior->>'status',(prior->>'affectedCount')::integer,(prior->>'auditEventId')::uuid;
    RETURN;
  END IF;
  IF app_ops.session_c04_assert_approval(approval_id,'STAGING_RLS_VALIDATION_FIXTURE',fixture_id::text,1)->>'requestedByUserId' IS DISTINCT FROM actor->>'id' THEN
    RAISE EXCEPTION 'SESSION_C04_FOREIGN_OPERATOR_APPROVAL';
  END IF;
  IF EXISTS (SELECT 1 FROM public."Organization" WHERE id=fixture_id::text AND name<>'MSCQR Staging RLS Validation Organization') THEN
    RAISE EXCEPTION 'SESSION_C04_FIXTURE_ID_FOREIGN';
  END IF;
  INSERT INTO public."Organization" (id,name,"isActive","updatedAt") VALUES (fixture_id::text,'MSCQR Staging RLS Validation Organization',true,transaction_timestamp())
    ON CONFLICT (id) DO UPDATE SET "isActive"=true,"updatedAt"=transaction_timestamp(); affected:=affected+1;
  INSERT INTO public."Licensee" (id,"orgId",name,prefix,"isActive",metadata,"updatedAt") VALUES (licensee_id,fixture_id::text,'MSCQR Staging RLS Validation Licensee',prefix,true,jsonb_build_object('synthetic',true,'tenantKey',tenant_key),transaction_timestamp()); affected:=affected+1;
  INSERT INTO public."User" (id,email,name,role,"orgId","licenseeId",status,"isActive","emailVerifiedAt",metadata,"updatedAt") VALUES
    (admin_id,'rls-admin-'||substr(md5(tenant_key),1,12)||'@example.invalid','RLS Fixture Admin','LICENSEE_ADMIN',fixture_id::text,licensee_id,'ACTIVE',true,transaction_timestamp(),jsonb_build_object('synthetic',true),transaction_timestamp()),
    (manufacturer_id,'rls-manufacturer-'||substr(md5(tenant_key),1,12)||'@example.invalid','RLS Fixture Manufacturer','MANUFACTURER',fixture_id::text,licensee_id,'ACTIVE',true,transaction_timestamp(),jsonb_build_object('synthetic',true),transaction_timestamp()); affected:=affected+2;
  INSERT INTO public."ManufacturerLicenseeLink" ("manufacturerId","licenseeId","isPrimary","updatedAt") VALUES (manufacturer_id,licensee_id,true,transaction_timestamp()); affected:=affected+1;
  INSERT INTO public."QRRange" (id,"licenseeId","startCode","endCode","totalCodes","usedCodes","updatedAt") VALUES (range_id,licensee_id,'RLS-'||prefix||'-0001','RLS-'||prefix||'-0005',5,5,transaction_timestamp()); affected:=affected+1;
  INSERT INTO public."Batch" (id,name,"licenseeId","manufacturerId","startCode","endCode","totalCodes","lifecycleState",metadata,"updatedAt") VALUES
    (batch_id,'MSCQR Staging RLS Validation Batch',licensee_id,manufacturer_id,'RLS-'||prefix||'-0001','RLS-'||prefix||'-0005',5,'CODES_GENERATED',jsonb_build_object('synthetic',true),transaction_timestamp()); affected:=affected+1;
  FOR i IN 1..5 LOOP
    INSERT INTO public."QRCode" (id,code,"licenseeId","batchId",status,"updatedAt") VALUES
      (gen_random_uuid()::text,'RLS-'||prefix||'-'||lpad(i::text,4,'0'),licensee_id,batch_id,'ALLOCATED',transaction_timestamp()); affected:=affected+1;
  END LOOP;
  audit_id := app_ops.session_c04_audit(actor->>'id','STAGING_RLS_VALIDATION_FIXTURE_PREPARED','Organization',fixture_id::text,
    jsonb_build_object('approvalId',approval_id,'tenantKey',tenant_key,'affectedCount',affected));
  response := jsonb_build_object('operationId',operation,'status','completed','affectedCount',affected,'auditEventId',audit_id);
  PERFORM app_ops.session_c04_complete('operator.staging-rls-fixture',operation,response);
  RETURN QUERY SELECT approval_id,'completed',affected,audit_id::uuid;
END;
$$;

CREATE OR REPLACE FUNCTION app_ops.bootstrap_configured_super_admin(p_email text,p_password_hash text,p_name text,p_auto_verify boolean)
RETURNS TABLE(status text,user_id uuid,email text,role text,auto_verified boolean,reason text,audit_event_id uuid)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  existing public."User"%ROWTYPE;
  created_id text;
  audit_id text;
BEGIN
  PERFORM app_ops.session_c04_assert_context('bootstrap-configured-super-admin','system-verified','migration',ARRAY['development','staging','production']);
  PERFORM pg_advisory_xact_lock(723425101);
  SELECT * INTO existing FROM public."User" u WHERE u.role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') AND u."deletedAt" IS NULL ORDER BY u."createdAt",u.id LIMIT 1 FOR UPDATE;
  IF FOUND THEN
    audit_id:=app_ops.session_c04_audit(NULL,'AUTH_SUPER_ADMIN_BOOTSTRAP_SKIPPED_EXISTING','User',existing.id,jsonb_build_object('migrationOnly',true));
    RETURN QUERY SELECT 'skipped_existing',existing.id::uuid,existing.email,existing.role::text,NULL::boolean,NULL::text,audit_id::uuid;
    RETURN;
  END IF;
  SELECT * INTO existing FROM public."User" WHERE lower(public."User".email)=lower(p_email) FOR UPDATE;
  IF FOUND THEN
    audit_id:=app_ops.session_c04_audit(NULL,'AUTH_SUPER_ADMIN_BOOTSTRAP_BLOCKED','User',existing.id,jsonb_build_object('reason','configured email belongs to another account','migrationOnly',true));
    RETURN QUERY SELECT 'blocked',NULL::uuid,existing.email,NULL::text,NULL::boolean,'Configured bootstrap email already belongs to a non-super-admin account.',audit_id::uuid;
    RETURN;
  END IF;
  created_id:=gen_random_uuid()::text;
  INSERT INTO public."User" (id,email,"passwordHash",name,role,status,"isActive","emailVerifiedAt","updatedAt") VALUES
    (created_id,lower(btrim(p_email)),p_password_hash,btrim(p_name),'SUPER_ADMIN','ACTIVE',true,CASE WHEN p_auto_verify THEN transaction_timestamp() ELSE NULL END,transaction_timestamp());
  audit_id:=app_ops.session_c04_audit(NULL,'AUTH_SUPER_ADMIN_BOOTSTRAPPED','User',created_id,jsonb_build_object('autoVerified',p_auto_verify,'migrationOnly',true));
  RETURN QUERY SELECT 'created',created_id::uuid,lower(btrim(p_email)),'SUPER_ADMIN',p_auto_verify,NULL::text,audit_id::uuid;
END;
$$;

REVOKE ALL ON FUNCTION app_ops.session_c04_assert_context(text,text,text,text[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_ops.session_c04_assert_actor(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_ops.session_c04_assert_approval(uuid,text,text,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_ops.session_c04_replay(text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_ops.session_c04_complete(text,text,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_ops.session_c04_audit(text,text,text,text,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_ops.print_diagnostic(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_ops.reissue_account_setup_link(uuid,uuid,text,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_ops.reset_account_mfa(uuid,uuid,text,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_ops.prepare_rls_validation_fixture(uuid,text,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_ops.bootstrap_configured_super_admin(text,text,text,boolean) FROM PUBLIC;
