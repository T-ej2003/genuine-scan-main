CREATE OR REPLACE FUNCTION app_rls.session_c_bind_admin(
  p_capability text,p_purpose text,p_request_id text,p_allow_tenant boolean
) RETURNS TABLE("sessionId" text,"userId" text,"role" text,"organizationId" text,"licenseeId" text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record;
BEGIN
  IF p_purpose NOT IN (
    'administration-create-licensee','administration-update-licensee','administration-delete-licensee',
    'administration-create-user','administration-update-user','administration-delete-user',
    'administration-restore-manufacturer','auth-invite-create','licensee-admin-invite-resend'
  ) OR p_request_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' THEN
    RAISE EXCEPTION 'SESSION_C_INVALID_CONTEXT' USING ERRCODE='42501';
  END IF;
  SELECT * INTO actor FROM app_auth.require_authenticated_session(p_capability,p_purpose,p_request_id);
  IF actor.assurance<>'ADMIN_MFA' OR actor.role NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN','LICENSEE_ADMIN')
     OR (NOT p_allow_tenant AND actor.role='LICENSEE_ADMIN') THEN
    RAISE EXCEPTION 'SESSION_C_WRONG_ROLE' USING ERRCODE='42501';
  END IF;
  IF actor.role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') AND (actor."organizationId" IS NOT NULL OR actor."licenseeId" IS NOT NULL) THEN
    RAISE EXCEPTION 'SESSION_C_STALE_PLATFORM_SCOPE' USING ERRCODE='42501';
  END IF;
  PERFORM set_config('app.admin_mutation_session_id',actor."sessionId",true),
          set_config('app.admin_mutation_user_id',actor."userId",true),
          set_config('app.admin_mutation_role',actor.role,true),
          set_config('app.admin_mutation_organization_id',coalesce(actor."organizationId",''),true),
          set_config('app.admin_mutation_licensee_id',coalesce(actor."licenseeId",''),true),
          set_config('app.admin_mutation_operation',p_purpose,true),
          set_config('app.admin_mutation_target_user_id','',true),
          set_config('app.admin_mutation_target_licensee_id','',true),
          set_config('app.admin_mutation_target_organization_id','',true),
          set_config('app.admin_mutation_target_email','',true),
          set_config('app.admin_mutation_target_prefix','',true),
          set_config('app.admin_mutation_audit_id','',true),
          set_config('app.admin_mutation_outbox_id','',true),
          set_config('app.admin_mutation_invite_id','',true),
          set_config('app.admin_mutation_idempotency_hash','',true);
  PERFORM app_rls.session_c_set_target(actor."licenseeId",actor."organizationId",NULL,NULL,NULL);
  IF actor.role='LICENSEE_ADMIN' AND NOT EXISTS (
    SELECT 1 FROM public."Licensee" l JOIN public."Organization" o ON o.id=l."orgId"
     WHERE l.id=actor."licenseeId" AND l."orgId"=actor."organizationId"
       AND l."isActive" AND l."suspendedAt" IS NULL AND o."isActive"
  ) THEN RAISE EXCEPTION 'SESSION_C_FOREIGN_SCOPE' USING ERRCODE='42501'; END IF;
  RETURN QUERY SELECT actor."sessionId"::text,actor."userId"::text,actor.role::text,
    actor."organizationId"::text,actor."licenseeId"::text;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.session_c_set_target(
  p_licensee_id text,p_organization_id text,p_user_id text,p_email text,p_prefix text
) RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
BEGIN
  PERFORM set_config('app.admin_mutation_target_licensee_id',coalesce(p_licensee_id,''),true),
          set_config('app.admin_mutation_target_organization_id',coalesce(p_organization_id,''),true),
          set_config('app.admin_mutation_target_user_id',coalesce(p_user_id,''),true),
          set_config('app.admin_mutation_target_email',coalesce(p_email,''),true),
          set_config('app.admin_mutation_target_prefix',coalesce(p_prefix,''),true);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.session_c_user_projection(p_target_id text)
RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
  SELECT jsonb_build_object(
    'id',u.id,'email',u.email,'name',u.name,'role',u.role::text,'licenseeId',u."licenseeId",
    'isActive',u."isActive",'deletedAt',u."deletedAt",'createdAt',u."createdAt",
    'location',u.location,'website',u.website,
    'licensee',CASE WHEN l.id IS NULL THEN NULL ELSE jsonb_build_object(
      'id',l.id,'name',l.name,'prefix',l.prefix,'brandName',l."brandName") END,
    'manufacturerLicenseeLinks',COALESCE((SELECT jsonb_agg(jsonb_build_object(
      'licenseeId',ml."licenseeId",'isPrimary',ml."isPrimary",'licensee',jsonb_build_object(
        'id',ll.id,'name',ll.name,'prefix',ll.prefix,'brandName',ll."brandName",'orgId',ll."orgId")
      ) ORDER BY ml."isPrimary" DESC,ml."createdAt")
      FROM public."ManufacturerLicenseeLink" ml JOIN public."Licensee" ll ON ll.id=ml."licenseeId"
      WHERE ml."manufacturerId"=u.id),'[]'::jsonb)
  ) FROM public."User" u LEFT JOIN public."Licensee" l ON l.id=u."licenseeId" WHERE u.id=p_target_id
$fn$;

CREATE OR REPLACE FUNCTION app_rls.session_c_write_audit(
  p_actor_id text,p_organization_id text,p_licensee_id text,p_action text,p_entity_type text,
  p_entity_id text,p_details jsonb,p_ip_hash text,p_user_agent text
) RETURNS text LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE audit_id text:=gen_random_uuid()::text; outbox_id text:=gen_random_uuid()::text; created_at timestamp without time zone:=transaction_timestamp();
BEGIN
  IF p_action !~ '^[A-Z0-9_]{1,120}$' OR p_entity_type NOT IN ('Licensee','User','Invite')
     OR (p_ip_hash IS NOT NULL AND p_ip_hash !~ '^([0-9a-f]{12}:)?[a-f0-9]{64}$')
     OR length(coalesce(p_user_agent,''))>512 THEN RAISE EXCEPTION 'SESSION_C_INVALID_AUDIT'; END IF;
  PERFORM set_config('app.admin_mutation_audit_id',audit_id,true),set_config('app.admin_mutation_outbox_id',outbox_id,true);
  INSERT INTO public."AuditLog" (id,"userId","orgId","licenseeId",action,"entityType","entityId",details,"ipHash","userAgent","createdAt")
  VALUES (audit_id,p_actor_id,p_organization_id,p_licensee_id,p_action,p_entity_type,p_entity_id,p_details,p_ip_hash,p_user_agent,created_at);
  INSERT INTO public."SecurityEventOutbox" (id,"eventType",payload,"requestId","organizationId","licenseeId","initiatingUserId","updatedAt")
  VALUES (outbox_id,'AUDIT_LOG',jsonb_build_object(
    'id',audit_id,'action',p_action,'entityType',p_entity_type,'entityId',p_entity_id,
    'userId',p_actor_id,'orgId',p_organization_id,'licenseeId',p_licensee_id,
    'details',p_details,'createdAt',created_at
  ),current_setting('app.request_id',true),p_organization_id,p_licensee_id,p_actor_id,created_at);
  RETURN audit_id;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.session_c_admin_command(
  p_capability text,p_purpose text,p_request_id text,p_command text,payload jsonb
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE
  actor record; target text; target_licensee text; target_org text; target_role text; new_user_id text;
  result jsonb; patch jsonb; hard_delete boolean; remaining record; affected integer:=0;
  idempotency_key text; key_hash text; request_hash text; prior record;
  audit_details jsonb:=coalesce(payload->'audit','{}'::jsonb); audit_action text; audit_entity text; audit_licensee text;
BEGIN
  IF jsonb_typeof(payload)<>'object' OR p_purpose IS DISTINCT FROM 'administration-'||p_command
     OR p_command NOT IN ('create-licensee','update-licensee','delete-licensee','create-user','update-user','delete-user','restore-manufacturer') THEN
    RAISE EXCEPTION 'SESSION_C_UNKNOWN_COMMAND' USING ERRCODE='42501';
  END IF;
  SELECT * INTO STRICT actor FROM app_rls.session_c_bind_admin(p_capability,p_purpose,p_request_id,p_command NOT LIKE '%licensee');

  IF p_command='create-licensee' THEN
    target:=payload->>'id'; idempotency_key:=NULLIF(btrim(payload->>'idempotencyKey'),'');
    IF target !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
       OR length(btrim(coalesce(payload->'licensee'->>'name',''))) NOT BETWEEN 2 AND 200
       OR upper(coalesce(payload->'licensee'->>'prefix','')) !~ '^[A-Z0-9]{1,5}$'
       OR lower(coalesce(payload->'admin'->>'email','')) !~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$'
       OR length(btrim(coalesce(payload->'admin'->>'name',''))) NOT BETWEEN 2 AND 120
       OR (NOT coalesce((payload->'admin'->>'sendInvite')::boolean,false) AND coalesce(payload->'admin'->>'passwordHash','') NOT LIKE '$argon2%') THEN
      RAISE EXCEPTION 'SESSION_C_INVALID_INPUT';
    END IF;
    PERFORM app_rls.session_c_set_target(target,target,NULL,lower(payload->'admin'->>'email'),upper(payload->'licensee'->>'prefix'));
    IF idempotency_key IS NOT NULL THEN
      key_hash:=encode(sha256(convert_to(actor."userId"||'|'||p_purpose||'|'||idempotency_key,'UTF8')),'hex');
      request_hash:=encode(sha256(convert_to((payload-'idempotencyKey'-'id'-'audit')::text,'UTF8')),'hex');
      PERFORM set_config('app.admin_mutation_idempotency_hash',key_hash,true),pg_advisory_xact_lock(hashtextextended(key_hash,0));
      SELECT "requestHash","completedAt","responsePayload" INTO prior FROM public."ActionIdempotencyKey" WHERE "keyHash"=key_hash FOR UPDATE;
      IF FOUND THEN
        IF prior."requestHash" IS DISTINCT FROM request_hash THEN RAISE EXCEPTION 'SESSION_C_IDEMPOTENCY_CONFLICT'; END IF;
        IF prior."completedAt" IS NULL THEN RAISE EXCEPTION 'SESSION_C_IDEMPOTENCY_IN_PROGRESS'; END IF;
        RETURN coalesce(prior."responsePayload",'{}'::jsonb)||'{"replayed":true}'::jsonb;
      END IF;
      INSERT INTO public."ActionIdempotencyKey" (id,"keyHash",action,scope,"requestHash","expiresAt")
      VALUES (gen_random_uuid()::text,key_hash,'licensee.create',actor."userId",request_hash,transaction_timestamp()+interval '30 minutes');
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(upper(payload->'licensee'->>'prefix'),0));
    IF EXISTS (SELECT 1 FROM public."Licensee" WHERE prefix=upper(payload->'licensee'->>'prefix'))
       OR EXISTS (SELECT 1 FROM public."User" WHERE email=lower(payload->'admin'->>'email')) THEN
      RAISE EXCEPTION 'SESSION_C_DUPLICATE_LICENSEE_OR_ADMIN';
    END IF;
    INSERT INTO public."Organization" (id,name,"isActive","updatedAt") VALUES
      (target,payload->'licensee'->>'name',coalesce((payload->'licensee'->>'isActive')::boolean,true),transaction_timestamp());
    INSERT INTO public."Licensee" (id,"orgId",name,prefix,description,"brandName",location,website,"supportEmail","supportPhone","isActive","updatedAt") VALUES
      (target,target,payload->'licensee'->>'name',upper(payload->'licensee'->>'prefix'),payload->'licensee'->>'description',payload->'licensee'->>'brandName',
       payload->'licensee'->>'location',payload->'licensee'->>'website',payload->'licensee'->>'supportEmail',payload->'licensee'->>'supportPhone',
       coalesce((payload->'licensee'->>'isActive')::boolean,true),transaction_timestamp());
    IF NOT coalesce((payload->'admin'->>'sendInvite')::boolean,false) THEN
      new_user_id:=gen_random_uuid()::text; PERFORM app_rls.session_c_set_target(target,target,new_user_id,lower(payload->'admin'->>'email'),upper(payload->'licensee'->>'prefix'));
      INSERT INTO public."User" (id,email,"passwordHash",name,role,"orgId","licenseeId",status,"isActive","emailVerifiedAt","updatedAt") VALUES
        (new_user_id,lower(payload->'admin'->>'email'),payload->'admin'->>'passwordHash',payload->'admin'->>'name','LICENSEE_ADMIN'::public."UserRole",
         target,target,'ACTIVE'::public."UserStatus",true,transaction_timestamp(),transaction_timestamp());
    END IF;
    SELECT jsonb_build_object('licensee',jsonb_build_object(
      'id',l.id,'orgId',l."orgId",'name',l.name,'prefix',l.prefix,'description',l.description,
      'brandName',l."brandName",'location',l.location,'website',l.website,'supportEmail',l."supportEmail",
      'supportPhone',l."supportPhone",'metadata',l.metadata,'isActive',l."isActive",
      'suspendedAt',l."suspendedAt",'suspendedReason',l."suspendedReason",
      'createdAt',l."createdAt",'updatedAt',l."updatedAt"
    ),'adminUser',(
      SELECT app_rls.session_c_user_projection(u.id) FROM public."User" u WHERE u."licenseeId"=target AND u.role='LICENSEE_ADMIN'::public."UserRole" LIMIT 1
    ),'replayed',false) INTO result FROM public."Licensee" l WHERE l.id=target;
    PERFORM app_rls.session_c_write_audit(actor."userId",target,target,
      CASE WHEN coalesce((payload->'admin'->>'sendInvite')::boolean,false) THEN 'CREATE_LICENSEE_WITH_ADMIN_INVITE' ELSE 'CREATE_LICENSEE_WITH_ADMIN' END,
      'Licensee',target,jsonb_build_object('workflowId','workflow-http-backend-src-controllers-licensee-controller-ts-create-licensee','requestId',p_request_id,
        'purposeCode',p_purpose,'licenseeName',payload->'licensee'->>'name','prefix',upper(payload->'licensee'->>'prefix'),
        'adminEmail',audit_details->>'adminEmail','sendInvite',coalesce((payload->'admin'->>'sendInvite')::boolean,false)),
      audit_details->>'ipHash',audit_details->>'userAgent');
    IF key_hash IS NOT NULL THEN UPDATE public."ActionIdempotencyKey" SET "statusCode"=201,"responsePayload"=result,"completedAt"=transaction_timestamp() WHERE "keyHash"=key_hash; END IF;
    RETURN result;
  END IF;

  target:=payload->>'id';
  IF target !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' THEN RAISE EXCEPTION 'SESSION_C_INVALID_INPUT'; END IF;
  PERFORM app_rls.session_c_set_target(NULL,NULL,target,NULL,NULL),pg_advisory_xact_lock(hashtextextended(target,0));

  IF p_command IN ('update-licensee','delete-licensee') THEN
    SELECT id,"orgId" INTO target_licensee,target_org FROM public."Licensee" WHERE id=target FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'SESSION_C_LICENSEE_NOT_FOUND'; END IF;
    PERFORM app_rls.session_c_set_target(target_licensee,target_org,NULL,NULL,NULL);
    IF p_command='update-licensee' THEN
      patch:=coalesce(payload->'patch','{}'::jsonb);
      IF jsonb_typeof(patch)<>'object' OR EXISTS (SELECT 1 FROM jsonb_object_keys(patch) k WHERE k NOT IN ('name','description','brandName','location','website','supportEmail','supportPhone','isActive')) THEN RAISE EXCEPTION 'SESSION_C_INVALID_INPUT'; END IF;
      UPDATE public."Licensee" SET
        name=CASE WHEN patch?'name' THEN patch->>'name' ELSE name END,
        description=CASE WHEN patch?'description' THEN patch->>'description' ELSE description END,
        "brandName"=CASE WHEN patch?'brandName' THEN patch->>'brandName' ELSE "brandName" END,
        location=CASE WHEN patch?'location' THEN patch->>'location' ELSE location END,
        website=CASE WHEN patch?'website' THEN patch->>'website' ELSE website END,
        "supportEmail"=CASE WHEN patch?'supportEmail' THEN patch->>'supportEmail' ELSE "supportEmail" END,
        "supportPhone"=CASE WHEN patch?'supportPhone' THEN patch->>'supportPhone' ELSE "supportPhone" END,
        "isActive"=CASE WHEN patch?'isActive' THEN (patch->>'isActive')::boolean ELSE "isActive" END,"updatedAt"=transaction_timestamp()
      WHERE id=target;
      SELECT jsonb_build_object('licensee',jsonb_build_object(
        'id',l.id,'orgId',l."orgId",'name',l.name,'prefix',l.prefix,'description',l.description,
        'brandName',l."brandName",'location',l.location,'website',l.website,'supportEmail',l."supportEmail",
        'supportPhone',l."supportPhone",'metadata',l.metadata,'isActive',l."isActive",
        'suspendedAt',l."suspendedAt",'suspendedReason',l."suspendedReason",
        'createdAt',l."createdAt",'updatedAt',l."updatedAt"
      )) INTO result FROM public."Licensee" l WHERE l.id=target;
      PERFORM app_rls.session_c_write_audit(actor."userId",target_org,target,'UPDATE_LICENSEE','Licensee',target,
        jsonb_build_object('workflowId','workflow-http-backend-src-controllers-licensee-controller-ts-update-licensee','requestId',p_request_id,'purposeCode',p_purpose,'changed',coalesce(audit_details->'changed','[]'::jsonb)),audit_details->>'ipHash',audit_details->>'userAgent');
      RETURN result;
    END IF;
    IF EXISTS (SELECT 1 FROM public."User" WHERE "licenseeId"=target) OR EXISTS (SELECT 1 FROM public."Batch" WHERE "licenseeId"=target)
       OR EXISTS (SELECT 1 FROM public."QRRange" WHERE "licenseeId"=target) OR EXISTS (SELECT 1 FROM public."QRCode" WHERE "licenseeId"=target) THEN
      RAISE EXCEPTION 'SESSION_C_LICENSEE_LINKED_DATA';
    END IF;
    DELETE FROM public."Licensee" WHERE id=target;
    PERFORM app_rls.session_c_write_audit(actor."userId",target_org,NULL,'HARD_DELETE_LICENSEE','Licensee',target,
      jsonb_build_object('workflowId','workflow-http-backend-src-controllers-licensee-controller-ts-delete-licensee','requestId',p_request_id,'purposeCode',p_purpose),audit_details->>'ipHash',audit_details->>'userAgent');
    RETURN jsonb_build_object('licenseeId',target_licensee,'organizationId',target_org);
  END IF;

  IF p_command='create-user' THEN
    target_licensee:=payload->>'licenseeId'; target_role:=payload->>'role'; new_user_id:=gen_random_uuid()::text;
    IF target_licensee !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
       OR target_role NOT IN ('LICENSEE_ADMIN','MANUFACTURER_ADMIN') OR lower(coalesce(payload->>'email','')) !~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$'
       OR coalesce(payload->>'passwordHash','') NOT LIKE '$argon2%' THEN RAISE EXCEPTION 'SESSION_C_INVALID_INPUT'; END IF;
    IF actor.role='LICENSEE_ADMIN' AND (actor."licenseeId" IS DISTINCT FROM target_licensee OR target_role<>'MANUFACTURER_ADMIN') THEN RAISE EXCEPTION 'SESSION_C_FOREIGN_SCOPE'; END IF;
    PERFORM app_rls.session_c_set_target(target_licensee,NULL,new_user_id,lower(payload->>'email'),NULL),
            pg_advisory_xact_lock(hashtextextended(target_licensee,0));
    SELECT l."orgId" INTO target_org FROM public."Licensee" l
      WHERE l.id=target_licensee AND l."isActive" AND l."suspendedAt" IS NULL;
    IF NOT FOUND THEN RAISE EXCEPTION 'SESSION_C_LICENSEE_NOT_FOUND'; END IF;
    IF actor.role='LICENSEE_ADMIN' AND actor."organizationId" IS DISTINCT FROM target_org THEN RAISE EXCEPTION 'SESSION_C_FOREIGN_SCOPE'; END IF;
    PERFORM app_rls.session_c_set_target(target_licensee,target_org,new_user_id,lower(payload->>'email'),NULL);
    IF NOT EXISTS (SELECT 1 FROM public."Organization" o WHERE o.id=target_org AND o."isActive") THEN
      RAISE EXCEPTION 'SESSION_C_LICENSEE_NOT_FOUND';
    END IF;
    BEGIN
      INSERT INTO public."User" (id,email,"passwordHash",name,role,"orgId","licenseeId",location,website,status,"isActive","emailVerifiedAt","updatedAt") VALUES
        (new_user_id,lower(payload->>'email'),payload->>'passwordHash',payload->>'name',target_role::public."UserRole",target_org,target_licensee,
         payload->>'location',payload->>'website','ACTIVE'::public."UserStatus",true,transaction_timestamp(),transaction_timestamp());
    EXCEPTION WHEN unique_violation THEN RAISE EXCEPTION 'SESSION_C_DUPLICATE_USER'; END;
    IF target_role='MANUFACTURER_ADMIN' THEN INSERT INTO public."ManufacturerLicenseeLink" ("manufacturerId","licenseeId","isPrimary","updatedAt") VALUES (new_user_id,target_licensee,true,transaction_timestamp()); END IF;
    result:=jsonb_build_object('user',app_rls.session_c_user_projection(new_user_id),'licenseeId',target_licensee,'organizationId',target_org);
    PERFORM app_rls.session_c_write_audit(actor."userId",target_org,target_licensee,'CREATE_USER','User',new_user_id,
      jsonb_build_object('workflowId','workflow-http-backend-src-controllers-user-controller-ts-create-user','requestId',p_request_id,'purposeCode',p_purpose,'role',target_role),audit_details->>'ipHash',audit_details->>'userAgent');
    RETURN result;
  END IF;

  SELECT u."licenseeId",u."orgId",u.role::text INTO target_licensee,target_org,target_role FROM public."User" u WHERE u.id=target FOR UPDATE;
  IF NOT FOUND OR target_role<>'MANUFACTURER_ADMIN' OR target=actor."userId" THEN RAISE EXCEPTION 'SESSION_C_USER_NOT_FOUND'; END IF;
  PERFORM app_rls.session_c_set_target(target_licensee,target_org,target,NULL,NULL);
  IF actor.role='LICENSEE_ADMIN' AND NOT EXISTS (SELECT 1 FROM public."ManufacturerLicenseeLink" ml WHERE ml."manufacturerId"=target AND ml."licenseeId"=actor."licenseeId") THEN RAISE EXCEPTION 'SESSION_C_FOREIGN_SCOPE'; END IF;

  IF p_command='update-user' THEN
    patch:=coalesce(payload->'patch','{}'::jsonb);
    IF jsonb_typeof(patch)<>'object' OR EXISTS (SELECT 1 FROM jsonb_object_keys(patch) k WHERE k NOT IN ('name','email','passwordHash','isActive','licenseeId','location','website'))
       OR (patch?'passwordHash' AND patch->>'passwordHash' NOT LIKE '$argon2%') THEN RAISE EXCEPTION 'SESSION_C_INVALID_INPUT'; END IF;
    IF patch?'licenseeId' THEN
      IF actor.role NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') THEN RAISE EXCEPTION 'SESSION_C_WRONG_ROLE'; END IF;
      target_licensee:=patch->>'licenseeId'; PERFORM app_rls.session_c_set_target(target_licensee,NULL,target,NULL,NULL);
      SELECT l."orgId" INTO target_org FROM public."Licensee" l JOIN public."Organization" o ON o.id=l."orgId" WHERE l.id=target_licensee AND l."isActive" AND l."suspendedAt" IS NULL AND o."isActive";
      IF NOT FOUND THEN RAISE EXCEPTION 'SESSION_C_LICENSEE_NOT_FOUND'; END IF;
      PERFORM app_rls.session_c_set_target(target_licensee,target_org,target,NULL,NULL);
      UPDATE public."ManufacturerLicenseeLink" SET "isPrimary"=false,"updatedAt"=transaction_timestamp() WHERE "manufacturerId"=target AND "isPrimary";
      INSERT INTO public."ManufacturerLicenseeLink" ("manufacturerId","licenseeId","isPrimary","updatedAt") VALUES (target,target_licensee,true,transaction_timestamp())
      ON CONFLICT ("manufacturerId","licenseeId") DO UPDATE SET "isPrimary"=true,"updatedAt"=transaction_timestamp();
    END IF;
    UPDATE public."User" SET name=CASE WHEN patch?'name' THEN patch->>'name' ELSE name END,email=CASE WHEN patch?'email' THEN lower(patch->>'email') ELSE email END,
      "passwordHash"=CASE WHEN patch?'passwordHash' THEN patch->>'passwordHash' ELSE "passwordHash" END,location=CASE WHEN patch?'location' THEN patch->>'location' ELSE location END,
      website=CASE WHEN patch?'website' THEN patch->>'website' ELSE website END,"licenseeId"=target_licensee,"orgId"=target_org,
      "isActive"=CASE WHEN patch?'isActive' THEN (patch->>'isActive')::boolean ELSE "isActive" END,
      status=CASE WHEN patch?'isActive' AND NOT (patch->>'isActive')::boolean THEN 'DISABLED'::public."UserStatus" WHEN patch?'isActive' THEN 'ACTIVE'::public."UserStatus" ELSE status END,
      "deletedAt"=CASE WHEN patch?'isActive' AND NOT (patch->>'isActive')::boolean THEN transaction_timestamp() WHEN patch?'isActive' THEN NULL ELSE "deletedAt" END,
      "disabledAt"=CASE WHEN patch?'isActive' AND NOT (patch->>'isActive')::boolean THEN transaction_timestamp() WHEN patch?'isActive' THEN NULL ELSE "disabledAt" END,"updatedAt"=transaction_timestamp() WHERE id=target;
    IF (patch?'isActive' AND NOT (patch->>'isActive')::boolean) OR patch?'passwordHash' THEN
      UPDATE public."RefreshToken" SET "revokedAt"=transaction_timestamp(),"revokedReason"='ACCOUNT_SECURITY_CHANGE',
        "sessionCapabilityRevokedAt"=coalesce("sessionCapabilityRevokedAt",transaction_timestamp()),"sessionCapabilityRevokedReason"=coalesce("sessionCapabilityRevokedReason",'ACCOUNT_SECURITY_CHANGE')
      WHERE "userId"=target AND "revokedAt" IS NULL;
    END IF;
    result:=jsonb_build_object('user',app_rls.session_c_user_projection(target),'licenseeId',target_licensee,'organizationId',target_org,'scopedLicenseeId',CASE WHEN actor.role='LICENSEE_ADMIN' THEN actor."licenseeId" ELSE target_licensee END);
    PERFORM app_rls.session_c_write_audit(actor."userId",target_org,target_licensee,'UPDATE_USER','User',target,
      jsonb_build_object('workflowId','workflow-http-backend-src-controllers-user-controller-ts-update-user','requestId',p_request_id,'purposeCode',p_purpose,'changed',coalesce(audit_details->'changed','[]'::jsonb)),audit_details->>'ipHash',audit_details->>'userAgent');
    RETURN result;
  END IF;

  IF p_command='delete-user' THEN
    hard_delete:=coalesce((payload->>'hard')::boolean,false);
    IF hard_delete THEN
      IF actor.role NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') THEN RAISE EXCEPTION 'SESSION_C_WRONG_ROLE'; END IF;
      UPDATE public."Batch" SET "manufacturerId"=NULL,"updatedAt"=transaction_timestamp() WHERE "manufacturerId"=target; GET DIAGNOSTICS affected=ROW_COUNT;
      DELETE FROM public."User" WHERE id=target; audit_action:='HARD_DELETE_MANUFACTURER'; audit_licensee:=target_licensee;
      result:=jsonb_build_object('deletedId',target,'hard',true,'unassignedBatches',affected);
    ELSIF actor.role='LICENSEE_ADMIN' THEN
      target_licensee:=actor."licenseeId"; target_org:=actor."organizationId"; PERFORM app_rls.session_c_set_target(target_licensee,target_org,target,NULL,NULL);
      IF EXISTS (SELECT 1 FROM public."Batch" WHERE "manufacturerId"=target AND "licenseeId"=target_licensee) THEN RAISE EXCEPTION 'SESSION_C_ASSIGNED_BATCHES'; END IF;
      DELETE FROM public."ManufacturerLicenseeLink" WHERE "manufacturerId"=target AND "licenseeId"=target_licensee;
      SELECT "licenseeId","isPrimary" INTO remaining FROM public."ManufacturerLicenseeLink" WHERE "manufacturerId"=target ORDER BY "isPrimary" DESC,"createdAt" LIMIT 1 FOR UPDATE;
      IF NOT FOUND THEN
        UPDATE public."User" SET "isActive"=false,status='DISABLED'::public."UserStatus","deletedAt"=transaction_timestamp(),"disabledAt"=transaction_timestamp(),"licenseeId"=NULL,"orgId"=NULL,"updatedAt"=transaction_timestamp() WHERE id=target;
        UPDATE public."RefreshToken" SET "revokedAt"=transaction_timestamp(),"revokedReason"='ACCOUNT_DISABLED',"sessionCapabilityRevokedAt"=coalesce("sessionCapabilityRevokedAt",transaction_timestamp()),"sessionCapabilityRevokedReason"=coalesce("sessionCapabilityRevokedReason",'ACCOUNT_DISABLED') WHERE "userId"=target AND "revokedAt" IS NULL;
      ELSE
        UPDATE public."ManufacturerLicenseeLink" SET "isPrimary"=("licenseeId"=remaining."licenseeId"),"updatedAt"=transaction_timestamp() WHERE "manufacturerId"=target;
        UPDATE public."User" SET "licenseeId"=remaining."licenseeId","orgId"=(SELECT "orgId" FROM public."Licensee" WHERE id=remaining."licenseeId"),"updatedAt"=transaction_timestamp() WHERE id=target;
      END IF;
      audit_action:='UNLINK_MANUFACTURER_FROM_LICENSEE'; audit_licensee:=target_licensee;
      result:=jsonb_build_object('deletedId',target,'hard',false,'unlinkedLicenseeId',target_licensee);
    ELSE
      UPDATE public."User" SET "isActive"=false,status='DISABLED'::public."UserStatus","deletedAt"=transaction_timestamp(),"disabledAt"=transaction_timestamp(),"updatedAt"=transaction_timestamp() WHERE id=target;
      UPDATE public."RefreshToken" SET "revokedAt"=transaction_timestamp(),"revokedReason"='ACCOUNT_DISABLED',"sessionCapabilityRevokedAt"=coalesce("sessionCapabilityRevokedAt",transaction_timestamp()),"sessionCapabilityRevokedReason"=coalesce("sessionCapabilityRevokedReason",'ACCOUNT_DISABLED') WHERE "userId"=target AND "revokedAt" IS NULL;
      audit_action:='SOFT_DELETE_MANUFACTURER'; audit_licensee:=target_licensee;
      result:=jsonb_build_object('deletedId',target,'hard',false,'id',target,'isActive',false,'deletedAt',transaction_timestamp());
    END IF;
    PERFORM app_rls.session_c_write_audit(actor."userId",target_org,audit_licensee,audit_action,'User',target,
      jsonb_build_object('workflowId','workflow-http-backend-src-controllers-user-controller-ts-delete-user','requestId',p_request_id,'purposeCode',p_purpose,'hard',hard_delete),audit_details->>'ipHash',audit_details->>'userAgent');
    RETURN jsonb_build_object('licenseeId',audit_licensee,'organizationId',target_org,'auditAction',audit_action,'response',result);
  END IF;

  IF p_command='restore-manufacturer' THEN
    IF actor.role='LICENSEE_ADMIN' THEN target_licensee:=actor."licenseeId"; target_org:=actor."organizationId"; END IF;
    IF target_licensee IS NULL OR NOT EXISTS (SELECT 1 FROM public."Licensee" l JOIN public."Organization" o ON o.id=l."orgId" WHERE l.id=target_licensee AND l."orgId"=target_org AND l."isActive" AND l."suspendedAt" IS NULL AND o."isActive") THEN RAISE EXCEPTION 'SESSION_C_FOREIGN_SCOPE'; END IF;
    PERFORM app_rls.session_c_set_target(target_licensee,target_org,target,NULL,NULL);
    INSERT INTO public."ManufacturerLicenseeLink" ("manufacturerId","licenseeId","isPrimary","updatedAt")
    SELECT target,target_licensee,NOT EXISTS (
      SELECT 1 FROM public."ManufacturerLicenseeLink" ml WHERE ml."manufacturerId"=target AND ml."isPrimary"
    ),transaction_timestamp()
    ON CONFLICT ("manufacturerId","licenseeId") DO UPDATE SET "updatedAt"=transaction_timestamp();
    UPDATE public."User" SET "isActive"=true,status='ACTIVE'::public."UserStatus","deletedAt"=NULL,"disabledAt"=NULL,"licenseeId"=target_licensee,"orgId"=target_org,"updatedAt"=transaction_timestamp() WHERE id=target;
    result:=jsonb_build_object('id',target,'isActive',true,'deletedAt',NULL);
    PERFORM app_rls.session_c_write_audit(actor."userId",target_org,target_licensee,'RESTORE_MANUFACTURER','User',target,
      jsonb_build_object('workflowId','workflow-http-backend-src-controllers-user-controller-ts-restore-manufacturer','requestId',p_request_id,'purposeCode',p_purpose,'licenseeId',target_licensee),audit_details->>'ipHash',audit_details->>'userAgent');
    RETURN jsonb_build_object('licenseeId',target_licensee,'organizationId',target_org,'auditAction','RESTORE_MANUFACTURER','response',result);
  END IF;
  RAISE EXCEPTION 'SESSION_C_UNKNOWN_COMMAND';
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.prepare_invitation(
  p_capability text,p_actor_user_id text,p_actor_session_id text,p_request_id text,p_purpose text,
  p_requested_email text,p_requested_name text,p_requested_role text,p_requested_licensee_id text,
  p_requested_manufacturer_id text,p_allow_existing_invited_user boolean,p_require_existing_user boolean,
  p_token_hash text,p_created_at timestamp without time zone,p_expires_at timestamp without time zone,
  p_ip_hash text,p_user_agent text
) RETURNS TABLE(
  "actorDisplayName" text,"actorEmail" text,"actorUserId" text,"inviteEmail" text,
  "inviteExpiresAt" timestamp without time zone,"inviteId" text,"inviteRole" text,
  "licenseeName" text,"linkAction" text,"userEmail" text,"userId" text,
  "userLicenseeId" text,"userName" text,"userOrganizationId" text,"userRole" text,
  "userStatus" text,"workspaceOrganizationId" text
) LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE
  actor record; target_user record; target_licensee record; prior record;
  requested_email text:=lower(btrim(coalesce(p_requested_email,'')));
  user_name text:=btrim(coalesce(p_requested_name,''));
  organization_id text; invite_id text; target_user_id text; link_action text; licensee_name text;
  key_hash text; request_hash text; response jsonb; inserted integer;
BEGIN
  SELECT * INTO actor FROM app_rls.session_c_bind_admin(p_capability,p_purpose,p_request_id,true);
  IF actor."userId" IS DISTINCT FROM p_actor_user_id OR actor."sessionId" IS DISTINCT FROM p_actor_session_id
     OR p_requested_role NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN','LICENSEE_ADMIN','MANUFACTURER_ADMIN')
     OR user_name='' OR length(user_name)>120 OR user_name~'[[:cntrl:]]'
     OR (requested_email<>'' AND (length(requested_email)>320 OR requested_email!~'^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$'))
     OR (NOT p_require_existing_user AND requested_email='')
     OR p_token_hash!~'^([0-9a-f]{12}:)?[0-9a-f]{64}$'
     OR p_created_at IS NULL OR abs(extract(epoch FROM (p_created_at-(clock_timestamp() AT TIME ZONE 'UTC'))))>300
     OR p_expires_at<=p_created_at OR p_expires_at>p_created_at+interval '24 hours'
     OR (p_ip_hash IS NOT NULL AND p_ip_hash!~'^([0-9a-f]{12}:)?[0-9a-f]{64}$')
     OR length(coalesce(p_user_agent,''))>512 OR coalesce(p_user_agent,'')~'[[:cntrl:]]'
  THEN RAISE EXCEPTION 'SESSION_C_INVITE_INPUT_DENIED' USING ERRCODE='42501'; END IF;

  IF p_requested_licensee_id IS NULL THEN
    IF p_requested_role NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') OR p_requested_manufacturer_id IS NOT NULL THEN
      RAISE EXCEPTION 'SESSION_C_INVITE_SCOPE_DENIED' USING ERRCODE='42501';
    END IF;
    organization_id:='00000000-0000-0000-0000-000000000000';
    PERFORM app_rls.session_c_set_target(NULL,organization_id,NULL,requested_email,NULL);
    INSERT INTO public."Organization" (id,name,"isActive","updatedAt") VALUES
      (organization_id,'Platform',true,transaction_timestamp()) ON CONFLICT (id) DO NOTHING;
    IF NOT EXISTS (SELECT 1 FROM public."Organization" WHERE id=organization_id AND "isActive") THEN
      RAISE EXCEPTION 'SESSION_C_INVITE_SCOPE_DENIED' USING ERRCODE='42501';
    END IF;
  ELSE
    PERFORM app_rls.session_c_set_target(p_requested_licensee_id,NULL,NULL,requested_email,NULL),
            pg_advisory_xact_lock(hashtextextended(p_requested_licensee_id,0));
    SELECT l.id,l."orgId",l.name INTO target_licensee FROM public."Licensee" l
      WHERE l.id=p_requested_licensee_id AND l."isActive" AND l."suspendedAt" IS NULL;
    IF NOT FOUND THEN RAISE EXCEPTION 'SESSION_C_INVITE_SCOPE_DENIED' USING ERRCODE='42501'; END IF;
    organization_id:=target_licensee."orgId";
    licensee_name:=target_licensee.name;
    PERFORM app_rls.session_c_set_target(p_requested_licensee_id,organization_id,NULL,requested_email,NULL);
    IF NOT EXISTS (SELECT 1 FROM public."Organization" o WHERE o.id=organization_id AND o."isActive") THEN
      RAISE EXCEPTION 'SESSION_C_INVITE_SCOPE_DENIED' USING ERRCODE='42501';
    END IF;
  END IF;

  IF p_purpose='licensee-admin-invite-resend' THEN
    IF actor.role NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') OR NOT p_allow_existing_invited_user
       OR NOT p_require_existing_user OR p_requested_licensee_id IS NULL
       OR p_requested_role<>'LICENSEE_ADMIN' OR p_requested_manufacturer_id IS NOT NULL THEN
      RAISE EXCEPTION 'SESSION_C_INVITE_SCOPE_DENIED' USING ERRCODE='42501';
    END IF;
  ELSIF actor.role='LICENSEE_ADMIN' THEN
    IF actor."licenseeId" IS DISTINCT FROM p_requested_licensee_id
       OR actor."organizationId" IS DISTINCT FROM organization_id OR p_requested_role<>'MANUFACTURER_ADMIN' THEN
      RAISE EXCEPTION 'SESSION_C_INVITE_SCOPE_DENIED' USING ERRCODE='42501';
    END IF;
  END IF;
  IF p_requested_manufacturer_id IS NOT NULL AND (p_requested_role<>'MANUFACTURER_ADMIN' OR NOT p_allow_existing_invited_user) THEN
    RAISE EXCEPTION 'SESSION_C_INVITE_SCOPE_DENIED' USING ERRCODE='42501';
  END IF;

  PERFORM pg_advisory_xact_lock(hashtextextended(coalesce(p_requested_licensee_id,'platform')||':'||coalesce(nullif(requested_email,''),p_requested_role),0));
  key_hash:=encode(sha256(convert_to('invite:'||actor."userId"||':'||p_request_id,'UTF8')),'hex');
  request_hash:=encode(sha256(convert_to(concat_ws('|',p_purpose,requested_email,user_name,p_requested_role,coalesce(p_requested_licensee_id,''),coalesce(p_requested_manufacturer_id,''),p_token_hash),'UTF8')),'hex');
  PERFORM set_config('app.admin_mutation_idempotency_hash',key_hash,true);
  SELECT "requestHash","completedAt","responsePayload" INTO prior FROM public."ActionIdempotencyKey" WHERE "keyHash"=key_hash FOR UPDATE;
  IF FOUND THEN
    IF prior."requestHash" IS DISTINCT FROM request_hash OR prior."completedAt" IS NULL THEN
      RAISE EXCEPTION 'SESSION_C_INVITE_REPLAY_DENIED' USING ERRCODE='42501';
    END IF;
    response:=prior."responsePayload";
    RETURN QUERY SELECT response->>'actorDisplayName',response->>'actorEmail',response->>'actorUserId',response->>'inviteEmail',
      (response->>'inviteExpiresAt')::timestamp,response->>'inviteId',response->>'inviteRole',response->>'licenseeName',
      response->>'linkAction',response->>'userEmail',response->>'userId',response->>'userLicenseeId',response->>'userName',
      response->>'userOrganizationId',response->>'userRole',response->>'userStatus',response->>'workspaceOrganizationId';
    RETURN;
  END IF;
  INSERT INTO public."ActionIdempotencyKey" (id,"keyHash",action,scope,"requestHash","expiresAt") VALUES
    (gen_random_uuid()::text,key_hash,'invitation.prepare',actor."userId",request_hash,transaction_timestamp()+interval '24 hours');

  IF p_require_existing_user THEN
    SELECT u.id,u.email,u.name,u.role,u."orgId",u."licenseeId",u.status,u."isActive",u."disabledAt",u."deletedAt",u."passwordHash"
      INTO target_user FROM public."User" u WHERE u."licenseeId"=p_requested_licensee_id
      AND u.role='LICENSEE_ADMIN'::public."UserRole" AND (requested_email='' OR u.email=requested_email);
    IF NOT FOUND OR target_user.status<>'INVITED'::public."UserStatus" OR NOT target_user."isActive"
       OR target_user."passwordHash" IS NOT NULL OR target_user."disabledAt" IS NOT NULL OR target_user."deletedAt" IS NOT NULL THEN
      RAISE EXCEPTION 'SESSION_C_INVITE_TARGET_DENIED' USING ERRCODE='42501';
    END IF;
    requested_email:=target_user.email;
  ELSIF p_requested_manufacturer_id IS NOT NULL THEN
    PERFORM app_rls.session_c_set_target(p_requested_licensee_id,organization_id,p_requested_manufacturer_id,requested_email,NULL);
    SELECT u.id,u.email,u.name,u.role,u."orgId",u."licenseeId",u.status,u."isActive",u."disabledAt",u."deletedAt",u."passwordHash"
      INTO target_user FROM public."User" u WHERE u.id=p_requested_manufacturer_id AND u.email=requested_email
      AND u.role='MANUFACTURER_ADMIN'::public."UserRole" AND u.status='ACTIVE'::public."UserStatus"
      AND u."isActive" AND u."disabledAt" IS NULL AND u."deletedAt" IS NULL;
    IF NOT FOUND THEN RAISE EXCEPTION 'SESSION_C_INVITE_TARGET_DENIED' USING ERRCODE='42501'; END IF;
  ELSE
    SELECT u.id,u.email,u.name,u.role,u."orgId",u."licenseeId",u.status,u."isActive",u."disabledAt",u."deletedAt",u."passwordHash"
      INTO target_user FROM public."User" u WHERE u.email=requested_email;
    IF FOUND THEN
      IF NOT p_allow_existing_invited_user THEN RAISE EXCEPTION 'SESSION_C_INVITE_ACCOUNT_EXISTS' USING ERRCODE='23505'; END IF;
      IF target_user.role='MANUFACTURER_ADMIN'::public."UserRole" AND p_requested_role='MANUFACTURER_ADMIN'
         AND target_user.status='ACTIVE'::public."UserStatus" AND target_user."isActive"
         AND target_user."disabledAt" IS NULL AND target_user."deletedAt" IS NULL THEN NULL;
      ELSIF target_user.role::text IS DISTINCT FROM p_requested_role OR target_user.status<>'INVITED'::public."UserStatus"
         OR NOT target_user."isActive" OR target_user."passwordHash" IS NOT NULL OR target_user."disabledAt" IS NOT NULL
         OR target_user."deletedAt" IS NOT NULL OR target_user."licenseeId" IS DISTINCT FROM p_requested_licensee_id
         OR target_user."orgId" IS DISTINCT FROM (CASE WHEN p_requested_role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') THEN NULL ELSE organization_id END) THEN
        RAISE EXCEPTION 'SESSION_C_INVITE_ACCOUNT_EXISTS' USING ERRCODE='23505';
      END IF;
    ELSE
      target_user_id:=gen_random_uuid()::text;
      PERFORM app_rls.session_c_set_target(p_requested_licensee_id,organization_id,target_user_id,requested_email,NULL);
      INSERT INTO public."User" (id,email,name,role,"orgId","licenseeId",status,"isActive","updatedAt") VALUES
        (target_user_id,requested_email,user_name,p_requested_role::public."UserRole",
         CASE WHEN p_requested_role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') THEN NULL ELSE organization_id END,
         p_requested_licensee_id,'INVITED'::public."UserStatus",true,transaction_timestamp());
      SELECT u.id,u.email,u.name,u.role,u."orgId",u."licenseeId",u.status,u."isActive",u."disabledAt",u."deletedAt",u."passwordHash"
        INTO STRICT target_user FROM public."User" u WHERE u.id=target_user_id;
    END IF;
  END IF;
  target_user_id:=target_user.id;
  PERFORM app_rls.session_c_set_target(p_requested_licensee_id,organization_id,target_user_id,requested_email,NULL);

  IF target_user.role='MANUFACTURER_ADMIN'::public."UserRole" THEN
    INSERT INTO public."ManufacturerLicenseeLink" ("manufacturerId","licenseeId","isPrimary","updatedAt")
      SELECT target_user.id,p_requested_licensee_id,NOT EXISTS (SELECT 1 FROM public."ManufacturerLicenseeLink" WHERE "manufacturerId"=target_user.id AND "isPrimary"),transaction_timestamp()
      ON CONFLICT ("manufacturerId","licenseeId") DO NOTHING;
    GET DIAGNOSTICS inserted=ROW_COUNT;
    IF target_user.status='ACTIVE'::public."UserStatus" THEN link_action:=CASE WHEN inserted=1 THEN 'LINKED_EXISTING' ELSE 'ALREADY_LINKED' END; END IF;
  END IF;

  IF link_action IS NULL THEN
    UPDATE public."Invite" invite SET "usedAt"=transaction_timestamp() WHERE invite.email=target_user.email AND invite."licenseeId" IS NOT DISTINCT FROM p_requested_licensee_id AND invite."usedAt" IS NULL;
    invite_id:=gen_random_uuid()::text;
    PERFORM set_config('app.admin_mutation_invite_id',invite_id,true);
    INSERT INTO public."Invite" (id,"orgId","licenseeId",email,role,"manufacturerId","tokenHash","expiresAt","createdByUserId","createdAt") VALUES
      (invite_id,organization_id,p_requested_licensee_id,requested_email,p_requested_role::public."UserRole",p_requested_manufacturer_id,p_token_hash,p_expires_at,actor."userId",p_created_at);
  END IF;
  response:=jsonb_build_object('actorDisplayName',actor_user.name,'actorEmail',actor_user.email,'actorUserId',actor."userId",
    'inviteEmail',requested_email,'inviteExpiresAt',CASE WHEN invite_id IS NULL THEN NULL ELSE p_expires_at END,'inviteId',invite_id,
    'inviteRole',p_requested_role,'licenseeName',licensee_name,'linkAction',link_action,'userEmail',target_user.email,
    'userId',target_user.id,'userLicenseeId',target_user."licenseeId",'userName',target_user.name,
    'userOrganizationId',target_user."orgId",'userRole',target_user.role::text,'userStatus',target_user.status::text,
    'workspaceOrganizationId',organization_id)
  FROM public."User" actor_user WHERE actor_user.id=actor."userId";
  PERFORM app_rls.session_c_write_audit(actor."userId",organization_id,p_requested_licensee_id,
    CASE WHEN link_action IS NULL THEN 'AUTH_INVITE_CREATED' ELSE 'MANUFACTURER_LICENSEE_LINKED' END,
    CASE WHEN link_action IS NULL THEN 'Invite' ELSE 'User' END,coalesce(invite_id,target_user.id),
    jsonb_build_object('workflowId',CASE WHEN p_purpose='licensee-admin-invite-resend' THEN 'workflow-http-backend-src-controllers-licensee-invite-controller-ts-resend-licensee-admin-invite' ELSE 'workflow-http-backend-src-controllers-auth-controller-ts-invite' END,
      'requestId',p_request_id,'purposeCode',p_purpose,'targetUserId',target_user.id,'role',p_requested_role,'linkAction',link_action),p_ip_hash,p_user_agent);
  UPDATE public."ActionIdempotencyKey" SET "statusCode"=201,"responsePayload"=response,"completedAt"=transaction_timestamp() WHERE "keyHash"=key_hash;
  RETURN QUERY SELECT response->>'actorDisplayName',response->>'actorEmail',response->>'actorUserId',response->>'inviteEmail',
    (response->>'inviteExpiresAt')::timestamp,response->>'inviteId',response->>'inviteRole',response->>'licenseeName',
    response->>'linkAction',response->>'userEmail',response->>'userId',response->>'userLicenseeId',response->>'userName',
    response->>'userOrganizationId',response->>'userRole',response->>'userStatus',response->>'workspaceOrganizationId';
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.session_c_create_licensee(p_capability text,p_purpose text,p_request_id text,payload jsonb) RETURNS jsonb LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$ SELECT app_rls.session_c_admin_command($1,$2,$3,'create-licensee',$4) $fn$;
CREATE OR REPLACE FUNCTION app_rls.session_c_update_licensee(p_capability text,p_purpose text,p_request_id text,payload jsonb) RETURNS jsonb LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$ SELECT app_rls.session_c_admin_command($1,$2,$3,'update-licensee',$4) $fn$;
CREATE OR REPLACE FUNCTION app_rls.session_c_delete_licensee(p_capability text,p_purpose text,p_request_id text,payload jsonb) RETURNS jsonb LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$ SELECT app_rls.session_c_admin_command($1,$2,$3,'delete-licensee',$4) $fn$;
CREATE OR REPLACE FUNCTION app_rls.session_c_create_user(p_capability text,p_purpose text,p_request_id text,payload jsonb) RETURNS jsonb LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$ SELECT app_rls.session_c_admin_command($1,$2,$3,'create-user',$4) $fn$;
CREATE OR REPLACE FUNCTION app_rls.session_c_update_user(p_capability text,p_purpose text,p_request_id text,payload jsonb) RETURNS jsonb LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$ SELECT app_rls.session_c_admin_command($1,$2,$3,'update-user',$4) $fn$;
CREATE OR REPLACE FUNCTION app_rls.session_c_delete_user(p_capability text,p_purpose text,p_request_id text,payload jsonb) RETURNS jsonb LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$ SELECT app_rls.session_c_admin_command($1,$2,$3,'delete-user',$4) $fn$;
CREATE OR REPLACE FUNCTION app_rls.session_c_restore_manufacturer(p_capability text,p_purpose text,p_request_id text,payload jsonb) RETURNS jsonb LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$ SELECT app_rls.session_c_admin_command($1,$2,$3,'restore-manufacturer',$4) $fn$;

REVOKE ALL ON FUNCTION app_rls.session_c_bind_admin(text,text,text,boolean) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.session_c_set_target(text,text,text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.session_c_user_projection(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.session_c_write_audit(text,text,text,text,text,text,jsonb,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.session_c_admin_command(text,text,text,text,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.prepare_invitation(text,text,text,text,text,text,text,text,text,text,boolean,boolean,text,timestamp without time zone,timestamp without time zone,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.session_c_create_licensee(text,text,text,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.session_c_update_licensee(text,text,text,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.session_c_delete_licensee(text,text,text,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.session_c_create_user(text,text,text,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.session_c_update_user(text,text,text,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.session_c_delete_user(text,text,text,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.session_c_restore_manufacturer(text,text,text,jsonb) FROM PUBLIC;
