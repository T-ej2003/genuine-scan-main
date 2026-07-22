-- Reviewed production B01 pre-authentication boundaries. Bearer hashes and
-- normalized email addresses are selectors only; the locked token/account
-- relationship is the sole authority for every mutation.

CREATE OR REPLACE FUNCTION app_auth.b01_preauth_audit(
  p_action text, p_entity_type text, p_entity_id text, p_at timestamp without time zone, p_details jsonb DEFAULT '{}'::jsonb
) RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
BEGIN
  IF p_action NOT IN ('AUTH_PASSWORD_RESET_REQUESTED','AUTH_PASSWORD_RESET_COMPLETED','AUTH_EMAIL_VERIFIED','AUTH_EMAIL_CHANGE_CONFIRMED','AUTH_INVITE_ACCEPTED')
     OR current_setting('app.b01_preauth_user_id',true)='' THEN
    RAISE EXCEPTION 'B01_PREAUTH_AUDIT_DENIED' USING ERRCODE='42501';
  END IF;
  INSERT INTO public."AuditLogOutbox" (id,payload,"updatedAt") VALUES (
    gen_random_uuid()::text,
    jsonb_build_object(
      'userId',current_setting('app.b01_preauth_user_id',true),
      'orgId',nullif(current_setting('app.b01_preauth_org_id',true),''),
      'licenseeId',nullif(current_setting('app.b01_preauth_licensee_id',true),''),
      'action',p_action,'entityType',p_entity_type,'entityId',p_entity_id,
      'details',coalesce(p_details,'{}'::jsonb)
    ), p_at
  );
END
$fn$;

CREATE OR REPLACE FUNCTION app_auth.lookup_password_user(p_requested_email text)
RETURNS TABLE(
  "id" text,"email" text,"passwordHash" text,"name" text,"role" text,"licenseeId" text,"orgId" text,
  "status" text,"isActive" boolean,"disabledAt" timestamp without time zone,"deletedAt" timestamp without time zone,
  "failedLoginAttempts" integer,"lockedUntil" timestamp without time zone,"lastLoginAt" timestamp without time zone,
  "emailVerifiedAt" timestamp without time zone
) LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE candidate_count integer;
BEGIN
  IF p_requested_email IS NULL OR length(p_requested_email) NOT BETWEEN 3 AND 320
     OR p_requested_email IS DISTINCT FROM lower(btrim(p_requested_email))
     OR p_requested_email !~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$' THEN
    RAISE EXCEPTION 'B01_PASSWORD_LOOKUP_DENIED' USING ERRCODE='22023';
  END IF;
  PERFORM set_config('app.b01_preauth_operation','password-lookup',true),
          set_config('app.b01_preauth_email',p_requested_email,true),
          set_config('app.b01_preauth_hashes','',true),set_config('app.b01_preauth_token_id','',true),
          set_config('app.b01_preauth_user_id','',true),set_config('app.b01_preauth_org_id','',true),
          set_config('app.b01_preauth_licensee_id','',true),set_config('app.b01_preauth_pending_email','',true);
  SELECT count(*)::integer INTO candidate_count FROM public."User" u WHERE lower(u.email)=p_requested_email;
  IF candidate_count<>1 THEN RETURN; END IF;
  RETURN QUERY SELECT u.id,u.email,u."passwordHash",u.name,u.role::text,u."licenseeId",u."orgId",u.status::text,
    u."isActive",u."disabledAt",u."deletedAt",u."failedLoginAttempts",u."lockedUntil",u."lastLoginAt",u."emailVerifiedAt"
    FROM public."User" u WHERE lower(u.email)=p_requested_email;
END
$fn$;

CREATE OR REPLACE FUNCTION app_auth.record_password_failure(
  p_requested_email text,p_attempted_at timestamp without time zone,p_max_attempts integer,p_lockout_minutes integer
) RETURNS TABLE("failedLoginAttempts" integer,"lockedUntil" timestamp without time zone)
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE candidate_count integer;
BEGIN
  IF p_requested_email IS NULL OR length(p_requested_email) NOT BETWEEN 3 AND 320
     OR p_requested_email IS DISTINCT FROM lower(btrim(p_requested_email))
     OR p_requested_email !~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$'
     OR p_attempted_at IS NULL OR abs(extract(epoch FROM (p_attempted_at-(clock_timestamp() AT TIME ZONE 'UTC'))))>300
     OR p_max_attempts NOT BETWEEN 1 AND 100 OR p_lockout_minutes NOT BETWEEN 1 AND 1440 THEN
    RAISE EXCEPTION 'B01_PASSWORD_FAILURE_DENIED' USING ERRCODE='22023';
  END IF;
  PERFORM set_config('app.b01_preauth_operation','password-failure',true),
          set_config('app.b01_preauth_email',p_requested_email,true),
          set_config('app.b01_preauth_hashes','',true),set_config('app.b01_preauth_token_id','',true),
          set_config('app.b01_preauth_user_id','',true),set_config('app.b01_preauth_org_id','',true),
          set_config('app.b01_preauth_licensee_id','',true),set_config('app.b01_preauth_pending_email','',true);
  SELECT count(*)::integer INTO candidate_count FROM public."User" u WHERE lower(u.email)=p_requested_email;
  IF candidate_count<>1 THEN RETURN; END IF;
  RETURN QUERY
  UPDATE public."User" u SET
    "failedLoginAttempts"=u."failedLoginAttempts"+1,
    "lockedUntil"=CASE WHEN u."failedLoginAttempts"+1>=p_max_attempts
      THEN greatest(coalesce(u."lockedUntil",p_attempted_at),p_attempted_at+make_interval(mins=>p_lockout_minutes))
      ELSE u."lockedUntil" END,
    "updatedAt"=p_attempted_at
  WHERE lower(u.email)=p_requested_email
  RETURNING u."failedLoginAttempts",u."lockedUntil";
END
$fn$;

CREATE OR REPLACE FUNCTION app_auth.request_password_reset(
  p_requested_email text,p_reset_token_hash text,p_expires_at timestamp without time zone,
  p_requested_at timestamp without time zone,p_created_ip_hash text,p_user_agent_hash text
) RETURNS TABLE("accepted" boolean,"deliveryRequired" boolean,"userId" text,"email" text,"licenseeId" text,"orgId" text,"expiresAt" timestamp without time zone)
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE candidate_count integer; actor_row record; reset_id text;
BEGIN
  IF p_requested_email IS NULL OR length(p_requested_email) NOT BETWEEN 3 AND 320
     OR p_requested_email IS DISTINCT FROM lower(btrim(p_requested_email))
     OR p_requested_email !~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$'
     OR p_reset_token_hash !~ '^([0-9a-f]{12}:)?[0-9a-f]{64}$'
     OR (p_created_ip_hash IS NOT NULL AND p_created_ip_hash !~ '^([0-9a-f]{12}:)?[0-9a-f]{64}$')
     OR (p_user_agent_hash IS NOT NULL AND p_user_agent_hash !~ '^([0-9a-f]{12}:)?[0-9a-f]{64}$')
     OR p_requested_at IS NULL OR abs(extract(epoch FROM (p_requested_at-(clock_timestamp() AT TIME ZONE 'UTC'))))>300
     OR p_expires_at<=p_requested_at OR p_expires_at>p_requested_at+interval '24 hours' THEN
    RAISE EXCEPTION 'B01_PASSWORD_RESET_REQUEST_DENIED' USING ERRCODE='22023';
  END IF;
  PERFORM set_config('app.b01_preauth_operation','reset-request',true),
          set_config('app.b01_preauth_email',p_requested_email,true),
          set_config('app.b01_preauth_hashes',p_reset_token_hash,true),set_config('app.b01_preauth_token_id','',true),
          set_config('app.b01_preauth_user_id','',true),set_config('app.b01_preauth_org_id','',true),
          set_config('app.b01_preauth_licensee_id','',true),set_config('app.b01_preauth_pending_email','',true);
  SELECT count(*)::integer INTO candidate_count FROM public."User" u WHERE lower(u.email)=p_requested_email;
  IF candidate_count<>1 THEN RETURN QUERY SELECT true,false,NULL::text,NULL::text,NULL::text,NULL::text,NULL::timestamp; RETURN; END IF;
  SELECT u.id,u.email,u."licenseeId",u."orgId" INTO actor_row FROM public."User" u
    WHERE lower(u.email)=p_requested_email AND u."isActive" AND u."disabledAt" IS NULL AND u."deletedAt" IS NULL AND u.status<>'DISABLED'::public."UserStatus";
  IF NOT FOUND THEN RETURN QUERY SELECT true,false,NULL::text,NULL::text,NULL::text,NULL::text,NULL::timestamp; RETURN; END IF;
  PERFORM set_config('app.b01_preauth_user_id',actor_row.id,true),
          set_config('app.b01_preauth_org_id',coalesce(actor_row."orgId",''),true),
          set_config('app.b01_preauth_licensee_id',coalesce(actor_row."licenseeId",''),true);
  reset_id:=gen_random_uuid()::text;
  INSERT INTO public."PasswordReset" (id,"orgId","userId","tokenHash","expiresAt","createdAt","createdIpHash","userAgentHash")
    VALUES (reset_id,actor_row."orgId",actor_row.id,p_reset_token_hash,p_expires_at,p_requested_at,p_created_ip_hash,p_user_agent_hash);
  PERFORM app_auth.b01_preauth_audit('AUTH_PASSWORD_RESET_REQUESTED','PasswordReset',reset_id,p_requested_at,jsonb_build_object('expiresAt',p_expires_at));
  RETURN QUERY SELECT true,true,actor_row.id::text,actor_row.email::text,actor_row."licenseeId"::text,actor_row."orgId"::text,p_expires_at;
END
$fn$;

CREATE OR REPLACE FUNCTION app_auth.consume_password_reset_token(
  p_token_hash_candidates text[],p_new_password_hash text,p_consumed_at timestamp without time zone
) RETURNS TABLE("id" text,"email" text,"name" text,"role" text,"licenseeId" text,"orgId" text)
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE token_row record; actor_row record; candidate_ids text[]; changed integer;
BEGIN
  IF coalesce(array_length(p_token_hash_candidates,1),0) NOT BETWEEN 1 AND 3
     OR EXISTS (SELECT 1 FROM unnest(p_token_hash_candidates) h WHERE h IS NULL OR h !~ '^([0-9a-f]{12}:)?[0-9a-f]{64}$')
     OR (SELECT count(DISTINCT h) FROM unnest(p_token_hash_candidates) h)<>array_length(p_token_hash_candidates,1)
     OR p_new_password_hash IS NULL OR p_new_password_hash NOT LIKE '$argon2id$%' OR length(p_new_password_hash)>512
     OR p_consumed_at IS NULL OR abs(extract(epoch FROM (p_consumed_at-(clock_timestamp() AT TIME ZONE 'UTC'))))>300 THEN
    RAISE EXCEPTION 'B01_PASSWORD_RESET_CONSUME_DENIED' USING ERRCODE='22023';
  END IF;
  PERFORM set_config('app.b01_preauth_operation','reset-consume',true),set_config('app.b01_preauth_email','',true),
          set_config('app.b01_preauth_hashes',array_to_string(p_token_hash_candidates,','),true),set_config('app.b01_preauth_token_id','',true),
          set_config('app.b01_preauth_user_id','',true),set_config('app.b01_preauth_org_id','',true),
          set_config('app.b01_preauth_licensee_id','',true),set_config('app.b01_preauth_pending_email','',true);
  SELECT array_agg(r.id ORDER BY r.id) INTO candidate_ids FROM public."PasswordReset" r
    WHERE r."tokenHash"=ANY(p_token_hash_candidates) AND r."usedAt" IS NULL AND r."expiresAt">p_consumed_at;
  IF coalesce(array_length(candidate_ids,1),0)<>1 THEN RETURN; END IF;
  SELECT r.id,r."orgId",r."userId",r."tokenHash",r."expiresAt",r."usedAt" INTO token_row
    FROM public."PasswordReset" r WHERE r.id=candidate_ids[1];
  PERFORM set_config('app.b01_preauth_token_id',token_row.id,true),set_config('app.b01_preauth_user_id',token_row."userId",true);
  SELECT u.id,u.email,u.name,u.role,u."orgId",u."licenseeId",u.status,u."isActive",u."disabledAt",u."deletedAt",u."emailVerifiedAt"
    INTO actor_row FROM public."User" u WHERE u.id=token_row."userId" FOR UPDATE;
  IF NOT FOUND OR NOT actor_row."isActive" OR actor_row."disabledAt" IS NOT NULL OR actor_row."deletedAt" IS NOT NULL OR actor_row.status='DISABLED'::public."UserStatus" THEN RETURN; END IF;
  SELECT r.id,r."orgId",r."userId",r."tokenHash",r."expiresAt",r."usedAt" INTO token_row
    FROM public."PasswordReset" r WHERE r.id=candidate_ids[1];
  IF NOT FOUND OR token_row."userId"<>actor_row.id OR token_row."usedAt" IS NOT NULL OR token_row."expiresAt"<=p_consumed_at THEN RETURN; END IF;
  PERFORM set_config('app.b01_preauth_org_id',coalesce(actor_row."orgId",''),true),
          set_config('app.b01_preauth_licensee_id',coalesce(actor_row."licenseeId",''),true);
  UPDATE public."User" u SET "passwordHash"=p_new_password_hash,status='ACTIVE'::public."UserStatus",
    "emailVerifiedAt"=coalesce(u."emailVerifiedAt",p_consumed_at),"failedLoginAttempts"=0,"lockedUntil"=NULL,"updatedAt"=p_consumed_at
    WHERE u.id=actor_row.id;
  UPDATE public."PasswordReset" r SET "usedAt"=p_consumed_at WHERE r.id=token_row.id AND r."usedAt" IS NULL;
  GET DIAGNOSTICS changed=ROW_COUNT; IF changed<>1 THEN RAISE EXCEPTION 'B01_PASSWORD_RESET_REPLAY' USING ERRCODE='40001'; END IF;
  UPDATE public."RefreshToken" r SET "revokedAt"=coalesce(r."revokedAt",p_consumed_at),
    "revokedReason"=coalesce(r."revokedReason",'PASSWORD_RESET'),"lastUsedAt"=p_consumed_at,
    "sessionCapabilityRevokedAt"=coalesce(r."sessionCapabilityRevokedAt",p_consumed_at),
    "sessionCapabilityRevokedReason"=coalesce(r."sessionCapabilityRevokedReason",'PASSWORD_RESET')
    WHERE r."userId"=actor_row.id AND (r."revokedAt" IS NULL OR r."sessionCapabilityRevokedAt" IS NULL);
  PERFORM app_auth.b01_preauth_audit('AUTH_PASSWORD_RESET_COMPLETED','User',actor_row.id,p_consumed_at,'{}'::jsonb);
  RETURN QUERY SELECT actor_row.id,actor_row.email,actor_row.name,actor_row.role::text,actor_row."licenseeId",actor_row."orgId";
END
$fn$;

CREATE OR REPLACE FUNCTION app_auth.lookup_invitation_token(p_token_hash_candidates text[],p_checked_at timestamp without time zone)
RETURNS TABLE("email" text,"role" text,"expiresAt" timestamp without time zone,"licenseeName" text,"requiresConnector" boolean)
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE invite_row record; actor_row record; candidate_ids text[]; candidate_user_ids text[]; licensee_name text;
BEGIN
  IF coalesce(array_length(p_token_hash_candidates,1),0) NOT BETWEEN 1 AND 3
     OR EXISTS (SELECT 1 FROM unnest(p_token_hash_candidates) h WHERE h IS NULL OR h !~ '^([0-9a-f]{12}:)?[0-9a-f]{64}$')
     OR (SELECT count(DISTINCT h) FROM unnest(p_token_hash_candidates) h)<>array_length(p_token_hash_candidates,1)
     OR p_checked_at IS NULL OR abs(extract(epoch FROM (p_checked_at-(clock_timestamp() AT TIME ZONE 'UTC'))))>300 THEN
    RAISE EXCEPTION 'B01_INVITE_LOOKUP_DENIED' USING ERRCODE='22023';
  END IF;
  PERFORM set_config('app.b01_preauth_operation','invite-lookup',true),set_config('app.b01_preauth_email','',true),
          set_config('app.b01_preauth_hashes',array_to_string(p_token_hash_candidates,','),true),set_config('app.b01_preauth_token_id','',true),
          set_config('app.b01_preauth_user_id','',true),set_config('app.b01_preauth_org_id','',true),
          set_config('app.b01_preauth_licensee_id','',true),set_config('app.b01_preauth_pending_email','',true);
  SELECT array_agg(i.id ORDER BY i.id) INTO candidate_ids FROM public."Invite" i
    WHERE i."tokenHash"=ANY(p_token_hash_candidates) AND i."usedAt" IS NULL AND i."expiresAt">p_checked_at;
  IF coalesce(array_length(candidate_ids,1),0)<>1 THEN RETURN; END IF;
  SELECT i.id,i."orgId",i."licenseeId",i.email,i.role,i."manufacturerId",i."tokenHash",i."expiresAt",i."usedAt"
    INTO invite_row FROM public."Invite" i WHERE i.id=candidate_ids[1];
  PERFORM set_config('app.b01_preauth_token_id',invite_row.id,true),set_config('app.b01_preauth_email',invite_row.email,true),
          set_config('app.b01_preauth_org_id',invite_row."orgId",true),set_config('app.b01_preauth_licensee_id',coalesce(invite_row."licenseeId",''),true);
  SELECT array_agg(u.id ORDER BY u.id) INTO candidate_user_ids FROM public."User" u WHERE lower(u.email)=invite_row.email;
  IF coalesce(array_length(candidate_user_ids,1),0)<>1 THEN RETURN; END IF;
  SELECT u.id,u.email,u.role,u."orgId",u."licenseeId",u.status,u."isActive",u."disabledAt",u."deletedAt",u."passwordHash"
    INTO actor_row FROM public."User" u WHERE u.id=candidate_user_ids[1];
  IF NOT FOUND OR actor_row.email<>invite_row.email OR NOT actor_row."isActive" OR actor_row.status<>'INVITED'::public."UserStatus"
     OR actor_row."disabledAt" IS NOT NULL OR actor_row."deletedAt" IS NOT NULL OR actor_row."passwordHash" IS NOT NULL
     OR (CASE WHEN actor_row.role::text IN ('LICENSEE_ADMIN','ORG_ADMIN') THEN 'LICENSEE_ADMIN' WHEN actor_row.role::text IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') THEN 'MANUFACTURER' ELSE actor_row.role::text END)
        IS DISTINCT FROM (CASE WHEN invite_row.role::text IN ('LICENSEE_ADMIN','ORG_ADMIN') THEN 'LICENSEE_ADMIN' WHEN invite_row.role::text IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') THEN 'MANUFACTURER' ELSE invite_row.role::text END)
     OR (invite_row.role::text IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') AND (actor_row."orgId" IS NOT NULL OR actor_row."licenseeId" IS NOT NULL))
     OR (invite_row.role::text NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') AND (actor_row."orgId" IS DISTINCT FROM invite_row."orgId" OR actor_row."licenseeId" IS DISTINCT FROM invite_row."licenseeId"))
     OR (invite_row."manufacturerId" IS NOT NULL AND actor_row.id IS DISTINCT FROM invite_row."manufacturerId") THEN RETURN; END IF;
  PERFORM set_config('app.b01_preauth_user_id',actor_row.id,true);
  IF NOT EXISTS (SELECT 1 FROM public."Organization" o WHERE o.id=invite_row."orgId" AND o."isActive") THEN RETURN; END IF;
  IF invite_row."licenseeId" IS NOT NULL THEN
    SELECT l.name INTO licensee_name FROM public."Licensee" l WHERE l.id=invite_row."licenseeId" AND l."orgId"=invite_row."orgId" AND l."isActive" AND l."suspendedAt" IS NULL;
    IF NOT FOUND THEN RETURN; END IF;
  END IF;
  RETURN QUERY SELECT invite_row.email,invite_row.role::text,invite_row."expiresAt",licensee_name,
    invite_row.role::text IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER');
END
$fn$;

CREATE OR REPLACE FUNCTION app_auth.consume_invitation_token(
  p_token_hash_candidates text[],p_new_password_hash text,p_requested_name text,p_consumed_at timestamp without time zone,
  p_request_id text,p_ip_hash text,p_user_agent text
) RETURNS TABLE("inviteId" text,"id" text,"email" text,"name" text,"role" text,"licenseeId" text,"orgId" text,"status" text)
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE invite_row record; actor_row record; candidate_ids text[]; candidate_user_ids text[]; requested_name text:=nullif(btrim(coalesce(p_requested_name,'')),''); changed integer;
BEGIN
  IF coalesce(array_length(p_token_hash_candidates,1),0) NOT BETWEEN 1 AND 3
     OR EXISTS (SELECT 1 FROM unnest(p_token_hash_candidates) h WHERE h IS NULL OR h !~ '^([0-9a-f]{12}:)?[0-9a-f]{64}$')
     OR (SELECT count(DISTINCT h) FROM unnest(p_token_hash_candidates) h)<>array_length(p_token_hash_candidates,1)
     OR p_new_password_hash IS NULL OR p_new_password_hash NOT LIKE '$argon2id$%' OR length(p_new_password_hash)>512
     OR (requested_name IS NOT NULL AND (length(requested_name)>120 OR requested_name~'[[:cntrl:]]'))
     OR p_consumed_at IS NULL OR abs(extract(epoch FROM (p_consumed_at-(clock_timestamp() AT TIME ZONE 'UTC'))))>300
     OR p_request_id IS NULL OR length(p_request_id) NOT BETWEEN 1 AND 128 OR p_request_id !~ '^[!-~]+$'
     OR (p_ip_hash IS NOT NULL AND p_ip_hash !~ '^([0-9a-f]{12}:)?[0-9a-f]{64}$')
     OR length(coalesce(p_user_agent,''))>512 OR coalesce(p_user_agent,'')~'[[:cntrl:]]' THEN
    RAISE EXCEPTION 'B01_INVITE_CONSUME_DENIED' USING ERRCODE='22023';
  END IF;
  PERFORM set_config('app.b01_preauth_operation','invite-consume',true),set_config('app.b01_preauth_email','',true),
          set_config('app.b01_preauth_hashes',array_to_string(p_token_hash_candidates,','),true),set_config('app.b01_preauth_token_id','',true),
          set_config('app.b01_preauth_user_id','',true),set_config('app.b01_preauth_org_id','',true),
          set_config('app.b01_preauth_licensee_id','',true),set_config('app.b01_preauth_pending_email','',true);
  SELECT array_agg(i.id ORDER BY i.id) INTO candidate_ids FROM public."Invite" i
    WHERE i."tokenHash"=ANY(p_token_hash_candidates) AND i."usedAt" IS NULL AND i."expiresAt">p_consumed_at;
  IF coalesce(array_length(candidate_ids,1),0)<>1 THEN RETURN; END IF;
  SELECT i.id,i."orgId",i."licenseeId",i.email,i.role,i."manufacturerId",i."tokenHash",i."expiresAt",i."usedAt"
    INTO invite_row FROM public."Invite" i WHERE i.id=candidate_ids[1];
  PERFORM set_config('app.b01_preauth_token_id',invite_row.id,true),set_config('app.b01_preauth_email',invite_row.email,true),
          set_config('app.b01_preauth_org_id',invite_row."orgId",true),set_config('app.b01_preauth_licensee_id',coalesce(invite_row."licenseeId",''),true);
  SELECT array_agg(u.id ORDER BY u.id) INTO candidate_user_ids FROM public."User" u WHERE lower(u.email)=invite_row.email;
  IF coalesce(array_length(candidate_user_ids,1),0)<>1 THEN RETURN; END IF;
  SELECT u.id,u.email,u."passwordHash",u.name,u.role,u."orgId",u."licenseeId",u.status,u."isActive",u."disabledAt",u."deletedAt"
    INTO actor_row FROM public."User" u WHERE u.id=candidate_user_ids[1];
  PERFORM set_config('app.b01_preauth_user_id',actor_row.id,true);
  SELECT u.id,u.email,u."passwordHash",u.name,u.role,u."orgId",u."licenseeId",u.status,u."isActive",u."disabledAt",u."deletedAt"
    INTO actor_row FROM public."User" u WHERE u.id=candidate_user_ids[1] FOR UPDATE;
  IF NOT FOUND THEN RETURN; END IF;
  SELECT i.id,i."orgId",i."licenseeId",i.email,i.role,i."manufacturerId",i."tokenHash",i."expiresAt",i."usedAt"
    INTO invite_row FROM public."Invite" i WHERE i.id=candidate_ids[1];
  IF NOT FOUND OR invite_row.email<>actor_row.email OR invite_row."usedAt" IS NOT NULL OR invite_row."expiresAt"<=p_consumed_at THEN RETURN; END IF;
  IF NOT FOUND OR actor_row.email<>invite_row.email OR NOT actor_row."isActive" OR actor_row.status<>'INVITED'::public."UserStatus"
     OR actor_row."disabledAt" IS NOT NULL OR actor_row."deletedAt" IS NOT NULL OR actor_row."passwordHash" IS NOT NULL
     OR (CASE WHEN actor_row.role::text IN ('LICENSEE_ADMIN','ORG_ADMIN') THEN 'LICENSEE_ADMIN' WHEN actor_row.role::text IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') THEN 'MANUFACTURER' ELSE actor_row.role::text END)
        IS DISTINCT FROM (CASE WHEN invite_row.role::text IN ('LICENSEE_ADMIN','ORG_ADMIN') THEN 'LICENSEE_ADMIN' WHEN invite_row.role::text IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') THEN 'MANUFACTURER' ELSE invite_row.role::text END)
     OR (invite_row.role::text IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') AND (actor_row."orgId" IS NOT NULL OR actor_row."licenseeId" IS NOT NULL))
     OR (invite_row.role::text NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') AND (actor_row."orgId" IS DISTINCT FROM invite_row."orgId" OR actor_row."licenseeId" IS DISTINCT FROM invite_row."licenseeId"))
     OR (invite_row."manufacturerId" IS NOT NULL AND actor_row.id IS DISTINCT FROM invite_row."manufacturerId") THEN RETURN; END IF;
  PERFORM set_config('app.b01_preauth_user_id',actor_row.id,true);
  IF NOT EXISTS (SELECT 1 FROM public."Organization" o WHERE o.id=invite_row."orgId" AND o."isActive")
     OR (invite_row."licenseeId" IS NOT NULL AND NOT EXISTS (SELECT 1 FROM public."Licensee" l WHERE l.id=invite_row."licenseeId" AND l."orgId"=invite_row."orgId" AND l."isActive" AND l."suspendedAt" IS NULL)) THEN RETURN; END IF;
  UPDATE public."User" u SET "passwordHash"=p_new_password_hash,name=coalesce(requested_name,u.name),status='ACTIVE'::public."UserStatus",
    "emailVerifiedAt"=p_consumed_at,"failedLoginAttempts"=0,"lockedUntil"=NULL,"updatedAt"=p_consumed_at WHERE u.id=actor_row.id;
  UPDATE public."Invite" i SET "usedAt"=p_consumed_at,"acceptedByUserId"=actor_row.id WHERE i.id=invite_row.id AND i."usedAt" IS NULL;
  GET DIAGNOSTICS changed=ROW_COUNT; IF changed<>1 THEN RAISE EXCEPTION 'B01_INVITE_REPLAY' USING ERRCODE='40001'; END IF;
  PERFORM app_auth.b01_preauth_audit('AUTH_INVITE_ACCEPTED','Invite',invite_row.id,p_consumed_at,
    jsonb_build_object('requestId',p_request_id,'targetUserId',actor_row.id,'email',actor_row.email,'role',actor_row.role::text,'ipHash',p_ip_hash,'userAgent',p_user_agent));
  RETURN QUERY SELECT invite_row.id,actor_row.id,actor_row.email,coalesce(requested_name,actor_row.name),actor_row.role::text,
    actor_row."licenseeId",actor_row."orgId",'ACTIVE'::text;
END
$fn$;

CREATE OR REPLACE FUNCTION app_auth.consume_email_verification_token(
  p_token_hash_candidates text[],p_consumed_at timestamp without time zone
) RETURNS TABLE("verified" boolean,"purpose" text,"userId" text,"email" text)
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE token_row record; actor_row record; candidate_ids text[]; changed integer; result_email text; audit_action text;
BEGIN
  IF coalesce(array_length(p_token_hash_candidates,1),0) NOT BETWEEN 1 AND 3
     OR EXISTS (SELECT 1 FROM unnest(p_token_hash_candidates) h WHERE h IS NULL OR h !~ '^([0-9a-f]{12}:)?[0-9a-f]{64}$')
     OR (SELECT count(DISTINCT h) FROM unnest(p_token_hash_candidates) h)<>array_length(p_token_hash_candidates,1)
     OR p_consumed_at IS NULL OR abs(extract(epoch FROM (p_consumed_at-(clock_timestamp() AT TIME ZONE 'UTC'))))>300 THEN
    RAISE EXCEPTION 'B01_EMAIL_VERIFICATION_DENIED' USING ERRCODE='22023';
  END IF;
  PERFORM set_config('app.b01_preauth_operation','email-consume',true),set_config('app.b01_preauth_email','',true),
          set_config('app.b01_preauth_hashes',array_to_string(p_token_hash_candidates,','),true),set_config('app.b01_preauth_token_id','',true),
          set_config('app.b01_preauth_user_id','',true),set_config('app.b01_preauth_org_id','',true),
          set_config('app.b01_preauth_licensee_id','',true),set_config('app.b01_preauth_pending_email','',true);
  SELECT array_agg(e.id ORDER BY e.id) INTO candidate_ids FROM public."EmailVerificationToken" e
    WHERE e."tokenHash"=ANY(p_token_hash_candidates) AND e."usedAt" IS NULL AND e."expiresAt">p_consumed_at;
  IF coalesce(array_length(candidate_ids,1),0)<>1 THEN RETURN; END IF;
  SELECT e.id,e."userId",e.email,e."pendingEmail",e.purpose,e."tokenHash",e."expiresAt",e."usedAt"
    INTO token_row FROM public."EmailVerificationToken" e WHERE e.id=candidate_ids[1];
  PERFORM set_config('app.b01_preauth_token_id',token_row.id,true),set_config('app.b01_preauth_user_id',token_row."userId",true),
          set_config('app.b01_preauth_pending_email',coalesce(token_row."pendingEmail",''),true);
  SELECT u.id,u.email,u."pendingEmail",u."orgId",u."licenseeId",u.status,u."isActive",u."disabledAt",u."deletedAt",u."emailVerifiedAt"
    INTO actor_row FROM public."User" u WHERE u.id=token_row."userId" FOR UPDATE;
  IF NOT FOUND OR NOT actor_row."isActive" OR actor_row.status='DISABLED'::public."UserStatus" OR actor_row."disabledAt" IS NOT NULL OR actor_row."deletedAt" IS NOT NULL THEN RETURN; END IF;
  SELECT e.id,e."userId",e.email,e."pendingEmail",e.purpose,e."tokenHash",e."expiresAt",e."usedAt"
    INTO token_row FROM public."EmailVerificationToken" e WHERE e.id=candidate_ids[1];
  IF NOT FOUND OR token_row."userId"<>actor_row.id OR token_row."usedAt" IS NOT NULL OR token_row."expiresAt"<=p_consumed_at
     OR token_row.purpose NOT IN ('EMAIL_CHANGE','EMAIL_VERIFICATION') THEN RETURN; END IF;
  PERFORM set_config('app.b01_preauth_org_id',coalesce(actor_row."orgId",''),true),set_config('app.b01_preauth_licensee_id',coalesce(actor_row."licenseeId",''),true);
  IF token_row.purpose='EMAIL_CHANGE' THEN
    IF token_row."pendingEmail" IS NULL OR lower(token_row."pendingEmail")<>token_row."pendingEmail"
       OR actor_row."pendingEmail" IS DISTINCT FROM token_row."pendingEmail"
       OR EXISTS (SELECT 1 FROM public."User" u WHERE lower(u.email)=token_row."pendingEmail" AND u.id<>actor_row.id) THEN RETURN; END IF;
    UPDATE public."User" u SET email=token_row."pendingEmail","pendingEmail"=NULL,"pendingEmailRequestedAt"=NULL,
      "emailVerifiedAt"=p_consumed_at,status='ACTIVE'::public."UserStatus","updatedAt"=p_consumed_at WHERE u.id=actor_row.id;
    UPDATE public."RefreshToken" r SET "revokedAt"=coalesce(r."revokedAt",p_consumed_at),"revokedReason"=coalesce(r."revokedReason",'EMAIL_CHANGE'),"lastUsedAt"=p_consumed_at,
      "sessionCapabilityRevokedAt"=coalesce(r."sessionCapabilityRevokedAt",p_consumed_at),"sessionCapabilityRevokedReason"=coalesce(r."sessionCapabilityRevokedReason",'EMAIL_CHANGE')
      WHERE r."userId"=actor_row.id AND (r."revokedAt" IS NULL OR r."sessionCapabilityRevokedAt" IS NULL);
    result_email:=token_row."pendingEmail"; audit_action:='AUTH_EMAIL_CHANGE_CONFIRMED';
  ELSE
    IF lower(token_row.email)<>lower(actor_row.email) THEN RETURN; END IF;
    UPDATE public."User" u SET "emailVerifiedAt"=coalesce(u."emailVerifiedAt",p_consumed_at),status='ACTIVE'::public."UserStatus","updatedAt"=p_consumed_at WHERE u.id=actor_row.id;
    result_email:=actor_row.email; audit_action:='AUTH_EMAIL_VERIFIED';
  END IF;
  UPDATE public."EmailVerificationToken" e SET "usedAt"=p_consumed_at WHERE e.id=token_row.id AND e."usedAt" IS NULL;
  GET DIAGNOSTICS changed=ROW_COUNT; IF changed<>1 THEN RAISE EXCEPTION 'B01_EMAIL_VERIFICATION_REPLAY' USING ERRCODE='40001'; END IF;
  PERFORM app_auth.b01_preauth_audit(audit_action,'User',actor_row.id,p_consumed_at,jsonb_build_object('email',result_email,'purpose',token_row.purpose));
  RETURN QUERY SELECT true,token_row.purpose,actor_row.id,result_email;
END
$fn$;

REVOKE ALL ON FUNCTION app_auth.b01_preauth_audit(text,text,text,timestamp without time zone,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_auth.lookup_password_user(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_auth.record_password_failure(text,timestamp without time zone,integer,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_auth.request_password_reset(text,text,timestamp without time zone,timestamp without time zone,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_auth.consume_password_reset_token(text[],text,timestamp without time zone) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_auth.lookup_invitation_token(text[],timestamp without time zone) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_auth.consume_invitation_token(text[],text,text,timestamp without time zone,text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_auth.consume_email_verification_token(text[],timestamp without time zone) FROM PUBLIC;
