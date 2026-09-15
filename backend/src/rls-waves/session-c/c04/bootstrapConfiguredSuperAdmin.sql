CREATE OR REPLACE FUNCTION app_ops.bootstrap_configured_super_admin(p_email text,p_password_hash text,p_name text,p_auto_verify boolean)
RETURNS TABLE(status text,user_id uuid,email text,role text,auto_verified boolean,reason text,audit_event_id uuid)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  existing_id text;
  existing_email text;
  existing_role text;
  created_id text;
  audit_id text;
BEGIN
  PERFORM app_ops.session_c04_assert_context('bootstrap-configured-super-admin','system-verified','migration',ARRAY['development','staging','production']);
  PERFORM set_config('app.bootstrap_email',lower(btrim(p_email)),true);
  PERFORM pg_advisory_xact_lock(723425101);
  SELECT u.id,u.email,u.role::text INTO existing_id,existing_email,existing_role
    FROM public."User" u
   WHERE u.role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')
     AND u."deletedAt" IS NULL
     AND NOT (
       u.id='174619c3-aabe-4096-a97d-886603ad825e'
       AND u.role='PLATFORM_SUPER_ADMIN'
       AND COALESCE(u.metadata->>'managedBy','')='production-green-pretraffic-canary-v1'
     )
   ORDER BY u."createdAt",u.id LIMIT 1;
  IF FOUND THEN
    audit_id:=app_ops.session_c04_audit(NULL,'AUTH_SUPER_ADMIN_BOOTSTRAP_SKIPPED_EXISTING','User',existing_id,jsonb_build_object('migrationOnly',true));
    RETURN QUERY SELECT 'skipped_existing',existing_id::uuid,existing_email,existing_role,NULL::boolean,NULL::text,audit_id::uuid;
    RETURN;
  END IF;
  SELECT u.id,u.email,u.role::text INTO existing_id,existing_email,existing_role FROM public."User" u WHERE lower(u.email)=lower(p_email);
  IF FOUND THEN
    audit_id:=app_ops.session_c04_audit(NULL,'AUTH_SUPER_ADMIN_BOOTSTRAP_BLOCKED','User',existing_id,jsonb_build_object('reason','configured email belongs to another account','migrationOnly',true));
    RETURN QUERY SELECT 'blocked',NULL::uuid,existing_email,NULL::text,NULL::boolean,'Configured bootstrap email already belongs to a non-super-admin account.',audit_id::uuid;
    RETURN;
  END IF;
  created_id:=gen_random_uuid()::text;
  INSERT INTO public."User" (id,email,"passwordHash",name,role,status,"isActive","emailVerifiedAt","updatedAt") VALUES
    (created_id,lower(btrim(p_email)),p_password_hash,btrim(p_name),'SUPER_ADMIN','ACTIVE',true,CASE WHEN p_auto_verify THEN transaction_timestamp() ELSE NULL END,transaction_timestamp());
  audit_id:=app_ops.session_c04_audit(NULL,'AUTH_SUPER_ADMIN_BOOTSTRAPPED','User',created_id,jsonb_build_object('autoVerified',p_auto_verify,'migrationOnly',true));
  RETURN QUERY SELECT 'created',created_id::uuid,lower(btrim(p_email)),'SUPER_ADMIN',p_auto_verify,NULL::text,audit_id::uuid;
END;
$$;

REVOKE ALL ON FUNCTION app_ops.bootstrap_configured_super_admin(text,text,text,boolean) FROM PUBLIC;
