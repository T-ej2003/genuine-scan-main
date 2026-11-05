-- Review artifact only: no role receives EXECUTE; no automatic installer consumes this file.
BEGIN;
DO $guard$
DECLARE table_name text;
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mscqr_victoria_diag_owner') OR
     to_regprocedure('app_ops.victoria_mfa_diagnostic()') IS NOT NULL THEN
    RAISE EXCEPTION 'VICTORIA_DIAGNOSTIC_ALREADY_EXISTS';
  END IF;
  FOREACH table_name IN ARRAY ARRAY['User','AdminMfaCredential','AdminWebAuthnCredential','UserMfaFactor','UserBackupCode'] LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname='public' AND c.relname=table_name AND c.relrowsecurity AND c.relforcerowsecurity) THEN
      RAISE EXCEPTION 'VICTORIA_DIAGNOSTIC_FORCE_RLS_REQUIRED';
    END IF;
  END LOOP;
END;
$guard$;
CREATE ROLE mscqr_victoria_diag_owner NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOINHERIT;
GRANT USAGE ON SCHEMA public, app_ops TO mscqr_victoria_diag_owner;
GRANT CREATE ON SCHEMA app_ops TO mscqr_victoria_diag_owner;
GRANT SELECT (id,email,"isActive",status,"deletedAt","disabledAt",role) ON public."User" TO mscqr_victoria_diag_owner;
GRANT SELECT ("userId","isEnabled","backupCodesHash") ON public."AdminMfaCredential" TO mscqr_victoria_diag_owner;
GRANT SELECT ("userId") ON public."AdminWebAuthnCredential" TO mscqr_victoria_diag_owner;
GRANT SELECT ("userId",type,"disabledAt","legacySource","lastUsedAt") ON public."UserMfaFactor" TO mscqr_victoria_diag_owner;
GRANT SELECT ("userId","usedAt") ON public."UserBackupCode" TO mscqr_victoria_diag_owner;
CREATE POLICY victoria_diag_user ON public."User" FOR SELECT TO mscqr_victoria_diag_owner USING (email='victoria@mscqr.com');
CREATE POLICY victoria_diag_totp ON public."AdminMfaCredential" FOR SELECT TO mscqr_victoria_diag_owner USING ("userId" IN (SELECT id FROM public."User" WHERE email='victoria@mscqr.com'));
CREATE POLICY victoria_diag_webauthn ON public."AdminWebAuthnCredential" FOR SELECT TO mscqr_victoria_diag_owner USING ("userId" IN (SELECT id FROM public."User" WHERE email='victoria@mscqr.com'));
CREATE POLICY victoria_diag_factor ON public."UserMfaFactor" FOR SELECT TO mscqr_victoria_diag_owner USING ("userId" IN (SELECT id FROM public."User" WHERE email='victoria@mscqr.com'));
CREATE POLICY victoria_diag_backup ON public."UserBackupCode" FOR SELECT TO mscqr_victoria_diag_owner USING ("userId" IN (SELECT id FROM public."User" WHERE email='victoria@mscqr.com'));
CREATE FUNCTION app_ops.victoria_mfa_diagnostic()
RETURNS TABLE(status text, account_active boolean, account_role text,
              mfa_enabled boolean, totp_enabled boolean, webauthn_present boolean,
              backup_codes_present boolean, c04_procedure_present boolean, c04_execution_grants jsonb)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog
AS $diagnostic$
DECLARE target_id text; target_active boolean; target_role text; totp boolean; webauthn boolean; backups boolean;
        reset_proc regprocedure;
BEGIN
  IF current_setting('transaction_read_only') <> 'on' THEN
    RAISE EXCEPTION 'VICTORIA_DIAGNOSTIC_READ_ONLY_REQUIRED';
  END IF;
  IF NOT (SELECT NOT rolsuper AND NOT rolbypassrls FROM pg_roles WHERE rolname = current_user)
     OR NOT row_security_active('public."User"'::regclass)
     OR NOT row_security_active('public."AdminMfaCredential"'::regclass)
     OR NOT row_security_active('public."AdminWebAuthnCredential"'::regclass)
     OR NOT row_security_active('public."UserMfaFactor"'::regclass)
     OR NOT row_security_active('public."UserBackupCode"'::regclass) THEN
    RETURN QUERY SELECT 'VISIBILITY_UNVERIFIED'::text, NULL::boolean, NULL::text,
      NULL::boolean, NULL::boolean, NULL::boolean, NULL::boolean, NULL::boolean, NULL::jsonb;
    RETURN;
  END IF;
  SELECT u.id, (u."isActive" AND u.status::text = 'ACTIVE' AND u."deletedAt" IS NULL AND u."disabledAt" IS NULL), u.role::text
    INTO target_id, target_active, target_role FROM public."User" u WHERE u.email = 'victoria@mscqr.com';
  IF target_id IS NULL THEN
    RETURN QUERY SELECT 'VISIBILITY_UNVERIFIED'::text, NULL::boolean, NULL::text,
      NULL::boolean, NULL::boolean, NULL::boolean, NULL::boolean, NULL::boolean, NULL::jsonb;
    RETURN;
  END IF;
  -- A negative factor query is not authoritative when RLS may hide rows.
  SELECT EXISTS(SELECT 1 FROM public."AdminMfaCredential" c WHERE c."userId"=target_id AND c."isEnabled"),
         EXISTS(SELECT 1 FROM public."AdminWebAuthnCredential" w WHERE w."userId"=target_id)
           OR EXISTS(SELECT 1 FROM public."UserMfaFactor" f WHERE f."userId"=target_id AND f.type='WEBAUTHN' AND f."disabledAt" IS NULL),
         EXISTS(SELECT 1 FROM public."UserBackupCode" b WHERE b."userId"=target_id AND b."usedAt" IS NULL)
           OR EXISTS(SELECT 1 FROM public."AdminMfaCredential" c WHERE c."userId"=target_id AND cardinality(c."backupCodesHash")>0)
    INTO totp, webauthn, backups;
  totp := totp OR EXISTS(SELECT 1 FROM public."UserMfaFactor" f WHERE f."userId"=target_id AND f.type='TOTP' AND f."disabledAt" IS NULL AND f."legacySource" IS DISTINCT FROM 'MFA_ENROLLMENT_PENDING' AND (f."lastUsedAt" IS NOT NULL OR f."legacySource"='AdminMfaCredential'));
  reset_proc := to_regprocedure('app_ops.reset_account_mfa(uuid,uuid,text,uuid)');
  RETURN QUERY SELECT 'ACCOUNT_PRESENT'::text, target_active, target_role,
    CASE WHEN totp OR webauthn THEN true ELSE NULL END, CASE WHEN totp THEN true ELSE NULL END,
    CASE WHEN webauthn THEN true ELSE NULL END, CASE WHEN backups THEN true ELSE NULL END,
    (reset_proc IS NOT NULL), CASE WHEN reset_proc IS NULL THEN NULL::jsonb ELSE
      (SELECT coalesce(jsonb_agg(rolname ORDER BY rolname), '[]'::jsonb) FROM pg_roles WHERE has_function_privilege(oid,reset_proc,'EXECUTE')) END;
EXCEPTION
  WHEN insufficient_privilege THEN
    RETURN QUERY SELECT 'EXECUTION_UNAUTHORIZED'::text, NULL::boolean, NULL::text,
      NULL::boolean, NULL::boolean, NULL::boolean, NULL::boolean, NULL::boolean, NULL::jsonb;
  WHEN OTHERS THEN
    RETURN QUERY SELECT 'DIAGNOSTIC_ERROR'::text, NULL::boolean, NULL::text,
      NULL::boolean, NULL::boolean, NULL::boolean, NULL::boolean, NULL::boolean, NULL::jsonb;
END;
$diagnostic$;
DO $acl$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_proc p, LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
    WHERE p.oid='app_ops.victoria_mfa_diagnostic()'::regprocedure AND a.grantee NOT IN (0,p.proowner)) THEN
    RAISE EXCEPTION 'VICTORIA_DIAGNOSTIC_UNEXPECTED_DEFAULT_GRANTS';
  END IF;
END;
$acl$;
REVOKE ALL ON FUNCTION app_ops.victoria_mfa_diagnostic() FROM PUBLIC;
ALTER FUNCTION app_ops.victoria_mfa_diagnostic() OWNER TO mscqr_victoria_diag_owner;
REVOKE CREATE ON SCHEMA app_ops FROM mscqr_victoria_diag_owner;
COMMIT;
