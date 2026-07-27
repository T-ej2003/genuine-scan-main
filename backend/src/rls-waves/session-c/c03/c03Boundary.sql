CREATE OR REPLACE FUNCTION app_rls.c03_revalidate_actor_scope(
  target_licensee_id text,
  allowed_roles_json jsonb,
  minimum_assurance text,
  purpose_code text
)
RETURNS TABLE(user_id text, role text, organization_id text, licensee_id text)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  actor record;
  target_org_id text;
  installed_licensee_id text := NULLIF(current_setting('app.licensee_id', true), '');
  installed_org_id text := NULLIF(current_setting('app.organization_id', true), '');
  installed_manufacturer_id text := NULLIF(current_setting('app.manufacturer_id', true), '');
  installed_assurance text := current_setting('app.auth_assurance', true);
BEGIN
  IF current_setting('app.user_id', true) !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
     OR current_setting('app.request_id', true) !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
     OR target_licensee_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
     OR current_setting('app.purpose', true) IS DISTINCT FROM purpose_code
     OR jsonb_typeof(allowed_roles_json) IS DISTINCT FROM 'array'
     OR NOT (allowed_roles_json ? current_setting('app.role', true))
     OR minimum_assurance NOT IN ('password-verified', 'mfa-verified', 'step-up-verified')
     OR (CASE minimum_assurance
          WHEN 'password-verified' THEN installed_assurance NOT IN ('password-verified','mfa-verified','step-up-verified')
          WHEN 'mfa-verified' THEN installed_assurance NOT IN ('mfa-verified','step-up-verified')
          ELSE installed_assurance <> 'step-up-verified'
        END) THEN
    RETURN;
  END IF;

  SELECT u.id, u.role::text AS role, u."orgId", u."licenseeId"
    INTO actor
    FROM public."User" u
   WHERE u.id = current_setting('app.user_id', true)
     AND u.role::text = current_setting('app.role', true)
     AND u."isActive"
     AND u.status = 'ACTIVE'::public."UserStatus"
     AND u."deletedAt" IS NULL
     AND u."disabledAt" IS NULL;
  IF NOT FOUND THEN RETURN; END IF;

  SELECT l."orgId" INTO target_org_id
    FROM public."Licensee" l
    JOIN public."Organization" o ON o.id = l."orgId"
   WHERE l.id = target_licensee_id
     AND l."isActive"
     AND l."suspendedAt" IS NULL
     AND o."isActive";
  IF NOT FOUND THEN RETURN; END IF;

  IF actor.role IN ('SUPER_ADMIN', 'PLATFORM_SUPER_ADMIN') THEN
    IF actor."orgId" IS NOT NULL OR actor."licenseeId" IS NOT NULL OR installed_org_id IS NOT NULL OR installed_manufacturer_id IS NOT NULL THEN
      RETURN;
    END IF;
  ELSIF actor.role = 'MANUFACTURER_ADMIN' THEN
    IF installed_licensee_id IS DISTINCT FROM target_licensee_id
       OR installed_manufacturer_id IS DISTINCT FROM actor.id
       OR NOT EXISTS (
         SELECT 1 FROM public."ManufacturerLicenseeLink" ml
          WHERE ml."manufacturerId" = actor.id AND ml."licenseeId" = target_licensee_id
       ) THEN
      RETURN;
    END IF;
  ELSIF actor.role <> 'LICENSEE_ADMIN'
        OR actor."licenseeId" IS DISTINCT FROM target_licensee_id
        OR actor."orgId" IS DISTINCT FROM target_org_id
        OR installed_licensee_id IS DISTINCT FROM target_licensee_id
        OR installed_org_id IS DISTINCT FROM target_org_id
        OR installed_manufacturer_id IS NOT NULL THEN
    RETURN;
  END IF;

  RETURN QUERY SELECT actor.id::text, actor.role::text, target_org_id, target_licensee_id;
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_revalidate_platform_actor_scope(
  allowed_roles_json jsonb,
  minimum_assurance text,
  purpose_code text
)
RETURNS TABLE(user_id text, role text)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
  SELECT actor.id::text, actor.role::text
    FROM public."User" actor
   WHERE actor.id = current_setting('app.user_id', true)
     AND actor.role::text = current_setting('app.role', true)
     AND actor.role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')
     AND actor."orgId" IS NULL AND actor."licenseeId" IS NULL
     AND actor."isActive" AND actor.status = 'ACTIVE'::public."UserStatus"
     AND actor."deletedAt" IS NULL AND actor."disabledAt" IS NULL
     AND NULLIF(current_setting('app.organization_id', true), '') IS NULL
     AND NULLIF(current_setting('app.licensee_id', true), '') IS NULL
     AND NULLIF(current_setting('app.manufacturer_id', true), '') IS NULL
     AND current_setting('app.request_id', true) ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
     AND current_setting('app.purpose', true) = purpose_code
     AND jsonb_typeof(allowed_roles_json) = 'array'
     AND allowed_roles_json ? actor.role::text
     AND CASE minimum_assurance
           WHEN 'password-verified' THEN current_setting('app.auth_assurance', true) IN ('password-verified','mfa-verified','step-up-verified')
           WHEN 'mfa-verified' THEN current_setting('app.auth_assurance', true) IN ('mfa-verified','step-up-verified')
           WHEN 'step-up-verified' THEN current_setting('app.auth_assurance', true) = 'step-up-verified'
           ELSE false
         END
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_revalidate_incident_actor_scope(
  incident_id text, allowed_roles_json jsonb, minimum_assurance text, purpose_code text
)
RETURNS TABLE(user_id text, role text, organization_id text, licensee_id text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
  SELECT actor.* FROM public."Incident" resource
  CROSS JOIN LATERAL app_rls.c03_revalidate_actor_scope(resource."licenseeId", allowed_roles_json, minimum_assurance, purpose_code) actor
  WHERE resource.id = incident_id AND resource."licenseeId" IS NOT NULL
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_revalidate_policy_rule_actor_scope(
  policy_rule_id text, allowed_roles_json jsonb, minimum_assurance text, purpose_code text
)
RETURNS TABLE(user_id text, role text, organization_id text, licensee_id text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
  SELECT actor.* FROM public."PolicyRule" resource
  CROSS JOIN LATERAL app_rls.c03_revalidate_actor_scope(resource."licenseeId", allowed_roles_json, minimum_assurance, purpose_code) actor
  WHERE resource.id = policy_rule_id AND resource."licenseeId" IS NOT NULL
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_revalidate_compliance_pack_job_actor_scope(
  compliance_pack_job_id text, allowed_roles_json jsonb, minimum_assurance text, purpose_code text
)
RETURNS TABLE(user_id text, role text, organization_id text, licensee_id text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
  SELECT actor.* FROM public."CompliancePackJob" resource
  CROSS JOIN LATERAL app_rls.c03_revalidate_actor_scope(resource."licenseeId", allowed_roles_json, minimum_assurance, purpose_code) actor
  WHERE resource.id = compliance_pack_job_id AND resource."licenseeId" IS NOT NULL
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_revalidate_incident_evidence_actor_scope(
  incident_evidence_id text, allowed_roles_json jsonb, minimum_assurance text, purpose_code text
)
RETURNS TABLE(user_id text, role text, organization_id text, licensee_id text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
  SELECT actor.* FROM public."IncidentEvidence" evidence
  JOIN public."Incident" resource ON resource.id = evidence."incidentId"
  CROSS JOIN LATERAL app_rls.c03_revalidate_actor_scope(resource."licenseeId", allowed_roles_json, minimum_assurance, purpose_code) actor
  WHERE evidence.id = incident_evidence_id AND resource."licenseeId" IS NOT NULL
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_revalidate_incident_evidence_storage_actor_scope(
  storage_key text, allowed_roles_json jsonb, minimum_assurance text, purpose_code text
)
RETURNS TABLE(user_id text, role text, organization_id text, licensee_id text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
  SELECT actor.* FROM public."IncidentEvidence" evidence
  JOIN public."Incident" resource ON resource.id = evidence."incidentId"
  CROSS JOIN LATERAL app_rls.c03_revalidate_actor_scope(resource."licenseeId", allowed_roles_json, minimum_assurance, purpose_code) actor
  WHERE evidence."storageKey" = storage_key AND resource."licenseeId" IS NOT NULL
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_revalidate_sensitive_approval_actor_scope(
  approval_id text, allowed_roles_json jsonb, minimum_assurance text, purpose_code text
)
RETURNS TABLE(user_id text, role text, organization_id text, licensee_id text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
  SELECT actor.* FROM public."SensitiveActionApproval" resource
  CROSS JOIN LATERAL app_rls.c03_revalidate_actor_scope(resource."licenseeId", allowed_roles_json, minimum_assurance, purpose_code) actor
  WHERE resource.id = approval_id AND resource."licenseeId" IS NOT NULL
$$;

REVOKE ALL ON FUNCTION app_rls.c03_revalidate_actor_scope(text,jsonb,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_revalidate_platform_actor_scope(jsonb,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_revalidate_incident_actor_scope(text,jsonb,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_revalidate_policy_rule_actor_scope(text,jsonb,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_revalidate_compliance_pack_job_actor_scope(text,jsonb,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_revalidate_incident_evidence_actor_scope(text,jsonb,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_revalidate_incident_evidence_storage_actor_scope(text,jsonb,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_revalidate_sensitive_approval_actor_scope(text,jsonb,text,text) FROM PUBLIC;
