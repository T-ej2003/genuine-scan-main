CREATE OR REPLACE FUNCTION app_rls.c02_audit_trace_session_valid()
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF session_user <> {{APP_ROLE}}
     OR current_setting('app.auth_session_verified', true) <> '1'
  THEN RETURN false; END IF;

  RETURN EXISTS (
    SELECT 1 FROM public."RefreshToken" session_row
     WHERE session_row.id = current_setting('app.auth_session_id', true)
       AND session_row."userId" = current_setting('app.user_id', true)
       AND session_row."sessionCapabilityHash" = current_setting('app.auth_session_hash', true)
       AND session_row."sessionCapabilityHashVersion" = 'sha256-v1'
       AND session_row."sessionCapabilityRevokedAt" IS NULL
       AND session_row."sessionCapabilityExpiresAt" > clock_timestamp()
       AND session_row."revokedAt" IS NULL
       AND session_row."expiresAt" > clock_timestamp()
  );
END;
$$;

REVOKE ALL ON FUNCTION app_rls.c02_audit_trace_session_valid() FROM PUBLIC;

CREATE OR REPLACE FUNCTION app_rls.c02_audit_trace_actor_valid(target_licensee_id text)
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  actor record;
  target_org_id text;
  actor_id text := current_setting('app.user_id', true);
  actor_role text := current_setting('app.role', true);
  actor_org_id text := NULLIF(current_setting('app.organization_id', true), '');
  actor_licensee_id text := NULLIF(current_setting('app.licensee_id', true), '');
  actor_manufacturer_id text := NULLIF(current_setting('app.manufacturer_id', true), '');
  assurance text := current_setting('app.auth_assurance', true);
  purpose_code text := current_setting('app.purpose', true);
BEGIN
  IF actor_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
     OR current_setting('app.request_id', true) !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
     OR target_licensee_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
     OR actor_licensee_id IS DISTINCT FROM target_licensee_id
     OR purpose_code NOT IN (
       'platform-audit-log-read', 'audit-log-read',
       'platform-audit-csv-export', 'tenant-audit-csv-export', 'manufacturer-audit-csv-export',
       'platform-fraud-report-read',
       'platform-trace-timeline-read', 'tenant-trace-timeline-read', 'manufacturer-trace-timeline-read'
     ) THEN
    RETURN false;
  END IF;

  SELECT u.id, u.role::text AS role, u."orgId", u."licenseeId"
    INTO actor
    FROM public."User" u
   WHERE u.id = actor_id
     AND u.role::text = actor_role
     AND u."isActive"
     AND u.status = 'ACTIVE'::public."UserStatus"
     AND u."deletedAt" IS NULL
     AND u."disabledAt" IS NULL;
  IF NOT FOUND THEN RETURN false; END IF;

  SELECT l."orgId" INTO target_org_id
    FROM public."Licensee" l
    JOIN public."Organization" o ON o.id = l."orgId"
   WHERE l.id = target_licensee_id
     AND l."isActive"
     AND l."suspendedAt" IS NULL
     AND o."isActive";
  IF NOT FOUND THEN RETURN false; END IF;

  IF actor_role IN ('SUPER_ADMIN', 'PLATFORM_SUPER_ADMIN') THEN
    RETURN assurance = 'mfa-verified'
       AND actor."orgId" IS NULL
       AND actor."licenseeId" IS NULL
       AND actor_org_id IS NULL
       AND actor_manufacturer_id IS NULL;
  END IF;

  IF actor_role = 'LICENSEE_ADMIN' THEN
    RETURN assurance IN ('password-verified', 'mfa-verified', 'step-up-verified')
       AND actor."licenseeId" = target_licensee_id
       AND actor."orgId" = target_org_id
       AND actor_org_id = target_org_id
       AND actor_manufacturer_id IS NULL
       AND (purpose_code <> 'audit-log-read' OR assurance IN ('mfa-verified', 'step-up-verified'));
  END IF;

  IF actor_role = 'MANUFACTURER_ADMIN' THEN
    RETURN assurance IN ('password-verified', 'mfa-verified', 'step-up-verified')
       AND actor_manufacturer_id = actor_id
       AND EXISTS (
         SELECT 1
           FROM public."ManufacturerLicenseeLink" ml
          WHERE ml."manufacturerId" = actor_id
            AND ml."licenseeId" = target_licensee_id
       );
  END IF;

  RETURN false;
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.platform_audit_log_details(audit_ids text[])
RETURNS TABLE(id text, ip_address text, user_agent text, user_id text, user_name text)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  target_licensee_id text := NULLIF(current_setting('app.licensee_id', true), '');
BEGIN
  IF current_setting('app.role', true) NOT IN ('SUPER_ADMIN', 'PLATFORM_SUPER_ADMIN')
     OR current_setting('app.purpose', true) <> 'platform-audit-log-read'
     OR NOT app_rls.c02_audit_trace_actor_valid(target_licensee_id)
     OR COALESCE(cardinality(audit_ids), 0) > 500
     OR EXISTS (
       SELECT 1 FROM unnest(COALESCE(audit_ids, ARRAY[]::text[])) requested(id)
       LEFT JOIN public."AuditLog" a ON a.id = requested.id AND a."licenseeId" = target_licensee_id
       WHERE a.id IS NULL
     ) THEN
    RAISE EXCEPTION 'SESSION_C_AUDIT_DETAIL_SCOPE_DENIED';
  END IF;

  RETURN QUERY
  SELECT a.id, a."ipAddress", a."userAgent", a."userId", u.name
    FROM public."AuditLog" a
    LEFT JOIN public."User" u ON u.id = a."userId"
   WHERE a.id = ANY(COALESCE(audit_ids, ARRAY[]::text[]))
     AND a."licenseeId" = target_licensee_id;
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c02_fraud_report_network_details(report_ids text[])
RETURNS TABLE(id text, ip_address text)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  target_licensee_id text := NULLIF(current_setting('app.licensee_id', true), '');
BEGIN
  IF current_setting('app.role', true) NOT IN ('SUPER_ADMIN', 'PLATFORM_SUPER_ADMIN')
     OR current_setting('app.purpose', true) <> 'platform-fraud-report-read'
     OR NOT app_rls.c02_audit_trace_actor_valid(target_licensee_id)
     OR COALESCE(cardinality(report_ids), 0) > 500
     OR EXISTS (
       SELECT 1 FROM unnest(COALESCE(report_ids, ARRAY[]::text[])) requested(id)
       LEFT JOIN public."AuditLog" a
         ON a.id = requested.id
        AND a."licenseeId" = target_licensee_id
        AND a.action = 'CUSTOMER_FRAUD_REPORT'
       WHERE a.id IS NULL
     ) THEN
    RAISE EXCEPTION 'SESSION_C_FRAUD_DETAIL_SCOPE_DENIED';
  END IF;

  RETURN QUERY
  SELECT a.id, a."ipAddress"
    FROM public."AuditLog" a
   WHERE a.id = ANY(COALESCE(report_ids, ARRAY[]::text[]))
     AND a."licenseeId" = target_licensee_id
     AND a.action = 'CUSTOMER_FRAUD_REPORT';
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c02_respond_fraud_report(
  report_id text,
  response_status text,
  requested_message text,
  notify_customer boolean
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  actor record;
  report record;
  target_org_id text;
  response_id text := gen_random_uuid()::text;
  normalized_code text;
  recipient_email text;
  response_message text;
  delivery jsonb;
  response_details jsonb;
BEGIN
  IF current_setting('app.purpose', true) <> 'platform-fraud-report-response'
     OR current_setting('app.auth_assurance', true) <> 'mfa-verified'
     OR current_setting('app.request_id', true) !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
     OR report_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
     OR response_status NOT IN ('REVIEWED', 'RESOLVED', 'DISMISSED') THEN
    RAISE EXCEPTION 'SESSION_C_INVALID_CONTEXT';
  END IF;

  SELECT u.id, u.role::text AS role
    INTO actor
    FROM public."User" u
   WHERE u.id = current_setting('app.user_id', true)
     AND u.role::text = current_setting('app.role', true)
     AND u.role IN ('SUPER_ADMIN', 'PLATFORM_SUPER_ADMIN')
     AND u."orgId" IS NULL
     AND u."licenseeId" IS NULL
     AND u."isActive"
     AND u.status = 'ACTIVE'::public."UserStatus"
     AND u."deletedAt" IS NULL
     AND u."disabledAt" IS NULL
   FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'SESSION_C_DISABLED_OR_STALE_ACTOR'; END IF;

  PERFORM pg_advisory_xact_lock(hashtextextended(report_id, 0));
  SELECT a.id, a."licenseeId", a."entityId", a.details
    INTO report
    FROM public."AuditLog" a
   WHERE a.id = report_id
     AND a.action = 'CUSTOMER_FRAUD_REPORT'
     AND a."licenseeId" IS NOT NULL
   FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'SESSION_C_FRAUD_REPORT_NOT_FOUND'; END IF;

  SELECT l."orgId" INTO target_org_id
    FROM public."Licensee" l
    JOIN public."Organization" o ON o.id = l."orgId"
   WHERE l.id = report."licenseeId"
     AND l."isActive"
     AND l."suspendedAt" IS NULL
     AND o."isActive";
  IF NOT FOUND THEN RAISE EXCEPTION 'SESSION_C_FRAUD_REPORT_NOT_FOUND'; END IF;

  normalized_code := COALESCE(NULLIF(report.details->>'code', ''), NULLIF(report."entityId", ''), 'UNKNOWN');
  recipient_email := NULLIF(btrim(report.details->>'contactEmail'), '');
  response_message := NULLIF(btrim(requested_message), '');
  IF response_message IS NULL THEN
    response_message := CASE response_status
      WHEN 'RESOLVED' THEN 'Thanks for reporting code ' || normalized_code || '. Our security team reviewed it and completed corrective action.'
      WHEN 'DISMISSED' THEN 'Thanks for reporting code ' || normalized_code || '. We reviewed the case and found no actionable fraud signal from current evidence.'
      ELSE 'Thanks for reporting code ' || normalized_code || '. Our security team has started investigating your report.'
    END;
  END IF;
  response_message := left(response_message, 1000);
  delivery := jsonb_build_object(
    'attempted', notify_customer,
    'delivered', notify_customer AND recipient_email IS NOT NULL,
    'transport', CASE WHEN notify_customer THEN 'simulated' ELSE 'none' END,
    'recipientEmail', CASE WHEN notify_customer THEN recipient_email ELSE NULL END,
    'reason', CASE WHEN notify_customer AND recipient_email IS NULL THEN 'Customer did not provide a contact email in the report.' ELSE NULL END,
    'deliveredAt', CASE WHEN notify_customer AND recipient_email IS NOT NULL THEN transaction_timestamp() ELSE NULL END
  );
  response_details := jsonb_build_object(
    'reportId', report.id,
    'status', response_status,
    'message', response_message,
    'notifyCustomer', notify_customer,
    'recipientEmail', recipient_email,
    'delivery', delivery,
    'sourceCode', normalized_code,
    'respondedAt', transaction_timestamp(),
    'requestId', current_setting('app.request_id', true),
    'purposeCode', current_setting('app.purpose', true)
  );

  INSERT INTO public."AuditLog"
    (id, "userId", "orgId", "licenseeId", action, "entityType", "entityId", details)
  VALUES
    (response_id, actor.id, target_org_id, report."licenseeId", 'CUSTOMER_FRAUD_REPORT_RESPONSE', 'FraudReport', report.id, response_details);
  INSERT INTO public."SecurityEventOutbox" (id, "eventType", payload, "updatedAt")
  VALUES (
    gen_random_uuid()::text,
    'AUDIT_LOG',
    jsonb_build_object(
      'id', response_id,
      'action', 'CUSTOMER_FRAUD_REPORT_RESPONSE',
      'entityType', 'FraudReport',
      'entityId', report.id,
      'userId', actor.id,
      'orgId', target_org_id,
      'licenseeId', report."licenseeId",
      'details', response_details,
      'createdAt', transaction_timestamp()
    ),
    transaction_timestamp()
  );

  RETURN jsonb_build_object(
    'responseId', response_id,
    'reportId', report.id,
    'status', response_status,
    'message', response_message,
    'notifyCustomer', notify_customer,
    'delivery', delivery
  );
END;
$$;

REVOKE ALL ON FUNCTION app_rls.c02_audit_trace_actor_valid(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.platform_audit_log_details(text[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c02_fraud_report_network_details(text[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c02_respond_fraud_report(text,text,text,boolean) FROM PUBLIC;
