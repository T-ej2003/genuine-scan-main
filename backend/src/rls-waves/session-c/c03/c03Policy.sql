CREATE SCHEMA IF NOT EXISTS app_rls;

CREATE OR REPLACE FUNCTION app_rls.c03_require_policy_actor(
  target_licensee_id text,
  purpose_code text
)
RETURNS TABLE(user_id text, organization_id text, licensee_id text)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  RETURN QUERY
  SELECT actor.id::text, organization.id::text, licensee.id::text
    FROM public."User" actor
    JOIN public."Licensee" licensee ON licensee.id = target_licensee_id
    JOIN public."Organization" organization ON organization.id = licensee."orgId"
   WHERE actor.id = current_setting('app.user_id', true)
     AND actor.role::text = current_setting('app.role', true)
     AND actor.role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')
     AND actor."orgId" IS NULL AND actor."licenseeId" IS NULL
     AND actor."isActive" AND actor.status = 'ACTIVE'::public."UserStatus"
     AND actor."deletedAt" IS NULL AND actor."disabledAt" IS NULL
     AND licensee."isActive" AND licensee."suspendedAt" IS NULL AND organization."isActive"
     AND current_setting('app.organization_id', true) = organization.id
     AND current_setting('app.licensee_id', true) = licensee.id
     AND current_setting('app.auth_assurance', true) IN ('mfa-verified','step-up-verified')
     AND current_setting('app.purpose', true) = purpose_code
     AND current_setting('app.request_id', true) ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$';
  IF NOT FOUND THEN
    RAISE EXCEPTION 'C03_POLICY_ACTOR_DENIED' USING ERRCODE = '42501';
  END IF;
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_policy_context_valid()
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
  SELECT current_setting('app.purpose', true) LIKE 'incident-response-policy-%'
     AND EXISTS (
       SELECT 1
         FROM public."User" actor
         JOIN public."Licensee" licensee ON licensee.id = current_setting('app.licensee_id', true)
         JOIN public."Organization" organization ON organization.id = licensee."orgId"
        WHERE actor.id = current_setting('app.user_id', true)
          AND actor.role::text = current_setting('app.role', true)
          AND actor.role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')
          AND actor."orgId" IS NULL AND actor."licenseeId" IS NULL
          AND actor."isActive" AND actor.status = 'ACTIVE'::public."UserStatus"
          AND actor."deletedAt" IS NULL AND actor."disabledAt" IS NULL
          AND licensee."isActive" AND licensee."suspendedAt" IS NULL AND organization."isActive"
          AND current_setting('app.organization_id', true) = organization.id
          AND current_setting('app.auth_assurance', true) IN ('mfa-verified','step-up-verified')
     )
     AND current_setting('app.request_id', true) ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_policy_replay(
  command_name text,
  command_payload jsonb
)
RETURNS TABLE(replayed boolean, result jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  key_value text := 'c03-policy:' || current_setting('app.licensee_id', true) || ':' || current_setting('app.user_id', true) || ':' || command_name || ':' || current_setting('app.request_id', true);
  request_hash text := encode(sha256(convert_to(command_payload::text, 'UTF8')), 'hex');
  inserted integer;
  existing record;
BEGIN
  INSERT INTO public."ActionIdempotencyKey"
    (id, "keyHash", action, scope, "requestHash", "expiresAt")
  VALUES
    (gen_random_uuid()::text, key_value, 'c03-policy-' || command_name,
     current_setting('app.licensee_id', true), request_hash, transaction_timestamp() + interval '24 hours')
  ON CONFLICT ("keyHash") DO NOTHING;
  GET DIAGNOSTICS inserted = ROW_COUNT;

  IF inserted = 1 THEN
    RETURN QUERY SELECT false, NULL::jsonb;
    RETURN;
  END IF;

  SELECT idem."requestHash", idem."responsePayload"
    INTO existing
    FROM public."ActionIdempotencyKey" idem
   WHERE idem."keyHash" = key_value
   FOR UPDATE;
  IF existing."requestHash" IS DISTINCT FROM request_hash THEN
    RAISE EXCEPTION 'C03_POLICY_REPLAY_CONFLICT' USING ERRCODE = '40001';
  END IF;
  IF existing."responsePayload" IS NULL THEN
    RAISE EXCEPTION 'C03_POLICY_REPLAY_IN_PROGRESS' USING ERRCODE = '40001';
  END IF;
  RETURN QUERY SELECT true, existing."responsePayload";
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_complete_policy_command(
  command_name text,
  command_result jsonb
)
RETURNS void
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
  UPDATE public."ActionIdempotencyKey"
     SET "statusCode" = 200,
         "responsePayload" = command_result,
         "completedAt" = transaction_timestamp()
   WHERE "keyHash" = 'c03-policy:' || current_setting('app.licensee_id', true) || ':' || current_setting('app.user_id', true) || ':' || command_name || ':' || current_setting('app.request_id', true)
     AND "responsePayload" IS NULL
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_list_policy_rules(
  rule_type_filter text,
  active_filter boolean,
  row_limit integer,
  row_offset integer
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  licensee_id text := current_setting('app.licensee_id', true);
  result jsonb;
BEGIN
  PERFORM 1 FROM app_rls.c03_require_policy_actor(licensee_id, 'incident-response-policy-list');
  IF row_limit < 1 OR row_limit > 200 OR row_offset < 0
     OR (rule_type_filter IS NOT NULL AND rule_type_filter NOT IN (
       'DISTINCT_DEVICES','MULTI_COUNTRY','BURST_SCANS','TOO_MANY_REPORTS'
     )) THEN
    RAISE EXCEPTION 'C03_POLICY_LIST_INVALID' USING ERRCODE = '22023';
  END IF;

  SELECT jsonb_build_object(
    'rules', COALESCE(jsonb_agg(to_jsonb(selected) ORDER BY selected."updatedAt" DESC, selected.id DESC), '[]'::jsonb),
    'total', (SELECT count(*) FROM public."PolicyRule" p
               WHERE p."licenseeId" = licensee_id
                 AND (rule_type_filter IS NULL OR p."ruleType"::text = rule_type_filter)
                 AND (active_filter IS NULL OR p."isActive" = active_filter))
  )
    INTO result
    FROM (
      SELECT p.id, p."orgId", p."licenseeId", p."manufacturerId", p."createdByUserId",
             p.name, p.description, p."ruleType", p."isActive", p.threshold, p."windowMinutes",
             p.severity, p."autoCreateIncident", p."incidentSeverity", p."incidentPriority",
             p."actionConfig", p."createdAt", p."updatedAt"
        FROM public."PolicyRule" p
       WHERE p."licenseeId" = licensee_id
         AND (rule_type_filter IS NULL OR p."ruleType"::text = rule_type_filter)
         AND (active_filter IS NULL OR p."isActive" = active_filter)
       ORDER BY p."updatedAt" DESC, p.id DESC
       LIMIT row_limit OFFSET row_offset
    ) selected;
  RETURN result;
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_create_policy_rule(input jsonb)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  actor record;
  replay record;
  created public."PolicyRule"%ROWTYPE;
  result jsonb;
BEGIN
  IF jsonb_typeof(input) IS DISTINCT FROM 'object'
     OR EXISTS (
       SELECT 1 FROM jsonb_object_keys(input) AS keys(value)
        WHERE value NOT IN ('name','description','ruleType','isActive','threshold','windowMinutes',
                            'severity','autoCreateIncident','incidentSeverity','incidentPriority','actionConfig')
     )
     OR length(btrim(COALESCE(input->>'name',''))) NOT BETWEEN 3 AND 120
     OR (input->>'threshold')::integer NOT BETWEEN 1 AND 100000
     OR (input->>'windowMinutes')::integer NOT BETWEEN 1 AND 43200
     OR input->>'ruleType' NOT IN ('DISTINCT_DEVICES','MULTI_COUNTRY','BURST_SCANS','TOO_MANY_REPORTS')
     OR COALESCE(input->>'severity','MEDIUM') NOT IN ('LOW','MEDIUM','HIGH','CRITICAL')
     OR (input ? 'incidentSeverity' AND input->>'incidentSeverity' IS NOT NULL
         AND input->>'incidentSeverity' NOT IN ('LOW','MEDIUM','HIGH','CRITICAL'))
     OR (input ? 'incidentPriority' AND input->>'incidentPriority' IS NOT NULL
         AND input->>'incidentPriority' NOT IN ('P1','P2','P3','P4')) THEN
    RAISE EXCEPTION 'C03_POLICY_CREATE_INVALID' USING ERRCODE = '22023';
  END IF;

  SELECT * INTO actor
    FROM app_rls.c03_require_policy_actor(
      current_setting('app.licensee_id', true),
      'incident-response-policy-create'
    );
  SELECT * INTO replay FROM app_rls.c03_policy_replay('create', input);
  IF replay.replayed THEN
    RETURN replay.result || '{"__c03Replay":true}'::jsonb;
  END IF;

  INSERT INTO public."PolicyRule"
    (id, "orgId", "licenseeId", "createdByUserId", name, description, "ruleType", "isActive",
     threshold, "windowMinutes", severity, "autoCreateIncident", "incidentSeverity",
     "incidentPriority", "actionConfig", "updatedAt")
  VALUES
    (gen_random_uuid()::text, actor.organization_id, actor.licensee_id, actor.user_id,
     btrim(input->>'name'), NULLIF(input->>'description',''), (input->>'ruleType')::public."PolicyRuleType",
     COALESCE((input->>'isActive')::boolean, true), (input->>'threshold')::integer,
     (input->>'windowMinutes')::integer, COALESCE(input->>'severity','MEDIUM')::public."AlertSeverity",
     COALESCE((input->>'autoCreateIncident')::boolean, false),
     NULLIF(input->>'incidentSeverity','')::public."IncidentSeverity",
     NULLIF(input->>'incidentPriority','')::public."IncidentPriority",
     CASE WHEN input ? 'actionConfig' THEN input->'actionConfig' ELSE NULL END,
     transaction_timestamp())
  RETURNING * INTO created;
  result := to_jsonb(created);
  PERFORM app_rls.c03_complete_policy_command('create', result);
  RETURN result || '{"__c03Replay":false}'::jsonb;
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.c03_update_policy_rule(policy_rule_id text, patch jsonb)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  current_row public."PolicyRule"%ROWTYPE;
  replay record;
  updated public."PolicyRule"%ROWTYPE;
  result jsonb;
BEGIN
  IF policy_rule_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
     OR jsonb_typeof(patch) IS DISTINCT FROM 'object' OR patch = '{}'::jsonb
     OR EXISTS (
       SELECT 1 FROM jsonb_object_keys(patch) AS keys(value)
        WHERE value NOT IN ('name','description','ruleType','isActive','threshold','windowMinutes',
                            'severity','autoCreateIncident','incidentSeverity','incidentPriority','actionConfig')
     ) THEN
    RAISE EXCEPTION 'C03_POLICY_UPDATE_INVALID' USING ERRCODE = '22023';
  END IF;

  SELECT * INTO current_row FROM public."PolicyRule" WHERE id = policy_rule_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'C03_POLICY_NOT_FOUND' USING ERRCODE = 'P0002'; END IF;
  PERFORM 1 FROM app_rls.c03_require_policy_actor(current_row."licenseeId", 'incident-response-policy-update');
  SELECT * INTO replay FROM app_rls.c03_policy_replay('update:' || policy_rule_id, patch);
  IF replay.replayed THEN
    RETURN replay.result || '{"__c03Replay":true}'::jsonb;
  END IF;

  UPDATE public."PolicyRule" p
     SET name = CASE WHEN patch ? 'name' THEN btrim(patch->>'name') ELSE p.name END,
         description = CASE WHEN patch ? 'description' THEN patch->>'description' ELSE p.description END,
         "ruleType" = CASE WHEN patch ? 'ruleType' THEN (patch->>'ruleType')::public."PolicyRuleType" ELSE p."ruleType" END,
         "isActive" = CASE WHEN patch ? 'isActive' THEN (patch->>'isActive')::boolean ELSE p."isActive" END,
         threshold = CASE WHEN patch ? 'threshold' THEN (patch->>'threshold')::integer ELSE p.threshold END,
         "windowMinutes" = CASE WHEN patch ? 'windowMinutes' THEN (patch->>'windowMinutes')::integer ELSE p."windowMinutes" END,
         severity = CASE WHEN patch ? 'severity' THEN (patch->>'severity')::public."AlertSeverity" ELSE p.severity END,
         "autoCreateIncident" = CASE WHEN patch ? 'autoCreateIncident' THEN (patch->>'autoCreateIncident')::boolean ELSE p."autoCreateIncident" END,
         "incidentSeverity" = CASE WHEN patch ? 'incidentSeverity' THEN NULLIF(patch->>'incidentSeverity','')::public."IncidentSeverity" ELSE p."incidentSeverity" END,
         "incidentPriority" = CASE WHEN patch ? 'incidentPriority' THEN NULLIF(patch->>'incidentPriority','')::public."IncidentPriority" ELSE p."incidentPriority" END,
         "actionConfig" = CASE WHEN patch ? 'actionConfig' THEN patch->'actionConfig' ELSE p."actionConfig" END,
         "updatedAt" = transaction_timestamp()
   WHERE p.id = policy_rule_id
  RETURNING * INTO updated;
  IF length(updated.name) NOT BETWEEN 3 AND 120 OR updated.threshold NOT BETWEEN 1 AND 100000
     OR updated."windowMinutes" NOT BETWEEN 1 AND 43200 THEN
    RAISE EXCEPTION 'C03_POLICY_UPDATE_INVALID' USING ERRCODE = '22023';
  END IF;
  result := to_jsonb(updated);
  PERFORM app_rls.c03_complete_policy_command('update:' || policy_rule_id, result);
  RETURN result || '{"__c03Replay":false}'::jsonb;
END;
$$;

REVOKE ALL ON FUNCTION app_rls.c03_require_policy_actor(text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_policy_context_valid() FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_policy_replay(text,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_complete_policy_command(text,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_list_policy_rules(text,boolean,integer,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_create_policy_rule(jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.c03_update_policy_rule(text,jsonb) FROM PUBLIC;
