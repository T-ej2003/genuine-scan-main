-- Capability-bound notification and incident-email persistence.
-- {{AUTH_OWNER}} owns these functions; runtime roles receive exact EXECUTE only.

CREATE OR REPLACE FUNCTION app_rls.b03_authenticated_context_valid()
RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $fn$
BEGIN
  IF session_user <> {{APP_ROLE}}
     OR current_setting('app.auth_session_verified',true) <> '1'
     OR current_setting('app.b03_actor_id',true) IS DISTINCT FROM current_setting('app.user_id',true)
  THEN RETURN false; END IF;

  RETURN EXISTS (
    SELECT 1 FROM public."RefreshToken" session_row
     WHERE session_row.id=current_setting('app.auth_session_id',true)
       AND session_row."userId"=current_setting('app.b03_actor_id',true)
       AND session_row."sessionCapabilityHash"=current_setting('app.auth_session_hash',true)
       AND session_row."sessionCapabilityHashVersion"='sha256-v1'
       AND session_row."sessionCapabilityRevokedAt" IS NULL
       AND session_row."sessionCapabilityExpiresAt">clock_timestamp()
       AND session_row."revokedAt" IS NULL
       AND session_row."expiresAt">clock_timestamp()
  );
END
$fn$;

REVOKE ALL ON FUNCTION app_rls.b03_authenticated_context_valid() FROM PUBLIC;

CREATE OR REPLACE FUNCTION app_rls.b03_require_authenticated_actor(p_request_id text)
RETURNS TABLE(user_id text, role text, organization_id text, licensee_id text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $fn$
DECLARE actor record;
BEGIN
  IF p_request_id IS NULL OR length(p_request_id) NOT BETWEEN 1 AND 128
     OR p_request_id !~ '^[!-~]+$'
     OR p_request_id IS DISTINCT FROM current_setting('app.request_id', true) THEN
    RAISE EXCEPTION 'B03_AUTHENTICATED_BOUNDARY_DENIED' USING ERRCODE='42501';
  END IF;

  SELECT * INTO actor
  FROM app_rls.b01_authenticated_actor(
    current_setting('app.user_id', true),
    current_setting('app.auth_session_id', true),
    p_request_id
  );

  IF actor.role NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN','LICENSEE_ADMIN','MANUFACTURER_ADMIN') THEN
    RAISE EXCEPTION 'B03_AUTHENTICATED_BOUNDARY_DENIED' USING ERRCODE='42501';
  END IF;

  PERFORM set_config('app.b03_actor_id', actor."userId", true),
          set_config('app.b03_actor_role', actor.role, true),
          set_config('app.b03_actor_org_id', coalesce(actor."organizationId", ''), true),
          set_config('app.b03_actor_licensee_id', coalesce(actor."licenseeId", ''), true);

  RETURN QUERY SELECT actor."userId"::text, actor.role::text,
    actor."organizationId"::text, actor."licenseeId"::text;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.b03_assert_requested_scope(
  p_licensee_id text,
  p_organization_id text
) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $fn$
DECLARE actor_role text := current_setting('app.b03_actor_role', true);
DECLARE actor_id text := current_setting('app.b03_actor_id', true);
DECLARE actor_licensee text := nullif(current_setting('app.b03_actor_licensee_id', true), '');
DECLARE actor_org text := nullif(current_setting('app.b03_actor_org_id', true), '');
BEGIN
  IF actor_role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') THEN
    IF p_licensee_id IS NOT NULL AND NOT EXISTS (
      SELECT 1 FROM public."Licensee" l
      JOIN public."Organization" o ON o.id=l."orgId"
      WHERE l.id=p_licensee_id
        AND (p_organization_id IS NULL OR o.id=p_organization_id)
        AND l."isActive" AND l."suspendedAt" IS NULL AND o."isActive"
    ) THEN
      RAISE EXCEPTION 'B03_TENANT_SCOPE_DENIED' USING ERRCODE='42501';
    END IF;
  ELSIF actor_role='LICENSEE_ADMIN' THEN
    IF p_licensee_id IS DISTINCT FROM actor_licensee
       OR (p_organization_id IS NOT NULL AND p_organization_id IS DISTINCT FROM actor_org) THEN
      RAISE EXCEPTION 'B03_TENANT_SCOPE_DENIED' USING ERRCODE='42501';
    END IF;
  ELSIF actor_role='MANUFACTURER_ADMIN' THEN
    IF p_licensee_id IS NULL OR NOT EXISTS (
      SELECT 1 FROM public."ManufacturerLicenseeLink" ml
      JOIN public."Licensee" l ON l.id=ml."licenseeId"
      JOIN public."Organization" o ON o.id=l."orgId"
      WHERE ml."manufacturerId"=actor_id AND ml."licenseeId"=p_licensee_id
        AND (p_organization_id IS NULL OR p_organization_id=actor_org)
        AND l."isActive" AND l."suspendedAt" IS NULL AND o."isActive"
    ) THEN
      RAISE EXCEPTION 'B03_TENANT_SCOPE_DENIED' USING ERRCODE='42501';
    END IF;
  ELSE
    RAISE EXCEPTION 'B03_AUTHENTICATED_BOUNDARY_DENIED' USING ERRCODE='42501';
  END IF;

  PERFORM set_config('app.b03_licensee_id', coalesce(p_licensee_id, ''), true),
          set_config('app.b03_organization_id', coalesce(p_organization_id, ''), true);
  RETURN true;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.b03_primary_superadmin_email()
RETURNS TABLE(email text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $fn$
BEGIN
  PERFORM app_rls.b03_require_authenticated_actor(current_setting('app.request_id', true));
  PERFORM set_config('app.b03_operation','superadmin-read',true);
  RETURN QUERY
  SELECT u.email::text
  FROM public."User" u
  WHERE u.role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')
    AND u."isActive" AND u.status='ACTIVE' AND u."deletedAt" IS NULL
  ORDER BY u."createdAt",u.id
  LIMIT 1;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.b03_superadmin_alert_emails()
RETURNS TABLE(email text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $fn$
BEGIN
  PERFORM app_rls.b03_require_authenticated_actor(current_setting('app.request_id', true));
  PERFORM set_config('app.b03_operation','superadmin-read',true);
  RETURN QUERY
  SELECT u.email::text
  FROM public."User" u
  WHERE u.role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')
    AND u."isActive" AND u.status='ACTIVE' AND u."deletedAt" IS NULL
  ORDER BY u."createdAt",u.id
  LIMIT 100;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.b03_resolve_incident_email_actor(p_actor_user_id text)
RETURNS TABLE(id text,email text,name text,role text,active boolean)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $fn$
DECLARE actor record;
BEGIN
  SELECT * INTO actor
  FROM app_rls.b03_require_authenticated_actor(current_setting('app.request_id', true));
  IF p_actor_user_id IS DISTINCT FROM actor.user_id THEN
    RAISE EXCEPTION 'B03_INCIDENT_EMAIL_ACTOR_DENIED' USING ERRCODE='42501';
  END IF;
  PERFORM set_config('app.b03_operation','actor-read',true);
  RETURN QUERY
  SELECT u.id::text,u.email::text,u.name::text,u.role::text,
    (u."isActive" AND u.status='ACTIVE' AND u."deletedAt" IS NULL AND u."disabledAt" IS NULL)
  FROM public."User" u WHERE u.id=actor.user_id;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.b03_create_role_notifications(
  p_audience text,p_title text,p_body text,p_type text,p_licensee_id text,p_organization_id text,
  p_incident_id text,p_data jsonb,p_channels text[],p_request_id text
) RETURNS TABLE(
  "notificationId" text,"userId" text,"userEmail" text,"userRole" text,
  "userLicenseeId" text,"userOrganizationId" text,"channel" text,
  "writeResult" jsonb,"sideEffectRequired" boolean
)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $fn$
DECLARE actor record;
DECLARE channel_value text;
DECLARE recipient record;
DECLARE notification_id text;
DECLARE audience_roles text[];
BEGIN
  SELECT * INTO actor FROM app_rls.b03_require_authenticated_actor(p_request_id);
  IF p_audience NOT IN ('SUPER_ADMIN','LICENSEE_ADMIN','MANUFACTURER','ALL')
     OR p_title IS NULL OR length(p_title) NOT BETWEEN 1 AND 255
     OR p_body IS NULL OR length(p_body) NOT BETWEEN 1 AND 10000
     OR p_type IS NULL OR length(p_type) NOT BETWEEN 1 AND 128
     OR p_channels IS NULL OR cardinality(p_channels) NOT BETWEEN 1 AND 2
     OR EXISTS (SELECT 1 FROM unnest(p_channels) c WHERE c NOT IN ('WEB','EMAIL'))
     OR cardinality(p_channels)<>(SELECT count(DISTINCT c) FROM unnest(p_channels) c)
     OR octet_length(coalesce(p_data,'null'::jsonb)::text)>65536 THEN
    RAISE EXCEPTION 'B03_NOTIFICATION_INPUT_DENIED' USING ERRCODE='22023';
  END IF;
  PERFORM app_rls.b03_assert_requested_scope(p_licensee_id,p_organization_id);
  IF actor.role='LICENSEE_ADMIN' AND p_audience NOT IN ('LICENSEE_ADMIN','ALL') THEN
    RAISE EXCEPTION 'B03_NOTIFICATION_AUDIENCE_DENIED' USING ERRCODE='42501';
  END IF;
  IF actor.role='MANUFACTURER_ADMIN' AND p_audience NOT IN ('MANUFACTURER','ALL') THEN
    RAISE EXCEPTION 'B03_NOTIFICATION_AUDIENCE_DENIED' USING ERRCODE='42501';
  END IF;
  IF p_incident_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM public."Incident" i
    WHERE i.id=p_incident_id AND (p_licensee_id IS NULL OR i."licenseeId"=p_licensee_id)
  ) THEN
    RAISE EXCEPTION 'B03_INCIDENT_SCOPE_DENIED' USING ERRCODE='42501';
  END IF;

  audience_roles := CASE p_audience
    WHEN 'SUPER_ADMIN' THEN ARRAY['SUPER_ADMIN','PLATFORM_SUPER_ADMIN']
    WHEN 'LICENSEE_ADMIN' THEN ARRAY['LICENSEE_ADMIN']
    WHEN 'MANUFACTURER' THEN ARRAY['MANUFACTURER_ADMIN']
    ELSE ARRAY['SUPER_ADMIN','PLATFORM_SUPER_ADMIN','LICENSEE_ADMIN','MANUFACTURER_ADMIN']
  END;
  PERFORM set_config('app.b03_operation','notification-write',true);

  FOR recipient IN
    SELECT u.id,u.email,u.role::text AS role,u."licenseeId",u."orgId"
    FROM public."User" u
    WHERE u.role::text=ANY(audience_roles)
      AND u."isActive" AND u.status='ACTIVE' AND u."deletedAt" IS NULL AND u."disabledAt" IS NULL
      AND (p_licensee_id IS NULL OR u."licenseeId"=p_licensee_id OR (
        u.role='MANUFACTURER_ADMIN' AND EXISTS (
          SELECT 1 FROM public."ManufacturerLicenseeLink" ml
          WHERE ml."manufacturerId"=u.id AND ml."licenseeId"=p_licensee_id
        )
      ))
      AND (p_organization_id IS NULL OR u."orgId"=p_organization_id)
    ORDER BY u.id
  LOOP
    FOREACH channel_value IN ARRAY p_channels LOOP
      notification_id:=gen_random_uuid()::text;
      INSERT INTO public."Notification"(
        id,"userId","orgId","licenseeId","incidentId",audience,channel,type,title,body,data,"updatedAt"
      ) VALUES (
        notification_id,recipient.id,coalesce(p_organization_id,recipient."orgId"),
        coalesce(p_licensee_id,recipient."licenseeId"),p_incident_id,
        p_audience::public."NotificationAudience",channel_value::public."NotificationChannel",
        p_type,p_title,p_body,p_data,clock_timestamp()
      );
      RETURN QUERY SELECT notification_id,recipient.id::text,recipient.email::text,recipient.role,
        recipient."licenseeId"::text,recipient."orgId"::text,channel_value,
        jsonb_build_object('count',1),true;
    END LOOP;
  END LOOP;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.b03_create_user_notification(
  p_user_id text,p_title text,p_body text,p_type text,p_licensee_id text,p_organization_id text,
  p_incident_id text,p_data jsonb,p_channel text,p_request_id text
) RETURNS TABLE(
  "notificationId" text,"userId" text,"userEmail" text,"userRole" text,
  "userLicenseeId" text,"userOrganizationId" text,"channel" text,
  "writeResult" jsonb,"sideEffectRequired" boolean,"notification" jsonb
)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $fn$
DECLARE actor record;
DECLARE recipient record;
DECLARE notification_id text := gen_random_uuid()::text;
DECLARE projection jsonb;
BEGIN
  SELECT * INTO actor FROM app_rls.b03_require_authenticated_actor(p_request_id);
  IF p_channel NOT IN ('WEB','EMAIL') OR p_title IS NULL OR length(p_title) NOT BETWEEN 1 AND 255
     OR p_body IS NULL OR length(p_body) NOT BETWEEN 1 AND 10000
     OR p_type IS NULL OR length(p_type) NOT BETWEEN 1 AND 128
     OR octet_length(coalesce(p_data,'null'::jsonb)::text)>65536 THEN
    RAISE EXCEPTION 'B03_NOTIFICATION_INPUT_DENIED' USING ERRCODE='22023';
  END IF;
  PERFORM app_rls.b03_assert_requested_scope(p_licensee_id,p_organization_id);
  PERFORM set_config('app.b03_operation','notification-write',true),
          set_config('app.b03_target_user_id',p_user_id,true);
  SELECT u.id,u.email,u.role::text AS role,u."licenseeId",u."orgId" INTO recipient
  FROM public."User" u
  WHERE u.id=p_user_id AND u."isActive" AND u.status='ACTIVE'
    AND u."deletedAt" IS NULL AND u."disabledAt" IS NULL;
  IF NOT FOUND
     OR (actor.role='LICENSEE_ADMIN' AND recipient."licenseeId" IS DISTINCT FROM actor.licensee_id)
     OR (actor.role='MANUFACTURER_ADMIN' AND NOT EXISTS (
       SELECT 1 FROM public."ManufacturerLicenseeLink" ml
       WHERE ml."manufacturerId"=actor.user_id AND ml."licenseeId"=recipient."licenseeId"
     )) THEN
    RAISE EXCEPTION 'B03_NOTIFICATION_TARGET_DENIED' USING ERRCODE='42501';
  END IF;
  IF p_licensee_id IS NOT NULL AND recipient."licenseeId" IS DISTINCT FROM p_licensee_id THEN
    RAISE EXCEPTION 'B03_NOTIFICATION_TARGET_DENIED' USING ERRCODE='42501';
  END IF;

  INSERT INTO public."Notification"(
    id,"userId","orgId","licenseeId","incidentId",audience,channel,type,title,body,data,"updatedAt"
  ) VALUES (
    notification_id,recipient.id,coalesce(p_organization_id,recipient."orgId"),
    coalesce(p_licensee_id,recipient."licenseeId"),p_incident_id,'ALL',
    p_channel::public."NotificationChannel",p_type,p_title,p_body,p_data,clock_timestamp()
  );
  SELECT jsonb_build_object(
    'id',notification_id,'userId',recipient.id,'orgId',coalesce(p_organization_id,recipient."orgId"),
    'licenseeId',coalesce(p_licensee_id,recipient."licenseeId"),'incidentId',p_incident_id,
    'audience','ALL','channel',p_channel,'type',p_type,'title',p_title,'body',p_body,
    'data',p_data,'readAt',NULL,'emailedAt',NULL,'createdAt',clock_timestamp(),'updatedAt',clock_timestamp()
  ) INTO projection;
  RETURN QUERY SELECT notification_id,recipient.id::text,recipient.email::text,recipient.role,
    recipient."licenseeId"::text,recipient."orgId"::text,p_channel,
    jsonb_build_object('count',1),true,projection;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.b03_mark_notification_emailed(
  p_notification_id text,p_emailed_at timestamp without time zone,p_request_id text
) RETURNS TABLE(updated boolean)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $fn$
DECLARE actor record;
DECLARE changed integer;
BEGIN
  SELECT * INTO actor FROM app_rls.b03_require_authenticated_actor(p_request_id);
  IF p_emailed_at IS NULL OR abs(extract(epoch FROM (p_emailed_at-clock_timestamp())))>300 THEN
    RAISE EXCEPTION 'B03_NOTIFICATION_INPUT_DENIED' USING ERRCODE='22023';
  END IF;
  PERFORM set_config('app.b03_operation','notification-email-update',true),
          set_config('app.b03_notification_id',p_notification_id,true);
  UPDATE public."Notification" n SET "emailedAt"=coalesce(n."emailedAt",p_emailed_at),"updatedAt"=clock_timestamp()
  WHERE n.id=p_notification_id AND (
    actor.role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')
    OR n."userId"=actor.user_id
    OR (actor.role='LICENSEE_ADMIN' AND n."licenseeId"=actor.licensee_id)
    OR (actor.role='MANUFACTURER_ADMIN' AND EXISTS (
      SELECT 1 FROM public."ManufacturerLicenseeLink" ml
      WHERE ml."manufacturerId"=actor.user_id AND ml."licenseeId"=n."licenseeId"
    ))
  );
  GET DIAGNOSTICS changed=ROW_COUNT;
  RETURN QUERY SELECT changed=1;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.b03_list_notifications_for_user(
  p_user_id text,p_limit integer,p_offset integer,p_unread_only boolean,
  p_cursor_created_at timestamp without time zone,p_cursor_id text,p_request_id text
) RETURNS TABLE(notifications jsonb,total integer,unread integer)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $fn$
DECLARE actor record;
DECLARE audience_value text;
DECLARE rows_json jsonb;
DECLARE total_count integer;
DECLARE unread_count integer;
BEGIN
  SELECT * INTO actor FROM app_rls.b03_require_authenticated_actor(p_request_id);
  IF p_user_id IS DISTINCT FROM actor.user_id OR p_limit NOT BETWEEN 1 AND 100
     OR p_offset NOT BETWEEN 0 AND 1000000 THEN
    RAISE EXCEPTION 'B03_NOTIFICATION_READ_DENIED' USING ERRCODE='42501';
  END IF;
  audience_value:=CASE actor.role
    WHEN 'SUPER_ADMIN' THEN 'SUPER_ADMIN'
    WHEN 'PLATFORM_SUPER_ADMIN' THEN 'SUPER_ADMIN'
    WHEN 'LICENSEE_ADMIN' THEN 'LICENSEE_ADMIN'
    ELSE 'MANUFACTURER'
  END;
  PERFORM set_config('app.b03_operation','notification-read',true);

  WITH visible AS (
    SELECT n.id,n."userId",n."orgId",n."licenseeId",n."incidentId",n.audience,n.channel,
      n.type,n.title,n.body,n.data,n."readAt",n."emailedAt",n."createdAt",n."updatedAt"
    FROM public."Notification" n
    WHERE n.channel='WEB'
      AND (n."userId"=actor.user_id OR (
        n."userId" IS NULL AND n.audience::text IN ('ALL',audience_value)
        AND (
          actor.role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')
          OR n."licenseeId" IS NULL
          OR (actor.role='LICENSEE_ADMIN' AND n."licenseeId"=actor.licensee_id)
          OR (actor.role='MANUFACTURER_ADMIN' AND EXISTS (
            SELECT 1 FROM public."ManufacturerLicenseeLink" ml
            WHERE ml."manufacturerId"=actor.user_id AND ml."licenseeId"=n."licenseeId"
          ))
        )
      ))
      AND NOT (actor.role='LICENSEE_ADMIN' AND lower(n.type)=ANY(ARRAY[
        'manufacturer_batch_assigned','manufacturer_print_job_created','manufacturer_print_job_confirmed',
        'system_print_job_created','system_print_job_completed','system_print_job_failed','system_printer_status_changed'
      ]))
  ), page AS (
    SELECT * FROM visible
    WHERE (NOT p_unread_only OR "readAt" IS NULL)
      AND (p_cursor_created_at IS NULL OR ("createdAt",id)<(p_cursor_created_at,p_cursor_id))
    ORDER BY "createdAt" DESC,id DESC
    LIMIT p_limit OFFSET CASE WHEN p_cursor_created_at IS NULL THEN p_offset ELSE 0 END
  )
  SELECT
    (SELECT coalesce(jsonb_agg(to_jsonb(page) ORDER BY "createdAt" DESC,id DESC),'[]'::jsonb) FROM page),
    (SELECT count(*)::integer FROM visible WHERE (NOT p_unread_only OR "readAt" IS NULL)),
    (SELECT count(*)::integer FROM visible WHERE "readAt" IS NULL)
  INTO rows_json,total_count,unread_count;
  RETURN QUERY SELECT rows_json,
    CASE WHEN p_cursor_created_at IS NULL THEN total_count ELSE NULL END,
    unread_count;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.b03_mark_notification_read(
  p_notification_id text,p_user_id text,p_read_at timestamp without time zone,p_request_id text
) RETURNS TABLE(notification jsonb)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $fn$
DECLARE actor record;
DECLARE selected record;
BEGIN
  SELECT * INTO actor FROM app_rls.b03_require_authenticated_actor(p_request_id);
  IF p_user_id IS DISTINCT FROM actor.user_id OR p_read_at IS NULL
     OR abs(extract(epoch FROM (p_read_at-clock_timestamp())))>300 THEN
    RAISE EXCEPTION 'B03_NOTIFICATION_READ_DENIED' USING ERRCODE='42501';
  END IF;
  PERFORM set_config('app.b03_operation','notification-read-update',true),
          set_config('app.b03_notification_id',p_notification_id,true);
  SELECT n.id,n."userId",n."orgId",n."licenseeId",n."incidentId",n.audience,n.channel,
    n.type,n.title,n.body,n.data,n."readAt",n."emailedAt",n."createdAt",n."updatedAt"
    INTO selected FROM public."Notification" n
  WHERE n.id=p_notification_id AND n.channel='WEB' AND n."userId"=actor.user_id
  FOR UPDATE;
  IF NOT FOUND THEN RETURN QUERY SELECT NULL::jsonb; RETURN; END IF;
  UPDATE public."Notification" n
  SET "readAt"=coalesce(n."readAt",p_read_at),"updatedAt"=clock_timestamp()
  WHERE n.id=selected.id
  RETURNING n.id,n."userId",n."orgId",n."licenseeId",n."incidentId",n.audience,n.channel,
    n.type,n.title,n.body,n.data,n."readAt",n."emailedAt",n."createdAt",n."updatedAt"
    INTO selected;
  RETURN QUERY SELECT to_jsonb(selected);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.b03_mark_all_notifications_read(
  p_user_id text,p_read_at timestamp without time zone,p_request_id text
) RETURNS TABLE(count integer)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $fn$
DECLARE actor record;
DECLARE changed integer;
BEGIN
  SELECT * INTO actor FROM app_rls.b03_require_authenticated_actor(p_request_id);
  IF p_user_id IS DISTINCT FROM actor.user_id OR p_read_at IS NULL
     OR abs(extract(epoch FROM (p_read_at-clock_timestamp())))>300 THEN
    RAISE EXCEPTION 'B03_NOTIFICATION_READ_DENIED' USING ERRCODE='42501';
  END IF;
  PERFORM set_config('app.b03_operation','notification-read-update',true);
  UPDATE public."Notification" n
  SET "readAt"=p_read_at,"updatedAt"=clock_timestamp()
  WHERE n."userId"=actor.user_id AND n.channel='WEB' AND n."readAt" IS NULL;
  GET DIAGNOSTICS changed=ROW_COUNT;
  RETURN QUERY SELECT changed;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.b03_attention_queue_projection(
  p_licensee_id text,p_since timestamp without time zone,p_request_id text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $fn$
DECLARE actor record;
DECLARE incidents jsonb;
DECLARE alerts jsonb;
DECLARE tickets jsonb;
DECLARE audits jsonb;
BEGIN
  SELECT * INTO actor FROM app_rls.b03_require_authenticated_actor(p_request_id);
  IF p_since IS NULL
     OR p_since < clock_timestamp()-interval '25 hours'
     OR p_since > clock_timestamp()+interval '1 minute'
     OR (p_licensee_id IS NOT NULL AND p_licensee_id !~ '^[0-9a-fA-F-]{36}$') THEN
    RAISE EXCEPTION 'B03_ATTENTION_QUEUE_DENIED' USING ERRCODE='42501';
  END IF;
  IF actor.role IN ('LICENSEE_ADMIN','MANUFACTURER_ADMIN') AND p_licensee_id IS NULL THEN
    RAISE EXCEPTION 'B03_ATTENTION_QUEUE_DENIED' USING ERRCODE='42501';
  END IF;
  PERFORM app_rls.b03_assert_requested_scope(
    p_licensee_id,
    CASE WHEN actor.role='LICENSEE_ADMIN' THEN actor.organization_id ELSE NULL END
  );
  PERFORM set_config('app.b03_operation','attention-read',true);

  WITH visible AS MATERIALIZED (
    SELECT i.id,i."qrCodeValue",i.severity::text AS severity,i.status::text AS status,i."createdAt"
    FROM public."Incident" i
    WHERE i.status::text=ANY(ARRAY[
      'NEW','TRIAGED','TRIAGE','INVESTIGATING','CONTAINMENT','ERADICATION',
      'RECOVERY','AWAITING_CUSTOMER','AWAITING_LICENSEE','REOPENED'
    ])
      AND (p_licensee_id IS NULL OR i."licenseeId"=p_licensee_id)
      AND (actor.role<>'MANUFACTURER_ADMIN' OR
        EXISTS (
          SELECT 1 FROM public."QRCode" q JOIN public."Batch" b ON b.id=q."batchId"
          WHERE q.id=i."qrCodeId" AND b."manufacturerId"=actor.user_id
        ) OR EXISTS (
          SELECT 1 FROM public."QrScanLog" s JOIN public."Batch" b ON b.id=s."batchId"
          WHERE s.id=i."scanEventId" AND b."manufacturerId"=actor.user_id
        )
      )
  )
  SELECT jsonb_build_object(
    'count',count(*)::integer,
    'latest',(SELECT jsonb_build_object(
      'id',v.id,'qrCodeValue',v."qrCodeValue",'severity',v.severity,
      'status',v.status,'createdAt',v."createdAt"
    ) FROM visible v ORDER BY v."createdAt" DESC,v.id DESC LIMIT 1)
  ) INTO incidents FROM visible;

  WITH visible AS MATERIALIZED (
    SELECT a.id,a."alertType"::text AS "alertType",a.severity::text AS severity,
      a.message,a."createdAt"
    FROM public."PolicyAlert" a
    WHERE a."acknowledgedAt" IS NULL
      AND (p_licensee_id IS NULL OR a."licenseeId"=p_licensee_id)
      AND (actor.role<>'MANUFACTURER_ADMIN' OR a."manufacturerId"=actor.user_id)
  )
  SELECT jsonb_build_object(
    'count',count(*)::integer,
    'latest',(SELECT jsonb_build_object(
      'id',v.id,'alertType',v."alertType",'severity',v.severity,
      'message',v.message,'createdAt',v."createdAt"
    ) FROM visible v ORDER BY v."createdAt" DESC,v.id DESC LIMIT 1)
  ) INTO alerts FROM visible;

  WITH visible AS MATERIALIZED (
    SELECT t.id,t."referenceCode",t.status::text AS status,t.priority::text AS priority,t."updatedAt"
    FROM public."SupportTicket" t
    WHERE actor.role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')
      AND t.status::text=ANY(ARRAY['OPEN','IN_PROGRESS','WAITING_CUSTOMER'])
      AND (p_licensee_id IS NULL OR t."licenseeId"=p_licensee_id)
  )
  SELECT jsonb_build_object(
    'count',count(*)::integer,
    'latest',(SELECT jsonb_build_object(
      'id',v.id,'referenceCode',v."referenceCode",'status',v.status,
      'priority',v.priority,'updatedAt',v."updatedAt"
    ) FROM visible v ORDER BY v."updatedAt" DESC,v.id DESC LIMIT 1)
  ) INTO tickets FROM visible;

  WITH visible AS MATERIALIZED (
    SELECT a.id,a.action,a."entityType",a."entityId",a."createdAt"
    FROM public."AuditLog" a
    WHERE a."createdAt">=p_since
      AND (
        (actor.role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')
          AND (p_licensee_id IS NULL OR a."licenseeId"=p_licensee_id))
        OR (actor.role='LICENSEE_ADMIN' AND a."licenseeId"=actor.licensee_id)
        OR (actor.role='MANUFACTURER_ADMIN' AND a."userId"=actor.user_id)
      )
  )
  SELECT jsonb_build_object(
    'count',count(*)::integer,
    'latest',(SELECT jsonb_build_object(
      'id',v.id,'action',v.action,'entityType',v."entityType",
      'entityId',v."entityId",'createdAt',v."createdAt"
    ) FROM visible v ORDER BY v."createdAt" DESC,v.id DESC LIMIT 1)
  ) INTO audits FROM visible;

  RETURN jsonb_build_object(
    'incidents',incidents,'policyAlerts',alerts,
    'supportTickets',tickets,'auditEvents',audits
  );
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.b03_resolve_incident_notification_scope(p_incident_id text)
RETURNS TABLE("incidentId" text,"licenseeId" text,"manufacturerOrganizationId" text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $fn$
DECLARE actor record;
DECLARE incident_scope record;
BEGIN
  SELECT * INTO actor
  FROM app_rls.b03_require_authenticated_actor(current_setting('app.request_id', true));
  PERFORM set_config('app.b03_operation','incident-scope-read',true),
          set_config('app.b03_incident_id',p_incident_id,true);
  SELECT i.id,i."licenseeId",manufacturer."orgId" INTO incident_scope
  FROM public."Incident" i
  LEFT JOIN public."QRCode" qr ON qr.id=i."qrCodeId"
  LEFT JOIN public."Batch" b ON b.id=qr."batchId"
  LEFT JOIN public."User" manufacturer ON manufacturer.id=b."manufacturerId"
  WHERE i.id=p_incident_id;
  IF NOT FOUND
     OR (actor.role='LICENSEE_ADMIN' AND incident_scope."licenseeId" IS DISTINCT FROM actor.licensee_id)
     OR (actor.role='MANUFACTURER_ADMIN' AND NOT EXISTS (
       SELECT 1 FROM public."ManufacturerLicenseeLink" ml
       WHERE ml."manufacturerId"=actor.user_id AND ml."licenseeId"=incident_scope."licenseeId"
     )) THEN
    RAISE EXCEPTION 'B03_INCIDENT_SCOPE_DENIED' USING ERRCODE='42501';
  END IF;
  RETURN QUERY SELECT incident_scope.id::text,incident_scope."licenseeId"::text,
    incident_scope."orgId"::text;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.b03_claim_incident_email_delivery(
  p_incident_id text,p_licensee_id text,p_actor_user_id text,p_sender_mode text,
  p_to_address text,p_subject text,p_body_preview text,p_attempted_from text,p_used_from text,
  p_reply_to text,p_template text,p_request_id text,p_idempotency_key text,p_payload_digest text
) RETURNS TABLE(
  "deliveryId" text,"disposition" text,"delivered" boolean,"providerMessageId" text,
  "emailErrorCode" text,"attemptedFrom" text,"usedFrom" text,"replyTo" text
)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $fn$
DECLARE actor record;
DECLARE incident_scope record;
DECLARE existing record;
DECLARE delivery_id text := gen_random_uuid()::text;
BEGIN
  SELECT * INTO actor FROM app_rls.b03_require_authenticated_actor(p_request_id);
  IF p_sender_mode NOT IN ('actor','system') OR p_to_address IS NULL OR length(p_to_address) NOT BETWEEN 3 AND 320
     OR p_to_address !~ '^[^[:space:]@]+@[^[:space:]@]+$'
     OR p_subject IS NULL OR length(p_subject) NOT BETWEEN 1 AND 998
     OR length(coalesce(p_body_preview,''))>500
     OR p_idempotency_key !~ '^[0-9a-f]{64}$' OR p_payload_digest !~ '^[0-9a-f]{64}$'
     OR (p_sender_mode='actor' AND p_actor_user_id IS DISTINCT FROM actor.user_id) THEN
    RAISE EXCEPTION 'B03_INCIDENT_EMAIL_INPUT_DENIED' USING ERRCODE='22023';
  END IF;
  PERFORM set_config('app.b03_operation','incident-email-write',true),
          set_config('app.b03_incident_id',p_incident_id,true);
  SELECT i.id,i."licenseeId" INTO incident_scope
  FROM public."Incident" i WHERE i.id=p_incident_id;
  IF NOT FOUND OR (p_licensee_id IS NOT NULL AND p_licensee_id IS DISTINCT FROM incident_scope."licenseeId")
     OR (actor.role='LICENSEE_ADMIN' AND actor.licensee_id IS DISTINCT FROM incident_scope."licenseeId")
     OR (actor.role='MANUFACTURER_ADMIN' AND NOT EXISTS (
       SELECT 1 FROM public."ManufacturerLicenseeLink" ml
       WHERE ml."manufacturerId"=actor.user_id AND ml."licenseeId"=incident_scope."licenseeId"
     )) THEN
    RAISE EXCEPTION 'B03_INCIDENT_SCOPE_DENIED' USING ERRCODE='42501';
  END IF;

  PERFORM set_config('app.b03_licensee_id',coalesce(incident_scope."licenseeId",''),true);
  SELECT k.id,k."requestHash",k."statusCode",k."responsePayload",k."completedAt"
    INTO existing FROM public."ActionIdempotencyKey" k
  WHERE k."keyHash"=p_idempotency_key FOR UPDATE;
  IF FOUND THEN
    IF existing."requestHash" IS DISTINCT FROM p_payload_digest THEN
      RAISE EXCEPTION 'B03_IDEMPOTENCY_CONFLICT' USING ERRCODE='23505';
    END IF;
    RETURN QUERY SELECT existing."responsePayload"->>'deliveryId',
      CASE
        WHEN existing."completedAt" IS NULL THEN 'IN_FLIGHT'
        WHEN existing."statusCode"=200 THEN 'REPLAY_SENT'
        ELSE 'REPLAY_FAILED'
      END,
      existing."statusCode"=200,
      existing."responsePayload"->>'providerMessageId',
      existing."responsePayload"->>'emailErrorCode',
      existing."responsePayload"->>'attemptedFrom',
      existing."responsePayload"->>'usedFrom',
      existing."responsePayload"->>'replyTo';
    RETURN;
  END IF;

  INSERT INTO public."ActionIdempotencyKey"(
    id,"keyHash",action,scope,"requestHash","responsePayload","expiresAt"
  ) VALUES (
    gen_random_uuid()::text,p_idempotency_key,'b03-incident-email',p_incident_id,
    p_payload_digest,jsonb_build_object('deliveryId',delivery_id),clock_timestamp()+interval '1 day'
  );
  INSERT INTO public."IncidentCommunication"(
    id,"incidentId",direction,channel,"toAddress",subject,"bodyPreview","attemptedFrom",
    "usedFrom","replyTo",status
  ) VALUES (
    delivery_id,p_incident_id,'OUTBOUND','EMAIL',lower(p_to_address),p_subject,p_body_preview,
    p_attempted_from,p_used_from,p_reply_to,'QUEUED'
  );
  RETURN QUERY SELECT delivery_id,'CLAIMED',false,NULL::text,NULL::text,
    p_attempted_from,p_used_from,p_reply_to;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.b03_complete_incident_email_delivery(
  p_delivery_id text,p_idempotency_key text,p_provider_message_id text,p_email_error_code text,
  p_status text,p_smtp_config_source text,p_used_from text,p_completed_at timestamp without time zone
) RETURNS TABLE("communicationId" text,"eventId" text,"auditLogId" text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $fn$
DECLARE actor record;
DECLARE delivery record;
DECLARE idem record;
DECLARE event_id text := gen_random_uuid()::text;
DECLARE audit_id text := gen_random_uuid()::text;
DECLARE delivery_licensee_id text;
BEGIN
  SELECT * INTO actor
  FROM app_rls.b03_require_authenticated_actor(current_setting('app.request_id', true));
  IF p_status NOT IN ('QUEUED','SENT','FAILED')
     OR p_idempotency_key !~ '^[0-9a-f]{64}$'
     OR p_completed_at IS NULL OR abs(extract(epoch FROM (p_completed_at-clock_timestamp())))>300 THEN
    RAISE EXCEPTION 'B03_INCIDENT_EMAIL_INPUT_DENIED' USING ERRCODE='22023';
  END IF;
  PERFORM set_config('app.b03_operation','incident-email-complete',true);
  PERFORM set_config('app.b03_delivery_id',p_delivery_id,true);
  SELECT k.id,k."responsePayload",k."completedAt"
    INTO idem FROM public."ActionIdempotencyKey" k
  WHERE k."keyHash"=p_idempotency_key AND k.action='b03-incident-email' FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'B03_INCIDENT_EMAIL_CLAIM_REQUIRED' USING ERRCODE='42501'; END IF;
  IF idem."completedAt" IS NOT NULL THEN
    RETURN QUERY SELECT idem."responsePayload"->>'deliveryId',
      idem."responsePayload"->>'eventId',idem."responsePayload"->>'auditLogId';
    RETURN;
  END IF;
  SELECT c.id,c."incidentId",c."attemptedFrom",c."replyTo"
    INTO delivery FROM public."IncidentCommunication" c
  WHERE c.id=p_delivery_id AND c.id=(idem."responsePayload"->>'deliveryId') FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'B03_INCIDENT_EMAIL_CLAIM_REQUIRED' USING ERRCODE='42501'; END IF;
  PERFORM set_config('app.b03_incident_id',delivery."incidentId",true);
  SELECT i."licenseeId" INTO STRICT delivery_licensee_id
  FROM public."Incident" i WHERE i.id=delivery."incidentId";
  PERFORM set_config('app.b03_licensee_id',coalesce(delivery_licensee_id,''),true);
  UPDATE public."IncidentCommunication" c SET
    "providerMessageId"=p_provider_message_id,"errorMessage"=p_email_error_code,
    "usedFrom"=p_used_from,status=p_status::public."IncidentCommStatus"
  WHERE c.id=p_delivery_id;
  INSERT INTO public."IncidentEvent"(id,"incidentId","actorType","actorUserId","eventType","eventPayload")
  VALUES (
    event_id,delivery."incidentId",'ADMIN',actor.user_id,'EMAIL_SENT',
    jsonb_build_object('delivered',p_status='SENT','providerMessageId',p_provider_message_id,
      'emailErrorCode',p_email_error_code,'smtpConfigSource',p_smtp_config_source)
  );
  INSERT INTO public."AuditLog"(id,"userId","orgId","licenseeId",action,"entityType","entityId",details)
  SELECT audit_id,actor.user_id,actor.organization_id,i."licenseeId",'INCIDENT_EMAIL_SENT',
    'Incident',i.id,jsonb_build_object('status',p_status,'delivered',p_status='SENT',
      'providerMessageId',p_provider_message_id,'emailErrorCode',p_email_error_code,
      'smtpConfigSource',p_smtp_config_source,'usedFrom',p_used_from)
  FROM public."Incident" i WHERE i.id=delivery."incidentId";
  UPDATE public."ActionIdempotencyKey" k SET
    "statusCode"=CASE WHEN p_status='SENT' THEN 200 ELSE 502 END,
    "responsePayload"=jsonb_build_object(
      'deliveryId',p_delivery_id,'eventId',event_id,'auditLogId',audit_id,
      'providerMessageId',p_provider_message_id,'emailErrorCode',p_email_error_code,
      'attemptedFrom',delivery."attemptedFrom",'usedFrom',p_used_from,'replyTo',delivery."replyTo"
    ),
    "completedAt"=p_completed_at
  WHERE k.id=idem.id;
  RETURN QUERY SELECT p_delivery_id,event_id,audit_id;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.b03_list_support_tickets(
  p_licensee_id text,p_status text,p_priority text,p_search text,
  p_limit integer,p_offset integer,p_request_id text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $fn$
DECLARE actor record;
DECLARE result jsonb;
BEGIN
  SELECT * INTO actor FROM app_rls.b03_require_authenticated_actor(p_request_id);
  IF actor.role NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')
     OR current_setting('app.purpose',true) NOT IN ('support-ticket-read','support-ticket-update')
     OR p_limit NOT BETWEEN 1 AND 200 OR p_offset NOT BETWEEN 0 AND 2000
     OR (p_licensee_id IS NOT NULL AND p_licensee_id !~ '^[0-9a-fA-F-]{36}$')
     OR (p_status IS NOT NULL AND p_status NOT IN ('OPEN','IN_PROGRESS','WAITING_CUSTOMER','RESOLVED','CLOSED'))
     OR (p_priority IS NOT NULL AND p_priority NOT IN ('P1','P2','P3','P4'))
     OR length(coalesce(p_search,''))>120 THEN
    RAISE EXCEPTION 'B03_SUPPORT_TICKET_DENIED' USING ERRCODE='42501';
  END IF;
  PERFORM 1 FROM app_rls.require_recent_mfa_session(
    current_setting('app.auth_session_id',true),clock_timestamp()::timestamp without time zone,30
  );
  PERFORM set_config('app.b03_operation','support-ticket-read',true),
          set_config('app.b03_licensee_id',coalesce(p_licensee_id,''),true);
  WITH visible AS MATERIALIZED (
    SELECT t.id,t."incidentId",t."referenceCode",t."licenseeId",t."customerEmail",t.subject,
      t.status::text AS status,t.priority::text AS priority,t."assignedToUserId",
      t."slaDueAt",t."firstResponseAt",t."resolvedAt",t."createdAt",t."updatedAt",
      i."qrCodeValue",i.status::text AS "incidentStatus",i.severity::text AS "incidentSeverity",
      i."slaDueAt" AS "incidentSlaDueAt",h."currentStage"::text AS "handoffStage",
      h."slaDueAt" AS "handoffSlaDueAt",u.name AS "assignedToName"
    FROM public."SupportTicket" t
    JOIN public."Incident" i ON i.id=t."incidentId"
    LEFT JOIN public."IncidentHandoff" h ON h."incidentId"=i.id
    LEFT JOIN public."User" u ON u.id=t."assignedToUserId"
    WHERE (p_licensee_id IS NULL OR t."licenseeId"=p_licensee_id)
      AND (p_status IS NULL OR t.status::text=p_status)
      AND (p_priority IS NULL OR t.priority::text=p_priority)
      AND (coalesce(p_search,'')='' OR position(lower(p_search) in lower(t."referenceCode"))>0
        OR position(lower(p_search) in lower(t.subject))>0
        OR position(upper(p_search) in upper(i."qrCodeValue"))>0)
  ), page AS (
    SELECT * FROM visible ORDER BY "createdAt" DESC,id DESC LIMIT p_limit OFFSET p_offset
  )
  SELECT jsonb_build_object(
    'tickets',coalesce((SELECT jsonb_agg(jsonb_build_object(
      'id',p.id,'incidentId',p."incidentId",'referenceCode',p."referenceCode",
      'licenseeId',p."licenseeId",'customerEmail',p."customerEmail",'subject',p.subject,
      'status',p.status,'priority',p.priority,'assignedToUserId',p."assignedToUserId",
      'slaDueAt',p."slaDueAt",'firstResponseAt',p."firstResponseAt",'resolvedAt',p."resolvedAt",
      'createdAt',p."createdAt",'updatedAt',p."updatedAt",
      'incident',jsonb_build_object('id',p."incidentId",'qrCodeValue',p."qrCodeValue",
        'status',p."incidentStatus",'severity',p."incidentSeverity",'slaDueAt',p."incidentSlaDueAt",
        'handoff',CASE WHEN p."handoffStage" IS NULL THEN NULL ELSE jsonb_build_object(
          'currentStage',p."handoffStage",'slaDueAt',p."handoffSlaDueAt") END),
      'assignedToUser',CASE WHEN p."assignedToUserId" IS NULL THEN NULL ELSE
        jsonb_build_object('id',p."assignedToUserId",'name',p."assignedToName") END
    ) ORDER BY p."createdAt" DESC,p.id DESC) FROM page p),'[]'::jsonb),
    'total',(SELECT count(*)::integer FROM visible),
    'limit',p_limit,'offset',p_offset
  ) INTO result;
  RETURN result;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.b03_get_support_ticket(
  p_ticket_id text,p_request_id text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $fn$
DECLARE actor record;
DECLARE result jsonb;
BEGIN
  SELECT * INTO actor FROM app_rls.b03_require_authenticated_actor(p_request_id);
  IF actor.role NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')
     OR current_setting('app.purpose',true) NOT IN ('support-ticket-read','support-ticket-update')
     OR p_ticket_id !~ '^[0-9a-fA-F-]{36}$' THEN
    RAISE EXCEPTION 'B03_SUPPORT_TICKET_DENIED' USING ERRCODE='42501';
  END IF;
  PERFORM 1 FROM app_rls.require_recent_mfa_session(
    current_setting('app.auth_session_id',true),clock_timestamp()::timestamp without time zone,30
  );
  PERFORM set_config('app.b03_operation','support-ticket-detail',true),
          set_config('app.b03_support_ticket_id',p_ticket_id,true);
  SELECT jsonb_build_object(
    'id',t.id,'incidentId',t."incidentId",'referenceCode',t."referenceCode",
    'licenseeId',t."licenseeId",'customerEmail',t."customerEmail",'subject',t.subject,
    'status',t.status::text,'priority',t.priority::text,'assignedToUserId',t."assignedToUserId",
    'slaDueAt',t."slaDueAt",'firstResponseAt',t."firstResponseAt",'resolvedAt',t."resolvedAt",
    'createdAt',t."createdAt",'updatedAt',t."updatedAt",
    'incident',jsonb_build_object('id',i.id,'qrCodeValue',i."qrCodeValue",
      'status',i.status::text,'severity',i.severity::text,'slaDueAt',i."slaDueAt",
      'handoff',CASE WHEN h.id IS NULL THEN NULL ELSE jsonb_build_object(
        'currentStage',h."currentStage"::text,'slaDueAt',h."slaDueAt") END),
    'assignedToUser',CASE WHEN u.id IS NULL THEN NULL ELSE jsonb_build_object('id',u.id,'name',u.name) END,
    'messages',coalesce((SELECT jsonb_agg(jsonb_build_object(
      'id',m.id,'actorType',m."actorType"::text,'actorUserId',m."actorUserId",
      'message',m.message,'isInternal',m."isInternal",'createdAt',m."createdAt",
      'actorUser',CASE WHEN author.id IS NULL THEN NULL ELSE jsonb_build_object('id',author.id,'name',author.name) END
    ) ORDER BY m."createdAt",m.id)
      FROM public."SupportTicketMessage" m LEFT JOIN public."User" author ON author.id=m."actorUserId"
      WHERE m."ticketId"=t.id),'[]'::jsonb)
  ) INTO result
  FROM public."SupportTicket" t
  JOIN public."Incident" i ON i.id=t."incidentId"
  LEFT JOIN public."IncidentHandoff" h ON h."incidentId"=i.id
  LEFT JOIN public."User" u ON u.id=t."assignedToUserId"
  WHERE t.id=p_ticket_id;
  RETURN result;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.b03_update_support_ticket(
  p_ticket_id text,p_status text,p_assigned_to_user_id text,p_set_assignee boolean,
  p_changed_at timestamp without time zone,p_request_id text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $fn$
DECLARE actor record;
DECLARE ticket record;
DECLARE audit_id text:=gen_random_uuid()::text;
BEGIN
  SELECT * INTO actor FROM app_rls.b03_require_authenticated_actor(p_request_id);
  IF actor.role NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')
     OR current_setting('app.purpose',true)<>'support-ticket-update'
     OR p_ticket_id !~ '^[0-9a-fA-F-]{36}$'
     OR (p_status IS NOT NULL AND p_status NOT IN ('OPEN','IN_PROGRESS','WAITING_CUSTOMER','RESOLVED','CLOSED'))
     OR (p_set_assignee AND p_assigned_to_user_id IS NOT NULL AND p_assigned_to_user_id !~ '^[0-9a-fA-F-]{36}$')
     OR p_changed_at IS NULL OR abs(extract(epoch FROM (p_changed_at-clock_timestamp())))>300 THEN
    RAISE EXCEPTION 'B03_SUPPORT_TICKET_DENIED' USING ERRCODE='42501';
  END IF;
  PERFORM 1 FROM app_rls.require_recent_mfa_session(
    current_setting('app.auth_session_id',true),clock_timestamp()::timestamp without time zone,30
  );
  PERFORM set_config('app.b03_operation','support-ticket-update',true),
          set_config('app.b03_support_ticket_id',p_ticket_id,true);
  SELECT t.id,t."licenseeId" INTO ticket FROM public."SupportTicket" t WHERE t.id=p_ticket_id FOR UPDATE;
  IF NOT FOUND THEN RETURN NULL; END IF;
  IF p_set_assignee AND p_assigned_to_user_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM public."User" u WHERE u.id=p_assigned_to_user_id
      AND u.role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') AND u."isActive" AND u.status='ACTIVE' AND u."deletedAt" IS NULL
  ) THEN RAISE EXCEPTION 'B03_SUPPORT_TICKET_ASSIGNEE_DENIED' USING ERRCODE='42501'; END IF;
  UPDATE public."SupportTicket" t SET
    status=coalesce(p_status,t.status::text)::public."SupportTicketStatus",
    "assignedToUserId"=CASE WHEN p_set_assignee THEN p_assigned_to_user_id ELSE t."assignedToUserId" END,
    "resolvedAt"=CASE WHEN p_status IN ('RESOLVED','CLOSED') THEN p_changed_at
      WHEN p_status IS NOT NULL THEN NULL ELSE t."resolvedAt" END,
    "updatedAt"=p_changed_at
  WHERE t.id=p_ticket_id;
  PERFORM set_config('app.b03_licensee_id',coalesce(ticket."licenseeId",''),true);
  INSERT INTO public."AuditLog"(id,"userId","orgId","licenseeId",action,"entityType","entityId",details,"createdAt")
  VALUES (audit_id,actor.user_id,actor.organization_id,ticket."licenseeId",'SUPPORT_TICKET_UPDATED',
    'SupportTicket',p_ticket_id,jsonb_build_object('status',p_status,'assignedToUserId',p_assigned_to_user_id),p_changed_at);
  RETURN app_rls.b03_get_support_ticket(p_ticket_id,p_request_id);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.b03_add_support_ticket_message(
  p_ticket_id text,p_message text,p_is_internal boolean,
  p_created_at timestamp without time zone,p_request_id text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $fn$
DECLARE actor record;
DECLARE ticket record;
DECLARE message_id text:=gen_random_uuid()::text;
BEGIN
  SELECT * INTO actor FROM app_rls.b03_require_authenticated_actor(p_request_id);
  IF actor.role NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')
     OR current_setting('app.purpose',true)<>'support-ticket-message'
     OR p_ticket_id !~ '^[0-9a-fA-F-]{36}$'
     OR length(btrim(coalesce(p_message,''))) NOT BETWEEN 2 AND 4000
     OR p_created_at IS NULL OR abs(extract(epoch FROM (p_created_at-clock_timestamp())))>300 THEN
    RAISE EXCEPTION 'B03_SUPPORT_TICKET_DENIED' USING ERRCODE='42501';
  END IF;
  PERFORM 1 FROM app_rls.require_recent_mfa_session(
    current_setting('app.auth_session_id',true),clock_timestamp()::timestamp without time zone,30
  );
  PERFORM set_config('app.b03_operation','support-ticket-message',true),
          set_config('app.b03_support_ticket_id',p_ticket_id,true);
  SELECT t.id,t."licenseeId" INTO ticket FROM public."SupportTicket" t WHERE t.id=p_ticket_id;
  IF NOT FOUND THEN RETURN NULL; END IF;
  PERFORM set_config('app.b03_licensee_id',coalesce(ticket."licenseeId",''),true);
  INSERT INTO public."SupportTicketMessage"(
    id,"ticketId","actorType","actorUserId",message,"isInternal","createdAt"
  ) VALUES (message_id,p_ticket_id,'ADMIN',actor.user_id,btrim(p_message),p_is_internal,p_created_at);
  INSERT INTO public."AuditLog"(id,"userId","orgId","licenseeId",action,"entityType","entityId",details,"createdAt")
  VALUES (gen_random_uuid()::text,actor.user_id,actor.organization_id,ticket."licenseeId",
    'SUPPORT_TICKET_MESSAGE_ADDED','SupportTicket',p_ticket_id,
    jsonb_build_object('isInternal',p_is_internal,'messageLength',length(btrim(p_message))),p_created_at);
  RETURN jsonb_build_object(
    'id',message_id,'ticketId',p_ticket_id,'actorType','ADMIN','actorUserId',actor.user_id,
    'message',btrim(p_message),'isInternal',p_is_internal,'createdAt',p_created_at,
    'actorUser',jsonb_build_object('id',actor.user_id,'name',(SELECT u.name FROM public."User" u WHERE u.id=actor.user_id))
  );
END
$fn$;

REVOKE ALL ON FUNCTION app_rls.b03_require_authenticated_actor(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.b03_assert_requested_scope(text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.b03_primary_superadmin_email() FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.b03_superadmin_alert_emails() FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.b03_resolve_incident_email_actor(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.b03_create_role_notifications(text,text,text,text,text,text,text,jsonb,text[],text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.b03_create_user_notification(text,text,text,text,text,text,text,jsonb,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.b03_mark_notification_emailed(text,timestamp without time zone,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.b03_list_notifications_for_user(text,integer,integer,boolean,timestamp without time zone,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.b03_mark_notification_read(text,text,timestamp without time zone,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.b03_mark_all_notifications_read(text,timestamp without time zone,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.b03_attention_queue_projection(text,timestamp without time zone,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.b03_resolve_incident_notification_scope(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.b03_claim_incident_email_delivery(text,text,text,text,text,text,text,text,text,text,text,text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.b03_complete_incident_email_delivery(text,text,text,text,text,text,text,timestamp without time zone) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.b03_list_support_tickets(text,text,text,text,integer,integer,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.b03_get_support_ticket(text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.b03_update_support_ticket(text,text,text,boolean,timestamp without time zone,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.b03_add_support_ticket_message(text,text,boolean,timestamp without time zone,text) FROM PUBLIC;
