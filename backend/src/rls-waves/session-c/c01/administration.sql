CREATE SCHEMA IF NOT EXISTS app_rls;

CREATE OR REPLACE FUNCTION app_rls.session_c_assert_admin(required_purpose text, allow_tenant boolean)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  actor jsonb;
  actor_role text := current_setting('app.role', true);
  actor_id text := current_setting('app.user_id', true);
  actor_licensee text := current_setting('app.licensee_id', true);
  actor_org text := current_setting('app.organization_id', true);
BEGIN
  IF current_setting('app.purpose', true) IS DISTINCT FROM required_purpose
     OR current_setting('app.auth_assurance', true) IS DISTINCT FROM 'mfa-verified'
     OR current_setting('app.request_id', true) !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' THEN
    RAISE EXCEPTION 'SESSION_C_INVALID_CONTEXT';
  END IF;

  SELECT jsonb_build_object('id', u.id, 'role', u.role::text, 'licenseeId', u."licenseeId", 'orgId', u."orgId")
    INTO actor
    FROM public."User" u
   WHERE u.id::text = actor_id
     AND u.role::text = actor_role
     AND u."isActive" = true
     AND u.status = 'ACTIVE'::public."UserStatus"
     AND u."deletedAt" IS NULL
     AND u."disabledAt" IS NULL
   FOR UPDATE;
  IF actor IS NULL THEN RAISE EXCEPTION 'SESSION_C_DISABLED_OR_STALE_ACTOR'; END IF;

  IF actor_role IN ('SUPER_ADMIN', 'PLATFORM_SUPER_ADMIN') THEN
    IF actor->>'licenseeId' IS NOT NULL OR actor->>'orgId' IS NOT NULL THEN
      RAISE EXCEPTION 'SESSION_C_STALE_PLATFORM_SCOPE';
    END IF;
  ELSIF allow_tenant AND actor_role IN ('LICENSEE_ADMIN', 'ORG_ADMIN') THEN
    IF NULLIF(actor_licensee, '') IS DISTINCT FROM actor->>'licenseeId'
       OR NULLIF(actor_org, '') IS DISTINCT FROM actor->>'orgId'
       OR NOT EXISTS (
         SELECT 1 FROM public."Licensee" l
         JOIN public."Organization" o ON o.id = l."orgId"
         WHERE l.id::text = actor_licensee AND o.id::text = actor_org
           AND l."isActive" AND l."suspendedAt" IS NULL AND o."isActive"
       ) THEN
      RAISE EXCEPTION 'SESSION_C_FOREIGN_SCOPE';
    END IF;
  ELSE
    RAISE EXCEPTION 'SESSION_C_WRONG_ROLE';
  END IF;
  RETURN actor;
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.session_c_user_projection(target_id text)
RETURNS jsonb
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
  SELECT jsonb_build_object(
    'id', u.id, 'email', u.email, 'name', u.name, 'role', u.role,
    'licenseeId', u."licenseeId", 'isActive', u."isActive", 'deletedAt', u."deletedAt",
    'createdAt', u."createdAt", 'location', u.location, 'website', u.website,
    'licensee', CASE WHEN l.id IS NULL THEN NULL ELSE jsonb_build_object(
      'id', l.id, 'name', l.name, 'prefix', l.prefix, 'brandName', l."brandName") END,
    'manufacturerLicenseeLinks', COALESCE((
      SELECT jsonb_agg(jsonb_build_object(
        'licenseeId', ml."licenseeId", 'isPrimary', ml."isPrimary",
        'licensee', jsonb_build_object('id', ll.id, 'name', ll.name, 'prefix', ll.prefix,
          'brandName', ll."brandName", 'orgId', ll."orgId")) ORDER BY ml."isPrimary" DESC, ml."createdAt")
      FROM public."ManufacturerLicenseeLink" ml
      JOIN public."Licensee" ll ON ll.id = ml."licenseeId"
      WHERE ml."manufacturerId" = u.id
    ), '[]'::jsonb)
  )
  FROM public."User" u
  LEFT JOIN public."Licensee" l ON l.id = u."licenseeId"
  WHERE u.id = target_id
$$;

CREATE OR REPLACE FUNCTION app_rls.session_c_audit_context_valid()
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
  SELECT current_setting('app.purpose', true) LIKE 'administration-%'
     AND current_setting('app.auth_assurance', true) = 'mfa-verified'
     AND current_setting('app.request_id', true) ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
     AND EXISTS (
       SELECT 1 FROM public."User" u
       WHERE u.id = current_setting('app.user_id', true)
         AND u.role::text = current_setting('app.role', true)
         AND u."isActive" AND u.status = 'ACTIVE'::public."UserStatus"
         AND u."deletedAt" IS NULL AND u."disabledAt" IS NULL
         AND (
           u.role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')
           OR (u."licenseeId" = current_setting('app.licensee_id', true)
               AND u."orgId" = current_setting('app.organization_id', true))
         )
     )
$$;

CREATE OR REPLACE FUNCTION app_rls.session_c_admin_command(command_name text, payload jsonb)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  purpose text := 'administration-' || command_name;
  actor jsonb;
  target text;
  target_licensee text;
  target_org text;
  target_role text;
  result jsonb;
  patch jsonb;
  hard_delete boolean;
  remaining record;
  affected integer := 0;
  idempotency_key text;
  key_hash text;
  request_hash text;
  prior record;
BEGIN
  actor := app_rls.session_c_assert_admin(purpose, command_name NOT IN ('create-licensee', 'update-licensee', 'delete-licensee'));

  IF command_name = 'create-licensee' THEN
    IF actor->>'role' NOT IN ('SUPER_ADMIN', 'PLATFORM_SUPER_ADMIN') THEN RAISE EXCEPTION 'SESSION_C_WRONG_ROLE'; END IF;
    target := payload->>'id';
    idempotency_key := NULLIF(btrim(payload->>'idempotencyKey'), '');
    IF idempotency_key IS NOT NULL THEN
      key_hash := encode(sha256(convert_to((actor->>'id') || '|' || purpose || '|' || idempotency_key, 'UTF8')), 'hex');
      request_hash := encode(sha256(convert_to(
        jsonb_set(payload - 'idempotencyKey' - 'id', '{admin}', (payload->'admin') - 'passwordHash')::text,
        'UTF8'
      )), 'hex');
      PERFORM pg_advisory_xact_lock(hashtextextended(key_hash, 0));
      SELECT "requestHash", "completedAt", "responsePayload" INTO prior
        FROM public."ActionIdempotencyKey" WHERE "keyHash" = key_hash FOR UPDATE;
      IF FOUND THEN
        IF prior."requestHash" IS DISTINCT FROM request_hash THEN RAISE EXCEPTION 'SESSION_C_IDEMPOTENCY_CONFLICT'; END IF;
        IF prior."completedAt" IS NULL THEN RAISE EXCEPTION 'SESSION_C_IDEMPOTENCY_IN_PROGRESS'; END IF;
        RETURN COALESCE(prior."responsePayload", '{}'::jsonb) || '{"replayed":true}'::jsonb;
      END IF;
      INSERT INTO public."ActionIdempotencyKey" (id, "keyHash", action, scope, "requestHash", "expiresAt")
      VALUES (gen_random_uuid()::text, key_hash, 'licensee.create', actor->>'id', request_hash, transaction_timestamp() + interval '30 minutes');
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(upper(payload->'licensee'->>'prefix'), 0));
    IF EXISTS (SELECT 1 FROM public."Licensee" WHERE prefix = upper(payload->'licensee'->>'prefix'))
       OR EXISTS (SELECT 1 FROM public."User" WHERE email = lower(payload->'admin'->>'email')) THEN
      RAISE EXCEPTION 'SESSION_C_DUPLICATE_LICENSEE_OR_ADMIN';
    END IF;
    INSERT INTO public."Organization" (id, name, "isActive", "updatedAt")
    VALUES (target, payload->'licensee'->>'name', COALESCE((payload->'licensee'->>'isActive')::boolean, true), transaction_timestamp());
    INSERT INTO public."Licensee" (id, "orgId", name, prefix, description, "brandName", location, website, "supportEmail", "supportPhone", "isActive", "updatedAt")
    VALUES (target, target, payload->'licensee'->>'name', upper(payload->'licensee'->>'prefix'),
      payload->'licensee'->>'description', payload->'licensee'->>'brandName', payload->'licensee'->>'location',
      payload->'licensee'->>'website', payload->'licensee'->>'supportEmail', payload->'licensee'->>'supportPhone',
      COALESCE((payload->'licensee'->>'isActive')::boolean, true), transaction_timestamp());
    IF NOT COALESCE((payload->'admin'->>'sendInvite')::boolean, false) THEN
      INSERT INTO public."User" (id, email, "passwordHash", name, role, "orgId", "licenseeId", status, "isActive", "emailVerifiedAt", "updatedAt")
      VALUES (gen_random_uuid()::text, lower(payload->'admin'->>'email'), payload->'admin'->>'passwordHash', payload->'admin'->>'name',
        'LICENSEE_ADMIN'::public."UserRole", target, target, 'ACTIVE'::public."UserStatus", true, transaction_timestamp(), transaction_timestamp());
    END IF;
    SELECT jsonb_build_object(
      'licensee', to_jsonb(l),
      'adminUser', (SELECT app_rls.session_c_user_projection(u.id) FROM public."User" u WHERE u."licenseeId" = target AND u.role = 'LICENSEE_ADMIN'::public."UserRole" LIMIT 1),
      'replayed', false) INTO result FROM public."Licensee" l WHERE l.id = target;
    IF key_hash IS NOT NULL THEN
      UPDATE public."ActionIdempotencyKey" SET "statusCode" = 201, "responsePayload" = result, "completedAt" = transaction_timestamp()
       WHERE "keyHash" = key_hash;
    END IF;
    RETURN result;
  END IF;

  target := payload->>'id';
  PERFORM pg_advisory_xact_lock(hashtextextended(target, 0));

  IF command_name IN ('update-licensee', 'delete-licensee') THEN
    IF actor->>'role' NOT IN ('SUPER_ADMIN', 'PLATFORM_SUPER_ADMIN') THEN RAISE EXCEPTION 'SESSION_C_WRONG_ROLE'; END IF;
    SELECT id, "orgId" INTO target_licensee, target_org FROM public."Licensee" WHERE id = target FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'SESSION_C_LICENSEE_NOT_FOUND'; END IF;
    IF command_name = 'update-licensee' THEN
      patch := payload->'patch';
      UPDATE public."Licensee" SET
        name = CASE WHEN patch ? 'name' THEN patch->>'name' ELSE name END,
        description = CASE WHEN patch ? 'description' THEN patch->>'description' ELSE description END,
        "brandName" = CASE WHEN patch ? 'brandName' THEN patch->>'brandName' ELSE "brandName" END,
        location = CASE WHEN patch ? 'location' THEN patch->>'location' ELSE location END,
        website = CASE WHEN patch ? 'website' THEN patch->>'website' ELSE website END,
        "supportEmail" = CASE WHEN patch ? 'supportEmail' THEN patch->>'supportEmail' ELSE "supportEmail" END,
        "supportPhone" = CASE WHEN patch ? 'supportPhone' THEN patch->>'supportPhone' ELSE "supportPhone" END,
        "isActive" = CASE WHEN patch ? 'isActive' THEN (patch->>'isActive')::boolean ELSE "isActive" END,
        "updatedAt" = transaction_timestamp()
      WHERE id = target;
      SELECT jsonb_build_object('licensee', to_jsonb(l)) INTO result FROM public."Licensee" l WHERE l.id = target;
      RETURN result;
    END IF;
    IF EXISTS (SELECT 1 FROM public."User" WHERE "licenseeId" = target)
       OR EXISTS (SELECT 1 FROM public."Batch" WHERE "licenseeId" = target)
       OR EXISTS (SELECT 1 FROM public."QRRange" WHERE "licenseeId" = target)
       OR EXISTS (SELECT 1 FROM public."QRCode" WHERE "licenseeId" = target) THEN
      RAISE EXCEPTION 'SESSION_C_LICENSEE_LINKED_DATA';
    END IF;
    DELETE FROM public."Licensee" WHERE id = target;
    RETURN jsonb_build_object('licenseeId', target_licensee, 'organizationId', target_org);
  END IF;

  IF command_name = 'create-user' THEN
    target_licensee := payload->>'licenseeId';
    SELECT l."orgId" INTO target_org FROM public."Licensee" l JOIN public."Organization" o ON o.id = l."orgId"
      WHERE l.id = target_licensee AND l."isActive" AND l."suspendedAt" IS NULL AND o."isActive" FOR UPDATE OF l;
    IF NOT FOUND THEN RAISE EXCEPTION 'SESSION_C_LICENSEE_NOT_FOUND'; END IF;
    target_role := payload->>'role';
    IF actor->>'role' IN ('LICENSEE_ADMIN', 'ORG_ADMIN') THEN
      IF actor->>'licenseeId' IS DISTINCT FROM target_licensee OR target_role NOT IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') THEN
        RAISE EXCEPTION 'SESSION_C_FOREIGN_SCOPE';
      END IF;
    END IF;
    BEGIN
      INSERT INTO public."User" (id, email, "passwordHash", name, role, "orgId", "licenseeId", location, website, status, "isActive", "emailVerifiedAt", "updatedAt")
      VALUES (gen_random_uuid()::text, lower(payload->>'email'), payload->>'passwordHash', payload->>'name', target_role::public."UserRole",
        target_org, target_licensee, payload->>'location', payload->>'website', 'ACTIVE'::public."UserStatus", true, transaction_timestamp(), transaction_timestamp())
      RETURNING id INTO target;
    EXCEPTION WHEN unique_violation THEN RAISE EXCEPTION 'SESSION_C_DUPLICATE_USER'; END;
    IF target_role IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') THEN
      INSERT INTO public."ManufacturerLicenseeLink" ("manufacturerId", "licenseeId", "isPrimary", "updatedAt") VALUES (target, target_licensee, true, transaction_timestamp());
    END IF;
    RETURN jsonb_build_object('user', app_rls.session_c_user_projection(target), 'licenseeId', target_licensee, 'organizationId', target_org);
  END IF;

  SELECT u."licenseeId", u."orgId", u.role::text INTO target_licensee, target_org, target_role
    FROM public."User" u WHERE u.id = target FOR UPDATE;
  IF NOT FOUND OR target_role NOT IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') THEN RAISE EXCEPTION 'SESSION_C_USER_NOT_FOUND'; END IF;
  IF actor->>'role' IN ('LICENSEE_ADMIN', 'ORG_ADMIN') AND NOT EXISTS (
    SELECT 1 FROM public."ManufacturerLicenseeLink" ml WHERE ml."manufacturerId" = target AND ml."licenseeId" = actor->>'licenseeId'
  ) THEN RAISE EXCEPTION 'SESSION_C_FOREIGN_SCOPE'; END IF;

  IF command_name = 'update-user' THEN
    patch := payload->'patch';
    IF patch ? 'licenseeId' THEN
      IF actor->>'role' NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') THEN RAISE EXCEPTION 'SESSION_C_WRONG_ROLE'; END IF;
      target_licensee := patch->>'licenseeId';
      SELECT l."orgId" INTO target_org FROM public."Licensee" l JOIN public."Organization" o ON o.id=l."orgId"
       WHERE l.id=target_licensee AND l."isActive" AND l."suspendedAt" IS NULL AND o."isActive";
      IF NOT FOUND THEN RAISE EXCEPTION 'SESSION_C_LICENSEE_NOT_FOUND'; END IF;
      UPDATE public."ManufacturerLicenseeLink" SET "isPrimary"=false, "updatedAt"=transaction_timestamp()
       WHERE "manufacturerId"=target AND "isPrimary";
      INSERT INTO public."ManufacturerLicenseeLink" ("manufacturerId","licenseeId","isPrimary","updatedAt") VALUES (target,target_licensee,true,transaction_timestamp())
       ON CONFLICT ("manufacturerId","licenseeId") DO UPDATE SET "isPrimary"=true,"updatedAt"=transaction_timestamp();
    END IF;
    UPDATE public."User" SET
      name = CASE WHEN patch ? 'name' THEN patch->>'name' ELSE name END,
      email = CASE WHEN patch ? 'email' THEN lower(patch->>'email') ELSE email END,
      "passwordHash" = CASE WHEN patch ? 'passwordHash' THEN patch->>'passwordHash' ELSE "passwordHash" END,
      location = CASE WHEN patch ? 'location' THEN patch->>'location' ELSE location END,
      website = CASE WHEN patch ? 'website' THEN patch->>'website' ELSE website END,
      "licenseeId" = target_licensee, "orgId" = target_org,
      "isActive" = CASE WHEN patch ? 'isActive' THEN (patch->>'isActive')::boolean ELSE "isActive" END,
      status = CASE WHEN patch ? 'isActive' AND NOT (patch->>'isActive')::boolean THEN 'DISABLED'::public."UserStatus"
                    WHEN patch ? 'isActive' THEN 'ACTIVE'::public."UserStatus" ELSE status END,
      "deletedAt" = CASE WHEN patch ? 'isActive' AND NOT (patch->>'isActive')::boolean THEN transaction_timestamp()
                         WHEN patch ? 'isActive' THEN NULL ELSE "deletedAt" END,
      "disabledAt" = CASE WHEN patch ? 'isActive' AND NOT (patch->>'isActive')::boolean THEN transaction_timestamp()
                          WHEN patch ? 'isActive' THEN NULL ELSE "disabledAt" END,
      "updatedAt" = transaction_timestamp()
    WHERE id=target;
    IF (patch ? 'isActive' AND NOT (patch->>'isActive')::boolean) OR patch ? 'passwordHash' THEN
      UPDATE public."RefreshToken" SET "revokedAt"=transaction_timestamp(), "revokedReason"='ACCOUNT_SECURITY_CHANGE'
       WHERE "userId"=target AND "revokedAt" IS NULL;
    END IF;
    RETURN jsonb_build_object('user',app_rls.session_c_user_projection(target),'licenseeId',target_licensee,'organizationId',target_org,'scopedLicenseeId',COALESCE(NULLIF(current_setting('app.licensee_id',true),''),target_licensee));
  END IF;

  IF command_name = 'delete-user' THEN
    hard_delete := COALESCE((payload->>'hard')::boolean,false);
    IF hard_delete THEN
      IF actor->>'role' NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') THEN RAISE EXCEPTION 'SESSION_C_WRONG_ROLE'; END IF;
      UPDATE public."Batch" SET "manufacturerId"=NULL,"updatedAt"=transaction_timestamp() WHERE "manufacturerId"=target;
      GET DIAGNOSTICS affected = ROW_COUNT;
      DELETE FROM public."User" WHERE id=target;
      RETURN jsonb_build_object('licenseeId',target_licensee,'organizationId',target_org,'auditAction','HARD_DELETE_MANUFACTURER',
        'auditDetails',jsonb_build_object('unassignedBatches',affected),'response',jsonb_build_object('deletedId',target,'hard',true,'unassignedBatches',affected));
    END IF;
    IF actor->>'role' IN ('LICENSEE_ADMIN','ORG_ADMIN') THEN
      target_licensee := actor->>'licenseeId';
      target_org := actor->>'orgId';
      IF EXISTS (SELECT 1 FROM public."Batch" WHERE "manufacturerId"=target AND "licenseeId"=target_licensee) THEN RAISE EXCEPTION 'SESSION_C_ASSIGNED_BATCHES'; END IF;
      DELETE FROM public."ManufacturerLicenseeLink" WHERE "manufacturerId"=target AND "licenseeId"=target_licensee;
      SELECT "licenseeId","isPrimary" INTO remaining FROM public."ManufacturerLicenseeLink" WHERE "manufacturerId"=target ORDER BY "isPrimary" DESC,"createdAt" LIMIT 1 FOR UPDATE;
      IF NOT FOUND THEN
        UPDATE public."User" SET "isActive"=false,status='DISABLED'::public."UserStatus","deletedAt"=transaction_timestamp(),"disabledAt"=transaction_timestamp(),"licenseeId"=NULL,"updatedAt"=transaction_timestamp() WHERE id=target;
        UPDATE public."RefreshToken" SET "revokedAt"=transaction_timestamp(),"revokedReason"='ACCOUNT_DISABLED' WHERE "userId"=target AND "revokedAt" IS NULL;
      ELSIF NOT remaining."isPrimary" THEN
        UPDATE public."ManufacturerLicenseeLink" SET "isPrimary"=true,"updatedAt"=transaction_timestamp() WHERE "manufacturerId"=target AND "licenseeId"=remaining."licenseeId";
        UPDATE public."User" SET "licenseeId"=remaining."licenseeId","updatedAt"=transaction_timestamp() WHERE id=target;
      END IF;
      RETURN jsonb_build_object('licenseeId',target_licensee,'organizationId',target_org,'auditAction','UNLINK_MANUFACTURER_FROM_LICENSEE',
        'auditDetails',jsonb_build_object('licenseeId',target_licensee),'response',jsonb_build_object('deletedId',target,'hard',false,'unlinkedLicenseeId',target_licensee));
    END IF;
    UPDATE public."User" SET "isActive"=false,status='DISABLED'::public."UserStatus","deletedAt"=transaction_timestamp(),"disabledAt"=transaction_timestamp(),"updatedAt"=transaction_timestamp() WHERE id=target;
    UPDATE public."RefreshToken" SET "revokedAt"=transaction_timestamp(),"revokedReason"='ACCOUNT_DISABLED' WHERE "userId"=target AND "revokedAt" IS NULL;
    RETURN jsonb_build_object('licenseeId',target_licensee,'organizationId',target_org,'auditAction','SOFT_DELETE_MANUFACTURER',
      'auditDetails','{}'::jsonb,'response',jsonb_build_object('deletedId',target,'hard',false,'id',target,'isActive',false,'deletedAt',transaction_timestamp()));
  END IF;

  IF command_name = 'restore-manufacturer' THEN
    IF actor->>'role' IN ('LICENSEE_ADMIN','ORG_ADMIN') THEN
      target_licensee := actor->>'licenseeId'; target_org := actor->>'orgId';
      UPDATE public."ManufacturerLicenseeLink" SET "isPrimary"=false,"updatedAt"=transaction_timestamp() WHERE "manufacturerId"=target AND "isPrimary" AND NOT EXISTS (SELECT 1 FROM public."ManufacturerLicenseeLink" WHERE "manufacturerId"=target AND "isPrimary");
      INSERT INTO public."ManufacturerLicenseeLink" ("manufacturerId","licenseeId","isPrimary","updatedAt") VALUES (target,target_licensee,NOT EXISTS(SELECT 1 FROM public."ManufacturerLicenseeLink" WHERE "manufacturerId"=target),transaction_timestamp())
       ON CONFLICT ("manufacturerId","licenseeId") DO NOTHING;
    ELSIF target_licensee IS NULL THEN
      SELECT ml."licenseeId",l."orgId" INTO target_licensee,target_org FROM public."ManufacturerLicenseeLink" ml JOIN public."Licensee" l ON l.id=ml."licenseeId" WHERE ml."manufacturerId"=target ORDER BY ml."isPrimary" DESC,ml."createdAt" LIMIT 1;
      IF NOT FOUND THEN RAISE EXCEPTION 'SESSION_C_FOREIGN_SCOPE'; END IF;
    END IF;
    UPDATE public."User" SET "isActive"=true,status='ACTIVE'::public."UserStatus","deletedAt"=NULL,"disabledAt"=NULL,"licenseeId"=COALESCE("licenseeId",target_licensee),"orgId"=COALESCE("orgId",target_org),"updatedAt"=transaction_timestamp() WHERE id=target;
    RETURN jsonb_build_object('licenseeId',target_licensee,'organizationId',target_org,
      'auditAction',CASE WHEN actor->>'role' IN ('LICENSEE_ADMIN','ORG_ADMIN') THEN 'RESTORE_MANUFACTURER_LINK' ELSE 'RESTORE_MANUFACTURER' END,
      'auditDetails',jsonb_build_object('licenseeId',target_licensee),'response',jsonb_build_object('id',target,'isActive',true,'deletedAt',NULL));
  END IF;

  IF command_name = 'upsert-manufacturer-licensee-link' THEN
    target := payload->>'manufacturerId'; target_licensee := payload->>'licenseeId';
    IF actor->>'role' IN ('LICENSEE_ADMIN','ORG_ADMIN') AND actor->>'licenseeId' IS DISTINCT FROM target_licensee THEN RAISE EXCEPTION 'SESSION_C_FOREIGN_SCOPE'; END IF;
    IF NOT EXISTS (SELECT 1 FROM public."User" WHERE id=target AND role IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER'))
       OR NOT EXISTS (SELECT 1 FROM public."Licensee" l JOIN public."Organization" o ON o.id=l."orgId" WHERE l.id=target_licensee AND l."isActive" AND l."suspendedAt" IS NULL AND o."isActive") THEN RAISE EXCEPTION 'SESSION_C_FOREIGN_SCOPE'; END IF;
    IF COALESCE((payload->>'makePrimary')::boolean,false) THEN UPDATE public."ManufacturerLicenseeLink" SET "isPrimary"=false,"updatedAt"=transaction_timestamp() WHERE "manufacturerId"=target AND "isPrimary" AND "licenseeId"<>target_licensee; END IF;
    INSERT INTO public."ManufacturerLicenseeLink" ("manufacturerId","licenseeId","isPrimary","updatedAt") VALUES (target,target_licensee,COALESCE((payload->>'makePrimary')::boolean,false),transaction_timestamp())
     ON CONFLICT ("manufacturerId","licenseeId") DO UPDATE SET "isPrimary"=CASE WHEN EXCLUDED."isPrimary" THEN true ELSE public."ManufacturerLicenseeLink"."isPrimary" END,"updatedAt"=transaction_timestamp();
    RETURN (SELECT to_jsonb(ml) FROM public."ManufacturerLicenseeLink" ml WHERE ml."manufacturerId"=target AND ml."licenseeId"=target_licensee);
  END IF;
  RAISE EXCEPTION 'SESSION_C_UNKNOWN_COMMAND';
END;
$$;

CREATE OR REPLACE FUNCTION app_rls.session_c_create_licensee(payload jsonb) RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS $$ SELECT app_rls.session_c_admin_command('create-licensee',$1) $$;
CREATE OR REPLACE FUNCTION app_rls.session_c_update_licensee(payload jsonb) RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS $$ SELECT app_rls.session_c_admin_command('update-licensee',$1) $$;
CREATE OR REPLACE FUNCTION app_rls.session_c_delete_licensee(payload jsonb) RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS $$ SELECT app_rls.session_c_admin_command('delete-licensee',$1) $$;
CREATE OR REPLACE FUNCTION app_rls.session_c_create_user(payload jsonb) RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS $$ SELECT app_rls.session_c_admin_command('create-user',$1) $$;
CREATE OR REPLACE FUNCTION app_rls.session_c_update_user(payload jsonb) RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS $$ SELECT app_rls.session_c_admin_command('update-user',$1) $$;
CREATE OR REPLACE FUNCTION app_rls.session_c_delete_user(payload jsonb) RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS $$ SELECT app_rls.session_c_admin_command('delete-user',$1) $$;
CREATE OR REPLACE FUNCTION app_rls.session_c_restore_manufacturer(payload jsonb) RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS $$ SELECT app_rls.session_c_admin_command('restore-manufacturer',$1) $$;
CREATE OR REPLACE FUNCTION app_rls.session_c_upsert_manufacturer_licensee_link(payload jsonb) RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS $$ SELECT app_rls.session_c_admin_command('upsert-manufacturer-licensee-link',$1) $$;

REVOKE ALL ON FUNCTION app_rls.session_c_assert_admin(text,boolean) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.session_c_user_projection(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.session_c_audit_context_valid() FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.session_c_admin_command(text,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.session_c_create_licensee(jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.session_c_update_licensee(jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.session_c_delete_licensee(jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.session_c_create_user(jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.session_c_update_user(jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.session_c_delete_user(jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.session_c_restore_manufacturer(jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.session_c_upsert_manufacturer_licensee_link(jsonb) FROM PUBLIC;
