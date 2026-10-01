-- Fixed aggregate-only release inventory. No caller-controlled selectors.
CREATE OR REPLACE FUNCTION app_rls.production_rotation_inventory()
RETURNS json
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog,public
SET row_security = on
AS $inventory$
DECLARE
  inventory json;
  setting_names constant text[] := ARRAY['app.rotation_inventory_operation','app.user_id','app.role','app.licensee_id','app.organization_id','app.manufacturer_id','app.auth_session_id','app.auth_session_verified','app.context_installed'];
  previous_values text[];
  setting_index integer;
BEGIN
  IF session_user <> {{APP_ROLE_LITERAL}}
     OR current_setting('transaction_read_only') <> 'on'
  THEN RAISE EXCEPTION 'rotation inventory requires the canonical read-only app session' USING ERRCODE='42501'; END IF;
  SELECT array_agg(current_setting(name,true) ORDER BY ordinal) INTO previous_values FROM unnest(setting_names) WITH ORDINALITY AS settings(name,ordinal);
  FOR setting_index IN 1..array_length(setting_names,1) LOOP
    PERFORM set_config(setting_names[setting_index],CASE WHEN setting_index=1 THEN 'rotation-inventory-v1' ELSE '' END,true);
  END LOOP;
  inventory := (SELECT json_build_object(
  'refreshSessions', (SELECT json_build_object('count', count(*)::int, 'maxExpiry', max("expiresAt")) FROM public."RefreshToken" WHERE "revokedAt" IS NULL AND "expiresAt" > now()),
  'adminSessions', (SELECT json_build_object('count', count(*)::int, 'maxExpiry', max(r."expiresAt")) FROM public."RefreshToken" r JOIN public."User" u ON u."id" = r."userId" WHERE r."revokedAt" IS NULL AND r."expiresAt" > now() AND u."status"::text = 'ACTIVE' AND u."isActive" = true AND u."deletedAt" IS NULL AND u."role"::text IN ('SUPER_ADMIN', 'PLATFORM_SUPER_ADMIN', 'LICENSEE_ADMIN', 'ORG_ADMIN', 'MANUFACTURER_ADMIN')),
  'customerSessions', (SELECT json_build_object('count', count(*)::int, 'maxExpiry', max("expiresAt")) FROM public."CustomerAuthSession" WHERE "revokedAt" IS NULL AND "expiresAt" > now()),
  'customerVerificationState', (SELECT json_build_object('count', count(*)::int, 'maxExpiry', max("expiresAt")) FROM public."CustomerVerificationSession" WHERE "expiresAt" IS NULL OR "expiresAt" > now()),
  'activeInvites', (SELECT json_build_object('count', count(*)::int, 'maxExpiry', max("expiresAt")) FROM public."Invite" WHERE "usedAt" IS NULL AND "expiresAt" > now()),
  'resetTokens', (SELECT json_build_object('count', count(*)::int, 'maxExpiry', max("expiresAt")) FROM public."PasswordReset" WHERE "usedAt" IS NULL AND "expiresAt" > now()),
  'emailVerification', (SELECT json_build_object('count', count(*)::int, 'maxExpiry', max("expiresAt")) FROM public."EmailVerificationToken" WHERE "usedAt" IS NULL AND "expiresAt" > now()),
  'qrArtifacts', (SELECT json_build_object('count', coalesce(sum(mode_count), 0)::int, 'maxExpiry', max(max_expiry), 'issuanceModes', coalesce(json_object_agg(mode, mode_count), '{}'::json), 'keyVersions', json_build_object('status', 'NOT_APPLICABLE', 'reason', 'QRCode has no persisted signing-key version column')) FROM (SELECT "issuanceMode" AS mode, count(*)::int AS mode_count, max("tokenExpiresAt") AS max_expiry FROM public."QRCode" WHERE "tokenExpiresAt" > now() GROUP BY "issuanceMode") q),
  'printerTestQrArtifacts', json_build_object('status', 'NOT_APPLICABLE', 'reason', 'printer-test identifiers are synthetic signed payload metadata and are not persisted as QRCode rows'),
  'artifactRecords', (SELECT json_build_object('count', coalesce(sum(algorithm_count), 0)::int, 'maxFinishedAt', max(max_finished_at), 'signatureAlgorithms', coalesce(json_object_agg(algorithm, algorithm_count), '{}'::json)) FROM (SELECT coalesce("signatureAlgorithm", 'unknown') AS algorithm, count(*)::int AS algorithm_count, max("finishedAt") AS max_finished_at FROM public."CompliancePackJob" WHERE "finishedAt" IS NOT NULL GROUP BY coalesce("signatureAlgorithm", 'unknown')) a),
  'legacyComplianceArtifacts', (SELECT json_build_object('count', count(*)::int, 'maxFinishedAt', max("finishedAt")) FROM public."CompliancePackJob" WHERE "finishedAt" IS NOT NULL AND lower(coalesce("signatureAlgorithm", '')) <> 'ed25519'),
  'legacyImmutableAuditArtifacts', json_build_object('status', 'NOT_APPLICABLE', 'reason', 'AuditLog has no legacy-artifact marker or separate immutable-artifact relation'),
  'oauthState', json_build_object('persisted', false, 'maxTtlSeconds', 900), 'oauthExchange', json_build_object('persisted', false, 'maxTtlSeconds', 600), 'printedQrCompatibility', json_build_object('maxConfiguredTtlSeconds', 31536000)));
  FOR setting_index IN 1..array_length(setting_names,1) LOOP
    PERFORM set_config(setting_names[setting_index],coalesce(previous_values[setting_index],''),true);
  END LOOP;
  RETURN inventory;
END
$inventory$;
REVOKE ALL ON FUNCTION app_rls.production_rotation_inventory() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_rls.production_rotation_inventory() TO {{APP_ROLE}};
