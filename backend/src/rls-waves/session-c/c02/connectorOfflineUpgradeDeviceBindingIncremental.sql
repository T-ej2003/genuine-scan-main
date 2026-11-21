-- Install as the existing printing auth-function owner before enabling the
-- upgrade challenge route. Replace {{APP_ROLE}} with the exact application role.
CREATE OR REPLACE FUNCTION app_rls.printing_upgrade_device_binding(
  p_capability text, p_request_id text, p_printer_id text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public
AS $fn$
DECLARE
  printer_row record;
  registration_row record;
  session_row record;
  maintenance_status jsonb;
BEGIN
  IF session_user <> '{{APP_ROLE}}' OR p_printer_id !~* '^[0-9a-f-]{36}$'
  THEN RAISE EXCEPTION 'PRINTING_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;

  -- The existing function validates the capability, actor and manufacturer
  -- scope, and establishes the transaction-local printing RLS context.
  maintenance_status:=app_rls.printing_printer_administration(
    p_capability,'printing-printer-admin',p_request_id,'MAINTENANCE_STATUS',p_printer_id,'{}'::jsonb);
  IF current_setting('app.printing_role',true)<>'MANUFACTURER_ADMIN'
  THEN RAISE EXCEPTION 'PRINTING_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;

  SELECT p.id,p."assignedUserId",p."orgId",p."licenseeId",p."printerRegistrationId",
    p."nativePrinterId",p."agentId",p."deviceFingerprint",p."isActive"
    INTO STRICT printer_row FROM public."Printer" p
    WHERE p.id=p_printer_id AND p."assignedUserId"=current_setting('app.printing_user_id',true);
  IF NOT printer_row."isActive" OR printer_row."printerRegistrationId" IS NULL
  THEN RAISE EXCEPTION 'PRINTING_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;

  SELECT r.id,r."userId",r."orgId",r."licenseeId",r."agentId",r."deviceFingerprint",
    r."publicKeyPem",r."trustStatus",r."approvedAt",r."revokedAt"
    INTO STRICT registration_row FROM public."PrinterRegistration" r
    WHERE r.id=printer_row."printerRegistrationId";
  IF registration_row."userId" IS DISTINCT FROM printer_row."assignedUserId" OR
     registration_row."orgId" IS DISTINCT FROM printer_row."orgId" OR
     registration_row."licenseeId" IS DISTINCT FROM printer_row."licenseeId" OR
     registration_row."agentId" IS DISTINCT FROM printer_row."agentId" OR
     registration_row."deviceFingerprint" IS DISTINCT FROM printer_row."deviceFingerprint" OR
     registration_row."trustStatus"<>'TRUSTED' OR registration_row."approvedAt" IS NULL OR
     registration_row."revokedAt" IS NOT NULL OR nullif(registration_row."publicKeyPem",'') IS NULL
  THEN RAISE EXCEPTION 'PRINTING_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;

  PERFORM set_config('app.printing_registration_id',registration_row.id,true),
    set_config('app.printing_operation','printing-readiness',true);
  SELECT s.metadata->>'connectorVersion' AS "connectorVersion",s."agentId",s."deviceFingerprint",s."publicKeyFingerprint",s."selectedPrinterId"
    INTO session_row FROM public."PrinterAgentSession" s
    WHERE s."registrationId"=registration_row.id AND s."connectionState"='CONNECTED'
      AND s."revokedAt" IS NULL AND s."expiresAt">transaction_timestamp()
      AND s."lastSignedHeartbeatAt">transaction_timestamp()-interval '35 seconds'
    ORDER BY s."lastSignedHeartbeatAt" DESC LIMIT 1;
  IF session_row."connectorVersion" IS NULL AND maintenance_status->>'state'='DISPATCH_FENCED' AND
     NOT EXISTS (SELECT 1 FROM public."PrinterAgentSession" active
       WHERE active."registrationId"=registration_row.id AND active."connectionState"='CONNECTED'
         AND active."revokedAt" IS NULL AND active."expiresAt">transaction_timestamp())
  THEN
    -- Only the certified stopped 2026.11.6.2 path may use a historical
    -- signed session. A fresh challenge and registered-key proof remain required.
    SELECT s.metadata->>'connectorVersion' AS "connectorVersion",s."agentId",s."deviceFingerprint",
      s."publicKeyFingerprint",s."selectedPrinterId"
      INTO session_row FROM public."PrinterAgentSession" s
      WHERE s."registrationId"=registration_row.id AND s."connectionState"='DISCONNECTED'
        AND s.metadata->>'connectorVersion'='2026.11.6.2'
      ORDER BY s."lastSignedHeartbeatAt" DESC LIMIT 1;
  END IF;
  IF session_row."agentId" IS DISTINCT FROM registration_row."agentId" OR
     session_row."deviceFingerprint" IS DISTINCT FROM registration_row."deviceFingerprint" OR
     session_row."publicKeyFingerprint" IS DISTINCT FROM encode(sha256(convert_to(registration_row."publicKeyPem",'UTF8')),'hex') OR
     (session_row."selectedPrinterId" IS DISTINCT FROM printer_row.id AND
      session_row."selectedPrinterId" IS DISTINCT FROM printer_row."nativePrinterId") OR
     session_row."connectorVersion" IS NULL OR
     session_row."connectorVersion" !~ '^[0-9]+[.][0-9]+[.][0-9]+([.][0-9]+)?$'
  THEN RAISE EXCEPTION 'PRINTING_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;

  RETURN jsonb_build_object('agentId',registration_row."agentId",
    'deviceFingerprint',registration_row."deviceFingerprint",'manufacturerId',printer_row."assignedUserId",
    'tenantId',printer_row."orgId",'printerId',printer_row.id,
    'registrationId',registration_row.id,'publicKeyPem',registration_row."publicKeyPem",
    'sourceVersion',session_row."connectorVersion");
END
$fn$;
REVOKE ALL ON FUNCTION app_rls.printing_upgrade_device_binding(text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_rls.printing_upgrade_device_binding(text,text,text) TO "{{APP_ROLE}}";
