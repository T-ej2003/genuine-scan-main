CREATE OR REPLACE FUNCTION app_public.public_verify_bind(
  p_operation text,
  p_request_id text,
  p_qr_id text DEFAULT NULL,
  p_code text DEFAULT NULL,
  p_decision_id text DEFAULT NULL,
  p_session_id text DEFAULT NULL,
  p_idempotency_hash text DEFAULT NULL
) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public
AS $$
BEGIN
  IF p_operation !~ '^public-verification-[a-z0-9-]{1,64}$'
     OR p_request_id !~ '^[!-~]{1,128}$' THEN
    RAISE EXCEPTION 'PUBLIC_VERIFICATION_INVALID_INPUT' USING ERRCODE='22023';
  END IF;
  PERFORM set_config('app.public_verification_operation',p_operation,true);
  PERFORM set_config('app.public_verification_request_id',p_request_id,true);
  PERFORM set_config('app.public_verification_qr_id',coalesce(p_qr_id,''),true);
  PERFORM set_config('app.public_verification_code',coalesce(p_code,''),true);
  PERFORM set_config('app.public_verification_decision_id',coalesce(p_decision_id,''),true);
  PERFORM set_config('app.public_verification_session_id',coalesce(p_session_id,''),true);
  PERFORM set_config('app.public_verification_idempotency_hash',coalesce(p_idempotency_hash,''),true);
  PERFORM set_config('app.public_verification_target_id','',true);
  PERFORM set_config('app.public_verification_support_id','',true);
  PERFORM set_config('app.public_verification_audit_id','',true);
  PERFORM set_config('app.public_verification_outbox_id','',true);
  PERFORM set_config('app.public_verification_organization_id','',true);
  PERFORM set_config('app.public_verification_licensee_id','',true);
  PERFORM set_config('app.public_verification_batch_id','',true);
  PERFORM set_config('app.public_verification_manufacturer_id','',true);
  PERFORM set_config('app.public_verification_customer_session_hash','',true);
  PERFORM set_config('app.public_verification_transfer_token_hash','',true);
  PERFORM set_config('app.public_verification_passkey_ticket_hashes','',true);
  PERFORM set_config('app.public_verification_customer_user_id','',true);
END
$$;

CREATE OR REPLACE FUNCTION app_public.issue_customer_auth_session(
  p_capability text,
  p_customer_user_id text,
  p_customer_email text,
  p_auth_strength text,
  p_auth_provider text,
  p_issued_at timestamp without time zone,
  p_expires_at timestamp without time zone,
  p_request_id text
) RETURNS TABLE("accepted" boolean)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public
AS $$
DECLARE session_id text:=gen_random_uuid()::text;
BEGIN
  IF length(p_capability)<32 OR length(p_capability)>4096
     OR p_customer_user_id !~ '^cust_[a-f0-9]{32}$'
     OR p_customer_email !~ '^[^[:space:]@]+@[^[:space:]@]+[.][^[:space:]@]+$'
     OR p_auth_strength NOT IN ('EMAIL_OTP','PASSKEY','SOCIAL')
     OR p_auth_provider NOT IN ('EMAIL_OTP','GOOGLE')
     OR p_issued_at IS NULL OR p_expires_at<=p_issued_at
     OR p_expires_at>p_issued_at+interval '31 days' THEN
    RAISE EXCEPTION 'PUBLIC_CUSTOMER_SESSION_INVALID' USING ERRCODE='22023';
  END IF;
  PERFORM app_public.public_verify_bind('public-verification-customer-session-issue',p_request_id,NULL,NULL,NULL,NULL,NULL);
  PERFORM set_config('app.public_verification_target_id',session_id,true);
  INSERT INTO public."CustomerAuthSession"(
    id,"tokenHash","customerUserId","customerEmail","authStrength","authProvider",
    "issuedAt","expiresAt","lastSeenAt","revokedAt","createdAt","updatedAt"
  ) VALUES (
    session_id,encode(sha256(convert_to(p_capability,'UTF8')),'hex'),p_customer_user_id,lower(p_customer_email),
    p_auth_strength,p_auth_provider,p_issued_at,p_expires_at,p_issued_at,NULL,p_issued_at,p_issued_at
  );
  PERFORM app_public.public_verify_write_evidence(
    CASE WHEN p_auth_strength='EMAIL_OTP' THEN 'VERIFY_CUSTOMER_OTP_VERIFIED'
      ELSE 'VERIFY_CUSTOMER_SESSION_ISSUED' END,
    'CustomerAuthSession',session_id,NULL,
    jsonb_build_object('authStrength',p_auth_strength,'authProvider',p_auth_provider),
    p_issued_at,p_request_id
  );
  RETURN QUERY SELECT true;
END
$$;

CREATE OR REPLACE FUNCTION app_public.require_customer_auth_session(
  p_capability text,
  p_checked_at timestamp without time zone,
  p_request_id text,
  p_operation text
) RETURNS TABLE(
  "sessionId" text,
  "customerUserId" text,
  "customerEmail" text,
  "authStrength" text,
  "authProvider" text
)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public
AS $$
DECLARE session_row record;
BEGIN
  IF length(p_capability)<32 OR length(p_capability)>4096
     OR p_checked_at IS NULL
     OR p_operation !~ '^customer-[a-z0-9-]{1,64}$' THEN
    RAISE EXCEPTION 'PUBLIC_CUSTOMER_SESSION_DENIED' USING ERRCODE='42501';
  END IF;
  PERFORM app_public.public_verify_bind('public-verification-'||p_operation,p_request_id,NULL,NULL,NULL,NULL,NULL);
  PERFORM set_config('app.public_verification_customer_session_hash',encode(sha256(convert_to(p_capability,'UTF8')),'hex'),true);
  SELECT s.id,s."customerUserId",s."customerEmail",s."authStrength",s."authProvider",
    s."expiresAt",s."revokedAt" INTO session_row
  FROM public."CustomerAuthSession" s
  WHERE s."tokenHash"=encode(sha256(convert_to(p_capability,'UTF8')),'hex');
  IF session_row.id IS NULL OR session_row."revokedAt" IS NOT NULL OR session_row."expiresAt"<=p_checked_at THEN
    RAISE EXCEPTION 'PUBLIC_CUSTOMER_SESSION_DENIED' USING ERRCODE='42501';
  END IF;
  PERFORM set_config('app.public_verification_target_id',session_row.id,true);
  UPDATE public."CustomerAuthSession" AS s SET "lastSeenAt"=p_checked_at,"updatedAt"=p_checked_at
  WHERE s.id=session_row.id AND s."revokedAt" IS NULL AND s."expiresAt">p_checked_at
  RETURNING s.id,s."customerUserId",s."customerEmail",s."authStrength",s."authProvider",s."expiresAt",s."revokedAt"
  INTO session_row;
  IF session_row.id IS NULL THEN
    RAISE EXCEPTION 'PUBLIC_CUSTOMER_SESSION_DENIED' USING ERRCODE='42501';
  END IF;
  RETURN QUERY SELECT session_row.id,session_row."customerUserId",session_row."customerEmail",
    session_row."authStrength",session_row."authProvider";
END
$$;

CREATE OR REPLACE FUNCTION app_public.read_customer_auth_session(
  p_capability text,
  p_checked_at timestamp without time zone,
  p_request_id text
) RETURNS TABLE(
  "customerUserId" text,
  "customerEmail" text,
  "authStrength" text,
  "authProvider" text
)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public
AS $$
DECLARE session_row record;
BEGIN
  SELECT * INTO session_row FROM app_public.require_customer_auth_session(
    p_capability,p_checked_at,p_request_id,'customer-session-read'
  );
  RETURN QUERY SELECT session_row."customerUserId",session_row."customerEmail",
    session_row."authStrength",session_row."authProvider";
END
$$;

CREATE OR REPLACE FUNCTION app_public.revoke_customer_auth_session(
  p_capability text,
  p_revoked_at timestamp without time zone,
  p_request_id text
) RETURNS TABLE("revoked" boolean)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public
AS $$
DECLARE session_row record;
BEGIN
  IF length(p_capability)<32 OR length(p_capability)>4096 OR p_revoked_at IS NULL THEN
    RAISE EXCEPTION 'PUBLIC_CUSTOMER_SESSION_DENIED' USING ERRCODE='42501';
  END IF;
  PERFORM app_public.public_verify_bind(
    'public-verification-customer-session-revoke',p_request_id,NULL,NULL,NULL,NULL,NULL
  );
  PERFORM set_config(
    'app.public_verification_customer_session_hash',
    encode(sha256(convert_to(p_capability,'UTF8')),'hex'),true
  );
  SELECT s.id,s."revokedAt" INTO session_row FROM public."CustomerAuthSession" s
  WHERE s."tokenHash"=encode(sha256(convert_to(p_capability,'UTF8')),'hex');
  IF session_row.id IS NULL THEN
    RAISE EXCEPTION 'PUBLIC_CUSTOMER_SESSION_DENIED' USING ERRCODE='42501';
  END IF;
  PERFORM set_config('app.public_verification_target_id',session_row.id,true);
  IF session_row."revokedAt" IS NULL THEN
    UPDATE public."CustomerAuthSession"
      SET "revokedAt"=p_revoked_at,"updatedAt"=p_revoked_at
    WHERE id=session_row.id;
    PERFORM app_public.public_verify_write_evidence(
      'VERIFY_CUSTOMER_LOGOUT','CustomerAuthSession',session_row.id,NULL,
      '{}'::jsonb,p_revoked_at,p_request_id
    );
  END IF;
  RETURN QUERY SELECT true;
END
$$;

CREATE OR REPLACE FUNCTION app_public.public_verify_execute(
  p_qr_id text,
  p_proof_source text,
  p_checked_at timestamp without time zone,
  p_request_id text,
  p_actor_ip_hash text,
  p_actor_device_hash text,
  p_session_start_token_hash text,
  p_signed_token_digest text DEFAULT NULL
) RETURNS TABLE(
  "result" text,
  "messageKey" text,
  "nextAction" text,
  "maskedCode" text,
  "brandName" text,
  "brandWebsite" text,
  "brandSupportEmail" text,
  "brandSupportPhone" text,
  "manufacturerName" text,
  "manufacturerWebsite" text,
  "printedAt" timestamp without time zone,
  "firstVerifiedAt" timestamp without time zone,
  "latestVerifiedAt" timestamp without time zone,
  "ownershipClaimAvailable" boolean,
  "sessionStartToken" text
)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public
AS $$
DECLARE
  qr record;
  batch record;
  brand record;
  organization record;
  manufacturer record;
  previous_scan record;
  replacement_status text := 'NONE';
  classification text;
  outcome public."VerificationDecisionOutcome";
  risk_band public."VerificationRiskBand";
  public_result text;
  message_key text;
  next_action text;
  decision_id text := gen_random_uuid()::text;
  evidence_id text := gen_random_uuid()::text;
  scan_id text := gen_random_uuid()::text;
  audit_id text := gen_random_uuid()::text;
  outbox_id text := gen_random_uuid()::text;
  next_scan_count integer;
  first_at timestamp without time zone;
  ready boolean;
  same_context boolean;
  claim_available boolean;
  scan_history_eligible boolean;
  safe_code text;
BEGIN
  IF p_proof_source NOT IN ('SIGNED_LABEL','MANUAL_CODE_LOOKUP')
     OR p_qr_id !~ '^[0-9a-fA-F-]{36}$'
     OR p_checked_at IS NULL
     OR p_session_start_token_hash !~ '^(?:[A-Za-z0-9._-]{1,32}:)?[a-f0-9]{64}$'
     OR (p_actor_ip_hash IS NOT NULL AND p_actor_ip_hash !~ '^(?:[A-Za-z0-9._-]{1,32}:)?[a-f0-9]{64}$')
     OR (p_actor_device_hash IS NOT NULL AND p_actor_device_hash !~ '^(?:[A-Za-z0-9._-]{1,32}:)?[a-f0-9]{64}$')
     OR (p_signed_token_digest IS NOT NULL AND p_signed_token_digest !~ '^(?:[A-Za-z0-9._-]{1,32}:)?[a-f0-9]{64}$') THEN
    RAISE EXCEPTION 'PUBLIC_VERIFICATION_INVALID_INPUT' USING ERRCODE='22023';
  END IF;
  SELECT NULL::text AS id,NULL::text AS "licenseeId",NULL::text AS "manufacturerId",
    NULL::text AS "lifecycleState",NULL::timestamp AS "printedAt",NULL::timestamp AS "suspendedAt" INTO batch;
  SELECT NULL::text AS id,NULL::text AS name,NULL::text AS website INTO manufacturer;
  SELECT NULL::text AS id,NULL::timestamp AS "scannedAt",NULL::text AS "ipAddress",NULL::text AS device INTO previous_scan;

  PERFORM app_public.public_verify_bind(
    'public-verification-execute',p_request_id,p_qr_id,NULL,decision_id,NULL,NULL
  );
  PERFORM set_config('app.public_verification_audit_id',audit_id,true);
  PERFORM set_config('app.public_verification_outbox_id',outbox_id,true);
  SELECT q.id,q.code,q."licenseeId",q."batchId",q.status,q."scanCount",q."scannedAt",q."printedAt",
    q."issuanceMode",q."customerVerifiableAt",q."signedFirstSeenAt",q."lastSignedVerificationAt",
    q."lastSignedVerificationIpHash",q."lastSignedVerificationDeviceHash"
  INTO STRICT qr
  FROM public."QRCode" q WHERE q.id=p_qr_id FOR UPDATE;
  PERFORM set_config('app.public_verification_licensee_id',qr."licenseeId",true);
  PERFORM set_config('app.public_verification_batch_id',coalesce(qr."batchId",''),true);
  SELECT l.id,l."orgId",l.name,l."brandName",l.website,l."supportEmail",l."supportPhone",
    l."isActive",l."suspendedAt"
  INTO brand
  FROM public."Licensee" l WHERE l.id=qr."licenseeId";
  IF brand.id IS NULL THEN RAISE EXCEPTION 'PUBLIC_VERIFICATION_SCOPE_INVALID' USING ERRCODE='42501'; END IF;
  PERFORM set_config('app.public_verification_organization_id',brand."orgId",true);
  SELECT o.id,o."isActive" INTO organization
  FROM public."Organization" o WHERE o.id=brand."orgId";
  IF organization.id IS NULL THEN
    RAISE EXCEPTION 'PUBLIC_VERIFICATION_SCOPE_INVALID' USING ERRCODE='42501';
  END IF;
  IF NOT brand."isActive" OR brand."suspendedAt" IS NOT NULL OR NOT organization."isActive" THEN
    RAISE EXCEPTION 'PUBLIC_VERIFICATION_SCOPE_INVALID' USING ERRCODE='42501';
  END IF;
  IF qr."batchId" IS NOT NULL THEN
    SELECT b.id,b."licenseeId",b."manufacturerId",b."lifecycleState",b."printedAt",b."suspendedAt"
    INTO batch
    FROM public."Batch" b WHERE b.id=qr."batchId";
    IF batch.id IS NULL OR batch."licenseeId"<>qr."licenseeId" THEN
      RAISE EXCEPTION 'PUBLIC_VERIFICATION_SCOPE_INVALID' USING ERRCODE='42501';
    END IF;
    IF batch.id IS NOT NULL AND batch."manufacturerId" IS NOT NULL THEN
      PERFORM set_config('app.public_verification_manufacturer_id',batch."manufacturerId",true);
      SELECT u.id,u.name,u.website INTO manufacturer
      FROM public."User" u WHERE u.id=batch."manufacturerId";
    END IF;
  END IF;
  SELECT s.id,s."scannedAt",s."ipAddress",s.device
  INTO previous_scan
  FROM public."QrScanLog" s
  WHERE s."qrCodeId"=qr.id
  ORDER BY s."scannedAt" DESC,s.id DESC LIMIT 1;
  SELECT min(s."scannedAt") INTO first_at
  FROM public."QrScanLog" s
  WHERE s."qrCodeId"=qr.id;
  SELECT CASE
    WHEN rc."originalQrCodeId"=qr.id THEN 'REPLACED_LABEL'
    ELSE 'ACTIVE_REPLACEMENT'
  END INTO replacement_status
  FROM public."ReplacementChain" rc
  WHERE rc.status='ACTIVE'
    AND (rc."originalQrCodeId"=qr.id OR rc."replacementQrCodeId"=qr.id)
  ORDER BY rc."createdAt" DESC LIMIT 1;
  replacement_status:=coalesce(replacement_status,'NONE');

  ready := qr.status IN ('PRINTED','SCANNED','REDEEMED')
    AND batch.id IS NOT NULL
    AND batch."lifecycleState"::text='RELEASED'
    AND batch."suspendedAt" IS NULL
    AND (qr."issuanceMode"<>'GOVERNED_PRINT' OR qr."customerVerifiableAt" IS NOT NULL);
  same_context := previous_scan.id IS NOT NULL
    AND p_actor_device_hash IS NOT NULL
    AND p_actor_ip_hash IS NOT NULL
    AND previous_scan.device=p_actor_device_hash
    AND previous_scan."ipAddress"=p_actor_ip_hash;
  IF qr.status='BLOCKED' OR replacement_status='REPLACED_LABEL' THEN
    classification:='BLOCKED_BY_SECURITY'; outcome:='BLOCKED'; risk_band:='CRITICAL';
    public_result:='BLOCKED'; message_key:='verification.blocked'; next_action:='REPORT_CONCERN';
  ELSIF NOT ready THEN
    classification:='NOT_READY_FOR_CUSTOMER_USE'; outcome:='NOT_READY'; risk_band:='ELEVATED';
    public_result:='NOT_READY'; message_key:='verification.not_ready'; next_action:='TRY_LATER';
  ELSIF previous_scan.id IS NULL THEN
    classification:='FIRST_SCAN'; outcome:='AUTHENTIC'; risk_band:='LOW';
    public_result:='AUTHENTIC'; message_key:='verification.first_scan'; next_action:='SAVE_OR_REPORT';
  ELSIF same_context THEN
    classification:='LEGIT_REPEAT'; outcome:='AUTHENTIC'; risk_band:='LOW';
    public_result:='AUTHENTIC_REPEAT'; message_key:='verification.repeat'; next_action:='SAVE_OR_REPORT';
  ELSE
    classification:='SUSPICIOUS_DUPLICATE'; outcome:='SUSPICIOUS_DUPLICATE'; risk_band:='HIGH';
    public_result:='REVIEW'; message_key:='verification.changed_context'; next_action:='REPORT_CONCERN';
  END IF;

  safe_code:=CASE WHEN length(qr.code)<=4 THEN repeat('*',length(qr.code))
    ELSE repeat('*',length(qr.code)-4)||right(qr.code,4) END;
  scan_history_eligible:=classification IN ('FIRST_SCAN','LEGIT_REPEAT','SUSPICIOUS_DUPLICATE');
  next_scan_count:=coalesce(qr."scanCount",0);
  IF scan_history_eligible THEN
    next_scan_count:=next_scan_count+1;
    INSERT INTO public."QrScanLog"(
      id,code,"qrCodeId","licenseeId","batchId",status,"scannedAt","isFirstScan","scanCount",
      "customerUserId","ownershipId","ownershipMatchMethod","isTrustedOwnerContext",
      "ipAddress","userAgent",device,latitude,longitude,accuracy,
      "locationName","locationCountry","locationRegion","locationCity"
    ) VALUES (
      scan_id,qr.code,qr.id,qr."licenseeId",qr."batchId",qr.status,p_checked_at,
      classification='FIRST_SCAN',next_scan_count,NULL,NULL,NULL,false,
      p_actor_ip_hash,NULL,p_actor_device_hash,NULL,NULL,NULL,NULL,NULL,NULL,NULL
    );
    UPDATE public."QRCode" SET
      "scanCount"=next_scan_count,"scannedAt"=p_checked_at,
      "lastScanIp"=p_actor_ip_hash,"lastScanDevice"=p_actor_device_hash,"lastScanUserAgent"=NULL,
      "signedFirstSeenAt"=CASE WHEN p_proof_source='SIGNED_LABEL' THEN coalesce("signedFirstSeenAt",p_checked_at) ELSE "signedFirstSeenAt" END,
      "lastSignedVerificationAt"=CASE WHEN p_proof_source='SIGNED_LABEL' AND classification<>'SUSPICIOUS_DUPLICATE' THEN p_checked_at ELSE "lastSignedVerificationAt" END,
      "lastSignedVerificationIpHash"=CASE WHEN p_proof_source='SIGNED_LABEL' AND classification<>'SUSPICIOUS_DUPLICATE' THEN p_actor_ip_hash ELSE "lastSignedVerificationIpHash" END,
      "lastSignedVerificationDeviceHash"=CASE WHEN p_proof_source='SIGNED_LABEL' AND classification<>'SUSPICIOUS_DUPLICATE' THEN p_actor_device_hash ELSE "lastSignedVerificationDeviceHash" END,
      "updatedAt"=transaction_timestamp()
    WHERE id=qr.id;
  END IF;
  INSERT INTO public."VerificationDecision"(
    id,"decisionVersion","qrCodeId",code,"licenseeId","batchId","proofSource","proofTier",
    outcome,classification,"reasonCodes","riskBand","replacementStatus","degradationMode",
    "customerTrustLevel","isAuthentic","scanCount","riskScore","actorIpHash","actorDeviceHash",metadata,"createdAt"
  ) VALUES (
    decision_id,1,qr.id,qr.code,qr."licenseeId",qr."batchId",p_proof_source,
    (CASE WHEN p_proof_source='SIGNED_LABEL' THEN 'SIGNED_LABEL' ELSE 'MANUAL_REGISTRY_LOOKUP' END)::public."VerificationProofTier",
    outcome,classification,ARRAY[classification,p_proof_source],risk_band,
    replacement_status::public."VerificationReplacementStatus",'NORMAL'::public."VerificationDegradationMode",
    'ANONYMOUS'::public."CustomerTrustLevel",outcome='AUTHENTIC',next_scan_count,
    CASE risk_band WHEN 'CRITICAL' THEN 100 WHEN 'HIGH' THEN 80 WHEN 'ELEVATED' THEN 50 ELSE 10 END,
    p_actor_ip_hash,p_actor_device_hash,
    jsonb_build_object(
      'publicOutcome',public_result,'messageKey',message_key,'nextActionKey',next_action,
      'requestId',p_request_id,'signedTokenDigestPresent',p_signed_token_digest IS NOT NULL
    ),p_checked_at
  );
  INSERT INTO public."VerificationEvidenceSnapshot"(
    id,"verificationDecisionId","scanSummary","ownershipSnapshot","riskSignals","policySnapshot",
    "lifecycleSnapshot",metadata,"createdAt"
  ) VALUES (
    evidence_id,decision_id,
    jsonb_build_object('totalScans',next_scan_count,'firstScan',scan_history_eligible AND classification='FIRST_SCAN',
      'firstVerifiedAt',CASE WHEN scan_history_eligible THEN coalesce(first_at,p_checked_at) ELSE first_at END,
      'latestVerifiedAt',CASE WHEN scan_history_eligible THEN p_checked_at ELSE qr."scannedAt" END),
    jsonb_build_object('claimAvailable',ready AND qr.status<>'BLOCKED'),
    jsonb_build_object('contextChanged',scan_history_eligible AND previous_scan.id IS NOT NULL AND NOT same_context),
    NULL,
    jsonb_build_object('qrStatus',qr.status,'batchLifecycle',batch."lifecycleState",
      'customerVerifiableAt',qr."customerVerifiableAt",'replacementStatus',replacement_status),
    jsonb_build_object(
      'publicSessionStart',jsonb_build_object('tokenHash',p_session_start_token_hash,'issuedAt',p_checked_at,
        'expiresAt',p_checked_at+interval '15 minutes'),
      'presentationSnapshot',jsonb_build_object(
        'publicOutcome',public_result,'messageKey',message_key,'nextActionKey',next_action,
        'maskedCode',safe_code,'brandName',coalesce(brand."brandName",brand.name),
        'brandWebsite',CASE WHEN brand.website ~ '^https?://' THEN brand.website ELSE NULL END,
        'brandSupportEmail',brand."supportEmail",'brandSupportPhone',brand."supportPhone",
        'manufacturerName',manufacturer.name,'manufacturerWebsite',
          CASE WHEN manufacturer.website ~ '^https?://' THEN manufacturer.website ELSE NULL END,
        'printedAt',coalesce(qr."printedAt",batch."printedAt"),
        'firstVerifiedAt',CASE WHEN scan_history_eligible THEN coalesce(first_at,p_checked_at) ELSE first_at END,
        'latestVerifiedAt',CASE WHEN scan_history_eligible THEN p_checked_at ELSE qr."scannedAt" END,
        'ownershipClaimAvailable',ready AND qr.status<>'BLOCKED',
        'proofSource',p_proof_source)
    ),
    p_checked_at
  );
  INSERT INTO public."AuditLog"(
    id,"userId","orgId","licenseeId",action,"entityType","entityId",details,
    "ipAddress","ipHash","userAgent","createdAt"
  ) VALUES (
    audit_id,NULL,NULL,qr."licenseeId",'PUBLIC_VERIFICATION_RECORDED','VerificationDecision',decision_id,
    jsonb_build_object('classification',classification,'proofSource',p_proof_source,
      'scanCount',next_scan_count,'requestId',p_request_id),
    NULL,NULL,NULL,p_checked_at
  );
  INSERT INTO public."SecurityEventOutbox"(
    id,"eventType",payload,"jobType","requestId","payloadDigest","idempotencyKey",
    "organizationId","licenseeId","manufacturerId","initiatingUserId","expiresAt",
    "claimedAt","claimLeaseExpiresAt","sinkEventId",status,attempts,"nextAttemptAt","lastError","sentAt",
    "createdAt","updatedAt"
  ) VALUES (
    outbox_id,'PUBLIC_VERIFICATION_DECISION',
    jsonb_build_object('decisionId',decision_id,'classification',classification,
      'proofSource',p_proof_source,'requestId',p_request_id),
    NULL,p_request_id,NULL,
    encode(sha256(convert_to('public-verification:'||decision_id,'UTF8')),'hex'),
    NULL,qr."licenseeId",batch."manufacturerId",NULL,p_checked_at+interval '30 days',
    NULL,NULL,NULL,'QUEUED',0,p_checked_at,NULL,NULL,p_checked_at,p_checked_at
  );

  claim_available:=ready AND qr.status<>'BLOCKED' AND replacement_status<>'REPLACED_LABEL';
  RETURN QUERY SELECT
    public_result,message_key,next_action,safe_code,
    coalesce(brand."brandName",brand.name),
    CASE WHEN brand.website ~ '^https?://' THEN brand.website ELSE NULL END,
    brand."supportEmail",brand."supportPhone",manufacturer.name,
    CASE WHEN manufacturer.website ~ '^https?://' THEN manufacturer.website ELSE NULL END,
    coalesce(qr."printedAt",batch."printedAt"),
    CASE WHEN scan_history_eligible THEN coalesce(first_at,p_checked_at) ELSE first_at END,
    CASE WHEN scan_history_eligible THEN p_checked_at ELSE qr."scannedAt" END,
    claim_available,NULL::text;
END
$$;

CREATE OR REPLACE FUNCTION app_public.verify_raw_qr(
  p_requested_code text,
  p_checked_at timestamp without time zone,
  p_request_id text,
  p_actor_ip_hash text,
  p_actor_device_hash text,
  p_session_start_token_hash text
) RETURNS TABLE(
  "result" text,"messageKey" text,"nextAction" text,"maskedCode" text,
  "brandName" text,"brandWebsite" text,"brandSupportEmail" text,"brandSupportPhone" text,
  "manufacturerName" text,"manufacturerWebsite" text,
  "printedAt" timestamp without time zone,"firstVerifiedAt" timestamp without time zone,
  "latestVerifiedAt" timestamp without time zone,"ownershipClaimAvailable" boolean,
  "sessionStartToken" text
)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public
AS $$
DECLARE qr_id text;
BEGIN
  IF p_requested_code IS NULL OR p_requested_code<>btrim(p_requested_code)
     OR length(p_requested_code)<8 OR length(p_requested_code)>128
     OR p_requested_code !~ '^[A-Za-z0-9][A-Za-z0-9_-]{7,127}$' THEN
    RAISE EXCEPTION 'PUBLIC_VERIFICATION_INVALID_INPUT' USING ERRCODE='22023';
  END IF;
  PERFORM app_public.public_verify_bind(
    'public-verification-raw-resolve',p_request_id,NULL,p_requested_code,NULL,NULL,NULL
  );
  SELECT q.id INTO qr_id FROM public."QRCode" q WHERE q.code=p_requested_code;
  IF qr_id IS NULL THEN
    -- Bounded PostgreSQL jitter reduces the unknown-code timing oracle without
    -- holding a QR row lock or allowing caller-controlled delay.
    PERFORM pg_sleep(0.015 + random()*0.010);
    RETURN QUERY SELECT 'NOT_FOUND','verification.not_found','TRY_AGAIN',
      CASE WHEN length(p_requested_code)<=4 THEN repeat('*',length(p_requested_code))
        ELSE repeat('*',length(p_requested_code)-4)||right(p_requested_code,4) END,
      NULL::text,NULL::text,NULL::text,NULL::text,NULL::text,NULL::text,
      NULL::timestamp,NULL::timestamp,NULL::timestamp,false,NULL::text;
    RETURN;
  END IF;
  RETURN QUERY SELECT * FROM app_public.public_verify_execute(
    qr_id,'MANUAL_CODE_LOOKUP',p_checked_at,p_request_id,p_actor_ip_hash,p_actor_device_hash,
    p_session_start_token_hash,NULL
  );
END
$$;

CREATE OR REPLACE FUNCTION app_public.verify_signed_qr(
  p_token_digest text,
  p_qr_id text,
  p_licensee_id text,
  p_batch_id text,
  p_manufacturer_id text,
  p_nonce text,
  p_replay_epoch integer,
  p_key_version text,
  p_issued_at timestamp without time zone,
  p_expires_at timestamp without time zone,
  p_checked_at timestamp without time zone,
  p_request_id text,
  p_actor_ip_hash text,
  p_actor_device_hash text,
  p_session_start_token_hash text
) RETURNS TABLE(
  "result" text,"messageKey" text,"nextAction" text,"verificationMethod" text,
  "maskedCode" text,"brandName" text,"brandWebsite" text,"brandSupportEmail" text,
  "brandSupportPhone" text,"manufacturerName" text,"manufacturerWebsite" text,
  "printedAt" timestamp without time zone,"firstVerifiedAt" timestamp without time zone,
  "latestVerifiedAt" timestamp without time zone,"ownershipClaimAvailable" boolean,
  "sessionStartToken" text
)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public
AS $$
DECLARE qr record; batch record;
BEGIN
  IF p_token_digest !~ '^(?:[A-Za-z0-9._-]{1,32}:)?[a-f0-9]{64}$'
     OR length(coalesce(p_nonce,'')) NOT BETWEEN 8 AND 256
     OR p_nonce !~ '^[A-Za-z0-9_-]+$'
     OR p_replay_epoch<1 OR p_key_version !~ '^[A-Za-z0-9._-]{1,64}$'
     OR p_issued_at>p_checked_at OR p_checked_at>=p_expires_at THEN
    RAISE EXCEPTION 'PUBLIC_SIGNED_TOKEN_INVALID' USING ERRCODE='22023';
  END IF;
  PERFORM app_public.public_verify_bind(
    'public-verification-signed-resolve',p_request_id,p_qr_id,NULL,NULL,NULL,NULL
  );
  SELECT q.id,q."licenseeId",q."batchId",q."tokenHash",q."tokenNonce",q."replayEpoch",
    q."tokenIssuedAt",q."tokenExpiresAt"
  INTO qr
  FROM public."QRCode" q WHERE q.id=p_qr_id;
  IF qr.id IS NULL OR qr."licenseeId"<>p_licensee_id
     OR qr."batchId" IS DISTINCT FROM p_batch_id
     OR qr."tokenHash" IS DISTINCT FROM p_token_digest
     OR qr."tokenNonce" IS DISTINCT FROM p_nonce
     OR qr."replayEpoch"<>p_replay_epoch
     OR qr."tokenIssuedAt" IS NULL
     OR abs(extract(epoch FROM (qr."tokenIssuedAt"-p_issued_at)))>1
     OR qr."tokenExpiresAt" IS NULL
     OR abs(extract(epoch FROM (qr."tokenExpiresAt"-p_expires_at)))>1
     OR qr."tokenExpiresAt"<=p_checked_at THEN
    RAISE EXCEPTION 'PUBLIC_SIGNED_TOKEN_INVALID' USING ERRCODE='42501';
  END IF;
  PERFORM set_config('app.public_verification_batch_id',coalesce(qr."batchId",''),true);
  IF qr."batchId" IS NOT NULL THEN
    SELECT b.id,b."manufacturerId" INTO batch
    FROM public."Batch" b WHERE b.id=qr."batchId";
    IF batch."manufacturerId" IS DISTINCT FROM p_manufacturer_id THEN
      RAISE EXCEPTION 'PUBLIC_SIGNED_TOKEN_INVALID' USING ERRCODE='42501';
    END IF;
  ELSIF p_manufacturer_id IS NOT NULL THEN
    RAISE EXCEPTION 'PUBLIC_SIGNED_TOKEN_INVALID' USING ERRCODE='42501';
  END IF;
  RETURN QUERY SELECT v."result",v."messageKey",v."nextAction",'SIGNED_LABEL'::text,
    v."maskedCode",v."brandName",v."brandWebsite",v."brandSupportEmail",v."brandSupportPhone",
    v."manufacturerName",v."manufacturerWebsite",
    v."printedAt",v."firstVerifiedAt",v."latestVerifiedAt",v."ownershipClaimAvailable",v."sessionStartToken"
  FROM app_public.public_verify_execute(
    p_qr_id,'SIGNED_LABEL',p_checked_at,p_request_id,p_actor_ip_hash,p_actor_device_hash,
    p_session_start_token_hash,p_token_digest
  ) v;
END
$$;

CREATE OR REPLACE FUNCTION app_public.record_qr_verification(
  p_qr_id text,p_proof_class text,p_outcome_code text,p_scanned_at timestamp without time zone,
  p_request_id text,p_actor_ip_hash text,p_actor_device_hash text
) RETURNS TABLE("decisionKey" text,"recorded" boolean)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public
AS $$
BEGIN
  RAISE EXCEPTION 'PUBLIC_VERIFICATION_INTERNAL_ONLY' USING ERRCODE='42501';
END
$$;

CREATE OR REPLACE FUNCTION app_public.start_verification_session(
  p_session_start_token_hash text,
  p_entry_method text,
  p_customer_capability text,
  p_checked_at timestamp without time zone,
  p_request_id text,
  p_session_proof_hash text
) RETURNS TABLE(
  "sessionId" text,"sessionProofToken" text,"maskedCode" text,"customerFacingState" text,
  "entryMethod" text,"authState" text,"startedAt" timestamp without time zone,
  "expiresAt" timestamp without time zone,"proofBindingExpiresAt" timestamp without time zone,
  "brandName" text
)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public
AS $$
DECLARE evidence record;
  decision record;
  customer record;
  session_id text:=gen_random_uuid()::text;
  expires_at timestamp without time zone:=p_checked_at+interval '24 hours';
  updated_metadata jsonb; token_state jsonb; brand_name text;
BEGIN
  SELECT NULL::text AS "customerUserId",NULL::text AS "customerEmail" INTO customer;
  IF p_entry_method NOT IN ('SIGNED_SCAN','MANUAL_CODE')
     OR p_session_start_token_hash !~ '^(?:[A-Za-z0-9._-]{1,32}:)?[a-f0-9]{64}$'
     OR p_session_proof_hash !~ '^(?:[A-Za-z0-9._-]{1,32}:)?[a-f0-9]{64}$' THEN
    RAISE EXCEPTION 'PUBLIC_VERIFICATION_SESSION_INVALID' USING ERRCODE='22023';
  END IF;
  IF p_customer_capability IS NOT NULL THEN
    SELECT * INTO customer FROM app_public.require_customer_auth_session(
      p_customer_capability,p_checked_at,p_request_id,'customer-verification-session-start'
    );
  END IF;
  PERFORM app_public.public_verify_bind(
    'public-verification-session-start',p_request_id,NULL,NULL,NULL,session_id,NULL
  );
  SELECT e.id,e."verificationDecisionId",e.metadata
  INTO evidence
  FROM public."VerificationEvidenceSnapshot" e
  WHERE e.metadata#>>'{publicSessionStart,tokenHash}'=p_session_start_token_hash
  ORDER BY e."createdAt" DESC LIMIT 1 FOR UPDATE;
  token_state:=coalesce(evidence.metadata->'publicSessionStart','{}'::jsonb);
  IF evidence.id IS NULL OR token_state ? 'consumedAt'
     OR (token_state->>'expiresAt')::timestamp without time zone<=p_checked_at THEN
    RAISE EXCEPTION 'PUBLIC_VERIFICATION_SESSION_INVALID' USING ERRCODE='42501';
  END IF;
  PERFORM set_config('app.public_verification_decision_id',evidence."verificationDecisionId",true);
  SELECT d.id,d."qrCodeId",d.code,d."licenseeId"
  INTO STRICT decision
  FROM public."VerificationDecision" d
  WHERE d.id=evidence."verificationDecisionId";
  IF decision."licenseeId" IS NOT NULL THEN
    PERFORM set_config('app.public_verification_licensee_id',decision."licenseeId",true);
    SELECT coalesce(l."brandName",l.name) INTO brand_name
    FROM public."Licensee" l WHERE l.id=decision."licenseeId";
  END IF;
  updated_metadata:=jsonb_set(evidence.metadata,'{publicSessionStart,consumedAt}',to_jsonb(p_checked_at),true);
  UPDATE public."VerificationEvidenceSnapshot" SET metadata=updated_metadata WHERE id=evidence.id;
  INSERT INTO public."CustomerVerificationSession"(
    id,"verificationDecisionId","qrCodeId",code,"entryMethod","authState",
    "customerUserId","customerEmail","intakeCompletedAt","revealedAt","expiresAt",
    "proofBindingTokenHash","proofBindingIssuedAt","proofBindingExpiresAt","proofBindingReplayEpoch",
    metadata,"createdAt","updatedAt"
  ) VALUES (
    session_id,decision.id,decision."qrCodeId",decision.code,
    p_entry_method::public."CustomerVerificationEntryMethod",
    (CASE WHEN customer."customerUserId" IS NULL THEN 'PENDING' ELSE 'VERIFIED' END)::public."CustomerVerificationAuthState",
    customer."customerUserId",customer."customerEmail",NULL,NULL,expires_at,p_session_proof_hash,p_checked_at,
    p_checked_at+interval '30 minutes',NULL,
    jsonb_build_object('boundCustomerUserId',customer."customerUserId"),p_checked_at,p_checked_at
  );
  PERFORM app_public.public_verify_write_evidence(
    'VERIFY_SESSION_STARTED','CustomerVerificationSession',session_id,decision."licenseeId",
    jsonb_build_object('entryMethod',p_entry_method),p_checked_at,p_request_id
  );
  RETURN QUERY SELECT session_id,NULL::text,
    CASE WHEN decision.code IS NULL THEN '' WHEN length(decision.code)<=4 THEN repeat('*',length(decision.code))
      ELSE repeat('*',length(decision.code)-4)||right(decision.code,4) END,
    CASE WHEN customer."customerUserId" IS NULL THEN 'AUTHENTICATION_REQUIRED' ELSE 'INTAKE_REQUIRED' END,
    p_entry_method,CASE WHEN customer."customerUserId" IS NULL THEN 'PENDING' ELSE 'VERIFIED' END,
    p_checked_at,expires_at,p_checked_at+interval '30 minutes',brand_name;
END
$$;

CREATE OR REPLACE FUNCTION app_public.read_verification_session(
  p_session_id text,p_session_proof_hash text,p_customer_capability text,
  p_checked_at timestamp without time zone,p_request_id text
) RETURNS TABLE(
  "sessionId" text,"maskedCode" text,"customerFacingState" text,"startedAt" timestamp without time zone,
  "expiresAt" timestamp without time zone,"proofBindingExpiresAt" timestamp without time zone,
  "entryMethod" text,"authState" text,"intakeCompleted" boolean,"revealed" boolean,
  "brandName" text,"verification" jsonb
)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public
AS $$
DECLARE s record; d record;
  evidence record; brand_name text;
  customer record;
BEGIN
  SELECT NULL::text AS "customerUserId",NULL::text AS "customerEmail" INTO customer;
  IF p_customer_capability IS NOT NULL THEN
    SELECT * INTO customer FROM app_public.require_customer_auth_session(
      p_customer_capability,p_checked_at,p_request_id,'customer-verification-session-read'
    );
  END IF;
  PERFORM app_public.public_verify_bind(
    'public-verification-session-read',p_request_id,NULL,NULL,NULL,p_session_id,NULL
  );
  SELECT cs.id,cs."verificationDecisionId",cs.code,cs."entryMethod",cs."authState",cs."customerUserId",
    cs."intakeCompletedAt",cs."revealedAt",cs."expiresAt",cs."proofBindingTokenHash",
    cs."proofBindingExpiresAt",cs."createdAt"
  INTO s
  FROM public."CustomerVerificationSession" cs WHERE cs.id=p_session_id;
  IF s.id IS NULL OR s."expiresAt"<=p_checked_at OR s."proofBindingExpiresAt"<=p_checked_at
     OR s."proofBindingTokenHash" IS DISTINCT FROM p_session_proof_hash
     OR (s."customerUserId" IS NOT NULL AND s."customerUserId" IS DISTINCT FROM customer."customerUserId") THEN
    RAISE EXCEPTION 'PUBLIC_VERIFICATION_SESSION_INVALID' USING ERRCODE='42501';
  END IF;
  PERFORM set_config('app.public_verification_decision_id',s."verificationDecisionId",true);
  SELECT vd.id,vd."licenseeId" INTO STRICT d
  FROM public."VerificationDecision" vd WHERE vd.id=s."verificationDecisionId";
  SELECT e.id,e.metadata INTO evidence
  FROM public."VerificationEvidenceSnapshot" e
  WHERE e."verificationDecisionId"=d.id ORDER BY e."createdAt" DESC LIMIT 1;
  PERFORM set_config('app.public_verification_licensee_id',coalesce(d."licenseeId",''),true);
  SELECT coalesce(l."brandName",l.name) INTO brand_name FROM public."Licensee" l WHERE l.id=d."licenseeId";
  RETURN QUERY SELECT s.id,
    CASE WHEN s.code IS NULL THEN '' WHEN length(s.code)<=4 THEN repeat('*',length(s.code))
      ELSE repeat('*',length(s.code)-4)||right(s.code,4) END,
    CASE WHEN s."revealedAt" IS NOT NULL THEN 'REVEALED'
      WHEN s."intakeCompletedAt" IS NOT NULL THEN 'READY_TO_REVEAL'
      WHEN s."customerUserId" IS NOT NULL THEN 'INTAKE_REQUIRED'
      ELSE 'AUTHENTICATION_REQUIRED' END,
    s."createdAt",s."expiresAt",s."proofBindingExpiresAt",s."entryMethod"::text,s."authState"::text,
    s."intakeCompletedAt" IS NOT NULL,s."revealedAt" IS NOT NULL,brand_name,
    CASE WHEN s."revealedAt" IS NOT NULL THEN evidence.metadata->'presentationSnapshot' ELSE NULL END;
END
$$;

CREATE OR REPLACE FUNCTION app_public.write_verification_session(
  p_session_id text,p_session_proof_hash text,p_customer_capability text,
  p_operation text,p_payload jsonb,p_checked_at timestamp without time zone,p_request_id text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public
AS $$
DECLARE s record; intake_id text; customer record;
BEGIN
  IF p_operation NOT IN ('INTAKE','REVEAL') THEN
    RAISE EXCEPTION 'PUBLIC_VERIFICATION_SESSION_INVALID' USING ERRCODE='22023';
  END IF;
  SELECT * INTO customer FROM app_public.require_customer_auth_session(
    p_customer_capability,p_checked_at,p_request_id,'customer-verification-session-write'
  );
  PERFORM app_public.public_verify_bind(
    'public-verification-session-write',p_request_id,NULL,NULL,NULL,p_session_id,NULL
  );
  SELECT cs.id,cs."customerUserId",cs."expiresAt",cs."proofBindingTokenHash",cs."proofBindingExpiresAt"
  INTO s
  FROM public."CustomerVerificationSession" cs WHERE cs.id=p_session_id FOR UPDATE;
  IF s.id IS NULL OR s."expiresAt"<=p_checked_at OR s."proofBindingExpiresAt"<=p_checked_at
     OR s."proofBindingTokenHash"<>p_session_proof_hash
     OR (s."customerUserId" IS NOT NULL AND s."customerUserId"<>customer."customerUserId") THEN
    RAISE EXCEPTION 'PUBLIC_VERIFICATION_SESSION_INVALID' USING ERRCODE='42501';
  END IF;
  IF p_operation='INTAKE' THEN
    IF p_payload->>'purchaseChannel' NOT IN ('online','offline','gifted','unknown')
       OR p_payload->>'scanReason' NOT IN ('routine_check','new_seller','pricing_concern','packaging_concern','authenticity_concern')
       OR p_payload->>'ownershipIntent' NOT IN ('verify_only','claim_ownership','report_concern','contact_support')
       OR length(coalesce(p_payload->>'notes',''))>2000 THEN
      RAISE EXCEPTION 'PUBLIC_VERIFICATION_INTAKE_INVALID' USING ERRCODE='22023';
    END IF;
    SELECT i.id INTO intake_id FROM public."CustomerTrustIntake" i WHERE i."sessionId"=s.id;
    IF intake_id IS NULL THEN
      intake_id:=gen_random_uuid()::text;
      INSERT INTO public."CustomerTrustIntake"(
        id,"sessionId","customerUserId","customerEmail","purchaseChannel","sourceCategory",
        "platformName","sellerName","listingUrl","orderReference","storeName","purchaseCity",
        "purchaseCountry","purchaseDate","packagingState","packagingConcern","scanReason",
        "ownershipIntent",notes,answers,"createdAt","updatedAt"
      ) VALUES (
        intake_id,s.id,customer."customerUserId",customer."customerEmail",p_payload->>'purchaseChannel',
        nullif(p_payload->>'sourceCategory',''),nullif(p_payload->>'platformName',''),
        nullif(p_payload->>'sellerName',''),nullif(p_payload->>'listingUrl',''),
        nullif(p_payload->>'orderReference',''),nullif(p_payload->>'storeName',''),
        nullif(p_payload->>'purchaseCity',''),nullif(p_payload->>'purchaseCountry',''),
        CASE WHEN nullif(p_payload->>'purchaseDate','') IS NULL THEN NULL ELSE (p_payload->>'purchaseDate')::timestamp END,
        nullif(p_payload->>'packagingState',''),nullif(p_payload->>'packagingConcern',''),
        p_payload->>'scanReason',p_payload->>'ownershipIntent',nullif(p_payload->>'notes',''),
        p_payload,p_checked_at,p_checked_at
      );
    ELSE
      UPDATE public."CustomerTrustIntake" SET
        "customerUserId"=customer."customerUserId","customerEmail"=customer."customerEmail",
        "purchaseChannel"=p_payload->>'purchaseChannel',"sourceCategory"=nullif(p_payload->>'sourceCategory',''),
        "platformName"=nullif(p_payload->>'platformName',''),"sellerName"=nullif(p_payload->>'sellerName',''),
        "listingUrl"=nullif(p_payload->>'listingUrl',''),"orderReference"=nullif(p_payload->>'orderReference',''),
        "storeName"=nullif(p_payload->>'storeName',''),"purchaseCity"=nullif(p_payload->>'purchaseCity',''),
        "purchaseCountry"=nullif(p_payload->>'purchaseCountry',''),
        "purchaseDate"=CASE WHEN nullif(p_payload->>'purchaseDate','') IS NULL THEN NULL ELSE (p_payload->>'purchaseDate')::timestamp END,
        "packagingState"=nullif(p_payload->>'packagingState',''),
        "packagingConcern"=nullif(p_payload->>'packagingConcern',''),
        "scanReason"=p_payload->>'scanReason',"ownershipIntent"=p_payload->>'ownershipIntent',
        notes=nullif(p_payload->>'notes',''),answers=p_payload,"updatedAt"=p_checked_at
      WHERE id=intake_id;
    END IF;
    UPDATE public."CustomerVerificationSession" SET "authState"='VERIFIED',
      "customerUserId"=customer."customerUserId","customerEmail"=customer."customerEmail",
      "intakeCompletedAt"=coalesce("intakeCompletedAt",p_checked_at),"updatedAt"=p_checked_at
    WHERE id=s.id;
    RETURN jsonb_build_object('intakeSaved',true);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM public."CustomerTrustIntake" WHERE "sessionId"=s.id) THEN
    RAISE EXCEPTION 'PUBLIC_VERIFICATION_INTAKE_REQUIRED' USING ERRCODE='22023';
  END IF;
  UPDATE public."CustomerVerificationSession" SET "authState"='VERIFIED',
    "customerUserId"=customer."customerUserId","customerEmail"=customer."customerEmail",
    "revealedAt"=coalesce("revealedAt",p_checked_at),"updatedAt"=p_checked_at WHERE id=s.id;
  RETURN jsonb_build_object('revealed',true,'sessionId',s.id);
END
$$;

CREATE OR REPLACE FUNCTION app_public.public_verify_write_evidence(
  p_action text,p_entity_type text,p_entity_id text,p_licensee_id text,
  p_details jsonb,p_recorded_at timestamp without time zone,p_request_id text
) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public
AS $$
DECLARE audit_id text:=gen_random_uuid()::text; outbox_id text:=gen_random_uuid()::text;
  safe_details jsonb:=coalesce(p_details,'{}'::jsonb);
BEGIN
  IF p_action !~ '^VERIFY_[A-Z0-9_]{1,96}$' OR p_entity_type !~ '^[A-Za-z][A-Za-z0-9]{1,63}$'
     OR p_entity_id IS NULL OR p_recorded_at IS NULL THEN
    RAISE EXCEPTION 'PUBLIC_VERIFICATION_EVIDENCE_INVALID' USING ERRCODE='22023';
  END IF;
  PERFORM set_config('app.public_verification_audit_id',audit_id,true);
  PERFORM set_config('app.public_verification_outbox_id',outbox_id,true);
  INSERT INTO public."AuditLog"(
    id,"userId","orgId","licenseeId",action,"entityType","entityId",details,
    "ipAddress","ipHash","userAgent","createdAt"
  ) VALUES (
    audit_id,NULL,NULL,p_licensee_id,p_action,p_entity_type,p_entity_id,
    safe_details||jsonb_build_object('requestId',p_request_id),NULL,NULL,NULL,p_recorded_at
  );
  INSERT INTO public."SecurityEventOutbox"(
    id,"eventType",payload,"jobType","requestId","payloadDigest","idempotencyKey",
    "organizationId","licenseeId","manufacturerId","initiatingUserId","expiresAt",
    "claimedAt","claimLeaseExpiresAt","sinkEventId",status,attempts,"nextAttemptAt",
    "lastError","sentAt","createdAt","updatedAt"
  ) VALUES (
    outbox_id,p_action,safe_details,NULL,p_request_id,
    encode(sha256(convert_to(safe_details::text,'UTF8')),'hex'),
    encode(sha256(convert_to(p_action||':'||p_entity_id,'UTF8')),'hex'),
    NULL,p_licensee_id,NULL,NULL,p_recorded_at+interval '7 days',
    NULL,NULL,NULL,'QUEUED',0,p_recorded_at,NULL,NULL,p_recorded_at,p_recorded_at
  );
END
$$;

CREATE OR REPLACE FUNCTION app_public.claim_customer_ownership(
  p_customer_capability text,p_session_id text,p_session_proof_hash text,
  p_device_token_hash text,p_ip_hash text,p_user_agent_hash text,p_link_only boolean,
  p_checked_at timestamp without time zone,p_request_id text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public
AS $$
DECLARE customer record; session_row record;
  qr record; batch_state text; ownership record; claim_available boolean;
  ownership_id text:=gen_random_uuid()::text; action text; result text;
BEGIN
  SELECT NULL::text AS "customerUserId",NULL::text AS "customerEmail" INTO customer;
  IF p_customer_capability IS NOT NULL THEN
    SELECT * INTO customer FROM app_public.require_customer_auth_session(
      p_customer_capability,p_checked_at,p_request_id,'customer-ownership'
    );
  END IF;
  IF p_link_only AND customer."customerUserId" IS NULL THEN
    RAISE EXCEPTION 'PUBLIC_CUSTOMER_SESSION_DENIED' USING ERRCODE='42501';
  END IF;
  IF p_session_id !~ '^[0-9a-fA-F-]{36}$'
     OR p_session_proof_hash !~ '^(?:[A-Za-z0-9._-]{1,32}:)?[a-f0-9]{64}$'
     OR (customer."customerUserId" IS NULL AND p_device_token_hash IS NULL)
     OR (p_device_token_hash IS NOT NULL AND p_device_token_hash !~ '^(?:[A-Za-z0-9._-]{1,32}:)?[a-f0-9]{64}$') THEN
    RAISE EXCEPTION 'PUBLIC_OWNERSHIP_INVALID' USING ERRCODE='22023';
  END IF;
  PERFORM app_public.public_verify_bind(
    'public-verification-ownership-claim',p_request_id,NULL,NULL,NULL,p_session_id,NULL
  );
  SELECT s.id,s."customerUserId",s."qrCodeId",s."verificationDecisionId"
  INTO session_row FROM public."CustomerVerificationSession" s
  WHERE s.id=p_session_id AND s."proofBindingTokenHash"=p_session_proof_hash
    AND s."proofBindingExpiresAt">p_checked_at AND s."expiresAt">p_checked_at;
  IF session_row.id IS NULL OR
     (session_row."customerUserId" IS NOT NULL
       AND session_row."customerUserId" IS DISTINCT FROM customer."customerUserId") THEN
    RAISE EXCEPTION 'PUBLIC_OWNERSHIP_SESSION_DENIED' USING ERRCODE='42501';
  END IF;
  PERFORM set_config('app.public_verification_decision_id',session_row."verificationDecisionId",true);
  SELECT coalesce((e.metadata#>>'{presentationSnapshot,ownershipClaimAvailable}')::boolean,false)
  INTO claim_available
  FROM public."VerificationEvidenceSnapshot" e
  WHERE e."verificationDecisionId"=session_row."verificationDecisionId"
  ORDER BY e."createdAt" DESC,e.id DESC LIMIT 1;
  IF NOT coalesce(claim_available,false) THEN
    RAISE EXCEPTION 'PUBLIC_OWNERSHIP_NOT_READY' USING ERRCODE='55000';
  END IF;
  PERFORM set_config('app.public_verification_qr_id',session_row."qrCodeId",true);
  SELECT q.id,q.code,q."licenseeId",q."batchId",q.status,q."issuanceMode",q."customerVerifiableAt"
  INTO qr
  FROM public."QRCode" q WHERE q.id=session_row."qrCodeId";
  IF qr.id IS NULL THEN RAISE EXCEPTION 'PUBLIC_OWNERSHIP_TARGET_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM set_config('app.public_verification_licensee_id',qr."licenseeId",true);
  IF qr."batchId" IS NOT NULL THEN
    PERFORM set_config('app.public_verification_batch_id',qr."batchId",true);
    SELECT b."lifecycleState"::text INTO batch_state FROM public."Batch" b WHERE b.id=qr."batchId";
  END IF;
  IF qr.status NOT IN ('PRINTED','SCANNED','REDEEMED')
     OR coalesce(batch_state,'RELEASED')<>'RELEASED'
     OR (qr."issuanceMode"='GOVERNED_PRINT' AND qr."customerVerifiableAt" IS NULL) THEN
    RAISE EXCEPTION 'PUBLIC_OWNERSHIP_NOT_READY' USING ERRCODE='55000';
  END IF;
  SELECT o.id,o."userId",o."deviceTokenHash",o."claimedAt" INTO ownership
    FROM public."Ownership" o WHERE o."qrCodeId"=qr.id FOR UPDATE;
  IF ownership.id IS NULL THEN
    IF p_link_only THEN RAISE EXCEPTION 'PUBLIC_OWNERSHIP_NOT_FOUND' USING ERRCODE='42501'; END IF;
    PERFORM set_config('app.public_verification_target_id',ownership_id,true);
    INSERT INTO public."Ownership"(
      id,"qrCodeId","userId","deviceTokenHash","ipHash","userAgentHash","claimSource","linkedAt","claimedAt"
    ) VALUES (
      ownership_id,qr.id,customer."customerUserId",p_device_token_hash,p_ip_hash,p_user_agent_hash,
      CASE WHEN customer."customerUserId" IS NULL THEN 'DEVICE' ELSE 'USER' END,
      CASE WHEN customer."customerUserId" IS NULL THEN NULL ELSE p_checked_at END,p_checked_at
    ) RETURNING id,"userId","deviceTokenHash","claimedAt" INTO ownership;
    result:=CASE WHEN customer."customerUserId" IS NULL THEN 'CLAIMED_DEVICE' ELSE 'CLAIMED_USER' END;
    action:='VERIFY_CLAIM_SUCCESS';
  ELSIF ownership."userId"=customer."customerUserId"
     OR (ownership."userId" IS NULL AND ownership."deviceTokenHash"=p_device_token_hash) THEN
    PERFORM set_config('app.public_verification_target_id',ownership.id,true);
    IF customer."customerUserId" IS NOT NULL AND ownership."userId" IS NULL THEN
      UPDATE public."Ownership" SET "userId"=customer."customerUserId","linkedAt"=p_checked_at,
        "claimSource"='DEVICE_AND_USER' WHERE id=ownership.id
      RETURNING id,"userId","deviceTokenHash","claimedAt" INTO ownership;
      result:='LINKED_TO_SIGNED_IN_ACCOUNT'; action:='VERIFY_CLAIM_LINKED_TO_USER';
    ELSE
      result:='ALREADY_OWNED_BY_YOU'; action:='VERIFY_CLAIM_IDEMPOTENT';
    END IF;
  ELSE
    result:='OWNED_BY_ANOTHER_USER'; action:='VERIFY_CLAIM_CONFLICT';
  END IF;
  PERFORM app_public.public_verify_write_evidence(
    action,'Ownership',qr.id,qr."licenseeId",
    jsonb_build_object('claimResult',result,'customerBound',customer."customerUserId" IS NOT NULL),
    p_checked_at,p_request_id
  );
  RETURN jsonb_build_object(
    'claimResult',result,'message',CASE
      WHEN result='OWNED_BY_ANOTHER_USER' THEN 'Ownership is already claimed by another account or device.'
      WHEN result='ALREADY_OWNED_BY_YOU' THEN 'This product is already owned by you on this device/account.'
      WHEN result='LINKED_TO_SIGNED_IN_ACCOUNT' THEN 'Device claim linked to your signed-in account.'
      ELSE 'Product ownership claimed.' END,
    'conflict',result='OWNED_BY_ANOTHER_USER','claimTimestamp',ownership."claimedAt",
    'ownershipStatus',jsonb_build_object(
      'isClaimed',true,'claimedAt',ownership."claimedAt",
      'isOwnedByRequester',result<>'OWNED_BY_ANOTHER_USER',
      'isClaimedByAnother',result='OWNED_BY_ANOTHER_USER','canClaim',false
    )
  );
END
$$;

CREATE OR REPLACE FUNCTION app_public.create_customer_ownership_transfer(
  p_customer_capability text,p_requested_code text,p_recipient_email text,p_token_hash text,
  p_expires_at timestamp without time zone,p_checked_at timestamp without time zone,p_request_id text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public
AS $$
DECLARE customer record; qr record; ownership record;
  transfer_id text:=gen_random_uuid()::text;
BEGIN
  SELECT * INTO customer FROM app_public.require_customer_auth_session(
    p_customer_capability,p_checked_at,p_request_id,'customer-ownership'
  );
  IF p_token_hash !~ '^(?:[A-Za-z0-9._-]{1,32}:)?[a-f0-9]{64}$'
     OR p_expires_at<=p_checked_at OR p_expires_at>p_checked_at+interval '8 days'
     OR (p_recipient_email IS NOT NULL AND length(p_recipient_email)>160) THEN
    RAISE EXCEPTION 'PUBLIC_OWNERSHIP_TRANSFER_INVALID' USING ERRCODE='22023';
  END IF;
  PERFORM app_public.public_verify_bind(
    'public-verification-ownership-transfer-create',p_request_id,NULL,p_requested_code,NULL,NULL,NULL
  );
  SELECT q.id,q.code,q."licenseeId" INTO qr
  FROM public."QRCode" q WHERE q.code=p_requested_code;
  IF qr.id IS NULL THEN RAISE EXCEPTION 'PUBLIC_OWNERSHIP_TARGET_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM set_config('app.public_verification_qr_id',qr.id,true);
  PERFORM set_config('app.public_verification_licensee_id',qr."licenseeId",true);
  SELECT o.id INTO ownership FROM public."Ownership" o
  WHERE o."qrCodeId"=qr.id AND o."userId"=customer."customerUserId" FOR UPDATE;
  IF ownership.id IS NULL THEN RAISE EXCEPTION 'PUBLIC_OWNERSHIP_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM set_config('app.public_verification_target_id',ownership.id,true);
  UPDATE public."OwnershipTransfer" SET status='CANCELLED',"cancelledAt"=p_checked_at,"updatedAt"=p_checked_at
  WHERE "qrCodeId"=qr.id AND "initiatedByCustomerId"=customer."customerUserId" AND status='PENDING';
  PERFORM set_config('app.public_verification_support_id',transfer_id,true);
  PERFORM set_config('app.public_verification_transfer_token_hash',p_token_hash,true);
  INSERT INTO public."OwnershipTransfer"(
    id,"qrCodeId","ownershipId","initiatedByCustomerId","initiatedByEmail","recipientEmail",
    "tokenHash",status,"expiresAt","acceptedAt","cancelledAt","lastViewedAt",metadata,"createdAt","updatedAt"
  ) VALUES (
    transfer_id,qr.id,ownership.id,customer."customerUserId",customer."customerEmail",
    CASE WHEN p_recipient_email IS NULL THEN NULL ELSE lower(p_recipient_email) END,
    p_token_hash,'PENDING',p_expires_at,NULL,NULL,NULL,
    jsonb_build_object('source','public_verification'),p_checked_at,p_checked_at
  );
  PERFORM app_public.public_verify_write_evidence(
    'VERIFY_OWNERSHIP_TRANSFER_CREATED','OwnershipTransfer',transfer_id,qr."licenseeId",
    jsonb_build_object('qrCodeId',qr.id,'recipientBound',p_recipient_email IS NOT NULL),
    p_checked_at,p_request_id
  );
  RETURN jsonb_build_object(
    'transferId',transfer_id,'status','PENDING','expiresAt',p_expires_at,
    'notificationEmails',jsonb_build_array(customer."customerEmail",lower(p_recipient_email))
  );
END
$$;

CREATE OR REPLACE FUNCTION app_public.cancel_customer_ownership_transfer(
  p_customer_capability text,p_requested_code text,p_transfer_id text,
  p_checked_at timestamp without time zone,p_request_id text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public
AS $$
DECLARE customer record; qr record; changed integer;
  transfer record;
BEGIN
  SELECT * INTO customer FROM app_public.require_customer_auth_session(
    p_customer_capability,p_checked_at,p_request_id,'customer-ownership'
  );
  PERFORM app_public.public_verify_bind(
    'public-verification-ownership-transfer-cancel',p_request_id,NULL,p_requested_code,NULL,NULL,NULL
  );
  SELECT q.id,q.code,q."licenseeId" INTO qr
  FROM public."QRCode" q WHERE q.code=p_requested_code;
  IF qr.id IS NULL THEN RAISE EXCEPTION 'PUBLIC_OWNERSHIP_TARGET_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM set_config('app.public_verification_qr_id',qr.id,true);
  PERFORM set_config('app.public_verification_licensee_id',qr."licenseeId",true);
  SELECT t.id,t."initiatedByEmail",t."recipientEmail" INTO transfer FROM public."OwnershipTransfer" t
  WHERE t."qrCodeId"=qr.id AND t."initiatedByCustomerId"=customer."customerUserId"
    AND t.status='PENDING' AND (p_transfer_id IS NULL OR t.id=p_transfer_id)
  ORDER BY t."createdAt" DESC,t.id DESC LIMIT 1 FOR UPDATE;
  IF transfer.id IS NULL THEN RAISE EXCEPTION 'PUBLIC_OWNERSHIP_TRANSFER_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM set_config('app.public_verification_support_id',transfer.id,true);
  UPDATE public."OwnershipTransfer" SET status='CANCELLED',"cancelledAt"=p_checked_at,"updatedAt"=p_checked_at
  WHERE id=transfer.id AND "qrCodeId"=qr.id AND "initiatedByCustomerId"=customer."customerUserId"
    AND status='PENDING';
  GET DIAGNOSTICS changed=ROW_COUNT;
  IF changed<>1 THEN RAISE EXCEPTION 'PUBLIC_OWNERSHIP_TRANSFER_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM app_public.public_verify_write_evidence(
    'VERIFY_OWNERSHIP_TRANSFER_CANCELLED','OwnershipTransfer',transfer.id,qr."licenseeId",
    jsonb_build_object('qrCodeId',qr.id),p_checked_at,p_request_id
  );
  RETURN jsonb_build_object(
    'transferId',transfer.id,'status','CANCELLED',
    'notificationEmails',jsonb_build_array(transfer."initiatedByEmail",transfer."recipientEmail")
  );
END
$$;

CREATE OR REPLACE FUNCTION app_public.accept_customer_ownership_transfer(
  p_customer_capability text,p_token_hash text,p_ip_hash text,p_user_agent_hash text,
  p_checked_at timestamp without time zone,p_request_id text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public
AS $$
DECLARE customer record; transfer record; qr record;
  ownership record;
BEGIN
  SELECT * INTO customer FROM app_public.require_customer_auth_session(
    p_customer_capability,p_checked_at,p_request_id,'customer-ownership'
  );
  IF p_token_hash !~ '^(?:[A-Za-z0-9._-]{1,32}:)?[a-f0-9]{64}$' THEN
    RAISE EXCEPTION 'PUBLIC_OWNERSHIP_TRANSFER_INVALID' USING ERRCODE='22023';
  END IF;
  PERFORM app_public.public_verify_bind(
    'public-verification-ownership-transfer-accept',p_request_id,NULL,NULL,NULL,NULL,NULL
  );
  PERFORM set_config('app.public_verification_transfer_token_hash',p_token_hash,true);
  SELECT t.id,t.status,t."expiresAt",t."initiatedByCustomerId",t."recipientEmail",
    t."qrCodeId",t."ownershipId",t."initiatedByEmail" INTO transfer FROM public."OwnershipTransfer" t
  WHERE t."tokenHash"=p_token_hash FOR UPDATE;
  IF transfer.id IS NULL OR transfer.status<>'PENDING' OR transfer."expiresAt"<=p_checked_at
     OR transfer."initiatedByCustomerId"=customer."customerUserId"
     OR (transfer."recipientEmail" IS NOT NULL
       AND lower(transfer."recipientEmail")<>lower(customer."customerEmail")) THEN
    RAISE EXCEPTION 'PUBLIC_OWNERSHIP_TRANSFER_DENIED' USING ERRCODE='42501';
  END IF;
  PERFORM set_config('app.public_verification_qr_id',transfer."qrCodeId",true);
  PERFORM set_config('app.public_verification_support_id',transfer.id,true);
  SELECT q.id,q.code,q."licenseeId" INTO STRICT qr
  FROM public."QRCode" q WHERE q.id=transfer."qrCodeId";
  PERFORM set_config('app.public_verification_licensee_id',qr."licenseeId",true);
  PERFORM set_config('app.public_verification_target_id',transfer."ownershipId",true);
  SELECT o.id INTO STRICT ownership FROM public."Ownership" o
  WHERE o.id=transfer."ownershipId" AND o."qrCodeId"=qr.id FOR UPDATE;
  UPDATE public."OwnershipTransfer" SET status='ACCEPTED',"acceptedAt"=p_checked_at,
    "lastViewedAt"=p_checked_at,"updatedAt"=p_checked_at WHERE id=transfer.id;
  UPDATE public."Ownership" SET "userId"=customer."customerUserId","linkedAt"=p_checked_at,
    "claimedAt"=p_checked_at,"ipHash"=p_ip_hash,"userAgentHash"=p_user_agent_hash,
    "claimSource"='USER_TRANSFERRED' WHERE id=ownership.id;
  UPDATE public."OwnershipTransfer" SET status='CANCELLED',"cancelledAt"=p_checked_at,"updatedAt"=p_checked_at
  WHERE "qrCodeId"=qr.id AND status='PENDING' AND id<>transfer.id;
  PERFORM app_public.public_verify_write_evidence(
    'VERIFY_OWNERSHIP_TRANSFER_ACCEPTED','OwnershipTransfer',transfer.id,qr."licenseeId",
    jsonb_build_object('qrCodeId',qr.id),p_checked_at,p_request_id
  );
  RETURN jsonb_build_object('transferId',transfer.id,'status','ACCEPTED','code',qr.code,
    'notificationEmails',jsonb_build_array(transfer."initiatedByEmail",customer."customerEmail",transfer."recipientEmail"),
    'ownershipStatus',jsonb_build_object('isClaimed',true,'claimedAt',p_checked_at,
      'isOwnedByRequester',true,'isClaimedByAnother',false,'canClaim',false));
END
$$;

CREATE OR REPLACE FUNCTION app_public.begin_customer_passkey(
  p_customer_capability text,p_customer_user_id text,p_customer_email text,p_purpose text,
  p_ticket_hash text,p_challenge_hash text,p_ip_hash text,p_user_agent_hash text,
  p_origin text,p_rp_id text,p_expires_at timestamp without time zone,
  p_checked_at timestamp without time zone,p_request_id text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public
AS $$
DECLARE customer record; challenge_id text:=gen_random_uuid()::text; credentials jsonb;
BEGIN
  SELECT NULL::text AS "customerUserId",NULL::text AS "customerEmail" INTO customer;
  IF p_purpose NOT IN ('ENROLLMENT','LOGIN','STEP_UP')
     OR p_customer_user_id !~ '^cust_[a-f0-9]{32}$'
     OR p_customer_email !~ '^[^[:space:]@]+@[^[:space:]@]+[.][^[:space:]@]+$'
     OR p_ticket_hash !~ '^(?:[A-Za-z0-9._-]{1,32}:)?[a-f0-9]{64}$'
     OR p_challenge_hash !~ '^(?:[A-Za-z0-9._-]{1,32}:)?[a-f0-9]{64}$'
     OR p_expires_at<=p_checked_at OR p_expires_at>p_checked_at+interval '15 minutes'
     OR length(coalesce(p_origin,''))>512 OR length(coalesce(p_rp_id,''))>253 THEN
    RAISE EXCEPTION 'PUBLIC_PASSKEY_INVALID' USING ERRCODE='22023';
  END IF;
  IF p_purpose<>'LOGIN' THEN
    SELECT * INTO customer FROM app_public.require_customer_auth_session(
      p_customer_capability,p_checked_at,p_request_id,'customer-passkey'
    );
    IF customer."customerUserId"<>p_customer_user_id
       OR lower(customer."customerEmail")<>lower(p_customer_email) THEN
      RAISE EXCEPTION 'PUBLIC_PASSKEY_DENIED' USING ERRCODE='42501';
    END IF;
  ELSE
    PERFORM app_public.public_verify_bind('public-verification-customer-passkey',p_request_id);
  END IF;
  PERFORM set_config('app.public_verification_customer_user_id',p_customer_user_id,true);
  SELECT coalesce(jsonb_agg(jsonb_build_object(
    'credentialId',c."credentialId",'transports',to_jsonb(c.transports)
  ) ORDER BY c."createdAt",c.id),'[]'::jsonb)
  INTO credentials
  FROM public."CustomerWebAuthnCredential" c
  WHERE c."customerUserId"=p_customer_user_id;
  IF p_purpose IN ('LOGIN','STEP_UP') AND jsonb_array_length(credentials)=0 THEN
    RAISE EXCEPTION 'WEBAUTHN_NOT_ENROLLED' USING ERRCODE='02000';
  END IF;
  PERFORM set_config('app.public_verification_target_id',challenge_id,true);
  INSERT INTO public."CustomerWebAuthnChallenge"(
    id,"customerUserId","customerEmail",purpose,"ticketHash","challengeHash","credentialIds",
    "createdIpHash","createdUserAgentHash",origin,"rpId","createdAt","expiresAt","consumedAt"
  ) VALUES (
    challenge_id,p_customer_user_id,lower(p_customer_email),p_purpose,p_ticket_hash,p_challenge_hash,
    ARRAY(SELECT value->>'credentialId' FROM jsonb_array_elements(credentials)),
    p_ip_hash,p_user_agent_hash,p_origin,p_rp_id,p_checked_at,p_expires_at,NULL
  );
  RETURN jsonb_build_object('challengeId',challenge_id,'credentials',credentials);
END
$$;

CREATE OR REPLACE FUNCTION app_public.load_customer_passkey(
  p_ticket_hashes text[],p_purpose text,p_credential_id text,
  p_checked_at timestamp without time zone,p_request_id text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public
AS $$
DECLARE challenge record;
  credential record;
BEGIN
  IF coalesce(array_length(p_ticket_hashes,1),0)<1 OR array_length(p_ticket_hashes,1)>4
     OR EXISTS (SELECT 1 FROM unnest(p_ticket_hashes) h
       WHERE h !~ '^(?:[A-Za-z0-9._-]{1,32}:)?[a-f0-9]{64}$')
     OR (p_purpose IS NOT NULL AND p_purpose NOT IN ('ENROLLMENT','LOGIN','STEP_UP')) THEN
    RAISE EXCEPTION 'PUBLIC_PASSKEY_INVALID' USING ERRCODE='22023';
  END IF;
  PERFORM app_public.public_verify_bind('public-verification-customer-passkey',p_request_id);
  PERFORM set_config('app.public_verification_passkey_ticket_hashes',array_to_string(p_ticket_hashes,','),true);
  SELECT c.id,c."customerUserId",c."customerEmail",c.purpose,c."challengeHash",
    c."credentialIds",c."expiresAt",c.origin,c."rpId" INTO challenge
    FROM public."CustomerWebAuthnChallenge" c
  WHERE c."ticketHash"=ANY(p_ticket_hashes)
    AND (p_purpose IS NULL OR c.purpose=p_purpose)
    AND c."consumedAt" IS NULL AND c."expiresAt">p_checked_at
  ORDER BY c."createdAt" DESC LIMIT 1;
  IF challenge.id IS NULL THEN RAISE EXCEPTION 'WEBAUTHN_CHALLENGE_NOT_FOUND' USING ERRCODE='02000'; END IF;
  PERFORM set_config('app.public_verification_target_id',challenge.id,true);
  IF p_credential_id IS NOT NULL THEN
    PERFORM set_config('app.public_verification_support_id',p_credential_id,true);
    SELECT c.id,c."customerUserId",c."customerEmail",c."credentialId",c."publicKeySpki",c.counter
      INTO credential FROM public."CustomerWebAuthnCredential" c
    WHERE c."customerUserId"=challenge."customerUserId" AND c."credentialId"=p_credential_id;
    IF credential.id IS NULL OR NOT p_credential_id=ANY(challenge."credentialIds") THEN
      RAISE EXCEPTION 'WEBAUTHN_CREDENTIAL_NOT_FOUND' USING ERRCODE='02000';
    END IF;
  END IF;
  RETURN jsonb_build_object(
    'id',challenge.id,'customerUserId',challenge."customerUserId",
    'customerEmail',challenge."customerEmail",'purpose',challenge.purpose,
    'challengeHash',challenge."challengeHash",'expiresAt',challenge."expiresAt",
    'credentialIds',to_jsonb(challenge."credentialIds"),'origin',challenge.origin,'rpId',challenge."rpId",
    'credential',CASE WHEN credential.id IS NULL THEN NULL ELSE jsonb_build_object(
      'id',credential.id,'customerUserId',credential."customerUserId",
      'customerEmail',credential."customerEmail",'credentialId',credential."credentialId",
      'publicKeySpki',credential."publicKeySpki",'counter',credential.counter
    ) END
  );
END
$$;

CREATE OR REPLACE FUNCTION app_public.finish_customer_passkey(
  p_customer_capability text,p_ticket_hashes text[],p_purpose text,p_payload jsonb,
  p_checked_at timestamp without time zone,p_request_id text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public
AS $$
DECLARE challenge record;
  credential record; customer record;
  credential_id text:=p_payload->>'credentialId'; next_counter integer;
BEGIN
  IF p_purpose NOT IN ('ENROLLMENT','LOGIN','STEP_UP')
     OR coalesce(array_length(p_ticket_hashes,1),0)<1 OR array_length(p_ticket_hashes,1)>4
     OR EXISTS (SELECT 1 FROM unnest(p_ticket_hashes) h
       WHERE h !~ '^(?:[A-Za-z0-9._-]{1,32}:)?[a-f0-9]{64}$')
     OR credential_id IS NULL OR length(credential_id)>1024 THEN
    RAISE EXCEPTION 'PUBLIC_PASSKEY_INVALID' USING ERRCODE='22023';
  END IF;
  IF p_customer_capability IS NOT NULL THEN
    SELECT * INTO customer FROM app_public.require_customer_auth_session(
      p_customer_capability,p_checked_at,p_request_id,'customer-passkey'
    );
  ELSE
    PERFORM app_public.public_verify_bind('public-verification-customer-passkey',p_request_id);
  END IF;
  PERFORM set_config('app.public_verification_passkey_ticket_hashes',array_to_string(p_ticket_hashes,','),true);
  SELECT c.id,c."customerUserId",c."customerEmail",c.purpose,c."credentialIds",c."expiresAt"
    INTO challenge FROM public."CustomerWebAuthnChallenge" c
  WHERE c."ticketHash"=ANY(p_ticket_hashes) AND c.purpose=p_purpose
    AND c."consumedAt" IS NULL AND c."expiresAt">p_checked_at
  ORDER BY c."createdAt" DESC LIMIT 1;
  IF challenge.id IS NULL THEN RAISE EXCEPTION 'WEBAUTHN_CHALLENGE_NOT_FOUND' USING ERRCODE='02000'; END IF;
  PERFORM set_config('app.public_verification_target_id',challenge.id,true);
  UPDATE public."CustomerWebAuthnChallenge"
  SET "consumedAt"=p_checked_at
  WHERE id=challenge.id AND "consumedAt" IS NULL AND "expiresAt">p_checked_at
  RETURNING id,"customerUserId","customerEmail",purpose,"credentialIds","expiresAt" INTO challenge;
  IF challenge.id IS NULL THEN RAISE EXCEPTION 'WEBAUTHN_CHALLENGE_NOT_FOUND' USING ERRCODE='02000'; END IF;
  PERFORM set_config('app.public_verification_customer_user_id',challenge."customerUserId",true);
  IF p_purpose IN ('ENROLLMENT','STEP_UP')
     AND (customer."customerUserId" IS NULL OR customer."customerUserId"<>challenge."customerUserId") THEN
    RAISE EXCEPTION 'PUBLIC_PASSKEY_DENIED' USING ERRCODE='42501';
  END IF;
  IF p_purpose='ENROLLMENT' THEN
    IF length(coalesce(p_payload->>'publicKeySpki',''))<16
       OR coalesce(jsonb_array_length(p_payload->'transports'),0)>16
       OR length(coalesce(p_payload->>'label',''))>120 THEN
      RAISE EXCEPTION 'PUBLIC_PASSKEY_INVALID' USING ERRCODE='22023';
    END IF;
    PERFORM set_config('app.public_verification_support_id',credential_id,true);
    SELECT c.id,c."customerUserId",c."credentialId",c.counter INTO credential
      FROM public."CustomerWebAuthnCredential" c
    WHERE c."credentialId"=credential_id;
    IF credential.id IS NOT NULL AND credential."customerUserId"<>challenge."customerUserId" THEN
      RAISE EXCEPTION 'PUBLIC_PASSKEY_DENIED' USING ERRCODE='42501';
    END IF;
    IF credential.id IS NULL THEN
      PERFORM set_config('app.public_verification_support_id',gen_random_uuid()::text,true);
      INSERT INTO public."CustomerWebAuthnCredential"(
        id,"customerUserId","customerEmail",label,"credentialId","publicKeySpki",
        "publicKeyAlgorithm",counter,transports,"lastUsedAt","createdAt","updatedAt"
      ) VALUES (
        current_setting('app.public_verification_support_id'),challenge."customerUserId",
        challenge."customerEmail",coalesce(nullif(p_payload->>'label',''),'Passkey'),credential_id,
        p_payload->>'publicKeySpki',(p_payload->>'publicKeyAlgorithm')::integer,
        (p_payload->>'counter')::integer,
        ARRAY(SELECT jsonb_array_elements_text(coalesce(p_payload->'transports','[]'::jsonb))),
        p_checked_at,p_checked_at,p_checked_at
      ) RETURNING id,"customerUserId","credentialId",counter INTO credential;
    ELSE
      PERFORM set_config('app.public_verification_support_id',credential.id,true);
      UPDATE public."CustomerWebAuthnCredential" SET
        label=coalesce(nullif(p_payload->>'label',''),'Passkey'),
        "publicKeySpki"=p_payload->>'publicKeySpki',
        "publicKeyAlgorithm"=(p_payload->>'publicKeyAlgorithm')::integer,
        counter=(p_payload->>'counter')::integer,
        transports=ARRAY(SELECT jsonb_array_elements_text(coalesce(p_payload->'transports','[]'::jsonb))),
        "lastUsedAt"=p_checked_at,"updatedAt"=p_checked_at
      WHERE id=credential.id RETURNING id,"customerUserId","credentialId",counter INTO credential;
    END IF;
  ELSE
    PERFORM set_config('app.public_verification_support_id',credential_id,true);
    SELECT c.id,c."customerUserId",c."credentialId",c.counter INTO credential
      FROM public."CustomerWebAuthnCredential" c
    WHERE c."customerUserId"=challenge."customerUserId" AND c."credentialId"=credential_id;
    IF credential.id IS NULL OR NOT credential_id=ANY(challenge."credentialIds") THEN
      RAISE EXCEPTION 'WEBAUTHN_CREDENTIAL_NOT_FOUND' USING ERRCODE='02000';
    END IF;
    PERFORM set_config('app.public_verification_support_id',credential.id,true);
    SELECT c.id,c."customerUserId",c."credentialId",c.counter INTO credential
      FROM public."CustomerWebAuthnCredential" c
    WHERE c.id=credential.id FOR UPDATE;
    next_counter:=(p_payload->>'nextCounter')::integer;
    IF next_counter<credential.counter OR (next_counter>0 AND credential.counter>0 AND next_counter<=credential.counter) THEN
      RAISE EXCEPTION 'WEBAUTHN_COUNTER_REPLAY' USING ERRCODE='55000';
    END IF;
    UPDATE public."CustomerWebAuthnCredential"
    SET counter=greatest(counter,next_counter),"lastUsedAt"=p_checked_at,"updatedAt"=p_checked_at
    WHERE id=credential.id;
  END IF;
  RETURN jsonb_build_object(
    'credentialId',credential."credentialId",'customerUserId',challenge."customerUserId",
    'customerEmail',challenge."customerEmail",'purpose',challenge.purpose,'assertedAt',p_checked_at
  );
END
$$;

CREATE OR REPLACE FUNCTION app_public.list_customer_passkeys(
  p_customer_capability text,p_checked_at timestamp without time zone,p_request_id text
) RETURNS TABLE(payload jsonb)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public
AS $$
DECLARE customer record;
BEGIN
  SELECT * INTO customer FROM app_public.require_customer_auth_session(
    p_customer_capability,p_checked_at,p_request_id,'customer-passkey'
  );
  PERFORM set_config('app.public_verification_customer_user_id',customer."customerUserId",true);
  RETURN QUERY SELECT jsonb_build_object(
    'id',c.id,'label',coalesce(c.label,'Passkey'),'credentialId',c."credentialId",
    'transports',to_jsonb(c.transports),'lastUsedAt',c."lastUsedAt",
    'createdAt',c."createdAt",'updatedAt',c."updatedAt"
  ) FROM public."CustomerWebAuthnCredential" c
  WHERE c."customerUserId"=customer."customerUserId"
  ORDER BY c."lastUsedAt" DESC NULLS LAST,c."createdAt" DESC,c.id DESC LIMIT 20;
END
$$;

CREATE OR REPLACE FUNCTION app_public.delete_customer_passkey(
  p_customer_capability text,p_credential_row_id text,
  p_checked_at timestamp without time zone,p_request_id text
) RETURNS TABLE(deleted boolean)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public
AS $$
DECLARE customer record; changed integer;
BEGIN
  SELECT * INTO customer FROM app_public.require_customer_auth_session(
    p_customer_capability,p_checked_at,p_request_id,'customer-passkey'
  );
  PERFORM set_config('app.public_verification_customer_user_id',customer."customerUserId",true);
  PERFORM set_config('app.public_verification_support_id',p_credential_row_id,true);
  DELETE FROM public."CustomerWebAuthnCredential"
  WHERE id=p_credential_row_id AND "customerUserId"=customer."customerUserId";
  GET DIAGNOSTICS changed=ROW_COUNT;
  RETURN QUERY SELECT changed=1;
END
$$;

CREATE OR REPLACE FUNCTION app_public.submit_product_feedback(
  p_requested_code text,p_rating integer,p_satisfaction text,p_notes text,p_observed_status text,
  p_observed_outcome text,p_page_url text,p_submitted_at timestamp without time zone,
  p_request_id text,p_actor_ip_hash text,p_idempotency_digest text
) RETURNS TABLE("accepted" boolean,"publicReference" text,"message" text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public
AS $$
DECLARE qr record; key_row record;
  reference text:='FB-'||upper(substr(replace(gen_random_uuid()::text,'-',''),1,12)); audit_id text;
BEGIN
  IF p_rating<1 OR p_rating>5 OR p_satisfaction NOT IN
    ('very_satisfied','satisfied','neutral','disappointed','very_disappointed')
    OR length(coalesce(p_notes,''))>1000 THEN
    RAISE EXCEPTION 'PUBLIC_FEEDBACK_INVALID' USING ERRCODE='22023';
  END IF;
  PERFORM app_public.public_verify_bind(
    'public-verification-feedback',p_request_id,NULL,p_requested_code,NULL,NULL,p_idempotency_digest
  );
  SELECT q.id,q."licenseeId" INTO qr
  FROM public."QRCode" q WHERE q.code=p_requested_code;
  IF qr.id IS NULL THEN RAISE EXCEPTION 'PUBLIC_FEEDBACK_TARGET_INVALID' USING ERRCODE='42501'; END IF;
  SELECT k.id,k."responsePayload" INTO key_row
  FROM public."ActionIdempotencyKey" k WHERE k."keyHash"=p_idempotency_digest;
  IF key_row.id IS NOT NULL THEN
    RETURN QUERY SELECT true,coalesce(key_row."responsePayload"->>'reference',reference),
      'Feedback submitted successfully.'; RETURN;
  END IF;
  INSERT INTO public."ActionIdempotencyKey"(
    id,"keyHash",action,scope,"requestHash","statusCode","responsePayload","createdAt","completedAt","expiresAt"
  ) VALUES (
    gen_random_uuid()::text,p_idempotency_digest,'PUBLIC_PRODUCT_FEEDBACK',qr.id,p_idempotency_digest,201,
    jsonb_build_object('reference',reference),p_submitted_at,p_submitted_at,p_submitted_at+interval '24 hours'
  );
  audit_id:=gen_random_uuid()::text;
  PERFORM set_config('app.public_verification_audit_id',audit_id,true);
  INSERT INTO public."AuditLog"(
    id,"userId","orgId","licenseeId",action,"entityType","entityId",details,
    "ipAddress","ipHash","userAgent","createdAt"
  ) VALUES (
    audit_id,NULL,NULL,qr."licenseeId",'CUSTOMER_PRODUCT_FEEDBACK','CustomerFeedback',qr.id,
    jsonb_build_object('reference',reference,'rating',p_rating,'satisfaction',p_satisfaction,
      'notesPresent',length(coalesce(p_notes,''))>0,'observedStatus',nullif(p_observed_status,''),
      'observedOutcome',nullif(p_observed_outcome,''),'requestId',p_request_id),
    NULL,NULL,NULL,p_submitted_at
  );
  RETURN QUERY SELECT true,reference,'Feedback submitted successfully.';
END
$$;

CREATE OR REPLACE FUNCTION app_public.submit_public_incident(
  p_session_id text,p_session_proof_hash text,p_incident_type text,p_description text,p_contact_email text,
  p_consent_to_contact boolean,p_evidence jsonb,p_submitted_at timestamp without time zone,p_request_id text,
  p_actor_ip_hash text,p_actor_device_hash text,p_idempotency_digest text
) RETURNS TABLE("accepted" boolean,"publicReference" text,"message" text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public
AS $$
DECLARE qr record; session_row record;
  key_row record;
  incident_id text:=gen_random_uuid()::text; ticket_id text:=gen_random_uuid()::text;
  outbox_id text:=gen_random_uuid()::text;
  reference text:='INC-'||upper(substr(replace(gen_random_uuid()::text,'-',''),1,12));
BEGIN
  IF p_session_id !~ '^[0-9a-fA-F-]{36}$'
     OR p_session_proof_hash !~ '^(?:[A-Za-z0-9._-]{1,32}:)?[a-f0-9]{64}$'
     OR p_incident_type NOT IN ('counterfeit_suspected','duplicate_scan','tampered_label','wrong_product','other')
     OR length(btrim(p_description))<3 OR length(p_description)>2000
     OR jsonb_typeof(coalesce(p_evidence,'[]'::jsonb))<>'array'
     OR jsonb_array_length(coalesce(p_evidence,'[]'::jsonb))>4
     OR (p_consent_to_contact AND (p_contact_email IS NULL OR length(p_contact_email)>160)) THEN
    RAISE EXCEPTION 'PUBLIC_INCIDENT_INVALID' USING ERRCODE='22023';
  END IF;
  PERFORM app_public.public_verify_bind(
    'public-verification-incident',p_request_id,NULL,NULL,NULL,p_session_id,p_idempotency_digest
  );
  SELECT s.id,s."qrCodeId" INTO session_row FROM public."CustomerVerificationSession" s
  WHERE s.id=p_session_id AND s."proofBindingTokenHash"=p_session_proof_hash
    AND s."proofBindingExpiresAt">p_submitted_at AND s."expiresAt">p_submitted_at;
  IF session_row.id IS NULL THEN
    RAISE EXCEPTION 'PUBLIC_INCIDENT_SESSION_DENIED' USING ERRCODE='42501';
  END IF;
  PERFORM set_config('app.public_verification_qr_id',session_row."qrCodeId",true);
  SELECT q.id,q.code,q."licenseeId" INTO qr
  FROM public."QRCode" q WHERE q.id=session_row."qrCodeId";
  IF qr.id IS NULL THEN RAISE EXCEPTION 'PUBLIC_INCIDENT_TARGET_INVALID' USING ERRCODE='42501'; END IF;
  PERFORM set_config('app.public_verification_qr_id',qr.id,true);
  PERFORM set_config('app.public_verification_target_id',incident_id,true);
  PERFORM set_config('app.public_verification_support_id',ticket_id,true);
  PERFORM set_config('app.public_verification_outbox_id',outbox_id,true);
  SELECT k.id,k."responsePayload" INTO key_row
  FROM public."ActionIdempotencyKey" k WHERE k."keyHash"=p_idempotency_digest;
  IF key_row.id IS NOT NULL THEN
    RETURN QUERY SELECT true,key_row."responsePayload"->>'reference','Concern submitted successfully.'; RETURN;
  END IF;
  INSERT INTO public."Incident"(
    id,"qrCodeId","qrCodeValue","scanEventId","licenseeId","reportedBy","customerName",
    "customerEmail","customerPhone","customerCountry","preferredContactMethod","consentToContact",
    "incidentType",severity,"severityOverridden",description,photos,"purchasePlace","purchaseDate",
    "productBatchNo","locationLat","locationLng","locationName","locationCountry","locationRegion",
    "locationCity","ipHash","userAgentHash","deviceFingerprintHash",status,priority,
    "assignedToUserId","slaDueAt",tags,"internalNotes","resolutionSummary","resolutionOutcome",
    "createdAt","updatedAt"
  ) VALUES (
    incident_id,qr.id,qr.code,NULL,qr."licenseeId",'CUSTOMER',NULL,
    CASE WHEN p_consent_to_contact THEN lower(p_contact_email) ELSE NULL END,NULL,NULL,
    (CASE WHEN p_consent_to_contact THEN 'EMAIL' ELSE 'NONE' END)::public."IncidentContactMethod",
    p_consent_to_contact,
    upper(p_incident_type)::public."IncidentType",'MEDIUM',false,p_description,ARRAY[]::text[],
    NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,p_actor_ip_hash,NULL,p_actor_device_hash,
    'NEW','P3',NULL,p_submitted_at+interval '24 hours',
    ARRAY['public_verification_concern'],NULL,NULL,NULL,p_submitted_at,p_submitted_at
  );
  INSERT INTO public."IncidentEvent"(
    id,"incidentId","actorType","actorUserId","eventType","eventPayload","createdAt"
  ) VALUES (
    gen_random_uuid()::text,incident_id,'CUSTOMER',NULL,'CREATED',
    jsonb_build_object('requestId',p_request_id,'source','public_verification'),p_submitted_at
  );
  IF EXISTS (
    SELECT 1 FROM jsonb_array_elements(coalesce(p_evidence,'[]'::jsonb)) e
    WHERE e->>'storageKey' !~ '^[A-Za-z0-9._-]{1,255}$'
       OR length(coalesce(e->>'fileUrl','')) NOT BETWEEN 31 AND 300
       OR e->>'fileUrl' !~ '^/api/incidents/evidence-files/[A-Za-z0-9._%-]+$'
       OR e->>'fileType' NOT IN ('image/jpeg','image/png','image/webp','application/pdf')
  ) THEN
    RAISE EXCEPTION 'PUBLIC_INCIDENT_EVIDENCE_INVALID' USING ERRCODE='22023';
  END IF;
  INSERT INTO public."IncidentEvidence"(
    id,"incidentId","fileUrl","storageKey","fileType","uploadedByUserId","uploadedBy","createdAt"
  )
  SELECT gen_random_uuid()::text,incident_id,e->>'fileUrl',e->>'storageKey',e->>'fileType',
    NULL,'CUSTOMER',p_submitted_at
  FROM jsonb_array_elements(coalesce(p_evidence,'[]'::jsonb)) e;
  INSERT INTO public."SupportTicket"(
    id,"incidentId","referenceCode","licenseeId","customerEmail",subject,status,priority,
    "assignedToUserId","slaDueAt","firstResponseAt","resolvedAt","createdAt","updatedAt"
  ) VALUES (
    ticket_id,incident_id,reference,qr."licenseeId",
    CASE WHEN p_consent_to_contact THEN lower(p_contact_email) ELSE NULL END,
    'Public verification concern','OPEN','P3',NULL,p_submitted_at+interval '24 hours',
    NULL,NULL,p_submitted_at,p_submitted_at
  );
  INSERT INTO public."ActionIdempotencyKey"(
    id,"keyHash",action,scope,"requestHash","statusCode","responsePayload","createdAt","completedAt","expiresAt"
  ) VALUES (
    gen_random_uuid()::text,p_idempotency_digest,'PUBLIC_VERIFICATION_INCIDENT',qr.id,
    p_idempotency_digest,201,jsonb_build_object('reference',reference),
    p_submitted_at,p_submitted_at,p_submitted_at+interval '24 hours'
  );
  INSERT INTO public."SecurityEventOutbox"(
    id,"eventType",payload,"jobType","requestId","payloadDigest","idempotencyKey",
    "organizationId","licenseeId","manufacturerId","initiatingUserId","expiresAt",
    "claimedAt","claimLeaseExpiresAt","sinkEventId",status,attempts,"nextAttemptAt",
    "lastError","sentAt","createdAt","updatedAt"
  ) VALUES (
    outbox_id,'PUBLIC_VERIFICATION_CONCERN',
    jsonb_build_object('incidentId',incident_id,'reference',reference,'requestId',p_request_id),
    NULL,p_request_id,NULL,
    encode(sha256(convert_to('public-incident:'||p_idempotency_digest,'UTF8')),'hex'),
    NULL,qr."licenseeId",NULL,NULL,p_submitted_at+interval '30 days',NULL,NULL,NULL,
    'QUEUED',0,p_submitted_at,NULL,NULL,p_submitted_at,p_submitted_at
  );
  RETURN QUERY SELECT true,reference,'Concern submitted successfully.';
END
$$;

CREATE OR REPLACE FUNCTION app_public.submit_request_access(
  p_full_name text,p_work_email text,p_company_name text,p_role_title text,p_country text,
  p_monthly_volume text,p_message text,p_source_page text,p_referrer text,
  p_submitted_at timestamp without time zone,p_request_id text,p_idempotency_digest text
) RETURNS TABLE("accepted" boolean,"publicReference" text,"message" text,"deliveryRequired" boolean)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public
AS $$
DECLARE
  existing record;
  row_id text:=gen_random_uuid()::text;
  reference text:='RA-'||upper(substr(replace(gen_random_uuid()::text,'-',''),1,12));
BEGIN
  IF length(btrim(p_full_name)) NOT BETWEEN 2 AND 120
     OR length(btrim(p_work_email)) NOT BETWEEN 3 AND 160
     OR p_work_email !~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$'
     OR length(btrim(p_company_name)) NOT BETWEEN 2 AND 160
     OR length(btrim(p_role_title)) NOT BETWEEN 2 AND 120
     OR length(btrim(p_country)) NOT BETWEEN 2 AND 120
     OR length(btrim(p_monthly_volume)) NOT BETWEEN 1 AND 80
     OR length(btrim(p_message)) NOT BETWEEN 10 AND 3000 THEN
    RAISE EXCEPTION 'PUBLIC_REQUEST_ACCESS_INVALID' USING ERRCODE='22023';
  END IF;
  PERFORM app_public.public_verify_bind(
    'public-verification-request-access',p_request_id,NULL,NULL,NULL,NULL,p_idempotency_digest
  );
  SELECT k.id,k."responsePayload" INTO existing
  FROM public."ActionIdempotencyKey" k WHERE k."keyHash"=p_idempotency_digest;
  IF existing.id IS NOT NULL THEN
    RETURN QUERY SELECT true,existing."responsePayload"->>'reference',
      'Request received. MSCQR will review your access request.',false;
    RETURN;
  END IF;
  PERFORM set_config('app.public_verification_target_id',row_id,true);
  INSERT INTO public."RequestAccess"(
    id,"referenceCode","fullName","workEmail","companyName","roleTitle",country,
    "monthlyGarmentVolume",message,"sourcePage",referrer,status,"internalNote",
    "assignedToUserId","reviewedByUserId","reviewedAt","adminEmailDeliveryStatus",
    "adminEmailErrorCode","acknowledgementEmailDeliveryStatus","acknowledgementEmailErrorCode",
    "createdAt","updatedAt"
  ) VALUES (
    row_id,reference,btrim(p_full_name),lower(btrim(p_work_email)),btrim(p_company_name),
    btrim(p_role_title),btrim(p_country),btrim(p_monthly_volume),btrim(p_message),
    nullif(btrim(p_source_page),''),nullif(btrim(p_referrer),''),'NEW',NULL,NULL,NULL,NULL,
    'QUEUED',NULL,'QUEUED',NULL,p_submitted_at,p_submitted_at
  );
  INSERT INTO public."ActionIdempotencyKey"(
    id,"keyHash",action,scope,"requestHash","statusCode","responsePayload",
    "createdAt","completedAt","expiresAt"
  ) VALUES (
    gen_random_uuid()::text,p_idempotency_digest,'PUBLIC_REQUEST_ACCESS',row_id,
    p_idempotency_digest,201,jsonb_build_object('reference',reference),
    p_submitted_at,p_submitted_at,p_submitted_at+interval '24 hours'
  );
  RETURN QUERY SELECT true,reference,'Request received. MSCQR will review your access request.',true;
END
$$;

CREATE OR REPLACE FUNCTION app_public.submit_public_support(
  p_public_name text,p_public_email text,p_issue_type text,p_title text,p_description text,
  p_verified_code text,p_product_reference text,p_source_path text,p_page_url text,
  p_submitted_at timestamp without time zone,p_request_id text,p_idempotency_digest text
) RETURNS TABLE("accepted" boolean,"publicReference" text,"message" text,"deliveryRequired" boolean)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public
AS $$
DECLARE
  existing record;
  qr record;
  row_id text:=gen_random_uuid()::text;
  reference text:='SUP-'||upper(substr(replace(gen_random_uuid()::text,'-',''),1,12));
BEGIN
  IF length(btrim(p_public_name)) NOT BETWEEN 2 AND 120
     OR length(btrim(p_public_email)) NOT BETWEEN 3 AND 160
     OR p_public_email !~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$'
     OR p_issue_type NOT IN ('verification_result','scan_problem','product_concern','platform_access','privacy','other')
     OR length(btrim(p_title)) NOT BETWEEN 5 AND 160
     OR length(btrim(p_description)) NOT BETWEEN 10 AND 4000
     OR (p_source_path IS NOT NULL AND (left(p_source_path,1)<>'/' OR position('..' in p_source_path)>0)) THEN
    RAISE EXCEPTION 'PUBLIC_SUPPORT_INVALID' USING ERRCODE='22023';
  END IF;
  PERFORM app_public.public_verify_bind(
    'public-verification-support',p_request_id,NULL,p_verified_code,NULL,NULL,p_idempotency_digest
  );
  IF p_verified_code IS NOT NULL THEN
    SELECT q.id,q.code,q."licenseeId" INTO qr
    FROM public."QRCode" q WHERE q.code=p_verified_code;
    IF qr.id IS NULL THEN RAISE EXCEPTION 'PUBLIC_SUPPORT_TARGET_INVALID' USING ERRCODE='42501'; END IF;
    PERFORM set_config('app.public_verification_qr_id',qr.id,true);
  END IF;
  SELECT k.id,k."responsePayload" INTO existing
  FROM public."ActionIdempotencyKey" k WHERE k."keyHash"=p_idempotency_digest;
  IF existing.id IS NOT NULL THEN
    RETURN QUERY SELECT true,existing."responsePayload"->>'reference',
      'Support request received.',false;
    RETURN;
  END IF;
  PERFORM set_config('app.public_verification_target_id',row_id,true);
  INSERT INTO public."SupportIssueReport"(
    id,"reporterUserId","reporterRole","licenseeId","referenceCode","publicName","publicEmail",
    "issueType","verificationCode","productReference",priority,title,description,status,
    "internalNote","responseMessage","respondedAt","respondedByUserId","emailDeliveryStatus",
    "emailErrorCode","acknowledgementEmailDeliveryStatus","acknowledgementEmailErrorCode",
    "sourcePath","pageUrl","autoDetected","screenshotPath","screenshotMime","screenshotSize",
    diagnostics,"createdAt","updatedAt"
  ) VALUES (
    row_id,NULL,NULL,qr."licenseeId",reference,btrim(p_public_name),lower(btrim(p_public_email)),
    p_issue_type,qr.code,nullif(btrim(p_product_reference),''),
    CASE WHEN p_issue_type IN ('verification_result','product_concern') THEN 'P2' ELSE 'P3' END,
    btrim(p_title),btrim(p_description),
    'OPEN',NULL,NULL,NULL,NULL,'QUEUED',NULL,'QUEUED',NULL,nullif(btrim(p_source_path),''),
    nullif(btrim(p_page_url),''),false,NULL,NULL,NULL,
    jsonb_build_object('verifiedQrBound',qr.id IS NOT NULL,'requestId',p_request_id),
    p_submitted_at,p_submitted_at
  );
  INSERT INTO public."ActionIdempotencyKey"(
    id,"keyHash",action,scope,"requestHash","statusCode","responsePayload",
    "createdAt","completedAt","expiresAt"
  ) VALUES (
    gen_random_uuid()::text,p_idempotency_digest,'PUBLIC_SUPPORT',row_id,
    p_idempotency_digest,201,jsonb_build_object('reference',reference),
    p_submitted_at,p_submitted_at,p_submitted_at+interval '24 hours'
  );
  RETURN QUERY SELECT true,reference,'Support request received.',true;
END
$$;

CREATE OR REPLACE FUNCTION app_public.complete_request_access_delivery(
  p_idempotency_digest text,p_admin_status text,p_admin_error text,
  p_ack_status text,p_ack_error text,p_completed_at timestamp without time zone,p_request_id text
) RETURNS TABLE("updated" boolean)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public
AS $$
DECLARE key_row record;
BEGIN
  IF p_idempotency_digest !~ '^(?:[A-Za-z0-9._-]{1,32}:)?[a-f0-9]{64}$'
     OR p_admin_status NOT IN ('SENT','DRY_RUN','DISABLED','FAILED','SKIPPED')
     OR p_ack_status NOT IN ('SENT','DRY_RUN','DISABLED','FAILED','SKIPPED')
     OR length(coalesce(p_admin_error,''))>80 OR length(coalesce(p_ack_error,''))>80
     OR p_completed_at IS NULL THEN
    RAISE EXCEPTION 'PUBLIC_REQUEST_ACCESS_DELIVERY_INVALID' USING ERRCODE='22023';
  END IF;
  PERFORM app_public.public_verify_bind(
    'public-verification-request-access-delivery',p_request_id,NULL,NULL,NULL,NULL,p_idempotency_digest
  );
  SELECT k.id,k.scope INTO key_row FROM public."ActionIdempotencyKey" k
  WHERE k."keyHash"=p_idempotency_digest AND k.action='PUBLIC_REQUEST_ACCESS';
  IF key_row.id IS NULL THEN
    RAISE EXCEPTION 'PUBLIC_REQUEST_ACCESS_DELIVERY_DENIED' USING ERRCODE='42501';
  END IF;
  PERFORM set_config('app.public_verification_target_id',key_row.scope,true);
  UPDATE public."RequestAccess" SET
    "adminEmailDeliveryStatus"=p_admin_status,
    "adminEmailErrorCode"=nullif(p_admin_error,''),
    "acknowledgementEmailDeliveryStatus"=p_ack_status,
    "acknowledgementEmailErrorCode"=nullif(p_ack_error,''),
    "updatedAt"=p_completed_at
  WHERE id=key_row.scope;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'PUBLIC_REQUEST_ACCESS_DELIVERY_DENIED' USING ERRCODE='42501';
  END IF;
  RETURN QUERY SELECT true;
END
$$;

CREATE OR REPLACE FUNCTION app_public.complete_public_support_delivery(
  p_idempotency_digest text,p_admin_status text,p_admin_error text,
  p_ack_status text,p_ack_error text,p_completed_at timestamp without time zone,p_request_id text
) RETURNS TABLE("updated" boolean)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public
AS $$
DECLARE key_row record;
BEGIN
  IF p_idempotency_digest !~ '^(?:[A-Za-z0-9._-]{1,32}:)?[a-f0-9]{64}$'
     OR p_admin_status NOT IN ('SENT','DRY_RUN','DISABLED','FAILED','SKIPPED')
     OR p_ack_status NOT IN ('SENT','DRY_RUN','DISABLED','FAILED','SKIPPED')
     OR length(coalesce(p_admin_error,''))>80 OR length(coalesce(p_ack_error,''))>80
     OR p_completed_at IS NULL THEN
    RAISE EXCEPTION 'PUBLIC_SUPPORT_DELIVERY_INVALID' USING ERRCODE='22023';
  END IF;
  PERFORM app_public.public_verify_bind(
    'public-verification-support-delivery',p_request_id,NULL,NULL,NULL,NULL,p_idempotency_digest
  );
  SELECT k.id,k.scope INTO key_row FROM public."ActionIdempotencyKey" k
  WHERE k."keyHash"=p_idempotency_digest AND k.action='PUBLIC_SUPPORT';
  IF key_row.id IS NULL THEN
    RAISE EXCEPTION 'PUBLIC_SUPPORT_DELIVERY_DENIED' USING ERRCODE='42501';
  END IF;
  PERFORM set_config('app.public_verification_target_id',key_row.scope,true);
  UPDATE public."SupportIssueReport" SET
    "emailDeliveryStatus"=p_admin_status,
    "emailErrorCode"=nullif(p_admin_error,''),
    "acknowledgementEmailDeliveryStatus"=p_ack_status,
    "acknowledgementEmailErrorCode"=nullif(p_ack_error,''),
    "updatedAt"=p_completed_at
  WHERE id=key_row.scope;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'PUBLIC_SUPPORT_DELIVERY_DENIED' USING ERRCODE='42501';
  END IF;
  RETURN QUERY SELECT true;
END
$$;

CREATE OR REPLACE FUNCTION app_public.track_support_status(
  p_reference_code text,p_proof_digest text,p_proof_version integer,
  p_checked_at timestamp without time zone,p_request_id text
) RETURNS TABLE(
  "referenceCode" text,"customerFacingStatus" text,"priority" text,
  "updatedAt" timestamp without time zone,"handoffStage" text,
  "slaDueAt" timestamp without time zone
)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public
AS $$
DECLARE
  ticket record;
  handoff record;
  expected_digest text;
BEGIN
  IF p_reference_code !~ '^[A-Z0-9][A-Z0-9_-]{3,63}$'
     OR p_proof_digest !~ '^sha256-v1:[a-f0-9]{64}$'
     OR p_proof_version<>1 OR p_checked_at IS NULL THEN
    RAISE EXCEPTION 'PUBLIC_SUPPORT_TRACK_INVALID' USING ERRCODE='22023';
  END IF;
  expected_digest:=substr(p_proof_digest,11);
  PERFORM app_public.public_verify_bind(
    'public-verification-support-track',p_request_id,NULL,p_reference_code,NULL,NULL,p_proof_digest
  );
  SELECT t.id,t."incidentId",t."referenceCode",t.status::text AS status,t.priority::text AS priority,
         t."updatedAt",t."slaDueAt"
    INTO ticket
    FROM public."SupportTicket" t
   WHERE t."referenceCode"=p_reference_code
     AND t."customerEmail" IS NOT NULL
     AND encode(sha256(convert_to(lower(t."customerEmail"),'UTF8')),'hex')=expected_digest;
  IF ticket.id IS NULL THEN RETURN; END IF;
  PERFORM set_config('app.public_verification_target_id',ticket."incidentId",true);
  SELECT h."currentStage"::text AS stage,h."slaDueAt"
    INTO handoff
    FROM public."IncidentHandoff" h
   WHERE h."incidentId"=ticket."incidentId";
  RETURN QUERY SELECT ticket."referenceCode",ticket.status,ticket.priority,ticket."updatedAt",
    handoff.stage,coalesce(handoff."slaDueAt",ticket."slaDueAt");
END
$$;

REVOKE ALL ON FUNCTION app_public.public_verify_bind(text,text,text,text,text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_public.issue_customer_auth_session(text,text,text,text,text,timestamp without time zone,timestamp without time zone,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_public.require_customer_auth_session(text,timestamp without time zone,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_public.revoke_customer_auth_session(text,timestamp without time zone,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_public.public_verify_execute(text,text,timestamp without time zone,text,text,text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_public.verify_raw_qr(text,timestamp without time zone,text,text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_public.verify_signed_qr(text,text,text,text,text,text,integer,text,timestamp without time zone,timestamp without time zone,timestamp without time zone,text,text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_public.record_qr_verification(text,text,text,timestamp without time zone,text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_public.start_verification_session(text,text,text,timestamp without time zone,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_public.read_verification_session(text,text,text,timestamp without time zone,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_public.write_verification_session(text,text,text,text,jsonb,timestamp without time zone,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_public.public_verify_write_evidence(text,text,text,text,jsonb,timestamp without time zone,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_public.claim_customer_ownership(text,text,text,text,text,text,boolean,timestamp without time zone,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_public.create_customer_ownership_transfer(text,text,text,text,timestamp without time zone,timestamp without time zone,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_public.cancel_customer_ownership_transfer(text,text,text,timestamp without time zone,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_public.accept_customer_ownership_transfer(text,text,text,text,timestamp without time zone,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_public.begin_customer_passkey(text,text,text,text,text,text,text,text,text,text,timestamp without time zone,timestamp without time zone,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_public.load_customer_passkey(text[],text,text,timestamp without time zone,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_public.finish_customer_passkey(text,text[],text,jsonb,timestamp without time zone,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_public.list_customer_passkeys(text,timestamp without time zone,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_public.delete_customer_passkey(text,text,timestamp without time zone,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_public.submit_product_feedback(text,integer,text,text,text,text,text,timestamp without time zone,text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_public.submit_public_incident(text,text,text,text,text,boolean,jsonb,timestamp without time zone,text,text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_public.submit_request_access(text,text,text,text,text,text,text,text,text,timestamp without time zone,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_public.submit_public_support(text,text,text,text,text,text,text,text,text,timestamp without time zone,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_public.complete_request_access_delivery(text,text,text,text,text,timestamp without time zone,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_public.complete_public_support_delivery(text,text,text,text,text,timestamp without time zone,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_public.track_support_status(text,text,integer,timestamp without time zone,text) FROM PUBLIC;
