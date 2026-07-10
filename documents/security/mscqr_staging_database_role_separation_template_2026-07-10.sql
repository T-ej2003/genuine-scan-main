-- MSCQR STAGING-ONLY DATABASE ROLE SEPARATION TEMPLATE.
--
-- DO NOT RUN IN PRODUCTION. DO NOT place this file in Prisma migrations.
-- DO NOT run it from CI, application startup, Terraform, or a deployment job.
-- This is a manually reviewed staging change. It contains no credentials.
--
-- PostgreSQL 16+ is required for membership option verification.
-- Required psql variables (identifiers only):
--   mscqr_previous_owner_role  current owner executing this template
--   mscqr_owner_role           new NOLOGIN object owner
--   mscqr_migrator_role        LOGIN migration role; SET ROLE owner is required
--   mscqr_app_role             LOGIN normal runtime role
--   mscqr_rls_read_role        LOGIN SELECT-only RLS route role

\set ON_ERROR_STOP on

\if :{?mscqr_previous_owner_role}
\else
\echo 'Missing -v mscqr_previous_owner_role=<current_staging_owner_role>'
\quit 3
\endif
\if :{?mscqr_owner_role}
\else
\echo 'Missing -v mscqr_owner_role=<new_nologin_owner_role>'
\quit 3
\endif
\if :{?mscqr_migrator_role}
\else
\echo 'Missing -v mscqr_migrator_role=<new_login_migrator_role>'
\quit 3
\endif
\if :{?mscqr_app_role}
\else
\echo 'Missing -v mscqr_app_role=<new_login_app_role>'
\quit 3
\endif
\if :{?mscqr_rls_read_role}
\else
\echo 'Missing -v mscqr_rls_read_role=<new_login_rls_read_role>'
\quit 3
\endif

BEGIN;

SELECT set_config('mscqr.role.previous_owner', :'mscqr_previous_owner_role', true);
SELECT set_config('mscqr.role.owner', :'mscqr_owner_role', true);
SELECT set_config('mscqr.role.migrator', :'mscqr_migrator_role', true);
SELECT set_config('mscqr.role.app', :'mscqr_app_role', true);
SELECT set_config('mscqr.role.rls_read', :'mscqr_rls_read_role', true);

DO $$
DECLARE
  previous_owner text := current_setting('mscqr.role.previous_owner', true);
  owner_role text := current_setting('mscqr.role.owner', true);
  migrator_role text := current_setting('mscqr.role.migrator', true);
  app_role text := current_setting('mscqr.role.app', true);
  rls_read_role text := current_setting('mscqr.role.rls_read', true);
  names text[] := ARRAY[previous_owner, owner_role, migrator_role, app_role, rls_read_role];
  database_name text := current_database();
BEGIN
  IF current_setting('server_version_num')::integer < 160000 THEN
    RAISE EXCEPTION 'PostgreSQL 16+ is required for controlled role membership options';
  END IF;
  IF database_name ~* '(^|[_-])(prod|production|live|primary)([_-]|$)' THEN
    RAISE EXCEPTION 'This staging-only template refuses production-like database name %', database_name;
  END IF;
  IF array_length(names, 1) <> (SELECT count(DISTINCT value) FROM unnest(names) AS value) THEN
    RAISE EXCEPTION 'Role variables must be distinct';
  END IF;
  IF EXISTS (SELECT 1 FROM unnest(names) AS value WHERE value !~ '^[a-z_][a-z0-9_]{0,62}$') THEN
    RAISE EXCEPTION 'Role variables must be lower-case PostgreSQL identifiers without quoting';
  END IF;
  IF current_user <> previous_owner THEN
    RAISE EXCEPTION 'Connected role % must equal mscqr_previous_owner_role %', current_user, previous_owner;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = ANY(ARRAY[owner_role, migrator_role, app_role, rls_read_role])) THEN
    RAISE EXCEPTION 'Refusing to reuse an existing separation role; choose fresh reviewed staging names or use the rollback template';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'public') THEN
    RAISE EXCEPTION 'Expected public schema is missing';
  END IF;

  EXECUTE format('CREATE ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT', owner_role);
  EXECUTE format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT', migrator_role);
  EXECUTE format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT', app_role);
  EXECUTE format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT', rls_read_role);
  EXECUTE format('GRANT %I TO %I WITH ADMIN FALSE, INHERIT FALSE, SET TRUE', owner_role, migrator_role);
  EXECUTE format('GRANT CONNECT ON DATABASE %I TO %I, %I, %I', database_name, migrator_role, app_role, rls_read_role);
END
$$;

-- The current Prisma schema has no serial/identity sequences. Fail closed if
-- that changes: a reviewed grant-inventory update is required before rollout.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relkind = 'S'
  ) THEN
    RAISE EXCEPTION 'Public sequences exist; update the reviewed role grant inventory before applying this template';
  END IF;
END
$$;

-- Move all current application relations and schemas to the NOLOGIN owner.
DO $$
DECLARE
  owner_role text := current_setting('mscqr.role.owner', true);
  relation record;
BEGIN
  EXECUTE format('ALTER SCHEMA public OWNER TO %I', owner_role);
  IF EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'app_rls') THEN
    EXECUTE format('ALTER SCHEMA app_rls OWNER TO %I', owner_role);
  END IF;
  FOR relation IN
    SELECT c.relname, c.relkind
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'S')
  LOOP
    IF relation.relkind = 'S' THEN
      EXECUTE format('ALTER SEQUENCE public.%I OWNER TO %I', relation.relname, owner_role);
    ELSE
      EXECUTE format('ALTER TABLE public.%I OWNER TO %I', relation.relname, owner_role);
    END IF;
  END LOOP;
END
$$;

-- Eliminate implicit PUBLIC access before adding exact role grants.
DO $$
BEGIN
  EXECUTE format('REVOKE ALL ON DATABASE %I FROM PUBLIC', current_database());
END
$$;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;
-- PostgreSQL requires membership to alter another role's default privileges.
-- Grant SET-only membership to the current owner for this transaction, set the
-- defaults as the NOLOGIN owner, and revoke it before final verification.
DO $$
BEGIN
  EXECUTE format(
    'GRANT %I TO %I WITH ADMIN FALSE, INHERIT FALSE, SET TRUE',
    current_setting('mscqr.role.owner', true),
    current_setting('mscqr.role.previous_owner', true)
  );
END
$$;
SET LOCAL ROLE :"mscqr_owner_role";
ALTER DEFAULT PRIVILEGES FOR ROLE :"mscqr_owner_role" IN SCHEMA public REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE :"mscqr_owner_role" IN SCHEMA public REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE :"mscqr_owner_role" IN SCHEMA public REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
RESET ROLE;
REVOKE :"mscqr_owner_role" FROM :"mscqr_previous_owner_role";

GRANT USAGE ON SCHEMA public TO :"mscqr_app_role", :"mscqr_rls_read_role";

-- Normal runtime reads are explicit, covering every current Prisma model.
GRANT SELECT ON TABLE
  "User", "Organization", "Licensee", "ManufacturerLicenseeLink", "QRRange", "Batch", "InventoryStatusRollup", "PrintJob", "QRCode", "PrintRenderToken", "PrintSession", "PrinterAgentSession", "PrintJobChunk", "PrintItem", "PrintItemEvent", "PrintAuditEvent", "PrinterRegistration", "Printer", "PrinterProfile", "PrinterProfileSnapshot", "PrintReissueRequest", "PrinterAttestation", "Ownership", "OwnershipTransfer", "QrScanLog", "BatchPrintPackToken", "AuditLog", "VerificationDecision", "VerificationEvidenceSnapshot", "ReplacementChain", "DegradationEvent", "CustomerTrustCredential", "CustomerWebAuthnCredential", "CustomerWebAuthnChallenge", "CustomerVerificationSession", "CustomerTrustIntake", "AuditLogOutbox", "SystemCheckpoint", "Invite", "PasswordReset", "EmailVerificationToken", "RefreshToken", "AdminMfaCredential", "AdminWebAuthnCredential", "UserMfaFactor", "UserBackupCode", "MfaLoginChallenge", "AuthMfaChallenge", "AuthWebAuthnChallenge", "AuthSessionRiskSignal", "SensitiveActionApproval", "SecurityEventOutbox", "CompliancePackJob", "QrAllocationRequest", "AllocationEvent", "TraceEvent", "ScanMetricsHourlyRollup", "SecurityPolicy", "PolicyRule", "PolicyAlert", "Incident", "IncidentEvent", "IncidentCommunication", "IncidentEvidence", "IncidentHandoff", "SupportTicket", "SupportTicketMessage", "RequestAccess", "SupportIssueReport", "Notification", "TenantFeatureFlag", "EvidenceRetentionPolicy", "EvidenceRetentionJob", "IncidentEvidenceFingerprint", "ForensicEventChain", "ActionIdempotencyKey", "RouteTransitionMetric"
TO :"mscqr_app_role";

-- These DML lists are derived from direct and nested backend Prisma write-path
-- inventory. They intentionally omit TRUNCATE, REFERENCES, TRIGGER, schema
-- creation, role/database administration, sequences, and function execution.
GRANT INSERT ON TABLE
  "ActionIdempotencyKey", "AdminMfaCredential", "AdminWebAuthnCredential", "AllocationEvent", "AuditLog", "AuthMfaChallenge", "AuthSessionRiskSignal", "AuthWebAuthnChallenge", "Batch", "CompliancePackJob", "EmailVerificationToken", "EvidenceRetentionJob", "EvidenceRetentionPolicy", "ForensicEventChain", "Incident", "IncidentCommunication", "IncidentEvent", "IncidentEvidence", "IncidentEvidenceFingerprint", "IncidentHandoff", "InventoryStatusRollup", "Invite", "Licensee", "ManufacturerLicenseeLink", "MfaLoginChallenge", "Notification", "Organization", "Ownership", "OwnershipTransfer", "PasswordReset", "PolicyAlert", "PolicyRule", "PrintAuditEvent", "PrintItem", "PrintItemEvent", "PrintJob", "PrintJobChunk", "PrintReissueRequest", "PrintSession", "Printer", "PrinterAgentSession", "PrinterAttestation", "PrinterProfile", "PrinterProfileSnapshot", "PrinterRegistration", "QRCode", "QRRange", "QrAllocationRequest", "QrScanLog", "RefreshToken", "RequestAccess", "RouteTransitionMetric", "ScanMetricsHourlyRollup", "SecurityEventOutbox", "SecurityPolicy", "SensitiveActionApproval", "SupportIssueReport", "SupportTicket", "SupportTicketMessage", "SystemCheckpoint", "TenantFeatureFlag", "TraceEvent", "User", "UserBackupCode", "UserMfaFactor"
TO :"mscqr_app_role";
GRANT UPDATE ON TABLE
  "ActionIdempotencyKey", "AdminMfaCredential", "AdminWebAuthnCredential", "AuthMfaChallenge", "AuthWebAuthnChallenge", "Batch", "CompliancePackJob", "EmailVerificationToken", "EvidenceRetentionPolicy", "Incident", "IncidentEvidenceFingerprint", "IncidentHandoff", "InventoryStatusRollup", "Invite", "Licensee", "ManufacturerLicenseeLink", "MfaLoginChallenge", "Notification", "Organization", "Ownership", "OwnershipTransfer", "PasswordReset", "PolicyAlert", "PolicyRule", "PrintItem", "PrintJob", "PrintJobChunk", "PrintReissueRequest", "PrintSession", "Printer", "PrinterAgentSession", "PrinterProfile", "PrinterRegistration", "QRCode", "QRRange", "QrAllocationRequest", "RefreshToken", "RequestAccess", "ScanMetricsHourlyRollup", "SecurityEventOutbox", "SecurityPolicy", "SensitiveActionApproval", "SupportIssueReport", "SupportTicket", "SystemCheckpoint", "TenantFeatureFlag", "User", "UserBackupCode", "UserMfaFactor"
TO :"mscqr_app_role";
GRANT DELETE ON TABLE
  "ActionIdempotencyKey", "AdminWebAuthnCredential", "AllocationEvent", "AuditLog", "Batch", "BatchPrintPackToken", "IncidentEvidence", "IncidentEvidenceFingerprint", "Licensee", "ManufacturerLicenseeLink", "PrintJob", "Printer", "PrinterAttestation", "QRCode", "QRRange", "QrAllocationRequest", "QrScanLog", "User", "UserBackupCode", "UserMfaFactor"
TO :"mscqr_app_role";

-- The dedicated RLS read role receives only the staged route graph's 16 tables.
GRANT SELECT ON TABLE
  "Organization", "Licensee", "User", "ManufacturerLicenseeLink", "Batch", "InventoryStatusRollup", "QRCode", "PrintJob", "PrintSession", "PrintItem", "PrinterRegistration", "Printer", "PrinterAttestation", "PrinterAgentSession", "PrinterProfile", "PrinterProfileSnapshot"
TO :"mscqr_rls_read_role";

-- Verify role attributes, ownership, membership, grants, and absence of PUBLIC grants.
DO $$
DECLARE
  owner_role text := current_setting('mscqr.role.owner', true);
  migrator_role text := current_setting('mscqr.role.migrator', true);
  app_role text := current_setting('mscqr.role.app', true);
  rls_read_role text := current_setting('mscqr.role.rls_read', true);
  protected_tables text[] := ARRAY['Organization','Licensee','User','ManufacturerLicenseeLink','Batch','InventoryStatusRollup','QRCode','PrintJob','PrintSession','PrintItem','PrinterRegistration','Printer','PrinterAttestation','PrinterAgentSession','PrinterProfile','PrinterProfileSnapshot'];
  app_tables text[] := ARRAY['User','Organization','Licensee','ManufacturerLicenseeLink','QRRange','Batch','InventoryStatusRollup','PrintJob','QRCode','PrintRenderToken','PrintSession','PrinterAgentSession','PrintJobChunk','PrintItem','PrintItemEvent','PrintAuditEvent','PrinterRegistration','Printer','PrinterProfile','PrinterProfileSnapshot','PrintReissueRequest','PrinterAttestation','Ownership','OwnershipTransfer','QrScanLog','BatchPrintPackToken','AuditLog','VerificationDecision','VerificationEvidenceSnapshot','ReplacementChain','DegradationEvent','CustomerTrustCredential','CustomerWebAuthnCredential','CustomerWebAuthnChallenge','CustomerVerificationSession','CustomerTrustIntake','AuditLogOutbox','SystemCheckpoint','Invite','PasswordReset','EmailVerificationToken','RefreshToken','AdminMfaCredential','AdminWebAuthnCredential','UserMfaFactor','UserBackupCode','MfaLoginChallenge','AuthMfaChallenge','AuthWebAuthnChallenge','AuthSessionRiskSignal','SensitiveActionApproval','SecurityEventOutbox','CompliancePackJob','QrAllocationRequest','AllocationEvent','TraceEvent','ScanMetricsHourlyRollup','SecurityPolicy','PolicyRule','PolicyAlert','Incident','IncidentEvent','IncidentCommunication','IncidentEvidence','IncidentHandoff','SupportTicket','SupportTicketMessage','RequestAccess','SupportIssueReport','Notification','TenantFeatureFlag','EvidenceRetentionPolicy','EvidenceRetentionJob','IncidentEvidenceFingerprint','ForensicEventChain','ActionIdempotencyKey','RouteTransitionMetric'];
  write_tables text[] := ARRAY['ActionIdempotencyKey','AdminMfaCredential','AdminWebAuthnCredential','AllocationEvent','AuditLog','AuthMfaChallenge','AuthSessionRiskSignal','AuthWebAuthnChallenge','Batch','BatchPrintPackToken','CompliancePackJob','EmailVerificationToken','EvidenceRetentionJob','EvidenceRetentionPolicy','ForensicEventChain','Incident','IncidentCommunication','IncidentEvent','IncidentEvidence','IncidentEvidenceFingerprint','IncidentHandoff','InventoryStatusRollup','Invite','Licensee','ManufacturerLicenseeLink','MfaLoginChallenge','Notification','Organization','Ownership','OwnershipTransfer','PasswordReset','PolicyAlert','PolicyRule','PrintAuditEvent','PrintItem','PrintItemEvent','PrintJob','PrintJobChunk','PrintReissueRequest','PrintSession','Printer','PrinterAgentSession','PrinterAttestation','PrinterProfile','PrinterProfileSnapshot','PrinterRegistration','QRCode','QRRange','QrAllocationRequest','QrScanLog','RefreshToken','RequestAccess','RouteTransitionMetric','ScanMetricsHourlyRollup','SecurityEventOutbox','SecurityPolicy','SensitiveActionApproval','SupportIssueReport','SupportTicket','SupportTicketMessage','SystemCheckpoint','TenantFeatureFlag','TraceEvent','User','UserBackupCode','UserMfaFactor'];
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_roles r
    WHERE r.rolname = owner_role AND (r.rolcanlogin OR r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls)
    UNION ALL
    SELECT 1 FROM pg_roles r
    WHERE r.rolname = ANY(ARRAY[migrator_role, app_role, rls_read_role])
      AND (NOT r.rolcanlogin OR r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls)
  ) THEN RAISE EXCEPTION 'Role attribute verification failed'; END IF;
  IF (SELECT count(*) FROM pg_auth_members m JOIN pg_roles granted ON granted.oid = m.roleid JOIN pg_roles member ON member.oid = m.member WHERE granted.rolname = owner_role AND member.rolname = migrator_role AND NOT m.admin_option AND NOT m.inherit_option AND m.set_option) <> 1 THEN
    RAISE EXCEPTION 'Migrator must have exactly one controlled SET ROLE membership in owner';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_auth_members m JOIN pg_roles member ON member.oid = m.member WHERE member.rolname IN (owner_role, app_role, rls_read_role))
     OR EXISTS (SELECT 1 FROM pg_auth_members m JOIN pg_roles member ON member.oid = m.member JOIN pg_roles granted ON granted.oid = m.roleid WHERE member.rolname = migrator_role AND granted.rolname <> owner_role) THEN
    RAISE EXCEPTION 'Owner, app, and RLS read roles must have no memberships; migrator may only SET ROLE owner';
  END IF;
  IF (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace JOIN pg_roles o ON o.oid = c.relowner WHERE n.nspname = 'public' AND c.relkind IN ('r','p','S') AND o.rolname = owner_role) <> (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public' AND c.relkind IN ('r','p','S')) THEN
    RAISE EXCEPTION 'NOLOGIN owner does not own every public table and sequence';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_namespace n JOIN pg_roles o ON o.oid = n.nspowner WHERE n.nspname IN ('public','app_rls') AND o.rolname <> owner_role) THEN
    RAISE EXCEPTION 'NOLOGIN owner does not own every present application schema';
  END IF;
  IF (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public' AND c.relkind IN ('r','p') AND c.relname = ANY(app_tables)) <> array_length(app_tables, 1) THEN
    RAISE EXCEPTION 'Grant inventory does not match the deployed Prisma table set';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public' AND c.relkind IN ('r','p') AND c.relname = ANY(app_tables) AND NOT has_table_privilege(app_role, c.oid, 'SELECT')) THEN
    RAISE EXCEPTION 'App role is missing a required SELECT grant';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public' AND c.relkind IN ('r','p') AND c.relname <> ALL(write_tables) AND (has_table_privilege(app_role, c.oid, 'INSERT') OR has_table_privilege(app_role, c.oid, 'UPDATE') OR has_table_privilege(app_role, c.oid, 'DELETE') OR has_table_privilege(app_role, c.oid, 'TRUNCATE') OR has_table_privilege(app_role, c.oid, 'REFERENCES') OR has_table_privilege(app_role, c.oid, 'TRIGGER'))) THEN
    RAISE EXCEPTION 'App role has an un-inventoried write grant';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public' AND c.relkind IN ('r','p') AND c.relname = ANY(protected_tables) AND (NOT has_table_privilege(rls_read_role, c.oid, 'SELECT') OR has_table_privilege(rls_read_role, c.oid, 'INSERT') OR has_table_privilege(rls_read_role, c.oid, 'UPDATE') OR has_table_privilege(rls_read_role, c.oid, 'DELETE') OR has_table_privilege(rls_read_role, c.oid, 'TRUNCATE') OR has_table_privilege(rls_read_role, c.oid, 'REFERENCES') OR has_table_privilege(rls_read_role, c.oid, 'TRIGGER'))) THEN
    RAISE EXCEPTION 'RLS read role grant verification failed';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public' AND c.relkind = 'S' AND (has_sequence_privilege(rls_read_role, c.oid, 'USAGE') OR has_sequence_privilege(rls_read_role, c.oid, 'SELECT') OR has_sequence_privilege(rls_read_role, c.oid, 'UPDATE'))) THEN
    RAISE EXCEPTION 'RLS read role must not have sequence privileges';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace CROSS JOIN LATERAL aclexplode(COALESCE(c.relacl, acldefault(CASE WHEN c.relkind = 'S' THEN 'S'::"char" ELSE 'r'::"char" END, c.relowner))) acl WHERE n.nspname = 'public' AND acl.grantee = 0)
     OR EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) acl WHERE n.nspname = 'public' AND acl.grantee = 0) THEN
    RAISE EXCEPTION 'PUBLIC grants remain on application relations or functions';
  END IF;
END
$$;

COMMIT;
