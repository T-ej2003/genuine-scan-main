-- MSCQR STAGING-ONLY SHARED BATCH RLS PHASE VERIFICATION.
-- Read-only proof executed by the brokered ECS admin helper after apply.

\set ON_ERROR_STOP on

\if :{?mscqr_app_role}
\else
\echo 'Missing required psql variable: mscqr_app_role'
\set mscqr_app_role __mscqr_missing__
\endif
\if :{?mscqr_rls_read_role}
\else
\echo 'Missing required psql variable: mscqr_rls_read_role'
\set mscqr_rls_read_role __mscqr_missing__
\endif
\if :{?mscqr_auth_owner_role}
\else
\echo 'Missing required psql variable: mscqr_auth_owner_role'
\set mscqr_auth_owner_role __mscqr_missing__
\endif

BEGIN READ ONLY;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '3min';
SELECT set_config('app_rls.shared_phase_app_role', :'mscqr_app_role', true);
SELECT set_config('app_rls.shared_phase_read_role', :'mscqr_rls_read_role', true);
SELECT set_config('app_rls.shared_phase_auth_owner_role', :'mscqr_auth_owner_role', true);
SELECT set_config('app.user_id', '', true);
SELECT set_config('app.role', '', true);
SELECT set_config('app.licensee_id', '', true);
SELECT set_config('app.manufacturer_id', '', true);
SELECT set_config('app.organization_id', '', true);
SELECT set_config('app.is_platform_admin', 'false', true);

DO $$
DECLARE
  app_role_name text := current_setting('app_rls.shared_phase_app_role');
  read_role_name text := current_setting('app_rls.shared_phase_read_role');
  auth_owner_role_name text := current_setting('app_rls.shared_phase_auth_owner_role');
  admin_role pg_roles%ROWTYPE;
  lookup_oid oid := (SELECT p.oid FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'app_auth' AND p.proname = 'lookup_password_user' AND oidvectortypes(p.proargtypes) = 'text');
  failure_oid oid := (SELECT p.oid FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'app_auth' AND p.proname = 'record_password_failure'
      AND oidvectortypes(p.proargtypes) = 'text, timestamp without time zone, integer, integer');
  empty_count bigint;
  auth_owner_oid oid := (SELECT oid FROM pg_roles WHERE rolname = current_setting('app_rls.shared_phase_auth_owner_role'));
  target text;
BEGIN
  IF current_database() <> 'mscqr_staging'
     OR current_user <> 'mscqr_staging_admin'
     OR current_role <> 'mscqr_staging_admin' THEN
    RAISE EXCEPTION 'Verification requires mscqr_staging and mscqr_staging_admin';
  END IF;
  IF ARRAY[app_role_name, read_role_name, auth_owner_role_name] <>
     ARRAY['mscqr_staging_app','mscqr_staging_rls_read','mscqr_staging_auth_owner']
     OR '__mscqr_missing__' = ANY(ARRAY[app_role_name, read_role_name, auth_owner_role_name]) THEN
    RAISE EXCEPTION 'Verification received missing or unreviewed role names';
  END IF;
  SELECT * INTO admin_role FROM pg_roles WHERE rolname = current_user;
  IF admin_role.rolsuper OR admin_role.rolbypassrls THEN
    RAISE EXCEPTION 'Verification executor must not bypass RLS';
  END IF;

  IF EXISTS (
    SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relname = ANY(ARRAY[
      'Organization','Licensee','User','ManufacturerLicenseeLink',
      'Batch','InventoryStatusRollup','QRCode','PrintJob','PrintSession','PrintItem'
    ]) AND (NOT c.relrowsecurity OR NOT c.relforcerowsecurity)
  ) OR (
    SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relname = ANY(ARRAY[
      'Organization','Licensee','User','ManufacturerLicenseeLink',
      'Batch','InventoryStatusRollup','QRCode','PrintJob','PrintSession','PrintItem'
    ])
  ) <> 10 THEN
    RAISE EXCEPTION 'Verification failed: exact 10-table ENABLE/FORCE posture is absent';
  END IF;

  IF (
    SELECT count(*) FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND p.polcmd = 'r' AND p.polname IN (
      'rls_candidate_organization_select','rls_candidate_licensee_select','rls_candidate_user_select',
      'rls_candidate_manufacturer_licensee_link_select','rls_candidate_batch_select',
      'rls_candidate_inventory_status_rollup_select','rls_candidate_qrcode_select',
      'rls_candidate_print_job_select','rls_candidate_print_session_select','rls_candidate_print_item_select'
    )
      AND c.relname = ANY(ARRAY[
        'Organization','Licensee','User','ManufacturerLicenseeLink',
        'Batch','InventoryStatusRollup','QRCode','PrintJob','PrintSession','PrintItem'
      ])
  ) <> 10 OR (
    SELECT count(*) FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relname = ANY(ARRAY['Organization','Licensee','User','ManufacturerLicenseeLink'])
  ) <> 7 THEN
    RAISE EXCEPTION 'Verification failed: candidate policy counts are not exact';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND (
      (c.relname = ANY(ARRAY['Batch','InventoryStatusRollup','QRCode','PrintJob','PrintSession','PrintItem']) AND
        (p.polcmd <> 'r' OR cardinality(p.polroles) <> 1 OR
          (SELECT array_agg(r.rolname::text ORDER BY r.rolname) FROM pg_roles r WHERE r.oid = ANY(p.polroles)) <> ARRAY[read_role_name]))
      OR (c.relname IN ('Organization','Licensee','ManufacturerLicenseeLink') AND
        (p.polcmd <> 'r' OR
          (SELECT array_agg(r.rolname::text ORDER BY r.rolname) FROM pg_roles r WHERE r.oid = ANY(p.polroles)) <> ARRAY[app_role_name,read_role_name]))
      OR (c.relname = 'User' AND p.polname = 'rls_candidate_user_select' AND
        (p.polcmd <> 'r' OR
          (SELECT array_agg(r.rolname::text ORDER BY r.rolname) FROM pg_roles r WHERE r.oid = ANY(p.polroles)) <> ARRAY[app_role_name,read_role_name]))
      OR (c.relname = 'User' AND p.polname = 'rls_candidate_user_auth_update' AND
        (p.polcmd <> 'w' OR p.polwithcheck IS NULL OR
          (SELECT array_agg(r.rolname::text ORDER BY r.rolname) FROM pg_roles r WHERE r.oid = ANY(p.polroles)) <> ARRAY[app_role_name]))
      OR (c.relname = 'User' AND p.polname = 'rls_candidate_user_auth_owner_read' AND
        (p.polcmd <> 'r' OR
          (SELECT array_agg(r.rolname::text ORDER BY r.rolname) FROM pg_roles r WHERE r.oid = ANY(p.polroles)) <> ARRAY[auth_owner_role_name]))
      OR (c.relname = 'User' AND p.polname = 'rls_candidate_user_auth_owner_update' AND
        (p.polcmd <> 'w' OR p.polwithcheck IS NULL OR
          (SELECT array_agg(r.rolname::text ORDER BY r.rolname) FROM pg_roles r WHERE r.oid = ANY(p.polroles)) <> ARRAY[auth_owner_role_name]))
    )
  ) THEN
    RAISE EXCEPTION 'Verification failed: policy commands or roles are not exact';
  END IF;

  IF (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname = 'app_auth' AND (
        (p.proname = 'lookup_password_user' AND oidvectortypes(p.proargtypes) = 'text')
        OR (p.proname = 'record_password_failure' AND oidvectortypes(p.proargtypes) = 'text, timestamp without time zone, integer, integer')
      )) <> 2 OR EXISTS (
       SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace JOIN pg_roles owner ON owner.oid = p.proowner
       WHERE n.nspname = 'app_auth' AND (
         owner.rolname <> auth_owner_role_name OR NOT p.prosecdef OR p.proconfig <> ARRAY['search_path=pg_catalog']::text[]
         OR (p.proname = 'lookup_password_user' AND (p.provolatile <> 's' OR p.proparallel <> 's'))
         OR (p.proname = 'record_password_failure' AND (p.provolatile <> 'v' OR p.proparallel <> 'u'))
       )
     ) THEN
    RAISE EXCEPTION 'Verification failed: auth function ownership/security is unsafe';
  END IF;
  IF has_function_privilege('public', lookup_oid, 'EXECUTE')
     OR has_function_privilege('public', failure_oid, 'EXECUTE')
     OR NOT has_function_privilege(app_role_name, lookup_oid, 'EXECUTE')
     OR NOT has_function_privilege(app_role_name, failure_oid, 'EXECUTE')
     OR has_function_privilege(read_role_name, lookup_oid, 'EXECUTE')
     OR has_function_privilege(read_role_name, failure_oid, 'EXECUTE')
     OR pg_has_role((SELECT oid FROM pg_roles WHERE rolname = app_role_name),
                    (SELECT oid FROM pg_roles WHERE rolname = auth_owner_role_name), 'SET') THEN
    RAISE EXCEPTION 'Verification failed: auth boundary grants or role reachability are unsafe';
  END IF;
  IF (SELECT count(*) FROM (
      SELECT n.oid FROM pg_namespace n WHERE n.nspowner = auth_owner_oid
      UNION ALL SELECT p.oid FROM pg_proc p WHERE p.proowner = auth_owner_oid
      UNION ALL SELECT c.oid FROM pg_class c WHERE c.relowner = auth_owner_oid
    ) owned) <> 3
    OR NOT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'app_auth' AND nspowner = auth_owner_oid)
    OR EXISTS (
      SELECT 1
      FROM pg_proc p
      JOIN pg_namespace n ON n.oid = p.pronamespace
      CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) acl
      WHERE n.nspname = 'app_auth'
        AND (acl.privilege_type <> 'EXECUTE'
          OR acl.grantee NOT IN (p.proowner, (SELECT oid FROM pg_roles WHERE rolname = app_role_name))
          OR (acl.grantee <> p.proowner AND acl.is_grantable))
    ) OR EXISTS (
      SELECT 1
      FROM pg_namespace n
      CROSS JOIN LATERAL aclexplode(COALESCE(n.nspacl, acldefault('n', n.nspowner))) acl
      WHERE n.nspname = 'app_auth'
        AND (acl.privilege_type <> 'USAGE'
          OR acl.grantee NOT IN (n.nspowner, (SELECT oid FROM pg_roles WHERE rolname = app_role_name))
          OR (acl.grantee <> n.nspowner AND acl.is_grantable))
    ) OR EXISTS (
      (SELECT column_name, privilege_type, is_grantable
       FROM information_schema.column_privileges
       WHERE table_schema = 'public' AND table_name = 'User' AND grantee = auth_owner_role_name
       EXCEPT
       SELECT column_name, privilege_type, 'NO'
       FROM (VALUES
         ('id','SELECT'),('email','SELECT'),('passwordHash','SELECT'),('name','SELECT'),
         ('role','SELECT'),('licenseeId','SELECT'),('orgId','SELECT'),('status','SELECT'),
         ('isActive','SELECT'),('disabledAt','SELECT'),('deletedAt','SELECT'),
         ('failedLoginAttempts','SELECT'),('lockedUntil','SELECT'),('lastLoginAt','SELECT'),
         ('emailVerifiedAt','SELECT'),('failedLoginAttempts','UPDATE'),
         ('lockedUntil','UPDATE'),('updatedAt','UPDATE')
       ) expected(column_name, privilege_type))
      UNION ALL
      (SELECT column_name, privilege_type, 'NO'
       FROM (VALUES
         ('id','SELECT'),('email','SELECT'),('passwordHash','SELECT'),('name','SELECT'),
         ('role','SELECT'),('licenseeId','SELECT'),('orgId','SELECT'),('status','SELECT'),
         ('isActive','SELECT'),('disabledAt','SELECT'),('deletedAt','SELECT'),
         ('failedLoginAttempts','SELECT'),('lockedUntil','SELECT'),('lastLoginAt','SELECT'),
         ('emailVerifiedAt','SELECT'),('failedLoginAttempts','UPDATE'),
         ('lockedUntil','UPDATE'),('updatedAt','UPDATE')
       ) expected(column_name, privilege_type)
       EXCEPT
       SELECT column_name, privilege_type, is_grantable
       FROM information_schema.column_privileges
       WHERE table_schema = 'public' AND table_name = 'User' AND grantee = auth_owner_role_name)
    ) OR EXISTS (
      SELECT 1 FROM information_schema.table_privileges
      WHERE table_schema = 'public' AND table_name = 'User' AND grantee = auth_owner_role_name
    ) THEN
    RAISE EXCEPTION 'Verification failed: auth owner object or grant boundary is not exact';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM unnest(ARRAY[
      'Organization','Licensee','User','ManufacturerLicenseeLink',
      'Batch','InventoryStatusRollup','QRCode','PrintJob','PrintSession','PrintItem'
    ]) table_name
    WHERE NOT has_table_privilege(read_role_name, format('public.%I', table_name), 'SELECT')
       OR has_table_privilege(read_role_name, format('public.%I', table_name), 'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
  ) THEN
    RAISE EXCEPTION 'Verification failed: read role is not SELECT-only across the 10-table graph';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM unnest(ARRAY['Organization','Licensee','User','ManufacturerLicenseeLink']) table_name
    CROSS JOIN unnest(ARRAY['SELECT','INSERT','UPDATE','DELETE']) privilege_name
    WHERE NOT has_table_privilege(app_role_name, format('public.%I', table_name), privilege_name)
  ) THEN
    RAISE EXCEPTION 'Verification failed: app role lost expected shared-table CRUD grants';
  END IF;

  IF EXISTS (
    SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relname = ANY(ARRAY[
      'PrinterRegistration','Printer','PrinterAttestation','PrinterAgentSession','PrinterProfile','PrinterProfileSnapshot'
    ]) AND (c.relrowsecurity OR c.relforcerowsecurity)
  ) OR EXISTS (
    SELECT 1 FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relname = ANY(ARRAY[
      'PrinterRegistration','Printer','PrinterAttestation','PrinterAgentSession','PrinterProfile','PrinterProfileSnapshot'
    ]) AND p.polname LIKE 'rls_candidate_%'
  ) THEN
    RAISE EXCEPTION 'Verification failed: printer-domain RLS or candidate policies exist';
  END IF;

  -- The admin executor is neither a table owner nor a policy target and cannot
  -- bypass RLS. With every request context value empty, all shared queries must
  -- therefore return zero rows even when the tables contain tenant data.
  FOREACH target IN ARRAY ARRAY['Organization','Licensee','User','ManufacturerLicenseeLink'] LOOP
    EXECUTE format('SELECT count(*) FROM public.%I', target) INTO empty_count;
    IF empty_count <> 0 THEN
      RAISE EXCEPTION 'Verification failed: empty-context query exposed rows from %', target;
    END IF;
  END LOOP;
END
$$;

COMMIT;

SELECT json_build_object(
  'status', 'staging_shared_batch_rls_verified',
  'database', current_database(),
  'protectedTables', 10,
  'candidateSelectPolicies', 10,
  'sharedPolicies', 7,
  'authFunctions', 2,
  'emptyContextSharedQueries', 'fail_closed',
  'rlsReadWrites', 'denied',
  'appSharedCrud', 'preserved',
  'printerProtectedTables', 0
);
