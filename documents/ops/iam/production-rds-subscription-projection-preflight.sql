-- Approved read-only preflight for the RDS-owned subscription projection.
-- Run with psql -X -v ON_ERROR_STOP=1 -f; never select or print subconninfo.
\set ON_ERROR_STOP on
BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY;
SET LOCAL search_path=pg_catalog;
SET LOCAL statement_timeout='30s';
DO $pre$
BEGIN
  IF current_database()<>'mscqr_production_rls_green_phase2'
     OR current_user<>'mscqr_prod_admin' OR session_user<>'mscqr_prod_admin'
     OR EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='mscqr_prod_admin' AND rolsuper)
     OR current_setting('transaction_read_only')<>'on'
     OR pg_catalog.to_regnamespace('app_rls') IS NULL
     OR (SELECT owner.rolname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_roles owner ON owner.oid=c.relowner
       WHERE c.oid='pg_catalog.pg_subscription'::pg_catalog.regclass)<>'rdsadmin'
     OR NOT pg_catalog.has_schema_privilege(current_user,'app_rls','CREATE')
     OR NOT pg_catalog.has_language_privilege(current_user,'sql','USAGE')
     OR pg_catalog.to_regrole('mscqr_prod_subscription_observer') IS NOT NULL
     OR pg_catalog.to_regprocedure('app_rls.production_security_subscription_inventory()') IS NOT NULL
     OR EXISTS (SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
       WHERE n.nspname='app_rls' AND p.proname='production_security_subscription_inventory')
     OR pg_catalog.to_regrole('mscqr_prod_rls_canary_read') IS NULL
     OR NOT pg_catalog.has_schema_privilege('mscqr_prod_rls_canary_read','app_rls','USAGE')
     OR pg_catalog.has_schema_privilege('mscqr_prod_rls_canary_read','app_rls','CREATE')
     OR EXISTS (SELECT 1 FROM pg_catalog.pg_roles r WHERE r.rolname='mscqr_prod_rls_canary_read'
       AND (r.rolsuper OR r.rolinherit OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication OR r.rolbypassrls))
     OR EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m WHERE m.member='mscqr_prod_rls_canary_read'::pg_catalog.regrole)
     OR pg_catalog.has_column_privilege('mscqr_prod_rls_canary_read','pg_catalog.pg_subscription','subconninfo','SELECT')
     OR NOT pg_catalog.has_table_privilege(current_user,'pg_catalog.pg_roles','SELECT')
     OR pg_catalog.has_column_privilege(current_user,'pg_catalog.pg_subscription','subconninfo','SELECT WITH GRANT OPTION')
     OR EXISTS (SELECT 1 FROM pg_catalog.pg_attribute a
       WHERE a.attrelid='pg_catalog.pg_subscription'::pg_catalog.regclass AND a.attnum>0 AND NOT a.attisdropped
         AND NOT pg_catalog.has_column_privilege(current_user,a.attrelid,a.attnum,'SELECT'))
     OR EXISTS (SELECT 1 FROM pg_catalog.pg_attribute a
       WHERE a.attrelid='pg_catalog.pg_subscription_rel'::pg_catalog.regclass AND a.attnum>0 AND NOT a.attisdropped
         AND NOT pg_catalog.has_column_privilege(current_user,a.attrelid,a.attnum,'SELECT'))
     OR EXISTS (SELECT 1 FROM pg_catalog.pg_attribute a
       WHERE a.attrelid IN ('pg_catalog.pg_class'::pg_catalog.regclass,'pg_catalog.pg_namespace'::pg_catalog.regclass)
         AND a.attnum>0 AND NOT a.attisdropped
         AND NOT pg_catalog.has_column_privilege(current_user,a.attrelid,a.attnum,'SELECT'))
     OR EXISTS (SELECT 1 FROM pg_catalog.pg_attribute a CROSS JOIN LATERAL pg_catalog.aclexplode(a.attacl) acl
       WHERE a.attrelid='pg_catalog.pg_subscription'::pg_catalog.regclass AND a.attname='subconninfo') THEN
    RAISE EXCEPTION 'RDS subscription projection preflight failed';
  END IF;
END $pre$;
SELECT 'RDS_SUBSCRIPTION_PREFLIGHT_PASS' AS result;
COMMIT;
