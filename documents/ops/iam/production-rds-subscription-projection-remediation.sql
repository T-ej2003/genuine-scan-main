-- Exact, transactional RDS PostgreSQL 18 subscription projection subset.
-- Independent DBA approval is required for this file's SHA-256; do not run the broad Phase 4 script.
\set ON_ERROR_STOP on
BEGIN;
SET LOCAL search_path=pg_catalog;
SET LOCAL lock_timeout='5s';
SET LOCAL statement_timeout='30s';
DO $pre$
BEGIN
  IF current_database()<>'mscqr_production_rls_green_phase2'
     OR current_user<>'mscqr_prod_admin' OR session_user<>'mscqr_prod_admin'
     OR EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='mscqr_prod_admin' AND rolsuper)
     OR current_setting('transaction_read_only')<>'off'
     OR pg_catalog.to_regnamespace('app_rls') IS NULL
     OR (SELECT owner.rolname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_roles owner ON owner.oid=c.relowner
       WHERE c.oid='pg_catalog.pg_subscription'::pg_catalog.regclass)<>'rdsadmin'
     OR NOT pg_catalog.has_schema_privilege(current_user,'app_rls','CREATE')
     OR NOT pg_catalog.has_language_privilege(current_user,'sql','USAGE')
     OR pg_catalog.to_regrole('mscqr_prod_subscription_observer') IS NOT NULL
     OR EXISTS (SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
       WHERE n.nspname='app_rls' AND p.proname='production_security_subscription_inventory' AND p.pronargs<>0)
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
    RAISE EXCEPTION 'RDS subscription projection predecessor mismatch';
  END IF;
  IF pg_catalog.to_regprocedure('app_rls.production_security_subscription_inventory()') IS NOT NULL
     AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_roles owner ON owner.oid=p.proowner
       WHERE p.oid='app_rls.production_security_subscription_inventory()'::pg_catalog.regprocedure
        AND owner.rolname='mscqr_prod_admin' AND p.prokind='f' AND p.pronargs=0
        AND p.prolang=(SELECT oid FROM pg_catalog.pg_language WHERE lanname='sql')
        AND p.prosecdef AND p.provolatile='s' AND p.proparallel='u' AND NOT p.proleakproof AND NOT p.proisstrict
        AND p.proconfig=ARRAY['search_path=pg_catalog']::text[]
         AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p.prosrc,'UTF8')),'hex')=
           'ba305e220456f461a9099f8fc1c05e01ca3d96240d4c41536739a0af59830447') THEN
    RAISE EXCEPTION 'Existing subscription projection conflicts with reviewed successor';
  END IF;
END $pre$;
SELECT CASE WHEN pg_catalog.to_regprocedure('app_rls.production_security_subscription_inventory()') IS NULL
  THEN 'true' ELSE 'false' END AS install_projection \gset
\if :install_projection
CREATE FUNCTION app_rls.production_security_subscription_inventory()
RETURNS TABLE(subscription_name text,subscription_owner text,enabled boolean,binary boolean,streaming text,two_phase text,
  disable_on_error boolean,password_required boolean,run_as_owner boolean,failover boolean,slot_name text,
  synchronous_commit text,publications text[],origin text,skip_lsn text,relations jsonb,connection_info_sha256 text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $subscription_inventory$
  SELECT s.subname::text,o.rolname::text,s.subenabled,s.subbinary,s.substream::text,s.subtwophasestate::text,
    s.subdisableonerr,s.subpasswordrequired,s.subrunasowner,s.subfailover,s.subslotname::text,s.subsynccommit,
    ARRAY(SELECT publication FROM pg_catalog.unnest(s.subpublications) publication ORDER BY publication),s.suborigin,s.subskiplsn::text,
    COALESCE((SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('schema',n.nspname,'relation',c.relname,
      'state',sr.srsubstate::text,'state_lsn',CASE WHEN sr.srsubstate IN ('s','r') THEN sr.srsublsn::text END)
      ORDER BY n.nspname,c.relname) FROM pg_catalog.pg_subscription_rel sr
      JOIN pg_catalog.pg_class c ON c.oid=sr.srrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
      WHERE sr.srsubid=s.oid),'[]'::jsonb),
    pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
      pg_catalog.jsonb_build_array('mscqr-security-subscription-connection-v1',s.subname,s.subconninfo)::text,'UTF8')),'hex')
  FROM pg_catalog.pg_subscription s JOIN pg_catalog.pg_roles o ON o.oid=s.subowner
$subscription_inventory$;
REVOKE ALL ON FUNCTION app_rls.production_security_subscription_inventory() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_rls.production_security_subscription_inventory() TO mscqr_prod_rls_canary_read;
\endif
DO $post$
DECLARE p_oid oid;
BEGIN
  SELECT p.oid INTO p_oid FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='app_rls' AND p.proname='production_security_subscription_inventory' AND p.pronargs=0;
  IF p_oid IS NULL OR NOT EXISTS (
      SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_roles owner ON owner.oid=p.proowner WHERE p.oid=p_oid
        AND owner.rolname='mscqr_prod_admin' AND p.prokind='f' AND p.prosecdef AND p.provolatile='s'
        AND p.prolang=(SELECT oid FROM pg_catalog.pg_language WHERE lanname='sql')
        AND p.proparallel='u' AND NOT p.proleakproof AND NOT p.proisstrict
        AND p.proconfig=ARRAY['search_path=pg_catalog']::text[]
        AND pg_catalog.pg_get_function_identity_arguments(p.oid)=''
        AND pg_catalog.pg_get_function_result(p.oid)=
          'TABLE(subscription_name text, subscription_owner text, enabled boolean, "binary" boolean, streaming text, two_phase text, disable_on_error boolean, password_required boolean, run_as_owner boolean, failover boolean, slot_name text, synchronous_commit text, publications text[], origin text, skip_lsn text, relations jsonb, connection_info_sha256 text)'
        AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p.prosrc,'UTF8')),'hex')=
          'ba305e220456f461a9099f8fc1c05e01ca3d96240d4c41536739a0af59830447')
     OR (SELECT count(*) FROM pg_catalog.pg_proc p CROSS JOIN LATERAL pg_catalog.aclexplode(p.proacl) acl
         WHERE p.oid=p_oid AND acl.privilege_type='EXECUTE' AND NOT acl.is_grantable
           AND acl.grantor=p.proowner AND acl.grantee IN (p.proowner,'mscqr_prod_rls_canary_read'::pg_catalog.regrole))<>2
     OR (SELECT count(*) FROM pg_catalog.pg_proc p CROSS JOIN LATERAL pg_catalog.aclexplode(p.proacl) acl
         WHERE p.oid=p_oid)<>2
     OR NOT pg_catalog.has_function_privilege('mscqr_prod_rls_canary_read',p_oid,'EXECUTE')
     OR pg_catalog.has_column_privilege('mscqr_prod_rls_canary_read','pg_catalog.pg_subscription','subconninfo','SELECT')
     OR (SELECT owner.rolname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_roles owner ON owner.oid=c.relowner
         WHERE c.oid='pg_catalog.pg_subscription'::pg_catalog.regclass)<>'rdsadmin'
     OR pg_catalog.to_regrole('mscqr_prod_subscription_observer') IS NOT NULL THEN
    RAISE EXCEPTION 'RDS subscription projection postcondition failed';
  END IF;
END $post$;
COMMIT;
