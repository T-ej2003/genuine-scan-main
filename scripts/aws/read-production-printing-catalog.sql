\set ON_ERROR_STOP on
BEGIN READ ONLY;
SELECT jsonb_build_object(
  'serverVersion', current_setting('server_version_num')::integer,
  'database', current_database(),
  'identity', session_user,
  'readOnly', current_setting('transaction_read_only') = 'on',
  'functions', (SELECT coalesce(jsonb_agg(jsonb_build_object(
    'signature', n.nspname || '.' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')',
    'definition', pg_get_functiondef(p.oid),
    'owner', pg_get_userbyid(p.proowner),
    'acl', coalesce(p.proacl::text, 'DEFAULT'),
    'publicExecute', EXISTS (SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
      WHERE a.grantee=0 AND a.privilege_type='EXECUTE'),
    'effectiveExecute', (SELECT coalesce(jsonb_object_agg(r.rolname,has_function_privilege(r.oid,p.oid,'EXECUTE') ORDER BY r.rolname),'{}'::jsonb)
      FROM pg_roles r WHERE r.rolname IN ('mscqr_prd_rls_phase2_app','mscqr_prd_rls_phase2_worker','mscqr_prd_rls_phase2_auth_owner'))
  ) ORDER BY p.proname, pg_get_function_identity_arguments(p.oid)), '[]'::jsonb)
  FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
  WHERE n.nspname IN ('app_rls','app_auth','app_ops','app_public')),
  'policies', (SELECT coalesce(jsonb_agg(jsonb_build_object(
    'table', c.relname, 'name', p.polname, 'command', p.polcmd,
    'roles', (SELECT jsonb_agg(r.rolname ORDER BY r.rolname) FROM pg_roles r WHERE r.oid=ANY(p.polroles)),
    'using', pg_get_expr(p.polqual,p.polrelid), 'check', pg_get_expr(p.polwithcheck,p.polrelid)
  ) ORDER BY c.relname,p.polname), '[]'::jsonb)
  FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid JOIN pg_namespace n ON n.oid=c.relnamespace
  WHERE n.nspname='public'),
  'tables', (SELECT coalesce(jsonb_agg(jsonb_build_object(
    'name',c.relname, 'owner',pg_get_userbyid(c.relowner),
    'rls',c.relrowsecurity, 'forceRls',c.relforcerowsecurity,
    'acl',coalesce(c.relacl::text,'DEFAULT'),
    'effectiveGrants', (SELECT coalesce(jsonb_object_agg(r.rolname,jsonb_build_object(
      'select',has_table_privilege(r.oid,c.oid,'SELECT'),
      'insert',has_table_privilege(r.oid,c.oid,'INSERT'),
      'update',has_table_privilege(r.oid,c.oid,'UPDATE'),
      'delete',has_table_privilege(r.oid,c.oid,'DELETE')) ORDER BY r.rolname),'{}'::jsonb)
      FROM pg_roles r WHERE r.rolname IN ('mscqr_prd_rls_phase2_app','mscqr_prd_rls_phase2_worker','mscqr_prd_rls_phase2_auth_owner')),
    'columnGrants', (SELECT coalesce(jsonb_agg(jsonb_build_object('column',a.attname,'role',r.rolname,
      'select',has_column_privilege(r.oid,c.oid,a.attnum,'SELECT'),
      'insert',has_column_privilege(r.oid,c.oid,a.attnum,'INSERT'),
      'update',has_column_privilege(r.oid,c.oid,a.attnum,'UPDATE')) ORDER BY a.attname,r.rolname),'[]'::jsonb)
      FROM pg_attribute a CROSS JOIN pg_roles r
      WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped
        AND c.relname='SystemCheckpoint'
        AND r.rolname IN ('mscqr_prd_rls_phase2_app','mscqr_prd_rls_phase2_worker','mscqr_prd_rls_phase2_auth_owner'))
  ) ORDER BY c.relname),'[]'::jsonb)
  FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
  WHERE n.nspname='public' AND c.relkind IN ('r','p')),
  'roles', (SELECT coalesce(jsonb_agg(jsonb_build_object('name',r.rolname,
    'login',r.rolcanlogin,'inherit',r.rolinherit,'super',r.rolsuper,
    'createDb',r.rolcreatedb,'createRole',r.rolcreaterole,'bypassRls',r.rolbypassrls)
    ORDER BY r.rolname),'[]'::jsonb) FROM pg_roles r
    WHERE r.rolname LIKE 'mscqr_prd_rls_phase2_%'),
  'schemas', (SELECT coalesce(jsonb_agg(jsonb_build_object('name',n.nspname,
    'owner',pg_get_userbyid(n.nspowner),'acl',coalesce(n.nspacl::text,'DEFAULT'))
    ORDER BY n.nspname),'[]'::jsonb) FROM pg_namespace n
    WHERE n.nspname IN ('app_rls','app_auth','app_ops','app_public')),
  'migrationLedger', (SELECT jsonb_build_object('exists',count(*)=1,
    'readable',coalesce(bool_or(has_table_privilege(c.oid,'SELECT')),false))
    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='public' AND c.relname='_prisma_migrations'),
  'installLedger', (SELECT jsonb_build_object('exists',count(*)=1,
    'readable',coalesce(bool_or(has_table_privilege(c.oid,'SELECT')),false))
    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='mscqr_rls_install' AND c.relname='state')
) AS evidence;
COMMIT;
