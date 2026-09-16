// This function is also serialized as the fixed, protected-source task command.
// It has no CLI/SQL/command overrides and requires one explicit Prisma
// transaction, avoiding pool-dependent BEGIN/query/COMMIT on different sessions.
export async function collectAppOnlyDatabaseCatalogue(client) {
  return client.$transaction(async (tx) => {
    await tx.$executeRawUnsafe("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY");
    const [identity] = await tx.$queryRawUnsafe(`SELECT current_user AS role, session_user AS session_role,
      current_database() AS database, current_setting('transaction_read_only') AS read_only,
      current_setting('default_transaction_read_only') AS default_read_only,
      r.rolsuper, r.rolinherit, r.rolcreaterole, r.rolcreatedb, r.rolreplication, r.rolbypassrls,
      EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members m WHERE m.member=r.oid) AS memberships,
      EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%'
          AND (c.relowner=r.oid OR (c.relkind IN ('r','p','v','m','f') AND
          (pg_catalog.has_table_privilege(r.oid,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER') OR
           pg_catalog.has_any_column_privilege(r.oid,c.oid,'INSERT,UPDATE'))))) AS write_privileges,
      EXISTS(SELECT 1 FROM pg_catalog.pg_namespace n WHERE n.nspname NOT LIKE 'pg_%'
        AND (n.nspowner=r.oid OR pg_catalog.has_schema_privilege(r.oid,n.oid,'CREATE'))) AS schema_write,
      pg_catalog.has_database_privilege(current_user,current_database(),'CREATE,TEMPORARY') AS database_write
      FROM pg_catalog.pg_roles r WHERE r.rolname=current_user`);
    if (!identity || identity.role !== "mscqr_prod_rls_canary_read" || identity.session_role !== identity.role
      || identity.database !== "mscqr_production_rls_green_phase2" || identity.read_only !== "on"
      || identity.default_read_only !== "on"
      || ["rolsuper", "rolinherit", "rolcreaterole", "rolcreatedb", "rolreplication", "rolbypassrls", "memberships", "write_privileges", "schema_write", "database_write"].some((key) => identity[key] !== false)) {
      throw new Error("Verifier database identity is not the restricted read-only contract");
    }
    // Metadata only: never invoke application functions, including SECURITY
    // DEFINER canaries. Qualify all catalogue functions and relations.
    const [routines] = await tx.$queryRawUnsafe(`SELECT COALESCE(jsonb_agg(x ORDER BY x.schema,x.name,x.arguments),'[]'::jsonb) AS rows FROM (
      SELECT n.nspname AS schema,p.proname AS name,pg_catalog.pg_get_function_identity_arguments(p.oid) AS arguments,
        pg_catalog.pg_get_function_result(p.oid) AS result,o.rolname AS owner,p.prosecdef AS security_definer,
        p.provolatile::text AS volatility,p.proparallel::text AS parallel,p.proleakproof AS leakproof,p.proisstrict AS strict,
        p.proconfig AS config,p.prosrc AS body,l.lanname AS language,
        pg_catalog.pg_get_functiondef(p.oid) AS definition,
        COALESCE((SELECT jsonb_agg(jsonb_build_object('role',COALESCE(g.rolname,'PUBLIC'),'privilege',a.privilege_type,'grantable',a.is_grantable)
          ORDER BY COALESCE(g.rolname,'PUBLIC'),a.privilege_type,a.is_grantable)
          FROM pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) a
          LEFT JOIN pg_catalog.pg_roles g ON g.oid=a.grantee),'[]'::jsonb) AS grants
      FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
      JOIN pg_catalog.pg_roles o ON o.oid=p.proowner JOIN pg_catalog.pg_language l ON l.oid=p.prolang
      WHERE n.nspname IN ('app_rls','app_auth','app_public','app_ops')
    ) x`);
    const [tables] = await tx.$queryRawUnsafe(`SELECT COALESCE(jsonb_agg(x ORDER BY x.name),'[]'::jsonb) AS rows FROM (
      SELECT c.relname AS name,c.relkind::text AS kind,c.relrowsecurity AS rls,c.relforcerowsecurity AS forced,
        o.rolname AS owner,COALESCE((SELECT jsonb_agg(jsonb_build_object('name',a.attname,'type',pg_catalog.format_type(a.atttypid,a.atttypmod),'notNull',a.attnotnull,
          'identity',a.attidentity::text,'generated',a.attgenerated::text,'default',pg_catalog.pg_get_expr(d.adbin,d.adrelid),
          'enumLabels',COALESCE((SELECT jsonb_agg(e.enumlabel ORDER BY e.enumsortorder)
            FROM pg_catalog.pg_enum e WHERE e.enumtypid IN
              (a.atttypid,(SELECT t.typelem FROM pg_catalog.pg_type t WHERE t.oid=a.atttypid))),'[]'::jsonb))
          ORDER BY a.attnum) FROM pg_catalog.pg_attribute a
          LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
          WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped),'[]'::jsonb) AS columns,
        COALESCE((SELECT jsonb_agg(jsonb_build_object('name',k.conname,'definition',pg_catalog.pg_get_constraintdef(k.oid),'validated',k.convalidated)
          ORDER BY k.conname) FROM pg_catalog.pg_constraint k WHERE k.conrelid=c.oid),'[]'::jsonb) AS constraints,
        COALESCE((SELECT jsonb_agg(jsonb_build_object('role',COALESCE(g.rolname,'PUBLIC'),'privilege',acl.privilege_type,'grantable',acl.is_grantable)
          ORDER BY COALESCE(g.rolname,'PUBLIC'),acl.privilege_type,acl.is_grantable)
          FROM pg_catalog.aclexplode(COALESCE(c.relacl,pg_catalog.acldefault('r',c.relowner))) acl
          LEFT JOIN pg_catalog.pg_roles g ON g.oid=acl.grantee),'[]'::jsonb) AS grants,
        COALESCE((SELECT jsonb_agg(jsonb_build_object('column',a.attname,'role',COALESCE(g.rolname,'PUBLIC'),'privilege',acl.privilege_type,'grantable',acl.is_grantable)
          ORDER BY a.attname,COALESCE(g.rolname,'PUBLIC'),acl.privilege_type,acl.is_grantable)
          FROM pg_catalog.pg_attribute a CROSS JOIN LATERAL pg_catalog.aclexplode(a.attacl) acl
          LEFT JOIN pg_catalog.pg_roles g ON g.oid=acl.grantee
          WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped),'[]'::jsonb) AS column_grants
      FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
      JOIN pg_catalog.pg_roles o ON o.oid=c.relowner WHERE n.nspname='public' AND c.relkind IN ('r','p')
    ) x`);
    const [policies] = await tx.$queryRawUnsafe(`SELECT COALESCE(jsonb_agg(x ORDER BY x."table",x.name),'[]'::jsonb) AS rows FROM (
      SELECT c.relname AS "table",p.polname AS name,p.polpermissive AS permissive,p.polcmd::text AS command,
        ARRAY(SELECT COALESCE(r.rolname,'PUBLIC') FROM unnest(p.polroles) i LEFT JOIN pg_catalog.pg_roles r ON r.oid=i ORDER BY COALESCE(r.rolname,'PUBLIC')) AS roles,
        pg_catalog.pg_get_expr(p.polqual,p.polrelid) AS "using",pg_catalog.pg_get_expr(p.polwithcheck,p.polrelid) AS "check"
      FROM pg_catalog.pg_policy p JOIN pg_catalog.pg_class c ON c.oid=p.polrelid
      JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public'
    ) x`);
    const [schemas] = await tx.$queryRawUnsafe(`SELECT COALESCE(jsonb_agg(x ORDER BY x.name),'[]'::jsonb) AS rows FROM (
      SELECT n.nspname AS name,o.rolname AS owner,
        COALESCE((SELECT jsonb_agg(jsonb_build_object('role',COALESCE(g.rolname,'PUBLIC'),'privilege',a.privilege_type,'grantable',a.is_grantable)
          ORDER BY COALESCE(g.rolname,'PUBLIC'),a.privilege_type,a.is_grantable)
          FROM pg_catalog.aclexplode(COALESCE(n.nspacl,pg_catalog.acldefault('n',n.nspowner))) a
          LEFT JOIN pg_catalog.pg_roles g ON g.oid=a.grantee),'[]'::jsonb) AS grants
      FROM pg_catalog.pg_namespace n JOIN pg_catalog.pg_roles o ON o.oid=n.nspowner
      WHERE n.nspname IN ('public','app_rls','app_auth','app_public','app_ops')
    ) x`);
    const [roles] = await tx.$queryRawUnsafe(`SELECT COALESCE(jsonb_agg(x ORDER BY x.name),'[]'::jsonb) AS rows FROM (
      SELECT r.rolname AS name,r.rolcanlogin AS login,r.rolsuper AS superuser,r.rolinherit AS inherit,
        r.rolcreaterole AS create_role,r.rolcreatedb AS create_database,r.rolreplication AS replication,r.rolbypassrls AS bypass_rls,
        COALESCE((SELECT jsonb_agg(jsonb_build_object('role',parent.rolname,'admin',m.admin_option,'inherit',m.inherit_option,'set',m.set_option)
          ORDER BY parent.rolname,m.admin_option,m.inherit_option,m.set_option)
          FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles parent ON parent.oid=m.roleid
          WHERE m.member=r.oid),'[]'::jsonb) AS memberships,
        COALESCE((SELECT jsonb_agg(jsonb_build_object('member',child.rolname,'admin',m.admin_option,'inherit',m.inherit_option,'set',m.set_option)
          ORDER BY child.rolname,m.admin_option,m.inherit_option,m.set_option)
          FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles child ON child.oid=m.member
          WHERE m.roleid=r.oid),'[]'::jsonb) AS members
      FROM pg_catalog.pg_roles r WHERE r.rolname LIKE 'mscqr\\_prd\\_rls\\_phase2\\_%' ESCAPE '\\'
        OR r.rolname='mscqr_prod_rls_canary_read'
    ) x`);
    return { identity, routines: routines.rows, tables: tables.rows, policies: policies.rows, schemas: schemas.rows, roles: roles.rows };
  }, { maxWait: 5000, timeout: 30000 });
}

// Local evaluation only. Expectations must be derived from the authenticated
// canonical candidate requirements; this is not an artifact authentication API.
export function evaluateAppOnlyDatabaseCatalogue(observed, required) {
  const equal = (a, b) => JSON.stringify(a) === JSON.stringify(b);
  const result = Object.fromEntries(["DATABASE_SCHEMA", "RLS_FUNCTIONS", "RLS_POLICIES", "RLS_GRANTS", "RLS_FORCE_STATUS", "GENERATED_RLS_CONTRACT"].map((key) => [key, "UNPROVEN"]));
  if (!required || !required.contractSha256 || !Array.isArray(required.routines)
    || !Array.isArray(required.tables) || !Array.isArray(required.policies) || !Array.isArray(required.schemas)
    || !Array.isArray(required.roles) || !required.roles.length
    || !required.routines.length || !required.tables.length || !required.policies.length || !required.schemas.length) return result;
  const unique = (rows, key) => Array.isArray(rows) && new Set(rows.map(key)).size === rows.length;
  if (!unique(observed?.routines, (row) => `${row.schema}.${row.name}(${row.arguments})`)
    || !unique(observed?.tables, (row) => row.name) || !unique(observed?.schemas, (row) => row.name)
    || !unique(observed?.roles, (row) => row.name) || !unique(observed?.policies, (row) => `${row.table}.${row.name}`)) return result;
  const mark = (value) => value ? "COMPATIBLE" : "INCOMPATIBLE";
  const routine = (r) => observed.routines.find((o) => o.schema === r.schema && o.name === r.name && o.arguments === r.arguments);
  const table = (r) => observed.tables.find((o) => o.name === r.name);
  result.RLS_FUNCTIONS = mark(required.routines.every((r) => {
    const o = routine(r);
    return o && ["result", "owner", "security_definer", "volatility", "parallel", "leakproof", "strict", "config", "body", "language", "definition"].every((key) => Object.hasOwn(r,key) && equal(o[key],r[key]));
  }));
  result.RLS_GRANTS = mark(required.routines.every((r) => routine(r) && Array.isArray(r.grants) && equal(routine(r).grants, r.grants))
    && required.tables.every((r) => table(r) && ["grants", "column_grants"].every((key) => Array.isArray(r[key]) && equal(table(r)[key], r[key])))
    && required.schemas.every((r) => Array.isArray(r.grants) && equal(observed.schemas.find((o) => o.name === r.name)?.grants, r.grants))
    && required.roles.every((r) => equal(observed.roles.find((o) => o.name === r.name), r)));
  result.RLS_POLICIES = mark(required.policies.every((r) => {
    const o = observed.policies.find((p) => p.table === r.table && p.name === r.name);
    return o && ["permissive", "command", "roles", "using", "check"].every((key) => Object.hasOwn(r,key) && equal(o[key],r[key]));
  }) && observed.policies.filter((o) => required.tables.some((t) => t.name === o.table)).every((o) => required.policies.some((r) => r.table === o.table && r.name === o.name)));
  result.DATABASE_SCHEMA = mark(required.tables.every((r) => {
    const o = table(r);
    return o && Object.hasOwn(r,"owner") && o.owner === r.owner && o.kind === r.kind
      && ["columns", "constraints"].every((key) => Array.isArray(r[key]) && equal(o[key],r[key]));
  }) && required.schemas.every((r) => typeof r.owner === "string" && observed.schemas.find((o) => o.name === r.name)?.owner === r.owner));
  result.RLS_FORCE_STATUS = mark(required.tables.every((r) => typeof r.rls === "boolean" && typeof r.forced === "boolean"
    && table(r)?.rls === r.rls && table(r)?.forced === r.forced));
  result.GENERATED_RLS_CONTRACT = Object.entries(result).filter(([key]) => key !== "GENERATED_RLS_CONTRACT").every(([, value]) => value === "COMPATIBLE") ? "COMPATIBLE" : "UNPROVEN";
  return result;
}
