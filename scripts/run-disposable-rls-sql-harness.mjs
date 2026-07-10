import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  contextMatrix,
  contextSql,
  fixtureIds,
  fixtureSql,
  tableProofs,
  truncateFixtureSql,
  visibilitySql,
} from "./lib/disposable-rls-runtime-proof.mjs";

export const CONFIRM_ENV = "MSCQR_DISPOSABLE_RLS_HARNESS_CONFIRM";
export const CONFIRM_VALUE = "MSCQR_RUN_DISPOSABLE_RLS_HARNESS";
export const DATABASE_URL_ENV = "MSCQR_DISPOSABLE_RLS_DATABASE_URL";
export const RUNTIME_ROLE_ENV = "MSCQR_DISPOSABLE_RLS_RUNTIME_ROLE";
export const PSQL_RUNTIME_ROLE_VARIABLE = "mscqr_runtime_role";

export const defaultCandidateSqlPath = "documents/security/mscqr_staging_rls_candidate_templates_2026-07-09.sql";
export const defaultRollbackSqlPath = "documents/security/mscqr_staging_rls_candidate_rollback_2026-07-09.sql";

export const expectedTables = [
  "Organization",
  "Licensee",
  "User",
  "ManufacturerLicenseeLink",
  "Batch",
  "InventoryStatusRollup",
  "QRCode",
  "PrintJob",
  "PrintSession",
  "PrintItem",
  "PrinterRegistration",
  "Printer",
  "PrinterAttestation",
  "PrinterAgentSession",
  "PrinterProfile",
  "PrinterProfileSnapshot",
];

export const expectedPolicies = [
  "rls_candidate_organization_select",
  "rls_candidate_licensee_select",
  "rls_candidate_user_select",
  "rls_candidate_manufacturer_licensee_link_select",
  "rls_candidate_batch_select",
  "rls_candidate_inventory_status_rollup_select",
  "rls_candidate_qrcode_select",
  "rls_candidate_print_job_select",
  "rls_candidate_print_session_select",
  "rls_candidate_print_item_select",
  "rls_candidate_printer_registration_select",
  "rls_candidate_printer_select",
  "rls_candidate_printer_attestation_select",
  "rls_candidate_printer_agent_session_select",
  "rls_candidate_printer_profile_select",
  "rls_candidate_printer_profile_snapshot_select",
];

export const expectedFunctions = [
  "setting",
  "current_user_id",
  "current_role",
  "current_licensee_id",
  "current_manufacturer_id",
  "current_organization_id",
  "is_platform_admin",
  "can_access_licensee",
  "can_access_organization",
  "can_access_batch",
  "can_access_qr",
  "can_access_printer_registration",
  "can_access_printer",
  "can_access_print_job",
  "can_access_print_session",
  "can_access_print_item",
  "can_access_printer_profile",
];

const urlEnvNames = ["DATABASE_URL", "TEST_DATABASE_URL", "P2_TEST_DATABASE_URL", DATABASE_URL_ENV];
const safeDatabaseNamePattern = /(^|[_-])(rls_harness|disposable|test|ci)([_-]|$)/i;
const localHosts = new Set(["localhost", "127.0.0.1", "::1", "postgres"]);
const forbiddenUrlMarkers = [
  "prod",
  "production",
  "staging",
  "rds.amazonaws.com",
  "amazonaws.com",
  "supabase",
  "neon.tech",
  "render.com",
  "railway.app",
  "database.azure.com",
  "heroku",
  "fly.dev",
];

const routeRuntimeCommands = [
  ["npm", ["--prefix", "backend", "run", "test:rls:manufacturer-printers-read-runtime"]],
  ["npm", ["--prefix", "backend", "run", "test:rls:batches-read-runtime"]],
  ["npm", ["--prefix", "backend", "run", "test:rls:batch-allocation-map-runtime"]],
];

const repoRoot = path.resolve(fileURLToPath(new URL("..", import.meta.url)));

export class HarnessSafetyError extends Error {
  constructor(message) {
    super(message);
    this.name = "HarnessSafetyError";
  }
}

const parsePostgresUrl = (databaseUrl, label = "database URL") => {
  const raw = String(databaseUrl || "").trim();
  if (!raw) throw new HarnessSafetyError(`Missing ${label}.`);
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    throw new HarnessSafetyError(`Invalid ${label}.`);
  }
  if (!["postgresql:", "postgres:"].includes(parsed.protocol)) {
    throw new HarnessSafetyError(`${label} must use postgres:// or postgresql://.`);
  }
  return parsed;
};

export const sanitizeConnectionMetadata = (databaseUrl) => {
  const parsed = parsePostgresUrl(databaseUrl);
  const databaseName = decodeURIComponent(parsed.pathname.replace(/^\//, ""));
  return {
    protocol: parsed.protocol.replace(/:$/, ""),
    host: parsed.hostname,
    hostCategory: localHosts.has(parsed.hostname.toLowerCase()) ? "local" : "rejected_non_local",
    port: parsed.port || "default",
    databaseName,
    usernamePresent: Boolean(parsed.username),
    passwordPresent: Boolean(parsed.password),
  };
};

export const assertSafeDisposableDatabaseUrl = (databaseUrl, label = "database URL") => {
  const parsed = parsePostgresUrl(databaseUrl, label);
  const rawLower = String(databaseUrl).toLowerCase();
  const host = parsed.hostname.toLowerCase();
  const databaseName = decodeURIComponent(parsed.pathname.replace(/^\//, ""));
  const databaseNameLower = databaseName.toLowerCase();

  if (forbiddenUrlMarkers.some((marker) => rawLower.includes(marker))) {
    throw new HarnessSafetyError(`${label} looks like staging, production, cloud, or shared database infrastructure.`);
  }

  if (!localHosts.has(host)) {
    throw new HarnessSafetyError(`${label} host must be local disposable Postgres, not "${host}".`);
  }

  if (!safeDatabaseNamePattern.test(databaseName)) {
    throw new HarnessSafetyError(`${label} database name must include rls_harness, disposable, test, or ci.`);
  }

  if (/^postgres$/i.test(databaseNameLower) || /^template[01]$/i.test(databaseNameLower)) {
    throw new HarnessSafetyError(`${label} must not target a PostgreSQL system database.`);
  }

  return sanitizeConnectionMetadata(databaseUrl);
};

export const assertNoUnsafeAmbientDatabaseUrls = (env = process.env, suppliedUrl) => {
  const checked = [];
  for (const name of urlEnvNames) {
    const value = String(env[name] || "").trim();
    if (!value) continue;
    checked.push(name);
    assertSafeDisposableDatabaseUrl(value, name);
  }
  if (suppliedUrl) {
    checked.push("supplied URL");
    assertSafeDisposableDatabaseUrl(suppliedUrl, "supplied URL");
  }
  return checked;
};

export const assertHarnessConfirmation = (env = process.env) => {
  if (env[CONFIRM_ENV] !== CONFIRM_VALUE) {
    throw new HarnessSafetyError(`Set ${CONFIRM_ENV}=${CONFIRM_VALUE} to run the disposable RLS SQL harness.`);
  }
};

export const assertSafeAppRole = (roleValue) => {
  const role = String(roleValue || "").trim();
  if (!role) throw new HarnessSafetyError("Missing explicit non-owner runtime database role.");
  if (role.toLowerCase() === "public") throw new HarnessSafetyError("PUBLIC must not be used as the RLS runtime role.");
  if (!/^[A-Za-z_][A-Za-z0-9_$-]{0,62}$/.test(role)) {
    throw new HarnessSafetyError("RLS helper grant role contains unsafe characters.");
  }
  return role;
};

export const assertSqlFileSafe = (filePath, root = repoRoot, label = "SQL file") => {
  const resolved = path.resolve(root, filePath);
  const relative = path.relative(root, resolved);
  if (relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new HarnessSafetyError(`${label} must stay inside the repository.`);
  }
  if (relative.includes(`backend${path.sep}prisma${path.sep}migrations${path.sep}`)) {
    throw new HarnessSafetyError(`${label} must not live under backend/prisma/migrations.`);
  }
  if (!fs.existsSync(resolved)) {
    throw new HarnessSafetyError(`${label} not found: ${relative}`);
  }
  if (!fs.statSync(resolved).isFile()) {
    throw new HarnessSafetyError(`${label} is not a file: ${relative}`);
  }
  return { resolved, relative };
};

export const parseArgs = (argv) => {
  const args = {
    candidateSql: defaultCandidateSqlPath,
    rollbackSql: defaultRollbackSqlPath,
    databaseUrl: "",
    runtimeRole: "",
    prepareSchema: false,
    runRouteTests: false,
    evidenceFile: true,
    json: false,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const readValue = () => {
      const value = argv[i + 1];
      if (!value || value.startsWith("--")) throw new HarnessSafetyError(`Missing value for ${arg}.`);
      i += 1;
      return value;
    };

    if (arg === "--database-url") args.databaseUrl = readValue();
    else if (arg === "--runtime-role") args.runtimeRole = readValue();
    else if (arg === "--candidate-sql") args.candidateSql = readValue();
    else if (arg === "--rollback-sql") args.rollbackSql = readValue();
    else if (arg === "--prepare-schema") args.prepareSchema = true;
    else if (arg === "--run-route-tests") args.runRouteTests = true;
    else if (arg === "--no-evidence-file") args.evidenceFile = false;
    else if (arg === "--json") args.json = true;
    else if (arg === "--help") args.help = true;
    else throw new HarnessSafetyError(`Unknown argument: ${arg}`);
  }

  return args;
};

const resolveTargetDatabaseUrl = (args, env = process.env) =>
  args.databaseUrl ||
  String(env[DATABASE_URL_ENV] || env.P2_TEST_DATABASE_URL || env.TEST_DATABASE_URL || env.DATABASE_URL || "").trim();

const resolveHarnessRuntimeRole = (databaseUrl, args, env = process.env) => {
  const explicit = assertSafeAppRole(args.runtimeRole || env[RUNTIME_ROLE_ENV]);
  const ownerRole = decodeURIComponent(parsePostgresUrl(databaseUrl).username || "");
  if (!ownerRole) throw new HarnessSafetyError("Owner database URL must contain an explicit username.");
  if (explicit === ownerRole) {
    throw new HarnessSafetyError("Runtime database role must differ from the migration/owner URL role.");
  }
  return explicit;
};

const sqlArray = (values) => `ARRAY[${values.map((value) => `'${value.replace(/'/g, "''")}'`).join(",")}]`;

const buildPsqlConnection = (databaseUrl) => {
  const parsed = parsePostgresUrl(databaseUrl);
  const password = parsed.password ? decodeURIComponent(parsed.password) : "";
  parsed.password = "";
  return {
    connectionString: parsed.toString(),
    password,
  };
};

const runPsql = (databaseUrl, psqlArgs, options = {}) => {
  const connection = buildPsqlConnection(databaseUrl);
  const runtimeRole = assertSafeAppRole(options.runtimeRole);
  const result = spawnSync(
    "psql",
    [
      connection.connectionString,
      "-v",
      "ON_ERROR_STOP=1",
      "-v",
      `${PSQL_RUNTIME_ROLE_VARIABLE}=${runtimeRole}`,
      "-X",
      ...psqlArgs,
    ],
    {
      cwd: repoRoot,
      env: { ...process.env, PGPASSWORD: connection.password || process.env.PGPASSWORD || "" },
      encoding: "utf8",
      stdio: options.stdio || "pipe",
      maxBuffer: 16 * 1024 * 1024,
    },
  );
  if (result.status !== 0) {
    const detail = [result.stderr, result.stdout].filter(Boolean).join("\n").trim();
    throw new Error(`${options.label || "psql"} failed${detail ? `: ${detail}` : "."}`);
  }
  return result.stdout || "";
};

const queryJson = (databaseUrl, sql, label, runtimeRole) => {
  const wrapped = `COPY (SELECT COALESCE(json_agg(row_to_json(q)), '[]'::json) FROM (${sql}) q) TO STDOUT`;
  const stdout = runPsql(databaseUrl, ["-q", "-t", "-A", "-c", wrapped], { label, runtimeRole });
  return JSON.parse(stdout.trim() || "[]");
};

const queryJsonAsRuntime = (databaseUrl, sql, label, runtimeRole, settings = {}) => {
  const wrapped = `
BEGIN;
SET LOCAL ROLE ${quoteIdentifier(runtimeRole)};
${contextSql(settings)}
COPY (SELECT COALESCE(json_agg(row_to_json(q)), '[]'::json) FROM (${sql}) q) TO STDOUT;
ROLLBACK;`;
  const stdout = runPsql(databaseUrl, ["-q", "-t", "-A", "-c", wrapped], { label, runtimeRole });
  return JSON.parse(stdout.trim() || "[]");
};

const collectCandidateObjects = (databaseUrl, runtimeRole) => ({
  schema: queryJson(
    databaseUrl,
    "SELECT nspname FROM pg_namespace WHERE nspname = 'app_rls'",
    "collect app_rls schema",
    runtimeRole,
  ),
  functions: queryJson(
    databaseUrl,
    `SELECT p.proname,
            has_function_privilege('${runtimeRole.replace(/'/g, "''")}', p.oid, 'EXECUTE') AS runtime_execute,
            has_function_privilege('public', p.oid, 'EXECUTE') AS public_execute
     FROM pg_proc p
     JOIN pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname = 'app_rls'
       AND p.proname = ANY(${sqlArray(expectedFunctions)})
     ORDER BY p.proname`,
    "collect app_rls functions",
    runtimeRole,
  ),
  policies: queryJson(
    databaseUrl,
    `SELECT tablename, policyname, cmd
     FROM pg_policies
     WHERE schemaname = 'public'
       AND policyname = ANY(${sqlArray(expectedPolicies)})
     ORDER BY tablename, policyname`,
    "collect candidate policies",
    runtimeRole,
  ),
  tableRls: queryJson(
    databaseUrl,
    `SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity
     FROM pg_class c
     JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public'
       AND c.relname = ANY(${sqlArray(expectedTables)})
     ORDER BY c.relname`,
    "collect table RLS state",
    runtimeRole,
  ),
});

const names = (rows, key) => new Set(rows.map((row) => row[key]));

const assertNoPreexistingCandidateObjects = (objects) => {
  if (objects.schema.length || objects.functions.length || objects.policies.length) {
    throw new Error("Refusing to run because candidate app_rls objects already exist. Run rollback or use a clean disposable DB.");
  }
};

const assertAppliedObjects = (objects) => {
  const functions = names(objects.functions, "proname");
  const policies = names(objects.policies, "policyname");
  const tableRows = new Map(objects.tableRls.map((row) => [row.relname, row]));
  const missingFunctions = expectedFunctions.filter((name) => !functions.has(name));
  const missingPolicies = expectedPolicies.filter((name) => !policies.has(name));
  const missingTables = expectedTables.filter((name) => !tableRows.has(name));
  const unforcedTables = expectedTables.filter((name) => {
    const row = tableRows.get(name);
    return row && (!row.relrowsecurity || !row.relforcerowsecurity);
  });
  const incorrectlyGrantedFunctions = objects.functions
    .filter((row) => !row.runtime_execute || row.public_execute)
    .map((row) => row.proname);

  if (
    missingFunctions.length ||
    missingPolicies.length ||
    missingTables.length ||
    unforcedTables.length ||
    incorrectlyGrantedFunctions.length
  ) {
    throw new Error(
      [
        "Candidate SQL did not produce expected RLS objects.",
        `missingFunctions=${missingFunctions.join(",") || "none"}`,
        `missingPolicies=${missingPolicies.join(",") || "none"}`,
        `missingTables=${missingTables.join(",") || "none"}`,
        `unforcedTables=${unforcedTables.join(",") || "none"}`,
        `incorrectFunctionGrants=${incorrectlyGrantedFunctions.join(",") || "none"}`,
      ].join(" "),
    );
  }
};

const quoteIdentifier = (value) => `"${String(value).replace(/"/g, '""')}"`;

const createRuntimeRole = (databaseUrl, runtimeRole) => {
  const existing = queryJson(
    databaseUrl,
    `SELECT rolname FROM pg_roles WHERE rolname = '${runtimeRole.replace(/'/g, "''")}'`,
    "check runtime role absence",
    runtimeRole,
  );
  if (existing.length) {
    throw new HarnessSafetyError(`Runtime role ${runtimeRole} already exists; use a fresh explicit harness role name.`);
  }

  const databaseName = decodeURIComponent(parsePostgresUrl(databaseUrl).pathname.replace(/^\//, ""));
  runPsql(
    databaseUrl,
    [
      "-q",
      "-c",
      `CREATE ROLE ${quoteIdentifier(runtimeRole)} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS INHERIT;
       GRANT ${quoteIdentifier(runtimeRole)} TO CURRENT_USER;
       GRANT CONNECT ON DATABASE ${quoteIdentifier(databaseName)} TO ${quoteIdentifier(runtimeRole)};
       GRANT USAGE ON SCHEMA public TO ${quoteIdentifier(runtimeRole)};`,
    ],
    { label: "create least-privileged runtime role", runtimeRole },
  );
};

const dropRuntimeRole = (databaseUrl, runtimeRole) => {
  runPsql(
    databaseUrl,
    [
      "-q",
      "-c",
      `DROP OWNED BY ${quoteIdentifier(runtimeRole)};
       DROP ROLE IF EXISTS ${quoteIdentifier(runtimeRole)};`,
    ],
    { label: "drop disposable runtime role", runtimeRole },
  );
};

const assertMigrationOwnerOwnsTables = (databaseUrl, runtimeRole) => {
  const rows = queryJson(
    databaseUrl,
    `SELECT c.relname, owner.rolname AS table_owner, current_user AS migration_owner
     FROM pg_class c
     JOIN pg_namespace n ON n.oid = c.relnamespace
     JOIN pg_roles owner ON owner.oid = c.relowner
     WHERE n.nspname = 'public'
       AND c.relname = ANY(${sqlArray(expectedTables)})
     ORDER BY c.relname`,
    "verify migration owner",
    runtimeRole,
  );
  const invalid = rows.filter((row) => row.table_owner !== row.migration_owner);
  if (rows.length !== expectedTables.length || invalid.length) {
    throw new HarnessSafetyError(
      `Migration URL role must own all protected tables; invalid=${invalid.map((row) => row.relname).join(",") || "count_mismatch"}.`,
    );
  }
};

const assertProtectedTablesEmpty = (databaseUrl, runtimeRole) => {
  const union = expectedTables
    .map((table) => `SELECT '${table}' AS table_name, count(*)::integer AS row_count FROM ${quoteIdentifier(table)}`)
    .join(" UNION ALL ");
  const rows = queryJson(databaseUrl, union, "verify clean fixture tables", runtimeRole);
  const populated = rows.filter((row) => row.row_count !== 0);
  if (populated.length) {
    throw new HarnessSafetyError(
      `Protected tables must be empty before fixture seeding: ${populated.map((row) => row.table_name).join(",")}.`,
    );
  }
};

const collectRuntimeDiagnostics = (databaseUrl, runtimeRole) => ({
  identity: queryJsonAsRuntime(
    databaseUrl,
    `SELECT session_user, current_user, current_role, current_setting('row_security') AS row_security,
            app_rls.setting('app.user_id') AS user_id,
            app_rls.setting('app.role') AS app_role,
            app_rls.setting('app.licensee_id') AS licensee_id,
            app_rls.setting('app.manufacturer_id') AS manufacturer_id,
            app_rls.setting('app.organization_id') AS organization_id,
            app_rls.setting('app.is_platform_admin') AS is_platform_admin`,
    "runtime identity diagnostics",
    runtimeRole,
  )[0],
  role: queryJson(
    databaseUrl,
    `SELECT rolname, rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls, rolinherit, rolcanlogin
     FROM pg_roles WHERE rolname = '${runtimeRole.replace(/'/g, "''")}'`,
    "runtime role attributes",
    runtimeRole,
  )[0],
  memberships: queryJson(
    databaseUrl,
    `WITH RECURSIVE inherited(role_oid, role_name, depth) AS (
       SELECT granted.oid, granted.rolname, 1
       FROM pg_auth_members m
       JOIN pg_roles member ON member.oid = m.member
       JOIN pg_roles granted ON granted.oid = m.roleid
       WHERE member.rolname = '${runtimeRole.replace(/'/g, "''")}'
       UNION ALL
       SELECT granted.oid, granted.rolname, inherited.depth + 1
       FROM inherited
       JOIN pg_auth_members m ON m.member = inherited.role_oid
       JOIN pg_roles granted ON granted.oid = m.roleid
     ) SELECT role_name, min(depth)::integer AS depth FROM inherited GROUP BY role_name ORDER BY role_name`,
    "runtime transitive memberships",
    runtimeRole,
  ),
  tables: queryJsonAsRuntime(
    databaseUrl,
    `SELECT c.relname, owner.rolname AS table_owner, c.relrowsecurity, c.relforcerowsecurity,
            has_table_privilege(current_user, c.oid, 'SELECT') AS has_select,
            pg_has_role(current_user, c.relowner, 'USAGE') AS owns_or_inherits_owner,
            current_user = owner.rolname AS current_role_owns
     FROM pg_class c
     JOIN pg_namespace n ON n.oid = c.relnamespace
     JOIN pg_roles owner ON owner.oid = c.relowner
     WHERE n.nspname = 'public' AND c.relname = ANY(${sqlArray(expectedTables)})
     ORDER BY c.relname`,
    "runtime table diagnostics",
    runtimeRole,
  ),
});

export const assertRuntimeRoleDiagnostics = (diagnostics, expectedRuntimeRole) => {
  const { identity, role, memberships, tables } = diagnostics;
  if (!identity || identity.current_user !== expectedRuntimeRole || identity.current_role !== expectedRuntimeRole) {
    throw new HarnessSafetyError("RLS assertions are not executing as the explicit runtime role.");
  }
  if (identity.session_user === expectedRuntimeRole) {
    throw new HarnessSafetyError("Runtime role must not be the migration/owner session role.");
  }
  if (identity.row_security !== "on") {
    throw new HarnessSafetyError(`Runtime row_security must be on, got ${identity.row_security || "missing"}.`);
  }
  if (!role || role.rolsuper || role.rolbypassrls || role.rolcreaterole || role.rolcreatedb || role.rolreplication) {
    throw new HarnessSafetyError("Runtime role has forbidden SUPERUSER, BYPASSRLS, CREATEROLE, CREATEDB, or REPLICATION privilege.");
  }
  if (memberships.length) {
    throw new HarnessSafetyError(`Runtime role inherits transitive role memberships: ${memberships.map((row) => row.role_name).join(",")}.`);
  }
  const unsafeTables = tables.filter(
    (row) => row.owns_or_inherits_owner || row.current_role_owns || !row.relrowsecurity || !row.relforcerowsecurity || !row.has_select,
  );
  if (tables.length !== expectedTables.length || unsafeTables.length) {
    throw new HarnessSafetyError(
      `Runtime role/table separation failed: ${unsafeTables.map((row) => row.relname).join(",") || "count_mismatch"}.`,
    );
  }
};

const assertDirectHelpersFailClosed = (databaseUrl, runtimeRole) => {
  const target = fixtureIds;
  const row = queryJsonAsRuntime(
    databaseUrl,
    `SELECT app_rls.setting('app.user_id') AS setting,
            app_rls.current_user_id() AS current_user_id,
            app_rls.current_role() AS current_role,
            app_rls.current_licensee_id() AS current_licensee_id,
            app_rls.current_manufacturer_id() AS current_manufacturer_id,
            app_rls.current_organization_id() AS current_organization_id,
            app_rls.is_platform_admin() AS is_platform_admin,
            app_rls.can_access_licensee('${target.licenseeA}') AS can_access_licensee,
            app_rls.can_access_organization('${target.orgA}') AS can_access_organization,
            app_rls.can_access_batch('rls-harness-batch-a') AS can_access_batch,
            app_rls.can_access_qr('rls-harness-qrcode-a') AS can_access_qr,
            app_rls.can_access_printer_registration('rls-harness-printerregistration-a') AS can_access_printer_registration,
            app_rls.can_access_printer('rls-harness-printer-a') AS can_access_printer,
            app_rls.can_access_print_job('rls-harness-printjob-a') AS can_access_print_job,
            app_rls.can_access_print_session('rls-harness-printsession-a') AS can_access_print_session,
            app_rls.can_access_print_item('rls-harness-printitem-a') AS can_access_print_item,
            app_rls.can_access_printer_profile('rls-harness-printerprofile-a') AS can_access_printer_profile`,
    "no-context direct helper probes",
    runtimeRole,
  )[0];
  const expectedFalse = [
    "is_platform_admin",
    "can_access_licensee",
    "can_access_organization",
    "can_access_batch",
    "can_access_qr",
    "can_access_printer_registration",
    "can_access_printer",
    "can_access_print_job",
    "can_access_print_session",
    "can_access_print_item",
    "can_access_printer_profile",
  ];
  const nullable = ["setting", "current_user_id", "current_licensee_id", "current_manufacturer_id", "current_organization_id"];
  if (row.current_role !== "" || nullable.some((key) => row[key] !== null) || expectedFalse.some((key) => row[key] !== false)) {
    throw new Error(`No-context helper probes did not fail closed: ${JSON.stringify(row)}`);
  }
};

const normalizeVisibility = (visibility) =>
  Object.fromEntries(
    Object.entries(visibility)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([table, ids]) => [table, [...ids].sort()]),
  );

const assertContextMatrix = (databaseUrl, runtimeRole) => {
  const results = [];
  for (const context of contextMatrix) {
    const row = queryJsonAsRuntime(
      databaseUrl,
      visibilitySql,
      `context matrix ${context.name}`,
      runtimeRole,
      context.settings,
    )[0];
    const actual = normalizeVisibility(row.visibility);
    const expected = normalizeVisibility(context.expected);
    if (JSON.stringify(actual) !== JSON.stringify(expected)) {
      throw new Error(`Context ${context.name} visibility mismatch: expected=${JSON.stringify(expected)} actual=${JSON.stringify(actual)}`);
    }
    if (context.forbiddenIds) {
      for (const [table, forbidden] of Object.entries(context.forbiddenIds)) {
        if (actual[table].some((id) => forbidden.includes(id))) {
          throw new Error(`Context ${context.name} exposed forbidden ${table} IDs.`);
        }
      }
    }
    results.push({ name: context.name, status: "passed" });
  }
  return results;
};

const runPsqlExpectingDenial = (databaseUrl, runtimeRole, sql, label) => {
  try {
    runPsql(
      databaseUrl,
      ["-q", "-c", `BEGIN; SET LOCAL ROLE ${quoteIdentifier(runtimeRole)}; ${sql}; ROLLBACK;`],
      { label, runtimeRole },
    );
  } catch (error) {
    if (/permission denied|row-level security policy/i.test(error.message)) return;
    throw error;
  }
  throw new Error(`${label} unexpectedly succeeded.`);
};

const assertSelectOnlyWriteDenial = (databaseUrl, runtimeRole) => {
  for (const { table } of tableProofs) {
    const quoted = quoteIdentifier(table);
    const updateColumn = queryJson(
      databaseUrl,
      `SELECT a.attname FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid
       JOIN pg_namespace n ON n.oid = c.relnamespace
       WHERE n.nspname = 'public' AND c.relname = '${table}' AND a.attnum > 0 AND NOT a.attisdropped
       ORDER BY a.attnum LIMIT 1`,
      `resolve ${table} update column`,
      runtimeRole,
    )[0].attname;
    const column = quoteIdentifier(updateColumn);
    runPsqlExpectingDenial(databaseUrl, runtimeRole, `INSERT INTO ${quoted} SELECT * FROM ${quoted} WHERE false`, `${table} INSERT denial`);
    runPsqlExpectingDenial(databaseUrl, runtimeRole, `UPDATE ${quoted} SET ${column} = ${column} WHERE false`, `${table} UPDATE denial`);
    runPsqlExpectingDenial(databaseUrl, runtimeRole, `DELETE FROM ${quoted} WHERE false`, `${table} DELETE denial`);
  }
};

const assertRollbackRemovedObjects = (objects) => {
  const remainingForced = objects.tableRls
    .filter((row) => row.relrowsecurity || row.relforcerowsecurity)
    .map((row) => row.relname);

  if (objects.schema.length || objects.functions.length || objects.policies.length || remainingForced.length) {
    throw new Error(
      [
        "Rollback left candidate RLS objects behind.",
        `schema=${objects.schema.length}`,
        `functions=${objects.functions.map((row) => row.proname).join(",") || "none"}`,
        `policies=${objects.policies.map((row) => row.policyname).join(",") || "none"}`,
        `tablesWithRls=${remainingForced.join(",") || "none"}`,
      ].join(" "),
    );
  }
};

const assertRuntimeTableGrantsRemoved = (databaseUrl, runtimeRole) => {
  const rows = queryJson(
    databaseUrl,
    `SELECT c.relname, has_table_privilege('${runtimeRole.replace(/'/g, "''")}', c.oid, 'SELECT') AS has_select
     FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public' AND c.relname = ANY(${sqlArray(expectedTables)})
     ORDER BY c.relname`,
    "verify rollback table grant removal",
    runtimeRole,
  );
  const remaining = rows.filter((row) => row.has_select).map((row) => row.relname);
  if (rows.length !== expectedTables.length || remaining.length) {
    throw new Error(`Rollback left runtime SELECT grants: ${remaining.join(",") || "count_mismatch"}.`);
  }
};

const runPrismaMigrateDeploy = (databaseUrl) => {
  execFileSync("npx", ["prisma", "validate", "--schema", "prisma/schema.prisma"], {
    cwd: path.join(repoRoot, "backend"),
    env: { ...process.env, NODE_ENV: "test", DATABASE_URL: databaseUrl },
    stdio: "inherit",
  });
  execFileSync("npx", ["prisma", "migrate", "deploy", "--schema", "prisma/schema.prisma"], {
    cwd: path.join(repoRoot, "backend"),
    env: { ...process.env, NODE_ENV: "test", DATABASE_URL: databaseUrl },
    stdio: "inherit",
  });
};

const runRouteRuntimeTests = () => {
  for (const [command, args] of routeRuntimeCommands) {
    execFileSync(command, args, {
      cwd: repoRoot,
      env: { ...process.env },
      stdio: "inherit",
    });
  }
};

const writeEvidence = (evidence) => {
  const artifactsRoot = path.join(repoRoot, "artifacts");
  if (!fs.existsSync(artifactsRoot)) return null;
  const evidenceRoot = path.join(artifactsRoot, "rls-disposable-harness");
  fs.mkdirSync(evidenceRoot, { recursive: true });
  const filePath = path.join(evidenceRoot, `rls-harness-${new Date().toISOString().replace(/[:.]/g, "-")}.json`);
  fs.writeFileSync(filePath, `${JSON.stringify(evidence, null, 2)}\n`, "utf8");
  return path.relative(repoRoot, filePath);
};

const usage = () => `
Usage:
  ${CONFIRM_ENV}=${CONFIRM_VALUE} ${DATABASE_URL_ENV}=postgresql://... \\
    node scripts/run-disposable-rls-sql-harness.mjs [options]

Options:
  --database-url <url>       Local disposable PostgreSQL URL. Env fallback: ${DATABASE_URL_ENV}.
  --runtime-role <role>      Required fresh non-owner runtime role. Env fallback: ${RUNTIME_ROLE_ENV}.
  --candidate-sql <path>     Candidate SQL template path.
  --rollback-sql <path>      Rollback SQL template path.
  --prepare-schema           Run Prisma validate and migrate deploy against the disposable DB first.
  --run-route-tests          Also run the three existing route-specific P2 runtime tests.
  --no-evidence-file         Print sanitized JSON evidence only.
  --json                     Print only sanitized JSON evidence.
`;

export const runHarness = async (args, env = process.env) => {
  assertHarnessConfirmation(env);
  const databaseUrl = resolveTargetDatabaseUrl(args, env);
  const safeMetadata = assertSafeDisposableDatabaseUrl(databaseUrl, "target database URL");
  const runtimeRole = resolveHarnessRuntimeRole(databaseUrl, args, env);
  const checkedUrlEnv = assertNoUnsafeAmbientDatabaseUrls(env, args.databaseUrl);
  const candidate = assertSqlFileSafe(args.candidateSql, repoRoot, "Candidate SQL file");
  const rollback = assertSqlFileSafe(args.rollbackSql, repoRoot, "Rollback SQL file");
  const evidence = {
    status: "started",
    target: safeMetadata,
    checkedUrlEnv,
    candidateSql: candidate.relative,
    rollbackSql: rollback.relative,
    roleModel: {
      migrationOwner: "database_url_username",
      runtimeRole,
      runtimeRoleSource: args.runtimeRole ? "command_line" : "explicit_environment",
      runtimeLogin: false,
    },
    prepareSchema: args.prepareSchema,
    routeRuntimeTests: args.runRouteTests ? "requested" : "skipped",
    checks: [],
  };

  let candidateApplied = false;
  let rollbackRan = false;
  let runtimeRoleCreated = false;
  let fixturesSeeded = false;

  try {
    if (args.prepareSchema) {
      runPrismaMigrateDeploy(databaseUrl);
      evidence.checks.push("prisma_schema_prepared");
    }

    assertMigrationOwnerOwnsTables(databaseUrl, runtimeRole);
    evidence.checks.push("migration_owner_owns_all_protected_tables");
    assertProtectedTablesEmpty(databaseUrl, runtimeRole);
    runPsql(databaseUrl, ["-q", "-c", fixtureSql], { label: "seed RLS matrix fixtures", runtimeRole });
    fixturesSeeded = true;
    evidence.checks.push("two_tenant_matrix_fixtures_seeded");

    createRuntimeRole(databaseUrl, runtimeRole);
    runtimeRoleCreated = true;
    evidence.checks.push("dedicated_non_owner_runtime_role_created");

    const before = collectCandidateObjects(databaseUrl, runtimeRole);
    assertNoPreexistingCandidateObjects(before);
    evidence.checks.push("preexisting_candidate_objects_absent");

    runPsql(databaseUrl, ["-f", candidate.resolved], {
      label: "candidate SQL",
      stdio: "inherit",
      runtimeRole,
    });
    candidateApplied = true;
    const afterApply = collectCandidateObjects(databaseUrl, runtimeRole);
    assertAppliedObjects(afterApply);
    evidence.checks.push("candidate_sql_applied");
    evidence.checks.push("expected_helpers_policies_and_forced_rls_present");

    const diagnostics = collectRuntimeDiagnostics(databaseUrl, runtimeRole);
    assertRuntimeRoleDiagnostics(diagnostics, runtimeRole);
    evidence.diagnostics = diagnostics;
    evidence.checks.push("runtime_identity_attributes_memberships_and_table_ownership_safe");

    assertDirectHelpersFailClosed(databaseUrl, runtimeRole);
    evidence.checks.push("all_17_helpers_fail_closed_without_context");

    evidence.contextMatrix = assertContextMatrix(databaseUrl, runtimeRole);
    evidence.checks.push("exact_id_context_matrix_passed");

    assertSelectOnlyWriteDenial(databaseUrl, runtimeRole);
    evidence.checks.push("insert_update_delete_denied_on_all_16_tables");

    if (args.runRouteTests) {
      runRouteRuntimeTests();
      evidence.routeRuntimeTests = "passed_existing_p2_disposable_tests";
    }
  } finally {
    if (candidateApplied) {
      runPsql(databaseUrl, ["-f", rollback.resolved], {
        label: "rollback SQL",
        stdio: "inherit",
        runtimeRole,
      });
      rollbackRan = true;
      const afterRollback = collectCandidateObjects(databaseUrl, runtimeRole);
      assertRollbackRemovedObjects(afterRollback);
      assertRuntimeTableGrantsRemoved(databaseUrl, runtimeRole);
      evidence.checks.push("rollback_sql_ran");
      evidence.checks.push("candidate_objects_and_runtime_grants_removed_after_rollback");
    }
    if (fixturesSeeded) {
      runPsql(databaseUrl, ["-q", "-c", truncateFixtureSql], { label: "remove RLS matrix fixtures", runtimeRole });
      evidence.checks.push("matrix_fixtures_removed");
    }
    if (runtimeRoleCreated) {
      dropRuntimeRole(databaseUrl, runtimeRole);
      evidence.checks.push("disposable_runtime_role_removed");
    }
  }

  evidence.status = "passed";
  evidence.rollbackRan = rollbackRan;
  const evidencePath = args.evidenceFile ? writeEvidence(evidence) : null;
  if (evidencePath) evidence.evidencePath = evidencePath;
  return evidence;
};

const main = async () => {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    process.stdout.write(usage());
    return;
  }

  try {
    const evidence = await runHarness(args);
    const output = JSON.stringify(evidence, null, 2);
    process.stdout.write(`${output}\n`);
  } catch (error) {
    const safeError = {
      status: "failed",
      error: error instanceof HarnessSafetyError ? "safety_guard_failed" : "harness_failed",
      message: error?.message || String(error),
    };
    process.stderr.write(`${JSON.stringify(safeError, null, 2)}\n`);
    process.exitCode = 1;
  }
};

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) {
  main();
}
