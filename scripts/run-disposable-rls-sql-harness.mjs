import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export const CONFIRM_ENV = "MSCQR_DISPOSABLE_RLS_HARNESS_CONFIRM";
export const CONFIRM_VALUE = "MSCQR_RUN_DISPOSABLE_RLS_HARNESS";
export const DATABASE_URL_ENV = "MSCQR_DISPOSABLE_RLS_DATABASE_URL";
export const APP_ROLE_ENV = "MSCQR_DISPOSABLE_RLS_APP_ROLE";
export const PSQL_APP_ROLE_VARIABLE = "mscqr_staging_app_role";

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
  if (!role) throw new HarnessSafetyError("Missing reviewed staging app DB role.");
  if (role.toLowerCase() === "public") throw new HarnessSafetyError("PUBLIC must not be used as the RLS helper grant role.");
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
    appRole: "",
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
    else if (arg === "--app-role") args.appRole = readValue();
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

const resolveHarnessAppRole = (databaseUrl, args, env = process.env) => {
  const explicit = String(args.appRole || env[APP_ROLE_ENV] || "").trim();
  if (explicit) return assertSafeAppRole(explicit);
  const parsed = parsePostgresUrl(databaseUrl);
  return assertSafeAppRole(decodeURIComponent(parsed.username || ""));
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
  const appRole = assertSafeAppRole(options.appRole || decodeURIComponent(parsePostgresUrl(databaseUrl).username || ""));
  const result = spawnSync(
    "psql",
    [
      connection.connectionString,
      "-v",
      "ON_ERROR_STOP=1",
      "-v",
      `${PSQL_APP_ROLE_VARIABLE}=${appRole}`,
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

const queryJson = (databaseUrl, sql, label, appRole) => {
  const wrapped = `COPY (SELECT COALESCE(json_agg(row_to_json(q)), '[]'::json) FROM (${sql}) q) TO STDOUT`;
  const stdout = runPsql(databaseUrl, ["-q", "-t", "-A", "-c", wrapped], { label, appRole });
  return JSON.parse(stdout.trim() || "[]");
};

const collectCandidateObjects = (databaseUrl, appRole) => ({
  schema: queryJson(
    databaseUrl,
    "SELECT nspname FROM pg_namespace WHERE nspname = 'app_rls'",
    "collect app_rls schema",
    appRole,
  ),
  functions: queryJson(
    databaseUrl,
    `SELECT p.proname
     FROM pg_proc p
     JOIN pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname = 'app_rls'
       AND p.proname = ANY(${sqlArray(expectedFunctions)})
     ORDER BY p.proname`,
    "collect app_rls functions",
    appRole,
  ),
  policies: queryJson(
    databaseUrl,
    `SELECT tablename, policyname, cmd
     FROM pg_policies
     WHERE schemaname = 'public'
       AND policyname = ANY(${sqlArray(expectedPolicies)})
     ORDER BY tablename, policyname`,
    "collect candidate policies",
    appRole,
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
    appRole,
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

  if (missingFunctions.length || missingPolicies.length || missingTables.length || unforcedTables.length) {
    throw new Error(
      [
        "Candidate SQL did not produce expected RLS objects.",
        `missingFunctions=${missingFunctions.join(",") || "none"}`,
        `missingPolicies=${missingPolicies.join(",") || "none"}`,
        `missingTables=${missingTables.join(",") || "none"}`,
        `unforcedTables=${unforcedTables.join(",") || "none"}`,
      ].join(" "),
    );
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
  --app-role <role>          Reviewed app DB role value. Env fallback: ${APP_ROLE_ENV}; default DB username.
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
  const appRole = resolveHarnessAppRole(databaseUrl, args, env);
  const checkedUrlEnv = assertNoUnsafeAmbientDatabaseUrls(env, args.databaseUrl);
  const candidate = assertSqlFileSafe(args.candidateSql, repoRoot, "Candidate SQL file");
  const rollback = assertSqlFileSafe(args.rollbackSql, repoRoot, "Rollback SQL file");
  const evidence = {
    status: "started",
    target: safeMetadata,
    checkedUrlEnv,
    candidateSql: candidate.relative,
    rollbackSql: rollback.relative,
    appRoleSource: args.appRole || env[APP_ROLE_ENV] ? "explicit" : "database_username",
    prepareSchema: args.prepareSchema,
    routeRuntimeTests: args.runRouteTests ? "requested" : "skipped",
    checks: [],
  };

  let candidateApplied = false;
  let rollbackRan = false;

  try {
    if (args.prepareSchema) {
      runPrismaMigrateDeploy(databaseUrl);
      evidence.checks.push("prisma_schema_prepared");
    }

    const before = collectCandidateObjects(databaseUrl, appRole);
    assertNoPreexistingCandidateObjects(before);
    evidence.checks.push("preexisting_candidate_objects_absent");

    runPsql(databaseUrl, ["-f", candidate.resolved], { label: "candidate SQL", stdio: "inherit", appRole });
    candidateApplied = true;
    const afterApply = collectCandidateObjects(databaseUrl, appRole);
    assertAppliedObjects(afterApply);
    evidence.checks.push("candidate_sql_applied");
    evidence.checks.push("expected_helpers_policies_and_forced_rls_present");

    if (args.runRouteTests) {
      runRouteRuntimeTests();
      evidence.routeRuntimeTests = "passed_existing_p2_disposable_tests";
    }
  } finally {
    if (candidateApplied) {
      runPsql(databaseUrl, ["-f", rollback.resolved], { label: "rollback SQL", stdio: "inherit", appRole });
      rollbackRan = true;
      const afterRollback = collectCandidateObjects(databaseUrl, appRole);
      assertRollbackRemovedObjects(afterRollback);
      evidence.checks.push("rollback_sql_ran");
      evidence.checks.push("candidate_objects_removed_after_rollback");
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
