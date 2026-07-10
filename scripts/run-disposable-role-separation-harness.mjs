import { execFileSync, spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const backendRoot = path.join(repoRoot, "backend");
const localHosts = new Set(["localhost", "127.0.0.1", "::1", "postgres"]);
const forbiddenMarkers = ["prod", "production", "staging", "rds.amazonaws.com", "amazonaws.com", "supabase", "neon.tech", "render.com", "railway.app", "database.azure.com", "heroku", "fly.dev"];

export const CONFIRM_ENV = "MSCQR_DISPOSABLE_ROLE_SEPARATION_CONFIRM";
export const CONFIRM_VALUE = "MSCQR_RUN_DISPOSABLE_ROLE_SEPARATION_HARNESS";
export const ADMIN_DATABASE_URL_ENV = "MSCQR_DISPOSABLE_ROLE_SEPARATION_ADMIN_URL";
export const APPLY_TEMPLATE = "documents/security/mscqr_staging_database_role_separation_template_2026-07-10.sql";
export const ROLLBACK_TEMPLATE = "documents/security/mscqr_staging_database_role_separation_rollback_2026-07-10.sql";

export const protectedTables = [
  "Organization", "Licensee", "User", "ManufacturerLicenseeLink", "Batch", "InventoryStatusRollup", "QRCode", "PrintJob",
  "PrintSession", "PrintItem", "PrinterRegistration", "Printer", "PrinterAttestation", "PrinterAgentSession", "PrinterProfile", "PrinterProfileSnapshot",
];

export class RoleSeparationHarnessSafetyError extends Error {}

const parseUrl = (databaseUrl, label = "database URL") => {
  if (!String(databaseUrl || "").trim()) throw new RoleSeparationHarnessSafetyError(`Missing ${label}.`);
  try {
    const parsed = new URL(databaseUrl);
    if (!["postgres:", "postgresql:"].includes(parsed.protocol)) throw new Error("protocol");
    return parsed;
  } catch {
    throw new RoleSeparationHarnessSafetyError(`Invalid ${label}; expected a PostgreSQL URL.`);
  }
};

export const assertSafeLocalAdminUrl = (databaseUrl) => {
  const parsed = parseUrl(databaseUrl, "role-separation admin URL");
  const raw = String(databaseUrl).toLowerCase();
  const databaseName = decodeURIComponent(parsed.pathname.replace(/^\//, ""));
  if (!parsed.username || !databaseName) throw new RoleSeparationHarnessSafetyError("Admin URL requires a username and database name.");
  if (!localHosts.has(parsed.hostname.toLowerCase())) throw new RoleSeparationHarnessSafetyError("Role-separation harness requires local disposable Postgres.");
  if (forbiddenMarkers.some((marker) => raw.includes(marker))) throw new RoleSeparationHarnessSafetyError("Role-separation harness refuses staging, production, cloud, or shared database URLs.");
  if (!/(?:test|disposable|harness|ci)/i.test(databaseName)) throw new RoleSeparationHarnessSafetyError("Admin database name must contain test, disposable, harness, or ci.");
  return parsed;
};

export const assertConfirmation = (env = process.env) => {
  if (env[CONFIRM_ENV] !== CONFIRM_VALUE) {
    throw new RoleSeparationHarnessSafetyError(`Set ${CONFIRM_ENV}=${CONFIRM_VALUE} to run the disposable role-separation harness.`);
  }
};

export const parseArgs = (argv) => {
  const args = { adminDatabaseUrl: "", json: false, help: false };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--admin-database-url") {
      const value = argv[index + 1];
      if (!value || value.startsWith("--")) throw new RoleSeparationHarnessSafetyError("Missing value for --admin-database-url.");
      args.adminDatabaseUrl = value;
      index += 1;
    } else if (arg === "--json") args.json = true;
    else if (arg === "--help") args.help = true;
    else throw new RoleSeparationHarnessSafetyError(`Unknown argument: ${arg}`);
  }
  return args;
};

const quoteIdentifier = (value) => `"${String(value).replace(/"/g, '""')}"`;
const roleName = (prefix) => `${prefix}_${process.pid}_${Date.now()}`.toLowerCase();

const psqlConnection = (databaseUrl) => {
  const parsed = parseUrl(databaseUrl);
  const password = parsed.password ? decodeURIComponent(parsed.password) : "";
  parsed.password = "";
  return { connectionString: parsed.toString(), password };
};

const runPsql = (databaseUrl, args, label) => {
  const connection = psqlConnection(databaseUrl);
  const result = spawnSync("psql", [connection.connectionString, "-X", "-v", "ON_ERROR_STOP=1", ...args], {
    cwd: repoRoot,
    env: { ...process.env, PGPASSWORD: connection.password || process.env.PGPASSWORD || "" },
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.status !== 0) {
    const detail = `${result.stderr || ""}${result.stdout || ""}`.trim();
    throw new Error(`${label} failed${detail ? `: ${detail}` : "."}`);
  }
  return String(result.stdout || "");
};

const runPsqlExpectDenied = (databaseUrl, statement, label) => {
  const connection = psqlConnection(databaseUrl);
  const result = spawnSync("psql", [connection.connectionString, "-X", "-v", "ON_ERROR_STOP=1", "-c", statement], {
    cwd: repoRoot,
    env: { ...process.env, PGPASSWORD: connection.password || process.env.PGPASSWORD || "" },
    encoding: "utf8",
  });
  const output = `${result.stderr || ""}${result.stdout || ""}`;
  if (result.status === 0 || !/permission denied|must be superuser|not permitted/i.test(output)) {
    throw new Error(`${label} was not denied as required: ${output.trim() || "command succeeded without output"}`);
  }
};

const runPsqlWriteProbe = (databaseUrl, statement, label) => {
  const connection = psqlConnection(databaseUrl);
  const result = spawnSync("psql", [connection.connectionString, "-X", "-v", "ON_ERROR_STOP=1", "-c", statement], {
    cwd: repoRoot,
    env: { ...process.env, PGPASSWORD: connection.password || process.env.PGPASSWORD || "" },
    encoding: "utf8",
  });
  if (result.status === 0) return;
  const output = `${result.stderr || ""}${result.stdout || ""}`;
  if (!/permission denied|must be superuser|not permitted/i.test(output)) {
    throw new Error(`${label} failed unexpectedly: ${output.trim() || "no diagnostic"}`);
  }
};

const scalar = (databaseUrl, sql, label) =>
  runPsql(databaseUrl, ["-q", "-t", "-A", "-c", sql], label).trim();

const databaseUrlFor = (adminUrl, databaseName, username) => {
  const parsed = parseUrl(adminUrl);
  parsed.pathname = `/${databaseName}`;
  parsed.username = username;
  parsed.password = "";
  return parsed.toString();
};

const templateVariables = (names, previousOwner) => [
  "-v", `mscqr_previous_owner_role=${previousOwner}`,
  "-v", `mscqr_owner_role=${names.owner}`,
  "-v", `mscqr_migrator_role=${names.migrator}`,
  "-v", `mscqr_app_role=${names.app}`,
  "-v", `mscqr_rls_read_role=${names.rlsRead}`,
];

const runPrismaMigrations = (databaseUrl) => {
  execFileSync("npx", ["prisma", "migrate", "deploy", "--schema", "prisma/schema.prisma"], {
    cwd: backendRoot,
    env: { ...process.env, DATABASE_URL: databaseUrl, NODE_ENV: "test" },
    stdio: "inherit",
  });
};

const assertWriteProbeDenied = (rlsDatabaseUrl, tableName, operation) => {
  const table = quoteIdentifier(tableName);
  const hasPrivilege = scalar(
    rlsDatabaseUrl,
    `SELECT has_table_privilege(current_user, 'public.${table}', '${operation}')`,
    `${operation} privilege probe for ${tableName}`,
  );
  if (hasPrivilege !== "f") throw new Error(`${operation} privilege remained granted to the RLS read role for ${tableName}.`);
  const updateColumn = operation === "UPDATE"
    ? scalar(
      rlsDatabaseUrl,
      `SELECT quote_ident(a.attname) FROM pg_attribute a WHERE a.attrelid = 'public.${table}'::regclass AND a.attnum > 0 AND NOT a.attisdropped ORDER BY a.attnum LIMIT 1`,
      `resolve UPDATE probe column for ${tableName}`,
    )
    : "";
  const statement = operation === "INSERT"
    ? `INSERT INTO ${table} DEFAULT VALUES;`
    : operation === "UPDATE"
      ? `UPDATE ${table} SET ${updateColumn} = ${updateColumn} WHERE ctid = '(0,0)';`
      : `DELETE FROM ${table} WHERE ctid = '(0,0)';`;
  if (operation === "INSERT") {
    runPsqlExpectDenied(rlsDatabaseUrl, statement, `${operation} probe for ${tableName}`);
  } else {
    // The disposable schema has no rows. PostgreSQL may either reject a
    // zero-row UPDATE/DELETE during permission checks or optimize it away; the
    // explicit has_table_privilege probe above is authoritative in both cases.
    runPsqlWriteProbe(rlsDatabaseUrl, statement, `${operation} zero-row probe for ${tableName}`);
  }
};

export const runHarness = async (args, env = process.env) => {
  assertConfirmation(env);
  const adminDatabaseUrl = args.adminDatabaseUrl || env[ADMIN_DATABASE_URL_ENV] || "";
  const adminParsed = assertSafeLocalAdminUrl(adminDatabaseUrl);
  const previousOwner = decodeURIComponent(adminParsed.username);
  const databaseName = `mscqr_role_separation_harness_${process.pid}_${Date.now()}`.toLowerCase();
  const names = {
    owner: roleName("mscqr_harness_owner"),
    migrator: roleName("mscqr_harness_migrator"),
    app: roleName("mscqr_harness_app"),
    rlsRead: roleName("mscqr_harness_rls_read"),
  };
  const databaseUrl = databaseUrlFor(adminDatabaseUrl, databaseName, previousOwner);
  const appDatabaseUrl = databaseUrlFor(adminDatabaseUrl, databaseName, names.app);
  const rlsDatabaseUrl = databaseUrlFor(adminDatabaseUrl, databaseName, names.rlsRead);
  const migratorDatabaseUrl = databaseUrlFor(adminDatabaseUrl, databaseName, names.migrator);
  const applyPath = path.join(repoRoot, APPLY_TEMPLATE);
  const rollbackPath = path.join(repoRoot, ROLLBACK_TEMPLATE);
  const result = { databaseName, roles: names, migrationApplied: false, appWrites: false, rlsWriteProbesDenied: 0, rollbackVerified: false };
  let databaseCreated = false;

  try {
    runPsql(adminDatabaseUrl, ["-c", `CREATE DATABASE ${quoteIdentifier(databaseName)}`], "create disposable role-separation database");
    databaseCreated = true;
    runPrismaMigrations(databaseUrl);
    runPsql(databaseUrl, [...templateVariables(names, previousOwner), "-f", applyPath], "apply role-separation template");

    const protectedOwnerCount = scalar(
      databaseUrl,
      `SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace JOIN pg_roles r ON r.oid = c.relowner WHERE n.nspname = 'public' AND c.relname IN (${protectedTables.map((table) => `'${table}'`).join(",")}) AND r.rolname = '${names.owner}'`,
      "verify NOLOGIN owner ownership",
    );
    if (Number(protectedOwnerCount) !== protectedTables.length) throw new Error("NOLOGIN owner did not receive every protected table.");

    runPsql(
      migratorDatabaseUrl,
      ["-c", `BEGIN; SET LOCAL ROLE ${quoteIdentifier(names.owner)}; CREATE TABLE "RoleSeparationHarnessMigration" ("id" text PRIMARY KEY); COMMIT;`],
      "migrator controlled migration",
    );
    const migrationOwner = scalar(
      databaseUrl,
      `SELECT r.rolname FROM pg_class c JOIN pg_roles r ON r.oid = c.relowner WHERE c.oid = 'public."RoleSeparationHarnessMigration"'::regclass`,
      "verify migrator migration ownership",
    );
    if (migrationOwner !== names.owner) throw new Error("Migrator migration was not owned by the NOLOGIN owner role.");
    result.migrationApplied = true;

    runPsql(appDatabaseUrl, ["-c", "INSERT INTO \"ActionIdempotencyKey\" (\"id\", \"keyHash\", \"action\", \"expiresAt\") VALUES ('role-harness-key', 'role-harness-hash', 'ROLE_HARNESS', NOW() + interval '1 hour'); UPDATE \"ActionIdempotencyKey\" SET \"action\" = 'ROLE_HARNESS_UPDATED' WHERE \"id\" = 'role-harness-key'; DELETE FROM \"ActionIdempotencyKey\" WHERE \"id\" = 'role-harness-key';"], "app role normal writes");
    result.appWrites = true;
    runPsqlExpectDenied(appDatabaseUrl, `CREATE ROLE ${quoteIdentifier(`${names.app}_forbidden`)}`, "app CREATEROLE probe");
    runPsqlExpectDenied(appDatabaseUrl, `CREATE DATABASE ${quoteIdentifier(`${databaseName}_forbidden`)}`, "app CREATEDB probe");
    const appOwnedProtected = scalar(
      appDatabaseUrl,
      `SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public' AND c.relname IN (${protectedTables.map((table) => `'${table}'`).join(",")}) AND c.relowner = (SELECT oid FROM pg_roles WHERE rolname = current_user)`,
      "app protected-table ownership probe",
    );
    if (Number(appOwnedProtected) !== 0) throw new Error("App role owns a protected table.");

    if (scalar(appDatabaseUrl, "SELECT current_user", "verify app role connection") !== names.app) {
      throw new Error("App role probe did not connect as the app role.");
    }
    if (scalar(rlsDatabaseUrl, "SELECT current_user", "verify RLS read role connection") !== names.rlsRead) {
      throw new Error("RLS read probe did not connect as the RLS read role.");
    }
    scalar(rlsDatabaseUrl, 'SELECT count(*) FROM "Batch"', "RLS read SELECT probe");
    for (const tableName of protectedTables) {
      for (const operation of ["INSERT", "UPDATE", "DELETE"]) {
        assertWriteProbeDenied(rlsDatabaseUrl, tableName, operation);
        result.rlsWriteProbesDenied += 1;
      }
    }
    if (result.rlsWriteProbesDenied !== 48) throw new Error("Expected all 48 RLS read write probes to be denied.");

    runPsql(
      migratorDatabaseUrl,
      ["-c", `BEGIN; SET LOCAL ROLE ${quoteIdentifier(names.owner)}; DROP TABLE "RoleSeparationHarnessMigration"; COMMIT;`],
      "remove disposable migration artifact before rollback",
    );
    runPsql(databaseUrl, [...templateVariables(names, previousOwner), "-f", rollbackPath], "rollback role-separation template");
    const remainingRoles = scalar(
      databaseUrl,
      `SELECT count(*) FROM pg_roles WHERE rolname IN ('${names.owner}', '${names.migrator}', '${names.app}', '${names.rlsRead}')`,
      "verify rollback role removal",
    );
    const restoredOwner = scalar(
      databaseUrl,
      `SELECT r.rolname FROM pg_class c JOIN pg_roles r ON r.oid = c.relowner WHERE c.oid = 'public."Batch"'::regclass`,
      "verify rollback ownership",
    );
    if (Number(remainingRoles) !== 0 || restoredOwner !== previousOwner) throw new Error("Role-separation rollback did not restore disposable ownership.");
    result.rollbackVerified = true;
    return result;
  } finally {
    if (databaseCreated) {
      runPsql(adminDatabaseUrl, ["-c", `DROP DATABASE IF EXISTS ${quoteIdentifier(databaseName)} WITH (FORCE)`], "drop disposable role-separation database");
    }
  }
};

const main = async () => {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    console.log(`Usage: ${path.basename(process.argv[1])} --admin-database-url <local-disposable-postgres-url> [--json]`);
    return;
  }
  const result = await runHarness(args);
  if (args.json) console.log(JSON.stringify({ ...result, roles: Object.keys(result.roles).sort() }, null, 2));
  else console.log(`Role-separation disposable harness passed: migrations=${result.migrationApplied} appWrites=${result.appWrites} deniedWriteProbes=${result.rlsWriteProbesDenied} rollback=${result.rollbackVerified}`);
};

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(error instanceof Error ? error.message : error);
    process.exit(1);
  });
}
