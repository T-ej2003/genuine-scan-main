const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const path = require("node:path");

const repoRoot = path.resolve(__dirname, "../../..");
const candidateSqlPath = path.join(
  repoRoot,
  "documents/security/mscqr_staging_rls_candidate_templates_2026-07-09.sql"
);
const rollbackSqlPath = path.join(
  repoRoot,
  "documents/security/mscqr_staging_rls_candidate_rollback_2026-07-09.sql"
);

const quoteIdent = (value) => {
  assert.match(value, /^[a-z0-9_]+$/i, "Unsafe PostgreSQL identifier");
  return `"${value.replace(/"/g, '""')}"`;
};

const parseDatabaseName = (databaseUrl) => {
  const parsed = new URL(databaseUrl);
  const databaseName = decodeURIComponent(parsed.pathname.replace(/^\//, ""));
  assert(databaseName, "Disposable PostgreSQL URL must include a database name");
  return databaseName;
};

const buildRoleUrl = (databaseUrl, roleName) => {
  const parsed = new URL(databaseUrl);
  parsed.username = roleName;
  parsed.password = "";
  parsed.searchParams.set("connection_limit", "1");
  return parsed.toString();
};

const runPsql = (databaseUrl, args) => {
  execFileSync("psql", [databaseUrl, "-v", "ON_ERROR_STOP=1", ...args], {
    cwd: repoRoot,
    env: { ...process.env },
    stdio: "inherit",
  });
};

const createRestrictedRlsReadRole = (databaseUrl, prefix) => {
  assert.match(prefix, /^[a-z0-9_]+$/i, "Unsafe PostgreSQL role prefix");
  const roleName = `${prefix}_${process.pid}_${Date.now()}`.toLowerCase();
  const role = quoteIdent(roleName);
  const appRole = quoteIdent(`${roleName}_app`);
  const databaseName = quoteIdent(parseDatabaseName(databaseUrl));
  runPsql(databaseUrl, [
    "-c",
    `
      DROP ROLE IF EXISTS ${role};
      CREATE ROLE ${role}
        LOGIN
        NOSUPERUSER
        NOCREATEDB
        NOCREATEROLE
        NOREPLICATION
        NOBYPASSRLS
        NOINHERIT;
      CREATE ROLE ${appRole}
        LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT;
      GRANT CONNECT ON DATABASE ${databaseName} TO ${role}, ${appRole};
      GRANT USAGE ON SCHEMA public TO ${role}, ${appRole};
      REVOKE CREATE ON SCHEMA public FROM ${role}, ${appRole};
      GRANT SELECT ON TABLE "Organization", "Licensee", "User", "ManufacturerLicenseeLink", "Batch", "InventoryStatusRollup", "QRCode", "PrintJob", "PrintSession", "PrintItem", "PrinterRegistration", "Printer", "PrinterAttestation", "PrinterAgentSession", "PrinterProfile", "PrinterProfileSnapshot" TO ${role};
      GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ${appRole};
    `,
  ]);
  return roleName;
};

const applyCandidateRls = (databaseUrl, runtimeRoleName) => {
  runPsql(databaseUrl, [
    "-v", `mscqr_app_role=${runtimeRoleName}_app`,
    "-v", `mscqr_rls_read_role=${runtimeRoleName}`,
    "-v", `mscqr_auth_owner_role=${runtimeRoleName}_auth_owner`,
    "-v", "mscqr_enable_shared_force_rls=true",
    "-v", "mscqr_enable_batch_force_rls=true",
    "-v", "mscqr_enable_printer_force_rls=true",
    "-f", candidateSqlPath,
  ]);
};

const rollbackCandidateRls = (databaseUrl, runtimeRoleName) => {
  runPsql(databaseUrl, [
    "-v", `mscqr_app_role=${runtimeRoleName}_app`,
    "-v", `mscqr_rls_read_role=${runtimeRoleName}`,
    "-v", `mscqr_auth_owner_role=${runtimeRoleName}_auth_owner`,
    "-f", rollbackSqlPath,
  ]);
};

const dropRestrictedRlsReadRole = (databaseUrl, roleName) => {
  if (!roleName) return;
  const role = quoteIdent(roleName);
  const appRole = quoteIdent(`${roleName}_app`);
  runPsql(databaseUrl, ["-c", `DROP OWNED BY ${appRole}; DROP OWNED BY ${role}; DROP ROLE IF EXISTS ${appRole}; DROP ROLE IF EXISTS ${role};`]);
};

module.exports = {
  applyCandidateRls,
  buildRoleUrl,
  createRestrictedRlsReadRole,
  dropRestrictedRlsReadRole,
  rollbackCandidateRls,
};
