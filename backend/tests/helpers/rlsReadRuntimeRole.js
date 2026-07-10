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
        NOBYPASSRLS;
      GRANT CONNECT ON DATABASE ${databaseName} TO ${role};
      GRANT USAGE ON SCHEMA public TO ${role};
    `,
  ]);
  return roleName;
};

const applyCandidateRls = (databaseUrl, runtimeRoleName) => {
  runPsql(databaseUrl, ["-v", `mscqr_runtime_role=${runtimeRoleName}`, "-f", candidateSqlPath]);
};

const rollbackCandidateRls = (databaseUrl, runtimeRoleName) => {
  runPsql(databaseUrl, ["-v", `mscqr_runtime_role=${runtimeRoleName}`, "-f", rollbackSqlPath]);
};

const dropRestrictedRlsReadRole = (databaseUrl, roleName) => {
  if (!roleName) return;
  const role = quoteIdent(roleName);
  runPsql(databaseUrl, ["-c", `DROP OWNED BY ${role}; DROP ROLE IF EXISTS ${role};`]);
};

module.exports = {
  applyCandidateRls,
  buildRoleUrl,
  createRestrictedRlsReadRole,
  dropRestrictedRlsReadRole,
  rollbackCandidateRls,
};
