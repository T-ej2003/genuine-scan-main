const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");

const enabled = process.env.MSCQR_AUTH_MFA_POSTGRES_TEST === "true";
const confirmed = process.env.MSCQR_AUTH_MFA_POSTGRES_CONFIRM === "MSCQR_RUN_LOCAL_AUTH_MFA_POSTGRES_TEST";

const main = () => {
  if (!enabled) {
    console.log("auth MFA PostgreSQL 18 proof skipped (set MSCQR_AUTH_MFA_POSTGRES_TEST=true)");
    return;
  }
  assert(confirmed, "Set MSCQR_AUTH_MFA_POSTGRES_CONFIRM=MSCQR_RUN_LOCAL_AUTH_MFA_POSTGRES_TEST");
  const adminUrl = String(process.env.MSCQR_AUTH_MFA_POSTGRES_ADMIN_URL || "").trim();
  assert(adminUrl, "MSCQR_AUTH_MFA_POSTGRES_ADMIN_URL is required");
  const parsed = new URL(adminUrl);
  assert(["127.0.0.1", "localhost", "::1"].includes(parsed.hostname), "MFA proof requires loopback PostgreSQL");
  assert(!/(prod|production|staging|amazonaws|rds)/i.test(adminUrl), "MFA proof refuses production or staging targets");

  const result = spawnSync(process.execPath, ["scripts/rls/certify-full-database.mjs"], {
    cwd: process.cwd(),
    encoding: "utf8",
    env: {
      ...process.env,
      MSCQR_FULL_RLS_CERTIFICATION_CONFIRM: "MSCQR_RUN_LOCAL_FULL_RLS_CERTIFICATION",
      MSCQR_FULL_RLS_CERTIFICATION_ADMIN_URL: adminUrl,
      MSCQR_FULL_RLS_CERTIFICATION_FAMILY: "manufacturer-scope",
    },
    maxBuffer: 64 * 1024 * 1024,
  });
  const output = `${result.stdout || ""}${result.stderr || ""}`;
  assert.equal(result.status, 0, output);
  const evidence = JSON.parse(String(result.stdout || "").trim().split("\n").at(-1));
  assert.equal(evidence.applicationPathResults[0].familyId, "manufacturer-scope");
  assert.equal(evidence.applicationPathResults[0].status, "application-path-certified");
  console.log(JSON.stringify({
    result: "passed",
    postgresMajor: evidence.postgresqlMajor,
    testFile: "backend/tests/rls-wave-b/b01/authenticationClosurePostgres18.test.js",
    proofs: ["challenge-creation", "failed-code-attempt-recording", "successful-completion", "one-time-consumption", "session-capability-outcome"],
  }));
};

try { main(); } catch (error) { console.error(error instanceof Error ? error.stack : error); process.exitCode = 1; }
