import assert from "node:assert/strict";
import fs from "node:fs";
import { createRequire } from "node:module";
import test from "node:test";
import {
  RUNTIME_IDENTITY_BEGIN,
  RUNTIME_IDENTITY_END,
  compensateEcsCutoverFailure,
  parseRuntimeIdentityProof,
  runtimeIdentityCommand,
} from "../lib/staging-database-role-credentials-core.mjs";

const require = createRequire(import.meta.url);
const probe = require("../../backend/scripts/runtimeDatabaseIdentity.js");
const expectedBlock = "MSCQR_DB_IDENTITY_BEGIN\n{\"database_name\":\"mscqr_staging\",\"database_user\":\"mscqr_staging_app\"}\nMSCQR_DB_IDENTITY_END\n";

test("runtime identity script is packaged by the backend runtime image", () => {
  assert.equal(fs.existsSync("backend/scripts/runtimeDatabaseIdentity.js"), true);
  const dockerfile = fs.readFileSync("backend/Dockerfile", "utf8");
  assert.match(dockerfile, /COPY --chown=node:node backend\/scripts \.\/scripts/);
});

test("ECS Exec command directly invokes the versioned runtime script", () => {
  assert.equal(probe.BEGIN, RUNTIME_IDENTITY_BEGIN);
  assert.equal(probe.END, RUNTIME_IDENTITY_END);
  assert.equal(runtimeIdentityCommand(), "node /app/scripts/runtimeDatabaseIdentity.js");
  assert.doesNotMatch(runtimeIdentityCommand(), /node\s+-e|['"`]/);
});

test("active-image preflight accepts only the expected admin identity", () => {
  const adminBlock = `${RUNTIME_IDENTITY_BEGIN}\n{\"database_name\":\"mscqr_staging\",\"database_user\":\"mscqr_staging_admin\"}\n${RUNTIME_IDENTITY_END}\n`;
  assert.deepEqual(
    parseRuntimeIdentityProof({ status: 0, stdout: adminBlock, stderr: "" }, { expectedUser: "mscqr_staging_admin" }),
    { databaseName: "mscqr_staging", databaseUser: "mscqr_staging_admin" },
  );
  assert.throws(() => parseRuntimeIdentityProof({ status: 0, stdout: adminBlock, stderr: "" }), (error) => error.code === "unexpected_user");
});

test("runtime identity script prints one exact stdout block and runs only the identity query", async () => {
  const queries = [];
  let stdout = "";
  let stderr = "";
  const exitCode = await probe.runRuntimeDatabaseIdentity({
    clientFactory: () => ({
      $queryRawUnsafe: async (sql) => { queries.push(sql); return [{ database_name: "mscqr_staging", database_user: "mscqr_staging_app" }]; },
      $disconnect: async () => {},
    }),
    stdout: { write: (value) => { stdout += value; } },
    stderr: { write: (value) => { stderr += value; } },
  });
  assert.equal(exitCode, 0);
  assert.equal(stdout, expectedBlock);
  assert.equal(stderr, "");
  assert.deepEqual(queries, ["SELECT current_database() AS database_name, current_user AS database_user"]);
});

test("missing runtime identity script output fails preflight before mutation", () => {
  assert.throws(
    () => parseRuntimeIdentityProof({ status: 0, stdout: "", stderr: "Cannot find module at reviewed runtime path" }),
    (error) => error.code === "delimiters_missing" && !error.message.includes("Cannot find module"),
  );
});

test("runtime identity script command failure is sanitized", () => {
  assert.throws(
    () => parseRuntimeIdentityProof({ status: 2, stdout: "", stderr: "unsanitized transport failure fixture" }),
    (error) => error.code === "command_failed" && !error.message.includes("transport failure fixture"),
  );
});

test("runtime identity script suppresses errors and stack traces", async () => {
  let stdout = "";
  let stderr = "";
  const exitCode = await probe.runRuntimeDatabaseIdentity({
    clientFactory: () => { throw new Error("credential-bearing internal failure"); },
    stdout: { write: (value) => { stdout += value; } },
    stderr: { write: (value) => { stderr += value; } },
  });
  assert.equal(exitCode, 2);
  assert.equal(stdout, "");
  assert.equal(stderr, '{"status":"blocked","code":"runtime_identity_probe_failed"}\n');
  assert.doesNotMatch(stderr, /credential|stack|database_url|postgres(?:ql)?:\/\//i);
});

test("preflight proof runs before task registration and post-deployment failure still rolls back", async () => {
  const source = fs.readFileSync("scripts/aws/staging-database-role-credentials.mjs", "utf8");
  const preflightIndex = source.indexOf("runtimeIdentity(C.runtimeAdminRole)");
  const registrationIndex = source.indexOf('"register-task-definition"');
  assert(preflightIndex > 0 && registrationIndex > preflightIndex);
  let rollbackCalls = 0;
  const failure = await compensateEcsCutoverFailure({
    error: Object.assign(new Error("sanitized"), { code: "delimiters_missing" }),
    serviceUpdated: true,
    rollback: async () => { rollbackCalls += 1; },
  });
  assert.deepEqual(failure, { failureClassification: "delimiters_missing", rollbackResult: "restored" });
  assert.equal(rollbackCalls, 1);
});
