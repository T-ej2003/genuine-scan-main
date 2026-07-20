import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import test from "node:test";

const disabledModes = JSON.parse(fs.readFileSync("documents/security/rls-program/staging-full-rls-executor-contract.json", "utf8")).disabledFullRlsModes;

test("blue executor rejects full-RLS process modes before PostgreSQL client construction", () => {
  for (const mode of disabledModes) {
    const result = spawnSync(process.execPath, ["backend/scripts/staging-database-role-vpc-executor.mjs"], {
      encoding: "utf8",
      env: { ...process.env, MSCQR_VPC_EXECUTOR_MODE: mode, DATABASE_URL: "" },
    });
    const output = `${result.stdout}\n${result.stderr}`;
    assert.notEqual(result.status, 0, mode);
    assert.match(output, /Full-RLS execution is disabled on the blue staging executor/, mode);
    assert.doesNotMatch(output, /DATABASE_URL is unavailable|Prisma|connect|ECONNREFUSED/i, mode);
  }
});
