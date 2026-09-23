import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { cleanRoomSourcePaths, calculateCleanRoomSourceContract } from "../rls/lib/clean-room-source-contract.mjs";

const bootstrap = "backend/src/rls-waves/session-c/c04/bootstrapConfiguredSuperAdmin.sql";
const operators = "backend/src/rls-waves/session-c/c04/operatorProcedures.sql";
const operatorRollback = "backend/src/rls-waves/session-c/c04/operatorProceduresRollback.sql";
const rolloutClassifier = "scripts/aws/exact-ecs-rollout-state.mjs";
const root = process.cwd();

const copyContractInputs = (target) => {
  for (const relative of cleanRoomSourcePaths) {
    const source = path.join(root, relative); const destination = path.join(target, relative);
    fs.mkdirSync(path.dirname(destination), { recursive: true }); fs.copyFileSync(source, destination);
  }
  const migrations = path.join(root, "backend/prisma/migrations");
  for (const entry of fs.readdirSync(migrations, { withFileTypes: true }).filter((entry) => entry.isDirectory())) {
    const destination = path.join(target, "backend/prisma/migrations", entry.name);
    fs.mkdirSync(destination, { recursive: true }); fs.copyFileSync(path.join(migrations, entry.name, "migration.sql"), path.join(destination, "migration.sql"));
  }
};

test("security-sensitive runtime and initial-admin sources bind the clean-room source contract", (t) => {
  for (const relative of [bootstrap, operators, operatorRollback, rolloutClassifier]) assert(cleanRoomSourcePaths.includes(relative));
  const fixture = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-source-contract-")); t.after(() => fs.rmSync(fixture, { recursive: true, force: true }));
  copyContractInputs(fixture);
  const baseline = calculateCleanRoomSourceContract(fixture).sourceContractSha256;
  const generated = JSON.parse(fs.readFileSync("documents/security/rls-program/generated/full-rls-implementation-manifest.json", "utf8"));
  assert.equal(generated.sourceContractSha256, baseline);
  assert.equal(calculateCleanRoomSourceContract(fixture).sourceContractSha256, baseline);
  for (const relative of [bootstrap, operators, operatorRollback, rolloutClassifier]) {
    const candidate = path.join(fixture, relative);
    fs.appendFileSync(candidate, `\n-- contract mutation ${crypto.randomUUID()}\n`);
    assert.notEqual(calculateCleanRoomSourceContract(fixture).sourceContractSha256, generated.sourceContractSha256);
    fs.copyFileSync(path.join(root, relative), candidate);
  }
  assert.equal(calculateCleanRoomSourceContract(fixture).sourceContractSha256, baseline);
});
