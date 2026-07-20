import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { BLUE_EXECUTOR_MODES, MUTATING_MODE_CONFIRMATIONS, validateBrokerEvent } from "../../infra/terraform/staging-api/lambda/database-role-executor-broker/index.mjs";

const contractPath = "documents/security/rls-program/staging-full-rls-executor-contract.json";
const contract = JSON.parse(fs.readFileSync(contractPath, "utf8"));

test("executor contract reserves full RLS for a separate fresh green database", () => {
  assert.equal(contract.schemaVersion, 2);
  assert.equal(contract.environment, "staging");
  assert.equal(contract.status, "blue-executor-full-rls-disabled");
  assert.equal(contract.deploymentModel, "blue-green-clean-room");
  assert.equal(contract.blueExecutor.database, "mscqr_staging");
  assert.equal(contract.blueExecutor.fullRlsMutationAllowed, false);
  assert.equal(contract.futureGreenExecutor.implemented, false);
  assert.equal(contract.futureGreenExecutor.targetMustBeFresh, true);
  assert.equal(contract.futureGreenExecutor.managedRolesMustBeNew, true);
  assert.equal(contract.futureGreenExecutor.separateTaskDefinitionRequired, true);
  assert.equal(contract.futureGreenExecutor.separateAdministrativeSecretRequired, true);
  assert(!Object.hasOwn(contract, "roles"));
  assert(!Object.hasOwn(contract, "roleAttributes"));
  assert(!Object.hasOwn(contract, "administratorMembership"));
});

test("blue broker rejects every contract-disabled full-RLS mode", () => {
  assert.equal(contract.disabledFullRlsModes.length, 8);
  assert.equal(new Set(contract.disabledFullRlsModes).size, contract.disabledFullRlsModes.length);
  for (const mode of contract.disabledFullRlsModes) {
    assert.throws(() => validateBrokerEvent({ mode }), /outside the reviewed executor set/);
  }
});

test("contract and broker agree on every preserved blue mode", () => {
  assert.deepEqual(contract.blueExecutor.allowedModes, ["probe", "provision", "verify", "rls-shared-apply", "rls-shared-verify", "rls-shared-rollback"]);
  assert.deepEqual(BLUE_EXECUTOR_MODES, contract.blueExecutor.allowedModes);
  for (const mode of contract.blueExecutor.allowedModes) {
    const confirmation = MUTATING_MODE_CONFIRMATIONS[mode];
    assert.equal(validateBrokerEvent({ mode, ...(confirmation ? { confirmation } : {}) }), mode);
  }
});

test("blue executor contains only the generic early rejection guard", () => {
  const source = fs.readFileSync("backend/scripts/staging-database-role-vpc-executor.mjs", "utf8");
  assert.match(source, /assertBlueExecutorModeAllowed\(MODE\)/);
  assert.equal(source.match(/full-rls-/g)?.length, 1);
  assert.doesNotMatch(source, /FULL_RLS|inspectFullRls|runFullRls|createFullRls|mscqr_staging_(?:preauth|worker|scheduled|migration|operator)/);
});

test("blue broker and Terraform contain no full-RLS modes, credentials, or package bindings", () => {
  const broker = fs.readFileSync("infra/terraform/staging-api/lambda/database-role-executor-broker/index.mjs", "utf8");
  const terraform = fs.readFileSync("infra/terraform/staging-api/main.tf", "utf8");
  for (const source of [broker, terraform]) {
    assert.doesNotMatch(source, /MSCQR_FULL_RLS|BROKER_PACKAGE_CHECKSUM|packageChecksumSha256|full-rls-(?:capability|role|admin|runtime|verification|rollback)|database-url\/(?:preauth|worker|scheduled|migration|operator)/);
  }
});
