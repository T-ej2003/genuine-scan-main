import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { classifyStageBPlan, STAGE_B_RESOURCE_ACTION_MATRIX } from "./stage-b-deployment-contract.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const terraformRoot = path.join(root, "infra/aws/terraform/production-green-stage-b");
const matrixPath = path.join(root, "documents/ops/iam/MSCQRProductionGreenStageBDeploymentClosure-v1.json");
const fixturePath = path.join(root, "scripts/tests/fixtures/production-green-stage-b-production-shaped.plan.json");

function filesUnder(directory) {
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const full = path.join(directory, entry.name);
    return entry.isDirectory() ? filesUnder(full) : [full];
  });
}

const matrix = JSON.parse(fs.readFileSync(matrixPath, "utf8"));
const fixture = JSON.parse(fs.readFileSync(fixturePath, "utf8"));
assert.equal(matrix.schemaVersion, 1, "Stage B closure matrix schema is unsupported.");
assert.equal(matrix.account, "368992683803");
assert.equal(matrix.region, "eu-west-2");
assert.equal(matrix.zeroDestroy, true);
for (const entry of matrix.resources) for (const action of entry.actions) assert(Array.isArray(matrix.actionLifecycle[action]), `Matrix action has no lifecycle contract: ${action}`);
assert.deepEqual(matrix.actionLifecycle.delete, []);
assert.deepEqual(matrix.actionLifecycle.replacement, []);

const declarations = filesUnder(terraformRoot)
  .filter((file) => file.endsWith(".tf"))
  .flatMap((file) => [...fs.readFileSync(file, "utf8").matchAll(/^resource\s+"([^"]+)"\s+"([^"]+)"\s*\{/gm)]
    .map((match) => `${match[1]}.${match[2]}`));
const matrixBases = matrix.resources.map((entry) => entry.addressPattern.split("[")[0]);
for (const declaration of declarations) assert(matrixBases.includes(declaration), `Terraform resource has no closure matrix entry: ${declaration}`);
for (const contractPattern of Object.keys(STAGE_B_RESOURCE_ACTION_MATRIX)) {
  const base = contractPattern.split("[")[0];
  assert(matrixBases.includes(base), `Shared classifier contract has no closure matrix entry: ${base}`);
}

const classified = classifyStageBPlan(fixture, { strict: false });
assert.deepEqual(classified.actionCounts, { "no-op": 58, create: 12, update: 3 });
assert.deepEqual(classified.unclassifiedResources, []);
assert.equal(fixture.resource_changes.length, 73);
assert(!fixture.resource_changes.some((change) => (change.change?.actions || []).some((action) => ["delete", "create-delete", "replace"].includes(action))), "Closure fixture contains a destructive action.");
assert.equal(matrix.resources.every((entry) => entry.layers.includes("plan-validator") && entry.layers.includes("apply-wrapper")), true);

const executableFiles = filesUnder(path.join(root, "scripts"))
  .filter((file) => file.endsWith(".mjs") && !file.includes(`${path.sep}tests${path.sep}`) && !file.endsWith("production-green-stage-b-contract.mjs") && !file.endsWith("stage-b-deployment-contract.mjs"));
const brokerPolicyLiteral = ["arn:aws:iam::368992683803:policy/mscqr-production-rls-approval-", "broker-runtime"].join("");
const duplicateBrokerPolicyLiterals = executableFiles.filter((file) => fs.readFileSync(file, "utf8").includes(brokerPolicyLiteral));
assert.deepEqual(duplicateBrokerPolicyLiterals, [], `Executable broker policy ARN duplicates found: ${duplicateBrokerPolicyLiterals.join(", ")}`);

process.stdout.write(JSON.stringify({
  status: "valid",
  matrixResources: matrix.resources.length,
  terraformDeclarations: declarations.length,
  fixtureResources: fixture.resource_changes.length,
  classifiedResources: classified.classifiedResources.length,
  actionCounts: classified.actionCounts,
  unclassifiedResources: classified.unclassifiedResources,
}, null, 2) + "\n");
