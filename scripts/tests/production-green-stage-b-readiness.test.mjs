import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { assertStageBProductionReadiness } from "../aws/check-stage-b-production-readiness.mjs";

const sha = "a".repeat(40);
const matrixPath = path.resolve(process.cwd(), "documents/ops/iam/MSCQRProductionGreenStageBReadinessMatrix-v1.json");
const makeInputs = () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-readiness-test-"));
  fs.chmodSync(directory, 0o700);
  const run = (file, args) => {
    if (file === "git" && args[0] === "rev-parse" && args[1] === "HEAD") return sha;
    if (file === "git" && args[0] === "status") return "";
    if (file === "git" && args[0] === "rev-parse" && args[1] === "--is-shallow-repository") return "false";
    if (file === "terraform") return JSON.stringify({ terraform_version: "1.15.7" });
    return file === "npm" ? "11.0.0" : `${file} 1.0.0`;
  };
  return { protectedSha: sha, artifactParent: directory, backendConfigPath: path.join(directory, "backend.hcl"), cwd: process.cwd(), env: { AWS_REGION: "eu-west-2" }, run, spawnTerraform: () => ({ status: 0, signal: null }), checkImports: async () => {} , cleanup: () => fs.rmSync(directory, { recursive: true, force: true }) };
};

test("readiness checks complete before the evidence clock starts", async () => {
  const input = makeInputs();
  try { const result = await assertStageBProductionReadiness(input); assert.equal(result.status, "READY"); assert.equal(result.terraform, "1.15.7"); } finally { input.cleanup(); }
});

test("readiness rejects a pre-existing backend output", async () => {
  const input = makeInputs();
  try { fs.writeFileSync(input.backendConfigPath, "backend", { mode: 0o600 }); await assert.rejects(assertStageBProductionReadiness(input), /must not exist/); } finally { input.cleanup(); }
});

test("readiness rejects unsupported Terraform and region contracts", async () => {
  const unsupported = makeInputs();
  const validRun = unsupported.run;
  try { unsupported.run = (file, args, cwd, env) => file === "terraform" ? JSON.stringify({ terraform_version: "2.0.0" }) : validRun(file, args, cwd, env); await assert.rejects(assertStageBProductionReadiness(unsupported), /outside the supported/); } finally { unsupported.cleanup(); }
  const wrongRegion = makeInputs();
  try { wrongRegion.env.AWS_REGION = "us-east-1"; await assert.rejects(assertStageBProductionReadiness(wrongRegion), /eu-west-2/); } finally { wrongRegion.cleanup(); }
});

test("readiness matrix is complete and uses only the source-controlled status vocabulary", () => {
  const matrix = JSON.parse(fs.readFileSync(matrixPath, "utf8"));
  const requiredFields = ["id", "phase", "requirement", "sourceOfTruth", "producer", "consumer", "inputs", "outputs", "identity", "freshness", "hashBinding", "signatureBinding", "expectedResourceActions", "failClosedBehavior", "testCoverage", "ciCoverage", "implementationStatus", "gap", "remediation"];
  assert.equal(matrix.schemaVersion, 1);
  assert.ok(Array.isArray(matrix.rows) && matrix.rows.length >= 20);
  assert.ok(new Set(matrix.rows.map((row) => row.id)).size === matrix.rows.length);
  for (const row of matrix.rows) {
    for (const field of requiredFields) assert.ok(Object.hasOwn(row, field), `${row.id} missing ${field}`);
    assert.ok(matrix.statusVocabulary.includes(row.implementationStatus), `${row.id} has unsupported status`);
    assert.ok(typeof row.requirement === "string" && row.requirement.length > 0);
  }
  const semantic = matrix.rows.find((row) => row.id === "PLAN-SEM-01");
  assert.equal(semantic?.implementationStatus, "SATISFIED");
  assert.match(semantic?.ciCoverage || "", /test:production-green-stage-b-control-plane/);
});
