import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { gzipSync } from "node:zlib";
import { buildInstallationAuthorizationDispatch, runInstallationAuthorizationDispatchCli } from "../aws/dispatch-production-initial-activation-reconciler-installation.mjs";
import { decodeWorkflowDispatchGzip, encodeWorkflowDispatchGzip, MAX_DECOMPRESSED_WORKFLOW_DISPATCH_BYTES, measureWorkflowDispatchInputs, WORKFLOW_DISPATCH_INTERNAL_BUDGET, WORKFLOW_DISPATCH_PLATFORM_LIMIT } from "../aws/workflow-dispatch-gzip-transport.mjs";
import { createInstallationPreparation, stateIdentity } from "../aws/production-initial-activation-reconciler-installation-contract.mjs";
import { currentInstallationPlan } from "./fixtures/production-initial-activation-reconciler-plan-current.mjs";
import { historicalInstallationPreparationGzipBase64 } from "./fixtures/initial-activation-reconciler-installation-preparation-393469a.mjs";

const preparationSha256 = "216847636cc790929abb5d45cadc45f89e96457f25677d4eec901ed354bc00b8";
const semanticSha256 = "74a84a6c9f7786412aee3bfdbd7d4c459d2508023c6e609783682da86ebcd8a6";
const sha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const preparationBytes = decodeWorkflowDispatchGzip(historicalInstallationPreparationGzipBase64, preparationSha256, { label: "Installation preparation artifact" });
const currentSourceSha = "a".repeat(40);
const currentPlan = currentInstallationPlan(JSON.parse(fs.readFileSync("scripts/tests/fixtures/production-initial-activation-reconciler-plan-absent.json", "utf8")));
const currentSavedPlanBytes = Buffer.from("current exact installation plan");
const currentPreparationBytes = Buffer.from(`${JSON.stringify(createInstallationPreparation({ sourceSha: currentSourceSha, state: stateIdentity(undefined), livePredecessor: "ABSENT", livePredecessorAddresses: [], planJson: currentPlan, planBytes: currentSavedPlanBytes, preparedAt: "2026-09-27T12:00:00.000Z" }))}\n`);

test("historical installation preparation uses deterministic bounded byte-exact transport", () => {
  assert.equal(preparationBytes.length, 53_880);
  assert.equal(sha256(preparationBytes), preparationSha256);
  assert.equal(JSON.parse(preparationBytes).preparationArtifactSha256, semanticSha256);
  assert.equal(encodeWorkflowDispatchGzip(preparationBytes, { label: "Installation preparation artifact" }), historicalInstallationPreparationGzipBase64);
  assert.deepEqual(decodeWorkflowDispatchGzip(historicalInstallationPreparationGzipBase64, preparationSha256, { label: "Installation preparation artifact" }), preparationBytes);
});

test("bounded gzip transport rejects altered, noncanonical, truncated, trailing, oversized, and wrong-hash inputs", () => {
  const compressed = Buffer.from(historicalInstallationPreparationGzipBase64, "base64");
  const altered = Buffer.from(compressed); altered[Math.floor(altered.length / 2)] ^= 1;
  for (const encoded of [altered.toString("base64"), historicalInstallationPreparationGzipBase64.slice(0, -4), `${historicalInstallationPreparationGzipBase64} `, "not+base64!", Buffer.concat([compressed, Buffer.from([0])]).toString("base64"), Buffer.concat([compressed, compressed]).toString("base64")]) {
    assert.throws(() => decodeWorkflowDispatchGzip(encoded, preparationSha256, { label: "Installation preparation artifact" }), /base64|invalid|SHA-256/);
  }
  assert.throws(() => decodeWorkflowDispatchGzip(historicalInstallationPreparationGzipBase64, "0".repeat(64), { label: "Installation preparation artifact" }), /SHA-256/);
  const oversized = Buffer.alloc(MAX_DECOMPRESSED_WORKFLOW_DISPATCH_BYTES + 1, 0x78);
  assert.throws(() => encodeWorkflowDispatchGzip(oversized), /decompressed limit/);
  assert.throws(() => decodeWorkflowDispatchGzip(gzipSync(oversized, { level: 9 }).toString("base64"), sha256(oversized)), /decompressed limit/);
});

test("current source-bound installation preparation fits the complete dispatch payload budget", () => {
  const dispatch = buildInstallationAuthorizationDispatch({ sourceSha: currentSourceSha, preparationBytes: currentPreparationBytes, savedPlanBytes: currentSavedPlanBytes });
  assert.equal(dispatch.preparationFileSha256, sha256(currentPreparationBytes));
  assert.equal(dispatch.preparationArtifactSha256, JSON.parse(currentPreparationBytes).preparationArtifactSha256);
  assert.equal(dispatch.savedPlanSha256, sha256(currentSavedPlanBytes));
  assert.ok(dispatch.payload.characters < WORKFLOW_DISPATCH_INTERNAL_BUDGET);
  assert.ok(WORKFLOW_DISPATCH_INTERNAL_BUDGET < WORKFLOW_DISPATCH_PLATFORM_LIMIT);
  assert.deepEqual(decodeWorkflowDispatchGzip(dispatch.inputs.preparation_artifact_gzip_base64, dispatch.inputs.preparation_artifact_sha256, { label: "Installation preparation artifact" }), currentPreparationBytes);
  assert.deepEqual(Buffer.from(dispatch.inputs.saved_plan_base64, "base64"), currentSavedPlanBytes);
});

test("dispatch rejects wrong source and any saved-plan byte change", () => {
  assert.throws(() => buildInstallationAuthorizationDispatch({ sourceSha: "0".repeat(40), preparationBytes: currentPreparationBytes, savedPlanBytes: currentSavedPlanBytes }), /identity or hash/);
  assert.throws(() => buildInstallationAuthorizationDispatch({ sourceSha: currentSourceSha, preparationBytes: currentPreparationBytes, savedPlanBytes: Buffer.concat([currentSavedPlanBytes, Buffer.from([0])]) }), /saved plan bytes changed/);
});

test("complete serialized dispatch input budget passes at 60000 and fails at 60001", () => {
  const overhead = JSON.stringify({ exact: "" }).length;
  const exact = { exact: "x".repeat(WORKFLOW_DISPATCH_INTERNAL_BUDGET - overhead) };
  assert.equal(measureWorkflowDispatchInputs(exact).characters, WORKFLOW_DISPATCH_INTERNAL_BUDGET);
  assert.throws(() => measureWorkflowDispatchInputs({ exact: `${exact.exact}x` }), /internal budget/);
});

test("dispatch CLI authenticates local artifacts and invokes only the exact workflow", (context) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "installation-dispatch-"));
  fs.chmodSync(directory, 0o700);
  context.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const preparation = path.join(directory, "preparation.json"), plan = path.join(directory, "installation.tfplan");
  fs.writeFileSync(preparation, currentPreparationBytes, { mode: 0o600 }); fs.writeFileSync(plan, currentSavedPlanBytes, { mode: 0o600 });
  let invocation;
  const result = runInstallationAuthorizationDispatchCli(["--source-sha", currentSourceSha, "--preparation", preparation, "--saved-plan", plan], { protectedMain: () => {}, run: (command, args) => { invocation = { command, args }; } });
  assert.equal(invocation.command, "gh");
  assert.deepEqual(invocation.args.slice(0, 7), ["workflow", "run", ".github/workflows/authorize-production-initial-activation-policy-reconciler-installation.yml", "--repo", "T-ej2003/genuine-scan-main", "--ref", "main"]);
  assert.equal(result.preparationFileSha256, sha256(currentPreparationBytes)); assert.equal(result.savedPlanSha256, sha256(currentSavedPlanBytes)); assert.equal(result.dispatchCount, 1);
  assert.throws(() => runInstallationAuthorizationDispatchCli(["--source-sha", currentSourceSha, "--preparation", preparation, "--saved-plan", plan, "--extra", "x"], { protectedMain: () => {}, run: () => {} }), /arguments are not exact/);
});

test("workflow decompresses before unchanged authorization and exact-plan execution", () => {
  const workflow = fs.readFileSync(".github/workflows/authorize-production-initial-activation-policy-reconciler-installation.yml", "utf8");
  assert.match(workflow, /preparation_artifact_gzip_base64/);
  assert.doesNotMatch(workflow, /inputs\.preparation_artifact_base64/);
  assert.match(workflow, /decodeWorkflowDispatchGzip\(process\.env\.PREPARATION_ARTIFACT_GZIP_BASE64, process\.env\.PREPARATION_SHA256/);
  assert.match(workflow, /--preparation-file-sha256 "\$PREPARATION_SHA256"/);
  assert.match(workflow, /--plan-file-sha256 "\$SAVED_PLAN_SHA256"/);
  assert.match(workflow, /production-initial-activation-reconciler-bootstrap/);
});
