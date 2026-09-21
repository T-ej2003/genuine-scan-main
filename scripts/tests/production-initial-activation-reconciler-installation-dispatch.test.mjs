import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { gzipSync } from "node:zlib";
import { buildInstallationAuthorizationDispatch, runInstallationAuthorizationDispatchCli } from "../aws/dispatch-production-initial-activation-reconciler-installation.mjs";
import { decodeWorkflowDispatchGzip, encodeWorkflowDispatchGzip, MAX_DECOMPRESSED_WORKFLOW_DISPATCH_BYTES, measureWorkflowDispatchInputs, WORKFLOW_DISPATCH_INTERNAL_BUDGET, WORKFLOW_DISPATCH_PLATFORM_LIMIT } from "../aws/workflow-dispatch-gzip-transport.mjs";
import { historicalInstallationPreparationGzipBase64, historicalInstallationSavedPlanGzipBase64 } from "./fixtures/initial-activation-reconciler-installation-preparation-393469a.mjs";

const sourceSha = "393469a5e82924caaf2f876c539b2be3cb3b763d";
const preparationSha256 = "216847636cc790929abb5d45cadc45f89e96457f25677d4eec901ed354bc00b8";
const semanticSha256 = "74a84a6c9f7786412aee3bfdbd7d4c459d2508023c6e609783682da86ebcd8a6";
const savedPlanSha256 = "d8a3cf54f5cbfc79c3125e5cc95f06d61576f4e7f418a115b0d91c9e8b12e6d0";
const sha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const preparationBytes = decodeWorkflowDispatchGzip(historicalInstallationPreparationGzipBase64, preparationSha256, { label: "Installation preparation artifact" });
const savedPlanBytes = decodeWorkflowDispatchGzip(historicalInstallationSavedPlanGzipBase64, savedPlanSha256, { label: "Installation saved plan" });

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

test("real failed-dispatch shape now authenticates under the complete payload budget", () => {
  assert.equal(savedPlanBytes.length, 15_152);
  assert.equal(sha256(savedPlanBytes), savedPlanSha256);
  const dispatch = buildInstallationAuthorizationDispatch({ sourceSha, preparationBytes, savedPlanBytes });
  assert.equal(dispatch.preparationFileSha256, preparationSha256);
  assert.equal(dispatch.preparationArtifactSha256, semanticSha256);
  assert.equal(dispatch.savedPlanSha256, savedPlanSha256);
  assert.equal(dispatch.inputs.preparation_artifact_gzip_base64.length, 6_524);
  assert.equal(dispatch.inputs.saved_plan_base64.length, 20_204);
  assert.equal(dispatch.payload.characters, 27_030);
  assert.ok(dispatch.payload.characters < WORKFLOW_DISPATCH_INTERNAL_BUDGET);
  assert.ok(WORKFLOW_DISPATCH_INTERNAL_BUDGET < WORKFLOW_DISPATCH_PLATFORM_LIMIT);
  assert.deepEqual(decodeWorkflowDispatchGzip(dispatch.inputs.preparation_artifact_gzip_base64, dispatch.inputs.preparation_artifact_sha256, { label: "Installation preparation artifact" }), preparationBytes);
  assert.deepEqual(Buffer.from(dispatch.inputs.saved_plan_base64, "base64"), savedPlanBytes);
});

test("dispatch rejects wrong source and any saved-plan byte change", () => {
  assert.throws(() => buildInstallationAuthorizationDispatch({ sourceSha: "0".repeat(40), preparationBytes, savedPlanBytes }), /identity or hash/);
  assert.throws(() => buildInstallationAuthorizationDispatch({ sourceSha, preparationBytes, savedPlanBytes: Buffer.concat([savedPlanBytes, Buffer.from([0])]) }), /saved plan bytes changed/);
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
  fs.writeFileSync(preparation, preparationBytes, { mode: 0o600 }); fs.writeFileSync(plan, savedPlanBytes, { mode: 0o600 });
  let invocation;
  const result = runInstallationAuthorizationDispatchCli(["--source-sha", sourceSha, "--preparation", preparation, "--saved-plan", plan], { protectedMain: () => {}, run: (command, args) => { invocation = { command, args }; } });
  assert.equal(invocation.command, "gh");
  assert.deepEqual(invocation.args.slice(0, 7), ["workflow", "run", ".github/workflows/authorize-production-initial-activation-policy-reconciler-installation.yml", "--repo", "T-ej2003/genuine-scan-main", "--ref", "main"]);
  assert.equal(result.preparationFileSha256, preparationSha256); assert.equal(result.savedPlanSha256, savedPlanSha256); assert.equal(result.dispatchCount, 1);
  assert.throws(() => runInstallationAuthorizationDispatchCli(["--source-sha", sourceSha, "--preparation", preparation, "--saved-plan", plan, "--extra", "x"], { protectedMain: () => {}, run: () => {} }), /arguments are not exact/);
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
