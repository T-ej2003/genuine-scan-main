#!/usr/bin/env node
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { INSTALLATION, assertInstallationPreparation } from "./production-initial-activation-reconciler-installation-contract.mjs";
import { assertProtectedCheckout } from "./prepare-production-initial-activation-reconciler-installation.mjs";
import { readStageBPrivateFileBytes } from "./stage-b-artifact-contract.mjs";
import { encodeWorkflowDispatchGzip, measureWorkflowDispatchInputs } from "./workflow-dispatch-gzip-transport.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const sha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const option = (argv, name) => { const index = argv.indexOf(name); return index < 0 ? undefined : argv[index + 1]; };
const required = (argv, name) => { const value = option(argv, name); if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };

export function buildInstallationAuthorizationDispatch({ sourceSha, preparationBytes, savedPlanBytes } = {}) {
  if (!/^[a-f0-9]{40}$/.test(sourceSha || "")) throw new Error("Installation dispatch source SHA is invalid.");
  let preparation;
  try { preparation = JSON.parse(preparationBytes); } catch { throw new Error("Installation preparation artifact is not valid JSON."); }
  assertInstallationPreparation(preparation, { sourceSha, planBytes: savedPlanBytes });
  const preparationSha256 = sha256(preparationBytes);
  const savedPlanSha256 = sha256(savedPlanBytes);
  const savedPlanBase64 = savedPlanBytes.toString("base64");
  if (!savedPlanBytes.length || Buffer.from(savedPlanBase64, "base64").toString("base64") !== savedPlanBase64) throw new Error("Installation saved-plan transport is not canonical Base64.");
  const inputs = Object.freeze({
    source_sha: sourceSha,
    preparation_artifact_gzip_base64: encodeWorkflowDispatchGzip(preparationBytes, { label: "Installation preparation artifact" }),
    preparation_artifact_sha256: preparationSha256,
    saved_plan_base64: savedPlanBase64,
    saved_plan_sha256: savedPlanSha256,
  });
  const payload = measureWorkflowDispatchInputs(inputs, { label: "Installation authorization workflow_dispatch payload" });
  const args = ["workflow", "run", INSTALLATION.authorizationWorkflowPath, "--repo", INSTALLATION.repository, "--ref", "main", ...Object.entries(inputs).flatMap(([name, value]) => ["--raw-field", `${name}=${value}`])];
  return Object.freeze({ args: Object.freeze(args), inputs, payload, preparationArtifactSha256: preparation.preparationArtifactSha256, preparationFileSha256: preparationSha256, savedPlanSha256 });
}

export function runInstallationAuthorizationDispatchCli(argv = process.argv.slice(2), deps = {}) {
  const allowed = new Set(["--source-sha", "--preparation", "--saved-plan"]);
  if (argv.length !== allowed.size * 2 || argv.some((value, index) => index % 2 === 0 && !allowed.has(value)) || new Set(argv.filter((_, index) => index % 2 === 0)).size !== allowed.size) throw new Error("Installation dispatch arguments are not exact.");
  const sourceSha = required(argv, "--source-sha");
  (deps.protectedMain || assertProtectedCheckout)({ sourceSha, repositoryRoot: root });
  const preparationBytes = readStageBPrivateFileBytes({ filePath: path.resolve(required(argv, "--preparation")), repositoryRoot: root, label: "Installation preparation artifact" }).bytes;
  const savedPlanBytes = readStageBPrivateFileBytes({ filePath: path.resolve(required(argv, "--saved-plan")), repositoryRoot: root, label: "Installation saved Terraform plan" }).bytes;
  const dispatch = buildInstallationAuthorizationDispatch({ sourceSha, preparationBytes, savedPlanBytes });
  (deps.run || execFileSync)("gh", dispatch.args, { cwd: root, encoding: "utf8", stdio: "inherit" });
  return Object.freeze({ sourceSha, preparationArtifactSha256: dispatch.preparationArtifactSha256, preparationFileSha256: dispatch.preparationFileSha256, savedPlanSha256: dispatch.savedPlanSha256, workflowDispatchPayloadCharacters: dispatch.payload.characters, dispatchCount: 1 });
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) {
  try { process.stdout.write(`${JSON.stringify(runInstallationAuthorizationDispatchCli())}\n`); }
  catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }
}
