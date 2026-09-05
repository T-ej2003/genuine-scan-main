#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createProductionAwsCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";
import { assertStageBArtifactPath, ensureStageBPrivateDirectory, readBoundStageBPrivateJson, readStageBPrivateFileBytes, writeStageBPrivateFilesAtomic } from "./stage-b-artifact-contract.mjs";
import { INSTALLATION, assertFreshInstallationAuthorization, assertInstallationPlan, assertInstallationPreparation, stateIdentity, assertInstallationResult } from "./production-initial-activation-reconciler-installation-contract.mjs";
import { discoverInstallationPredecessor, assertProtectedCheckout } from "./prepare-production-initial-activation-reconciler-installation.mjs";
import { verifyInitialActivationPolicyReconciler } from "./verify-production-initial-activation-policy-reconciler.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const sha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const option = (argv, name) => { const index = argv.indexOf(name); return index < 0 ? undefined : argv[index + 1]; };
const required = (argv, name) => { const value = option(argv, name); if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };

function consumeOnce({ authorizationSha256, directory, fsOps = fs } = {}) {
  ensureStageBPrivateDirectory({ directory, repositoryRoot: root, create: true, fsOps, label: "Installation consumption directory" });
  const filePath = path.join(directory, `${authorizationSha256}.consumed`);
  const stat = fsOps.lstatSync(filePath, { throwIfNoEntry: false });
  if (stat) throw new Error("Installation authorization has already been consumed.");
  fsOps.writeFileSync(filePath, `${authorizationSha256}\n`, { flag: "wx", mode: 0o600 });
  return filePath;
}

export function executeInstallation({ sourceSha, preparation, authorization, planBytes, planJson, administratorArn = INSTALLATION.administratorArn, livePredecessor, applySavedPlan, verifyInstalled, readState, resultPath, consumptionDirectory, now = new Date() } = {}) {
  assertInstallationPreparation(preparation, { sourceSha, planBytes });
  assertFreshInstallationAuthorization(authorization, { sourceSha, preparation, now });
  if (administratorArn !== INSTALLATION.administratorArn) throw new Error("Installation administrator identity is not exact.");
  const semantics = assertInstallationPlan(planJson);
  if (livePredecessor !== "ABSENT" && livePredecessor !== "EXACT_PARTIAL" && livePredecessor !== "EXACT_COMPLETE") throw new Error("Installation live predecessor is not a supported exact state.");
  if (livePredecessor === "ABSENT" && semantics.resourceChangeCount !== INSTALLATION.expectedAddresses.length) throw new Error("First-install plan mutation scope is not exact.");
  if (livePredecessor === "EXACT_PARTIAL" && semantics.resourceChangeCount < 1) throw new Error("Partial-install plan mutation scope is not exact.");
  if (livePredecessor !== "EXACT_COMPLETE" && livePredecessor !== preparation.livePredecessor) throw new Error("Installation live predecessor changed after preparation.");
  const beforeState = stateIdentity(readState?.());
  if (JSON.stringify(beforeState) !== JSON.stringify(preparation.predecessorState)) throw new Error("Installation Terraform state changed after preparation.");
  const output = assertStageBArtifactPath({ artifactPath: resultPath, repositoryRoot: root, label: "Installation result", allowExisting: false });
  ensureStageBPrivateDirectory({ directory: path.dirname(output), repositoryRoot: root, create: true, label: "Installation result directory" });
  if (livePredecessor === "EXACT_COMPLETE") {
    if (typeof verifyInstalled !== "function") throw new Error("Canonical verifier is required for exact-complete replay.");
    verifyInstalled();
    const result = { kind: "PRODUCTION_INITIAL_ACTIVATION_POLICY_RECONCILER_INSTALLATION_RESULT", schemaVersion: 1, operation: INSTALLATION.operation, sourceSha, authorizationSha256: authorization.authorizationSha256, status: "COMPLETE", applyCount: 0, targetPolicyCreatePolicyVersionCount: 0, verifier: "PASS", state: stateIdentity(readState?.()), completedAt: new Date().toISOString() };
    writeStageBPrivateFilesAtomic({ repositoryRoot: root, files: [{ filePath: output, bytes: Buffer.from(`${JSON.stringify(result, null, 2)}\n`), label: "Installation result" }] });
    return Object.freeze(result);
  }
  if (typeof applySavedPlan !== "function") throw new Error("Installation saved-plan apply function is required.");
  consumeOnce({ authorizationSha256: authorization.authorizationSha256, directory: consumptionDirectory || path.join(osTmp(), "mscqr-initial-activation-installation-consumptions") });
  if (typeof verifyInstalled !== "function") throw new Error("Canonical verifier is required after apply.");
  try {
    applySavedPlan({ planBytes });
  } catch (error) {
    // An apply process can exit after AWS/Terraform commits the resources but
    // before returning a success status. Recover only by read-only verifier;
    // never retry the saved plan blindly.
    try { verifyInstalled(); } catch { throw error; }
    const recovered = { kind: "PRODUCTION_INITIAL_ACTIVATION_POLICY_RECONCILER_INSTALLATION_RESULT", schemaVersion: 1, operation: INSTALLATION.operation, sourceSha, authorizationSha256: authorization.authorizationSha256, status: "COMPLETE", applyCount: 1, targetPolicyCreatePolicyVersionCount: 0, verifier: "PASS", state: stateIdentity(readState?.()), completedAt: new Date().toISOString(), recoveredFromAmbiguousApply: true };
    writeStageBPrivateFilesAtomic({ repositoryRoot: root, files: [{ filePath: output, bytes: Buffer.from(`${JSON.stringify(recovered, null, 2)}\n`), label: "Installation result" }] });
    return Object.freeze(recovered);
  }
  verifyInstalled();
  const result = { kind: "PRODUCTION_INITIAL_ACTIVATION_POLICY_RECONCILER_INSTALLATION_RESULT", schemaVersion: 1, operation: INSTALLATION.operation, sourceSha, authorizationSha256: authorization.authorizationSha256, status: "COMPLETE", applyCount: 1, targetPolicyCreatePolicyVersionCount: 0, verifier: "PASS", state: stateIdentity(readState?.()), completedAt: new Date().toISOString() };
  writeStageBPrivateFilesAtomic({ repositoryRoot: root, files: [{ filePath: output, bytes: Buffer.from(`${JSON.stringify(result, null, 2)}\n`), label: "Installation result" }] });
  return Object.freeze(result);
}

const osTmp = () => process.env.TMPDIR || "/tmp";

export function runInstallCli(argv = process.argv.slice(2), deps = {}) {
  if (!argv.includes("--execute")) throw new Error("Installation requires --execute.");
  const sourceSha = required(argv, "--source-sha");
  const profile = required(argv, "--admin-profile");
  const preparationPath = path.resolve(required(argv, "--preparation"));
  const preparationSha256 = required(argv, "--preparation-sha256");
  const authorizationPath = path.resolve(required(argv, "--authorization"));
  const authorizationSha256 = required(argv, "--authorization-sha256");
  const planPath = path.resolve(required(argv, "--plan"));
  const planJsonPath = path.resolve(required(argv, "--plan-json"));
  const resultPath = path.resolve(required(argv, "--result"));
  const terraformDataDir = path.resolve(required(argv, "--terraform-data-dir"));
  const exec = deps.exec || execFileSync;
  assertProtectedCheckout({ sourceSha, repositoryRoot: root, exec });
  const preparation = readBoundStageBPrivateJson({ filePath: preparationPath, expectedSha256: preparationSha256, repositoryRoot: root, label: "Installation preparation artifact" });
  const plan = readStageBPrivateFileBytes({ filePath: planPath, repositoryRoot: root, label: "Installation saved Terraform plan" });
  const planJson = JSON.parse(readStageBPrivateFileBytes({ filePath: planJsonPath, repositoryRoot: root, label: "Installation rendered Terraform plan" }).bytes.toString("utf8"));
  const authorization = readBoundStageBPrivateJson({ filePath: authorizationPath, expectedSha256: authorizationSha256, repositoryRoot: root, label: "Installation authorization artifact" });
  const run = deps.run || createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile });
  const identity = JSON.parse(run(["sts", "get-caller-identity", "--output", "json", "--no-cli-pager"]));
  if (identity?.Arn !== INSTALLATION.administratorArn) throw new Error("Installation requires the exact root administrator identity.");
  const livePredecessor = discoverInstallationPredecessor({ run });
  if (livePredecessor === "UNEXPECTED") throw new Error("Installation live predecessor is unexpected.");
  const applySavedPlan = ({ planBytes }) => {
    const appliedPath = path.join(path.dirname(planPath), "authorized-installation.tfplan");
    fs.writeFileSync(appliedPath, planBytes, { flag: "wx", mode: 0o600 });
    const env = { ...process.env, AWS_PROFILE: profile, AWS_REGION: INSTALLATION.region, AWS_DEFAULT_REGION: INSTALLATION.region, AWS_EC2_METADATA_DISABLED: "true", TF_DATA_DIR: terraformDataDir };
    exec("terraform", [`-chdir=${path.join(root, INSTALLATION.terraformRoot)}`, "apply", "-input=false", "-lock=false", appliedPath], { cwd: root, env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  };
  const verifyInstalled = () => verifyInitialActivationPolicyReconciler({ run });
  const readState = () => { try { return Buffer.from(exec("terraform", [`-chdir=${path.join(root, INSTALLATION.terraformRoot)}`, "state", "pull"], { cwd: root, env: { ...process.env, AWS_PROFILE: profile, AWS_REGION: INSTALLATION.region, AWS_DEFAULT_REGION: INSTALLATION.region, AWS_EC2_METADATA_DISABLED: "true", TF_DATA_DIR: terraformDataDir }, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] })); } catch { return undefined; } };
  return executeInstallation({ sourceSha, preparation, authorization, planBytes: plan.bytes, planJson, administratorArn: identity.Arn, livePredecessor, applySavedPlan, verifyInstalled, readState, resultPath, consumptionDirectory: path.join(path.dirname(resultPath), ".consumptions") });
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) runInstallCli().then((value) => process.stdout.write(`${JSON.stringify(value, null, 2)}\n`));
