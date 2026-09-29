#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createProductionAwsCommandRunner, createProductionAwsCredentialEnvironment, createProductionGithubCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE as SOURCES } from "./production-credential-source-contract.mjs";
import { assertStageBArtifactPath, ensureStageBPrivateDirectory, ensureStageBPrivateFile, readBoundStageBPrivateJson, readStageBPrivateFileBytes, writeStageBPrivateFileExclusive } from "./stage-b-artifact-contract.mjs";
import { assertProtectedCheckout, discoverInstallationPredecessor } from "./prepare-production-initial-activation-reconciler-installation.mjs";
import { INSTALLATION } from "./production-initial-activation-reconciler-installation-contract.mjs";
import { stateB, bootstrapPolicy, init, stableState, render, resolveReconcilerStateReconciliationAuthorization } from "./reconcile-production-initial-activation-reconciler-state.mjs";
import { SIGNER_STATE_RECONCILIATION as CONTRACT, assertSignerRefreshOnlyPlan, assertSignerStateAuthorization, assertSignerStateRecoveryAuthorization, createSignerStatePreparation, createSignerStateRecoveryPreparation, executeSignerStateReconciliation, executeSignerStateRecovery } from "./production-initial-activation-signer-state-reconciliation.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const sha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const required = (argv, key) => { const i = argv.indexOf(key); if (i < 0 || !argv[i + 1] || argv[i + 1].startsWith("--")) throw new Error(`${key} is required.`); return argv[i + 1]; };
const exactArgs = (argv, allowed) => { const seen = new Set(); for (let i = 0; i < argv.length; i += 2) { if (!allowed.has(argv[i]) || seen.has(argv[i]) || !argv[i + 1] || argv[i + 1].startsWith("--")) throw new Error("Signer state CLI arguments are not exact."); seen.add(argv[i]); } };
const json = (run, args) => JSON.parse(run([...args, "--output", "json", "--no-cli-pager"]));
const live = (run) => { stateB(run); bootstrapPolicy(run); const found = discoverInstallationPredecessor({ run }); if (found.classification !== "EXACT_AUTHORIZER_POLICY_UPDATE") throw new Error("Signer state reconciliation requires exact live authorizer policy update predecessor."); return found; };
const artifact = (file, label, existing = false) => assertStageBArtifactPath({ artifactPath: path.resolve(file), repositoryRoot: root, label, allowExisting: existing });
const write = (file, value, label) => { const output = artifact(file, label); ensureStageBPrivateDirectory({ directory: path.dirname(output), repositoryRoot: root, create: true, label: `${label} directory` }); writeStageBPrivateFileExclusive({ filePath: output, bytes: Buffer.from(`${JSON.stringify(value, null, 2)}\n`), repositoryRoot: root, label }); };
const read = (file, digest, label) => readBoundStageBPrivateJson({ filePath: artifact(file, label, true), expectedSha256: digest, repositoryRoot: root, label });
const tf = (exec, env, args) => exec("terraform", [`-chdir=${path.join(root, CONTRACT.terraformRoot)}`, ...args], { cwd: root, env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
const normalPlan = (exec, env, data) => { const file = path.join(data, `.post-signer-refresh-${crypto.randomUUID()}.tfplan`); try { tf(exec, env, ["plan", "-input=false", "-lock=false", "-out", file]); ensureStageBPrivateFile({ filePath: file, repositoryRoot: root, normalize: true, label: "Signer post-refresh normal plan" }); return render({ exec, env, planPath: file }); } finally { fs.rmSync(file, { force: true }); } };
const resolveAuthorization = (deps, input) => (deps.resolveAuthorization || resolveReconcilerStateReconciliationAuthorization)({ ...input, contract: CONTRACT, githubRun: deps.githubRun || createProductionGithubCommandRunner() });

export function runSignerStateReconciliation(argv = process.argv.slice(2), deps = {}) {
  const mode = required(argv, "--mode"); const prepare = mode === "prepare"; const recoveryPrepare = mode === "recovery-prepare"; const recoveryExecute = mode === "recovery-execute";
  if (!["prepare", "execute", "recovery-prepare", "recovery-execute"].includes(mode)) throw new Error("Signer state reconciliation mode is invalid.");
  exactArgs(argv, new Set(prepare ? ["--mode", "--source-sha", "--admin-profile", "--terraform-data-dir", "--saved-plan-out", "--preparation-out"] : recoveryPrepare ? ["--mode", "--source-sha", "--admin-profile", "--terraform-data-dir", "--original-preparation", "--original-preparation-file-sha256", "--original-authorization-workflow-run-id", "--original-authorization-workflow-run-attempt", "--recovery-preparation-out"] : recoveryExecute ? ["--mode", "--source-sha", "--terraform-data-dir", "--recovery-preparation", "--recovery-preparation-file-sha256", "--recovery-authorization-workflow-run-id", "--recovery-authorization-workflow-run-attempt", "--result-out"] : ["--mode", "--source-sha", "--terraform-data-dir", "--preparation", "--preparation-file-sha256", "--authorization-workflow-run-id", "--authorization-workflow-run-attempt", "--saved-plan", "--saved-plan-sha256", "--result-out"]));
  const sourceSha = required(argv, "--source-sha"); const exec = deps.exec || execFileSync; assertProtectedCheckout({ sourceSha, repositoryRoot: root, exec });
  const data = path.resolve(required(argv, "--terraform-data-dir")); ensureStageBPrivateDirectory({ directory: data, repositoryRoot: root, create: true, label: "Signer state Terraform data directory" });
  const profile = prepare || recoveryPrepare ? required(argv, "--admin-profile") : undefined;
  const credentialSource = profile ? SOURCES.NAMED_PROFILE : SOURCES.GITHUB_OIDC_INITIAL_ACTIVATION_BOOTSTRAP;
  const env = { ...createProductionAwsCredentialEnvironment({ credentialSource, ...(profile ? { profile } : { env: deps.env || process.env }) }), TF_DATA_DIR: data, TF_WORKSPACE: "default" };
  const run = deps.run || createProductionAwsCommandRunner({ credentialSource, ...(profile ? { profile } : { env: deps.env || process.env }) });
  if (prepare || recoveryPrepare) {
    const identity = json(run, ["sts", "get-caller-identity"]);
    if (identity.Account !== CONTRACT.account || identity.Arn !== `arn:aws:iam::${CONTRACT.account}:root`) throw new Error("Signer state preparation requires exact production root.");
    live(run); init({ exec, env, data }); const current = stableState({ exec, env, run });
    if (recoveryPrepare) {
      const original = read(required(argv, "--original-preparation"), required(argv, "--original-preparation-file-sha256"), "Signer original preparation");
      const originalRunId = required(argv, "--original-authorization-workflow-run-id"); const originalRunAttempt = required(argv, "--original-authorization-workflow-run-attempt");
      const authorization = resolveAuthorization(deps, { workflowRunId: originalRunId, workflowRunAttempt: originalRunAttempt, sourceSha: original.sourceSha, preparation: original, allowExpired: true, assertAuthorization: assertSignerStateAuthorization });
      const recovery = createSignerStateRecoveryPreparation({ sourceSha, originalPreparation: original, originalAuthorization: authorization, originalRunId, originalRunAttempt, stateBytes: current.bytes, stateObject: current.object });
      write(required(argv, "--recovery-preparation-out"), recovery, "Signer state recovery preparation"); return { mode, preparation: recovery, remoteMutationCount: 0 };
    }
    const saved = artifact(required(argv, "--saved-plan-out"), "Signer refresh-only saved plan");
    tf(exec, env, ["plan", "-refresh-only", "-input=false", "-lock=false", "-out", saved]); ensureStageBPrivateFile({ filePath: saved, repositoryRoot: root, normalize: true, label: "Signer refresh-only saved plan" });
    const planBytes = readStageBPrivateFileBytes({ filePath: saved, repositoryRoot: root, label: "Signer refresh-only saved plan" }).bytes;
    const planJson = render({ exec, env, planPath: saved }); assertSignerRefreshOnlyPlan(planJson, current.bytes);
    const after = stableState({ exec, env, run }); if (!after.bytes.equals(current.bytes) || JSON.stringify(after.object) !== JSON.stringify(current.object)) throw new Error("Signer state changed during read-only preparation.");
    const preparation = createSignerStatePreparation({ sourceSha, stateBytes: current.bytes, stateObject: current.object, planBytes, planJson });
    write(required(argv, "--preparation-out"), preparation, "Signer state preparation"); return { mode, preparation, savedPlanPath: saved, remoteMutationCount: 0 };
  }
  const runtime = deps.env || process.env; const workflow = recoveryExecute ? CONTRACT.recoveryExecutionWorkflowPath : CONTRACT.executionWorkflowPath;
  if (runtime.GITHUB_ACTIONS !== "true" || runtime.GITHUB_REPOSITORY !== CONTRACT.repository || runtime.GITHUB_WORKFLOW_REF !== `${CONTRACT.repository}/${workflow}@refs/heads/main` || runtime.GITHUB_EVENT_NAME !== "workflow_dispatch" || runtime.GITHUB_RUN_ATTEMPT !== "1") throw new Error("Signer state execution is workflow-only.");
  const identity = json(run, ["sts", "get-caller-identity"]);
  if (identity.Account !== CONTRACT.account || !new RegExp(`^arn:aws:sts::${CONTRACT.account}:assumed-role/${CONTRACT.bootstrapRoleArn.split("/").at(-1)}/[^/]+$`).test(identity.Arn || "")) throw new Error("Signer state execution requires exact bootstrap role.");
  init({ exec, env, data }); live(run); const current = stableState({ exec, env, run });
  const reauthenticateSource = () => assertProtectedCheckout({ sourceSha, repositoryRoot: root, exec }); const verifyLive = () => live(run);
  const renderNormalPlan = () => normalPlan(exec, env, data);
  if (recoveryExecute) {
    const preparation = read(required(argv, "--recovery-preparation"), required(argv, "--recovery-preparation-file-sha256"), "Signer state recovery preparation");
    const authorization = resolveAuthorization(deps, { workflowRunId: required(argv, "--recovery-authorization-workflow-run-id"), workflowRunAttempt: required(argv, "--recovery-authorization-workflow-run-attempt"), sourceSha, preparation, workflowPath: CONTRACT.recoveryAuthorizationWorkflowPath, artifactName: CONTRACT.recoveryAuthorizationArtifactName, filename: CONTRACT.recoveryAuthorizationFilename, assertAuthorization: assertSignerStateRecoveryAuthorization });
    const result = executeSignerStateRecovery({ sourceSha, recoveryPreparation: preparation, recoveryAuthorization: authorization, stateBytes: current.bytes, stateObject: current.object, renderNormalPlan, reauthenticateSource, verifyLive });
    write(required(argv, "--result-out"), result, "Signer state recovery result"); return result;
  }
  const preparation = read(required(argv, "--preparation"), required(argv, "--preparation-file-sha256"), "Signer state preparation");
  const authorization = resolveAuthorization(deps, { workflowRunId: required(argv, "--authorization-workflow-run-id"), workflowRunAttempt: required(argv, "--authorization-workflow-run-attempt"), sourceSha, preparation, assertAuthorization: assertSignerStateAuthorization });
  const saved = artifact(required(argv, "--saved-plan"), "Signer refresh-only saved plan", true); ensureStageBPrivateFile({ filePath: saved, repositoryRoot: root, normalize: true, label: "Signer refresh-only saved plan" });
  const planBytes = readStageBPrivateFileBytes({ filePath: saved, repositoryRoot: root, label: "Signer refresh-only saved plan" }).bytes;
  if (sha256(planBytes) !== required(argv, "--saved-plan-sha256")) throw new Error("Signer saved-plan input digest changed.");
  const planJson = render({ exec, env, planPath: saved });
  const applySavedPlan = (bytes) => { const staged = path.join(path.dirname(saved), `.authorized-${crypto.randomUUID()}.tfplan`); try { fs.writeFileSync(staged, bytes, { flag: "wx", mode: 0o600 }); tf(exec, env, ["apply", "-input=false", "-lock-timeout=60s", staged]); } finally { fs.rmSync(staged, { force: true }); } };
  const result = executeSignerStateReconciliation({ sourceSha, preparation, authorization, planBytes, planJson, beforeStateBytes: current.bytes, beforeObject: current.object, applySavedPlan, readPostSnapshot: () => stableState({ exec, env, run }), renderNormalPlan, reauthenticateSource, verifyLive });
  write(required(argv, "--result-out"), result, "Signer state result"); return result;
}
if (import.meta.url === pathToFileURL(process.argv[1] || "").href) { try { process.stdout.write(`${JSON.stringify(runSignerStateReconciliation(), null, 2)}\n`); } catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; } }
