#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createProductionAwsCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";
import { createRootAttestationKmsVerifier } from "./production-root-attestation-key.mjs";
import { createStageAProductionArtifactsReconciliationAuthorization as createCoreAuthorization, createTerraformStageAAdapter, runStageAProductionArtifactsStateReconciliation } from "./production-stage-a-control-plane.mjs";
import { STAGE_A_TERRAFORM_BACKEND } from "./production-stage-a-root-drop-orphan-recovery.mjs";
import { createStageAProductionArtifactsJournal, STAGE_A_PRODUCTION_ARTIFACTS_RECONCILIATION_OPERATION } from "./production-stage-a-production-artifacts-journal.mjs";
import { assertStageAProductionArtifactsRecoveryAuthorization, assertStageAProductionArtifactsRecoveryCompletionEvidence, assertStageAProductionArtifactsReconciliationGovernanceAuthorization, resolveStageAProductionArtifactsAuthorizationArtifact, STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_OPERATION } from "./production-stage-a-production-artifacts-recovery-governance.mjs";
import { readFreshProtectedMainIdentity } from "./stage-b-deployment-identity.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const required = (argv, name) => { const i = argv.indexOf(name); const value = i < 0 ? undefined : argv[i + 1]; if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };
const awsJson = (run, args) => JSON.parse(run([...args, "--output", "json", "--no-cli-pager"]));
const exactRelease = (value) => value?.Account === "368992683803" && /^arn:aws:sts::368992683803:assumed-role\/mscqr-production-release-deployer\/[^/]+$/.test(value?.Arn || "");
const readPolicy = (run) => JSON.parse(awsJson(run, ["s3api", "get-bucket-policy", "--bucket", "mscqr-prod-euw2-artifacts-368992683803-eu-west-2-an"]).Policy);

export async function runStageAProductionArtifactsReconciliation({ sourceSha, recoveryWorkflowRunId, recoveryWorkflowRunAttempt, reconciliationWorkflowRunId, reconciliationWorkflowRunAttempt, releaseRun, adapter, resolveAuthorization = resolveStageAProductionArtifactsAuthorizationArtifact, journal, verifySignature, readProtectedSource = readFreshProtectedMainIdentity } = {}) {
  if (typeof releaseRun !== "function" || !adapter || typeof resolveAuthorization !== "function" || !journal || typeof journal.readRecoveryCompletion !== "function" || typeof verifySignature !== "function") throw new Error("Stage A production-artifacts reconciliation composition is incomplete.");
  const fresh = readProtectedSource({ run: (args) => execFileSync("git", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }), expectedSourceSha: sourceSha });
  if (!exactRelease(awsJson(releaseRun, ["sts", "get-caller-identity"]))) throw new Error("Stage A production-artifacts reconciliation requires the exact release-deployer session.");
  const recovery = resolveAuthorization({ workflowRunId: recoveryWorkflowRunId, workflowRunAttempt: recoveryWorkflowRunAttempt, sourceSha: fresh.headSha, operation: STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_OPERATION });
  const preState = await adapter.readStateIdentity(); assertStageAProductionArtifactsRecoveryAuthorization(recovery.authorization, { sourceSha: fresh.headSha, preState });
  const persisted = journal.readRecoveryCompletion(recovery.authorization.authorizationSha256); if (!persisted) throw new Error("Stage A production-artifacts recovery completion is absent from the durable journal.");
  let completionEvidence; try { completionEvidence = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(persisted.bytes)); } catch { throw new Error("Stage A production-artifacts recovery completion is malformed."); }
  assertStageAProductionArtifactsRecoveryCompletionEvidence(completionEvidence, { authorization: recovery.authorization, verify: verifySignature });
  const saved = await adapter.createSavedRefreshOnlyPlan();
  const reconciliation = resolveAuthorization({ workflowRunId: reconciliationWorkflowRunId, workflowRunAttempt: reconciliationWorkflowRunAttempt, sourceSha: fresh.headSha, operation: STAGE_A_PRODUCTION_ARTIFACTS_RECONCILIATION_OPERATION });
  assertStageAProductionArtifactsReconciliationGovernanceAuthorization(reconciliation.authorization, { sourceSha: fresh.headSha, preState, recoveryAuthorization: recovery.authorization, recoveryCompletion: completionEvidence, savedPlanSha256: saved.savedPlanSha256, verifyRecoveryCompletionEvidence: verifySignature });
  const verifyRecoveryCompletion = (completion) => {
    if (completion?.completionSha256 !== completionEvidence.completion.completionSha256) return false;
    assertStageAProductionArtifactsRecoveryCompletionEvidence(completionEvidence, { authorization: recovery.authorization, verify: verifySignature });
    return { authorizationSha256: recovery.authorization.authorizationSha256, livePolicySha256: completionEvidence.postRecoveryLivePolicySha256, completed: true };
  };
  const coreAuthorization = createCoreAuthorization({ sourceSha: fresh.headSha, recoveryCompletion: completionEvidence.completion, savedPlanSha256: saved.savedPlanSha256, stateLineage: preState.lineage, preStateSerial: preState.serial, preStateSha256: preState.stateSha256, verifyRecoveryCompletion });
  const identity = { operation: STAGE_A_PRODUCTION_ARTIFACTS_RECONCILIATION_OPERATION, sourceSha: fresh.headSha, account: "368992683803", region: "eu-west-2", executionPrincipal: "arn:aws:iam::368992683803:role/mscqr-production-release-deployer", authorizationSha256: reconciliation.authorization.authorizationSha256, recoveryCompletionSha256: completionEvidence.completionEvidenceSha256, savedPlanSha256: saved.savedPlanSha256, preStateLineage: preState.lineage, preStateSerial: preState.serial, preStateSha256: preState.stateSha256, desiredPolicySha256: completionEvidence.desiredPolicySha256 };
  const result = await runStageAProductionArtifactsStateReconciliation({ adapter: { ...adapter, createSavedRefreshOnlyPlan: async () => saved }, sourceSha: fresh.headSha, recoveryCompletion: completionEvidence.completion, verifyRecoveryCompletion, reconciliationAuthorization: coreAuthorization, verifyReconciliationAuthorization: (authorization) => {
    if (authorization?.authorizationSha256 !== coreAuthorization.authorizationSha256) return false;
    assertStageAProductionArtifactsReconciliationGovernanceAuthorization(reconciliation.authorization, { sourceSha: fresh.headSha, preState, recoveryAuthorization: recovery.authorization, recoveryCompletion: completionEvidence, savedPlanSha256: saved.savedPlanSha256, verifyRecoveryCompletionEvidence: verifySignature });
    return { authorizationSha256: coreAuthorization.authorizationSha256, approved: true, independent: true };
  }, authorizationIdentity: reconciliation.authorization.authorizationSha256, reserveConsumption: async (consumption) => {
    if (consumption.authorizationSha256 !== identity.authorizationSha256 || consumption.completionSha256 !== completionEvidence.completion.completionSha256 || consumption.savedPlanSha256 !== identity.savedPlanSha256 || consumption.preStateSha256 !== identity.preStateSha256) throw new Error("Stage A reconciliation consumption identity is substituted.");
    return journal.reserve(identity);
  }, finalizeConsumption: async ({ reservation, status, postState, postLivePolicySha256 }) => journal.finalize({ reservation: reservation?.reservation, status, postState, postLivePolicySha256 }), abortConsumption: async ({ reservation }) => journal.finalize({ reservation: reservation?.reservation, status: "ABORTED_BEFORE_APPLY" }) });
  return Object.freeze({ ...result, recoveryAuthorizationSha256: recovery.authorization.authorizationSha256, recoveryCompletionSha256: completionEvidence.completionEvidenceSha256, reconciliationAuthorizationSha256: reconciliation.authorization.authorizationSha256 });
}

export async function runStageAProductionArtifactsReconciliationCli(argv = process.argv.slice(2), deps = {}) {
  if (!argv.includes("--production")) throw new Error("Stage A production-artifacts reconciliation requires --production.");
  const sourceSha = required(argv, "--source-sha"); const terraformDataDir = path.resolve(required(argv, "--terraform-data-dir")); const refreshPlanPath = path.resolve(required(argv, "--refresh-only-plan"));
  if (!path.isAbsolute(terraformDataDir) || terraformDataDir.startsWith(`${root}${path.sep}`) || !path.isAbsolute(refreshPlanPath) || refreshPlanPath.startsWith(`${root}${path.sep}`)) throw new Error("Stage A reconciliation private Terraform paths must be external and absolute.");
  fs.mkdirSync(terraformDataDir, { recursive: true, mode: 0o700 }); fs.chmodSync(terraformDataDir, 0o700);
  const releaseRun = createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: "mscqr-production-release-deployer", region: "eu-west-2" });
  const terraformRun = async (args) => execFileSync(args[0], args.slice(1), { cwd: root, env: { ...process.env, AWS_PROFILE: "mscqr-production-release-deployer", AWS_REGION: "eu-west-2", TF_DATA_DIR: terraformDataDir }, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  const adapter = createTerraformStageAAdapter({ root: "infra/aws/terraform/production-green-stage-a", planPath: path.join(terraformDataDir, "unused.tfplan"), refreshOnlyPlanPath, backendArgs: Object.entries(STAGE_A_TERRAFORM_BACKEND).filter(([key]) => key !== "type").map(([key, value]) => `-backend-config=${key}=${value}`), run: terraformRun, describeIngress: async () => ({ present: false }), readProductionArtifactsPolicy: async () => readPolicy(releaseRun), sourceSha });
  const result = await runStageAProductionArtifactsReconciliation({ sourceSha, recoveryWorkflowRunId: required(argv, "--recovery-authorization-workflow-run-id"), recoveryWorkflowRunAttempt: required(argv, "--recovery-authorization-workflow-run-attempt"), reconciliationWorkflowRunId: required(argv, "--reconciliation-authorization-workflow-run-id"), reconciliationWorkflowRunAttempt: required(argv, "--reconciliation-authorization-workflow-run-attempt"), releaseRun, adapter, journal: createStageAProductionArtifactsJournal({ run: releaseRun }), verifySignature: createRootAttestationKmsVerifier({ run: releaseRun }), ...deps });
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`); return result;
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) runStageAProductionArtifactsReconciliationCli().catch((error) => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
