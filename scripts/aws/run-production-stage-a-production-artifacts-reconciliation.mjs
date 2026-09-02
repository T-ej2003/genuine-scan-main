#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createProductionAwsCommandRunner, createProductionAwsCredentialEnvironment, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";
import { createRootAttestationKmsVerifier } from "./production-root-attestation-key.mjs";
import { assertStageAProductionArtifactsReconciliationPrepareEvidence, buildStageAProductionArtifactsBucketPolicy, createStageAProductionArtifactsReconciliationAuthorization as createCoreAuthorization, createTerraformStageAAdapter, prepareStageAProductionArtifactsStateReconciliation, runStageAProductionArtifactsStateReconciliation, stageAProductionArtifactsPolicySha256 } from "./production-stage-a-control-plane.mjs";
import { STAGE_A_TERRAFORM_BACKEND } from "./production-stage-a-root-drop-orphan-recovery.mjs";
import { assertStageATerraformVariables, STAGE_A_REQUIRED_TERRAFORM_VARIABLE_KEYS } from "./recover-production-green-stage-a-root-drop-orphan.mjs";
import { buildRecoveryTerraformEnvironment } from "./recover-stage-b-backend-task-definition.mjs";
import { createStageAProductionArtifactsJournal, STAGE_A_PRODUCTION_ARTIFACTS_RECONCILIATION_OPERATION } from "./production-stage-a-production-artifacts-journal.mjs";
import { assertStageAProductionArtifactsRecoveryAuthorization, assertStageAProductionArtifactsRecoveryCompletionEvidence, assertStageAProductionArtifactsRecoverySourceCompatibility, assertStageAProductionArtifactsReconciliationGovernanceAuthorization, resolveStageAProductionArtifactsAuthorizationArtifact, STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_OPERATION } from "./production-stage-a-production-artifacts-recovery-governance.mjs";
import { readStageBProtectedMainCheckout } from "./stage-b-deployment-identity.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const required = (argv, name) => { const i = argv.indexOf(name); const value = i < 0 ? undefined : argv[i + 1]; if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };
const awsJson = (run, args) => JSON.parse(run([...args, "--output", "json", "--no-cli-pager"]));
const exactRelease = (value) => value?.Account === "368992683803" && /^arn:aws:sts::368992683803:assumed-role\/mscqr-production-release-deployer\/[^/]+$/.test(value?.Arn || "");
const readPolicy = (run) => JSON.parse(awsJson(run, ["s3api", "get-bucket-policy", "--bucket", "mscqr-prod-euw2-artifacts-368992683803-eu-west-2-an"]).Policy);

const sourceHead = (value) => value?.headSha || value?.currentHead || value?.toolingSha;
const readCompletion = (journal, authorization, verifySignature) => {
  const persisted = journal.readRecoveryCompletion(authorization.authorizationSha256);
  if (!persisted) throw new Error("Stage A production-artifacts recovery completion is absent from the durable journal.");
  let evidence; try { evidence = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(persisted.bytes)); } catch { throw new Error("Stage A production-artifacts recovery completion is malformed."); }
  assertStageAProductionArtifactsRecoveryCompletionEvidence(evidence, { authorization, verify: verifySignature });
  return evidence;
};
const proveProtectedMainDescendant = ({ ancestorSha, descendantSha }) => {
  try {
    execFileSync("git", ["cat-file", "-e", `${ancestorSha}^{commit}`], { cwd: root, stdio: "ignore" });
    execFileSync("git", ["merge-base", "--is-ancestor", ancestorSha, descendantSha], { cwd: root, stdio: "ignore" });
    return true;
  } catch { return false; }
};
const protectedSource = (readProtectedSource, sourceSha) => {
  const fresh = readProtectedSource({ cwd: root, expectedSourceSha: sourceSha, requireCanonicalRepository: true, run: (args) => execFileSync("git", args, { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }) });
  const head = sourceHead(fresh);
  if (head !== sourceSha) throw new Error("Stage A production-artifacts reconciliation source SHA is not authenticated.");
  return { fresh, head };
};
const authenticateRecovery = async ({ sourceSha, recoverySourceSha = sourceSha, releaseRun, adapter, journal, verifySignature, recoveryWorkflowRunId, recoveryWorkflowRunAttempt, resolveAuthorization, readProtectedSource, proveDescendant }) => {
  const source = protectedSource(readProtectedSource, sourceSha);
  assertStageAProductionArtifactsRecoverySourceCompatibility({ sourceSha: source.head, recoverySourceSha, proveDescendant });
  if (!exactRelease(awsJson(releaseRun, ["sts", "get-caller-identity"]))) throw new Error("Stage A production-artifacts reconciliation requires the exact release-deployer session.");
  const recovery = resolveAuthorization({ workflowRunId: recoveryWorkflowRunId, workflowRunAttempt: recoveryWorkflowRunAttempt, sourceSha: recoverySourceSha, operation: STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_OPERATION });
  const preState = await adapter.readStateIdentity();
  assertStageAProductionArtifactsRecoveryAuthorization(recovery.authorization, { sourceSha: recoverySourceSha, preState });
  const completionEvidence = readCompletion(journal, recovery.authorization, verifySignature);
  const livePolicy = await adapter.readProductionArtifactsPolicy();
  if (stageAProductionArtifactsPolicySha256(livePolicy) !== completionEvidence.desiredPolicySha256 || stageAProductionArtifactsPolicySha256(livePolicy) !== stageAProductionArtifactsPolicySha256(buildStageAProductionArtifactsBucketPolicy())) throw new Error("Stage A production-artifacts reconciliation requires the exact live desired policy.");
  const verifyRecoveryCompletion = (completion) => {
    if (completion?.completionSha256 !== completionEvidence.completion.completionSha256) return false;
    assertStageAProductionArtifactsRecoveryCompletionEvidence(completionEvidence, { authorization: recovery.authorization, verify: verifySignature });
    return { authorizationSha256: recovery.authorization.authorizationSha256, livePolicySha256: completionEvidence.postRecoveryLivePolicySha256, completed: true };
  };
  return Object.freeze({ ...source, recoverySourceSha, recovery, preState, completionEvidence, verifyRecoveryCompletion });
};

export async function prepareStageAProductionArtifactsReconciliation({ sourceSha, recoverySourceSha = sourceSha, recoveryWorkflowRunId, recoveryWorkflowRunAttempt, releaseRun, adapter, resolveAuthorization = resolveStageAProductionArtifactsAuthorizationArtifact, journal, verifySignature, readProtectedSource = readStageBProtectedMainCheckout, proveDescendant = proveProtectedMainDescendant } = {}) {
  if (typeof releaseRun !== "function" || !adapter || typeof adapter.createSavedRefreshOnlyPlan !== "function" || typeof adapter.readStateIdentity !== "function" || typeof adapter.readProductionArtifactsPolicy !== "function" || typeof resolveAuthorization !== "function" || !journal || typeof journal.readRecoveryCompletion !== "function" || typeof verifySignature !== "function") throw new Error("Stage A production-artifacts preparation composition is incomplete.");
  const context = await authenticateRecovery({ sourceSha, recoverySourceSha, releaseRun, adapter, journal, verifySignature, recoveryWorkflowRunId, recoveryWorkflowRunAttempt, resolveAuthorization, readProtectedSource, proveDescendant });
  return Object.freeze({ ...context, prepared: await prepareStageAProductionArtifactsStateReconciliation({ adapter, sourceSha: context.head, recoverySourceSha: context.recoverySourceSha, recoveryCompletion: context.completionEvidence.completion, verifyRecoveryCompletion: context.verifyRecoveryCompletion, preState: context.preState, assertSourceIntegrity: () => protectedSource(readProtectedSource, context.head) }) });
}

export async function runStageAProductionArtifactsReconciliation({ sourceSha, recoverySourceSha = sourceSha, recoveryWorkflowRunId, recoveryWorkflowRunAttempt, reconciliationWorkflowRunId, reconciliationWorkflowRunAttempt, releaseRun, adapter, resolveAuthorization = resolveStageAProductionArtifactsAuthorizationArtifact, journal, verifySignature, readProtectedSource = readStageBProtectedMainCheckout, proveDescendant = proveProtectedMainDescendant, preparedEvidence, saved: suppliedSaved, savedPlanPath, prepareEvidencePath } = {}) {
  if (typeof releaseRun !== "function" || !adapter || typeof resolveAuthorization !== "function" || !journal || typeof journal.readRecoveryCompletion !== "function" || typeof verifySignature !== "function") throw new Error("Stage A production-artifacts reconciliation composition is incomplete.");
  const context = await authenticateRecovery({ sourceSha, recoverySourceSha, releaseRun, adapter, journal, verifySignature, recoveryWorkflowRunId, recoveryWorkflowRunAttempt, resolveAuthorization, readProtectedSource, proveDescendant });
  if (!preparedEvidence && !prepareEvidencePath) throw new Error("Stage A reconciliation execution requires the prepared evidence path.");
  const evidence = preparedEvidence || JSON.parse(fs.readFileSync(path.resolve(prepareEvidencePath), "utf8"));
  let saved = suppliedSaved;
  if (!saved) {
    const planPath = path.resolve(savedPlanPath || "");
    if (!path.isAbsolute(savedPlanPath || "") || !fs.existsSync(planPath) || planPath.startsWith(`${root}${path.sep}`)) throw new Error("Stage A reconciliation execution requires an external prepared plan path.");
    if (typeof adapter.readSavedRefreshOnlyPlan !== "function") throw new Error("Stage A reconciliation adapter cannot inspect the prepared saved plan.");
    const savedBytes = fs.readFileSync(planPath);
    saved = { planPath, plan: await adapter.readSavedRefreshOnlyPlan(planPath), sourceSha: context.head, refreshOnly: true, preState: context.preState, savedPlanSha256: createHash("sha256").update(savedBytes).digest("hex"), savedPlanByteLength: savedBytes.length };
  }
  assertStageAProductionArtifactsReconciliationPrepareEvidence(evidence, { sourceSha: context.head, recoveryCompletion: context.completionEvidence.completion, preState: context.preState, savedPlanSha256: saved.savedPlanSha256, savedPlanByteLength: saved.savedPlanByteLength });
  const reconciliation = resolveAuthorization({ workflowRunId: reconciliationWorkflowRunId, workflowRunAttempt: reconciliationWorkflowRunAttempt, sourceSha: context.head, operation: STAGE_A_PRODUCTION_ARTIFACTS_RECONCILIATION_OPERATION });
  assertStageAProductionArtifactsReconciliationGovernanceAuthorization(reconciliation.authorization, { sourceSha: context.head, recoverySourceSha: context.recoverySourceSha, preState: context.preState, recoveryAuthorization: context.recovery.authorization, recoveryCompletion: context.completionEvidence, prepareEvidence: evidence, savedPlanSha256: saved.savedPlanSha256, verifyRecoveryCompletionEvidence: verifySignature, proveDescendant });
  const coreAuthorization = createCoreAuthorization({ sourceSha: context.head, recoverySourceSha: context.recoverySourceSha, recoveryCompletion: context.completionEvidence.completion, savedPlanSha256: saved.savedPlanSha256, stateLineage: context.preState.lineage, preStateSerial: context.preState.serial, preStateSha256: context.preState.stateSha256, verifyRecoveryCompletion: context.verifyRecoveryCompletion });
  const identity = { operation: STAGE_A_PRODUCTION_ARTIFACTS_RECONCILIATION_OPERATION, sourceSha: context.head, account: "368992683803", region: "eu-west-2", executionPrincipal: "arn:aws:iam::368992683803:role/mscqr-production-release-deployer", authorizationSha256: reconciliation.authorization.authorizationSha256, recoveryCompletionSha256: context.completionEvidence.completionEvidenceSha256, savedPlanSha256: saved.savedPlanSha256, preStateLineage: context.preState.lineage, preStateSerial: context.preState.serial, preStateSha256: context.preState.stateSha256, desiredPolicySha256: context.completionEvidence.desiredPolicySha256 };
  const result = await runStageAProductionArtifactsStateReconciliation({ adapter, sourceSha: context.head, recoverySourceSha: context.recoverySourceSha, recoveryCompletion: context.completionEvidence.completion, verifyRecoveryCompletion: context.verifyRecoveryCompletion, reconciliationAuthorization: coreAuthorization, saved, preparedState: context.preState, assertSourceIntegrity: () => protectedSource(readProtectedSource, context.head), verifyReconciliationAuthorization: (authorization) => {
    if (authorization?.authorizationSha256 !== coreAuthorization.authorizationSha256) return false;
    assertStageAProductionArtifactsReconciliationGovernanceAuthorization(reconciliation.authorization, { sourceSha: context.head, recoverySourceSha: context.recoverySourceSha, preState: context.preState, recoveryAuthorization: context.recovery.authorization, recoveryCompletion: context.completionEvidence, prepareEvidence: evidence, savedPlanSha256: saved.savedPlanSha256, verifyRecoveryCompletionEvidence: verifySignature, proveDescendant });
    return { authorizationSha256: coreAuthorization.authorizationSha256, approved: true, independent: true };
  }, authorizationIdentity: reconciliation.authorization.authorizationSha256, reserveConsumption: async (consumption) => {
    if (consumption.authorizationSha256 !== identity.authorizationSha256 || consumption.completionSha256 !== context.completionEvidence.completion.completionSha256 || consumption.savedPlanSha256 !== identity.savedPlanSha256 || consumption.preStateSha256 !== identity.preStateSha256) throw new Error("Stage A reconciliation consumption identity is substituted.");
    return journal.reserve(identity);
  }, finalizeConsumption: async ({ reservation, status, postState, postLivePolicySha256 }) => journal.finalize({ reservation: reservation?.reservation, status, postState, postLivePolicySha256 }), abortConsumption: async ({ reservation }) => journal.finalize({ reservation: reservation?.reservation, status: "ABORTED_BEFORE_APPLY" }) });
  return Object.freeze({ ...result, prepareEvidenceSha256: evidence.prepareEvidenceSha256, recoveryAuthorizationSha256: context.recovery.authorization.authorizationSha256, recoveryCompletionSha256: context.completionEvidence.completionEvidenceSha256, reconciliationAuthorizationSha256: reconciliation.authorization.authorizationSha256 });
}

export async function runStageAProductionArtifactsReconciliationCli(argv = process.argv.slice(2), deps = {}) {
  if (!argv.includes("--production")) throw new Error("Stage A production-artifacts reconciliation requires --production.");
  const preparing = argv.includes("--prepare"); const executing = argv.includes("--execute");
  if (preparing === executing) throw new Error("Stage A reconciliation requires exactly one of --prepare or --execute.");
  const sourceSha = required(argv, "--source-sha"); const recoverySourceSha = argv.includes("--recovery-source-sha") ? required(argv, "--recovery-source-sha") : sourceSha; const terraformDataDir = path.resolve(required(argv, "--terraform-data-dir")); const refreshPlanPath = path.resolve(required(argv, "--refresh-only-plan"));
  const prepareEvidencePath = path.resolve(required(argv, "--prepare-evidence"));
  if (!path.isAbsolute(terraformDataDir) || terraformDataDir.startsWith(`${root}${path.sep}`) || !path.isAbsolute(refreshPlanPath) || refreshPlanPath.startsWith(`${root}${path.sep}`) || !path.isAbsolute(prepareEvidencePath) || prepareEvidencePath.startsWith(`${root}${path.sep}`)) throw new Error("Stage A reconciliation private Terraform paths/evidence must be external and absolute.");
  fs.mkdirSync(terraformDataDir, { recursive: true, mode: 0o700 }); fs.chmodSync(terraformDataDir, 0o700);
  const releaseRun = createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: "mscqr-production-release-deployer", region: "eu-west-2" });
  const terraformInputEnvironment = deps.terraformInputEnvironment || process.env;
  assertStageATerraformVariables(terraformInputEnvironment);
  const terraformEnvironment = { ...buildRecoveryTerraformEnvironment("mscqr-production-release-deployer", terraformInputEnvironment, { allowedTerraformVariableKeys: STAGE_A_REQUIRED_TERRAFORM_VARIABLE_KEYS }), TF_DATA_DIR: terraformDataDir };
  const terraformRun = async (args) => execFileSync(args[0], args.slice(1), { cwd: root, env: terraformEnvironment, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  const adapter = createTerraformStageAAdapter({ root: "infra/aws/terraform/production-green-stage-a", planPath: path.join(terraformDataDir, "unused.tfplan"), refreshOnlyPlanPath: refreshPlanPath, backendArgs: Object.entries(STAGE_A_TERRAFORM_BACKEND).filter(([key]) => key !== "type").map(([key, value]) => `-backend-config=${key}=${value}`), run: terraformRun, describeIngress: async () => ({ present: false }), readProductionArtifactsPolicy: async () => readPolicy(releaseRun), sourceSha });
  const common = { sourceSha, recoverySourceSha, recoveryWorkflowRunId: required(argv, "--recovery-authorization-workflow-run-id"), recoveryWorkflowRunAttempt: required(argv, "--recovery-authorization-workflow-run-attempt"), releaseRun, adapter, journal: createStageAProductionArtifactsJournal({ run: releaseRun }), verifySignature: createRootAttestationKmsVerifier({ run: releaseRun }), ...deps };
  const result = preparing
    ? await prepareStageAProductionArtifactsReconciliation(common)
    : await runStageAProductionArtifactsReconciliation({ ...common, reconciliationWorkflowRunId: required(argv, "--reconciliation-authorization-workflow-run-id"), reconciliationWorkflowRunAttempt: required(argv, "--reconciliation-authorization-workflow-run-attempt"), prepareEvidencePath, savedPlanPath: refreshPlanPath });
  if (preparing) {
    fs.writeFileSync(prepareEvidencePath, `${JSON.stringify(result.prepared.prepareEvidence, null, 2)}\n`, { mode: 0o600, flag: "wx" });
    return process.stdout.write(`${JSON.stringify({ prepareEvidenceSha256: result.prepared.prepareEvidence.prepareEvidenceSha256, savedPlanSha256: result.prepared.saved.savedPlanSha256, savedPlanByteLength: result.prepared.saved.savedPlanByteLength, preState: result.prepared.preState, planPath: result.prepared.saved.planPath }, null, 2)}\n`);
  }
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`); return result;
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) runStageAProductionArtifactsReconciliationCli().catch((error) => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
