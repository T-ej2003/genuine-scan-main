#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import os from "node:os";
import { fileURLToPath, pathToFileURL } from "node:url";
import { assertProductionEnvironmentApprovalEvidence, assertProductionEnvironmentApprovalIdentity, PRODUCTION_ENVIRONMENT_APPROVAL } from "./production-github-environment-approval.mjs";
import { assertStageAApprovalKeyPolicyDocument } from "./production-stage-a-control-plane.mjs";
import { buildStageAStateIdentity, parseAuthenticatedStateBytes } from "./generate-production-green-stage-a-prerequisites.mjs";
import { readFreshProtectedMainIdentity } from "./stage-b-deployment-identity.mjs";
import { assertStageBArtifactPath, ensureStageBPrivateDirectory, readBoundStageBPrivateJson, readStageBPrivateFileBytes, writeStageBPrivateFileExclusive, writeStageBPrivateFilesAtomic } from "./stage-b-artifact-contract.mjs";
import { canonicalSha256 } from "./stage-b-task-definition-recovery-contract.mjs";

export const STAGE_A_RECONCILIATION_AUTHORIZATION = Object.freeze({ schemaVersion: 1, kind: "STAGE_A_APPROVAL_KEY_RECONCILIATION_AUTHORIZATION", terraformRoot: "infra/aws/terraform/production-green-stage-a", approvalKeyTerraformAddress: "aws_kms_key.approval", maxTerraformApplies: 1 });
export const STAGE_A_RECONCILIATION_POLICY_DELTA = Object.freeze({ added: ["DenyNonCheckerApprovalSigning"], removed: [], modified: [] });
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const SHA = /^[a-f0-9]{64}$/;
const SHA40 = /^[a-f0-9]{40}$/;
const sha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const required = (argv, name) => { const i = argv.indexOf(name); const value = i < 0 ? undefined : argv[i + 1]; if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };
const exactFields = (value, fields, label) => {
  if (!value || typeof value !== "object" || Array.isArray(value) || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...fields].sort())) throw new Error(`${label} schema is invalid.`);
};
const requireSha = (value, label) => { if (!SHA.test(value || "")) throw new Error(`${label} is invalid.`); return value; };
const requireSha40 = (value, label) => { if (!SHA40.test(value || "")) throw new Error(`${label} is invalid.`); return value; };
const policySha256 = (policy) => canonicalSha256(policy);
const repository = PRODUCTION_ENVIRONMENT_APPROVAL.repository;
const artifactName = "stage-a-approval-key-reconciliation-authorization";
const maxArtifactArchiveBytes = 64 * 1024 * 1024;

function parsePolicy(value, label) {
  try { return typeof value === "string" ? JSON.parse(value) : value; } catch { throw new Error(`${label} is malformed.`); }
}

export function assertStageAApprovalKeyReconciliationPlan(plan, { approvalKeyArn, beforePolicySha256, afterPolicySha256 } = {}) {
  const changes = plan?.resource_changes;
  if (!Array.isArray(changes)) throw new Error("Stage-A reconciliation rendered plan is missing resource changes.");
  const actionable = changes.filter(({ change } = {}) => JSON.stringify(change?.actions) !== JSON.stringify(["no-op"]) && JSON.stringify(change?.actions) !== JSON.stringify(["read"]));
  if (actionable.length !== 1) throw new Error("Stage-A reconciliation plan must contain exactly one actionable resource.");
  const [entry] = actionable;
  if (entry.address !== STAGE_A_RECONCILIATION_AUTHORIZATION.approvalKeyTerraformAddress || entry.type !== "aws_kms_key" || JSON.stringify(entry.change?.actions) !== JSON.stringify(["update"]) || entry.change?.replace_paths?.length) throw new Error("Stage-A reconciliation plan is not the exact approval-key policy update.");
  const beforeResource = entry.change?.before; const afterResource = entry.change?.after;
  if (!beforeResource || typeof beforeResource !== "object" || !afterResource || typeof afterResource !== "object") throw new Error("Stage-A reconciliation plan resource values are incomplete.");
  const withoutPolicy = (value) => { const copy = { ...value }; delete copy.policy; return copy; };
  if (canonicalSha256(withoutPolicy(beforeResource)) !== canonicalSha256(withoutPolicy(afterResource))) throw new Error("Stage-A reconciliation plan changes a non-policy approval-key attribute.");
  const normalizeMetadata = (value, label) => {
    if (value === undefined || value === null) return {};
    if (typeof value !== "object" || Array.isArray(value)) throw new Error(`Stage-A reconciliation plan ${label} metadata is invalid.`);
    const normalized = {};
    for (const [key, child] of Object.entries(value)) {
      if (child === false || child === null) continue;
      if (child === true) { normalized[key] = true; continue; }
      if (typeof child !== "object" || Array.isArray(child)) throw new Error(`Stage-A reconciliation plan ${label} metadata is invalid.`);
      const nested = normalizeMetadata(child, label);
      if (Object.keys(nested).length > 0) normalized[key] = nested;
    }
    return normalized;
  };
  const metadata = Object.fromEntries(["before_unknown", "after_unknown", "before_sensitive", "after_sensitive"].map((field) => [field, normalizeMetadata(entry.change?.[field], field)]));
  const nonPolicyMetadata = (field) => withoutPolicy(metadata[field]);
  if (canonicalSha256(nonPolicyMetadata("before_unknown")) !== canonicalSha256(nonPolicyMetadata("after_unknown"))
    || canonicalSha256(nonPolicyMetadata("before_sensitive")) !== canonicalSha256(nonPolicyMetadata("after_sensitive"))) throw new Error("Stage-A reconciliation plan contains non-policy unknown or sensitive changes.");
  if (Object.keys(nonPolicyMetadata("before_unknown")).length > 0 || Object.keys(nonPolicyMetadata("after_unknown")).length > 0) throw new Error("Stage-A reconciliation plan contains actionable non-policy unknown changes.");
  if (metadata.before_unknown.policy || metadata.after_unknown.policy) throw new Error("Stage-A reconciliation plan policy must be known.");
  const before = parsePolicy(entry.change?.before?.policy, "Stage-A approval-key before policy");
  const after = parsePolicy(entry.change?.after?.policy, "Stage-A approval-key after policy");
  if (entry.change?.before?.arn !== approvalKeyArn || entry.change?.after?.arn !== approvalKeyArn || policySha256(before) !== beforePolicySha256 || policySha256(after) !== afterPolicySha256) throw new Error("Stage-A reconciliation plan policy binding is not exact.");
  const sids = (policy) => new Map((policy?.Statement || []).map((statement) => [statement?.Sid, canonicalSha256(statement)]));
  const oldSids = sids(before); const newSids = sids(after);
  const added = [...newSids.keys()].filter((sid) => !oldSids.has(sid)).sort();
  const removed = [...oldSids.keys()].filter((sid) => !newSids.has(sid)).sort();
  const modified = [...newSids.keys()].filter((sid) => oldSids.has(sid) && oldSids.get(sid) !== newSids.get(sid)).sort();
  if (JSON.stringify({ added, removed, modified }) !== JSON.stringify(STAGE_A_RECONCILIATION_POLICY_DELTA)) throw new Error("Stage-A reconciliation plan policy delta is not exact.");
  assertStageAApprovalKeyPolicyDocument(after);
  if (!(before?.Statement || []).some(({ Sid }) => Sid === "AccountAdministration") || !(before?.Statement || []).some(({ Sid }) => Sid === "IndependentCheckerSigns") || (before?.Statement || []).some(({ Sid }) => Sid === "DenyNonCheckerApprovalSigning")) throw new Error("Stage-A reconciliation predecessor policy is not the expected drift state.");
  return Object.freeze({ resourceChangeCount: 1, createCount: 0, updateCount: 1, deleteCount: 0, replaceCount: 0, changedAddresses: [entry.address], policyStatementsAdded: added, policyStatementsRemoved: removed, policyStatementsModified: modified });
}

const authorizationFields = new Set(["schemaVersion", "kind", "environment", "sourceSha", "protectedEnvironmentApprovalEvidence", "protectedEnvironmentApprovalEvidenceSha256", "savedPlanSha256", "renderedPlanSha256", "stageAStateLineage", "stageAStateSerial", "stageAStateSha256", "approvalKeyTerraformAddress", "approvalKeyArn", "beforePolicySha256", "afterPolicySha256", "planResourceChangeCount", "planCreateCount", "planUpdateCount", "planDeleteCount", "planReplaceCount", "planChangedAddresses", "policyStatementsAdded", "policyStatementsRemoved", "policyStatementsModified", "maxTerraformApplies", "authorizationSha256"]);

export function createStageAApprovalKeyReconciliationAuthorization(input = {}) {
  const environmentEvidence = input.protectedEnvironmentApprovalEvidence;
  assertProductionEnvironmentApprovalIdentity(environmentEvidence, { sourceSha: input.sourceSha, repository: PRODUCTION_ENVIRONMENT_APPROVAL.repository });
  if (environmentEvidence.workflowRef !== PRODUCTION_ENVIRONMENT_APPROVAL.stageAReconciliationWorkflowRef) throw new Error("Stage-A reconciliation requires authorization-only protected-environment evidence.");
  const plan = input.renderedPlan === undefined
    ? { resourceChangeCount: 1, createCount: 0, updateCount: 1, deleteCount: 0, replaceCount: 0, changedAddresses: [STAGE_A_RECONCILIATION_AUTHORIZATION.approvalKeyTerraformAddress], policyStatementsAdded: STAGE_A_RECONCILIATION_POLICY_DELTA.added, policyStatementsRemoved: [], policyStatementsModified: [] }
    : assertStageAApprovalKeyReconciliationPlan(input.renderedPlan, input);
  const body = {
    schemaVersion: STAGE_A_RECONCILIATION_AUTHORIZATION.schemaVersion, kind: STAGE_A_RECONCILIATION_AUTHORIZATION.kind, environment: "production", sourceSha: requireSha40(input.sourceSha, "sourceSha"), protectedEnvironmentApprovalEvidence: environmentEvidence, protectedEnvironmentApprovalEvidenceSha256: environmentEvidence.evidenceSha256,
    savedPlanSha256: requireSha(input.savedPlanSha256, "savedPlanSha256"), renderedPlanSha256: requireSha(input.renderedPlanSha256, "renderedPlanSha256"), stageAStateLineage: input.stageAStateLineage, stageAStateSerial: input.stageAStateSerial, stageAStateSha256: requireSha(input.stageAStateSha256, "stageAStateSha256"), approvalKeyTerraformAddress: input.approvalKeyTerraformAddress, approvalKeyArn: input.approvalKeyArn, beforePolicySha256: requireSha(input.beforePolicySha256, "beforePolicySha256"), afterPolicySha256: requireSha(input.afterPolicySha256, "afterPolicySha256"),
    planResourceChangeCount: plan.resourceChangeCount, planCreateCount: plan.createCount, planUpdateCount: plan.updateCount, planDeleteCount: plan.deleteCount, planReplaceCount: plan.replaceCount, planChangedAddresses: plan.changedAddresses, policyStatementsAdded: plan.policyStatementsAdded, policyStatementsRemoved: plan.policyStatementsRemoved, policyStatementsModified: plan.policyStatementsModified, maxTerraformApplies: STAGE_A_RECONCILIATION_AUTHORIZATION.maxTerraformApplies,
  };
  if (!/^[0-9a-f-]{36}$/.test(body.stageAStateLineage || "") || !Number.isSafeInteger(body.stageAStateSerial) || body.stageAStateSerial < 1 || body.approvalKeyTerraformAddress !== STAGE_A_RECONCILIATION_AUTHORIZATION.approvalKeyTerraformAddress || !/^arn:aws:kms:eu-west-2:368992683803:key\/[0-9a-f-]{36}$/.test(body.approvalKeyArn || "")) throw new Error("Stage-A reconciliation authorization bindings are invalid.");
  return Object.freeze({ ...body, authorizationSha256: canonicalSha256(body) });
}

export function assertStageAApprovalKeyReconciliationAuthorization(value, { sourceSha } = {}) {
  exactFields(value, authorizationFields, "Stage-A reconciliation authorization");
  if (value.schemaVersion !== STAGE_A_RECONCILIATION_AUTHORIZATION.schemaVersion || value.kind !== STAGE_A_RECONCILIATION_AUTHORIZATION.kind || value.environment !== "production" || value.sourceSha !== sourceSha) throw new Error("Stage-A reconciliation authorization identity is invalid.");
  const { authorizationSha256, ...body } = value;
  if (!SHA.test(authorizationSha256 || "") || canonicalSha256(body) !== authorizationSha256 || body.protectedEnvironmentApprovalEvidenceSha256 !== body.protectedEnvironmentApprovalEvidence?.evidenceSha256) throw new Error("Stage-A reconciliation authorization hash is invalid.");
  assertProductionEnvironmentApprovalIdentity(body.protectedEnvironmentApprovalEvidence, { sourceSha, repository: PRODUCTION_ENVIRONMENT_APPROVAL.repository });
  if (body.protectedEnvironmentApprovalEvidence.workflowRef !== PRODUCTION_ENVIRONMENT_APPROVAL.stageAReconciliationWorkflowRef
    || !SHA.test(body.savedPlanSha256) || !SHA.test(body.renderedPlanSha256) || !/^[0-9a-f-]{36}$/.test(body.stageAStateLineage || "")
    || !Number.isSafeInteger(body.stageAStateSerial) || body.stageAStateSerial < 1 || !SHA.test(body.stageAStateSha256)
    || body.approvalKeyTerraformAddress !== STAGE_A_RECONCILIATION_AUTHORIZATION.approvalKeyTerraformAddress
    || !/^arn:aws:kms:eu-west-2:368992683803:key\/[0-9a-f-]{36}$/.test(body.approvalKeyArn || "")
    || !SHA.test(body.beforePolicySha256) || !SHA.test(body.afterPolicySha256)
    || body.planResourceChangeCount !== 1 || body.planCreateCount !== 0 || body.planUpdateCount !== 1 || body.planDeleteCount !== 0 || body.planReplaceCount !== 0
    || JSON.stringify(body.planChangedAddresses) !== JSON.stringify([STAGE_A_RECONCILIATION_AUTHORIZATION.approvalKeyTerraformAddress])
    || JSON.stringify(body.policyStatementsAdded) !== JSON.stringify(STAGE_A_RECONCILIATION_POLICY_DELTA.added)
    || JSON.stringify(body.policyStatementsRemoved) !== JSON.stringify([]) || JSON.stringify(body.policyStatementsModified) !== JSON.stringify([])
    || body.maxTerraformApplies !== 1) throw new Error("Stage-A reconciliation authorization binding is invalid.");
  return value;
}

export function materializeStageAReconciliationPlan({ savedPlanBytes, expectedSha256, applyPlanPath, repositoryRoot = root } = {}) {
  if (!Buffer.isBuffer(savedPlanBytes) || sha256(savedPlanBytes) !== expectedSha256) throw new Error("Stage-A reconciliation saved plan bytes are not authorized.");
  writeStageBPrivateFileExclusive({ filePath: applyPlanPath, bytes: savedPlanBytes, repositoryRoot, label: "Stage-A executor-owned saved plan" });
  const captured = readStageBPrivateFileBytes({ filePath: applyPlanPath, repositoryRoot, label: "Stage-A executor-owned saved plan" });
  if (captured.sha256 !== expectedSha256 || !captured.bytes.equals(savedPlanBytes)) throw new Error("Stage-A executor-owned saved plan changed during materialization.");
  return captured;
}

export function executeStageAApprovalKeyReconciliation({ authorization, sourceSha, savedPlanBytes, renderedPlanBytes, executorSavedPlanPath, repositoryRoot = root, readState, readPolicy, applySavedPlan, recordConsumption }) {
  assertStageAApprovalKeyReconciliationAuthorization(authorization, { sourceSha });
  if (!Buffer.isBuffer(savedPlanBytes) || sha256(savedPlanBytes) !== authorization.savedPlanSha256 || !Buffer.isBuffer(renderedPlanBytes) || sha256(renderedPlanBytes) !== authorization.renderedPlanSha256) throw new Error("Stage-A reconciliation saved or rendered plan changed after authorization.");
  const executorPlan = readStageBPrivateFileBytes({ filePath: executorSavedPlanPath, repositoryRoot, label: "Stage-A executor-owned saved plan" });
  if (executorPlan.sha256 !== authorization.savedPlanSha256 || !executorPlan.bytes.equals(savedPlanBytes)) throw new Error("Stage-A executor-owned saved plan is not the authenticated plan.");
  const plan = JSON.parse(renderedPlanBytes); const semantics = assertStageAApprovalKeyReconciliationPlan(plan, authorization);
  const beforeStateBytes = Buffer.from(readState()); const beforeState = parseAuthenticatedStateBytes(beforeStateBytes); const state = buildStageAStateIdentity(beforeState, { stateBytes: beforeStateBytes });
  if (state.lineage !== authorization.stageAStateLineage || state.serial !== authorization.stageAStateSerial || state.stateSha256 !== authorization.stageAStateSha256) throw new Error("Stage-A state changed since authorization.");
  const beforePolicy = readPolicy();
  if (policySha256(beforePolicy) !== authorization.beforePolicySha256) throw new Error("Stage-A approval-key policy changed since authorization.");
  recordConsumption({ authorizationSha256: authorization.authorizationSha256 });
  applySavedPlan({ path: executorPlan.path, bytes: executorPlan.bytes, sha256: executorPlan.sha256 });
  const afterStateBytes = Buffer.from(readState()); const afterState = parseAuthenticatedStateBytes(afterStateBytes); const next = buildStageAStateIdentity(afterState, { stateBytes: afterStateBytes });
  if (next.lineage !== state.lineage || next.serial !== state.serial + 1) throw new Error("Stage-A post-apply state progression is invalid.");
  const afterPolicy = readPolicy();
  if (policySha256(afterPolicy) !== authorization.afterPolicySha256) throw new Error("Stage-A approval-key policy does not match authorized postcondition.");
  assertStageAApprovalKeyPolicyDocument(afterPolicy);
  return Object.freeze({ applied: true, appliedPlanSha256: executorPlan.sha256, authorizationSha256: authorization.authorizationSha256, semantics, preApplyState: state, postApplyState: next });
}

export function resolveStageAReconciliationAuthorizationArtifact({ workflowRunId, workflowRunAttempt, sourceSha, run = (command, args, options = {}) => execFileSync(command, args, { encoding: options.encoding === null ? null : "utf8", maxBuffer: options.maxBuffer }), download } = {}) {
  if (!/^[1-9][0-9]*$/.test(String(workflowRunId || "")) || !/^[1-9][0-9]*$/.test(String(workflowRunAttempt || "")) || !SHA40.test(sourceSha || "")) throw new Error("Stage-A authorization workflow coordinates are invalid.");
  const workflow = JSON.parse(run("gh", ["api", `repos/${repository}/actions/runs/${workflowRunId}`]));
  if (String(workflow.id) !== String(workflowRunId) || workflow.repository?.full_name !== repository || workflow.head_repository?.full_name !== repository || workflow.path !== ".github/workflows/authorize-production-stage-a-reconciliation.yml" || workflow.event !== "workflow_dispatch" || workflow.head_sha !== sourceSha || workflow.status !== "completed" || workflow.conclusion !== "success" || String(workflow.run_attempt) !== String(workflowRunAttempt)) throw new Error("Stage-A authorization workflow provenance is not authentic.");
  const pages = JSON.parse(run("gh", ["api", `repos/${repository}/actions/runs/${workflowRunId}/artifacts`, "--paginate", "--slurp"]));
  if (!Array.isArray(pages) || pages.some((page) => !Array.isArray(page?.artifacts))) throw new Error("Stage-A authorization artifact listing is malformed.");
  const matches = pages.flatMap((page) => page.artifacts).filter((artifact) => artifact.name === artifactName && artifact.expired === false && String(artifact.workflow_run?.id) === String(workflowRunId) && artifact.workflow_run?.head_sha === sourceSha && artifact.workflow_run?.repository_id === workflow.repository.id && /^sha256:[a-f0-9]{64}$/.test(artifact.digest || ""));
  if (matches.length !== 1) throw new Error("Stage-A authorization workflow must expose exactly one unexpired authorization artifact.");
  const artifact = matches[0];
  if (!Number.isSafeInteger(artifact.id) || artifact.id < 1) throw new Error("Stage-A authorization artifact ID is invalid.");
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-stage-a-authorization-")); const archive = path.join(directory, "authorization.zip");
  try {
    const downloadArtifact = download || ((id, file) => {
      const archiveBytes = run("gh", ["api", `repos/${repository}/actions/artifacts/${id}/zip`], { encoding: null, maxBuffer: maxArtifactArchiveBytes });
      if (!Buffer.isBuffer(archiveBytes) || archiveBytes.length === 0) throw new Error("Stage-A authorization artifact download is empty or not binary.");
      writeStageBPrivateFileExclusive({ filePath: file, bytes: archiveBytes, repositoryRoot: root, label: "Stage-A authorization artifact archive" });
    });
    downloadArtifact(artifact.id, archive);
    const archiveBytes = fs.readFileSync(archive);
    if (`sha256:${sha256(archiveBytes)}` !== artifact.digest) throw new Error("Stage-A authorization artifact archive digest is invalid.");
    const entries = String(run("unzip", ["-Z1", archive])).trim().split("\n").filter(Boolean);
    if (JSON.stringify(entries) !== JSON.stringify(["authorization.json"])) throw new Error("Stage-A authorization archive contents are not exact.");
    const listing = String(run("unzip", ["-Z", "-l", archive])).split("\n").filter((line) => line.trim().endsWith(" authorization.json"));
    if (listing.length !== 1 || !listing[0].trim().startsWith("-")) throw new Error("Stage-A authorization archive authorization.json must be a regular file.");
    const authorizationBytes = Buffer.from(run("unzip", ["-p", archive, "authorization.json"]));
    return { workflow, artifact, authorizationBytes };
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
}

export async function runCli(argv = process.argv.slice(2), deps = {}) {
  if (argv.includes("--execute")) {
    const run = deps.run || ((command, args) => execFileSync(command, args, { encoding: "utf8" }));
    const sourceSha = required(argv, "--source-sha");
    const resolved = (deps.resolveAuthorizationArtifact || resolveStageAReconciliationAuthorizationArtifact)({ workflowRunId: required(argv, "--workflow-run-id"), workflowRunAttempt: required(argv, "--workflow-run-attempt"), sourceSha, run });
    const authorization = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(resolved.authorizationBytes));
    if (authorization?.protectedEnvironmentApprovalEvidence?.workflowRunId !== String(resolved.workflow.id) || authorization?.protectedEnvironmentApprovalEvidence?.workflowRunAttempt !== String(resolved.workflow.run_attempt) || authorization?.protectedEnvironmentApprovalEvidence?.executionActor?.toLowerCase() !== String(resolved.workflow.actor?.login || "").toLowerCase()) throw new Error("Stage-A authorization environment approval is not bound to the resolved workflow run.");
    const checkout = (deps.readProtectedMain || readFreshProtectedMainIdentity)({ cwd: root, expectedSourceSha: sourceSha });
    if (checkout.headSha !== sourceSha || checkout.freshRemoteMainSha !== sourceSha) throw new Error("Stage-A executor is not at the authorized protected source.");
    const savedPlanPath = path.resolve(required(argv, "--saved-plan")); const savedPlanBytes = fs.readFileSync(savedPlanPath);
    const consumeDirectory = path.join(process.env.HOME || "", ".mscqr", "production-stage-a", "reconciliation-attempts");
    ensureStageBPrivateDirectory({ directory: consumeDirectory, repositoryRoot: root, create: true, label: "Stage-A reconciliation consumption directory" });
    const executorSavedPlanPath = path.join(consumeDirectory, `${authorization.authorizationSha256}.tfplan`);
    const executorPlan = materializeStageAReconciliationPlan({ savedPlanBytes, expectedSha256: authorization.savedPlanSha256, applyPlanPath: executorSavedPlanPath, repositoryRoot: root });
    const renderedPlanBytes = Buffer.from(run("terraform", [`-chdir=${STAGE_A_RECONCILIATION_AUTHORIZATION.terraformRoot}`, "show", "-json", executorPlan.path]));
    const readState = () => run("terraform", [`-chdir=${STAGE_A_RECONCILIATION_AUTHORIZATION.terraformRoot}`, "state", "pull"]);
    const readPolicy = () => {
      const output = JSON.parse(run("aws", ["kms", "get-key-policy", "--key-id", authorization.approvalKeyArn, "--policy-name", "default", "--output", "json", "--no-cli-pager"]));
      return parsePolicy(decodeURIComponent(output.Policy), "Live Stage-A approval-key policy");
    };
    return executeStageAApprovalKeyReconciliation({ authorization, sourceSha, savedPlanBytes, renderedPlanBytes, executorSavedPlanPath, repositoryRoot: root, readState, readPolicy,
      recordConsumption: () => writeStageBPrivateFileExclusive({ filePath: path.join(consumeDirectory, `${authorization.authorizationSha256}.json`), bytes: Buffer.from(`${JSON.stringify({ authorizationSha256: authorization.authorizationSha256, attemptedAt: new Date().toISOString() })}\n`), repositoryRoot: root, label: "Stage-A reconciliation consumption record" }),
      applySavedPlan: ({ path: applyPath, sha256: appliedPlanSha256 }) => { if (appliedPlanSha256 !== authorization.savedPlanSha256 || applyPath !== executorSavedPlanPath) throw new Error("Stage-A executor apply artifact binding is invalid."); return run("terraform", [`-chdir=${STAGE_A_RECONCILIATION_AUTHORIZATION.terraformRoot}`, "apply", "-input=false", applyPath]); },
    });
  }
  if (!argv.includes("--authorize")) throw new Error("Stage-A reconciliation CLI requires --authorize or --execute.");
  const output = assertStageBArtifactPath({ artifactPath: path.resolve(required(argv, "--output")), repositoryRoot: root, label: "Stage-A reconciliation authorization", allowExisting: false });
  ensureStageBPrivateDirectory({ directory: path.dirname(output), repositoryRoot: root, label: "Stage-A reconciliation authorization directory" });
  const env = deps.env || process.env;
  const environmentApproval = readBoundStageBPrivateJson({ filePath: required(argv, "--environment-approval"), expectedSha256: required(argv, "--environment-approval-sha256"), repositoryRoot: root, label: "Protected-environment approval evidence" });
  const sourceSha = required(argv, "--source-sha");
  assertProductionEnvironmentApprovalEvidence(environmentApproval, { sourceSha, repository: env.GITHUB_REPOSITORY, environment: "production", workflowRef: env.GITHUB_WORKFLOW_REF, eventName: env.GITHUB_EVENT_NAME, workflowRunId: env.GITHUB_RUN_ID, workflowRunAttempt: env.GITHUB_RUN_ATTEMPT, executionActor: env.GITHUB_ACTOR, githubActions: env.GITHUB_ACTIONS });
  const authorization = createStageAApprovalKeyReconciliationAuthorization({ protectedEnvironmentApprovalEvidence: environmentApproval, sourceSha, savedPlanSha256: required(argv, "--saved-plan-sha256"), renderedPlanSha256: required(argv, "--rendered-plan-sha256"), stageAStateLineage: required(argv, "--stage-a-state-lineage"), stageAStateSerial: Number(required(argv, "--stage-a-state-serial")), stageAStateSha256: required(argv, "--stage-a-state-sha256"), approvalKeyTerraformAddress: required(argv, "--approval-key-terraform-address"), approvalKeyArn: required(argv, "--approval-key-arn"), beforePolicySha256: required(argv, "--before-policy-sha256"), afterPolicySha256: required(argv, "--after-policy-sha256") });
  writeStageBPrivateFilesAtomic({ repositoryRoot: root, files: [{ filePath: output, bytes: Buffer.from(`${JSON.stringify(authorization, null, 2)}\n`), label: "Stage-A reconciliation authorization" }] });
  return authorization;
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) runCli().then((result) => process.stdout.write(`${JSON.stringify(result, null, 2)}\n`));
