import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import JSZip from "jszip";
import { buildStageAApprovalKeyPolicy } from "../aws/production-stage-a-control-plane.mjs";
import { createProductionEnvironmentApprovalEvidence, PRODUCTION_ENVIRONMENT_APPROVAL } from "../aws/production-github-environment-approval.mjs";
import { createStageAApprovalKeyReconciliationAuthorization, runCli as authorizationCli } from "../aws/production-stage-a-approval-key-reconciliation-authorization.mjs";
import { assertTemporaryReleasePolicy } from "../aws/production-stage-a-temporary-kms-capability.mjs";
import { assertApprovalKeyReconciliationCapabilityEvidence, assertApprovalKeyReconciliationSteadyPolicy, assertTemporaryApprovalKeyCapabilityPolicy, buildApprovalKeyReconciliationCapabilityEvidence, buildTemporaryApprovalKeyCapabilityPolicy, createApprovalKeyReconciliationCapabilityRunner, STAGE_A_APPROVAL_KEY_RECONCILIATION_CAPABILITY } from "../aws/run-production-stage-a-approval-key-reconciliation.mjs";
import { canonicalSha256 } from "../aws/stage-b-task-definition-recovery-contract.mjs";
import { stageAStateSemanticSha256 } from "../aws/generate-production-green-stage-a-prerequisites.mjs";

const sourceSha = "e".repeat(40);
const approvalKeyArn = STAGE_A_APPROVAL_KEY_RECONCILIATION_CAPABILITY.approvalKeyArn;
const steadyPolicy = JSON.parse(fs.readFileSync("documents/ops/iam/MSCQRProductionGreenStageAReleaseS3Contract-v1.json", "utf8"));
const beforePolicy = { Version: "2012-10-17", Statement: buildStageAApprovalKeyPolicy().Statement.filter(({ Sid }) => Sid !== "DenyNonCheckerApprovalSigning") };
const afterPolicy = buildStageAApprovalKeyPolicy();
const evidence = () => createProductionEnvironmentApprovalEvidence({ repository: PRODUCTION_ENVIRONMENT_APPROVAL.repository, environment: "production", sourceSha, workflowRef: PRODUCTION_ENVIRONMENT_APPROVAL.stageAReconciliationWorkflowRef, eventName: "workflow_dispatch", workflowRunId: "17", workflowRunAttempt: "2", executionActor: "operator", observedAt: "2026-08-28T12:00:00.000Z", environmentConfig: { id: 1, name: "production", can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: false, reviewers: [{ type: "User", reviewer: { id: 1, login: "reviewer" } }] }] } });
const authorization = () => createStageAApprovalKeyReconciliationAuthorization({ protectedEnvironmentApprovalEvidence: evidence(), sourceSha, savedPlanSha256: "a".repeat(64), renderedPlanSha256: "b".repeat(64), stageAStateLineage: "02afb75a-f902-ab8a-f4c1-751d4aef7837", stageAStateSerial: 53, stageAStateSha256: "c".repeat(64), approvalKeyTerraformAddress: "aws_kms_key.approval", approvalKeyArn, beforePolicySha256: canonicalSha256(beforePolicy), afterPolicySha256: canonicalSha256(afterPolicy) });
const workflow = () => ({ id: 17, run_attempt: 2, path: ".github/workflows/authorize-production-stage-a-reconciliation.yml" });
const artifact = () => ({ id: 9, name: "stage-a-approval-key-reconciliation-authorization", expired: false, digest: `sha256:${"d".repeat(64)}`, workflow_run: { id: 17, head_sha: sourceSha } });

function lifecycle({ failApply = false, failCleanup = false, createThrowsAfterMutation = false, failAllRecoveryReads = false, failFirstRecoveryRead = false, setDefaultReportsFailure = false, deleteReportsFailure = false, makeCapabilityAbsentBeforeCleanup = false, returnedVersionId = "v2", staleCreateReads = 0, staleRestoreReads = 0, staleDeleteReads = 0 } = {}) {
  const auth = authorization(); let defaultVersionId = "v1"; const versions = new Map([["v1", steadyPolicy]]); let applies = 0; const calls = []; const delays = []; let createAttempted = false; let recoveryReads = 0; let phase = "steady";
  const snapshot = (temporary = false) => temporary ? { defaultVersionId: "v2", versions: [["v1", steadyPolicy], ["v2", buildTemporaryApprovalKeyCapabilityPolicy(steadyPolicy, auth)]].map(([VersionId, document]) => ({ VersionId, document })) } : { defaultVersionId: "v1", versions: [["v1", steadyPolicy]].map(([VersionId, document]) => ({ VersionId, document })) };
  const topology = () => {
    if (createAttempted && (failAllRecoveryReads || (failFirstRecoveryRead && recoveryReads++ === 0))) throw new Error("topology read failed");
    if (phase === "temporary" && staleCreateReads-- > 0) return snapshot();
    if (phase === "restored" && staleRestoreReads-- > 0) return snapshot(true);
    if (phase === "deleted" && staleDeleteReads-- > 0) return snapshot(true);
    return { defaultVersionId, versions: [...versions].map(([VersionId, document]) => ({ VersionId, document })) };
  };
  const runner = createApprovalKeyReconciliationCapabilityRunner({ authorization: auth, sourceSha, workflow: workflow(), artifact: artifact(), steadyPolicy,
    readTopology: topology,
    createTemporaryVersion: (document) => { calls.push("create"); createAttempted = true; versions.set("v2", document); defaultVersionId = "v2"; phase = "temporary"; if (createThrowsAfterMutation) throw new Error("create failed after remote acceptance"); return { VersionId: returnedVersionId }; },
    setDefaultVersion: (versionId) => { calls.push(`restore:${versionId}`); if (failCleanup) throw new Error("restore failed"); defaultVersionId = versionId; phase = "restored"; if (setDefaultReportsFailure) throw new Error("restore response lost"); },
    deletePolicyVersion: (versionId) => { calls.push(`delete:${versionId}`); versions.delete(versionId); phase = "deleted"; if (deleteReportsFailure) throw new Error("delete response lost"); },
    verifyEffectiveCapability: () => { calls.push("effective"); return true; },
    verifyCapabilityAbsent: () => { calls.push("absent"); return true; },
    executeAuthorization: () => { calls.push("apply"); applies += 1; if (makeCapabilityAbsentBeforeCleanup) { defaultVersionId = "v1"; versions.delete("v2"); phase = "deleted"; } if (failApply) throw new Error("apply failed"); return { applied: true }; },
    sleep: (milliseconds) => { delays.push(milliseconds); },
  });
  return { auth, runner, topology, calls, delays, applies: () => applies };
}

test("approval-key capability is a single exact PutKeyPolicy statement and preserves steady state", () => {
  const auth = authorization(); const policy = buildTemporaryApprovalKeyCapabilityPolicy(steadyPolicy, auth);
  assert.equal(assertApprovalKeyReconciliationSteadyPolicy(steadyPolicy), true);
  assert.equal(assertTemporaryApprovalKeyCapabilityPolicy(policy, { steadyPolicy, authorization: auth }), true);
  const statement = policy.Statement.at(-1);
  assert.deepEqual({ Effect: statement.Effect, Action: statement.Action, Resource: statement.Resource }, { Effect: "Allow", Action: "kms:PutKeyPolicy", Resource: approvalKeyArn });
  assert.equal(statement.Resource === "*", false);
  assert.throws(() => assertTemporaryApprovalKeyCapabilityPolicy({ ...policy, Statement: [...policy.Statement.slice(0, -1), { ...statement, Resource: "*" }] }, { steadyPolicy, authorization: auth }), /exact|changes/i);
  assert.throws(() => assertTemporaryApprovalKeyCapabilityPolicy({ ...policy, Statement: [...policy.Statement.slice(0, -1), { ...statement, Action: ["kms:PutKeyPolicy", "kms:ScheduleKeyDeletion"] }] }, { steadyPolicy, authorization: auth }), /exact|additional/i);
  assert.throws(() => assertTemporaryReleasePolicy(policy, { steadyStatePolicy: steadyPolicy, sourceSha, transitionId: "root-drop" }), /exact|temporary/i);
});

test("capability evidence binds the independently approved authorization, workflow, artifact, source, plan, state, and policy", () => {
  const auth = authorization(); const record = buildApprovalKeyReconciliationCapabilityEvidence({ authorization: auth, workflow: workflow(), artifact: artifact(), previousDefaultVersionId: "v1", temporaryVersionId: "v2" });
  assert.equal(assertApprovalKeyReconciliationCapabilityEvidence(record, { authorization: auth, workflow: workflow(), artifact: artifact() }), record);
  for (const field of ["repository", "sourceSha", "workflowRef", "workflowRunId", "workflowRunAttempt", "authorizationArtifactId", "authorizationArtifactName", "authorizationArtifactDigest", "savedPlanSha256", "renderedPlanSha256", "stageAStateLineage", "stageAStateSerial", "stageAStateSha256", "approvalKeyArn", "beforePolicySha256", "afterPolicySha256"]) {
    const changed = { ...record, [field]: typeof record[field] === "number" ? record[field] + 1 : `${record[field]}x` }; const { capabilitySha256, ...body } = changed; changed.capabilitySha256 = canonicalSha256(body);
    assert.throws(() => assertApprovalKeyReconciliationCapabilityEvidence(changed, { authorization: auth, workflow: workflow(), artifact: artifact() }), /bound|invalid/i, field);
  }
  assert.throws(() => createApprovalKeyReconciliationCapabilityRunner({ authorization: { kind: "MSCQR_TEMPORARY_STAGE_A_KMS_CAPABILITY" }, sourceSha, workflow: workflow(), artifact: artifact(), steadyPolicy }), /schema|identity/i);
});

test("capability applies once only after establishment and restores then deletes on success and failure", () => {
  const success = lifecycle(); const result = success.runner.execute();
  assert.equal(result.applied, true); assert.deepEqual(success.calls, ["create", "effective", "apply", "restore:v1", "delete:v2", "absent"]); assert.equal(success.topology().defaultVersionId, "v1"); assert.equal(success.topology().versions.some(({ VersionId }) => VersionId === "v2"), false);
  assert.throws(() => success.runner.execute(), /already been attempted/i);
  const failure = lifecycle({ failApply: true }); assert.throws(() => failure.runner.execute(), /apply failed/); assert.deepEqual(failure.calls, ["create", "effective", "apply", "restore:v1", "delete:v2", "absent"]); assert.equal(failure.applies(), 1);
  const cleanupFailure = lifecycle({ failCleanup: true }); assert.throws(() => cleanupFailure.runner.execute(), /CRITICAL_TEMPORARY_CAPABILITY_CLEANUP_FAILURE/); assert.equal(cleanupFailure.calls.includes("apply"), true); assert.equal(cleanupFailure.calls.filter((call) => call === "restore:v1").length, 2);
});

test("unknown CreatePolicyVersion outcomes converge by exact policy identity before apply", () => {
  const remoteAccepted = lifecycle({ createThrowsAfterMutation: true, returnedVersionId: "v999" });
  assert.equal(remoteAccepted.runner.execute().applied, true);
  assert.equal(remoteAccepted.applies(), 1);
  assert.equal(remoteAccepted.topology().defaultVersionId, "v1");
  assert.equal(remoteAccepted.topology().versions.some(({ VersionId }) => VersionId === "v2"), false);
  assert.deepEqual(remoteAccepted.calls, ["create", "effective", "apply", "restore:v1", "delete:v2", "absent"]);

  const delayedRecovery = lifecycle({ createThrowsAfterMutation: true, failFirstRecoveryRead: true });
  assert.equal(delayedRecovery.runner.execute().applied, true);
  assert.equal(delayedRecovery.applies(), 1);
  assert.equal(delayedRecovery.topology().defaultVersionId, "v1");
  assert.equal(delayedRecovery.topology().versions.some(({ VersionId }) => VersionId === "v2"), false);
});

test("successful stale IAM topology reads converge before create, restore, and delete are accepted", () => {
  const delayed = lifecycle({ staleCreateReads: 3, staleRestoreReads: 2, staleDeleteReads: 2 });
  assert.equal(delayed.runner.execute().applied, true);
  assert.equal(delayed.applies(), 1);
  assert.equal(delayed.delays.length >= 7, true);
  assert.equal(delayed.delays.every((milliseconds) => milliseconds >= 100), true);
  assert.equal(delayed.topology().defaultVersionId, "v1");
  assert.equal(delayed.topology().versions.some(({ VersionId }) => VersionId === "v2"), false);

  const responseLost = lifecycle({ createThrowsAfterMutation: true, staleCreateReads: 2 });
  assert.equal(responseLost.runner.execute().applied, true);
  assert.equal(responseLost.applies(), 1);
  assert.equal(responseLost.delays.length >= 2, true);
});

test("unresolved successful stale reads fail closed before apply", () => {
  const unresolved = lifecycle({ staleCreateReads: Number.POSITIVE_INFINITY });
  assert.throws(() => unresolved.runner.execute(), (error) => error.code === "CRITICAL_TEMPORARY_CAPABILITY_CLEANUP_FAILURE" && error.capabilityState === "UNKNOWN");
  assert.equal(unresolved.applies(), 0);
  assert.equal(unresolved.delays.length > 0, true);
});

test("unrecoverable capability topology fails closed instead of skipping cleanup", () => {
  const unrecoverable = lifecycle({ createThrowsAfterMutation: true, failAllRecoveryReads: true });
  assert.throws(() => unrecoverable.runner.execute(), (error) => error.code === "CRITICAL_TEMPORARY_CAPABILITY_CLEANUP_FAILURE" && error.capabilityState === "UNKNOWN" && error.capabilityMutationAttempted === true);
  assert.equal(unrecoverable.applies(), 0);
});

test("restore and delete command errors are authenticated by live topology", () => {
  const restoreUnknown = lifecycle({ setDefaultReportsFailure: true });
  assert.equal(restoreUnknown.runner.execute().applied, true);
  assert.equal(restoreUnknown.topology().defaultVersionId, "v1");
  assert.equal(restoreUnknown.topology().versions.some(({ VersionId }) => VersionId === "v2"), false);

  const deleteUnknown = lifecycle({ deleteReportsFailure: true });
  assert.equal(deleteUnknown.runner.execute().applied, true);
  assert.equal(deleteUnknown.topology().defaultVersionId, "v1");
  assert.equal(deleteUnknown.topology().versions.some(({ VersionId }) => VersionId === "v2"), false);

  const alreadyAbsent = lifecycle({ makeCapabilityAbsentBeforeCleanup: true });
  assert.equal(alreadyAbsent.runner.execute().temporaryCapabilityRemoved, true);
  assert.equal(alreadyAbsent.topology().versions.some(({ VersionId }) => VersionId === "v2"), false);
});

test("wrong authorization source, approval key, steady privilege, or capacity is rejected before apply", () => {
  const auth = authorization(); const base = lifecycle();
  assert.throws(() => createApprovalKeyReconciliationCapabilityRunner({ authorization: auth, sourceSha: "a".repeat(40), workflow: workflow(), artifact: artifact(), steadyPolicy, readTopology: base.topology, createTemporaryVersion: () => {}, setDefaultVersion: () => {}, deletePolicyVersion: () => {}, verifyEffectiveCapability: () => true, verifyCapabilityAbsent: () => true, executeAuthorization: () => {} }), /identity/i);
  const altered = { ...auth, approvalKeyArn: "arn:aws:kms:eu-west-2:368992683803:key/11111111-1111-1111-1111-111111111111" }; const { authorizationSha256, ...body } = altered; altered.authorizationSha256 = canonicalSha256(body);
  assert.throws(() => buildTemporaryApprovalKeyCapabilityPolicy(steadyPolicy, altered), /exact approval key/i);
  assert.throws(() => assertApprovalKeyReconciliationSteadyPolicy({ ...steadyPolicy, Statement: [...steadyPolicy.Statement, { Effect: "Allow", Action: "kms:PutKeyPolicy", Resource: approvalKeyArn }] }), /must not grant/i);
  const full = lifecycle(); const five = { ...full.topology(), versions: ["v1", "v2", "v3", "v4", "v5"].map((VersionId) => ({ VersionId, document: VersionId === "v1" ? steadyPolicy : { Version: "2012-10-17", Statement: [] } })) };
  const capacity = createApprovalKeyReconciliationCapabilityRunner({ authorization: auth, sourceSha, workflow: workflow(), artifact: artifact(), steadyPolicy, readTopology: () => five, createTemporaryVersion: () => { throw new Error("must be unreachable"); }, setDefaultVersion: () => {}, deletePolicyVersion: () => {}, verifyEffectiveCapability: () => true, verifyCapabilityAbsent: () => true, executeAuthorization: () => { throw new Error("must be unreachable"); } });
  assert.throws(() => capacity.execute(), /capacity/i);
});

test("full managed-policy capacity prunes only a dated non-default authenticated steady version", () => {
  const auth = authorization(); let defaultVersionId = "v1"; const versions = new Map([["v1", steadyPolicy], ["v2", steadyPolicy], ["v3", { Version: "2012-10-17", Statement: [] }], ["v4", { Version: "2012-10-17", Statement: [] }], ["v5", { Version: "2012-10-17", Statement: [] }]]); const calls = [];
  const topology = () => ({ defaultVersionId, versions: [...versions].map(([VersionId, document], index) => ({ VersionId, document, CreateDate: `2026-08-0${index + 1}T00:00:00.000Z` })) });
  const runner = createApprovalKeyReconciliationCapabilityRunner({ authorization: auth, sourceSha, workflow: workflow(), artifact: artifact(), steadyPolicy, readTopology: topology,
    createTemporaryVersion: (document) => { calls.push("create"); versions.set("v6", document); defaultVersionId = "v6"; return { VersionId: "v6" }; },
    setDefaultVersion: (versionId) => { calls.push(`restore:${versionId}`); defaultVersionId = versionId; },
    deletePolicyVersion: (versionId) => { calls.push(`delete:${versionId}`); versions.delete(versionId); },
    verifyEffectiveCapability: () => { calls.push("effective"); return true; }, verifyCapabilityAbsent: () => { calls.push("absent"); return true; }, executeAuthorization: () => { calls.push("apply"); return { applied: true }; }, sleep: () => {},
  });
  const result = runner.execute();
  assert.equal(result.capacityDeletedVersionId, "v2");
  assert.deepEqual(calls, ["delete:v2", "create", "effective", "apply", "restore:v1", "delete:v6", "absent"]);
});

test("authorization workflow authenticates protected source before lifecycle code and rechecks inputs afterward", async () => {
  const workflowSource = fs.readFileSync(".github/workflows/authorize-production-stage-a-reconciliation.yml", "utf8");
  assert.match(workflowSource, /actions\/setup-node@v6/); assert.match(workflowSource, /node-version: 24/); assert.match(workflowSource, /run: npm ci/);
  assert.doesNotMatch(workflowSource, /npm install|npm install -g|configure-aws-credentials|terraform (?:plan|apply)|update-service|stage-b/i);
  assert.match(workflowSource, /cache: npm/);
  const protectedSource = workflowSource.indexOf("Authenticate protected source before dependencies"); const install = workflowSource.indexOf("Install locked authorization dependencies"); const npm = workflowSource.indexOf("run: npm ci"); const postInstall = workflowSource.indexOf("Re-authenticate protected source after dependency installation"); const producer = workflowSource.indexOf("Authenticate protected environment approval");
  assert.equal(protectedSource >= 0 && protectedSource < npm && npm < postInstall && postInstall < producer, true);
  const preInstall = workflowSource.slice(protectedSource, install);
  assert.match(preInstall, /gh api "repos\/\$EXPECTED_REPOSITORY\/branches\/main"/); assert.match(preInstall, /test "\$SOURCE_SHA" = "\$protected_main_sha"/); assert.match(preInstall, /test "\$\(git rev-parse HEAD\)" = "\$SOURCE_SHA"/);
  assert.doesNotMatch(preInstall, /origin\/main|merge-base/);
  const preInstallScript = preInstall.match(/run: \|\n([\s\S]*?)\n\s*- name:/)?.[1] || "";
  assert.doesNotMatch(preInstallScript, /\bnpm\b|\bnode\b|scripts\//);
  const integrity = workflowSource.slice(postInstall, producer);
  assert.match(integrity, /git status --porcelain --untracked-files=no/); assert.match(integrity, /cmp --silent/); assert.match(integrity, /protected-source-inputs\.sha256/);
  assert.equal(fs.existsSync("package-lock.json"), true);
  assert.equal(typeof (await import("jszip")).default, "function");
});

test("governed CLI composes approved artifact, temporary capability, one saved-plan apply, and mandatory cleanup", async () => {
  const beforeState = { version: 4, lineage: "02afb75a-f902-ab8a-f4c1-751d4aef7837", serial: 53, resources: [] };
  const afterState = { ...beforeState, serial: 54 };
  const rendered = { resource_changes: [{ address: "aws_kms_key.approval", type: "aws_kms_key", change: { actions: ["update"], before: { arn: approvalKeyArn, policy: JSON.stringify(beforePolicy) }, after: { arn: approvalKeyArn, policy: JSON.stringify(afterPolicy) }, before_unknown: {}, after_unknown: {}, before_sensitive: { tags: {} }, after_sensitive: { tags: {} } } }] };
  const savedPlanBytes = Buffer.from("exact-saved-plan");
  const auth = createStageAApprovalKeyReconciliationAuthorization({ protectedEnvironmentApprovalEvidence: evidence(), sourceSha, savedPlanSha256: cryptoHash(savedPlanBytes), renderedPlanSha256: cryptoHash(Buffer.from(JSON.stringify(rendered))), renderedPlan: rendered, stageAStateLineage: beforeState.lineage, stageAStateSerial: beforeState.serial, stageAStateSha256: stageAStateSemanticSha256(beforeState), approvalKeyTerraformAddress: "aws_kms_key.approval", approvalKeyArn, beforePolicySha256: canonicalSha256(beforePolicy), afterPolicySha256: canonicalSha256(afterPolicy) });
  const bytes = Buffer.from(`${JSON.stringify(auth)}\n`); const archive = await new JSZip().file("authorization.json", bytes).generateAsync({ type: "nodebuffer" });
  const approvedRun = { id: 17, run_attempt: 2, path: ".github/workflows/authorize-production-stage-a-reconciliation.yml", event: "workflow_dispatch", head_sha: sourceSha, status: "completed", conclusion: "success", repository: { id: 1, full_name: "T-ej2003/genuine-scan-main" }, head_repository: { id: 1, full_name: "T-ej2003/genuine-scan-main" }, actor: { login: "operator" } };
  const artifact = { id: 9, name: "stage-a-approval-key-reconciliation-authorization", expired: false, digest: `sha256:${cryptoHash(archive)}`, workflow_run: { id: 17, head_sha: sourceSha, repository_id: 1 } };
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-stage-a-capability-cli-")); const planPath = path.join(directory, "approved.tfplan"); fs.writeFileSync(planPath, savedPlanBytes); const oldHome = process.env.HOME; process.env.HOME = directory;
  let state = beforeState; let policy = beforePolicy; let defaultVersion = "v1"; const versions = new Map([["v1", steadyPolicy]]); const calls = [];
  const run = (command, args, options = {}) => {
    calls.push({ command, args, options });
    if (command === "gh" && args[1] === "repos/T-ej2003/genuine-scan-main/actions/runs/17") return JSON.stringify(approvedRun);
    if (command === "gh" && args[1] === "repos/T-ej2003/genuine-scan-main/actions/runs/17/artifacts") return JSON.stringify([{ artifacts: [artifact] }]);
    if (command === "gh" && args[1] === "repos/T-ej2003/genuine-scan-main/actions/artifacts/9/zip") { assert.equal(options.encoding, null); return archive; }
    if (command === "unzip" && args[0] === "-Z1") return "authorization.json\n";
    if (command === "unzip" && args[0] === "-Z") return "-rw------- 1 operator operator 1 authorization.json\n";
    if (command === "unzip" && args[0] === "-p") return bytes.toString("utf8");
    throw new Error(`unexpected host command ${command}`);
  };
  const adminRun = (args) => {
    const operation = args[1]; calls.push({ command: "aws-admin", args });
    if (operation === "get-caller-identity") return JSON.stringify({ Arn: "arn:aws:iam::368992683803:root" });
    if (operation === "get-role") return JSON.stringify({ Role: { Arn: STAGE_A_APPROVAL_KEY_RECONCILIATION_CAPABILITY.releaseRoleArn } });
    if (operation === "list-attached-role-policies") return JSON.stringify({ AttachedPolicies: [{ PolicyArn: STAGE_A_APPROVAL_KEY_RECONCILIATION_CAPABILITY.policyArn }] });
    if (operation === "simulate-principal-policy") return JSON.stringify({ EvaluationResults: [{ EvalDecision: defaultVersion === "v2" ? "allowed" : "implicitDeny" }] });
    if (operation === "get-policy") return JSON.stringify({ Policy: { DefaultVersionId: defaultVersion } });
    if (operation === "list-policy-versions") return JSON.stringify({ Versions: [...versions.keys()].map((VersionId) => ({ VersionId })) });
    if (operation === "get-policy-version") return JSON.stringify({ PolicyVersion: { Document: versions.get(args.at(-1)) } });
    if (operation === "create-policy-version") { const file = args[args.indexOf("--policy-document") + 1].slice("file://".length); versions.set("v2", JSON.parse(fs.readFileSync(file, "utf8"))); defaultVersion = "v2"; return JSON.stringify({ PolicyVersion: { VersionId: "v2" } }); }
    if (operation === "set-default-policy-version") { defaultVersion = args.at(-1); return "{}"; }
    if (operation === "delete-policy-version") { versions.delete(args.at(-1)); return "{}"; }
    throw new Error(`unexpected administrator operation ${operation}`);
  };
  const releaseAws = (args) => {
    calls.push({ command: "aws-release", args });
    if (args[1] === "get-caller-identity") return JSON.stringify({ Arn: "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test" });
    if (args[1] === "get-key-policy") return JSON.stringify({ Policy: encodeURIComponent(JSON.stringify(policy)) });
    throw new Error(`unexpected release operation ${args[1]}`);
  };
  const releaseRun = (command, args) => {
    calls.push({ command, args });
    if (command !== "terraform") throw new Error("only Terraform may use release runner");
    if (args.includes("show")) return JSON.stringify(rendered);
    if (args.includes("state")) return JSON.stringify(state);
    if (args.includes("apply")) { state = afterState; policy = afterPolicy; return ""; }
    throw new Error("unexpected Terraform command");
  };
  try {
    const result = await authorizationCli(["--execute", "--source-sha", sourceSha, "--workflow-run-id", "17", "--workflow-run-attempt", "2", "--saved-plan", planPath, "--admin-profile", "root", "--release-profile", "release"], { run, adminRun, releaseAws, releaseRun, sleep: () => {}, readProtectedCheckout: () => ({ toolingSha: sourceSha }) });
    assert.equal(result.applied, true); assert.equal(result.temporaryCapabilityRemoved, true); assert.equal(defaultVersion, "v1"); assert.equal(versions.has("v2"), false);
    const zip = calls.find(({ command, args }) => command === "gh" && args[1].endsWith("/zip")); assert.equal(zip.options.encoding, null); assert.equal(calls.some(({ command, args }) => command === "terraform" && args.includes("apply") && args.includes(planPath)), false);
  } finally { process.env.HOME = oldHome; fs.rmSync(directory, { recursive: true, force: true }); }
});

const cryptoHash = (value) => crypto.createHash("sha256").update(value).digest("hex");
