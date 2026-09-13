#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { normalizeIamPolicyDocument } from "./iam-policy-document.mjs";
import { canonicalJson } from "./production-green-stage-b-contract.mjs";
import { createProductionAwsCommandRunner, createProductionGithubCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";
import { PRODUCTION_ENVIRONMENT_APPROVAL, assertProductionEnvironmentActualReviewer, assertProductionEnvironmentApprovalEvidence, assertProductionEnvironmentApprovalFreshness, assertProductionEnvironmentApprovalIdentity, createProductionEnvironmentApprovalEvidence } from "./production-github-environment-approval.mjs";
import { assertStageBArtifactPath, ensureStageBPrivateDirectory, readBoundStageBPrivateJson, writeStageBPrivateFilesAtomic } from "./stage-b-artifact-contract.mjs";
import { assertProtectedCheckout } from "./prepare-production-initial-activation-reconciler-installation.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const sha256 = (value) => crypto.createHash("sha256").update(Buffer.isBuffer(value) ? value : Buffer.from(canonicalJson(value))).digest("hex");
const runJson = (run, args) => JSON.parse(run([...args, "--output", "json", "--no-cli-pager"]));
const exactKeys = (value, keys, label) => {
  if (!value || typeof value !== "object" || Array.isArray(value) || canonicalJson(Object.keys(value).sort()) !== canonicalJson([...keys].sort())) throw new Error(`${label} schema is invalid.`);
  return value;
};
const required = (argv, name) => { const index = argv.indexOf(name); const value = index < 0 ? undefined : argv[index + 1]; if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };
const requiredSha = (value, label) => { if (!/^[a-f0-9]{40}$/.test(value || "")) throw new Error(`${label} must be an exact source SHA.`); return value; };
const parseGithubJson = (run, args, label) => { try { return JSON.parse(run("gh", args)); } catch { throw new Error(`${label} is malformed or unavailable.`); } };

export const BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION = Object.freeze({
  schemaVersion: 1,
  operation: "PRODUCTION_BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION",
  repository: "T-ej2003/genuine-scan-main",
  environment: "production",
  account: "368992683803",
  administratorArn: "arn:aws:iam::368992683803:root",
  userName: "mscqr-production-bootstrap-operator",
  userArn: "arn:aws:iam::368992683803:user/mscqr-production-bootstrap-operator",
  inlinePolicyName: "MSCQRProductionBootstrapOperator",
  releaseRoleArn: "arn:aws:iam::368992683803:role/mscqr-production-release-deployer",
  verifierRoleArn: "arn:aws:iam::368992683803:role/mscqr-production-ecs-exec-verifier",
  publisherBootstrapRoleArn: "arn:aws:iam::368992683803:role/mscqr-production-stage-b-publisher-bootstrap",
  sourcePath: "documents/ops/iam/MSCQRProductionBootstrapOperator-v1.json",
  workflowPath: ".github/workflows/authorize-production-bootstrap-operator-policy-reconciliation.yml",
  workflowRef: PRODUCTION_ENVIRONMENT_APPROVAL.bootstrapOperatorPolicyReconciliationWorkflowRef,
  artifactName: "production-bootstrap-operator-policy-reconciliation-authorization",
  authorizationFilename: "authorization.json",
  maxAgeMs: 30 * 60 * 1000,
  maxAwsMutations: Object.freeze({ "iam:PutUserPolicy": 1 }),
});

export function readBootstrapOperatorDesiredPolicy({ repositoryRoot = root } = {}) {
  const document = normalizeIamPolicyDocument(fs.readFileSync(path.resolve(repositoryRoot, BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.sourcePath), "utf8"), "bootstrap operator source policy");
  const expected = [
    { Sid: "AssumeReleaseRoleOnlyWithMfa", Effect: "Allow", Action: "sts:AssumeRole", Resource: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.releaseRoleArn, Condition: { Bool: { "aws:MultiFactorAuthPresent": "true" } } },
    { Sid: "AssumeEcsExecVerifierRoleOnlyWithMfa", Effect: "Allow", Action: "sts:AssumeRole", Resource: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.verifierRoleArn, Condition: { Bool: { "aws:MultiFactorAuthPresent": "true" } } },
    { Sid: "AssumeStageBPublisherBootstrapRoleOnlyWithMfa", Effect: "Allow", Action: "sts:AssumeRole", Resource: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.publisherBootstrapRoleArn, Condition: { Bool: { "aws:MultiFactorAuthPresent": "true" } } },
    { Sid: "ReadOwnMfaState", Effect: "Allow", Action: ["iam:GetUser", "iam:ListMFADevices"], Resource: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.userArn },
  ];
  if (document.Version !== "2012-10-17" || !Array.isArray(document.Statement) || document.Statement.length !== expected.length || expected.some((statement) => canonicalJson(document.Statement.find(({ Sid }) => Sid === statement.Sid)) !== canonicalJson(statement))) throw new Error("Bootstrap operator source policy is not the reviewed exact document.");
  const predecessorDocument = { Version: "2012-10-17", Statement: document.Statement.filter(({ Sid }) => Sid !== "AssumeEcsExecVerifierRoleOnlyWithMfa") };
  return Object.freeze({ document, predecessorDocument, sourcePolicySha256: sha256(document), predecessorPolicySha256: sha256(predecessorDocument) });
}

export function authenticateBootstrapOperatorLiveState(value, { desired = readBootstrapOperatorDesiredPolicy(), allowPostState = true } = {}) {
  exactKeys(value, ["user", "attachedPolicies", "inlinePolicyNames", "groups", "document"], "Bootstrap operator live state");
  if (value.user?.Arn !== BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.userArn || value.user?.UserName !== BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.userName || value.user?.Path !== "/" || Object.hasOwn(value.user, "PermissionsBoundary")) throw new Error("Bootstrap operator user identity is unexpected.");
  if (!Array.isArray(value.attachedPolicies) || value.attachedPolicies.length || !Array.isArray(value.groups) || value.groups.length || canonicalJson(value.inlinePolicyNames) !== canonicalJson([BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.inlinePolicyName])) throw new Error("Bootstrap operator policy topology is unexpected.");
  const document = normalizeIamPolicyDocument(value.document, "bootstrap operator live policy");
  const documentSha256 = sha256(document);
  const pre = documentSha256 === desired.predecessorPolicySha256;
  const post = allowPostState && documentSha256 === desired.sourcePolicySha256;
  if (!pre && !post) throw new Error("Bootstrap operator policy contains unexpected drift.");
  return Object.freeze({ ...value, document, documentSha256, status: post ? "EXACT_COMPLETE" : "EXACT_PREDECESSOR" });
}

export function readBootstrapOperatorLiveState({ run } = {}) {
  if (typeof run !== "function") throw new Error("Bootstrap operator IAM runner is required.");
  const user = runJson(run, ["iam", "get-user", "--user-name", BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.userName]).User;
  const attachedPolicies = runJson(run, ["iam", "list-attached-user-policies", "--user-name", BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.userName]).AttachedPolicies;
  const inlinePolicyNames = runJson(run, ["iam", "list-user-policies", "--user-name", BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.userName]).PolicyNames;
  const groups = runJson(run, ["iam", "list-groups-for-user", "--user-name", BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.userName]).Groups;
  const document = runJson(run, ["iam", "get-user-policy", "--user-name", BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.userName, "--policy-name", BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.inlinePolicyName]).PolicyDocument;
  return authenticateBootstrapOperatorLiveState({ user, attachedPolicies, inlinePolicyNames, groups, document });
}

const preparationBody = ({ sourceSha, state, preparedAt }) => ({
  schemaVersion: 1, kind: "PRODUCTION_BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION_PREPARATION", operation: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.operation,
  sourceSha, userArn: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.userArn, inlinePolicyName: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.inlinePolicyName,
  predecessorPolicySha256: state.documentSha256, successorPolicySha256: readBootstrapOperatorDesiredPolicy().sourcePolicySha256,
  expectedWritePlan: [{ action: "iam:PutUserPolicy", userArn: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.userArn, inlinePolicyName: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.inlinePolicyName, policySha256: readBootstrapOperatorDesiredPolicy().sourcePolicySha256 }],
  expectedWritePlanSha256: sha256([{ action: "iam:PutUserPolicy", userArn: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.userArn, inlinePolicyName: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.inlinePolicyName, policySha256: readBootstrapOperatorDesiredPolicy().sourcePolicySha256 }]),
  createdAt: new Date(preparedAt).toISOString(), expiresAt: new Date(new Date(preparedAt).getTime() + BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.maxAgeMs).toISOString(),
});
const PREPARATION_KEYS = ["schemaVersion", "kind", "operation", "sourceSha", "userArn", "inlinePolicyName", "predecessorPolicySha256", "successorPolicySha256", "expectedWritePlan", "expectedWritePlanSha256", "createdAt", "expiresAt", "preparationSha256"];
export function createBootstrapOperatorPolicyPreparation({ sourceSha, liveState, preparedAt = new Date().toISOString() } = {}) {
  requiredSha(sourceSha, "Bootstrap operator preparation source SHA");
  const state = authenticateBootstrapOperatorLiveState(liveState, { allowPostState: false });
  if (state.status !== "EXACT_PREDECESSOR") throw new Error("Bootstrap operator preparation requires the exact predecessor policy.");
  const body = preparationBody({ sourceSha, state, preparedAt });
  return Object.freeze({ ...body, preparationSha256: sha256(body) });
}
export function assertBootstrapOperatorPolicyPreparation(value, { sourceSha, now = new Date(), allowExpired = false } = {}) {
  exactKeys(value, PREPARATION_KEYS, "Bootstrap operator preparation");
  const desired = readBootstrapOperatorDesiredPolicy(); const { preparationSha256, ...body } = value;
  const created = new Date(value.createdAt); const expires = new Date(value.expiresAt);
  if (value.schemaVersion !== 1 || value.kind !== "PRODUCTION_BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION_PREPARATION" || value.operation !== BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.operation || value.sourceSha !== sourceSha || value.userArn !== BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.userArn || value.inlinePolicyName !== BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.inlinePolicyName || value.predecessorPolicySha256 !== desired.predecessorPolicySha256 || value.successorPolicySha256 !== desired.sourcePolicySha256 || value.expectedWritePlanSha256 !== sha256(value.expectedWritePlan) || canonicalJson(value.expectedWritePlan) !== canonicalJson(preparationBody({ sourceSha, state: { documentSha256: desired.predecessorPolicySha256 }, preparedAt: value.createdAt }).expectedWritePlan) || preparationSha256 !== sha256(body) || !Number.isFinite(created.getTime()) || created.toISOString() !== value.createdAt || !Number.isFinite(expires.getTime()) || expires.toISOString() !== value.expiresAt || expires.getTime() - created.getTime() !== BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.maxAgeMs || (!allowExpired && now.getTime() > expires.getTime())) throw new Error("Bootstrap operator preparation is not exact or fresh.");
  return value;
}

const AUTHORIZATION_KEYS = ["schemaVersion", "kind", "operation", "repository", "environment", "sourceSha", "administratorArn", "userArn", "inlinePolicyName", "maxAwsMutations", "preparation", "preparationSha256", "protectedEnvironmentApprovalEvidence", "approvedBy", "authorizedAt", "authorizationSha256"];
export function createBootstrapOperatorPolicyAuthorization({ sourceSha, preparation, protectedEnvironmentApprovalEvidence, authorizedAt = new Date().toISOString() } = {}) {
  const prepared = assertBootstrapOperatorPolicyPreparation(preparation, { sourceSha, now: new Date(authorizedAt) });
  assertProductionEnvironmentApprovalEvidence(protectedEnvironmentApprovalEvidence, { sourceSha, repository: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.repository, environment: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.environment, workflowRef: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.workflowRef, eventName: "workflow_dispatch", workflowRunId: protectedEnvironmentApprovalEvidence?.workflowRunId, workflowRunAttempt: protectedEnvironmentApprovalEvidence?.workflowRunAttempt, executionActor: protectedEnvironmentApprovalEvidence?.executionActor, githubActions: "true", now: new Date(authorizedAt) });
  const body = { schemaVersion: 1, kind: "PRODUCTION_BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION_AUTHORIZATION", operation: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.operation, repository: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.repository, environment: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.environment, sourceSha, administratorArn: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.administratorArn, userArn: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.userArn, inlinePolicyName: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.inlinePolicyName, maxAwsMutations: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.maxAwsMutations, preparation: prepared, preparationSha256: prepared.preparationSha256, protectedEnvironmentApprovalEvidence, approvedBy: assertProductionEnvironmentActualReviewer(protectedEnvironmentApprovalEvidence, { sourceSha, repository: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.repository, executionActor: protectedEnvironmentApprovalEvidence.executionActor }), authorizedAt };
  return Object.freeze({ ...body, authorizationSha256: sha256(body) });
}
export function assertBootstrapOperatorPolicyAuthorization(value, { sourceSha, now = new Date(), allowExpired = false } = {}) {
  exactKeys(value, AUTHORIZATION_KEYS, "Bootstrap operator authorization"); const { authorizationSha256, ...body } = value;
  if (value.schemaVersion !== 1 || value.kind !== "PRODUCTION_BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION_AUTHORIZATION" || value.operation !== BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.operation || value.repository !== BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.repository || value.environment !== BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.environment || value.sourceSha !== sourceSha || value.administratorArn !== BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.administratorArn || value.userArn !== BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.userArn || value.inlinePolicyName !== BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.inlinePolicyName || canonicalJson(value.maxAwsMutations) !== canonicalJson(BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.maxAwsMutations) || value.preparationSha256 !== value.preparation?.preparationSha256 || value.authorizationSha256 !== sha256(body)) throw new Error("Bootstrap operator authorization binding is invalid.");
  assertBootstrapOperatorPolicyPreparation(value.preparation, { sourceSha, now, allowExpired });
  assertProductionEnvironmentApprovalIdentity(value.protectedEnvironmentApprovalEvidence, { sourceSha, repository: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.repository });
  assertProductionEnvironmentApprovalFreshness(value.protectedEnvironmentApprovalEvidence, { now });
  if (value.protectedEnvironmentApprovalEvidence.workflowRef !== BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.workflowRef || value.approvedBy !== assertProductionEnvironmentActualReviewer(value.protectedEnvironmentApprovalEvidence, { sourceSha, repository: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.repository, executionActor: value.protectedEnvironmentApprovalEvidence.executionActor })) throw new Error("Bootstrap operator authorization approval is invalid.");
  return value;
}

export function reconcileBootstrapOperatorPolicy({ run, authorization, sourceSha, now = new Date() } = {}) {
  assertBootstrapOperatorPolicyAuthorization(authorization, { sourceSha, now, allowExpired: true });
  const before = readBootstrapOperatorLiveState({ run });
  if (before.status === "EXACT_COMPLETE") return Object.freeze({ status: "COMPLETE", iamPutUserPolicyCount: 0, recovered: true });
  if (before.status !== "EXACT_PREDECESSOR" || before.documentSha256 !== authorization.preparation.predecessorPolicySha256) throw new Error("Bootstrap operator predecessor changed after authorization.");
  try {
    run(["iam", "put-user-policy", "--user-name", BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.userName, "--policy-name", BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.inlinePolicyName, "--policy-document", `file://${path.join(root, BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.sourcePath)}`, "--no-cli-pager"]);
  } catch (error) {
    if (readBootstrapOperatorLiveState({ run }).status !== "EXACT_COMPLETE") throw error;
    return Object.freeze({ status: "COMPLETE", iamPutUserPolicyCount: 1, recovered: true });
  }
  if (readBootstrapOperatorLiveState({ run }).status !== "EXACT_COMPLETE") throw new Error("Bootstrap operator policy readback is not exact.");
  return Object.freeze({ status: "COMPLETE", iamPutUserPolicyCount: 1, recovered: false });
}

export function resolveBootstrapOperatorPolicyAuthorization({ workflowRunId, workflowRunAttempt, sourceSha, githubRun = createProductionGithubCommandRunner(), now = new Date() } = {}) {
  if (!/^[1-9][0-9]*$/.test(String(workflowRunId || "")) || String(workflowRunAttempt) !== "1") throw new Error("Bootstrap operator authorization workflow coordinates are invalid.");
  const workflow = parseGithubJson(githubRun, ["api", `repos/${BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.repository}/actions/runs/${workflowRunId}`], "Bootstrap operator workflow");
  if (String(workflow.id) !== String(workflowRunId) || workflow.repository?.full_name !== BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.repository || workflow.head_repository?.full_name !== BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.repository || workflow.path !== BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.workflowPath || workflow.event !== "workflow_dispatch" || workflow.head_sha !== sourceSha || workflow.status !== "completed" || workflow.conclusion !== "success" || String(workflow.run_attempt) !== "1") throw new Error("Bootstrap operator authorization workflow provenance is not authentic.");
  const pages = parseGithubJson(githubRun, ["api", `repos/${BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.repository}/actions/runs/${workflowRunId}/artifacts`, "--paginate", "--slurp"], "Bootstrap operator authorization artifacts");
  const matches = (Array.isArray(pages) ? pages.flatMap((page) => page?.artifacts || []) : []).filter((artifact) => artifact?.name === BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.artifactName && artifact.expired === false && String(artifact.workflow_run?.id) === String(workflowRunId) && artifact.workflow_run?.head_sha === sourceSha && artifact.workflow_run?.repository_id === workflow.repository.id && /^sha256:[a-f0-9]{64}$/.test(artifact.digest || ""));
  if (matches.length !== 1 || !Number.isSafeInteger(matches[0]?.id)) throw new Error("Bootstrap operator authorization artifact identity is not exact.");
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-bootstrap-operator-auth-")); const archive = path.join(directory, "authorization.zip");
  try {
    const bytes = Buffer.from(githubRun("gh", ["api", `repos/${BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.repository}/actions/artifacts/${matches[0].id}/zip`], { encoding: null, maxBuffer: 8 * 1024 * 1024 }));
    if (`sha256:${sha256(bytes)}` !== matches[0].digest) throw new Error("Bootstrap operator authorization artifact digest is invalid.");
    fs.writeFileSync(archive, bytes, { flag: "wx", mode: 0o600 });
    if (String(githubRun("unzip", ["-Z1", archive])).trim() !== BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.authorizationFilename) throw new Error("Bootstrap operator authorization artifact contents are not exact.");
    const authorization = JSON.parse(Buffer.from(githubRun("unzip", ["-p", archive, BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.authorizationFilename])).toString("utf8"));
    assertBootstrapOperatorPolicyAuthorization(authorization, { sourceSha, now });
    const environment = parseGithubJson(githubRun, ["api", `repos/${BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.repository}/environments/production`], "Bootstrap operator environment");
    const approvals = parseGithubJson(githubRun, ["api", `repos/${BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.repository}/actions/runs/${workflowRunId}/approvals`], "Bootstrap operator approvals");
    const actual = (Array.isArray(approvals) ? approvals : []).flatMap((approval) => approval?.state === "approved" ? (approval.environments || []).filter((item) => item?.id === environment.id && item?.name === "production").map(() => ({ state: "approved", environmentId: environment.id, environmentName: "production", userId: approval.user?.id, userLogin: approval.user?.login })) : []);
    if (actual.length !== 1) throw new Error("Exactly one authenticated bootstrap operator production approval is required.");
    const observed = createProductionEnvironmentApprovalEvidence({ environmentConfig: environment, repository: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.repository, environment: "production", sourceSha, workflowRef: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.workflowRef, eventName: "workflow_dispatch", workflowRunId: String(workflow.id), workflowRunAttempt: "1", executionActor: workflow.actor?.login, observedAt: authorization.protectedEnvironmentApprovalEvidence.observedAt, actualApproval: actual[0] });
    if (canonicalJson(observed) !== canonicalJson(authorization.protectedEnvironmentApprovalEvidence)) throw new Error("Bootstrap operator authorization approval differs from GitHub provenance.");
    return authorization;
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
}

export function runBootstrapOperatorPolicyReconciliationCli(argv = process.argv.slice(2), deps = {}) {
  const sourceSha = requiredSha(required(argv, "--source-sha"), "Bootstrap operator policy source SHA");
  if (argv.includes("--prepare")) {
    assertProtectedCheckout({ sourceSha, repositoryRoot: root, exec: deps.exec || execFileSync });
    const run = deps.run || createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: required(argv, "--admin-profile") });
    if (runJson(run, ["sts", "get-caller-identity"]).Arn !== BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.administratorArn) throw new Error("Bootstrap operator preparation requires the exact root administrator.");
    const preparation = createBootstrapOperatorPolicyPreparation({ sourceSha, liveState: readBootstrapOperatorLiveState({ run }), preparedAt: (deps.now || new Date()).toISOString() });
    const output = assertStageBArtifactPath({ artifactPath: path.resolve(required(argv, "--output")), repositoryRoot: root, label: "Bootstrap operator preparation", allowExisting: false });
    ensureStageBPrivateDirectory({ directory: path.dirname(output), repositoryRoot: root, create: true, label: "Bootstrap operator preparation directory" });
    writeStageBPrivateFilesAtomic({ repositoryRoot: root, files: [{ filePath: output, bytes: Buffer.from(`${JSON.stringify(preparation, null, 2)}\n`), label: "Bootstrap operator preparation" }] }); return preparation;
  }
  if (argv.includes("--authorize")) {
    const preparation = readBoundStageBPrivateJson({ filePath: path.resolve(required(argv, "--preparation")), expectedSha256: required(argv, "--preparation-file-sha256"), repositoryRoot: root, label: "Bootstrap operator preparation" });
    const approval = readBoundStageBPrivateJson({ filePath: path.resolve(required(argv, "--environment-approval")), expectedSha256: required(argv, "--environment-approval-file-sha256"), repositoryRoot: root, label: "Bootstrap operator environment approval" });
    const authorization = createBootstrapOperatorPolicyAuthorization({ sourceSha, preparation, protectedEnvironmentApprovalEvidence: approval, authorizedAt: (deps.now || new Date()).toISOString() });
    const output = assertStageBArtifactPath({ artifactPath: path.resolve(required(argv, "--output")), repositoryRoot: root, label: "Bootstrap operator authorization", allowExisting: false }); ensureStageBPrivateDirectory({ directory: path.dirname(output), repositoryRoot: root, create: true, label: "Bootstrap operator authorization directory" }); writeStageBPrivateFilesAtomic({ repositoryRoot: root, files: [{ filePath: output, bytes: Buffer.from(`${JSON.stringify(authorization, null, 2)}\n`), label: "Bootstrap operator authorization" }] }); return authorization;
  }
  if (!argv.includes("--execute")) throw new Error("Bootstrap operator reconciliation requires --prepare, --authorize, or --execute.");
  assertProtectedCheckout({ sourceSha, repositoryRoot: root, exec: deps.exec || execFileSync });
  const authorization = (deps.resolveAuthorization || resolveBootstrapOperatorPolicyAuthorization)({ workflowRunId: required(argv, "--authorization-workflow-run-id"), workflowRunAttempt: required(argv, "--authorization-workflow-run-attempt"), sourceSha, githubRun: deps.githubRun || createProductionGithubCommandRunner(), now: deps.now || new Date() });
  const run = deps.run || createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: required(argv, "--admin-profile") });
  if (runJson(run, ["sts", "get-caller-identity"]).Arn !== BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.administratorArn) throw new Error("Bootstrap operator execution requires the exact root administrator.");
  const reconciliation = reconcileBootstrapOperatorPolicy({ run, authorization, sourceSha, now: deps.now || new Date() });
  const result = Object.freeze({ schemaVersion: 1, kind: "PRODUCTION_BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION_RESULT", operation: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.operation, sourceSha, userArn: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.userArn, authorizationSha256: authorization.authorizationSha256, ...reconciliation, completedAt: (deps.now || new Date()).toISOString() });
  const output = assertStageBArtifactPath({ artifactPath: path.resolve(required(argv, "--result")), repositoryRoot: root, label: "Bootstrap operator reconciliation result", allowExisting: false }); ensureStageBPrivateDirectory({ directory: path.dirname(output), repositoryRoot: root, create: true, label: "Bootstrap operator reconciliation result directory" }); writeStageBPrivateFilesAtomic({ repositoryRoot: root, files: [{ filePath: output, bytes: Buffer.from(`${JSON.stringify(result, null, 2)}\n`), label: "Bootstrap operator reconciliation result" }] }); return result;
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) process.stdout.write(`${JSON.stringify(runBootstrapOperatorPolicyReconciliationCli(), null, 2)}\n`);
