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
import { PRODUCTION_ENVIRONMENT_APPROVAL, assertProductionEnvironmentApprovalEvidence, assertProductionEnvironmentApprovalFreshness, assertProductionEnvironmentApprovalIdentity, createProductionEnvironmentApprovalEvidence } from "./production-github-environment-approval.mjs";
import { assertStageBArtifactPath, ensureStageBPrivateDirectory, readBoundStageBPrivateJson, writeStageBPrivateFilesAtomic } from "./stage-b-artifact-contract.mjs";
import { assertProtectedCheckout } from "./prepare-production-initial-activation-reconciler-installation.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const canonicalSha256 = (value) => sha256(Buffer.from(canonicalJson(value)));
const readSource = (relative) => fs.readFileSync(path.join(root, relative));
const readSourceJson = (relative) => JSON.parse(readSource(relative));
const runJson = (run, args) => JSON.parse(run([...args, "--output", "json", "--no-cli-pager"]));
const noSuchEntity = (error) => /\bNoSuchEntity(?:Exception)?\b/.test(`${error?.stderr || ""} ${error?.message || ""}`);
const exactFields = (value, names, label) => {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).sort().join(",") !== [...names].sort().join(",")) throw new Error(`${label} fields are not exact.`);
};

export const INSTALLATION_BOOTSTRAP = Object.freeze({
  schemaVersion: 1,
  operation: "PRODUCTION_INITIAL_ACTIVATION_POLICY_RECONCILER_BOOTSTRAP_INSTALLATION",
  repository: "T-ej2003/genuine-scan-main",
  environment: "production",
  account: "368992683803",
  region: "eu-west-2",
  administratorArn: "arn:aws:iam::368992683803:root",
  roleName: "mscqr-production-initial-activation-policy-reconciler-bootstrap",
  roleArn: "arn:aws:iam::368992683803:role/mscqr-production-initial-activation-policy-reconciler-bootstrap",
  inlinePolicyName: "MSCQRProductionInitialActivationPolicyReconcilerBootstrap",
  trustPath: "documents/ops/iam/MSCQRProductionInitialActivationPolicyReconcilerBootstrapTrust-v1.json",
  permissionsPath: "documents/ops/iam/MSCQRProductionInitialActivationPolicyReconcilerBootstrapPermissions-v1.json",
  workflowPath: ".github/workflows/authorize-production-initial-activation-policy-reconciler-bootstrap.yml",
  workflowRef: PRODUCTION_ENVIRONMENT_APPROVAL.installationBootstrapWorkflowRef,
  artifactName: "production-initial-activation-policy-reconciler-bootstrap-authorization",
  roleDescription: "GitHub production-environment installer for the exact InitialActivation reconciler Terraform root.",
  tags: Object.freeze({ ManagedBy: "GovernedBootstrap", Environment: "production", Component: "initial-activation-policy-reconciler-installation" }),
  maxAwsMutations: Object.freeze({ "iam:CreateRole": 1, "iam:PutRolePolicy": 1 }),
});

export const bootstrapSourceHashes = () => Object.freeze({
  trustPolicySha256: sha256(readSource(INSTALLATION_BOOTSTRAP.trustPath)),
  permissionsPolicySha256: sha256(readSource(INSTALLATION_BOOTSTRAP.permissionsPath)),
});

const AUTH_FIELDS = new Set(["schemaVersion", "kind", "operation", "repository", "environment", "sourceSha", "administratorArn", "roleArn", "roleName", "inlinePolicyName", "sourceHashes", "maxAwsMutations", "approval", "approvalSha256", "authorizedAt", "authorizationSha256"]);

export function createBootstrapAuthorization({ sourceSha, approval, authorizedAt = new Date().toISOString() } = {}) {
  assertProductionEnvironmentApprovalEvidence(approval, { sourceSha, repository: INSTALLATION_BOOTSTRAP.repository, environment: INSTALLATION_BOOTSTRAP.environment, workflowRef: INSTALLATION_BOOTSTRAP.workflowRef, eventName: "workflow_dispatch", workflowRunId: approval?.workflowRunId, workflowRunAttempt: approval?.workflowRunAttempt, executionActor: approval?.executionActor, githubActions: "true", now: new Date(authorizedAt) });
  const body = { schemaVersion: 1, kind: "PRODUCTION_INITIAL_ACTIVATION_POLICY_RECONCILER_BOOTSTRAP_AUTHORIZATION", operation: INSTALLATION_BOOTSTRAP.operation, repository: INSTALLATION_BOOTSTRAP.repository, environment: INSTALLATION_BOOTSTRAP.environment, sourceSha, administratorArn: INSTALLATION_BOOTSTRAP.administratorArn, roleArn: INSTALLATION_BOOTSTRAP.roleArn, roleName: INSTALLATION_BOOTSTRAP.roleName, inlinePolicyName: INSTALLATION_BOOTSTRAP.inlinePolicyName, sourceHashes: bootstrapSourceHashes(), maxAwsMutations: INSTALLATION_BOOTSTRAP.maxAwsMutations, approval, approvalSha256: approval.evidenceSha256, authorizedAt };
  return Object.freeze({ ...body, authorizationSha256: canonicalSha256(body) });
}

export function assertBootstrapAuthorization(value, { sourceSha, now = new Date() } = {}) {
  exactFields(value, AUTH_FIELDS, "Bootstrap authorization");
  const { authorizationSha256, ...body } = value;
  if (value.schemaVersion !== 1 || value.kind !== "PRODUCTION_INITIAL_ACTIVATION_POLICY_RECONCILER_BOOTSTRAP_AUTHORIZATION" || value.operation !== INSTALLATION_BOOTSTRAP.operation || value.repository !== INSTALLATION_BOOTSTRAP.repository || value.environment !== INSTALLATION_BOOTSTRAP.environment || value.sourceSha !== sourceSha || value.administratorArn !== INSTALLATION_BOOTSTRAP.administratorArn || value.roleArn !== INSTALLATION_BOOTSTRAP.roleArn || value.roleName !== INSTALLATION_BOOTSTRAP.roleName || value.inlinePolicyName !== INSTALLATION_BOOTSTRAP.inlinePolicyName || canonicalJson(value.sourceHashes) !== canonicalJson(bootstrapSourceHashes()) || canonicalJson(value.maxAwsMutations) !== canonicalJson(INSTALLATION_BOOTSTRAP.maxAwsMutations) || value.approvalSha256 !== value.approval?.evidenceSha256 || canonicalSha256(body) !== authorizationSha256) throw new Error("Bootstrap authorization binding is invalid.");
  assertProductionEnvironmentApprovalIdentity(value.approval, { sourceSha, repository: INSTALLATION_BOOTSTRAP.repository });
  assertProductionEnvironmentApprovalFreshness(value.approval, { now });
  if (value.approval.workflowRef !== INSTALLATION_BOOTSTRAP.workflowRef) throw new Error("Bootstrap authorization workflow binding is invalid.");
  return value;
}

function assertTags(tags) {
  if (!Array.isArray(tags) || tags.some((tag) => !tag || Object.keys(tag).sort().join(",") !== "Key,Value")) throw new Error("Bootstrap role tags are malformed.");
  if (canonicalJson(Object.fromEntries(tags.map(({ Key, Value }) => [Key, Value]))) !== canonicalJson(INSTALLATION_BOOTSTRAP.tags)) throw new Error("Bootstrap role tags are not exact.");
}

export function assertBootstrapRole(role) {
  if (role?.Arn !== INSTALLATION_BOOTSTRAP.roleArn || role?.RoleName !== INSTALLATION_BOOTSTRAP.roleName || role?.Path !== "/" || role?.Description !== INSTALLATION_BOOTSTRAP.roleDescription || role?.MaxSessionDuration !== 3600 || Object.hasOwn(role, "PermissionsBoundary")) throw new Error("Bootstrap role metadata is not exact.");
  if (canonicalJson(normalizeIamPolicyDocument(role.AssumeRolePolicyDocument, "bootstrap trust policy")) !== canonicalJson(readSourceJson(INSTALLATION_BOOTSTRAP.trustPath))) throw new Error("Bootstrap role trust is not exact.");
  assertTags(role.Tags);
  return role;
}

export function discoverBootstrapRole({ run } = {}) {
  let role;
  try { role = runJson(run, ["iam", "get-role", "--role-name", INSTALLATION_BOOTSTRAP.roleName]).Role; } catch (error) { if (noSuchEntity(error)) return Object.freeze({ classification: "ABSENT" }); throw error; }
  assertBootstrapRole(role);
  const attached = runJson(run, ["iam", "list-attached-role-policies", "--role-name", INSTALLATION_BOOTSTRAP.roleName]).AttachedPolicies;
  const inline = runJson(run, ["iam", "list-role-policies", "--role-name", INSTALLATION_BOOTSTRAP.roleName]).PolicyNames;
  if (!Array.isArray(attached) || attached.length !== 0 || !Array.isArray(inline) || inline.some((name) => name !== INSTALLATION_BOOTSTRAP.inlinePolicyName) || inline.length > 1) throw new Error("Bootstrap role policy topology is unexpected.");
  if (inline.length === 0) return Object.freeze({ classification: "EXACT_PARTIAL" });
  const document = runJson(run, ["iam", "get-role-policy", "--role-name", INSTALLATION_BOOTSTRAP.roleName, "--policy-name", INSTALLATION_BOOTSTRAP.inlinePolicyName]).PolicyDocument;
  if (canonicalJson(normalizeIamPolicyDocument(document, "bootstrap permissions policy")) !== canonicalJson(readSourceJson(INSTALLATION_BOOTSTRAP.permissionsPath))) throw new Error("Bootstrap role permissions are not exact.");
  return Object.freeze({ classification: "EXACT_COMPLETE" });
}

const parseGithubJson = (githubRun, args, label) => { try { return JSON.parse(githubRun("gh", args)); } catch { throw new Error(`${label} is malformed or unavailable.`); } };

export function resolveBootstrapAuthorization({ workflowRunId, workflowRunAttempt, sourceSha, githubRun = createProductionGithubCommandRunner(), now = new Date() } = {}) {
  if (!/^[1-9][0-9]*$/.test(String(workflowRunId || "")) || !/^[1-9][0-9]*$/.test(String(workflowRunAttempt || "")) || !/^[a-f0-9]{40}$/.test(sourceSha || "")) throw new Error("Bootstrap authorization workflow coordinates are invalid.");
  const workflow = parseGithubJson(githubRun, ["api", `repos/${INSTALLATION_BOOTSTRAP.repository}/actions/runs/${workflowRunId}`], "Bootstrap workflow");
  if (String(workflow.id) !== String(workflowRunId) || workflow.repository?.full_name !== INSTALLATION_BOOTSTRAP.repository || workflow.head_repository?.full_name !== INSTALLATION_BOOTSTRAP.repository || workflow.path !== INSTALLATION_BOOTSTRAP.workflowPath || workflow.event !== "workflow_dispatch" || workflow.head_sha !== sourceSha || workflow.status !== "completed" || workflow.conclusion !== "success" || String(workflow.run_attempt) !== String(workflowRunAttempt)) throw new Error("Bootstrap workflow provenance is not authentic.");
  const pages = parseGithubJson(githubRun, ["api", `repos/${INSTALLATION_BOOTSTRAP.repository}/actions/runs/${workflowRunId}/artifacts`, "--paginate", "--slurp"], "Bootstrap artifacts");
  const matches = (Array.isArray(pages) ? pages.flatMap((page) => page?.artifacts || []) : []).filter((artifact) => artifact?.name === INSTALLATION_BOOTSTRAP.artifactName && artifact.expired === false && String(artifact.workflow_run?.id) === String(workflowRunId) && artifact.workflow_run?.head_sha === sourceSha && artifact.workflow_run?.repository_id === workflow.repository.id && /^sha256:[a-f0-9]{64}$/.test(artifact.digest || ""));
  if (matches.length !== 1 || !Number.isSafeInteger(matches[0]?.id)) throw new Error("Bootstrap authorization artifact identity is not exact.");
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-bootstrap-auth-"));
  const archive = path.join(directory, "authorization.zip");
  try {
    const bytes = Buffer.from(githubRun("gh", ["api", `repos/${INSTALLATION_BOOTSTRAP.repository}/actions/artifacts/${matches[0].id}/zip`], { encoding: null, maxBuffer: 64 * 1024 * 1024 }));
    if (`sha256:${sha256(bytes)}` !== matches[0].digest) throw new Error("Bootstrap artifact digest is invalid.");
    fs.writeFileSync(archive, bytes, { flag: "wx", mode: 0o600 });
    if (String(githubRun("unzip", ["-Z1", archive])).trim() !== "bootstrap-authorization.json") throw new Error("Bootstrap artifact contents are not exact.");
    const authorizationBytes = Buffer.from(githubRun("unzip", ["-p", archive, "bootstrap-authorization.json"]));
    const authorization = JSON.parse(authorizationBytes.toString("utf8"));
    assertBootstrapAuthorization(authorization, { sourceSha, now });
    const environment = parseGithubJson(githubRun, ["api", `repos/${INSTALLATION_BOOTSTRAP.repository}/environments/production`], "Production environment");
    const approvals = parseGithubJson(githubRun, ["api", `repos/${INSTALLATION_BOOTSTRAP.repository}/actions/runs/${workflowRunId}/approvals`], "Bootstrap approvals");
    const matchesApproval = (Array.isArray(approvals) ? approvals : []).flatMap((approval) => approval?.state === "approved" ? (approval.environments || []).filter((item) => item?.id === environment.id && item?.name === "production").map(() => ({ state: "approved", environmentId: environment.id, environmentName: "production", userId: approval.user?.id, userLogin: approval.user?.login })) : []);
    if (matchesApproval.length !== 1) throw new Error("Exactly one bootstrap production approval is required.");
    const observed = createProductionEnvironmentApprovalEvidence({ environmentConfig: environment, repository: INSTALLATION_BOOTSTRAP.repository, environment: "production", sourceSha, workflowRef: INSTALLATION_BOOTSTRAP.workflowRef, eventName: "workflow_dispatch", workflowRunId: String(workflow.id), workflowRunAttempt: String(workflow.run_attempt), executionActor: workflow.actor?.login, observedAt: authorization.approval.observedAt, actualApproval: matchesApproval[0] });
    if (canonicalJson(observed) !== canonicalJson(authorization.approval)) throw new Error("Bootstrap approval differs from GitHub provenance.");
    return authorization;
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
}

export function installBootstrapRole({ run, authorization, sourceSha, now = new Date(), afterCreate } = {}) {
  assertBootstrapAuthorization(authorization, { sourceSha, now });
  const identity = runJson(run, ["sts", "get-caller-identity"]);
  if (identity?.Arn !== INSTALLATION_BOOTSTRAP.administratorArn) throw new Error("Bootstrap installation requires the exact root administrator.");
  let before = discoverBootstrapRole({ run });
  if (before.classification === "EXACT_COMPLETE") return Object.freeze({ status: "COMPLETE", createRoleCount: 0, putRolePolicyCount: 0, recovered: false });
  let createRoleCount = 0;
  let putRolePolicyCount = 0;
  if (before.classification === "ABSENT") {
    try {
      run(["iam", "create-role", "--role-name", INSTALLATION_BOOTSTRAP.roleName, "--path", "/", "--description", INSTALLATION_BOOTSTRAP.roleDescription, "--max-session-duration", "3600", "--assume-role-policy-document", `file://${path.join(root, INSTALLATION_BOOTSTRAP.trustPath)}`, "--tags", ...Object.entries(INSTALLATION_BOOTSTRAP.tags).map(([Key, Value]) => `Key=${Key},Value=${Value}`), "--output", "json", "--no-cli-pager"]);
      createRoleCount = 1;
      afterCreate?.();
    } catch (error) {
      const observed = discoverBootstrapRole({ run });
      if (observed.classification === "EXACT_COMPLETE") return Object.freeze({ status: "COMPLETE", createRoleCount: 0, putRolePolicyCount: 0, recovered: true });
      throw error;
    }
    before = discoverBootstrapRole({ run });
    if (before.classification !== "EXACT_PARTIAL") throw new Error("Bootstrap role create did not converge to the exact partial state.");
  }
  try {
    run(["iam", "put-role-policy", "--role-name", INSTALLATION_BOOTSTRAP.roleName, "--policy-name", INSTALLATION_BOOTSTRAP.inlinePolicyName, "--policy-document", `file://${path.join(root, INSTALLATION_BOOTSTRAP.permissionsPath)}`, "--no-cli-pager"]);
    putRolePolicyCount = 1;
  } catch (error) {
    if (discoverBootstrapRole({ run }).classification !== "EXACT_COMPLETE") throw error;
    return Object.freeze({ status: "COMPLETE", createRoleCount, putRolePolicyCount: 1, recovered: true });
  }
  if (discoverBootstrapRole({ run }).classification !== "EXACT_COMPLETE") throw new Error("Bootstrap role installation readback is not exact.");
  return Object.freeze({ status: "COMPLETE", createRoleCount, putRolePolicyCount, recovered: false });
}

const required = (argv, name) => { const index = argv.indexOf(name); const value = index < 0 ? undefined : argv[index + 1]; if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };

export function runBootstrapCli(argv = process.argv.slice(2), deps = {}) {
  const sourceSha = required(argv, "--source-sha");
  if (argv.includes("--authorize")) {
    const approval = readBoundStageBPrivateJson({ filePath: path.resolve(required(argv, "--environment-approval")), expectedSha256: required(argv, "--environment-approval-sha256"), repositoryRoot: root, label: "Bootstrap environment approval" });
    const authorization = createBootstrapAuthorization({ sourceSha, approval, authorizedAt: (deps.now || new Date()).toISOString() });
    const output = assertStageBArtifactPath({ artifactPath: path.resolve(required(argv, "--output")), repositoryRoot: root, label: "Bootstrap authorization", allowExisting: false });
    ensureStageBPrivateDirectory({ directory: path.dirname(output), repositoryRoot: root, create: true, label: "Bootstrap authorization directory" });
    writeStageBPrivateFilesAtomic({ repositoryRoot: root, files: [{ filePath: output, bytes: Buffer.from(`${JSON.stringify(authorization, null, 2)}\n`), label: "Bootstrap authorization" }] });
    return authorization;
  }
  if (!argv.includes("--execute")) throw new Error("Bootstrap installation requires --authorize or --execute.");
  const exec = deps.exec || execFileSync;
  assertProtectedCheckout({ sourceSha, repositoryRoot: root, exec });
  const output = assertStageBArtifactPath({ artifactPath: path.resolve(required(argv, "--result")), repositoryRoot: root, label: "Bootstrap result", allowExisting: false });
  ensureStageBPrivateDirectory({ directory: path.dirname(output), repositoryRoot: root, create: true, label: "Bootstrap result directory" });
  const authorization = (deps.resolveAuthorization || resolveBootstrapAuthorization)({ workflowRunId: required(argv, "--authorization-workflow-run-id"), workflowRunAttempt: required(argv, "--authorization-workflow-run-attempt"), sourceSha, githubRun: deps.githubRun || createProductionGithubCommandRunner(), now: deps.now || new Date() });
  const run = deps.run || createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: required(argv, "--admin-profile") });
  const installation = installBootstrapRole({ run, authorization, sourceSha, now: deps.now || new Date() });
  const result = { schemaVersion: 1, kind: "PRODUCTION_INITIAL_ACTIVATION_POLICY_RECONCILER_BOOTSTRAP_RESULT", operation: INSTALLATION_BOOTSTRAP.operation, repository: INSTALLATION_BOOTSTRAP.repository, environment: INSTALLATION_BOOTSTRAP.environment, sourceSha, authorizationSha256: authorization.authorizationSha256, roleArn: INSTALLATION_BOOTSTRAP.roleArn, sourceHashes: bootstrapSourceHashes(), ...installation, completedAt: (deps.now || new Date()).toISOString() };
  writeStageBPrivateFilesAtomic({ repositoryRoot: root, files: [{ filePath: output, bytes: Buffer.from(`${JSON.stringify(result, null, 2)}\n`), label: "Bootstrap result" }] });
  return Object.freeze(result);
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) process.stdout.write(`${JSON.stringify(runBootstrapCli(), null, 2)}\n`);
