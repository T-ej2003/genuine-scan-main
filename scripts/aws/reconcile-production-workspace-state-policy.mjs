#!/usr/bin/env node
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createProductionAwsCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";
import { createWorkspaceStateContinuationPreparation, createWorkspaceStateJournal, createWorkspaceStatePreparation, executeWorkspaceStateReconciliation, resolveWorkspaceStateAuthorizationArtifact, WORKSPACE_STATE_RECONCILIATION, WorkspaceStateRetryableObservationError, workspaceStateProductionSleep } from "./production-workspace-state-policy-reconciliation.mjs";
import { readStageBProtectedMainCheckout } from "./stage-b-deployment-identity.mjs";
import { assertStageBArtifactPath, ensureStageBPrivateDirectory, readBoundStageBPrivateJson, writeStageBPrivateFileExclusive } from "./stage-b-artifact-contract.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const option = (argv, name) => { const index = argv.indexOf(name); return index < 0 ? undefined : argv[index + 1]; };
const required = (argv, name) => { const value = option(argv, name); if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };
const exactOptions = (argv, allowed) => { const seen = new Set(); for (let index = 0; index < argv.length; index += 2) { const name = argv[index], value = argv[index + 1]; if (!allowed.has(name) || seen.has(name) || !value || value.startsWith("--")) throw new Error("WorkspaceState reconciliation arguments are not exact."); seen.add(name); } };
const RETRYABLE_IAM_READ_CODES = /\((?:Throttling|ThrottlingException|RequestLimitExceeded|ServiceUnavailable|ServiceFailure|InternalFailure|InternalError|RequestTimeout|RequestTimeoutException|PriorRequestNotComplete)\)/;
const IAM_READ_COMMANDS = new Set(["get-policy", "list-policy-versions", "get-policy-version", "list-entities-for-policy"]);
const errorText = error => [error?.message, error?.stderr, error?.stdout].map(value => Buffer.isBuffer(value) ? value.toString("utf8") : String(value || "")).join("\n");
const json = (run, args) => {
  try { return JSON.parse(run([...args, "--output", "json", "--no-cli-pager"])); }
  catch (error) {
    const message = errorText(error); const retryableCode = RETRYABLE_IAM_READ_CODES.test(message) || (args[1] === "get-policy-version" && /\((?:NoSuchEntity|NoSuchEntityException)\)/.test(message));
    if (args[0] === "iam" && IAM_READ_COMMANDS.has(args[1]) && retryableCode) throw new WorkspaceStateRetryableObservationError(`Retryable ${args[1]} observation failed.`, { cause: error });
    throw error;
  }
};
const paged = (run, args, fields) => {
  const result = Object.fromEntries(fields.map(field => [field, []])); const markers = new Set(); let marker;
  for (;;) {
    const page = json(run, [...args, "--no-paginate", ...(marker ? ["--marker", marker] : [])]);
    if (fields.some(field => !Array.isArray(page[field])) || typeof page.IsTruncated !== "boolean") throw new Error("WorkspaceState IAM pagination evidence is malformed.");
    for (const field of fields) result[field].push(...page[field]);
    if (!page.IsTruncated) return result;
    if (!page.Marker || markers.has(page.Marker)) throw new Error("WorkspaceState IAM pagination is incomplete."); markers.add(page.Marker); marker = page.Marker;
  }
};

export function readWorkspaceStateLiveState(run) {
  const policy = json(run, ["iam", "get-policy", "--policy-arn", WORKSPACE_STATE_RECONCILIATION.policyArn]).Policy;
  const versions = json(run, ["iam", "list-policy-versions", "--policy-arn", WORKSPACE_STATE_RECONCILIATION.policyArn]).Versions;
  const entities = paged(run, ["iam", "list-entities-for-policy", "--policy-arn", WORKSPACE_STATE_RECONCILIATION.policyArn], ["PolicyRoles", "PolicyUsers", "PolicyGroups"]);
  if (policy?.Arn !== WORKSPACE_STATE_RECONCILIATION.policyArn || !Array.isArray(versions)) throw new Error("WorkspaceState IAM response is malformed.");
  const listedDefaults = versions.filter(version => version?.IsDefaultVersion === true);
  if (listedDefaults.length !== 1 || listedDefaults[0].VersionId !== policy.DefaultVersionId) throw new WorkspaceStateRetryableObservationError("WorkspaceState policy and version-list snapshot is internally inconsistent.");
  return { policyArn: policy.Arn, defaultVersionId: policy.DefaultVersionId, versions: versions.map(version => {
    const observed = json(run, ["iam", "get-policy-version", "--policy-arn", WORKSPACE_STATE_RECONCILIATION.policyArn, "--version-id", version.VersionId]).PolicyVersion;
    if (observed?.VersionId !== version.VersionId || observed.IsDefaultVersion !== version.IsDefaultVersion) throw new WorkspaceStateRetryableObservationError("WorkspaceState policy-version readback is internally inconsistent.");
    return { versionId: observed.VersionId, isDefault: observed.IsDefaultVersion, createDate: new Date(version.CreateDate).toISOString(), document: observed.Document };
  }), attachedRoles: entities.PolicyRoles.map(({ RoleName }) => RoleName), attachedUsers: entities.PolicyUsers.map(({ UserName }) => UserName), attachedGroups: entities.PolicyGroups.map(({ GroupName }) => GroupName), permissionsBoundaryUsageCount: policy.PermissionsBoundaryUsageCount };
}

const temporaryFile = (prefix, callback) => { const directory = fs.mkdtempSync(path.join(os.tmpdir(), prefix)); fs.chmodSync(directory, 0o700); try { return callback(directory); } finally { fs.rmSync(directory, { recursive: true, force: true }); } };
const journalRead = (run, key) => temporaryFile("mscqr-workspace-state-journal-", directory => {
  const output = path.join(directory, "record.json");
  try { run(["s3api", "get-object", "--bucket", WORKSPACE_STATE_RECONCILIATION.journalBucket, "--key", key, "--expected-bucket-owner", WORKSPACE_STATE_RECONCILIATION.account, "--output", "json", "--no-cli-pager", output]); }
  catch (error) { if (/NoSuchKey|NotFound|404/i.test(`${error.message || ""}\n${error.stderr || ""}`)) return null; throw error; }
  return fs.readFileSync(output);
});
const journalCreate = (run, key, bytes) => temporaryFile("mscqr-workspace-state-journal-", directory => {
  const body = path.join(directory, "record.json"); fs.writeFileSync(body, bytes, { mode: 0o600, flag: "wx" });
  try { run(["s3api", "put-object", "--bucket", WORKSPACE_STATE_RECONCILIATION.journalBucket, "--key", key, "--body", body, "--content-type", "application/json", "--server-side-encryption", "AES256", "--if-none-match", "*", "--expected-bucket-owner", WORKSPACE_STATE_RECONCILIATION.account, "--output", "json", "--no-cli-pager"]); }
  catch (error) { if (/PreconditionFailed|ConditionalRequestConflict|412|409/i.test(`${error.message || ""}\n${error.stderr || ""}`)) return false; throw error; }
  return true;
});

export function createWorkspaceStateCommandRunner({ exec = execFileSync, profile, ...options } = {}) {
  return createProductionAwsCommandRunner({ ...options, credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile, exec: (file, args, execution) => exec(file, args, { ...execution, env: args[0] === "iam" && ["delete-policy-version", "create-policy-version"].includes(args[1]) ? { ...execution.env, AWS_MAX_ATTEMPTS: "1" } : execution.env }) });
}

export async function runWorkspaceStateReconciliation(argv = process.argv.slice(2), deps = {}) {
  const mode = required(argv, "--mode"); if (!["prepare", "prepare-continuation", "execute"].includes(mode)) throw new Error("--mode must be prepare, prepare-continuation, or execute; mutation is never implicit.");
  exactOptions(argv, new Set(mode === "prepare" ? ["--mode", "--source-sha", "--preparation-out", "--admin-profile"] : mode === "prepare-continuation" ? ["--mode", "--source-sha", "--base-preparation", "--base-preparation-file-sha256", "--continuation-kind", "--preparation-out", "--admin-profile"] : ["--mode", "--source-sha", "--preparation", "--preparation-file-sha256", "--authorization-workflow-run-id", "--authorization-workflow-run-attempt", "--admin-profile", "--result-out"]));
  const sourceSha = required(argv, "--source-sha"); const checkout = (deps.readProtectedCheckout || readStageBProtectedMainCheckout)({ cwd: root, expectedSourceSha: sourceSha, requireCanonicalRepository: true });
  if (checkout.toolingSha !== sourceSha) throw new Error("WorkspaceState reconciler is not at the exact protected source.");
  const run = deps.awsRun || createWorkspaceStateCommandRunner({ profile: required(argv, "--admin-profile") });
  const caller = json(run, ["sts", "get-caller-identity"]); if (caller?.Account !== WORKSPACE_STATE_RECONCILIATION.account || caller?.Arn !== `arn:aws:iam::${WORKSPACE_STATE_RECONCILIATION.account}:root`) throw new Error("WorkspaceState reconciliation requires the authenticated governed root operator.");
  if (mode === "prepare") {
    const output = assertStageBArtifactPath({ artifactPath: path.resolve(required(argv, "--preparation-out")), repositoryRoot: root, label: "WorkspaceState preparation", allowExisting: false }); ensureStageBPrivateDirectory({ directory: path.dirname(output), repositoryRoot: root, label: "WorkspaceState preparation directory" });
    const preparation = createWorkspaceStatePreparation({ sourceSha, liveState: readWorkspaceStateLiveState(run) }); writeStageBPrivateFileExclusive({ filePath: output, bytes: Buffer.from(`${JSON.stringify(preparation, null, 2)}\n`), repositoryRoot: root, label: "WorkspaceState preparation" });
    return Object.freeze({ mode, preparation, preparationFile: output, iamDeleteCount: 0, iamCreateCount: 0 });
  }
  if (mode === "prepare-continuation") {
    const basePreparation = readBoundStageBPrivateJson({ filePath: path.resolve(required(argv, "--base-preparation")), expectedSha256: required(argv, "--base-preparation-file-sha256"), repositoryRoot: root, label: "WorkspaceState base preparation" });
    const kind = required(argv, "--continuation-kind"); if (!["PROVED_NO_DELETE_WRITE", "PROVED_NO_CREATE_WRITE"].includes(kind)) throw new Error("WorkspaceState continuation kind is invalid.");
    const journal = deps.journal || createWorkspaceStateJournal({ read: key => journalRead(run, key), create: journalCreate.bind(null, run) }); const identity = { operationId: basePreparation.operationId };
    const readRecord = record => journal.read(identity, record);
    const [reservation, deletionAttempt, deletionPrewriteFailed, deletionRetryAttempt, deletionComplete, creationAttempt, terminalRecord] = await Promise.all(["reservation.json", "deletion-attempt.json", "deletion-prewrite-failed.json", "deletion-retry-attempt.json", "deletion-complete.json", "creation-attempt.json", "terminal.json"].map(readRecord));
    if (creationAttempt || terminalRecord) throw new Error("WorkspaceState continuation is unavailable after create or terminal evidence.");
    const preparation = createWorkspaceStateContinuationPreparation({ sourceSha, basePreparation, kind, reservation, deletionAttempt, proofRecord: kind === "PROVED_NO_DELETE_WRITE" ? deletionPrewriteFailed : deletionComplete, deletionPrewriteFailed, deletionRetryAttempt, deletionComplete, creationAttempt, terminalRecord, liveState: readWorkspaceStateLiveState(run) });
    const output = assertStageBArtifactPath({ artifactPath: path.resolve(required(argv, "--preparation-out")), repositoryRoot: root, label: "WorkspaceState continuation preparation", allowExisting: false }); ensureStageBPrivateDirectory({ directory: path.dirname(output), repositoryRoot: root, label: "WorkspaceState continuation preparation directory" });
    writeStageBPrivateFileExclusive({ filePath: output, bytes: Buffer.from(`${JSON.stringify(preparation, null, 2)}\n`), repositoryRoot: root, label: "WorkspaceState continuation preparation" });
    return Object.freeze({ mode, preparation, preparationFile: output, iamDeleteCount: 0, iamCreateCount: 0 });
  }
  const preparation = readBoundStageBPrivateJson({ filePath: path.resolve(required(argv, "--preparation")), expectedSha256: required(argv, "--preparation-file-sha256"), repositoryRoot: root, label: "WorkspaceState preparation" });
  const resolved = await (deps.resolveAuthorization || resolveWorkspaceStateAuthorizationArtifact)({ workflowRunId: required(argv, "--authorization-workflow-run-id"), workflowRunAttempt: required(argv, "--authorization-workflow-run-attempt"), sourceSha, preparation, run: deps.githubRun || execFileSync, now: deps.now || new Date(), allowExpired: true });
  const journal = deps.journal || createWorkspaceStateJournal({ read: key => journalRead(run, key), create: (key, bytes) => journalCreate(run, key, bytes) });
  const reauthenticateSource = () => { const current = (deps.readProtectedCheckout || readStageBProtectedMainCheckout)({ cwd: root, expectedSourceSha: sourceSha, requireCanonicalRepository: true }); if (current.toolingSha !== sourceSha) throw new Error("WorkspaceState source changed after authorization."); };
  const result = await (deps.execute || executeWorkspaceStateReconciliation)({ sourceSha, preparation, ...resolved, readLiveState: async () => readWorkspaceStateLiveState(run), deletePolicyVersion: async ({ PolicyArn, VersionId }) => run(["iam", "delete-policy-version", "--policy-arn", PolicyArn, "--version-id", VersionId, "--no-cli-pager"]), createPolicyVersion: async ({ PolicyArn, PolicyDocument, SetAsDefault }) => json(run, ["iam", "create-policy-version", "--policy-arn", PolicyArn, "--policy-document", JSON.stringify(PolicyDocument), ...(SetAsDefault ? ["--set-as-default"] : [])]), journal, reauthenticateSource, now: deps.clock || (() => new Date()), sleep: workspaceStateProductionSleep });
  if (option(argv, "--result-out")) { const output = assertStageBArtifactPath({ artifactPath: path.resolve(required(argv, "--result-out")), repositoryRoot: root, label: "WorkspaceState result", allowExisting: false }); ensureStageBPrivateDirectory({ directory: path.dirname(output), repositoryRoot: root, label: "WorkspaceState result directory" }); writeStageBPrivateFileExclusive({ filePath: output, bytes: Buffer.from(`${JSON.stringify(result, null, 2)}\n`), repositoryRoot: root, label: "WorkspaceState result" }); }
  return result;
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) runWorkspaceStateReconciliation().then(value => process.stdout.write(`${JSON.stringify(value, null, 2)}\n`)).catch(error => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
