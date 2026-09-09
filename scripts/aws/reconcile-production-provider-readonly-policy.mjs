#!/usr/bin/env node
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createProductionAwsCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";
import { authenticateProviderReadonlyLiveState, createProviderReadonlyJournal, createProviderReadonlyPreparation, executeProviderReadonlyReconciliation, providerReadonlyProductionSleep, PROVIDER_READONLY_RECONCILIATION, readProviderReadonlyDesiredPolicy, resolveProviderReadonlyAuthorizationArtifact } from "./production-provider-readonly-policy-reconciliation.mjs";
import { readStageBProtectedMainCheckout } from "./stage-b-deployment-identity.mjs";
import { assertStageBArtifactPath, ensureStageBPrivateDirectory, readBoundStageBPrivateJson, writeStageBPrivateFileExclusive } from "./stage-b-artifact-contract.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const option = (argv, name) => { const index = argv.indexOf(name); return index < 0 ? undefined : argv[index + 1]; };
const required = (argv, name) => { const value = option(argv, name); if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };
const assertExactOptions = (argv, allowed) => {
  const seen = new Set();
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index]; const value = argv[index + 1];
    if (!allowed.has(name) || seen.has(name) || !value || value.startsWith("--")) throw new Error("ProviderReadOnly CLI arguments are not exact.");
    seen.add(name);
  }
};
const json = (run, args) => JSON.parse(run(args));
const paged = (run, args, fields) => {
  const result = Object.fromEntries(fields.map((field) => [field, []])); const markers = new Set(); let marker;
  for (;;) {
    const page = json(run, [...args, "--no-paginate", ...(marker ? ["--marker", marker] : [])]);
    if (fields.some((field) => !Array.isArray(page[field])) || typeof page.IsTruncated !== "boolean") throw new Error("ProviderReadOnly IAM pagination evidence is malformed.");
    for (const field of fields) result[field].push(...page[field]);
    if (!page.IsTruncated) return result;
    if (!page.Marker || markers.has(page.Marker)) throw new Error("ProviderReadOnly IAM pagination evidence is incomplete.");
    markers.add(page.Marker); marker = page.Marker;
  }
};

export function readProviderReadonlyLiveState(run) {
  const policy = json(run, ["iam", "get-policy", "--policy-arn", PROVIDER_READONLY_RECONCILIATION.policyArn]).Policy;
  const document = json(run, ["iam", "get-policy-version", "--policy-arn", PROVIDER_READONLY_RECONCILIATION.policyArn, "--version-id", policy?.DefaultVersionId]).PolicyVersion?.Document;
  const versions = json(run, ["iam", "list-policy-versions", "--policy-arn", PROVIDER_READONLY_RECONCILIATION.policyArn]).Versions;
  const entities = paged(run, ["iam", "list-entities-for-policy", "--policy-arn", PROVIDER_READONLY_RECONCILIATION.policyArn], ["PolicyRoles", "PolicyUsers", "PolicyGroups"]);
  if (policy?.Arn !== PROVIDER_READONLY_RECONCILIATION.policyArn || !Array.isArray(versions)) throw new Error("ProviderReadOnly IAM response is malformed.");
  return {
    policyArn: policy.Arn, defaultVersionId: policy.DefaultVersionId, document,
    versions: versions.map(({ VersionId, IsDefaultVersion }) => ({ versionId: VersionId, isDefault: IsDefaultVersion })),
    attachedRoles: entities.PolicyRoles.map(({ RoleName }) => RoleName), attachedUsers: entities.PolicyUsers.map(({ UserName }) => UserName), attachedGroups: entities.PolicyGroups.map(({ GroupName }) => GroupName),
    permissionsBoundaryUsageCount: policy.PermissionsBoundaryUsageCount,
  };
}

const s3Read = (run, key) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-provider-readonly-journal-")); const output = path.join(directory, "record.json");
  try {
    try { run(["s3api", "get-object", "--bucket", PROVIDER_READONLY_RECONCILIATION.journalBucket, "--key", key, "--output", "json", "--no-cli-pager", output]); }
    catch (error) { if (/NoSuchKey|NotFound|404/i.test(`${error.message || ""}\n${error.stderr || ""}`)) return null; throw error; }
    return fs.readFileSync(output);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
};
const s3Create = (run, key, bytes) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-provider-readonly-journal-")); const body = path.join(directory, "record.json");
  try {
    fs.writeFileSync(body, bytes, { mode: 0o600, flag: "wx" });
    try { run(["s3api", "put-object", "--bucket", PROVIDER_READONLY_RECONCILIATION.journalBucket, "--key", key, "--body", body, "--content-type", "application/json", "--server-side-encryption", "AES256", "--if-none-match", "*", "--output", "json", "--no-cli-pager"]); }
    catch (error) { if (/PreconditionFailed|ConditionalRequestConflict|412|409/i.test(`${error.message || ""}\n${error.stderr || ""}`)) return false; throw error; }
    return true;
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
};

export function createProviderReadonlyCommandRunner({ exec = execFileSync, ...options } = {}) {
  return createProductionAwsCommandRunner({ ...options, exec: (file, args, execution) => exec(file, args, { ...execution, env: args[0] === "iam" && args[1] === "create-policy-version" ? { ...execution.env, AWS_MAX_ATTEMPTS: "1" } : execution.env }) });
}

export async function runProviderReadonlyReconciliation(argv = process.argv.slice(2), deps = {}) {
  const mode = required(argv, "--mode");
  if (!['prepare', 'execute'].includes(mode)) throw new Error("--mode must be prepare or execute; there is no mutating default.");
  if (mode === "execute" && argv.includes("--admin-profile")) throw new Error("ProviderReadOnly execution does not accept an administrator profile.");
  if (mode === "execute" && argv.includes("--executor-profile")) throw new Error("ProviderReadOnly execution does not accept a local executor profile.");
  assertExactOptions(argv, new Set(mode === "prepare" ? ["--mode", "--source-sha", "--preparation-out", "--admin-profile"] : ["--mode", "--source-sha", "--preparation", "--preparation-file-sha256", "--authorization-workflow-run-id", "--authorization-workflow-run-attempt", "--result-out"]));
  const sourceSha = required(argv, "--source-sha");
  const checkout = (deps.readProtectedCheckout || readStageBProtectedMainCheckout)({ cwd: root, expectedSourceSha: sourceSha, requireCanonicalRepository: true });
  if (checkout.toolingSha !== sourceSha) throw new Error("ProviderReadOnly reconciler is not at the exact protected source.");
  const desired = readProviderReadonlyDesiredPolicy({ repositoryRoot: root });
  if (mode === "prepare") {
    const output = assertStageBArtifactPath({ artifactPath: path.resolve(required(argv, "--preparation-out")), repositoryRoot: root, label: "ProviderReadOnly preparation", allowExisting: false });
    ensureStageBPrivateDirectory({ directory: path.dirname(output), repositoryRoot: root, label: "ProviderReadOnly preparation directory" });
    const run = deps.awsRun || createProviderReadonlyCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: required(argv, "--admin-profile") });
    if (json(run, ["sts", "get-caller-identity"])?.Arn !== "arn:aws:iam::368992683803:root") throw new Error("ProviderReadOnly preparation requires the authenticated root operator.");
    const liveState = readProviderReadonlyLiveState(run);
    const preparedAt = typeof deps.now === "function" ? deps.now() : deps.now || new Date();
    const preparation = createProviderReadonlyPreparation({ sourceSha, liveState, desired, preparedAt: preparedAt.toISOString() });
    writeStageBPrivateFileExclusive({ filePath: output, bytes: Buffer.from(`${JSON.stringify(preparation, null, 2)}\n`), repositoryRoot: root, label: "ProviderReadOnly preparation" });
    return Object.freeze({ mode, preparation, preparationFile: output, iamWriteCount: 0 });
  }
  const environment = deps.env || process.env;
  if (environment.GITHUB_ACTIONS !== "true" || environment.GITHUB_REPOSITORY !== "T-ej2003/genuine-scan-main" || environment.GITHUB_WORKFLOW_REF !== PROVIDER_READONLY_RECONCILIATION.executionWorkflowRef || environment.GITHUB_EVENT_NAME !== "workflow_dispatch" || environment.GITHUB_RUN_ATTEMPT !== "1") throw new Error("ProviderReadOnly execution is reachable only from the exact protected execution workflow.");
  const preparationFile = path.resolve(required(argv, "--preparation")); const preparationFileSha256 = required(argv, "--preparation-file-sha256");
  const preparation = readBoundStageBPrivateJson({ filePath: preparationFile, expectedSha256: preparationFileSha256, repositoryRoot: root, label: "ProviderReadOnly preparation" });
  const resolved = await (deps.resolveAuthorization || resolveProviderReadonlyAuthorizationArtifact)({ workflowRunId: required(argv, "--authorization-workflow-run-id"), workflowRunAttempt: required(argv, "--authorization-workflow-run-attempt"), sourceSha, preparation, run: deps.githubRun, now: deps.now || new Date(), allowExpired: true });
  const run = deps.awsRun || createProviderReadonlyCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_OIDC_POLICY_RECONCILER, env: environment });
  const arn = json(run, ["sts", "get-caller-identity"])?.Arn;
  if (!new RegExp(`^arn:aws:sts::${PROVIDER_READONLY_RECONCILIATION.account}:assumed-role/${PROVIDER_READONLY_RECONCILIATION.executorRoleName}/[^/]+$`).test(arn || "")) throw new Error("ProviderReadOnly mutation requires the exact reconciler role.");
  const journal = deps.journal || createProviderReadonlyJournal({ read: async (key) => s3Read(run, key), create: async (key, bytes) => s3Create(run, key, bytes) });
  const reauthenticateSource = () => {
    const current = (deps.readProtectedCheckout || readStageBProtectedMainCheckout)({ cwd: root, expectedSourceSha: sourceSha, requireCanonicalRepository: true });
    if (current.toolingSha !== sourceSha) throw new Error("ProviderReadOnly source changed after authorization.");
  };
  const result = await (deps.execute || executeProviderReadonlyReconciliation)({ sourceSha, preparation, ...resolved, reauthenticateSource, readLiveState: async () => readProviderReadonlyLiveState(run), createPolicyVersion: async ({ PolicyArn, PolicyDocument, SetAsDefault }) => json(run, ["iam", "create-policy-version", "--policy-arn", PolicyArn, "--policy-document", JSON.stringify(PolicyDocument), ...(SetAsDefault ? ["--set-as-default"] : [])]), journal, now: deps.clock || (() => new Date()), sleep: providerReadonlyProductionSleep });
  if (option(argv, "--result-out")) {
    const output = assertStageBArtifactPath({ artifactPath: path.resolve(required(argv, "--result-out")), repositoryRoot: root, label: "ProviderReadOnly result", allowExisting: false });
    ensureStageBPrivateDirectory({ directory: path.dirname(output), repositoryRoot: root, label: "ProviderReadOnly result directory" });
    writeStageBPrivateFileExclusive({ filePath: output, bytes: Buffer.from(`${JSON.stringify(result, null, 2)}\n`), repositoryRoot: root, label: "ProviderReadOnly result" });
  }
  return result;
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) runProviderReadonlyReconciliation().then((value) => process.stdout.write(`${JSON.stringify(value, null, 2)}\n`)).catch((error) => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
