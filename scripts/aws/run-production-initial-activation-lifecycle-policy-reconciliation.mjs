#!/usr/bin/env node
import fs from "node:fs";
import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createProductionAwsCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";
import { INITIAL_ACTIVATION_POLICY_RECONCILIATION, INITIAL_ACTIVATION_TRANSIENT_POLICY_VERSION_READ, assertInitialActivationLifecyclePolicyReconciliationAuthorization, assertInitialActivationLifecyclePolicyState, buildInitialActivationLifecyclePolicyReconciliationResult, executeInitialActivationLifecyclePolicyReconciliation, readInitialActivationLifecycleDesiredPolicy } from "./production-initial-activation-policy-reconciliation.mjs";
import { readStageBProtectedMainCheckout } from "./stage-b-deployment-identity.mjs";
import { assertStageBArtifactPath, ensureStageBPrivateDirectory, readBoundStageBPrivateJson, writeStageBPrivateFileExclusive } from "./stage-b-artifact-contract.mjs";
import { PRODUCTION_ENVIRONMENT_APPROVAL, assertProductionEnvironmentApprovalEvidence } from "./production-github-environment-approval.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const required = (argv, name) => { const index = argv.indexOf(name); const value = index < 0 ? undefined : argv[index + 1]; if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };
const json = (run, args) => JSON.parse(run(args));
export function createInitialActivationReconciliationCommandRunner({ exec = execFileSync, ...options } = {}) {
  return createProductionAwsCommandRunner({ ...options, exec: (file, args, execution) => exec(file, args, {
    ...execution,
    env: args[0] === "iam" && args[1] === "create-policy-version"
      ? { ...execution.env, AWS_MAX_ATTEMPTS: "1" }
      : execution.env,
  }) });
}
const paged = (run, command, collection) => {
  const values = []; const markers = new Set(); let marker;
  for (;;) {
    const page = json(run, [...command, "--no-paginate", ...(marker ? ["--marker", marker] : [])]);
    if (!Array.isArray(page?.[collection]) || typeof page.IsTruncated !== "boolean") throw new Error("Initial activation lifecycle policy pagination evidence is malformed.");
    values.push(...page[collection]);
    if (!page.IsTruncated) return values;
    if (typeof page.Marker !== "string" || !page.Marker || markers.has(page.Marker)) throw new Error("Initial activation lifecycle policy pagination evidence is incomplete.");
    markers.add(page.Marker); marker = page.Marker;
  }
};
const resolveResultOutput = (argv) => {
  const resultOut = assertStageBArtifactPath({ artifactPath: path.resolve(required(argv, "--result-out")), repositoryRoot: root, label: "Initial activation lifecycle policy result", allowExisting: false });
  ensureStageBPrivateDirectory({ directory: path.dirname(resultOut), repositoryRoot: root, create: false, label: "Initial activation lifecycle policy result directory" });
  fs.accessSync(path.dirname(resultOut), fs.constants.W_OK);
  return resultOut;
};

export function readInitialActivationLifecyclePolicyLiveState(run) {
  const policy = json(run, ["iam", "get-policy", "--policy-arn", INITIAL_ACTIVATION_POLICY_RECONCILIATION.policyArn]).Policy;
  const defaultVersionId = policy?.DefaultVersionId;
  let version;
  try { version = json(run, ["iam", "get-policy-version", "--policy-arn", INITIAL_ACTIVATION_POLICY_RECONCILIATION.policyArn, "--version-id", defaultVersionId]).PolicyVersion; }
  catch (error) {
    if (/^NoSuchEntity(?:Exception)?$/.test(error?.code || error?.name || "") || /^An error occurred \(NoSuchEntity(?:Exception)?\) when calling the GetPolicyVersion operation: [^\n]+$/.test(String(error?.stderr || "").trim())) error.code = INITIAL_ACTIVATION_TRANSIENT_POLICY_VERSION_READ;
    throw error;
  }
  const versions = json(run, ["iam", "list-policy-versions", "--policy-arn", INITIAL_ACTIVATION_POLICY_RECONCILIATION.policyArn]).Versions;
  const role = json(run, ["iam", "get-role", "--role-name", "mscqr-production-release-deployer"]).Role;
  const attached = paged(run, ["iam", "list-attached-role-policies", "--role-name", "mscqr-production-release-deployer"], "AttachedPolicies");
  const entityPages = []; let marker;
  for (;;) {
    const page = json(run, ["iam", "list-entities-for-policy", "--policy-arn", INITIAL_ACTIVATION_POLICY_RECONCILIATION.policyArn, "--no-paginate", ...(marker ? ["--marker", marker] : [])]);
    if (!Array.isArray(page?.PolicyRoles) || !Array.isArray(page?.PolicyUsers) || !Array.isArray(page?.PolicyGroups) || typeof page.IsTruncated !== "boolean") throw new Error("Initial activation lifecycle policy entity pagination evidence is malformed.");
    entityPages.push(page);
    if (!page.IsTruncated) break;
    if (typeof page.Marker !== "string" || !page.Marker || entityPages.slice(0, -1).some(({ Marker }) => Marker === page.Marker)) throw new Error("Initial activation lifecycle policy entity pagination evidence is incomplete.");
    marker = page.Marker;
  }
  if (policy?.Arn !== INITIAL_ACTIVATION_POLICY_RECONCILIATION.policyArn || role?.Arn !== INITIAL_ACTIVATION_POLICY_RECONCILIATION.releaseRoleArn || !Array.isArray(versions)) throw new Error("Initial activation lifecycle policy live read is malformed.");
  return { policyArn: policy.Arn, defaultVersionId, document: version?.Document, policyVersionCount: versions.length, releaseRolePolicyArns: attached.map(({ PolicyArn }) => PolicyArn).sort(), targetPolicyRoles: entityPages.flatMap(({ PolicyRoles }) => PolicyRoles.map(({ RoleName }) => RoleName)).sort(), targetPolicyUsers: entityPages.flatMap(({ PolicyUsers }) => PolicyUsers.map(({ UserName }) => UserName)).sort(), targetPolicyGroups: entityPages.flatMap(({ PolicyGroups }) => PolicyGroups.map(({ GroupName }) => GroupName)).sort(), permissionsBoundaryUsageCount: policy.PermissionsBoundaryUsageCount };
}

export function runInitialActivationLifecyclePolicyReconciliation(argv = process.argv.slice(2), deps = {}) {
  const prepare = argv.includes("--prepare"); const executeMode = argv.includes("--execute");
  if (prepare === executeMode) throw new Error("Initial activation lifecycle policy reconciliation requires exactly one of --prepare or --execute.");
  const sourceSha = required(argv, "--source-sha");
  const adminProfile = prepare ? required(argv, "--admin-profile") : undefined;
  const checkout = (deps.readProtectedCheckout || readStageBProtectedMainCheckout)({ cwd: root, expectedSourceSha: sourceSha, requireCanonicalRepository: true });
  if (checkout.toolingSha !== sourceSha) throw new Error("Initial activation lifecycle policy executor is not at the authorized protected source.");
  const workflowEnvironment = deps.env || process.env;
  if (executeMode && (workflowEnvironment.GITHUB_ACTIONS !== "true" || workflowEnvironment.GITHUB_REPOSITORY !== "T-ej2003/genuine-scan-main" || workflowEnvironment.GITHUB_WORKFLOW_REF !== `${PRODUCTION_ENVIRONMENT_APPROVAL.repository}/${INITIAL_ACTIVATION_POLICY_RECONCILIATION.workflowPath}@refs/heads/main` || workflowEnvironment.GITHUB_EVENT_NAME !== "workflow_dispatch")) throw new Error("Initial activation lifecycle policy mutation is reachable only inside its canonical protected GitHub workflow.");
  if (executeMode && workflowEnvironment.GITHUB_RUN_ATTEMPT !== "1") throw new Error("Reconciliation workflow reruns are forbidden; use read-only live verification after an ambiguous attempt.");
  const run = deps.run || createInitialActivationReconciliationCommandRunner({ credentialSource: executeMode ? PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_OIDC_INITIAL_ACTIVATION_BOOTSTRAP : PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: adminProfile, env: workflowEnvironment });
  const identity = json(run, ["sts", "get-caller-identity"]);
  if (prepare && identity?.Arn !== "arn:aws:iam::368992683803:root") throw new Error("Initial activation lifecycle policy preparation requires the independently authenticated root operator.");
  if (executeMode && !new RegExp("^arn:aws:sts::368992683803:assumed-role/mscqr-production-initial-activation-policy-reconciler/[^/]+$").test(identity?.Arn || "")) throw new Error("Initial activation lifecycle policy mutation requires the exact OIDC reconciler role session.");
  const desired = readInitialActivationLifecycleDesiredPolicy({ repositoryRoot: root });
  if (prepare) {
    const liveState = readInitialActivationLifecyclePolicyLiveState(run);
    const authenticated = assertInitialActivationLifecyclePolicyState(liveState, { desired });
    if (authenticated.status === "AUTHENTICATED_PREDECESSOR" && authenticated.policyVersionCount > INITIAL_ACTIVATION_POLICY_RECONCILIATION.maxPolicyVersionsBeforeCreate) throw new Error("Initial activation lifecycle policy version capacity requires pruning and is not authorized.");
    const output = assertStageBArtifactPath({ artifactPath: path.resolve(required(argv, "--live-state-out")), repositoryRoot: root, label: "Initial activation lifecycle policy authorization request", allowExisting: false });
    ensureStageBPrivateDirectory({ directory: path.dirname(output), repositoryRoot: root, label: "Initial activation lifecycle policy authorization request directory" });
    writeStageBPrivateFileExclusive({ filePath: output, bytes: Buffer.from(`${JSON.stringify(liveState, null, 2)}\n`), repositoryRoot: root, label: "Initial activation lifecycle policy authorization request" });
    return Object.freeze({ sourceSha, targetPolicyArn: INITIAL_ACTIVATION_POLICY_RECONCILIATION.policyArn, desiredPolicySha256: desired.policySha256, livePolicySha256: authenticated.policySha256, liveDefaultVersionId: authenticated.defaultVersionId, policyVersionCount: authenticated.policyVersionCount, status: authenticated.status });
  }
  if (argv.includes("--admin-profile")) throw new Error("Workflow-only reconciliation does not accept a local administrator profile.");
  const authorizationPath = path.resolve(required(argv, "--authorization"));
  const authorizationFileSha256 = required(argv, "--authorization-file-sha256");
  const authorization = readBoundStageBPrivateJson({ filePath: authorizationPath, expectedSha256: authorizationFileSha256, repositoryRoot: root, label: "Initial activation lifecycle policy authorization" });
  assertInitialActivationLifecyclePolicyReconciliationAuthorization(authorization, { sourceSha });
  assertProductionEnvironmentApprovalEvidence(authorization.protectedEnvironmentApprovalEvidence, { sourceSha, repository: PRODUCTION_ENVIRONMENT_APPROVAL.repository, environment: PRODUCTION_ENVIRONMENT_APPROVAL.environment, workflowRef: workflowEnvironment.GITHUB_WORKFLOW_REF, eventName: workflowEnvironment.GITHUB_EVENT_NAME, workflowRunId: workflowEnvironment.GITHUB_RUN_ID, workflowRunAttempt: workflowEnvironment.GITHUB_RUN_ATTEMPT, executionActor: workflowEnvironment.GITHUB_ACTOR, githubActions: workflowEnvironment.GITHUB_ACTIONS });
  const resultOut = resolveResultOutput(argv);
  const outcome = (deps.executeReconciliation || executeInitialActivationLifecyclePolicyReconciliation)({ authorization, sourceSha, desired, readLiveState: () => readInitialActivationLifecyclePolicyLiveState(run), createPolicyVersion: ({ PolicyArn, PolicyDocument, SetAsDefault }) => json(run, ["iam", "create-policy-version", "--policy-arn", PolicyArn, "--policy-document", JSON.stringify(PolicyDocument), "--set-as-default"]) });
  const result = buildInitialActivationLifecyclePolicyReconciliationResult({ authorization, outcome });
  writeStageBPrivateFileExclusive({ filePath: resultOut, bytes: Buffer.from(`${JSON.stringify(result, null, 2)}\n`), repositoryRoot: root, label: "Initial activation lifecycle policy result" });
  return result;
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) process.stdout.write(`${JSON.stringify(runInitialActivationLifecyclePolicyReconciliation(), null, 2)}\n`);
