#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createProductionAwsCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";
import { INITIAL_ACTIVATION_POLICY_RECONCILIATION, INITIAL_ACTIVATION_TRANSIENT_POLICY_VERSION_READ, assertInitialActivationLifecyclePolicyState, buildInitialActivationLifecyclePolicyReconciliationResult, createInitialActivationLifecyclePolicyReservationStore, executeInitialActivationLifecyclePolicyReconciliation, readInitialActivationLifecycleDesiredPolicy, resolveInitialActivationLifecyclePolicyReconciliationAuthorizationArtifact } from "./production-initial-activation-policy-reconciliation.mjs";
import { readStageBProtectedMainCheckout } from "./stage-b-deployment-identity.mjs";
import { assertStageBArtifactPath, ensureStageBPrivateDirectory, writeStageBPrivateFileExclusive } from "./stage-b-artifact-contract.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const required = (argv, name) => { const index = argv.indexOf(name); const value = index < 0 ? undefined : argv[index + 1]; if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };
const json = (run, args) => JSON.parse(run(args));
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
    if (/NoSuchEntity(?:Exception)?/i.test(`${error?.name || ""}\n${error?.code || ""}\n${error?.message || ""}\n${error?.stderr || ""}`)) error.code = INITIAL_ACTIVATION_TRANSIENT_POLICY_VERSION_READ;
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
  const sourceSha = required(argv, "--source-sha"); const adminProfile = required(argv, "--admin-profile");
  const checkout = (deps.readProtectedCheckout || readStageBProtectedMainCheckout)({ cwd: root, expectedSourceSha: sourceSha, requireCanonicalRepository: true });
  if (checkout.toolingSha !== sourceSha) throw new Error("Initial activation lifecycle policy executor is not at the authorized protected source.");
  const run = deps.run || createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: adminProfile });
  const identity = json(run, ["sts", "get-caller-identity"]);
  if (identity?.Arn !== "arn:aws:iam::368992683803:root") throw new Error("Initial activation lifecycle policy reconciliation requires the independently authenticated root operator.");
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
  const resolved = (deps.resolveAuthorizationArtifact || resolveInitialActivationLifecyclePolicyReconciliationAuthorizationArtifact)({ workflowRunId: required(argv, "--workflow-run-id"), workflowRunAttempt: required(argv, "--workflow-run-attempt"), sourceSha });
  const authorization = resolved.authorization;
  const resultOut = resolveResultOutput(argv);
  const reservationStore = deps.reservationStore || createInitialActivationLifecyclePolicyReservationStore({ run });
  const outcome = (deps.executeReconciliation || executeInitialActivationLifecyclePolicyReconciliation)({ authorization, sourceSha, desired, reserve: (identity) => reservationStore.reserve(identity), readLiveState: () => readInitialActivationLifecyclePolicyLiveState(run), createPolicyVersion: ({ PolicyArn, PolicyDocument, SetAsDefault }) => json(run, ["iam", "create-policy-version", "--policy-arn", PolicyArn, "--policy-document", JSON.stringify(PolicyDocument), "--set-as-default"]) });
  const result = buildInitialActivationLifecyclePolicyReconciliationResult({ authorization, outcome });
  writeStageBPrivateFileExclusive({ filePath: resultOut, bytes: Buffer.from(`${JSON.stringify(result, null, 2)}\n`), repositoryRoot: root, label: "Initial activation lifecycle policy result" });
  return result;
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) process.stdout.write(`${JSON.stringify(runInitialActivationLifecyclePolicyReconciliation(), null, 2)}\n`);
