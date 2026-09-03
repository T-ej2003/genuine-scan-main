import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalJson, PRODUCTION_ACTIVATION_LIFECYCLE, STAGE_B } from "./production-green-stage-b-contract.mjs";
import { assertProductionEnvironmentActualReviewer, assertProductionEnvironmentApprovalIdentity, assertProductionEnvironmentReviewer, PRODUCTION_ENVIRONMENT_APPROVAL } from "./production-github-environment-approval.mjs";
import { ROOT_ATTESTATION_KEY_ALIAS_ARN, ROOT_ATTESTATION_SIGNING_ALGORITHM } from "./production-root-attestation-key.mjs";
import { assertStageAProductionArtifactsRecoveryCompletion, assertStageAProductionArtifactsReconciliationPrepareEvidence, buildStageAProductionArtifactsBucketPolicy, buildStageAProductionArtifactsBucketPolicyPredecessor, createStageAProductionArtifactsRecoveryCompletion, STAGE_A_LOCKED_AWS_RESOURCE_STATE_SCHEMA_VERSIONS, STAGE_A_TERRAFORM_VERSION, stageAProductionArtifactsPolicySha256 } from "./production-stage-a-control-plane.mjs";
import { STAGE_A_PRODUCTION_ARTIFACTS_JOURNAL_PREFIX, STAGE_A_PRODUCTION_ARTIFACTS_RECONCILIATION_OPERATION } from "./production-stage-a-production-artifacts-journal.mjs";
import { STAGE_A_TERRAFORM_BACKEND } from "./production-stage-a-root-drop-orphan-recovery.mjs";
import { createProductionGithubCommandRunner } from "./production-credential-source-contract.mjs";

export const STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_OPERATION = "STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY_RECOVERY";
export const STAGE_A_PRODUCTION_ARTIFACTS_CONTINUATION_REBIND_OPERATION = "STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_CONTINUATION_REBIND";
export const STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_WORKFLOW_REF = "T-ej2003/genuine-scan-main/.github/workflows/authorize-production-stage-a-production-artifacts-recovery.yml@refs/heads/main";
export const STAGE_A_PRODUCTION_ARTIFACTS_RECONCILIATION_WORKFLOW_REF = "T-ej2003/genuine-scan-main/.github/workflows/authorize-production-stage-a-production-artifacts-reconciliation.yml@refs/heads/main";
export const STAGE_A_PRODUCTION_ARTIFACTS_CONTINUATION_REBIND_WORKFLOW_REF = "T-ej2003/genuine-scan-main/.github/workflows/authorize-production-stage-a-production-artifacts-continuation-rebind.yml@refs/heads/main";
export const STAGE_A_PRODUCTION_ARTIFACTS_ROOT_PRINCIPAL = "arn:aws:iam::368992683803:root";
export const STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_AUTHORIZATION_ARTIFACT = "stage-a-production-artifacts-recovery-authorization";
export const STAGE_A_PRODUCTION_ARTIFACTS_RECONCILIATION_AUTHORIZATION_ARTIFACT = "stage-a-production-artifacts-reconciliation-authorization";
export const STAGE_A_PRODUCTION_ARTIFACTS_CONTINUATION_REBIND_AUTHORIZATION_ARTIFACT = "stage-a-production-artifacts-continuation-rebind-authorization";
const SHA256 = /^[a-f0-9]{64}$/;
const SHA40 = /^[a-f0-9]{40}$/;
const LINEAGE = /^[0-9a-f-]{36}$/;
const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const governedEntrypoints = Object.freeze([
  "scripts/aws/authorize-production-stage-a-production-artifacts-reconciliation.mjs",
  "scripts/aws/authorize-production-stage-a-production-artifacts-recovery.mjs",
  "scripts/aws/run-production-stage-a-production-artifacts-reconciliation.mjs",
  "scripts/aws/run-production-stage-a-production-artifacts-recovery.mjs",
]);
const continuationRebindGovernedEntrypoint = "scripts/aws/authorize-production-stage-a-production-artifacts-continuation-rebind.mjs";
const terraformRoot = "infra/aws/terraform/production-green-stage-a/";
const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const policySha256 = stageAProductionArtifactsPolicySha256;
const exactKeys = (value, fields, label) => {
  if (!value || typeof value !== "object" || Array.isArray(value) || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...fields].sort())) throw new Error(`${label} schema is invalid.`);
};
const state = (value, label) => {
  if (!value || !LINEAGE.test(value.lineage || "") || !Number.isSafeInteger(value.serial) || value.serial < 1 || !SHA256.test(value.stateSha256 || "")) throw new Error(`${label} state identity is invalid.`);
  return value;
};
const approval = (value, { sourceSha, workflowRef }) => {
  assertProductionEnvironmentApprovalIdentity(value, { sourceSha, repository: PRODUCTION_ENVIRONMENT_APPROVAL.repository });
  if (value.schemaVersion !== 3 || value.workflowRef !== workflowRef) throw new Error("Stage A production-artifacts authorization requires actual protected-environment approval.");
  const reviewer = assertProductionEnvironmentActualReviewer(value, { sourceSha, repository: PRODUCTION_ENVIRONMENT_APPROVAL.repository, executionActor: value.executionActor });
  assertProductionEnvironmentReviewer(value, { approvedBy: reviewer, executionActor: value.executionActor });
  return value;
};
const recoverFields = Object.freeze(["schemaVersion", "kind", "operation", "sourceSha", "account", "region", "bucket", "executionPrincipal", "predecessorPolicySha256", "desiredPolicySha256", "expectedLivePolicySha256", "preStateLineage", "preStateSerial", "preStateSha256", "governedExecutableManifestSha256", "continuationCompatibilitySha256", "maxPutBucketPolicy", "maxDeleteBucketPolicy", "protectedEnvironmentApprovalEvidence", "protectedEnvironmentApprovalEvidenceSha256", "verificationRef", "authorizationSha256"]);
const reconcileFields = Object.freeze(["schemaVersion", "kind", "operation", "sourceSha", "recoverySourceSha", "account", "region", "bucket", "executionPrincipal", "recoveryAuthorizationSha256", "recoveryCompletionSha256", "continuationRebindAuthorizationSha256", "desiredPolicySha256", "preStateLineage", "preStateSerial", "preStateSha256", "savedPlanSha256", "savedPlanByteLength", "prepareEvidenceSha256", "maxRefreshOnlyApplies", "maxInfrastructureWrites", "protectedEnvironmentApprovalEvidence", "protectedEnvironmentApprovalEvidenceSha256", "verificationRef", "authorizationSha256"]);
const rebindFields = Object.freeze(["schemaVersion", "kind", "operation", "repository", "environment", "account", "region", "artifactsBucket", "historicalRecoverySourceSha", "historicalRecoveryAuthorizationSha256", "recoveryCompletionSha256", "reviewedContinuationSourceSha", "reviewedGovernedExecutableManifestSha256", "stateLineage", "stateSerial", "rawStateSha256", "semanticDesiredP2PolicySha256", "maxPutBucketPolicy", "maxRefreshOnlyApplies", "maxInfrastructureWrites", "protectedEnvironmentApprovalEvidence", "protectedEnvironmentApprovalEvidenceSha256", "verificationRef", "authorizationSha256"]);
const completionFields = Object.freeze(["schemaVersion", "kind", "operation", "sourceSha", "account", "region", "bucket", "executionPrincipal", "recoveryAuthorizationSha256", "predecessorPolicySha256", "desiredPolicySha256", "preRecoveryLivePolicySha256", "postRecoveryLivePolicySha256", "preStateLineage", "preStateSerial", "preStateSha256", "maxPutBucketPolicy", "putBucketPolicyCount", "deleteBucketPolicyCount", "protectedEnvironmentApprovalEvidenceSha256", "workflowRunId", "workflowRunAttempt", "independentReviewer", "completion", "signature", "completionEvidenceSha256"]);
const attemptFields = Object.freeze(["schemaVersion", "kind", "operation", "sourceSha", "account", "region", "bucket", "executionPrincipal", "recoveryAuthorizationSha256", "predecessorPolicySha256", "desiredPolicySha256", "preStateLineage", "preStateSerial", "preStateSha256", "protectedEnvironmentApprovalEvidenceSha256", "workflowRunId", "workflowRunAttempt", "independentReviewer", "signature", "attemptEvidenceSha256"]);

function common({ sourceSha, preState, protectedEnvironmentApprovalEvidence, workflowRef, verificationRef }) {
  if (!SHA40.test(sourceSha || "") || typeof verificationRef !== "string" || !verificationRef.trim()) throw new Error("Stage A production-artifacts authorization source binding is invalid.");
  state(preState, "Stage A production-artifacts authorization"); approval(protectedEnvironmentApprovalEvidence, { sourceSha, workflowRef });
  return { sourceSha, account: STAGE_B.account, region: STAGE_B.region, bucket: PRODUCTION_ACTIVATION_LIFECYCLE.bucket, preStateLineage: preState.lineage, preStateSerial: preState.serial, preStateSha256: preState.stateSha256, protectedEnvironmentApprovalEvidence, protectedEnvironmentApprovalEvidenceSha256: protectedEnvironmentApprovalEvidence.evidenceSha256, verificationRef: verificationRef.trim() };
}

const relativeImports = (bytes) => {
  const source = bytes.toString("utf8"); const imports = new Set();
  for (const expression of [/\bimport\s*["'](\.[^"']+)["']/g, /\b(?:import|export)\s+[^;]*?\sfrom\s*["'](\.[^"']+)["']/g, /\bimport\s*\(\s*["'](\.[^"']+)["']\s*\)/g]) {
    for (const match of source.matchAll(expression)) imports.add(match[1]);
  }
  return [...imports];
};

export function stageAProductionArtifactsGovernedExecutableManifest(sourceSha, { git = (args, options = {}) => execFileSync("git", args, { cwd: repositoryRoot, ...options }) } = {}) {
  if (!SHA40.test(sourceSha || "") || typeof git !== "function") throw new Error("Stage A production-artifacts governed source coordinate is invalid.");
  const tree = new Map();
  for (const entry of Buffer.from(git(["ls-tree", "-r", "-z", "--full-tree", sourceSha])).toString("utf8").split("\0").filter(Boolean)) {
    const match = /^(\d+) (\w+) ([a-f0-9]+)\t(.+)$/.exec(entry);
    if (!match) throw new Error("Stage A production-artifacts governed source tree is malformed.");
    tree.set(match[4], { mode: match[1], type: match[2], object: match[3] });
  }
  // The historical recovery source predates the rebind authorizer. Once present,
  // it is an exact governed entrypoint rather than an optional dependency.
  const entrypoints = tree.has(continuationRebindGovernedEntrypoint) ? [...governedEntrypoints, continuationRebindGovernedEntrypoint] : governedEntrypoints;
  const selected = new Set(entrypoints); const pending = [...entrypoints]; const bytesByPath = new Map();
  while (pending.length) {
    const file = pending.pop(); const object = tree.get(file);
    if (!object || object.type !== "blob" || !["100644", "100755"].includes(object.mode)) throw new Error(`Stage A production-artifacts governed source file is missing or unsafe: ${file}`);
    const bytes = Buffer.from(git(["cat-file", "blob", object.object])); bytesByPath.set(file, bytes);
    for (const specifier of relativeImports(bytes)) {
      let dependency = path.posix.normalize(path.posix.join(path.posix.dirname(file), specifier));
      if (!path.posix.extname(dependency)) dependency += ".mjs";
      if (dependency.startsWith("../") || dependency.startsWith("/") || !tree.has(dependency)) throw new Error(`Stage A production-artifacts governed source import is invalid: ${file} -> ${specifier}`);
      if (!selected.has(dependency)) { selected.add(dependency); pending.push(dependency); }
    }
  }
  for (const file of tree.keys()) if ((file.startsWith(terraformRoot) && file.endsWith(".tf")) || file === `${terraformRoot}.terraform.lock.hcl`) selected.add(file);
  const files = [...selected].sort().map((file) => {
    const object = tree.get(file);
    if (!object || object.type !== "blob" || !["100644", "100755"].includes(object.mode)) throw new Error(`Stage A production-artifacts governed source file is missing or unsafe: ${file}`);
    const bytes = bytesByPath.get(file) || Buffer.from(git(["cat-file", "blob", object.object]));
    return Object.freeze({ path: file, sha256: sha256(bytes) });
  });
  return Object.freeze({ schemaVersion: 1, sourceSha, files: Object.freeze(files) });
}

export const stageAProductionArtifactsGovernedExecutableManifestSha256 = (sourceSha, options) => {
  const { schemaVersion, files } = stageAProductionArtifactsGovernedExecutableManifest(sourceSha, options);
  return sha256(canonicalJson({ schemaVersion, files }));
};

export const STAGE_A_RECOVERY_CONTINUATION_SAFE_FILES = Object.freeze([
  "scripts/aws/production-stage-a-control-plane.mjs",
  "scripts/aws/production-stage-a-production-artifacts-recovery-governance.mjs",
  "scripts/aws/run-production-stage-a-production-artifacts-recovery.mjs",
]);

export function assertStageAProductionArtifactsRecoverySourceCompatibility({ sourceSha, recoverySourceSha, proveDescendant, historicalGovernedExecutableManifestSha256, readGovernedExecutableManifestSha256 = stageAProductionArtifactsGovernedExecutableManifestSha256, readContinuationChangedFiles } = {}) {
  if (!SHA40.test(sourceSha || "") || !SHA40.test(recoverySourceSha || "")) throw new Error("Stage A production-artifacts recovery source compatibility is invalid.");
  if (sourceSha === recoverySourceSha) return true;
  if (typeof proveDescendant !== "function" || proveDescendant({ ancestorSha: recoverySourceSha, descendantSha: sourceSha }) !== true) throw new Error("Stage A production-artifacts current source is not an authenticated descendant of the recovery source.");
  const historical = typeof readGovernedExecutableManifestSha256 === "function" && readGovernedExecutableManifestSha256(recoverySourceSha);
  if (!SHA256.test(historical || "") || (historicalGovernedExecutableManifestSha256 !== undefined && historical !== historicalGovernedExecutableManifestSha256)) throw new Error("Stage A production-artifacts descendant changed the governed executable source.");
  const current = readGovernedExecutableManifestSha256(sourceSha);
  if (historical === current) return true;
  if (typeof readContinuationChangedFiles !== "function") throw new Error("Stage A production-artifacts descendant changed the governed executable source.");
  const changed = readContinuationChangedFiles({ ancestorSha: recoverySourceSha, descendantSha: sourceSha });
  if (!Array.isArray(changed) || JSON.stringify([...changed].sort()) !== JSON.stringify(STAGE_A_RECOVERY_CONTINUATION_SAFE_FILES)) throw new Error("Stage A production-artifacts descendant changed an unsafe governed executable source.");
  return true;
}

export const stageAProductionArtifactsContinuationCompatibilitySha256 = ({ governedExecutableManifestSha256 } = {}) => {
  if (!SHA256.test(governedExecutableManifestSha256 || "")) throw new Error("Stage A production-artifacts governed executable manifest identity is invalid.");
  return sha256(canonicalJson({
  schemaVersion: 1,
  recoveryOperation: STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_OPERATION,
  reconciliationOperation: STAGE_A_PRODUCTION_ARTIFACTS_RECONCILIATION_OPERATION,
  account: STAGE_B.account,
  region: STAGE_B.region,
  bucket: PRODUCTION_ACTIVATION_LIFECYCLE.bucket,
  rootPrincipal: STAGE_A_PRODUCTION_ARTIFACTS_ROOT_PRINCIPAL,
  releasePrincipal: PRODUCTION_ACTIVATION_LIFECYCLE.releaseRoleArn,
  predecessorPolicySha256: policySha256(buildStageAProductionArtifactsBucketPolicyPredecessor()),
  desiredPolicySha256: policySha256(buildStageAProductionArtifactsBucketPolicy()),
  journalPrefix: STAGE_A_PRODUCTION_ARTIFACTS_JOURNAL_PREFIX,
  terraformVersion: STAGE_A_TERRAFORM_VERSION,
  awsProviderVersion: "6.56.0",
  terraformRoot: "infra/aws/terraform/production-green-stage-a",
  terraformBackend: STAGE_A_TERRAFORM_BACKEND,
  stateSchemaVersions: STAGE_A_LOCKED_AWS_RESOURCE_STATE_SCHEMA_VERSIONS,
  rootAttestationKey: ROOT_ATTESTATION_KEY_ALIAS_ARN,
  rootAttestationSigningAlgorithm: ROOT_ATTESTATION_SIGNING_ALGORITHM,
  governedExecutableManifestSha256,
  }));
};

export function createStageAProductionArtifactsRecoveryAuthorization({ sourceSha, preState, protectedEnvironmentApprovalEvidence, verificationRef, governedExecutableManifestSha256 = stageAProductionArtifactsGovernedExecutableManifestSha256(sourceSha) } = {}) {
  const body = { schemaVersion: 1, kind: "STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_AUTHORIZATION", operation: STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_OPERATION, ...common({ sourceSha, preState, protectedEnvironmentApprovalEvidence, workflowRef: STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_WORKFLOW_REF, verificationRef }), executionPrincipal: STAGE_A_PRODUCTION_ARTIFACTS_ROOT_PRINCIPAL, predecessorPolicySha256: policySha256(buildStageAProductionArtifactsBucketPolicyPredecessor()), desiredPolicySha256: policySha256(buildStageAProductionArtifactsBucketPolicy()), expectedLivePolicySha256: policySha256(buildStageAProductionArtifactsBucketPolicyPredecessor()), governedExecutableManifestSha256, continuationCompatibilitySha256: stageAProductionArtifactsContinuationCompatibilitySha256({ governedExecutableManifestSha256 }), maxPutBucketPolicy: 1, maxDeleteBucketPolicy: 0 };
  return Object.freeze({ ...body, authorizationSha256: sha256(canonicalJson(body)) });
}

export function assertStageAProductionArtifactsRecoveryAuthorization(value, { sourceSha, preState, expectedContinuationCompatibilitySha256 } = {}) {
  exactKeys(value, recoverFields, "Stage A production-artifacts recovery authorization"); state(preState, "Stage A production-artifacts recovery authorization");
  const compatibilitySha256 = stageAProductionArtifactsContinuationCompatibilitySha256({ governedExecutableManifestSha256: value.governedExecutableManifestSha256 });
  if (value.schemaVersion !== 1 || value.kind !== "STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_AUTHORIZATION" || value.operation !== STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_OPERATION || value.sourceSha !== sourceSha || value.account !== STAGE_B.account || value.region !== STAGE_B.region || value.bucket !== PRODUCTION_ACTIVATION_LIFECYCLE.bucket || value.executionPrincipal !== STAGE_A_PRODUCTION_ARTIFACTS_ROOT_PRINCIPAL || value.predecessorPolicySha256 !== policySha256(buildStageAProductionArtifactsBucketPolicyPredecessor()) || value.desiredPolicySha256 !== policySha256(buildStageAProductionArtifactsBucketPolicy()) || value.expectedLivePolicySha256 !== value.predecessorPolicySha256 || value.preStateLineage !== preState.lineage || value.preStateSerial !== preState.serial || value.preStateSha256 !== preState.stateSha256 || value.continuationCompatibilitySha256 !== compatibilitySha256 || (expectedContinuationCompatibilitySha256 !== undefined && value.continuationCompatibilitySha256 !== expectedContinuationCompatibilitySha256) || value.maxPutBucketPolicy !== 1 || value.maxDeleteBucketPolicy !== 0 || value.protectedEnvironmentApprovalEvidenceSha256 !== value.protectedEnvironmentApprovalEvidence?.evidenceSha256 || !SHA256.test(value.authorizationSha256 || "")) throw new Error("Stage A production-artifacts recovery authorization binding is invalid.");
  approval(value.protectedEnvironmentApprovalEvidence, { sourceSha, workflowRef: STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_WORKFLOW_REF }); const { authorizationSha256, ...body } = value;
  if (authorizationSha256 !== sha256(canonicalJson(body))) throw new Error("Stage A production-artifacts recovery authorization hash is invalid.");
  return Object.freeze(value);
}

export function createStageAProductionArtifactsRecoveryCompletionEvidence({ authorization, preRecoveryLivePolicy, postRecoveryLivePolicy, sign } = {}) {
  assertStageAProductionArtifactsRecoveryAuthorization(authorization, { sourceSha: authorization?.sourceSha, preState: { lineage: authorization?.preStateLineage, serial: authorization?.preStateSerial, stateSha256: authorization?.preStateSha256 } });
  if (policySha256(preRecoveryLivePolicy) !== authorization.expectedLivePolicySha256 || policySha256(postRecoveryLivePolicy) !== authorization.desiredPolicySha256 || typeof sign !== "function") throw new Error("Stage A production-artifacts recovery completion inputs are invalid.");
  const completion = createStageAProductionArtifactsRecoveryCompletion({ sourceSha: authorization.sourceSha, recoveryAuthorizationSha256: authorization.authorizationSha256, livePolicy: postRecoveryLivePolicy, stateLineage: authorization.preStateLineage, preStateSerial: authorization.preStateSerial, preStateSha256: authorization.preStateSha256 });
  const digest = Buffer.from(completion.completionSha256, "hex"); const signatureBase64 = sign({ digest, keyArn: ROOT_ATTESTATION_KEY_ALIAS_ARN, signingAlgorithm: ROOT_ATTESTATION_SIGNING_ALGORITHM });
  if (typeof signatureBase64 !== "string" || !signatureBase64) throw new Error("Stage A production-artifacts recovery completion signature is invalid.");
  const body = { schemaVersion: 1, kind: "STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_COMPLETION_EVIDENCE", operation: STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_OPERATION, sourceSha: authorization.sourceSha, account: STAGE_B.account, region: STAGE_B.region, bucket: PRODUCTION_ACTIVATION_LIFECYCLE.bucket, executionPrincipal: authorization.executionPrincipal, recoveryAuthorizationSha256: authorization.authorizationSha256, predecessorPolicySha256: authorization.predecessorPolicySha256, desiredPolicySha256: authorization.desiredPolicySha256, preRecoveryLivePolicySha256: policySha256(preRecoveryLivePolicy), postRecoveryLivePolicySha256: policySha256(postRecoveryLivePolicy), preStateLineage: authorization.preStateLineage, preStateSerial: authorization.preStateSerial, preStateSha256: authorization.preStateSha256, maxPutBucketPolicy: 1, putBucketPolicyCount: 1, deleteBucketPolicyCount: 0, protectedEnvironmentApprovalEvidenceSha256: authorization.protectedEnvironmentApprovalEvidenceSha256, workflowRunId: authorization.protectedEnvironmentApprovalEvidence.workflowRunId, workflowRunAttempt: authorization.protectedEnvironmentApprovalEvidence.workflowRunAttempt, independentReviewer: authorization.protectedEnvironmentApprovalEvidence.actualApproval.userLogin, completion, signature: { keyArn: ROOT_ATTESTATION_KEY_ALIAS_ARN, signingAlgorithm: ROOT_ATTESTATION_SIGNING_ALGORITHM, signatureBase64 } };
  return Object.freeze({ ...body, completionEvidenceSha256: sha256(canonicalJson(body)) });
}

export function createStageAProductionArtifactsRecoveryAttemptEvidence({ authorization, sign } = {}) {
  assertStageAProductionArtifactsRecoveryAuthorization(authorization, { sourceSha: authorization?.sourceSha, preState: { lineage: authorization?.preStateLineage, serial: authorization?.preStateSerial, stateSha256: authorization?.preStateSha256 } });
  if (typeof sign !== "function") throw new Error("Stage A production-artifacts recovery attempt signer is required.");
  const body = { schemaVersion: 1, kind: "STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_ATTEMPT_EVIDENCE", operation: authorization.operation, sourceSha: authorization.sourceSha, account: authorization.account, region: authorization.region, bucket: authorization.bucket, executionPrincipal: authorization.executionPrincipal, recoveryAuthorizationSha256: authorization.authorizationSha256, predecessorPolicySha256: authorization.predecessorPolicySha256, desiredPolicySha256: authorization.desiredPolicySha256, preStateLineage: authorization.preStateLineage, preStateSerial: authorization.preStateSerial, preStateSha256: authorization.preStateSha256, protectedEnvironmentApprovalEvidenceSha256: authorization.protectedEnvironmentApprovalEvidenceSha256, workflowRunId: authorization.protectedEnvironmentApprovalEvidence.workflowRunId, workflowRunAttempt: authorization.protectedEnvironmentApprovalEvidence.workflowRunAttempt, independentReviewer: authorization.protectedEnvironmentApprovalEvidence.actualApproval.userLogin };
  const digest = Buffer.from(sha256(canonicalJson(body)), "hex"); const signatureBase64 = sign({ digest, keyArn: ROOT_ATTESTATION_KEY_ALIAS_ARN, signingAlgorithm: ROOT_ATTESTATION_SIGNING_ALGORITHM });
  if (typeof signatureBase64 !== "string" || !signatureBase64) throw new Error("Stage A production-artifacts recovery attempt signature is invalid.");
  const signed = { ...body, signature: { keyArn: ROOT_ATTESTATION_KEY_ALIAS_ARN, signingAlgorithm: ROOT_ATTESTATION_SIGNING_ALGORITHM, signatureBase64 } };
  return Object.freeze({ ...signed, attemptEvidenceSha256: sha256(canonicalJson(signed)) });
}

export function assertStageAProductionArtifactsRecoveryAttemptEvidence(value, { authorization, verify } = {}) {
  exactKeys(value, attemptFields, "Stage A production-artifacts recovery attempt evidence");
  assertStageAProductionArtifactsRecoveryAuthorization(authorization, { sourceSha: authorization?.sourceSha, preState: { lineage: authorization?.preStateLineage, serial: authorization?.preStateSerial, stateSha256: authorization?.preStateSha256 } });
  const { signature, attemptEvidenceSha256, ...body } = value;
  if (value.schemaVersion !== 1 || value.kind !== "STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_ATTEMPT_EVIDENCE" || value.operation !== authorization.operation || value.sourceSha !== authorization.sourceSha || value.account !== authorization.account || value.region !== authorization.region || value.bucket !== authorization.bucket || value.executionPrincipal !== authorization.executionPrincipal || value.recoveryAuthorizationSha256 !== authorization.authorizationSha256 || value.predecessorPolicySha256 !== authorization.predecessorPolicySha256 || value.desiredPolicySha256 !== authorization.desiredPolicySha256 || value.preStateLineage !== authorization.preStateLineage || value.preStateSerial !== authorization.preStateSerial || value.preStateSha256 !== authorization.preStateSha256 || value.protectedEnvironmentApprovalEvidenceSha256 !== authorization.protectedEnvironmentApprovalEvidenceSha256 || value.workflowRunId !== authorization.protectedEnvironmentApprovalEvidence.workflowRunId || value.workflowRunAttempt !== authorization.protectedEnvironmentApprovalEvidence.workflowRunAttempt || value.independentReviewer !== authorization.protectedEnvironmentApprovalEvidence.actualApproval.userLogin || signature?.keyArn !== ROOT_ATTESTATION_KEY_ALIAS_ARN || signature?.signingAlgorithm !== ROOT_ATTESTATION_SIGNING_ALGORITHM || typeof signature?.signatureBase64 !== "string" || attemptEvidenceSha256 !== sha256(canonicalJson({ ...body, signature }))) throw new Error("Stage A production-artifacts recovery attempt evidence binding is invalid.");
  const digest = Buffer.from(sha256(canonicalJson(body)), "hex");
  if (typeof verify !== "function" || verify({ digest, signature: Buffer.from(signature.signatureBase64, "base64"), keyArn: signature.keyArn, signingAlgorithm: signature.signingAlgorithm }) !== true) throw new Error("Stage A production-artifacts recovery attempt signature is invalid.");
  return Object.freeze(value);
}

export function assertStageAProductionArtifactsRecoveryCompletionEvidence(value, { authorization, verify } = {}) {
  exactKeys(value, completionFields, "Stage A production-artifacts recovery completion evidence"); assertStageAProductionArtifactsRecoveryAuthorization(authorization, { sourceSha: authorization?.sourceSha, preState: { lineage: authorization?.preStateLineage, serial: authorization?.preStateSerial, stateSha256: authorization?.preStateSha256 } });
  if (value.schemaVersion !== 1 || value.kind !== "STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_COMPLETION_EVIDENCE" || value.operation !== STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_OPERATION || value.sourceSha !== authorization.sourceSha || value.account !== STAGE_B.account || value.region !== STAGE_B.region || value.bucket !== authorization.bucket || value.executionPrincipal !== STAGE_A_PRODUCTION_ARTIFACTS_ROOT_PRINCIPAL || value.recoveryAuthorizationSha256 !== authorization.authorizationSha256 || value.predecessorPolicySha256 !== authorization.predecessorPolicySha256 || value.desiredPolicySha256 !== authorization.desiredPolicySha256 || value.preRecoveryLivePolicySha256 !== authorization.expectedLivePolicySha256 || value.postRecoveryLivePolicySha256 !== authorization.desiredPolicySha256 || value.preStateLineage !== authorization.preStateLineage || value.preStateSerial !== authorization.preStateSerial || value.preStateSha256 !== authorization.preStateSha256 || value.maxPutBucketPolicy !== 1 || value.putBucketPolicyCount !== 1 || value.deleteBucketPolicyCount !== 0 || value.protectedEnvironmentApprovalEvidenceSha256 !== authorization.protectedEnvironmentApprovalEvidenceSha256 || value.workflowRunId !== authorization.protectedEnvironmentApprovalEvidence.workflowRunId || value.workflowRunAttempt !== authorization.protectedEnvironmentApprovalEvidence.workflowRunAttempt || value.independentReviewer !== authorization.protectedEnvironmentApprovalEvidence.actualApproval.userLogin || value.completion?.completionSha256 === undefined || value.completion?.livePolicySha256 !== authorization.desiredPolicySha256 || value.signature?.keyArn !== ROOT_ATTESTATION_KEY_ALIAS_ARN || value.signature?.signingAlgorithm !== ROOT_ATTESTATION_SIGNING_ALGORITHM || typeof value.signature?.signatureBase64 !== "string" || !SHA256.test(value.completionEvidenceSha256 || "")) throw new Error("Stage A production-artifacts recovery completion evidence binding is invalid.");
  const { completionEvidenceSha256, signature, ...body } = value; if (completionEvidenceSha256 !== sha256(canonicalJson({ ...body, signature }))) throw new Error("Stage A production-artifacts recovery completion evidence hash is invalid.");
  if (typeof verify !== "function" || verify({ digest: Buffer.from(value.completion.completionSha256, "hex"), signature: Buffer.from(value.signature.signatureBase64, "base64"), keyArn: value.signature.keyArn, signingAlgorithm: value.signature.signingAlgorithm }) !== true) throw new Error("Stage A production-artifacts recovery completion signature is invalid.");
  assertStageAProductionArtifactsRecoveryCompletion(value.completion, { sourceSha: authorization.sourceSha, preStateSerial: authorization.preStateSerial, preStateSha256: authorization.preStateSha256, verifyRecoveryCompletion: (completion) => completion.recoveryAuthorizationSha256 === authorization.authorizationSha256 && completion.livePolicySha256 === authorization.desiredPolicySha256 ? { authorizationSha256: authorization.authorizationSha256, livePolicySha256: authorization.desiredPolicySha256, completed: true } : false });
  return Object.freeze(value);
}

export function createStageAProductionArtifactsContinuationRebindAuthorization({ historicalRecoveryAuthorization, recoveryCompletion, reviewedContinuationSourceSha, reviewedGovernedExecutableManifestSha256, protectedEnvironmentApprovalEvidence, verificationRef } = {}) {
  const preState = { lineage: historicalRecoveryAuthorization?.preStateLineage, serial: historicalRecoveryAuthorization?.preStateSerial, stateSha256: historicalRecoveryAuthorization?.preStateSha256 };
  assertStageAProductionArtifactsRecoveryAuthorization(historicalRecoveryAuthorization, { sourceSha: historicalRecoveryAuthorization?.sourceSha, preState });
  if (!SHA40.test(reviewedContinuationSourceSha || "") || !SHA256.test(reviewedGovernedExecutableManifestSha256 || "") || recoveryCompletion?.completionEvidenceSha256 === undefined) throw new Error("Stage A continuation rebind inputs are invalid.");
  const body = { schemaVersion: 1, kind: "STAGE_A_PRODUCTION_ARTIFACTS_CONTINUATION_REBIND_AUTHORIZATION", operation: STAGE_A_PRODUCTION_ARTIFACTS_CONTINUATION_REBIND_OPERATION, repository: PRODUCTION_ENVIRONMENT_APPROVAL.repository, environment: "production", account: STAGE_B.account, region: STAGE_B.region, artifactsBucket: PRODUCTION_ACTIVATION_LIFECYCLE.bucket, historicalRecoverySourceSha: historicalRecoveryAuthorization.sourceSha, historicalRecoveryAuthorizationSha256: historicalRecoveryAuthorization.authorizationSha256, recoveryCompletionSha256: recoveryCompletion.completionEvidenceSha256, reviewedContinuationSourceSha, reviewedGovernedExecutableManifestSha256, stateLineage: preState.lineage, stateSerial: preState.serial, rawStateSha256: preState.stateSha256, semanticDesiredP2PolicySha256: historicalRecoveryAuthorization.desiredPolicySha256, maxPutBucketPolicy: 0, maxRefreshOnlyApplies: 0, maxInfrastructureWrites: 0, protectedEnvironmentApprovalEvidence, protectedEnvironmentApprovalEvidenceSha256: protectedEnvironmentApprovalEvidence?.evidenceSha256, verificationRef: verificationRef?.trim?.() };
  approval(protectedEnvironmentApprovalEvidence, { sourceSha: reviewedContinuationSourceSha, workflowRef: STAGE_A_PRODUCTION_ARTIFACTS_CONTINUATION_REBIND_WORKFLOW_REF });
  if (typeof body.verificationRef !== "string" || !body.verificationRef) throw new Error("Stage A continuation rebind verification reference is invalid.");
  return Object.freeze({ ...body, authorizationSha256: sha256(canonicalJson(body)) });
}

export function assertStageAProductionArtifactsContinuationRebindAuthorization(value, { historicalRecoveryAuthorization, recoveryCompletion, sourceSha, readGovernedExecutableManifestSha256 = stageAProductionArtifactsGovernedExecutableManifestSha256 } = {}) {
  exactKeys(value, rebindFields, "Stage A continuation rebind authorization");
  const preState = { lineage: historicalRecoveryAuthorization?.preStateLineage, serial: historicalRecoveryAuthorization?.preStateSerial, stateSha256: historicalRecoveryAuthorization?.preStateSha256 };
  assertStageAProductionArtifactsRecoveryAuthorization(historicalRecoveryAuthorization, { sourceSha: historicalRecoveryAuthorization?.sourceSha, preState });
  if (value.schemaVersion !== 1 || value.kind !== "STAGE_A_PRODUCTION_ARTIFACTS_CONTINUATION_REBIND_AUTHORIZATION" || value.operation !== STAGE_A_PRODUCTION_ARTIFACTS_CONTINUATION_REBIND_OPERATION || value.repository !== PRODUCTION_ENVIRONMENT_APPROVAL.repository || value.environment !== "production" || value.account !== STAGE_B.account || value.region !== STAGE_B.region || value.artifactsBucket !== PRODUCTION_ACTIVATION_LIFECYCLE.bucket || value.historicalRecoverySourceSha !== historicalRecoveryAuthorization.sourceSha || value.historicalRecoveryAuthorizationSha256 !== historicalRecoveryAuthorization.authorizationSha256 || value.recoveryCompletionSha256 !== recoveryCompletion?.completionEvidenceSha256 || value.reviewedContinuationSourceSha !== sourceSha || value.reviewedGovernedExecutableManifestSha256 !== readGovernedExecutableManifestSha256(sourceSha) || value.stateLineage !== preState.lineage || value.stateSerial !== preState.serial || value.rawStateSha256 !== preState.stateSha256 || value.semanticDesiredP2PolicySha256 !== historicalRecoveryAuthorization.desiredPolicySha256 || value.maxPutBucketPolicy !== 0 || value.maxRefreshOnlyApplies !== 0 || value.maxInfrastructureWrites !== 0 || value.protectedEnvironmentApprovalEvidenceSha256 !== value.protectedEnvironmentApprovalEvidence?.evidenceSha256 || !SHA256.test(value.authorizationSha256 || "")) throw new Error("Stage A continuation rebind authorization binding is invalid.");
  approval(value.protectedEnvironmentApprovalEvidence, { sourceSha, workflowRef: STAGE_A_PRODUCTION_ARTIFACTS_CONTINUATION_REBIND_WORKFLOW_REF }); const { authorizationSha256, ...body } = value;
  if (authorizationSha256 !== sha256(canonicalJson(body))) throw new Error("Stage A continuation rebind authorization hash is invalid.");
  return Object.freeze(value);
}

export function assertStageAProductionArtifactsReconciliationSourceCompatibility({ sourceSha, recoverySourceSha, recoveryAuthorization, recoveryCompletion, continuationRebindAuthorization, proveDescendant, readGovernedExecutableManifestSha256 } = {}) {
  if (sourceSha === recoverySourceSha) {
    if (continuationRebindAuthorization !== undefined && continuationRebindAuthorization !== null) throw new Error("Stage A production-artifacts same-source reconciliation must not consume a continuation rebind.");
    assertStageAProductionArtifactsRecoverySourceCompatibility({ sourceSha, recoverySourceSha, proveDescendant, historicalGovernedExecutableManifestSha256: recoveryAuthorization?.governedExecutableManifestSha256, readGovernedExecutableManifestSha256 });
    return null;
  }
  if (typeof proveDescendant !== "function" || proveDescendant({ ancestorSha: recoverySourceSha, descendantSha: sourceSha }) !== true) throw new Error("Stage A production-artifacts reconciliation source is not an authenticated descendant of the recovery source.");
  return assertStageAProductionArtifactsContinuationRebindAuthorization(continuationRebindAuthorization, { historicalRecoveryAuthorization: recoveryAuthorization, recoveryCompletion, sourceSha, readGovernedExecutableManifestSha256 }).authorizationSha256;
}

export function createStageAProductionArtifactsReconciliationAuthorization({ sourceSha, recoverySourceSha, preState, recoveryAuthorization, recoveryCompletion, continuationRebindAuthorization, prepareEvidence, savedPlanSha256, protectedEnvironmentApprovalEvidence, verificationRef, verifyRecoveryCompletionEvidence, proveDescendant, readGovernedExecutableManifestSha256 } = {}) {
  recoverySourceSha ||= recoveryAuthorization?.sourceSha;
  const continuationRebindAuthorizationSha256 = assertStageAProductionArtifactsReconciliationSourceCompatibility({ sourceSha, recoverySourceSha, recoveryAuthorization, recoveryCompletion, continuationRebindAuthorization, proveDescendant, readGovernedExecutableManifestSha256 });
  assertStageAProductionArtifactsRecoveryAuthorization(recoveryAuthorization, { sourceSha: recoverySourceSha, preState });
  assertStageAProductionArtifactsRecoveryCompletionEvidence(recoveryCompletion, { authorization: recoveryAuthorization, verify: verifyRecoveryCompletionEvidence });
  if (!SHA256.test(savedPlanSha256 || "") || !recoveryCompletion || recoveryCompletion.recoveryAuthorizationSha256 !== recoveryAuthorization.authorizationSha256 || recoveryCompletion.completion?.completionSha256 === undefined || !prepareEvidence || prepareEvidence.savedPlanSha256 !== savedPlanSha256 || !Number.isSafeInteger(prepareEvidence.savedPlanByteLength) || prepareEvidence.savedPlanByteLength < 1) throw new Error("Stage A production-artifacts reconciliation authorization inputs are invalid.");
  assertStageAProductionArtifactsReconciliationPrepareEvidence(prepareEvidence, { sourceSha, recoveryCompletion: recoveryCompletion.completion, preState, savedPlanSha256, savedPlanByteLength: prepareEvidence.savedPlanByteLength });
  const body = { schemaVersion: 1, kind: "STAGE_A_PRODUCTION_ARTIFACTS_RECONCILIATION_AUTHORIZATION", operation: STAGE_A_PRODUCTION_ARTIFACTS_RECONCILIATION_OPERATION, ...common({ sourceSha, preState, protectedEnvironmentApprovalEvidence, workflowRef: STAGE_A_PRODUCTION_ARTIFACTS_RECONCILIATION_WORKFLOW_REF, verificationRef }), recoverySourceSha, executionPrincipal: PRODUCTION_ACTIVATION_LIFECYCLE.releaseRoleArn, recoveryAuthorizationSha256: recoveryAuthorization.authorizationSha256, recoveryCompletionSha256: recoveryCompletion.completionEvidenceSha256, continuationRebindAuthorizationSha256, desiredPolicySha256: recoveryAuthorization.desiredPolicySha256, savedPlanSha256, savedPlanByteLength: prepareEvidence.savedPlanByteLength, prepareEvidenceSha256: prepareEvidence.prepareEvidenceSha256, maxRefreshOnlyApplies: 1, maxInfrastructureWrites: 0 };
  return Object.freeze({ ...body, authorizationSha256: sha256(canonicalJson(body)) });
}

export function assertStageAProductionArtifactsReconciliationGovernanceAuthorization(value, { sourceSha, recoverySourceSha, preState, recoveryAuthorization, recoveryCompletion, continuationRebindAuthorization, prepareEvidence, savedPlanSha256, verifyRecoveryCompletionEvidence, proveDescendant, readGovernedExecutableManifestSha256 } = {}) {
  recoverySourceSha ||= value?.recoverySourceSha || recoveryAuthorization?.sourceSha;
  exactKeys(value, reconcileFields, "Stage A production-artifacts reconciliation authorization"); const continuationRebindAuthorizationSha256 = assertStageAProductionArtifactsReconciliationSourceCompatibility({ sourceSha, recoverySourceSha, recoveryAuthorization, recoveryCompletion, continuationRebindAuthorization, proveDescendant, readGovernedExecutableManifestSha256 }); assertStageAProductionArtifactsRecoveryAuthorization(recoveryAuthorization, { sourceSha: recoverySourceSha, preState });
  assertStageAProductionArtifactsRecoveryCompletionEvidence(recoveryCompletion, { authorization: recoveryAuthorization, verify: verifyRecoveryCompletionEvidence });
  if (value.schemaVersion !== 1 || value.kind !== "STAGE_A_PRODUCTION_ARTIFACTS_RECONCILIATION_AUTHORIZATION" || value.operation !== STAGE_A_PRODUCTION_ARTIFACTS_RECONCILIATION_OPERATION || value.sourceSha !== sourceSha || value.recoverySourceSha !== recoverySourceSha || value.account !== STAGE_B.account || value.region !== STAGE_B.region || value.bucket !== PRODUCTION_ACTIVATION_LIFECYCLE.bucket || value.executionPrincipal !== PRODUCTION_ACTIVATION_LIFECYCLE.releaseRoleArn || value.recoveryAuthorizationSha256 !== recoveryAuthorization.authorizationSha256 || value.recoveryCompletionSha256 !== recoveryCompletion?.completionEvidenceSha256 || value.continuationRebindAuthorizationSha256 !== continuationRebindAuthorizationSha256 || value.desiredPolicySha256 !== recoveryAuthorization.desiredPolicySha256 || value.preStateLineage !== preState?.lineage || value.preStateSerial !== preState?.serial || value.preStateSha256 !== preState?.stateSha256 || value.savedPlanSha256 !== savedPlanSha256 || !SHA256.test(value.savedPlanSha256 || "") || !Number.isSafeInteger(value.savedPlanByteLength) || value.savedPlanByteLength < 1 || value.prepareEvidenceSha256 !== prepareEvidence?.prepareEvidenceSha256 || value.maxRefreshOnlyApplies !== 1 || value.maxInfrastructureWrites !== 0 || value.protectedEnvironmentApprovalEvidenceSha256 !== value.protectedEnvironmentApprovalEvidence?.evidenceSha256 || !SHA256.test(value.authorizationSha256 || "")) throw new Error("Stage A production-artifacts reconciliation authorization binding is invalid.");
  assertStageAProductionArtifactsReconciliationPrepareEvidence(prepareEvidence, { sourceSha, recoveryCompletion: recoveryCompletion.completion, preState, savedPlanSha256, savedPlanByteLength: value.savedPlanByteLength });
  approval(value.protectedEnvironmentApprovalEvidence, { sourceSha, workflowRef: STAGE_A_PRODUCTION_ARTIFACTS_RECONCILIATION_WORKFLOW_REF }); const { authorizationSha256, ...body } = value;
  if (authorizationSha256 !== sha256(canonicalJson(body))) throw new Error("Stage A production-artifacts reconciliation authorization hash is invalid.");
  return Object.freeze(value);
}

export function resolveStageAProductionArtifactsAuthorizationArtifact({ workflowRunId, workflowRunAttempt, sourceSha, operation, githubRun = createProductionGithubCommandRunner(), readGovernedExecutableManifestSha256 = stageAProductionArtifactsGovernedExecutableManifestSha256 } = {}) {
  if (!/^[1-9][0-9]*$/.test(String(workflowRunId || "")) || !/^[1-9][0-9]*$/.test(String(workflowRunAttempt || "")) || !SHA40.test(sourceSha || "") || ![STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_OPERATION, STAGE_A_PRODUCTION_ARTIFACTS_RECONCILIATION_OPERATION, STAGE_A_PRODUCTION_ARTIFACTS_CONTINUATION_REBIND_OPERATION].includes(operation) || typeof githubRun !== "function") throw new Error("Stage A production-artifacts authorization artifact coordinates are invalid.");
  const recovery = operation === STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_OPERATION;
  const rebind = operation === STAGE_A_PRODUCTION_ARTIFACTS_CONTINUATION_REBIND_OPERATION;
  const workflowPath = recovery ? ".github/workflows/authorize-production-stage-a-production-artifacts-recovery.yml" : rebind ? ".github/workflows/authorize-production-stage-a-production-artifacts-continuation-rebind.yml" : ".github/workflows/authorize-production-stage-a-production-artifacts-reconciliation.yml";
  const artifactName = recovery ? STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_AUTHORIZATION_ARTIFACT : rebind ? STAGE_A_PRODUCTION_ARTIFACTS_CONTINUATION_REBIND_AUTHORIZATION_ARTIFACT : STAGE_A_PRODUCTION_ARTIFACTS_RECONCILIATION_AUTHORIZATION_ARTIFACT;
  const workflow = JSON.parse(githubRun("gh", ["api", `repos/${PRODUCTION_ENVIRONMENT_APPROVAL.repository}/actions/runs/${workflowRunId}`]));
  if (String(workflow.id) !== String(workflowRunId) || workflow.repository?.full_name !== PRODUCTION_ENVIRONMENT_APPROVAL.repository || workflow.head_repository?.full_name !== PRODUCTION_ENVIRONMENT_APPROVAL.repository || workflow.path !== workflowPath || workflow.event !== "workflow_dispatch" || workflow.head_sha !== sourceSha || workflow.status !== "completed" || workflow.conclusion !== "success" || String(workflow.run_attempt) !== String(workflowRunAttempt)) throw new Error("Stage A production-artifacts authorization workflow provenance is invalid.");
  const pages = JSON.parse(githubRun("gh", ["api", `repos/${PRODUCTION_ENVIRONMENT_APPROVAL.repository}/actions/runs/${workflowRunId}/artifacts`, "--paginate", "--slurp"])); const artifacts = Array.isArray(pages) ? pages.flatMap((page) => page?.artifacts || []) : [];
  const matches = artifacts.filter((artifact) => artifact.name === artifactName && artifact.expired === false && String(artifact.workflow_run?.id) === String(workflowRunId) && artifact.workflow_run?.head_sha === sourceSha && artifact.workflow_run?.repository_id === workflow.repository.id && /^sha256:[a-f0-9]{64}$/.test(artifact.digest || ""));
  if (matches.length !== 1 || !Number.isSafeInteger(matches[0]?.id) || matches[0].id < 1) throw new Error("Stage A production-artifacts authorization artifact identity is invalid.");
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-stage-a-production-artifacts-auth-")); const archive = path.join(directory, "authorization.zip");
  try {
    const archiveBytes = Buffer.from(githubRun("gh", ["api", `repos/${PRODUCTION_ENVIRONMENT_APPROVAL.repository}/actions/artifacts/${matches[0].id}/zip`], { encoding: null, maxBuffer: 64 * 1024 * 1024 }));
    if (`sha256:${sha256(archiveBytes)}` !== matches[0].digest) throw new Error("Stage A production-artifacts authorization archive digest is invalid.");
    fs.writeFileSync(archive, archiveBytes, { mode: 0o600, flag: "wx" }); const entries = String(githubRun("unzip", ["-Z1", archive])).trim().split("\n").filter(Boolean);
    if (JSON.stringify(entries) !== JSON.stringify(["authorization.json"])) throw new Error("Stage A production-artifacts authorization archive contents are invalid.");
    const authorization = JSON.parse(Buffer.from(githubRun("unzip", ["-p", archive, "authorization.json"])).toString("utf8"));
    if (recovery) assertStageAProductionArtifactsRecoveryAuthorization(authorization, { sourceSha, preState: { lineage: authorization.preStateLineage, serial: authorization.preStateSerial, stateSha256: authorization.preStateSha256 }, expectedContinuationCompatibilitySha256: stageAProductionArtifactsContinuationCompatibilitySha256({ governedExecutableManifestSha256: readGovernedExecutableManifestSha256(sourceSha) }) });
    const approvalEvidence = authorization.protectedEnvironmentApprovalEvidence;
    const workflowRunId = String(approvalEvidence?.workflowRunId || ""); const workflowRunAttempt = String(approvalEvidence?.workflowRunAttempt || "");
    if (!/^[1-9][0-9]*$/.test(workflowRunId) || !/^[1-9][0-9]*$/.test(workflowRunAttempt) || workflowRunId !== String(workflow.id || "") || workflowRunAttempt !== String(workflow.run_attempt || "") || approvalEvidence?.executionActor !== workflow.actor?.login) throw new Error("Stage A production-artifacts authorization approval evidence does not belong to its workflow.");
    return Object.freeze({ workflow, artifact: matches[0], authorization, authorizationArtifactDigest: matches[0].digest });
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
}
