import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { persistProductionBackendRecoveryCandidate, prepareProductionBackendRecoveryCandidate } from "../aws/prepare-production-backend-recovery-candidate.mjs";
import { prepareProductionEcsRuntimeConsumability, prepareProductionEcsRuntimeInventory } from "../aws/prepare-production-ecs-runtime-consumability.mjs";
import { createAwsCliAdapter, createRuntimePolicyConvergenceAuthorization, planProductionEcsRuntimePolicyConvergence, runCli as convergeRuntimePolicy } from "../aws/converge-production-ecs-runtime-policy.mjs";
import { RUNTIME_CONSUMABILITY } from "../aws/production-ecs-runtime-consumability.mjs";
import { assertLegacyBackendRecoveryCandidate } from "../aws/production-backend-health-recovery-contract.mjs";
import { assertAuthenticatedFailedRecoveryEvidence } from "../aws/production-backend-failed-recovery-evidence.mjs";
import { prepareProductionBackendFailedRecoveryEvidence } from "../aws/prepare-production-backend-failed-recovery-evidence.mjs";
import { publishProductionBackendFailedRecoveryEvidence } from "../aws/publish-production-backend-failed-recovery-evidence.mjs";
import { resolveProductionBackendFailedRecoveryEvidence } from "../aws/resolve-production-backend-failed-recovery-evidence.mjs";
import { buildBackendHealthRecoveryDispatch, parseBackendHealthRecoveryDispatchBundle } from "../aws/dispatch-production-backend-health-recovery.mjs";
import { extractProductionBackendRecoveryDispatchBundle } from "../aws/extract-production-backend-recovery-dispatch-bundle.mjs";
import { canonicalSha256 } from "../aws/stage-b-task-definition-recovery-contract.mjs";
import { createProductionEnvironmentApprovalEvidence } from "../aws/production-github-environment-approval.mjs";
import { makeCanonicalImageAuthorization } from "./fixtures/canonical-image-authorization.mjs";

const sourceSha = "b64274e155434ae9390d28762d40a37801be5362";
const legacy = JSON.parse(fs.readFileSync(new URL("./fixtures/mscqr-backend-47.task-definition.json", import.meta.url)));
const bindings = Object.fromEntries(["PRIVATE_KEY_CURRENT", "PUBLIC_KEY_CURRENT", "ACTIVE_KEY_VERSION", "PUBLIC_KEYS_JSON"].map((suffix) => [`ARTIFACT_SIGN_${suffix}`, `arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/artifact-signing/${suffix.toLowerCase().replaceAll("_", "-")}-AbCd12`]));
const image = makeCanonicalImageAuthorization({ sourceSha, imageReleaseSha: sourceSha });
const hashFile = (file) => crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
const writeJson = (file, value) => fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600, flag: "wx" });
const noRepositoryPolicy = () => {
  const error = new Error("AWS CLI failed");
  error.stderr = Buffer.from("aws: [ERROR]: An error occurred (RepositoryPolicyNotFoundException) when calling the GetRepositoryPolicy operation: Repository policy does not exist\n");
  return error;
};

test("real file boundaries support inventory, CAS convergence, post-convergence closure, and recovery candidate consumption", async (context) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-recovery-runtime-rehearsal-")); fs.chmodSync(directory, 0o700);
  context.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const candidateFile = path.join(directory, "candidate.json"); const inventoryFile = path.join(directory, "inventory.json"); const evidenceFile = path.join(directory, "consumability.json"); const authorizationFile = path.join(directory, "convergence-authorization.json"); const failedEvidenceFile = path.join(directory, "failed-recovery-evidence.json"); const failedReferenceFile = path.join(directory, "failed-recovery-evidence-reference.json");
  const prepared = prepareProductionBackendRecoveryCandidate({ sourceSha, taskDefinition: legacy, imageAuthorization: image.authorization, imageValidation: { verifyImageEvidence: image.verifyImageEvidence, now: image.now }, artifactSigningBindings: bindings, artifactSigningBindingSha256: "7".repeat(64) });
  const candidateArtifact = persistProductionBackendRecoveryCandidate({ ...prepared, candidateCanonicalSha256: "0".repeat(64), candidateFingerprint: "0".repeat(64) }, candidateFile);
  assert.equal(candidateArtifact.candidateFileSha256, hashFile(candidateFile));
  assert.equal(candidateArtifact.candidateCanonicalSha256, canonicalSha256(JSON.parse(fs.readFileSync(candidateFile))));
  assert.notEqual(candidateArtifact.candidateFileSha256, candidateArtifact.candidateCanonicalSha256);

  let runtimePolicy = { Version: "2012-10-17", Statement: [{ Effect: "Allow", Action: "secretsmanager:GetSecretValue", Resource: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:legacy-only" }] };
  let simulations = 0; let writes = 0;
  const aws = (args) => {
    const operation = args.slice(0, 2).join(" "); const valueAfter = (flag) => args[args.indexOf(flag) + 1];
    if (operation === "sts get-caller-identity") return { Account: "368992683803", Arn: "arn:aws:sts::368992683803:assumed-role/mscqr-production-bootstrap-mfa/operator" };
    if (operation === "ecr describe-images") return { imageDetails: [{ registryId: "368992683803", repositoryName: valueAfter("--repository-name"), imageDigest: valueAfter("--image-ids").slice("imageDigest=".length) }] };
    if (operation === "ecr get-repository-policy") throw noRepositoryPolicy();
    if (operation === "secretsmanager describe-secret") return { ARN: valueAfter("--secret-id"), KmsKeyId: null, VersionIdsToStages: { [`fixture_version_${"0".repeat(16)}`]: ["AWSCURRENT"] } };
    if (operation === "secretsmanager list-secret-version-ids") return { Versions: [{ VersionId: `fixture_version_${"0".repeat(16)}`, VersionStages: ["AWSCURRENT"] }] };
    if (operation === "secretsmanager get-secret-value") return { ARN: valueAfter("--secret-id"), VersionId: valueAfter("--version-id"), SecretString: JSON.stringify({ DATABASE_URL: "fixture-present", REDIS_URL: "fixture-present" }) };
    if (operation === "secretsmanager get-resource-policy") return { ARN: valueAfter("--secret-id"), ResourcePolicy: null };
    if (operation === "logs describe-log-groups") { const logGroupName = valueAfter("--log-group-name-prefix"); return { logGroups: [{ logGroupName, logGroupArn: `arn:aws:logs:eu-west-2:368992683803:log-group:${logGroupName}`, creationTime: 1, storedBytes: 0 }] }; }
    if (operation === "kms sign") return { Signature: "AQ==" };
    if (operation === "kms verify") return { SignatureValid: true };
    if (operation === "iam get-role") return { Role: { Arn: prepared.candidate.executionRoleArn, AssumeRolePolicyDocument: RUNTIME_CONSUMABILITY.ecsTaskTrust } };
    if (operation === "iam list-role-policies") return { PolicyNames: ["mscqr-ecs-secrets-read"] };
    if (operation === "iam get-role-policy") return { RoleName: "mscqr-ecs-execution-role", PolicyName: "mscqr-ecs-secrets-read", PolicyDocument: structuredClone(runtimePolicy) };
    if (operation === "iam list-attached-role-policies") return { AttachedPolicies: [{ PolicyName: "AmazonECSTaskExecutionRolePolicy", PolicyArn: RUNTIME_CONSUMABILITY.awsManagedExecutionPolicyArn }] };
    if (operation === "iam get-policy") return { Policy: { Arn: RUNTIME_CONSUMABILITY.awsManagedExecutionPolicyArn, DefaultVersionId: "v1" } };
    if (operation === "iam get-policy-version") return { PolicyVersion: { Document: { Version: "2012-10-17", Statement: [] } } };
    if (operation === "iam simulate-principal-policy") { simulations += 1; const action = valueAfter("--action-names"); const resource = valueAfter("--resource-arns"); return { EvaluationResults: [{ EvalActionName: action, EvalResourceName: resource, EvalDecision: "allowed" }] }; }
    if (operation === "iam put-role-policy") { writes += 1; runtimePolicy = JSON.parse(valueAfter("--policy-document")); return {}; }
    throw new Error(`unexpected local AWS adapter operation: ${operation}`);
  };
  const run = (args) => JSON.stringify(aws(args));

  const inventoryResult = await prepareProductionEcsRuntimeInventory({ sourceSha, candidateFile, candidateFileSha256: candidateArtifact.candidateFileSha256, outputFile: inventoryFile, run, protectedMain: () => {}, now: "2026-08-24T18:00:00.000Z" });
  assert.equal(simulations, 0, "read-only inventory must not require corrected runtime authority");
  const inventoryEnvelope = JSON.parse(fs.readFileSync(inventoryFile)); const plan = planProductionEcsRuntimePolicyConvergence({ candidate: prepared.candidate, candidateFileSha256: candidateArtifact.candidateFileSha256, runtimeInventory: inventoryEnvelope.inventory, livePolicyDocument: runtimePolicy });
  writeJson(authorizationFile, createRuntimePolicyConvergenceAuthorization({ sourceSha, plan, ticket: "INC-49", approvedBy: "operator", approverRole: "Production Operator", reason: "candidate-derived runtime closure", verificationRef: "https://example.invalid/49" }));
  const convergenceAws = createAwsCliAdapter((_command, args) => args[1] === "put-role-policy" ? (aws(args), "") : JSON.stringify(aws(args)));
  const convergence = await convergeRuntimePolicy(["--source-sha", sourceSha, "--candidate", candidateFile, "--candidate-file-sha256", candidateArtifact.candidateFileSha256, "--runtime-inventory", inventoryFile, "--runtime-inventory-sha256", inventoryResult.outputSha256, "--authorization", authorizationFile, "--authorization-sha256", hashFile(authorizationFile), "--execute"], { run: convergenceAws, protectedMain: () => {}, verifyInventory: () => true });
  assert.equal(convergence.applied, true); assert.equal(writes, 1);

  const consumability = await prepareProductionEcsRuntimeConsumability({ sourceSha, candidateFile, candidateFileSha256: candidateArtifact.candidateFileSha256, inventoryFile, inventoryFileSha256: inventoryResult.outputSha256, outputFile: evidenceFile, run, protectedMain: () => {}, now: "2026-08-24T18:01:00.000Z" });
  const consumabilityEnvelope = JSON.parse(fs.readFileSync(evidenceFile));
  assert.equal(consumability.inventorySha256, inventoryResult.inventorySha256); assert.ok(simulations > 0);
  assert.doesNotThrow(() => assertLegacyBackendRecoveryCandidate({ currentTaskDefinition: legacy, candidate: JSON.parse(fs.readFileSync(candidateFile)), recoveryImageDigest: image.authorization.backendDigest, imageReleaseSha: sourceSha, artifactSigningBindings: bindings }));
  const historicalEnvironment = createProductionEnvironmentApprovalEvidence({ repository: "T-ej2003/genuine-scan-main", environment: "production", sourceSha, workflowRunId: "32759665989", workflowRunAttempt: "1", workflowRef: "T-ej2003/genuine-scan-main/.github/workflows/release-gate.yml@refs/heads/main", eventName: "workflow_dispatch", executionActor: "operator", observedAt: "2026-08-24T18:01:00.000Z", environmentConfig: { id: 1, name: "production", can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: true, reviewers: [{ type: "User", reviewer: { id: 1, login: "reviewer" } }] }] } });
  const historicalEnvironmentBytes = Buffer.from(`${JSON.stringify(historicalEnvironment, null, 2)}\n`);
  const recoveryBody = { schemaVersion: 6, kind: "BACKEND_HEALTH_RECOVERY_EVIDENCE", sourceSha, authorizationFileSha256: "a".repeat(64), authorizationSha256: "b".repeat(64), environmentApprovalFileSha256: crypto.createHash("sha256").update(historicalEnvironmentBytes).digest("hex"), environmentApprovalSha256: historicalEnvironment.evidenceSha256, imageAuthorizationFileSha256: "c".repeat(64), imageAuthorizationSha256: "d".repeat(64), artifactSigningBindingSha256: "7".repeat(64), runtimeConsumabilitySha256: consumability.evidenceSha256, rollbackProofSha256: null, currentTaskDefinitionArn: legacy.taskDefinition.taskDefinitionArn, recoveryImageDigest: image.authorization.backendDigest, imageReleaseSha: sourceSha, account: "368992683803", region: "eu-west-2", status: "SERVICE_UPDATE_CONFIRMED", targetArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:49", registrations: 1, updates: 1, candidateFingerprint: consumabilityEnvelope.evidence.candidateFingerprint, initialRevisionCensusSha256: "1".repeat(64), expectedRevisionCensusSha256: "2".repeat(64), artifactSigningVerification: "VERIFIED", artifactSigningFailure: null, knownFailedRevisions: [], generatedAt: "2026-08-24T18:01:30.000Z" };
  const historicalRecoveryBytes = Buffer.from(`${JSON.stringify({ ...recoveryBody, evidenceSha256: canonicalSha256(recoveryBody) }, null, 2)}\n`);
  const historicalFiles = [["recoveryEvidence", historicalRecoveryBytes], ["environmentApproval", historicalEnvironmentBytes], ["runtimeConsumability", fs.readFileSync(evidenceFile)]];
  const historicalManifest = { schemaVersion: 1, records: [Object.fromEntries(historicalFiles.map(([name, value]) => { const file = path.join(directory, `historical-${name}.json`); fs.writeFileSync(file, value, { mode: 0o600, flag: "wx" }); return [name, { file, sha256: crypto.createHash("sha256").update(value).digest("hex") }]; }))] };
  const historicalManifestFile = path.join(directory, "historical-manifest.json"); const historicalManifestBytes = Buffer.from(`${JSON.stringify(historicalManifest, null, 2)}\n`); fs.writeFileSync(historicalManifestFile, historicalManifestBytes, { mode: 0o600, flag: "wx" });
  prepareProductionBackendFailedRecoveryEvidence({ sourceSha, manifestFile: historicalManifestFile, manifestSha256: crypto.createHash("sha256").update(historicalManifestBytes).digest("hex"), outputFile: failedEvidenceFile, now: Date.parse("2026-08-24T18:02:00.000Z"), protectedMain: () => {}, run: (_command, args) => JSON.stringify(args[1] === "verify" ? { SignatureValid: true } : { Signature: "AQ==" }) });
  const failedRecoveryEvidence = JSON.parse(fs.readFileSync(failedEvidenceFile));
  const failedEvidenceBytes = fs.readFileSync(failedEvidenceFile);
  const asset = { id: 202, name: `backend-failed-recovery-evidence-${failedRecoveryEvidence.envelopeSha256}.json`, state: "uploaded", size: failedEvidenceBytes.length, digest: `sha256:${hashFile(failedEvidenceFile)}` };
  const releaseTag = `mscqr-backend-failed-recovery-evidence-${failedRecoveryEvidence.envelopeSha256}`;
  const release = { id: 101, immutable: true, draft: false, tag_name: releaseTag, target_commitish: sourceSha, name: releaseTag, body: "KMS-authenticated MSCQR backend failed-recovery history.", assets: [asset] };
  const releaseView = { databaseId: release.id, tagName: release.tag_name, targetCommitish: release.target_commitish, name: release.name, body: release.body, isDraft: release.draft, isImmutable: release.immutable, assets: [{ ...asset, id: "node-202", apiUrl: "https://api.github.com/repos/T-ej2003/genuine-scan-main/releases/assets/202" }] };
  const releaseRun = (_command, args, options = {}) => args[0] === "release" ? JSON.stringify(releaseView) : args[1].endsWith("/releases/101") ? JSON.stringify(release) : args[1].endsWith("/assets/202") && options.encoding === null ? failedEvidenceBytes : JSON.stringify(asset);
  const published = publishProductionBackendFailedRecoveryEvidence({ sourceSha, evidenceFile: failedEvidenceFile, evidenceFileSha256: hashFile(failedEvidenceFile), outputFile: failedReferenceFile, protectedMain: () => {}, run: releaseRun });
  const approval = { ticket: "INC-49", approvedBy: "operator", approverRole: "Production Operator", reason: "reconcile an interrupted recovery mutation", verificationRef: "https://example.invalid/49", sourceSha, currentTaskDefinitionArn: legacy.taskDefinition.taskDefinitionArn, recoveryImageDigest: image.authorization.backendDigest, runtimeConsumabilitySha256: consumability.evidenceSha256, failedRecoveryEvidenceSha256: failedRecoveryEvidence.envelopeSha256, failedRecoveryEvidenceReferenceSha256: published.referenceSha256 };
  const dispatch = buildBackendHealthRecoveryDispatch({ sourceSha, currentTaskDefinitionArn: legacy.taskDefinition.taskDefinitionArn, recoveryImageDigest: image.authorization.backendDigest, service: "mscqr-backend-servi-euw2", releaseMode: "BACKEND_HEALTH_RECOVERY_LEGACY_RUNTIME", imageAuthorizationBytes: Buffer.from(JSON.stringify(image.authorization)), imageValidation: { now: image.now, verifyImageEvidence: image.verifyImageEvidence }, approvalBytes: Buffer.from(JSON.stringify(approval)), runtimeConsumabilityBytes: fs.readFileSync(evidenceFile), failedRecoveryEvidenceReferenceBytes: fs.readFileSync(failedReferenceFile) });
  const roundTrip = parseBackendHealthRecoveryDispatchBundle(dispatch.bundle.bytes, dispatch.bundle.sha256);
  assert.equal(roundTrip.value.sourceSha, sourceSha); assert.equal(JSON.parse(roundTrip.components.failedRecoveryEvidenceReference.value).referenceSha256, published.referenceSha256);
  const extractedDirectory = path.join(directory, "extracted"); fs.mkdirSync(extractedDirectory, { mode: 0o700 });
  const dispatchFile = path.join(directory, "dispatch.json"); fs.writeFileSync(dispatchFile, dispatch.bundle.bytes, { mode: 0o600 });
  const extracted = extractProductionBackendRecoveryDispatchBundle({ bundleFile: dispatchFile, bundleSha256: dispatch.bundle.sha256, outputDirectory: extractedDirectory, expected: { sourceSha, currentTaskDefinitionArn: legacy.taskDefinition.taskDefinitionArn, recoveryImageDigest: image.authorization.backendDigest, service: "mscqr-backend-servi-euw2", releaseMode: "BACKEND_HEALTH_RECOVERY_LEGACY_RUNTIME" } });
  const resolvedFile = path.join(directory, "resolved-failed-recovery-evidence.json");
  const reference = JSON.parse(fs.readFileSync(extracted.manifest.components.failedRecoveryEvidenceReference.file));
  resolveProductionBackendFailedRecoveryEvidence({ sourceSha, referenceFile: extracted.manifest.components.failedRecoveryEvidenceReference.file, referenceFileSha256: extracted.manifest.components.failedRecoveryEvidenceReference.sha256, outputFile: resolvedFile, run: (_command, args, options = {}) => args[1].endsWith(`/releases/${reference.releaseId}`) ? JSON.stringify(release) : args[1].endsWith(`/assets/${reference.assetId}`) && options.encoding === null ? failedEvidenceBytes : JSON.stringify(asset) });
  const authenticated = assertAuthenticatedFailedRecoveryEvidence(JSON.parse(fs.readFileSync(resolvedFile)), { verify: () => true, now: Date.parse("2026-08-24T18:02:00.000Z") });
  assert.equal(authenticated.knownFailedRevisions.length, 0);
  assert.equal(authenticated.interruptedRecoveries[0].taskDefinitionArn, recoveryBody.targetArn);
  const mutated = structuredClone(failedRecoveryEvidence); mutated.records[0].recoveryEvidence.bytesBase64 = `${mutated.records[0].recoveryEvidence.bytesBase64.slice(0, -4)}AAAA`;
  assert.throws(() => assertAuthenticatedFailedRecoveryEvidence(mutated, { verify: () => true, now: Date.parse("2026-08-24T18:02:00.000Z") }), /tampered|hash|signature/);

  const semanticEquivalent = path.join(directory, "candidate-canonical.json"); writeJson(semanticEquivalent, JSON.parse(fs.readFileSync(candidateFile)));
  const compact = Buffer.from(JSON.stringify(JSON.parse(fs.readFileSync(candidateFile)))); fs.writeFileSync(semanticEquivalent, compact);
  await assert.rejects(() => prepareProductionEcsRuntimeInventory({ sourceSha, candidateFile: semanticEquivalent, candidateFileSha256: candidateArtifact.candidateFileSha256, outputFile: path.join(directory, "should-not-exist.json"), run, protectedMain: () => {} }), /file bytes changed/);
});
