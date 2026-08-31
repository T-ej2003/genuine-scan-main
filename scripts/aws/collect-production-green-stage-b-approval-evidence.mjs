import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { assertImageAuthorization } from "./production-cutover-control-plane.mjs";
import { assertStageBBrokerConfigurationBindings, assertStageBBrokerConfigurationIdentity, assertStageBBrokerRuntimeBindings, assertStageBBrokerTaskDefinitionMap, canonicalJson, canonicalStageBBrokerApprovalExpected, hasCompleteStageBTaskMaps, STAGE_B } from "./production-green-stage-b-contract.mjs";
import { assertStageBTfvarsBinding, deriveContractDigests } from "./generate-production-green-stage-b-tfvars.mjs";
import { assertStageBDeploymentEvidenceFreshness } from "./stage-b-evidence-freshness.mjs";
import { readStageBPrivateFileBytes } from "./stage-b-artifact-contract.mjs";
import { renderStageBTaskDefinition, stageBTemplateHashes } from "./production-green-stage-b-task-definitions.mjs";
import { authenticateReleasePreflightCheckerTrustEvidence } from "./production-release-preflight-checker-attestation.mjs";
import { assertEcsTaskDefinitionReadback, canonicalizeEcsTaskDefinition } from "../../infra/aws/terraform/lambda/production-rls-approval-broker/ecs-task-definition-readback.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const SHA = /^[a-f0-9]{40}$/;
const RELEASE = /^arn:aws:sts::368992683803:assumed-role\/mscqr-production-release-deployer\/[A-Za-z0-9+=,.@_-]{2,64}$/;
const CHECKER = /^arn:aws:sts::368992683803:assumed-role\/mscqr-production-rls-independent-checker\/[A-Za-z0-9+=,.@_-]{2,64}$/;
const digest = (value) => crypto.createHash("sha256").update(value).digest("hex");
const exact = (left, right) => canonicalJson(left) === canonicalJson(right);
const parse = (value, label) => { try { return JSON.parse(value); } catch { throw new Error(`${label} is malformed.`); } };
const authenticatedEvidence = new WeakSet();

function assertBrokerCodeBinding({ configuration, broker, brokerPackageRawSha256 }) {
  if (!/^[a-f0-9]{64}$/.test(brokerPackageRawSha256 || "")) throw new Error("Canonical broker package raw SHA256 is malformed.");
  const codeSha256 = configuration?.CodeSha256;
  if (typeof codeSha256 !== "string" || !/^[A-Za-z0-9+/]{43}=$/.test(codeSha256)) throw new Error("Resolved broker Lambda CodeSha256 is malformed.");
  const codeBytes = Buffer.from(codeSha256, "base64");
  if (codeBytes.length !== 32 || codeBytes.toString("base64") !== codeSha256) throw new Error("Resolved broker Lambda CodeSha256 is not a canonical SHA256 encoding.");
  if (codeSha256 !== Buffer.from(brokerPackageRawSha256, "hex").toString("base64")
      || String(configuration.Version) !== broker.configurationVersion
      || ![STAGE_B.brokerFunctionArn, STAGE_B.brokerAliasArn, `${STAGE_B.brokerFunctionArn}:${broker.configurationVersion}`].includes(configuration.FunctionArn)) {
    throw new Error("Resolved broker Lambda code is not the reviewed package for the authenticated alias version.");
  }
  return codeSha256;
}

function authenticateBrokerTaskDefinitions({ taskDefinitionArns, liveTaskDefinitions, sourceSha, contracts, images }) {
  if (!liveTaskDefinitions || typeof liveTaskDefinitions !== "object" || Array.isArray(liveTaskDefinitions)) throw new Error("Exact live broker task-definition readbacks are required.");
  const bindings = { imageReleaseSha: sourceSha, sourceContractSha256: contracts.sourceContractSha256, migrationSetDigest: contracts.migrationSetDigest, packageChecksumSha256: contracts.packageChecksumSha256, receiptBucket: STAGE_B.receiptBucket, executorLogGroup: STAGE_B.executorLogGroupName, canaryLogGroup: STAGE_B.canaryLogGroupName, backendLogGroup: "/ecs/mscqr-production/rls-green-backend", workerLogGroup: "/ecs/mscqr-production/rls-green-worker" };
  const contentHashes = {};
  for (const [mode, taskDefinitionArn] of Object.entries(taskDefinitionArns)) {
    const kind = mode === "full-rls-application-canary" ? "canary" : "executor";
    const expected = renderStageBTaskDefinition(kind, { ...bindings, [`${kind}Image`]: kind === "canary" ? images.canaryImageDigest : images.executorImageDigest, ...(kind === "executor" ? { mode } : {}) });
    const readback = liveTaskDefinitions[mode]?.taskDefinition || liveTaskDefinitions[mode];
    assertEcsTaskDefinitionReadback({ definition: readback, taskDefinitionArn, expected, label: `Live broker task definition ${mode}` });
    contentHashes[mode] = digest(canonicalizeEcsTaskDefinition(readback));
  }
  return Object.freeze(contentHashes);
}

export const STAGE_B_APPROVAL_EVIDENCE_PRODUCER = "scripts/aws/collect-production-green-stage-b-approval-evidence.mjs";
export const STAGE_B_APPROVAL_EVIDENCE_SCHEMA_VERSION = 1;

export function collectProductionGreenStageBApprovalEvidence({ sourceSha, imageAuthorization, tfvarsPath, bindingReportPath, releasePreflightPath, releasePreflightAttestationPath, releasePreflightAttestationSignaturePath, releasePreflightTrustEvidence, checkerIdentity, live, now = new Date(), verifyImageEvidence, verifyReleasePreflightAttestationSignature, validateImageAuthorization = assertImageAuthorization, validateTfvarsBinding = assertStageBTfvarsBinding, deriveContracts = deriveContractDigests, readPreflight } = {}) {
  if (!SHA.test(sourceSha || "") || !CHECKER.test(checkerIdentity || "")) throw new Error("Approval evidence source or checker identity is invalid.");
  validateImageAuthorization(imageAuthorization, sourceSha, { now, verifyImageEvidence });
  const imageEvidenceSha256 = imageAuthorization.imageEvidenceSha256;
  const report = validateTfvarsBinding({ tfvarsPath, bindingReportPath, expectedToolingSha: sourceSha, expectedImageReleaseSha: imageAuthorization.imageReleaseSha, expectedImageEvidenceSha256: imageEvidenceSha256 });
  const reportBytes = readPreflight
    ? Buffer.from(`${JSON.stringify(readPreflight(releasePreflightPath))}\n`)
    : readStageBPrivateFileBytes({ filePath: releasePreflightPath, repositoryRoot: root, label: "Release-deployer preflight evidence" }).bytes;
  const preflight = readPreflight ? JSON.parse(reportBytes) : JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(reportBytes));
  const trust = releasePreflightTrustEvidence || (() => {
    if (!releasePreflightAttestationPath || !releasePreflightAttestationSignaturePath) throw new Error("Canonical release-preflight checker-trust attestation and signature are required.");
    const attestationBytes = readStageBPrivateFileBytes({ filePath: releasePreflightAttestationPath, repositoryRoot: root, label: "Release-preflight checker-trust attestation" }).bytes;
    const signatureBytes = readStageBPrivateFileBytes({ filePath: releasePreflightAttestationSignaturePath, repositoryRoot: root, label: "Release-preflight checker-trust attestation signature" }).bytes;
    return { reportBytes, attestation: JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(attestationBytes)), attestationBytes, signatureArtifact: JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(signatureBytes)), signatureBytes };
  })();
  if (!trust || !Buffer.isBuffer(trust.reportBytes) || canonicalJson(JSON.parse(trust.reportBytes)) !== canonicalJson(preflight)) throw new Error("Release-preflight checker-trust evidence is not bound to the exact consumed report bytes.");
  authenticateReleasePreflightCheckerTrustEvidence({
    report: preflight,
    reportBytes,
    attestation: trust.attestation,
    attestationBytes: trust.attestationBytes,
    signatureArtifact: trust.signatureArtifact,
    signatureBytes: trust.signatureBytes,
    sourceSha,
    administratorReportSha256: preflight.administratorReportSha256,
    expectedAttestationFileSha256: digest(trust.attestationBytes),
    expectedSignatureFileSha256: digest(trust.signatureBytes),
    now,
    verifySignature: verifyReleasePreflightAttestationSignature,
  });
  if (preflight?.status !== "ready-for-plan" || preflight?.sourceSha !== sourceSha || !RELEASE.test(preflight?.caller || "")
      || preflight.account !== STAGE_B.account || preflight.region !== STAGE_B.region
      || preflight.backendReady !== true || preflight.stateReady !== true || preflight.handoffReady !== true || preflight.tfvarsReady !== true
      || !Array.isArray(preflight.failed) || preflight.failed.length !== 0 || !Array.isArray(preflight.skipped) || preflight.skipped.length !== 0
      || !preflight.requiredReads || typeof preflight.requiredReads !== "object" || Object.values(preflight.requiredReads).some((status) => status !== "allowed")
      || !Number.isSafeInteger(preflight.total) || preflight.total <= 0 || preflight.allowed !== preflight.total
      || preflight.checkerTrust?.exact !== true || preflight.checkerTrust?.mfaRequired !== true
      || !/^[a-f0-9]{64}$/.test(preflight.administratorReportSha256 || "")
      || preflight.releaseReadFailures !== 0 || preflight.configurationFailures !== 0 || preflight.unmappedCalls !== 0
      || preflight.unclassifiedCapabilities !== 0 || preflight.identityBoundaryViolations !== 0
      || preflight.sourceLivePolicyMismatches !== 0 || preflight.administratorSimulationFailures !== 0) {
    throw new Error("Release-deployer preflight is not an authenticated ready-for-plan report.");
  }
  const tfvarsBytes = readPreflight ? null : readStageBPrivateFileBytes({ filePath: tfvarsPath, repositoryRoot: root, label: "Stage B tfvars" }).bytes;
  const bindingReportBytes = readPreflight ? null : readStageBPrivateFileBytes({ filePath: bindingReportPath, repositoryRoot: root, label: "Stage B tfvars binding report" }).bytes;
  const tfvarsSha256 = tfvarsBytes ? digest(tfvarsBytes) : preflight.tfvarsSha256;
  const bindingReportSha256 = bindingReportBytes ? digest(bindingReportBytes) : undefined;
  if (!/^[a-f0-9]{64}$/.test(tfvarsSha256 || "") || report.tfvarsSha256 !== tfvarsSha256 || preflight.tfvarsSha256 !== tfvarsSha256
      || preflight.bindingReportSha256 !== undefined && preflight.bindingReportSha256 !== bindingReportSha256) {
    throw new Error("Release-deployer preflight is not bound to the selected canonical tfvars and binding report.");
  }
  if (!live || typeof live !== "object") throw new Error("Live Stage B approval evidence reader is required.");
  const broker = assertStageBBrokerConfigurationIdentity({ configuration: live.configuration, alias: live.alias });
  const variables = live.configuration?.Environment?.Variables;
  const taskDefinitionArns = parse(variables?.BROKER_TASK_DEFINITIONS_JSON, "Live broker task-definition map");
  const approvalExpected = parse(variables?.BROKER_APPROVAL_EXPECTED_JSON, "Live broker approval bindings");
  const templateHashes = parse(variables?.BROKER_TASK_TEMPLATE_HASHES_JSON, "Live broker task-definition template hashes");
  const liveImages = parse(variables?.BROKER_IMAGES_JSON, "Live broker image bindings");
  const privateSubnetIds = parse(variables?.BROKER_PRIVATE_SUBNETS_JSON, "Live broker private subnets");
  assertStageBBrokerRuntimeBindings({ clusterArn: variables?.BROKER_CLUSTER_ARN, approvalSecretArn: variables?.BROKER_APPROVAL_SECRET_ARN, executorSecurityGroupId: variables?.BROKER_EXECUTOR_SECURITY_GROUP_ID, privateSubnetIds, replayTable: variables?.BROKER_REPLAY_TABLE, receiptBucket: variables?.BROKER_RECEIPT_BUCKET });
  if (!hasCompleteStageBTaskMaps(taskDefinitionArns, templateHashes)) throw new Error("Live broker task-definition map is incomplete.");
  assertStageBBrokerTaskDefinitionMap(taskDefinitionArns);
  const images = Object.fromEntries(imageAuthorization.images.map(({ service, digest: value }) => [service, value]));
  const reportImages = { backend: report.images.backend.digest, worker: report.images.worker.digest, "rls-executor": report.images.executor.digest, "rls-canary": report.images.canary.digest };
  if (!exact(images, reportImages)) throw new Error("Signed image authorization does not match the canonical Stage B tfvars bindings.");
  const contracts = deriveContracts();
  const expectedApproval = canonicalStageBBrokerApprovalExpected({ releaseSha: sourceSha, ...contracts });
  const expectedImages = { backendImageDigest: report.images.backend.imageReference, workerImageDigest: report.images.worker.imageReference, executorImageDigest: report.images.executor.imageReference, canaryImageDigest: report.images.canary.imageReference };
  assertStageBBrokerConfigurationBindings({ approvalExpected, images: liveImages, templateHashes });
  if (!exact(approvalExpected, expectedApproval)
      || !exact(liveImages, expectedImages) || !exact(templateHashes, stageBTemplateHashes())) throw new Error("Live broker bindings are stale or do not match the authenticated Stage B authorities.");
  const brokerCodeSha256 = assertBrokerCodeBinding({ configuration: live.configuration, broker, brokerPackageRawSha256: report.brokerPackageRawSha256 });
  const taskDefinitionContentSha256 = authenticateBrokerTaskDefinitions({ taskDefinitionArns, liveTaskDefinitions: live.taskDefinitions, sourceSha, contracts, images: { executorImageDigest: report.images.executor.imageReference, canaryImageDigest: report.images.canary.imageReference } });
  const observedAt = now.toISOString();
  assertStageBDeploymentEvidenceFreshness(observedAt, { now, evidenceType: "Stage B approval live observation" });
  const evidence = Object.freeze({
    schemaVersion: STAGE_B_APPROVAL_EVIDENCE_SCHEMA_VERSION,
    producer: STAGE_B_APPROVAL_EVIDENCE_PRODUCER,
    observedAt,
    sourceCurrent: true,
    runtimeBindingsCurrent: true,
    releaseSha: sourceSha,
    backendImageDigest: `${STAGE_B.account}.dkr.ecr.${STAGE_B.region}.amazonaws.com/mscqr-backend@${images.backend}`,
    workerImageDigest: `${STAGE_B.account}.dkr.ecr.${STAGE_B.region}.amazonaws.com/mscqr-worker@${images.worker}`,
    executorImageDigest: `${STAGE_B.account}.dkr.ecr.${STAGE_B.region}.amazonaws.com/mscqr-backend@${images["rls-executor"]}`,
    canaryImageDigest: `${STAGE_B.account}.dkr.ecr.${STAGE_B.region}.amazonaws.com/mscqr-backend@${images["rls-canary"]}`,
    sourceContractSha256: contracts.sourceContractSha256,
    migrationSetDigest: contracts.migrationSetDigest,
    packageChecksumSha256: contracts.packageChecksumSha256,
    taskDefinitionArns: Object.freeze({ ...taskDefinitionArns }),
    taskDefinitionContentSha256,
    brokerVersion: broker.configurationVersion,
    brokerPackageRawSha256: report.brokerPackageRawSha256,
    brokerCodeSha256,
    checkerIdentity,
    deployerIdentity: preflight.caller,
    imageAuthorizationSha256: imageAuthorization.authorizationSha256,
    tfvarsBindingSha256: bindingReportBytes ? digest(bindingReportBytes) : digest(canonicalJson(report)),
    runtimeBindingSha256: digest(canonicalJson({ broker, brokerCodeSha256, taskDefinitionArns, taskDefinitionContentSha256, templateHashes, approvalExpected, images: liveImages })),
  });
  authenticatedEvidence.add(evidence);
  return Object.freeze({ evidence, evidenceSha256: digest(canonicalJson(evidence)) });
}

export const isAuthenticatedProductionGreenStageBApprovalEvidence = (value) => authenticatedEvidence.has(value);
