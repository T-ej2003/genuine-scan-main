import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { assertImageAuthorization } from "./production-cutover-control-plane.mjs";
import { assertStageBBrokerConfigurationBindings, assertStageBBrokerConfigurationIdentity, canonicalJson, canonicalStageBBrokerApprovalExpected, hasCompleteStageBTaskMaps, STAGE_B, STAGE_B_MODES } from "./production-green-stage-b-contract.mjs";
import { assertStageBTfvarsBinding, deriveContractDigests } from "./generate-production-green-stage-b-tfvars.mjs";
import { assertStageBDeploymentEvidenceFreshness } from "./stage-b-evidence-freshness.mjs";
import { readStageBPrivateFileBytes } from "./stage-b-artifact-contract.mjs";
import { stageBTemplateHashes } from "./production-green-stage-b-task-definitions.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const SHA = /^[a-f0-9]{40}$/;
const RELEASE = /^arn:aws:sts::368992683803:assumed-role\/mscqr-production-release-deployer\/[A-Za-z0-9+=,.@_-]{2,64}$/;
const CHECKER = /^arn:aws:sts::368992683803:assumed-role\/mscqr-production-rls-independent-checker\/[A-Za-z0-9+=,.@_-]{2,64}$/;
const digest = (value) => crypto.createHash("sha256").update(value).digest("hex");
const exact = (left, right) => canonicalJson(left) === canonicalJson(right);
const parse = (value, label) => { try { return JSON.parse(value); } catch { throw new Error(`${label} is malformed.`); } };
const authenticatedEvidence = new WeakSet();

export const STAGE_B_APPROVAL_EVIDENCE_PRODUCER = "scripts/aws/collect-production-green-stage-b-approval-evidence.mjs";
export const STAGE_B_APPROVAL_EVIDENCE_SCHEMA_VERSION = 1;

export function collectProductionGreenStageBApprovalEvidence({ sourceSha, imageAuthorization, tfvarsPath, bindingReportPath, releasePreflightPath, checkerIdentity, live, now = new Date(), verifyImageEvidence, validateImageAuthorization = assertImageAuthorization, validateTfvarsBinding = assertStageBTfvarsBinding, deriveContracts = deriveContractDigests, readPreflight } = {}) {
  if (!SHA.test(sourceSha || "") || !CHECKER.test(checkerIdentity || "")) throw new Error("Approval evidence source or checker identity is invalid.");
  validateImageAuthorization(imageAuthorization, sourceSha, { now, verifyImageEvidence });
  const imageEvidenceSha256 = imageAuthorization.imageEvidenceSha256;
  const report = validateTfvarsBinding({ tfvarsPath, bindingReportPath, expectedToolingSha: sourceSha, expectedImageReleaseSha: imageAuthorization.imageReleaseSha, expectedImageEvidenceSha256: imageEvidenceSha256 });
  const preflight = readPreflight ? readPreflight(releasePreflightPath) : JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(readStageBPrivateFileBytes({ filePath: releasePreflightPath, repositoryRoot: root, label: "Release-deployer preflight evidence" }).bytes));
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
  if (!hasCompleteStageBTaskMaps(taskDefinitionArns, templateHashes) || !exact(Object.keys(taskDefinitionArns || {}).sort(), [...STAGE_B_MODES].sort()) || Object.values(taskDefinitionArns).some((arn) => !/^arn:aws:ecs:eu-west-2:368992683803:task-definition\/[A-Za-z0-9_-]+:[1-9][0-9]*$/.test(arn || ""))) throw new Error("Live broker task-definition map is incomplete.");
  const images = Object.fromEntries(imageAuthorization.images.map(({ service, digest: value }) => [service, value]));
  const reportImages = { backend: report.images.backend.digest, worker: report.images.worker.digest, "rls-executor": report.images.executor.digest, "rls-canary": report.images.canary.digest };
  if (!exact(images, reportImages)) throw new Error("Signed image authorization does not match the canonical Stage B tfvars bindings.");
  const contracts = deriveContracts();
  const expectedApproval = canonicalStageBBrokerApprovalExpected({ releaseSha: sourceSha, ...contracts });
  const expectedImages = { backendImageDigest: report.images.backend.imageReference, workerImageDigest: report.images.worker.imageReference, executorImageDigest: report.images.executor.imageReference, canaryImageDigest: report.images.canary.imageReference };
  assertStageBBrokerConfigurationBindings({ approvalExpected, images: liveImages, templateHashes });
  if (!exact(approvalExpected, expectedApproval)
      || !exact(liveImages, expectedImages) || !exact(templateHashes, stageBTemplateHashes())) throw new Error("Live broker bindings are stale or do not match the authenticated Stage B authorities.");
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
    brokerVersion: broker.configurationVersion,
    checkerIdentity,
    deployerIdentity: preflight.caller,
    imageAuthorizationSha256: imageAuthorization.authorizationSha256,
    tfvarsBindingSha256: bindingReportBytes ? digest(bindingReportBytes) : digest(canonicalJson(report)),
    runtimeBindingSha256: digest(canonicalJson({ broker, taskDefinitionArns, templateHashes, approvalExpected, images: liveImages })),
  });
  authenticatedEvidence.add(evidence);
  return Object.freeze({ evidence, evidenceSha256: digest(canonicalJson(evidence)) });
}

export const isAuthenticatedProductionGreenStageBApprovalEvidence = (value) => authenticatedEvidence.has(value);
