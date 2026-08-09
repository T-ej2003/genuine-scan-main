import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { canonicalJson, STAGE_B } from "./production-green-stage-b-contract.mjs";
import { assertStageBBrokerFunctionUpdate } from "./stage-b-deployment-contract.mjs";
import { assertStageBPrivateFile, assertStageBArtifactPath, ensureStageBPrivateDirectory, writeStageBPrivateFilesAtomic } from "./stage-b-artifact-contract.mjs";
import { assertStageBDeploymentEvidenceFreshness } from "./stage-b-evidence-freshness.mjs";

export const STAGE_B_PARTIAL_APPLY_RECOVERY_SCHEMA_VERSION = 1;
export const STAGE_B_PARTIAL_APPLY_RECOVERY_EVIDENCE_KIND = "STAGE_B_PARTIAL_APPLY_RECOVERY_ATTESTATION";
export const STAGE_B_PARTIAL_APPLY_RECOVERY_BINDING_DOMAIN = "MSCQR_STAGE_B_PARTIAL_APPLY_RECOVERY_V1";
export const STAGE_B_PARTIAL_APPLY_RECOVERY_SIGNATURE_SCHEMA_VERSION = 3;
export const STAGE_B_PARTIAL_APPLY_RECOVERY_REFRESH_STATUS = "REVIEWED_PARTIAL_APPLY_RESIDUE";
export const STAGE_B_PARTIAL_APPLY_RECOVERY_ADDRESS = "aws_lambda_alias.reviewed";
export const STAGE_B_PARTIAL_APPLY_RECOVERY_CALLER = "arn:aws:iam::368992683803:root";
export const STAGE_B_PARTIAL_APPLY_RECOVERY_KEY_ARN = STAGE_B.approvalKmsKeyArn;
export const STAGE_B_PARTIAL_APPLY_RECOVERY_ALGORITHM = "RSASSA_PSS_SHA_256";

const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const canonicalBytes = (value) => Buffer.from(canonicalJson(value));
const fileBytes = (filePath, label) => { assertStageBPrivateFile({ filePath, repositoryRoot: path.resolve(process.cwd()), label }); return fs.readFileSync(filePath); };
const exact = (a, b) => canonicalJson(a) === canonicalJson(b);
const requiredSha = (value, label) => { if (!/^[a-f0-9]{64}$/.test(value || "")) throw new Error(`${label} must be a SHA256.`); return value; };
const requiredVersion = (value, label) => { if (!/^[1-9][0-9]*$/.test(String(value || ""))) throw new Error(`${label} must be a positive version.`); return String(value); };

export function assertCanonicalTerraformSerialNumber(value, label = "Terraform serial") {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) throw new Error(`${label} must be a safe non-negative integer number.`);
  return value;
}

export function parseCanonicalTerraformSerialCliText(value, label = "Terraform serial") {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]*)$/.test(value)) throw new Error(`${label} must be a canonical decimal integer.`);
  return assertCanonicalTerraformSerialNumber(Number(value), label);
}

export function inventoryHistoricalInput({ name, filePath, trust, required = true } = {}) {
  if (!/^[A-Za-z][A-Za-z0-9]*$/.test(name || "")) throw new Error("Historical input name is malformed.");
  if (!["STRUCTURED_VERIFIED", "RAW_FORENSIC", "UNAVAILABLE"].includes(trust)) throw new Error(`Historical input ${name} trust classification is invalid.`);
  if (trust === "UNAVAILABLE") return { name, path: null, sha256: null, trustClassification: trust, required };
  if (!filePath) throw new Error(`Historical input ${name} path is required.`);
  const bytes = fileBytes(filePath, `Historical input ${name}`);
  return { name, path: path.resolve(filePath), sha256: sha256(bytes), trustClassification: trust, required };
}

function assertHistoricalEvidence(value) {
  if (!value || typeof value !== "object" || !Array.isArray(value.inputs)) throw new Error("Historical recovery evidence is malformed.");
  const names = new Set();
  for (const input of value.inputs) {
    if (!input || names.has(input.name) || !["STRUCTURED_VERIFIED", "RAW_FORENSIC", "UNAVAILABLE"].includes(input.trustClassification)) throw new Error("Historical recovery evidence contains a duplicate or invalid input.");
    names.add(input.name);
    if (input.trustClassification === "UNAVAILABLE") { if (input.sha256 !== null || input.path !== null) throw new Error(`Unavailable input ${input.name} must not contain evidence.`); }
    else requiredSha(input.sha256, `Historical input ${input.name}`);
  }
  for (const name of ["savedPlan", "planJson", "logicalPlan", "planApproved", "planBoundPermission", "applyStdout", "applyStderr"]) if (!names.has(name)) throw new Error(`Historical input ${name} is required.`);
  if (!/^[a-f0-9]{40}$/.test(value.protectedSourceSha || "")) throw new Error("Historical protected source SHA is malformed.");
  if (!/^[0-9a-f-]{36}$/i.test(value.terraformLineage || "")) throw new Error("Historical Terraform lineage is malformed.");
  assertCanonicalTerraformSerialNumber(value.preApplySerial, "Historical pre-apply serial");
  const mutation = value.failedMutation;
  if (mutation?.terraformAddress !== STAGE_B_PARTIAL_APPLY_RECOVERY_ADDRESS || mutation.awsService !== "lambda" || mutation.operation !== "UpdateAlias" || mutation.result !== "FAILED" || mutation.failureClass !== "AUTHORIZATION" || mutation.awsErrorClass !== "AccessDeniedException" || !/^[1-9][0-9]*$/.test(String(mutation.attemptedTargetVersion || ""))) throw new Error("Historical failed UpdateAlias evidence is missing or unsupported.");
  return value;
}

function assertCurrentEvidence(value) {
  if (!value || typeof value !== "object") throw new Error("Current recovery evidence is malformed.");
  for (const [name, pattern] of [["protectedSourceSha", /^[a-f0-9]{40}$/], ["terraformLineage", /^[0-9a-f-]{36}$/i], ["refreshReportSha256", /^[a-f0-9]{64}$/]]) if (!pattern.test(String(value[name] || ""))) throw new Error(`Current ${name} is malformed.`);
  assertCanonicalTerraformSerialNumber(value.terraformSerial, "Current Terraform serial");
  if (value.terraformAddress !== STAGE_B_PARTIAL_APPLY_RECOVERY_ADDRESS || value.resourceMode !== "managed" || value.resourceModule !== null || value.resourceType !== "aws_lambda_alias" || value.resourceName !== "reviewed") throw new Error("Current recovery resource identity is not the exact root-managed alias.");
  if (value.functionName !== "mscqr-production-rls-approval-broker" || value.aliasName !== "reviewed") throw new Error("Current recovery Lambda identity is invalid.");
  for (const name of ["stateVersion", "configuredDesiredVersion", "liveVersion"]) requiredVersion(value[name], `Current ${name}`);
  if (value.stateVersion !== value.configuredDesiredVersion || value.liveVersion === value.configuredDesiredVersion) throw new Error("Current recovery versions do not describe the expected residue.");
  if (!exact(value.changedAttributes, ["function_version"]) || value.routingConfigurationChanged !== false || value.descriptionChanged !== false || value.functionIdentityChanged !== false || value.aliasIdentityChanged !== false || value.additionalManagedResourceDrift !== false) throw new Error("Current recovery delta is not an exact alias function-version change.");
  return value;
}

export function createRecoveryAttestation({ generatedAt = new Date().toISOString(), producerCallerArn, historicalObservedEvidence, currentObservedEvidence, reviewedRecoveryAssertion } = {}) {
  if (producerCallerArn !== STAGE_B_PARTIAL_APPLY_RECOVERY_CALLER) throw new Error("Recovery attestation requires the exact administrator caller.");
  const current = assertCurrentEvidence(currentObservedEvidence); const historical = assertHistoricalEvidence(historicalObservedEvidence);
  if (!reviewedRecoveryAssertion || reviewedRecoveryAssertion.historicalFailedTarget !== current.configuredDesiredVersion || historical.failedMutation.attemptedTargetVersion !== current.configuredDesiredVersion || reviewedRecoveryAssertion.stateTarget !== current.configuredDesiredVersion || reviewedRecoveryAssertion.liveTarget === current.configuredDesiredVersion || reviewedRecoveryAssertion.onlyFunctionVersionChanged !== true || reviewedRecoveryAssertion.noAdditionalManagedDrift !== true || reviewedRecoveryAssertion.authorizesPlan !== false || reviewedRecoveryAssertion.authorizesApply !== false || reviewedRecoveryAssertion.failureClass !== "AUTHORIZATION" || reviewedRecoveryAssertion.operation !== "lambda:UpdateAlias") throw new Error("Recovery review assertion is incomplete or authorizes an unsafe operation.");
  return { schemaVersion: STAGE_B_PARTIAL_APPLY_RECOVERY_SCHEMA_VERSION, evidenceKind: STAGE_B_PARTIAL_APPLY_RECOVERY_EVIDENCE_KIND, generatedAt, producerCallerArn, historicalObservedEvidence: historical, currentObservedEvidence: current, reviewedRecoveryAssertion };
}

export function recoveryBinding({ report, canonicalPayloadSha256, reportFileSha256, keyArn = STAGE_B_PARTIAL_APPLY_RECOVERY_KEY_ARN, signingAlgorithm = STAGE_B_PARTIAL_APPLY_RECOVERY_ALGORITHM } = {}) {
  return { domain: STAGE_B_PARTIAL_APPLY_RECOVERY_BINDING_DOMAIN, schemaVersion: 1, evidenceKind: report?.evidenceKind, canonicalPayloadSha256, reportFileSha256, protectedSourceSha: report?.currentObservedEvidence?.protectedSourceSha, terraformLineage: report?.currentObservedEvidence?.terraformLineage, terraformSerial: report?.currentObservedEvidence?.terraformSerial, refreshReportSha256: report?.currentObservedEvidence?.refreshReportSha256, resourceIdentity: report?.currentObservedEvidence?.terraformAddress, historicalEvidenceSha256: sha256(canonicalBytes(report?.historicalObservedEvidence)), keyArn, signingAlgorithm };
}

export function assertRecoveryAttestation(report, { expected = {}, now = new Date() } = {}) {
  if (report?.schemaVersion !== STAGE_B_PARTIAL_APPLY_RECOVERY_SCHEMA_VERSION || report.evidenceKind !== STAGE_B_PARTIAL_APPLY_RECOVERY_EVIDENCE_KIND || report.producerCallerArn !== STAGE_B_PARTIAL_APPLY_RECOVERY_CALLER) throw new Error("Recovery attestation identity/schema is invalid.");
  assertStageBDeploymentEvidenceFreshness(report.generatedAt, { now, evidenceType: "Recovery attestation" });
  const current = assertCurrentEvidence(report.currentObservedEvidence); assertHistoricalEvidence(report.historicalObservedEvidence);
  const expectedSerial = expected.terraformSerial === undefined ? undefined : assertCanonicalTerraformSerialNumber(expected.terraformSerial, "Expected Terraform serial");
  for (const [field, value] of Object.entries(expected)) if (value !== undefined && current[field] !== (field === "terraformSerial" ? expectedSerial : value)) throw new Error(`Recovery attestation ${field} binding mismatch.`);
  return current;
}

export function signRecoveryAttestation(report, { now = new Date().toISOString(), sign } = {}) {
  assertRecoveryAttestation(report, { now });
  const reportBytes = Buffer.from(`${JSON.stringify(report, null, 2)}\n`); const canonicalPayloadSha256 = sha256(canonicalBytes(report)); const reportFileSha256 = sha256(reportBytes);
  const binding = recoveryBinding({ report, canonicalPayloadSha256, reportFileSha256 }); const signedBindingSha256 = sha256(canonicalBytes(binding));
  const signatureBase64 = String(sign({ digest: Buffer.from(signedBindingSha256, "hex"), binding }) || ""); if (!/^[A-Za-z0-9+/]+={0,2}$/.test(signatureBase64)) throw new Error("Recovery signature is malformed.");
  return { schemaVersion: STAGE_B_PARTIAL_APPLY_RECOVERY_SIGNATURE_SCHEMA_VERSION, hashDomain: "signedBindingSha256", bindingDomain: STAGE_B_PARTIAL_APPLY_RECOVERY_BINDING_DOMAIN, evidenceKind: report.evidenceKind, keyArn: STAGE_B_PARTIAL_APPLY_RECOVERY_KEY_ARN, signingAlgorithm: STAGE_B_PARTIAL_APPLY_RECOVERY_ALGORITHM, canonicalPayloadSha256, reportFileSha256, signedBindingSha256, signatureBase64, signedAt: now };
}

export function verifyRecoveryAttestation({ report, signature, reportBytes = Buffer.from(`${JSON.stringify(report, null, 2)}\n`), signatureBytes = Buffer.from(`${JSON.stringify(signature, null, 2)}\n`), expected = {}, verify, now = new Date() } = {}) {
  assertRecoveryAttestation(report, { expected, now });
  if (!Buffer.isBuffer(reportBytes) || reportBytes.toString() !== `${JSON.stringify(report, null, 2)}\n`) throw new Error("Recovery report bytes are not the signed canonical report.");
  if (!Buffer.isBuffer(signatureBytes) || signatureBytes.toString() !== `${JSON.stringify(signature, null, 2)}\n`) throw new Error("Recovery signature bytes are not self-consistent.");
  if (signature?.schemaVersion !== 3 || signature.hashDomain !== "signedBindingSha256" || signature.bindingDomain !== STAGE_B_PARTIAL_APPLY_RECOVERY_BINDING_DOMAIN || signature.keyArn !== STAGE_B_PARTIAL_APPLY_RECOVERY_KEY_ARN || signature.signingAlgorithm !== STAGE_B_PARTIAL_APPLY_RECOVERY_ALGORITHM) throw new Error("Recovery signature schema is invalid.");
  const canonicalPayloadSha256 = sha256(canonicalBytes(report)); const reportFileSha256 = sha256(reportBytes); const signatureFileSha256 = sha256(signatureBytes); const binding = recoveryBinding({ report, canonicalPayloadSha256, reportFileSha256 }); const signedBindingSha256 = sha256(canonicalBytes(binding));
  if (signature.canonicalPayloadSha256 !== canonicalPayloadSha256 || signature.reportFileSha256 !== reportFileSha256 || signature.signedBindingSha256 !== signedBindingSha256) throw new Error("Recovery signature hash domain mismatch.");
  assertStageBDeploymentEvidenceFreshness(signature.signedAt, { now, evidenceType: "Recovery signature" });
  if (typeof verify !== "function" || verify({ digest: Buffer.from(signedBindingSha256, "hex"), signature: Buffer.from(signature.signatureBase64, "base64"), binding }) !== true) throw new Error("Recovery KMS signature verification failed.");
  return { canonicalPayloadSha256, reportFileSha256, signatureFileSha256, signedBindingSha256 };
}

export function classifyRecoveryResidue({ refreshReport, refreshReportSha256, attestation, attestationSignature, attestationBytes, attestationSignatureBytes, expected, verify, now = new Date() } = {}) {
  if (refreshReport?.status !== "RESOURCE_DRIFT" || refreshReportSha256 !== attestation?.currentObservedEvidence?.refreshReportSha256) throw new Error("Recovery classification requires the immutable matching RESOURCE_DRIFT report.");
  verifyRecoveryAttestation({ report: attestation, signature: attestationSignature, reportBytes: attestationBytes, signatureBytes: attestationSignatureBytes, expected, verify, now });
  const current = assertCurrentEvidence(attestation.currentObservedEvidence);
  if (!Array.isArray(refreshReport.resourceChanges?.changes) || refreshReport.resourceChanges.nonNoOp !== 1 || refreshReport.resourceChanges.changes.length !== 1) throw new Error("Recovery classification requires exactly one refresh resource change.");
  const change = refreshReport.resourceChanges.changes[0]; if (change.address !== current.terraformAddress || change.type !== current.resourceType || !exact(change.actions, ["update"])) throw new Error("Recovery refresh resource change is not the attested root-managed alias update.");
  return { schemaVersion: 1, status: STAGE_B_PARTIAL_APPLY_RECOVERY_REFRESH_STATUS, deployablePlan: false, refreshReportSha256, recoveryAttestationSha256: sha256(attestationBytes), state: { lineage: current.terraformLineage, serial: current.terraformSerial }, sourceSha: current.protectedSourceSha, resource: { address: current.terraformAddress, functionVersion: { live: current.liveVersion, desired: current.configuredDesiredVersion } } };
}

export function assertRecoveryClassification(classification, { refreshReportSha256, recoveryAttestationSha256, expectedSourceSha, expectedLineage, expectedSerial } = {}) {
  const expected = assertCanonicalTerraformSerialNumber(expectedSerial, "Expected Terraform serial");
  if (!classification || classification.schemaVersion !== 1 || classification.status !== STAGE_B_PARTIAL_APPLY_RECOVERY_REFRESH_STATUS || classification.deployablePlan !== false || Object.hasOwn(classification, "attestationVerified") || !/^[a-f0-9]{40}$/.test(classification.sourceSha || "") || !/^[a-f0-9]{64}$/.test(classification.refreshReportSha256 || "") || !/^[a-f0-9]{64}$/.test(classification.recoveryAttestationSha256 || "") || classification.refreshReportSha256 !== refreshReportSha256 || classification.recoveryAttestationSha256 !== recoveryAttestationSha256 || classification.sourceSha !== expectedSourceSha || classification.resource?.address !== STAGE_B_PARTIAL_APPLY_RECOVERY_ADDRESS || classification.state?.lineage !== expectedLineage || classification.state?.serial !== expected) throw new Error("Stage B recovery classification binding is invalid.");
  return true;
}

export function verifyStageBRecoverySignatureWithKms({ digest, signature } = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-stage-b-recovery-verify-"));
  try {
    const digestPath = path.join(directory, "digest"); const signaturePath = path.join(directory, "signature");
    fs.writeFileSync(digestPath, digest, { mode: 0o600, flag: "wx" }); fs.writeFileSync(signaturePath, signature, { mode: 0o600, flag: "wx" });
    const result = JSON.parse(execFileSync("aws", ["kms", "verify", "--key-id", STAGE_B_PARTIAL_APPLY_RECOVERY_KEY_ARN, "--message", `fileb://${digestPath}`, "--message-type", "DIGEST", "--signature", `fileb://${signaturePath}`, "--signing-algorithm", STAGE_B_PARTIAL_APPLY_RECOVERY_ALGORITHM, "--output", "json"], { encoding: "utf8" }));
    return result.SignatureValid === true;
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
}

export function assertVerifiedStageBRecovery({ refreshReport, refreshReportBytes, refreshReportSha256, classification, classificationBytes, classificationSha256, attestation, attestationBytes, attestationSha256, signature, signatureBytes, signatureSha256, expectedSourceSha, expectedLineage, expectedSerial, now = new Date(), verifySignature = verifyStageBRecoverySignatureWithKms } = {}) {
  const canonicalExpectedSerial = assertCanonicalTerraformSerialNumber(expectedSerial, "Expected Terraform serial");
  for (const [label, bytes, expectedSha] of [["refresh report", refreshReportBytes, refreshReportSha256], ["recovery classification", classificationBytes, classificationSha256], ["recovery attestation", attestationBytes, attestationSha256], ["recovery signature", signatureBytes, signatureSha256]]) {
    if (!Buffer.isBuffer(bytes) || sha256(bytes) !== expectedSha) throw new Error(`Stage B ${label} bytes do not match their approved SHA256.`);
  }
  const parsedRefresh = JSON.parse(refreshReportBytes); const parsedClassification = JSON.parse(classificationBytes); const parsedAttestation = JSON.parse(attestationBytes); const parsedSignature = JSON.parse(signatureBytes);
  if (!exact(parsedRefresh, refreshReport) || !exact(parsedClassification, classification) || !exact(parsedAttestation, attestation) || !exact(parsedSignature, signature)) throw new Error("Stage B recovery inputs are not byte-bound to their parsed values.");
  if (refreshReportSha256 !== parsedClassification.refreshReportSha256 || attestationSha256 !== parsedClassification.recoveryAttestationSha256) throw new Error("Stage B recovery classification is bound to different recovery bytes.");
  const verified = verifyRecoveryAttestation({ report: parsedAttestation, signature: parsedSignature, reportBytes: attestationBytes, signatureBytes, expected: { protectedSourceSha: expectedSourceSha, terraformLineage: expectedLineage, terraformSerial: canonicalExpectedSerial, refreshReportSha256 }, verify: verifySignature, now });
  const derived = classifyRecoveryResidue({ refreshReport: parsedRefresh, refreshReportSha256, attestation: parsedAttestation, attestationSignature: parsedSignature, attestationBytes, attestationSignatureBytes: signatureBytes, expected: { protectedSourceSha: expectedSourceSha, terraformLineage: expectedLineage, terraformSerial: canonicalExpectedSerial, refreshReportSha256 }, verify: verifySignature, now });
  assertRecoveryClassification(parsedClassification, { refreshReportSha256, recoveryAttestationSha256: attestationSha256, expectedSourceSha, expectedLineage, expectedSerial: canonicalExpectedSerial });
  if (!exact(parsedClassification, derived)) throw new Error("Stage B recovery classification is not the verified derivation of the signed attestation.");
  return { refreshReport: parsedRefresh, classification: parsedClassification, attestation: parsedAttestation, signature: parsedSignature, attestationSha256, signatureSha256, classificationSha256, refreshReportSha256, ...verified, derivedClassification: derived };
}

function assertAliasUnknownShape(change, computed) {
  const unknown = change.change?.after_unknown;
  if (unknown === undefined) {
    if (computed) throw new Error("Recovery plan computed alias target is missing after_unknown.function_version.");
    return;
  }
  if (!unknown || typeof unknown !== "object" || Array.isArray(unknown)) throw new Error("Recovery plan alias unknown-value metadata is malformed.");
  for (const [field, value] of Object.entries(unknown)) {
    if (field === "function_version" && value === true) continue;
    if (field === "routing_config" && exact(value, [])) continue;
    throw new Error(`Recovery plan alias contains an unreviewed unknown field: ${field}.`);
  }
  if (computed && unknown.function_version !== true) throw new Error("Recovery plan computed alias target is not explicitly unknown.");
  if (!computed && unknown.function_version === true) throw new Error("Recovery plan alias target is both concrete and unknown.");
}

function assertConcreteRecoveryBrokerVersion(plan, current) {
  const brokers = (plan.resource_changes || []).filter((change) => change?.address === "aws_lambda_function.broker");
  if (brokers.length > 1) throw new Error("Recovery plan contains duplicate broker function updates.");
  if (brokers.length === 0 || exact(brokers[0].change?.actions, ["no-op"])) return;
  const broker = brokers[0];
  if (broker.mode !== "managed" || broker.module || broker.type !== "aws_lambda_function" || !exact(broker.change?.actions, ["update"])) {
    throw new Error("Recovery plan broker publication is not the exact root-managed update.");
  }
  assertStageBBrokerFunctionUpdate(broker);
  if (broker.change?.after?.version !== current.configuredDesiredVersion || broker.change?.after_unknown?.version === true) {
    throw new Error("Recovery plan broker publication does not prove the exact attested desired version.");
  }
}

export function assertRecoveryPlanDelta(plan, attestation) {
  const current = assertCurrentEvidence(attestation?.currentObservedEvidence);
  const changes = Array.isArray(plan?.resource_changes) ? plan.resource_changes : [];
  const aliases = changes.filter((change) => change?.address === current.terraformAddress);
  const alias = aliases[0];
  if (aliases.length !== 1 || !alias || !exact(alias.change?.actions, ["update"]) || alias.mode !== "managed" || alias.module || alias.type !== current.resourceType || alias.change?.before?.function_version !== current.liveVersion) throw new Error("Recovery plan must contain the exact attested alias live-to-configured update.");
  const afterVersion = alias.change?.after?.function_version;
  const hasConcreteTarget = afterVersion !== undefined && afterVersion !== null;
  if (hasConcreteTarget) {
    assertAliasUnknownShape(alias, false);
    if (afterVersion !== current.configuredDesiredVersion) throw new Error("Recovery plan must contain the exact attested alias live-to-configured update.");
    assertConcreteRecoveryBrokerVersion(plan, current);
  } else {
    throw new Error("Recovery plan computed alias target cannot prove the exact attested desired version.");
  }
  return { address: alias.address, action: "update", beforeVersion: current.liveVersion, afterVersion: current.configuredDesiredVersion };
}

export function publishRecoveryAttestation({ reportPath, signaturePath, report, signature, repositoryRoot = path.resolve(process.cwd()) } = {}) {
  assertStageBArtifactPath({ artifactPath: reportPath, repositoryRoot, label: "Recovery attestation", allowExisting: false }); assertStageBArtifactPath({ artifactPath: signaturePath, repositoryRoot, label: "Recovery attestation signature", allowExisting: false });
  if (path.dirname(reportPath) !== path.dirname(signaturePath) || path.resolve(reportPath) === path.resolve(signaturePath)) throw new Error("Recovery outputs must be distinct files in one directory.");
  ensureStageBPrivateDirectory({ directory: path.dirname(reportPath), repositoryRoot, create: true });
  const reportBytes = Buffer.from(`${JSON.stringify(report, null, 2)}\n`); const signatureBytes = Buffer.from(`${JSON.stringify(signature, null, 2)}\n`);
  writeStageBPrivateFilesAtomic({ repositoryRoot, files: [{ filePath: reportPath, bytes: reportBytes, label: "Recovery attestation" }, { filePath: signaturePath, bytes: signatureBytes, label: "Recovery attestation signature" }] });
  return { reportSha256: sha256(reportBytes), signatureSha256: sha256(signatureBytes) };
}
