import crypto from "node:crypto";
import fs from "node:fs";
import { canonicalJson } from "./production-green-stage-b-contract.mjs";
import { assertStageBPartialApplyRecoveryPlan, assertStageBFreshImagePartialApplyRecoveryPlan, classifyStageBPlan, STAGE_B_NORMAL_STATIC_RESOURCE_ADDRESSES } from "./stage-b-deployment-contract.mjs";
import { assertStageBReferenceAuditFreshness, STAGE_B_TASK_DEFINITION_FAMILIES, STAGE_B_TASK_DEFINITION_ROTATION_ACTIONS, STAGE_B_TASK_DEFINITION_ROTATION_REPLACE_PATHS } from "./stage-b-reference-audit-contract.mjs";
import { assertStageBPrivateFile, writeStageBPrivateFileAtomic } from "./stage-b-artifact-contract.mjs";
import { assertCanonicalTerraformSerialNumber } from "./stage-b-partial-apply-recovery-contract.mjs";

export const STAGE_B_PLAN_EVIDENCE_SCHEMA_VERSION = 1;
export const STAGE_B_PLAN_CAPTURED = "PLAN_CAPTURED";
export const STAGE_B_PLAN_APPROVED = "PLAN_APPROVED";

const sha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const STAGE_B_CAPTURE_BROKER_ADDRESSES = ["aws_iam_policy.broker", "aws_lambda_alias.reviewed", "aws_lambda_function.broker"];
export const STAGE_B_PLAN_PROFILES = Object.freeze(["BASELINE", "IMPORTED_BACKEND_METADATA_NORMALIZATION", "ECS_TASK_DEFINITION_ROTATION", "RECOVERY_ALIAS_ONLY", "PARTIAL_APPLY_RECOVERY", "FRESH_IMAGE_PARTIAL_APPLY_RECOVERY"]);

function assertPartialApplyRecoveryEvidence(report) {
  if (["PARTIAL_APPLY_RECOVERY", "FRESH_IMAGE_PARTIAL_APPLY_RECOVERY"].includes(report?.planProfile) && (report.recoveryAttestationSha256 !== undefined || report.recoveryPlan === true)) throw new Error(`${report.planProfile} cannot carry RECOVERY_ALIAS_ONLY attestation evidence.`);
}
export const STAGE_B_BROKER_OPERATIONS = Object.freeze(["none", "initial-create", "update", "recovery-alias-only", "partial-apply-recovery", "fresh-image-partial-apply-recovery"]);
export const STAGE_B_PLAN_PROFILE_CENSUS = Object.freeze({
  BASELINE: Object.freeze({ create: 12, replacement: 0, update: 3, destroy: 0, unclassified: 0 }),
  IMPORTED_BACKEND_METADATA_NORMALIZATION: Object.freeze({ create: 1, replacement: 11, update: 4, destroy: 0, unclassified: 0 }),
  PARTIAL_APPLY_RECOVERY: Object.freeze({ create: 0, replacement: 0, update: 2, destroy: 11, unclassified: 0 }),
  FRESH_IMAGE_PARTIAL_APPLY_RECOVERY: Object.freeze({ create: 0, replacement: 12, update: 3, destroy: 11, unclassified: 0 }),
});

function assertPlanProfile(profile, label = "Stage B plan evidence") {
  if (!STAGE_B_PLAN_PROFILES.includes(profile)) throw new Error(`${label} profile is unsupported: ${profile}`);
  return profile;
}

function expectedBrokerEvidence(operation) {
  if (operation === "none") return { updatePresent: false, actions: [], addresses: [], pending: false };
  if (operation === "initial-create") return { updatePresent: false, actions: ["create"], addresses: STAGE_B_CAPTURE_BROKER_ADDRESSES, pending: false };
  if (operation === "update") return { updatePresent: true, actions: ["update"], addresses: STAGE_B_CAPTURE_BROKER_ADDRESSES, pending: true };
  if (operation === "recovery-alias-only") return { updatePresent: false, actions: ["no-op"], addresses: ["aws_lambda_alias.reviewed"], pending: false };
  if (operation === "partial-apply-recovery") return { updatePresent: true, actions: ["update"], addresses: ["aws_lambda_alias.reviewed", "aws_lambda_function.broker"], pending: true };
  if (operation === "fresh-image-partial-apply-recovery") return { updatePresent: true, actions: ["update"], addresses: STAGE_B_CAPTURE_BROKER_ADDRESSES, pending: true };
  throw new Error(`Stage B broker operation is unsupported: ${operation}`);
}

function assertBrokerEvidence(report, { approved = false } = {}) {
  if (!STAGE_B_BROKER_OPERATIONS.includes(report?.brokerOperation)) throw new Error("Stage B broker operation is unsupported.");
  const expected = expectedBrokerEvidence(report.brokerOperation);
  if (report.brokerUpdatePresent !== expected.updatePresent || report.brokerReferenceValidationPending !== (approved ? false : expected.pending)
    || JSON.stringify(report.brokerActions) !== JSON.stringify(expected.actions)
    || JSON.stringify(report.brokerResourceAddresses) !== JSON.stringify(expected.addresses)) throw new Error("Stage B broker evidence is malformed.");
  return true;
}

function assertPlanProfileCensus(classification, profile, label) {
  const expected = STAGE_B_PLAN_PROFILE_CENSUS[profile];
  if (!expected || Object.entries(expected).some(([key, value]) => (classification?.[key] ?? 0) !== value)) {
    throw new Error(`${label} is not the exact ${profile} census.`);
  }
}

export function stageBPlanHashes({ savedPlanBytes, planJsonBytes, canonicalPlanJsonBytes }) {
  if (![savedPlanBytes, planJsonBytes, canonicalPlanJsonBytes].every(Buffer.isBuffer)) throw new Error("Stage B plan artifact bytes are required.");
  let plan;
  try { plan = JSON.parse(planJsonBytes); } catch { throw new Error("Stage B plan JSON is malformed."); }
  return {
    savedPlanSha256: sha256(savedPlanBytes),
    planJsonSha256: sha256(planJsonBytes),
    canonicalPlanFileSha256: sha256(canonicalPlanJsonBytes),
    logicalCanonicalPlanJsonSha256: sha256(Buffer.from(canonicalJson(plan))),
  };
}

function assertTaskDefinitionRotations(rotations) {
  const expectedAddresses = Object.keys(STAGE_B_TASK_DEFINITION_FAMILIES);
  if (!Array.isArray(rotations) || rotations.length !== expectedAddresses.length) throw new Error("Stage B task-definition rotation metadata must cover the exact twelve-address collection.");
  const seen = new Set();
  for (const rotation of rotations) {
    const expectedFamily = STAGE_B_TASK_DEFINITION_FAMILIES[rotation?.address];
    if (!expectedFamily || seen.has(rotation.address) || rotation.classification !== "rollover"
      || !STAGE_B_TASK_DEFINITION_ROTATION_ACTIONS.some((actions) => JSON.stringify(actions) === JSON.stringify(rotation.actions))
      || JSON.stringify(rotation.replacePaths) !== JSON.stringify(STAGE_B_TASK_DEFINITION_ROTATION_REPLACE_PATHS)
      || rotation.family !== expectedFamily || !new RegExp(`^arn:aws:ecs:eu-west-2:368992683803:task-definition/${expectedFamily.replace(/[.*+?^${}()|[\]\\]/g, "\\\\$&")}:\\d+$`).test(rotation.oldArn || "")) {
      throw new Error(`Stage B task-definition rotation metadata is malformed: ${rotation?.address || "<missing>"}`);
    }
    seen.add(rotation.address);
  }
  if (seen.size !== expectedAddresses.length || expectedAddresses.some((address) => !seen.has(address))) throw new Error("Stage B task-definition rotation metadata must cover the exact twelve-address collection.");
}

const retainedTaskDefinitionAddress = /^aws_ecs_task_definition\.(candidate|executor)_retained\["([a-f0-9]{7,40})-([^"]+)"\]$/;
const retainedTaskDefinitionDescriptorEntries = Object.entries(STAGE_B_TASK_DEFINITION_FAMILIES).map(([address, family]) => {
  const match = /^aws_ecs_task_definition\.(candidate|executor)\["([^"]+)"\]$/.exec(address);
  if (!match) throw new Error(`Stage B current task-definition address is malformed: ${address}`);
  return [match[2], Object.freeze({ kind: match[1], family })];
});
if (new Set(retainedTaskDefinitionDescriptorEntries.map(([key]) => key)).size !== retainedTaskDefinitionDescriptorEntries.length) throw new Error("Stage B retained task-definition keys are ambiguous across candidate and executor collections.");
export const STAGE_B_RETAINED_TASK_DEFINITION_DESCRIPTORS = Object.freeze(Object.fromEntries(retainedTaskDefinitionDescriptorEntries));
const currentTaskDefinitionAddresses = Object.freeze(Object.keys(STAGE_B_TASK_DEFINITION_FAMILIES));

function retainedEntryAddress(entry) {
  return entry?.terraformAddress || entry?.address;
}

function assertRetainedTaskDefinitionEntry(entry, { requireMetadata, seenFamilyRevisions } = {}) {
  const address = retainedEntryAddress(entry);
  const match = retainedTaskDefinitionAddress.exec(address || "");
  if (!match) throw new Error(`Stage B retained task-definition address is malformed: ${address || "<missing>"}`);
  const descriptor = STAGE_B_RETAINED_TASK_DEFINITION_DESCRIPTORS[match[3]];
  if (!descriptor || descriptor.kind !== match[1]) throw new Error(`Stage B retained task-definition collection kind is outside the exact contract: ${address}`);
  if (entry.family !== undefined && entry.family !== descriptor.family) throw new Error(`Stage B retained task-definition family is outside the exact contract: ${address}`);
  if (entry.classification !== undefined && entry.classification !== "retained-no-op") throw new Error(`Stage B retained task-definition classification is not retained-no-op: ${address}`);
  if (requireMetadata) {
    const arnMatch = /^arn:aws:ecs:eu-west-2:368992683803:task-definition\/([^:]+):([1-9][0-9]*)$/.exec(entry.oldTaskDefinitionArn || entry.oldArn || "");
    if (!arnMatch || arnMatch[1] !== descriptor.family) throw new Error(`Stage B retained task-definition ARN is invalid: ${address}`);
    const familyRevision = `${descriptor.family}:${arnMatch[2]}`;
    if (seenFamilyRevisions.has(familyRevision)) throw new Error(`Stage B retained task-definition family/revision is duplicated: ${familyRevision}`);
    seenFamilyRevisions.add(familyRevision);
  }
  return address;
}

export function assertStageBNormalPlanCompleteness(plan, { referenceAudit, expectedRetainedAddresses, strict = true, terraformConfiguration } = {}) {
  const changes = plan?.resource_changes;
  if (!Array.isArray(changes)) throw new Error("Stage B normal plan resource_changes are missing.");
  const addresses = changes.map((change) => change?.address);
  const seenAddresses = new Set();
  for (const address of addresses) {
    if (!address || seenAddresses.has(address)) throw new Error(`Stage B normal plan contains a duplicate or malformed address: ${address || "<missing>"}`);
    seenAddresses.add(address);
  }

  let retainedEntries;
  if (referenceAudit !== undefined) {
    if (!Array.isArray(referenceAudit?.retainedTaskDefinitions)) throw new Error("Stage B normal plan retained-history audit is missing.");
    const seenFamilyRevisions = new Set();
    retainedEntries = referenceAudit.retainedTaskDefinitions.map((entry) => {
      const address = assertRetainedTaskDefinitionEntry(entry, { requireMetadata: true, seenFamilyRevisions });
      if (entry.classification !== "retained-no-op") throw new Error(`Stage B retained-history audit entry is not a retained no-op: ${address}`);
      return address;
    });
  } else if (Array.isArray(expectedRetainedAddresses)) {
    retainedEntries = expectedRetainedAddresses.map((address) => assertRetainedTaskDefinitionEntry({ address }, { requireMetadata: false, seenFamilyRevisions: new Set() }));
  } else {
    throw new Error("Stage B normal plan requires an independently bound retained-history address set.");
  }
  const retainedAddresses = new Set(retainedEntries);
  if (retainedAddresses.size !== retainedEntries.length) throw new Error("Stage B retained-history address set contains duplicates.");

  const expectedAddresses = new Set([
    ...STAGE_B_NORMAL_STATIC_RESOURCE_ADDRESSES,
    ...currentTaskDefinitionAddresses,
    ...retainedAddresses,
  ]);
  if (expectedAddresses.size !== addresses.length) throw new Error(`Stage B normal plan resource universe size differs from the canonical address set: expected ${expectedAddresses.size}, got ${addresses.length}.`);
  for (const address of addresses) if (!expectedAddresses.has(address)) throw new Error(`Stage B normal plan contains an address outside the canonical resource universe: ${address}`);
  for (const address of expectedAddresses) if (!seenAddresses.has(address)) throw new Error(`Stage B normal plan omits a canonical managed resource: ${address}`);
  for (const change of changes.filter((item) => retainedAddresses.has(item?.address))) {
    if (JSON.stringify(change?.change?.actions) !== JSON.stringify(["no-op"])) throw new Error(`Stage B retained task-definition is not an exact no-op: ${change.address}`);
  }

  const classified = classifyStageBPlan(plan, { strict, terraformConfiguration });
  const noOp = classified.actionCounts["no-op"] || 0;
  const importedBackendNormalization = classified.classifiedResources.filter(({ classification }) => classification === "imported-backend-task-definition-metadata-normalization");
  const expectedProfile = importedBackendNormalization.length === 1 ? "IMPORTED_BACKEND_METADATA_NORMALIZATION" : "BASELINE";
  const expectedCensus = STAGE_B_PLAN_PROFILE_CENSUS[expectedProfile];
  const expectedChanged = expectedCensus.create + expectedCensus.replacement + expectedCensus.update + expectedCensus.destroy;
  if ((classified.planProfile !== expectedProfile && !(expectedProfile === "BASELINE" && classified.planProfile === "ECS_TASK_DEFINITION_ROTATION"))
    || classified.actionCounts.create !== expectedCensus.create || (classified.actionCounts.replacement || 0) !== expectedCensus.replacement
    || classified.actionCounts.update !== expectedCensus.update || (classified.actionCounts.destroy || 0) !== expectedCensus.destroy
    || noOp !== expectedAddresses.size - expectedChanged || classified.unclassifiedResources.length !== expectedCensus.unclassified) {
    throw new Error("Stage B normal plan mutation census is outside the exact structural contract.");
  }
  return { expectedAddresses: [...expectedAddresses].sort(), retainedAddresses: [...retainedAddresses].sort(), classification: classified };
}

function assertClassification(report) {
  const classification = report?.classification;
  const profileValue = report?.planProfile === undefined
    ? (report?.recoveryPlan === true || report?.recoveryAttestationSha256 ? undefined : "BASELINE")
    : report.planProfile;
  const profile = assertPlanProfile(profileValue);
  const validCounts = classification && ["noOp", "create", "update", "destroy", "replacement", "unclassified"].every((key) => Number.isSafeInteger(classification[key]) && classification[key] >= 0);
  if (!validCounts) throw new Error("Stage B plan evidence classification counters are malformed.");
  if (profile === "ECS_TASK_DEFINITION_ROTATION") {
    assertTaskDefinitionRotations(report.taskDefinitionRotations);
    if (classification.replacement !== report.taskDefinitionRotations.length || classification.destroy !== 0 || classification.unclassified !== 0) throw new Error("Stage B task-definition rotation classification is not exact and non-destructive.");
  } else if (profile === "RECOVERY_ALIAS_ONLY") {
    if (!/^[a-f0-9]{64}$/.test(report.recoveryAttestationSha256 || "") || report.recoveryPlan !== true
      || report.brokerOperation !== "recovery-alias-only" || classification.update !== 1
      || classification.destroy !== 0 || classification.replacement !== 0 || classification.unclassified !== 0) {
      throw new Error("Stage B recovery-alias-only classification is not exact and non-destructive.");
    }
    assertBrokerEvidence(report);
    return;
  }
  if (profile === "IMPORTED_BACKEND_METADATA_NORMALIZATION") {
    assertPlanProfileCensus(classification, profile, "Stage B imported-backend normalization classification");
    return;
  }
  if (profile === "PARTIAL_APPLY_RECOVERY" || profile === "FRESH_IMAGE_PARTIAL_APPLY_RECOVERY") {
    assertPlanProfileCensus(classification, profile, "Stage B partial-apply recovery classification");
    return;
  }
  if (report?.recoveryAttestationSha256 !== undefined) {
    if (!/^[a-f0-9]{64}$/.test(report.recoveryAttestationSha256) || report.recoveryPlan !== true || classification.destroy !== 0 || classification.unclassified !== 0) throw new Error("Stage B recovery plan evidence classification is not exact and non-destructive.");
    return;
  }
  if (profile === "ECS_TASK_DEFINITION_ROTATION") return;
  if (profile !== "BASELINE") throw new Error("Stage B plan evidence classification profile is unsupported.");
  assertPlanProfileCensus(classification, profile, "Stage B baseline plan evidence classification");
}

function assertPlanHashes(report, hashes) {
  for (const [name, value] of Object.entries(hashes)) {
    if (report?.[name] !== value) throw new Error(`Stage B plan evidence ${name} does not match the selected artifact.`);
  }
}

function assertBoundReferenceAudit(report, { referenceAudit, referenceAuditBytes, hashes, required }) {
  if (!referenceAudit && !referenceAuditBytes) {
    if (required) throw new Error("BASELINE plan approval requires the bound reference audit.");
    return false;
  }
  if (!referenceAudit || !Buffer.isBuffer(referenceAuditBytes)) throw new Error("Stage B reference audit object and bytes must be supplied together.");
  let parsedAudit;
  try { parsedAudit = JSON.parse(referenceAuditBytes); } catch { throw new Error("Stage B reference audit bytes are malformed."); }
  if (canonicalJson(parsedAudit) !== canonicalJson(referenceAudit)) throw new Error("Stage B reference audit object does not match its bound bytes.");
  if (sha256(referenceAuditBytes) !== report.referenceAuditSha256) throw new Error("Stage B plan approval report reference-audit SHA256 mismatch.");
  if (parsedAudit.planJsonSha256 !== hashes.planJsonSha256) throw new Error("Stage B reference audit is bound to a different plan JSON.");
  if (parsedAudit.recoveryAttestationSha256 !== report.recoveryAttestationSha256) throw new Error("Stage B reference audit recovery-attestation binding differs from the approval report.");
  return parsedAudit;
}

export function createStageBPlanCaptureReport({ toolingSha, toolingTreeSha256, refreshReportSha256, refreshBindingReportSha256, recoveryAttestationSha256, hashes, capturedAt, stageBLineage, stageBSerial, terraformVersion, terraformFormatVersion, planExitCode = 0, showExitCode = 0, classification, planProfile = "BASELINE", taskDefinitionRotations = [], brokerEvidence = {} }) {
  assertCanonicalTerraformSerialNumber(stageBSerial, "Stage B serial");
  const profile = assertPlanProfile(planProfile);
  assertPartialApplyRecoveryEvidence({ planProfile: profile, recoveryAttestationSha256, recoveryPlan: recoveryAttestationSha256 !== undefined });
  return {
    schemaVersion: STAGE_B_PLAN_EVIDENCE_SCHEMA_VERSION,
    state: STAGE_B_PLAN_CAPTURED,
    toolingSha,
    toolingTreeSha256,
    refreshReportSha256,
    ...(refreshBindingReportSha256 ? { refreshBindingReportSha256 } : {}),
    ...(recoveryAttestationSha256 ? { recoveryAttestationSha256, recoveryPlan: true } : {}),
    planProfile: profile,
    ...(planProfile === "ECS_TASK_DEFINITION_ROTATION" ? { taskDefinitionRotations } : {}),
    ...hashes,
    classification,
    terraformVersion,
    terraformFormatVersion,
    planExitCode,
    showExitCode,
    capturedAt,
    stageBLineage,
    stageBSerial,
    referenceAuditRequired: true,
    brokerOperation: brokerEvidence.brokerOperation || "none",
    brokerUpdatePresent: brokerEvidence.brokerUpdatePresent === true,
    brokerActions: Array.isArray(brokerEvidence.brokerActions) ? brokerEvidence.brokerActions : [],
    brokerResourceAddresses: Array.isArray(brokerEvidence.brokerResourceAddresses) ? brokerEvidence.brokerResourceAddresses : [],
    brokerReferenceValidationPending: brokerEvidence.brokerReferenceValidationPending === true,
    approvedForApply: false,
  };
}

export function assertStageBPlanCaptureReport(report, { captureReportBytes, hashes, toolingSha, toolingTreeSha256, refreshReportSha256, recoveryAttestationSha256, stageBLineage, stageBSerial } = {}) {
  assertCanonicalTerraformSerialNumber(report?.stageBSerial, "Stage B plan capture serial");
  if (report?.schemaVersion !== STAGE_B_PLAN_EVIDENCE_SCHEMA_VERSION || report.state !== STAGE_B_PLAN_CAPTURED || report.approvedForApply !== false || report.referenceAuditRequired !== true || typeof report.planProfile !== "string" || typeof report.brokerReferenceValidationPending !== "boolean" || typeof report.brokerUpdatePresent !== "boolean" || !Array.isArray(report.brokerActions) || !Array.isArray(report.brokerResourceAddresses)) {
    throw new Error("Stage B plan capture report is missing the PLAN_CAPTURED contract.");
  }
  assertPlanProfile(report.planProfile, "Stage B plan capture");
  assertPartialApplyRecoveryEvidence(report);
  if (["RECOVERY_ALIAS_ONLY", "PARTIAL_APPLY_RECOVERY", "FRESH_IMAGE_PARTIAL_APPLY_RECOVERY"].includes(report.planProfile) && !/^[a-f0-9]{64}$/.test(report.refreshBindingReportSha256 || "")) throw new Error("Stage B recovery plan capture observation-binding SHA256 is missing or malformed.");
  assertBrokerEvidence(report);
  if (!Buffer.isBuffer(captureReportBytes) || sha256(captureReportBytes) !== sha256(Buffer.from(JSON.stringify(report, null, 2) + "\n"))) throw new Error("Stage B plan capture report bytes are not self-consistent.");
  assertPlanHashes(report, hashes);
  if ((recoveryAttestationSha256 || report.recoveryAttestationSha256) && report.recoveryAttestationSha256 !== recoveryAttestationSha256) throw new Error("Stage B plan capture recovery-attestation binding differs from the selected recovery evidence.");
  for (const [name, value] of Object.entries({ toolingSha, toolingTreeSha256, refreshReportSha256, stageBLineage, stageBSerial })) {
    if (value !== undefined && report[name] !== value) throw new Error(`Stage B plan capture report ${name} does not match the selected release.`);
  }
  if (report.planExitCode !== 0 && report.planExitCode !== 2) throw new Error("Stage B plan capture Terraform exit code is unsupported.");
  if (report.showExitCode !== 0) throw new Error("Stage B plan capture Terraform show exit code is unsupported.");
  assertClassification(report);
  return true;
}

export function createStageBPlanApprovalReport({ captureReportSha256, referenceAuditPath, referenceAuditSha256, referenceAuditCallerArn, referenceAuditAt, toolingSha, toolingTreeSha256, refreshReportSha256, refreshBindingReportSha256, recoveryAttestationSha256, stageBLineage, stageBSerial, hashes, logicalCanonicalPlanJsonSha256, approvedAt, classification, planProfile = "BASELINE", taskDefinitionRotations = [], brokerOperation = "none", brokerUpdatePresent = false, brokerActions = [], brokerResourceAddresses = [] }) {
  assertCanonicalTerraformSerialNumber(stageBSerial, "Stage B serial");
  const profile = assertPlanProfile(planProfile);
  assertPartialApplyRecoveryEvidence({ planProfile: profile, recoveryAttestationSha256, recoveryPlan: recoveryAttestationSha256 !== undefined });
  return {
    schemaVersion: STAGE_B_PLAN_EVIDENCE_SCHEMA_VERSION,
    state: STAGE_B_PLAN_APPROVED,
    captureReportSha256,
    toolingSha,
    toolingTreeSha256,
    refreshReportSha256,
    ...(refreshBindingReportSha256 ? { refreshBindingReportSha256 } : {}),
    ...(recoveryAttestationSha256 ? { recoveryAttestationSha256, recoveryPlan: true } : {}),
    planProfile: profile,
    ...(planProfile === "ECS_TASK_DEFINITION_ROTATION" ? { taskDefinitionRotations } : {}),
    stageBLineage,
    stageBSerial,
    referenceAuditPath,
    referenceAuditSha256,
    referenceAuditCallerArn,
    referenceAuditAt,
    ...hashes,
    logicalCanonicalPlanJsonSha256,
    classification,
    brokerOperation,
    brokerUpdatePresent,
    brokerActions,
    brokerResourceAddresses,
    brokerReferenceValidationPending: false,
    brokerReferenceValidationPassed: true,
    approvedAt,
    approvedForApply: true,
  };
}

export function assertStageBPlanApprovalReport(report, { approvalReportBytes, captureReport, captureReportBytes, referenceAudit, referenceAuditBytes, plan, hashes, logicalCanonicalPlanJsonSha256, referenceAuditSha256, trustedCallerArn, stageBLineage, stageBSerial, terraformConfiguration } = {}) {
  assertCanonicalTerraformSerialNumber(report?.stageBSerial, "Stage B plan approval serial");
  if (report?.schemaVersion !== STAGE_B_PLAN_EVIDENCE_SCHEMA_VERSION || report.state !== STAGE_B_PLAN_APPROVED || report.approvedForApply !== true || report.brokerReferenceValidationPending !== false || report.brokerReferenceValidationPassed !== true) throw new Error("Stage B plan approval report is required; PLAN_CAPTURED is not deployable.");
  if (!Buffer.isBuffer(approvalReportBytes) || sha256(approvalReportBytes) !== sha256(Buffer.from(JSON.stringify(report, null, 2) + "\n"))) throw new Error("Stage B plan approval report bytes are not self-consistent.");
  if (!Buffer.isBuffer(captureReportBytes)) throw new Error("Stage B plan approval report capture binding is missing.");
  assertStageBPlanCaptureReport(captureReport, { captureReportBytes, hashes, stageBLineage, stageBSerial, recoveryAttestationSha256: report.recoveryAttestationSha256 });
  if (report.brokerOperation !== captureReport.brokerOperation || report.brokerUpdatePresent !== captureReport.brokerUpdatePresent || JSON.stringify(report.brokerActions) !== JSON.stringify(captureReport.brokerActions) || JSON.stringify(report.brokerResourceAddresses) !== JSON.stringify(captureReport.brokerResourceAddresses)) throw new Error("Stage B plan approval broker evidence is not bound to the captured plan.");
  assertBrokerEvidence(report, { approved: true });
  assertPlanProfile(report.planProfile, "Stage B plan approval");
  assertPartialApplyRecoveryEvidence(report);
  if (["RECOVERY_ALIAS_ONLY", "PARTIAL_APPLY_RECOVERY", "FRESH_IMAGE_PARTIAL_APPLY_RECOVERY"].includes(report.planProfile) && report.refreshBindingReportSha256 !== captureReport.refreshBindingReportSha256) throw new Error("Stage B recovery approval observation-binding SHA256 is not inherited from the captured plan.");
  if (report.planProfile !== captureReport.planProfile || JSON.stringify(report.taskDefinitionRotations || []) !== JSON.stringify(captureReport.taskDefinitionRotations || [])) throw new Error("Stage B plan approval profile is not bound to the captured plan.");
  if (report.captureReportSha256 !== sha256(captureReportBytes)) throw new Error("Stage B plan approval report is bound to a different capture report.");
  if (report.recoveryAttestationSha256 !== captureReport.recoveryAttestationSha256) throw new Error("Stage B approval recovery-attestation binding is not inherited from the capture report.");
  assertPlanHashes(report, hashes);
  for (const [name, value] of Object.entries({ toolingSha: captureReport.toolingSha, toolingTreeSha256: captureReport.toolingTreeSha256, refreshReportSha256: captureReport.refreshReportSha256, stageBLineage: captureReport.stageBLineage, stageBSerial: captureReport.stageBSerial })) {
    if (report[name] !== value) throw new Error(`Stage B plan approval report ${name} is not bound to the captured release.`);
  }
  if (report.logicalCanonicalPlanJsonSha256 !== logicalCanonicalPlanJsonSha256) throw new Error("Stage B logical canonical plan hash is not bound to the approved plan.");
  assertBoundReferenceAudit(report, { referenceAudit, referenceAuditBytes, hashes, required: true });
  if (referenceAuditSha256 !== undefined && report.referenceAuditSha256 !== referenceAuditSha256) throw new Error("Stage B plan approval report reference-audit binding is invalid.");
  if (captureReport.recoveryAttestationSha256 !== referenceAudit?.recoveryAttestationSha256) throw new Error("Stage B reference audit does not inherit the recovery-attestation binding.");
  if (trustedCallerArn !== undefined && referenceAudit?.callerArn !== trustedCallerArn) throw new Error("Stage B reference audit caller does not match the trusted release caller.");
  if (report.referenceAuditCallerArn !== referenceAudit?.callerArn || report.referenceAuditAt !== referenceAudit?.auditedAt) throw new Error("Stage B plan approval report reference-audit identity is incomplete.");
  if (["BASELINE", "IMPORTED_BACKEND_METADATA_NORMALIZATION"].includes(report.planProfile) && plan && referenceAudit) assertStageBNormalPlanCompleteness(plan, { referenceAudit, strict: false, terraformConfiguration });
  if (report.planProfile === "PARTIAL_APPLY_RECOVERY" && plan) assertStageBPartialApplyRecoveryPlan(plan);
  if (report.planProfile === "FRESH_IMAGE_PARTIAL_APPLY_RECOVERY" && plan) assertStageBFreshImagePartialApplyRecoveryPlan(plan, { terraformConfiguration });
  assertClassification(report);
  return true;
}

export function assertStageBPlanApprovedBinding(report, { approvalReportBytes, approvalReportSha256, savedPlanBytes, planJsonBytes, canonicalPlanJsonBytes, referenceAudit, referenceAuditBytes, expectedToolingSha, expectedToolingTreeSha256, expectedRefreshReportSha256, expectedRefreshBindingReportSha256, expectedRecoveryAttestationSha256, expectedStageBLineage, expectedStageBSerial, terraformConfiguration, now = new Date() } = {}) {
  assertCanonicalTerraformSerialNumber(report?.stageBSerial, "Stage B plan approval serial");
  if (report?.schemaVersion !== STAGE_B_PLAN_EVIDENCE_SCHEMA_VERSION || report.state !== STAGE_B_PLAN_APPROVED || report.approvedForApply !== true || report.brokerReferenceValidationPending !== false || report.brokerReferenceValidationPassed !== true) throw new Error("PLAN_APPROVED evidence is required; PLAN_CAPTURED is not deployable.");
  if (!Buffer.isBuffer(approvalReportBytes) || sha256(approvalReportBytes) !== approvalReportSha256) throw new Error("Stage B plan approval report SHA256 mismatch.");
  const hashes = stageBPlanHashes({ savedPlanBytes, planJsonBytes, canonicalPlanJsonBytes });
  assertPlanHashes(report, hashes);
  if (typeof report.captureReportSha256 !== "string" || !/^[a-f0-9]{64}$/.test(report.referenceAuditSha256 || "") || !report.referenceAuditCallerArn || !report.referenceAuditAt) throw new Error("Stage B plan approval report is incomplete.");
  for (const [name, value] of Object.entries({ expectedToolingSha: report.toolingSha, expectedToolingTreeSha256: report.toolingTreeSha256, expectedRefreshReportSha256: report.refreshReportSha256, expectedStageBLineage: report.stageBLineage, expectedStageBSerial: report.stageBSerial })) {
    if (value === undefined || value === null || value === "") throw new Error(`Stage B plan approval report is missing ${name.replace(/^expected/, "").toLowerCase()}.`);
  }
  for (const [name, expected] of Object.entries({ toolingSha: expectedToolingSha, toolingTreeSha256: expectedToolingTreeSha256, refreshReportSha256: expectedRefreshReportSha256, stageBLineage: expectedStageBLineage, stageBSerial: expectedStageBSerial })) {
    if (expected !== undefined && report[name] !== expected) throw new Error(`Stage B plan approval report ${name} does not match the current deployment binding.`);
  }
  if (expectedRecoveryAttestationSha256 !== undefined && report.recoveryAttestationSha256 !== expectedRecoveryAttestationSha256) throw new Error("Stage B approval recovery-attestation binding differs from the current recovery evidence.");
  assertPlanProfile(report.planProfile, "Stage B plan approval");
  assertPartialApplyRecoveryEvidence(report);
  if (["RECOVERY_ALIAS_ONLY", "PARTIAL_APPLY_RECOVERY", "FRESH_IMAGE_PARTIAL_APPLY_RECOVERY"].includes(report.planProfile) && expectedRefreshBindingReportSha256 !== undefined && report.refreshBindingReportSha256 !== expectedRefreshBindingReportSha256) throw new Error("Stage B recovery approval observation-binding SHA256 differs from the selected observation binding.");
  assertBrokerEvidence(report, { approved: true });
  assertStageBReferenceAuditFreshness(report.referenceAuditAt, now);
  const boundReferenceAudit = assertBoundReferenceAudit(report, {
    referenceAudit,
    referenceAuditBytes,
    hashes,
    required: ["BASELINE", "IMPORTED_BACKEND_METADATA_NORMALIZATION", "PARTIAL_APPLY_RECOVERY", "FRESH_IMAGE_PARTIAL_APPLY_RECOVERY"].includes(report.planProfile),
  });
  if (["BASELINE", "IMPORTED_BACKEND_METADATA_NORMALIZATION"].includes(report.planProfile)) assertStageBNormalPlanCompleteness(JSON.parse(planJsonBytes.toString("utf8")), { referenceAudit: boundReferenceAudit, strict: false, terraformConfiguration });
  if (report.planProfile === "PARTIAL_APPLY_RECOVERY") assertStageBPartialApplyRecoveryPlan(JSON.parse(planJsonBytes.toString("utf8")));
  if (report.planProfile === "FRESH_IMAGE_PARTIAL_APPLY_RECOVERY") assertStageBFreshImagePartialApplyRecoveryPlan(JSON.parse(planJsonBytes.toString("utf8")), { terraformConfiguration });
  assertClassification(report);
  return true;
}

export function writeStageBPlanEvidence({ filePath, report, repositoryRoot, label }) {
  const bytes = Buffer.from(`${JSON.stringify(report, null, 2)}\n`);
  writeStageBPrivateFileAtomic({ filePath, bytes, repositoryRoot, label });
  assertStageBPrivateFile({ filePath, repositoryRoot, label });
  return { path: filePath, sha256: sha256(bytes) };
}

export function readStageBPlanEvidence(filePath, repositoryRoot, label) {
  assertStageBPrivateFile({ filePath, repositoryRoot, label });
  const bytes = fs.readFileSync(filePath);
  return { report: JSON.parse(bytes), bytes, sha256: sha256(bytes) };
}
