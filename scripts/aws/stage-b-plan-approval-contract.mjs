import crypto from "node:crypto";
import fs from "node:fs";
import { canonicalJson } from "./production-green-stage-b-contract.mjs";
import { assertStageBReferenceAuditFreshness } from "./stage-b-reference-audit-contract.mjs";
import { assertStageBPrivateFile, writeStageBPrivateFileAtomic } from "./stage-b-artifact-contract.mjs";

export const STAGE_B_PLAN_EVIDENCE_SCHEMA_VERSION = 1;
export const STAGE_B_PLAN_CAPTURED = "PLAN_CAPTURED";
export const STAGE_B_PLAN_APPROVED = "PLAN_APPROVED";

const sha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const STAGE_B_CAPTURE_BROKER_ADDRESSES = ["aws_iam_policy.broker", "aws_lambda_alias.reviewed", "aws_lambda_function.broker"];
const STAGE_B_BROKER_OPERATIONS = new Set(["none", "initial-create", "update"]);

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

function assertClassification(report) {
  const classification = report?.classification;
  if (!classification || classification.noOp !== 58 || classification.create !== 12 || classification.update !== 3
    || classification.destroy !== 0 || classification.replacement !== 0 || classification.unclassified !== 0) {
    throw new Error("Stage B plan evidence classification is not the reviewed 58/12/3/0/0 contract.");
  }
}

function assertPlanHashes(report, hashes) {
  for (const [name, value] of Object.entries(hashes)) {
    if (report?.[name] !== value) throw new Error(`Stage B plan evidence ${name} does not match the selected artifact.`);
  }
}

export function createStageBPlanCaptureReport({ toolingSha, toolingTreeSha256, refreshReportSha256, hashes, capturedAt, stageBLineage, stageBSerial, terraformVersion, terraformFormatVersion, planExitCode = 0, showExitCode = 0, classification, brokerEvidence = {} }) {
  return {
    schemaVersion: STAGE_B_PLAN_EVIDENCE_SCHEMA_VERSION,
    state: STAGE_B_PLAN_CAPTURED,
    toolingSha,
    toolingTreeSha256,
    refreshReportSha256,
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

export function assertStageBPlanCaptureReport(report, { captureReportBytes, hashes, toolingSha, toolingTreeSha256, refreshReportSha256, stageBLineage, stageBSerial } = {}) {
  if (report?.schemaVersion !== STAGE_B_PLAN_EVIDENCE_SCHEMA_VERSION || report.state !== STAGE_B_PLAN_CAPTURED || report.approvedForApply !== false || report.referenceAuditRequired !== true || !STAGE_B_BROKER_OPERATIONS.has(report.brokerOperation) || typeof report.brokerReferenceValidationPending !== "boolean" || typeof report.brokerUpdatePresent !== "boolean" || !Array.isArray(report.brokerActions) || !Array.isArray(report.brokerResourceAddresses)) {
    throw new Error("Stage B plan capture report is missing the PLAN_CAPTURED contract.");
  }
  const expectedBrokerEvidence = report.brokerOperation === "initial-create"
    ? { updatePresent: false, actions: ["create"], pending: false }
    : report.brokerOperation === "update"
      ? { updatePresent: true, actions: ["update"], pending: true }
      : { updatePresent: false, actions: [], pending: false };
  if (report.brokerUpdatePresent !== expectedBrokerEvidence.updatePresent || report.brokerReferenceValidationPending !== expectedBrokerEvidence.pending || JSON.stringify(report.brokerActions) !== JSON.stringify(expectedBrokerEvidence.actions)
    || (report.brokerOperation !== "none" && JSON.stringify(report.brokerResourceAddresses) !== JSON.stringify(STAGE_B_CAPTURE_BROKER_ADDRESSES))
    || (report.brokerOperation === "none" && report.brokerResourceAddresses.length !== 0)) {
    throw new Error("Stage B plan capture broker evidence is malformed.");
  }
  if (!Buffer.isBuffer(captureReportBytes) || sha256(captureReportBytes) !== sha256(Buffer.from(JSON.stringify(report, null, 2) + "\n"))) throw new Error("Stage B plan capture report bytes are not self-consistent.");
  assertPlanHashes(report, hashes);
  for (const [name, value] of Object.entries({ toolingSha, toolingTreeSha256, refreshReportSha256, stageBLineage, stageBSerial })) {
    if (value !== undefined && report[name] !== value) throw new Error(`Stage B plan capture report ${name} does not match the selected release.`);
  }
  if (report.planExitCode !== 0 && report.planExitCode !== 2) throw new Error("Stage B plan capture Terraform exit code is unsupported.");
  if (report.showExitCode !== 0) throw new Error("Stage B plan capture Terraform show exit code is unsupported.");
  assertClassification(report);
  return true;
}

export function createStageBPlanApprovalReport({ captureReportSha256, referenceAuditPath, referenceAuditSha256, referenceAuditCallerArn, referenceAuditAt, toolingSha, toolingTreeSha256, refreshReportSha256, stageBLineage, stageBSerial, hashes, logicalCanonicalPlanJsonSha256, approvedAt, classification, brokerOperation = "none", brokerUpdatePresent = false, brokerActions = [], brokerResourceAddresses = [] }) {
  return {
    schemaVersion: STAGE_B_PLAN_EVIDENCE_SCHEMA_VERSION,
    state: STAGE_B_PLAN_APPROVED,
    captureReportSha256,
    toolingSha,
    toolingTreeSha256,
    refreshReportSha256,
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

export function assertStageBPlanApprovalReport(report, { approvalReportBytes, captureReport, captureReportBytes, referenceAudit, referenceAuditBytes, hashes, logicalCanonicalPlanJsonSha256, referenceAuditSha256, trustedCallerArn, stageBLineage, stageBSerial } = {}) {
  if (report?.schemaVersion !== STAGE_B_PLAN_EVIDENCE_SCHEMA_VERSION || report.state !== STAGE_B_PLAN_APPROVED || report.approvedForApply !== true || report.brokerReferenceValidationPending !== false || report.brokerReferenceValidationPassed !== true) throw new Error("Stage B plan approval report is required; PLAN_CAPTURED is not deployable.");
  if (!Buffer.isBuffer(approvalReportBytes) || sha256(approvalReportBytes) !== sha256(Buffer.from(JSON.stringify(report, null, 2) + "\n"))) throw new Error("Stage B plan approval report bytes are not self-consistent.");
  if (!Buffer.isBuffer(captureReportBytes)) throw new Error("Stage B plan approval report capture binding is missing.");
  assertStageBPlanCaptureReport(captureReport, { captureReportBytes, hashes, stageBLineage, stageBSerial });
  if (report.brokerOperation !== captureReport.brokerOperation || report.brokerUpdatePresent !== captureReport.brokerUpdatePresent || JSON.stringify(report.brokerActions) !== JSON.stringify(captureReport.brokerActions) || JSON.stringify(report.brokerResourceAddresses) !== JSON.stringify(captureReport.brokerResourceAddresses)) throw new Error("Stage B plan approval broker evidence is not bound to the captured plan.");
  if (report.captureReportSha256 !== sha256(captureReportBytes)) throw new Error("Stage B plan approval report is bound to a different capture report.");
  assertPlanHashes(report, hashes);
  for (const [name, value] of Object.entries({ toolingSha: captureReport.toolingSha, toolingTreeSha256: captureReport.toolingTreeSha256, refreshReportSha256: captureReport.refreshReportSha256, stageBLineage: captureReport.stageBLineage, stageBSerial: captureReport.stageBSerial })) {
    if (report[name] !== value) throw new Error(`Stage B plan approval report ${name} is not bound to the captured release.`);
  }
  if (report.logicalCanonicalPlanJsonSha256 !== logicalCanonicalPlanJsonSha256) throw new Error("Stage B logical canonical plan hash is not bound to the approved plan.");
  if (!Buffer.isBuffer(referenceAuditBytes) || sha256(referenceAuditBytes) !== referenceAuditSha256 || report.referenceAuditSha256 !== referenceAuditSha256) throw new Error("Stage B plan approval report reference-audit binding is invalid.");
  if (referenceAudit?.planJsonSha256 !== hashes.planJsonSha256) throw new Error("Stage B reference audit is bound to a different plan JSON.");
  if (trustedCallerArn !== undefined && referenceAudit?.callerArn !== trustedCallerArn) throw new Error("Stage B reference audit caller does not match the trusted release caller.");
  if (report.referenceAuditCallerArn !== referenceAudit?.callerArn || report.referenceAuditAt !== referenceAudit?.auditedAt) throw new Error("Stage B plan approval report reference-audit identity is incomplete.");
  assertClassification(report);
  return true;
}

export function assertStageBPlanApprovedBinding(report, { approvalReportBytes, approvalReportSha256, savedPlanBytes, planJsonBytes, canonicalPlanJsonBytes, referenceAudit, referenceAuditBytes, expectedToolingSha, expectedToolingTreeSha256, expectedRefreshReportSha256, expectedStageBLineage, expectedStageBSerial, now = new Date() } = {}) {
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
  assertStageBReferenceAuditFreshness(report.referenceAuditAt, now);
  if (referenceAuditBytes && (sha256(referenceAuditBytes) !== report.referenceAuditSha256 || referenceAudit?.planJsonSha256 !== hashes.planJsonSha256)) throw new Error("Stage B plan approval report reference-audit binding is invalid.");
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
