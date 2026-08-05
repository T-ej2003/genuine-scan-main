import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { canonicalJson } from "../aws/production-green-stage-b-contract.mjs";
import { assertStageBPlanApprovedBinding, assertStageBPlanApprovalReport, assertStageBPlanCaptureReport, createStageBPlanApprovalReport, createStageBPlanCaptureReport, stageBPlanHashes } from "../aws/stage-b-plan-approval-contract.mjs";

const fixture = JSON.parse(fs.readFileSync("scripts/tests/fixtures/production-green-stage-b-production-shaped.plan.json", "utf8"));
const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-plan-approval-"));
const hash = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const savedPlanBytes = Buffer.from("captured-binary-plan\n");
const planJsonBytes = Buffer.from(`${JSON.stringify(fixture)}\n`);
const canonicalPlanJsonBytes = Buffer.from(`${canonicalJson(fixture)}\n`);
const hashes = stageBPlanHashes({ savedPlanBytes, planJsonBytes, canonicalPlanJsonBytes });
const capture = createStageBPlanCaptureReport({ toolingSha: "b".repeat(40), toolingTreeSha256: "c".repeat(64), refreshReportSha256: "d".repeat(64), hashes, capturedAt: "2026-08-05T14:00:00.000Z", stageBLineage: "4e438e59-8b8b-194d-030c-5ede0c26344a", stageBSerial: 76, terraformVersion: fixture.terraform_version, terraformFormatVersion: fixture.format_version, classification: { noOp: 58, create: 12, update: 3, destroy: 0, replacement: 0, unclassified: 0 } });
const captureBytes = Buffer.from(`${JSON.stringify(capture, null, 2)}\n`);
const audit = { schemaVersion: 1, planJsonSha256: hashes.planJsonSha256, callerArn: "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test", auditedAt: "2026-08-05T14:01:00.000Z" };
const auditBytes = Buffer.from(`${JSON.stringify(audit)}\n`);
const approval = createStageBPlanApprovalReport({ captureReportSha256: hash(captureBytes), referenceAuditPath: path.join(directory, "audit.json"), referenceAuditSha256: hash(auditBytes), referenceAuditCallerArn: audit.callerArn, referenceAuditAt: audit.auditedAt, toolingSha: capture.toolingSha, toolingTreeSha256: capture.toolingTreeSha256, refreshReportSha256: capture.refreshReportSha256, stageBLineage: capture.stageBLineage, stageBSerial: capture.stageBSerial, hashes, logicalCanonicalPlanJsonSha256: hashes.logicalCanonicalPlanJsonSha256, approvedAt: "2026-08-05T14:02:00.000Z", classification: capture.classification });
const approvalBytes = Buffer.from(`${JSON.stringify(approval, null, 2)}\n`);

test.after(() => fs.rmSync(directory, { recursive: true, force: true }));

test("capture proves the one-plan structural boundary but is not deployable", () => {
  assert.doesNotThrow(() => assertStageBPlanCaptureReport(capture, { captureReportBytes: captureBytes, hashes, toolingSha: capture.toolingSha, toolingTreeSha256: capture.toolingTreeSha256, refreshReportSha256: capture.refreshReportSha256, stageBLineage: capture.stageBLineage, stageBSerial: capture.stageBSerial }));
  assert.throws(() => assertStageBPlanApprovedBinding(capture, { approvalReportBytes: captureBytes, approvalReportSha256: hash(captureBytes), savedPlanBytes, planJsonBytes, canonicalPlanJsonBytes }), /PLAN_APPROVED/);
});

test("approval binds exact captured artifacts and audit without another plan", () => {
  assert.doesNotThrow(() => assertStageBPlanApprovalReport(approval, { approvalReportBytes: approvalBytes, captureReport: capture, captureReportBytes: captureBytes, referenceAudit: audit, referenceAuditBytes: auditBytes, hashes, logicalCanonicalPlanJsonSha256: hashes.logicalCanonicalPlanJsonSha256, referenceAuditSha256: hash(auditBytes), trustedCallerArn: audit.callerArn, stageBLineage: capture.stageBLineage, stageBSerial: capture.stageBSerial }));
  assert.doesNotThrow(() => assertStageBPlanApprovedBinding(approval, { approvalReportBytes: approvalBytes, approvalReportSha256: hash(approvalBytes), savedPlanBytes, planJsonBytes, canonicalPlanJsonBytes, now: new Date("2026-08-05T14:02:00.000Z") }));
});

test("approval rejects every changed plan artifact and stale capture binding", () => {
  for (const [name, bytes] of [["binary", Buffer.from("changed\n")], ["plan json", Buffer.from(`${JSON.stringify({ ...fixture, terraform_version: "1.6.0" })}\n`)], ["canonical", Buffer.from(`${canonicalJson({ ...fixture, terraform_version: "1.6.0" })}\n`)]]) {
    const changed = { ...hashes, ...(name === "binary" ? { savedPlanSha256: hash(bytes) } : {}), ...(name === "plan json" ? { planJsonSha256: hash(bytes) } : {}), ...(name === "canonical" ? { canonicalPlanFileSha256: hash(bytes) } : {}) };
    assert.throws(() => assertStageBPlanApprovedBinding(approval, { approvalReportBytes: approvalBytes, approvalReportSha256: hash(approvalBytes), savedPlanBytes: changed.savedPlanSha256 === hashes.savedPlanSha256 ? savedPlanBytes : bytes, planJsonBytes: changed.planJsonSha256 === hashes.planJsonSha256 ? planJsonBytes : bytes, canonicalPlanJsonBytes: changed.canonicalPlanFileSha256 === hashes.canonicalPlanFileSha256 ? canonicalPlanJsonBytes : bytes }), /does not match|different/ , name);
  }
  const tamperedApproval = { ...approval, referenceAuditSha256: "0".repeat(64) }; const tamperedApprovalBytes = Buffer.from(`${JSON.stringify(tamperedApproval, null, 2)}\n`);
  assert.throws(() => assertStageBPlanApprovalReport(tamperedApproval, { approvalReportBytes: tamperedApprovalBytes, captureReport: capture, captureReportBytes: captureBytes, referenceAudit: audit, referenceAuditBytes: auditBytes, hashes, logicalCanonicalPlanJsonSha256: hashes.logicalCanonicalPlanJsonSha256, referenceAuditSha256: hash(auditBytes), trustedCallerArn: audit.callerArn, stageBLineage: capture.stageBLineage, stageBSerial: capture.stageBSerial }), /reference-audit/);
});

test("approval is deterministic for unchanged captured artifacts", () => {
  const second = createStageBPlanApprovalReport({ captureReportSha256: hash(captureBytes), referenceAuditPath: approval.referenceAuditPath, referenceAuditSha256: hash(auditBytes), referenceAuditCallerArn: audit.callerArn, referenceAuditAt: audit.auditedAt, toolingSha: capture.toolingSha, toolingTreeSha256: capture.toolingTreeSha256, refreshReportSha256: capture.refreshReportSha256, stageBLineage: capture.stageBLineage, stageBSerial: capture.stageBSerial, hashes, logicalCanonicalPlanJsonSha256: hashes.logicalCanonicalPlanJsonSha256, approvedAt: approval.approvedAt, classification: capture.classification });
  assert.deepEqual(second, approval);
});
