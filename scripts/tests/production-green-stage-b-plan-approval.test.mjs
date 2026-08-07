import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { canonicalJson } from "../aws/production-green-stage-b-contract.mjs";
import { assertStageBPlanApprovedBinding, assertStageBPlanApprovalReport, assertStageBPlanCaptureReport, createStageBPlanApprovalReport, createStageBPlanCaptureReport, stageBPlanHashes } from "../aws/stage-b-plan-approval-contract.mjs";
import { finalizeCapturedStageBPlanApproval, readStageBApprovalPlanArtifacts } from "../plan-production-green-stage-b.mjs";
import { writeStageBPrivateFileAtomic } from "../aws/stage-b-artifact-contract.mjs";

const fixture = JSON.parse(fs.readFileSync("scripts/tests/fixtures/production-green-stage-b-production-shaped.plan.json", "utf8"));
const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-plan-approval-"));
const hash = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const savedPlanBytes = Buffer.from("captured-binary-plan\n");
const planJsonBytes = Buffer.from(`${JSON.stringify(fixture)}\n`);
const canonicalPlanJsonBytes = Buffer.from(`${canonicalJson(fixture)}\n`);
const hashes = stageBPlanHashes({ savedPlanBytes, planJsonBytes, canonicalPlanJsonBytes });
const capture = createStageBPlanCaptureReport({ toolingSha: "b".repeat(40), toolingTreeSha256: "c".repeat(64), refreshReportSha256: "d".repeat(64), hashes, capturedAt: "2026-08-05T14:00:00.000Z", stageBLineage: "4e438e59-8b8b-194d-030c-5ede0c26344a", stageBSerial: 76, terraformVersion: fixture.terraform_version, terraformFormatVersion: fixture.format_version, classification: { noOp: 58, create: 12, update: 3, destroy: 0, replacement: 0, unclassified: 0 }, brokerEvidence: { brokerOperation: "update", brokerUpdatePresent: true, brokerActions: ["update"], brokerResourceAddresses: ["aws_iam_policy.broker", "aws_lambda_alias.reviewed", "aws_lambda_function.broker"], brokerReferenceValidationPending: true } });
const captureBytes = Buffer.from(`${JSON.stringify(capture, null, 2)}\n`);
const audit = { schemaVersion: 1, planJsonSha256: hashes.planJsonSha256, callerArn: "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test", auditedAt: "2026-08-05T14:01:00.000Z" };
const auditBytes = Buffer.from(`${JSON.stringify(audit)}\n`);
const approval = createStageBPlanApprovalReport({ captureReportSha256: hash(captureBytes), referenceAuditPath: path.join(directory, "audit.json"), referenceAuditSha256: hash(auditBytes), referenceAuditCallerArn: audit.callerArn, referenceAuditAt: audit.auditedAt, toolingSha: capture.toolingSha, toolingTreeSha256: capture.toolingTreeSha256, refreshReportSha256: capture.refreshReportSha256, stageBLineage: capture.stageBLineage, stageBSerial: capture.stageBSerial, hashes, logicalCanonicalPlanJsonSha256: hashes.logicalCanonicalPlanJsonSha256, approvedAt: "2026-08-05T14:02:00.000Z", classification: capture.classification, brokerOperation: capture.brokerOperation, brokerUpdatePresent: capture.brokerUpdatePresent, brokerActions: capture.brokerActions, brokerResourceAddresses: capture.brokerResourceAddresses });
const approvalBytes = Buffer.from(`${JSON.stringify(approval, null, 2)}\n`);
const plannerSource = fs.readFileSync("scripts/plan-production-green-stage-b.mjs", "utf8");
const approvalPathSource = plannerSource.slice(plannerSource.indexOf("export function approveCapturedStageBPlan"), plannerSource.indexOf("\n}\n\nif (process.argv[1]"));

test.after(() => fs.rmSync(directory, { recursive: true, force: true }));

function outputDirectory(name) {
  const output = path.join(directory, name);
  fs.mkdirSync(output, { recursive: true, mode: 0o700 });
  return output;
}

function finalizeOptions(approvalReportPath, overrides = {}) {
  return {
    approval,
    approvalReportPath,
    repositoryRoot: process.cwd(),
    captureReport: capture,
    captureReportBytes: captureBytes,
    referenceAudit: audit,
    referenceAuditBytes: auditBytes,
    hashes,
    logicalCanonicalPlanJsonSha256: hashes.logicalCanonicalPlanJsonSha256,
    referenceAuditSha256: hash(auditBytes),
    trustedCallerArn: audit.callerArn,
    stageBLineage: capture.stageBLineage,
    stageBSerial: capture.stageBSerial,
    savedPlanPath: path.join(directory, "saved.tfplan"),
    planJsonPath: path.join(directory, "plan.json"),
    canonicalPlanJsonPath: path.join(directory, "canonical.json"),
    ...overrides,
  };
}

test("approval imports PLAN_APPROVED from the canonical contract and keeps approval-only Terraform-free", () => {
  assert.match(plannerSource, /import \{[^}]*STAGE_B_PLAN_APPROVED[^}]*\} from "\.\/aws\/stage-b-plan-approval-contract\.mjs";/);
  assert.doesNotMatch(plannerSource, /(?:const|let|var)\s+STAGE_B_PLAN_APPROVED\s*=/);
  assert.doesNotMatch(approvalPathSource, /execFileSync\("terraform"[^)]*\bplan\b/);
  assert.doesNotMatch(approvalPathSource, /execFileSync\("terraform"[^)]*\bshow\b/);
  assert.doesNotMatch(approvalPathSource, /console\.(log|error|warn)\s*\(/);
});

test("approval finalization returns PLAN_APPROVED and constructs the complete result before publication", () => {
  const output = path.join(outputDirectory("result-before-publication"), "approval.json");
  let published = 0;
  const result = finalizeCapturedStageBPlanApproval(finalizeOptions(output, {
    publish: ({ filePath, report }) => {
      published += 1;
      assert.equal(filePath, output);
      assert.deepEqual(report, approval);
      assert.equal(fs.existsSync(output), false);
    },
  }));
  assert.equal(published, 1);
  assert.equal(result.status, "PLAN_APPROVED");
  assert.equal(result.state, "PLAN_APPROVED");
  assert.equal(result.approvedForApply, true);
  assert.equal(result.savedPlanSha256, hashes.savedPlanSha256);
  assert.equal(result.planJsonSha256, hashes.planJsonSha256);
  assert.equal(result.canonicalPlanFileSha256, hashes.canonicalPlanFileSha256);
  assert.equal(result.canonicalPlanJsonSha256, hashes.canonicalPlanFileSha256);
  assert.equal(result.logicalCanonicalPlanJsonSha256, hashes.logicalCanonicalPlanJsonSha256);
  assert.equal(fs.existsSync(output), false);
});

test("approval validation failure after object construction publishes no report", () => {
  const parent = outputDirectory("validation-failure");
  const output = path.join(parent, "approval.json");
  const invalidApproval = { ...approval, approvedForApply: false };
  assert.throws(() => finalizeCapturedStageBPlanApproval(finalizeOptions(output, { approval: invalidApproval })), /PLAN_CAPTURED|PLAN_APPROVED/);
  assert.equal(fs.existsSync(output), false);
  assert.deepEqual(fs.readdirSync(parent), []);
});

test("plan and approval evidence require canonical numeric serials", () => {
  assert.doesNotThrow(() => createStageBPlanCaptureReport({ ...capture, stageBSerial: Number.MAX_SAFE_INTEGER }));
  assert.throws(() => createStageBPlanCaptureReport({ ...capture, stageBSerial: "76" }), /serial/);
  assert.throws(() => createStageBPlanCaptureReport({ ...capture, stageBSerial: -1 }), /serial/);
  assert.throws(() => createStageBPlanCaptureReport({ ...capture, stageBSerial: 76.5 }), /serial/);
  assert.throws(() => createStageBPlanCaptureReport({ ...capture, stageBSerial: Number.MAX_SAFE_INTEGER + 1 }), /serial/);
  assert.throws(() => assertStageBPlanApprovedBinding({ ...approval, stageBSerial: "76" }, { approvalReportBytes: approvalBytes, approvalReportSha256: hash(approvalBytes), savedPlanBytes, planJsonBytes, canonicalPlanJsonBytes }), /serial/);
  assert.throws(() => assertStageBPlanApprovedBinding({ ...approval, stageBSerial: -1 }, { approvalReportBytes: approvalBytes, approvalReportSha256: hash(approvalBytes), savedPlanBytes, planJsonBytes, canonicalPlanJsonBytes }), /serial/);
});

test("atomic publication failure removes temporary artifacts and final report", () => {
  const parent = outputDirectory("publication-failure");
  const output = path.join(parent, "approval.json");
  const failingFs = {
    ...fs,
    renameSync: (source, destination) => {
      if (path.basename(path.dirname(source)).startsWith(".stage-b-artifact-")) throw new Error("simulated approval publication failure");
      return fs.renameSync(source, destination);
    },
  };
  assert.throws(() => finalizeCapturedStageBPlanApproval(finalizeOptions(output, {
    publish: ({ filePath, report, repositoryRoot, label }) => writeStageBPrivateFileAtomic({ filePath, bytes: Buffer.from(`${JSON.stringify(report, null, 2)}\n`), repositoryRoot, label, fsOps: failingFs }),
  })), /simulated approval publication failure/);
  assert.equal(fs.existsSync(output), false);
  assert.deepEqual(fs.readdirSync(parent), []);
});

test("successful approval publishes one private regular report", () => {
  const parent = outputDirectory("successful-publication");
  const output = path.join(parent, "approval.json");
  const result = finalizeCapturedStageBPlanApproval(finalizeOptions(output));
  const stat = fs.lstatSync(output);
  assert.equal(result.state, "PLAN_APPROVED");
  assert.equal(result.approvedForApply, true);
  assert.equal(stat.isFile(), true);
  assert.equal(stat.isSymbolicLink(), false);
  assert.equal(stat.mode & 0o777, 0o600);
  assert.deepEqual(fs.readdirSync(parent), ["approval.json"]);
});

test("approval-only loads all plan artifacts as raw bytes for hashing", () => {
  const paths = {
    savedPlanPath: path.join(directory, "saved.tfplan"),
    planJsonPath: path.join(directory, "plan.json"),
    canonicalPlanJsonPath: path.join(directory, "canonical.json"),
  };
  fs.writeFileSync(paths.savedPlanPath, savedPlanBytes);
  fs.writeFileSync(paths.planJsonPath, planJsonBytes);
  fs.writeFileSync(paths.canonicalPlanJsonPath, canonicalPlanJsonBytes);
  const loaded = readStageBApprovalPlanArtifacts(paths);
  assert.deepEqual(loaded.savedPlanBytes, savedPlanBytes);
  assert.deepEqual(loaded.planJsonBytes, planJsonBytes);
  assert.deepEqual(loaded.canonicalPlanJsonBytes, canonicalPlanJsonBytes);
  assert.deepEqual(stageBPlanHashes(loaded), hashes);
  assert.deepEqual(JSON.parse(loaded.planJsonBytes.toString("utf8")), fixture);
});

test("capture proves the one-plan structural boundary but is not deployable", () => {
  assert.equal(capture.brokerOperation, "update");
  assert.equal(capture.brokerReferenceValidationPending, true);
  assert.equal(approval.brokerReferenceValidationPending, false);
  assert.equal(approval.brokerReferenceValidationPassed, true);
  assert.doesNotThrow(() => assertStageBPlanCaptureReport(capture, { captureReportBytes: captureBytes, hashes, toolingSha: capture.toolingSha, toolingTreeSha256: capture.toolingTreeSha256, refreshReportSha256: capture.refreshReportSha256, stageBLineage: capture.stageBLineage, stageBSerial: capture.stageBSerial }));
  assert.throws(() => assertStageBPlanApprovedBinding(capture, { approvalReportBytes: captureBytes, approvalReportSha256: hash(captureBytes), savedPlanBytes, planJsonBytes, canonicalPlanJsonBytes }), /PLAN_APPROVED/);
});

test("approval binds exact captured artifacts and audit without another plan", () => {
  assert.equal(approval.brokerOperation, "update");
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
  const second = createStageBPlanApprovalReport({ captureReportSha256: hash(captureBytes), referenceAuditPath: approval.referenceAuditPath, referenceAuditSha256: hash(auditBytes), referenceAuditCallerArn: audit.callerArn, referenceAuditAt: audit.auditedAt, toolingSha: capture.toolingSha, toolingTreeSha256: capture.toolingTreeSha256, refreshReportSha256: capture.refreshReportSha256, stageBLineage: capture.stageBLineage, stageBSerial: capture.stageBSerial, hashes, logicalCanonicalPlanJsonSha256: hashes.logicalCanonicalPlanJsonSha256, approvedAt: approval.approvedAt, classification: capture.classification, brokerOperation: capture.brokerOperation, brokerUpdatePresent: capture.brokerUpdatePresent, brokerActions: capture.brokerActions, brokerResourceAddresses: capture.brokerResourceAddresses });
  assert.deepEqual(second, approval);
});
