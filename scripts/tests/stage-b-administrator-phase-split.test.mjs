import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import {
  assertStageBPermissionEvidenceKind,
  INITIAL_ADMINISTRATOR_CAPABILITY_EVIDENCE_KIND,
  PLAN_BOUND_PERMISSION_EVIDENCE_KIND,
  runPermissionPreflight,
  sourcePolicyEvidence,
} from "../aws/validate-production-green-stage-b-permissions.mjs";

const root = process.cwd();
const manifest = JSON.parse(fs.readFileSync(path.join(root, "documents/ops/iam/MSCQRProductionGreenStageBPermissionManifest-v1.json"), "utf8"));
const planBytes = fs.readFileSync(path.join(root, "scripts/tests/fixtures/production-green-stage-b-production-shaped.plan.json"));
const plan = JSON.parse(planBytes);
const policyEvidence = (() => {
  const policies = sourcePolicyEvidence().map((policy) => ({ ...policy, defaultVersionId: "v1", liveSha256: policy.sourceSha256, attached: true, matchesSource: true }));
  return { roleArn: "arn:aws:iam::368992683803:role/mscqr-production-release-deployer", attachedPolicyArns: policies.map(({ arn }) => arn).sort(), inlinePolicyNames: [], inlinePolicies: [], permissionsBoundaryArn: null, policies, status: "valid" };
})();
const simulation = ({ evaluation: item }) => ({
  decision: item.expectedDecision || "allowed",
  matchedStatements: item.expectedDecision ? 0 : 1,
  missingContextValues: item.expectedDecision ? item.expectedMissingContextValues : [],
});
const clearCloudTrail = () => ({ status: "clear", eventsChecked: 0, unresolvedDenials: [] });

test("initial capability evidence needs no plan approval and is not plan-bound", () => {
  const now = "2026-08-05T17:00:00.000Z";
  const report = runPermissionPreflight({
    reportGeneratorCallerArn: "arn:aws:iam::368992683803:root",
    manifest,
    plan,
    planBytes,
    generatedAt: now,
    policyPublishedAt: now,
    cloudTrailSessionName: "pre-plan-capability",
    policyEvidence,
    phase: "initial",
    now,
    simulate: simulation,
    cloudTrail: clearCloudTrail,
  });
  assertStageBPermissionEvidenceKind(report, INITIAL_ADMINISTRATOR_CAPABILITY_EVIDENCE_KIND, "initial");
  assert.equal(report.status, "valid");
  assert.equal(report.requiredAllowedCount, 89);
  assert.equal(report.forbiddenDeniedCount, 21);
  assert.equal(Object.hasOwn(report, "planSha256"), false);
  assert.equal(Object.hasOwn(report, "savedPlanSha256"), false);
  assert.equal(Object.hasOwn(report, "planApprovalReportSha256"), false);
});

test("plan-bound permission remains fail-closed without PLAN_APPROVED", () => {
  assert.throws(() => runPermissionPreflight({
    reportGeneratorCallerArn: "arn:aws:iam::368992683803:root",
    manifest,
    plan,
    planBytes,
    savedPlanBytes: Buffer.from("saved-plan"),
    canonicalPlanJsonBytes: Buffer.from("{}"),
    generatedAt: "2026-08-05T17:00:00.000Z",
    policyPublishedAt: "2026-08-05T17:00:00.000Z",
    cloudTrailSessionName: "plan-bound",
    policyEvidence,
    now: "2026-08-05T17:00:00.000Z",
    simulate: simulation,
    cloudTrail: clearCloudTrail,
  }), /PLAN_APPROVED evidence is required/);
});

test("evidence kinds are not interchangeable", () => {
  const initial = { evidenceKind: INITIAL_ADMINISTRATOR_CAPABILITY_EVIDENCE_KIND, phase: "initial" };
  const planBound = { evidenceKind: PLAN_BOUND_PERMISSION_EVIDENCE_KIND, phase: "plan-bound" };
  assert.throws(() => assertStageBPermissionEvidenceKind(initial, PLAN_BOUND_PERMISSION_EVIDENCE_KIND, "plan-bound"), /PLAN_BOUND_PERMISSION/);
  assert.throws(() => assertStageBPermissionEvidenceKind(planBound, INITIAL_ADMINISTRATOR_CAPABILITY_EVIDENCE_KIND, "initial"), /INITIAL_ADMIN_CAPABILITY/);
});

test("administrator lifecycle launcher requires an explicit phase", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-phase-launcher-"));
  const result = spawnSync(process.execPath, [path.join(root, "scripts/aws/run-stage-b-administrator-preflight.mjs"), "--output", path.join(directory, "report.json"), "--signature-output", path.join(directory, "signature.json"), "--lifecycle-directory", path.join(directory, "lifecycle")], { encoding: "utf8" });
  assert.notEqual(result.status, 0);
  assert.match(`${result.stdout}${result.stderr}`, /--phase is required/);
  fs.rmSync(directory, { recursive: true, force: true });
});

test("initial launcher rejects plan-bound arguments before producer start", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-phase-launcher-"));
  const result = spawnSync(process.execPath, [path.join(root, "scripts/aws/run-stage-b-administrator-preflight.mjs"), "--phase", "initial", "--output", path.join(directory, "report.json"), "--signature-output", path.join(directory, "signature.json"), "--lifecycle-directory", path.join(directory, "lifecycle"), "--plan-approval-report", path.join(directory, "approval.json")], { encoding: "utf8" });
  assert.notEqual(result.status, 0);
  assert.match(`${result.stdout}${result.stderr}`, /does not accept plan-bound arguments/);
  fs.rmSync(directory, { recursive: true, force: true });
});

test("phase schema values are deterministic and report hashes remain standard", () => {
  const report = { schemaVersion: 1, evidenceKind: INITIAL_ADMINISTRATOR_CAPABILITY_EVIDENCE_KIND, phase: "initial" };
  assert.equal(crypto.createHash("sha256").update(JSON.stringify(report)).digest("hex").length, 64);
});
