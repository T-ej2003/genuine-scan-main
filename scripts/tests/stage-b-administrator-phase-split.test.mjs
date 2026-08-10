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
import { parseStageBAdministratorPreflightArgs } from "../aws/stage-b-administrator-preflight-args.mjs";

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
  assert.equal(report.requiredAllowedCount, 93);
  assert.equal(report.forbiddenDeniedCount, 23);
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

test("launcher preserves producer flags around boolean retry and strips only launcher arguments", () => {
  const args = parseStageBAdministratorPreflightArgs([
    "--phase", "plan-bound",
    "--retry",
    "--report-generator-caller-arn", "arn:aws:iam::368992683803:root",
    "--simulated-role-arn", "arn:aws:iam::368992683803:role/mscqr-production-release-deployer",
    "--output", "/private/tmp/report.json",
    "--signature-output", "/private/tmp/signature.json",
    "--lifecycle-directory", "/private/tmp/lifecycle",
  ]);
  assert.equal(args.retry, true);
  assert.deepEqual(args.forwarded, [
    "--report-generator-caller-arn", "arn:aws:iam::368992683803:root",
    "--simulated-role-arn", "arn:aws:iam::368992683803:role/mscqr-production-release-deployer",
  ]);
});

test("retry placement does not change ordered producer arguments", () => {
  const base = [
    "--phase", "plan-bound",
    "--report-generator-caller-arn", "root-caller",
    "--simulated-role-arn", "release-role",
    "--output", "/tmp/report",
    "--signature-output", "/tmp/signature",
    "--lifecycle-directory", "/tmp/lifecycle",
  ];
  const before = parseStageBAdministratorPreflightArgs([base[0], base[1], "--retry", ...base.slice(2)]);
  const after = parseStageBAdministratorPreflightArgs([...base.slice(0, 6), "--retry", ...base.slice(6)]);
  const between = parseStageBAdministratorPreflightArgs([base[0], base[1], ...base.slice(2, 4), "--retry", ...base.slice(4)]);
  assert.deepEqual(before.forwarded, after.forwarded);
  assert.deepEqual(after.forwarded, between.forwarded);
  assert.equal(before.forwarded.includes("--retry"), false);
});

test("launcher rejects missing or duplicate value options without exposing values", () => {
  for (const option of ["--phase", "--output", "--signature-output", "--lifecycle-directory"]) {
    const args = option === "--phase" ? [option] : ["--phase", "plan-bound", option];
    assert.throws(() => parseStageBAdministratorPreflightArgs(args), new RegExp(`${option} requires a value`));
  }
  assert.throws(() => parseStageBAdministratorPreflightArgs(["--phase", "plan-bound", "--output", "one", "--output", "two"]), /may be specified only once/);
  assert.throws(() => parseStageBAdministratorPreflightArgs(["--phase", "plan-bound", "--retry", "--retry"]), /may be specified only once/);
  assert.throws(() => parseStageBAdministratorPreflightArgs(["--phase", "plan-bound", "--retry", "--output", "secret-value"]), /--signature-output is required/);
  assert.doesNotMatch((() => { try { parseStageBAdministratorPreflightArgs(["--phase", "plan-bound", "--output", "secret-value"]); } catch (error) { return error.message; } return ""; })(), /secret-value/);
});

test("unknown phases remain fail-closed", () => {
  assert.throws(() => parseStageBAdministratorPreflightArgs(["--phase", "unsupported"]), /--phase must be initial or plan-bound/);
});

test("phase schema values are deterministic and report hashes remain standard", () => {
  const report = { schemaVersion: 1, evidenceKind: INITIAL_ADMINISTRATOR_CAPABILITY_EVIDENCE_KIND, phase: "initial" };
  assert.equal(crypto.createHash("sha256").update(JSON.stringify(report)).digest("hex").length, 64);
});
