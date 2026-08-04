import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  RELEASE_READ_PROBES,
  readIdentityCapabilityMatrix,
  runReleaseReadPreflight,
} from "../aws/production-green-stage-b-identity-capabilities.mjs";
import { sourcePolicyEvidence } from "../aws/validate-production-green-stage-b-permissions.mjs";
import { runProductionPreflightCli } from "../aws/run-production-green-stage-b-preflight.mjs";

const caller = "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test";
const shapedPolicyEvidence = () => {
  const policies = sourcePolicyEvidence().map((policy) => ({ ...policy, defaultVersionId: "v1", liveSha256: policy.sourceSha256, attached: true, matchesSource: true }));
  return { roleArn: "arn:aws:iam::368992683803:role/mscqr-production-release-deployer", attachedPolicyArns: policies.map(({ arn }) => arn).sort(), inlinePolicyNames: [], inlinePolicies: [], permissionsBoundaryArn: null, policies, status: "valid" };
};
const temp = () => fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-release-preflight-test-"));
const allowed = (args) => {
  if (args[0] === "sts") return JSON.stringify({ Arn: caller });
  if (args[0] === "ecs" && args[1] === "list-services") return JSON.stringify({ serviceArns: ["arn:aws:ecs:eu-west-2:368992683803:service/mscqr-prod-euw2-main/frontend"] });
  if (args[0] === "ecs" && args[1] === "list-tasks") return JSON.stringify({ taskArns: ["arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/abc"] });
  if (args[0] === "iam" && args[1] === "get-policy") return JSON.stringify({ Policy: { DefaultVersionId: "v1" } });
  if (args[0] === "iam" && args[1] === "list-role-policies") return JSON.stringify({ PolicyNames: ["inline"] });
  return "{}";
};

test("identity matrix assigns IAM simulation only to administrator", () => {
  const matrix = readIdentityCapabilityMatrix();
  assert(matrix.calls.some(({ identity, action }) => identity === "administrator" && action === "iam:SimulatePrincipalPolicy"));
  assert(!matrix.calls.some(({ identity, action }) => identity === "release-deployer" && action === "iam:SimulatePrincipalPolicy"));
  assert.equal(new Set(matrix.calls.filter(({ permissionManifestId }) => permissionManifestId).map(({ permissionManifestId }) => permissionManifestId)).size > 0, true);
});

test("release preflight aggregates independent read denials and never simulates IAM", () => {
  const calls = [];
  const report = runReleaseReadPreflight({ outputDirectory: temp(), run: (args, probe) => {
    calls.push(probe.action);
    if (["ecs:DescribeClusters", "rds:DescribeDBInstances"].includes(probe.action)) throw new Error("AccessDenied");
    return allowed(args);
  } });
  assert.equal(report.status, "blocked");
  assert.deepEqual(report.failed.map(({ action }) => action), ["ecs:DescribeClusters", "rds:DescribeDBInstances"]);
  assert(calls.length >= RELEASE_READ_PROBES.length);
  assert(!calls.includes("iam:SimulatePrincipalPolicy"));
});

test("complete release preflight is valid and has no skipped probes", () => {
  const report = runReleaseReadPreflight({ outputDirectory: temp(), run: allowed });
  assert.equal(report.status, "valid");
  assert.deepEqual(report.failed, []);
  assert.deepEqual(report.skipped, []);
  assert.equal(report.caller, caller);
});

test("wrong caller and region fail closed", () => {
  const wrongCaller = runReleaseReadPreflight({ outputDirectory: temp(), run: (args) => args[0] === "sts" ? JSON.stringify({ Arn: "arn:aws:iam::368992683803:root" }) : "{}" });
  assert.equal(wrongCaller.status, "blocked");
  assert.equal(wrongCaller.failed[0].id, "caller");
  assert.throws(() => runReleaseReadPreflight({ outputDirectory: temp(), region: "us-east-1", run: allowed }), /region/);
});

test("one command keeps administrator simulation and release reads on separate identities", () => {
  const directory = temp(); const adminPath = path.join(directory, "admin.json"); const signaturePath = path.join(directory, "admin.signature.json");
  let administratorSimulations = 0;
  const admin = runProductionPreflightCli(["--identity", "administrator", "--output", adminPath, "--signature-output", signaturePath], {
    caller: () => "arn:aws:iam::368992683803:root",
    collectPolicies: shapedPolicyEvidence,
    permissionPreflight: (input) => { administratorSimulations += 1; return { schemaVersion: 1, purpose: input.purpose, status: "valid", deniedCount: 0, simulatedRoleArn: input.simulatedRoleArn, generatedAt: input.generatedAt, policyEvidence: input.policyEvidence }; },
    sign: (report) => ({ schemaVersion: 1, reportSha256: "a".repeat(64), signedAt: report.generatedAt }),
  });
  assert.equal(admin.status, "valid"); assert.equal(administratorSimulations, 1);
  const releasePath = path.join(directory, "release.json"); let releaseReads = 0;
  const release = runProductionPreflightCli(["--identity", "release-deployer", "--output", releasePath, "--administrator-report", adminPath, "--administrator-report-signature", signaturePath], {
    caller: () => caller,
    verify: () => true,
    releasePreflight: () => { releaseReads += 1; return { schemaVersion: 1, caller, account: "368992683803", region: "eu-west-2", requiredReads: {}, failed: [], skipped: [], status: "valid" }; },
    continueReadiness: () => ({ backendReady: true, stateReady: true, handoffReady: true, tfvarsReady: true }),
  });
  assert.equal(release.status, "ready-for-plan"); assert.equal(releaseReads, 1);
});

test("invalid release capability report stops before backend readiness", () => {
  const directory = temp(); const adminPath = path.join(directory, "admin.json"); const signaturePath = path.join(directory, "signature.json");
  fs.writeFileSync(adminPath, JSON.stringify({ schemaVersion: 1, purpose: "pre-plan-capability", status: "valid", simulatedRoleArn: "arn:aws:iam::368992683803:role/mscqr-production-release-deployer", policyEvidence: shapedPolicyEvidence() }));
  fs.writeFileSync(signaturePath, "{}"); let continued = 0;
  const result = runProductionPreflightCli(["--identity", "release-deployer", "--output", path.join(directory, "release.json"), "--administrator-report", adminPath, "--administrator-report-signature", signaturePath], {
    caller: () => caller, verify: () => true,
    releasePreflight: () => ({ requiredReads: { "ecs:DescribeClusters": "denied" }, failed: [{ action: "ecs:DescribeClusters" }], skipped: [], status: "blocked" }),
    continueReadiness: () => { continued += 1; },
  });
  assert.equal(result.status, "blocked"); assert.equal(continued, 0); assert.equal(result.backendReady, false);
});
