import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import crypto from "node:crypto";
import {
  RELEASE_READ_PROBES,
  readIdentityCapabilityMatrix,
  runReleaseReadPreflight,
} from "../aws/production-green-stage-b-identity-capabilities.mjs";
import { assertStageBAwsCallCoverage, assertStageBDeploymentCapabilityGraph, buildStageBDeploymentCapabilityGraph } from "../aws/generate-production-green-stage-b-capability-graph.mjs";
import { canonicalizeJson, PERMISSION_REPORT_HASH_DOMAIN, PERMISSION_REPORT_SIGNATURE_SCHEMA_VERSION, sourcePolicyEvidence } from "../aws/validate-production-green-stage-b-permissions.mjs";
import { runProductionPreflightCli } from "../aws/run-production-green-stage-b-preflight.mjs";

const caller = "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test";
const shapedPolicyEvidence = () => {
  const policies = sourcePolicyEvidence().map((policy) => ({ ...policy, defaultVersionId: "v1", liveSha256: policy.sourceSha256, attached: true, matchesSource: true }));
  return { roleArn: "arn:aws:iam::368992683803:role/mscqr-production-release-deployer", attachedPolicyArns: policies.map(({ arn }) => arn).sort(), inlinePolicyNames: [], inlinePolicies: [], permissionsBoundaryArn: null, policies, status: "valid" };
};
const temp = () => fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-release-preflight-test-"));
const allowed = (args) => {
  if (args[0] === "sts") return JSON.stringify({ Arn: caller });
  if (args[0] === "s3api" && args[1] === "get-object") {
    fs.writeFileSync(args.at(-1), JSON.stringify({ lineage: "fixture", serial: 1 }), { mode: 0o644 });
    return "";
  }
  if (args[0] === "ecs" && args[1] === "list-services") return JSON.stringify({ serviceArns: ["arn:aws:ecs:eu-west-2:368992683803:service/mscqr-prod-euw2-main/frontend"] });
  if (args[0] === "ecs" && args[1] === "list-tasks") return JSON.stringify({ taskArns: ["arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/abc"] });
  if (args[0] === "iam" && args[1] === "get-policy") return JSON.stringify({ Policy: { DefaultVersionId: "v1" } });
  if (args[0] === "iam" && args[1] === "list-role-policies") return JSON.stringify({ PolicyNames: ["inline"] });
  return "{}";
};

test("identity matrix assigns IAM simulation only to administrator", () => {
  const matrix = readIdentityCapabilityMatrix();
  assert(matrix.calls.some(({ identity, action }) => identity === "ADMINISTRATOR" && action === "iam:SimulatePrincipalPolicy"));
  assert(!matrix.calls.some(({ identity, action }) => identity === "RELEASE_DEPLOYER" && action === "iam:SimulatePrincipalPolicy"));
  assert.equal(matrix.phases.length, 31);
});

test("generated capability graph is exhaustive, deterministic, and identity-exact", () => {
  const first = buildStageBDeploymentCapabilityGraph(); const second = buildStageBDeploymentCapabilityGraph();
  assert.deepEqual(first, second);
  assert.deepEqual(assertStageBDeploymentCapabilityGraph(first), { phases: 31, capabilities: 111, uniqueActions: 78, unmappedCalls: 0, unclassifiedCapabilities: 0, identityBoundaryViolations: 0, sourcePolicyMismatches: 0, manifestMismatches: 0, configurationContradictions: 0 });
  assert(first.capabilities.every(({ identity }) => first.identities.includes(identity)));
  assert(first.capabilities.every(({ id }, index) => first.capabilities.findIndex((item) => item.id === id) === index));
});

test("unknown, removed, or identity-reassigned capabilities fail graph verification", () => {
  const unknown = buildStageBDeploymentCapabilityGraph(); unknown.capabilities.push({ ...unknown.capabilities[0], id: "unknown-call", action: "sns:Publish" });
  assert.throws(() => assertStageBDeploymentCapabilityGraph(unknown), /stale or incomplete/);
  const removed = buildStageBDeploymentCapabilityGraph(); removed.capabilities.pop();
  assert.throws(() => assertStageBDeploymentCapabilityGraph(removed), /stale or incomplete/);
  const reassigned = buildStageBDeploymentCapabilityGraph(); reassigned.capabilities.find(({ action }) => action === "iam:SimulatePrincipalPolicy").identity = "RELEASE_DEPLOYER";
  assert.throws(() => assertStageBDeploymentCapabilityGraph(reassigned), /stale or incomplete/);
});

test("a newly discovered AWS CLI action fails until it is classified", () => {
  assert.throws(() => assertStageBAwsCallCoverage(buildStageBDeploymentCapabilityGraph(), [{ sourceFile: "new-production-path.mjs", action: "sns:Publish" }]), /absent from capability graph/);
});

test("release probes cover policy-list access on both canary roles", () => {
  for (const role of ["mscqr-production-full-rls-green-read-only-canary-execution", "mscqr-production-full-rls-green-read-only-canary-task"]) {
    for (const operation of ["list-role-policies", "list-attached-role-policies"]) assert(RELEASE_READ_PROBES.some(({ args }) => args.includes(role) && args.includes(operation)));
  }
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
  const admin = runProductionPreflightCli(["--identity", "administrator", "--phase", "initial", "--output", adminPath, "--signature-output", signaturePath], {
    caller: () => "arn:aws:iam::368992683803:root",
    collectPolicies: shapedPolicyEvidence,
    permissionPreflight: (input) => { administratorSimulations += 1; return { schemaVersion: 1, evidenceKind: "INITIAL_ADMIN_CAPABILITY", phase: "initial", purpose: input.purpose, status: "valid", deniedCount: 0, simulatedRoleArn: input.simulatedRoleArn, generatedAt: input.generatedAt, policyEvidence: input.policyEvidence }; },
    sign: (report, { reportBytes }) => ({ schemaVersion: PERMISSION_REPORT_SIGNATURE_SCHEMA_VERSION, hashDomain: PERMISSION_REPORT_HASH_DOMAIN, canonicalPayloadSha256: crypto.createHash("sha256").update(Buffer.from(canonicalizeJson(report))).digest("hex"), reportFileSha256: crypto.createHash("sha256").update(reportBytes).digest("hex"), signedAt: report.generatedAt }),
  });
  assert.equal(admin.status, "valid"); assert.equal(administratorSimulations, 1);
  const releasePath = path.join(directory, "release.json"); let releaseReads = 0;
  const release = runProductionPreflightCli(["--identity", "release-deployer", "--output", releasePath, "--administrator-report", adminPath, "--administrator-report-signature", signaturePath], {
    caller: () => caller,
    verify: () => true,
    releasePreflight: () => { releaseReads += 1; return { schemaVersion: 1, caller, account: "368992683803", region: "eu-west-2", requiredReads: {}, failed: [], skipped: [], status: "valid" }; },
    continueReadiness: () => ({ backendReady: true, stateReady: true, handoffReady: true, tfvarsReady: true }), validateCapabilityGraph: () => admin.capabilityGraph,
  });
  assert.equal(release.status, "ready-for-plan"); assert.equal(releaseReads, 1);
});

test("invalid release capability report stops before backend readiness", () => {
  const directory = temp(); const adminPath = path.join(directory, "admin.json"); const signaturePath = path.join(directory, "signature.json");
  const capabilityGraph = assertStageBDeploymentCapabilityGraph();
  fs.writeFileSync(adminPath, JSON.stringify({ schemaVersion: 1, evidenceKind: "INITIAL_ADMIN_CAPABILITY", phase: "initial", purpose: "pre-plan-capability", status: "valid", simulatedRoleArn: "arn:aws:iam::368992683803:role/mscqr-production-release-deployer", policyEvidence: shapedPolicyEvidence(), capabilityGraph }));
  fs.writeFileSync(signaturePath, "{}"); let continued = 0;
  const result = runProductionPreflightCli(["--identity", "release-deployer", "--output", path.join(directory, "release.json"), "--administrator-report", adminPath, "--administrator-report-signature", signaturePath], {
    caller: () => caller, verify: () => true,
    releasePreflight: () => ({ requiredReads: { "ecs:DescribeClusters": "denied" }, failed: [{ action: "ecs:DescribeClusters" }], skipped: [], status: "blocked" }),
    continueReadiness: () => { continued += 1; }, validateCapabilityGraph: () => capabilityGraph,
  });
  assert.equal(result.status, "blocked"); assert.equal(continued, 0); assert.equal(result.backendReady, false);
});
