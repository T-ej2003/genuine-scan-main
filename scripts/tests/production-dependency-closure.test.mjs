import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { CAPABILITY_GRAPH_PATH, discoverAwsCliActions } from "../aws/generate-production-green-stage-b-capability-graph.mjs";
import { assertChangedAwsCallClosure, assertNoUnknownRollbackDependency, assertRollbackSemanticBoundary, buildProductionDependencyClosure } from "../aws/verify-production-dependency-closure.mjs";

const graph = () => JSON.parse(fs.readFileSync(CAPABILITY_GRAPH_PATH, "utf8"));

test("complete production dependency closure is exact across modes and failure paths", () => {
  const report = buildProductionDependencyClosure();
  assert.equal(report.status, "PASS");
  assert.equal(report.newAwsCalls.length, 13);
  assert.deepEqual(new Set(Object.values(report.modes)), new Set(["PASS"]));
  assert.deepEqual(report.pathClosure, { forward: "PASS", rollback: "PASS", reconciliation: "PASS" });
  assert.deepEqual(new Set(Object.values(report.counters)), new Set([0]));
});

test("unknown AWS calls and incomplete exact call classifications fail CI", () => {
  const calls = discoverAwsCliActions();
  const current = graph();
  assert.throws(() => assertChangedAwsCallClosure([...calls, { sourceFile: "scripts/aws/production-ecs-rollback-viability.mjs", action: "ecs:DeleteService" }], current), /Unknown production AWS call/);
  assert.throws(() => assertChangedAwsCallClosure(calls.filter(({ sourceFile, action }) => !(sourceFile.endsWith("production-ecs-rollback-viability.mjs") && action === "ecs:DescribeServiceRevisions")), current), /Changed production AWS calls/);
  for (const change of [
    (capability) => { capability.identity = "ADMINISTRATOR"; },
    (capability) => { capability.resources = ["*"]; },
    (capability) => { capability.probeIds = []; },
  ]) {
    const changed = structuredClone(current);
    change(changed.capabilities.find(({ id }) => id === "manifest-backend-health-recovery-describe-service-revisions"));
    assert.throws(() => assertChangedAwsCallClosure(calls, changed), /lacks exact IAM\/capability\/preflight closure/);
  }
});

test("documented ECS response shape is represented by the real service-revision boundary", () => {
  const source = fs.readFileSync("scripts/aws/production-ecs-rollback-viability.mjs", "utf8");
  assert.match(source, /targetServiceRevision\?\.arn/);
  assert.match(source, /rollback\?\.serviceRevisionArn/);
  assert.match(source, /sourceServiceRevisions/);
  assert.match(source, /describe-service-revisions/);
  assert.match(source, /serviceRevisions/);
  assert.match(source, /revision\?\.taskDefinition/);
  assert.doesNotMatch(source, /targetServiceRevision\?\.taskDefinition/);
  assert.equal(assertRollbackSemanticBoundary(source), true);
  assert.throws(() => assertRollbackSemanticBoundary(source.replaceAll("deployment?.rollback?.serviceRevisionArn", "deployment?.targetServiceRevision?.arn")), /semantic boundary|never derive/);
});

test("unknown runtime dependencies fail CI", () => {
  const source = fs.readFileSync("scripts/aws/production-ecs-rollback-viability.mjs", "utf8");
  assert.equal(assertNoUnknownRollbackDependency(source), true);
  assert.throws(() => assertNoUnknownRollbackDependency(`${source}\nconst endpoint = process.env.ARBITRARY_ENDPOINT;`), /unclassified environment dependency/);
  assert.throws(() => assertNoUnknownRollbackDependency(`${source}\nimport client from "imagined-aws-client";`), /undeclared external Node dependency/);
});

test("rotation closure cannot borrow legacy backend recovery mutation authority", () => {
  const source = fs.readFileSync("scripts/aws/verify-production-dependency-closure.mjs", "utf8");
  for (const mode of ["ROTATION_OVERLAP", "ROTATION_CLEANUP"]) {
    const capabilityList = source.match(new RegExp(`${mode}: \\[([^\\n]+)\\]`))?.[1] || "";
    assert.match(capabilityList, /manifest-activate-exact-ecs-service/);
    assert.match(capabilityList, /manifest-rollback-exact-ecs-service/);
    assert.doesNotMatch(capabilityList, /manifest-backend-health-recovery-update-service/);
  }
});
