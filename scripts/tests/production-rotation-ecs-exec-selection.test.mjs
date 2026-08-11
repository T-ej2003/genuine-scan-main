import assert from "node:assert/strict";
import test from "node:test";
import { requireExecuteCommandEnabled, revalidateExactTargetTask, selectTargetTask } from "../aws/ecs-exec-target-selection.mjs";

const clusterArn = "arn:aws:ecs:eu-west-2:368992683803:cluster/mscqr-prod-euw2-main";
const definitionArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:8";
const digest = `sha256:${"a".repeat(64)}`;
const targetTag = { key: "MSCQRExecTarget", value: "production-backend" };
const task = (id, overrides = {}) => ({
  taskArn: `arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/${id}`,
  clusterArn,
  taskDefinitionArn: definitionArn,
  lastStatus: "RUNNING",
  group: "service:mscqr-backend-servi-euw2",
  containers: [{ name: "backend", imageDigest: digest }],
  healthStatus: "HEALTHY",
  tags: [targetTag],
  managedAgents: [{ name: "ExecuteCommandAgent", lastStatus: "RUNNING" }],
  ...overrides,
});
const select = (tasks) => selectTargetTask({ tasks, expectedClusterArn: clusterArn, expectedTaskDefinitionArn: definitionArn, expectedImageDigest: digest, serviceName: "mscqr-backend-servi-euw2", containerName: "backend", expectedTaskTagKey: "MSCQRExecTarget", expectedTaskTagValue: "production-backend" });

test("service ECS Exec must be explicitly enabled", () => {
  assert.equal(requireExecuteCommandEnabled({ enableExecuteCommand: true }), true);
  assert.throws(() => requireExecuteCommandEnabled({ enableExecuteCommand: false }), /disabled/);
});

test("zero matching tasks fails closed", () => assert.throws(() => select([]), /no running target task/));

test("one matching task passes", () => {
  const result = select([task("one")]);
  assert.equal(result.matchingTaskCount, 1);
  assert.match(result.selectedTask.taskArn, /\/one$/);
});

test("replacement backend task retains the actual task-tag boundary", () => {
  const replacement = task("replacement");
  const result = select([replacement]);
  assert.equal(result.matchingTaskCount, 1);
  assert.match(result.selectedTask.taskArn, /\/replacement$/);
  assert.equal(result.selectedTask.tags[0].value, "production-backend");
});

test("multiple valid tasks choose the lexicographically smallest ARN", () => {
  const result = select([task("z"), task("a")]);
  assert.equal(result.matchingTaskCount, 2);
  assert.match(result.selectedTask.taskArn, /\/a$/);
  assert.equal(select([task("a"), task("z")]).selectedTask.taskArn, result.selectedTask.taskArn);
});

test("wrong digest, old deployment, and disconnected agents are excluded", () => {
  const result = select([
    task("wrong-digest", { containers: [{ name: "backend", imageDigest: `sha256:${"b".repeat(64)}` }] }),
    task("old-definition", { taskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/old:1" }),
    task("disconnected", { managedAgents: [{ name: "ExecuteCommandAgent", lastStatus: "STOPPED" }] }),
    task("target"),
  ]);
  assert.equal(result.matchingTaskCount, 1);
  assert.match(result.selectedTask.taskArn, /\/target$/);
});

test("unapproved task identities and unhealthy tasks are excluded", () => {
  const result = select([
    task("worker", { tags: [{ key: "MSCQRExecTarget", value: "worker" }], containers: [{ name: "worker", imageDigest: digest }] }),
    task("missing-tag", { tags: [] }),
    task("unhealthy", { healthStatus: "UNHEALTHY" }),
    task("approved"),
  ]);
  assert.equal(result.matchingTaskCount, 1);
  assert.match(result.selectedTask.taskArn, /\/approved$/);
});

test("wrong container is excluded even when the task identity tag is approved", () => {
  assert.throws(() => select([task("wrong-container", { containers: [{ name: "worker", imageDigest: digest }] })]), /no running target task/);
});

test("final exact-ARN tag revalidation rejects a replacement or changed task", () => {
  const expected = { expectedClusterArn: clusterArn, expectedTaskDefinitionArn: definitionArn, expectedImageDigest: digest, serviceName: "mscqr-backend-servi-euw2", containerName: "backend", expectedTaskTagKey: "MSCQRExecTarget", expectedTaskTagValue: "production-backend" };
  const selected = selectTargetTask({ ...expected, tasks: [task("selected")] }).selectedTask;
  assert.equal(revalidateExactTargetTask({ ...expected, selectedTaskArn: selected.taskArn, tasks: [selected] }).taskArn, selected.taskArn);
  assert.throws(() => revalidateExactTargetTask({ ...expected, selectedTaskArn: selected.taskArn, tasks: [{ ...selected, tags: [] }] }), /identity contract/);
  assert.throws(() => revalidateExactTargetTask({ ...expected, selectedTaskArn: selected.taskArn, tasks: [{ ...selected, taskArn: `${selected.taskArn}-other` }] }), /changed/);
});
