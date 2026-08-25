import assert from "node:assert/strict";
import test from "node:test";
import { collectEcsServiceTasks, collectEcsServiceTaskArns, ECS_TASK_CENSUS } from "../aws/production-ecs-task-census.mjs";

const cluster = "mscqr-prod-euw2-main"; const service = "mscqr-backend-servi-euw2";
const arn = (index) => `arn:aws:ecs:eu-west-2:368992683803:task/${cluster}/${index.toString(16).padStart(32, "0")}`;
const task = (taskArn) => ({ taskArn, taskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:49", desiredStatus: "STOPPED", lastStatus: "STOPPED", containers: [] });

function adapter(pages, { reverseDescribe = false, failBatch = -1 } = {}) {
  const calls = []; let page = 0; let batch = 0;
  return { calls, aws: async (args) => {
    calls.push(args);
    if (args[1] === "list-tasks") {
      assert.deepEqual(args.slice(2, 10), ["--cluster", cluster, "--service-name", service, "--desired-status", "STOPPED", "--page-size", "100"]);
      assert.equal(args[10], "--max-items"); assert.equal(args[11], "100");
      if (page) assert.deepEqual(args.slice(12), ["--starting-token", `token-${page}`]);
      return pages[page++];
    }
    if (args[1] === "describe-tasks") {
      const requested = args.slice(args.indexOf("--tasks") + 1); const tasks = requested.map(task);
      return { failures: batch++ === failBatch ? [{ arn: requested[0], reason: "MISSING" }] : [], tasks: reverseDescribe ? tasks.reverse() : tasks };
    }
    throw new Error(args.join(" "));
  } };
}

for (const count of [0, 1, 99, 100, 101, 200, 201]) test(`complete stopped-task census covers ${count} tasks`, async () => {
  const all = Array.from({ length: count }, (_, index) => arn(index + 1));
  const pages = [];
  for (let offset = 0; offset < Math.max(count, 1); offset += 100) pages.push({ taskArns: all.slice(offset, offset + 100), ...(offset + 100 < count ? { NextToken: `token-${pages.length + 1}` } : {}) });
  const fixture = adapter(pages, { reverseDescribe: true });
  const result = await collectEcsServiceTasks({ aws: fixture.aws, cluster, service, desiredStatus: "STOPPED" });
  assert.deepEqual(result.map(({ taskArn }) => taskArn), [...all].sort());
  assert.equal(fixture.calls.filter((args) => args[1] === "describe-tasks").length, Math.ceil(count / ECS_TASK_CENSUS.describeBatchSize));
});

test("duplicates across pages count once and task failures are page-position independent", async () => {
  const pageOne = Array.from({ length: 100 }, (_, index) => arn(index + 1)); const final = arn(101);
  const fixture = adapter([{ taskArns: pageOne, NextToken: "token-1" }, { taskArns: [pageOne[0], final] }]);
  const result = await collectEcsServiceTasks({ aws: fixture.aws, cluster, service, desiredStatus: "STOPPED" });
  assert.equal(result.length, 101); assert.equal(result.some(({ taskArn }) => taskArn === final), true);
  assert.equal(fixture.calls.filter((args) => args[1] === "describe-tasks").length, 2);
});

test("empty intermediate pages are consumed and token cycles fail closed", async () => {
  const valid = adapter([{ taskArns: [], NextToken: "token-1" }, { taskArns: [arn(1)] }]);
  assert.equal((await collectEcsServiceTaskArns({ aws: valid.aws, cluster, service, desiredStatus: "STOPPED" })).length, 1);
  for (const pages of [
    [{ taskArns: [], NextToken: "token-1" }, { taskArns: [], NextToken: "token-1" }],
    [{ taskArns: [], NextToken: "token-1" }, { taskArns: [], NextToken: "token-2" }, { taskArns: [], NextToken: "token-1" }],
    [{ taskArns: [], NextToken: "" }], [{ taskArns: [], NextToken: 1 }], [{ taskArns: [], nextToken: "wrong-shape" }],
  ]) await assert.rejects(() => collectEcsServiceTaskArns({ aws: adapter(pages).aws, cluster, service, desiredStatus: "STOPPED" }), /malformed|cyclic/);
});

test("later-page and describe-batch errors fail closed without prefix results", async () => {
  const later = adapter([{ taskArns: [arn(1)], NextToken: "token-1" }]);
  const aws = async (args) => args.includes("--starting-token") ? Promise.reject(new Error("AWS failure")) : later.aws(args);
  await assert.rejects(() => collectEcsServiceTaskArns({ aws, cluster, service, desiredStatus: "STOPPED" }), /AWS failure/);
  const all = Array.from({ length: 101 }, (_, index) => arn(index + 1)); const described = adapter([{ taskArns: all }], { failBatch: 1 });
  await assert.rejects(() => collectEcsServiceTasks({ aws: described.aws, cluster, service, desiredStatus: "STOPPED" }), /incomplete/);
});

test("bounded census rejects unbounded pages and malformed real response shapes", async () => {
  const pages = Array.from({ length: ECS_TASK_CENSUS.maxPages }, (_, index) => ({ taskArns: [], NextToken: `token-${index + 1}` }));
  await assert.rejects(() => collectEcsServiceTaskArns({ aws: adapter(pages).aws, cluster, service, desiredStatus: "STOPPED" }), /bounded page limit/);
  for (const page of [null, {}, { taskArns: "wrong" }, { taskArns: ["task-id-only"] }])
    await assert.rejects(() => collectEcsServiceTaskArns({ aws: async () => page, cluster, service, desiredStatus: "STOPPED" }), /malformed|invalid task ARN/);
});
