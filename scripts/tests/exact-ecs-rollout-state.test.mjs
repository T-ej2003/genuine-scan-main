import assert from "node:assert/strict";
import test from "node:test";
import {
  MAX_ROLLOUT_WAIT_MS,
  ROLLOUT_POLL_INTERVAL_MS,
  classifyExactEcsRollout,
  waitForExactEcsRollout,
} from "../aws/exact-ecs-rollout-state.mjs";

const region = "eu-west-2";
const account = "368992683803";
const cluster = "mscqr-prod-euw2-main";
const service = "mscqr-backend-servi-euw2";
const taskDefinition = `arn:aws:ecs:${region}:${account}:task-definition/mscqr-production-rls-green-backend-candidate:18`;

function response(rolloutState = "IN_PROGRESS") {
  return { failures: [], services: [{
    serviceName: service,
    serviceArn: `arn:aws:ecs:${region}:${account}:service/${cluster}/${service}`,
    clusterArn: `arn:aws:ecs:${region}:${account}:cluster/${cluster}`,
    status: "ACTIVE",
    taskDefinition,
    desiredCount: 2,
    runningCount: 2,
    pendingCount: 0,
    deployments: [{ status: "PRIMARY", taskDefinition, desiredCount: 2, runningCount: 2, pendingCount: 0, rolloutState }],
  }] };
}

function run({ states = ["IN_PROGRESS", "COMPLETED"], describeTimes = [], classifyTimes = [], start = 0, maxWaitMs = MAX_ROLLOUT_WAIT_MS } = {}, metrics = {}) {
  let clock = start;
  let calls = 0;
  const sleeps = [];
  const callBudgets = [];
  const result = waitForExactEcsRollout({
    expectedTaskDefinitionArn: taskDefinition,
    expectedClusterName: cluster,
    expectedServiceName: service,
    expectedDesiredCount: 2,
    maxWaitMs,
    monotonicNow: () => clock,
    describeServices: ({ timeoutMs }) => {
      callBudgets.push(timeoutMs);
      clock += describeTimes[calls] || 0;
      const value = response(states[Math.min(calls++, states.length - 1)]);
      Object.assign(metrics, { calls, callBudgets: [...callBudgets], clock });
      return value;
    },
    classify: (input) => {
      clock += classifyTimes[calls - 1] || 0;
      return classifyExactEcsRollout(input);
    },
    sleep: (milliseconds) => { sleeps.push(milliseconds); clock += milliseconds; Object.assign(metrics, { sleeps: [...sleeps], clock }); },
  });
  return { result, calls, sleeps, callBudgets, clock };
}

test("monotonic deadline permits IN_PROGRESS then COMPLETED before the deadline", () => {
  const observed = run();
  assert.equal(observed.result, "SUCCESS");
  assert.deepEqual(observed.sleeps, [ROLLOUT_POLL_INTERVAL_MS]);
});

test("DescribeServices and classifier latency consume the total rollout budget", () => {
  const describeMetrics = {};
  assert.throws(() => run({ states: ["IN_PROGRESS"], describeTimes: [590_000] }, describeMetrics), /beyond 600 seconds/);
  assert.deepEqual(describeMetrics, { calls: 1, callBudgets: [600_000], clock: 600_000, sleeps: [10_000] });
  const classifyMetrics = {};
  assert.throws(() => run({ states: ["IN_PROGRESS"], classifyTimes: [600_000] }, classifyMetrics), /beyond 600 seconds/);
  assert.equal(classifyMetrics.calls, 1);
});

test("sleep is clamped to the remaining deadline and no extra AWS call starts at the boundary", () => {
  let clock = 0;
  let calls = 0;
  const sleeps = [];
  assert.throws(() => waitForExactEcsRollout({
    expectedTaskDefinitionArn: taskDefinition,
    expectedClusterName: cluster,
    expectedServiceName: service,
    expectedDesiredCount: 2,
    maxWaitMs: 20_000,
    monotonicNow: () => clock,
    describeServices: () => { calls += 1; clock += 12_000; return response(); },
    sleep: (milliseconds) => { sleeps.push(milliseconds); clock += milliseconds; },
  }), /beyond 20 seconds/);
  assert.deepEqual(sleeps, [8_000]);
  assert.equal(calls, 1);
});

test("DescribeServices failure is immediate and never becomes CONTINUE", () => {
  let slept = false;
  assert.throws(() => waitForExactEcsRollout({
    expectedTaskDefinitionArn: taskDefinition,
    expectedClusterName: cluster,
    expectedServiceName: service,
    expectedDesiredCount: 2,
    monotonicNow: () => 0,
    describeServices: () => { throw new Error("AWS timeout"); },
    sleep: () => { slept = true; },
  }), /AWS timeout/);
  assert.equal(slept, false);
});

test("COMPLETED just before the deadline succeeds while IN_PROGRESS at the deadline times out", () => {
  assert.equal(run({ states: ["COMPLETED"], describeTimes: [MAX_ROLLOUT_WAIT_MS - 1] }).result, "SUCCESS");
  assert.throws(() => run({ states: ["IN_PROGRESS"], describeTimes: [MAX_ROLLOUT_WAIT_MS] }), /beyond 600 seconds/);
});

test("malformed or regressing monotonic clocks fail closed", () => {
  for (const values of [[Number.NaN], [10, 9]]) {
    let index = 0;
    assert.throws(() => waitForExactEcsRollout({
      expectedTaskDefinitionArn: taskDefinition,
      expectedClusterName: cluster,
      expectedServiceName: service,
      expectedDesiredCount: 2,
      monotonicNow: () => values[Math.min(index++, values.length - 1)],
      describeServices: () => response(),
      sleep: () => {},
    }), /monotonic clock/);
  }
});
