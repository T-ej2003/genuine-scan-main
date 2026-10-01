import assert from "node:assert/strict";
import test from "node:test";
import { persistVictoriaRecoveryCleanup, stopVictoriaRecoveryTasks, victoriaRecoveryIngressRules } from "../../infra/aws/terraform/lambda/victoria-recovery-broker/task-cleanup.mjs";

const cluster = "arn:aws:ecs:eu-west-2:368992683803:cluster/production";
const nonce = "123e4567-e89b-42d3-a456-426614174000", sourceSha = "a".repeat(40);
const arn = (id) => `${cluster.replace(":cluster/", ":task/")}/${id}`;
const databaseSecurityGroup = "sg-database", recoverySecurityGroup = "sg-recovery";
const ingress = (id, values = {}) => ({ SecurityGroupRuleId: id, GroupId: databaseSecurityGroup, IsEgress: false,
  IpProtocol: "tcp", FromPort: 5432, ToPort: 5432, ReferencedGroupInfo: { GroupId: recoverySecurityGroup },
  Tags: Object.entries({ Operation: "VICTORIA_FAILED_ONBOARDING_RECOVERY_V1", Target: "victoria@mscqr.com",
    AuthorizationNonce: nonce, SourceSha: sourceSha, ...values }).map(([Key, Value]) => ({ Key, Value })) });
const task = (id, changes = {}) => ({ taskArn: arn(id), clusterArn: cluster, group: "family:mscqr-production-victoria-recovery",
  startedBy: nonce, lastStatus: "RUNNING", tags: ["Operation", "AuthorizationNonce", "SourceSha"].map((key, i) =>
    ({ key, value: ["VICTORIA_FAILED_ONBOARDING_RECOVERY_V1", nonce, sourceSha][i] })), ...changes });

async function execute(tasks, { listed = tasks.map(({ taskArn }) => taskArn), listError, describeError, stopError, noTaskLaunchProven = false } = {}) {
  const calls = [];
  const result = await stopVictoriaRecoveryTasks({ cluster, nonce, sourceSha, knownTaskArns: [], noTaskLaunchProven,
    listTasks: async (input) => { calls.push(["list", input]); if (listError) throw listError; return { taskArns: listed }; },
    describeTasks: async (input) => { calls.push(["describe", input]); if (describeError) throw describeError; return { tasks }; },
    stopTask: async (input) => { calls.push(["stop", input]); if (stopError) throw stopError; },
    waitStopped: async (taskArn) => { calls.push(["wait", taskArn]); return true; },
  });
  return { result, calls };
}

test("PENDING and RUNNING matching tasks are stopped, scoped to the cluster with startedBy as the sole task filter", async () => {
  for (const status of ["PENDING", "RUNNING"]) {
    const fixture = task(status.toLowerCase(), { lastStatus: status });
    const { result, calls } = await execute([fixture]);
    assert.deepEqual(calls[0], ["list", { cluster, startedBy: nonce }]);
    assert.deepEqual(result, { taskStopped: true, taskCleanupFailed: false, stoppedTaskCount: 1 });
    assert.equal(calls.filter(([kind]) => kind === "stop").length, 1);
  }
});

test("STOPPED task is verified without StopTask", async () => {
  const { result, calls } = await execute([task("stopped", { lastStatus: "STOPPED" })]);
  assert.equal(result.taskStopped, true);
  assert.equal(calls.some(([kind]) => kind === "stop"), false);
});

test("unrelated and wrong-family tasks are never stopped", async () => {
  for (const fixture of [task("unrelated", { startedBy: "other" }), task("wrong-family", { group: "family:other" })]) {
    const { result, calls } = await execute([fixture]);
    assert.equal(result.taskStopped, false);
    assert.equal(calls.some(([kind]) => kind === "stop"), false);
  }
});

test("multiple returned tasks are all inspected, valid tasks stopped, and anomaly recorded", async () => {
  const fixtures = [task("one"), task("two")];
  const { result, calls } = await execute(fixtures);
  assert.equal(calls.filter(([kind]) => kind === "stop").length, 2);
  assert.equal(result.taskStopped, false);
  assert.equal(result.taskCleanupFailed, true);
});

test("empty result succeeds only with a durable no-launch receipt", async () => {
  const { result, calls } = await execute([], { listed: [], noTaskLaunchProven: true });
  assert.deepEqual(result, { taskStopped: true, taskCleanupFailed: false, stoppedTaskCount: 0 });
  assert.equal(calls.some(([kind]) => kind === "stop"), false);
  assert.deepEqual((await execute([], { listed: [] })).result,
    { taskStopped: false, taskCleanupFailed: true, stoppedTaskCount: 0 });
});

test("ListTasks and DescribeTasks errors fail closed", async () => {
  assert.equal((await execute([], { listError: Error("list") })).result.taskStopped, false);
  assert.equal((await execute([task("describe")], { describeError: Error("describe") })).result.taskStopped, false);
});

test("StopTask failure is accepted only when the exact task is subsequently proven stopped", async () => {
  const fixture = task("stop-error");
  const calls = [];
  const result = await stopVictoriaRecoveryTasks({ cluster, nonce, sourceSha, listTasks: async () => ({ taskArns: [fixture.taskArn] }),
    describeTasks: async () => ({ tasks: [fixture] }), stopTask: async () => { throw Error("stop"); },
    waitStopped: async (taskArn) => { calls.push(taskArn); return true; } });
  assert.equal(result.taskStopped, true);
  assert.deepEqual(calls, [fixture.taskArn]);
});

test("cleanup failure evidence is persisted before failure is surfaced", async () => {
  let persisted;
  await assert.rejects(() => persistVictoriaRecoveryCleanup({
    receipt: { networkAuthorityRevoked: true, taskStopped: false },
    putEvidence: async (receipt) => { persisted = receipt; },
  }), /RECOVERY_CLEANUP_INCOMPLETE_EVIDENCE_PERSISTED/);
  assert.deepEqual(persisted, { networkAuthorityRevoked: true, taskStopped: false });
});

test("late cleanup selects only the exact authorization attempt ingress", () => {
  const nonceB = "123e4567-e89b-42d3-a456-426614174001";
  const attemptA = ingress("sgr-a");
  const attemptB = ingress("sgr-b", { AuthorizationNonce: nonceB });
  const unrelated = [
    ingress("sgr-wrong-source", { SourceSha: "b".repeat(40) }),
    ingress("sgr-wrong-operation", { Operation: "OTHER" }),
    { ...ingress("sgr-untagged"), Tags: [] },
    { ...ingress("sgr-other-port"), FromPort: 443, ToPort: 443 },
    { ...ingress("sgr-other-group"), ReferencedGroupInfo: { GroupId: "sg-other" } },
  ];
  const rules = [attemptA, attemptB, ...unrelated];
  const select = (attemptNonce, attemptSourceSha = sourceSha) => victoriaRecoveryIngressRules(rules, {
    databaseSecurityGroup, recoverySecurityGroup, nonce: attemptNonce, sourceSha: attemptSourceSha,
  }).map(({ SecurityGroupRuleId }) => SecurityGroupRuleId);
  assert.deepEqual(select(nonce), ["sgr-a"]);
  assert.deepEqual(select(nonceB), ["sgr-b"]);
  assert.deepEqual(select("123e4567-e89b-42d3-a456-426614174002"), []);
  assert.deepEqual(select(nonce, "c".repeat(40)), []);
});

test("attempt A cleanup cannot revoke attempt B ingress", () => {
  const nonceB = "123e4567-e89b-42d3-a456-426614174001";
  let rules = [ingress("sgr-a"), ingress("sgr-b", { AuthorizationNonce: nonceB })];
  const revoke = (attemptNonce) => {
    const selected = victoriaRecoveryIngressRules(rules, { databaseSecurityGroup, recoverySecurityGroup,
      nonce: attemptNonce, sourceSha });
    rules = rules.filter((rule) => !selected.includes(rule));
  };
  revoke(nonce);
  assert.deepEqual(rules.map(({ SecurityGroupRuleId }) => SecurityGroupRuleId), ["sgr-b"]);
  revoke(nonceB);
  assert.deepEqual(rules, []);
});
