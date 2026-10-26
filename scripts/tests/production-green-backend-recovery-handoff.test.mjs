import assert from "node:assert/strict";
import test from "node:test";
import { prepareGreenRecoveryHandoff, assertGreenRecoveryHandoff } from "../aws/production-green-backend-recovery-handoff.mjs";
import { assertGreenRecoveryAlbTargets, assertNormalDeployerUpdateAuthority, collectCurrentGreenRecoveryRuntimeIdentity,
  runGreenRecoveryCommand, waitForGreenBackendService } from "../aws/recover-production-green-backend-health.mjs";
import { APP_ONLY } from "../aws/production-app-only-contract.mjs";
import { PRODUCTION_CLIENT_IP_TRUST } from "../aws/production-client-ip-trust-runtime.mjs";

const now = Date.parse("2026-10-25T20:00:00.000Z");
const input = { sourceSha: "a".repeat(40), taskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:24",
  recoveryImageDigest: `sha256:${"b".repeat(64)}`, candidateFingerprint: "c".repeat(64), deploymentId: "ecs-svc/1",
  serviceConfigurationSha256: "d".repeat(64), runtimeConsumabilitySha256: "e".repeat(64),
  approval: { ticket: "CHG-20261025-007", authorizationSha256: "f".repeat(64) },
  environmentApproval: { evidenceSha256: "1".repeat(64) }, imageAuthorization: { evidenceSha256: "2".repeat(64) },
  databaseCompatibility: { resultSha256: "3".repeat(64) } };
const componentState = { generation: 1, components: { backend: { taskDefinitionArn: input.taskDefinitionArn } } };
const githubContext = { repository: "T-ej2003/genuine-scan-main", workflowRunId: "123", workflowRunAttempt: "1" };
const context = { input, componentState, githubContext, operationId: "4".repeat(64),
  registeredTaskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:35", now };

test("handoff binds source, ticket, digest, predecessor, component state and exact run", () => {
  const handoff = prepareGreenRecoveryHandoff({ ...context, livePolicyIdentity: { task: "5".repeat(64) } });
  assert.equal(assertGreenRecoveryHandoff(handoff, context), handoff);
  for (const changed of [
    { input: { ...input, sourceSha: "6".repeat(40) } },
    { input: { ...input, recoveryImageDigest: `sha256:${"7".repeat(64)}` } },
    { input: { ...input, approval: { ...input.approval, ticket: "CHG-OTHER" } } },
    { input: { ...input, deploymentId: "ecs-svc/2" } },
    { input: { ...input, serviceConfigurationSha256: "8".repeat(64) } },
    { componentState: { ...componentState, generation: 2 } },
    { githubContext: { ...githubContext, workflowRunAttempt: "2" } },
    { registeredTaskDefinitionArn: context.registeredTaskDefinitionArn.replace(":35", ":36") },
  ]) assert.throws(() => assertGreenRecoveryHandoff(handoff, { ...context, ...changed }));
  assert.throws(() => assertGreenRecoveryHandoff({ ...handoff, ticket: "forged" }, context));
  assert.throws(() => assertGreenRecoveryHandoff(handoff, { ...context, now: now + 10 * 60_000 + 1 }), /stale/);
  assert.throws(() => assertGreenRecoveryHandoff(handoff, { ...context, now: now - 1 }), /stale/);
});

test("normal execution re-reads runtime IAM after approval and before dispatch", async () => {
  const candidate = { executionRoleArn: APP_ONLY.executionRoleArn, taskRoleArn: APP_ONLY.taskRoleArn,
    containerDefinitions: [{ name: "backend", image: `${APP_ONLY.backendRepository}@${input.recoveryImageDigest}` }] };
  const prepared = { identitySha256: "a".repeat(64) };
  const aws = () => { throw new Error("unexpected AWS call"); };
  const collect = async (principals) => { assert.deepEqual([...new Set(principals)], [APP_ONLY.executionRoleArn]); return prepared; };
  assert.deepEqual(await collectCurrentGreenRecoveryRuntimeIdentity(candidate, aws, prepared, collect), prepared);
  await assert.rejects(() => collectCurrentGreenRecoveryRuntimeIdentity(candidate, aws, prepared,
    async () => ({ identitySha256: "b".repeat(64) })), /changed after preparation/);
  let calls = 0;
  await assert.rejects(() => collectCurrentGreenRecoveryRuntimeIdentity(candidate, aws, prepared,
    async () => (++calls === 1 ? prepared : { identitySha256: "c".repeat(64) })), /changed during recovery/);
  await assert.rejects(() => collectCurrentGreenRecoveryRuntimeIdentity(candidate, aws, prepared,
    async () => { throw new Error("IAM read denied"); }), /IAM read denied/);
});

test("normal execution simulates its exact service update before claiming dispatch", () => {
  const target = context.registeredTaskDefinitionArn;
  const allowed = { EvaluationResults: [{ EvalActionName: "ecs:UpdateService", EvalResourceName: APP_ONLY.serviceArn,
    EvalDecision: "allowed", MissingContextValues: [], OrganizationsDecisionDetail: { AllowedByOrganizations: true } }] };
  assert.equal(assertNormalDeployerUpdateAuthority(target, (args) => {
    assert.ok(args.some((arg) => arg.includes(target)));
    assert.ok(args.includes(APP_ONLY.serviceArn));
    assert.ok(args.includes(`ContextKeyName=ecs:cluster,ContextKeyValues=${APP_ONLY.clusterArn},ContextKeyType=string`));
    return allowed;
  }), true);
  for (const result of [
    { ...allowed.EvaluationResults[0], EvalDecision: "implicitDeny" },
    { ...allowed.EvaluationResults[0], MissingContextValues: ["ecs:task-definition"] },
    { ...allowed.EvaluationResults[0], OrganizationsDecisionDetail: { AllowedByOrganizations: false } },
    { ...allowed.EvaluationResults[0], EvalResourceName: "arn:aws:ecs:eu-west-2:368992683803:service/other" },
    { ...allowed.EvaluationResults[0], ResourceSpecificResults: [{ EvalResourceName: APP_ONLY.serviceArn, EvalResourceDecision: "explicitDeny" }] },
  ]) assert.throws(() => assertNormalDeployerUpdateAuthority(target, () => ({ EvaluationResults: [result] })));
  assert.throws(() => assertNormalDeployerUpdateAuthority(target, () => ({ ...allowed, IsTruncated: true })));
  assert.throws(() => assertNormalDeployerUpdateAuthority(target.replace(":35", ":wrong"), () => allowed));
});

test("recovered ECS tasks must each own a healthy target in the exact backend ALB group", () => {
  const live = { service: { loadBalancers: [{ targetGroupArn: PRODUCTION_CLIENT_IP_TRUST.targetGroupArn,
    containerName: "backend", containerPort: 4000 }] }, tasks: ["10.0.0.1", "10.0.0.2"].map((value) => ({
    attachments: [{ details: [{ name: "privateIPv4Address", value }] }] })) };
  const response = { TargetHealthDescriptions: live.tasks.map((task) => ({ Target: {
    Id: task.attachments[0].details[0].value, Port: 4000 }, TargetHealth: { State: "healthy" } })) };
  assert.equal(assertGreenRecoveryAlbTargets(live, response), true);
  for (const changed of [
    { ...response, TargetHealthDescriptions: response.TargetHealthDescriptions.slice(0, 1) },
    { ...response, TargetHealthDescriptions: response.TargetHealthDescriptions.map((target) => ({ ...target, TargetHealth: { State: "unhealthy" } })) },
  ]) assert.throws(() => assertGreenRecoveryAlbTargets(live, changed));
  assert.throws(() => assertGreenRecoveryAlbTargets({ ...live, service: { loadBalancers: [] } }, response));
});

test("green recovery classifies AWS timeouts without retrying or exposing command arguments", () => {
  const target = context.registeredTaskDefinitionArn;
  let calls = 0;
  const execute = (_command, _args, options) => {
    calls++;
    assert.equal(options.timeout, 120_000);
    assert.equal(options.env.AWS_MAX_ATTEMPTS, "1");
    const error = new Error("spawnSync aws ETIMEDOUT"); error.code = "ETIMEDOUT"; throw error;
  };
  assert.throws(() => runGreenRecoveryCommand("aws", ["ecs", "update-service", "--task-definition", target],
    { execute, environment: {}, singleAttempt: true }), (error) => {
    assert.equal(error.code, "ETIMEDOUT");
    assert.match(error.message, /ecs update-service timed out after 120s; mutation outcome unknown/);
    assert.ok(!error.message.includes(target));
    return true;
  });
  assert.equal(calls, 1);
  assert.equal(runGreenRecoveryCommand("aws", ["ecs", "describe-services"], {
    execute: (_command, _args, options) => { assert.equal(options.env.AWS_MAX_ATTEMPTS, undefined); return "slow read succeeded"; },
    environment: {},
  }), "slow read succeeded");
});

test("green recovery waits for native ECS convergence beyond the former two-minute subprocess limit", async () => {
  let time = 0, reads = 0;
  const targetArn = context.registeredTaskDefinitionArn;
  const result = await waitForGreenBackendService({ targetArn, now: () => time,
    delay: async (ms) => { time += ms; }, readService: () => {
      reads++;
      if (reads === 2) { const error = new Error("slow read"); error.code = "ETIMEDOUT"; throw error; }
      const ready = time >= 4 * 60_000;
      return { status: "ACTIVE", taskDefinition: targetArn, desiredCount: 2,
        runningCount: ready ? 2 : 0, pendingCount: ready ? 0 : 2,
        deployments: [{ status: "PRIMARY", taskDefinition: reads === 1 ? input.taskDefinitionArn : targetArn,
          rolloutState: ready ? "COMPLETED" : "IN_PROGRESS" }] };
    } });
  assert.equal(result.runningCount, 2);
  assert.ok(time >= 4 * 60_000 && reads > 2);
});

test("green recovery stops on competing deployment, failed rollout, and bounded stabilization expiry", async () => {
  const targetArn = context.registeredTaskDefinitionArn;
  const service = { status: "ACTIVE", taskDefinition: targetArn, desiredCount: 2,
    runningCount: 0, pendingCount: 2, deployments: [{ status: "PRIMARY", taskDefinition: targetArn, rolloutState: "IN_PROGRESS" }] };
  await assert.rejects(waitForGreenBackendService({ targetArn, readService: () => ({ ...service, taskDefinition: input.taskDefinitionArn }) }), /Competing ECS deployment/);
  await assert.rejects(waitForGreenBackendService({ targetArn, readService: () => ({ ...service,
    deployments: [{ ...service.deployments[0], rolloutState: "FAILED" }] }) }), /rollout failed/);
  let time = 0;
  await assert.rejects(waitForGreenBackendService({ targetArn, now: () => time,
    delay: async (ms) => { time += ms; }, readService: () => service, timeoutMs: 30_000 }), /stabilization exceeded 30s/);
});
