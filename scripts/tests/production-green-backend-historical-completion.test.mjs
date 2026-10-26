import assert from "node:assert/strict";
import test from "node:test";
import { APP_ONLY, appOnlyServiceConfigurationSha256 } from "../aws/production-app-only-contract.mjs";
import { completeHistoricalGreenBackendRecovery } from "../aws/production-green-backend-historical-completion.mjs";
import { assertHistoricalLiveService } from "../aws/complete-production-historical-green-backend-recovery.mjs";
import { canonicalSha256 } from "../aws/production-green-stage-b-contract.mjs";

const source = "a".repeat(40), imageDigest = `sha256:${"b".repeat(64)}`;
const oldTask = `arn:aws:ecs:${APP_ONLY.region}:${APP_ONLY.account}:task-definition/${APP_ONLY.family}:24`;
const targetTask = oldTask.replace(":24", ":37");
const operationId = canonicalSha256({ kind: "BACKEND_HEALTH_RECOVERY_GREEN_CANDIDATE", sourceSha: source,
  taskDefinitionArn: oldTask, imageDigest });
const eventId = "af14fafb-126c-468b-9dee-616c955a0f1b";
const dispatchAt = "2026-10-26T00:19:51Z";
const baseInput = { operationId, originalSourceSha: source, originalRunId: "40248378928", ticket: "CHG-20261025-008",
  originalTaskDefinitionArn: oldTask, targetTaskDefinitionArn: targetTask, imageDigest,
  cloudTrailEventId: eventId, expectedComponentGeneration: 1 };

function fixture() {
  const service = { serviceArn: APP_ONLY.serviceArn, clusterArn: APP_ONLY.clusterArn, serviceName: APP_ONLY.service,
    status: "ACTIVE", taskDefinition: targetTask, desiredCount: 2, runningCount: 2, pendingCount: 0,
    deployments: [{ id: "ecs-svc/101", status: "PRIMARY", taskDefinition: targetTask, rolloutState: "COMPLETED" }],
    networkConfiguration: {}, loadBalancers: [] };
  const failureProof = { desiredCount: 2 };
  const predecessor = { sourceSha: source, taskDefinitionArn: oldTask, recoveryImageDigest: imageDigest,
    failureProof, failureProofSha256: canonicalSha256(failureProof), candidateFingerprint: "c".repeat(64),
    serviceConfigurationSha256: appOnlyServiceConfigurationSha256(service) };
  const intent = { operationId, sourceSha: source, sourceTaskDefinitionArn: oldTask, targetTaskDefinitionArn: targetTask,
    imageDigest, candidateFingerprint: predecessor.candidateFingerprint,
    failureProofSha256: predecessor.failureProofSha256,
    serviceConfigurationSha256: predecessor.serviceConfigurationSha256 };
  const authSha = "d".repeat(64), registerAuthSha = "e".repeat(64);
  const dispatch = { ...intent, phase: "BACKEND:UPDATE", authorizationSha256: authSha };
  const registrationDispatch = { ...intent, phase: "BACKEND:REGISTER", authorizationSha256: registerAuthSha };
  const originalBackend = { taskDefinitionArn: oldTask, imageDigest: `sha256:${"1".repeat(64)}` };
  const handoffBody = { operationId, sourceSha: source, ticket: baseInput.ticket,
    registeredTaskDefinitionArn: targetTask, imageDigest, approvalSha256: authSha,
    componentGeneration: 1, componentBackendSha256: canonicalSha256(originalBackend),
    githubContext: { workflowRunId: baseInput.originalRunId } };
  const entries = new Map([
    ["BACKEND:PREDECESSOR", predecessor], ["BACKEND:REGISTER:DISPATCH", registrationDispatch],
    ["BACKEND:REGISTER:COMPLETED", { intent, taskDefinitionArn: targetTask }],
    ["BACKEND:UPDATE:INTENT", intent], ["BACKEND:UPDATE:DISPATCH", dispatch],
    [`BACKEND:AUTHORIZATION:BACKEND:UPDATE:${authSha}`, { phase: "BACKEND:UPDATE", input: { approval: { authorizationSha256: authSha, ticket: baseInput.ticket } }, githubContext: { workflowRunId: baseInput.originalRunId } }],
    [`BACKEND:AUTHORIZATION:BACKEND:REGISTER:${registerAuthSha}`, { phase: "BACKEND:REGISTER", input: { approval: { authorizationSha256: registerAuthSha, ticket: baseInput.ticket } }, githubContext: { workflowRunId: "40246529553" } }],
    [`BACKEND:HANDOFF:PREPARED:${authSha}`, { ...handoffBody, handoffSha256: canonicalSha256(handoffBody) }],
  ]);
  const state = { generation: 1, components: { backend: originalBackend } };
  let writes = 0, commits = 0, approvals = 0;
  const store = {
    readOperation: async (_id, phase) => structuredClone(entries.get(phase) || null),
    readOperationCommittedAt: async () => dispatchAt,
    writeOperation: async (_id, phase, value) => {
      if (entries.has(phase)) throw new Error("conflicting S3 completion");
      entries.set(phase, structuredClone(value)); writes++; return true;
    },
    claimOperation: () => { throw new Error("second dispatch claim forbidden"); },
  };
  const event = { eventID: eventId, eventName: "UpdateService", eventSource: "ecs.amazonaws.com", eventTime: "2026-10-26T00:19:53Z",
    awsRegion: APP_ONLY.region, recipientAccountId: APP_ONLY.account, userIdentity: { type: "AssumedRole",
      arn: `arn:aws:sts::${APP_ONLY.account}:assumed-role/mscqr-production-normal-deployer/GitHubActions` },
    requestParameters: { cluster: APP_ONLY.clusterArn, service: APP_ONLY.serviceArn, taskDefinition: targetTask },
    responseElements: { service: { serviceArn: APP_ONLY.serviceArn, taskDefinition: targetTask,
      desiredCount: 2, deployments: [{ id: "ecs-svc/101", taskDefinition: targetTask }] } } };
  const adapters = { store, verifyOriginalSource: async () => {}, verifyOriginalAuthorization: async () => {},
    verifyFreshApproval: async () => { approvals++; }, verifyRegisteredRevision: async () => {},
    readCloudTrailEvent: async () => structuredClone(event), readService: async () => structuredClone(service),
    verifyCurrent: async () => ({ healthy: true, dependencies: { database: "ready" } }),
    readComponentState: async () => structuredClone(state),
    commitComponentState: async (evidence) => {
      commits++;
      assert.ok(entries.has("BACKEND:UPDATE:COMPLETED") && entries.has("BACKEND:RECOVERY:COMPLETE"));
      state.generation = 2;
      state.components.backend = { taskDefinitionArn: targetTask, imageDigest, establishedThroughSha: source };
      state.completedEmergencyWork = { "backend-health-recovery": { sourceSha: source, evidenceSha256: evidence.evidenceSha256 } };
      return { state: structuredClone(state) };
    },
  };
  return { input: { ...baseInput }, adapters, entries, service, event, state,
    counts: () => ({ writes, commits, approvals }) };
}

test("historical completion adopts the claimed update and commits state without any ECS mutation", async () => {
  const run = fixture();
  const result = await completeHistoricalGreenBackendRecovery(run.input, run.adapters);
  assert.equal(result.componentState.generation, 2);
  assert.equal(result.taskDefinitionArn, targetTask);
  assert.equal(run.entries.get("BACKEND:UPDATE:COMPLETED").nativeResult.deploymentId, "ecs-svc/101");
  assert.equal(run.entries.get("BACKEND:RECOVERY:COMPLETE").completedAt.endsWith("Z"), true);
  assert.deepEqual(run.counts(), { writes: 2, commits: 1, approvals: run.counts().approvals });
  assert.ok(run.counts().approvals >= 3);
});

test("final native service guard rejects a competing deployment and configuration drift", () => {
  const run = fixture();
  const expected = { targetArn: targetTask, deploymentId: "ecs-svc/101",
    configurationSha256: run.entries.get("BACKEND:PREDECESSOR").serviceConfigurationSha256 };
  assert.equal(assertHistoricalLiveService(run.service, expected), expected.deploymentId);
  assert.throws(() => assertHistoricalLiveService({ ...run.service,
    deployments: [{ ...run.service.deployments[0], id: "ecs-svc/102" }] }, expected), /deployment changed/);
  assert.throws(() => assertHistoricalLiveService({ ...run.service, desiredCount: 1 }, expected));
  assert.throws(() => assertHistoricalLiveService({ ...run.service, networkConfiguration: { changed: true } }, expected));
});

for (const [name, change, expected] of [
  ["missing original dispatch", (run) => run.entries.delete("BACKEND:UPDATE:DISPATCH"), /lacks immutable/],
  ["wrong source ancestry", (run) => { run.adapters.verifyOriginalSource = async () => { throw new Error("not protected-main ancestry"); }; }, /ancestry/],
  ["invalid original authorization", (run) => { run.adapters.verifyOriginalAuthorization = async () => { throw new Error("invalid original authorization"); }; }, /authorization/],
  ["expired fresh approval", (run) => { run.adapters.verifyFreshApproval = async () => { throw new Error("approval expired"); }; }, /approval expired/],
  ["missing CloudTrail event", (run) => { run.adapters.readCloudTrailEvent = async () => null; }, /CloudTrail event ID/],
  ["unrelated CloudTrail target", (run) => { run.adapters.readCloudTrailEvent = async () => ({ ...run.event,
    requestParameters: { ...run.event.requestParameters, taskDefinition: oldTask } }); }, /CloudTrail task definition/],
  ["wrong CloudTrail principal", (run) => { run.adapters.readCloudTrailEvent = async () => ({ ...run.event,
    userIdentity: { ...run.event.userIdentity, arn: `arn:aws:sts::${APP_ONLY.account}:assumed-role/another-role/GitHubActions` } }); }, /match/],
  ["wrong live image", (run) => { run.adapters.verifyCurrent = async () => { throw new Error("digest changed"); }; }, /digest changed/],
  ["component generation drift", (run) => { run.state.generation = 3; }, /generation changed/],
  ["service drift", (run) => { run.service.taskDefinition = oldTask; }, /Live ECS task definition/],
]) test(`historical completion rejects ${name} before any S3 completion`, async () => {
  const run = fixture(); change(run);
  await assert.rejects(completeHistoricalGreenBackendRecovery(run.input, run.adapters), expected);
  assert.equal(run.counts().writes, 0);
  assert.equal(run.counts().commits, 0);
});

test("conflicting completion fails closed", async () => {
  const run = fixture(); run.entries.set("BACKEND:UPDATE:COMPLETED", { intent: { operationId: "f".repeat(64) } });
  await assert.rejects(completeHistoricalGreenBackendRecovery(run.input, run.adapters), /conflicts with durable history/);
  assert.equal(run.counts().commits, 0);
});

test("late handoff and unhealthy preexisting receipt fail closed", async () => {
  const late = fixture();
  late.adapters.store.readOperationCommittedAt = async (_id, phase) => phase.startsWith("BACKEND:HANDOFF:")
    ? "2026-10-26T00:30:00Z" : dispatchAt;
  await assert.rejects(completeHistoricalGreenBackendRecovery(late.input, late.adapters), /handoff was committed after/);
  assert.equal(late.counts().writes, 0);
  const bad = fixture();
  bad.entries.set("BACKEND:RECOVERY:COMPLETE", { ...bad.entries.get("BACKEND:UPDATE:INTENT"),
    taskDefinitionArn: targetTask, health: { healthy: false }, completedAt: "2026-10-26T00:30:00Z" });
  await assert.rejects(completeHistoricalGreenBackendRecovery(bad.input, bad.adapters), /true/);
  assert.equal(bad.counts().commits, 0);
});

test("substituted image, task definition or ticket cannot address the historical claim", async () => {
  for (const altered of [{ imageDigest: `sha256:${"f".repeat(64)}` },
    { targetTaskDefinitionArn: targetTask.replace(":37", ":38") }, { ticket: "CHG-OTHER" }]) {
    const run = fixture();
    await assert.rejects(completeHistoricalGreenBackendRecovery({ ...run.input, ...altered }, run.adapters));
    assert.equal(run.counts().writes, 0);
  }
});

test("health drift after journal completion stops before the component CAS", async () => {
  const run = fixture(), write = run.adapters.store.writeOperation;
  run.adapters.store.writeOperation = async (...args) => {
    const result = await write(...args);
    if (args[1] === "BACKEND:RECOVERY:COMPLETE") run.adapters.verifyCurrent = async () => { throw new Error("ALB health changed"); };
    return result;
  };
  await assert.rejects(completeHistoricalGreenBackendRecovery(run.input, run.adapters), /ALB health changed/);
  assert.equal(run.counts().writes, 2);
  assert.equal(run.counts().commits, 0);
});

test("lost S3 completion response is adopted without another dispatch", async () => {
  const run = fixture(), write = run.adapters.store.writeOperation;
  let lost = false;
  run.adapters.store.writeOperation = async (...args) => { await write(...args); if (!lost) { lost = true; throw new Error("S3 response lost"); } };
  await assert.rejects(completeHistoricalGreenBackendRecovery(run.input, run.adapters), /S3 response lost/);
  const result = await completeHistoricalGreenBackendRecovery(run.input, run.adapters);
  assert.equal(result.componentState.generation, 2);
  assert.equal(run.counts().writes, 2);
});

test("lost CAS response is adopted from the exact committed component state", async () => {
  const run = fixture(), commit = run.adapters.commitComponentState;
  let lost = false;
  run.adapters.commitComponentState = async (evidence) => { const result = await commit(evidence);
    if (!lost) { lost = true; throw new Error("DynamoDB response lost"); } return result; };
  await assert.rejects(completeHistoricalGreenBackendRecovery(run.input, run.adapters), /DynamoDB response lost/);
  const result = await completeHistoricalGreenBackendRecovery(run.input, run.adapters);
  assert.equal(result.componentState.generation, 2);
  assert.equal(run.counts().writes, 2);
});

test("competing completion cannot overwrite the first immutable S3 receipt", async () => {
  const run = fixture();
  let simultaneous = false, firstWrite = true;
  const write = run.adapters.store.writeOperation;
  run.adapters.store.writeOperation = async (...args) => { if (firstWrite) { firstWrite = false;
    if (!simultaneous) { simultaneous = true; await completeHistoricalGreenBackendRecovery(run.input, run.adapters); }
  } return write(...args); };
  await assert.rejects(completeHistoricalGreenBackendRecovery(run.input, run.adapters), /conflicting S3 completion|generation changed/);
  assert.equal(run.state.generation, 2);
});
