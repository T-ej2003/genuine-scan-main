#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";
import { parseArgs } from "node:util";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { APP_ONLY } from "./production-app-only-contract.mjs";
import { createProductionAwsCredentialEnvironment, productionAwsExecutable, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";
import { assertProtectedCheckout } from "./prepare-production-initial-activation-reconciler-installation.mjs";
import { assertEcsTaskDefinitionReadback } from "../../infra/aws/terraform/lambda/production-rls-approval-broker/ecs-task-definition-readback.mjs";
import { B01_PREREQUISITE, assertB01AmbiguousMutationTaskQuiescent, assertB01ExpiredMutationTaskQuiescent, assertB01LivePredecessor, assertB01RunTaskRequestEvidence,
  assertSemanticallyEmptyB01TaskOverrides, attestBridgeDiff, buildB01ExecutorDefinition, buildB01ReadOnlyDefinition,
  buildB01RunTaskRequest, canonicalSha256, authenticateB01TerminalTaskEvents, collectB01TerminalTaskEvents } from "./production-b01-prerequisite-contract.mjs";
import { B01_CLASSIFICATION_INVARIANTS, authenticateB01ExecutorCommand, authenticateB01RunTaskCloudTrail, buildB01ReadOnlyInput } from "./apply-production-b01-prerequisite.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url));
const parse = (value) => JSON.parse(Buffer.isBuffer(value) ? value.toString("utf8") : value);
const MUTATION_TASK_DEFINITION = /^arn:aws:ecs:eu-west-2:368992683803:task-definition\/mscqr-production-b01-prerequisite:[1-9][0-9]*$/;

export function authenticateB01ReadOnlyResult(message, contract) {
  assert.ok(typeof message === "string" && Buffer.byteLength(message) <= 4096);
  const value = JSON.parse(message), { evidenceSha256, ...body } = value; assert.equal(evidenceSha256, canonicalSha256(body));
  assert.equal(body.schemaVersion, 1); assert.equal(body.kind, "PRODUCTION_B01_READONLY_RESULT"); assert.equal(body.mode, "READ_ONLY");
  assert.ok(["PREDECESSOR","SUCCESSOR","PARTIAL","UNKNOWN"].includes(body.classification));
  if (body.classification === "UNKNOWN") { assert.ok(["BOOTSTRAP","INPUT_AUTHENTICATION","SECRET_ACCESS","DATABASE_CONNECTIVITY",
    "DATABASE_SYNCHRONIZATION","PREDECESSOR_COLLECTION","PREDECESSOR_CLASSIFICATION"].includes(body.stage));
    assert.ok(["CONTRACT_REJECTED","UNEXPECTED_FAILURE"].includes(body.code));
    const keys = ["schemaVersion","kind","mode","classification","stage","code",...(body.classificationInvariant === undefined ? [] : ["classificationInvariant"])];
    assert.deepEqual(Object.keys(body).sort(), keys.sort());
    if (body.classificationInvariant !== undefined) { assert.equal(body.stage, "PREDECESSOR_CLASSIFICATION"); assert.equal(body.code, "CONTRACT_REJECTED");
      assert.ok(B01_CLASSIFICATION_INVARIANTS.includes(body.classificationInvariant)); }
    return Object.freeze(value); }
  assert.equal(body.rlsDeltaOriginSha, B01_PREREQUISITE.rlsDeltaOriginSha); assert.equal(body.contractSha256, canonicalSha256(contract));
  assert.match(body.liveRlsIdentity, /^[a-f0-9]{64}$/); assert.equal(body.transactionReadOnly, true);
  assert.equal(body.livePredecessorMatch, body.classification === "PREDECESSOR"); assert.equal(body.liveSuccessorMatch, body.classification === "SUCCESSOR");
  assert.equal(body.unauthorizedCatalogueDelta, body.classification === "PARTIAL");
  assert.deepEqual(body.mismatchIdentifiers, body.classification === "PARTIAL" ? ["CATALOGUE_IDENTITY"] : []);
  return Object.freeze(value);
}

export function authenticateB01AmbiguousMutationTask({ expectedTaskArn, task, taskDefinition, taskDefinitionTags = [], events,
  activeMutationTaskArns = [], ambiguousDeploymentSourceSha, deploymentSourceSha, repositoryRoot = root,
  readExecutorSource = (sha) => execFileSync("git", ["show", `${sha}:scripts/aws/production-b01-prerequisite-executor.cjs`],
    { cwd: repositoryRoot, encoding: "utf8" }) } = {}) {
  assert.match(ambiguousDeploymentSourceSha || "", /^[a-f0-9]{40}$/); assert.match(deploymentSourceSha || "", /^[a-f0-9]{40}$/);
  assert.ok([B01_PREREQUISITE.correctionBaseSha, deploymentSourceSha].includes(ambiguousDeploymentSourceSha));
  assert.equal(task?.taskArn, expectedTaskArn);
  const command = taskDefinition?.containerDefinitions?.find(({ name }) => name === B01_PREREQUISITE.executorContainer)?.command;
  const executorSource = readExecutorSource(ambiguousDeploymentSourceSha);
  authenticateB01ExecutorCommand({ command, deploymentSourceSha: ambiguousDeploymentSourceSha, repositoryRoot, executorSource });
  assertEcsTaskDefinitionReadback({ definition: { ...taskDefinition, tags: taskDefinitionTags }, taskDefinitionArn: task.taskDefinitionArn,
    expected: buildB01ExecutorDefinition(command), label: "ambiguous B01 mutation task" });
  const runTaskRequestEvidence = authenticateB01RunTaskCloudTrail(events, { taskArn: task.taskArn,
    taskDefinitionArn: task.taskDefinitionArn, deploymentSourceSha: ambiguousDeploymentSourceSha });
  return assertB01AmbiguousMutationTaskQuiescent({ task, taskArn: task.taskArn, deploymentSourceSha: ambiguousDeploymentSourceSha,
    runTaskRequestEvidence, activeMutationTaskArns });
}

export function authenticateB01ExpiredMutationTask({ expectedTaskArn, taskDefinitionArn, taskDefinition, taskDefinitionTags = [], events,
  launchHistoryEvidenceSha256, terminalTaskEvidence, activeMutationTaskArns = [], ambiguousDeploymentSourceSha, deploymentSourceSha, repositoryRoot = root,
  readExecutorSource = (sha) => execFileSync("git", ["show", `${sha}:scripts/aws/production-b01-prerequisite-executor.cjs`],
    { cwd: repositoryRoot, encoding: "utf8" }) } = {}) {
  assert.match(ambiguousDeploymentSourceSha || "", /^[a-f0-9]{40}$/); assert.match(deploymentSourceSha || "", /^[a-f0-9]{40}$/);
  assert.ok([B01_PREREQUISITE.correctionBaseSha, deploymentSourceSha].includes(ambiguousDeploymentSourceSha));
  assert.match(taskDefinitionArn || "", MUTATION_TASK_DEFINITION);
  const command = taskDefinition?.containerDefinitions?.find(({ name }) => name === B01_PREREQUISITE.executorContainer)?.command;
  const executorSource = readExecutorSource(ambiguousDeploymentSourceSha);
  authenticateB01ExecutorCommand({ command, deploymentSourceSha: ambiguousDeploymentSourceSha, repositoryRoot, executorSource });
  assertEcsTaskDefinitionReadback({ definition: { ...taskDefinition, tags: taskDefinitionTags }, taskDefinitionArn,
    expected: buildB01ExecutorDefinition(command), label: "expired ambiguous B01 mutation task" });
  const runTaskRequestEvidence = authenticateB01RunTaskCloudTrail(events, { taskArn: expectedTaskArn,
    taskDefinitionArn, deploymentSourceSha: ambiguousDeploymentSourceSha });
  return assertB01ExpiredMutationTaskQuiescent({ taskArn: expectedTaskArn, taskDefinitionArn,
    deploymentSourceSha: ambiguousDeploymentSourceSha, runTaskRequestEvidence, launchHistoryEvidenceSha256, terminalTaskEvidence, activeMutationTaskArns });
}

export function authenticateB01MissingTask(response, expectedTaskArn) {
  assert.deepEqual(response?.tasks || [], []); assert.equal(response?.failures?.length, 1);
  assert.deepEqual(response.failures[0], { arn: expectedTaskArn, reason: "MISSING" }); return true;
}

export function authenticateB01MutationLaunchHistory(events, { expectedTaskArn, taskDefinitionArn, deploymentSourceSha } = {}) {
  assert.ok(Array.isArray(events)); assert.match(expectedTaskArn || "", /^arn:aws:ecs:eu-west-2:368992683803:task\/mscqr-prod-euw2-main\/[a-f0-9]{32}$/);
  assert.match(taskDefinitionArn || "", MUTATION_TASK_DEFINITION);
  const parsed = events.map((event) => ({ event, body: JSON.parse(event.CloudTrailEvent) }));
  assert.equal(new Set(parsed.map(({ event }) => event.EventId)).size, parsed.length, "CloudTrail RunTask history contains duplicate events.");
  const target = parsed.filter(({ body }) => body.responseElements?.tasks?.some(({ taskArn }) => taskArn === expectedTaskArn));
  assert.equal(target.length, 1, "Historical B01 RunTask event is unavailable or ambiguous.");
  const targetTime = Date.parse(target[0].body.eventTime); assert.ok(Number.isFinite(targetTime));
  const family = parsed.filter(({ body }) => MUTATION_TASK_DEFINITION.test(body.requestParameters?.taskDefinition || "")
    || body.responseElements?.tasks?.some(({ group, taskDefinitionArn: definition }) => group === `family:${B01_PREREQUISITE.executorFamily}`
      || MUTATION_TASK_DEFINITION.test(definition || "")));
  const relevant = family.filter(({ body }) => Date.parse(body.eventTime) >= targetTime);
  assert.equal(relevant.length, 1, "A later or ambiguous B01 mutation launch is not independently accounted for.");
  const { event, body } = relevant[0]; assert.equal(body.eventSource, "ecs.amazonaws.com"); assert.equal(body.eventName, "RunTask");
  assert.equal(body.recipientAccountId, B01_PREREQUISITE.account); assert.equal(body.awsRegion, B01_PREREQUISITE.region);
  assert.equal(body.userIdentity?.accountId, B01_PREREQUISITE.account); assert.equal(body.userIdentity?.arn, `arn:aws:iam::${B01_PREREQUISITE.account}:root`);
  assert.equal(event.EventId, body.eventID); assert.equal(Date.parse(event.EventTime), targetTime); assert.equal(event.EventSource, "ecs.amazonaws.com");
  assert.equal(event.EventName, "RunTask"); assert.equal(event.ReadOnly, "false"); assert.deepEqual(body.responseElements?.failures || [], []);
  assert.equal(body.responseElements?.tasks?.length, 1); const task = body.responseElements.tasks[0];
  assert.equal(task.taskArn, expectedTaskArn); assert.equal(task.taskDefinitionArn, taskDefinitionArn);
  assert.equal(task.clusterArn, `arn:aws:ecs:${B01_PREREQUISITE.region}:${B01_PREREQUISITE.account}:cluster/${B01_PREREQUISITE.cluster}`);
  assert.equal(task.group, `family:${B01_PREREQUISITE.executorFamily}`); assert.equal(task.launchType, "FARGATE");
  assert.equal(task.enableExecuteCommand, false); assert.equal(task.desiredStatus, "RUNNING");
  assert.ok(["PROVISIONING", "PENDING", "ACTIVATING", "RUNNING"].includes(task.lastStatus));
  assertSemanticallyEmptyB01TaskOverrides(task.overrides); assert.equal(task.containers?.length, 1);
  assert.equal(task.containers[0]?.name, B01_PREREQUISITE.executorContainer); assert.equal(task.containers[0]?.image, B01_PREREQUISITE.executorImage);
  const requestEvidence = authenticateB01RunTaskCloudTrail(events, { taskArn: expectedTaskArn, taskDefinitionArn, deploymentSourceSha });
  const bodyEvidence = { schemaVersion: 1, kind: "PRODUCTION_B01_MUTATION_LAUNCH_HISTORY", expectedTaskArn,
    taskDefinitionArn, deploymentSourceSha, targetEventId: body.eventID, targetEventTime: body.eventTime,
    familyLaunchEventIds: relevant.map(({ body: value }) => value.eventID).sort(), requestEvidence };
  return Object.freeze({ ...bodyEvidence, evidenceSha256: canonicalSha256(bodyEvidence), requestEvidence });
}

export function collectB01RunTaskEvents(aws) {
  assert.equal(typeof aws, "function"); const events = [], tokens = new Set(); let token;
  for (let page = 0; page < 20; page += 1) {
    const args = ["cloudtrail","lookup-events","--region",APP_ONLY.region,"--lookup-attributes","AttributeKey=EventName,AttributeValue=RunTask",
      "--max-results","50","--no-paginate",...(token ? ["--next-token",token] : [])];
    const response = aws(args); assert.ok(Array.isArray(response?.Events) && response.Events.length <= 50);
    events.push(...response.Events); const next = response.NextToken;
    if (next === undefined) return Object.freeze(events);
    assert.ok(typeof next === "string" && next && !tokens.has(next), "CloudTrail RunTask pagination is incomplete or cyclic.");
    tokens.add(next); token = next;
  }
  throw new Error("CloudTrail RunTask history exceeds the bounded page limit.");
}

export function authenticateB01MutationTaskListing(response) {
  assert.ok(Array.isArray(response?.taskArns) && response.taskArns.length <= 100);
  assert.equal(response.nextToken, undefined, "B01 mutation task census is incomplete.");
  for (const taskArn of response.taskArns) assert.match(taskArn, /^arn:aws:ecs:eu-west-2:368992683803:task\/mscqr-prod-euw2-main\/[a-f0-9]{32}$/);
  assert.equal(new Set(response.taskArns).size, response.taskArns.length);
  return response.taskArns;
}

export function collectB01MutationTaskArns(aws, status) {
  assert.equal(typeof aws, "function"); assert.ok(["RUNNING","PENDING","STOPPED"].includes(status));
  const arns = new Set(), tokens = new Set(); let token;
  for (let page = 0; page < 10; page += 1) {
    const args = ["ecs","list-tasks","--region",APP_ONLY.region,"--cluster",APP_ONLY.cluster,"--family",B01_PREREQUISITE.executorFamily,
      "--desired-status",status,"--max-results","100","--no-paginate",...(token ? ["--next-token",token] : [])];
    const response = aws(args); assert.ok(Array.isArray(response?.taskArns) && response.taskArns.length <= 100);
    for (const arn of response.taskArns) { assert.match(arn, /^arn:aws:ecs:eu-west-2:368992683803:task\/mscqr-prod-euw2-main\/[a-f0-9]{32}$/); assert.ok(!arns.has(arn)); arns.add(arn); }
    const next = response.nextToken ?? response.NextToken;
    if (next === undefined) return Object.freeze([...arns].sort());
    assert.ok(typeof next === "string" && next && !tokens.has(next), "B01 mutation task census pagination is incomplete or cyclic.");
    tokens.add(next); token = next;
  }
  throw new Error("B01 mutation task census exceeds the bounded page limit.");
}

export function findNonTerminalB01MutationTasks(response, expectedTaskArns) {
  assert.deepEqual(response?.failures || [], []); assert.ok(Array.isArray(response?.tasks));
  assert.deepEqual(response.tasks.map(({ taskArn }) => taskArn).sort(), [...expectedTaskArns].sort());
  return response.tasks.filter(({ lastStatus }) => lastStatus !== "STOPPED").map(({ taskArn }) => taskArn);
}

export function collectB01MutationCensus(aws) {
  const collect = (status) => collectB01MutationTaskArns(aws, status);
  const runningBefore = collect("RUNNING"), stoppedBefore = collect("STOPPED");
  const runningAfter = collect("RUNNING"), stoppedAfter = collect("STOPPED");
  const taskCensus = { RUNNING: [...new Set([...runningBefore, ...runningAfter])].sort(), PENDING: [],
    STOPPED: [...new Set([...stoppedBefore, ...stoppedAfter])].sort() };
  const transitioningToStopped = taskCensus.STOPPED.length === 0 ? [] : findNonTerminalB01MutationTasks(
    aws(["ecs","describe-tasks","--region",APP_ONLY.region,"--cluster",APP_ONLY.cluster,"--tasks",...taskCensus.STOPPED]), taskCensus.STOPPED);
  const activeMutationTaskArns = [...taskCensus.RUNNING, ...transitioningToStopped];
  assert.equal(new Set(activeMutationTaskArns).size, activeMutationTaskArns.length); return { taskCensus, activeMutationTaskArns };
}

export function assertB01RecoveryPostflight({ initialLaunchHistorySha256, beforeCensusLaunchHistorySha256,
  afterCensusLaunchHistorySha256, trailingLaunchHistorySha256, firstCensus, finalCensus, ambiguousTaskArn } = {}) {
  assert.match(initialLaunchHistorySha256 || "", /^[a-f0-9]{64}$/);
  assert.equal(beforeCensusLaunchHistorySha256, initialLaunchHistorySha256, "B01 mutation launch history changed before the final census.");
  assert.match(ambiguousTaskArn || "", /^arn:aws:ecs:eu-west-2:368992683803:task\/mscqr-prod-euw2-main\/[a-f0-9]{32}$/);
  const assertCensus = ({ taskCensus, activeMutationTaskArns } = {}) => {
    assert.deepEqual(activeMutationTaskArns, [], "A B01 mutation executor became active during reconciliation.");
    assert.deepEqual(Object.keys(taskCensus || {}).sort(), ["PENDING","RUNNING","STOPPED"].sort());
    const observed = [...taskCensus.RUNNING, ...taskCensus.PENDING, ...taskCensus.STOPPED];
    assert.equal(new Set(observed).size, observed.length); assert.ok(observed.every((taskArn) => taskArn === ambiguousTaskArn),
      "An unaccounted B01 mutation task exists in the current family census.");
    return observed.sort();
  };
  const firstObserved = assertCensus(firstCensus);
  assert.equal(afterCensusLaunchHistorySha256, beforeCensusLaunchHistorySha256,
    "B01 mutation launch history changed across the final census.");
  assert.deepEqual(assertCensus(finalCensus), firstObserved, "B01 mutation family census changed after the history bracket.");
  assert.equal(trailingLaunchHistorySha256, afterCensusLaunchHistorySha256,
    "B01 mutation launch history changed after the final census.");
  return true;
}

export function collectB01RecoveryPostflight({ collectLaunchHistory, collectMutationCensus,
  initialLaunchHistorySha256, ambiguousTaskArn } = {}) {
  assert.equal(typeof collectLaunchHistory, "function"); assert.equal(typeof collectMutationCensus, "function");
  const beforeCensus = collectLaunchHistory();
  const firstCensus = collectMutationCensus();
  const afterCensus = collectLaunchHistory();
  const finalCensus = collectMutationCensus();
  const trailingHistory = collectLaunchHistory();
  assertB01RecoveryPostflight({ initialLaunchHistorySha256, beforeCensusLaunchHistorySha256: beforeCensus.evidenceSha256,
    afterCensusLaunchHistorySha256: afterCensus.evidenceSha256, trailingLaunchHistorySha256: trailingHistory.evidenceSha256,
    firstCensus, finalCensus, ambiguousTaskArn });
  return Object.freeze({ beforeCensus, firstCensus, afterCensus, finalCensus, trailingHistory });
}

export async function probeProductionB01Prerequisite({ deploymentSourceSha, ambiguousTaskArn, ambiguousDeploymentSourceSha, awsProfile, repositoryRoot = root,
  run = (file, args, options) => execFileSync(file, args, options), wait = sleep, now = () => new Date() } = {}) {
  assertProtectedCheckout({ sourceSha: deploymentSourceSha, repositoryRoot }); attestBridgeDiff({ deploymentSourceSha, repositoryRoot });
  const env = createProductionAwsCredentialEnvironment({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: awsProfile });
  const aws = (args) => parse(run(productionAwsExecutable(), [...args,"--output","json","--no-cli-pager"], { env, encoding: "utf8", timeout: 30000, maxBuffer: 8*1024*1024 }));
  const caller = aws(["sts","get-caller-identity"]); assert.equal(caller.Account, APP_ONLY.account); assert.equal(caller.Arn, `arn:aws:iam::${APP_ONLY.account}:root`);
  const service = aws(["ecs","describe-services","--region",APP_ONLY.region,"--cluster",APP_ONLY.cluster,"--services",APP_ONLY.service]).services?.[0];
  const liveDefinition = aws(["ecs","describe-task-definition","--region",APP_ONLY.region,"--task-definition",service.taskDefinition]).taskDefinition;
  const digest = B01_PREREQUISITE.executorImage.split("@")[1];
  const repository = aws(["ecr","describe-repositories","--region",APP_ONLY.region,"--repository-names","mscqr-backend"]).repositories?.[0];
  const imageDetails = aws(["ecr","describe-images","--region",APP_ONLY.region,"--repository-name","mscqr-backend","--image-ids",`imageDigest=${digest}`]).imageDetails;
  assertB01LivePredecessor({ service, taskDefinition: liveDefinition, repository, imageDetails });
  const database = aws(["rds","describe-db-instances","--region",APP_ONLY.region,"--db-instance-identifier",B01_PREREQUISITE.databaseIdentifier]).DBInstances?.[0];
  assert.equal(database?.DBInstanceIdentifier,B01_PREREQUISITE.databaseIdentifier); assert.equal(database?.DBInstanceStatus, "available");
  assert.match(database?.Endpoint?.Address||"",/^[a-z0-9.-]+$/); assert.equal(database?.Endpoint?.Port,5432);
  assert.match(ambiguousTaskArn || "", /^arn:aws:ecs:eu-west-2:368992683803:task\/mscqr-prod-euw2-main\/[a-f0-9]{32}$/);
  const mutationCensus = () => collectB01MutationCensus(aws);
  const ambiguousEvents = collectB01RunTaskEvents(aws);
  const matchingEvents = ambiguousEvents.map((event) => ({ event, body: JSON.parse(event.CloudTrailEvent) })).filter(({ body }) =>
    body.responseElements?.tasks?.some(({ taskArn }) => taskArn === ambiguousTaskArn));
  assert.equal(matchingEvents.length, 1, "Historical B01 RunTask event is unavailable or ambiguous.");
  const ambiguousTaskDefinitionArn = matchingEvents[0].body.requestParameters?.taskDefinition;
  assert.match(ambiguousTaskDefinitionArn || "", MUTATION_TASK_DEFINITION);
  const launchHistory = authenticateB01MutationLaunchHistory(ambiguousEvents, { expectedTaskArn: ambiguousTaskArn,
    taskDefinitionArn: ambiguousTaskDefinitionArn, deploymentSourceSha: ambiguousDeploymentSourceSha });
  const { activeMutationTaskArns } = mutationCensus(); assert.deepEqual(activeMutationTaskArns, []);
  const ambiguousResponse = aws(["ecs","describe-tasks","--region",APP_ONLY.region,"--cluster",APP_ONLY.cluster,"--tasks",ambiguousTaskArn]);
  const ambiguousDefinition = aws(["ecs","describe-task-definition","--region",APP_ONLY.region,"--task-definition",ambiguousTaskDefinitionArn,"--include","TAGS"]);
  let quiescence;
  if ((ambiguousResponse.tasks || []).length === 1 && (ambiguousResponse.failures || []).length === 0) {
    const ambiguousTask = ambiguousResponse.tasks[0]; assert.equal(ambiguousTask.taskDefinitionArn, ambiguousTaskDefinitionArn);
    quiescence = authenticateB01AmbiguousMutationTask({ expectedTaskArn: ambiguousTaskArn, task: ambiguousTask, taskDefinition: ambiguousDefinition.taskDefinition,
      taskDefinitionTags: ambiguousDefinition.tags || [], events: ambiguousEvents, activeMutationTaskArns, ambiguousDeploymentSourceSha,
      deploymentSourceSha, repositoryRoot });
  } else {
    authenticateB01MissingTask(ambiguousResponse, ambiguousTaskArn);
    const legacyExpired = ambiguousTaskArn === B01_PREREQUISITE.legacyExpiredTaskArn
      && ambiguousTaskDefinitionArn === B01_PREREQUISITE.legacyExpiredTaskDefinitionArn
      && ambiguousDeploymentSourceSha === B01_PREREQUISITE.legacyExpiredDeploymentSourceSha;
    const observationEventTime = now().toISOString();
    const terminalEvidence = legacyExpired ? undefined : authenticateB01TerminalTaskEvents(
      collectB01TerminalTaskEvents(aws, ambiguousTaskArn, { launchEventTime: launchHistory.targetEventTime,
        observationEventTime }), { taskArn: ambiguousTaskArn,
        taskDefinitionArn: ambiguousTaskDefinitionArn, launchEventTime: launchHistory.targetEventTime, observationEventTime });
    quiescence = authenticateB01ExpiredMutationTask({ expectedTaskArn: ambiguousTaskArn, taskDefinitionArn: ambiguousTaskDefinitionArn,
      taskDefinition: ambiguousDefinition.taskDefinition, taskDefinitionTags: ambiguousDefinition.tags || [], events: ambiguousEvents,
      launchHistoryEvidenceSha256: launchHistory.evidenceSha256, terminalTaskEvidence: terminalEvidence,
      activeMutationTaskArns, ambiguousDeploymentSourceSha,
      deploymentSourceSha, repositoryRoot });
  }
  const built = buildB01ReadOnlyInput({ deploymentSourceSha, databaseHostname: database.Endpoint?.Address,
    ambiguousMutationTaskEvidenceSha256: quiescence.evidenceSha256, repositoryRoot });
  const definition = buildB01ReadOnlyDefinition(built.command); assertProtectedCheckout({ sourceSha: deploymentSourceSha, repositoryRoot });
  const registered = aws(["ecs","register-task-definition","--region",APP_ONLY.region,"--cli-input-json",JSON.stringify(definition)]).taskDefinition;
  const taskDefinitionArn = registered?.taskDefinitionArn; assert.match(taskDefinitionArn || "", new RegExp(`/${B01_PREREQUISITE.readOnlyFamily}:[1-9][0-9]*$`));
  const readback = aws(["ecs","describe-task-definition","--region",APP_ONLY.region,"--task-definition",taskDefinitionArn,"--include","TAGS"]);
  assertEcsTaskDefinitionReadback({ definition: { ...readback.taskDefinition, tags: readback.tags || [] }, taskDefinitionArn, expected: definition, label: "B01 read-only reconciliation" });
  const request = buildB01RunTaskRequest({ taskDefinitionArn, deploymentSourceSha, readOnly: true });
  const launched = aws(["ecs","run-task","--region",APP_ONLY.region,"--cli-input-json",JSON.stringify(request)]); assert.deepEqual(launched.failures || [], []); assert.equal(launched.tasks?.length, 1);
  const taskArn = launched.tasks[0].taskArn; let task;
  for (let attempt=0; attempt<60; attempt++) { const response=aws(["ecs","describe-tasks","--region",APP_ONLY.region,"--cluster",APP_ONLY.cluster,"--tasks",taskArn]); assert.deepEqual(response.failures||[],[]); task=response.tasks?.[0]; if(task?.lastStatus==="STOPPED") break; await wait(5000); }
  assert.equal(task?.taskArn,taskArn); assert.equal(task?.taskDefinitionArn,taskDefinitionArn); assert.equal(task?.clusterArn,APP_ONLY.clusterArn);
  assert.equal(task?.lastStatus,"STOPPED"); assert.equal(task?.stopCode,"EssentialContainerExited"); assert.equal(task.enableExecuteCommand,false);
  assertSemanticallyEmptyB01TaskOverrides(task.overrides,B01_PREREQUISITE.readOnlyContainer);
  assert.equal(task.containers?.length,1); assert.equal(task.containers[0]?.name,B01_PREREQUISITE.readOnlyContainer);
  let requestEvidence;
  for (let attempt=0; attempt<12 && !requestEvidence; attempt++) { const events=aws(["cloudtrail","lookup-events","--region",APP_ONLY.region,"--lookup-attributes","AttributeKey=EventName,AttributeValue=RunTask","--start-time",new Date(new Date(task.createdAt).getTime()-60_000).toISOString(),"--end-time",new Date(new Date(task.stoppedAt).getTime()+60_000).toISOString(),"--max-results","50"]).Events||[];
    try { requestEvidence=authenticateB01RunTaskCloudTrail(events,{taskArn,taskDefinitionArn,deploymentSourceSha,readOnly:true}); } catch { if(attempt===11) throw new Error("RunTask evidence unavailable"); await wait(5000); } }
  assertB01RunTaskRequestEvidence(requestEvidence,{taskArn,taskDefinitionArn,deploymentSourceSha,readOnly:true});
  const stream=`b01-prerequisite-readonly/${B01_PREREQUISITE.readOnlyContainer}/${taskArn.split("/").at(-1)}`; let message;
  for(let attempt=0; attempt<12 && !message; attempt++){const events=aws(["logs","get-log-events","--region",APP_ONLY.region,"--log-group-name",B01_PREREQUISITE.logGroup,"--log-stream-name",stream,"--start-from-head","--limit","10"]).events||[];if(events.length){assert.equal(events.length,1);message=events[0].message;}else await wait(5000);}
  assert.ok(message); const result=authenticateB01ReadOnlyResult(message,built.contract);
  assert.equal(task.containers[0].exitCode,result.classification==="UNKNOWN"?2:0);
  collectB01RecoveryPostflight({ initialLaunchHistorySha256: launchHistory.evidenceSha256, ambiguousTaskArn,
    collectLaunchHistory: () => authenticateB01MutationLaunchHistory(collectB01RunTaskEvents(aws), { expectedTaskArn: ambiguousTaskArn,
      taskDefinitionArn: ambiguousTaskDefinitionArn, deploymentSourceSha: ambiguousDeploymentSourceSha }),
    collectMutationCensus: mutationCensus });
  return Object.freeze({ status:"PRODUCTION_B01_READONLY_RECONCILED",ambiguousMutationTaskEvidenceSha256:quiescence.evidenceSha256,
    taskArn,taskDefinitionArn,requestEvidence,classification:result.classification,liveRlsIdentity:result.liveRlsIdentity||null,
    livePredecessorMatch:result.livePredecessorMatch??false,liveSuccessorMatch:result.liveSuccessorMatch??false,unauthorizedCatalogueDelta:result.unauthorizedCatalogueDelta??null,
    temporaryPrivilegeResidue:result.temporaryPrivilegeResidue??null,transactionReadOnly:result.transactionReadOnly??null });
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href===import.meta.url) {
  try { const {values}=parseArgs({options:{"deployment-source-sha":{type:"string"},"ambiguous-task-arn":{type:"string"},
      "ambiguous-deployment-source-sha":{type:"string"},"aws-profile":{type:"string"}},strict:true});
    const result=await probeProductionB01Prerequisite({deploymentSourceSha:values["deployment-source-sha"],ambiguousTaskArn:values["ambiguous-task-arn"],
      ambiguousDeploymentSourceSha:values["ambiguous-deployment-source-sha"],awsProfile:values["aws-profile"]}); process.stdout.write(`${JSON.stringify(result)}\n`);
    if(result.classification==="PARTIAL"||result.classification==="UNKNOWN") process.exitCode=2;
  } catch { process.stderr.write("Production B01 read-only reconciliation failed closed; no database mutation was attempted.\n"); process.exitCode=1; }
}
