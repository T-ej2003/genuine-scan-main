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
import { B01_PREREQUISITE, assertB01AmbiguousMutationTaskQuiescent, assertB01LivePredecessor, assertB01RunTaskRequestEvidence,
  assertSemanticallyEmptyB01TaskOverrides, attestBridgeDiff, buildB01ExecutorDefinition, buildB01ReadOnlyDefinition,
  buildB01RunTaskRequest, canonicalSha256 } from "./production-b01-prerequisite-contract.mjs";
import { authenticateB01ExecutorCommand, authenticateB01RunTaskCloudTrail, buildB01ReadOnlyInput } from "./apply-production-b01-prerequisite.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url));
const parse = (value) => JSON.parse(Buffer.isBuffer(value) ? value.toString("utf8") : value);

export function authenticateB01ReadOnlyResult(message, contract) {
  assert.ok(typeof message === "string" && Buffer.byteLength(message) <= 4096);
  const value = JSON.parse(message), { evidenceSha256, ...body } = value; assert.equal(evidenceSha256, canonicalSha256(body));
  assert.equal(body.schemaVersion, 1); assert.equal(body.kind, "PRODUCTION_B01_READONLY_RESULT"); assert.equal(body.mode, "READ_ONLY");
  assert.ok(["PREDECESSOR","SUCCESSOR","PARTIAL","UNKNOWN"].includes(body.classification));
  if (body.classification === "UNKNOWN") { assert.ok(["BOOTSTRAP","INPUT_AUTHENTICATION","SECRET_ACCESS","DATABASE_CONNECTIVITY",
    "DATABASE_SYNCHRONIZATION","PREDECESSOR_COLLECTION","PREDECESSOR_CLASSIFICATION"].includes(body.stage));
    assert.ok(["CONTRACT_REJECTED","UNEXPECTED_FAILURE"].includes(body.code)); return Object.freeze(value); }
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

export function authenticateB01MutationTaskListing(response) {
  assert.ok(Array.isArray(response?.taskArns) && response.taskArns.length <= 100);
  assert.equal(response.nextToken, undefined, "B01 mutation task census is incomplete.");
  for (const taskArn of response.taskArns) assert.match(taskArn, /^arn:aws:ecs:eu-west-2:368992683803:task\/mscqr-prod-euw2-main\/[a-f0-9]{32}$/);
  assert.equal(new Set(response.taskArns).size, response.taskArns.length);
  return response.taskArns;
}

export function findNonTerminalB01MutationTasks(response, expectedTaskArns) {
  assert.deepEqual(response?.failures || [], []); assert.ok(Array.isArray(response?.tasks));
  assert.deepEqual(response.tasks.map(({ taskArn }) => taskArn).sort(), [...expectedTaskArns].sort());
  return response.tasks.filter(({ lastStatus }) => lastStatus !== "STOPPED").map(({ taskArn }) => taskArn);
}

export async function probeProductionB01Prerequisite({ deploymentSourceSha, ambiguousTaskArn, ambiguousDeploymentSourceSha, awsProfile, repositoryRoot = root,
  run = (file, args, options) => execFileSync(file, args, options), wait = sleep } = {}) {
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
  const taskCensus = Object.fromEntries(["RUNNING","PENDING","STOPPED"].map((status) => {
    const response = aws(["ecs","list-tasks","--region",APP_ONLY.region,"--cluster",APP_ONLY.cluster,"--family",B01_PREREQUISITE.executorFamily,"--desired-status",status]);
    return [status, authenticateB01MutationTaskListing(response)];
  }));
  const stoppedDesired = taskCensus.STOPPED;
  const transitioningToStopped = stoppedDesired.length === 0 ? [] : findNonTerminalB01MutationTasks(
    aws(["ecs","describe-tasks","--region",APP_ONLY.region,"--cluster",APP_ONLY.cluster,"--tasks",...stoppedDesired]), stoppedDesired);
  const activeMutationTaskArns = [...taskCensus.RUNNING, ...taskCensus.PENDING, ...transitioningToStopped];
  assert.equal(new Set(activeMutationTaskArns).size, activeMutationTaskArns.length);
  const ambiguousResponse = aws(["ecs","describe-tasks","--region",APP_ONLY.region,"--cluster",APP_ONLY.cluster,"--tasks",ambiguousTaskArn]);
  assert.deepEqual(ambiguousResponse.failures || [], []); assert.equal(ambiguousResponse.tasks?.length, 1);
  const ambiguousTask = ambiguousResponse.tasks[0];
  const ambiguousDefinition = aws(["ecs","describe-task-definition","--region",APP_ONLY.region,"--task-definition",ambiguousTask.taskDefinitionArn,"--include","TAGS"]);
  const ambiguousEvents = aws(["cloudtrail","lookup-events","--region",APP_ONLY.region,"--lookup-attributes","AttributeKey=EventName,AttributeValue=RunTask",
    "--start-time",new Date(new Date(ambiguousTask.createdAt).getTime()-60_000).toISOString(),"--end-time",new Date(new Date(ambiguousTask.stoppedAt).getTime()+60_000).toISOString(),"--max-results","50"]).Events||[];
  const quiescence = authenticateB01AmbiguousMutationTask({ expectedTaskArn: ambiguousTaskArn, task: ambiguousTask, taskDefinition: ambiguousDefinition.taskDefinition,
    taskDefinitionTags: ambiguousDefinition.tags || [], events: ambiguousEvents, activeMutationTaskArns, ambiguousDeploymentSourceSha,
    deploymentSourceSha, repositoryRoot });
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
