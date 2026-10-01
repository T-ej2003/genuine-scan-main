import path from "node:path";
import fs from "node:fs";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { parseArgs } from "node:util";
import { pathToFileURL } from "node:url";
import { canonicalInventoryInstallation, executeInventoryInstallation } from "./production-rotation-inventory-installation.mjs";
import { APP_ONLY } from "./production-app-only-contract.mjs";
import { appOnlyVerifierNetwork } from "./production-app-only-policy.mjs";
import { canonicalSha256, STAGE_B } from "./production-green-stage-b-contract.mjs";
import { PRINTING_ROUTINE_DELTA } from "./apply-production-printing-routine-delta.mjs";
import { assertProtectedCheckout } from "./prepare-production-initial-activation-reconciler-installation.mjs";
import { assertEcsTaskDefinitionReadback } from "../../infra/aws/terraform/lambda/production-rls-approval-broker/ecs-task-definition-readback.mjs";
import { createProductionAwsCredentialEnvironment, productionAwsExecutable, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";
import { assertStageBArtifactPath, ensureStageBPrivateDirectory, ensureStageBPrivateFile, writeStageBPrivateFileAtomicExclusive } from "./stage-b-artifact-contract.mjs";

const family = "mscqr-production-rotation-inventory-contract", container = "inventory-contract";
export function buildInventoryInstallationTask({ sourceSha, databaseHostname }) {
  assert.match(sourceSha || "", /^[a-f0-9]{40}$/);
  assert.match(databaseHostname || "", /^mscqr-production-rls-green-phase2\.[a-z0-9]+\.eu-west-2\.rds\.amazonaws\.com$/);
  const contract = canonicalInventoryInstallation(), contractSha256 = canonicalSha256({ sourceSha, ...contract });
  const command = ["-e", `const assert=require('node:assert/strict');const {PrismaClient}=require('@prisma/client');const contract=${JSON.stringify(contract)};const execute=${executeInventoryInstallation.toString()};const sourceSha=${JSON.stringify(sourceSha)};const contractSha256=${JSON.stringify(contractSha256)};(async()=>{const url=new URL('postgresql://${databaseHostname}:5432/mscqr_production_rls_green_phase2?sslmode=require');url.username='mscqr_prod_admin';url.password=process.env.MSCQR_INVENTORY_ADMIN_PASSWORD;assert.ok(url.password);const db=new PrismaClient({datasources:{db:{url:url.toString()}}});try{const result=await db.$transaction(tx=>execute(tx,contract),{timeout:60000,maxWait:10000,isolationLevel:'Serializable'});console.log(JSON.stringify({schemaVersion:1,kind:'PRODUCTION_ROTATION_INVENTORY_INSTALLATION',sourceSha,contractSha256,...result}));}finally{await db.$disconnect();}})().catch(()=>{console.error('Inventory contract installation failed; inspect live contract before retrying.');process.exitCode=1;});`];
  const definition = { family, networkMode: "awsvpc", requiresCompatibilities: ["FARGATE"], cpu: "256", memory: "512", executionRoleArn: PRINTING_ROUTINE_DELTA.executionRoleArn, runtimePlatform: STAGE_B.taskRuntimePlatform, volumes: [{ name: "executor-tmp" }], containerDefinitions: [{ name: container, image: PRINTING_ROUTINE_DELTA.executorImage, essential: true, entryPoint: ["node"], command, readonlyRootFilesystem: true, mountPoints: [{ sourceVolume: "executor-tmp", containerPath: "/tmp", readOnly: false }], privileged: false, interactive: false, pseudoTerminal: false, environment: [{ name: "NODE_ENV", value: "production" }], secrets: [{ name: "MSCQR_INVENTORY_ADMIN_PASSWORD", valueFrom: PRINTING_ROUTINE_DELTA.administratorSecretArn }], logConfiguration: { logDriver: "awslogs", options: { "awslogs-region": STAGE_B.region, "awslogs-group": STAGE_B.executorLogGroupName, "awslogs-stream-prefix": "inventory-contract" } } }] };
  assert.ok(Buffer.byteLength(JSON.stringify(definition)) <= 60 * 1024);
  return { definition, contractSha256, statementsSha256: contract.statementsSha256 };
}

export async function applyProductionInventoryContract({ sourceSha, awsProfile, receiptOut, repositoryRoot = process.cwd(), verifyOnly = false, run = execFileSync, wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms)) }) {
  assertProtectedCheckout({ sourceSha, repositoryRoot });
  assertStageBArtifactPath({ artifactPath: receiptOut, repositoryRoot, allowExisting: verifyOnly });
  assertStageBArtifactPath({ artifactPath: `${receiptOut}.result.json`, repositoryRoot, allowExisting: false });
  ensureStageBPrivateDirectory({ directory: path.dirname(receiptOut), repositoryRoot });
  assertStageBArtifactPath({ artifactPath: `${receiptOut}.launch.json`, repositoryRoot, allowExisting: verifyOnly });
  const env = createProductionAwsCredentialEnvironment({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: awsProfile });
  const aws = (args) => JSON.parse(run(productionAwsExecutable(), [...args, "--region", STAGE_B.region, "--output", "json", "--no-cli-pager"], { env, encoding: "utf8", timeout: 30000, maxBuffer: 8 * 1024 * 1024 }));
  const caller = aws(["sts", "get-caller-identity"]); assert.equal(caller.Account, STAGE_B.account); assert.equal(caller.Arn, `arn:aws:iam::${STAGE_B.account}:root`);
  const database = aws(["rds", "describe-db-instances", "--db-instance-identifier", STAGE_B.greenDatabaseIdentifier]).DBInstances?.[0]; assert.equal(database?.DBInstanceIdentifier, STAGE_B.greenDatabaseIdentifier); assert.equal(database.DBInstanceStatus, "available");
  const built = buildInventoryInstallationTask({ sourceSha, databaseHostname: database.Endpoint.Address });
  const image = aws(["ecr", "describe-images", "--repository-name", "mscqr-backend", "--image-ids", `imageDigest=${PRINTING_ROUTINE_DELTA.executorImage.split("@")[1]}`]).imageDetails;
  assert.equal(image?.length, 1); assert.equal(image[0].imageDigest, PRINTING_ROUTINE_DELTA.executorImage.split("@")[1]);
  assertProtectedCheckout({ sourceSha, repositoryRoot });
  let taskDefinitionArn, taskArn;
  if (verifyOnly) {
    ensureStageBPrivateFile({ filePath: receiptOut, repositoryRoot });
    ensureStageBPrivateFile({ filePath: `${receiptOut}.launch.json`, repositoryRoot });
    const prepared = JSON.parse(fs.readFileSync(receiptOut, "utf8"));
    const launch = JSON.parse(fs.readFileSync(`${receiptOut}.launch.json`, "utf8"));
    assert.equal(prepared.sourceSha, sourceSha); assert.equal(prepared.contractSha256, built.contractSha256);
    assert.deepEqual(prepared.definition, built.definition); assert.equal(launch.sourceSha, sourceSha);
    assert.equal(launch.contractSha256, built.contractSha256); assert.equal(launch.taskDefinitionArn, prepared.taskDefinitionArn);
    ({ taskDefinitionArn, taskArn } = launch);
  } else {
  taskDefinitionArn = aws(["ecs", "register-task-definition", "--cli-input-json", JSON.stringify(built.definition)]).taskDefinition?.taskDefinitionArn;
  assert.match(taskDefinitionArn || "", new RegExp(`^arn:aws:ecs:eu-west-2:368992683803:task-definition/${family}:[1-9][0-9]*$`));
  const readback = aws(["ecs", "describe-task-definition", "--task-definition", taskDefinitionArn]).taskDefinition;
  assertEcsTaskDefinitionReadback({ definition: readback, taskDefinitionArn, expected: built.definition, label: "Fixed inventory installation" });
  writeStageBPrivateFileAtomicExclusive({ filePath: receiptOut, repositoryRoot, bytes: Buffer.from(`${JSON.stringify({ status: "PREPARED", sourceSha, taskDefinitionArn, ...built })}\n`) });
  const request = { cluster: APP_ONLY.clusterArn, taskDefinition: taskDefinitionArn, launchType: "FARGATE", count: 1, enableExecuteCommand: false, clientToken: canonicalSha256({ sourceSha, contractSha256: built.contractSha256 }), networkConfiguration: appOnlyVerifierNetwork() };
  const launched = aws(["ecs", "run-task", "--cli-input-json", JSON.stringify(request)]); assert.deepEqual(launched.failures || [], []); assert.equal(launched.tasks?.length, 1);
  taskArn = launched.tasks[0].taskArn;
  writeStageBPrivateFileAtomicExclusive({ filePath: `${receiptOut}.launch.json`, repositoryRoot, bytes: Buffer.from(`${JSON.stringify({ sourceSha, contractSha256: built.contractSha256, taskDefinitionArn, taskArn })}\n`) });
  }
  assert.match(taskArn || "", /^arn:aws:ecs:eu-west-2:368992683803:task\/mscqr-prod-euw2-main\/[a-f0-9]{32}$/);
  const authenticatedDefinition = aws(["ecs", "describe-task-definition", "--task-definition", taskDefinitionArn]).taskDefinition;
  assertEcsTaskDefinitionReadback({ definition: authenticatedDefinition, taskDefinitionArn, expected: built.definition, label: "Fixed inventory installation" });
  let task; for (let attempt = 0; attempt < 60; attempt++) { const result = aws(["ecs", "describe-tasks", "--cluster", APP_ONLY.cluster, "--tasks", taskArn]); assert.deepEqual(result.failures || [], []); assert.equal(result.tasks?.length, 1); task = result.tasks[0]; assert.equal(task.taskArn, taskArn); assert.equal(task.clusterArn, APP_ONLY.clusterArn); assert.equal(task.taskDefinitionArn, taskDefinitionArn); if (task.lastStatus === "STOPPED") break; await wait(5000); }
  assert.equal(task?.lastStatus, "STOPPED", "Inspect live contract and task before retrying"); assert.equal(task.containers?.length, 1); assert.equal(task.containers[0].exitCode, 0, "Inspect live contract before retrying");
  const logs = aws(["logs", "get-log-events", "--log-group-name", STAGE_B.executorLogGroupName, "--log-stream-name", `inventory-contract/${container}/${taskArn.split("/").pop()}`, "--start-from-head"]);
  const lines = (logs.events || []).filter(({ message }) => message.trim().startsWith("{")); assert.equal(lines.length, 1);
  const receipt = JSON.parse(lines[0].message); assert.equal(receipt.kind, "PRODUCTION_ROTATION_INVENTORY_INSTALLATION"); assert.equal(receipt.sourceSha, sourceSha); assert.equal(receipt.contractSha256, built.contractSha256); assert.equal(receipt.statementsSha256, built.statementsSha256); assert.equal(receipt.status, "APPLIED"); assert.equal(receipt.directTableGrantsAdded, 0);
  writeStageBPrivateFileAtomicExclusive({ filePath: `${receiptOut}.result.json`, repositoryRoot, bytes: Buffer.from(`${JSON.stringify({ ...receipt, taskArn, taskDefinitionArn })}\n`) });
  return receipt;
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const { values } = parseArgs({ options: { "source-sha": { type: "string" }, "aws-profile": { type: "string" }, "receipt-out": { type: "string" }, "verify-only": { type: "boolean", default: false } } });
  await applyProductionInventoryContract({ sourceSha: values["source-sha"], awsProfile: values["aws-profile"], receiptOut: values["receipt-out"], verifyOnly: values["verify-only"] });
}
