import crypto from "node:crypto";
import { STAGE_B, canonicalSha256 } from "../../aws/production-green-stage-b-contract.mjs";
import { createProductionComponentDeploymentState, stateHash } from "../../aws/production-component-deployment-state.mjs";
import { COMPONENT_STATE_BOOTSTRAP_WORKFLOW } from "../../aws/production-bootstrap-stage-b-predecessor-contract.mjs";
import { prepareHistoricalRuntimeReference } from "../../aws/production-historical-runtime-contract.mjs";
import { signPermissionReport } from "../../aws/validate-production-green-stage-b-permissions.mjs";
import { historicalRuntimeEvidence } from "../../aws/production-historical-runtime-evidence.mjs";

export function historicalRuntimeFixture() {
  const source = "a".repeat(40), release = "b".repeat(40), imageDigest = `sha256:${"c".repeat(64)}`;
  const definitionArn = `arn:aws:ecs:${STAGE_B.region}:${STAGE_B.account}:task-definition/mscqr-production-rls-green-worker-candidate:7`;
  const taskArn = `arn:aws:ecs:${STAGE_B.region}:${STAGE_B.account}:task/mscqr-prod-euw2-main/${"1".repeat(32)}`;
  const taskRoleArn = "arn:aws:iam::368992683803:role/mscqr-production-rls-green-worker-task", executionRoleArn = "arn:aws:iam::368992683803:role/mscqr-production-rls-green-worker-execution";
  const definition = { taskDefinitionArn: definitionArn, family: "mscqr-production-rls-green-worker-candidate", revision: 7, status: "ACTIVE", registeredAt: "2026-09-28T09:00:00.000Z", registeredBy: `arn:aws:iam::${STAGE_B.account}:root`, networkMode: "awsvpc", taskRoleArn, executionRoleArn,
    containerDefinitions: [{ name: "worker", image: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-worker@${imageDigest}`, essential: true, entryPoint: ["node", "dist/worker.js"], environment: [{ name: "RELEASE_GIT_SHA", value: source }], secrets: [{ name: "DATABASE_URL", valueFrom: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:worker-ref" }] }] };
  const task = { taskArn, taskDefinitionArn: definitionArn, clusterArn: STAGE_B.clusterArn, lastStatus: "RUNNING", desiredStatus: "RUNNING", group: "family:mscqr-production-rls-green-worker-candidate", createdAt: "2026-09-28T09:05:00.000Z", launchType: "FARGATE", platformVersion: "1.4.0", overrides: { containerOverrides: [{ name: "worker" }] }, containers: [{ name: "worker", imageDigest }],
    attachments: [{ type: "ElasticNetworkInterface", details: [{ name: "networkInterfaceId", value: "eni-abcdef" }, { name: "subnetId", value: "subnet-abcdef" }, { name: "privateIPv4Address", value: "10.0.1.9" }] }] };
  const eni = { NetworkInterfaceId: "eni-abcdef", SubnetId: "subnet-abcdef", PrivateIpAddress: "10.0.1.9", Groups: [{ GroupId: "sg-abcdef" }] };
  const identity = { type: "Root", arn: `arn:aws:iam::${STAGE_B.account}:root`, sessionContext: { attributes: { mfaAuthenticated: "true" } } };
  const registration = { eventID: "11111111-1111-1111-1111-111111111111", eventName: "RegisterTaskDefinition", eventTime: definition.registeredAt, eventSource: "ecs.amazonaws.com", awsRegion: STAGE_B.region, recipientAccountId: STAGE_B.account, userIdentity: identity, responseElements: { taskDefinition: { taskDefinitionArn: definitionArn } } };
  const launch = { eventID: "22222222-2222-2222-2222-222222222222", eventName: "RunTask", eventTime: task.createdAt, eventSource: "ecs.amazonaws.com", awsRegion: STAGE_B.region, recipientAccountId: STAGE_B.account, userIdentity: identity, responseElements: { tasks: [{ taskArn, taskDefinitionArn: definitionArn, clusterArn: STAGE_B.clusterArn }] } };
  const state = createProductionComponentDeploymentState({ updatedByWorkflow: COMPONENT_STATE_BOOTSTRAP_WORKFLOW, githubRunId: "101", now: "2026-09-29T10:00:00.000Z", components: {
    backend: { sourceSha: source, establishedThroughSha: source, imageDigest, taskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:3", desiredCount: 2 },
    frontend: { sourceSha: "d".repeat(40), establishedThroughSha: "d".repeat(40), imageDigest: `sha256:${"e".repeat(64)}`, taskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-frontend:4", desiredCount: 2 }, database: null, security: null,
  } });
  const tasks = [task];
  const reader = { describeTasks: (arns) => ({ tasks: structuredClone(tasks.filter((entry) => arns.includes(entry.taskArn))), failures: [] }), describeTaskDefinition: () => ({ taskDefinition: structuredClone(definition), tags: [] }), describeImages: () => ({ imageDetails: [{ repositoryName: "mscqr-worker", registryId: STAGE_B.account, imageDigest, imageTags: [source] }] }), describeRepositories: () => ({ repositories: [{ repositoryName: "mscqr-worker", registryId: STAGE_B.account, imageTagMutability: "IMMUTABLE" }] }), describeNetworkInterfaces: () => ({ NetworkInterfaces: [structuredClone(eni)] }), lookupEvents: (operation) => [{ CloudTrailEvent: JSON.stringify(operation === "RunTask" ? launch : registration) }], listTasks: () => tasks.map(({ taskArn }) => taskArn) };
  const reference = prepareHistoricalRuntimeReference({ reader, taskArn, componentState: state, componentStateSha256: stateHash(state), recoverySourceSha: release, recoveryTreeSha256: "f".repeat(64), isProtectedSource: () => true });
  const now = "2026-09-29T11:00:00.000Z";
  const report = { schemaVersion: 1, status: "valid", sourceSha: release, evidenceKind: "PLAN_BOUND_PERMISSION", phase: "plan-bound", purpose: "saved-plan-authorization", historicalRuntimeAuthority: { sourceSha: release, referenceSha256: reference.referenceSha256, planApprovalReportSha256: "1".repeat(64), referenceAuditSha256: "2".repeat(64), approvedAt: now } };
  // An actual keyed signature verifier at the injected crypto boundary: unlike
  // `verify: () => true`, a changed signed binding cannot pass these tests.
  const key = crypto.randomBytes(32);
  const sign = ({ digest }) => crypto.createHmac("sha256", key).update(digest).digest("base64");
  const verify = ({ digest, signature }) => signature.equals(Buffer.from(sign({ digest }), "base64"));
  const signature = signPermissionReport(report, { sign, now });
  const evidence = historicalRuntimeEvidence({ reference, report, signatureArtifact: signature });
  const writerContext = { updatedByWorkflow: "T-ej2003/genuine-scan-main/.github/workflows/release-gate.yml@refs/heads/main", githubRunId: "202" };
  return { source, release, imageDigest, taskArn, definitionArn, definition, task, tasks, eni, registration, launch, reader, state, reference, report, signature, evidence, verify, sign, now, writerContext };
}

export const rehashReference = (reference) => { const { referenceSha256, ...body } = reference; reference.referenceSha256 = canonicalSha256(body); return reference; };
