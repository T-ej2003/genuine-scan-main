#!/usr/bin/env node
import { createHash, timingSafeEqual } from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { canonicalJson, PRODUCTION_ACTIVATION_LIFECYCLE } from "./production-green-stage-b-contract.mjs";
import { PRODUCTION_ENVIRONMENT_APPROVAL, assertProductionEnvironmentApprovalIdentity, assertProductionEnvironmentActualReviewer, assertProductionEnvironmentReviewer, assertProductionEnvironmentApprovalFreshness } from "./production-github-environment-approval.mjs";
import { createProductionAwsCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";
import { createStageATerraformBackendLock } from "./production-stage-a-root-drop-orphan-recovery.mjs";

export const STAGE_A_TEMPORARY_EGRESS_CLEANUP = Object.freeze({
  operation: "STAGE_A_EXACT_TEMPORARY_EXECUTOR_EGRESS_CLEANUP",
  workflowRef: "T-ej2003/genuine-scan-main/.github/workflows/authorize-stage-a-temporary-egress-cleanup.yml@refs/heads/main",
  account: "368992683803", region: "eu-west-2", vpcId: "vpc-09825a6dc884b486a",
  ruleId: "sgr-0b8c789e9694d4b77", sourceGroupId: "sg-051a24aedff773761", destinationGroupId: "sg-0c00eb354e0135478",
  protocol: "tcp", fromPort: 443, toPort: 443, ruleDescription: "Temporary ssmmessages endpoint for canary DBA bootstrap",
  sourceGroupName: "mscqr-production-rls-green-executor", sourceGroupDescription: "No-ingress or egress executor security group until reviewed Stage B networking",
  destinationGroupName: "mscqr-temporary-ssmmessages-canary-dba-20260916", destinationGroupDescription: "Temporary ssmmessages endpoint for one read-only canary DBA bootstrap",
  endpointId: "vpce-01baa774cc4ccf0c4", endpointService: "com.amazonaws.eu-west-2.ssmmessages",
  endpointProvenanceEventId: "34f93049-1404-4978-8a05-dfa15d5f4104", endpointProvenanceEventTime: "2026-09-16T10:07:11Z",
  ruleProvenanceEventId: "aeaa2ac0-d693-49ea-98a4-e36d43c1cc99", ruleProvenanceEventTime: "2026-09-16T10:07:09Z",
  provenanceSourceSha: "c402261923e0e4587f9420547d96108e637c4dfe",
  journalPrefix: `${PRODUCTION_ACTIVATION_LIFECYCLE.stageAProductionArtifactsReconciliationPrefix}recovery/temporary-executor-egress-cleanup/`,
});

const SHA256 = /^[a-f0-9]{64}$/;
const SHA40 = /^[a-f0-9]{40}$/;
const TICKET = /^CHG-[0-9]{8}-[0-9]{3,}$/;
const APPROVAL = STAGE_A_TEMPORARY_EGRESS_CLEANUP.workflowRef;
const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const digest = (value) => sha256(canonicalJson(value));
const fail = (message) => { throw new Error(message); };
const required = (argv, key) => { const index = argv.indexOf(key); const value = index < 0 ? undefined : argv[index + 1]; if (!value || value.startsWith("--")) fail(`${key} is required.`); return value; };
const exactKeys = (value, keys) => value && typeof value === "object" && !Array.isArray(value) && canonicalJson(Object.keys(value).sort()) === canonicalJson([...keys].sort());

const authorizationFields = ["schemaVersion", "kind", "operation", "repository", "environment", "sourceSha", "changeTicket", "verificationRef", "account", "region", "vpcId", "ruleId", "sourceGroupId", "destinationGroupId", "protocol", "fromPort", "toPort", "ruleDescription", "sourceGroupName", "sourceGroupDescription", "destinationGroupName", "destinationGroupDescription", "endpointId", "endpointService", "endpointProvenanceEventId", "endpointProvenanceEventTime", "ruleProvenanceEventId", "ruleProvenanceEventTime", "provenanceSourceSha", "maxRuleRevocations", "maxBulkRevocations", "protectedEnvironmentApprovalEvidence", "protectedEnvironmentApprovalEvidenceSha256", "authorizationSha256"];

export function createStageATemporaryEgressCleanupAuthorization({ sourceSha, changeTicket, verificationRef, protectedEnvironmentApprovalEvidence } = {}) {
  const target = STAGE_A_TEMPORARY_EGRESS_CLEANUP;
  if (!SHA40.test(sourceSha || "") || !TICKET.test(changeTicket || "") || typeof verificationRef !== "string" || !verificationRef.trim() || verificationRef.trim().length > 240) fail("Stage-A temporary egress cleanup authorization inputs are invalid.");
  assertProductionEnvironmentApprovalIdentity(protectedEnvironmentApprovalEvidence, { sourceSha, repository: PRODUCTION_ENVIRONMENT_APPROVAL.repository });
  if (protectedEnvironmentApprovalEvidence.workflowRef !== target.workflowRef || protectedEnvironmentApprovalEvidence.environment !== "production") fail("Stage-A temporary egress cleanup requires its exact protected production approval.");
  const body = {
    schemaVersion: 1, kind: "STAGE_A_TEMPORARY_EGRESS_CLEANUP_AUTHORIZATION", operation: target.operation,
    repository: PRODUCTION_ENVIRONMENT_APPROVAL.repository, environment: "production", sourceSha,
    changeTicket, verificationRef: verificationRef.trim(),
    account: target.account, region: target.region, vpcId: target.vpcId, ruleId: target.ruleId,
    sourceGroupId: target.sourceGroupId, destinationGroupId: target.destinationGroupId,
    protocol: target.protocol, fromPort: target.fromPort, toPort: target.toPort, ruleDescription: target.ruleDescription,
    sourceGroupName: target.sourceGroupName, sourceGroupDescription: target.sourceGroupDescription,
    destinationGroupName: target.destinationGroupName, destinationGroupDescription: target.destinationGroupDescription,
    endpointId: target.endpointId, endpointService: target.endpointService,
    endpointProvenanceEventId: target.endpointProvenanceEventId, endpointProvenanceEventTime: target.endpointProvenanceEventTime,
    ruleProvenanceEventId: target.ruleProvenanceEventId, ruleProvenanceEventTime: target.ruleProvenanceEventTime,
    provenanceSourceSha: target.provenanceSourceSha,
    maxRuleRevocations: 1, maxBulkRevocations: 0,
    protectedEnvironmentApprovalEvidence,
    protectedEnvironmentApprovalEvidenceSha256: protectedEnvironmentApprovalEvidence.evidenceSha256,
  };
  return Object.freeze({ ...body, authorizationSha256: digest(body) });
}

export function assertStageATemporaryEgressCleanupAuthorization(value, { sourceSha, workflowRunId, workflowRunAttempt, executionActor, now = new Date() } = {}) {
  if (!exactKeys(value, authorizationFields)) fail("Stage-A temporary egress cleanup authorization schema is invalid.");
  const target = STAGE_A_TEMPORARY_EGRESS_CLEANUP;
  const approval = value.protectedEnvironmentApprovalEvidence;
  assertProductionEnvironmentApprovalIdentity(approval, { sourceSha, repository: PRODUCTION_ENVIRONMENT_APPROVAL.repository });
  if (value.schemaVersion !== 1 || value.kind !== "STAGE_A_TEMPORARY_EGRESS_CLEANUP_AUTHORIZATION" || value.operation !== target.operation
    || value.repository !== PRODUCTION_ENVIRONMENT_APPROVAL.repository || value.environment !== "production" || value.sourceSha !== sourceSha
    || value.changeTicket !== value.changeTicket?.trim?.() || !TICKET.test(value.changeTicket || "") || !value.verificationRef?.trim?.()
    || value.account !== target.account || value.region !== target.region || value.vpcId !== target.vpcId || value.ruleId !== target.ruleId
    || value.sourceGroupId !== target.sourceGroupId || value.destinationGroupId !== target.destinationGroupId
    || value.protocol !== target.protocol || value.fromPort !== target.fromPort || value.toPort !== target.toPort || value.ruleDescription !== target.ruleDescription
    || value.sourceGroupName !== target.sourceGroupName || value.sourceGroupDescription !== target.sourceGroupDescription
    || value.destinationGroupName !== target.destinationGroupName || value.destinationGroupDescription !== target.destinationGroupDescription
    || value.endpointId !== target.endpointId || value.endpointService !== target.endpointService
    || value.endpointProvenanceEventId !== target.endpointProvenanceEventId || value.endpointProvenanceEventTime !== target.endpointProvenanceEventTime
    || value.ruleProvenanceEventId !== target.ruleProvenanceEventId || value.ruleProvenanceEventTime !== target.ruleProvenanceEventTime || value.provenanceSourceSha !== target.provenanceSourceSha
    || value.maxRuleRevocations !== 1 || value.maxBulkRevocations !== 0
    || value.protectedEnvironmentApprovalEvidenceSha256 !== approval?.evidenceSha256
    || approval.workflowRef !== target.workflowRef || approval.workflowRunId !== String(workflowRunId)
    || approval.workflowRunAttempt !== String(workflowRunAttempt)) fail("Stage-A temporary egress cleanup authorization binding is invalid.");
  assertProductionEnvironmentApprovalFreshness(approval, { now });
  const reviewer = assertProductionEnvironmentActualReviewer(approval, { sourceSha, repository: PRODUCTION_ENVIRONMENT_APPROVAL.repository, executionActor: executionActor || approval.executionActor });
  assertProductionEnvironmentReviewer(approval, { approvedBy: reviewer, executionActor: executionActor || approval.executionActor });
  const { authorizationSha256, ...body } = value;
  if (!SHA256.test(authorizationSha256 || "") || digest(body) !== authorizationSha256) fail("Stage-A temporary egress cleanup authorization hash is invalid.");
  return Object.freeze(value);
}

export function assertStageATemporaryEgressCloudTrailProvenance({ endpointEvents, ruleEvents } = {}) {
  const target = STAGE_A_TEMPORARY_EGRESS_CLEANUP;
  const one = (events, eventId, eventName, eventTime) => {
    if (!Array.isArray(events)) fail("Temporary egress CloudTrail provenance is incomplete.");
    const matches = events.flatMap(({ EventId, CloudTrailEvent }) => {
      try { return EventId === eventId ? [JSON.parse(CloudTrailEvent)] : []; } catch { return []; }
    });
    if (matches.length !== 1 || matches[0].eventID !== eventId || matches[0].eventName !== eventName || matches[0].eventSource !== "ec2.amazonaws.com"
      || matches[0].eventTime !== eventTime || matches[0].userIdentity?.arn !== `arn:aws:iam::${target.account}:root`) fail("Temporary egress CloudTrail provenance does not match the exact root bootstrap events.");
    return matches[0];
  };
  const endpoint = one(endpointEvents, target.endpointProvenanceEventId, "CreateVpcEndpoint", target.endpointProvenanceEventTime);
  const request = endpoint.requestParameters?.CreateVpcEndpointRequest;
  if (request?.VpcId !== target.vpcId || request?.ServiceName !== target.endpointService || request?.VpcEndpointType !== "Interface"
    || request?.SecurityGroupId?.content !== target.destinationGroupId) fail("Temporary ssmmessages endpoint creation provenance changed.");
  const rule = one(ruleEvents, target.ruleProvenanceEventId, "AuthorizeSecurityGroupEgress", target.ruleProvenanceEventTime);
  const parameters = rule.requestParameters; const permissions = parameters?.ipPermissions?.items;
  if (parameters?.groupId !== target.sourceGroupId || !Array.isArray(permissions) || permissions.length !== 1
    || permissions[0].ipProtocol !== target.protocol || permissions[0].fromPort !== target.fromPort || permissions[0].toPort !== target.toPort
    || permissions[0].groups?.items?.length !== 1 || permissions[0].groups.items[0].groupId !== target.destinationGroupId
    || permissions[0].groups.items[0].description !== target.ruleDescription) fail("Temporary executor egress rule creation provenance changed.");
  return true;
}

export function validateStageATemporaryEgressLiveInventory({ caller, region = STAGE_A_TEMPORARY_EGRESS_CLEANUP.region, ruleResponse, sourceGroup, destinationGroup, endpointResponse, networkInterfaces, activeTaskUsesSourceGroup, canonicalDependencyPresent = false, provenanceEvents } = {}) {
  const target = STAGE_A_TEMPORARY_EGRESS_CLEANUP;
  if (region !== target.region || caller?.Account !== target.account || caller?.Arn !== `arn:aws:iam::${target.account}:root`) fail("Temporary egress cleanup requires the exact production root caller and region.");
  const rules = ruleResponse?.SecurityGroupRules;
  if (!Array.isArray(rules) || rules.length !== 1) fail("Temporary egress cleanup rule readback is missing or ambiguous.");
  const [rule] = rules;
  if (rule?.SecurityGroupRuleId !== target.ruleId || rule.GroupId !== target.sourceGroupId || rule.IsEgress !== true
    || rule.IpProtocol !== target.protocol || rule.FromPort !== target.fromPort || rule.ToPort !== target.toPort
    || rule.ReferencedGroupInfo?.GroupId !== target.destinationGroupId || rule.ReferencedGroupInfo?.UserId !== target.account
    || rule.Description !== target.ruleDescription || rule.GroupOwnerId !== target.account || (rule.VpcId !== undefined && rule.VpcId !== target.vpcId)) fail("Temporary egress cleanup rule identity changed.");
  const source = sourceGroup?.SecurityGroups;
  const destination = destinationGroup?.SecurityGroups;
  if (!Array.isArray(source) || source.length !== 1 || !Array.isArray(destination) || destination.length !== 1) fail("Temporary egress cleanup security-group readback is incomplete.");
  const [src] = source; const [dst] = destination;
  if (src.GroupId !== target.sourceGroupId || src.GroupName !== target.sourceGroupName || src.Description !== target.sourceGroupDescription || src.VpcId !== target.vpcId || src.OwnerId !== target.account
    || dst.GroupId !== target.destinationGroupId || dst.GroupName !== target.destinationGroupName || dst.Description !== target.destinationGroupDescription || dst.VpcId !== target.vpcId || dst.OwnerId !== target.account
    || !Array.isArray(dst.Tags) || !dst.Tags.some(({ Key, Value }) => Key === "MSCQRTemporary" && Value === "true")
    || !dst.Tags.some(({ Key, Value }) => Key === "MSCQROperation" && Value === "read-only-canary-credential-bootstrap")
    || !dst.Tags.some(({ Key, Value }) => Key === "MSCQRSourceSha" && Value === target.provenanceSourceSha)
    || !Array.isArray(src.Tags) || !src.Tags.some(({ Key, Value }) => Key === "ManagedBy" && Value === "Terraform")) fail("Temporary egress cleanup security-group ownership or provenance changed.");
  const sourcePairs = (src.IpPermissionsEgress || []).flatMap(({ UserIdGroupPairs = [] }) => UserIdGroupPairs).filter(({ GroupId, Description }) => GroupId === target.destinationGroupId && Description === target.ruleDescription);
  const endpointIngress = dst.IpPermissions;
  const endpointPairs = Array.isArray(endpointIngress) ? endpointIngress.flatMap(({ UserIdGroupPairs = [] }) => UserIdGroupPairs).filter(({ GroupId, Description, UserId }) => GroupId === target.sourceGroupId && UserId === target.account && Description === "Temporary ECS Exec from isolated DBA task only") : [];
  const endpointRule = endpointIngress?.[0];
  if (sourcePairs.length !== 1 || endpointIngress?.length !== 1 || endpointRule?.IpProtocol !== target.protocol || endpointRule?.FromPort !== target.fromPort || endpointRule?.ToPort !== target.toPort
    || endpointPairs.length !== 1 || endpointRule.IpRanges?.length !== 0 || endpointRule.Ipv6Ranges?.length !== 0 || endpointRule.PrefixListIds?.length !== 0 || (dst.IpPermissionsEgress || []).length !== 0) fail("Temporary egress cleanup security-group rule topology is incomplete or ambiguous.");
  const endpoints = endpointResponse?.VpcEndpoints;
  if (!Array.isArray(endpoints) || endpoints.length !== 1) fail("Temporary egress cleanup endpoint readback is incomplete.");
  const [endpoint] = endpoints;
  if (endpoint.VpcEndpointId !== target.endpointId || endpoint.OwnerId !== target.account || endpoint.VpcId !== target.vpcId
    || endpoint.ServiceName !== target.endpointService || endpoint.State !== "available"
    || !Array.isArray(endpoint.Groups) || endpoint.Groups.length !== 1 || endpoint.Groups[0]?.GroupId !== target.destinationGroupId) fail("Temporary egress cleanup endpoint identity or attachment changed.");
  assertStageATemporaryEgressCloudTrailProvenance(provenanceEvents);
  if (!Array.isArray(networkInterfaces) || networkInterfaces.length !== 0) fail("Temporary egress cleanup has an active source security-group ENI dependency.");
  if (activeTaskUsesSourceGroup !== false || canonicalDependencyPresent !== false) fail("Temporary egress cleanup has an active task or canonical source dependency.");
  return Object.freeze({ ruleId: target.ruleId, sourceGroupId: target.sourceGroupId, destinationGroupId: target.destinationGroupId, endpointId: target.endpointId, revocationCount: 1 });
}

function decodeJson(output, label) { try { return JSON.parse(output); } catch { fail(`${label} response is malformed.`); } }
function activeTaskUsesSourceGroup(run, sourceNetworkInterfaces) {
  const clusters = decodeJson(run(["ecs", "list-clusters", "--output", "json", "--no-cli-pager"]), "ECS cluster census").clusterArns;
  if (!Array.isArray(clusters)) fail("ECS cluster census is incomplete.");
  const tasksByCluster = new Map();
  for (const cluster of clusters) {
    const arns = decodeJson(run(["ecs", "list-tasks", "--cluster", cluster, "--desired-status", "RUNNING", "--output", "json", "--no-cli-pager"]), "ECS active-task census").taskArns;
    if (!Array.isArray(arns) || arns.some((arn) => typeof arn !== "string" || !arn.startsWith("arn:aws:ecs:eu-west-2:368992683803:task/"))) fail("ECS active-task census is malformed.");
    tasksByCluster.set(cluster, arns);
  }
  const allTasks = [...tasksByCluster.values()].flat();
  if (new Set(allTasks).size !== allTasks.length) fail("ECS active-task census contains duplicate task identities.");
  const enis = new Set();
  for (const [cluster, arns] of tasksByCluster) for (let index = 0; index < arns.length; index += 100) {
    const batch = arns.slice(index, index + 100);
    const response = decodeJson(run(["ecs", "describe-tasks", "--cluster", cluster, "--tasks", ...batch, "--output", "json", "--no-cli-pager"]), "ECS active-task details");
    if (!Array.isArray(response.tasks) || response.failures?.length || response.tasks.length !== batch.length) fail("ECS active-task details are incomplete.");
    for (const task of response.tasks) {
      if (!Array.isArray(task.attachments)) fail("ECS task network attachment details are incomplete.");
      for (const { name, value } of task.attachments.flatMap(({ details }) => Array.isArray(details) ? details : [])) if (name === "networkInterfaceId") {
        if (typeof value !== "string" || !/^eni-[a-f0-9]+$/.test(value)) fail("ECS task ENI binding is malformed.");
        enis.add(value);
      }
    }
  }
  const taskEnis = [...enis];
  for (let index = 0; index < taskEnis.length; index += 100) {
    const batch = taskEnis.slice(index, index + 100);
    const response = decodeJson(run(["ec2", "describe-network-interfaces", "--network-interface-ids", ...batch, "--output", "json", "--no-cli-pager"]), "ECS task ENI details");
    if (!Array.isArray(response.NetworkInterfaces) || response.NetworkInterfaces.length !== batch.length) fail("ECS task ENI details are incomplete.");
    if (response.NetworkInterfaces.some(({ Groups }) => !Array.isArray(Groups) || Groups.some(({ GroupId }) => GroupId === STAGE_A_TEMPORARY_EGRESS_CLEANUP.sourceGroupId))) return true;
  }
  return sourceNetworkInterfaces.some(({ NetworkInterfaceId }) => enis.has(NetworkInterfaceId));
}

const readInventory = (run) => {
  const target = STAGE_A_TEMPORARY_EGRESS_CLEANUP;
  const caller = decodeJson(run(["sts", "get-caller-identity", "--output", "json", "--no-cli-pager"]), "Caller identity");
  const ruleResponse = decodeJson(run(["ec2", "describe-security-group-rules", "--security-group-rule-ids", target.ruleId, "--output", "json", "--no-cli-pager"]), "Security-group rule");
  const sourceGroup = decodeJson(run(["ec2", "describe-security-groups", "--group-ids", target.sourceGroupId, "--output", "json", "--no-cli-pager"]), "Source security group");
  const destinationGroup = decodeJson(run(["ec2", "describe-security-groups", "--group-ids", target.destinationGroupId, "--output", "json", "--no-cli-pager"]), "Destination security group");
  const endpointResponse = decodeJson(run(["ec2", "describe-vpc-endpoints", "--vpc-endpoint-ids", target.endpointId, "--output", "json", "--no-cli-pager"]), "VPC endpoint");
  const network = decodeJson(run(["ec2", "describe-network-interfaces", "--filters", `Name=group-id,Values=${target.sourceGroupId}`, "--output", "json", "--no-cli-pager"]), "Source ENI census");
  if (!Array.isArray(network.NetworkInterfaces)) fail("Source ENI census is incomplete.");
  const taskDependency = activeTaskUsesSourceGroup(run, network.NetworkInterfaces);
  const endpointEvents = decodeJson(run(["cloudtrail", "lookup-events", "--lookup-attributes", "AttributeKey=EventName,AttributeValue=CreateVpcEndpoint", "--start-time", "2026-09-16T00:00:00Z", "--end-time", "2026-09-17T23:59:59Z", "--output", "json", "--no-cli-pager"]), "Endpoint CloudTrail provenance").Events;
  const ruleEvents = decodeJson(run(["cloudtrail", "lookup-events", "--lookup-attributes", "AttributeKey=EventName,AttributeValue=AuthorizeSecurityGroupEgress", "--start-time", "2026-09-16T00:00:00Z", "--end-time", "2026-09-17T23:59:59Z", "--output", "json", "--no-cli-pager"]), "Egress CloudTrail provenance").Events;
  const source = fs.readFileSync(path.join(repositoryRoot(), "infra/aws/terraform/production-green-stage-a/main.tf"), "utf8");
  const canonicalExecutorEndpointRule = /resource "aws_vpc_security_group_egress_rule" "executor_interface_endpoints" \{\s+security_group_id\s+=\s+aws_security_group\.executor\.id\s+referenced_security_group_id\s+=\s+aws_security_group\.executor_endpoints\.id\s+from_port\s+=\s+443\s+to_port\s+=\s+443\s+ip_protocol\s+=\s+"tcp"\s+description\s+=\s+"Reviewed AWS interface endpoints only"\s+\}/.test(source);
  const canonicalDependencyPresent = source.includes(target.destinationGroupId) || source.includes(target.endpointService) || !canonicalExecutorEndpointRule;
  const validated = validateStageATemporaryEgressLiveInventory({ caller, ruleResponse, sourceGroup, destinationGroup, endpointResponse, networkInterfaces: network.NetworkInterfaces, activeTaskUsesSourceGroup: taskDependency, canonicalDependencyPresent, provenanceEvents: { endpointEvents, ruleEvents } });
  return { validated, ruleResponse, sourceNetworkInterfaceCount: network.NetworkInterfaces.length, activeTaskUsesSourceGroup: taskDependency, canonicalDependencyPresent };
};

export function readStageATemporaryEgressInventory({ run } = {}) {
  const reader = run || createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: "mscqr-production-root", region: STAGE_A_TEMPORARY_EGRESS_CLEANUP.region });
  if (typeof reader !== "function") fail("Temporary egress cleanup read-only inventory requires a command runner.");
  return readInventory(reader);
}

function repositoryRoot() { return path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../.."); }

function resolveAuthorizationArtifact({ workflowRunId, workflowRunAttempt, sourceSha, run = (command, args, options = {}) => execFileSync(command, args, { encoding: options.encoding === null ? null : "utf8", stdio: ["ignore", "pipe", "pipe"] }) } = {}) {
  if (!/^[1-9][0-9]*$/.test(String(workflowRunId || "")) || !/^[1-9][0-9]*$/.test(String(workflowRunAttempt || ""))) fail("Temporary egress cleanup workflow coordinates are invalid.");
  const workflow = decodeJson(run("gh", ["api", `repos/${PRODUCTION_ENVIRONMENT_APPROVAL.repository}/actions/runs/${workflowRunId}`]), "Authorization workflow");
  if (String(workflow.id) !== String(workflowRunId) || workflow.repository?.full_name !== PRODUCTION_ENVIRONMENT_APPROVAL.repository || workflow.head_repository?.full_name !== PRODUCTION_ENVIRONMENT_APPROVAL.repository
    || workflow.path !== ".github/workflows/authorize-stage-a-temporary-egress-cleanup.yml" || workflow.event !== "workflow_dispatch" || workflow.head_sha !== sourceSha
    || workflow.status !== "completed" || workflow.conclusion !== "success" || String(workflow.run_attempt) !== String(workflowRunAttempt)) fail("Temporary egress cleanup workflow provenance is invalid.");
  const pages = decodeJson(run("gh", ["api", `repos/${PRODUCTION_ENVIRONMENT_APPROVAL.repository}/actions/runs/${workflowRunId}/artifacts`, "--paginate", "--slurp"]), "Authorization artifact index");
  const artifacts = pages.flatMap((page) => page.artifacts || []).filter((item) => item.name === "stage-a-temporary-egress-cleanup-authorization" && item.expired === false && String(item.workflow_run?.id) === String(workflowRunId) && item.workflow_run?.head_sha === sourceSha && item.workflow_run?.repository_id === workflow.repository?.id && /^sha256:[a-f0-9]{64}$/.test(item.digest || ""));
  if (artifacts.length !== 1) fail("Temporary egress cleanup authorization artifact is missing, duplicated, or unbound.");
  const archive = run("gh", ["api", `repos/${PRODUCTION_ENVIRONMENT_APPROVAL.repository}/actions/artifacts/${artifacts[0].id}/zip`, "--header", "Accept: application/vnd.github+json", "--output", "-"], { encoding: null }); const bytes = Buffer.isBuffer(archive) ? archive : Buffer.from(archive);
  const expectedDigest = Buffer.from(artifacts[0].digest.slice("sha256:".length), "hex"); const actualDigest = createHash("sha256").update(bytes).digest();
  if (!timingSafeEqual(expectedDigest, actualDigest)) fail("Temporary egress cleanup authorization artifact digest is invalid.");
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-stage-a-egress-authorization-")); const zip = path.join(directory, "authorization.zip");
  try {
    fs.writeFileSync(zip, bytes, { mode: 0o600, flag: "wx" });
    const members = run("unzip", ["-Z1", zip]).trim().split(/\r?\n/).filter(Boolean);
    if (members.length !== 1 || members[0] !== "authorization.json") fail("Temporary egress cleanup artifact contents are unexpected.");
    const authorization = decodeJson(run("unzip", ["-p", zip, "authorization.json"]), "Temporary egress cleanup authorization");
    return assertStageATemporaryEgressCleanupAuthorization(authorization, { sourceSha, workflowRunId, workflowRunAttempt, executionActor: workflow.actor?.login });
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
}

function reserveCleanupAuthorization({ releaseRun, authorization }) {
  const target = STAGE_A_TEMPORARY_EGRESS_CLEANUP; const key = `${target.journalPrefix}${authorization.authorizationSha256}/attempt.json`;
  const body = { schemaVersion: 1, kind: "STAGE_A_TEMPORARY_EGRESS_CLEANUP_ATTEMPT", operation: target.operation, sourceSha: authorization.sourceSha, changeTicket: authorization.changeTicket, authorizationSha256: authorization.authorizationSha256, ruleId: target.ruleId, createdAt: new Date().toISOString() };
  const bytes = Buffer.from(`${canonicalJson(body)}\n`); const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-stage-a-egress-journal-")); const file = path.join(directory, "attempt.json");
  try {
    fs.writeFileSync(file, bytes, { mode: 0o600, flag: "wx" });
    try { releaseRun(["s3api", "put-object", "--expected-bucket-owner", STAGE_A_TEMPORARY_EGRESS_CLEANUP.account, "--bucket", PRODUCTION_ACTIVATION_LIFECYCLE.bucket, "--key", key, "--body", file, "--content-type", "application/json", "--server-side-encryption", "AES256", "--if-none-match", "*", "--output", "json", "--no-cli-pager"]); }
    catch (error) { if (/PreconditionFailed|ConditionalRequestConflict|412|409/i.test(`${error.message || ""}\n${error.stderr || ""}`)) fail("Temporary egress cleanup authorization has already been consumed; replay is forbidden."); throw error; }
    const readbackPath = path.join(directory, "attempt-readback.json");
    releaseRun(["s3api", "get-object", "--expected-bucket-owner", STAGE_A_TEMPORARY_EGRESS_CLEANUP.account, "--bucket", PRODUCTION_ACTIVATION_LIFECYCLE.bucket, "--key", key, "--output", "json", "--no-cli-pager", readbackPath]);
    if (!fs.readFileSync(readbackPath).equals(bytes)) fail("Temporary egress cleanup attempt journal readback differs from the conditional reservation.");
    return key;
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
}

export async function executeStageATemporaryEgressCleanup({ authorization, sourceSha, workflowRunId, workflowRunAttempt, rootRun, releaseRun, terraformStateLock, read = readInventory, reserve = reserveCleanupAuthorization } = {}) {
  const target = STAGE_A_TEMPORARY_EGRESS_CLEANUP;
  assertStageATemporaryEgressCleanupAuthorization(authorization, { sourceSha, workflowRunId, workflowRunAttempt });
  if (typeof rootRun !== "function" || typeof releaseRun !== "function" || !terraformStateLock || typeof terraformStateLock.acquire !== "function" || typeof terraformStateLock.release !== "function") fail("Temporary egress cleanup execution composition is incomplete.");
  const before = read(rootRun);
  await terraformStateLock.acquire(); let locked = true;
  try {
    const lockedBefore = read(rootRun);
    if (lockedBefore.validated.ruleId !== before.validated.ruleId) fail("Temporary egress cleanup target changed while acquiring the Stage-A lock.");
    await reserve({ releaseRun, authorization });
    const finalCheck = read(rootRun);
    if (finalCheck.validated.ruleId !== target.ruleId || canonicalJson(finalCheck.ruleResponse) !== canonicalJson(lockedBefore.ruleResponse)) fail("Temporary egress cleanup live rule changed after authorization; no mutation was performed.");
    try { rootRun(["ec2", "revoke-security-group-egress", "--security-group-rule-ids", target.ruleId, "--output", "json", "--no-cli-pager"]); }
    catch (error) {
      const observed = read(rootRun);
      if (observed.ruleResponse?.SecurityGroupRules?.length !== 0) throw new Error("Temporary egress cleanup revoke outcome is ambiguous; authorization consumed and no retry is permitted.", { cause: error });
    }
    const after = read(rootRun);
    if (after.ruleResponse?.SecurityGroupRules?.length !== 0) fail("Temporary egress cleanup rule remains after the exact revoke.");
    const result = { schemaVersion: 1, kind: "STAGE_A_TEMPORARY_EGRESS_CLEANUP_RESULT", operation: target.operation, sourceSha, changeTicket: authorization.changeTicket, authorizationSha256: authorization.authorizationSha256, ruleId: target.ruleId, revocationCount: 1, completedAt: new Date().toISOString() };
    writeCleanupResult({ releaseRun, authorization, result });
    return Object.freeze({ completed: true, ruleId: target.ruleId, revocationCount: 1 });
  } finally { if (locked) { await terraformStateLock.release(); locked = false; } }
}

function writeCleanupResult({ releaseRun, authorization, result }) {
  const key = `${STAGE_A_TEMPORARY_EGRESS_CLEANUP.journalPrefix}${authorization.authorizationSha256}/result.json`;
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-stage-a-egress-result-")); const file = path.join(directory, "result.json"); const bytes = Buffer.from(`${canonicalJson(result)}\n`);
  try {
    fs.writeFileSync(file, bytes, { mode: 0o600, flag: "wx" });
    releaseRun(["s3api", "put-object", "--expected-bucket-owner", STAGE_A_TEMPORARY_EGRESS_CLEANUP.account, "--bucket", PRODUCTION_ACTIVATION_LIFECYCLE.bucket, "--key", key, "--body", file, "--content-type", "application/json", "--server-side-encryption", "AES256", "--if-none-match", "*", "--output", "json", "--no-cli-pager"]);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
}

export async function runStageATemporaryEgressCleanupCli(argv = process.argv.slice(2)) {
  if (!argv.includes("--production")) fail("Stage-A temporary egress cleanup requires --production.");
  const sourceSha = required(argv, "--source-sha"); const runId = required(argv, "--authorization-workflow-run-id"); const attempt = required(argv, "--authorization-workflow-run-attempt"); const rootProfile = required(argv, "--root-profile");
  if (rootProfile !== "mscqr-production-root") fail("Stage-A exact temporary egress cleanup requires the documented root-only recovery credential boundary.");
  const checkout = repositoryRoot(); const head = execFileSync("git", ["rev-parse", "HEAD"], { cwd: checkout, encoding: "utf8" }).trim();
  const branchStatus = execFileSync("git", ["status", "--porcelain=v1", "--untracked-files=all"], { cwd: checkout, encoding: "utf8" });
  const protectedMainSha = execFileSync("gh", ["api", `repos/${PRODUCTION_ENVIRONMENT_APPROVAL.repository}/branches/main`, "--jq", ".commit.sha"], { encoding: "utf8" }).trim();
  if (head !== sourceSha || protectedMainSha !== sourceSha || branchStatus) fail("Stage-A temporary egress cleanup requires the exact clean current protected-main checkout.");
  const authorization = resolveAuthorizationArtifact({ workflowRunId: runId, workflowRunAttempt: attempt, sourceSha });
  const rootRun = createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: rootProfile, region: STAGE_A_TEMPORARY_EGRESS_CLEANUP.region });
  const releaseRun = createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: "mscqr-production-release-deployer", region: STAGE_A_TEMPORARY_EGRESS_CLEANUP.region });
  const terraformStateLock = createStageATerraformBackendLock({ run: releaseRun, lockFilePath: path.join(os.tmpdir(), `stage-a-exact-egress-cleanup-${authorization.authorizationSha256}.tflock`) });
  const result = await executeStageATemporaryEgressCleanup({ authorization, sourceSha, workflowRunId: runId, workflowRunAttempt: attempt, rootRun, releaseRun, terraformStateLock });
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`); return result;
}

export async function authorizeStageATemporaryEgressCleanupCli(argv = process.argv.slice(2), env = process.env) {
  if (!argv.includes("--production")) fail("Stage-A temporary egress cleanup authorization requires --production.");
  const sourceSha = required(argv, "--source-sha"); const approvalPath = required(argv, "--environment-approval"); const outputPath = required(argv, "--output");
  const authorization = createStageATemporaryEgressCleanupAuthorization({ sourceSha, changeTicket: required(argv, "--change-ticket"), verificationRef: required(argv, "--verification-ref"), protectedEnvironmentApprovalEvidence: JSON.parse(fs.readFileSync(approvalPath, "utf8")) });
  assertProductionEnvironmentApprovalIdentity(authorization.protectedEnvironmentApprovalEvidence, { sourceSha, repository: PRODUCTION_ENVIRONMENT_APPROVAL.repository });
  if (env.GITHUB_ACTIONS !== "true" || env.GITHUB_WORKFLOW_REF !== APPROVAL || env.GITHUB_EVENT_NAME !== "workflow_dispatch" || authorization.protectedEnvironmentApprovalEvidence.workflowRunId !== env.GITHUB_RUN_ID || authorization.protectedEnvironmentApprovalEvidence.workflowRunAttempt !== env.GITHUB_RUN_ATTEMPT) fail("Temporary egress cleanup authorization is not running in its exact protected GitHub workflow.");
  fs.writeFileSync(outputPath, `${canonicalJson(authorization)}\n`, { mode: 0o600, flag: "wx" });
  process.stdout.write(`${JSON.stringify({ operation: authorization.operation, sourceSha, changeTicket: authorization.changeTicket, authorizationSha256: authorization.authorizationSha256 })}\n`);
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) {
  const command = process.argv[2];
  const run = command === "--authorize" ? authorizeStageATemporaryEgressCleanupCli(process.argv.slice(3)) : runStageATemporaryEgressCleanupCli(process.argv.slice(2));
  Promise.resolve(run).catch((error) => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
}
