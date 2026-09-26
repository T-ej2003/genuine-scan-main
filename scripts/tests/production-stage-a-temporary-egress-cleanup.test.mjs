import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import JSZip from "jszip";
import { createProductionEnvironmentApprovalEvidence, PRODUCTION_ENVIRONMENT_APPROVAL } from "../aws/production-github-environment-approval.mjs";
import { assertStageATemporaryEgressCleanupAuthorization, assertStageATemporaryEgressCleanupJournalRetention, assertStageATemporaryEgressCloudTrailProvenance, createStageATemporaryEgressCleanupAuthorization, executeStageATemporaryEgressCleanup, resolveStageATemporaryEgressCleanupAuthorizationArtifact, STAGE_A_TEMPORARY_EGRESS_CLEANUP, validateStageATemporaryEgressLiveInventory } from "../aws/production-stage-a-temporary-egress-cleanup.mjs";
import { canonicalJson } from "../aws/production-green-stage-b-contract.mjs";
import { createProductionGithubCommandRunner } from "../aws/production-credential-source-contract.mjs";

const sourceSha = "1d2bda9fd3e740d51fba199021b354724cf479d3";
const now = new Date();
const approval = createProductionEnvironmentApprovalEvidence({
  environmentConfig: { id: 1, name: "production", can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: true, reviewers: [{ type: "User", reviewer: { id: 7, login: "reviewer" } }] }] },
  repository: PRODUCTION_ENVIRONMENT_APPROVAL.repository, environment: "production", sourceSha,
  workflowRef: STAGE_A_TEMPORARY_EGRESS_CLEANUP.workflowRef, eventName: "workflow_dispatch", workflowRunId: "42", workflowRunAttempt: "1", executionActor: "operator", observedAt: now.toISOString(),
  actualApproval: { state: "approved", environmentId: 1, environmentName: "production", userId: 7, userLogin: "reviewer" },
});
const authorization = createStageATemporaryEgressCleanupAuthorization({ sourceSha, changeTicket: "CHG-20260925-001", verificationRef: "stage-a-plan-run-1", protectedEnvironmentApprovalEvidence: approval });
const identity = { Account: "368992683803", Arn: "arn:aws:iam::368992683803:root" };
const rule = { SecurityGroupRuleId: "sgr-0b8c789e9694d4b77", GroupId: "sg-051a24aedff773761", IsEgress: true, IpProtocol: "tcp", FromPort: 443, ToPort: 443, ReferencedGroupInfo: { GroupId: "sg-0c00eb354e0135478", UserId: "368992683803" }, Description: "Temporary ssmmessages endpoint for canary DBA bootstrap", GroupOwnerId: "368992683803", VpcId: "vpc-09825a6dc884b486a" };
const sourceGroup = { SecurityGroups: [{ GroupId: "sg-051a24aedff773761", GroupName: "mscqr-production-rls-green-executor", Description: "No-ingress or egress executor security group until reviewed Stage B networking", VpcId: "vpc-09825a6dc884b486a", OwnerId: "368992683803", Tags: [{ Key: "ManagedBy", Value: "Terraform" }], IpPermissionsEgress: [{ UserIdGroupPairs: [{ GroupId: "sg-0c00eb354e0135478", Description: "Temporary ssmmessages endpoint for canary DBA bootstrap" }] }] }] };
const destinationGroup = { SecurityGroups: [{ GroupId: "sg-0c00eb354e0135478", GroupName: "mscqr-temporary-ssmmessages-canary-dba-20260916", Description: "Temporary ssmmessages endpoint for one read-only canary DBA bootstrap", VpcId: "vpc-09825a6dc884b486a", OwnerId: "368992683803", Tags: [{ Key: "MSCQRTemporary", Value: "true" }, { Key: "MSCQROperation", Value: "read-only-canary-credential-bootstrap" }, { Key: "MSCQRSourceSha", Value: "c402261923e0e4587f9420547d96108e637c4dfe" }], IpPermissions: [{ IpProtocol: "tcp", FromPort: 443, ToPort: 443, UserIdGroupPairs: [{ GroupId: "sg-051a24aedff773761", UserId: "368992683803", Description: "Temporary ECS Exec from isolated DBA task only" }], IpRanges: [], Ipv6Ranges: [], PrefixListIds: [] }], IpPermissionsEgress: [] }] };
const endpointResponse = { VpcEndpoints: [{ VpcEndpointId: "vpce-01baa774cc4ccf0c4", OwnerId: "368992683803", VpcId: "vpc-09825a6dc884b486a", ServiceName: "com.amazonaws.eu-west-2.ssmmessages", State: "available", Groups: [{ GroupId: "sg-0c00eb354e0135478" }] }] };
const provenanceEvents = {
  endpointEvents: [{ EventId: "34f93049-1404-4978-8a05-dfa15d5f4104", CloudTrailEvent: JSON.stringify({ eventID: "34f93049-1404-4978-8a05-dfa15d5f4104", eventTime: "2026-09-16T10:07:11Z", eventName: "CreateVpcEndpoint", eventSource: "ec2.amazonaws.com", userIdentity: { arn: "arn:aws:iam::368992683803:root" }, requestParameters: { CreateVpcEndpointRequest: { VpcId: "vpc-09825a6dc884b486a", ServiceName: "com.amazonaws.eu-west-2.ssmmessages", VpcEndpointType: "Interface", SecurityGroupId: { content: "sg-0c00eb354e0135478" } } } }) }],
  ruleEvents: [{ EventId: "aeaa2ac0-d693-49ea-98a4-e36d43c1cc99", CloudTrailEvent: JSON.stringify({ eventID: "aeaa2ac0-d693-49ea-98a4-e36d43c1cc99", eventTime: "2026-09-16T10:07:09Z", eventName: "AuthorizeSecurityGroupEgress", eventSource: "ec2.amazonaws.com", userIdentity: { arn: "arn:aws:iam::368992683803:root" }, requestParameters: { groupId: "sg-051a24aedff773761", ipPermissions: { items: [{ ipProtocol: "tcp", fromPort: 443, toPort: 443, groups: { items: [{ groupId: "sg-0c00eb354e0135478", description: "Temporary ssmmessages endpoint for canary DBA bootstrap" }] } }] } } }) }],
};
const inventory = (overrides = {}) => ({ caller: identity, ruleResponse: { SecurityGroupRules: [rule] }, sourceGroup, destinationGroup, endpointResponse, networkInterfaces: [], activeTaskUsesSourceGroup: false, canonicalDependencyPresent: false, provenanceEvents, ...overrides });
const lock = () => ({ acquire: async () => {}, release: async () => {} });
const rootRunner = (calls = []) => (args) => {
  if (args[1] === "get-bucket-versioning") return JSON.stringify({ Status: "Enabled" });
  if (args[1] === "get-bucket-lifecycle-configuration") throw Object.assign(new Error("NoSuchLifecycleConfiguration"), { stderr: "NoSuchLifecycleConfiguration" });
  calls.push(args);
  return "{}";
};

test("authorization binds one exact source, ticket, target, and actual protected-environment approval", () => {
  assert.doesNotThrow(() => assertStageATemporaryEgressCleanupAuthorization(authorization, { sourceSha, workflowRunId: "42", workflowRunAttempt: "1", now }));
  for (const mutate of [
    (value) => ({ ...value, ruleId: "sgr-other" }),
    (value) => ({ ...value, sourceSha: "2".repeat(40) }),
    (value) => ({ ...value, changeTicket: "CHG-20260925-002" }),
    (value) => ({ ...value, maxRuleRevocations: 2 }),
    (value) => ({ ...value, protectedEnvironmentApprovalEvidenceSha256: "0".repeat(64) }),
  ]) assert.throws(() => assertStageATemporaryEgressCleanupAuthorization(mutate(authorization), { sourceSha, workflowRunId: "42", workflowRunAttempt: "1", now }));
  assert.throws(() => assertStageATemporaryEgressCleanupAuthorization(authorization, { sourceSha: "3".repeat(40), workflowRunId: "42", workflowRunAttempt: "1", now }));
  assert.throws(() => assertStageATemporaryEgressCleanupAuthorization(authorization, { sourceSha, workflowRunId: "43", workflowRunAttempt: "1", now }));
  assert.throws(() => assertStageATemporaryEgressCleanupAuthorization(authorization, { sourceSha, workflowRunId: "42", workflowRunAttempt: "2", now }));
  assert.throws(() => assertStageATemporaryEgressCleanupAuthorization(authorization, { sourceSha, workflowRunId: "42", workflowRunAttempt: "1", now: new Date(now.getTime() + 31 * 60_000) }), /stale/);
});

test("live cleanup readback accepts only exact SG, endpoint, rule, and dependency state", () => {
  assert.equal(validateStageATemporaryEgressLiveInventory(inventory()).revocationCount, 1);
  for (const overrides of [
    { caller: { ...identity, Account: "000000000000" } },
    { region: "us-east-1" },
    { ruleResponse: { SecurityGroupRules: [{ ...rule, SecurityGroupRuleId: "sgr-wrong" }] } },
    { ruleResponse: { SecurityGroupRules: [{ ...rule, GroupId: "sg-wrong" }] } },
    { ruleResponse: { SecurityGroupRules: [{ ...rule, ReferencedGroupInfo: { ...rule.ReferencedGroupInfo, GroupId: "sg-wrong" } }] } },
    { ruleResponse: { SecurityGroupRules: [{ ...rule, FromPort: 444 }] } },
    { ruleResponse: { SecurityGroupRules: [{ ...rule, IpProtocol: "udp" }] } },
    { ruleResponse: { SecurityGroupRules: [{ ...rule, Description: "unexpected" }] } },
    { ruleResponse: { SecurityGroupRules: [{ ...rule, VpcId: "vpc-wrong" }] } },
    { ruleResponse: { SecurityGroupRules: [] } },
    { sourceGroup: { SecurityGroups: [{ ...sourceGroup.SecurityGroups[0], VpcId: "vpc-wrong" }] } },
    { destinationGroup: { SecurityGroups: [{ ...destinationGroup.SecurityGroups[0], Tags: [] }] } },
    { destinationGroup: { SecurityGroups: [{ ...destinationGroup.SecurityGroups[0], OwnerId: "000000000000" }] } },
    { destinationGroup: { SecurityGroups: [{ ...destinationGroup.SecurityGroups[0], VpcId: "vpc-wrong" }] } },
    { destinationGroup: { SecurityGroups: [{ ...destinationGroup.SecurityGroups[0], IpPermissions: [{ ...destinationGroup.SecurityGroups[0].IpPermissions[0], FromPort: 1 }] }] } },
    { endpointResponse: { VpcEndpoints: [{ ...endpointResponse.VpcEndpoints[0], VpcEndpointId: "vpce-wrong" }] } },
    { endpointResponse: { VpcEndpoints: [{ ...endpointResponse.VpcEndpoints[0], ServiceName: "com.amazonaws.eu-west-2.ec2messages" }] } },
    { endpointResponse: { VpcEndpoints: [{ ...endpointResponse.VpcEndpoints[0], VpcId: "vpc-wrong" }] } },
    { endpointResponse: { VpcEndpoints: [{ ...endpointResponse.VpcEndpoints[0], State: "deleted" }] } },
    { networkInterfaces: [{ NetworkInterfaceId: "eni-active" }] },
    { activeTaskUsesSourceGroup: true },
    { canonicalDependencyPresent: true },
  ]) assert.throws(() => validateStageATemporaryEgressLiveInventory(inventory(overrides)));
});

test("post-revoke inventory accepts only absence of the exact rule with the remaining topology unchanged", () => {
  const withoutRule = structuredClone(sourceGroup);
  withoutRule.SecurityGroups[0].IpPermissionsEgress = [];
  const result = validateStageATemporaryEgressLiveInventory(inventory({ ruleResponse: { SecurityGroupRules: [] }, sourceGroup: withoutRule, allowRuleAbsent: true }));
  assert.equal(result.rulePresent, false);
  assert.throws(() => validateStageATemporaryEgressLiveInventory(inventory({ allowRuleAbsent: true })), /still present/);
});

test("cleanup journals require versioning and protect the exact prefix from destructive lifecycle rules", () => {
  assert.equal(assertStageATemporaryEgressCleanupJournalRetention({ versioning: { Status: "Enabled" }, lifecycle: { Rules: [] } }), true);
  assert.throws(() => assertStageATemporaryEgressCleanupJournalRetention({ versioning: {}, lifecycle: { Rules: [] } }), /requires production-artifacts bucket versioning/);
  assert.throws(() => assertStageATemporaryEgressCleanupJournalRetention({ versioning: { Status: "Enabled" }, lifecycle: { Rules: [{ ID: "cleanup-expiration", Status: "Enabled", Prefix: STAGE_A_TEMPORARY_EGRESS_CLEANUP.journalPrefix, Expiration: { Days: 1 } }] } }), /protected immutable record unavailable/);
});

test("cleanup refuses to consume authorization when journal retention is unsafe", async () => {
  const awsCalls = []; let reservations = 0;
  const rootRun = (args) => {
    if (args[1] === "get-bucket-versioning") return JSON.stringify({ Status: "Enabled" });
    if (args[1] === "get-bucket-lifecycle-configuration") return JSON.stringify({ Rules: [{ ID: "cleanup-expiration", Status: "Enabled", Prefix: STAGE_A_TEMPORARY_EGRESS_CLEANUP.journalPrefix, Expiration: { Days: 1 } }] });
    awsCalls.push(args);
    return "{}";
  };
  await assert.rejects(executeStageATemporaryEgressCleanup({ authorization, sourceSha, workflowRunId: "42", workflowRunAttempt: "1", rootRun, releaseRun: async () => {}, terraformStateLock: lock(), read: () => ({ validated: { ruleId: STAGE_A_TEMPORARY_EGRESS_CLEANUP.ruleId }, ruleResponse: { SecurityGroupRules: [rule] } }), reserve: async () => { reservations += 1; } }), /protected immutable record unavailable/);
  assert.equal(reservations, 0);
  assert.equal(awsCalls.filter((args) => args[1] === "revoke-security-group-egress").length, 0);
});

test("cleanup provenance authenticates the exact root-created endpoint and egress rule", () => {
  assert.equal(assertStageATemporaryEgressCloudTrailProvenance(provenanceEvents), true);
  assert.throws(() => assertStageATemporaryEgressCloudTrailProvenance({ ...provenanceEvents, ruleEvents: [] }));
  const wrong = structuredClone(provenanceEvents); wrong.ruleEvents[0].CloudTrailEvent = JSON.stringify({ ...JSON.parse(wrong.ruleEvents[0].CloudTrailEvent), userIdentity: { arn: "arn:aws:iam::368992683803:user/other" } });
  assert.throws(() => assertStageATemporaryEgressCloudTrailProvenance(wrong));
  const wrongPort = structuredClone(provenanceEvents); const event = JSON.parse(wrongPort.ruleEvents[0].CloudTrailEvent); event.requestParameters.ipPermissions.items[0].toPort = 444; wrongPort.ruleEvents[0].CloudTrailEvent = JSON.stringify(event);
  assert.throws(() => assertStageATemporaryEgressCloudTrailProvenance(wrongPort));
});

test("authorization artifact resolution uses the hardened GitHub runner and exact source-bound archive", async () => {
  const archive = await new JSZip().file("authorization.json", JSON.stringify(authorization)).generateAsync({ type: "nodebuffer" }); const calls = [];
  const run = (command, args, options = {}) => {
    calls.push({ command, args, options });
    if (command === "gh" && args[1] === "repos/T-ej2003/genuine-scan-main/actions/runs/42") return JSON.stringify({ id: 42, repository: { id: 77, full_name: "T-ej2003/genuine-scan-main" }, head_repository: { full_name: "T-ej2003/genuine-scan-main" }, path: ".github/workflows/authorize-stage-a-temporary-egress-cleanup.yml", event: "workflow_dispatch", head_sha: sourceSha, status: "completed", conclusion: "success", run_attempt: 1, actor: { login: "operator" } });
    if (command === "gh" && args[1].endsWith("/actions/runs/42/artifacts")) return JSON.stringify([{ artifacts: [{ id: 99, name: "stage-a-temporary-egress-cleanup-authorization", expired: false, workflow_run: { id: 42, head_sha: sourceSha, repository_id: 77 }, digest: `sha256:${createHash("sha256").update(archive).digest("hex")}` }] }]);
    if (command === "gh" && args[1].endsWith("/actions/artifacts/99/zip")) return archive;
    if (command === "unzip" && args[0] === "-Z1") return "authorization.json\n";
    if (command === "unzip" && args[0] === "-p") return JSON.stringify(authorization);
    throw new Error(`unexpected ${command} ${args.join(" ")}`);
  };
  const githubRun = createProductionGithubCommandRunner({ env: { PATH: process.env.PATH, GH_TOKEN: "fixture" }, exec: run });
  const result = await resolveStageATemporaryEgressCleanupAuthorizationArtifact({ workflowRunId: "42", workflowRunAttempt: "1", sourceSha, githubRun });
  assert.equal(result.authorizationSha256, authorization.authorizationSha256);
  const download = calls.find(({ command, args }) => command === "gh" && args[1].endsWith("/actions/artifacts/99/zip"));
  assert.deepEqual(download.args, ["api", "repos/T-ej2003/genuine-scan-main/actions/artifacts/99/zip"]);
  assert.equal(download.options.encoding, null);
  assert.equal(calls.some(({ command }) => command === "unzip"), false);
});

test("executor consumes authorization before one exact revoke and refuses changed live rule", async () => {
  let readCount = 0; const calls = []; const reserves = [];
  const read = () => {
    readCount += 1;
    const observed = readCount === 3 ? { ...rule, Description: "changed after authorization" } : rule;
    return { validated: { ruleId: STAGE_A_TEMPORARY_EGRESS_CLEANUP.ruleId }, ruleResponse: { SecurityGroupRules: [observed] } };
  };
  await assert.rejects(executeStageATemporaryEgressCleanup({ authorization, sourceSha, workflowRunId: "42", workflowRunAttempt: "1", rootRun: rootRunner(calls), releaseRun: async () => {}, terraformStateLock: lock(), read, reserve: async ({ authorization: value }) => reserves.push(value.authorizationSha256) }), /changed after authorization/);
  assert.equal(reserves.length, 1);
  assert.equal(calls.length, 0);
});

test("executor refuses a replayed authorization before issuing any revoke", async () => {
  const awsCalls = [];
  await assert.rejects(executeStageATemporaryEgressCleanup({ authorization, sourceSha, workflowRunId: "42", workflowRunAttempt: "1", rootRun: rootRunner(awsCalls), releaseRun: async () => {}, terraformStateLock: lock(), read: () => ({ validated: { ruleId: STAGE_A_TEMPORARY_EGRESS_CLEANUP.ruleId }, ruleResponse: { SecurityGroupRules: [rule] } }), reserve: async () => { throw new Error("Temporary egress cleanup authorization has already been consumed; replay is forbidden."); } }), /already been consumed/);
  assert.equal(awsCalls.filter((args) => args[1] === "revoke-security-group-egress").length, 0);
});

test("executor can emit only the exact rule-ID revoke and never bulk-revokes", async () => {
  let reads = 0; const awsCalls = []; let reservationCount = 0;
  const read = () => { reads += 1; const absent = reads >= 4; return { validated: { ruleId: STAGE_A_TEMPORARY_EGRESS_CLEANUP.ruleId, rulePresent: !absent }, ruleResponse: { SecurityGroupRules: absent ? [] : [rule] } }; };
  const result = await executeStageATemporaryEgressCleanup({ authorization, sourceSha, workflowRunId: "42", workflowRunAttempt: "1", rootRun: rootRunner(awsCalls), releaseRun: async (args) => { if (args.includes("put-object")) reservationCount += 1; }, terraformStateLock: lock(), read, reserve: async () => { reservationCount += 1; } });
  assert.deepEqual(result, { completed: true, ruleId: "sgr-0b8c789e9694d4b77", revocationCount: 1 });
  assert.deepEqual(awsCalls.filter((args) => args[1] === "revoke-security-group-egress"), [["ec2", "revoke-security-group-egress", "--group-id", "sg-051a24aedff773761", "--security-group-rule-ids", "sgr-0b8c789e9694d4b77", "--output", "json", "--no-cli-pager"]]);
  assert.equal(reservationCount, 2); // immutable attempt and terminal result records
});

test("Stage-A cleanup journaling is bound to authorization and change ticket", () => {
  assert.match(STAGE_A_TEMPORARY_EGRESS_CLEANUP.journalPrefix, /^production-stage-a-production-artifacts-reconciliation\/recovery\//);
  assert.equal(createHash("sha256").update(canonicalJson({ sourceSha, changeTicket: authorization.changeTicket, authorizationSha256: authorization.authorizationSha256 })).digest("hex").length, 64);
});
