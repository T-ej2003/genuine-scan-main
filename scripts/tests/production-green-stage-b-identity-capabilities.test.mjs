import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import crypto from "node:crypto";
import {
  RELEASE_READ_PROBES,
  readIdentityCapabilityMatrix,
  runReleaseReadPreflight,
} from "../aws/production-green-stage-b-identity-capabilities.mjs";
import { STAGE_A_EXPECTED_STATE_LINEAGE, STAGE_A_STATE_IDENTITY_VERSION, stageAStateSemanticSha256 } from "../aws/generate-production-green-stage-a-prerequisites.mjs";
import { assertStageBAwsCallCoverage, assertStageBDeploymentCapabilityGraph, buildStageBDeploymentCapabilityGraph } from "../aws/generate-production-green-stage-b-capability-graph.mjs";
import { buildPermissionReportBinding, canonicalizeJson, PERMISSION_REPORT_BINDING_DOMAIN, PERMISSION_REPORT_BINDING_SCHEMA_VERSION, PERMISSION_REPORT_HASH_DOMAIN, PERMISSION_REPORT_SIGNING_ALGORITHM, PERMISSION_REPORT_SIGNING_KEY_ARN, PERMISSION_REPORT_SIGNATURE_SCHEMA_VERSION, runPermissionPreflight, signedPermissionReportBindingSha256, sourcePolicyEvidence } from "../aws/validate-production-green-stage-b-permissions.mjs";
import { runProductionPreflightCli } from "../aws/run-production-green-stage-b-preflight.mjs";
import { buildEcsExecOperatorEvidence } from "../aws/production-ecs-exec-operator-contract.mjs";
import { CHECKER_SOURCE_ROLE_ARN, CHECKER_USER_ARN } from "../aws/production-checker-chain-contract.mjs";
import { ECR_DOCUMENTED_NO_RESOURCE_POLICY, MALFORMED_ECR_REPOSITORY_POLICIES } from "./fixtures/ecr-repository-policy-fixtures.mjs";

const caller = "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test";
const stageAState = JSON.stringify({ lineage: STAGE_A_EXPECTED_STATE_LINEAGE, serial: 35, resources: [] });
const shapedPolicyEvidence = () => {
  const policies = sourcePolicyEvidence().map((policy) => ({ ...policy, defaultVersionId: "v1", liveSha256: policy.sourceSha256, attached: true, matchesSource: true }));
  return { roleArn: "arn:aws:iam::368992683803:role/mscqr-production-release-deployer", attachedPolicyArns: policies.map(({ arn }) => arn).sort(), inlinePolicyNames: [], inlinePolicies: [], permissionsBoundaryArn: null, policies, status: "valid" };
};
const temp = () => fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-release-preflight-test-"));
const allowed = (args) => {
  if (args[0] === "sts") return JSON.stringify({ Arn: caller });
  if (args[0] === "ecr" && args[1] === "get-repository-policy") {
    const repositoryName = args[args.indexOf("--repository-name") + 1];
    return JSON.stringify({ registryId: "368992683803", repositoryName, policyText: JSON.stringify({ Version: "2012-10-17", Statement: [{ Effect: "Allow", Principal: { AWS: "arn:aws:iam::368992683803:role/mscqr-ecs-execution-role" }, Action: ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"], Resource: `arn:aws:ecr:eu-west-2:368992683803:repository/${repositoryName}` }] }) });
  }
  if (args[0] === "iam" && args[1] === "get-role" && args.includes("mscqr-production-independent-checker")) return JSON.stringify({ Role: { Arn: CHECKER_SOURCE_ROLE_ARN, AssumeRolePolicyDocument: { Version: "2012-10-17", Statement: [{ Effect: "Allow", Principal: { AWS: CHECKER_USER_ARN }, Action: "sts:AssumeRole", Condition: { Bool: { "aws:MultiFactorAuthPresent": "true" } } }] } } });
  if (args[0] === "s3api" && args[1] === "get-object") {
    fs.writeFileSync(args.at(-1), args.includes("mscqr/production/rls-green/stage-a/terraform.tfstate") ? stageAState : JSON.stringify({ lineage: "fixture", serial: 1 }), { mode: 0o644 });
    return "";
  }
  if (args[0] === "ecs" && args[1] === "list-services") return JSON.stringify({ serviceArns: ["arn:aws:ecs:eu-west-2:368992683803:service/mscqr-prod-euw2-main/frontend"] });
  if (args[0] === "ecs" && args[1] === "list-tasks") return JSON.stringify({ taskArns: ["arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/abc"] });
  if (args[0] === "iam" && args[1] === "get-policy") return JSON.stringify({ Policy: { DefaultVersionId: "v1" } });
  if (args[0] === "iam" && args[1] === "list-role-policies") return JSON.stringify({ PolicyNames: ["inline"] });
  return "{}";
};

test("identity matrix assigns IAM simulation only to administrator", () => {
  const matrix = readIdentityCapabilityMatrix();
  assert(matrix.calls.some(({ identity, action }) => identity === "ADMINISTRATOR" && action === "iam:SimulatePrincipalPolicy"));
  assert(!matrix.calls.some(({ identity, action }) => identity === "RELEASE_DEPLOYER" && action === "iam:SimulatePrincipalPolicy"));
  assert.equal(matrix.phases.length, 41);
});

test("Stage B release readiness requires the completed Stage A contract", () => {
  const source = fs.readFileSync("scripts/aws/run-production-green-stage-b-preflight.mjs", "utf8");
  assert.match(source, /generateStageAPrerequisites\(\{[^;]+phase: "POST_APPLY" \}\);/);
  assert.doesNotMatch(source, /recoveryMode === "NORMAL" \? "PRE_APPLY"/);
});

test("generated capability graph is exhaustive, deterministic, and identity-exact", () => {
  const first = buildStageBDeploymentCapabilityGraph(); const second = buildStageBDeploymentCapabilityGraph();
  assert.deepEqual(first, second);
  assert.deepEqual(assertStageBDeploymentCapabilityGraph(first), { phases: 41, capabilities: 329, uniqueActions: 130, unmappedCalls: 0, unclassifiedCapabilities: 0, identityBoundaryViolations: 0, sourcePolicyMismatches: 0, manifestMismatches: 0, configurationContradictions: 0 });
  assert(first.capabilities.every(({ identity }) => first.identities.includes(identity)));
  assert(first.capabilities.every(({ id }, index) => first.capabilities.findIndex((item) => item.id === id) === index));
  assert(first.capabilities.some(({ identity, action }) => identity === "ECS_EXEC_VERIFIER_OPERATOR" && action === "ecs:ExecuteCommand"));
  assert.equal(first.capabilities.filter(({ identity, action }) => identity === "RELEASE_DEPLOYER" && action === "ecs:ExecuteCommand").length, 0);
  assert.equal(first.capabilities.find(({ id }) => id === "manifest-release-deployer-ecs-exec").identity, "ADMINISTRATOR");
  assert.equal(first.capabilities.filter(({ identity, action, resources }) => identity === "INDEPENDENT_CHECKER" && action === "secretsmanager:PutSecretValue" && resources.includes("arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/phase2/approval-e0shho")).length, 1);
  assert.equal(first.capabilities.filter(({ identity, action, resources }) => identity === "RELEASE_DEPLOYER" && action === "secretsmanager:PutSecretValue" && resources.includes("arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/phase2/approval-e0shho")).length, 0);
  assert(first.capabilities.some(({ id, action }) => id === "recovery-list-backend-revisions" && action === "ecs:ListTaskDefinitions"));
  assert(first.capabilities.some(({ id, action, resources, phase, classification, mutation }) => id === "manifest-backend-health-recovery-register-legacy-task-definition" && action === "ecs:RegisterTaskDefinition" && resources.length === 1 && resources[0].endsWith("task-definition/mscqr-backend:*") && phase === "backend-health-recovery" && classification === "RELEASE_DIRECT_MUTATION" && mutation === true));
  assert(first.capabilities.some(({ id, action, resources, phase, classification, mutation }) => id === "manifest-backend-health-recovery-update-service" && action === "ecs:UpdateService" && resources.length === 1 && resources[0].endsWith("service/mscqr-prod-euw2-main/mscqr-backend-servi-euw2") && phase === "backend-health-recovery" && classification === "RELEASE_DIRECT_MUTATION" && mutation === true));
  for (const [id, action, probeId] of [
    ["manifest-backend-health-recovery-describe-images", "ecr:DescribeImages", "backend-health-recovery-images"],
    ["manifest-backend-health-recovery-describe-repositories", "ecr:DescribeRepositories", "backend-health-recovery-repository"],
  ]) {
    assert(first.capabilities.some((capability) => capability.id === id && capability.action === action
      && capability.phase === "backend-health-recovery" && capability.classification === "RELEASE_DIRECT_READ"
      && capability.mutation === false && capability.probe === "direct"
      && capability.probeIds.includes(probeId)
      && capability.resources.length === 1
      && capability.resources[0] === "arn:aws:ecr:eu-west-2:368992683803:repository/mscqr-backend"
      && capability.policy.sourceFile === "documents/ops/iam/MSCQRProductionGreenStageBProviderReadOnly-v1.json"));
  }
  assert(first.sourceScan.some(({ sourceFile, action }) => sourceFile === "scripts/aws/recover-production-backend-health.mjs" && action === "ecs:RegisterTaskDefinition"));
  assert(first.sourceScan.some(({ sourceFile, action }) => sourceFile === "scripts/aws/recover-production-backend-health.mjs" && action === "ecs:UpdateService"));
  assert(first.sourceScan.some(({ sourceFile, action }) => sourceFile === "scripts/aws/recover-production-backend-health.mjs" && action === "ecr:DescribeImages"));
  assert(first.sourceScan.some(({ sourceFile, action }) => sourceFile === "scripts/aws/recover-production-backend-health.mjs" && action === "ecr:DescribeRepositories"));
  assert(first.sourceScan.some(({ sourceFile, action }) => sourceFile === "scripts/aws/production-ecs-rollback-viability.mjs" && action === "ecs:DescribeServiceDeployments"));
  const forward = first.capabilities.filter(({ phase }) => phase === "existing-revision-forward-recovery");
  assert.equal(forward.length, 9);
  assert(forward.every(({ sourceFile, identity }) => sourceFile === "scripts/aws/forward-recover-stage-b-existing-revision.mjs" && identity === "RELEASE_DEPLOYER"));
  assert(forward.every(({ action }) => !["ecs:RegisterTaskDefinition", "ecs:DeregisterTaskDefinition", "ecs:UpdateService", "terraform:Apply"].includes(action)));
  assert(first.configurationContracts.includes("checker-user-mfa-live-trust-to-independent-role-chain"));
  for (const [id, action, resource, mutation] of [
    ["admin-release-oidc-identify", "sts:GetCallerIdentity", "*", false],
    ["admin-release-oidc-trust-read", "iam:GetRole", "arn:aws:iam::368992683803:role/mscqr-production-release-deployer", false],
    ["admin-release-oidc-trust-update", "iam:UpdateAssumeRolePolicy", "arn:aws:iam::368992683803:role/mscqr-production-release-deployer", true],
  ]) assert(first.capabilities.some((capability) => capability.id === id && capability.action === action && capability.identity === "ADMINISTRATOR" && capability.resources[0] === resource && capability.mutation === mutation));
  for (const [id, action, resource] of [
    ["normal-activation-admin-describe-candidate", "ecs:DescribeTaskDefinition", "*"],
    ["normal-activation-admin-describe-service", "ecs:DescribeServices", "arn:aws:ecs:eu-west-2:368992683803:service/mscqr-prod-euw2-main/mscqr-backend-servi-euw2"],
    ["normal-activation-admin-list-tasks", "ecs:ListTasks", "arn:aws:ecs:eu-west-2:368992683803:service/mscqr-prod-euw2-main/mscqr-backend-servi-euw2"],
    ["normal-activation-admin-describe-tasks", "ecs:DescribeTasks", "arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/*"],
  ]) assert(first.capabilities.some((capability) => capability.id === id && capability.action === action && capability.identity === "ADMINISTRATOR" && capability.resources[0] === resource && capability.mutation === false));
  for (const action of ["sts:GetCallerIdentity", "iam:GetRole", "iam:UpdateAssumeRolePolicy"]) assert(first.sourceScan.some(({ sourceFile, action: discovered }) => sourceFile === "scripts/aws/production-release-oidc-contract.mjs" && discovered === action));
  const rootDrop = first.capabilities.find(({ id }) => id === "root-drop-sign-evidence");
  const rootCall = first.sourceScan.find(({ capabilityId }) => capabilityId === "root-drop-sign-evidence");
  assert.equal(rootDrop.identity, "ROOT_OPERATOR");
  assert.deepEqual(rootDrop.resources, ["arn:aws:kms:eu-west-2:368992683803:alias/mscqr-production-root-drop"]);
  assert.doesNotThrow(() => assertStageBAwsCallCoverage(first, [rootCall]));
  for (const mutation of [{ sourceFile: "wrong.mjs" }, { sourceFunction: "wrong-function" }, { identity: "ADMINISTRATOR" }, { resources: ["arn:aws:kms:eu-west-2:368992683803:key/unrelated"] }]) {
    assert.throws(() => assertStageBAwsCallCoverage(first, [{ ...rootCall, ...mutation }]), /exact capability coverage/);
  }
  assert.throws(() => assertStageBAwsCallCoverage(first, [{ sourceFile: rootCall.sourceFile, action: rootCall.action }]), /lacks exact capability coverage/);
  const withoutRoot = { ...first, capabilities: first.capabilities.filter(({ id }) => id !== "root-drop-sign-evidence") };
  assert.throws(() => assertStageBAwsCallCoverage(withoutRoot, [rootCall]), /exact capability coverage/);
});

test("unknown, removed, or identity-reassigned capabilities fail graph verification", () => {
  const unknown = buildStageBDeploymentCapabilityGraph(); unknown.capabilities.push({ ...unknown.capabilities[0], id: "unknown-call", action: "sns:Publish" });
  assert.throws(() => assertStageBDeploymentCapabilityGraph(unknown), /stale or incomplete/);
  const removed = buildStageBDeploymentCapabilityGraph(); removed.capabilities.pop();
  assert.throws(() => assertStageBDeploymentCapabilityGraph(removed), /stale or incomplete/);
  const reassigned = buildStageBDeploymentCapabilityGraph(); reassigned.capabilities.find(({ action }) => action === "iam:SimulatePrincipalPolicy").identity = "RELEASE_DEPLOYER";
  assert.throws(() => assertStageBDeploymentCapabilityGraph(reassigned), /stale or incomplete/);
});

test("a newly discovered AWS CLI action fails until it is classified", () => {
  assert.throws(() => assertStageBAwsCallCoverage(buildStageBDeploymentCapabilityGraph(), [{ sourceFile: "new-production-path.mjs", action: "sns:Publish" }]), /absent from capability graph/);
});

test("release probes cover policy-list access on both canary roles", () => {
  for (const role of ["mscqr-production-full-rls-green-read-only-canary-execution", "mscqr-production-full-rls-green-read-only-canary-task"]) {
    for (const operation of ["list-role-policies", "list-attached-role-policies"]) assert(RELEASE_READ_PROBES.some(({ args }) => args.includes(role) && args.includes(operation)));
  }
});

test("backend recovery ECR probes are exact read-only repository calls", () => {
  assert.deepEqual(RELEASE_READ_PROBES.filter(({ id }) => id.startsWith("backend-health-recovery-")), [
    { id: "backend-health-recovery-images", action: "ecr:DescribeImages", args: ["ecr", "describe-images", "--repository-name", "mscqr-backend", "--max-results", "1"] },
    { id: "backend-health-recovery-repository", action: "ecr:DescribeRepositories", args: ["ecr", "describe-repositories", "--repository-names", "mscqr-backend"] },
    { id: "backend-health-recovery-service-deployments", action: "ecs:ListServiceDeployments", args: ["ecs", "list-service-deployments", "--cluster", "arn:aws:ecs:eu-west-2:368992683803:cluster/mscqr-prod-euw2-main", "--service", "arn:aws:ecs:eu-west-2:368992683803:service/mscqr-prod-euw2-main/mscqr-backend-servi-euw2"] },
  ]);
});

test("release preflight aggregates independent read denials and never simulates IAM", () => {
  const calls = []; const directory = temp();
  const report = runReleaseReadPreflight({ outputDirectory: directory, run: (args, probe) => {
    calls.push(probe.action);
    if (["ecs:DescribeClusters", "rds:DescribeDBInstances"].includes(probe.action)) throw new Error("AccessDenied");
    return allowed(args);
  } });
  assert.equal(report.status, "blocked");
  assert.deepEqual(report.failed.map(({ action }) => action), ["ecs:DescribeClusters", "rds:DescribeDBInstances"]);
  assert(calls.length >= RELEASE_READ_PROBES.length);
  assert(!calls.includes("iam:SimulatePrincipalPolicy"));
  assert.equal(fs.existsSync(path.join(directory, "stage-a-state-identity.json")), false);
});

test("backend recovery ECR denial blocks the release preflight before mutation", () => {
  for (const deniedAction of ["ecr:DescribeImages", "ecr:DescribeRepositories"]) {
    const report = runReleaseReadPreflight({ outputDirectory: temp(), run: (args, probe) => {
      if (probe.action === deniedAction) throw new Error("AccessDenied");
      return allowed(args);
    } });
    assert.equal(report.status, "blocked");
    assert.deepEqual(report.failed.filter(({ action }) => action === deniedAction), [{
      id: deniedAction === "ecr:DescribeImages" ? "backend-health-recovery-images" : "backend-health-recovery-repository",
      action: deniedAction,
      classification: "AccessDenied",
    }]);
  }
});

test("release preflight treats current AWS CLI no-policy errors as authenticated absence", () => {
  const report = runReleaseReadPreflight({ outputDirectory: temp(), run: (args, probe) => {
    if (probe.action === "ecr:GetRepositoryPolicy") {
      const error = new Error("no repository policy");
      const repositoryName = args[args.indexOf("--repository-name") + 1];
      error.stderr = Buffer.from(`\naws: [ERROR]: An error occurred (RepositoryPolicyNotFoundException) when calling the GetRepositoryPolicy operation: Repository policy does not exist for the repository with name '${repositoryName}' in the registry with id '368992683803'\n`);
      throw error;
    }
    return allowed(args);
  } });
  assert.equal(report.status, "valid");
  assert.equal(report.requiredReads["ecr:GetRepositoryPolicy"], "allowed");
});

test("release preflight accepts the documented repository-scoped ECR policy without Resource", () => {
  const report = runReleaseReadPreflight({ outputDirectory: temp(), run: (args, probe) => {
    if (probe.action === "ecr:GetRepositoryPolicy") {
      const repositoryName = args[args.indexOf("--repository-name") + 1];
      return JSON.stringify({ registryId: "368992683803", repositoryName, policyText: JSON.stringify(ECR_DOCUMENTED_NO_RESOURCE_POLICY) });
    }
    return allowed(args);
  } });
  assert.equal(report.status, "valid");
  assert.equal(report.requiredReads["ecr:GetRepositoryPolicy"], "allowed");
});

test("release preflight accepts structurally valid ECR action wildcard policies", () => {
  const report = runReleaseReadPreflight({ outputDirectory: temp(), run: (args, probe) => {
    if (probe.action === "ecr:GetRepositoryPolicy") {
      const repositoryName = args[args.indexOf("--repository-name") + 1];
      const policy = { Version: "2012-10-17", Statement: [
        { Effect: "Allow", Principal: "*", Action: "ECR:*" },
        { Effect: "Deny", Principal: "*", Action: ["ecr:Batch*Image", "ecr:BatchGetIma?e"] },
      ] };
      return JSON.stringify({ registryId: "368992683803", repositoryName, policyText: JSON.stringify(policy) });
    }
    return allowed(args);
  } });
  assert.equal(report.status, "valid");
  assert.equal(report.requiredReads["ecr:GetRepositoryPolicy"], "allowed");
});

test("release preflight rejects malformed successful ECR policy responses", () => {
  for (const [label, policy] of MALFORMED_ECR_REPOSITORY_POLICIES) {
    const report = runReleaseReadPreflight({ outputDirectory: temp(), run: (args, probe) => {
      if (probe.action === "ecr:GetRepositoryPolicy") {
        const repositoryName = args[args.indexOf("--repository-name") + 1];
        return JSON.stringify({ registryId: "368992683803", repositoryName, policyText: JSON.stringify(policy) });
      }
      return allowed(args);
    } });
    assert.equal(report.status, "blocked", label);
    assert.equal(report.failed.filter(({ action }) => action === "ecr:GetRepositoryPolicy").length, 3, label);
  }
});

test("active rollback discovery reads the exact deployment details", () => {
  const calls = [];
  const deploymentArn = "arn:aws:ecs:eu-west-2:368992683803:service-deployment/mscqr-prod-euw2-main/mscqr-backend-servi-euw2/deployment";
  const targetRevisionArn = "arn:aws:ecs:eu-west-2:368992683803:service-revision/mscqr-prod-euw2-main/mscqr-backend-servi-euw2/target";
  const rollbackRevisionArn = "arn:aws:ecs:eu-west-2:368992683803:service-revision/mscqr-prod-euw2-main/mscqr-backend-servi-euw2/rollback";
  const report = runReleaseReadPreflight({ outputDirectory: temp(), run: (args, probe) => {
    calls.push({ args, probe });
    if (probe.id === "backend-health-recovery-service-deployments") return JSON.stringify({ serviceDeployments: [{ serviceDeploymentArn: deploymentArn, status: "ROLLBACK_IN_PROGRESS" }] });
    if (probe.id === "backend-health-recovery-service-deployment-details") return JSON.stringify({ serviceDeployments: [{ serviceDeploymentArn: deploymentArn, targetServiceRevision: { arn: targetRevisionArn }, sourceServiceRevisions: [{ arn: rollbackRevisionArn }], rollback: { serviceRevisionArn: rollbackRevisionArn } }] });
    return allowed(args);
  } });
  assert.equal(report.status, "valid");
  assert(calls.some(({ args, probe }) => probe.id === "backend-health-recovery-service-deployment-details" && probe.action === "ecs:DescribeServiceDeployments" && args[1] === "describe-service-deployments"));
  const revisionCall = calls.find(({ probe }) => probe.id === "backend-health-recovery-service-revision-details");
  assert(revisionCall?.args.includes(targetRevisionArn));
  assert(revisionCall?.args.includes(rollbackRevisionArn));
});

test("complete release preflight is valid and has no skipped probes", () => {
  const directory = temp();
  const report = runReleaseReadPreflight({ outputDirectory: directory, run: allowed });
  assert.equal(report.status, "valid");
  assert.deepEqual(report.failed, []);
  assert.deepEqual(report.skipped, []);
  assert.equal(report.caller, caller);
  assert.equal(report.stageAStateIdentityPath, path.join(directory, "stage-a-state-identity.json"));
  assert.deepEqual(JSON.parse(fs.readFileSync(report.stageAStateIdentityPath, "utf8")), { stateIdentityVersion: STAGE_A_STATE_IDENTITY_VERSION, stateObject: "mscqr/production/rls-green/stage-a/terraform.tfstate", lineage: STAGE_A_EXPECTED_STATE_LINEAGE, serial: 35, stateSha256: stageAStateSemanticSha256(JSON.parse(stageAState)), account: "368992683803", region: "eu-west-2" });
});

test("release preflight blocks when authenticated Stage-A state cannot produce an identity", () => {
  const directory = temp();
  const report = runReleaseReadPreflight({ outputDirectory: directory, run: (args, probe) => {
    if (probe.id === "stage-a-state") { fs.writeFileSync(args.at(-1), JSON.stringify({ lineage: "wrong", serial: 35 }), { mode: 0o600 }); return ""; }
    return allowed(args);
  } });
  assert.equal(report.status, "blocked");
  assert.equal(report.stageAStateIdentityPath, null);
  assert(report.failed.some(({ id }) => id === "stage-a-state"));
  assert.equal(fs.existsSync(path.join(directory, "stage-a-state-identity.json")), false);
});

test("wrong caller and region fail closed", () => {
  const directory = temp();
  const wrongCaller = runReleaseReadPreflight({ outputDirectory: directory, run: (args) => args[0] === "sts" ? JSON.stringify({ Arn: "arn:aws:iam::368992683803:root" }) : allowed(args) });
  assert.equal(wrongCaller.status, "blocked");
  assert.equal(wrongCaller.failed[0].id, "caller");
  assert.equal(wrongCaller.stageAStateIdentityPath, null);
  assert.equal(fs.existsSync(path.join(directory, "stage-a-state-identity.json")), false);
  assert.throws(() => runReleaseReadPreflight({ outputDirectory: temp(), region: "us-east-1", run: allowed }), /region/);
});

test("failed preflight removes a stale Stage-A identity instead of preserving it", () => {
  const directory = temp();
  const identityPath = path.join(directory, "stage-a-state-identity.json");
  fs.writeFileSync(identityPath, JSON.stringify({ stateSha256: "f".repeat(64) }), { mode: 0o600 });
  const report = runReleaseReadPreflight({ outputDirectory: directory, run: (args, probe) => {
    if (probe.id === "stage-a-cluster") throw new Error("AccessDenied");
    return allowed(args);
  } });
  assert.equal(report.status, "blocked");
  assert.equal(report.stageAStateIdentityPath, null);
  assert.equal(fs.existsSync(identityPath), false);
});

test("one command keeps administrator simulation and release reads on separate identities", () => {
  const directory = temp(); const adminPath = path.join(directory, "admin.json"); const signaturePath = path.join(directory, "admin.signature.json");
  let administratorSimulations = 0;
  const admin = runProductionPreflightCli(["--identity", "administrator", "--phase", "initial", "--output", adminPath, "--signature-output", signaturePath], {
    caller: () => "arn:aws:iam::368992683803:root",
    collectPolicies: shapedPolicyEvidence,
    collectEcsExecOperatorEvidence: () => buildEcsExecOperatorEvidence(),
    permissionPreflight: (input) => { administratorSimulations += 1; return runPermissionPreflight({ ...input, simulate: ({ evaluation }) => ({ decision: evaluation.expectedDecision || "allowed", matchedStatements: evaluation.expectedDecision ? 0 : 1, missingContextValues: evaluation.expectedDecision ? evaluation.expectedMissingContextValues : [] }), cloudTrail: () => ({ status: "clear", eventsChecked: 0, unresolvedDenials: [] }) }); },
    sign: (report, { reportBytes }) => { const canonicalPayloadSha256 = crypto.createHash("sha256").update(Buffer.from(canonicalizeJson(report))).digest("hex"); const reportFileSha256 = crypto.createHash("sha256").update(reportBytes).digest("hex"); const bindingPayload = buildPermissionReportBinding({ report, canonicalPayloadSha256, reportFileSha256, keyArn: PERMISSION_REPORT_SIGNING_KEY_ARN, signingAlgorithm: PERMISSION_REPORT_SIGNING_ALGORITHM }); return { schemaVersion: PERMISSION_REPORT_SIGNATURE_SCHEMA_VERSION, hashDomain: PERMISSION_REPORT_HASH_DOMAIN, bindingDomain: PERMISSION_REPORT_BINDING_DOMAIN, bindingSchemaVersion: PERMISSION_REPORT_BINDING_SCHEMA_VERSION, evidenceKind: report.evidenceKind, phase: report.phase, purpose: report.purpose, accountId: "368992683803", region: "eu-west-2", keyId: PERMISSION_REPORT_SIGNING_KEY_ARN, keyArn: PERMISSION_REPORT_SIGNING_KEY_ARN, signingAlgorithm: PERMISSION_REPORT_SIGNING_ALGORITHM, canonicalPayloadSha256, reportFileSha256, signedBindingSha256: signedPermissionReportBindingSha256(bindingPayload), signatureBase64: "AQ==", signedAt: report.generatedAt }; },
  });
  assert.equal(admin.status, "valid"); assert.equal(administratorSimulations, 1);
  const releasePath = path.join(directory, "release.json"); let releaseReads = 0;
  const release = runProductionPreflightCli(["--identity", "release-deployer", "--output", releasePath, "--administrator-report", adminPath, "--administrator-report-signature", signaturePath], {
    caller: () => caller,
    verify: () => true,
    releasePreflight: () => { releaseReads += 1; return { schemaVersion: 1, caller, account: "368992683803", region: "eu-west-2", requiredReads: {}, failed: [], skipped: [], status: "valid" }; },
    continueReadiness: () => ({ backendReady: true, stateReady: true, handoffReady: true, tfvarsReady: true }), validateCapabilityGraph: () => admin.capabilityGraph,
  });
  assert.equal(release.status, "ready-for-plan"); assert.equal(releaseReads, 1);
});

test("administrator preflight rejects a root-drop policy missing provider rotation readback", () => {
  const directory = temp(); let simulated = false;
  assert.throws(() => runProductionPreflightCli(["--identity", "administrator", "--phase", "initial", "--output", path.join(directory, "admin.json"), "--signature-output", path.join(directory, "admin.signature.json")], {
    caller: () => "arn:aws:iam::368992683803:root",
    readStageATerraformSource: () => fs.readFileSync("infra/aws/terraform/production-green-stage-a/main.tf", "utf8").replace("kms:GetKeyRotationStatus", "kms:GetKeyPolicy"),
    permissionPreflight: () => { simulated = true; return {}; },
  }), /provider read/);
  assert.equal(simulated, false);
});

test("invalid release capability report stops before backend readiness", () => {
  const directory = temp(); const adminPath = path.join(directory, "admin.json"); const signaturePath = path.join(directory, "signature.json");
  const capabilityGraph = assertStageBDeploymentCapabilityGraph();
  fs.writeFileSync(adminPath, JSON.stringify({ schemaVersion: 1, evidenceKind: "INITIAL_ADMIN_CAPABILITY", phase: "initial", purpose: "pre-plan-capability", status: "valid", simulatedRoleArn: "arn:aws:iam::368992683803:role/mscqr-production-release-deployer", policyEvidence: shapedPolicyEvidence(), capabilityGraph }));
  fs.writeFileSync(signaturePath, "{}"); let continued = 0;
  assert.throws(() => runProductionPreflightCli(["--identity", "release-deployer", "--output", path.join(directory, "release.json"), "--administrator-report", adminPath, "--administrator-report-signature", signaturePath], {
    caller: () => caller, verify: () => true,
    releasePreflight: () => ({ requiredReads: { "ecs:DescribeClusters": "denied" }, failed: [{ action: "ecs:DescribeClusters" }], skipped: [], status: "blocked" }),
    continueReadiness: () => { continued += 1; }, validateCapabilityGraph: () => capabilityGraph,
  }), /Cutover-critical release capability lacks valid evidence/);
  assert.equal(continued, 0);
});

test("administrator cannot promote an unsigned readiness report", () => {
  const directory = temp();
  try {
    assert.throws(() => runProductionPreflightCli([
      "--identity", "administrator", "--phase", "readiness", "--output", path.join(directory, "readiness.json"),
    ], { caller: () => "arn:aws:iam::368992683803:root" }), /phase initial/);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});
