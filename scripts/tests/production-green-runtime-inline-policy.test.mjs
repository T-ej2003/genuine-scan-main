import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import yaml from "js-yaml";
import { APP_ONLY } from "../aws/production-app-only-contract.mjs";
import { evaluateAppOnlySourceIam } from "../aws/production-app-only-iam-source.mjs";
import { canonicalSha256, STAGE_B } from "../aws/production-green-stage-b-contract.mjs";
import { parseEcsSecretsManagerReference } from "../aws/production-ecs-runtime-dependencies.mjs";
import {
  RUNTIME_CONSUMABILITY, assertRuntimeConsumabilityEvidence, buildRuntimeConsumabilityEvidence,
  collectLiveRolePolicyIdentity, deriveEcsRuntimeDependencies, simulateRuntimeDependencies,
  sourceRuntimePolicyOwnership,
} from "../aws/production-ecs-runtime-consumability.mjs";

const sourceSha = "a".repeat(40);
const digest = `sha256:${"1".repeat(64)}`;
const policyName = "stage-b-exact-image-logs-and-secrets";
const sourcePolicy = evaluateAppOnlySourceIam({ repositoryRoot: process.cwd() }).policies.execution;
const roleName = APP_ONLY.executionRoleArn.split("/").at(-1);
const logName = "/ecs/mscqr-production/rls-green-backend";
const ecrResource = `arn:aws:ecr:${APP_ONLY.region}:${APP_ONLY.account}:repository/mscqr-backend`;
const logResource = `arn:aws:logs:${APP_ONLY.region}:${APP_ONLY.account}:log-group:${logName}`;

const candidate = () => ({ family: APP_ONLY.family, taskRoleArn: APP_ONLY.taskRoleArn, executionRoleArn: APP_ONLY.executionRoleArn,
  containerDefinitions: [{ name: "backend", image: `${APP_ONLY.backendRepository}@${digest}`, secrets: [],
    logConfiguration: { logDriver: "awslogs", options: { "awslogs-region": APP_ONLY.region,
      "awslogs-group": logName, "awslogs-stream-prefix": "stage-b" } } }] });
const metadata = () => {
  const ecr = { resource: ecrResource, repositoryName: "mscqr-backend", imageDigest: digest, imageAvailability: "EXISTS",
    repositoryPolicyState: "NO_POLICY", repositoryPolicySha256: canonicalSha256(null) };
  const logs = { resource: logResource, logGroupName: logName, availability: "EXISTENCE_PROVEN", createGroup: false };
  return { [ecrResource]: { ...ecr, metadataSha256: canonicalSha256(ecr) },
    [logResource]: { ...logs, metadataSha256: canonicalSha256(logs) } };
};
function iam(mutator = () => {}, observed = []) {
  return async (args) => {
    observed.push(args);
    const operation = `${args[0]} ${args[1]}`;
    const response = operation === "iam get-role" ? { Role: { Arn: APP_ONLY.executionRoleArn, RoleName: roleName,
      RoleId: "AROAEXACTGREENBACKEND", AssumeRolePolicyDocument: RUNTIME_CONSUMABILITY.ecsTaskTrust } }
      : operation === "iam list-role-policies" ? { PolicyNames: [policyName] }
        : operation === "iam list-attached-role-policies" ? { AttachedPolicies: [] }
          : operation === "iam get-role-policy" ? { RoleName: roleName, PolicyName: policyName, PolicyDocument: structuredClone(sourcePolicy) }
            : operation === "iam simulate-principal-policy" ? { EvaluationResults: [{ EvalActionName: args[args.indexOf("--action-names") + 1],
              EvalResourceName: args[args.indexOf("--resource-arns") + 1], EvalDecision: "allowed", MissingContextValues: [] }] }
              : null;
    assert.ok(response, `Unexpected IAM read: ${operation}`);
    mutator(response, args, observed);
    return response;
  };
}

test("exact Terraform inline policy proves every green runtime dependency without a managed attachment", async () => {
  const value = candidate(); const resources = metadata(); const calls = [];
  const livePolicyIdentity = await collectLiveRolePolicyIdentity([APP_ONLY.executionRoleArn], iam(() => {}, calls), value);
  assert.deepEqual(livePolicyIdentity.roles[0].attachedPolicies, []);
  assert.equal(livePolicyIdentity.roles[0].loggingAuthorization.positivePolicyName, policyName);
  const dependencies = deriveEcsRuntimeDependencies(value);
  const ownership = sourceRuntimePolicyOwnership(value, resources);
  assert.equal(Object.keys(ownership).length, dependencies.length);
  assert.ok(Object.values(ownership).every(({ policyName: name }) => name === policyName));
  const simulations = await simulateRuntimeDependencies(dependencies, iam(() => {}, calls), { loggingResourceMode: "exact-dependency" });
  assert.ok(calls.filter(([service, operation]) => service === "iam" && operation === "simulate-principal-policy")
    .every((args) => args[args.indexOf("--resource-arns") + 1] !== "*" || args.includes("ecr:getauthorizationtoken")));
  const evidence = buildRuntimeConsumabilityEvidence({ sourceSha, candidate: value, resourceMetadata: resources,
    sourcePolicyOwnership: ownership, livePolicyIdentity, simulations });
  assert.equal(assertRuntimeConsumabilityEvidence(evidence, { sourceSha, candidate: value,
    livePolicyIdentity, resourceMetadata: resources }).status, "PASS");
  assert.throws(() => assertRuntimeConsumabilityEvidence(evidence, { sourceSha: "b".repeat(40), candidate: value,
    livePolicyIdentity, resourceMetadata: resources }), /stale|tampered/);
  const changed = candidate(); changed.containerDefinitions[0].image = `${APP_ONLY.backendRepository}@sha256:${"2".repeat(64)}`;
  assert.throws(() => assertRuntimeConsumabilityEvidence(evidence, { sourceSha, candidate: changed,
    livePolicyIdentity, resourceMetadata: resources }));
});

test("green runtime refuses missing, broad, drifted, or incomplete IAM", async () => {
  const changes = [
    (r) => { if (r.Role) r.Role.Arn = `arn:aws:iam::${APP_ONLY.account}:role/wrong`; },
    (r) => { if (r.Role) delete r.Role.RoleId; },
    (r) => { if (r.PolicyNames) r.PolicyNames = []; },
    (r) => { if (r.PolicyNames) r.PolicyNames.push("unreviewed"); },
    (r) => { if (r.AttachedPolicies) r.AttachedPolicies.push({ PolicyArn: RUNTIME_CONSUMABILITY.awsManagedExecutionPolicyArn }); },
    (r) => { if (r.PolicyNames) r.IsTruncated = true; },
    (r) => { if (r.AttachedPolicies) r.IsTruncated = true; },
    (r) => { if (r.PolicyDocument) r.PolicyDocument.Statement.find(({ Sid }) => Sid === "WriteOnlyExactTaskLogs").Resource = "*"; },
    (r) => { if (r.PolicyDocument) r.PolicyDocument.Statement.find(({ Sid }) => Sid === "WriteOnlyExactTaskLogs").Resource = `${logResource}-wrong:log-stream:*`; },
    (r) => { if (r.PolicyDocument) r.PolicyDocument.Statement.find(({ Sid }) => Sid === "PullOnlyApprovedRepository").Action = ["ecr:BatchGetImage"]; },
    (r) => { if (r.PolicyDocument) r.PolicyDocument.Statement.find(({ Sid }) => Sid === "ReadOnlyExactInjectedSecrets").Resource = "*"; },
    (r) => { if (r.PolicyDocument) r.PolicyDocument.Statement.push({ Effect: "Deny", Action: "logs:PutLogEvents", Resource: logResource + ":log-stream:*" }); },
    (r) => { if (r.PolicyDocument) r.PolicyDocument.Statement.push({ Effect: "Allow", Action: "iam:*", Resource: "*" }); },
  ];
  for (const change of changes) await assert.rejects(() => collectLiveRolePolicyIdentity([APP_ONLY.executionRoleArn], iam(change), candidate()));
  const wrongRole = candidate(); wrongRole.executionRoleArn = `arn:aws:iam::${APP_ONLY.account}:role/wrong`;
  assert.throws(() => sourceRuntimePolicyOwnership(wrongRole, metadata()), /execution role/);
  const wrongNamespace = candidate(); wrongNamespace.containerDefinitions[0].logConfiguration.options["awslogs-group"] = "/ecs/unreviewed";
  assert.throws(() => sourceRuntimePolicyOwnership(wrongNamespace, metadata()));
});

test("green runtime simulation fails closed on explicit deny, missing context, or incomplete readback", async () => {
  const dependencies = deriveEcsRuntimeDependencies(candidate());
  for (const change of [
    (r) => { if (r.EvaluationResults) r.EvaluationResults[0].EvalDecision = "explicitDeny"; },
    (r) => { if (r.EvaluationResults) r.EvaluationResults[0].MissingContextValues = ["aws:PrincipalTag/unreviewed"]; },
    (r) => { if (r.EvaluationResults) delete r.EvaluationResults[0].EvalResourceName; },
  ]) {
    const simulations = await simulateRuntimeDependencies(dependencies, iam(change), { loggingResourceMode: "exact-dependency" });
    assert.ok(Object.values(simulations).every(({ decision }) => decision === "denied"));
  }
  let reads = 0;
  await assert.rejects(() => collectLiveRolePolicyIdentity([APP_ONLY.executionRoleArn], iam((response) => {
    if (response.PolicyDocument && ++reads === 1) delete response.PolicyDocument.Statement;
  }), candidate()));
});

test("Terraform owns exact injected-secret reads and refuses unowned customer KMS decrypt", () => {
  const value = candidate();
  const resource = sourcePolicy.Statement.find(({ Sid }) => Sid === "ReadOnlyExactInjectedSecrets").Resource[0];
  value.containerDefinitions[0].secrets = [{ name: "RUNTIME_SECRET", valueFrom: resource }];
  const selector = parseEcsSecretsManagerReference(resource);
  const versionIdsToStages = { ["1".repeat(32)]: ["AWSCURRENT"] };
  const secretVersions = [{ versionId: "1".repeat(32), versionStages: ["AWSCURRENT"] }];
  const selectorResolutions = [{ selector, resolvedVersionId: "1".repeat(32), jsonKeyState: "NOT_REQUESTED" }];
  const secret = { resource, availability: "AVAILABLE", deletedDate: null, versionIdsToStages, secretVersions,
    selectorResolutions, encryption: "AWS_MANAGED", kmsKeyArn: null, resourcePolicyAccess: "NO_RESOURCE_POLICY",
    resourcePolicySha256: canonicalSha256(null) };
  secret.metadataSha256 = canonicalSha256({ ARN: resource, KmsKeyId: null, availability: secret.availability,
    deletedDate: null, versionIdsToStages, secretVersions, selectorResolutions });
  const resources = { ...metadata(), [resource]: secret };
  const ownership = sourceRuntimePolicyOwnership(value, resources);
  assert.ok(Object.values(ownership).some(({ action, resource: arn }) => action === "secretsmanager:GetSecretValue" && arn === resource));
  assert.throws(() => sourceRuntimePolicyOwnership(value, metadata()), /encryption metadata is missing/);
  const customerManaged = { ...secret, encryption: "CUSTOMER_MANAGED", kmsKeyArn: STAGE_B.approvalKmsKeyArn,
    kmsKeyPolicySha256: "a".repeat(64), kmsKeyPolicyAccess: "EXACT_ROLE" };
  customerManaged.metadataSha256 = canonicalSha256({ ARN: resource, KmsKeyId: customerManaged.kmsKeyArn,
    availability: secret.availability, deletedDate: null, versionIdsToStages, secretVersions, selectorResolutions });
  assert.throws(() => sourceRuntimePolicyOwnership(value, { ...resources, [resource]: customerManaged }), /does not own/);
});

test("production Release Gate installs pinned Terraform before green recovery source evaluation", () => {
  const workflow = yaml.load(fs.readFileSync(".github/workflows/release-gate.yml", "utf8"));
  const steps = workflow.jobs["deploy-production-ecs"].steps;
  const setup = steps.findIndex(({ name }) => name === "Install pinned Terraform for green runtime policy verification");
  const recovery = steps.findIndex(({ name }) => name === "Execute governed green backend health recovery with verified Terraform source");
  assert.ok(setup >= 0 && recovery > setup);
  assert.equal(steps[setup].uses, "hashicorp/setup-terraform@v3");
  assert.equal(steps[setup].with.terraform_version, "1.15.8");
  assert.equal(steps[setup].with.terraform_wrapper, false);
  assert.equal(steps[setup].if, steps[recovery].if);
  assert.match(steps[recovery].run, /recover-production-green-backend-health\.mjs/);
});
