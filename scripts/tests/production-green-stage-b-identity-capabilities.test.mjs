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
import { assertInitialActivationReconcilerAuthority, assertStageBAwsCallCoverage, assertStageBDeploymentCapabilityGraph, buildStageBDeploymentCapabilityGraph, classifyStageARecoveryAwsCliAction, discoverAwsCliActions } from "../aws/generate-production-green-stage-b-capability-graph.mjs";
import { assertStageBAdministratorEvidenceIdentity, buildPermissionReportBinding, canonicalizeJson, PERMISSION_REPORT_BINDING_DOMAIN, PERMISSION_REPORT_BINDING_SCHEMA_VERSION, PERMISSION_REPORT_HASH_DOMAIN, PERMISSION_REPORT_SIGNING_ALGORITHM, PERMISSION_REPORT_SIGNING_KEY_ARN, PERMISSION_REPORT_SIGNATURE_SCHEMA_VERSION, runPermissionPreflight, signedPermissionReportBindingSha256, sourcePolicyEvidence } from "../aws/validate-production-green-stage-b-permissions.mjs";
import { runProductionPreflightCli } from "../aws/run-production-green-stage-b-preflight.mjs";
import { createProductionCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "../aws/production-cutover-production-adapters.mjs";
import { buildEcsExecOperatorEvidence } from "../aws/production-ecs-exec-operator-contract.mjs";
import { CHECKER_SOURCE_ROLE_ARN, CHECKER_USER_ARN } from "../aws/production-checker-chain-contract.mjs";
import { ECR_DOCUMENTED_NO_RESOURCE_POLICY, MALFORMED_ECR_REPOSITORY_POLICIES } from "./fixtures/ecr-repository-policy-fixtures.mjs";
import { makeCanonicalImageAuthorization } from "./fixtures/canonical-image-authorization.mjs";
import { imageEvidenceSha256 } from "../aws/production-green-stage-b-image-evidence.mjs";

const caller = "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test";
const protectedSourceSha = "73e5908658edadd9f4b2d678adec0affef0dbbac";
const stageAState = JSON.stringify({ lineage: STAGE_A_EXPECTED_STATE_LINEAGE, serial: 35, resources: [] });
const shapedPolicyEvidence = () => {
  const policies = sourcePolicyEvidence().map((policy) => ({ ...policy, defaultVersionId: "v1", liveSha256: policy.sourceSha256, attached: true, matchesSource: true }));
  return { roleArn: "arn:aws:iam::368992683803:role/mscqr-production-release-deployer", attachedPolicyArns: policies.map(({ arn }) => arn).sort(), inlinePolicyNames: [], inlinePolicies: [], permissionsBoundaryArn: null, policies, status: "valid" };
};
const temp = () => fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-release-preflight-test-"));
const imageFixture = makeCanonicalImageAuthorization({ sourceSha: protectedSourceSha, imageReleaseSha: protectedSourceSha });
const imageAuthorizationPath = path.join(temp(), "image-authorization.json");
const imageAuthorizationBytes = Buffer.from(`${JSON.stringify(imageFixture.authorization, null, 2)}\n`);
fs.writeFileSync(imageAuthorizationPath, imageAuthorizationBytes, { mode: 0o600 });
const imageAuthorizationSha256 = crypto.createHash("sha256").update(imageAuthorizationBytes).digest("hex");
const writePublicationFiles = (fixture, name) => {
  const directory = temp(); const evidencePath = path.join(directory, `${name}.image-evidence.json`); const signaturePath = path.join(directory, `${name}.image-evidence.signature.json`);
  fs.writeFileSync(evidencePath, `${JSON.stringify(fixture.authorization.imageEvidence, null, 2)}\n`, { mode: 0o600 });
  fs.writeFileSync(signaturePath, `${JSON.stringify(fixture.authorization.imageEvidenceSignature, null, 2)}\n`, { mode: 0o600 });
  return { evidencePath, signaturePath, artifactSha256: fixture.authorization.imageEvidence.canonicalArtifactSha256, workflowRunId: fixture.workflowRunId, imageReleaseSha: fixture.authorization.imageReleaseSha };
};
const publicationA = writePublicationFiles(imageFixture, "publication-a");
const imageFixtureB = makeCanonicalImageAuthorization({
  sourceSha: protectedSourceSha,
  imageReleaseSha: protectedSourceSha,
  publicationWorkflowRunId: "31582010245",
  publicationWorkflowDatabaseId: "402",
  imageDigests: {
    backend: "sha256:7c03df843e46dd0853762108c7ae780a4d06b7e11cac585d9d2b2cd3d196f6ad",
    worker: "sha256:849a4f25d9cc5d67358722c7af75e91bd9a944e75496c76fa36b4677fd152cfe",
    "rls-executor": "sha256:9a06c2435f7330c0b5efacce91e526aa0cca9f3f1df02efaec2c8f993b6fde37",
    "rls-canary": "sha256:026b3c87ef6b7d1545936e50a41a049e5d02b3f11ef81bd41946ca1c967b05ab",
  },
});
const publicationB = writePublicationFiles(imageFixtureB, "publication-b");
const releaseReadinessArgs = (publication = publicationA) => [
  "--image-evidence", publication.evidencePath, "--image-evidence-signature", publication.signaturePath,
  "--image-release-sha", publication.imageReleaseSha, "--workflow-run-id", publication.workflowRunId,
  "--canonical-artifact-sha256", publication.artifactSha256,
];
const runPreflightCli = (argv, dependencies = {}) => runProductionPreflightCli([
  ...argv, ...(dependencies.readinessArgs || releaseReadinessArgs()),
  "--image-authorization", imageAuthorizationPath,
  "--image-authorization-sha256", imageAuthorizationSha256,
], { verifyImageEvidence: imageFixture.verifyImageEvidence, ...dependencies });
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

test("Stage-A raw backend-state read has one exact release-deployer capability", () => {
  const rawStateCommand = '["s3api", "get-object", "--bucket", STAGE_A_TERRAFORM_BACKEND.bucket, "--key", STAGE_A_TERRAFORM_BACKEND.key, "--expected-bucket-owner", "368992683803", output]';
  assert.deepEqual(classifyStageARecoveryAwsCliAction({ action: "s3:GetObject", source: rawStateCommand, offset: 0 }), [{ identity: "RELEASE_DEPLOYER", capabilityId: "stage-a-artifacts-recovery-release-read-raw-state", sourceFunction: "stage-a-artifacts-recovery-release-read-raw-state", phase: "stage-a-production-artifacts-policy-recovery", resources: ["arn:aws:s3:::mscqr-production-terraform-state-368992683803-eu-west-2/mscqr/production/rls-green/stage-a/terraform.tfstate"] }]);
  assert.deepEqual(classifyStageARecoveryAwsCliAction({ action: "s3:GetBucketPolicy", source: "", offset: 0 }), [{ identity: "RELEASE_DEPLOYER" }]);
  for (const action of ["s3:PutBucketPolicy", "s3:PutObject", "s3:DeleteObject"]) assert.deepEqual(classifyStageARecoveryAwsCliAction({ action, source: rawStateCommand, offset: 0 }), [{ identity: "ROOT_OPERATOR" }]);
  for (const source of [
    rawStateCommand.replace("STAGE_A_TERRAFORM_BACKEND.bucket", '"wrong-bucket"'),
    rawStateCommand.replace("STAGE_A_TERRAFORM_BACKEND.key", '"wrong-key"'),
    '["s3api", "get-object", "--bucket", bucket, "--key", key, output]',
  ]) assert.deepEqual(classifyStageARecoveryAwsCliAction({ action: "s3:GetObject", source, offset: 0 }), [{ identity: "ROOT_OPERATOR" }]);
  const rawRead = buildStageBDeploymentCapabilityGraph().capabilities.find(({ id }) => id === "stage-a-artifacts-recovery-release-read-raw-state");
  assert.deepEqual(rawRead && [rawRead.identity, rawRead.action, rawRead.resources, rawRead.mutation], ["RELEASE_DEPLOYER", "s3:GetObject", ["arn:aws:s3:::mscqr-production-terraform-state-368992683803-eu-west-2/mscqr/production/rls-green/stage-a/terraform.tfstate"], false]);
});

test("reconciliation raw backend-state CAS is an exact AWS CLI capability", () => {
  const graph = buildStageBDeploymentCapabilityGraph();
  const capability = graph.capabilities.find(({ id }) => id === "stage-a-artifacts-reconciliation-release-read-raw-state");
  const call = graph.sourceScan.find(({ capabilityId }) => capabilityId === "stage-a-artifacts-reconciliation-release-read-raw-state");
  assert.deepEqual(capability && [capability.phase, capability.identity, capability.executor, capability.action, capability.resources, capability.mutation], ["stage-a-production-artifacts-state-reconciliation", "RELEASE_DEPLOYER", "aws-cli", "s3:GetObject", ["arn:aws:s3:::mscqr-production-terraform-state-368992683803-eu-west-2/mscqr/production/rls-green/stage-a/terraform.tfstate"], false]);
  assert.doesNotThrow(() => assertStageBAwsCallCoverage(graph, [call]));
  assert.throws(() => assertStageBAwsCallCoverage({ ...graph, capabilities: graph.capabilities.filter(({ id }) => id !== capability.id) }, [call]), /exact capability coverage/);
  for (const mutation of [{ executor: "terraform" }, { identity: "ROOT_OPERATOR" }, { resources: ["arn:aws:s3:::mscqr-production-terraform-state-368992683803-eu-west-2/*"] }]) {
    const changed = structuredClone(graph); Object.assign(changed.capabilities.find(({ id }) => id === capability.id), mutation);
    assert.throws(() => assertStageBDeploymentCapabilityGraph(changed), /stale or incomplete/);
  }
});

test("release preflight routes every S3 and Lambda probe through the credential-bound AWS runner", () => {
  const calls = [];
  const run = createProductionCommandRunner({
    credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE,
    profile: "mscqr-production-release-deployer",
    env: { PATH: process.env.PATH },
    exec: (file, args, options) => {
      calls.push({ file, args, options });
      const normalized = [...args];
      const region = normalized.indexOf("--region");
      if (region !== -1) normalized.splice(region, 2);
      return allowed(normalized);
    },
  });
  const report = runReleaseReadPreflight({ outputDirectory: temp(), run });
  const affected = calls.filter(({ args }) => ["s3api", "lambda"].includes(args[0]));

  assert.equal(report.status, "valid");
  assert.deepEqual(affected.map(({ file, args }) => [file, args[0], args[1]]), [
    ["aws", "s3api", "get-bucket-location"],
    ["aws", "s3api", "get-object"],
    ["aws", "s3api", "get-object"],
    ["aws", "lambda", "get-function-configuration"],
    ["aws", "lambda", "get-alias"],
  ]);
  assert.equal(calls.filter(({ file }) => file === "s3api").length, 0);
  assert.equal(calls.filter(({ file }) => file === "lambda").length, 0);
  assert.equal(affected.every(({ options }) => options.env.AWS_PROFILE === "mscqr-production-release-deployer"), true);

  run(["node", "fixture.mjs"]);
  assert.equal(calls.at(-1).file, "node");
});

test("identity matrix assigns IAM simulation only to administrator", () => {
  const matrix = readIdentityCapabilityMatrix();
  assert(matrix.calls.some(({ identity, action }) => identity === "ADMINISTRATOR" && action === "iam:SimulatePrincipalPolicy"));
  assert(!matrix.calls.some(({ identity, action }) => identity === "RELEASE_DEPLOYER" && action === "iam:SimulatePrincipalPolicy"));
  assert.equal(matrix.phases.length, 46);
});

test("Stage B release readiness requires the completed Stage A contract", () => {
  const source = fs.readFileSync("scripts/aws/run-production-green-stage-b-preflight.mjs", "utf8");
  assert.match(source, /generateStageAPrerequisites\(\{[^;]+phase: "POST_APPLY", run: \(args\) => releaseAwsRun\(args\) \}\);/);
  assert.doesNotMatch(source, /recoveryMode === "NORMAL" \? "PRE_APPLY"/);
});

test("generated capability graph is exhaustive, deterministic, and identity-exact", () => {
  const first = buildStageBDeploymentCapabilityGraph(); const second = buildStageBDeploymentCapabilityGraph();
  assert.deepEqual(first, second);
  assert.deepEqual(assertStageBDeploymentCapabilityGraph(first), { phases: 46, capabilities: 384, uniqueActions: 134, unmappedCalls: 0, unclassifiedCapabilities: 0, identityBoundaryViolations: 0, sourcePolicyMismatches: 0, manifestMismatches: 0, configurationContradictions: 0 });
  assert(first.capabilities.every(({ identity }) => first.identities.includes(identity)));
  assert(first.capabilities.every(({ id }, index) => first.capabilities.findIndex((item) => item.id === id) === index));
  assert(first.capabilities.some(({ identity, action }) => identity === "ECS_EXEC_VERIFIER_OPERATOR" && action === "ecs:ExecuteCommand"));
  assert.equal(first.capabilities.filter(({ identity, action }) => identity === "RELEASE_DEPLOYER" && action === "ecs:ExecuteCommand").length, 0);
  const reconcilerCapabilities = first.capabilities.filter(({ identity }) => identity === "INITIAL_ACTIVATION_RECONCILER");
  assert.equal(reconcilerCapabilities.length, 8);
  for (const capability of reconcilerCapabilities) {
    assert.deepEqual(capability.policy, assertInitialActivationReconcilerAuthority(capability));
    assert.equal(capability.policy.sourceFile, "infra/aws/terraform/production-initial-activation-policy-reconciler/permissions-policy.json");
    assert.equal(capability.policy.livePolicyArn, "arn:aws:iam::368992683803:policy/MSCQRProductionInitialActivationPolicyReconciler");
    assert.equal(capability.context.targetPolicyArn, "arn:aws:iam::368992683803:policy/MSCQRProductionInitialActivationLifecycle");
  }
  const targetBound = structuredClone(first); targetBound.capabilities.find(({ identity }) => identity === "INITIAL_ACTIVATION_RECONCILER").policy.livePolicyArn = "arn:aws:iam::368992683803:policy/MSCQRProductionInitialActivationLifecycle";
  assert.throws(() => assertStageBDeploymentCapabilityGraph(targetBound), /stale or incomplete/);
  const reconcilerPolicy = JSON.parse(fs.readFileSync("infra/aws/terraform/production-initial-activation-policy-reconciler/permissions-policy.json", "utf8"));
  assert.throws(() => assertInitialActivationReconcilerAuthority({ action: "iam:CreatePolicyVersion", resources: ["arn:aws:iam::368992683803:policy/MSCQRProductionInitialActivationLifecycle"] }, { ...reconcilerPolicy, Statement: reconcilerPolicy.Statement.map((statement) => statement.Sid === "CreateExactInitialActivationLifecyclePolicyVersion" ? { ...statement, Action: "iam:GetPolicy" } : statement) }), /does not authorize/);
  assert.throws(() => assertInitialActivationReconcilerAuthority({ action: "iam:CreatePolicyVersion", resources: ["arn:aws:iam::368992683803:policy/other"] }, reconcilerPolicy), /does not authorize/);
  assert.throws(() => assertInitialActivationReconcilerAuthority({ action: "iam:CreatePolicyVersion", resources: ["arn:aws:iam::368992683803:policy/MSCQRProductionInitialActivationLifecycle"] }, JSON.parse(fs.readFileSync("documents/ops/iam/MSCQRProductionInitialActivationLifecycle-v1.json", "utf8"))), /does not authorize/);
  assert.equal(first.capabilities.find(({ id }) => id === "manifest-release-deployer-ecs-exec").identity, "ADMINISTRATOR");
  assert.equal(first.capabilities.filter(({ identity, action, resources }) => identity === "INDEPENDENT_CHECKER" && action === "secretsmanager:PutSecretValue" && resources.includes("arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/phase2/approval-e0shho")).length, 1);
  assert.equal(first.capabilities.filter(({ identity, action, resources }) => identity === "RELEASE_DEPLOYER" && action === "secretsmanager:PutSecretValue" && resources.includes("arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/phase2/approval-e0shho")).length, 0);
  assert.equal(first.capabilities.filter(({ id, identity, action, resources }) => id === "administrator-release-preflight-trust-attestation-sign" && identity === "ADMINISTRATOR" && action === "kms:Sign" && resources.includes("arn:aws:kms:eu-west-2:368992683803:alias/mscqr-production-root-attestation")).length, 1);
  assert.equal(first.capabilities.filter(({ identity, action }) => identity === "RELEASE_DEPLOYER" && action === "kms:Sign").length, 0);
  assert.equal(first.capabilities.filter(({ id, phase, identity, action, resources }) => id === "stage-a-artifacts-recovery-root-sign" && phase === "stage-a-production-artifacts-policy-recovery" && identity === "ROOT_OPERATOR" && action === "kms:Sign" && resources.includes("arn:aws:kms:eu-west-2:368992683803:alias/mscqr-production-root-attestation")).length, 1);
  for (const [id, action] of [["admin-image-evidence-describe-key", "kms:DescribeKey"], ["admin-image-evidence-read-key-policy", "kms:GetKeyPolicy"], ["admin-image-evidence-read-key-tags", "kms:ListResourceTags"], ["admin-verify-image-evidence", "kms:Verify"]]) {
    assert.equal(first.capabilities.filter(({ id: capabilityId, identity, action: capabilityAction, resources }) => capabilityId === id && identity === "ADMINISTRATOR" && capabilityAction === action && resources.includes("arn:aws:kms:eu-west-2:368992683803:alias/mscqr-production-root-attestation")).length, 1);
  }
  for (const [id, action, mutation] of [
    ["manifest-refresh-stage-a-production-artifacts-bucket-policy", "s3:GetBucketPolicy", false],
    ["manifest-apply-stage-a-production-artifacts-bucket-policy", "s3:PutBucketPolicy", true],
  ]) assert(first.capabilities.some((capability) => capability.id === id
    && capability.action === action
    && capability.identity === "RELEASE_DEPLOYER"
    && capability.resources.length === 1
    && capability.resources[0] === "arn:aws:s3:::mscqr-prod-euw2-artifacts-368992683803-eu-west-2-an"
    && capability.policy.sourceFile === "documents/ops/iam/MSCQRProductionInitialActivationLifecycle-v1.json"
    && capability.mutation === mutation));
  assert(first.capabilities.some((capability) => capability.id === "manifest-unrelated-bucket-policy-write"
    && capability.action === "s3:PutBucketPolicy"
    && capability.classification === "FORBIDDEN"
    && capability.resources.length === 1
    && capability.resources[0] === "arn:aws:s3:::unrelated-bucket"));
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

test("administrator preflight binds live temporary-KMS absence evidence to protected main, not the simulation fixture", () => {
  const directory = temp(); const adminPath = path.join(directory, "admin.json"); const signaturePath = path.join(directory, "admin.signature.json");
  let administratorSimulations = 0;
  const admin = runPreflightCli(["--identity", "administrator", "--phase", "initial", "--source-sha", protectedSourceSha, "--output", adminPath, "--signature-output", signaturePath], {
    caller: () => "arn:aws:iam::368992683803:root",
    collectPolicies: shapedPolicyEvidence,
    collectEcsExecOperatorEvidence: () => buildEcsExecOperatorEvidence(),
    readProtectedMainCheckout: () => ({ toolingSha: protectedSourceSha, currentHead: protectedSourceSha, originMainHead: protectedSourceSha, porcelainStatus: "" }),
    permissionPreflight: (input) => { administratorSimulations += 1; assert.equal(input.plan.variables.tooling_sha.value, protectedSourceSha); assert.equal(input.plan.variables.image_release_sha.value, imageFixture.authorization.imageReleaseSha); assert.equal(input.plan.variables.canonical_image_evidence_sha256.value, imageFixture.authorization.imageEvidenceSha256); return runPermissionPreflight({ ...input, simulate: ({ evaluation }) => ({ decision: evaluation.expectedDecision || "allowed", matchedStatements: evaluation.expectedDecision ? 0 : 1, missingContextValues: evaluation.expectedDecision ? evaluation.expectedMissingContextValues : [] }), cloudTrail: () => ({ status: "clear", eventsChecked: 0, unresolvedDenials: [] }) }); },
    sign: (report, { reportBytes }) => { const canonicalPayloadSha256 = crypto.createHash("sha256").update(Buffer.from(canonicalizeJson(report))).digest("hex"); const reportFileSha256 = crypto.createHash("sha256").update(reportBytes).digest("hex"); const bindingPayload = buildPermissionReportBinding({ report, canonicalPayloadSha256, reportFileSha256, keyArn: PERMISSION_REPORT_SIGNING_KEY_ARN, signingAlgorithm: PERMISSION_REPORT_SIGNING_ALGORITHM }); return { schemaVersion: PERMISSION_REPORT_SIGNATURE_SCHEMA_VERSION, hashDomain: PERMISSION_REPORT_HASH_DOMAIN, bindingDomain: PERMISSION_REPORT_BINDING_DOMAIN, bindingSchemaVersion: PERMISSION_REPORT_BINDING_SCHEMA_VERSION, evidenceKind: report.evidenceKind, phase: report.phase, purpose: report.purpose, accountId: "368992683803", region: "eu-west-2", keyId: PERMISSION_REPORT_SIGNING_KEY_ARN, keyArn: PERMISSION_REPORT_SIGNING_KEY_ARN, signingAlgorithm: PERMISSION_REPORT_SIGNING_ALGORITHM, canonicalPayloadSha256, reportFileSha256, signedBindingSha256: signedPermissionReportBindingSha256(bindingPayload), signatureBase64: "AQ==", signedAt: report.generatedAt }; },
  });
  assert.equal(admin.status, "valid"); assert.equal(administratorSimulations, 1);
  const administratorReport = JSON.parse(fs.readFileSync(adminPath, "utf8"));
  const administratorSignature = JSON.parse(fs.readFileSync(signaturePath, "utf8"));
  assert.equal(administratorReport.sourceSha, protectedSourceSha);
  assert.equal(administratorReport.toolingSha, protectedSourceSha);
  assert.equal(administratorReport.imageReleaseSha, imageFixture.authorization.imageReleaseSha);
  assert.equal(administratorReport.canonicalImageEvidenceSha256, imageFixture.authorization.imageEvidenceSha256);
  assert.equal(administratorReport.imageAuthorizationSha256, imageFixture.authorization.authorizationSha256);
  assert.equal(administratorReport.imageAuthorizationFileSha256, imageAuthorizationSha256);
  assert.equal(administratorReport.temporaryKmsCapability.sourceSha, protectedSourceSha);
  assert.equal(administratorReport.temporaryKmsCapability.transitionId, `preflight-${protectedSourceSha.slice(0, 12)}`);
  assert.equal(administratorSignature.canonicalPayloadSha256, crypto.createHash("sha256").update(Buffer.from(canonicalizeJson(administratorReport))).digest("hex"));
  const releasePath = path.join(directory, "release.json"); let releaseReads = 0;
  const release = runPreflightCli(["--identity", "release-deployer", "--tooling-sha", protectedSourceSha, "--output", releasePath, "--administrator-report", adminPath, "--administrator-report-signature", signaturePath], {
    caller: () => caller,
    verify: () => true,
    readProtectedMainCheckout: () => ({ toolingSha: protectedSourceSha, currentHead: protectedSourceSha, originMainHead: protectedSourceSha, porcelainStatus: "" }),
    releasePreflight: () => { releaseReads += 1; return { schemaVersion: 1, caller, account: "368992683803", region: "eu-west-2", requiredReads: {}, failed: [], skipped: [], status: "valid" }; },
    continueReadiness: () => ({ backendReady: true, stateReady: true, handoffReady: true, tfvarsReady: true }), validateCapabilityGraph: () => admin.capabilityGraph,
  });
  assert.equal(release.status, "ready-for-plan"); assert.equal(releaseReads, 1);
  assert.equal(JSON.parse(fs.readFileSync(releasePath, "utf8")).sourceSha, protectedSourceSha);

  const releaseArguments = ["--identity", "release-deployer", "--tooling-sha", protectedSourceSha, "--output", path.join(directory, "release-cross-binding.json"), "--administrator-report", adminPath, "--administrator-report-signature", signaturePath];
  let continued = 0;
  const releaseDependencies = {
    caller: () => caller,
    verify: () => true,
    readProtectedMainCheckout: () => ({ toolingSha: protectedSourceSha, currentHead: protectedSourceSha, originMainHead: protectedSourceSha, porcelainStatus: "" }),
    releasePreflight: () => ({ schemaVersion: 1, caller, account: "368992683803", region: "eu-west-2", requiredReads: {}, failed: [], skipped: [], status: "valid" }),
    continueReadiness: () => { continued += 1; },
    validateCapabilityGraph: () => admin.capabilityGraph,
  };
  const runReleaseWithPublication = (publication, overrides = {}, args = releaseArguments) => runPreflightCli(args, { ...releaseDependencies, ...overrides, readinessArgs: overrides.readinessArgs || releaseReadinessArgs(publication) });
  assert.doesNotThrow(() => runReleaseWithPublication(publicationA));
  assert.equal(continued, 1);
  assert.throws(() => runReleaseWithPublication(publicationB), /workflow-run-id|canonical-artifact-sha256|image evidence/);
  assert.throws(() => runReleaseWithPublication(publicationA, { readinessArgs: releaseReadinessArgs(publicationA).map((item, index, args) => index === args.indexOf("--workflow-run-id") + 1 ? publicationB.workflowRunId : item) }), /workflow-run-id/);
  assert.throws(() => runReleaseWithPublication(publicationA, { readinessArgs: releaseReadinessArgs(publicationA).map((item, index, args) => index === args.indexOf("--canonical-artifact-sha256") + 1 ? "0".repeat(64) : item) }), /canonical-artifact-sha256/);
  assert.throws(() => runReleaseWithPublication(publicationA, { readinessArgs: releaseReadinessArgs(publicationA).map((item, index, args) => index === args.indexOf("--image-release-sha") + 1 ? "b".repeat(40) : item) }), /image-release-sha/);
  assert.throws(() => runReleaseWithPublication(publicationA, { readinessArgs: ["--image-evidence", publicationB.evidencePath, "--image-evidence-signature", publicationB.signaturePath, ...releaseReadinessArgs(publicationA).slice(4)] }), /image evidence/);
  assert.equal(continued, 1);

  const originalEvidenceBytes = fs.readFileSync(publicationA.evidencePath); const originalSignatureBytes = fs.readFileSync(publicationA.signaturePath); let pinnedPublication;
  try {
    assert.doesNotThrow(() => runReleaseWithPublication(publicationA, {
      releasePreflight: () => { fs.copyFileSync(publicationB.evidencePath, publicationA.evidencePath); fs.copyFileSync(publicationB.signaturePath, publicationA.signaturePath); return releaseDependencies.releasePreflight(); },
      continueReadiness: (_args, publication) => { pinnedPublication = publication; return { backendReady: true, stateReady: true, handoffReady: true, tfvarsReady: true }; },
    }, releaseArguments.map((item, index, args) => index === args.indexOf("--output") + 1 ? path.join(directory, "release-toctou.json") : item)));
  } finally {
    fs.writeFileSync(publicationA.evidencePath, originalEvidenceBytes, { mode: 0o600 }); fs.writeFileSync(publicationA.signaturePath, originalSignatureBytes, { mode: 0o600 });
  }
  assert.equal(imageEvidenceSha256(JSON.parse(pinnedPublication.imageEvidenceBytes)), imageFixture.authorization.imageEvidenceSha256);
  assert.equal(imageEvidenceSha256(JSON.parse(pinnedPublication.imageEvidenceBytes)), imageEvidenceSha256(JSON.parse(originalEvidenceBytes)));
});

test("administrator preflight requires current image authorization and rejects fixture-bound identities", () => {
  const directory = temp();
  const args = ["--identity", "administrator", "--phase", "initial", "--source-sha", protectedSourceSha, "--output", path.join(directory, "admin.json"), "--signature-output", path.join(directory, "admin.signature.json")];
  assert.throws(() => runProductionPreflightCli(args, { caller: () => "arn:aws:iam::368992683803:root", readProtectedMainCheckout: () => ({ toolingSha: protectedSourceSha, currentHead: protectedSourceSha, originMainHead: protectedSourceSha, porcelainStatus: "" }) }), /image-authorization/);
  const valid = { evidenceKind: "INITIAL_ADMIN_CAPABILITY", phase: "initial", sourceSha: protectedSourceSha, toolingSha: "e".repeat(40), imageReleaseSha: "a".repeat(40), canonicalImageEvidenceSha256: "f".repeat(64), imageAuthorizationSha256: imageFixture.authorization.authorizationSha256 };
  assert.throws(() => assertStageBAdministratorEvidenceIdentity(valid, { sourceSha: protectedSourceSha, imageAuthorization: imageFixture.authorization }), /tooling SHA|image release|canonical image-evidence/);
  assert.throws(() => assertStageBAdministratorEvidenceIdentity(valid), /source binding is required/);
});

test("administrator preflight forwards its credential-bound command runner to every IAM simulation", () => {
  const directory = temp(); const adminPath = path.join(directory, "admin.json"); const signaturePath = path.join(directory, "admin.signature.json");
  const plan = JSON.parse(fs.readFileSync("scripts/tests/fixtures/production-green-stage-b-production-shaped.plan.json", "utf8"));
  const manifest = JSON.parse(fs.readFileSync("documents/ops/iam/MSCQRProductionGreenStageBPermissionManifest-v1.json", "utf8"));
  const simulations = [];
  const generatedAt = new Date().toISOString();
  assert.equal(runPermissionPreflight({
    reportGeneratorCallerArn: "arn:aws:iam::368992683803:root", simulatedRoleArn: "arn:aws:iam::368992683803:role/mscqr-production-release-deployer",
    manifest, plan, planBytes: Buffer.from(JSON.stringify(plan)), generatedAt, now: generatedAt, policyPublishedAt: generatedAt,
    cloudTrailSessionName: "pre-plan-capability", policyEvidence: shapedPolicyEvidence(), ecsExecVerifierEvidence: buildEcsExecOperatorEvidence(), phase: "initial",
    simulate: ({ evaluation }) => {
      const decision = evaluation.expectedDecision || "allowed";
      simulations.push({ action: evaluation.action, resource: evaluation.resource, decision, matchedStatements: evaluation.expectedDecision ? 0 : 1, missingContextValues: evaluation.expectedMissingContextValues || [] });
      return simulations.at(-1);
    },
    cloudTrail: () => ({ status: "clear", eventsChecked: 0, unresolvedDenials: [] }),
  }).status, "valid");
  const calls = [];
  const commandRun = (args) => {
    assert.deepEqual(args.slice(0, 2), ["iam", "simulate-principal-policy"]);
    calls.push(args);
    const expected = simulations.shift(); assert(expected);
    const action = args[args.indexOf("--action-names") + 1]; const resource = args[args.indexOf("--resource-arns") + 1];
    assert.equal(action, expected.action); assert.equal(resource, expected.resource);
    return JSON.stringify({ EvaluationResults: [{ EvalActionName: action, EvalResourceName: resource, EvalDecision: expected.decision, MatchedStatements: Array.from({ length: expected.matchedStatements }, () => ({})), MissingContextValues: expected.missingContextValues }] });
  };
  const result = runPreflightCli(["--identity", "administrator", "--phase", "initial", "--source-sha", protectedSourceSha, "--output", adminPath, "--signature-output", signaturePath], {
    commandRun,
    caller: () => "arn:aws:iam::368992683803:root",
    collectPolicies: shapedPolicyEvidence,
    collectEcsExecOperatorEvidence: () => buildEcsExecOperatorEvidence(),
    readProtectedMainCheckout: () => ({ toolingSha: protectedSourceSha, currentHead: protectedSourceSha, originMainHead: protectedSourceSha, porcelainStatus: "" }),
    sign: () => ({}),
  });
  const report = JSON.parse(fs.readFileSync(adminPath, "utf8"));
  assert.equal(result.status, "valid");
  assert.equal(calls.length, report.iamEvaluationCensus.total);
  assert.equal(simulations.length, 0);
  assert.equal(report.iamEvaluationCensus.failures.filter(({ error }) => /explicit credential-bound AWS command runner/.test(error || "")).length, 0);
});

test("administrator preflight rejects a root-drop policy missing provider rotation readback", () => {
  const directory = temp(); let simulated = false;
  assert.throws(() => runPreflightCli(["--identity", "administrator", "--phase", "initial", "--source-sha", protectedSourceSha, "--output", path.join(directory, "admin.json"), "--signature-output", path.join(directory, "admin.signature.json")], {
    caller: () => "arn:aws:iam::368992683803:root",
    readProtectedMainCheckout: () => ({ toolingSha: protectedSourceSha, currentHead: protectedSourceSha, originMainHead: protectedSourceSha, porcelainStatus: "" }),
    readStageATerraformSource: () => fs.readFileSync("infra/aws/terraform/production-green-stage-a/main.tf", "utf8").replace("kms:GetKeyRotationStatus", "kms:GetKeyPolicy"),
    permissionPreflight: () => { simulated = true; return {}; },
  }), /provider read/);
  assert.equal(simulated, false);
});

test("administrator preflight rejects missing, malformed, fixture-bound, and stale protected source identities", () => {
  const directory = temp();
  const base = ["--identity", "administrator", "--phase", "initial", "--output", path.join(directory, "admin.json"), "--signature-output", path.join(directory, "admin.signature.json")];
  const deps = { caller: () => "arn:aws:iam::368992683803:root", readProtectedMainCheckout: () => ({ toolingSha: protectedSourceSha, currentHead: protectedSourceSha, originMainHead: protectedSourceSha, porcelainStatus: "" }) };
  assert.throws(() => runPreflightCli(base, deps), /exactly one --source-sha/);
  assert.throws(() => runPreflightCli(["--identity", "administrator", "--phase", "initial", "--source-sha", protectedSourceSha, "--source-sha", protectedSourceSha, "--output", path.join(directory, "duplicate.json"), "--signature-output", path.join(directory, "duplicate.signature.json")], deps), /exactly one --source-sha/);
  assert.throws(() => runPreflightCli(["--identity", "administrator", "--phase", "initial", "--source-sha", "bad", "--output", path.join(directory, "malformed.json"), "--signature-output", path.join(directory, "malformed.signature.json")], deps), /full protected source SHA/);
  for (const sourceSha of ["e".repeat(40), "a".repeat(40)]) {
    assert.throws(() => runPreflightCli(["--identity", "administrator", "--phase", "initial", "--source-sha", sourceSha, "--output", path.join(directory, `${sourceSha.slice(0, 1)}.json`), "--signature-output", path.join(directory, `${sourceSha.slice(0, 1)}.signature.json`)], deps), /exact clean protected-main source/);
  }
});

test("invalid release capability report stops before backend readiness", () => {
  const directory = temp(); const adminPath = path.join(directory, "admin.json"); const signaturePath = path.join(directory, "signature.json");
  const capabilityGraph = assertStageBDeploymentCapabilityGraph();
  fs.writeFileSync(adminPath, JSON.stringify({ schemaVersion: 1, evidenceKind: "INITIAL_ADMIN_CAPABILITY", phase: "initial", purpose: "pre-plan-capability", status: "valid", simulatedRoleArn: "arn:aws:iam::368992683803:role/mscqr-production-release-deployer", policyEvidence: shapedPolicyEvidence(), capabilityGraph }));
  fs.writeFileSync(signaturePath, "{}"); let continued = 0;
  assert.throws(() => runPreflightCli(["--identity", "release-deployer", "--tooling-sha", protectedSourceSha, "--output", path.join(directory, "release.json"), "--administrator-report", adminPath, "--administrator-report-signature", signaturePath], {
    caller: () => caller, verify: () => true,
    readProtectedMainCheckout: () => ({ toolingSha: protectedSourceSha, currentHead: protectedSourceSha, originMainHead: protectedSourceSha, porcelainStatus: "" }),
    releasePreflight: () => ({ requiredReads: { "ecs:DescribeClusters": "denied" }, failed: [{ action: "ecs:DescribeClusters" }], skipped: [], status: "blocked" }),
    continueReadiness: () => { continued += 1; }, validateCapabilityGraph: () => capabilityGraph,
  }), /Cutover-critical release capability lacks valid evidence|full 40-character commit SHA|source binding/);
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
