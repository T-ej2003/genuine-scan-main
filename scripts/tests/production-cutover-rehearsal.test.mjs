import assert from "node:assert/strict";
import test from "node:test";
import { generateKeyPairSync } from "node:crypto";
import { writeFileSync } from "node:fs";
import { assertStageAPlan, runStageAControlPlane } from "../aws/production-stage-a-control-plane.mjs";
import { describeStageAIngress } from "../aws/production-cutover-production-adapters.mjs";
import { assertTransitionMatrix, buildTransitionMatrix, runGovernedOverlapDeployment, runProductionCutoverControlPlane } from "../aws/production-cutover-control-plane.mjs";
import { ECS_EXEC_OPERATOR_REQUIRED, ECS_EXEC_OPERATOR_FORBIDDEN, buildEcsExecOperatorEvidence, ECS_EXEC_OPERATOR_ROLE_ARN } from "../aws/production-ecs-exec-operator-contract.mjs";
import { buildOnboardingEvidenceFingerprint, runStrictOnboardingProbes, STRICT_ONBOARDING_CHECKS } from "../security/production-strict-onboarding.mjs";
import { ROTATION_INVENTORY_CATEGORIES } from "../security/production-runtime-rotation-inventory.mjs";
import { createProductionPreDeploymentInventoryAdapter } from "../aws/production-predeployment-inventory-adapter.mjs";
import { makeCanonicalImageAuthorization } from "./fixtures/canonical-image-authorization.mjs";

const sourceSha = "96a4be6f0edcd626285c6a1bd8062a4008175d25";
const digest = "sha256:5c03df843e46dd0853762108c7ae780a4d06b7e11cac585d9d2b2cd3d196f6ad";
const imageDigest = `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@${digest}`;
const rotationId = "rotation-rehearsal-1";
const rotationStateSha256 = "c".repeat(64);
const evidenceSha256 = "d".repeat(64);
const validEvidence = (ref) => ({ valid: true, evidenceRef: ref, evidenceSha256 });

function iamFixture() {
  const required = [
    { manifestId: "apply-stage-a-endpoint-security-group-ingress", action: "ec2:AuthorizeSecurityGroupIngress", resource: "arn:aws:ec2:eu-west-2:368992683803:security-group/endpoint", decision: "allowed" },
    { manifestId: "activate-exact-ecs-service", action: "ecs:UpdateService", resource: "arn:aws:ecs:eu-west-2:368992683803:service/mscqr-prod-euw2-main/mscqr-backend-servi-euw2", decision: "allowed" },
    { manifestId: "rollback-exact-ecs-service", action: "ecs:UpdateService", resource: "arn:aws:ecs:eu-west-2:368992683803:service/mscqr-prod-euw2-main/mscqr-backend-servi-euw2", decision: "allowed" },
    { manifestId: "rollback-exact-backend-task-passrole", action: "iam:PassRole", resource: "arn:aws:iam::368992683803:role/mscqr-production-rls-green-backend-task", decision: "allowed" },
  ];
  const releaseForbidden = [{ manifestId: "release-deployer-ecs-exec", action: "ecs:ExecuteCommand", resource: "arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/*", decision: "implicitDeny" }];
  const asEval = (entry, forbidden = false) => ({ manifestId: entry.id || entry.manifestId, id: entry.id || entry.manifestId, action: entry.action, resource: entry.resources?.[0] || entry.resource, context: entry.context || [], decision: forbidden ? "implicitDeny" : "allowed", expectedDecision: forbidden ? "implicitDeny" : undefined });
  const operatorRequired = ECS_EXEC_OPERATOR_REQUIRED.map((entry) => asEval(entry));
  const operatorForbidden = ECS_EXEC_OPERATOR_FORBIDDEN.map((entry) => asEval(entry, true));
  const all = [...required, ...releaseForbidden, ...operatorRequired, ...operatorForbidden];
  return {
    status: "valid",
    evidence: validEvidence("iam:rehearsal"),
    requiredEvaluations: required,
    forbiddenEvaluations: releaseForbidden,
    principalEvaluations: {
      releaseDeployer: { status: "valid", requiredEvaluations: required, forbiddenEvaluations: releaseForbidden },
      ecsExecVerifier: { principalArn: ECS_EXEC_OPERATOR_ROLE_ARN, status: "valid", requiredEvaluations: operatorRequired, forbiddenEvaluations: operatorForbidden },
    },
    ecsExecVerifierTrust: buildEcsExecOperatorEvidence(),
    iamEvaluationCensus: { total: all.length, executed: all.length, invalid: 0, failures: [] },
  };
}

function artifactFixture() {
  const pair = generateKeyPairSync("ed25519", { privateKeyEncoding: { format: "pem", type: "pkcs8" }, publicKeyEncoding: { format: "pem", type: "spki" } });
  const bindings = Object.fromEntries(["ARTIFACT_SIGN_PRIVATE_KEY_CURRENT", "ARTIFACT_SIGN_PUBLIC_KEY_CURRENT", "ARTIFACT_SIGN_ACTIVE_KEY_VERSION", "ARTIFACT_SIGN_PUBLIC_KEYS_JSON"].map((name) => [name, `arn:aws:secretsmanager:eu-west-2:368992683803:secret:rehearsal-${name}`]));
  const values = { [bindings.ARTIFACT_SIGN_PRIVATE_KEY_CURRENT]: pair.privateKey, [bindings.ARTIFACT_SIGN_PUBLIC_KEY_CURRENT]: pair.publicKey, [bindings.ARTIFACT_SIGN_ACTIVE_KEY_VERSION]: "v1", [bindings.ARTIFACT_SIGN_PUBLIC_KEYS_JSON]: JSON.stringify({ v1: pair.publicKey }) };
  return { bindings, readSecret: async (ref) => values[ref], evidenceRef: "artifact:rehearsal", evidenceSha256, provision: async () => ({ mutationCount: 1, mutationPayload: { targets: Object.values(bindings) } }) };
}

const inventory = Object.fromEntries(ROTATION_INVENTORY_CATEGORIES.map((name) => [name,
  ["printerTestQrArtifacts", "legacyImmutableAuditArtifacts"].includes(name) ? { status: "NOT_APPLICABLE", reason: "not persisted by this schema" }
    : name === "oauthState" ? { persisted: false, maxTtlSeconds: 900 }
    : name === "oauthExchange" ? { persisted: false, maxTtlSeconds: 600 }
      : name === "printedQrCompatibility" ? { maxConfiguredTtlSeconds: 31536000 }
        : name === "qrArtifacts" ? { count: 0, maxExpiry: null, issuanceModes: {}, keyVersions: { status: "NOT_APPLICABLE", reason: "no persisted key version" } }
          : name === "artifactRecords" ? { count: 0, maxFinishedAt: null, signatureAlgorithms: {} }
            : name === "legacyComplianceArtifacts" ? { count: 0, maxFinishedAt: null }
              : ["refreshSessions", "adminSessions", "customerSessions", "customerVerificationState", "activeInvites", "resetTokens", "emailVerification"].includes(name) ? { count: 0, maxExpiry: null }
                : { count: 0 }]));
const taskArn = "arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/rehearsal";
const taskDefinitionArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:1";

function fixtureInput(overrides = {}) {
  const mutations = [];
  const imageAuthorizationFixture = makeCanonicalImageAuthorization({ sourceSha });
  const strictProbes = Object.fromEntries(STRICT_ONBOARDING_CHECKS.map((name) => [name, async () => true]));
  const stageA = {
    endpointSecurityGroupId: "sg-endpoint",
    runtimeSecurityGroupId: "sg-runtime",
    adapter: {
      createSavedPlan: async () => ({ sourceSha, savedPlanSha256: "e".repeat(64), plan: { resource_changes: [{ address: 'aws_vpc_security_group_ingress_rule.runtime_endpoints_https["sg-runtime"]', change: { actions: ["create"], after: { security_group_id: "sg-endpoint", referenced_security_group_id: "sg-runtime", from_port: 443, to_port: 443, ip_protocol: "tcp", cidr_ipv4: null, cidr_ipv6: null, prefix_list_id: null } } }] }, evidenceRef: "terraform-plan:rehearsal", evidenceSha256 }),
      applySavedPlan: async () => { mutations.push("M2_STAGE_A_APPLY"); },
      describeIngress: async () => ({ present: true }),
    },
  };
  const secretBindings = Object.fromEntries(["JWT_SECRET_CURRENT", "JWT_SECRET_PREVIOUS", "QR_SIGN_PRIVATE_KEY_CURRENT", "QR_SIGN_PUBLIC_KEY_CURRENT", "QR_SIGN_ACTIVE_KEY_VERSION", "QR_SIGN_PUBLIC_KEY_PREVIOUS", "QR_SIGN_PREVIOUS_KEY_VERSION", "ARTIFACT_SIGN_PRIVATE_KEY_CURRENT", "ARTIFACT_SIGN_PUBLIC_KEY_CURRENT", "ARTIFACT_SIGN_ACTIVE_KEY_VERSION", "ARTIFACT_SIGN_PUBLIC_KEYS_JSON"].map((name) => [name, `arn:aws:secretsmanager:eu-west-2:368992683803:secret:rehearsal-${name}`]));
  return {
    sourceSha, rotationId, rotationStateSha256,
    imageAuthorization: structuredClone(imageAuthorizationFixture.authorization),
    imageAuthorizationValidation: { now: imageAuthorizationFixture.now, verifyImageEvidence: imageAuthorizationFixture.verifyImageEvidence },
    iamReport: iamFixture(),
    identities: { rootDrop: { ...validEvidence("root:drop"), callerArn: "arn:aws:iam::368992683803:root" }, releaseDeployer: { ...validEvidence("sts:release"), callerArn: "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/rehearsal" }, verifier: { ...validEvidence("sts:verifier"), callerArn: "arn:aws:sts::368992683803:assumed-role/mscqr-production-ecs-exec-verifier/rehearsal" } },
    stageA,
    artifactSigning: artifactFixture(),
    overlapTask: { input: { backendImage: imageDigest, releaseSha: sourceSha, backendLogGroup: "/aws/ecs/rehearsal", secretBindings: { ...secretBindings, ROTATION_INVENTORY_RLS_ROLE: "mscqr_prod_rls_read" } }, register: async () => { mutations.push("M4_REGISTER_TASK_DEFINITION"); return { taskDefinition: { taskDefinitionArn } }; }, describe: async (arn) => ({ taskDefinitionArn: arn, family: "mscqr-production-rls-green-backend-candidate", status: "ACTIVE", tags: [{ key: "MSCQRExecTarget", value: "production-backend" }] }) },
    inventory: { taskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:47", execute: async () => ({ inventory, taskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:47", taskArn }) },
    rotationPrepare: { run: async () => { mutations.push("M5_ROTATION_STATE_PERSISTENCE"); return { valid: true, prepared: true, rotationId, rotationStateSha256, evidenceRef: "rotation:rehearsal", evidenceSha256, mutationCount: 1 }; } },
    deployOverlap: { run: async ({ taskDefinitionArn: arn }) => { mutations.push("M6_ECS_UPDATE_SERVICE"); return { updateServiceCount: 1, propagateTags: "TASK_DEFINITION", taskDefinitionArn: arn, mutationPayload: { cluster: "mscqr-prod-euw2-main", service: "mscqr-backend-servi-euw2", taskDefinition: arn, enableExecuteCommand: true, propagateTags: "TASK_DEFINITION" } }; } },
    postDeploy: { run: async () => ({ valid: true, taskArn, taskDefinitionArn, imageDigest: digest, taskTag: "MSCQRExecTarget=production-backend", evidenceRef: "deploy:rehearsal", evidenceSha256 }) },
    ecsExec: { run: async () => ({ valid: true, evidenceRef: "exec:rehearsal", evidenceSha256 }) },
    onboarding: { run: async (expected) => { const evidence = await runStrictOnboardingProbes({ probes: strictProbes, expected: { ...expected, taskDefinitionArn, taskArn, rotationId } }); return evidence; } },
    ...overrides,
    _mutations: mutations,
  };
}

const stageAPlan = ({ address = 'aws_vpc_security_group_ingress_rule.runtime_endpoints_https["sg-runtime"]', actions = ["create"], after = {}, extra = [] } = {}) => ({
  resource_changes: [{ address, change: { actions, after: { security_group_id: "sg-endpoint", referenced_security_group_id: "sg-runtime", from_port: 443, to_port: 443, ip_protocol: "tcp", cidr_ipv4: null, cidr_ipv6: null, prefix_list_id: null, ...after } } }, ...extra],
});

test("Stage A accepts only the reviewed indexed for_each instance", () => {
  const inputs = { endpointSecurityGroupId: "sg-endpoint", runtimeSecurityGroupId: "sg-runtime" };
  assert.equal(assertStageAPlan(stageAPlan(), inputs).valid, true);
  for (const plan of [
    stageAPlan({ address: "aws_vpc_security_group_ingress_rule.runtime_endpoints_https" }),
    stageAPlan({ address: 'aws_vpc_security_group_ingress_rule.runtime_endpoints_https["sg-endpoint"]' }),
    stageAPlan({ address: 'aws_vpc_security_group_ingress_rule.runtime_endpoints_https["sg-third"]' }),
    stageAPlan({ address: 'aws_security_group.runtime_endpoints_https["sg-endpoint"]' }),
    stageAPlan({ after: { security_group_id: "sg-other" } }),
    stageAPlan({ after: { referenced_security_group_id: "sg-other" } }),
    stageAPlan({ after: { from_port: 80 } }),
    stageAPlan({ after: { ip_protocol: "udp" } }),
    stageAPlan({ after: { cidr_ipv4: "10.0.0.0/8" } }),
    stageAPlan({ after: { cidr_ipv6: "::/0" } }),
    stageAPlan({ after: { prefix_list_id: "pl-unsupported" } }),
    stageAPlan({ actions: ["update"] }),
    stageAPlan({ actions: ["delete"] }),
    stageAPlan({ actions: ["create", "delete"] }),
    stageAPlan({ extra: [{ address: "aws_vpc_security_group.foo", change: { actions: ["create"], after: {} } }] }),
  ]) assert.throws(() => assertStageAPlan(plan, inputs));
});

test("Stage A rejects malformed unexpected entries before any apply", async () => {
  const inputs = { endpointSecurityGroupId: "sg-endpoint", runtimeSecurityGroupId: "sg-runtime" };
  const malformedEntries = [
    { address: "aws_vpc_security_group.foo", change: {} },
    { address: "aws_vpc_security_group.foo", change: { actions: [] } },
    { address: "aws_vpc_security_group.foo", change: { actions: null } },
    { address: "aws_vpc_security_group.foo", change: { actions: "no-op" } },
    { address: "aws_vpc_security_group.foo" },
    { address: "aws_vpc_security_group.foo", change: { actions: ["no-op", null] } },
  ];
  for (const entry of malformedEntries) {
    assert.throws(() => assertStageAPlan({ resource_changes: [stageAPlan().resource_changes[0], entry] }, inputs));
    let applyCalls = 0;
    await assert.rejects(() => runStageAControlPlane({
      adapter: {
        createSavedPlan: async () => ({ sourceSha: "a".repeat(40), savedPlanSha256: "b".repeat(64), evidenceRef: "terraform-plan:test", evidenceSha256: "b".repeat(64), plan: { resource_changes: [stageAPlan().resource_changes[0], entry] } }),
        applySavedPlan: async () => { applyCalls += 1; },
        describeIngress: async () => ({ present: true }),
      },
      ...inputs,
      sourceSha: "a".repeat(40),
    }));
    assert.equal(applyCalls, 0);
  }
});

test("Stage A applies exact create once and reads the postcondition", async () => {
  const inputs = { endpointSecurityGroupId: "sg-endpoint", runtimeSecurityGroupId: "sg-runtime" };
  const saved = { sourceSha: "a".repeat(40), savedPlanSha256: "b".repeat(64), evidenceRef: "terraform-plan:test", evidenceSha256: "b".repeat(64), plan: stageAPlan() };
  let applyCalls = 0;
  let postconditionReads = 0;
  const result = await runStageAControlPlane({
    adapter: {
      createSavedPlan: async () => saved,
      applySavedPlan: async () => { applyCalls += 1; },
      describeIngress: async () => { postconditionReads += 1; return { present: true }; },
    },
    ...inputs,
    sourceSha: saved.sourceSha,
  });
  assert.equal(result.alreadyConverged, false);
  assert.equal(result.appliedExactSavedPlan, true);
  assert.equal(result.mutationCount, 1);
  assert.equal(applyCalls, 1);
  assert.equal(postconditionReads, 1);
});

test("Stage A recognizes the exact indexed no-op as already converged", async () => {
  const inputs = { endpointSecurityGroupId: "sg-endpoint", runtimeSecurityGroupId: "sg-runtime" };
  const saved = { sourceSha: "a".repeat(40), savedPlanSha256: "b".repeat(64), evidenceRef: "terraform-plan:test", evidenceSha256: "b".repeat(64), plan: stageAPlan({ actions: ["no-op"] }) };
  let applyCalls = 0;
  const result = await runStageAControlPlane({
    adapter: {
      createSavedPlan: async () => saved,
      applySavedPlan: async () => { applyCalls += 1; },
      describeIngress: async () => ({ present: true }),
    },
    ...inputs,
    sourceSha: saved.sourceSha,
  });
  assert.equal(result.alreadyConverged, true);
  assert.equal(result.appliedExactSavedPlan, false);
  assert.equal(result.mutationCount, 0);
  assert.equal(applyCalls, 0);
});

test("Stage A postcondition reads exact SG-to-SG ingress from production-shaped AWS responses", () => {
  const inputs = { endpointSecurityGroupId: "sg-endpoint", runtimeSecurityGroupId: "sg-runtime" };
  const rule = (overrides = {}) => ({
    GroupId: "sg-endpoint", ReferencedGroupInfo: { GroupId: "sg-runtime" }, IsEgress: false,
    IpProtocol: "tcp", FromPort: 443, ToPort: 443, ...overrides,
  });
  const calls = [];
  const read = (rules) => describeStageAIngress({ run: (args) => { calls.push(args); return JSON.stringify({ SecurityGroupRules: rules }); }, ...inputs });
  assert.deepEqual(read([rule()]), { present: true });
  assert.equal(calls[0].some((arg) => String(arg).includes("referenced-group-id")), false);
  for (const rules of [
    [rule({ ReferencedGroupInfo: { GroupId: "sg-other" } })],
    [rule({ ReferencedGroupInfo: undefined })],
    [rule({ GroupId: "sg-other" })],
    [rule({ IsEgress: true })],
    [rule({ IpProtocol: "udp" })],
    [rule({ FromPort: 80 })],
    [rule({ ToPort: 80 })],
    [{ GroupId: "sg-endpoint", CidrIpv4: "10.0.0.0/8", IsEgress: false, IpProtocol: "tcp", FromPort: 443, ToPort: 443 }],
    [{ GroupId: "sg-endpoint", PrefixListId: "pl-unsupported", IsEgress: false, IpProtocol: "tcp", FromPort: 443, ToPort: 443 }],
  ]) assert.deepEqual(read(rules), { present: false });
});

test("the real cutover orchestrator reaches synthetic onboarding with ordered mutation intents", async () => {
  const input = fixtureInput();
  const result = await runProductionCutoverControlPlane(input);
  assert.equal(result.readyForOnboarding, true);
  assert.deepEqual(result.mutationSequence.map(({ name }) => name), ["M2_STAGE_A_APPLY", "M3_ARTIFACT_SECRET_PROVISION", "M5_ROTATION_STATE_PERSISTENCE", "M4_REGISTER_TASK_DEFINITION", "M6_ECS_UPDATE_SERVICE"]);
  assert.equal(result.transitionMatrix.every((edge) => edge.result === "PASS"), true);
});

test("the real predeployment adapter feeds the same cutover spine before deployment", async () => {
  const input = fixtureInput();
  const order = [];
  let registeredDefinition;
  const preAdapter = createProductionPreDeploymentInventoryAdapter({
    sourceSha,
    imageDigest: imageDigest,
    config: { inventoryApprovalId: "APR-STAGE-B-0001", rotationInventoryRlsRole: "mscqr_prod_rls_read", inventoryLogGroupName: "/ecs/mscqr-production/rls-green-backend", overlapTaskInput: { backendLogGroup: "/ecs/mscqr-production/rls-green-backend", secretBindings: { ROTATION_INVENTORY_RLS_ROLE: "mscqr_prod_rls_read" } } },
    run: (args) => {
      if (args[0] === "ecs" && args[1] === "register-task-definition") {
        const payload = JSON.parse(args[3]);
        const { tags, ...definition } = payload;
        registeredDefinition = definition;
        return JSON.stringify({ taskDefinition: { ...definition, taskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-predeployment-inventory:22" }, tags });
      }
      if (args[0] === "ecs" && args[1] === "describe-task-definition") return JSON.stringify({ taskDefinition: { ...registeredDefinition, taskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-predeployment-inventory:22", status: "ACTIVE" } });
      if (args[0] === "lambda" && args[1] === "invoke") {
        writeFileSync(args.at(-4), JSON.stringify({ status: "completed", sourceSha, rotationId, taskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-predeployment-inventory:22", taskArn: "arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/inventory-22", inventory }));
        return JSON.stringify({ StatusCode: 200 });
      }
      throw new Error(`unexpected predeployment command: ${args.join(" ")}`);
    },
  });
  input.preDeploymentInventory = { execute: async ({ rotationId: currentRotationId }) => { order.push("PREDEPLOY_INVENTORY"); return preAdapter.run({ rotationId: currentRotationId }); } };
  const originalRotation = input.rotationPrepare.run;
  input.rotationPrepare.run = async (...args) => { order.push("ROTATION_PREPARE"); return originalRotation(...args); };
  const originalRegister = input.overlapTask.register;
  input.overlapTask.register = async (...args) => { order.push("TASK_REGISTER"); return originalRegister(...args); };
  const originalDeploy = input.deployOverlap.run;
  input.deployOverlap.run = async (...args) => { order.push("UPDATE_SERVICE"); return originalDeploy(...args); };
  const originalPostDeploy = input.postDeploy.run;
  input.postDeploy.run = async (...args) => { order.push("STABILIZATION", "POSTDEPLOY"); return originalPostDeploy(...args); };
  const originalExec = input.ecsExec.run;
  input.ecsExec.run = async (...args) => { order.push("ECS_EXEC"); return originalExec(...args); };
  const originalOnboarding = input.onboarding.run;
  input.onboarding.run = async (...args) => { order.push("ONBOARDING"); return originalOnboarding(...args); };
  const result = await runProductionCutoverControlPlane(input);
  order.push("ROTATION_CLOSE");
  assert.deepEqual(order, ["PREDEPLOY_INVENTORY", "ROTATION_PREPARE", "TASK_REGISTER", "UPDATE_SERVICE", "STABILIZATION", "POSTDEPLOY", "ECS_EXEC", "ONBOARDING", "ROTATION_CLOSE"]);
  assert.equal(result.readyForOnboarding, true);
  assert.equal(result.mutationSequence.filter(({ name }) => name === "M6_ECS_UPDATE_SERVICE").length, 1);
});

test("bootstrap ARNs replace stale overlap bindings on the real control-plane path", async () => {
  const input = fixtureInput();
  const pair = generateKeyPairSync("ed25519", { privateKeyEncoding: { format: "pem", type: "pkcs8" }, publicKeyEncoding: { format: "pem", type: "spki" } });
  const runtimeBindings = Object.fromEntries(["ARTIFACT_SIGN_PRIVATE_KEY_CURRENT", "ARTIFACT_SIGN_PUBLIC_KEY_CURRENT", "ARTIFACT_SIGN_ACTIVE_KEY_VERSION", "ARTIFACT_SIGN_PUBLIC_KEYS_JSON"].map((name, index) => [name, `arn:aws:secretsmanager:eu-west-2:368992683803:secret:generated-runtime-${index}-Unique` ]));
  const values = {
    [runtimeBindings.ARTIFACT_SIGN_PRIVATE_KEY_CURRENT]: pair.privateKey,
    [runtimeBindings.ARTIFACT_SIGN_PUBLIC_KEY_CURRENT]: pair.publicKey,
    [runtimeBindings.ARTIFACT_SIGN_ACTIVE_KEY_VERSION]: "v1",
    [runtimeBindings.ARTIFACT_SIGN_PUBLIC_KEYS_JSON]: JSON.stringify({ v1: pair.publicKey }),
  };
  const artifact = {
    bindings: runtimeBindings,
    bootstrap: async () => ({ valid: true, bindings: runtimeBindings, created: [], createSecretCount: 0 }),
    provision: async () => ({ mutationCount: 0 }),
    readSecret: async (ref) => values[ref],
    evidenceRef: "artifact:runtime-bootstrap",
  };
  input.artifactSigning = artifact;
  let registeredPayload;
  const originalRegister = input.overlapTask.register;
  input.overlapTask.register = async (payload) => {
    registeredPayload = payload;
    return originalRegister(payload);
  };
  const result = await runProductionCutoverControlPlane(input);
  const registeredSecrets = Object.fromEntries(registeredPayload.taskDefinition.containerDefinitions.find(({ name }) => name === "backend").secrets.map(({ name, valueFrom }) => [name, valueFrom]));
  for (const name of Object.keys(runtimeBindings)) assert.equal(registeredSecrets[name], runtimeBindings[name]);
  assert.equal(registeredPayload.taskDefinition.containerDefinitions.find(({ name }) => name === "backend").image, imageDigest);
  assert.equal(registeredPayload.taskDefinition.containerDefinitions.find(({ name }) => name === "backend").environment.find(({ name }) => name === "RELEASE_GIT_SHA").value, sourceSha);
  assert.equal(result.results.overlapTaskDefinition.valid, true);
});

test("a bootstrap result that disagrees with the artifact adapter fails before registration", async () => {
  const input = fixtureInput();
  const runtimeBindings = Object.fromEntries(["ARTIFACT_SIGN_PRIVATE_KEY_CURRENT", "ARTIFACT_SIGN_PUBLIC_KEY_CURRENT", "ARTIFACT_SIGN_ACTIVE_KEY_VERSION", "ARTIFACT_SIGN_PUBLIC_KEYS_JSON"].map((name, index) => [name, `arn:aws:secretsmanager:eu-west-2:368992683803:secret:wrong-runtime-${index}-Unique` ]));
  input.artifactSigning.bootstrap = async () => ({ valid: true, bindings: runtimeBindings, created: [], createSecretCount: 0 });
  await assert.rejects(() => runProductionCutoverControlPlane(input), /Overlap task artifact binding diverges/);
  assert.equal(input._mutations.some((name) => name === "M4_REGISTER_TASK_DEFINITION"), false);
});

test("rotation preparation hash is the only deployment authorization hash", async () => {
  let deployedHash;
  const input = fixtureInput({ deployOverlap: { run: async ({ taskDefinitionArn: arn, rotationStateSha256: hash }) => {
    deployedHash = hash;
    return { updateServiceCount: 1, propagateTags: "TASK_DEFINITION", taskDefinitionArn: arn, mutationPayload: { rotationStateSha256: hash } };
  } } });
  const result = await runProductionCutoverControlPlane(input);
  assert.equal(deployedHash, rotationStateSha256);
  let called = false;
  await assert.rejects(() => runGovernedOverlapDeployment({ readiness: result.readiness, sourceSha, rotationId, rotationStateSha256: "f".repeat(64), taskDefinitionArn, deployOverlap: { run: async () => { called = true; } } }), /rotationStateSha256/i);
  assert.equal(called, false);
});

test("invalid predecessor stops before the next mutation boundary", async () => {
  const input = fixtureInput({ imageAuthorization: { ...validEvidence("images:bad"), sourceSha: "f".repeat(40), imageReleaseSha: "e".repeat(40), workflowRunId: "31509287814", imageReuseCompatible: true, imageBuildInputsChanged: false, images: ["backend", "worker", "rls-executor", "rls-canary"].map((service) => ({ service, digest })), signatureVerified: true, attestationVerified: true, provenanceVerified: true } });
  await assert.rejects(() => runProductionCutoverControlPlane(input), /canonical image authorization|image evidence/i);
  assert.deepEqual(input._mutations, []);
});

test("transition matrix rejects field, SHA, identity, and ARN handoff corruption", async () => {
  const result = await runProductionCutoverControlPlane(fixtureInput());
  for (const corrupt of [
    (results) => { results.stageA.evidenceSha256 = "not-a-sha"; },
    (results) => { results.artifactSigning.sourceSha = "b".repeat(40); },
    (results) => { results.registrationReadback = { ...results.registrationReadback, taskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/wrong:1" }; },
    (results) => { delete results.onboardingEvidence.evidenceSha256; },
  ]) {
    const results = structuredClone(result.results);
    corrupt(results);
    assert.throws(() => assertTransitionMatrix(buildTransitionMatrix(results)), /failed edge/);
  }
});

test("strict onboarding has no skip path", async () => {
  const probes = Object.fromEntries(STRICT_ONBOARDING_CHECKS.map((name) => [name, async () => true]));
  delete probes.rbac;
  await assert.rejects(() => runStrictOnboardingProbes({ probes, expected: { sourceSha, imageDigest: digest, taskDefinitionArn, taskArn, rotationId } }), /unavailable/);
});

test("onboarding evidence fingerprint contains only non-secret metadata", async () => {
  const probes = Object.fromEntries(STRICT_ONBOARDING_CHECKS.map((name) => [name, async () => true]));
  const evidence = await runStrictOnboardingProbes({ probes, expected: { sourceSha, imageDigest: digest, taskDefinitionArn, taskArn, rotationId } });
  const fingerprint = buildOnboardingEvidenceFingerprint(evidence);
  assert.deepEqual(Object.keys(fingerprint).sort(), ["checks", "imageDigest", "rotationId", "rotationPhase", "sourceSha", "taskArn", "taskDefinitionArn"].sort());
  assert.doesNotMatch(JSON.stringify(fingerprint), /password|database_url|private.?key|secret|bearer|qr.?payload/i);
});

const failCases = [
  ["wrong-protected-main-sha", (i) => { i.imageAuthorization.sourceSha = "f".repeat(40); }],
  ["wrong-image-sha", (i) => { i.imageAuthorization.sourceSha = "f".repeat(40); }],
  ["wrong-image-digest", (i) => { i.imageAuthorization.backendDigest = `sha256:${"e".repeat(64)}`; }],
  ["invalid-signature", (i) => { i.imageAuthorization.signatureVerified = false; }],
  ["invalid-attestation", (i) => { i.imageAuthorization.attestationVerified = false; }],
  ["invalid-provenance", (i) => { i.imageAuthorization.provenanceVerified = false; }],
  ["iam-incomplete-census", (i) => { i.iamReport.iamEvaluationCensus.executed -= 1; }],
  ["iam-evaluation-failure", (i) => { i.iamReport.status = "invalid"; }],
  ["release-identity-mismatch", (i) => { i.identities.releaseDeployer.valid = false; }],
  ["verifier-identity-mismatch", (i) => { i.identities.verifier.valid = false; }],
  ["mfa-absent", (i) => { i.iamReport.ecsExecVerifierTrust.mfaRequired = false; }],
  ["mfa-malformed", (i) => { i.identities.verifier.callerArn = "arn:aws:iam::368992683803:user/wrong"; }],
  ["stage-a-unexpected-plan", (i) => { i.stageA.adapter.createSavedPlan = async () => ({ plan: { resource_changes: [] }, evidenceRef: "bad", evidenceSha256 }); }],
  ["saved-plan-bytes-changed", (i) => { i.stageA.adapter.applySavedPlan = async () => { throw new Error("saved plan changed"); }; }],
  ["stage-a-postcondition-missing", (i) => { i.stageA.adapter.describeIngress = async () => ({ present: false }); }],
  ["artifact-partial-domain", (i) => { i.artifactSigning.readSecret = async () => ""; }],
  ["artifact-mismatched-ed25519-pair", (i) => { i.artifactSigning.readSecret = async (ref) => ref.includes("PRIVATE") ? "not-a-key" : ""; }],
  ["artifact-wrong-active-version", (i) => { const read = i.artifactSigning.readSecret; i.artifactSigning.readSecret = async (ref) => ref.includes("ACTIVE") ? "bad version!" : read(ref); }],
  ["artifact-registry-mismatch", (i) => { const read = i.artifactSigning.readSecret; i.artifactSigning.readSecret = async (ref) => ref.includes("PUBLIC_KEYS") ? "{}" : read(ref); }],
  ["artifact-unapproved-secret", (i) => { i.artifactSigning.bindings.ARTIFACT_SIGN_PRIVATE_KEY_CURRENT = "*"; }],
  ["artifact-evidence-leak", (i) => { i.artifactSigning.evidenceRef = "secret=leak"; }],
  ["td-wrong-family", (i) => { i.overlapTask.input.secretBindings.ROTATION_INVENTORY_RLS_ROLE = "bad role"; }],
  ["td-wrong-digest", (i) => { i.overlapTask.input.backendImage = "bad"; }],
  ["td-wrong-role", (i) => { i.overlapTask.input.secretBindings.BAD_ROLE = "x"; }],
  ["td-wrong-secret-ref", (i) => { i.overlapTask.input.secretBindings.JWT_SECRET_CURRENT = "not-an-arn"; }],
  ["td-missing-execution-marker", (i) => { i.overlapTask.input.secretBindings.ROTATION_INVENTORY_RLS_ROLE = ""; }],
  ["td-payload-hash-mismatch", (i) => { i.overlapTask.register = async () => ({ taskDefinition: { taskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/wrong:1" } }); }],
  ["registration-readback-mismatch", (i) => { i.overlapTask.describe = async () => ({ taskDefinitionArn: "wrong", family: "wrong", status: "ACTIVE" }); }],
  ["inventory-missing-category", (i) => { i.inventory.execute = async () => ({ refreshSessions: { count: 0 } }); }],
  ["inventory-unknown-category", (i) => { i.inventory.execute = async () => ({ ...inventory, unknown: { count: 0 } }); }],
  ["inventory-sensitive-field", (i) => { i.inventory.execute = async () => ({ ...inventory, refreshSessions: { count: 0, token: "x" } }); }],
  ["inventory-malformed-count", (i) => { i.inventory.execute = async () => ({ ...inventory, refreshSessions: { count: "0" } }); }],
  ["rotation-persistence-mismatch", (i) => { i.rotationPrepare.run = async () => ({ valid: true, prepared: true, rotationId: "wrong", rotationStateSha256, evidenceRef: "bad", evidenceSha256 }); }],
  ["readiness-evidence-hash-mismatch", (i) => { i.readiness = { produce: async () => ({}) }; }],
  ["readiness-identity-mismatch", (i) => { i.rotationPrepare.run = async () => ({ valid: true, prepared: true, rotationId, rotationStateSha256: "f".repeat(64), evidenceRef: "bad", evidenceSha256 }); }],
  ["deployment-wrong-task-definition", (i) => { i.deployOverlap.run = async () => ({ updateServiceCount: 1, propagateTags: "TASK_DEFINITION", taskDefinitionArn: "wrong" }); }],
  ["deployment-missing-propagate-tags", (i) => { i.deployOverlap.run = async ({ taskDefinitionArn: arn }) => ({ updateServiceCount: 1, taskDefinitionArn: arn }); }],
  ["deployment-extra-update-service", (i) => { i.deployOverlap.run = async ({ taskDefinitionArn: arn }) => ({ updateServiceCount: 2, propagateTags: "TASK_DEFINITION", taskDefinitionArn: arn }); }],
  ["replacement-task-wrong-definition", (i) => { i.postDeploy.run = async () => ({ valid: true, taskArn, taskDefinitionArn: "wrong", imageDigest: digest, taskTag: "MSCQRExecTarget=production-backend", evidenceRef: "bad", evidenceSha256 }); }],
  ["replacement-task-wrong-digest", (i) => { i.postDeploy.run = async () => ({ valid: true, taskArn, taskDefinitionArn, imageDigest: `sha256:${"e".repeat(64)}`, taskTag: "MSCQRExecTarget=production-backend", evidenceRef: "bad", evidenceSha256 }); }],
  ["replacement-task-missing-marker", (i) => { i.postDeploy.run = async () => ({ valid: true, taskArn, taskDefinitionArn, imageDigest: digest, taskTag: "", evidenceRef: "bad", evidenceSha256 }); }],
  ["ecs-exec-revalidation-different-arn", (i) => { i.ecsExec.run = async () => { throw new Error("selected ARN changed"); }; }],
  ["ecs-exec-revalidation-different-td", (i) => { i.ecsExec.run = async () => { throw new Error("task definition changed"); }; }],
  ["ecs-exec-revalidation-different-digest", (i) => { i.ecsExec.run = async () => { throw new Error("digest changed"); }; }],
  ["ecs-exec-missing-marker", (i) => { i.ecsExec.run = async () => { throw new Error("marker changed"); }; }],
  ["ecs-exec-wrong-container", (i) => { i.ecsExec.run = async () => { throw new Error("container changed"); }; }],
  ["onboarding-mandatory-skipped", (i) => { i.onboarding.run = async () => { throw new Error("mandatory check skipped"); }; }],
  ["onboarding-mandatory-unavailable", (i) => { i.onboarding.run = async () => { throw new Error("mandatory check unavailable"); }; }],
  ["onboarding-mandatory-failed", (i) => { i.onboarding.run = async () => { throw new Error("mandatory check failed"); }; }],
  ["onboarding-wrong-source-sha", (i) => { i.onboarding.run = async () => { throw new Error("source SHA mismatch"); }; }],
  ["onboarding-wrong-digest", (i) => { i.onboarding.run = async () => { throw new Error("digest mismatch"); }; }],
  ["onboarding-evidence-leak", (i) => { i.onboarding.run = async () => { throw new Error("evidence leak"); }; }],
];

test("every cutover failure injection fails closed", async () => {
  let unexpectedPasses = 0;
  const failureResults = [];
  const mutationOrder = ["M2_STAGE_A_APPLY", "M3_ARTIFACT_SECRET_PROVISION", "M4_REGISTER_TASK_DEFINITION", "M5_ROTATION_STATE_PERSISTENCE", "M6_ECS_UPDATE_SERVICE"];
  const boundaryFor = (id) => id.startsWith("stage-a") || id === "saved-plan-bytes-changed" ? "stageA" : id.startsWith("artifact-") ? "artifactSigning" : id.startsWith("td-") || id === "registration-readback-mismatch" ? "taskDefinition" : id.startsWith("inventory-") ? "inventory" : id.startsWith("rotation-") ? "rotationPrepare" : id.startsWith("readiness-") ? "readiness" : id.startsWith("deployment-") ? "deployment" : id.startsWith("replacement-") ? "postDeploy" : id.startsWith("ecs-exec-") ? "ecsExec" : id.startsWith("onboarding-") ? "onboarding" : id.startsWith("iam-") ? "iam" : "identity";
  const maxMutation = { identity: -1, iam: -1, stageA: 0, artifactSigning: 0, taskDefinition: 3, inventory: 2, rotationPrepare: 2, readiness: 3, deployment: 3, postDeploy: 4, ecsExec: 4, onboarding: 4 };
  for (const [id, inject] of failCases) {
    const input = fixtureInput();
    inject(input);
    const boundary = boundaryFor(id);
    try {
      await runProductionCutoverControlPlane(input);
      unexpectedPasses += 1;
      failureResults.push({ injectionId: id, boundary, expectedFailureStage: boundary, actualFailureStage: "READY_FOR_ONBOARDING", nextMutationAttempted: input._mutations, result: "UNEXPECTED_PASS" });
    } catch (error) {
      assert.ok(error instanceof Error, id);
      const attempted = input._mutations.filter((name) => mutationOrder.indexOf(name) > maxMutation[boundary]);
      failureResults.push({ injectionId: id, boundary, expectedFailureStage: boundary, actualFailureStage: boundary, nextMutationAttempted: attempted, result: "EXPECTED_FAILURE" });
      assert.deepEqual(attempted, [], `${id} crossed its mutation boundary`);
    }
  }
  assert.equal(unexpectedPasses, 0);
  assert.equal(failCases.length, 52);
  assert.equal(failureResults.length, failCases.length);
  assert.equal(failureResults.filter(({ result }) => result !== "EXPECTED_FAILURE").length, 0);
});
