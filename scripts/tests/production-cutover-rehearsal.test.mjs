import assert from "node:assert/strict";
import test from "node:test";
import { createHash, generateKeyPairSync } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { assertStageAPlan, createTerraformStageAAdapter, runStageAControlPlane, STAGE_A_CHECKER_POLICY, STAGE_A_CHECKER_PUBLICATION_POLICY, STAGE_A_CHECKER_ROLE_TRUST } from "../aws/production-stage-a-control-plane.mjs";
import { describeStageAIngress } from "../aws/production-cutover-production-adapters.mjs";
import { assertTransitionMatrix, buildTransitionMatrix, runGovernedOverlapDeployment, runProductionCutoverControlPlane } from "../aws/production-cutover-control-plane.mjs";
import { ECS_EXEC_OPERATOR_REQUIRED, ECS_EXEC_OPERATOR_FORBIDDEN, buildEcsExecOperatorEvidence, ECS_EXEC_OPERATOR_ROLE_ARN } from "../aws/production-ecs-exec-operator-contract.mjs";
import { buildOnboardingEvidenceFingerprint, runStrictOnboardingProbes, STRICT_ONBOARDING_CHECKS } from "../security/production-strict-onboarding.mjs";
import { ROTATION_INVENTORY_CATEGORIES } from "../security/production-runtime-rotation-inventory.mjs";
import { createProductionPreDeploymentInventoryAdapter } from "../aws/production-predeployment-inventory-adapter.mjs";
import { makeCanonicalImageAuthorization } from "./fixtures/canonical-image-authorization.mjs";
import { CHECKER_SOURCE_ROLE_ARN, CHECKER_TARGET_ROLE_ARN, CHECKER_USER_ARN } from "../aws/production-checker-chain-contract.mjs";
import { stageBApprovalIdForReleaseSha } from "../aws/production-green-stage-b-contract.mjs";
import { buildRootDropEvidence, buildRootDropPayload } from "../aws/production-root-drop-evidence.mjs";
import { buildTemporaryCapabilityEvidence } from "../aws/production-stage-a-temporary-kms-capability.mjs";

export const sourceSha = "96a4be6f0edcd626285c6a1bd8062a4008175d25";
const digest = "sha256:5c03df843e46dd0853762108c7ae780a4d06b7e11cac585d9d2b2cd3d196f6ad";
const imageDigest = `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@${digest}`;
const rotationId = "rotation-rehearsal-1";
const rotationStateSha256 = "c".repeat(64);
const rotationFixtureSha256 = "e".repeat(64);
const evidenceSha256 = "d".repeat(64);
const validEvidence = (ref) => ({ valid: true, evidenceRef: ref, evidenceSha256 });
const checkerPolicyDocument = ({ action = STAGE_A_CHECKER_POLICY.action, resource = STAGE_A_CHECKER_POLICY.resource, extraStatements = [] } = {}) => JSON.stringify({
  Version: "2012-10-17",
  Statement: [{ Sid: STAGE_A_CHECKER_POLICY.sid, Effect: "Allow", Action: action, Resource: resource }, ...extraStatements],
});
const checkerPolicyChange = (actions = ["create"], after = {}) => ({
  address: STAGE_A_CHECKER_POLICY.address,
  type: STAGE_A_CHECKER_POLICY.type,
  change: {
    actions,
    after: { role: STAGE_A_CHECKER_POLICY.role, name: STAGE_A_CHECKER_POLICY.name, policy: checkerPolicyDocument(), ...after },
  },
});
const checkerPublicationPolicy = ({ predecessor = false, extraStatement = false, kmsAction = STAGE_A_CHECKER_PUBLICATION_POLICY.kmsAction, publishResource = STAGE_A_CHECKER_PUBLICATION_POLICY.publishResource, publishAction = STAGE_A_CHECKER_PUBLICATION_POLICY.publishAction, condition = undefined } = {}) => {
  if (predecessor) return { Version: "2012-10-17", Statement: [{ Action: [...STAGE_A_CHECKER_PUBLICATION_POLICY.kmsAction], Effect: "Allow", Resource: STAGE_A_CHECKER_PUBLICATION_POLICY.kmsResource }] };
  const statements = [{ Sid: "SignExactStageBApproval", Effect: "Allow", Action: [...kmsAction], Resource: STAGE_A_CHECKER_PUBLICATION_POLICY.kmsResource }, { Sid: "PublishExactStageBApproval", Effect: "Allow", Action: publishAction, Resource: publishResource, ...(condition ? { Condition: condition } : {}) }];
  if (extraStatement) statements.push({ Sid: "Unexpected", Effect: "Allow", Action: "secretsmanager:DeleteSecret", Resource: STAGE_A_CHECKER_PUBLICATION_POLICY.publishResource });
  return { Version: "2012-10-17", Statement: statements };
};
const checkerPublicationChange = ({ actions = ["no-op"], beforePolicy = checkerPublicationPolicy(), beforePolicyBytes, afterPolicy = checkerPublicationPolicy(), before = {}, after = {}, replacePaths } = {}) => ({
  address: STAGE_A_CHECKER_PUBLICATION_POLICY.address,
  type: STAGE_A_CHECKER_PUBLICATION_POLICY.type,
  change: { actions, before: { role: STAGE_A_CHECKER_PUBLICATION_POLICY.role, name: STAGE_A_CHECKER_PUBLICATION_POLICY.name, policy: beforePolicyBytes ?? JSON.stringify(beforePolicy), ...before }, after: { role: STAGE_A_CHECKER_PUBLICATION_POLICY.role, name: STAGE_A_CHECKER_PUBLICATION_POLICY.name, policy: JSON.stringify(afterPolicy), ...after }, ...(replacePaths ? { replace_paths: replacePaths } : {}) },
});
const checkerRoleTrustDocument = ({ condition } = {}) => JSON.stringify({
  Version: "2012-10-17",
  Statement: [{ Effect: "Allow", Principal: { AWS: STAGE_A_CHECKER_ROLE_TRUST.principal }, Action: STAGE_A_CHECKER_ROLE_TRUST.action, ...(condition ? { Condition: condition } : {}) }],
});
const checkerRoleChange = ({ actions = ["no-op"], before = {}, after = {} } = {}) => ({
  address: STAGE_A_CHECKER_ROLE_TRUST.address,
  type: STAGE_A_CHECKER_ROLE_TRUST.type,
  change: {
    actions,
    before: { name: STAGE_A_CHECKER_ROLE_TRUST.name, assume_role_policy: checkerRoleTrustDocument({ condition: actions[0] === "update" ? { Bool: { "aws:MultiFactorAuthPresent": "true" } } : undefined }), ...before },
    after: { name: STAGE_A_CHECKER_ROLE_TRUST.name, assume_role_policy: checkerRoleTrustDocument(), ...after },
  },
});

function iamFixture() {
  const required = [
    { manifestId: "apply-stage-a-endpoint-security-group-ingress", action: "ec2:AuthorizeSecurityGroupIngress", resource: "arn:aws:ec2:eu-west-2:368992683803:security-group/endpoint", decision: "allowed" },
    { manifestId: "apply-stage-a-checker-role-chain-policy", action: "iam:PutRolePolicy", resource: "arn:aws:iam::368992683803:role/mscqr-production-independent-checker", decision: "allowed" },
    { manifestId: "apply-stage-a-checker-publication-policy", action: "iam:PutRolePolicy", resource: "arn:aws:iam::368992683803:role/mscqr-production-rls-independent-checker", decision: "allowed" },
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
    checkerTrust: { exact: true, mfaRequired: true, principal: CHECKER_USER_ARN, roleArn: CHECKER_SOURCE_ROLE_ARN },
    temporaryKmsCapability: buildTemporaryCapabilityEvidence({ state: "ABSENCE_VERIFIED", sourceSha, transitionId: "rehearsal-transition", defaultVersionId: "v1", observedAt: "2026-08-18T12:00:00.000Z" }),
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

export function fixtureInput(overrides = {}) {
  const mutations = [];
  const imageAuthorizationFixture = makeCanonicalImageAuthorization({ sourceSha });
  const strictProbes = Object.fromEntries(STRICT_ONBOARDING_CHECKS.map((name) => [name, async () => true]));
  const stageA = {
    endpointSecurityGroupId: "sg-endpoint",
    runtimeSecurityGroupId: "sg-runtime",
    adapter: {
      createSavedPlan: async () => ({ sourceSha, savedPlanSha256: "e".repeat(64), plan: { resource_changes: [{ address: 'aws_vpc_security_group_ingress_rule.runtime_endpoints_https["sg-runtime"]', change: { actions: ["create"], after: { security_group_id: "sg-endpoint", referenced_security_group_id: "sg-runtime", from_port: 443, to_port: 443, ip_protocol: "tcp", cidr_ipv4: null, cidr_ipv6: null, prefix_list_id: null } } }, checkerPolicyChange(), checkerRoleChange(), checkerPublicationChange()] }, evidenceRef: "terraform-plan:rehearsal", evidenceSha256 }),
      applySavedPlan: async () => { mutations.push("M2_STAGE_A_APPLY"); },
      describeIngress: async () => ({ present: true, endpointSecurityGroupId: "sg-endpoint", runtimeSecurityGroupId: "sg-runtime", direction: "ingress", protocol: "tcp", fromPort: 443, toPort: 443 }),
    },
  };
  const ecsJsonKeyBindings = new Set(["JWT_SECRET_PREVIOUS", "QR_SIGN_ACTIVE_KEY_VERSION", "QR_SIGN_PUBLIC_KEY_PREVIOUS", "QR_SIGN_PREVIOUS_KEY_VERSION"]);
  const secretBindings = Object.fromEntries(["JWT_SECRET_CURRENT", "JWT_SECRET_PREVIOUS", "QR_SIGN_PRIVATE_KEY_CURRENT", "QR_SIGN_PUBLIC_KEY_CURRENT", "QR_SIGN_ACTIVE_KEY_VERSION", "QR_SIGN_PUBLIC_KEY_PREVIOUS", "QR_SIGN_PREVIOUS_KEY_VERSION", "ARTIFACT_SIGN_PRIVATE_KEY_CURRENT", "ARTIFACT_SIGN_PUBLIC_KEY_CURRENT", "ARTIFACT_SIGN_ACTIVE_KEY_VERSION", "ARTIFACT_SIGN_PUBLIC_KEYS_JSON"].map((name) => {
    const base = `arn:aws:secretsmanager:eu-west-2:368992683803:secret:rehearsal-${name}`;
    return [name, ecsJsonKeyBindings.has(name) ? `${base}:value::` : base];
  }));
  return {
    sourceSha, rotationId, rotationStateSha256, rotationFixtureSha256,
    imageAuthorization: structuredClone(imageAuthorizationFixture.authorization),
    imageAuthorizationValidation: { now: imageAuthorizationFixture.now, verifyImageEvidence: imageAuthorizationFixture.verifyImageEvidence },
    iamReport: iamFixture(),
    checkerChain: {
      verifySourceTrust: async () => ({ exact: true, mfaRequired: true, principal: CHECKER_USER_ARN, roleArn: CHECKER_SOURCE_ROLE_ARN }),
      verifyComplete: async () => ({ valid: true, sourceTrust: { exact: true, mfaRequired: true, principal: CHECKER_USER_ARN, roleArn: CHECKER_SOURCE_ROLE_ARN }, sourcePermission: { exact: true, action: "sts:AssumeRole", resource: CHECKER_TARGET_ROLE_ARN }, targetTrust: { exact: true, secondHopMfaRequired: false, principal: CHECKER_SOURCE_ROLE_ARN, roleArn: CHECKER_TARGET_ROLE_ARN }, checkerUserExact: true, firstHopMfaRequired: true, roleAAssumeTargetPermissionExact: true, roleBTrustExactRoleA: true, roleBSecondHopMfaRequired: false }),
    },
    identities: { rootDrop: buildRootDropEvidence({ payload: buildRootDropPayload({ sourceSha, callerArn: "arn:aws:iam::368992683803:root", now: new Date().toISOString(), nonce: "rehearsal-root-with-enough-entropy" }), signatureBase64: "c2lnbmF0dXJl" }), releaseDeployer: { ...validEvidence("sts:release"), callerArn: "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/rehearsal" }, verifier: { ...validEvidence("sts:verifier"), callerArn: "arn:aws:sts::368992683803:assumed-role/mscqr-production-ecs-exec-verifier/rehearsal" } },
    verifyRootDropSignature: () => true,
    stageA,
    artifactSigning: artifactFixture(),
    overlapTask: { input: { backendImage: imageDigest, releaseSha: sourceSha, backendLogGroup: "/aws/ecs/rehearsal", secretBindings: { ...secretBindings, ROTATION_INVENTORY_RLS_ROLE: "mscqr_prod_rls_read" } }, register: async () => { mutations.push("M4_REGISTER_TASK_DEFINITION"); return { taskDefinition: { taskDefinitionArn } }; }, describe: async (arn) => ({ taskDefinitionArn: arn, family: "mscqr-production-rls-green-backend-candidate", status: "ACTIVE", tags: [{ key: "MSCQRExecTarget", value: "production-backend" }] }) },
    inventory: { taskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:47", execute: async () => ({ inventory, taskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:47", taskArn }) },
    rotationPrepare: { run: async () => { mutations.push("M5_ROTATION_STATE_PERSISTENCE"); return { valid: true, prepared: true, rotationId, rotationStateSha256, rotationFixtureSha256, evidenceRef: "rotation:rehearsal", evidenceSha256, mutationCount: 1 }; } },
    rotationInfrastructure: { run: async ({ sourceSha: currentSourceSha, rotationId: currentRotationId, secretBindings }) => { mutations.push("M5_ROTATION_INFRA_CONVERGENCE"); const overlapSecretSet = Object.values(secretBindings).filter((value) => typeof value === "string" && value.startsWith("arn:aws:secretsmanager:")).map((value) => value.replace(/:value::$/, "")); return { valid: true, converged: true, rotationEnabled: true, sourceSha: currentSourceSha, rotationId: currentRotationId, applyCount: 1, overlapSecretSet, authorizedOverlapSecretSet: overlapSecretSet, unrelatedSecretAccess: false, evidenceRef: "terraform:rotation-infrastructure", evidenceSha256, mutationCount: 1 }; } },
    deployOverlap: { run: async ({ taskDefinitionArn: arn }) => { mutations.push("M6_ECS_UPDATE_SERVICE"); return { updateServiceCount: 1, propagateTags: "TASK_DEFINITION", taskDefinitionArn: arn, mutationPayload: { cluster: "mscqr-prod-euw2-main", service: "mscqr-backend-servi-euw2", taskDefinition: arn, enableExecuteCommand: true, propagateTags: "TASK_DEFINITION" } }; } },
    postDeploy: { run: async () => ({ valid: true, taskArn, taskDefinitionArn, imageDigest: digest, taskTag: "MSCQRExecTarget=production-backend", evidenceRef: "deploy:rehearsal", evidenceSha256 }) },
    ecsExec: { run: async () => ({ valid: true, evidenceRef: "exec:rehearsal", evidenceSha256 }) },
    onboarding: { run: async (expected) => { const evidence = await runStrictOnboardingProbes({ probes: strictProbes, expected: { ...expected, taskDefinitionArn, taskArn, rotationId } }); return evidence; } },
    ...overrides,
    _mutations: mutations,
  };
}

const stageAPlan = ({ address = 'aws_vpc_security_group_ingress_rule.runtime_endpoints_https["sg-runtime"]', actions = ["create"], checkerActions = actions, after = {}, checkerAfter = {}, checkerRole = checkerRoleChange(), checkerPublication = checkerPublicationChange(), extra = [] } = {}) => ({
  resource_changes: [{ address, change: { actions, after: { security_group_id: "sg-endpoint", referenced_security_group_id: "sg-runtime", from_port: 443, to_port: 443, ip_protocol: "tcp", cidr_ipv4: null, cidr_ipv6: null, prefix_list_id: null, ...after } } }, checkerPolicyChange(checkerActions, checkerAfter), checkerRole, checkerPublication, ...extra],
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
    { ...stageAPlan({ actions: ["no-op"], checkerActions: ["no-op"] }), resource_drift: [{ address: "aws_security_group.executor_endpoints", change: { actions: ["update"] } }] },
  ]) assert.throws(() => assertStageAPlan(plan, inputs));
  assert.throws(() => assertStageAPlan({ ...stageAPlan(), resource_drift: {} }, inputs));
  assert.doesNotThrow(() => assertStageAPlan({ ...stageAPlan(), resource_drift: [{ address: "aws_db_instance.green", mode: "managed", type: "aws_db_instance", name: "green", change: { actions: ["update"], before: { identifier: "mscqr-production-rls-green", latest_restorable_time: "2026-08-18T22:41:17Z", storage_encrypted: true }, after: { identifier: "mscqr-production-rls-green", latest_restorable_time: "2026-08-19T20:01:16Z", storage_encrypted: true }, replace_paths: [] } }] }, inputs));
});

test("Stage A admits only the exact checker role-chain policy semantics", () => {
  const inputs = { endpointSecurityGroupId: "sg-endpoint", runtimeSecurityGroupId: "sg-runtime" };
  assert.equal(assertStageAPlan(stageAPlan(), inputs).valid, true);
  for (const checkerAfter of [
    { policy: checkerPolicyDocument({ action: "sts:*" }) },
    { policy: checkerPolicyDocument({ resource: "*" }) },
    { policy: checkerPolicyDocument({ resource: "arn:aws:iam::368992683803:role/other" }) },
    { policy: checkerPolicyDocument({ extraStatements: [{ Sid: "Extra", Effect: "Allow", Action: "sts:AssumeRole", Resource: STAGE_A_CHECKER_POLICY.resource }] }) },
    { role: "mscqr-production-release-deployer" },
  ]) assert.throws(() => assertStageAPlan(stageAPlan({ checkerAfter }), inputs));
  assert.throws(() => assertStageAPlan(stageAPlan({ checkerActions: ["update"] }), inputs));
  assert.throws(() => assertStageAPlan(stageAPlan({ extra: [{ address: "aws_iam_role_policy.unrelated", type: "aws_iam_role_policy", change: { actions: ["create"], after: {} } }] }), inputs));
});

test("Stage A admits only the exact checker publication policy transition", () => {
  const inputs = { endpointSecurityGroupId: "sg-endpoint", runtimeSecurityGroupId: "sg-runtime" };
  const exact = stageAPlan({ actions: ["no-op"], checkerActions: ["no-op"], checkerPublication: checkerPublicationChange({ actions: ["update"], beforePolicy: checkerPublicationPolicy({ predecessor: true }) }) });
  assert.equal(assertStageAPlan(exact, inputs).changes, 1);
  const reordered = checkerPublicationPolicy();
  reordered.Statement.reverse();
  reordered.Statement[1].Action.reverse();
  assert.doesNotThrow(() => assertStageAPlan(stageAPlan({ actions: ["no-op"], checkerActions: ["no-op"], checkerPublication: checkerPublicationChange({ actions: ["update"], beforePolicy: checkerPublicationPolicy({ predecessor: true }), afterPolicy: reordered }) }), inputs));
  for (const checkerPublication of [
    checkerPublicationChange({ actions: ["update"], beforePolicy: checkerPublicationPolicy({ predecessor: true }), afterPolicy: checkerPublicationPolicy({ publishResource: "*" }) }),
    checkerPublicationChange({ actions: ["update"], beforePolicy: checkerPublicationPolicy({ predecessor: true }), afterPolicy: checkerPublicationPolicy({ publishResource: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:unrelated" }) }),
    checkerPublicationChange({ actions: ["update"], beforePolicy: checkerPublicationPolicy({ predecessor: true }), afterPolicy: checkerPublicationPolicy({ publishAction: "secretsmanager:*" }) }),
    checkerPublicationChange({ actions: ["update"], beforePolicy: checkerPublicationPolicy({ predecessor: true }), afterPolicy: checkerPublicationPolicy({ publishAction: "secretsmanager:GetSecretValue" }) }),
    checkerPublicationChange({ actions: ["update"], beforePolicy: checkerPublicationPolicy({ predecessor: true }), afterPolicy: checkerPublicationPolicy({ publishAction: "secretsmanager:UpdateSecretVersionStage" }) }),
    checkerPublicationChange({ actions: ["update"], beforePolicy: checkerPublicationPolicy({ predecessor: true }), afterPolicy: checkerPublicationPolicy({ publishAction: ["secretsmanager:PutSecretValue", "secretsmanager:DeleteSecret"] }) }),
    checkerPublicationChange({ actions: ["update"], beforePolicy: checkerPublicationPolicy({ predecessor: true }), afterPolicy: checkerPublicationPolicy({ kmsAction: [...STAGE_A_CHECKER_PUBLICATION_POLICY.kmsAction, "kms:Decrypt"] }) }),
    checkerPublicationChange({ actions: ["update"], beforePolicy: checkerPublicationPolicy({ predecessor: true }), afterPolicy: checkerPublicationPolicy({ extraStatement: true }) }),
    checkerPublicationChange({ actions: ["update"], beforePolicy: checkerPublicationPolicy({ predecessor: true }), afterPolicy: { Version: "2012-10-17", Statement: [{ Sid: "PublishExactStageBApproval", Effect: "Allow", Action: "secretsmanager:PutSecretValue", Resource: STAGE_A_CHECKER_PUBLICATION_POLICY.publishResource }] } }),
    checkerPublicationChange({ actions: ["update"], beforePolicy: checkerPublicationPolicy({ predecessor: true }), afterPolicy: checkerPublicationPolicy({ condition: { Bool: { "aws:MultiFactorAuthPresent": "true" } } }) }),
    checkerPublicationChange({ actions: ["update"], beforePolicyBytes: "not-json", beforePolicy: checkerPublicationPolicy({ predecessor: true }) }),
    checkerPublicationChange({ actions: ["create"], beforePolicy: checkerPublicationPolicy({ predecessor: true }) }),
    checkerPublicationChange({ actions: ["delete"], beforePolicy: checkerPublicationPolicy({ predecessor: true }) }),
    checkerPublicationChange({ actions: ["update"], beforePolicy: checkerPublicationPolicy(), afterPolicy: checkerPublicationPolicy() }),
    checkerPublicationChange({ actions: ["update"], beforePolicy: checkerPublicationPolicy({ predecessor: true }), afterPolicy: checkerPublicationPolicy(), after: { role: "mscqr-production-release-deployer" } }),
    checkerPublicationChange({ actions: ["update"], beforePolicy: checkerPublicationPolicy({ predecessor: true }), replacePaths: [["policy"]] }),
  ]) assert.throws(() => assertStageAPlan(stageAPlan({ actions: ["no-op"], checkerActions: ["no-op"], checkerPublication }), inputs));
  assert.throws(() => assertStageAPlan(stageAPlan({ actions: ["no-op"], checkerActions: ["no-op"], checkerPublication: checkerPublicationChange({ actions: ["update"], beforePolicy: checkerPublicationPolicy({ predecessor: true }) }), extra: [{ address: "aws_iam_role_policy.unrelated", type: "aws_iam_role_policy", change: { actions: ["update"], before: {}, after: {} } }] }), inputs));
});

test("Stage A admits only the exact Role-B trust transition", () => {
  const inputs = { endpointSecurityGroupId: "sg-endpoint", runtimeSecurityGroupId: "sg-runtime" };
  const oldCondition = { Bool: { "aws:MultiFactorAuthPresent": "true" } };
  assert.equal(assertStageAPlan(stageAPlan({ checkerRole: checkerRoleChange({ actions: ["update"] }) }), inputs).valid, true);
  for (const checkerRole of [
    checkerRoleChange({ actions: ["no-op"], before: { assume_role_policy: checkerRoleTrustDocument({ condition: oldCondition }) } }),
    checkerRoleChange({ actions: ["create"] }),
    checkerRoleChange({ actions: ["delete"] }),
    checkerRoleChange({ actions: ["update", "delete"] }),
    checkerRoleChange({ actions: ["update"], after: { assume_role_policy: checkerRoleTrustDocument({ condition: oldCondition }) } }),
    checkerRoleChange({ actions: ["update"], after: { assume_role_policy: checkerRoleTrustDocument({ condition: { Bool: { "aws:MultiFactorAuthPresent": "false" } } }) } }),
    checkerRoleChange({ actions: ["update"], after: { assume_role_policy: JSON.stringify({ Version: "2012-10-17", Statement: [{ Effect: "Allow", Principal: { AWS: "*" }, Action: "sts:AssumeRole" }] }) } }),
    checkerRoleChange({ actions: ["update"], after: { assume_role_policy: JSON.stringify({ Version: "2012-10-17", Statement: [{ Effect: "Allow", Principal: { AWS: "arn:aws:iam::368992683803:root" }, Action: "sts:AssumeRole" }] }) } }),
    checkerRoleChange({ actions: ["update"], after: { assume_role_policy: JSON.stringify({ Version: "2012-10-17", Statement: [{ Effect: "Allow", Principal: { AWS: CHECKER_USER_ARN }, Action: "sts:AssumeRole" }] }) } }),
    checkerRoleChange({ actions: ["update"], after: { assume_role_policy: JSON.stringify({ Version: "2012-10-17", Statement: [{ Effect: "Allow", Principal: { AWS: "arn:aws:iam::368992683803:role/other" }, Action: "sts:AssumeRole" }] }) } }),
    checkerRoleChange({ actions: ["update"], after: { assume_role_policy: JSON.stringify({ Version: "2012-10-17", Statement: [{ Effect: "Allow", Principal: { AWS: STAGE_A_CHECKER_ROLE_TRUST.principal }, Action: ["sts:AssumeRole", "sts:TagSession"] }] }) } }),
    checkerRoleChange({ actions: ["update"], after: { name: "other-role" } }),
    checkerRoleChange({ actions: ["update"], after: { permissions_boundary: "arn:aws:iam::368992683803:policy/other" } }),
    checkerRoleChange({ actions: ["update"], after: { tags: { Changed: "true" } } }),
    checkerRoleChange({ actions: ["update"], after: { max_session_duration: 7200 } }),
    checkerRoleChange({ actions: ["update"], before: { tags: { Stable: "true" } } }),
  ]) assert.throws(() => assertStageAPlan(stageAPlan({ checkerRole }), inputs));
  assert.throws(() => assertStageAPlan(stageAPlan({ checkerRole: checkerRoleChange({ actions: ["update"] }), extra: [{ address: "aws_iam_role.unrelated", type: "aws_iam_role", change: { actions: ["update"], before: {}, after: {} } }] }), inputs));
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
    assert.throws(() => assertStageAPlan({ resource_changes: [stageAPlan().resource_changes[0], stageAPlan().resource_changes[1], entry] }, inputs));
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
  assert.equal(result.mutationCount, 2);
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

test("Stage A resumes an existing saved plan without a state backend", async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-stage-a-resume-"));
  const planPath = path.join(directory, "stage-a.tfplan");
  const planBytes = Buffer.from("preserved-plan-bytes");
  writeFileSync(planPath, planBytes, { mode: 0o600 });
  const stageAPlanSha256 = createHash("sha256").update(planBytes).digest("hex");
  const calls = [];
  try {
    const adapter = createTerraformStageAAdapter({
      root: "infra/aws/terraform/production-green-stage-a",
      planPath,
      stageAPlanSha256,
      backendArgs: ["-backend-config=must-not-be-used"],
      sourceSha: "a".repeat(40),
      run: async (args) => {
        calls.push(args);
        if (args.includes("show")) return JSON.stringify(stageAPlan({ actions: ["no-op"] }));
        if (args.includes("-backend=false")) return "";
        throw new Error(`unexpected Terraform call: ${args.join(" ")}`);
      },
      describeIngress: async () => ({ present: true }),
    });
    const result = await runStageAControlPlane({ adapter, endpointSecurityGroupId: "sg-endpoint", runtimeSecurityGroupId: "sg-runtime", sourceSha: "a".repeat(40) });
    assert.equal(result.alreadyConverged, true);
    assert.equal(result.mutationCount, 0);
    assert.equal(calls.some((args) => args.includes("must-not-be-used")), false);
    assert.equal(calls.some((args) => args.includes("plan")), false);
    assert.equal(calls.filter((args) => args.includes("show")).length, 1);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("Stage A rejects an invalid preserved-plan digest before Terraform show", async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-stage-a-plan-hash-"));
  const planPath = path.join(directory, "stage-a.tfplan");
  writeFileSync(planPath, "preserved-plan-bytes", { mode: 0o600 });
  const calls = [];
  try {
    const adapter = createTerraformStageAAdapter({ planPath, stageAPlanSha256: "0".repeat(64), run: async (args) => { calls.push(args); return ""; }, describeIngress: async () => ({ present: true }) });
    await assert.rejects(() => adapter.createSavedPlan(), /SHA-256 does not match/);
    assert.equal(calls.length, 0);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("Stage A rejects malformed or missing preserved-plan digest bindings", async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-stage-a-plan-hash-"));
  const planPath = path.join(directory, "stage-a.tfplan");
  writeFileSync(planPath, "preserved-plan-bytes", { mode: 0o600 });
  try {
    for (const stageAPlanSha256 of [undefined, "not-a-sha"]) {
      const adapter = createTerraformStageAAdapter({ planPath, stageAPlanSha256, run: async () => "", describeIngress: async () => ({ present: true }) });
      await assert.rejects(() => adapter.createSavedPlan(), /SHA-256 is missing or malformed/);
    }
    const missingPlan = path.join(directory, "missing.tfplan");
    const adapter = createTerraformStageAAdapter({ planPath: missingPlan, stageAPlanSha256: "a".repeat(64), run: async () => "", describeIngress: async () => ({ present: true }) });
    await assert.rejects(() => adapter.createSavedPlan(), /preserved plan is missing/);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("Stage A rechecks the preserved-plan digest immediately before apply", async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-stage-a-plan-hash-"));
  const planPath = path.join(directory, "stage-a.tfplan");
  const planBytes = Buffer.from("preserved-plan-bytes");
  writeFileSync(planPath, planBytes, { mode: 0o600 });
  const stageAPlanSha256 = createHash("sha256").update(planBytes).digest("hex");
  let applyCalls = 0;
  try {
    const adapter = createTerraformStageAAdapter({
      planPath, stageAPlanSha256,
      run: async (args) => { if (args.includes("apply")) applyCalls += 1; return args.includes("show") ? JSON.stringify(stageAPlan()) : ""; },
      describeIngress: async () => ({ present: true }),
    });
    const saved = await adapter.createSavedPlan();
    writeFileSync(planPath, "tampered-plan-bytes", { mode: 0o600 });
    const originalRun = adapter.applySavedPlan;
    await assert.rejects(() => originalRun(saved), /saved plan changed|SHA-256 does not match/);
    assert.equal(applyCalls, 0);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("Stage A postcondition reads exact SG-to-SG ingress from production-shaped AWS responses", () => {
  const inputs = { endpointSecurityGroupId: "sg-0123456789abcdef0", runtimeSecurityGroupId: "sg-051a24aedff773761" };
  const rule = (overrides = {}) => ({
    GroupId: inputs.endpointSecurityGroupId, ReferencedGroupInfo: { GroupId: inputs.runtimeSecurityGroupId }, IsEgress: false,
    IpProtocol: "tcp", FromPort: 443, ToPort: 443, ...overrides,
  });
  const calls = [];
  const read = (rules) => describeStageAIngress({ run: (args) => { calls.push(args); return JSON.stringify({ SecurityGroupRules: rules }); }, ...inputs });
  assert.deepEqual(read([rule()]), { present: true, ...inputs, direction: "ingress", protocol: "tcp", fromPort: 443, toPort: 443 });
  assert.equal(calls[0].some((arg) => String(arg).includes("referenced-group-id")), false);
  for (const rules of [
    [rule({ ReferencedGroupInfo: { GroupId: "sg-0123456789abcdef1" } })],
    [rule({ ReferencedGroupInfo: undefined })],
    [rule({ GroupId: "sg-0123456789abcdef1" })],
    [rule({ IsEgress: true })],
    [rule({ IpProtocol: "udp" })],
    [rule({ FromPort: 80 })],
    [rule({ ToPort: 80 })],
    [{ GroupId: inputs.endpointSecurityGroupId, CidrIpv4: "10.0.0.0/8", IsEgress: false, IpProtocol: "tcp", FromPort: 443, ToPort: 443 }],
    [{ GroupId: inputs.endpointSecurityGroupId, PrefixListId: "pl-unsupported", IsEgress: false, IpProtocol: "tcp", FromPort: 443, ToPort: 443 }],
  ]) assert.equal(read(rules).present, false);
});

test("the real cutover orchestrator reaches synthetic onboarding with ordered mutation intents", async () => {
  const input = fixtureInput();
  const result = await runProductionCutoverControlPlane(input);
  assert.equal(result.readyForOnboarding, true);
  assert.deepEqual(result.mutationSequence.map(({ name }) => name), ["M2_STAGE_A_APPLY", "M3_ARTIFACT_SECRET_PROVISION", "M5_ROTATION_STATE_PERSISTENCE", "M5_ROTATION_INFRA_CONVERGENCE", "M4_REGISTER_TASK_DEFINITION", "M6_ECS_UPDATE_SERVICE"]);
  assert.equal(result.results.rotationInfrastructure.applyCount, 1);
  assert.equal(result.results.rotationInfrastructure.overlapSecretCount, 11);
  assert.equal(result.results.rotationInfrastructure.authorizedOverlapSecretCount, 11);
  assert.equal(result.results.rotationInfrastructure.unrelatedSecretAccess, false);
  assert.equal(result.mutationSequence.find(({ name }) => name === "M5_ROTATION_INFRA_CONVERGENCE").count, 1);
  assert.equal(result.transitionMatrix.every((edge) => edge.result === "PASS"), true);
});

test("invalid IAM evidence is rejected before reconciliation", async () => {
  const input = fixtureInput();
  let reconciliationCalls = 0;
  input.iamReport = { ...input.iamReport, status: "invalid" };
  input.iam = { report: input.iamReport, reconcile: async () => { reconciliationCalls += 1; return { mutationCount: 1 }; } };
  await assert.rejects(() => runProductionCutoverControlPlane(input), /IAM preflight is invalid/);
  assert.equal(reconciliationCalls, 0);
  assert.deepEqual(input._mutations, []);
});

test("the real predeployment adapter feeds the same cutover spine before deployment", async () => {
  const input = fixtureInput();
  const order = [];
  let registeredDefinition;
  const preAdapter = createProductionPreDeploymentInventoryAdapter({
    sourceSha,
    imageDigest: imageDigest,
    config: { inventoryApprovalId: stageBApprovalIdForReleaseSha(sourceSha), rotationInventoryRlsRole: "mscqr_prod_rls_read", inventoryLogGroupName: "/ecs/mscqr-production/rls-green-backend", overlapTaskInput: { backendLogGroup: "/ecs/mscqr-production/rls-green-backend", secretBindings: { ROTATION_INVENTORY_RLS_ROLE: "mscqr_prod_rls_read" } } },
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
  const originalRotationInfrastructure = input.rotationInfrastructure.run;
  input.rotationInfrastructure.run = async (...args) => { order.push("ROTATION_INFRA"); return originalRotationInfrastructure(...args); };
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
  assert.deepEqual(order, ["PREDEPLOY_INVENTORY", "ROTATION_PREPARE", "ROTATION_INFRA", "TASK_REGISTER", "UPDATE_SERVICE", "STABILIZATION", "POSTDEPLOY", "ECS_EXEC", "ONBOARDING", "ROTATION_CLOSE"]);
  assert.equal(result.readyForOnboarding, true);
  assert.equal(result.mutationSequence.filter(({ name }) => name === "M6_ECS_UPDATE_SERVICE").length, 1);
});

test("missing rotation infrastructure convergence fails before task registration or ECS update", async () => {
  const input = fixtureInput({ rotationInfrastructure: undefined });
  await assert.rejects(() => runProductionCutoverControlPlane(input), /Rotation infrastructure convergence is required/);
  assert.equal(input._mutations.includes("M4_REGISTER_TASK_DEFINITION"), false);
  assert.equal(input._mutations.includes("M6_ECS_UPDATE_SERVICE"), false);
});

test("unauthorized overlap image variants fail before pre-deployment task registration", async () => {
  const authorizedImage = imageDigest;
  const unauthorizedImages = [
    `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@sha256:${"a".repeat(64)}`,
    authorizedImage.replace("mscqr-backend", "unreviewed-backend"),
    authorizedImage.replace("368992683803", "111111111111"),
    authorizedImage.replace("eu-west-2", "us-east-1"),
    authorizedImage.replace(/@sha256:[a-f0-9]{64}$/, ":latest"),
    authorizedImage.slice(authorizedImage.indexOf("@") + 1),
    undefined,
  ];
  for (const backendImage of unauthorizedImages) {
    const input = fixtureInput();
    const registrationCalls = [];
    input.overlapTask.input.backendImage = backendImage;
    input.preDeploymentInventory = {
      taskDefinitionArn: input.inventory.taskDefinitionArn,
      execute: async () => {
        registrationCalls.push("register-task-definition");
        return input.inventory.execute();
      },
    };
    await assert.rejects(() => runProductionCutoverControlPlane(input), /authorized backend image/);
    assert.equal(registrationCalls.length, 0);
    assert.equal(input._mutations.includes("M4_REGISTER_TASK_DEFINITION"), false);
  }
});

test("drifted Role-A trust fails before Stage-A or target-role convergence", async () => {
  const input = fixtureInput({ checkerChain: {
    verifySourceTrust: async () => ({ exact: false, mfaRequired: false }),
    verifyComplete: async () => { throw new Error("must not reach target-role verification"); },
  } });
  await assert.rejects(() => runProductionCutoverControlPlane(input), /Live Role-A trust/);
  assert.equal(input._mutations.includes("M2_STAGE_A_APPLY"), false);
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

test("post-prepare overlap registration uses JSON-key references for promoted current secrets", async () => {
  const input = fixtureInput();
  const current = input.overlapTask.input.secretBindings;
  const overlapSecretBindings = Object.fromEntries(Object.entries(current).map(([name, value]) => [name,
    ["JWT_SECRET_CURRENT", "QR_SIGN_PRIVATE_KEY_CURRENT", "QR_SIGN_PUBLIC_KEY_CURRENT"].includes(name) ? `${value}:value::` : value]));
  input.rotationPrepare.run = async () => ({ valid: true, prepared: true, rotationId, rotationStateSha256, rotationFixtureSha256, evidenceRef: "rotation:rehearsal", evidenceSha256, mutationCount: 1, overlapSecretBindings });
  let registeredPayload;
  input.overlapTask.register = async (payload) => {
    registeredPayload = payload;
    return { taskDefinition: { taskDefinitionArn } };
  };
  await runProductionCutoverControlPlane(input);
  const secrets = registeredPayload.taskDefinition.containerDefinitions.find(({ name }) => name === "backend").secrets;
  const values = Object.fromEntries(secrets.map(({ name, valueFrom }) => [name, valueFrom]));
  for (const name of ["JWT_SECRET_CURRENT", "QR_SIGN_PRIVATE_KEY_CURRENT", "QR_SIGN_PUBLIC_KEY_CURRENT"]) {
    assert.match(values[name], /:value::$/);
    assert.doesNotMatch(values[name], /:value::.*:value::/);
  }
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
  await assert.rejects(() => runStrictOnboardingProbes({ probes, expected: { sourceSha, imageDigest: digest, taskDefinitionArn, taskArn, rotationId, rotationStateSha256 } }), /unavailable/);
});

test("onboarding evidence fingerprint contains only non-secret metadata", async () => {
  const probes = Object.fromEntries(STRICT_ONBOARDING_CHECKS.map((name) => [name, async () => true]));
  const evidence = await runStrictOnboardingProbes({ probes, expected: { sourceSha, imageDigest: digest, taskDefinitionArn, taskArn, rotationId, rotationStateSha256 } });
  const fingerprint = buildOnboardingEvidenceFingerprint(evidence);
  assert.deepEqual(Object.keys(fingerprint).sort(), ["checks", "imageDigest", "rotationId", "rotationStateSha256", "rotationPhase", "sourceSha", "taskArn", "taskDefinitionArn"].sort());
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
  ["temporary-kms-capability-residue", (i) => { i.iamReport.temporaryKmsCapability = buildTemporaryCapabilityEvidence({ state: "AUTHORIZED_FOR_ROOT_DROP_CREATION", sourceSha, transitionId: "rehearsal-transition", defaultVersionId: "v2", temporaryVersionId: "v2", observedAt: "2026-08-18T12:00:00.000Z" }); }],
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
  ["rotation-persistence-mismatch", (i) => { i.rotationPrepare.run = async () => ({ valid: true, prepared: true, rotationId: "wrong", rotationStateSha256, rotationFixtureSha256, evidenceRef: "bad", evidenceSha256 }); }],
  ["rotation-fixture-unbound", (i) => { i.rotationPrepare.run = async () => ({ valid: true, prepared: true, rotationId, rotationStateSha256, evidenceRef: "bad", evidenceSha256 }); }],
  ["readiness-evidence-hash-mismatch", (i) => { i.readiness = { produce: async () => ({}) }; }],
  ["readiness-identity-mismatch", (i) => { i.rotationPrepare.run = async () => ({ valid: true, prepared: true, rotationId, rotationStateSha256: "f".repeat(64), rotationFixtureSha256, evidenceRef: "bad", evidenceSha256 }); }],
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
  assert.equal(failCases.length, 54);
  assert.equal(failureResults.length, failCases.length);
  assert.equal(failureResults.filter(({ result }) => result !== "EXPECTED_FAILURE").length, 0);
});
