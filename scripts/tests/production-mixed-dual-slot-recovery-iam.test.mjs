import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { MIXED_DUAL_SLOT_RECOVERY_EXECUTION_ROLE_ARN, MIXED_DUAL_SLOT_RECOVERY_IAM_ACTION, MIXED_DUAL_SLOT_RECOVERY_IAM_RESOURCES, assertMixedDualSlotRecoveryIamPreflight } from "../aws/production-mixed-dual-slot-recovery-contract.mjs";
import { readMixedDualSlotRecoveryIamCapabilityPreflight } from "../aws/preflight-production-mixed-dual-slot-recovery-iam.mjs";
import { assertMixedDualSlotRecoveryIamAttestation, createMixedDualSlotRecoveryIamAttestation } from "../aws/production-mixed-dual-slot-recovery-iam-attestation.mjs";
import { createPinnedRootAttestationVerifier, ROOT_ATTESTATION_KEY_ALIAS_ARN, ROOT_ATTESTATION_SIGNING_ALGORITHM } from "../aws/production-root-attestation-key.mjs";

const sourceSha = "a".repeat(40);
const observedAt = new Date("2026-09-10T00:00:00.000Z");
const allowed = (resource) => ({ EvalActionName: MIXED_DUAL_SLOT_RECOVERY_IAM_ACTION, EvalResourceName: resource, EvalDecision: "allowed", MatchedStatements: [{}], MissingContextValues: [], OrganizationsDecisionDetail: { AllowedByOrganizations: true } });
const runner = ({ caller = { Account: "368992683803", Arn: "arn:aws:iam::368992683803:root" }, role = { Arn: MIXED_DUAL_SLOT_RECOVERY_EXECUTION_ROLE_ARN }, results = MIXED_DUAL_SLOT_RECOVERY_IAM_RESOURCES.map(allowed), resourcePolicies = Object.fromEntries(MIXED_DUAL_SLOT_RECOVERY_IAM_RESOURCES.map((resource) => [resource, null])) } = {}) => (args) => {
  const operation = args.slice(0, 2).join(" ");
  if (operation === "sts get-caller-identity") return JSON.stringify(caller);
  if (operation === "iam get-role") return JSON.stringify({ Role: role });
  if (operation === "secretsmanager get-resource-policy") {
    const resource = args.at(-1); return JSON.stringify({ ARN: resource, ResourcePolicy: resourcePolicies[resource] ?? null });
  }
  if (operation === "iam simulate-principal-policy") {
    const resources = args.slice(args.indexOf("--resource-arns") + 1); assert.equal(resources.length, 1);
    return JSON.stringify({ EvaluationResults: results.filter(({ EvalResourceName }) => EvalResourceName === resources[0]) });
  }
  throw new Error(`unexpected ${operation}`);
};

test("canonical release policy grants only seven exact recovery label mutations", () => {
  const policy = JSON.parse(fs.readFileSync("documents/ops/iam/MSCQRProductionInitialActivationLifecycle-v1.json", "utf8"));
  const statement = policy.Statement.find(({ Sid }) => Sid === "RecoverExactMixedDualSlotTopology");
  assert.deepEqual(statement, { Sid: "RecoverExactMixedDualSlotTopology", Effect: "Allow", Action: MIXED_DUAL_SLOT_RECOVERY_IAM_ACTION, Resource: [...MIXED_DUAL_SLOT_RECOVERY_IAM_RESOURCES] });
  const actions = policy.Statement.flatMap(({ Action }) => Array.isArray(Action) ? Action : [Action]);
  for (const forbidden of ["secretsmanager:PutSecretValue", "secretsmanager:CreateSecret", "secretsmanager:DeleteSecret", "secretsmanager:UpdateSecret"]) assert.equal(actions.includes(forbidden), false);
});

test("effective-capability preflight requires all seven exact allows", () => {
  const preflight = readMixedDualSlotRecoveryIamCapabilityPreflight({ sourceSha, now: observedAt, run: runner() });
  assert.equal(preflight.evaluations.length, 7);
  assert.doesNotThrow(() => assertMixedDualSlotRecoveryIamPreflight(preflight, { sourceSha, now: new Date("2026-09-10T00:05:00.000Z"), requireFresh: true }));
  for (let index = 0; index < 7; index += 1) {
    const denied = MIXED_DUAL_SLOT_RECOVERY_IAM_RESOURCES.map(allowed); denied[index] = { ...denied[index], EvalDecision: "implicitDeny" };
    assert.throws(() => readMixedDualSlotRecoveryIamCapabilityPreflight({ sourceSha, now: observedAt, run: runner({ results: denied }) }), new RegExp(`resource ${index + 1}`));
  }
});

test("effective-capability preflight authenticates every exact secret resource policy", () => {
  const denied = JSON.stringify({ Version: "2012-10-17", Statement: [{ Effect: "Deny", Principal: "*", Action: MIXED_DUAL_SLOT_RECOVERY_IAM_ACTION, Resource: "*" }] });
  for (const resource of MIXED_DUAL_SLOT_RECOVERY_IAM_RESOURCES) {
    assert.throws(() => readMixedDualSlotRecoveryIamCapabilityPreflight({ sourceSha, now: observedAt, run: runner({ resourcePolicies: { [resource]: denied } }) }), /unsupported/);
  }
  assert.throws(() => readMixedDualSlotRecoveryIamCapabilityPreflight({ sourceSha, now: observedAt, run: (args) => {
    const result = runner()(args); return args.slice(0, 2).join(" ") === "secretsmanager get-resource-policy" ? JSON.stringify({ ARN: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:wrong", ResourcePolicy: null }) : result;
  } }), /identity changed/);
});

test("effective-capability preflight rejects identity, scope, deny, boundary and indeterminate drift", () => {
  assert.throws(() => readMixedDualSlotRecoveryIamCapabilityPreflight({ sourceSha, now: observedAt, run: runner({ caller: { Account: "368992683803", Arn: "arn:aws:iam::368992683803:user/operator" } }) }), /administrator identity/);
  assert.throws(() => readMixedDualSlotRecoveryIamCapabilityPreflight({ sourceSha, now: observedAt, run: runner({ role: { Arn: "arn:aws:iam::368992683803:role/wrong" } }) }), /role or permissions boundary/);
  assert.throws(() => readMixedDualSlotRecoveryIamCapabilityPreflight({ sourceSha, now: observedAt, run: runner({ role: { Arn: MIXED_DUAL_SLOT_RECOVERY_EXECUTION_ROLE_ARN, PermissionsBoundary: { PermissionsBoundaryArn: "arn:aws:iam::368992683803:policy/boundary" } } }) }), /permissions boundary/);
  for (const results of [
    MIXED_DUAL_SLOT_RECOVERY_IAM_RESOURCES.slice(1).map(allowed),
    [allowed(MIXED_DUAL_SLOT_RECOVERY_IAM_RESOURCES[0]), ...MIXED_DUAL_SLOT_RECOVERY_IAM_RESOURCES.map(allowed)],
    MIXED_DUAL_SLOT_RECOVERY_IAM_RESOURCES.map((resource, index) => index ? allowed(resource) : { ...allowed(resource), EvalActionName: "secretsmanager:PutSecretValue" }),
    MIXED_DUAL_SLOT_RECOVERY_IAM_RESOURCES.map((resource, index) => index ? allowed(resource) : { ...allowed(resource), EvalDecision: "explicitDeny" }),
    MIXED_DUAL_SLOT_RECOVERY_IAM_RESOURCES.map((resource, index) => index ? allowed(resource) : { ...allowed(resource), MissingContextValues: ["aws:PrincipalTag/Unexpected"] }),
    MIXED_DUAL_SLOT_RECOVERY_IAM_RESOURCES.map((resource, index) => index ? allowed(resource) : { ...allowed(resource), PermissionsBoundaryDecisionDetail: { AllowedByPermissionsBoundary: false } }),
    MIXED_DUAL_SLOT_RECOVERY_IAM_RESOURCES.map((resource, index) => index ? allowed(resource) : { ...allowed(resource), OrganizationsDecisionDetail: { AllowedByOrganizations: false } }),
  ]) assert.throws(() => readMixedDualSlotRecoveryIamCapabilityPreflight({ sourceSha, now: observedAt, run: runner({ results }) }), /count|action|resource|capability/);
});

test("preflight canonical identity rejects wildcard, missing, extra and stale substitutions", () => {
  const preflight = readMixedDualSlotRecoveryIamCapabilityPreflight({ sourceSha, now: observedAt, run: runner() });
  for (const changed of [
    { principalArn: "arn:aws:iam::368992683803:role/wrong" },
    { action: "secretsmanager:*" },
    { resources: ["*"] },
    { resources: preflight.resources.slice(0, 6) },
    { resources: [...preflight.resources, "arn:aws:secretsmanager:eu-west-2:368992683803:secret:arbitrary"] },
    { rolePermissionsBoundary: "arn:aws:iam::368992683803:policy/boundary" },
    { resourcePolicies: preflight.resourcePolicies.slice(0, 6) },
    { resourcePolicies: preflight.resourcePolicies.map((value, index) => index ? value : { ...value, resourcePolicyAccess: "UNVERIFIED" }) },
  ]) assert.throws(() => assertMixedDualSlotRecoveryIamPreflight({ ...preflight, ...changed }, { sourceSha }), /identity|hash|resource policy/);
  assert.throws(() => assertMixedDualSlotRecoveryIamPreflight(preflight, { sourceSha, now: new Date("2026-09-10T01:00:00.000Z"), requireFresh: true }), /stale/);
});

test("root-signed capability attestation binds the exact live preflight before approval", () => {
  const preflight = readMixedDualSlotRecoveryIamCapabilityPreflight({ sourceSha, now: observedAt, run: runner() });
  const attestation = createMixedDualSlotRecoveryIamAttestation({ preflight, now: new Date("2026-09-10T00:05:00.000Z"), sign: ({ digest, keyArn, signingAlgorithm }) => {
    assert.equal(digest.length, 32);
    assert.equal(keyArn, ROOT_ATTESTATION_KEY_ALIAS_ARN); assert.equal(signingAlgorithm, ROOT_ATTESTATION_SIGNING_ALGORITHM); return "c2ln";
  } });
  assert.doesNotThrow(() => assertMixedDualSlotRecoveryIamAttestation(attestation, { preflight, sourceSha, now: new Date("2026-09-10T00:05:00.000Z"), verify: () => true }));
  for (const changed of [{ preflightSha256: "f".repeat(64) }, { sourceSha: "b".repeat(40) }, { resources: ["*"] }]) assert.throws(() => assertMixedDualSlotRecoveryIamAttestation({ ...attestation, ...changed }, { preflight, sourceSha, now: new Date("2026-09-10T00:05:00.000Z"), verify: () => true }), /authenticated exact capability proof/);
  assert.throws(() => assertMixedDualSlotRecoveryIamAttestation({ ...attestation, signatureBase64: "YmFk" }, { preflight, sourceSha, now: new Date("2026-09-10T00:05:00.000Z"), verify: ({ signature }) => signature.toString("base64") === "c2ln" }), /authenticated exact capability proof/);
  assert.throws(() => assertMixedDualSlotRecoveryIamAttestation(attestation, { preflight, sourceSha, now: new Date("2026-09-10T00:05:00.000Z"), verify: () => false }), /authenticated exact capability proof/);
});

test("pinned root verifier is fail closed and invokes exact RSA-PSS verification", () => {
  let args;
  const verify = createPinnedRootAttestationVerifier({ execute: (_command, captured) => { args = captured; } });
  assert.equal(verify({ keyArn: ROOT_ATTESTATION_KEY_ALIAS_ARN, signingAlgorithm: ROOT_ATTESTATION_SIGNING_ALGORITHM, digest: Buffer.alloc(32), signature: Buffer.from("sig") }), true);
  assert.deepEqual(args.slice(0, 5), ["pkeyutl", "-verify", "-pubin", "-keyform", "DER"]);
  assert.equal(verify({ keyArn: "wrong", signingAlgorithm: ROOT_ATTESTATION_SIGNING_ALGORITHM, digest: Buffer.alloc(32), signature: Buffer.from("sig") }), false);
  assert.equal(createPinnedRootAttestationVerifier({ execute: () => { throw new Error("invalid"); } })({ keyArn: ROOT_ATTESTATION_KEY_ALIAS_ARN, signingAlgorithm: ROOT_ATTESTATION_SIGNING_ALGORITHM, digest: Buffer.alloc(32), signature: Buffer.from("sig") }), false);
});
