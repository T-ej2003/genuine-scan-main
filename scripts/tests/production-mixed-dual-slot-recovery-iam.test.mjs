import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { MIXED_DUAL_SLOT_RECOVERY_EXECUTION_POLICY_ARN, MIXED_DUAL_SLOT_RECOVERY_EXECUTION_ROLE_ARN, MIXED_DUAL_SLOT_RECOVERY_EXECUTION_TRUST_PATH, MIXED_DUAL_SLOT_RECOVERY_IAM_ACTION, MIXED_DUAL_SLOT_RECOVERY_IAM_CAPABILITIES, MIXED_DUAL_SLOT_RECOVERY_IAM_RESOURCES, MIXED_DUAL_SLOT_RECOVERY_OIDC_PROVIDER_ARN, assertMixedDualSlotRecoveryIamPreflight } from "../aws/production-mixed-dual-slot-recovery-contract.mjs";
import { readMixedDualSlotRecoveryIamCapabilityPreflight } from "../aws/preflight-production-mixed-dual-slot-recovery-iam.mjs";
import { assertMixedDualSlotRecoveryIamAttestation, createMixedDualSlotRecoveryIamAttestation } from "../aws/production-mixed-dual-slot-recovery-iam-attestation.mjs";
import { createPinnedRootAttestationVerifier, ROOT_ATTESTATION_KEY_ALIAS_ARN, ROOT_ATTESTATION_SIGNING_ALGORITHM } from "../aws/production-root-attestation-key.mjs";

const sourceSha = "a".repeat(40);
const observedAt = new Date("2026-09-10T00:00:00.000Z");
const trust = JSON.parse(fs.readFileSync(MIXED_DUAL_SLOT_RECOVERY_EXECUTION_TRUST_PATH, "utf8"));
const allowed = (action, resource) => ({ EvalActionName: action, EvalResourceName: resource === "*" ? "*" : "arn:${Partition}:secretsmanager:${Region}:${Account}:secret:${SecretId}", EvalDecision: "allowed", MatchedStatements: [{}], MissingContextValues: [], OrganizationsDecisionDetail: { AllowedByOrganizations: true }, ResourceSpecificResults: [{ EvalResourceName: resource, EvalResourceDecision: "allowed", MissingContextValues: [] }] });
const allAllowed = () => MIXED_DUAL_SLOT_RECOVERY_IAM_CAPABILITIES.flatMap(({ action, resources }) => resources.map((resource) => allowed(action, resource)));
const runner = ({ caller = { Account: "368992683803", Arn: "arn:aws:iam::368992683803:root" }, role = { Arn: MIXED_DUAL_SLOT_RECOVERY_EXECUTION_ROLE_ARN, AssumeRolePolicyDocument: trust }, results = allAllowed(), resourcePolicies = Object.fromEntries(MIXED_DUAL_SLOT_RECOVERY_IAM_RESOURCES.map((resource) => [resource, null])) } = {}) => (args) => {
  const operation = args.slice(0, 2).join(" ");
  if (operation === "sts get-caller-identity") return JSON.stringify(caller);
  if (operation === "organizations describe-organization") throw Object.assign(new Error("AWSOrganizationsNotInUseException"), { stderr: "AWSOrganizationsNotInUseException" });
  if (operation === "iam get-open-id-connect-provider") return JSON.stringify({ Url: "token.actions.githubusercontent.com", ClientIDList: ["sts.amazonaws.com"] });
  if (operation === "iam get-role") return JSON.stringify({ Role: role });
  if (operation === "secretsmanager get-resource-policy") {
    const resource = args.at(-1); return JSON.stringify({ ARN: resource, ResourcePolicy: resourcePolicies[resource] ?? null });
  }
  if (operation === "iam simulate-principal-policy") {
    const action = args[args.indexOf("--action-names") + 1];
    const resources = args.slice(args.indexOf("--resource-arns") + 1); assert.equal(resources.length, 1);
    return JSON.stringify({ EvaluationResults: results.filter((result) => result.EvalActionName === action && result.ResourceSpecificResults?.some(({ EvalResourceName }) => EvalResourceName === resources[0])) });
  }
  throw new Error(`unexpected ${operation}`);
};

test("dedicated executor policy grants only seven exact label mutations and shared release role has no grant", () => {
  const policy = JSON.parse(fs.readFileSync("infra/aws/terraform/production-initial-activation-policy-reconciler/mixed-recovery-permissions-policy.json", "utf8"));
  const statement = policy.Statement.find(({ Sid }) => Sid === "RemoveExactRecoveryAwscurrentLabels");
  assert.deepEqual(statement, { Sid: "RemoveExactRecoveryAwscurrentLabels", Effect: "Allow", Action: MIXED_DUAL_SLOT_RECOVERY_IAM_ACTION, Resource: [...MIXED_DUAL_SLOT_RECOVERY_IAM_RESOURCES] });
  const shared = JSON.parse(fs.readFileSync("documents/ops/iam/MSCQRProductionInitialActivationLifecycle-v1.json", "utf8"));
  assert.equal(shared.Statement.some(({ Effect, Action }) => Effect === "Allow" && [Action].flat().includes(MIXED_DUAL_SLOT_RECOVERY_IAM_ACTION)), false);
  const actions = policy.Statement.flatMap(({ Action }) => Array.isArray(Action) ? Action : [Action]);
  for (const forbidden of ["secretsmanager:PutSecretValue", "secretsmanager:CreateSecret", "secretsmanager:DeleteSecret", "secretsmanager:UpdateSecret"]) assert.equal(actions.includes(forbidden), false);
  assert.equal(MIXED_DUAL_SLOT_RECOVERY_EXECUTION_ROLE_ARN.endsWith("/mscqr-production-mixed-dual-slot-recovery-executor"), true);
  assert.equal(MIXED_DUAL_SLOT_RECOVERY_EXECUTION_POLICY_ARN.endsWith("/MSCQRProductionMixedDualSlotRecoveryExecutor"), true);
});

test("effective-capability preflight requires all seven exact allows", () => {
  const preflight = readMixedDualSlotRecoveryIamCapabilityPreflight({ sourceSha, now: observedAt, run: runner() });
  assert.equal(preflight.evaluations.length, 24);
  assert.doesNotThrow(() => assertMixedDualSlotRecoveryIamPreflight(preflight, { sourceSha, now: new Date("2026-09-10T00:05:00.000Z"), requireFresh: true }));
  for (let index = 0; index < 7; index += 1) {
    const denied = allAllowed(); const target = denied.findIndex(({ EvalActionName, ResourceSpecificResults }) => EvalActionName === MIXED_DUAL_SLOT_RECOVERY_IAM_ACTION && ResourceSpecificResults[0].EvalResourceName === MIXED_DUAL_SLOT_RECOVERY_IAM_RESOURCES[index]); denied[target] = { ...denied[target], EvalDecision: "implicitDeny", ResourceSpecificResults: [{ ...denied[target].ResourceSpecificResults[0], EvalResourceDecision: "implicitDeny" }] };
    assert.throws(() => readMixedDualSlotRecoveryIamCapabilityPreflight({ sourceSha, now: observedAt, run: runner({ results: denied }) }), /capability/);
  }
});

test("effective-capability preflight requires every executor read and mutation", () => {
  for (const [index] of allAllowed().entries()) {
    const denied = allAllowed(); denied[index] = { ...denied[index], EvalDecision: "implicitDeny", ResourceSpecificResults: [{ ...denied[index].ResourceSpecificResults[0], EvalResourceDecision: "implicitDeny" }] };
    assert.throws(() => readMixedDualSlotRecoveryIamCapabilityPreflight({ sourceSha, now: observedAt, run: runner({ results: denied }) }), /capability/);
  }
});

test("effective-capability preflight independently proves that no SCP layer applies", () => {
  assert.throws(() => readMixedDualSlotRecoveryIamCapabilityPreflight({ sourceSha, now: observedAt, run: (args) => args.slice(0, 2).join(" ") === "organizations describe-organization" ? JSON.stringify({ Organization: { Id: "o-example" } }) : runner()(args) }), /cannot authenticate the effective SCP layer/);
  assert.throws(() => readMixedDualSlotRecoveryIamCapabilityPreflight({ sourceSha, now: observedAt, run: (args) => { if (args.slice(0, 2).join(" ") === "organizations describe-organization") throw Object.assign(new Error("AccessDeniedException"), { stderr: "AccessDeniedException" }); return runner()(args); } }), /AccessDeniedException/);
  const preflight = readMixedDualSlotRecoveryIamCapabilityPreflight({ sourceSha, now: observedAt, run: runner() });
  assert.deepEqual(preflight.organizationsGuard, { accountId: "368992683803", status: "NOT_IN_ORGANIZATION", evidence: "AWSOrganizationsNotInUseException" });
});

test("effective-capability preflight authenticates the live GitHub OIDC provider", () => {
  const preflight = readMixedDualSlotRecoveryIamCapabilityPreflight({ sourceSha, now: observedAt, run: runner() });
  assert.deepEqual(preflight.oidcProviderGuard, { providerArn: MIXED_DUAL_SLOT_RECOVERY_OIDC_PROVIDER_ARN, url: "token.actions.githubusercontent.com", audience: "sts.amazonaws.com" });
  for (const provider of [{ Url: "wrong.example.com", ClientIDList: ["sts.amazonaws.com"] }, { Url: "token.actions.githubusercontent.com", ClientIDList: ["other"] }, { Url: "token.actions.githubusercontent.com", ClientIDList: ["sts.amazonaws.com", "other"] }, { Url: "token.actions.githubusercontent.com", ClientIDList: null }]) assert.throws(() => readMixedDualSlotRecoveryIamCapabilityPreflight({ sourceSha, now: observedAt, run: (args) => args.slice(0, 2).join(" ") === "iam get-open-id-connect-provider" ? JSON.stringify(provider) : runner()(args) }), /OIDC provider/);
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
  assert.throws(() => readMixedDualSlotRecoveryIamCapabilityPreflight({ sourceSha, now: observedAt, run: runner({ role: { Arn: MIXED_DUAL_SLOT_RECOVERY_EXECUTION_ROLE_ARN, AssumeRolePolicyDocument: trust, PermissionsBoundary: { PermissionsBoundaryArn: "arn:aws:iam::368992683803:policy/boundary" } } }) }), /permissions boundary/);
  assert.throws(() => readMixedDualSlotRecoveryIamCapabilityPreflight({ sourceSha, now: observedAt, run: runner({ role: { Arn: MIXED_DUAL_SLOT_RECOVERY_EXECUTION_ROLE_ARN, AssumeRolePolicyDocument: { ...trust, Version: "2008-10-17" } } }) }), /role trust/);
  const first = allAllowed()[0];
  for (const results of [
    allAllowed().slice(1),
    [...allAllowed(), first],
    [{ ...first, EvalActionName: "secretsmanager:PutSecretValue" }, ...allAllowed().slice(1)],
    [{ ...first, EvalDecision: "explicitDeny", ResourceSpecificResults: [{ ...first.ResourceSpecificResults[0], EvalResourceDecision: "explicitDeny" }] }, ...allAllowed().slice(1)],
    [{ ...first, MissingContextValues: ["aws:PrincipalTag/Unexpected"] }, ...allAllowed().slice(1)],
    [{ ...first, PermissionsBoundaryDecisionDetail: { AllowedByPermissionsBoundary: false } }, ...allAllowed().slice(1)],
    [{ ...first, OrganizationsDecisionDetail: { AllowedByOrganizations: false } }, ...allAllowed().slice(1)],
  ]) assert.throws(() => readMixedDualSlotRecoveryIamCapabilityPreflight({ sourceSha, now: observedAt, run: runner({ results }) }), /count|action|resource|capability/);
});

test("effective-capability preflight requires the sole exact AWS per-resource result", () => {
  const first = allAllowed()[0];
  for (const changed of [
    { ResourceSpecificResults: undefined },
    { ResourceSpecificResults: [] },
    { ResourceSpecificResults: [first.ResourceSpecificResults[0], first.ResourceSpecificResults[0]] },
    { ResourceSpecificResults: [{ ...first.ResourceSpecificResults[0], EvalResourceName: "arn:aws:iam::368992683803:role/wrong" }] },
    { ResourceSpecificResults: [{ ...first.ResourceSpecificResults[0], EvalResourceDecision: "implicitDeny" }] },
    { ResourceSpecificResults: [{ ...first.ResourceSpecificResults[0], MissingContextValues: ["aws:PrincipalTag/Unexpected"] }] },
    { ResourceSpecificResults: [{ ...first.ResourceSpecificResults[0], MissingContextValues: "" }] },
    { ResourceSpecificResults: [{ ...first.ResourceSpecificResults[0], PermissionsBoundaryDecisionDetail: { AllowedByPermissionsBoundary: false } }] },
    { ResourceSpecificResults: [{ ...first.ResourceSpecificResults[0], OrganizationsDecisionDetail: {} }] },
    { MissingContextValues: "" },
    { PermissionsBoundaryDecisionDetail: {} },
  ]) {
    const results = allAllowed(); results[0] = { ...first, ...changed };
    assert.throws(() => readMixedDualSlotRecoveryIamCapabilityPreflight({ sourceSha, now: observedAt, run: runner({ results }) }), /count|action|resource|capability|malformed/);
  }
});

test("preflight canonical identity rejects wildcard, missing, extra and stale substitutions", () => {
  const preflight = readMixedDualSlotRecoveryIamCapabilityPreflight({ sourceSha, now: observedAt, run: runner() });
  const legacyPreflight = structuredClone(preflight); delete legacyPreflight.oidcProviderGuard;
  assert.throws(() => assertMixedDualSlotRecoveryIamPreflight({ ...legacyPreflight, schemaVersion: 4 }, { sourceSha }), /schema/);
  for (const changed of [
    { principalArn: "arn:aws:iam::368992683803:role/wrong" },
    { action: "secretsmanager:*" },
    { resources: ["*"] },
    { resources: preflight.resources.slice(0, 6) },
    { resources: [...preflight.resources, "arn:aws:secretsmanager:eu-west-2:368992683803:secret:arbitrary"] },
    { roleTrustPolicySha256: "f".repeat(64) },
    { rolePermissionsBoundary: "arn:aws:iam::368992683803:policy/boundary" },
    { oidcProviderGuard: { providerArn: MIXED_DUAL_SLOT_RECOVERY_OIDC_PROVIDER_ARN, url: "token.actions.githubusercontent.com", audience: "other" } },
    { organizationsGuard: { accountId: "368992683803", status: "IN_ORGANIZATION", evidence: "unverified" } },
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
