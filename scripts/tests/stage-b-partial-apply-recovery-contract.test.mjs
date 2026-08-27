import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import { assertCanonicalTerraformSerialNumber, parseCanonicalTerraformSerialCliText, assertRecoveryOnlyPlan, assertRecoveryPlanDelta, assertRecoveryAttestation, assertVerifiedStageBRecovery, classifyRecoveryResidue, createRecoveryAttestation, createStageBRecoveryKmsVerifier, signRecoveryAttestation, verifyRecoveryAttestation } from "../aws/stage-b-partial-apply-recovery-contract.mjs";
import { STAGE_B } from "../aws/production-green-stage-b-contract.mjs";
import { buildRootAttestationKeyPolicy, ROOT_ATTESTATION_KEY_DESCRIPTION, ROOT_ATTESTATION_TAGS } from "../aws/production-root-attestation-key.mjs";

const digest = "a".repeat(64);
const current = (overrides = {}) => ({ protectedSourceSha: "523817e71755616ed004a5dea03ea4e10672723b", terraformLineage: "4e438e59-8b8b-194d-030c-5ede0c26344a", terraformSerial: 78, refreshReportSha256: digest, terraformAddress: "aws_lambda_alias.reviewed", resourceMode: "managed", resourceModule: null, resourceType: "aws_lambda_alias", resourceName: "reviewed", functionName: "mscqr-production-rls-approval-broker", aliasName: "reviewed", stateVersion: "3", configuredDesiredVersion: "3", liveVersion: "2", changedAttributes: ["function_version"], routingConfigurationChanged: false, descriptionChanged: false, functionIdentityChanged: false, aliasIdentityChanged: false, additionalManagedResourceDrift: false, ...overrides });
const historical = (overrides = {}) => ({ protectedSourceSha: "0".repeat(40), terraformLineage: "4e438e59-8b8b-194d-030c-5ede0c26344a", preApplySerial: 76, failedMutation: { terraformAddress: "aws_lambda_alias.reviewed", awsService: "lambda", operation: "UpdateAlias", result: "FAILED", failureClass: "AUTHORIZATION", awsErrorClass: "AccessDeniedException", attemptedTargetVersion: "3" }, inputs: ["savedPlan", "planJson", "logicalPlan", "planApproved", "planBoundPermission", "applyStdout", "applyStderr"].map((name) => ({ name, path: `/private/tmp/${name}`, sha256: digest, trustClassification: name.startsWith("apply") ? "RAW_FORENSIC" : "STRUCTURED_VERIFIED", required: true })), ...overrides });
const assertion = { historicalFailedTarget: "3", stateTarget: "3", liveTarget: "2", onlyFunctionVersionChanged: true, noAdditionalManagedDrift: true, authorizesPlan: false, authorizesApply: false, failureClass: "AUTHORIZATION", operation: "lambda:UpdateAlias" };
const report = () => createRecoveryAttestation({ generatedAt: new Date().toISOString(), producerCallerArn: "arn:aws:iam::368992683803:root", historicalObservedEvidence: historical(), currentObservedEvidence: current(), reviewedRecoveryAssertion: assertion });
const computedPlan = (overrides = {}) => {
  const qualifiedArn = `${STAGE_B.brokerFunctionArn}:3`;
  const qualifiedInvokeArn = `arn:aws:apigateway:eu-west-2:lambda:path/2015-03-31/functions/${qualifiedArn}/invocations`;
  const alias = {
    address: "aws_lambda_alias.reviewed", mode: "managed", module: null, type: "aws_lambda_alias",
    change: { actions: ["update"], before: { function_version: "2" }, after: {}, after_unknown: { function_version: true, routing_config: [] }, ...overrides.aliasChange },
  };
  const broker = {
    address: "aws_lambda_function.broker", mode: "managed", module: null, type: "aws_lambda_function",
    change: {
      actions: ["update"],
      before: { function_name: "mscqr-production-rls-approval-broker", filename: "old.zip", code_sha256: "old-code-sha", source_code_size: 100, last_modified: "old", qualified_arn: qualifiedArn, qualified_invoke_arn: qualifiedInvokeArn, version: "3" },
      after: { function_name: "mscqr-production-rls-approval-broker", filename: "new.zip" },
      after_unknown: { code_sha256: true, source_code_size: true, last_modified: true, qualified_arn: true, qualified_invoke_arn: true, version: true },
      ...overrides.brokerChange,
      before: { function_name: "mscqr-production-rls-approval-broker", filename: "old.zip", code_sha256: "old-code-sha", source_code_size: 100, last_modified: "old", qualified_arn: qualifiedArn, qualified_invoke_arn: qualifiedInvokeArn, version: "3", ...(overrides.brokerChange?.before || {}) },
      after: { function_name: "mscqr-production-rls-approval-broker", filename: "new.zip", ...(overrides.brokerChange?.after || {}) },
      after_unknown: { code_sha256: true, source_code_size: true, last_modified: true, qualified_arn: true, qualified_invoke_arn: true, ...(overrides.brokerChange?.after_unknown || {}) },
    },
  };
  return {
    resource_changes: overrides.resource_changes || [alias, broker],
    configuration: { root_module: { resources: overrides.configurationResources || [
      { address: "aws_lambda_alias.reviewed", mode: "managed", type: "aws_lambda_alias", expressions: { function_version: { references: ["aws_lambda_function.broker.version", "aws_lambda_function.broker"] } } },
      { address: "aws_lambda_function.broker", mode: "managed", type: "aws_lambda_function", expressions: { publish: { constant_value: true } } },
    ] } },
  };
};

const recoveryBundle = () => {
  const refreshReport = { status: "RESOURCE_DRIFT", resourceChanges: { nonNoOp: 1, changes: [{ address: "aws_lambda_alias.reviewed", type: "aws_lambda_alias", actions: ["update"] }] } };
  const refreshReportBytes = Buffer.from(`${JSON.stringify(refreshReport)}\n`);
  const refreshReportSha256 = crypto.createHash("sha256").update(refreshReportBytes).digest("hex");
  const attestation = createRecoveryAttestation({ generatedAt: new Date().toISOString(), producerCallerArn: "arn:aws:iam::368992683803:root", historicalObservedEvidence: historical(), currentObservedEvidence: current({ refreshReportSha256 }), reviewedRecoveryAssertion: assertion });
  const signature = signRecoveryAttestation(attestation, { sign: () => "AQ==" });
  const attestationBytes = Buffer.from(`${JSON.stringify(attestation, null, 2)}\n`);
  const signatureBytes = Buffer.from(`${JSON.stringify(signature, null, 2)}\n`);
  const classification = classifyRecoveryResidue({ refreshReport, refreshReportSha256, attestation, attestationSignature: signature, attestationBytes, attestationSignatureBytes: signatureBytes, verify: ({ signature: bytes }) => bytes.equals(Buffer.from([1])) });
  const classificationBytes = Buffer.from(`${JSON.stringify(classification, null, 2)}\n`);
  const sha = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
  return { refreshReport, refreshReportBytes, refreshReportSha256, attestation, attestationBytes, attestationSha256: sha(attestationBytes), signature, signatureBytes, signatureSha256: sha(signatureBytes), classification, classificationBytes, classificationSha256: sha(classificationBytes) };
};

test("valid present-time attestation validates exact residue and is non-authorizing", () => { const value = report(); assert.doesNotThrow(() => assertRecoveryAttestation(value)); assert.equal(value.reviewedRecoveryAssertion.authorizesApply, false); });
test("wrong producer, target, lineage, serial, refresh, or identity fails closed", () => { for (const change of [{ producerCallerArn: "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/x" }, { currentObservedEvidence: current({ configuredDesiredVersion: "4" }) }, { currentObservedEvidence: current({ terraformLineage: "bad" }) }, { currentObservedEvidence: current({ resourceMode: "data" }) }, { currentObservedEvidence: current({ resourceModule: "module.foo" }) }]) assert.throws(() => createRecoveryAttestation({ ...{ generatedAt: new Date().toISOString(), producerCallerArn: "arn:aws:iam::368992683803:root", historicalObservedEvidence: historical(), currentObservedEvidence: current(), reviewedRecoveryAssertion: assertion }, ...change })); assert.throws(() => assertRecoveryAttestation(report(), { expected: { terraformSerial: 79 } })); assert.throws(() => assertRecoveryAttestation(report(), { expected: { refreshReportSha256: "b".repeat(64) } })); });

test("Terraform serial uses one strict safe non-negative integer contract", () => {
  assert.equal(assertCanonicalTerraformSerialNumber(78), 78);
  assert.equal(assertCanonicalTerraformSerialNumber(Number.MAX_SAFE_INTEGER), Number.MAX_SAFE_INTEGER);
  assert.equal(parseCanonicalTerraformSerialCliText("78"), 78);
  assert.throws(() => assertCanonicalTerraformSerialNumber("78"));
  for (const value of ["78foo", "078", " 78 ", "78.0", "7.8e1", "-1", "+78", "", null, undefined, NaN, Infinity, 1.5, Number.MAX_SAFE_INTEGER + 1]) assert.throws(() => parseCanonicalTerraformSerialCliText(value));
  assert.throws(() => assertCanonicalTerraformSerialNumber(-1));
});
test("raw logs without the structured inventory are insufficient", () => assert.throws(() => createRecoveryAttestation({ generatedAt: new Date().toISOString(), producerCallerArn: "arn:aws:iam::368992683803:root", historicalObservedEvidence: { ...historical(), inputs: [{ name: "applyStdout", path: "/private/tmp/apply.stdout.log", sha256: digest, trustClassification: "RAW_FORENSIC" }] }, currentObservedEvidence: current(), reviewedRecoveryAssertion: assertion }), /required/));
test("authorizing flags, extra drift, and historical success fail closed", () => { assert.throws(() => createRecoveryAttestation({ generatedAt: new Date().toISOString(), producerCallerArn: "arn:aws:iam::368992683803:root", historicalObservedEvidence: historical(), currentObservedEvidence: current({ changedAttributes: ["function_version", "description"] }), reviewedRecoveryAssertion: assertion }), /exact alias/); assert.throws(() => createRecoveryAttestation({ generatedAt: new Date().toISOString(), producerCallerArn: "arn:aws:iam::368992683803:root", historicalObservedEvidence: historical(), currentObservedEvidence: current(), reviewedRecoveryAssertion: { ...assertion, authorizesApply: true } }), /incomplete/); assert.throws(() => createRecoveryAttestation({ generatedAt: new Date().toISOString(), producerCallerArn: "arn:aws:iam::368992683803:root", historicalObservedEvidence: historical({ failedMutation: { result: "SUCCEEDED" } }), currentObservedEvidence: current(), reviewedRecoveryAssertion: assertion }), /Historical/); });
test("signature and report hash domains are verified before recovery classification", () => {
  const value = report();
  const signature = signRecoveryAttestation(value, { sign: () => "AQ==" });
  const reportBytes = Buffer.from(`${JSON.stringify(value, null, 2)}\n`);
  const signatureBytes = Buffer.from(`${JSON.stringify(signature, null, 2)}\n`);
  assert.doesNotThrow(() => verifyRecoveryAttestation({ report: value, signature, reportBytes, signatureBytes, verify: ({ signature: bytes }) => bytes.equals(Buffer.from([1])) }));
  assert.throws(() => verifyRecoveryAttestation({ report: { ...value, currentObservedEvidence: current({ liveVersion: "1" }) }, signature, reportBytes, signatureBytes, verify: () => true }), /canonical report|hash domain|residue/);
  assert.throws(() => verifyRecoveryAttestation({ report: value, signature, reportBytes: Buffer.from("tampered"), signatureBytes, verify: () => true }), /canonical report/);
  assert.throws(() => verifyRecoveryAttestation({ report: value, signature: { ...signature, signatureBase64: "Ag==" }, reportBytes, signatureBytes: Buffer.from(`${JSON.stringify({ ...signature, signatureBase64: "Ag==" }, null, 2)}\n`), verify: ({ signature: bytes }) => bytes.equals(Buffer.from([1])) }), /verification failed/);
});

test("production recovery verifier authenticates the root-exclusive key before signature verification", () => {
  const calls = [];
  const keyArn = "arn:aws:kms:eu-west-2:368992683803:key/11111111-1111-1111-1111-111111111111";
  const responses = {
    "describe-key": { KeyMetadata: { Arn: keyArn, KeyId: keyArn.split("/").at(-1), Description: ROOT_ATTESTATION_KEY_DESCRIPTION, KeyUsage: "SIGN_VERIFY", KeySpec: "RSA_3072", KeyState: "Enabled", Enabled: true, KeyManager: "CUSTOMER", Origin: "AWS_KMS", MultiRegion: false } },
    "get-key-policy": { Policy: JSON.stringify(buildRootAttestationKeyPolicy()) },
    "list-resource-tags": { Tags: Object.entries(ROOT_ATTESTATION_TAGS).map(([TagKey, TagValue]) => ({ TagKey, TagValue })) },
    verify: { SignatureValid: true },
  };
  const verify = createStageBRecoveryKmsVerifier({ run: (args) => { calls.push(args); return JSON.stringify(responses[args[1]]); } });
  assert.equal(verify({ digest: Buffer.alloc(32), signature: Buffer.from([1]) }), true);
  assert.deepEqual(calls.map((args) => args[1]), ["describe-key", "get-key-policy", "list-resource-tags", "verify"]);
  assert.equal(calls.at(-1).includes(keyArn), true);
});

test("central recovery verification rejects unsigned or forged derived classifications", () => {
  const bundle = recoveryBundle();
  const verify = ({ signature: bytes }) => bytes.equals(Buffer.from([1]));
  const valid = (overrides = {}) => assertVerifiedStageBRecovery({ ...bundle, expectedSourceSha: current().protectedSourceSha, expectedLineage: current().terraformLineage, expectedSerial: current().terraformSerial, verifySignature: verify, ...overrides });
  assert.doesNotThrow(valid);
  for (const mutation of [
    { classification: { ...bundle.classification, attestationVerified: true } },
    { classification: { ...bundle.classification, recoveryAttestationSha256: "b".repeat(64) } },
    { attestationBytes: Buffer.from("tampered") },
    { signatureBytes: Buffer.from("tampered") },
    { signatureSha256: "c".repeat(64) },
    { verifySignature: () => false },
  ]) assert.throws(() => valid.call(null, mutation), /Stage B|Recovery/);
});

test("central recovery verification binds every raw byte hash before trusting fields", () => {
  const bundle = recoveryBundle();
  const verify = ({ signature: bytes }) => bytes.equals(Buffer.from([1]));
  for (const [field, value] of [["refreshReportSha256", "0".repeat(64)], ["classificationSha256", "0".repeat(64)], ["attestationSha256", "0".repeat(64)], ["signatureSha256", "0".repeat(64)]]) assert.throws(() => assertVerifiedStageBRecovery({ ...bundle, [field]: value, expectedSourceSha: current().protectedSourceSha, expectedLineage: current().terraformLineage, expectedSerial: current().terraformSerial, verifySignature: verify }), /bytes do not match/);
  assert.throws(() => assertVerifiedStageBRecovery({ ...bundle, expectedSourceSha: "f".repeat(40), expectedLineage: current().terraformLineage, expectedSerial: current().terraformSerial, verifySignature: verify }), /binding|identity|source/i);
});

test("recovery plan rejects a computed alias target without exact version proof", () => {
  const value = report();
  assert.throws(() => assertRecoveryPlanDelta(computedPlan(), value), /exact attested desired version/);
  assert.throws(() => assertRecoveryPlanDelta(computedPlan({ brokerChange: { before: { version: "4" } } }), value), /exact attested desired version/);
  const concrete = computedPlan({ aliasChange: { after: { function_version: "3" }, after_unknown: { routing_config: [] } }, brokerChange: { after: { function_name: "mscqr-production-rls-approval-broker", filename: "new.zip", version: "3" }, after_unknown: {} } });
  assert.deepEqual(assertRecoveryPlanDelta(concrete, value), { address: "aws_lambda_alias.reviewed", action: "update", beforeVersion: "2", afterVersion: "3" });
  assert.throws(() => assertRecoveryPlanDelta(computedPlan({ aliasChange: { after: { function_version: "3" }, after_unknown: { routing_config: [] } } }), value), /exact attested desired version/);
  assert.throws(() => assertRecoveryPlanDelta(computedPlan({ aliasChange: { after: { function_version: "3" }, after_unknown: { routing_config: [] } }, brokerChange: { after: { function_name: "mscqr-production-rls-approval-broker", filename: "new.zip", version: "4" }, after_unknown: {} } }), value), /exact attested desired version/);
  const existingVersion = computedPlan({
    aliasChange: { after: { function_version: "3" }, after_unknown: { routing_config: [] } },
    brokerChange: { actions: ["no-op"], after: { function_name: "mscqr-production-rls-approval-broker", filename: "old.zip", version: "3" }, after_unknown: {} },
  });
  assert.deepEqual(assertRecoveryPlanDelta(existingVersion, value), { address: "aws_lambda_alias.reviewed", action: "update", beforeVersion: "2", afterVersion: "3" });
});

test("recovery-only profile permits only the concrete attested alias update", () => {
  const value = report();
  const plan = computedPlan({
    aliasChange: { after: { function_version: "3" }, after_unknown: { routing_config: [] } },
    brokerChange: { actions: ["no-op"], after: { function_name: "mscqr-production-rls-approval-broker", filename: "old.zip", version: "3" }, after_unknown: {} },
  });
  assert.deepEqual(assertRecoveryOnlyPlan(plan, value), { profile: "RECOVERY_ALIAS_ONLY", address: "aws_lambda_alias.reviewed", action: "update", beforeVersion: "2", afterVersion: "3", nonNoOpMutations: 1 });
  const withBrokerNoOp = computedPlan({
    aliasChange: { after: { function_version: "3" }, after_unknown: { routing_config: [] } },
    brokerChange: { actions: ["no-op"], after: { function_name: "mscqr-production-rls-approval-broker", filename: "old.zip", version: "3" }, after_unknown: {} },
  });
  withBrokerNoOp.resource_changes.push({ address: "aws_ecs_task_definition.candidate[\"backend\"]", type: "aws_ecs_task_definition", change: { actions: ["create"], before: {}, after: {} } });
  assert.throws(() => assertRecoveryOnlyPlan(withBrokerNoOp, value), /exactly one non-no-op/);
});

test("computed alias target rejects missing, wrong, duplicate, or indirect configuration references", () => {
  const value = report();
  const cases = [
    { configurationResources: [{ address: "aws_lambda_alias.reviewed", mode: "managed", type: "aws_lambda_alias", expressions: { function_version: {} } }, { address: "aws_lambda_function.broker", mode: "managed", type: "aws_lambda_function", expressions: { publish: { constant_value: true } } }] },
    { configurationResources: [{ address: "aws_lambda_alias.reviewed", mode: "managed", type: "aws_lambda_alias", expressions: { function_version: { references: ["aws_lambda_function.other", "aws_lambda_function.other.version"] } } }, { address: "aws_lambda_function.broker", mode: "managed", type: "aws_lambda_function", expressions: { publish: { constant_value: true } } }] },
    { configurationResources: [{ address: "aws_lambda_alias.reviewed", mode: "managed", type: "aws_lambda_alias", expressions: { function_version: { references: ["var.broker_version"] } } }, { address: "aws_lambda_function.broker", mode: "managed", type: "aws_lambda_function", expressions: { publish: { constant_value: true } } }] },
    { configurationResources: [{ address: "aws_lambda_alias.reviewed", mode: "managed", type: "aws_lambda_alias", expressions: { function_version: { references: ["aws_lambda_function.broker", "aws_lambda_function.broker.version", "local.target"] } } }, { address: "aws_lambda_function.broker", mode: "managed", type: "aws_lambda_function", expressions: { publish: { constant_value: true } } }] },
  ];
  for (const overrides of cases) assert.throws(() => assertRecoveryPlanDelta(computedPlan(overrides), value), /exact attested desired version/);
});

test("computed alias target rejects an absent, non-update, non-root, or non-publishing broker", () => {
  const value = report();
  for (const brokerChange of [null, { actions: ["no-op"] }, { actions: ["create"] }, { actions: ["delete", "create"] }, { actions: ["update"], after: { function_name: "mscqr-production-rls-approval-broker", filename: "new.zip", description: "unexpected" }, after_unknown: { version: true } }, { actions: ["update"], after: { function_name: "mscqr-production-rls-approval-broker", filename: "new.zip" }, after_unknown: {} }]) {
    const plan = computedPlan({ resource_changes: brokerChange === null ? [computedPlan().resource_changes[0]] : [computedPlan().resource_changes[0], { ...computedPlan().resource_changes[1], change: { ...computedPlan().resource_changes[1].change, ...brokerChange } }] });
    assert.throws(() => assertRecoveryPlanDelta(plan, value), /exact attested desired version/);
  }
  const nonRoot = computedPlan(); nonRoot.resource_changes[1].module = "module.broker";
  assert.throws(() => assertRecoveryPlanDelta(nonRoot, value), /exact attested desired version/);
  const unpublished = computedPlan({ configurationResources: [{ address: "aws_lambda_alias.reviewed", mode: "managed", type: "aws_lambda_alias", expressions: { function_version: { references: ["aws_lambda_function.broker.version", "aws_lambda_function.broker"] } } }, { address: "aws_lambda_function.broker", mode: "managed", type: "aws_lambda_function", expressions: { publish: { constant_value: false } } }] });
  assert.throws(() => assertRecoveryPlanDelta(unpublished, value), /publish|exact attested desired version/);
});

test("computed alias target rejects conflicting concrete values, wrong target, wrong action, and other unknown fields", () => {
  const value = report();
  for (const aliasChange of [
    { after: { function_version: "3" }, after_unknown: { function_version: true, routing_config: [] } },
    { after: { function_version: "4" }, after_unknown: { routing_config: [] } },
    { actions: ["create"] },
    { after: {}, after_unknown: { function_version: true, description: true } },
  ]) assert.throws(() => assertRecoveryPlanDelta(computedPlan({ aliasChange }), value), /exact|unknown/);
  assert.throws(() => assertRecoveryPlanDelta(computedPlan(), null), /Current recovery evidence/);
});
