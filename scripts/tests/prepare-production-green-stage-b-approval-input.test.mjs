import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { prepareStageBApproval } from "../aws/create-production-green-stage-b-approval.mjs";
import { collectProductionGreenStageBApprovalEvidence } from "../aws/collect-production-green-stage-b-approval-evidence.mjs";
import { CHECKER_SOURCE_ROLE_ARN, CHECKER_USER_ARN } from "../aws/production-checker-chain-contract.mjs";
import { RELEASE_ROLE_ARN } from "../aws/production-identity-adapters.mjs";
import { buildReleasePreflightCheckerTrustAttestation } from "../aws/production-release-preflight-checker-attestation.mjs";
import { signPermissionReport } from "../aws/validate-production-green-stage-b-permissions.mjs";
import { assertStageBBrokerLambdaConfiguration, normalizeStageBBrokerRuntimeVersionConfig, STAGE_B, STAGE_B_APPROVAL_ALGORITHM, STAGE_B_BROKER_TASK_DEFINITION_FAMILIES, STAGE_B_MODES } from "../aws/production-green-stage-b-contract.mjs";
import { assertStableBrokerAliasObservation, authenticateApprovalInputCheckerIdentity, createApprovalInputEvidenceRunners, prepareProductionGreenStageBApprovalInput, writeProductionGreenStageBApprovalInput } from "../aws/prepare-production-green-stage-b-approval-input.mjs";
import { renderStageBTaskDefinition, stageBTemplateHashes } from "../aws/production-green-stage-b-task-definitions.mjs";

const releaseSha = "8d7ecc53a0c8d0ec07dfce1aeb03dc22d0f43f82";
const checkerIdentity = "arn:aws:sts::368992683803:assumed-role/mscqr-production-rls-independent-checker/checker-session";
const deployerIdentity = "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/deployer-session";
const digest = (character) => character.repeat(64);
const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const taskDefinitionArns = Object.fromEntries(STAGE_B_MODES.map((mode) => [mode, `arn:aws:ecs:eu-west-2:368992683803:task-definition/${STAGE_B_BROKER_TASK_DEFINITION_FAMILIES[mode]}:4`]));
const now = new Date("2026-08-31T10:01:00.000Z");
const image = (repository, character) => ({ digest: `sha256:${character.repeat(64)}`, imageReference: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/${repository}@sha256:${character.repeat(64)}` });
const tfvarsBytes = Buffer.from("canonical-tfvars\n");
const report = { tfvarsSha256: sha256(tfvarsBytes), brokerPackageRawSha256: digest("e"), images: { backend: image("mscqr-backend", "b"), worker: image("mscqr-worker", "a"), executor: image("mscqr-backend", "e"), canary: image("mscqr-backend", "c") } };
const bindingReportBytes = Buffer.from(`${JSON.stringify(report)}\n`);
const authorization = { imageEvidenceSha256: digest("d"), authorizationSha256: digest("f"), imageReleaseSha: releaseSha, images: [{ service: "backend", digest: report.images.backend.digest }, { service: "worker", digest: report.images.worker.digest }, { service: "rls-executor", digest: report.images.executor.digest }, { service: "rls-canary", digest: report.images.canary.digest }] };
const brokerApprovalExpected = { releaseSha, sourceContractSha256: digest("a"), migrationSetDigest: digest("b"), packageChecksumSha256: digest("c"), deploymentId: "phase2", greenDatabaseName: "mscqr_production_rls_green_phase2", administratorIdentity: "mscqr_prod_admin", databaseSecurityGroupId: STAGE_B.databaseSecurityGroupId, executorSecurityGroupId: STAGE_B.executorSecurityGroupId };
const brokerImages = { backendImageDigest: report.images.backend.imageReference, workerImageDigest: report.images.worker.imageReference, executorImageDigest: report.images.executor.imageReference, canaryImageDigest: report.images.canary.imageReference };
const taskDefinitionReadbacks = Object.fromEntries(STAGE_B_MODES.map((mode) => {
  const kind = mode === "full-rls-application-canary" ? "canary" : "executor";
  const definition = renderStageBTaskDefinition(kind, { imageReleaseSha: releaseSha, sourceContractSha256: brokerApprovalExpected.sourceContractSha256, migrationSetDigest: brokerApprovalExpected.migrationSetDigest, packageChecksumSha256: brokerApprovalExpected.packageChecksumSha256, receiptBucket: STAGE_B.receiptBucket, executorLogGroup: STAGE_B.executorLogGroupName, canaryLogGroup: STAGE_B.canaryLogGroupName, backendLogGroup: "/ecs/mscqr-production/rls-green-backend", workerLogGroup: "/ecs/mscqr-production/rls-green-worker", [`${kind}Image`]: kind === "canary" ? report.images.canary.imageReference : report.images.executor.imageReference, ...(kind === "executor" ? { mode } : {}) });
  return [mode, { taskDefinition: { ...definition, taskDefinitionArn: taskDefinitionArns[mode], revision: 4, status: "ACTIVE" } }];
}));
const awsNormalizedTaskDefinitionReadbacks = Object.fromEntries(Object.entries(taskDefinitionReadbacks).map(([mode, value]) => {
  const definition = structuredClone(value.taskDefinition);
  delete definition.containerDefinitions[0].cpu;
  definition.containerDefinitions[0].environmentFiles = [];
  definition.containerDefinitions[0].mountPoints = definition.containerDefinitions[0].mountPoints || [];
  definition.containerDefinitions[0].portMappings = definition.containerDefinitions[0].portMappings || [];
  definition.containerDefinitions[0].systemControls = [];
  definition.containerDefinitions[0].ulimits = [];
  definition.containerDefinitions[0].volumesFrom = [];
  definition.containerDefinitions[0].logConfiguration = { ...definition.containerDefinitions[0].logConfiguration, secretOptions: [] };
  definition.placementConstraints = [];
  definition.volumes = definition.volumes || [];
  definition.enableFaultInjection = false;
  return [mode, { taskDefinition: Object.fromEntries(Object.entries(definition).reverse()) }];
}));
const preflight = (overrides = {}) => ({ status: "ready-for-plan", sourceSha: releaseSha, caller: deployerIdentity, account: STAGE_B.account, region: STAGE_B.region, backendReady: true, stateReady: true, handoffReady: true, tfvarsReady: true, failed: [], skipped: [], requiredReads: { "ecs:DescribeTasks": "allowed" }, total: 1, allowed: 1, checkerTrust: { exact: true, mfaRequired: true, principal: CHECKER_USER_ARN, roleArn: CHECKER_SOURCE_ROLE_ARN }, administratorReportSha256: digest("b"), releaseReadFailures: 0, configurationFailures: 0, unmappedCalls: 0, unclassifiedCapabilities: 0, identityBoundaryViolations: 0, sourceLivePolicyMismatches: 0, administratorSimulationFailures: 0, tfvarsSha256: report.tfvarsSha256, bindingReportSha256: sha256(bindingReportBytes), ...overrides });
const live = (overrides = {}) => {
  const base = { observedAt: now.toISOString(), configuration: { FunctionName: STAGE_B.brokerLambdaConfiguration.functionName, FunctionArn: STAGE_B.brokerAliasArn, Version: "4", CodeSha256: Buffer.from(report.brokerPackageRawSha256, "hex").toString("base64"), Role: STAGE_B.brokerLambdaConfiguration.role, Handler: STAGE_B.brokerLambdaConfiguration.handler, Runtime: STAGE_B.brokerLambdaConfiguration.runtime, Architectures: [...STAGE_B.brokerLambdaConfiguration.architectures], Timeout: STAGE_B.brokerLambdaConfiguration.timeout, MemorySize: STAGE_B.brokerLambdaConfiguration.memorySize, PackageType: STAGE_B.brokerLambdaConfiguration.packageType, EphemeralStorage: { ...STAGE_B.brokerLambdaConfiguration.ephemeralStorage }, Layers: [], FileSystemConfigs: [], DeadLetterConfig: {}, VpcConfig: { VpcId: "", SubnetIds: [], SecurityGroupIds: [], Ipv6AllowedForDualStack: false }, SnapStart: { ApplyOn: "None" }, TracingConfig: { Mode: "PassThrough" }, Environment: { Variables: { BROKER_CLUSTER_ARN: STAGE_B.clusterArn, BROKER_APPROVAL_SECRET_ARN: STAGE_B.approvalSecretArn, BROKER_EXECUTOR_SECURITY_GROUP_ID: STAGE_B.executorSecurityGroupId, BROKER_PRIVATE_SUBNETS_JSON: JSON.stringify(STAGE_B.privateSubnetIds), BROKER_REPLAY_TABLE: STAGE_B.replayTable, BROKER_RECEIPT_BUCKET: STAGE_B.receiptBucket, BROKER_TASK_DEFINITIONS_JSON: JSON.stringify(taskDefinitionArns), BROKER_TASK_TEMPLATE_HASHES_JSON: JSON.stringify(stageBTemplateHashes()), BROKER_APPROVAL_EXPECTED_JSON: JSON.stringify(brokerApprovalExpected), BROKER_IMAGES_JSON: JSON.stringify(brokerImages) } } }, alias: { AliasArn: STAGE_B.brokerAliasArn, Name: STAGE_B.brokerAliasQualifier, FunctionVersion: "4" }, taskDefinitions: taskDefinitionReadbacks };
  return { ...base, ...overrides, configuration: overrides.configuration || base.configuration, alias: overrides.alias || base.alias, taskDefinitions: overrides.taskDefinitions || base.taskDefinitions };
};

function signedPreflightTrust(reportValue = preflight(), source = releaseSha) {
  const reportBytes = Buffer.from(`${JSON.stringify(reportValue)}\n`);
  const attestation = buildReleasePreflightCheckerTrustAttestation({ report: reportValue, reportBytes, sourceSha: source, administratorReportSha256: reportValue.administratorReportSha256 });
  const attestationBytes = Buffer.from(`${JSON.stringify(attestation)}\n`);
  const signatureArtifact = signPermissionReport(attestation, { now: now.toISOString(), reportBytes: attestationBytes, sign: () => "AQ==" });
  const signatureBytes = Buffer.from(`${JSON.stringify(signatureArtifact)}\n`);
  return { reportBytes, attestation, attestationBytes, signatureArtifact, signatureBytes };
}

function evidence(overrides = {}) {
  const selectedPreflight = { ...preflight(overrides.preflight), stageBApprovalLiveObservation: live(overrides.live) };
  const trust = overrides.trust || signedPreflightTrust(overrides.trustReport || selectedPreflight, overrides.trustSource || releaseSha);
  return collectProductionGreenStageBApprovalEvidence({ sourceSha: releaseSha, imageAuthorization: authorization, tfvarsPath: "/secure/t.tfvars", bindingReportPath: "/secure/t.json", releasePreflightPath: "/secure/preflight.json", checkerIdentity, now, validateImageAuthorization: () => {}, validateTfvarsBinding: () => ({ ...report, ...(overrides.report || {}) }), deriveContracts: () => ({ sourceContractSha256: digest("a"), migrationSetDigest: digest("b"), packageChecksumSha256: digest("c") }), readTfvarsBinding: () => ({ tfvarsBytes, bindingReportBytes }), readPreflight: () => selectedPreflight, releasePreflightTrustEvidence: trust, verifyReleasePreflightAttestationSignature: () => true }).evidence;
}

test("approval-input authenticates the release runner before root-attestation verification", async () => {
  const checkerCalls = [];
  const releaseCalls = [];
  const rootAttestationActions = ["describe-key", "get-key-policy", "list-resource-tags", "verify"];
  const createRunner = ({ credentialSource, profile }) => {
    if (credentialSource === "inherited-checker-session") return (args) => {
      checkerCalls.push(args);
      if (args[0] === "kms") throw new Error("checker must not verify root attestations");
      return JSON.stringify({ Arn: checkerIdentity });
    };
    assert.equal(credentialSource, "named-profile");
    assert.equal(profile, "mscqr-production-release-deployer");
    return (args) => {
      releaseCalls.push(args);
      return args[0] === "sts" ? JSON.stringify({ Arn: deployerIdentity }) : "true";
    };
  };
  const routes = await createApprovalInputEvidenceRunners({
    createRunner,
    verifyImageEvidence: ({ run }) => rootAttestationActions.forEach((action) => run(["kms", action])),
    createReleasePreflightTrustVerifier: ({ releaseRun }) => () => rootAttestationActions.forEach((action) => releaseRun(["kms", action])),
  });
  assert.equal(routes.releaseIdentity.roleArn, RELEASE_ROLE_ARN);
  assert.equal(authenticateApprovalInputCheckerIdentity(routes.checkerRun), checkerIdentity);
  assert.doesNotThrow(() => routes.verifyImageEvidence({}));
  assert.doesNotThrow(() => routes.verifyReleasePreflightAttestationSignature({}));
  assert.deepEqual(checkerCalls.map(([service, action]) => [service, action]), [["sts", "get-caller-identity"]]);
  assert.deepEqual(releaseCalls.map(([service, action]) => [service, action]), [["sts", "get-caller-identity"], ...[...rootAttestationActions, ...rootAttestationActions].map((action) => ["kms", action])]);
});

test("approval-input rejects substitute release identities before KMS", async () => {
  for (const substitute of ["arn:aws:iam::368992683803:root", checkerIdentity, "arn:aws:sts::368992683803:assumed-role/other-role/session", "arn:aws:iam::368992683803:user/operator"]) {
    const releaseCalls = [];
    await assert.rejects(() => createApprovalInputEvidenceRunners({
      createRunner: ({ credentialSource }) => credentialSource === "inherited-checker-session"
        ? () => JSON.stringify({ Arn: checkerIdentity })
        : (args) => { releaseCalls.push(args); return JSON.stringify({ Arn: substitute }); },
      verifyImageEvidence: () => true,
      createReleasePreflightTrustVerifier: () => () => true,
    }), /Caller is not the reviewed assumed role/);
    assert.deepEqual(releaseCalls.map(([service, action]) => [service, action]), [["sts", "get-caller-identity"]]);
  }
});

test("approval-input fails closed when either mandatory principal fails", async () => {
  const releaseFailure = await createApprovalInputEvidenceRunners({
    createRunner: ({ credentialSource }) => credentialSource === "inherited-checker-session"
      ? () => JSON.stringify({ Arn: checkerIdentity })
      : (args) => args[0] === "sts" ? JSON.stringify({ Arn: deployerIdentity }) : (() => { throw new Error("release root-attestation verification denied"); })(),
    verifyImageEvidence: ({ run }) => run(["kms", "describe-key"]),
    createReleasePreflightTrustVerifier: ({ releaseRun }) => () => releaseRun(["kms", "verify"]),
  });
  assert.throws(() => releaseFailure.verifyImageEvidence({}), /release root-attestation verification denied/);
  assert.throws(() => releaseFailure.verifyReleasePreflightAttestationSignature({}), /release root-attestation verification denied/);
  const checkerFailure = await createApprovalInputEvidenceRunners({
    createRunner: ({ credentialSource }) => credentialSource === "inherited-checker-session"
      ? () => { throw new Error("checker identity denied"); }
      : () => JSON.stringify({ Arn: deployerIdentity }),
    verifyImageEvidence: () => true,
    createReleasePreflightTrustVerifier: () => () => true,
  });
  assert.throws(() => authenticateApprovalInputCheckerIdentity(checkerFailure.checkerRun), /checker identity denied/);
});

test("canonical collector produces evidence accepted by the existing creator", async () => {
  const result = await prepareProductionGreenStageBApprovalInput({ evidence: evidence(), protectedSourceSha: releaseSha, operator: { ticketId: "CHG-STAGE-B-0001" }, now, randomUuid: () => "12345678-1234-1234-1234-123456789abc" });
  assert.equal(result.input.approvalId, `APR-STAGE-B-${releaseSha}`);
  assert.equal(result.input.signatureAlgorithm, STAGE_B_APPROVAL_ALGORITHM);
  assert.deepEqual(result.input.taskDefinitionTemplateHashes, stageBTemplateHashes());
  await assert.doesNotReject(() => prepareStageBApproval(result.input, { now }));
});

test("fabricated evidence and self-declared provenance cannot enter the producer", async () => {
  await assert.rejects(() => prepareProductionGreenStageBApprovalInput({ evidence: { ...evidence() }, protectedSourceSha: releaseSha, operator: { ticketId: "CHG-STAGE-B-0001" }, now }), /canonical authenticated evidence/);
});

test("unsigned ready-for-plan, forged permissions, or a modified attested report is rejected", () => {
  assert.throws(() => collectProductionGreenStageBApprovalEvidence({ sourceSha: releaseSha, imageAuthorization: authorization, checkerIdentity, now, validateImageAuthorization: () => {}, validateTfvarsBinding: () => report, readTfvarsBinding: () => ({ tfvarsBytes, bindingReportBytes }), readPreflight: () => ({ ...preflight(), stageBApprovalLiveObservation: live() }) }), /attestation|trust/i);
  assert.throws(() => evidence({ preflight: { caller: "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/forged" }, trustReport: preflight() }), /attestation|bound/i);
});

test("runtime approval preparation stops before creation because PLAN_APPROVED, not a guessed live version, is the bootstrap authority", () => {
  const selected = preflight();
  const trust = signedPreflightTrust(selected);
  assert.throws(() => collectProductionGreenStageBApprovalEvidence({
    sourceSha: releaseSha, imageAuthorization: authorization, tfvarsPath: "/secure/t.tfvars", bindingReportPath: "/secure/t.json", releasePreflightPath: "/secure/preflight.json", checkerIdentity, now,
    validateImageAuthorization: () => {}, validateTfvarsBinding: () => report, readTfvarsBinding: () => ({ tfvarsBytes, bindingReportBytes }),
    readPreflight: () => selected, releasePreflightTrustEvidence: trust, verifyReleasePreflightAttestationSignature: () => true,
    deriveContracts: () => ({ sourceContractSha256: digest("a"), migrationSetDigest: digest("b"), packageChecksumSha256: digest("c") }),
  }), /PLAN_APPROVED.*resource creation|post-creation/i);
});

test("preflight trust attestation binds source, signature authority, and exact report bytes", () => {
  assert.throws(() => evidence({ trustSource: "f".repeat(40) }), /source|attestation/i);
  const trust = signedPreflightTrust();
  const wrongSigner = { ...trust, signatureArtifact: { ...trust.signatureArtifact, keyArn: "arn:aws:kms:eu-west-2:368992683803:key/wrong" } };
  assert.throws(() => evidence({ trust: wrongSigner }), /signature|identity|key|bound/i);
  assert.throws(() => evidence({ preflight: { status: "blocked" }, trustReport: preflight() }), /bound|attestation/i);
});

test("same-source evidence expires instead of receiving a fresh approval lifetime", async () => {
  const collected = evidence();
  await assert.rejects(() => prepareProductionGreenStageBApprovalInput({ evidence: collected, protectedSourceSha: releaseSha, operator: { ticketId: "CHG-STAGE-B-0001" }, now: new Date("2026-08-31T11:01:00.000Z") }), /stale/);
});

test("collector preserves the attested live-observation capture time", () => {
  const stale = new Date(now.getTime() - 60 * 60 * 1000).toISOString();
  assert.throws(() => evidence({ live: { observedAt: stale } }), /stale|expired/i);
  const future = new Date(now.getTime() + 61_000).toISOString();
  assert.throws(() => evidence({ live: { observedAt: future } }), /future/i);
  assert.throws(() => evidence({ live: { observedAt: "not-a-timestamp" } }), /malformed/i);
});

for (const [label, overrides] of [
  ["blocked status", { preflight: { status: "blocked" } }],
  ["denied read", { preflight: { requiredReads: { "ecs:DescribeTasks": "denied" }, failed: [{ id: "read", action: "ecs:DescribeTasks" }] } }],
  ["incomplete readiness", { preflight: { tfvarsReady: false } }],
  ["wrong tfvars digest", { preflight: { tfvarsSha256: digest("c") } }],
  ["wrong binding report digest", { preflight: { bindingReportSha256: digest("c") } }],
]) test(`collector rejects ${label} preflight`, () => assert.throws(() => evidence(overrides), /preflight|tfvars|binding/i));

test("collector accepts order-independent live broker JSON", () => {
  const reverse = (value) => Object.fromEntries(Object.entries(value).reverse());
  const current = live().configuration;
  const variables = current.Environment.Variables;
  const reordered = { ...variables, BROKER_IMAGES_JSON: JSON.stringify(reverse(brokerImages)), BROKER_APPROVAL_EXPECTED_JSON: JSON.stringify(reverse(brokerApprovalExpected)), BROKER_TASK_TEMPLATE_HASHES_JSON: JSON.stringify(reverse(stageBTemplateHashes())), BROKER_TASK_DEFINITIONS_JSON: JSON.stringify(reverse(taskDefinitionArns)) };
  assert.doesNotThrow(() => evidence({ live: { configuration: { ...current, Environment: { Variables: reordered } } } }));
});

for (const field of Object.keys(brokerApprovalExpected)) test(`collector rejects live broker approval ${field} drift`, () => {
  const changed = { ...brokerApprovalExpected, [field]: field === "releaseSha" ? "f".repeat(40) : field.endsWith("Sha256") ? digest("d") : `${brokerApprovalExpected[field]}-changed` };
  const variables = { ...live().configuration.Environment.Variables, BROKER_APPROVAL_EXPECTED_JSON: JSON.stringify(changed) };
  assert.throws(() => evidence({ live: { configuration: { ...live().configuration, Environment: { Variables: variables } } } }), /broker|binding|contract/i);
});

for (const field of ["backendImageDigest", "workerImageDigest", "executorImageDigest", "canaryImageDigest"]) test(`collector rejects live broker ${field} drift`, () => {
  const changed = { ...brokerImages, [field]: brokerImages[field].replace(/[a-f0-9]{64}$/, "d".repeat(64)) };
  const variables = { ...live().configuration.Environment.Variables, BROKER_IMAGES_JSON: JSON.stringify(changed) };
  assert.throws(() => evidence({ live: { configuration: { ...live().configuration, Environment: { Variables: variables } } } }), /broker|image|binding/i);
});

for (const field of STAGE_B_MODES.length ? Object.keys(stageBTemplateHashes()) : []) test(`collector rejects live broker template hash ${field} drift`, () => {
  const changed = { ...stageBTemplateHashes(), [field]: digest("d") };
  const variables = { ...live().configuration.Environment.Variables, BROKER_TASK_TEMPLATE_HASHES_JSON: JSON.stringify(changed) };
  assert.throws(() => evidence({ live: { configuration: { ...live().configuration, Environment: { Variables: variables } } } }), /broker|template|binding/i);
});

for (const [label, mutate] of [
  ["backend image", () => ({ report: { images: { ...report.images, backend: { digest: `sha256:${"9".repeat(64)}` } } } })],
  ["task map", () => ({ live: { configuration: { ...live().configuration, Environment: { Variables: { ...live().configuration.Environment.Variables, BROKER_TASK_DEFINITIONS_JSON: JSON.stringify({ ...taskDefinitionArns, rogue: taskDefinitionArns[STAGE_B_MODES[0]] }) } } } } })],
  ["broker binding", () => ({ live: { alias: { ...live().alias, FunctionVersion: "5" } } })],
]) test(`collector rejects current runtime ${label} drift`, () => assert.throws(() => evidence(mutate()), /match|broker|version|binding/i));

test("collector binds the alias-resolved Lambda code bytes, not only its environment", () => {
  assert.throws(() => evidence({ live: { configuration: { ...live().configuration, CodeSha256: Buffer.from(digest("f"), "hex").toString("base64") } } }), /Lambda configuration|package/);
  assert.throws(() => evidence({ report: { brokerPackageRawSha256: "f".repeat(63) } }), /Lambda configuration|package raw SHA256|malformed/);
  assert.throws(() => evidence({ live: { configuration: { ...live().configuration, CodeSha256: "not-base64" } } }), /Lambda configuration|CodeSha256|malformed/);
});

test("production-shaped Lambda configuration fixture binds the reviewed executable contract", () => {
  const configuration = JSON.parse(fs.readFileSync("scripts/tests/fixtures/production-stage-b-broker-get-function-configuration.json", "utf8"));
  const result = assertStageBBrokerLambdaConfiguration({ configuration, alias: live().alias, brokerPackageRawSha256: report.brokerPackageRawSha256 });
  assert.deepEqual(result.configuration.RuntimeVersionConfig, configuration.RuntimeVersionConfig);
});

const runtimeVersionArn = "arn:aws:lambda:eu-west-2::runtime:8eeff65f6809a3ce81507fe733fe09b835899b99481ba22fd75b5a7338290ec1";

test("RuntimeVersionConfig accepts absent or opaque AWS-managed runtime state and binds it canonically", () => {
  assert.deepEqual(normalizeStageBBrokerRuntimeVersionConfig(undefined), null);
  assert.deepEqual(normalizeStageBBrokerRuntimeVersionConfig({ RuntimeVersionArn: runtimeVersionArn }), { RuntimeVersionArn: runtimeVersionArn });
  const absent = evidence().runtimeBindingSha256;
  const observed = evidence({ live: { configuration: { ...live().configuration, RuntimeVersionConfig: { RuntimeVersionArn: runtimeVersionArn } } } }).runtimeBindingSha256;
  assert.notEqual(absent, observed);
  const otherObserved = evidence({ live: { configuration: { ...live().configuration, RuntimeVersionConfig: { RuntimeVersionArn: `${runtimeVersionArn.slice(0, -1)}2` } } } }).runtimeBindingSha256;
  assert.notEqual(observed, otherObserved);
});

test("RuntimeVersionConfig rejects invalid managed-runtime ARNs and malformed shapes", () => {
  for (const value of [
    { RuntimeVersionArn: "arn:aws-us-gov:lambda:eu-west-2::runtime:opaque" },
    { RuntimeVersionArn: "arn:aws:s3:eu-west-2::runtime:opaque" },
    { RuntimeVersionArn: "arn:aws:lambda:us-east-1::runtime:opaque" },
    { RuntimeVersionArn: "arn:aws:lambda:eu-west-2::function:opaque" },
    { RuntimeVersionArn: "arn:aws:lambda:eu-west-2::runtime:" },
    null,
    [],
    { Unknown: true },
    { RuntimeVersionArn: runtimeVersionArn, Unknown: true },
  ]) assert.throws(() => normalizeStageBBrokerRuntimeVersionConfig(value), /runtime|malformed|unknown/i);
});

test("RuntimeVersionConfig rejects documented runtime retrieval errors after validating their shape", () => {
  assert.throws(() => normalizeStageBBrokerRuntimeVersionConfig({ Error: { ErrorCode: "InvalidRuntime", Message: "redacted test detail" } }), /retrieval|runtime/i);
  assert.throws(() => normalizeStageBBrokerRuntimeVersionConfig({ Error: { ErrorCode: 42 } }), /malformed|unknown/i);
  assert.throws(() => normalizeStageBBrokerRuntimeVersionConfig({ Error: { ErrorCode: "InvalidRuntime", Unexpected: true } }), /malformed|unknown/i);
  assert.throws(() => normalizeStageBBrokerRuntimeVersionConfig({ ErrorCode: "InvalidRuntime" }), /malformed|unknown/i);
});

test("canonical Lambda logging and disabled optional configuration defaults are accepted", () => {
  const configuration = { ...live().configuration, LoggingConfig: { LogFormat: "Text", LogGroup: "/aws/lambda/mscqr-production-rls-approval-broker", SystemLogLevel: "INFO" }, KMSKeyArn: "" };
  assert.doesNotThrow(() => assertStageBBrokerLambdaConfiguration({ configuration, alias: live().alias, brokerPackageRawSha256: report.brokerPackageRawSha256 }));
});

test("collector and Lambda configuration reject weighted reviewed-alias routing", () => {
  const alias = { ...live().alias, RoutingConfig: { AdditionalVersionWeights: { "5": 0.01 } } };
  assert.throws(() => assertStageBBrokerLambdaConfiguration({ configuration: live().configuration, alias, brokerPackageRawSha256: report.brokerPackageRawSha256 }), /routing|unreviewed/i);
  assert.throws(() => evidence({ live: { alias } }), /routing|unreviewed/i);
});

for (const [field, value] of [
  ["Role", "arn:aws:iam::368992683803:role/unreviewed"], ["Handler", "unreviewed.handler"], ["Runtime", "nodejs22.x"],
  ["Architectures", ["arm64"]], ["Timeout", 181], ["MemorySize", 256], ["PackageType", "Image"],
  ["EphemeralStorage", { Size: 1024 }], ["Layers", ["arn:aws:lambda:eu-west-2:368992683803:layer:unreviewed:1"]], ["LoggingConfig", { LogFormat: "JSON" }],
  ["KMSKeyArn", "arn:aws:kms:eu-west-2:368992683803:key/unreviewed"], ["CodeSigningConfigArn", "arn:aws:lambda:eu-west-2:368992683803:code-signing-config:csc-unreviewed"],
  ["FileSystemConfigs", [{ Arn: "arn:aws:elasticfilesystem:eu-west-2:368992683803:access-point/fsap-unreviewed", LocalMountPath: "/mnt" }]],
  ["DeadLetterConfig", { TargetArn: "arn:aws:sqs:eu-west-2:368992683803:unreviewed" }],
  ["VpcConfig", { VpcId: "vpc-unreviewed", SubnetIds: ["subnet-unreviewed"], SecurityGroupIds: ["sg-unreviewed"] }],
  ["SnapStart", { ApplyOn: "PublishedVersions" }], ["TracingConfig", { Mode: "Active" }],
]) test(`collector rejects broker Lambda ${field} drift`, () => {
  assert.throws(() => evidence({ live: { configuration: { ...live().configuration, [field]: value } } }), /Lambda configuration|broker/i);
});

test("collector rejects an exact-shaped but wrong replay table", () => {
  const variables = { ...live().configuration.Environment.Variables, BROKER_REPLAY_TABLE: "mscqr-production-rls-stage-b-replay-shadow" };
  assert.throws(() => evidence({ live: { configuration: { ...live().configuration, Environment: { Variables: variables } } } }), /runtime bindings/i);
});

for (const [field, value] of [
  ["BROKER_CLUSTER_ARN", "arn:aws:ecs:eu-west-2:368992683803:cluster/unreviewed"],
  ["BROKER_APPROVAL_SECRET_ARN", "arn:aws:secretsmanager:eu-west-2:368992683803:secret:unreviewed"],
  ["BROKER_EXECUTOR_SECURITY_GROUP_ID", "sg-unreviewed"], ["BROKER_RECEIPT_BUCKET", "unreviewed-receipts"],
  ["BROKER_REPLAY_TABLE", "mscqr-production-rls-stage-b-replay-shadow"],
  ["BROKER_PRIVATE_SUBNETS_JSON", JSON.stringify([STAGE_B.privateSubnetIds[0], "subnet-unreviewed"])],
  ["BROKER_PRIVATE_SUBNETS_JSON", JSON.stringify([...STAGE_B.privateSubnetIds, "subnet-unreviewed"])],
]) test(`collector rejects exact runtime binding drift: ${field}`, () => {
  const variables = { ...live().configuration.Environment.Variables, [field]: value };
  assert.throws(() => evidence({ live: { configuration: { ...live().configuration, Environment: { Variables: variables } } } }), /runtime bindings/i);
});

test("collector rejects missing or unexpected broker runtime environment bindings", () => {
  const variables = { ...live().configuration.Environment.Variables };
  delete variables.BROKER_REPLAY_TABLE;
  assert.throws(() => evidence({ live: { configuration: { ...live().configuration, Environment: { Variables: variables } } } }), /Lambda configuration/i);
  assert.throws(() => evidence({ live: { configuration: { ...live().configuration, Environment: { Variables: { ...live().configuration.Environment.Variables, BROKER_UNREVIEWED_TARGET: "value" } } } } }), /Lambda configuration/i);
});

test("attested report bytes cannot be replayed with a modified observation timestamp", () => {
  const selected = { ...preflight(), stageBApprovalLiveObservation: live() };
  const trust = signedPreflightTrust(selected);
  assert.throws(() => collectProductionGreenStageBApprovalEvidence({
    sourceSha: releaseSha, imageAuthorization: authorization, checkerIdentity, now, validateImageAuthorization: () => {}, validateTfvarsBinding: () => report,
    readTfvarsBinding: () => ({ tfvarsBytes, bindingReportBytes }), readPreflight: () => ({ ...selected, stageBApprovalLiveObservation: { ...selected.stageBApprovalLiveObservation, observedAt: "2026-08-31T10:02:00.000Z" } }),
    releasePreflightTrustEvidence: trust, verifyReleasePreflightAttestationSignature: () => true, deriveContracts: () => ({ sourceContractSha256: digest("a"), migrationSetDigest: digest("b"), packageChecksumSha256: digest("c") }),
  }), /bound|attestation/i);
});

test("qualified broker observation rejects mixed or changed Lambda versions", () => {
  const alias = { AliasArn: STAGE_B.brokerAliasArn, Name: STAGE_B.brokerAliasQualifier, FunctionVersion: "4" };
  const configuration = { FunctionArn: STAGE_B.brokerAliasArn, Version: "4" };
  assert.equal(assertStableBrokerAliasObservation({ initialAlias: alias, confirmedAlias: alias, configuration }), "4");
  assert.throws(() => assertStableBrokerAliasObservation({ initialAlias: alias, confirmedAlias: { ...alias, FunctionVersion: "5" }, configuration }), /changed|version/);
  assert.throws(() => assertStableBrokerAliasObservation({ initialAlias: alias, confirmedAlias: alias, configuration: { ...configuration, Version: "5" } }), /changed|version/);
});

test("collector binds every exact broker task-definition revision to reviewed content", () => {
  const changed = structuredClone(taskDefinitionReadbacks);
  changed[STAGE_B_MODES[0]].taskDefinition.containerDefinitions[0].command = ["node", "unexpected.mjs"];
  assert.throws(() => evidence({ live: { taskDefinitions: changed } }), /task definition|execution contract/i);
  const wrongArn = structuredClone(taskDefinitionReadbacks);
  wrongArn[STAGE_B_MODES[1]].taskDefinition.taskDefinitionArn = taskDefinitionArns[STAGE_B_MODES[0]];
  assert.throws(() => evidence({ live: { taskDefinitions: wrongArn } }), /task definition|execution contract/i);
  const missing = structuredClone(taskDefinitionReadbacks);
  delete missing[STAGE_B_MODES[2]];
  assert.throws(() => evidence({ live: { taskDefinitions: missing } }), /task definition|execution contract/i);
});

test("collector accepts AWS-normalized task readbacks with omitted defaults and reordered keys", () => {
  assert.doesNotThrow(() => evidence({ live: { taskDefinitions: awsNormalizedTaskDefinitionReadbacks } }));
});

test("collector binds one captured binding-report byte sequence for semantics and digest", () => {
  let reads = 0;
  let validatedBytes;
  const selected = { ...preflight(), stageBApprovalLiveObservation: live() };
  const trust = signedPreflightTrust(selected);
  assert.doesNotThrow(() => collectProductionGreenStageBApprovalEvidence({
    sourceSha: releaseSha, imageAuthorization: authorization, tfvarsPath: "/secure/t.tfvars", bindingReportPath: "/secure/t.json", releasePreflightPath: "/secure/preflight.json", checkerIdentity, now,
    validateImageAuthorization: () => {},
    readTfvarsBinding: () => { reads += 1; return { tfvarsBytes, bindingReportBytes }; },
    validateTfvarsBinding: ({ bindingReportBytes: bytes }) => { validatedBytes = bytes; return report; },
    readPreflight: () => selected, releasePreflightTrustEvidence: trust, verifyReleasePreflightAttestationSignature: () => true,
    deriveContracts: () => ({ sourceContractSha256: digest("a"), migrationSetDigest: digest("b"), packageChecksumSha256: digest("c") }),
  }));
  assert.equal(reads, 1);
  assert.equal(validatedBytes, bindingReportBytes);
  const spliced = { ...selected, bindingReportSha256: digest("f") };
  assert.throws(() => collectProductionGreenStageBApprovalEvidence({
    sourceSha: releaseSha, imageAuthorization: authorization, tfvarsPath: "/secure/t.tfvars", bindingReportPath: "/secure/t.json", releasePreflightPath: "/secure/preflight.json", checkerIdentity, now,
    validateImageAuthorization: () => {}, readTfvarsBinding: () => ({ tfvarsBytes, bindingReportBytes }), validateTfvarsBinding: () => report,
    readPreflight: () => spliced, releasePreflightTrustEvidence: signedPreflightTrust(spliced), verifyReleasePreflightAttestationSignature: () => true,
    deriveContracts: () => ({ sourceContractSha256: digest("a"), migrationSetDigest: digest("b"), packageChecksumSha256: digest("c") }),
  }), /binding report/);
});

for (const [label, mutate] of [
  ["image", (definition) => { definition.containerDefinitions[0].image = report.images.executor.imageReference.replace(/e{64}$/, "f".repeat(64)); }],
  ["environment", (definition) => { definition.containerDefinitions[0].environment[0].value = "changed"; }],
  ["secrets", (definition) => { definition.containerDefinitions[0].secrets[0].valueFrom = "arn:aws:secretsmanager:eu-west-2:368992683803:secret:changed"; }],
  ["task role", (definition) => { definition.taskRoleArn = "arn:aws:iam::368992683803:role/changed"; }],
  ["network", (definition) => { definition.networkMode = "bridge"; }],
  ["missing runtime platform", (definition) => { delete definition.runtimePlatform; }],
  ["runtime platform", (definition) => { definition.runtimePlatform = { cpuArchitecture: "ARM64", operatingSystemFamily: "LINUX" }; }],
  ["extra container", (definition) => { definition.containerDefinitions.push(structuredClone(definition.containerDefinitions[0])); }],
]) test(`collector rejects broker task-definition ${label} drift`, () => {
  const changed = structuredClone(taskDefinitionReadbacks);
  mutate(changed[STAGE_B_MODES[0]].taskDefinition);
  assert.throws(() => evidence({ live: { taskDefinitions: changed } }), /task definition|execution contract/i);
});

test("only ticket is operator-controlled; time and nonce are internally derived", async () => {
  const result = await prepareProductionGreenStageBApprovalInput({ evidence: evidence(), protectedSourceSha: releaseSha, operator: { ticketId: "CHG-STAGE-B-0001" }, now, randomUuid: () => "12345678-1234-1234-1234-123456789abc" });
  assert.equal(result.input.issuedAt, now.toISOString()); assert.equal(result.input.expiresAt, "2026-08-31T12:01:00.000Z");
  await assert.rejects(() => prepareProductionGreenStageBApprovalInput({ evidence: evidence(), protectedSourceSha: releaseSha, operator: { ticketId: "CHG-STAGE-B-0001", nonce: "12345678-1234-1234-1234-123456789abc" }, now }), /unexpected/);
});

test("source exposes no caller-controlled evidence hash or time/nonce CLI switches", () => {
  const source = fs.readFileSync(path.resolve("scripts/aws/prepare-production-green-stage-b-approval-input.mjs"), "utf8");
  for (const option of ["--evidence", "--evidence-sha256", "--issued-at", "--expires-at", "--nonce"]) assert.doesNotMatch(source, new RegExp(option));
  assert.match(source, /writeStageBPrivateFilesAtomic/);
  assert.doesNotMatch(source, /checkerRun\(\["(?:lambda|ecs)/);
  assert.match(fs.readFileSync(path.resolve("scripts/aws/run-production-green-stage-b-preflight.mjs"), "utf8"), /capture-stage-b-approval-live-observation/);
});

test("input and mandatory review are an immutable transactional pair", async () => {
  const result = await prepareProductionGreenStageBApprovalInput({ evidence: evidence(), protectedSourceSha: releaseSha, operator: { ticketId: "CHG-STAGE-B-0001" }, now, randomUuid: () => "12345678-1234-1234-1234-123456789abc" });
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-approval-input-test-")); fs.chmodSync(directory, 0o700);
  const input = path.join(directory, "input.json"); const review = path.join(directory, "review.txt");
  const written = writeProductionGreenStageBApprovalInput({ result, outputPath: input, reviewOutputPath: review });
  assert.equal(written.written.sha256, result.inputSha256); assert.match(fs.readFileSync(review, "utf8"), new RegExp(result.inputSha256));
  assert.throws(() => writeProductionGreenStageBApprovalInput({ result, outputPath: input, reviewOutputPath: path.join(directory, "other.txt") }), /overwrite/);
  assert.equal(fs.existsSync(path.join(directory, "other.txt")), false); fs.rmSync(directory, { recursive: true, force: true });
});

test("review output failure rolls back the input", async () => {
  const result = await prepareProductionGreenStageBApprovalInput({ evidence: evidence(), protectedSourceSha: releaseSha, operator: { ticketId: "CHG-STAGE-B-0001" }, now });
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-approval-input-test-")); fs.chmodSync(directory, 0o700);
  const input = path.join(directory, "input.json"); const review = path.join(directory, "review.txt"); const fake = { ...fs, renameSync(from, to) { if (to === review) throw new Error("simulated review commit failure"); return fs.renameSync(from, to); } };
  assert.throws(() => writeProductionGreenStageBApprovalInput({ result, outputPath: input, reviewOutputPath: review, fsOps: fake }), /simulated/);
  assert.equal(fs.existsSync(input), false); assert.equal(fs.existsSync(review), false); fs.rmSync(directory, { recursive: true, force: true });
});
