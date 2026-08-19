import assert from "node:assert/strict";
import crypto from "node:crypto";
import { chmodSync, existsSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { buildStageAStateIdentity } from "../aws/generate-production-green-stage-a-prerequisites.mjs";
import { STAGE_B } from "../aws/production-green-stage-b-contract.mjs";
import { buildStageARootDropKeyPolicy } from "../aws/production-stage-a-control-plane.mjs";
import { TEMPORARY_KMS_CAPABILITY } from "../aws/production-stage-a-temporary-kms-capability.mjs";
import {
  ROOT_DROP_ALIAS_NAME,
  ROOT_DROP_ALIAS_ADDRESS,
  ROOT_DROP_KEY_ADDRESS,
  ROOT_DROP_KEY_DESCRIPTION,
  ROOT_DROP_LEGACY_POLICY_BINDING,
  assertRootDropAliasOnlyPlan,
  assertLegacyRootDropPolicyBinding,
  assertRootDropCensus,
  assertRootDropCreationInterlock,
  assertRootDropPreImportPlan,
  assertRootDropStateIdentity,
  authenticateRootDropOrphan,
  buildRootDropCensus,
  buildRootDropAwsReadAdapter,
  buildLegacyRootDropKeyPolicy,
  collectRootDropCensus,
  rootDropRecoverySha256,
  createRootDropRecoveryRunner,
  STAGE_A_TERRAFORM_BACKEND,
  assertStageATerraformBackendMetadata,
} from "../aws/production-stage-a-root-drop-orphan-recovery.mjs";
import { assertNoAutoLoadedTerraformVariableFiles, assertRootDropExecutionSource, formatRootDropRecoveryFailure, runAdoption, runCensus, validateRootDropPlanPaths, STAGE_A_REQUIRED_TERRAFORM_VARIABLE_KEYS } from "../aws/recover-production-green-stage-a-root-drop-orphan.mjs";
import { buildRecoveryTerraformEnvironment } from "../aws/recover-stage-b-backend-task-definition.mjs";
import { productionStageAState } from "./fixtures/production-stage-a-state.mjs";

const sourceSha = "f03fb3266385486d25317b8c2b202c408ae8771f";
const transitionId = "stage-a-root-drop-orphan-recovery-20260819";
const keyId = "11111111-1111-1111-1111-111111111111";
const keyArn = `arn:aws:kms:${STAGE_B.region}:${STAGE_B.account}:key/${keyId}`;
const legacyKeyId = ROOT_DROP_LEGACY_POLICY_BINDING.keyArn.split("/").at(-1);
const legacyKeyArn = ROOT_DROP_LEGACY_POLICY_BINDING.keyArn;
const state = productionStageAState({ serial: 46 });
const absentState = { ...state, resources: state.resources.map((resource) => (resource.type === "aws_kms_key" && resource.name === "root_drop") || (resource.type === "aws_kms_alias" && resource.name === "root_drop") ? { ...resource, instances: [] } : resource) };
const stateBytes = Buffer.from(JSON.stringify(absentState));
const stateIdentity = buildStageAStateIdentity(absentState, { stateBytes });
const cleanGit = (head = sourceSha, status = "", ignored = "", trackedModes = "") => (args) => {
  if (args[0] === "rev-parse" && args[1] === "HEAD") return `${head}\n`;
  if (args[0] === "rev-parse" && args[1] === "--show-toplevel") return `${realpathSync(process.cwd())}\n`;
  if (args[0] === "rev-parse" && args[1] === "--is-shallow-repository") return "false\n";
  if (args[0] === "status" && args.includes("--ignored=matching")) return ignored;
  if (args[0] === "status") return status;
  if (args[0] === "ls-files") return trackedModes;
  throw new Error(`unexpected git command: ${args.join(" ")}`);
};
const stageAVars = Object.freeze({
  TF_VAR_aws_region: STAGE_B.region,
  TF_VAR_vpc_id: "vpc-00000000",
  TF_VAR_private_subnet_ids: '["subnet-00000000"]',
  TF_VAR_runtime_security_group_ids: '["sg-00000000"]',
  TF_VAR_s3_prefix_list_id: "pl-00000000",
  TF_VAR_vpc_dns_resolver_cidr: "10.0.0.2/32",
  TF_VAR_checker_principal_arns: `["arn:aws:iam::${STAGE_B.account}:role/mscqr-production-independent-checker"]`,
  TF_VAR_release_role_arn: `arn:aws:iam::${STAGE_B.account}:role/mscqr-production-release-deployer`,
  TF_VAR_receipt_bucket_arn: `arn:aws:s3:::mscqr-prod-euw2-artifacts-${STAGE_B.account}-${STAGE_B.region}-an`,
});
const failedApplyEvidence = { sourceSha, transitionId, planSha256: crypto.createHash("sha256").update("exact-plan").digest("hex"), creatorArn: "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/launch", creationEventId: "event-root-drop-1", failedApplyWindow: { start: "2026-08-19T00:00:00.000Z", end: "2026-08-19T23:59:59.999Z" } };
const legacyFailedApplyEvidence = { ...failedApplyEvidence, sourceSha: ROOT_DROP_LEGACY_POLICY_BINDING.sourceSha, transitionId: ROOT_DROP_LEGACY_POLICY_BINDING.transitionId, planSha256: ROOT_DROP_LEGACY_POLICY_BINDING.planSha256, creationEventId: ROOT_DROP_LEGACY_POLICY_BINDING.creationEventId, stageAStateIdentity: ROOT_DROP_LEGACY_POLICY_BINDING.stageAStateIdentity };
const event = { eventId: failedApplyEvidence.creationEventId, eventName: "CreateKey", eventSource: "kms.amazonaws.com", awsRegion: STAGE_B.region, recipientAccountId: STAGE_B.account, eventTime: "2026-08-19T12:00:00.000Z", userIdentity: { arn: failedApplyEvidence.creatorArn }, resources: [{ ARN: keyArn }] };
const awsLookupEvent = { EventId: event.eventId, EventName: event.eventName, EventSource: event.eventSource, EventTime: event.eventTime, CloudTrailEvent: JSON.stringify({ eventID: event.eventId, eventName: event.eventName, eventSource: event.eventSource, awsRegion: event.awsRegion, recipientAccountId: event.recipientAccountId, eventTime: event.eventTime, userIdentity: event.userIdentity, resources: event.resources }) };
const candidate = (overrides = {}) => ({
  keyId,
  metadata: { KeyId: keyId, Arn: keyArn, AWSAccountId: STAGE_B.account, KeyState: "Enabled", KeyManager: "CUSTOMER", Origin: "AWS_KMS", KeySpec: "RSA_3072", KeyUsage: "SIGN_VERIFY", MultiRegion: false, Description: ROOT_DROP_KEY_DESCRIPTION },
  tags: { ...TEMPORARY_KMS_CAPABILITY.tags },
  policy: buildStageARootDropKeyPolicy(),
  publicKey: { KeyId: keyId, KeySpec: "RSA_3072", KeyUsage: "SIGN_VERIFY", SigningAlgorithms: ["RSASSA_PSS_SHA_256"] },
  aliases: [],
  creationEvents: [event],
  ...overrides,
});
const legacyCandidate = (overrides = {}) => candidate({
  keyId: legacyKeyId,
  metadata: { ...candidate().metadata, KeyId: legacyKeyId, Arn: legacyKeyArn },
  policy: buildLegacyRootDropKeyPolicy(),
  creationEvents: [{ ...event, eventId: ROOT_DROP_LEGACY_POLICY_BINDING.creationEventId, resources: [{ ARN: legacyKeyArn }] }],
  ...overrides,
});
const realAwsAdapter = () => buildRootDropAwsReadAdapter({ profile: "administrator", run: (args) => {
  if (args[0] === "kms" && args[1] === "list-keys") return JSON.stringify({ Keys: [{ KeyId: keyId }] });
  if (args[0] === "kms" && args[1] === "describe-key") return JSON.stringify({ KeyMetadata: candidate().metadata });
  if (args[0] === "kms" && args[1] === "list-resource-tags") return JSON.stringify({ Tags: Object.entries(candidate().tags).map(([TagKey, TagValue]) => ({ TagKey, TagValue })) });
  if (args[0] === "kms" && args[1] === "get-key-policy") return JSON.stringify({ Policy: encodeURIComponent(JSON.stringify(candidate().policy)) });
  if (args[0] === "kms" && args[1] === "get-public-key") return JSON.stringify(candidate().publicKey);
  if (args[0] === "kms" && args[1] === "list-aliases") return JSON.stringify({ Aliases: [] });
  if (args[0] === "cloudtrail") return JSON.stringify({ Events: [awsLookupEvent] });
  throw new Error(`unexpected read ${args.join(" ")}`);
}});
const realAwsCensus = () => collectRootDropCensus({ adapter: realAwsAdapter(), terraformState: absentState, sourceSha, transitionId, stageAStateIdentity: stateIdentity, failedApplyEvidence });
const authenticated = () => authenticateRootDropOrphan({ candidate: candidate(), terraformState: absentState, sourceSha, transitionId, failedApplyEvidence });
const census = () => buildRootDropCensus({ sourceSha, transitionId, stageAStateIdentity: stateIdentity, keyUniverse: [keyId], candidates: [{ ...candidate(), ...authenticated() }], failedApplyEvidence });
const noCandidateCensus = () => buildRootDropCensus({ sourceSha, transitionId, stageAStateIdentity: stateIdentity, keyUniverse: [], candidates: [] });
const exactCreatePlan = { resource_changes: [
  { address: ROOT_DROP_KEY_ADDRESS, type: "aws_kms_key", change: { before: null, actions: ["create"], after: { description: ROOT_DROP_KEY_DESCRIPTION, policy: JSON.stringify(buildStageARootDropKeyPolicy()), customer_master_key_spec: "RSA_3072", key_usage: "SIGN_VERIFY", deletion_window_in_days: 30, bypass_policy_lockout_safety_check: false, tags: { ...TEMPORARY_KMS_CAPABILITY.tags } } } },
  { address: ROOT_DROP_ALIAS_ADDRESS, type: "aws_kms_alias", change: { before: null, actions: ["create"], after: { name: ROOT_DROP_ALIAS_NAME, target_key_id: null }, after_unknown: { target_key_id: true } } },
], configuration: { root_module: { resources: [{ address: ROOT_DROP_ALIAS_ADDRESS, expressions: { name: { constant_value: ROOT_DROP_ALIAS_NAME }, target_key_id: { references: [`${ROOT_DROP_KEY_ADDRESS}.key_id`] } } }] } } };
const aliasPlan = (changes = [{ address: ROOT_DROP_ALIAS_ADDRESS, change: { actions: ["create"], after: { name: ROOT_DROP_ALIAS_NAME, target_key_id: keyId } } }]) => ({ resource_changes: changes });
const legacyAliasPolicyPlan = ({ key = legacyKeyId, beforePolicy = buildLegacyRootDropKeyPolicy(), afterPolicy = buildStageARootDropKeyPolicy() } = {}) => ({ resource_changes: [
  { address: ROOT_DROP_KEY_ADDRESS, type: "aws_kms_key", change: { before: { policy: JSON.stringify(beforePolicy) }, actions: ["update"], after: { policy: JSON.stringify(afterPolicy) }, replace_paths: [] } },
  { address: ROOT_DROP_ALIAS_ADDRESS, type: "aws_kms_alias", change: { actions: ["create"], after: { name: ROOT_DROP_ALIAS_NAME, target_key_id: key }, replace_paths: [] } },
] });
const keyState = () => ({ ...absentState, resources: absentState.resources.map((resource) => resource.type === "aws_kms_key" && resource.name === "root_drop" ? { ...resource, instances: [{ schema_version: 0, attributes: { arn: keyArn, key_id: keyId, key_usage: "SIGN_VERIFY", customer_master_key_spec: "RSA_3072" } }] } : resource) });
const ownedState = () => ({ ...keyState(), resources: keyState().resources.map((resource) => resource.type === "aws_kms_alias" && resource.name === "root_drop" ? { ...resource, instances: [{ schema_version: 0, attributes: { arn: STAGE_B.rootDropKmsKeyArn, target_key_id: keyId, target_key_arn: keyArn } }] } : resource) });
const stateWithRootDropPolicy = (value, policy) => ({ ...value, resources: value.resources.map((resource) => resource.type === "aws_kms_key" && resource.name === "root_drop" ? { ...resource, instances: resource.instances.map((instance) => ({ ...instance, attributes: { ...instance.attributes, policy: JSON.stringify(policy) } })) } : resource) });
const identityForState = (value) => buildStageAStateIdentity(value, { stateBytes: Buffer.from(JSON.stringify(value)) });
const keyOnlyStateIdentity = () => identityForState(keyState());
const ownedStateIdentity = () => identityForState(ownedState());
const keyOnlyCensus = () => buildRootDropCensus({ sourceSha, transitionId, stageAStateIdentity: keyOnlyStateIdentity(), keyUniverse: [keyId], candidates: [{ ...candidate(), ...authenticated() }], failedApplyEvidence });

test("exact orphan authentication requires account, region, metadata, tags, policy, no alias, and CloudTrail creator/window", () => {
  assert.equal(authenticated().authenticated, true);
  for (const [label, overrides] of [
    ["wrong tags", { tags: { ...TEMPORARY_KMS_CAPABILITY.tags, Component: "wrong" } }],
    ["wrong policy", { policy: { Version: "2012-10-17", Statement: [] } }],
    ["wrong usage", { metadata: { ...candidate().metadata, KeyUsage: "ENCRYPT_DECRYPT" } }],
    ["wrong description", { metadata: { ...candidate().metadata, Description: "different key" } }],
    ["empty description", { metadata: { ...candidate().metadata, Description: "" } }],
    ["wrong account", { metadata: { ...candidate().metadata, AWSAccountId: "000000000000" } }],
    ["wrong region", { arn: `arn:aws:kms:us-east-1:${STAGE_B.account}:key/${keyId}`, metadata: { ...candidate().metadata, Arn: `arn:aws:kms:us-east-1:${STAGE_B.account}:key/${keyId}` } }],
    ["unexpected alias", { aliases: [{ AliasName: ROOT_DROP_ALIAS_NAME, TargetKeyId: keyId }] }],
    ["CloudTrail mismatch", { creationEvents: [{ ...event, eventTime: "2025-01-01T00:00:00.000Z" }] }],
  ]) assert.throws(() => authenticateRootDropOrphan({ candidate: candidate(overrides), terraformState: absentState, sourceSha, transitionId, failedApplyEvidence }), new RegExp(label === "CloudTrail mismatch" ? "outside" : "orphan|candidate|policy|metadata|tags|alias"));
});

test("historical root-drop policy is accepted only for the exact failed apply binding", () => {
  assert.equal(authenticateRootDropOrphan({ candidate: legacyCandidate(), terraformState: absentState, sourceSha: ROOT_DROP_LEGACY_POLICY_BINDING.sourceSha, transitionId: ROOT_DROP_LEGACY_POLICY_BINDING.transitionId, failedApplyEvidence: legacyFailedApplyEvidence }).policyCompatibility, "LEGACY_BOUND_HISTORICAL");
  assert.doesNotThrow(() => assertLegacyRootDropPolicyBinding({ candidate: legacyCandidate(), sourceSha: ROOT_DROP_LEGACY_POLICY_BINDING.sourceSha, transitionId: ROOT_DROP_LEGACY_POLICY_BINDING.transitionId, failedApplyEvidence: legacyFailedApplyEvidence }));
  for (const [label, overrides] of [
    ["wrong key", { keyId, metadata: candidate().metadata }],
    ["ARN/key ID mismatch", { metadata: { ...legacyCandidate().metadata, KeyId: keyId } }],
    ["wrong account", { metadata: { ...legacyCandidate().metadata, AWSAccountId: "000000000000" } }],
    ["wrong region", { metadata: { ...legacyCandidate().metadata, Arn: `arn:aws:kms:us-east-1:${STAGE_B.account}:key/${legacyKeyId}` } }],
    ["wrong policy", { policy: { ...buildLegacyRootDropKeyPolicy(), Statement: buildLegacyRootDropKeyPolicy().Statement.map((statement) => statement.Sid === "ReleaseReadsRootDropKey" ? { ...statement, Action: [...statement.Action, "kms:ListAliases"] } : statement) } }],
  ]) assert.throws(() => assertLegacyRootDropPolicyBinding({ candidate: legacyCandidate(overrides), sourceSha: ROOT_DROP_LEGACY_POLICY_BINDING.sourceSha, transitionId: ROOT_DROP_LEGACY_POLICY_BINDING.transitionId, failedApplyEvidence: legacyFailedApplyEvidence }), /legacy root-drop policy|orphan key identity/, label);
  for (const [label, field, value] of [["wrong source", "sourceSha", sourceSha], ["wrong transition", "transitionId", transitionId], ["wrong plan", "planSha256", failedApplyEvidence.planSha256], ["wrong event", "creationEventId", failedApplyEvidence.creationEventId]]) {
    const evidence = { ...legacyFailedApplyEvidence, [field]: value };
    assert.throws(() => assertLegacyRootDropPolicyBinding({ candidate: legacyCandidate(), sourceSha: evidence.sourceSha, transitionId: evidence.transitionId, failedApplyEvidence: evidence }), /legacy root-drop policy/, label);
  }
  assert.throws(() => assertLegacyRootDropPolicyBinding({ candidate: legacyCandidate(), sourceSha: ROOT_DROP_LEGACY_POLICY_BINDING.sourceSha, transitionId: ROOT_DROP_LEGACY_POLICY_BINDING.transitionId, failedApplyEvidence: { ...legacyFailedApplyEvidence, stageAStateIdentity: { ...ROOT_DROP_LEGACY_POLICY_BINDING.stageAStateIdentity, serial: 46 } } }), /legacy root-drop policy/);
  assert.throws(() => assertLegacyRootDropPolicyBinding({ candidate: legacyCandidate(), sourceSha: ROOT_DROP_LEGACY_POLICY_BINDING.sourceSha, transitionId: ROOT_DROP_LEGACY_POLICY_BINDING.transitionId, failedApplyEvidence: { ...legacyFailedApplyEvidence, stageAStateIdentity: undefined } }), /legacy root-drop policy/);
  assert.equal(authenticated().policyCompatibility, "CANONICAL");
});

test("production candidate snapshot shape authenticates and persists the exact historical orphan", () => {
  const snapshot = legacyCandidate();
  const adapter = {
    listKeys: () => [{ KeyId: legacyKeyId }],
    describeKey: () => snapshot.metadata,
    listTags: () => Object.entries(snapshot.tags).map(([TagKey, TagValue]) => ({ TagKey, TagValue })),
    getPolicy: () => snapshot.policy,
    getPublicKey: () => snapshot.publicKey,
    listAliases: () => snapshot.aliases,
    lookupCreateKeyEvents: () => snapshot.creationEvents,
  };
  const census = collectRootDropCensus({ adapter, terraformState: absentState, sourceSha: ROOT_DROP_LEGACY_POLICY_BINDING.sourceSha, transitionId: ROOT_DROP_LEGACY_POLICY_BINDING.transitionId, stageAStateIdentity: ROOT_DROP_LEGACY_POLICY_BINDING.stageAStateIdentity, failedApplyEvidence: legacyFailedApplyEvidence });
  assert.equal(census.status, "AUTHENTICATED_ORPHAN");
  assert.equal(Object.hasOwn(census.candidates[0], "arn"), false);
  assert.equal(census.candidates[0].metadata.Arn, legacyKeyArn);
  assert.equal(census.candidates[0].keyArn, legacyKeyArn);
  const persisted = JSON.parse(JSON.stringify(census));
  assert.doesNotThrow(() => assertRootDropCensus(persisted, { sourceSha: ROOT_DROP_LEGACY_POLICY_BINDING.sourceSha, transitionId: ROOT_DROP_LEGACY_POLICY_BINDING.transitionId, stageAStateIdentity: ROOT_DROP_LEGACY_POLICY_BINDING.stageAStateIdentity }));
});

test("legacy policy convergence requires the exact update plus alias plan", () => {
  assert.equal(assertRootDropAliasOnlyPlan(legacyAliasPolicyPlan(), { keyId: legacyKeyId, policyCompatibility: "LEGACY_BOUND_HISTORICAL" }).policyConverged, true);
  assert.throws(() => assertRootDropAliasOnlyPlan(legacyAliasPolicyPlan(), { keyId: legacyKeyId }), /canonical root-drop recovery/);
  assert.throws(() => assertRootDropAliasOnlyPlan(legacyAliasPolicyPlan({ afterPolicy: buildLegacyRootDropKeyPolicy() }), { keyId: legacyKeyId, policyCompatibility: "LEGACY_BOUND_HISTORICAL" }), /exact legacy policy convergence/);
  assert.throws(() => assertRootDropAliasOnlyPlan({ resource_changes: [...legacyAliasPolicyPlan().resource_changes, { address: "aws_vpc.other", change: { actions: ["update"], before: {}, after: {} } }] }, { keyId: legacyKeyId, policyCompatibility: "LEGACY_BOUND_HISTORICAL" }), /unexpected changes/);
});

test("root-drop description contract matches the canonical Terraform resource", () => {
  const terraform = readFileSync("infra/aws/terraform/production-green-stage-a/main.tf", "utf8");
  assert.match(terraform, new RegExp(`description\\s*=\\s*"${ROOT_DROP_KEY_DESCRIPTION}"`));
  assert.equal(authenticated().authenticated, true);
});

test("partial, conflicting, and ambiguous state never authenticates an orphan", () => {
  const partial = { ...absentState, resources: absentState.resources.map((resource) => resource.type === "aws_kms_key" && resource.name === "root_drop" ? { ...resource, instances: [{ attributes: { arn: keyArn } }] } : resource) };
  assert.throws(() => authenticateRootDropOrphan({ candidate: candidate(), terraformState: partial, sourceSha, transitionId, failedApplyEvidence }), /counts|partial/);
  const foreign = { ...ownedState(), resources: ownedState().resources.map((resource) => resource.type === "aws_kms_key" && resource.name === "root_drop" ? { ...resource, instances: [{ attributes: { arn: `arn:aws:kms:${STAGE_B.region}:${STAGE_B.account}:key/22222222-2222-2222-2222-222222222222` } }] } : resource) };
  assert.throws(() => assertRootDropStateIdentity(foreign, { keyId }), /does not own/);
  const ambiguous = buildRootDropCensus({ sourceSha, transitionId, stageAStateIdentity: stateIdentity, keyUniverse: [keyId], candidates: [authenticated(), authenticated()] });
  assert.throws(() => assertRootDropCreationInterlock({ plan: exactCreatePlan, terraformState: absentState, census: ambiguous, sourceSha, transitionId, stageAStateIdentity: stateIdentity }), /blocked/);
});

test("zero-candidate pre-apply permits only the exact creation envelope", () => {
  assert.doesNotThrow(() => assertRootDropCreationInterlock({ plan: exactCreatePlan, terraformState: absentState, census: noCandidateCensus(), sourceSha, transitionId, stageAStateIdentity: stateIdentity }));
  for (const candidateCensus of [census(), buildRootDropCensus({ sourceSha, transitionId, stageAStateIdentity: stateIdentity, keyUniverse: [keyId], candidates: [{ authenticated: false, keyId }] })]) assert.throws(() => assertRootDropCreationInterlock({ plan: exactCreatePlan, terraformState: absentState, census: candidateCensus, sourceSha, transitionId, stageAStateIdentity: stateIdentity }), /blocked/);
});

test("root-drop census is bound to eu-west-2 and rejects wrong regions before AWS", async () => {
  let calls = 0;
  for (const region of [undefined, STAGE_B.region]) {
    const adapter = buildRootDropAwsReadAdapter({ run: (args) => { calls += 1; assert.equal(args.at(-5), "--region"); assert.equal(args.at(-4), STAGE_B.region); return JSON.stringify({ Keys: [] }); }, profile: "administrator", region });
    assert.deepEqual(adapter.listKeys(), []);
  }
  calls = 0;
  assert.throws(() => buildRootDropAwsReadAdapter({ run: () => { calls += 1; return "{}"; }, profile: "administrator", region: "us-east-1" }), /protected production boundary/);
  assert.equal(calls, 0);
  for (const region of ["us-east-1", "eu-west-1", "not-a-region"]) {
    await assert.rejects(() => runCensus({ argv: ["--admin-profile", "administrator", "--release-profile", "release", "--region", region], run: () => { calls += 1; return "{}"; } }), /protected production boundary/);
  }
  assert.equal(calls, 0);
  for (const region of ["us-east-1", undefined]) {
    const value = { ...noCandidateCensus(), ...(region === undefined ? { region: undefined } : { region }) };
    const unsigned = { ...value };
    delete unsigned.censusSha256;
    value.censusSha256 = rootDropRecoverySha256(unsigned);
    assert.throws(() => assertRootDropCensus(value, { sourceSha, transitionId, stageAStateIdentity: stateIdentity }), /regional|current/);
  }
});

test("root-drop census rejects a missing explicit region before AWS", async () => {
  let calls = 0;
  await assert.rejects(() => runCensus({ argv: ["--admin-profile", "administrator", "--release-profile", "release", "--region"], run: () => { calls += 1; return "{}"; } }), /--region requires a value/);
  assert.equal(calls, 0);
});

test("orphan AWS reads and every Terraform subprocess use the selected release environment", async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-orphan-credential-boundary-"));
  const statePath = path.join(directory, "state.json");
  const identityPath = path.join(directory, "identity.json");
  const censusPath = path.join(directory, "census.json");
  const outputPath = path.join(directory, "output.json");
  const planPath = path.join(directory, "alias.plan");
  const terraformRoot = path.join(process.cwd(), "infra/aws/terraform/production-green-stage-a");
  const stateBytes = Buffer.from(JSON.stringify(absentState));
  writeFileSync(statePath, stateBytes, { mode: 0o600 });
  writeFileSync(identityPath, `${JSON.stringify(stateIdentity)}\n`, { mode: 0o600 });
  const suppliedCensus = census();
  writeFileSync(censusPath, `${JSON.stringify(suppliedCensus)}\n`, { mode: 0o600 });
  const saved = Object.fromEntries(["AWS_PROFILE", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN", "AWS_DEFAULT_PROFILE", "AWS_REGION", "AWS_DEFAULT_REGION", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE", "TF_DATA_DIR", "TF_WORKSPACE", "TF_CLI_CONFIG_FILE", "TF_CLI_ARGS", "TF_CLI_ARGS_init", "TF_CLI_ARGS_import", "TF_CLI_ARGS_plan", "TF_CLI_ARGS_apply", ...STAGE_A_REQUIRED_TERRAFORM_VARIABLE_KEYS].map((key) => [key, process.env[key]]));
  const restore = () => { for (const [key, value] of Object.entries(saved)) { if (value === undefined) delete process.env[key]; else process.env[key] = value; } };
  const observedAws = [];
  const observedTerraform = [];
  let currentState = absentState;
  let showCount = 0;
  try {
    Object.assign(process.env, { ...stageAVars, AWS_PROFILE: "administrator", AWS_ACCESS_KEY_ID: "ambient-key", AWS_SECRET_ACCESS_KEY: "ambient-secret", AWS_SESSION_TOKEN: "ambient-session", AWS_SECURITY_TOKEN: "ambient-security", AWS_DEFAULT_PROFILE: "ambient-default", AWS_REGION: "us-east-1", AWS_DEFAULT_REGION: "us-east-1", AWS_CONFIG_FILE: "/tmp/config", AWS_SHARED_CREDENTIALS_FILE: "/tmp/credentials", TF_DATA_DIR: "/tmp/hostile-data", TF_WORKSPACE: "wrong-workspace", TF_CLI_CONFIG_FILE: "/tmp/hostile-cli.tfrc", TF_CLI_ARGS: "-refresh=false", TF_CLI_ARGS_init: "-backend-config=/tmp/wrong-backend", TF_CLI_ARGS_import: "-state=/tmp/wrong.tfstate", TF_CLI_ARGS_plan: "-target=aws_kms_key.wrong", TF_CLI_ARGS_apply: "-auto-approve" });
    await runCensus({ argv: ["--admin-profile", "administrator", "--release-profile", "release", "--stage-a-state", statePath, "--stage-a-state-identity", identityPath, "--source-sha", sourceSha, "--transition-id", transitionId, "--plan-sha256", failedApplyEvidence.planSha256, "--failed-apply-start", failedApplyEvidence.failedApplyWindow.start, "--failed-apply-end", failedApplyEvidence.failedApplyWindow.end, "--output", outputPath], execFile: (command, args, options) => { observedAws.push({ command, args, env: options.env }); return JSON.stringify({ Keys: [] }); }, write: () => {} });
    assert.equal(observedAws[0].args[observedAws[0].args.indexOf("--profile") + 1], "administrator");
    assert.equal(observedAws[0].env.AWS_PROFILE, "release");
    assert.equal(observedAws[0].env.AWS_REGION, STAGE_B.region);
    assert.equal(observedAws[0].env.AWS_DEFAULT_REGION, STAGE_B.region);
    for (const key of ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN", "AWS_DEFAULT_PROFILE"]) assert.equal(observedAws[0].env[key], undefined);
    assert.equal(observedAws[0].env.AWS_CONFIG_FILE, "/tmp/config");
    assert.equal(observedAws[0].env.AWS_SHARED_CREDENTIALS_FILE, "/tmp/credentials");
    let adoptionCensusProfile;
    const result = await runAdoption({ argv: ["--census", censusPath, "--stage-a-state", statePath, "--stage-a-state-identity", identityPath, "--admin-profile", "administrator", "--release-profile", "release", "--terraform-root", terraformRoot, "--plan-path", planPath, "--execute"], runGit: cleanGit(), readRootDropCensus: ({ profile, adminProfile, releaseProfile }) => { adoptionCensusProfile = { profile, adminProfile, releaseProfile }; return suppliedCensus; }, readTerraformBackendMetadata: () => ({ type: STAGE_A_TERRAFORM_BACKEND.type, config: { bucket: STAGE_A_TERRAFORM_BACKEND.bucket, key: STAGE_A_TERRAFORM_BACKEND.key, region: STAGE_A_TERRAFORM_BACKEND.region, encrypt: STAGE_A_TERRAFORM_BACKEND.encrypt, use_lockfile: STAGE_A_TERRAFORM_BACKEND.use_lockfile } }), execFile: (command, args, options) => {
      observedTerraform.push({ command, args, env: options.env });
      if (args.includes("workspace") && args.includes("show")) return "default\n";
      if (args.includes("state") && args.includes("pull")) return JSON.stringify(currentState);
      if (args.includes("import")) { currentState = keyState(); return ""; }
      if (args.includes("apply")) { currentState = ownedState(); return ""; }
      if (args.includes("plan") && args.includes("-out")) { writeFileSync(args[args.indexOf("-out") + 1], "saved-plan"); return ""; }
      if (args.includes("show")) { showCount += 1; return JSON.stringify(showCount === 1 ? exactCreatePlan : (args.at(-1).endsWith("zero-drift") ? { resource_changes: [] } : aliasPlan())); }
      return "";
    }, write: () => {} });
    assert.equal(result.status, "RECOVERED");
    assert.deepEqual(adoptionCensusProfile, { profile: "release", adminProfile: "administrator", releaseProfile: "release" });
    assert(observedTerraform.some(({ args }) => args.includes("state")));
    assert(observedTerraform.some(({ args }) => args.includes("import")));
    assert(observedTerraform.some(({ args }) => args.includes("plan")));
    assert(observedTerraform.some(({ args }) => args.includes("apply")));
    for (const { env } of observedTerraform) {
      assert.equal(env.AWS_PROFILE, "release");
      assert.equal(env.AWS_REGION, STAGE_B.region);
      assert.equal(env.AWS_DEFAULT_REGION, STAGE_B.region);
      for (const key of ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN", "AWS_DEFAULT_PROFILE"]) assert.equal(env[key], undefined);
      for (const key of ["TF_DATA_DIR", "TF_WORKSPACE", "TF_CLI_CONFIG_FILE", "TF_CLI_ARGS", "TF_CLI_ARGS_init", "TF_CLI_ARGS_import", "TF_CLI_ARGS_plan", "TF_CLI_ARGS_apply"]) assert.equal(env[key], undefined);
      for (const key of STAGE_A_REQUIRED_TERRAFORM_VARIABLE_KEYS) assert.equal(env[key], stageAVars[key]);
      assert.equal(env.AWS_CONFIG_FILE, "/tmp/config");
      assert.equal(env.AWS_SHARED_CREDENTIALS_FILE, "/tmp/credentials");
    }
    assert.deepEqual({ AWS_PROFILE: process.env.AWS_PROFILE, AWS_REGION: process.env.AWS_REGION, AWS_DEFAULT_REGION: process.env.AWS_DEFAULT_REGION }, { AWS_PROFILE: "administrator", AWS_REGION: "us-east-1", AWS_DEFAULT_REGION: "us-east-1" });
  } finally { restore(); rmSync(directory, { recursive: true, force: true }); }
});

test("runAdoption resumes S1 key-only state without reimporting", async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-orphan-s1-retry-"));
  const statePath = path.join(directory, "state.json");
  const identityPath = path.join(directory, "identity.json");
  const censusPath = path.join(directory, "census.json");
  const planPath = path.join(directory, "alias.plan");
  const currentKeyState = keyState();
  const currentCensus = keyOnlyCensus();
  writeFileSync(statePath, JSON.stringify(currentKeyState), { mode: 0o600 });
  writeFileSync(identityPath, `${JSON.stringify(keyOnlyStateIdentity())}\n`, { mode: 0o600 });
  writeFileSync(censusPath, `${JSON.stringify(currentCensus)}\n`, { mode: 0o600 });
  let currentState = currentKeyState;
  let imports = 0;
  let applies = 0;
  let showCount = 0;
  const savedVariables = Object.fromEntries(STAGE_A_REQUIRED_TERRAFORM_VARIABLE_KEYS.map((key) => [key, process.env[key]]));
  try {
    Object.assign(process.env, stageAVars);
    const result = await runAdoption({
      argv: ["--census", censusPath, "--stage-a-state", statePath, "--stage-a-state-identity", identityPath, "--admin-profile", "administrator", "--release-profile", "release", "--plan-path", planPath, "--execute"],
      runGit: cleanGit(),
      readRootDropCensus: async () => currentCensus,
      readTerraformBackendMetadata: () => ({ type: STAGE_A_TERRAFORM_BACKEND.type, config: { bucket: STAGE_A_TERRAFORM_BACKEND.bucket, key: STAGE_A_TERRAFORM_BACKEND.key, region: STAGE_A_TERRAFORM_BACKEND.region, encrypt: STAGE_A_TERRAFORM_BACKEND.encrypt, use_lockfile: STAGE_A_TERRAFORM_BACKEND.use_lockfile } }),
      execFile: (command, args) => {
        if (args.includes("workspace") && args.includes("show")) return "default\n";
        if (args.includes("state") && args.includes("pull")) return JSON.stringify(currentState);
        if (args.includes("import")) { imports += 1; throw new Error("S1 retry must not import"); }
        if (args.includes("apply")) { applies += 1; currentState = ownedState(); return ""; }
        if (args.includes("plan") && args.includes("-out")) { writeFileSync(args[args.indexOf("-out") + 1], "alias-plan"); return ""; }
        if (args.includes("show")) { showCount += 1; return JSON.stringify(args.at(-1).endsWith("zero-drift") ? { resource_changes: [] } : aliasPlan()); }
        throw new Error(`unexpected Terraform command: ${args.join(" ")}`);
      },
      write: () => {},
    });
    assert.equal(result.status, "RECOVERED");
    assert.deepEqual({ imports, applies }, { imports: 0, applies: 1 });
    assert.equal(showCount, 3);
  } finally {
    for (const [key, value] of Object.entries(savedVariables)) { if (value === undefined) delete process.env[key]; else process.env[key] = value; }
    rmSync(directory, { recursive: true, force: true });
  }
});

test("adoption rejects a non-canonical Terraform root before any Terraform subprocess", async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-orphan-root-pin-"));
  const statePath = path.join(directory, "state.json");
  const identityPath = path.join(directory, "identity.json");
  const censusPath = path.join(directory, "census.json");
  try {
    writeFileSync(statePath, stateBytes, { mode: 0o600 });
    writeFileSync(identityPath, `${JSON.stringify(stateIdentity)}\n`, { mode: 0o600 });
    writeFileSync(censusPath, `${JSON.stringify(census())}\n`, { mode: 0o600 });
    let terraformCalls = 0;
    await assert.rejects(() => runAdoption({
      argv: ["--census", censusPath, "--stage-a-state", statePath, "--stage-a-state-identity", identityPath, "--admin-profile", "administrator", "--release-profile", "release", "--terraform-root", directory, "--plan-path", path.join(directory, "alias.plan"), "--execute"],
      runGit: cleanGit(),
      readRootDropCensus: async () => census(),
      execFile: () => { terraformCalls += 1; throw new Error("Terraform must not run"); },
      write: () => {},
    }), /canonical production Stage-A Terraform root/);
    assert.equal(terraformCalls, 0);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("source checkout is bound to census.sourceSha and rejects execution-relevant drift before import", async () => {
  assert.doesNotThrow(() => assertRootDropExecutionSource({ sourceSha, runGit: cleanGit() }));
  assert.throws(() => assertRootDropExecutionSource({ sourceSha: "0".repeat(40), runGit: cleanGit() }), /HEAD does not match/);
  assert.throws(() => assertRootDropExecutionSource({ sourceSha, runGit: cleanGit(sourceSha, " M infra/aws/terraform/production-green-stage-a/main.tf\n") }), /tracked modifications/);
  assert.throws(() => assertRootDropExecutionSource({ sourceSha, runGit: cleanGit(sourceSha, "M  infra/aws/terraform/production-green-stage-a/main.tf\n") }), /tracked modifications/);
  assert.throws(() => assertRootDropExecutionSource({ sourceSha, runGit: cleanGit(sourceSha, "?? infra/aws/terraform/production-green-stage-a/local.tf\n") }), /untracked file/);
  assert.throws(() => assertRootDropExecutionSource({ sourceSha, runGit: cleanGit(sourceSha, "", "!! infra/aws/terraform/production-green-stage-a/local.auto.tfvars\n") }), /ignored Terraform configuration/);
  assert.throws(() => assertRootDropExecutionSource({ sourceSha, runGit: cleanGit(sourceSha, "", "!! infra/aws/terraform/production-green-stage-a/override.tf\n") }), /ignored Terraform configuration/);
  assert.throws(() => assertRootDropExecutionSource({ sourceSha, runGit: cleanGit(sourceSha, "", "", "120000 abc\t infra/aws/terraform/production-green-stage-a/main.tf\n") }), /symlinked/);
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-orphan-source-boundary-"));
  try {
    const statePath = path.join(directory, "state.json");
    const identityPath = path.join(directory, "identity.json");
    const censusPath = path.join(directory, "census.json");
    const planPath = path.join(directory, "adoption.plan");
    writeFileSync(statePath, stateBytes, { mode: 0o600 });
    writeFileSync(identityPath, `${JSON.stringify(stateIdentity)}\n`, { mode: 0o600 });
    writeFileSync(censusPath, `${JSON.stringify(census())}\n`, { mode: 0o600 });
    let terraformCalls = 0;
    await assert.rejects(() => runAdoption({ argv: ["--census", censusPath, "--stage-a-state", statePath, "--stage-a-state-identity", identityPath, "--admin-profile", "administrator", "--release-profile", "release", "--plan-path", planPath, "--execute"], runGit: cleanGit("0".repeat(40)), execFile: () => { terraformCalls += 1; throw new Error("Terraform must not run"); }, write: () => {} }), /HEAD does not match/);
    assert.equal(terraformCalls, 0);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("adoption validates both new private plan outputs before any Terraform import", async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-orphan-plan-path-"));
  const statePath = path.join(directory, "state.json");
  const identityPath = path.join(directory, "identity.json");
  const censusPath = path.join(directory, "census.json");
  writeFileSync(statePath, stateBytes, { mode: 0o600 });
  writeFileSync(identityPath, `${JSON.stringify(stateIdentity)}\n`, { mode: 0o600 });
  writeFileSync(censusPath, `${JSON.stringify(census())}\n`, { mode: 0o600 });
  const args = (planPath) => ["--census", censusPath, "--stage-a-state", statePath, "--stage-a-state-identity", identityPath, "--admin-profile", "administrator", "--release-profile", "release", "--plan-path", planPath, "--execute"];
  const assertRejectedBeforeTerraform = async (planPath, expected) => {
    let terraformCalls = 0;
    await assert.rejects(() => runAdoption({ argv: args(planPath), execFile: () => { terraformCalls += 1; throw new Error("Terraform must not run"); }, write: () => {} }), expected);
    assert.equal(terraformCalls, 0);
  };
  try {
    const valid = path.join(directory, "valid.plan");
    const validated = validateRootDropPlanPaths({ planPath: valid, reservedPaths: [censusPath, statePath, identityPath] });
    const canonicalValid = path.join(realpathSync(directory), "valid.plan");
    assert.equal(validated.planPath, canonicalValid);
    assert.equal(validated.zeroDriftPlanPath, `${canonicalValid}.zero-drift`);
    assert.equal(validated.preImportPlanPath, `${canonicalValid}.pre-import`);
    assert.equal(existsSync(canonicalValid), false);
    assert.equal(existsSync(validated.zeroDriftPlanPath), false);
    assert.equal(existsSync(validated.preImportPlanPath), false);

    await assertRejectedBeforeTerraform("relative.plan", /absolute path/);
    await assertRejectedBeforeTerraform(path.join(process.cwd(), "repository.plan"), /outside the repository/);

    const existing = path.join(directory, "existing.plan");
    writeFileSync(existing, "occupied", { mode: 0o600 });
    await assertRejectedBeforeTerraform(existing, /new absolute private output path/);

    const symlinkTarget = path.join(directory, "symlink-target.plan");
    const symlinkPath = path.join(directory, "symlink.plan");
    writeFileSync(symlinkTarget, "target", { mode: 0o600 });
    symlinkSync(symlinkTarget, symlinkPath);
    await assertRejectedBeforeTerraform(symlinkPath, /must not be a symlink/);

    const zeroDriftCollision = path.join(directory, "collision.plan");
    writeFileSync(`${zeroDriftCollision}.zero-drift`, "occupied", { mode: 0o600 });
    await assertRejectedBeforeTerraform(zeroDriftCollision, /new absolute private output path/);

    const preImportCollision = path.join(directory, "pre-import-collision.plan");
    writeFileSync(`${preImportCollision}.pre-import`, "occupied", { mode: 0o600 });
    await assertRejectedBeforeTerraform(preImportCollision, /new absolute private output path/);

    chmodSync(directory, 0o755);
    await assertRejectedBeforeTerraform(path.join(directory, "permissive.plan"), /mode 0700/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("Stage-A backend metadata is exact and rejects a redirected state target", () => {
  const valid = { type: STAGE_A_TERRAFORM_BACKEND.type, config: { bucket: STAGE_A_TERRAFORM_BACKEND.bucket, key: STAGE_A_TERRAFORM_BACKEND.key, region: STAGE_A_TERRAFORM_BACKEND.region, encrypt: STAGE_A_TERRAFORM_BACKEND.encrypt, use_lockfile: STAGE_A_TERRAFORM_BACKEND.use_lockfile } };
  assert.doesNotThrow(() => assertStageATerraformBackendMetadata(valid));
  for (const config of [{ ...valid.config, key: "wrong/state.tfstate" }, { ...valid.config, bucket: "wrong-bucket" }, { ...valid.config, region: "us-east-1" }, { ...valid.config, use_lockfile: false }]) assert.throws(() => assertStageATerraformBackendMetadata({ ...valid, config }), /backend/);
});

test("adoption rejects a non-default workspace before state access", async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-orphan-workspace-pin-"));
  const statePath = path.join(directory, "state.json");
  const identityPath = path.join(directory, "identity.json");
  const censusPath = path.join(directory, "census.json");
  const saved = Object.fromEntries(STAGE_A_REQUIRED_TERRAFORM_VARIABLE_KEYS.map((key) => [key, process.env[key]]));
  try {
    Object.assign(process.env, stageAVars);
    writeFileSync(statePath, stateBytes, { mode: 0o600 });
    writeFileSync(identityPath, `${JSON.stringify(stateIdentity)}\n`, { mode: 0o600 });
    writeFileSync(censusPath, `${JSON.stringify(census())}\n`, { mode: 0o600 });
    let terraformCalls = 0;
    await assert.rejects(() => runAdoption({
      argv: ["--census", censusPath, "--stage-a-state", statePath, "--stage-a-state-identity", identityPath, "--admin-profile", "administrator", "--release-profile", "release", "--plan-path", path.join(directory, "alias.plan"), "--execute"],
      runGit: cleanGit(),
      readRootDropCensus: async () => census(),
      readTerraformBackendMetadata: () => ({ type: STAGE_A_TERRAFORM_BACKEND.type, config: { bucket: STAGE_A_TERRAFORM_BACKEND.bucket, key: STAGE_A_TERRAFORM_BACKEND.key, region: STAGE_A_TERRAFORM_BACKEND.region, encrypt: STAGE_A_TERRAFORM_BACKEND.encrypt, use_lockfile: STAGE_A_TERRAFORM_BACKEND.use_lockfile } }),
      execFile: () => { terraformCalls += 1; return "wrong-workspace\n"; },
      write: () => {},
    }), /canonical default Terraform workspace/);
    assert.equal(terraformCalls, 1);
  } finally {
    for (const [key, value] of Object.entries(saved)) { if (value === undefined) delete process.env[key]; else process.env[key] = value; }
    rmSync(directory, { recursive: true, force: true });
  }
});

test("Stage-A recovery preserves only the reviewed required variables and performs readiness before census/import", async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-orphan-variable-contract-"));
  const statePath = path.join(directory, "state.json");
  const identityPath = path.join(directory, "identity.json");
  const censusPath = path.join(directory, "census.json");
  const planPath = path.join(directory, "alias.plan");
  writeFileSync(statePath, stateBytes, { mode: 0o600 });
  writeFileSync(identityPath, `${JSON.stringify(stateIdentity)}\n`, { mode: 0o600 });
  writeFileSync(censusPath, `${JSON.stringify(census())}\n`, { mode: 0o600 });
  const saved = Object.fromEntries([...STAGE_A_REQUIRED_TERRAFORM_VARIABLE_KEYS, "TF_VAR_unreviewed"].map((key) => [key, process.env[key]]));
  const sequence = [];
  try {
    Object.assign(process.env, { ...stageAVars, TF_VAR_unreviewed: "must-not-pass" });
    assert.throws(() => buildRecoveryTerraformEnvironment("release", process.env, { allowedTerraformVariableKeys: STAGE_A_REQUIRED_TERRAFORM_VARIABLE_KEYS }), /unreviewed/);
    delete process.env.TF_VAR_unreviewed;
    let currentState = absentState;
    const result = await runAdoption({
      argv: ["--census", censusPath, "--stage-a-state", statePath, "--stage-a-state-identity", identityPath, "--admin-profile", "administrator", "--release-profile", "release", "--plan-path", planPath, "--execute"],
      runGit: cleanGit(),
      readRootDropCensus: async () => { sequence.push("census"); return census(); },
      readTerraformBackendMetadata: () => ({ type: STAGE_A_TERRAFORM_BACKEND.type, config: { bucket: STAGE_A_TERRAFORM_BACKEND.bucket, key: STAGE_A_TERRAFORM_BACKEND.key, region: STAGE_A_TERRAFORM_BACKEND.region, encrypt: STAGE_A_TERRAFORM_BACKEND.encrypt, use_lockfile: STAGE_A_TERRAFORM_BACKEND.use_lockfile } }),
      execFile: (command, args, options) => {
        sequence.push(args.includes("plan") && args.includes("-refresh=true") ? "readiness" : args.includes("workspace") ? "workspace" : args.includes("state") ? "state" : args[0]);
        assert.equal(options.env.AWS_PROFILE, "release");
        for (const key of STAGE_A_REQUIRED_TERRAFORM_VARIABLE_KEYS) assert.equal(options.env[key], stageAVars[key]);
        assert.equal(options.env.TF_VAR_unreviewed, undefined);
        if (args.includes("workspace")) return "default\n";
        if (args.includes("state")) return JSON.stringify(currentState);
        if (args.includes("import")) { currentState = keyState(); return ""; }
        if (args.includes("apply")) { currentState = ownedState(); return ""; }
        if (args.includes("plan") && args.includes("-out")) { writeFileSync(args[args.indexOf("-out") + 1], "saved-plan"); return ""; }
        if (args.includes("show")) return JSON.stringify(sequence.includes("pre-import-plan-shown") ? (args.at(-1).endsWith("zero-drift") ? { resource_changes: [] } : aliasPlan()) : (sequence.push("pre-import-plan-shown"), exactCreatePlan));
        return "";
      },
      write: () => {},
    });
    assert.equal(result.status, "RECOVERED");
    assert.deepEqual(sequence.slice(0, 3), ["workspace", "state", "readiness"]);
    assert(sequence.indexOf("state") < sequence.indexOf("readiness"));
    assert(sequence.lastIndexOf("state") > sequence.indexOf("readiness"));
    assert(sequence.indexOf("census") > sequence.indexOf("state"));
  } finally {
    for (const [key, value] of Object.entries(saved)) { if (value === undefined) delete process.env[key]; else process.env[key] = value; }
    rmSync(directory, { recursive: true, force: true });
  }
});

test("missing, malformed, or wrong-identity Stage-A variables fail before Terraform", async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-orphan-variable-fail-"));
  const statePath = path.join(directory, "state.json");
  const identityPath = path.join(directory, "identity.json");
  const censusPath = path.join(directory, "census.json");
  writeFileSync(statePath, stateBytes, { mode: 0o600 });
  writeFileSync(identityPath, `${JSON.stringify(stateIdentity)}\n`, { mode: 0o600 });
  writeFileSync(censusPath, `${JSON.stringify(census())}\n`, { mode: 0o600 });
  const saved = Object.fromEntries(STAGE_A_REQUIRED_TERRAFORM_VARIABLE_KEYS.map((key) => [key, process.env[key]]));
  try {
    for (const [key, value, expected] of [["TF_VAR_vpc_id", undefined, /requires TF_VAR_vpc_id/], ["TF_VAR_private_subnet_ids", "not-hcl", /Terraform must not run/], ["TF_VAR_aws_region", "us-east-1", /outside the protected production Stage-A variable contract/]]) {
      Object.assign(process.env, stageAVars);
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
      let terraformImports = 0;
      await assert.rejects(() => runAdoption({ argv: ["--census", censusPath, "--stage-a-state", statePath, "--stage-a-state-identity", identityPath, "--admin-profile", "administrator", "--release-profile", "release", "--plan-path", path.join(directory, `${key}.plan`)], runGit: cleanGit(), readRootDropCensus: async () => census(), readTerraformBackendMetadata: () => ({ type: STAGE_A_TERRAFORM_BACKEND.type, config: { bucket: STAGE_A_TERRAFORM_BACKEND.bucket, key: STAGE_A_TERRAFORM_BACKEND.key, region: STAGE_A_TERRAFORM_BACKEND.region, encrypt: STAGE_A_TERRAFORM_BACKEND.encrypt, use_lockfile: STAGE_A_TERRAFORM_BACKEND.use_lockfile } }), execFile: (command, args) => { if (args.includes("import")) terraformImports += 1; if (args.includes("state")) return JSON.stringify(absentState); if (args.includes("plan")) throw new Error("Terraform must not run"); return "default\n"; }, write: () => {} }), expected);
      assert.equal(terraformImports, 0);
    }
  } finally {
    for (const [key, value] of Object.entries(saved)) { if (value === undefined) delete process.env[key]; else process.env[key] = value; }
    rmSync(directory, { recursive: true, force: true });
  }
});

async function runPreImportReadinessCase(readinessPlan, { variables = stageAVars, mutateSavedPlan = false, stateAfterReadiness } = {}) {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-orphan-pre-import-plan-"));
  const statePath = path.join(directory, "state.json");
  const identityPath = path.join(directory, "identity.json");
  const censusPath = path.join(directory, "census.json");
  const planPath = path.join(directory, "adoption.plan");
  writeFileSync(statePath, stateBytes, { mode: 0o600 });
  writeFileSync(identityPath, `${JSON.stringify(stateIdentity)}\n`, { mode: 0o600 });
  writeFileSync(censusPath, `${JSON.stringify(census())}\n`, { mode: 0o600 });
  const saved = Object.fromEntries(STAGE_A_REQUIRED_TERRAFORM_VARIABLE_KEYS.map((key) => [key, process.env[key]]));
  let currentState = absentState;
  let imports = 0;
  let applies = 0;
  let planCalls = 0;
  let showCalls = 0;
  let statePulls = 0;
  const terraformArgs = [];
  try {
    Object.assign(process.env, variables);
    const result = await runAdoption({
      argv: ["--census", censusPath, "--stage-a-state", statePath, "--stage-a-state-identity", identityPath, "--admin-profile", "administrator", "--release-profile", "release", "--plan-path", planPath, "--execute"],
      runGit: cleanGit(),
      readRootDropCensus: async () => census(),
      readTerraformBackendMetadata: () => ({ type: STAGE_A_TERRAFORM_BACKEND.type, config: { bucket: STAGE_A_TERRAFORM_BACKEND.bucket, key: STAGE_A_TERRAFORM_BACKEND.key, region: STAGE_A_TERRAFORM_BACKEND.region, encrypt: STAGE_A_TERRAFORM_BACKEND.encrypt, use_lockfile: STAGE_A_TERRAFORM_BACKEND.use_lockfile } }),
      execFile: (command, args) => {
        terraformArgs.push(args);
        if (args.includes("workspace")) return "default\n";
        if (args.includes("state")) { statePulls += 1; return JSON.stringify(stateAfterReadiness && statePulls === 1 ? stateAfterReadiness : currentState); }
        if (args.includes("import")) { imports += 1; currentState = keyState(); return ""; }
        if (args.includes("apply")) { applies += 1; currentState = ownedState(); return ""; }
        if (args.includes("plan") && args.includes("-out")) { planCalls += 1; writeFileSync(args[args.indexOf("-out") + 1], `saved-plan-${planCalls}`); return ""; }
        if (args.includes("show")) {
          showCalls += 1;
          if (showCalls === 1) {
            if (mutateSavedPlan) writeFileSync(args.at(-1), "tampered-plan");
            return JSON.stringify(readinessPlan);
          }
          return JSON.stringify(showCalls === 2 ? aliasPlan() : { resource_changes: [] });
        }
        throw new Error(`unexpected Terraform command: ${args.join(" ")}`);
      },
      write: () => {},
    });
    return { result, imports, applies, terraformArgs };
  } catch (error) {
    return { error, imports, applies, terraformArgs };
  } finally {
    for (const [key, value] of Object.entries(saved)) { if (value === undefined) delete process.env[key]; else process.env[key] = value; }
    rmSync(directory, { recursive: true, force: true });
  }
}

test("pre-import Terraform plan is saved, machine-classified, and exact before import", async () => {
  assert.deepEqual(assertRootDropPreImportPlan(exactCreatePlan).addresses, [ROOT_DROP_KEY_ADDRESS, ROOT_DROP_ALIAS_ADDRESS]);
  const valid = await runPreImportReadinessCase(exactCreatePlan);
  assert.equal(valid.result.status, "RECOVERED");
  assert.equal(valid.result.preImportPlanSha256.length, 64);
  assert.deepEqual({ imports: valid.imports, applies: valid.applies }, { imports: 1, applies: 1 });
  assert(valid.terraformArgs.some((args) => args.includes("plan") && args.includes("-refresh=true")));
  const invalidPlans = [
    ["unrelated update", { ...exactCreatePlan, resource_changes: [...exactCreatePlan.resource_changes, { address: "aws_vpc.other", type: "aws_vpc", change: { before: {}, actions: ["update"], after: {} } }] }],
    ["replacement", { ...exactCreatePlan, resource_changes: exactCreatePlan.resource_changes.map((entry) => entry.address === ROOT_DROP_KEY_ADDRESS ? { ...entry, change: { ...entry.change, actions: ["create", "delete"] } } : entry) }],
    ["delete", { ...exactCreatePlan, resource_changes: [...exactCreatePlan.resource_changes, { address: "aws_vpc.other", type: "aws_vpc", change: { before: {}, actions: ["delete"], after: null } }] }],
    ["unexpected create", { ...exactCreatePlan, resource_changes: [...exactCreatePlan.resource_changes, { address: "aws_vpc.other", type: "aws_vpc", change: { before: null, actions: ["create"], after: {} } }] }],
    ["unknown action", { ...exactCreatePlan, resource_changes: exactCreatePlan.resource_changes.map((entry) => entry.address === ROOT_DROP_ALIAS_ADDRESS ? { ...entry, change: { ...entry.change, actions: ["migrate"] } } : entry) }],
  ];
  for (const [label, plan] of invalidPlans) {
    const invalid = await runPreImportReadinessCase(plan);
    assert.match(invalid.error?.message || "", /pre-import|unexpected|replacement|action|contract/, label);
    assert.deepEqual({ imports: invalid.imports, applies: invalid.applies }, { imports: 0, applies: 0 }, label);
  }
  const staleVariables = await runPreImportReadinessCase(invalidPlans[0][1], { variables: { ...stageAVars, TF_VAR_vpc_id: "vpc-stale" } });
  assert.equal(staleVariables.imports, 0);
  const tampered = await runPreImportReadinessCase(exactCreatePlan, { mutateSavedPlan: true });
  assert.match(tampered.error?.message || "", /changed while it was being classified/);
  assert.deepEqual({ imports: tampered.imports, applies: tampered.applies }, { imports: 0, applies: 0 });
  const changedState = { ...absentState, serial: absentState.serial + 1 };
  const refreshedIdentityMismatch = await runPreImportReadinessCase(exactCreatePlan, { stateAfterReadiness: changedState });
  assert.match(refreshedIdentityMismatch.error?.message || "", /identity|binding/);
  assert.deepEqual({ imports: refreshedIdentityMismatch.imports, applies: refreshedIdentityMismatch.applies }, { imports: 0, applies: 0 });
});

test("pre-import classifier binds the alias target expression to root_drop.key_id", () => {
  const wrong = structuredClone(exactCreatePlan);
  wrong.configuration.root_module.resources[0].expressions.target_key_id.references = ["aws_kms_key.other.key_id"];
  assert.throws(() => assertRootDropPreImportPlan(wrong), /exact root-drop creation contract/);
});

test("CLI failure formatting preserves confirmed, ambiguous, and zero mutation accounting", () => {
  const confirmed = new Error("post-import refresh failed");
  confirmed.recoveryAccounting = { terraformImports: 1, terraformApplies: 0, kmsWrites: 0, iamWrites: 0, unknownMutations: 0, unclassifiedMutations: 0 };
  assert.deepEqual(JSON.parse(formatRootDropRecoveryFailure(confirmed)), { status: "FAILED", error: confirmed.message, recoveryAccounting: confirmed.recoveryAccounting });
  const ambiguous = new Error("import response lost");
  ambiguous.mutationOutcome = "AMBIGUOUS";
  ambiguous.recoveryAccounting = { terraformImports: 1, terraformApplies: 0, kmsWrites: 0, iamWrites: 0, unknownMutations: 1, unclassifiedMutations: 0 };
  assert.equal(JSON.parse(formatRootDropRecoveryFailure(ambiguous)).recoveryAccounting.unknownMutations, 1);
  assert.equal(JSON.parse(formatRootDropRecoveryFailure(ambiguous)).mutationOutcome, "AMBIGUOUS");
  assert.deepEqual(JSON.parse(formatRootDropRecoveryFailure(new Error("preflight failed"))).recoveryAccounting, { terraformImports: 0, terraformApplies: 0, kmsWrites: 0, iamWrites: 0, unknownMutations: 0, unclassifiedMutations: 0 });
});

test("auto-loaded Terraform variable files are rejected before readiness", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-orphan-auto-tfvars-"));
  try {
    writeFileSync(path.join(directory, "terraform.tfvars"), "vpc_id = \"unreviewed\"\n");
    assert.throws(() => assertNoAutoLoadedTerraformVariableFiles(directory), /auto-loaded/);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("root-drop census consumes every paginated KMS and CloudTrail page", () => {
  const seen = [];
  const adapter = buildRootDropAwsReadAdapter({ profile: "administrator", run: (args) => {
    seen.push(args);
    if (args[0] === "kms" && args[1] === "list-keys") return args.includes("page-2") ? JSON.stringify({ Keys: [{ KeyId: keyId }] }) : JSON.stringify({ Keys: [], NextToken: "page-2" });
    if (args[0] === "kms" && args[1] === "list-aliases") return args.includes("page-2") ? JSON.stringify({ Aliases: [] }) : JSON.stringify({ Aliases: [], NextToken: "page-2" });
    if (args[0] === "cloudtrail") return args.includes("page-2") ? JSON.stringify({ Events: [awsLookupEvent] }) : JSON.stringify({ Events: [], NextToken: "page-2" });
    if (args[0] === "kms" && args[1] === "describe-key") return JSON.stringify({ KeyMetadata: { KeyId: keyId, Arn: keyArn, KeySpec: "RSA_3072", KeyUsage: "SIGN_VERIFY" } });
    if (args[0] === "kms" && args[1] === "list-resource-tags") return JSON.stringify({ Tags: [] });
    if (args[0] === "kms" && args[1] === "get-key-policy") return JSON.stringify({ Policy: encodeURIComponent(JSON.stringify({})) });
    if (args[0] === "kms" && args[1] === "get-public-key") return JSON.stringify(candidate().publicKey);
    throw new Error(`unexpected read ${args.join(" ")}`);
  }});
  assert.deepEqual(adapter.listKeys(), [{ KeyId: keyId }]);
  assert.deepEqual(adapter.listAliases(keyId), []);
  assert.deepEqual(adapter.lookupCreateKeyEvents(keyArn), [event]);
  const census = collectRootDropCensus({ adapter, terraformState: absentState, sourceSha, transitionId, stageAStateIdentity: stateIdentity, failedApplyEvidence });
  assert.equal(census.status, "AMBIGUOUS");
  assert.equal(seen.filter((args) => args[0] === "kms" && args[1] === "list-keys").length, 6);
  assert(seen.some((args) => args.includes("--starting-token") && args.includes("page-2")));
  assert(seen.some((args) => args.includes("--next-token") && args.includes("page-2")));
});

test("real LookupEvents IDs normalize once and survive census JSON round-trip", () => {
  const adapter = realAwsAdapter();
  assert.deepEqual(adapter.lookupCreateKeyEvents(keyArn), [event]);
  const value = realAwsCensus();
  assert.equal(value.status, "AUTHENTICATED_ORPHAN");
  assert.equal(value.candidates[0].creationEventId, failedApplyEvidence.creationEventId);
  const withoutExplicitEventId = { ...failedApplyEvidence };
  delete withoutExplicitEventId.creationEventId;
  const withoutExplicitEvidence = collectRootDropCensus({ adapter: realAwsAdapter(), terraformState: absentState, sourceSha, transitionId, stageAStateIdentity: stateIdentity, failedApplyEvidence: withoutExplicitEventId });
  assert.equal(withoutExplicitEvidence.status, "AUTHENTICATED_ORPHAN");
  assert.equal(withoutExplicitEvidence.candidates[0].creationEventId, event.eventId);
  const persisted = JSON.parse(JSON.stringify(value));
  assert.equal(persisted.censusSha256, rootDropRecoverySha256(Object.fromEntries(Object.entries(persisted).filter(([key]) => key !== "censusSha256"))));
  assert.doesNotThrow(() => assertRootDropCensus(persisted, { sourceSha, transitionId, stageAStateIdentity: stateIdentity }));
});

test("optional failed-apply evidence fields preserve the census digest across JSON persistence", () => {
  for (const omitted of [[], ["creatorArn"], ["creationEventId"], ["creatorArn", "creationEventId"]]) {
    const evidence = { ...failedApplyEvidence };
    for (const field of omitted) delete evidence[field];
    const value = buildRootDropCensus({ sourceSha, transitionId, stageAStateIdentity: stateIdentity, keyUniverse: [], candidates: [], failedApplyEvidence: evidence });
    const persisted = JSON.parse(JSON.stringify(value));
    const unsigned = Object.fromEntries(Object.entries(persisted).filter(([key]) => key !== "censusSha256"));
    assert.equal(value.censusSha256, rootDropRecoverySha256(unsigned), `digest changed for omitted fields: ${omitted.join(",") || "none"}`);
    assert.doesNotThrow(() => assertRootDropCensus(persisted, { sourceSha, transitionId, stageAStateIdentity: stateIdentity }));
  }
});

test("root-drop census adapter binds discovery and CloudTrail provenance to administrator while scoped reads use release", () => {
  const seen = [];
  const adapter = buildRootDropAwsReadAdapter({
    profile: "release",
    discoveryProfile: "administrator",
    provenanceProfile: "administrator",
    run: (args) => {
      seen.push(args);
      if (args[0] === "kms" && args[1] === "describe-key") return JSON.stringify({ KeyMetadata: {} });
      return args[0] === "cloudtrail" ? JSON.stringify({ Events: [] }) : JSON.stringify({ Keys: [] });
    },
  });
  adapter.listKeys();
  adapter.describeKey(keyId);
  adapter.discoveryPublicKey(keyId);
  adapter.listTags(keyId);
  adapter.lookupCreateKeyEvents(keyArn);
  assert.equal(seen[0][seen[0].indexOf("--profile") + 1], "administrator");
  assert.equal(seen[1][seen[1].indexOf("--profile") + 1], "administrator");
  assert.equal(seen[2][seen[2].indexOf("--profile") + 1], "administrator");
  assert.equal(seen[3][seen[3].indexOf("--profile") + 1], "release");
  assert.equal(seen[4][seen[4].indexOf("--profile") + 1], "administrator");
  assert.deepEqual(adapter.actorBindings, { discovery: "ADMINISTRATOR", resourceReads: "RELEASE_DEPLOYER", provenance: "ADMINISTRATOR" });
});

test("root-drop census requires a stable complete key universe across both enumerations", () => {
  const secondKeyId = "22222222-2222-2222-2222-222222222222";
  const metadata = (id) => ({ KeyId: id, Arn: `arn:aws:kms:${STAGE_B.region}:${STAGE_B.account}:key/${id}`, AWSAccountId: STAGE_B.account, KeyState: "Enabled", KeyManager: "AWS", Origin: "AWS_KMS", KeySpec: "SYMMETRIC_DEFAULT", KeyUsage: "ENCRYPT_DECRYPT", MultiRegion: false });
  const adapter = (universes) => {
    let enumeration = 0;
    return {
      listKeys: () => universes[enumeration++],
      describeKey: (id) => metadata(id),
      listTags: () => [],
      getPolicy: () => ({}),
      getPublicKey: () => ({}),
      listAliases: () => [],
      lookupCreateKeyEvents: () => [],
    };
  };
  const collect = (universes) => collectRootDropCensus({ adapter: adapter(universes), terraformState: absentState, sourceSha, transitionId, stageAStateIdentity: stateIdentity, failedApplyEvidence });
  const keys = (ids) => ids.map((KeyId) => ({ KeyId }));
  assert.equal(collect([keys([keyId]), keys([keyId])]).status, "NO_CANDIDATE");
  assert.equal(collect([keys([keyId, secondKeyId]), keys([secondKeyId, keyId])]).status, "NO_CANDIDATE");
  for (const universes of [[keys([keyId]), keys([keyId, secondKeyId])], [keys([keyId, secondKeyId]), keys([keyId])]]) assert.throws(() => collect(universes), /CENSUS_UNSTABLE/);
});

test("root-drop census revalidates candidate attributes at the final observation boundary", () => {
  for (const changed of ["aliases-added", "aliases-removed", "tags", "policy", "metadata"]) {
    const reads = Object.fromEntries(["aliases", "tags", "policy", "metadata", "publicKey", "events"].map((name) => [name, 0]));
    const adapter = {
      listKeys: () => [{ KeyId: keyId }],
      describeKey: () => { reads.metadata += 1; return changed === "metadata" && reads.metadata === 2 ? { ...candidate().metadata, Description: "changed" } : candidate().metadata; },
      listTags: () => { reads.tags += 1; return Object.entries(changed === "tags" && reads.tags === 2 ? { ...candidate().tags, Component: "changed" } : candidate().tags).map(([TagKey, TagValue]) => ({ TagKey, TagValue })); },
      getPolicy: () => { reads.policy += 1; return changed === "policy" && reads.policy === 2 ? { Version: "2012-10-17", Statement: [] } : candidate().policy; },
      getPublicKey: () => { reads.publicKey += 1; return candidate().publicKey; },
      listAliases: () => { reads.aliases += 1; return changed === "aliases-added" && reads.aliases === 2 || changed === "aliases-removed" && reads.aliases === 1 ? [{ AliasName: "alias/unrelated", TargetKeyId: keyId }] : []; },
      lookupCreateKeyEvents: () => { reads.events += 1; return [event]; },
    };
    assert.throws(() => collectRootDropCensus({ adapter, terraformState: absentState, sourceSha, transitionId, stageAStateIdentity: stateIdentity, failedApplyEvidence }), /CENSUS_UNSTABLE/);
  }
  assert.equal(realAwsCensus().status, "AUTHENTICATED_ORPHAN");
});

test("key-universe enumeration errors and malformed identities fail closed", () => {
  for (const listKeys of [
    () => { throw new Error("AccessDenied: kms:ListKeys"); },
    () => [{ KeyId: keyId }, { KeyId: keyId }],
    () => [{ KeyId: "not-a-key-id" }],
  ]) assert.throws(() => collectRootDropCensus({ adapter: { listKeys, describeKey: () => ({}), listTags: () => [], getPolicy: () => ({}), getPublicKey: () => ({}), listAliases: () => [], lookupCreateKeyEvents: () => [] }, terraformState: absentState, sourceSha, transitionId, stageAStateIdentity: stateIdentity, failedApplyEvidence }), /ListKeys|universe|AccessDenied/);
  let calls = 0;
  assert.throws(() => collectRootDropCensus({ adapter: { listKeys: () => { calls += 1; if (calls === 1) return [{ KeyId: keyId }]; throw new Error("AccessDenied on second ListKeys"); }, describeKey: () => ({}), listTags: () => [], getPolicy: () => ({}), getPublicKey: () => ({}), listAliases: () => [], lookupCreateKeyEvents: () => [] }, terraformState: absentState, sourceSha, transitionId, stageAStateIdentity: stateIdentity, failedApplyEvidence }), /AccessDenied/);
  assert.equal(calls, 2);
});

test("privileged coarse discovery excludes unrelated keys without hiding a later root-drop candidate", () => {
  const unrelatedKeyId = "22222222-2222-2222-2222-222222222222";
  const unrelatedArn = `arn:aws:kms:${STAGE_B.region}:${STAGE_B.account}:key/${unrelatedKeyId}`;
  const calls = [];
  const adapter = buildRootDropAwsReadAdapter({
    profile: "release",
    discoveryProfile: "administrator",
    provenanceProfile: "administrator",
    run: (args) => {
      const profile = args[args.indexOf("--profile") + 1];
      calls.push({ args, profile });
      if (args[0] === "kms" && args[1] === "list-keys") return JSON.stringify({ Keys: [{ KeyId: unrelatedKeyId }, { KeyId: keyId }] });
      if (args[0] === "kms" && args[1] === "describe-key" && args.includes(unrelatedKeyId)) return JSON.stringify({ KeyMetadata: { KeyId: unrelatedKeyId, Arn: unrelatedArn, AWSAccountId: STAGE_B.account, KeyManager: "AWS", KeySpec: "SYMMETRIC_DEFAULT", KeyUsage: "ENCRYPT_DECRYPT", Origin: "AWS_KMS", MultiRegion: false } });
      if (args[0] === "kms" && args[1] === "describe-key") return JSON.stringify({ KeyMetadata: candidate().metadata });
      if (args[0] === "kms" && args[1] === "list-resource-tags") return JSON.stringify({ Tags: Object.entries(candidate().tags).map(([TagKey, TagValue]) => ({ TagKey, TagValue })) });
      if (args[0] === "kms" && args[1] === "get-key-policy") return JSON.stringify({ Policy: encodeURIComponent(JSON.stringify(candidate().policy)) });
      if (args[0] === "kms" && args[1] === "get-public-key") return JSON.stringify(candidate().publicKey);
      if (args[0] === "kms" && args[1] === "list-aliases") return JSON.stringify({ Aliases: [] });
      if (args[0] === "cloudtrail") return JSON.stringify({ Events: [awsLookupEvent] });
      throw new Error(`unexpected read ${args.join(" ")}`);
    },
  });
  const result = collectRootDropCensus({ adapter, terraformState: absentState, sourceSha, transitionId, stageAStateIdentity: stateIdentity, failedApplyEvidence });
  assert.equal(result.status, "AUTHENTICATED_ORPHAN");
  assert.equal(result.candidates[0].keyId, keyId);
  assert.deepEqual(calls.filter(({ args }) => args.includes(unrelatedKeyId)).map(({ args, profile }) => ({ action: args.slice(0, 2).join(":"), profile })), [{ action: "kms:describe-key", profile: "administrator" }, { action: "kms:describe-key", profile: "administrator" }]);
  assert(calls.some(({ args, profile }) => args[0] === "kms" && args[1] === "list-resource-tags" && profile === "release"));
});

test("administrator description classification excludes an inaccessible unrelated RSA signing key", () => {
  const unrelatedKeyId = "22222222-2222-2222-2222-222222222222";
  const calls = [];
  const adapter = buildRootDropAwsReadAdapter({
    profile: "release",
    discoveryProfile: "administrator",
    provenanceProfile: "administrator",
    run: (args) => {
      const profile = args[args.indexOf("--profile") + 1];
      calls.push({ args, profile });
      if (args[0] === "kms" && args[1] === "list-keys") return JSON.stringify({ Keys: [{ KeyId: unrelatedKeyId }, { KeyId: keyId }] });
      if (args[0] === "kms" && args[1] === "describe-key" && args.includes(unrelatedKeyId)) return JSON.stringify({ KeyMetadata: { KeyId: unrelatedKeyId, Arn: `arn:aws:kms:${STAGE_B.region}:${STAGE_B.account}:key/${unrelatedKeyId}`, AWSAccountId: STAGE_B.account, KeyState: "Enabled", KeyManager: "CUSTOMER", Origin: "AWS_KMS", KeySpec: "RSA_3072", KeyUsage: "SIGN_VERIFY", MultiRegion: false, Description: "Independent production RLS approval signing key" } });
      if (args[0] === "kms" && args[1] === "describe-key") return JSON.stringify({ KeyMetadata: candidate().metadata });
      if (args[0] === "kms" && args[1] === "list-resource-tags") return JSON.stringify({ Tags: Object.entries(candidate().tags).map(([TagKey, TagValue]) => ({ TagKey, TagValue })) });
      if (args[0] === "kms" && args[1] === "get-key-policy") return JSON.stringify({ Policy: encodeURIComponent(JSON.stringify(candidate().policy)) });
      if (args[0] === "kms" && args[1] === "get-public-key" && args.includes(unrelatedKeyId)) throw new Error("release must not inspect unrelated key public key");
      if (args[0] === "kms" && args[1] === "get-public-key") return JSON.stringify(candidate().publicKey);
      if (args[0] === "kms" && args[1] === "list-aliases") return JSON.stringify({ Aliases: [] });
      if (args[0] === "cloudtrail") return JSON.stringify({ Events: [awsLookupEvent] });
      throw new Error(`unexpected read ${args.join(" ")}`);
    },
  });
  const result = collectRootDropCensus({ adapter, terraformState: absentState, sourceSha, transitionId, stageAStateIdentity: stateIdentity, failedApplyEvidence });
  assert.equal(result.status, "AUTHENTICATED_ORPHAN");
  assert.deepEqual(calls.filter(({ args }) => args.includes(unrelatedKeyId)).map(({ args, profile }) => ({ action: args.slice(0, 2).join(":"), profile })), [{ action: "kms:describe-key", profile: "administrator" }, { action: "kms:describe-key", profile: "administrator" }]);
});

test("release denial on a potentially relevant candidate fails closed instead of becoming NO_CANDIDATE", () => {
  const adapter = buildRootDropAwsReadAdapter({
    profile: "release",
    discoveryProfile: "administrator",
    provenanceProfile: "administrator",
    run: (args) => {
      if (args[0] === "kms" && args[1] === "list-keys") return JSON.stringify({ Keys: [{ KeyId: keyId }] });
      if (args[0] === "kms" && args[1] === "describe-key") return JSON.stringify({ KeyMetadata: candidate().metadata });
      if (args[0] === "kms" && args[1] === "get-public-key" && args.includes("--profile") && args[args.indexOf("--profile") + 1] === "administrator") return JSON.stringify(candidate().publicKey);
      if (args[0] === "kms" && args[1] === "list-resource-tags") throw new Error("AccessDenied: kms:ListResourceTags");
      throw new Error(`unexpected read ${args.join(" ")}`);
    },
  });
  assert.throws(() => collectRootDropCensus({ adapter, terraformState: absentState, sourceSha, transitionId, stageAStateIdentity: stateIdentity, failedApplyEvidence }), /AccessDenied/);
});

test("real LookupEvents wrapper/payload ID disagreement or missing IDs fails closed", () => {
  const entries = [
    { ...awsLookupEvent, EventId: "different-event-id" },
    { ...awsLookupEvent, EventId: undefined },
    { ...awsLookupEvent, CloudTrailEvent: JSON.stringify({ eventName: "CreateKey" }) },
    { EventName: "CreateKey", CloudTrailEvent: JSON.stringify({ eventName: "CreateKey" }) },
    { ...awsLookupEvent, CloudTrailEvent: "not-json" },
  ];
  for (const entry of entries) {
    const adapter = buildRootDropAwsReadAdapter({ profile: "administrator", run: (args) => args[0] === "cloudtrail" ? JSON.stringify({ Events: [entry] }) : JSON.stringify({ Events: [] }) });
    assert.throws(() => adapter.lookupCreateKeyEvents(keyArn), /event ID|malformed/);
  }
});

test("wrong explicit creation-event-id and duplicate CreateKey IDs remain fail closed", () => {
  assert.throws(() => authenticateRootDropOrphan({ candidate: candidate({ creationEvents: [{ ...event, eventId: "different-event-id" }] }), terraformState: absentState, sourceSha, transitionId, failedApplyEvidence }), /event ID/);
  const duplicate = collectRootDropCensus({
    adapter: { listKeys: () => [{ KeyId: keyId }], describeKey: () => candidate().metadata, listTags: () => [], getPolicy: () => ({}), getPublicKey: () => ({}), listAliases: () => [], lookupCreateKeyEvents: () => [{ ...event, eventId: "event-a" }, { ...event, eventId: "event-b" }] },
    terraformState: absentState, sourceSha, transitionId, stageAStateIdentity: stateIdentity, failedApplyEvidence,
  });
  assert.equal(duplicate.status, "AMBIGUOUS");
});

test("fresh census includes a key created after a replayed observation even outside its old failed window", () => {
  const fresh = collectRootDropCensus({
    adapter: {
      listKeys: () => [{ KeyId: keyId }],
      describeKey: () => ({ KeyId: keyId, Arn: keyArn, CreationDate: "2026-08-20T00:00:00.000Z" }),
      lookupCreateKeyEvents: () => [{ eventName: "CreateKey", eventSource: "kms.amazonaws.com", awsRegion: STAGE_B.region, eventTime: "2026-08-20T00:00:01.000Z" }],
      listTags: () => [],
      getPolicy: () => ({}),
      getPublicKey: () => ({}),
      listAliases: () => [],
    },
    terraformState: absentState,
    sourceSha,
    transitionId,
    stageAStateIdentity: stateIdentity,
    failedApplyEvidence,
  });
  assert.equal(fresh.status, "AMBIGUOUS");
  assert.throws(() => assertRootDropCreationInterlock({ plan: exactCreatePlan, terraformState: absentState, census: fresh, sourceSha, transitionId, stageAStateIdentity: stateIdentity }), /blocked/);
});

test("older potentially relevant keys never disappear into NO_CANDIDATE", () => {
  const adapter = {
    listKeys: () => [{ KeyId: keyId }],
    describeKey: () => ({ KeyId: keyId, Arn: keyArn, KeySpec: "RSA_3072", KeyUsage: "SIGN_VERIFY", KeyManager: "CUSTOMER", Origin: "AWS_KMS", MultiRegion: false }),
    listTags: () => Object.entries(TEMPORARY_KMS_CAPABILITY.tags).map(([TagKey, TagValue]) => ({ TagKey, TagValue })),
    getPolicy: () => buildStageARootDropKeyPolicy(),
    getPublicKey: () => ({ KeySpec: "RSA_3072", KeyUsage: "SIGN_VERIFY", SigningAlgorithms: ["RSASSA_PSS_SHA_256"] }),
    listAliases: () => [],
    lookupCreateKeyEvents: () => [{ ...event, eventTime: "2025-01-01T00:00:00.000Z" }],
  };
  const old = collectRootDropCensus({ adapter, terraformState: absentState, sourceSha, transitionId, stageAStateIdentity: stateIdentity, failedApplyEvidence });
  assert.equal(old.status, "AMBIGUOUS");
  assert.throws(() => assertRootDropCreationInterlock({ plan: exactCreatePlan, terraformState: absentState, census: old, sourceSha, transitionId, stageAStateIdentity: stateIdentity }), /blocked/);
  const unrelated = collectRootDropCensus({ adapter: { ...adapter, describeKey: () => ({ KeySpec: "SYMMETRIC_DEFAULT", KeyUsage: "ENCRYPT_DECRYPT" }) }, terraformState: absentState, sourceSha, transitionId, stageAStateIdentity: stateIdentity, failedApplyEvidence });
  assert.equal(unrelated.status, "NO_CANDIDATE");
});

test("missing CloudTrail history for a potentially relevant key fails closed", () => {
  const current = collectRootDropCensus({
    adapter: {
      listKeys: () => [{ KeyId: keyId }], describeKey: () => ({ KeyId: keyId, Arn: keyArn, KeySpec: "RSA_3072", KeyUsage: "SIGN_VERIFY" }),
      listTags: () => [], getPolicy: () => ({}), getPublicKey: () => ({}), listAliases: () => [], lookupCreateKeyEvents: () => [],
    }, terraformState: absentState, sourceSha, transitionId, stageAStateIdentity: stateIdentity, failedApplyEvidence,
  });
  assert.equal(current.status, "AMBIGUOUS");
});

test("an authenticated orphan blocks CreateKey and allows only adoption's alias-only boundary", () => {
  assert.throws(() => assertRootDropCreationInterlock({ plan: exactCreatePlan, terraformState: absentState, census: census(), sourceSha, transitionId, stageAStateIdentity: stateIdentity }), /blocked/);
  assert.doesNotThrow(() => assertRootDropCreationInterlock({ plan: aliasPlan(), terraformState: keyState(), census: census(), sourceSha, transitionId, stageAStateIdentity: stateIdentity }));
  assert.doesNotThrow(() => assertRootDropStateIdentity(ownedState(), { keyId }));
});

test("alias-only recovery plan rejects key creation, replacement, destroy, unrelated, and wrong target", () => {
  assert.doesNotThrow(() => assertRootDropAliasOnlyPlan(aliasPlan(), { keyId }));
  for (const plan of [
    exactCreatePlan,
    aliasPlan([{ address: ROOT_DROP_ALIAS_ADDRESS, change: { actions: ["update", "delete"], after: { name: ROOT_DROP_ALIAS_NAME } } }]),
    aliasPlan([{ address: ROOT_DROP_ALIAS_ADDRESS, change: { actions: ["delete"], after: { name: ROOT_DROP_ALIAS_NAME } } }]),
    aliasPlan([{ address: ROOT_DROP_ALIAS_ADDRESS, change: { actions: ["create"], after: { name: ROOT_DROP_ALIAS_NAME } } }]),
    aliasPlan([{ address: "aws_kms_key.other", change: { actions: ["create"], after: {} } }]),
    aliasPlan([{ address: ROOT_DROP_ALIAS_ADDRESS, change: { actions: ["create"], after: { name: ROOT_DROP_ALIAS_NAME, target_key_id: "22222222-2222-2222-2222-222222222222" } } }]),
  ]) assert.throws(() => assertRootDropAliasOnlyPlan(plan, { keyId }), /only one|target|alias/);
});

function runner({ execute = false, initial = absentState, importOutcome, applyOutcome, plan = aliasPlan(), zeroDrift = { resource_changes: [] }, injectFresh = true } = {}) {
  let current = initial;
  let imports = 0;
  let applies = 0;
  const recovery = createRootDropRecoveryRunner({ execute, readState: async () => current, readStateSnapshot: async () => ({ state: current, stateBytes: Buffer.from(JSON.stringify(current)) }), importKey: async () => { imports += 1; if (importOutcome) { const error = new Error(importOutcome); error.mutationOutcome = importOutcome; throw error; } current = keyState(); }, refreshState: async () => current, createPlan: async ({ zeroDrift: requested }) => requested ? "zero" : "alias", readPlan: async (path) => path === "zero" ? zeroDrift : plan, readPlanBytes: async (path) => Buffer.from(path), applyPlan: async () => { applies += 1; if (applyOutcome) { const error = new Error(applyOutcome); error.mutationOutcome = applyOutcome; throw error; } current = ownedState(); }, });
  return {
    counts: () => ({ imports, applies }),
    run: (input) => injectFresh ? recovery({ ...input, freshCensus: input.freshCensus || input.census }) : recovery(input),
  };
}

test("dry-run cannot import an absent key; replay dry-run remains mutation-free", async () => {
  const value = runner();
  await assert.rejects(() => value.run({ census: census(), terraformState: absentState, stageAStateIdentity: stateIdentity, sourceSha, transitionId, planSha256: failedApplyEvidence.planSha256 }), /explicit recovery execution authorization/);
  assert.deepEqual(value.counts(), { imports: 0, applies: 0 });
  const replay = runner({ initial: keyState() });
  const result = await replay.run({ census: keyOnlyCensus(), terraformState: keyState(), stageAStateIdentity: keyOnlyStateIdentity(), sourceSha, transitionId, planSha256: failedApplyEvidence.planSha256 });
  assert.equal(result.status, "READY_FOR_ALIAS_ADOPTION");
  assert.deepEqual(result.accounting, { terraformImports: 0, terraformApplies: 0, kmsWrites: 0, iamWrites: 0, unknownMutations: 0, unclassifiedMutations: 0 });
  assert.deepEqual(replay.counts(), { imports: 0, applies: 0 });
});

test("adoption reaches its read-only boundary with normalized real AWS event evidence", async () => {
  const value = runner({ initial: keyState() });
  const real = realAwsCensus();
  const persisted = JSON.parse(JSON.stringify(real));
  const keyOnly = buildRootDropCensus({ sourceSha, transitionId, stageAStateIdentity: keyOnlyStateIdentity(), keyUniverse: [keyId], candidates: [{ ...candidate(), ...authenticated() }], failedApplyEvidence });
  const persistedKeyOnly = JSON.parse(JSON.stringify(keyOnly));
  const result = await value.run({ census: persistedKeyOnly, freshCensus: persistedKeyOnly, terraformState: keyState(), stageAStateIdentity: keyOnlyStateIdentity(), sourceSha, transitionId, planSha256: failedApplyEvidence.planSha256 });
  assert.equal(result.status, "READY_FOR_ALIAS_ADOPTION");
  assert.deepEqual(value.counts(), { imports: 0, applies: 0 });
});

test("successful adoption imports exactly once, creates only the alias, verifies ownership, and proves zero drift", async () => {
  const value = runner({ execute: true });
  const result = await value.run({ census: census(), freshCensus: census(), terraformState: absentState, stageAStateIdentity: stateIdentity, sourceSha, transitionId, planSha256: failedApplyEvidence.planSha256 });
  assert.equal(result.status, "RECOVERED");
  assert.deepEqual(result.accounting, { terraformImports: 1, terraformApplies: 1, kmsWrites: 1, iamWrites: 0, unknownMutations: 0, unclassifiedMutations: 0 });
  assert.deepEqual(value.counts(), { imports: 1, applies: 1 });
});

test("historical policy adoption converges policy before reporting the alias recovered", async () => {
  const legacyCensus = buildRootDropCensus({ sourceSha: ROOT_DROP_LEGACY_POLICY_BINDING.sourceSha, transitionId: ROOT_DROP_LEGACY_POLICY_BINDING.transitionId, stageAStateIdentity: stateIdentity, keyUniverse: [legacyKeyId], candidates: [{ ...legacyCandidate(), ...authenticateRootDropOrphan({ candidate: legacyCandidate(), terraformState: absentState, sourceSha: ROOT_DROP_LEGACY_POLICY_BINDING.sourceSha, transitionId: ROOT_DROP_LEGACY_POLICY_BINDING.transitionId, failedApplyEvidence: legacyFailedApplyEvidence }) }], failedApplyEvidence: legacyFailedApplyEvidence });
  const legacyState = stateWithRootDropPolicy({ ...keyState(), resources: keyState().resources.map((resource) => resource.type === "aws_kms_key" && resource.name === "root_drop" ? { ...resource, instances: [{ schema_version: 0, attributes: { arn: legacyKeyArn, key_id: legacyKeyId, key_usage: "SIGN_VERIFY", customer_master_key_spec: "RSA_3072" } }] } : resource) }, buildLegacyRootDropKeyPolicy());
  const canonicalOwnedState = stateWithRootDropPolicy({ ...ownedState(), resources: ownedState().resources.map((resource) => resource.type === "aws_kms_key" && resource.name === "root_drop" ? { ...resource, instances: [{ schema_version: 0, attributes: { arn: legacyKeyArn, key_id: legacyKeyId, key_usage: "SIGN_VERIFY", customer_master_key_spec: "RSA_3072" } }] } : resource.type === "aws_kms_alias" && resource.name === "root_drop" ? { ...resource, instances: [{ schema_version: 0, attributes: { arn: STAGE_B.rootDropKmsKeyArn, target_key_id: legacyKeyId, target_key_arn: legacyKeyArn } }] } : resource) }, buildStageARootDropKeyPolicy());
  let current = absentState;
  let imports = 0;
  let applies = 0;
  const recovery = createRootDropRecoveryRunner({
    execute: true,
    readState: async () => current,
    readStateSnapshot: async () => ({ state: current, stateBytes: Buffer.from(JSON.stringify(current)) }),
    importKey: async () => { imports += 1; current = legacyState; return { outcome: "CONFIRMED_SUCCESS" }; },
    refreshState: async () => current,
    createPlan: async ({ zeroDrift }) => zeroDrift ? "zero-drift" : "legacy-alias",
    readPlan: async (path) => path === "zero-drift" ? { resource_changes: [] } : legacyAliasPolicyPlan({ key: legacyKeyId }),
    readPlanBytes: async (path) => Buffer.from(path),
    applyPlan: async () => { applies += 1; current = canonicalOwnedState; return { outcome: "CONFIRMED_SUCCESS" }; },
  });
  const result = await recovery({ census: legacyCensus, freshCensus: legacyCensus, terraformState: absentState, stageAStateIdentity: stateIdentity, sourceSha: ROOT_DROP_LEGACY_POLICY_BINDING.sourceSha, transitionId: ROOT_DROP_LEGACY_POLICY_BINDING.transitionId, planSha256: ROOT_DROP_LEGACY_POLICY_BINDING.planSha256 });
  assert.equal(result.status, "RECOVERED");
  assert.deepEqual({ imports, applies }, { imports: 1, applies: 1 });
  assert.equal(result.accounting.kmsWrites, 2);
  assert.doesNotThrow(() => assertRootDropStateIdentity(current, { keyId: legacyKeyId, requireCanonicalPolicy: true }));
});

test("successful import replay never imports again", async () => {
  const value = runner({ initial: keyState() });
  const result = await value.run({ census: keyOnlyCensus(), terraformState: keyState(), stageAStateIdentity: keyOnlyStateIdentity(), sourceSha, transitionId, planSha256: failedApplyEvidence.planSha256 });
  assert.equal(result.accounting.terraformImports, 0);
  assert.deepEqual(value.counts(), { imports: 0, applies: 0 });
});

test("S1 key-only retry accepts only the alias plan and never reimports", async () => {
  const value = runner({ execute: true, initial: keyState() });
  const result = await value.run({ census: keyOnlyCensus(), freshCensus: keyOnlyCensus(), terraformState: keyState(), stageAStateIdentity: keyOnlyStateIdentity(), sourceSha, transitionId, planSha256: failedApplyEvidence.planSha256 });
  assert.equal(result.status, "RECOVERED");
  assert.equal(result.accounting.terraformImports, 0);
  assert.equal(result.accounting.terraformApplies, 1);
  assert.deepEqual(value.counts(), { imports: 0, applies: 1 });
});

test("S2 replay validates ownership and zero drift without import or apply", async () => {
  const value = runner({ execute: true, initial: ownedState() });
  const result = await value.run({ census: keyOnlyCensus(), terraformState: ownedState(), stageAStateIdentity: ownedStateIdentity(), sourceSha, transitionId, planSha256: failedApplyEvidence.planSha256 });
  assert.equal(result.status, "ALREADY_RECOVERED");
  assert.deepEqual(result.accounting, { terraformImports: 0, terraformApplies: 0, kmsWrites: 0, iamWrites: 0, unknownMutations: 0, unclassifiedMutations: 0 });
  assert.deepEqual(value.counts(), { imports: 0, applies: 0 });
});

test("stale S0 and S1 census evidence cannot authorize a mutation", async () => {
  const staleS0 = census();
  staleS0.observedAt = "2020-01-01T00:00:00.000Z";
  staleS0.censusSha256 = rootDropRecoverySha256(Object.fromEntries(Object.entries(staleS0).filter(([key]) => key !== "censusSha256")));
  const s0 = runner({ execute: true, injectFresh: false });
  await assert.rejects(() => s0.run({ census: staleS0, terraformState: absentState, stageAStateIdentity: stateIdentity, sourceSha, transitionId, planSha256: failedApplyEvidence.planSha256 }), /fresh authoritative census|stale/);
  assert.deepEqual(s0.counts(), { imports: 0, applies: 0 });

  const staleS1 = keyOnlyCensus();
  staleS1.observedAt = "2020-01-01T00:00:00.000Z";
  staleS1.censusSha256 = rootDropRecoverySha256(Object.fromEntries(Object.entries(staleS1).filter(([key]) => key !== "censusSha256")));
  const s1 = runner({ execute: true, initial: keyState(), injectFresh: false });
  await assert.rejects(() => s1.run({ census: staleS1, terraformState: keyState(), stageAStateIdentity: keyOnlyStateIdentity(), sourceSha, transitionId, planSha256: failedApplyEvidence.planSha256 }), /fresh authoritative census|stale/);
  assert.deepEqual(s1.counts(), { imports: 0, applies: 0 });
});

test("expired S2 census replay is already recovered and remains mutation-free", async () => {
  const staleS2 = keyOnlyCensus();
  staleS2.observedAt = "2020-01-01T00:00:00.000Z";
  staleS2.censusSha256 = rootDropRecoverySha256(Object.fromEntries(Object.entries(staleS2).filter(([key]) => key !== "censusSha256")));
  const value = runner({ execute: true, initial: ownedState() });
  const result = await value.run({ census: staleS2, terraformState: ownedState(), stageAStateIdentity: ownedStateIdentity(), sourceSha, transitionId, planSha256: failedApplyEvidence.planSha256 });
  assert.equal(result.status, "ALREADY_RECOVERED");
  assert.deepEqual(result.accounting, { terraformImports: 0, terraformApplies: 0, kmsWrites: 0, iamWrites: 0, unknownMutations: 0, unclassifiedMutations: 0 });
  assert.deepEqual(value.counts(), { imports: 0, applies: 0 });
});

test("S1 retry rejects changed candidate topology before mutation", async () => {
  const cases = [
    ["different key", buildRootDropCensus({ sourceSha, transitionId, stageAStateIdentity: keyOnlyStateIdentity(), keyUniverse: [keyId, "22222222-2222-2222-2222-222222222222"], candidates: [{ ...candidate({ keyId: "22222222-2222-2222-2222-222222222222", arn: `arn:aws:kms:${STAGE_B.region}:${STAGE_B.account}:key/22222222-2222-2222-2222-222222222222` }), authenticated: false, reason: "different" }, { ...candidate(), ...authenticated() }], failedApplyEvidence })],
    ["unexpected alias", buildRootDropCensus({ sourceSha, transitionId, stageAStateIdentity: keyOnlyStateIdentity(), keyUniverse: [keyId], candidates: [{ ...candidate(), ...authenticated(), aliases: [{ AliasName: "alias/unrelated", TargetKeyId: keyId }] }], failedApplyEvidence })],
  ];
  for (const [label, changed] of cases) {
    const value = runner({ execute: true, initial: keyState() });
    await assert.rejects(() => value.run({ census: keyOnlyCensus(), freshCensus: changed, terraformState: keyState(), stageAStateIdentity: keyOnlyStateIdentity(), sourceSha, transitionId, planSha256: failedApplyEvidence.planSha256 }), /changed|candidate|trust boundary|authenticated/ , label);
    assert.deepEqual(value.counts(), { imports: 0, applies: 0 }, label);
  }
});

test("alias saved-plan bytes are revalidated immediately before apply", async () => {
  let reads = 0;
  let applies = 0;
  const recovery = createRootDropRecoveryRunner({
    execute: true,
    readState: async () => keyState(),
    readStateSnapshot: async () => ({ state: keyState(), stateBytes: Buffer.from(JSON.stringify(keyState())) }),
    importKey: async () => { throw new Error("reimport must not occur"); },
    refreshState: async () => keyState(),
    createPlan: async () => "alias",
    readPlan: async () => aliasPlan(),
    readPlanBytes: async () => Buffer.from(reads++ === 0 ? "classified-plan" : "replaced-plan"),
    applyPlan: async () => { applies += 1; },
  });
  await assert.rejects(() => recovery({ census: keyOnlyCensus(), freshCensus: keyOnlyCensus(), terraformState: keyState(), stageAStateIdentity: keyOnlyStateIdentity(), sourceSha, transitionId, planSha256: failedApplyEvidence.planSha256 }), /changed after classification/);
  assert.equal(applies, 0);
});

test("state identity changes with unchanged root-drop counts block import", async () => {
  const changedState = { ...absentState, serial: absentState.serial + 1 };
  const changedStateBytes = Buffer.from(JSON.stringify(changedState));
  let imports = 0;
  const recovery = createRootDropRecoveryRunner({
    execute: true,
    readState: async () => changedState,
    readStateSnapshot: async () => ({ state: changedState, stateBytes: changedStateBytes }),
    importKey: async () => { imports += 1; },
    refreshState: async () => keyState(),
    createPlan: async () => "alias",
    readPlan: async () => aliasPlan(),
    readPlanBytes: async () => Buffer.from("alias-plan"),
    applyPlan: async () => ({ outcome: "CONFIRMED_SUCCESS" }),
  });
  await assert.rejects(() => recovery({ census: census(), freshCensus: census(), terraformState: absentState, stageAStateIdentity: stateIdentity, sourceSha, transitionId, planSha256: failedApplyEvidence.planSha256 }), /state identity|authenticated snapshot/);
  assert.equal(imports, 0);
});

test("every post-mutation recovery failure preserves the accumulated accounting", async () => {
  const cases = [
    {
      name: "import refresh",
      terraformState: absentState,
      build: () => createRootDropRecoveryRunner({
        execute: true,
        readState: async () => absentState,
        readStateSnapshot: async () => ({ state: absentState, stateBytes: Buffer.from(JSON.stringify(absentState)) }),
        importKey: async () => ({ outcome: "CONFIRMED_SUCCESS" }),
        refreshState: async () => { throw new Error("refresh failed after import"); },
        createPlan: async () => "alias",
        readPlan: async () => aliasPlan(),
        readPlanBytes: async () => Buffer.from("alias-plan"),
        applyPlan: async () => ({ outcome: "CONFIRMED_SUCCESS" }),
      }),
    },
    {
      name: "post-import plan",
      terraformState: absentState,
      build: () => createRootDropRecoveryRunner({
        execute: true,
        readState: async () => absentState,
        readStateSnapshot: async () => ({ state: absentState, stateBytes: Buffer.from(JSON.stringify(absentState)) }),
        importKey: async () => ({ outcome: "CONFIRMED_SUCCESS" }),
        refreshState: async () => keyState(),
        createPlan: async () => { throw new Error("plan failed after import"); },
        readPlan: async () => aliasPlan(),
        readPlanBytes: async () => Buffer.from("alias-plan"),
        applyPlan: async () => ({ outcome: "CONFIRMED_SUCCESS" }),
      }),
    },
    {
      name: "post-apply readback",
      terraformState: keyState(),
      build: () => createRootDropRecoveryRunner({
        execute: true,
        readState: async () => keyState(),
        readStateSnapshot: async () => ({ state: keyState(), stateBytes: Buffer.from(JSON.stringify(keyState())) }),
        importKey: async () => ({ outcome: "CONFIRMED_SUCCESS" }),
        refreshState: async () => { throw new Error("readback failed after alias apply"); },
        createPlan: async () => "alias",
        readPlan: async () => aliasPlan(),
        readPlanBytes: async () => Buffer.from("alias-plan"),
        applyPlan: async () => ({ outcome: "CONFIRMED_SUCCESS" }),
      }),
    },
  ];
  for (const { name, terraformState, build } of cases) {
    const inputCensus = name === "post-apply readback" ? keyOnlyCensus() : census();
    const inputIdentity = name === "post-apply readback" ? keyOnlyStateIdentity() : stateIdentity;
    await assert.rejects(
      () => build()({ census: inputCensus, freshCensus: inputCensus, terraformState, stageAStateIdentity: inputIdentity, sourceSha, transitionId, planSha256: failedApplyEvidence.planSha256 }),
      (error) => error.recoveryAccounting.terraformImports === (name === "post-apply readback" ? 0 : 1)
        && error.recoveryAccounting.terraformApplies === (name === "post-apply readback" ? 1 : 0)
        && error.recoveryAccounting.unknownMutations === 0,
    );
  }
});

test("definite and ambiguous import failures are never retried and are distinguished", async () => {
  for (const outcome of ["DEFINITE_FAILURE", "AMBIGUOUS"]) {
    const value = runner({ execute: true, importOutcome: outcome });
    await assert.rejects(() => value.run({ census: census(), terraformState: absentState, stageAStateIdentity: stateIdentity, sourceSha, transitionId, planSha256: failedApplyEvidence.planSha256 }), new RegExp(outcome === "AMBIGUOUS" ? "ambiguous" : "DEFINITE_FAILURE|definitely", "i"));
    assert.deepEqual(value.counts(), { imports: 1, applies: 0 });
  }
});

test("refresh denial, wrong imported key, alias failure, ambiguous alias apply, and non-zero drift fail closed", async () => {
  const wrongState = { ...keyState(), resources: keyState().resources.map((resource) => resource.type === "aws_kms_key" && resource.name === "root_drop" ? { ...resource, instances: [{ attributes: { arn: `arn:aws:kms:${STAGE_B.region}:${STAGE_B.account}:key/22222222-22222222-2222-2222-222222222222`, key_id: "22222222-2222-2222-2222-222222222222", key_usage: "SIGN_VERIFY", customer_master_key_spec: "RSA_3072" } }] } : resource) };
  const wrong = createRootDropRecoveryRunner({ execute: true, readState: async () => wrongState, readStateSnapshot: async () => ({ state: wrongState, stateBytes: Buffer.from(JSON.stringify(wrongState)) }), importKey: async () => {}, refreshState: async () => wrongState, createPlan: async () => "alias", readPlan: async () => aliasPlan(), readPlanBytes: async () => Buffer.from("alias-plan"), applyPlan: async () => {} });
  await assert.rejects(() => wrong({ census: keyOnlyCensus(), freshCensus: keyOnlyCensus(), terraformState: keyState(), stageAStateIdentity: keyOnlyStateIdentity(), sourceSha, transitionId, planSha256: failedApplyEvidence.planSha256 }));
  for (const [label, options] of [["alias failure", { execute: true, applyOutcome: "DEFINITE_FAILURE" }], ["ambiguous alias", { execute: true, applyOutcome: "AMBIGUOUS" }], ["drift", { execute: true, zeroDrift: aliasPlan() }]]) {
    const value = runner(options);
    await assert.rejects(() => value.run({ census: census(), terraformState: absentState, stageAStateIdentity: stateIdentity, sourceSha, transitionId, planSha256: failedApplyEvidence.planSha256 }), new RegExp(label === "drift" ? "zero drift" : "DEFINITE_FAILURE|ambiguous|alias", "i"));
  }
});

test("adoption rejects a supplied census when fresh re-census finds a changed alias", async () => {
  const value = runner({ execute: true });
  const changed = buildRootDropCensus({ sourceSha, transitionId, stageAStateIdentity: stateIdentity, keyUniverse: [keyId], candidates: [{ ...candidate(), aliases: [{ AliasName: "alias/unrelated", TargetKeyId: keyId }] }], failedApplyEvidence });
  await assert.rejects(() => value.run({ census: census(), freshCensus: changed, terraformState: absentState, stageAStateIdentity: stateIdentity, sourceSha, transitionId, planSha256: failedApplyEvidence.planSha256 }), /changed|trust boundary/);
  assert.deepEqual(value.counts(), { imports: 0, applies: 0 });
});

test("adoption requires fresh census evidence and accepts only a fresh replacement for stale supplied evidence", async () => {
  const value = runner({ initial: keyState() });
  const supplied = census(); supplied.observedAt = "2020-01-01T00:00:00.000Z"; delete supplied.censusSha256; supplied.censusSha256 = rootDropRecoverySha256(Object.fromEntries(Object.entries(supplied).filter(([key]) => key !== "censusSha256")));
  const fresh = keyOnlyCensus();
  const result = await value.run({ census: supplied, freshCensus: fresh, terraformState: keyState(), stageAStateIdentity: keyOnlyStateIdentity(), sourceSha, transitionId, planSha256: failedApplyEvidence.planSha256 });
  assert.equal(result.status, "READY_FOR_ALIAS_ADOPTION");
  const noFresh = runner({ initial: keyState(), injectFresh: false });
  await assert.rejects(() => noFresh.run({ census: fresh, terraformState: keyState(), stageAStateIdentity: keyOnlyStateIdentity(), sourceSha, transitionId, planSha256: failedApplyEvidence.planSha256 }), /fresh authoritative census/);
});

test("multiple candidates, wrong default/state conflict, and no candidate are fail closed at the workflow boundary", async () => {
  const ambiguous = buildRootDropCensus({ sourceSha, transitionId, stageAStateIdentity: stateIdentity, keyUniverse: [keyId, "22222222-2222-2222-2222-222222222222"], candidates: [{ authenticated: false, keyId }, { authenticated: false, keyId: "22222222-2222-2222-2222-222222222222" }] });
  await assert.rejects(() => runner().run({ census: ambiguous, terraformState: absentState, stageAStateIdentity: stateIdentity, sourceSha, transitionId, planSha256: failedApplyEvidence.planSha256 }), /ambiguous|candidate/);
  await assert.rejects(() => runner().run({ census: noCandidateCensus(), terraformState: absentState, stageAStateIdentity: stateIdentity, sourceSha, transitionId, planSha256: failedApplyEvidence.planSha256 }), /authenticated candidate/);
});
