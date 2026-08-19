import assert from "node:assert/strict";
import crypto from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
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
  assertRootDropAliasOnlyPlan,
  assertRootDropCensus,
  assertRootDropCreationInterlock,
  assertRootDropStateIdentity,
  authenticateRootDropOrphan,
  buildRootDropCensus,
  buildRootDropAwsReadAdapter,
  collectRootDropCensus,
  rootDropRecoverySha256,
  createRootDropRecoveryRunner,
  STAGE_A_TERRAFORM_BACKEND,
  assertStageATerraformBackendMetadata,
} from "../aws/production-stage-a-root-drop-orphan-recovery.mjs";
import { runAdoption, runCensus } from "../aws/recover-production-green-stage-a-root-drop-orphan.mjs";
import { productionStageAState } from "./fixtures/production-stage-a-state.mjs";

const sourceSha = "f03fb3266385486d25317b8c2b202c408ae8771f";
const transitionId = "stage-a-root-drop-orphan-recovery-20260819";
const keyId = "11111111-1111-1111-1111-111111111111";
const keyArn = `arn:aws:kms:${STAGE_B.region}:${STAGE_B.account}:key/${keyId}`;
const state = productionStageAState({ serial: 46 });
const absentState = { ...state, resources: state.resources.map((resource) => (resource.type === "aws_kms_key" && resource.name === "root_drop") || (resource.type === "aws_kms_alias" && resource.name === "root_drop") ? { ...resource, instances: [] } : resource) };
const stateBytes = Buffer.from(JSON.stringify(absentState));
const stateIdentity = buildStageAStateIdentity(absentState, { stateBytes });
const failedApplyEvidence = { sourceSha, transitionId, planSha256: crypto.createHash("sha256").update("exact-plan").digest("hex"), creatorArn: "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/launch", creationEventId: "event-root-drop-1", failedApplyWindow: { start: "2026-08-19T00:00:00.000Z", end: "2026-08-19T23:59:59.999Z" } };
const event = { eventId: failedApplyEvidence.creationEventId, eventName: "CreateKey", eventSource: "kms.amazonaws.com", awsRegion: STAGE_B.region, recipientAccountId: STAGE_B.account, eventTime: "2026-08-19T12:00:00.000Z", userIdentity: { arn: failedApplyEvidence.creatorArn }, resources: [{ ARN: keyArn }] };
const awsLookupEvent = { EventId: event.eventId, EventName: event.eventName, EventSource: event.eventSource, EventTime: event.eventTime, CloudTrailEvent: JSON.stringify({ eventID: event.eventId, eventName: event.eventName, eventSource: event.eventSource, awsRegion: event.awsRegion, recipientAccountId: event.recipientAccountId, eventTime: event.eventTime, userIdentity: event.userIdentity, resources: event.resources }) };
const candidate = (overrides = {}) => ({
  keyId,
  arn: keyArn,
  metadata: { KeyId: keyId, Arn: keyArn, AWSAccountId: STAGE_B.account, KeyState: "Enabled", KeyManager: "CUSTOMER", Origin: "AWS_KMS", KeySpec: "RSA_3072", KeyUsage: "SIGN_VERIFY", MultiRegion: false, Description: ROOT_DROP_KEY_DESCRIPTION },
  tags: { ...TEMPORARY_KMS_CAPABILITY.tags },
  policy: buildStageARootDropKeyPolicy(),
  publicKey: { KeyId: keyId, KeySpec: "RSA_3072", KeyUsage: "SIGN_VERIFY", SigningAlgorithms: ["RSASSA_PSS_SHA_256"] },
  aliases: [],
  creationEvents: [event],
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
  { address: ROOT_DROP_KEY_ADDRESS, change: { actions: ["create"], after: { policy: JSON.stringify(buildStageARootDropKeyPolicy()), customer_master_key_spec: "RSA_3072", key_usage: "SIGN_VERIFY", bypass_policy_lockout_safety_check: false } } },
  { address: ROOT_DROP_ALIAS_ADDRESS, change: { actions: ["create"], after: { name: ROOT_DROP_ALIAS_NAME } } },
] };
const aliasPlan = (changes = [{ address: ROOT_DROP_ALIAS_ADDRESS, change: { actions: ["create"], after: { name: ROOT_DROP_ALIAS_NAME, target_key_id: keyId } } }]) => ({ resource_changes: changes });
const keyState = () => ({ ...absentState, resources: absentState.resources.map((resource) => resource.type === "aws_kms_key" && resource.name === "root_drop" ? { ...resource, instances: [{ schema_version: 0, attributes: { arn: keyArn, key_id: keyId, key_usage: "SIGN_VERIFY", customer_master_key_spec: "RSA_3072" } }] } : resource) });
const ownedState = () => ({ ...keyState(), resources: keyState().resources.map((resource) => resource.type === "aws_kms_alias" && resource.name === "root_drop" ? { ...resource, instances: [{ schema_version: 0, attributes: { arn: STAGE_B.rootDropKmsKeyArn, target_key_id: keyId, target_key_arn: keyArn } }] } : resource) });

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
  const saved = Object.fromEntries(["AWS_PROFILE", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN", "AWS_DEFAULT_PROFILE", "AWS_REGION", "AWS_DEFAULT_REGION", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE", "TF_DATA_DIR", "TF_WORKSPACE", "TF_CLI_CONFIG_FILE", "TF_CLI_ARGS", "TF_CLI_ARGS_init", "TF_CLI_ARGS_import", "TF_CLI_ARGS_plan", "TF_CLI_ARGS_apply", "TF_VAR_aws_region"].map((key) => [key, process.env[key]]));
  const restore = () => { for (const [key, value] of Object.entries(saved)) { if (value === undefined) delete process.env[key]; else process.env[key] = value; } };
  const observedAws = [];
  const observedTerraform = [];
  let currentState = absentState;
  try {
    Object.assign(process.env, { AWS_PROFILE: "administrator", AWS_ACCESS_KEY_ID: "ambient-key", AWS_SECRET_ACCESS_KEY: "ambient-secret", AWS_SESSION_TOKEN: "ambient-session", AWS_SECURITY_TOKEN: "ambient-security", AWS_DEFAULT_PROFILE: "ambient-default", AWS_REGION: "us-east-1", AWS_DEFAULT_REGION: "us-east-1", AWS_CONFIG_FILE: "/tmp/config", AWS_SHARED_CREDENTIALS_FILE: "/tmp/credentials", TF_DATA_DIR: "/tmp/hostile-data", TF_WORKSPACE: "wrong-workspace", TF_CLI_CONFIG_FILE: "/tmp/hostile-cli.tfrc", TF_CLI_ARGS: "-refresh=false", TF_CLI_ARGS_init: "-backend-config=/tmp/wrong-backend", TF_CLI_ARGS_import: "-state=/tmp/wrong.tfstate", TF_CLI_ARGS_plan: "-target=aws_kms_key.wrong", TF_CLI_ARGS_apply: "-auto-approve", TF_VAR_aws_region: "us-east-1" });
    await runCensus({ argv: ["--admin-profile", "administrator", "--release-profile", "release", "--stage-a-state", statePath, "--stage-a-state-identity", identityPath, "--source-sha", sourceSha, "--transition-id", transitionId, "--plan-sha256", failedApplyEvidence.planSha256, "--failed-apply-start", failedApplyEvidence.failedApplyWindow.start, "--failed-apply-end", failedApplyEvidence.failedApplyWindow.end, "--output", outputPath], execFile: (command, args, options) => { observedAws.push({ command, args, env: options.env }); return JSON.stringify({ Keys: [] }); }, write: () => {} });
    assert.equal(observedAws[0].args[observedAws[0].args.indexOf("--profile") + 1], "administrator");
    assert.equal(observedAws[0].env.AWS_PROFILE, "release");
    assert.equal(observedAws[0].env.AWS_REGION, STAGE_B.region);
    assert.equal(observedAws[0].env.AWS_DEFAULT_REGION, STAGE_B.region);
    for (const key of ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN", "AWS_DEFAULT_PROFILE"]) assert.equal(observedAws[0].env[key], undefined);
    assert.equal(observedAws[0].env.AWS_CONFIG_FILE, "/tmp/config");
    assert.equal(observedAws[0].env.AWS_SHARED_CREDENTIALS_FILE, "/tmp/credentials");
    let adoptionCensusProfile;
    const result = await runAdoption({ argv: ["--census", censusPath, "--stage-a-state", statePath, "--stage-a-state-identity", identityPath, "--admin-profile", "administrator", "--release-profile", "release", "--terraform-root", terraformRoot, "--plan-path", planPath, "--execute"], readRootDropCensus: ({ profile, adminProfile, releaseProfile }) => { adoptionCensusProfile = { profile, adminProfile, releaseProfile }; return suppliedCensus; }, readTerraformBackendMetadata: () => ({ type: STAGE_A_TERRAFORM_BACKEND.type, config: { bucket: STAGE_A_TERRAFORM_BACKEND.bucket, key: STAGE_A_TERRAFORM_BACKEND.key, region: STAGE_A_TERRAFORM_BACKEND.region, encrypt: STAGE_A_TERRAFORM_BACKEND.encrypt, use_lockfile: STAGE_A_TERRAFORM_BACKEND.use_lockfile } }), execFile: (command, args, options) => {
      observedTerraform.push({ command, args, env: options.env });
      if (args.includes("workspace") && args.includes("show")) return "default\n";
      if (args.includes("state") && args.includes("pull")) return JSON.stringify(currentState);
      if (args.includes("import")) { currentState = keyState(); return ""; }
      if (args.includes("apply")) { currentState = ownedState(); return ""; }
      if (args.includes("show")) return JSON.stringify(args.at(-1).endsWith("zero-drift") ? { resource_changes: [] } : aliasPlan());
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
      for (const key of ["TF_DATA_DIR", "TF_WORKSPACE", "TF_CLI_CONFIG_FILE", "TF_CLI_ARGS", "TF_CLI_ARGS_init", "TF_CLI_ARGS_import", "TF_CLI_ARGS_plan", "TF_CLI_ARGS_apply", "TF_VAR_aws_region"]) assert.equal(env[key], undefined);
      assert.equal(env.AWS_CONFIG_FILE, "/tmp/config");
      assert.equal(env.AWS_SHARED_CREDENTIALS_FILE, "/tmp/credentials");
    }
    assert.deepEqual({ AWS_PROFILE: process.env.AWS_PROFILE, AWS_REGION: process.env.AWS_REGION, AWS_DEFAULT_REGION: process.env.AWS_DEFAULT_REGION }, { AWS_PROFILE: "administrator", AWS_REGION: "us-east-1", AWS_DEFAULT_REGION: "us-east-1" });
  } finally { restore(); rmSync(directory, { recursive: true, force: true }); }
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
      readRootDropCensus: async () => census(),
      execFile: () => { terraformCalls += 1; throw new Error("Terraform must not run"); },
      write: () => {},
    }), /canonical production Stage-A Terraform root/);
    assert.equal(terraformCalls, 0);
  } finally { rmSync(directory, { recursive: true, force: true }); }
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
  try {
    writeFileSync(statePath, stateBytes, { mode: 0o600 });
    writeFileSync(identityPath, `${JSON.stringify(stateIdentity)}\n`, { mode: 0o600 });
    writeFileSync(censusPath, `${JSON.stringify(census())}\n`, { mode: 0o600 });
    let terraformCalls = 0;
    await assert.rejects(() => runAdoption({
      argv: ["--census", censusPath, "--stage-a-state", statePath, "--stage-a-state-identity", identityPath, "--admin-profile", "administrator", "--release-profile", "release", "--plan-path", path.join(directory, "alias.plan"), "--execute"],
      readRootDropCensus: async () => census(),
      readTerraformBackendMetadata: () => ({ type: STAGE_A_TERRAFORM_BACKEND.type, config: { bucket: STAGE_A_TERRAFORM_BACKEND.bucket, key: STAGE_A_TERRAFORM_BACKEND.key, region: STAGE_A_TERRAFORM_BACKEND.region, encrypt: STAGE_A_TERRAFORM_BACKEND.encrypt, use_lockfile: STAGE_A_TERRAFORM_BACKEND.use_lockfile } }),
      execFile: () => { terraformCalls += 1; return "wrong-workspace\n"; },
      write: () => {},
    }), /canonical default Terraform workspace/);
    assert.equal(terraformCalls, 1);
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
    if (args[0] === "kms" && args[1] === "get-public-key") return JSON.stringify({});
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
  adapter.listTags(keyId);
  adapter.lookupCreateKeyEvents(keyArn);
  assert.equal(seen[0][seen[0].indexOf("--profile") + 1], "administrator");
  assert.equal(seen[1][seen[1].indexOf("--profile") + 1], "administrator");
  assert.equal(seen[2][seen[2].indexOf("--profile") + 1], "release");
  assert.equal(seen[3][seen[3].indexOf("--profile") + 1], "administrator");
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
  assert.deepEqual(calls.filter(({ args }) => args.includes(unrelatedKeyId)).map(({ args, profile }) => ({ action: args.slice(0, 2).join(":"), profile })), [{ action: "kms:describe-key", profile: "administrator" }]);
  assert(calls.some(({ args, profile }) => args[0] === "kms" && args[1] === "list-resource-tags" && profile === "release"));
});

test("release denial on a potentially relevant candidate fails closed instead of becoming NO_CANDIDATE", () => {
  const adapter = buildRootDropAwsReadAdapter({
    profile: "release",
    discoveryProfile: "administrator",
    provenanceProfile: "administrator",
    run: (args) => {
      if (args[0] === "kms" && args[1] === "list-keys") return JSON.stringify({ Keys: [{ KeyId: keyId }] });
      if (args[0] === "kms" && args[1] === "describe-key") return JSON.stringify({ KeyMetadata: candidate().metadata });
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
  const recovery = createRootDropRecoveryRunner({ execute, readState: async () => current, readStateSnapshot: async () => ({ state: current, stateBytes: Buffer.from(JSON.stringify(current)) }), importKey: async () => { imports += 1; if (importOutcome) { const error = new Error(importOutcome); error.mutationOutcome = importOutcome; throw error; } current = keyState(); }, refreshState: async () => current, createPlan: async ({ zeroDrift: requested }) => requested ? "zero" : "alias", readPlan: async (path) => path === "zero" ? zeroDrift : plan, applyPlan: async () => { applies += 1; if (applyOutcome) { const error = new Error(applyOutcome); error.mutationOutcome = applyOutcome; throw error; } current = ownedState(); }, });
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
  const result = await replay.run({ census: census(), terraformState: keyState(), stageAStateIdentity: stateIdentity, sourceSha, transitionId, planSha256: failedApplyEvidence.planSha256 });
  assert.equal(result.status, "READY_FOR_ALIAS_ADOPTION");
  assert.deepEqual(result.accounting, { terraformImports: 0, terraformApplies: 0, kmsWrites: 0, iamWrites: 0, unknownMutations: 0, unclassifiedMutations: 0 });
  assert.deepEqual(replay.counts(), { imports: 0, applies: 0 });
});

test("adoption reaches its read-only boundary with normalized real AWS event evidence", async () => {
  const value = runner({ initial: keyState() });
  const real = realAwsCensus();
  const persisted = JSON.parse(JSON.stringify(real));
  const result = await value.run({ census: persisted, freshCensus: persisted, terraformState: keyState(), stageAStateIdentity: stateIdentity, sourceSha, transitionId, planSha256: failedApplyEvidence.planSha256 });
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

test("successful import replay never imports again", async () => {
  const value = runner({ initial: keyState() });
  const result = await value.run({ census: census(), terraformState: keyState(), stageAStateIdentity: stateIdentity, sourceSha, transitionId, planSha256: failedApplyEvidence.planSha256 });
  assert.equal(result.accounting.terraformImports, 0);
  assert.deepEqual(value.counts(), { imports: 0, applies: 0 });
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
        applyPlan: async () => ({ outcome: "CONFIRMED_SUCCESS" }),
      }),
    },
  ];
  for (const { name, terraformState, build } of cases) {
    await assert.rejects(
      () => build()({ census: census(), freshCensus: census(), terraformState, stageAStateIdentity: stateIdentity, sourceSha, transitionId, planSha256: failedApplyEvidence.planSha256 }),
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
  const wrong = createRootDropRecoveryRunner({ execute: true, readState: async () => wrongState, readStateSnapshot: async () => ({ state: wrongState, stateBytes: Buffer.from(JSON.stringify(wrongState)) }), importKey: async () => {}, refreshState: async () => wrongState, createPlan: async () => "alias", readPlan: async () => aliasPlan(), applyPlan: async () => {} });
  await assert.rejects(() => wrong({ census: census(), freshCensus: census(), terraformState: keyState(), stageAStateIdentity: stateIdentity, sourceSha, transitionId, planSha256: failedApplyEvidence.planSha256 }));
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
  const fresh = census();
  const result = await value.run({ census: supplied, freshCensus: fresh, terraformState: keyState(), stageAStateIdentity: stateIdentity, sourceSha, transitionId, planSha256: failedApplyEvidence.planSha256 });
  assert.equal(result.status, "READY_FOR_ALIAS_ADOPTION");
  const noFresh = runner({ initial: keyState(), injectFresh: false });
  await assert.rejects(() => noFresh.run({ census: fresh, terraformState: keyState(), stageAStateIdentity: stateIdentity, sourceSha, transitionId, planSha256: failedApplyEvidence.planSha256 }), /fresh authoritative census/);
});

test("multiple candidates, wrong default/state conflict, and no candidate are fail closed at the workflow boundary", async () => {
  const ambiguous = buildRootDropCensus({ sourceSha, transitionId, stageAStateIdentity: stateIdentity, keyUniverse: [keyId, "22222222-2222-2222-2222-222222222222"], candidates: [{ authenticated: false, keyId }, { authenticated: false, keyId: "22222222-2222-2222-2222-222222222222" }] });
  await assert.rejects(() => runner().run({ census: ambiguous, terraformState: absentState, stageAStateIdentity: stateIdentity, sourceSha, transitionId, planSha256: failedApplyEvidence.planSha256 }), /ambiguous|candidate/);
  await assert.rejects(() => runner().run({ census: noCandidateCensus(), terraformState: absentState, stageAStateIdentity: stateIdentity, sourceSha, transitionId, planSha256: failedApplyEvidence.planSha256 }), /authenticated candidate/);
});
