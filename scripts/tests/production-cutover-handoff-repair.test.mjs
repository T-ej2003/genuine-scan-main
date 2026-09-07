import assert from "node:assert/strict";
import test from "node:test";
import { constants, createHash, generateKeyPairSync, sign, verify } from "node:crypto";
import { lstatSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import os from "node:os";
import path from "node:path";
import { assertRootDropEvidence, buildRootDropEvidence, buildRootDropPayload, canonicalRootDropPayload, ROOT_DROP_SIGNING_KEY_ARN } from "../aws/production-root-drop-evidence.mjs";
import { assertAuthenticatedCurrentStageBState, assertPostApplyStageAPlanRecovery, producePostApplyStageAPlanRecovery, readAuthenticatedStageARecoverySources } from "../aws/production-stage-a-recovery-evidence.mjs";
import { assertStageAStateContract, STAGE_A_STATE_IDENTITY_VERSION, stageAStateSemanticSha256 } from "../aws/generate-production-green-stage-a-prerequisites.mjs";
import { bootstrapInitialDualSlotRotation, createInitialDualSlotSecretsManagerClient, generatePendingMaterial, INITIAL_DUAL_SLOT_NAMES, supersedeStalePendingRotation, verifyLiveInitialDualSlotBindingWithRunner } from "../aws/production-initial-dual-slot-bootstrap.mjs";
import { buildProductionRotationConfig } from "../aws/production-cutover-runtime-bootstrap.mjs";
import { PARTIAL_REBASELINE_RECOVERY_ORIGINAL_SOURCE_SHA } from "../aws/production-dual-slot-rebaseline-contract.mjs";
import { STAGE_B } from "../aws/production-green-stage-b-contract.mjs";
import { fixtureInput, sourceSha as rehearsalSourceSha } from "./production-cutover-rehearsal.test.mjs";
import { runProductionCutoverControlPlane } from "../aws/production-cutover-control-plane.mjs";
import { createProductionCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "../aws/production-cutover-production-adapters.mjs";
import { productionStageAIngress, productionStageAState, STAGE_A_LINEAGE, STAGE_A_STATE_OBJECT } from "./fixtures/production-stage-a-state.mjs";
import { prepare, readCurrentState } from "../../backend/scripts/security/rotate-production-signing-material.mjs";
import { validateRotationTransition } from "../security/check-production-rotation-transition.mjs";
import { assertProductionStaleSupersessionPredecessor, productionStaleSupersessionPredecessorIdentity } from "../security/production-initial-migration-source-advance.mjs";

const sourceSha = "8".repeat(40);
const staleSourceSha = "e".repeat(40);
const rotationId = "rotation-new-20260817";
const staleRotationId = "rotation-old-20260812";
const arn = (name) => `arn:aws:secretsmanager:eu-west-2:368992683803:secret:${name.replaceAll("/", "-")}-abc`;
const digest = (value) => createHash("sha256").update(value).digest("hex");
const requireBackend = createRequire(path.resolve("backend/package.json"));
const currentOwnerRotationId = "rotation-current-20260801";
const productionQrMetadataIdentifier = "c41ca96ab047dd25"; // ggignore: authenticated public-key fingerprint, not secret material
const currentNames = { jwt: "current-jwt", qrPrivate: "current-qr-private", qrPublic: "current-qr-public" };
const staleTaskDefinition = { taskDefinition: { containerDefinitions: [{ name: "backend", environment: [{ name: "QR_SIGN_ACTIVE_KEY_VERSION", value: "2026-04-20" }], secrets: [{ name: "JWT_SECRET", valueFrom: arn(currentNames.jwt) }, { name: "QR_SIGN_PRIVATE_KEY", valueFrom: arn(currentNames.qrPrivate) }, { name: "QR_SIGN_PUBLIC_KEY", valueFrom: arn(currentNames.qrPublic) }] }] } };
const supersessionArgs = (overrides = {}) => ({ taskDefinition: staleTaskDefinition, sourceSha, staleSourceSha, rotationId, staleRotationId, proveDescendant: ({ ancestorSha, descendantSha }) => ancestorSha === staleSourceSha && descendantSha === sourceSha, ...overrides });

function rotationStore() {
  const pair = generateKeyPairSync("ed25519", { privateKeyEncoding: { format: "pem", type: "pkcs8" }, publicKeyEncoding: { format: "pem", type: "spki" } });
  const keyVersion = digest(pair.publicKey).slice(0, 16);
  const store = new Map();
  for (const [slot, name] of Object.entries(INITIAL_DUAL_SLOT_NAMES)) {
    const pending = ["jwtPending", "qrPrivatePending", "qrPublicPending"].includes(slot);
    const value = pending
      ? { value: slot === "jwtPending" ? "jwt-old-material" : slot === "qrPrivatePending" ? pair.privateKey : pair.publicKey, sourceSha: staleSourceSha, rotationId: staleRotationId, family: slot === "jwtPending" ? "jwt_secrets" : "qr_signing_keys", slot: slot === "jwtPending" ? "pending" : slot === "qrPrivatePending" ? "pending-private" : "pending-public", ...(slot === "qrPrivatePending" || slot === "qrPublicPending" ? { keyVersion } : {}), materialFingerprint: digest(slot === "jwtPending" ? "jwt-old-material" : slot === "qrPrivatePending" ? pair.privateKey : pair.publicKey).slice(0, 16) }
      : { value: slot === "qrCurrentVersion" ? "2026-04-20" : "", sourceSha: staleSourceSha, family: slot === "qrCurrentVersion" || slot === "qrPreviousVersion" ? "qr_key_versions" : slot === "jwtPrevious" ? "jwt_secrets" : "qr_signing_keys", slot: slot === "qrCurrentVersion" ? "current" : slot === "qrPreviousVersion" ? "previous-empty" : "empty", initialMigration: true };
    store.set(name, { value, versionId: `${slot}-old` });
  }
  const currentPair = generateKeyPairSync("ed25519", { privateKeyEncoding: { format: "pem", type: "pkcs8" }, publicKeyEncoding: { format: "pem", type: "spki" } });
  const metadataKeyVersion = digest(currentPair.publicKey).slice(0, 16);
  for (const [name, value, family, slot] of [["jwt", "jwt-current-material", "jwt_secrets", "current"], ["qrPrivate", currentPair.privateKey, "qr_signing_keys", "current-private"], ["qrPublic", currentPair.publicKey, "qr_signing_keys", "current-public"]]) {
    store.set(currentNames[name], { value: { value, rotationId: currentOwnerRotationId, family, slot, ...(name === "jwt" ? {} : { keyVersion: metadataKeyVersion }), materialFingerprint: digest(value).slice(0, 16) }, versionId: `${name}-current-version` });
  }
  return store;
}

function rotationSender(store, { failAt, onDescribe, onGet } = {}) {
  let writes = 0;
  let updates = 0;
  const reads = [];
  const send = async (command) => {
    const name = command.input.SecretId;
    const key = [...store.keys()].find((candidate) => candidate === name || arn(candidate) === name);
    if (command.constructor.name === "DescribeSecretCommand") {
      const record = store.get(key);
      const response = { Name: key, ARN: arn(key), VersionIdsToStages: { [record.versionId]: ["AWSCURRENT"], ...(record.previous ? { [record.previous.versionId]: ["AWSPREVIOUS"] } : {}) } };
      await onDescribe?.({ key, record: structuredClone(record), store });
      return response;
    }
    if (command.constructor.name === "GetSecretValueCommand") {
      const record = store.get(key);
      reads.push({ key, versionId: command.input.VersionId || null });
      const selected = command.input.VersionId && command.input.VersionId === record.previous?.versionId ? record.previous : record;
      const response = { SecretString: JSON.stringify(selected.value), VersionId: selected.versionId };
      return await onGet?.({ response, key, versionId: command.input.VersionId || null }) || response;
    }
    if (command.constructor.name === "PutSecretValueCommand") {
      writes += 1;
      store.set(key, { value: JSON.parse(command.input.SecretString), versionId: command.input.ClientRequestToken, previous: store.get(key) });
      if (writes === failAt) throw new Error(`injected PutSecretValue failure ${writes}`);
      return { VersionId: command.input.ClientRequestToken };
    }
    if (command.constructor.name === "UpdateSecretVersionStageCommand") { updates += 1; return {}; }
    throw new Error(`unexpected command ${command.constructor.name}`);
  };
  return { send, get writes() { return writes; }, get updates() { return updates; }, get reads() { return reads; } };
}

function originRunner(store, { mutateDescribe, mutateValue } = {}) {
  return (args) => {
    const action = args[2];
    const secretId = args[args.indexOf("--secret-id") + 1];
    const key = [...store.keys()].find((candidate) => candidate === secretId || arn(candidate) === secretId);
    const record = store.get(key);
    if (action === "describe-secret") {
      const response = { Name: key, ARN: arn(key), VersionIdsToStages: { [record.versionId]: ["AWSCURRENT"], ...(record.previous ? { [record.previous.versionId]: ["AWSPREVIOUS"] } : {}) } };
      return JSON.stringify(mutateDescribe?.(structuredClone(response), { key, record }) || response);
    }
    if (action === "get-secret-value") {
      const versionId = args[args.indexOf("--version-id") + 1];
      const selected = versionId && versionId === record.previous?.versionId ? record.previous : record;
      const response = { VersionId: selected.versionId, SecretString: JSON.stringify(selected.value) };
      return JSON.stringify(mutateValue?.(structuredClone(response), { key, record, versionId }) || response);
    }
    throw new Error(`unexpected runner action ${action}`);
  };
}

function convergedStageBState() {
  return { version: 4, serial: 98, lineage: "4e438e59-8b8b-194d-030c-5ede0c26344a", outputs: {}, resources: [{ mode: "managed", type: "aws_ecs_service", name: "backend", instances: [{ schema_version: 0, attributes: { id: "mscqr-backend-servi-euw2" } }] }] };
}

test("historical Stage-B provenance remains distinct from authenticated current Stage-B state", () => {
  const current = { ...convergedStageBState(), serial: 100, outputs: { bound_images: { value: { backend: "sha256:fixture" }, type: ["object", { backend: "string" }] } } };
  const prepared = JSON.parse(JSON.stringify(current));
  assert.equal(assertAuthenticatedCurrentStageBState(current, prepared, { lineage: current.lineage }), true);
  prepared.resources[0].instances[0].attributes.id = "different-service";
  assert.throws(() => assertAuthenticatedCurrentStageBState(current, prepared, { lineage: current.lineage }), /does not match/);
  assert.throws(() => assertAuthenticatedCurrentStageBState(current, { ...current, serial: 99 }, { lineage: current.lineage }), /does not match/);
  assert.throws(() => assertAuthenticatedCurrentStageBState(current, { ...current, lineage: "wrong" }, { lineage: current.lineage }), /identity is invalid/);
});

test("Stage-A metadata-only state cannot authorize post-apply recovery", () => {
  assert.throws(() => assertStageAStateContract({ version: 4, serial: 42, lineage: "02afb75a-f902-ab8a-f4c1-751d4aef7837" }), /stage_b_prerequisites|output/);
});

test("Secrets Manager mutation credentials are explicit and account-bound", async () => {
  assert.throws(() => createInitialDualSlotSecretsManagerClient(), /explicit/);
  const client = createInitialDualSlotSecretsManagerClient({ profile: "mscqr-production-release-deployer", credentials: async () => ({}), stsClient: { send: async () => ({ Account: "111111111111", Arn: "arn:aws:iam::111111111111:role/wrong" }) } });
  await assert.rejects(() => client.assertCredentialIdentity(), /outside/);
});

test("credential provider runtime export is the profile-bound INI provider", () => {
  const { fromIni } = requireBackend("@aws-sdk/credential-provider-ini");
  assert.equal(typeof fromIni, "function");
  assert.equal(typeof fromIni({ profile: "mscqr-production-release-deployer" }), "function");
  assert.equal(typeof requireBackend("@aws-sdk/credential-provider-node").fromIni, "undefined");
});

test("profile-bound AWS command runners cannot fall back to ambient static credentials", () => {
  let options;
  const run = createProductionCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: "mscqr-production-root-operator", exec: (_file, _args, received) => { options = received; return "{}"; } });
  run(["sts", "get-caller-identity"]);
  assert.equal(options.env.AWS_PROFILE, "mscqr-production-root-operator");
  for (const key of ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN", "AWS_DEFAULT_PROFILE"]) assert.equal(Object.hasOwn(options.env, key), false);
});

test("root-drop evidence is exact, continuity-bound, fresh, and tamper-evident", () => {
  const continuity = { rotationId, imageAuthorizationSha256: "1".repeat(64), successorRecoveryAuthorizationSha256: "2".repeat(64), administratorEvidenceSha256: "3".repeat(64), administratorSignatureSha256: "4".repeat(64) };
  const payload = buildRootDropPayload({ sourceSha, callerArn: "arn:aws:iam::368992683803:root", now: new Date().toISOString(), nonce: "nonce-1-with-enough-entropy", ...continuity });
  const keyPair = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const signature = sign("sha256", Buffer.from(canonicalRootDropPayload(payload)), { key: keyPair.privateKey, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 });
  const evidence = buildRootDropEvidence({ payload, signatureBase64: signature.toString("base64") });
  let signedMessage;
  const verifySignature = ({ message, signature: received }) => { signedMessage = message; return verify("sha256", message, { key: keyPair.publicKey, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }, received); };
  assert.equal(assertRootDropEvidence(evidence, { sourceSha, ...continuity, verifySignature }).valid, true);
  assert.equal(signedMessage.toString(), canonicalRootDropPayload(payload));
  assert.equal(ROOT_DROP_SIGNING_KEY_ARN, STAGE_B.rootDropKmsKeyArn);
  assert.throws(() => assertRootDropEvidence({ ...evidence, sourceSha: staleSourceSha }, { sourceSha, ...continuity, verifySignature: () => true }), /source/);
  assert.throws(() => assertRootDropEvidence({ ...evidence, rotationId: staleRotationId }, { sourceSha, ...continuity, verifySignature: () => true }), /rotation|chain/);
  assert.throws(() => assertRootDropEvidence({ ...evidence, imageAuthorizationSha256: "5".repeat(64) }, { sourceSha, ...continuity, verifySignature: () => true }), /image|chain/);
  assert.throws(() => assertRootDropEvidence({ ...evidence, successorRecoveryAuthorizationSha256: "5".repeat(64) }, { sourceSha, ...continuity, verifySignature: () => true }), /recovery|chain/);
  assert.throws(() => assertRootDropEvidence({ ...evidence, administratorEvidenceSha256: "5".repeat(64) }, { sourceSha, ...continuity, verifySignature: () => true }), /administrator|chain/);
  assert.throws(() => assertRootDropEvidence({ ...evidence, administratorSignatureSha256: "5".repeat(64) }, { sourceSha, ...continuity, verifySignature: () => true }), /administrator|chain/);
  assert.throws(() => assertRootDropEvidence({ ...evidence, callerArn: "arn:aws:iam::368992683803:user:admin" }, { sourceSha, ...continuity, verifySignature: () => true }), /source|chain/);
  assert.throws(() => assertRootDropEvidence({ ...evidence, accountId: "000000000000" }, { sourceSha, ...continuity, verifySignature: () => true }), /chain|source/);
  assert.throws(() => assertRootDropEvidence({ ...evidence, region: "us-east-1" }, { sourceSha, ...continuity, verifySignature: () => true }), /chain|source/);
  assert.throws(() => assertRootDropEvidence({ ...evidence, generatedAt: "2000-01-01T00:00:00.000Z" }, { sourceSha, ...continuity, verifySignature: () => true }), /stale/);
  const missing = { ...evidence }; delete missing.rotationId;
  assert.throws(() => assertRootDropEvidence(missing, { sourceSha, ...continuity, verifySignature: () => true }), /chain|canonical/);
  assert.throws(() => assertRootDropEvidence({ ...evidence, unexpected: true }, { sourceSha, ...continuity, verifySignature: () => true }), /chain|canonical/);
  assert.throws(() => assertRootDropEvidence({ ...evidence, evidenceSha256: "0".repeat(64) }, { sourceSha, ...continuity, verifySignature: () => true }), /hash/);
  const forged = { ...evidence, signatureBase64: "Zm9yZ2Vk", evidenceSha256: digest(JSON.stringify({ ...evidence, signatureBase64: "Zm9yZ2Vk", evidenceSha256: undefined })) };
  assert.throws(() => assertRootDropEvidence(forged, { sourceSha, ...continuity, verifySignature: () => false }), /hash|signature/);
  const mutated = buildRootDropEvidence({ payload: { ...payload, nonceHash: digest("different") }, signatureBase64: signature.toString("base64") });
  assert.throws(() => assertRootDropEvidence(mutated, { sourceSha, ...continuity, verifySignature }), /signature/);
  assert.throws(() => buildRootDropEvidence({ payload, signatureBase64: signature.toString("base64"), signingKeyArn: STAGE_B.approvalKmsKeyArn }), /reviewed KMS signature/);
  const rootKeyPolicy = readFileSync("infra/aws/terraform/production-green-stage-a/main.tf", "utf8");
  assert.match(rootKeyPolicy, /Sid = "DenyNonRootRootDropSigning"/);
  assert.match(rootKeyPolicy, /StringNotEquals = \{ "aws:PrincipalArn" = "arn:aws:iam::368992683803:root" \}/);
});

test("replacement credentials use fresh entropy rather than public identifiers", () => {
  const first = generatePendingMaterial({ sourceSha, rotationId });
  const second = generatePendingMaterial({ sourceSha, rotationId });
  assert.notEqual(first.jwt, second.jwt);
  assert.notEqual(first.qrPrivate, second.qrPrivate);
  assert.notEqual(first.qrPublic, second.qrPublic);
});

test("post-apply Stage-A recovery is distinct from and stricter than a historical plan", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-stage-a-recovery-"));
  const stateBytes = Buffer.from(JSON.stringify(productionStageAState()));
  const statePath = path.join(directory, "stage-a-state.json");
  const handoffPath = path.join(directory, "stage-a-handoff.json");
  const stageBPath = path.join(directory, "stage-b-state.json");
  const outputPath = path.join(directory, "recovery-evidence.json");
  writeFileSync(statePath, stateBytes, { mode: 0o600 });
  writeFileSync(handoffPath, JSON.stringify({ toolingSha: sourceSha, stageAStateIdentityVersion: STAGE_A_STATE_IDENTITY_VERSION, stageAStateObject: STAGE_A_STATE_OBJECT, stageAStateLineage: STAGE_A_LINEAGE, stageAStateSerial: 42, stageAStateSha256: stageAStateSemanticSha256(JSON.parse(stateBytes)) }), { mode: 0o600 });
  writeFileSync(stageBPath, JSON.stringify(convergedStageBState()), { mode: 0o600 });
  const evidence = producePostApplyStageAPlanRecovery({ sourceSha, stageAStatePath: statePath, stageAHandoffPath: handoffPath, stageBStatePath: stageBPath, ingress: productionStageAIngress(), outputPath, repositoryRoot: "/private/tmp/mscqr-post330-exec" });
  assert.equal(evidence.historicalPlanPresent, false);
  const authenticated = { ...readAuthenticatedStageARecoverySources({ stageAStatePath: statePath, stageAHandoffPath: handoffPath, stageBStatePath: stageBPath, repositoryRoot: "/private/tmp/mscqr-post330-exec" }), ingress: productionStageAIngress() };
  assert.equal(assertPostApplyStageAPlanRecovery(JSON.parse(readFileSync(outputPath)), { sourceSha, expectedStageBLineage: "4e438e59-8b8b-194d-030c-5ede0c26344a", expectedStageBSerial: 98, authenticated }).alreadyConverged, true);
  assert.throws(() => assertPostApplyStageAPlanRecovery({ ...JSON.parse(readFileSync(outputPath)), sourceSha: staleSourceSha }, { sourceSha, expectedStageBLineage: "4e438e59-8b8b-194d-030c-5ede0c26344a", expectedStageBSerial: 98, authenticated }), /source/);
  assert.throws(() => assertPostApplyStageAPlanRecovery(JSON.parse(readFileSync(outputPath)), { sourceSha, expectedStageBLineage: "4e438e59-8b8b-194d-030c-5ede0c26344a", expectedStageBSerial: 98 }), /independently authenticated/);
  const forged = JSON.parse(readFileSync(outputPath));
  forged.ingress = { ...forged.ingress, endpointSecurityGroupId: "sg-abcdef12" };
  const unsigned = { ...forged };
  delete unsigned.evidenceSha256;
  forged.evidenceSha256 = digest(JSON.stringify(unsigned));
  assert.throws(() => assertPostApplyStageAPlanRecovery(forged, { sourceSha, expectedStageBLineage: "4e438e59-8b8b-194d-030c-5ede0c26344a", expectedStageBSerial: 98, authenticated }), /does not match independently authenticated/);
});

test("stale rotation supersession requires exact old topology and writes a new identity", async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-rotation-supersession-"));
  const store = rotationStore();
  const sender = rotationSender(store);
  const result = await supersedeStalePendingRotation({ send: sender.send, ...supersessionArgs(), outputFile: path.join(directory, "supersession.json"), repositoryRoot: "/private/tmp/mscqr-post330-exec" });
  assert.equal(result.writes, 7);
  const persistedEvidenceBytes = readFileSync(path.join(directory, "supersession.json"));
  const persistedEvidence = JSON.parse(persistedEvidenceBytes);
  await new Promise((resolve) => setTimeout(resolve, 5));
  const replay = await supersedeStalePendingRotation({ send: sender.send, ...supersessionArgs(), outputFile: path.join(directory, "supersession.json"), repositoryRoot: "/private/tmp/mscqr-post330-exec" });
  assert.equal(replay.writes, 0);
  assert.equal(replay.idempotentReplay, true);
  assert.deepEqual(replay.evidence, persistedEvidence);
  assert.equal(replay.evidenceSha256, digest(persistedEvidenceBytes));
  const tampered = JSON.parse(readFileSync(path.join(directory, "supersession.json"), "utf8"));
  tampered.rotationId = "rotation-tampered-20260817";
  writeFileSync(path.join(directory, "supersession.json"), `${JSON.stringify(tampered)}\n`, { mode: 0o600 });
  await assert.rejects(() => supersedeStalePendingRotation({ send: sender.send, ...supersessionArgs(), outputFile: path.join(directory, "supersession.json"), repositoryRoot: "/private/tmp/mscqr-post330-exec" }), /existing.*does not match|authenticated transition|evidence .*binding/i);
  await assert.rejects(() => supersedeStalePendingRotation({ send: sender.send, ...supersessionArgs({ sourceSha: "7".repeat(40), rotationId: "rotation-new-20260818" }), outputFile: path.join(directory, "second.json"), repositoryRoot: "/private/tmp/mscqr-post330-exec" }), /ancestor|unknown|invalid|resumable/i);
});

test("stale QR runtime marker mismatch fails before stale-supersession mutation", async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-stale-qr-runtime-mismatch-"));
  const store = rotationStore();
  store.get(INITIAL_DUAL_SLOT_NAMES.qrCurrentVersion).value.value = "v1";
  const sender = rotationSender(store);
  try {
    const evidenceFile = path.join(directory, "supersession.json");
    const bindingFile = path.join(directory, "bindings.json");
    await assert.rejects(() => supersedeStalePendingRotation({ send: sender.send, ...supersessionArgs(), outputFile: evidenceFile, repositoryRoot: "/private/tmp/mscqr-post330-exec" }), /current key-version marker does not match the authenticated runtime baseline/);
    assert.equal(sender.writes, 0);
    assert.equal(sender.updates, 0);
    assert.equal(store.get(INITIAL_DUAL_SLOT_NAMES.qrCurrentVersion).value.value, "v1");
    assert.equal(lstatSync(evidenceFile, { throwIfNoEntry: false }), undefined);
    assert.equal(lstatSync(bindingFile, { throwIfNoEntry: false }), undefined);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("stale predecessor capture pins every version and rejects an AWSCURRENT race before mutation", async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-supersession-predecessor-race-"));
  const store = rotationStore();
  const capturedVersionId = store.get(INITIAL_DUAL_SLOT_NAMES.jwtPending).versionId;
  let raced = false;
  const sender = rotationSender(store, { onDescribe: ({ key, record, store: mutableStore }) => {
    if (raced || key !== INITIAL_DUAL_SLOT_NAMES.jwtPending) return;
    raced = true;
    const value = { ...record.value, value: "raced-current-material", materialFingerprint: digest("raced-current-material").slice(0, 16) };
    mutableStore.set(key, { value, versionId: "jwt-pending-raced-current", previous: record });
  } });
  const evidenceFile = path.join(directory, "supersession.json");
  try {
    await assert.rejects(() => supersedeStalePendingRotation({ send: sender.send, ...supersessionArgs(), outputFile: evidenceFile, repositoryRoot: "/private/tmp/mscqr-post330-exec" }), /predecessor changed before mutation/);
    assert.equal(raced, true);
    assert.equal(sender.reads.find(({ key }) => key === INITIAL_DUAL_SLOT_NAMES.jwtPending)?.versionId, capturedVersionId);
    for (const [slot, name] of Object.entries(INITIAL_DUAL_SLOT_NAMES)) assert.equal(sender.reads.find(({ key, versionId }) => key === name && versionId === `${slot}-old`)?.versionId, `${slot}-old`, `${slot} predecessor read is version-pinned`);
    assert.equal(sender.writes, 0);
    assert.equal(sender.updates, 0);
    assert.equal(lstatSync(evidenceFile, { throwIfNoEntry: false }), undefined);
    assert.equal(lstatSync(path.join(directory, "bindings.json"), { throwIfNoEntry: false }), undefined);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("stale predecessor capture rejects a mismatched pinned-read response before mutation", async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-supersession-predecessor-response-"));
  const store = rotationStore();
  let replaced = false;
  const sender = rotationSender(store, { onGet: ({ response, key }) => {
    if (!replaced && key === INITIAL_DUAL_SLOT_NAMES.jwtPending) {
      replaced = true;
      return { ...response, VersionId: "substituted-version-id" };
    }
    return response;
  } });
  const evidenceFile = path.join(directory, "supersession.json");
  try {
    await assert.rejects(() => supersedeStalePendingRotation({ send: sender.send, ...supersessionArgs(), outputFile: evidenceFile, repositoryRoot: "/private/tmp/mscqr-post330-exec" }), /predecessor version is not authenticated/);
    assert.equal(sender.writes, 0);
    assert.equal(sender.updates, 0);
    assert.equal(lstatSync(evidenceFile, { throwIfNoEntry: false }), undefined);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("stale supersession rechecks the authenticated current JWT predecessor before mutation", async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-supersession-current-predecessor-race-"));
  const store = rotationStore();
  let raced = false;
  const sender = rotationSender(store, { onDescribe: ({ key, record, store: mutableStore }) => {
    if (raced || key !== currentNames.jwt) return;
    raced = true;
    const value = { ...record.value, value: "raced-legacy-jwt", materialFingerprint: digest("raced-legacy-jwt").slice(0, 16) };
    mutableStore.set(key, { value, versionId: "current-jwt-raced-version", previous: record });
  } });
  const evidenceFile = path.join(directory, "supersession.json");
  try {
    await assert.rejects(() => supersedeStalePendingRotation({ send: sender.send, ...supersessionArgs(), outputFile: evidenceFile, repositoryRoot: "/private/tmp/mscqr-post330-exec" }), /current jwt predecessor changed before mutation/);
    assert.equal(raced, true);
    assert.equal(sender.writes, 0);
    assert.equal(sender.updates, 0);
    assert.equal(lstatSync(evidenceFile, { throwIfNoEntry: false }), undefined);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("every stale supersession retains schema-v3 origin verification when legacy QR labels already match", async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-supersession-matching-labels-"));
  const store = rotationStore();
  const matchingTaskDefinition = structuredClone(staleTaskDefinition);
  const runtimeVersion = store.get(currentNames.qrPublic).value.keyVersion;
  matchingTaskDefinition.taskDefinition.containerDefinitions[0].environment[0].value = runtimeVersion;
  store.get(INITIAL_DUAL_SLOT_NAMES.qrCurrentVersion).value.value = runtimeVersion;
  const sender = rotationSender(store);
  try {
    const result = await supersedeStalePendingRotation({ send: sender.send, ...supersessionArgs({ taskDefinition: matchingTaskDefinition }), outputFile: path.join(directory, "supersession.json"), repositoryRoot: "/private/tmp/mscqr-post330-exec" });
    const binding = await bootstrapInitialDualSlotRotation({ send: sender.send, taskDefinition: matchingTaskDefinition, sourceSha, rotationId, supersessionEvidence: result.evidence, supersessionPredecessor: result.predecessor, outputFile: path.join(directory, "bindings.json"), repositoryRoot: "/private/tmp/mscqr-post330-exec" });
    assert.equal(binding.bindings.schemaVersion, 3);
    const origin = verifyLiveInitialDualSlotBindingWithRunner({ run: originRunner(store), bindings: binding.bindings, proveDescendant: ({ ancestorSha, descendantSha }) => ancestorSha === staleSourceSha && descendantSha === sourceSha });
    assert.equal(origin.originSha256.length, 64);
    const config = buildProductionRotationConfig({
      sourceSha,
      rotationId,
      liveCurrentKeyVersion: runtimeVersion,
      approval: { ticket: "CHG-MATCHING-SUPERSESSION", approvedBy: "checker", approverRole: "production-independent-checker", reason: "matching legacy labels fixture", verificationRef: "fixture://matching-supersession", minimumGraceSeconds: 2592000 },
      bindings: binding.bindings,
      verifyInitialBindingOrigin: () => origin,
    });
    const context = { config, sm: { send: sender.send }, identity: "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/fixture", clock: () => Date.parse("2026-09-07T00:00:00.000Z"), proveDescendant: ({ ancestorSha, descendantSha }) => ancestorSha === sourceSha && descendantSha === sourceSha, values: new Map([["state-file", path.join(directory, "state.json")], ["fixture-file", path.join(directory, "fixture.json")]]) };
    await prepare(context);
    assert.equal(readCurrentState(context).phase, "overlap-deploy-required");
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("unknown rotation slot evidence fails closed before any write", async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-rotation-unknown-"));
  const store = rotationStore();
  const first = store.keys().next().value;
  store.get(first).value.sourceSha = "f".repeat(40);
  const sender = rotationSender(store);
  await assert.rejects(() => supersedeStalePendingRotation({ send: sender.send, ...supersessionArgs(), outputFile: path.join(directory, "unknown.json"), repositoryRoot: "/private/tmp/mscqr-post330-exec" }), /unknown/);
  assert.equal(sender.writes, 0);
});

test("stale rotation supersession resumes every sequential write boundary without rewriting authenticated new slots", async () => {
  for (let failure = 1; failure <= 7; failure += 1) {
    const directory = mkdtempSync(path.join(os.tmpdir(), `mscqr-rotation-resume-${failure}-`));
    const store = rotationStore();
    const first = rotationSender(store, { failAt: failure });
    const outputFile = path.join(directory, "first.json");
    await assert.rejects(() => supersedeStalePendingRotation({ send: first.send, ...supersessionArgs(), outputFile, repositoryRoot: "/private/tmp/mscqr-post330-exec" }), /injected PutSecretValue failure/);
    const journal = JSON.parse(readFileSync(`${outputFile}.material`, "utf8"));
    assert.equal(statSync(`${outputFile}.material`).mode & 0o077, 0);
    const retry = rotationSender(store);
    const result = await supersedeStalePendingRotation({ send: retry.send, ...supersessionArgs(), outputFile, repositoryRoot: "/private/tmp/mscqr-post330-exec" });
    assert.equal(result.writes, 7 - failure);
    assert.equal(result.idempotentReplay, failure === 7);
    for (const slot of ["jwtPending", "qrPrivatePending", "qrPublicPending"]) assert.equal(store.get(INITIAL_DUAL_SLOT_NAMES[slot]).value.value, journal.material[slot === "jwtPending" ? "jwt" : slot === "qrPrivatePending" ? "qrPrivate" : "qrPublic"]);
    assert.notEqual(store.get(INITIAL_DUAL_SLOT_NAMES.jwtPending).value.value, "jwt-old-material");
    assert.equal(lstatSync(`${outputFile}.material`, { throwIfNoEntry: false }), undefined);
  }
});

test("production-shaped stale supersession bootstraps a distinct canonical rotation through real prepare", async () => {
  const productionOldRotationId = "rotation-20260829015311-765c8a16";
  const productionOldSource = PARTIAL_REBASELINE_RECOVERY_ORIGINAL_SOURCE_SHA;
  const protectedSource = "61ef3f172a501880d4a8d3b59a5aab8ff4e1a1b3";
  const currentProtectedDescendant = "9".repeat(40);
  const freshRotationId = "rotation-fresh-source-only-fixture";
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-fresh-supersession-"));
  const store = rotationStore();
  for (const name of Object.values(INITIAL_DUAL_SLOT_NAMES)) {
    const record = store.get(name);
    record.value.sourceSha = productionOldSource;
    if (record.value.rotationId === staleRotationId) record.value.rotationId = productionOldRotationId;
  }
  store.get(INITIAL_DUAL_SLOT_NAMES.qrCurrentVersion).value.value = "2026-04-20";
  const sender = rotationSender(store);
  try {
    const result = await supersedeStalePendingRotation({
      send: sender.send,
      taskDefinition: staleTaskDefinition,
      sourceSha: protectedSource,
      staleSourceSha: productionOldSource,
      rotationId: freshRotationId,
      staleRotationId: productionOldRotationId,
      proveDescendant: ({ ancestorSha, descendantSha }) => ancestorSha === productionOldSource && descendantSha === protectedSource,
      outputFile: path.join(directory, "supersession.json"),
      repositoryRoot: "/private/tmp/mscqr-post330-exec",
    });
    assert.equal(result.writes, 7);
    assert.notEqual(result.rotationId, result.staleRotationId);
    assert.equal(result.predecessor.runtimeQrVersionLabel, "2026-04-20");
    assert.notEqual(result.predecessor.current.qrPublic.keyVersion, result.predecessor.runtimeQrVersionLabel);
    const productionIdentityFixture = structuredClone(result.predecessor);
    productionIdentityFixture.current.qrPrivate.keyVersion = productionQrMetadataIdentifier;
    productionIdentityFixture.current.qrPublic.keyVersion = productionQrMetadataIdentifier;
    productionIdentityFixture.predecessorIdentitySha256 = productionStaleSupersessionPredecessorIdentity(productionIdentityFixture);
    assert.equal(assertProductionStaleSupersessionPredecessor(productionIdentityFixture).current.qrPublic.keyVersion, productionQrMetadataIdentifier);
    const binding = await bootstrapInitialDualSlotRotation({
      send: sender.send,
      taskDefinition: staleTaskDefinition,
      sourceSha: protectedSource,
      rotationId: freshRotationId,
      supersessionEvidence: result.evidence,
      supersessionPredecessor: result.predecessor,
      outputFile: path.join(directory, "rotation-bindings.json"),
      repositoryRoot: "/private/tmp/mscqr-post330-exec",
    });
    assert.equal(binding.secretValueWrites, 0);
    assert.equal(binding.bindings.schemaVersion, 3);
    const origin = verifyLiveInitialDualSlotBindingWithRunner({ run: originRunner(store), bindings: binding.bindings, proveDescendant: ({ ancestorSha, descendantSha }) => ancestorSha === productionOldSource && descendantSha === protectedSource });
    for (const [slot, name] of Object.entries(INITIAL_DUAL_SLOT_NAMES)) {
      assert.throws(() => verifyLiveInitialDualSlotBindingWithRunner({
        run: originRunner(store, { mutateDescribe: (response, context) => {
          if (context.key === name) delete response.VersionIdsToStages[context.record.previous.versionId];
          return response;
        } }),
        bindings: binding.bindings,
        proveDescendant: () => true,
      }), /supersession version topology/, `${slot} must retain its authenticated AWSPREVIOUS predecessor`);
    }
    for (const [label, mutateDescribe] of [
      ["missing authenticated current", (response, { record }) => { delete response.VersionIdsToStages[record.versionId]; return response; }],
      ["predecessor marked current", (response, { record }) => { response.VersionIdsToStages[record.previous.versionId] = ["AWSCURRENT"]; return response; }],
      ["unexpected third labeled version", (response) => { response.VersionIdsToStages["unrelated-version"] = ["AWSPREVIOUS"]; return response; }],
      ["unexpected stage label", (response, { record }) => { response.VersionIdsToStages[record.previous.versionId] = ["AWSPREVIOUS", "AWSPENDING"]; return response; }],
    ]) {
      assert.throws(() => verifyLiveInitialDualSlotBindingWithRunner({ run: originRunner(store, { mutateDescribe }), bindings: binding.bindings, proveDescendant: () => true }), /topology/, label);
    }
    assert.throws(() => verifyLiveInitialDualSlotBindingWithRunner({
      run: originRunner(store, { mutateValue: (response, { key, record, versionId }) => {
        if (key === INITIAL_DUAL_SLOT_NAMES.jwtPending && versionId === record.previous.versionId) response.SecretString = JSON.stringify({ ...record.previous.value, value: "substituted-predecessor", materialFingerprint: digest("substituted-predecessor").slice(0, 16) });
        return response;
      } }),
      bindings: binding.bindings,
      proveDescendant: () => true,
    }), /predecessor payload/, "the authenticated predecessor payload is required");
    const unlabeledHistoryOrigin = verifyLiveInitialDualSlotBindingWithRunner({
      run: originRunner(store, { mutateDescribe: (response) => ({ ...response, VersionIdsToStages: { ...response.VersionIdsToStages, "retained-unlabelled-history": [] } }) }),
      bindings: binding.bindings,
      proveDescendant: () => true,
    });
    assert.equal(unlabeledHistoryOrigin.originSha256, origin.originSha256);
    assert.throws(() => verifyLiveInitialDualSlotBindingWithRunner({ run: originRunner(store), bindings: binding.bindings, proveDescendant: () => false }), /ancestry/);
    const substitutedBinding = structuredClone(binding.bindings);
    substitutedBinding.supersessionPredecessor.current.jwt.materialFingerprint = "0".repeat(16);
    substitutedBinding.supersessionPredecessor.predecessorIdentitySha256 = productionStaleSupersessionPredecessorIdentity(substitutedBinding.supersessionPredecessor);
    assert.throws(() => verifyLiveInitialDualSlotBindingWithRunner({ run: originRunner(store), bindings: substitutedBinding, proveDescendant: () => true }), /stale-supersession predecessor/);
    const directConfig = buildProductionRotationConfig({
      sourceSha: currentProtectedDescendant,
      rotationId: freshRotationId,
      liveCurrentKeyVersion: "2026-04-20",
      approval: { ticket: "CHG-FRESH-SUPERSESSION", approvedBy: "checker", approverRole: "production-independent-checker", reason: "source-only fresh rotation fixture", verificationRef: "fixture://fresh-supersession", minimumGraceSeconds: 2592000 },
      bindings: binding.bindings,
      verifyInitialBindingOrigin: () => origin,
    });
    const config = { ...directConfig, initialMigrationSourceAdvance: { schemaVersion: 1, kind: "PRODUCTION_INITIAL_MIGRATION_SOURCE_ADVANCE", currentSourceSha: currentProtectedDescendant, supersessionEvidence: result.evidence } };
    const stateFile = path.join(directory, "rotation-state.json");
    const context = { config, sm: { send: sender.send }, identity: "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/fixture", clock: () => Date.parse("2026-09-07T00:00:00.000Z"), proveDescendant: ({ ancestorSha, descendantSha }) => ancestorSha === protectedSource && descendantSha === currentProtectedDescendant, values: new Map([["state-file", stateFile], ["fixture-file", path.join(directory, "rotation-fixture.json")]]) };
    const writesBeforePrepare = sender.writes;
    await assert.rejects(() => prepare({ ...context, proveDescendant: () => false, values: new Map([["state-file", path.join(directory, "unrelated-state.json")], ["fixture-file", path.join(directory, "unrelated-fixture.json")]]) }), /ancestry/);
    await assert.rejects(() => prepare({ ...context, config: { ...config, staleSupersessionPredecessor: undefined }, values: new Map([["state-file", path.join(directory, "unbound-state.json")], ["fixture-file", path.join(directory, "unbound-fixture.json")]]) }), /complete stale-supersession binding origin/);
    const forged = structuredClone(config);
    forged.staleSupersessionPredecessor.current.jwt.materialFingerprint = "0".repeat(16);
    forged.staleSupersessionPredecessor.predecessorIdentitySha256 = productionStaleSupersessionPredecessorIdentity(forged.staleSupersessionPredecessor);
    await assert.rejects(() => prepare({ ...context, config: forged, values: new Map([["state-file", path.join(directory, "forged-state.json")], ["fixture-file", path.join(directory, "forged-fixture.json")]]) }), /binding origin|live jwt/);
    const rejectChangedSupersessionSlot = async (slot, mutate, label) => {
      const original = structuredClone(store.get(INITIAL_DUAL_SLOT_NAMES[slot]));
      mutate(store.get(INITIAL_DUAL_SLOT_NAMES[slot]));
      await assert.rejects(() => prepare({ ...context, sm: { send: async (command) => {
        if (command.constructor.name === "PutSecretValueCommand") throw new Error("unexpected mutation before supersession slot authentication");
        return sender.send(command);
      } }, values: new Map([["state-file", path.join(directory, `${label}-state.json`)], ["fixture-file", path.join(directory, `${label}-fixture.json`)]]) }), /authenticated stale-supersession binding origin/);
      store.set(INITIAL_DUAL_SLOT_NAMES[slot], original);
    };
    await rejectChangedSupersessionSlot("jwtPending", (record) => { record.versionId = "substituted-jwt-version"; }, "changed-version");
    await rejectChangedSupersessionSlot("jwtPending", (record) => { record.value.value = "substituted-jwt-pending"; record.value.materialFingerprint = digest(record.value.value).slice(0, 16); }, "changed-payload");
    await rejectChangedSupersessionSlot("qrPreviousVersion", (record) => { record.value.sourceSha = "0".repeat(40); }, "changed-marker");
    const forgedOrigin = structuredClone(config);
    forgedOrigin.staleSupersessionBindingOrigin.observedSlots.jwtPending.versionId = "forged-origin-version";
    await assert.rejects(() => prepare({ ...context, config: forgedOrigin, values: new Map([["state-file", path.join(directory, "forged-origin-state.json")], ["fixture-file", path.join(directory, "forged-origin-fixture.json")]]) }), /binding origin integrity/);
    assert.equal(sender.writes, writesBeforePrepare);
    await prepare(context);
    const state = readCurrentState(context);
    assert.equal(state.phase, "overlap-deploy-required");
    assert.equal(state.qr.oldKeyVersion, "2026-04-20");
    assert.equal(state.qr.oldMetadataKeyVersion, result.predecessor.current.qrPublic.keyVersion);
    assert.equal(store.get(currentNames.qrPublic).value.keyVersion, store.get(INITIAL_DUAL_SLOT_NAMES.qrCurrentVersion).value.value);
    assert.equal(store.get(INITIAL_DUAL_SLOT_NAMES.qrPublicPrevious).value.keyVersion, store.get(INITIAL_DUAL_SLOT_NAMES.qrPreviousVersion).value.value);
    const writesAfterPrepare = sender.writes;
    await prepare(context);
    assert.equal(sender.writes, writesAfterPrepare);
    const rawState = readFileSync(stateFile);
    assert.equal(validateRotationTransition({ mode: "rotation-overlap", sourceSha: currentProtectedDescendant, rotationId: freshRotationId, deploymentSha: state.overlapDeploymentSha, rawState, stateSha256: digest(rawState), taskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:51", expectedCurrentTaskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:50", imageDigest: `sha256:${"d".repeat(64)}`, now: Date.now() }).phase, "overlap-deploy-required");
    const alteredState = JSON.parse(rawState);
    alteredState.jwt.oldFingerprint = "0".repeat(16);
    writeFileSync(stateFile, `${JSON.stringify(alteredState, null, 2)}\n`, { mode: 0o600 });
    assert.throws(() => readCurrentState(context), /authenticated stale-supersession predecessor/);
    await assert.rejects(() => supersedeStalePendingRotation({ send: sender.send, taskDefinition: staleTaskDefinition, sourceSha: protectedSource, staleSourceSha: productionOldSource, rotationId: freshRotationId, staleRotationId: productionOldRotationId, proveDescendant: () => true, outputFile: path.join(directory, "replay.json"), repositoryRoot: "/private/tmp/mscqr-post330-exec" }), /lineage|invalid|unknown/);
    assert.equal(sender.writes, writesAfterPrepare);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("stale supersession rejects incomplete or substituted predecessor provenance before its first write", async () => {
  const cases = [
    ["unproven source", (store, args) => { args.proveDescendant = () => false; }],
    ["wrong stale owner", (store) => { store.get(INITIAL_DUAL_SLOT_NAMES.jwtPending).value.rotationId = "rotation-unrelated-pending"; }],
    ["wrong stale rotation", (_store, args) => { args.staleRotationId = "rotation-unrelated-stale"; }],
    ["forged previous marker", (store) => { store.get(INITIAL_DUAL_SLOT_NAMES.jwtPrevious).value.initialMigration = false; }],
    ["nonempty previous marker", (store) => { store.get(INITIAL_DUAL_SLOT_NAMES.qrPublicPrevious).value.value = "substituted"; }],
    ["malformed stale QR marker", (store) => { store.get(INITIAL_DUAL_SLOT_NAMES.qrCurrentVersion).value.value = "not a valid version"; }],
    ["runtime active version unavailable", (_store, args) => { const altered = structuredClone(staleTaskDefinition); altered.taskDefinition.containerDefinitions[0].environment = []; args.taskDefinition = altered; }],
    ["runtime active version malformed", (_store, args) => { const altered = structuredClone(staleTaskDefinition); altered.taskDefinition.containerDefinitions[0].environment[0].value = "not a valid version"; args.taskDefinition = altered; }],
    ["substituted JWT", (store) => { store.get(currentNames.jwt).value.value = "substituted-current-jwt"; }],
    ["wrong JWT version metadata", (store) => { store.get(currentNames.jwt).value.materialFingerprint = "0".repeat(16); }],
    ["cross-rotation current JWT", (store) => { store.get(currentNames.jwt).value.rotationId = "rotation-unrelated-current"; }],
    ["substituted QR public", (store) => { store.get(currentNames.qrPublic).value.value = generateKeyPairSync("ed25519", { publicKeyEncoding: { format: "pem", type: "spki" }, privateKeyEncoding: { format: "pem", type: "pkcs8" } }).publicKey; }],
    ["substituted QR private", (store) => { store.get(currentNames.qrPrivate).value.value = generateKeyPairSync("ed25519", { publicKeyEncoding: { format: "pem", type: "spki" }, privateKeyEncoding: { format: "pem", type: "pkcs8" } }).privateKey; }],
    ["wrong QR metadata", (store) => { store.get(currentNames.qrPublic).value.keyVersion = "wrong-key-version"; }],
    ["wrong resource", (_store, args) => { const altered = structuredClone(staleTaskDefinition); altered.taskDefinition.containerDefinitions[0].secrets[0].valueFrom = arn("unreviewed-current-jwt"); args.taskDefinition = altered; }],
  ];
  for (const [label, mutate] of cases) {
    const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-supersession-reject-"));
    const store = rotationStore();
    const sender = rotationSender(store);
    const args = supersessionArgs({ outputFile: path.join(directory, "supersession.json"), repositoryRoot: "/private/tmp/mscqr-post330-exec" });
    mutate(store, args);
    try {
      await assert.rejects(() => supersedeStalePendingRotation({ send: sender.send, ...args }), undefined, label);
      assert.equal(sender.writes, 0, label);
    } finally { rmSync(directory, { recursive: true, force: true }); }
  }
});

test("fresh bootstrap rejects forged or incomplete supersession handoff provenance without another write", async () => {
  const mutations = [
    ["runtime label", (value) => { value.runtimeQrVersionLabel = "forged-runtime-label"; }],
    ["JWT fingerprint", (value) => { value.current.jwt.materialFingerprint = "0".repeat(16); }],
    ["JWT version", (value) => { value.current.jwt.versionId = "forged-current-version"; }],
    ["QR metadata", (value) => { value.current.qrPrivate.keyVersion = "forged-key-version"; value.current.qrPublic.keyVersion = "forged-key-version"; }],
    ["resource ARN", (value) => { value.current.qrPublic.secretArn = arn("forged-current-public"); }],
  ];
  for (const [label, mutate] of mutations) {
    const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-bootstrap-reject-"));
    const store = rotationStore();
    const sender = rotationSender(store);
    try {
      const result = await supersedeStalePendingRotation({ send: sender.send, ...supersessionArgs(), outputFile: path.join(directory, "supersession.json"), repositoryRoot: "/private/tmp/mscqr-post330-exec" });
      const forged = structuredClone(result.predecessor);
      mutate(forged);
      forged.predecessorIdentitySha256 = productionStaleSupersessionPredecessorIdentity(forged);
      const writes = sender.writes;
      await assert.rejects(() => bootstrapInitialDualSlotRotation({ send: sender.send, taskDefinition: staleTaskDefinition, sourceSha, rotationId, supersessionEvidence: result.evidence, supersessionPredecessor: forged, outputFile: path.join(directory, "bindings.json"), repositoryRoot: "/private/tmp/mscqr-post330-exec" }), undefined, label);
      assert.equal(sender.writes, writes, label);
      await assert.rejects(() => bootstrapInitialDualSlotRotation({ send: sender.send, taskDefinition: staleTaskDefinition, sourceSha, rotationId, supersessionPredecessor: result.predecessor, outputFile: path.join(directory, "incomplete.json"), repositoryRoot: "/private/tmp/mscqr-post330-exec" }), /Complete stale-supersession/);
      assert.equal(sender.writes, writes, label);
    } finally { rmSync(directory, { recursive: true, force: true }); }
  }
});

test("serial-98 Stage-A recovery evidence traverses the real cutover spine without an apply", async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-serial-98-twin-"));
  const state = productionStageAState();
  const stateBytes = Buffer.from(JSON.stringify(state));
  const statePath = path.join(directory, "stage-a-state.json");
  const handoffPath = path.join(directory, "stage-a-handoff.json");
  const stageBPath = path.join(directory, "stage-b-state.json");
  const evidencePath = path.join(directory, "stage-a-recovery.json");
  writeFileSync(statePath, stateBytes, { mode: 0o600 });
  writeFileSync(handoffPath, JSON.stringify({ toolingSha: rehearsalSourceSha, stageAStateIdentityVersion: STAGE_A_STATE_IDENTITY_VERSION, stageAStateObject: STAGE_A_STATE_OBJECT, stageAStateLineage: state.lineage, stageAStateSerial: state.serial, stageAStateSha256: stageAStateSemanticSha256(state) }), { mode: 0o600 });
  writeFileSync(stageBPath, JSON.stringify(convergedStageBState()), { mode: 0o600 });
  const recovery = producePostApplyStageAPlanRecovery({ sourceSha: rehearsalSourceSha, stageAStatePath: statePath, stageAHandoffPath: handoffPath, stageBStatePath: stageBPath, ingress: productionStageAIngress(), outputPath: evidencePath, repositoryRoot: "/private/tmp/mscqr-post330-exec" });
  const result = await runProductionCutoverControlPlane({ ...fixtureInput({ stageA: { recoveryEvidence: JSON.parse(readFileSync(evidencePath, "utf8")), revalidateRecovery: async () => ({ ...readAuthenticatedStageARecoverySources({ stageAStatePath: statePath, stageAHandoffPath: handoffPath, stageBStatePath: stageBPath, repositoryRoot: "/private/tmp/mscqr-post330-exec" }), ingress: productionStageAIngress() }) } }), sourceSha: rehearsalSourceSha });
  assert.equal(result.results.stageA.recoveryMode, "POST_APPLY_STAGE_A_PLAN_RECOVERY");
  assert.equal(result.mutationSequence.some(({ name }) => name === "M2_STAGE_A_APPLY"), false);
  assert.equal(result.readyForOnboarding, true);
});
