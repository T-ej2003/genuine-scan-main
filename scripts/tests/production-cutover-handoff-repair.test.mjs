import assert from "node:assert/strict";
import test from "node:test";
import { constants, createHash, generateKeyPairSync, sign, verify } from "node:crypto";
import { lstatSync, mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import os from "node:os";
import path from "node:path";
import { assertRootDropEvidence, buildRootDropEvidence, buildRootDropPayload, canonicalRootDropPayload, ROOT_DROP_SIGNING_KEY_ARN } from "../aws/production-root-drop-evidence.mjs";
import { assertPostApplyStageAPlanRecovery, producePostApplyStageAPlanRecovery, readAuthenticatedStageARecoverySources } from "../aws/production-stage-a-recovery-evidence.mjs";
import { assertStageAStateContract } from "../aws/generate-production-green-stage-a-prerequisites.mjs";
import { createInitialDualSlotSecretsManagerClient, generatePendingMaterial, INITIAL_DUAL_SLOT_NAMES, supersedeStalePendingRotation } from "../aws/production-initial-dual-slot-bootstrap.mjs";
import { STAGE_B } from "../aws/production-green-stage-b-contract.mjs";
import { fixtureInput, sourceSha as rehearsalSourceSha } from "./production-cutover-rehearsal.test.mjs";
import { runProductionCutoverControlPlane } from "../aws/production-cutover-control-plane.mjs";
import { createProductionCommandRunner } from "../aws/production-cutover-production-adapters.mjs";
import { productionStageAIngress, productionStageAState, STAGE_A_LINEAGE, STAGE_A_STATE_OBJECT } from "./fixtures/production-stage-a-state.mjs";

const sourceSha = "8".repeat(40);
const staleSourceSha = "e".repeat(40);
const rotationId = "rotation-new-20260817";
const staleRotationId = "rotation-old-20260812";
const arn = (name) => `arn:aws:secretsmanager:eu-west-2:368992683803:secret:${name.replaceAll("/", "-")}-abc`;
const digest = (value) => createHash("sha256").update(value).digest("hex");
const requireBackend = createRequire(path.resolve("backend/package.json"));

function rotationStore() {
  const pair = generateKeyPairSync("ed25519", { privateKeyEncoding: { format: "pem", type: "pkcs8" }, publicKeyEncoding: { format: "pem", type: "spki" } });
  const keyVersion = digest(pair.publicKey).slice(0, 16);
  const store = new Map();
  for (const [slot, name] of Object.entries(INITIAL_DUAL_SLOT_NAMES)) {
    const pending = ["jwtPending", "qrPrivatePending", "qrPublicPending"].includes(slot);
    const value = pending
      ? { value: slot === "jwtPending" ? "jwt-old-material" : slot === "qrPrivatePending" ? pair.privateKey : pair.publicKey, sourceSha: staleSourceSha, rotationId: staleRotationId, family: slot === "jwtPending" ? "jwt_secrets" : "qr_signing_keys", slot: slot === "jwtPending" ? "pending" : slot === "qrPrivatePending" ? "pending-private" : "pending-public", ...(slot === "qrPrivatePending" || slot === "qrPublicPending" ? { keyVersion } : {}), materialFingerprint: digest(slot === "jwtPending" ? "jwt-old-material" : slot === "qrPrivatePending" ? pair.privateKey : pair.publicKey).slice(0, 16) }
      : { value: slot === "qrCurrentVersion" ? "v1" : "", sourceSha: staleSourceSha, family: slot === "qrCurrentVersion" || slot === "qrPreviousVersion" ? "qr_key_versions" : slot === "jwtPrevious" ? "jwt_secrets" : "qr_signing_keys", slot: slot === "qrCurrentVersion" ? "current" : slot === "qrPreviousVersion" ? "previous-empty" : "empty", initialMigration: true };
    store.set(name, { value, versionId: `${slot}-old` });
  }
  return store;
}

function rotationSender(store, { failAt } = {}) {
  let writes = 0;
  const send = async (command) => {
    const name = command.input.SecretId;
    const key = [...store.keys()].find((candidate) => candidate === name || arn(candidate) === name);
    if (command.constructor.name === "DescribeSecretCommand") return { Name: key, ARN: arn(key), VersionIdsToStages: { [store.get(key).versionId]: ["AWSCURRENT"] } };
    if (command.constructor.name === "GetSecretValueCommand") return { SecretString: JSON.stringify(store.get(key).value) };
    if (command.constructor.name === "PutSecretValueCommand") {
      writes += 1;
      store.set(key, { value: JSON.parse(command.input.SecretString), versionId: command.input.ClientRequestToken });
      if (writes === failAt) throw new Error(`injected PutSecretValue failure ${writes}`);
      return { VersionId: command.input.ClientRequestToken };
    }
    throw new Error(`unexpected command ${command.constructor.name}`);
  };
  return { send, get writes() { return writes; } };
}

function convergedStageBState() {
  return { version: 4, serial: 98, lineage: "4e438e59-8b8b-194d-030c-5ede0c26344a", outputs: {}, resources: [{ mode: "managed", type: "aws_ecs_service", name: "backend", instances: [{ schema_version: 0, attributes: { id: "mscqr-backend-servi-euw2" } }] }] };
}

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
  const run = createProductionCommandRunner({ profile: "mscqr-production-root-operator", exec: (_file, _args, received) => { options = received; return "{}"; } });
  run(["sts", "get-caller-identity"]);
  assert.equal(options.env.AWS_PROFILE, "mscqr-production-root-operator");
  for (const key of ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN", "AWS_DEFAULT_PROFILE"]) assert.equal(Object.hasOwn(options.env, key), false);
});

test("root-drop evidence is exact, source-bound, fresh, and tamper-evident", () => {
  const payload = buildRootDropPayload({ sourceSha, callerArn: "arn:aws:iam::368992683803:root", now: new Date().toISOString(), nonce: "nonce-1-with-enough-entropy" });
  const keyPair = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const signature = sign("sha256", Buffer.from(canonicalRootDropPayload(payload)), { key: keyPair.privateKey, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 });
  const evidence = buildRootDropEvidence({ payload, signatureBase64: signature.toString("base64") });
  let signedMessage;
  const verifySignature = ({ message, signature: received }) => { signedMessage = message; return verify("sha256", message, { key: keyPair.publicKey, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }, received); };
  assert.equal(assertRootDropEvidence(evidence, { sourceSha, verifySignature }).valid, true);
  assert.equal(signedMessage.toString(), canonicalRootDropPayload(payload));
  assert.equal(ROOT_DROP_SIGNING_KEY_ARN, STAGE_B.rootDropKmsKeyArn);
  assert.throws(() => assertRootDropEvidence({ ...evidence, sourceSha: staleSourceSha }, { sourceSha, verifySignature: () => true }), /source/);
  assert.throws(() => assertRootDropEvidence({ ...evidence, callerArn: "arn:aws:iam::368992683803:user:admin" }, { sourceSha, verifySignature: () => true }), /source/);
  assert.throws(() => assertRootDropEvidence({ ...evidence, evidenceSha256: "0".repeat(64) }, { sourceSha, verifySignature: () => true }), /hash/);
  const forged = { ...evidence, signatureBase64: "Zm9yZ2Vk", evidenceSha256: digest(JSON.stringify({ ...evidence, signatureBase64: "Zm9yZ2Vk", evidenceSha256: undefined })) };
  assert.throws(() => assertRootDropEvidence(forged, { sourceSha, verifySignature: () => false }), /hash|signature/);
  const mutated = buildRootDropEvidence({ payload: { ...payload, nonceHash: digest("different") }, signatureBase64: signature.toString("base64") });
  assert.throws(() => assertRootDropEvidence(mutated, { sourceSha, verifySignature }), /signature/);
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
  writeFileSync(handoffPath, JSON.stringify({ toolingSha: sourceSha, stageAStateObject: STAGE_A_STATE_OBJECT, stageAStateLineage: STAGE_A_LINEAGE, stageAStateSerial: 42, stageAStateSha256: digest(stateBytes) }), { mode: 0o600 });
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
  const store = new Map();
  const pair = generateKeyPairSync("ed25519", { privateKeyEncoding: { format: "pem", type: "pkcs8" }, publicKeyEncoding: { format: "pem", type: "spki" } });
  const keyVersion = digest(pair.publicKey).slice(0, 16);
  for (const [slot, name] of Object.entries(INITIAL_DUAL_SLOT_NAMES)) {
    const value = ["jwtPending", "qrPrivatePending", "qrPublicPending"].includes(slot)
      ? { value: slot === "jwtPending" ? "jwt-old-material" : slot === "qrPrivatePending" ? pair.privateKey : pair.publicKey, sourceSha: staleSourceSha, rotationId: staleRotationId, family: slot === "jwtPending" ? "jwt_secrets" : "qr_signing_keys", slot: slot === "jwtPending" ? "pending" : slot === "qrPrivatePending" ? "pending-private" : "pending-public", ...(slot === "qrPrivatePending" || slot === "qrPublicPending" ? { keyVersion } : {}), materialFingerprint: digest(slot === "jwtPending" ? "jwt-old-material" : slot === "qrPrivatePending" ? pair.privateKey : pair.publicKey).slice(0, 16) }
      : { value: slot === "qrCurrentVersion" ? "v1" : "", sourceSha: staleSourceSha, family: slot === "qrCurrentVersion" || slot === "qrPreviousVersion" ? "qr_key_versions" : slot === "jwtPrevious" ? "jwt_secrets" : "qr_signing_keys", slot: slot === "qrCurrentVersion" ? "current" : slot === "qrPreviousVersion" ? "previous-empty" : "empty", initialMigration: true };
    store.set(name, { value, versionId: `${slot}-old` });
  }
  const send = async (command) => {
    const name = command.input.SecretId;
    const key = [...store.keys()].find((candidate) => candidate === name || arn(candidate) === name);
    if (command.constructor.name === "DescribeSecretCommand") return { Name: key, ARN: arn(key), VersionIdsToStages: { [store.get(key).versionId]: ["AWSCURRENT"] } };
    if (command.constructor.name === "GetSecretValueCommand") return { SecretString: JSON.stringify(store.get(key).value) };
    if (command.constructor.name === "PutSecretValueCommand") { const versionId = command.input.ClientRequestToken; store.set(key, { value: JSON.parse(command.input.SecretString), versionId }); return { VersionId: versionId }; }
    throw new Error(`unexpected command ${command.constructor.name}`);
  };
  const result = await supersedeStalePendingRotation({ send, sourceSha, staleSourceSha, rotationId, staleRotationId, outputFile: path.join(directory, "supersession.json"), repositoryRoot: "/private/tmp/mscqr-post330-exec" });
  assert.equal(result.writes, 7);
  const replay = await supersedeStalePendingRotation({ send, sourceSha, staleSourceSha, rotationId, staleRotationId, outputFile: path.join(directory, "supersession.json"), repositoryRoot: "/private/tmp/mscqr-post330-exec" });
  assert.equal(replay.writes, 0);
  assert.equal(replay.idempotentReplay, true);
  const tampered = JSON.parse(readFileSync(path.join(directory, "supersession.json"), "utf8"));
  tampered.rotationId = "rotation-tampered-20260817";
  writeFileSync(path.join(directory, "supersession.json"), `${JSON.stringify(tampered)}\n`, { mode: 0o600 });
  await assert.rejects(() => supersedeStalePendingRotation({ send, sourceSha, staleSourceSha, rotationId, staleRotationId, outputFile: path.join(directory, "supersession.json"), repositoryRoot: "/private/tmp/mscqr-post330-exec" }), /existing.*does not match|authenticated transition/i);
  await assert.rejects(() => supersedeStalePendingRotation({ send, sourceSha: "7".repeat(40), staleSourceSha, rotationId: "rotation-new-20260818", staleRotationId, outputFile: path.join(directory, "second.json"), repositoryRoot: "/private/tmp/mscqr-post330-exec" }), /unknown|invalid|resumable/i);
});

test("unknown rotation slot evidence fails closed before any write", async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-rotation-unknown-"));
  const store = rotationStore();
  const first = store.keys().next().value;
  store.get(first).value.sourceSha = "f".repeat(40);
  const sender = rotationSender(store);
  await assert.rejects(() => supersedeStalePendingRotation({ send: sender.send, sourceSha, staleSourceSha, rotationId, staleRotationId, outputFile: path.join(directory, "unknown.json"), repositoryRoot: "/private/tmp/mscqr-post330-exec" }), /unknown/);
  assert.equal(sender.writes, 0);
});

test("stale rotation supersession resumes every sequential write boundary without rewriting authenticated new slots", async () => {
  for (let failure = 1; failure <= 7; failure += 1) {
    const directory = mkdtempSync(path.join(os.tmpdir(), `mscqr-rotation-resume-${failure}-`));
    const store = rotationStore();
    const first = rotationSender(store, { failAt: failure });
    const outputFile = path.join(directory, "first.json");
    await assert.rejects(() => supersedeStalePendingRotation({ send: first.send, sourceSha, staleSourceSha, rotationId, staleRotationId, outputFile, repositoryRoot: "/private/tmp/mscqr-post330-exec" }), /injected PutSecretValue failure/);
    const journal = JSON.parse(readFileSync(`${outputFile}.material`, "utf8"));
    assert.equal(statSync(`${outputFile}.material`).mode & 0o077, 0);
    const retry = rotationSender(store);
    const result = await supersedeStalePendingRotation({ send: retry.send, sourceSha, staleSourceSha, rotationId, staleRotationId, outputFile, repositoryRoot: "/private/tmp/mscqr-post330-exec" });
    assert.equal(result.writes, 7 - failure);
    assert.equal(result.idempotentReplay, failure === 7);
    for (const slot of ["jwtPending", "qrPrivatePending", "qrPublicPending"]) assert.equal(store.get(INITIAL_DUAL_SLOT_NAMES[slot]).value.value, journal.material[slot === "jwtPending" ? "jwt" : slot === "qrPrivatePending" ? "qrPrivate" : "qrPublic"]);
    assert.notEqual(store.get(INITIAL_DUAL_SLOT_NAMES.jwtPending).value.value, "jwt-old-material");
    assert.equal(lstatSync(`${outputFile}.material`, { throwIfNoEntry: false }), undefined);
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
  writeFileSync(handoffPath, JSON.stringify({ toolingSha: rehearsalSourceSha, stageAStateObject: STAGE_A_STATE_OBJECT, stageAStateLineage: state.lineage, stageAStateSerial: state.serial, stageAStateSha256: digest(stateBytes) }), { mode: 0o600 });
  writeFileSync(stageBPath, JSON.stringify(convergedStageBState()), { mode: 0o600 });
  const recovery = producePostApplyStageAPlanRecovery({ sourceSha: rehearsalSourceSha, stageAStatePath: statePath, stageAHandoffPath: handoffPath, stageBStatePath: stageBPath, ingress: productionStageAIngress(), outputPath: evidencePath, repositoryRoot: "/private/tmp/mscqr-post330-exec" });
  const result = await runProductionCutoverControlPlane({ ...fixtureInput({ stageA: { recoveryEvidence: JSON.parse(readFileSync(evidencePath, "utf8")), revalidateRecovery: async () => ({ ...readAuthenticatedStageARecoverySources({ stageAStatePath: statePath, stageAHandoffPath: handoffPath, stageBStatePath: stageBPath, repositoryRoot: "/private/tmp/mscqr-post330-exec" }), ingress: productionStageAIngress() }) } }), sourceSha: rehearsalSourceSha });
  assert.equal(result.results.stageA.recoveryMode, "POST_APPLY_STAGE_A_PLAN_RECOVERY");
  assert.equal(result.mutationSequence.some(({ name }) => name === "M2_STAGE_A_APPLY"), false);
  assert.equal(result.readyForOnboarding, true);
});
