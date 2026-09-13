import assert from "node:assert/strict";
import test from "node:test";
import { constants, createHash, generateKeyPairSync, sign, verify } from "node:crypto";
import { lstatSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import os from "node:os";
import path from "node:path";
import JSZip from "jszip";
import { assertRootDropEvidence, buildRootDropEvidence, buildRootDropPayload, canonicalRootDropPayload, ROOT_DROP_SIGNING_KEY_ARN } from "../aws/production-root-drop-evidence.mjs";
import { assertAuthenticatedCurrentStageBState, assertPostApplyStageAPlanRecovery, producePostApplyStageAPlanRecovery, readAuthenticatedStageARecoverySources } from "../aws/production-stage-a-recovery-evidence.mjs";
import { assertStageAStateContract, STAGE_A_STATE_IDENTITY_VERSION, stageAStateSemanticSha256 } from "../aws/generate-production-green-stage-a-prerequisites.mjs";
import { bootstrapInitialDualSlotRotation, createInitialDualSlotSecretsManagerClient, finalizeStaleRotationSupersessionMaterialJournal, generatePendingMaterial, INITIAL_DUAL_SLOT_NAMES, supersedeStalePendingRotation, verifyLiveInitialDualSlotBindingWithRunner } from "../aws/production-initial-dual-slot-bootstrap.mjs";
import { buildProductionRotationConfig } from "../aws/production-cutover-runtime-bootstrap.mjs";
import { buildRebaselinePayloads, PARTIAL_REBASELINE_RECOVERY_ORIGINAL_SOURCE_SHA } from "../aws/production-dual-slot-rebaseline-contract.mjs";
import { STAGE_B } from "../aws/production-green-stage-b-contract.mjs";
import { fixtureInput, sourceSha as rehearsalSourceSha } from "./production-cutover-rehearsal.test.mjs";
import { runProductionCutoverControlPlane } from "../aws/production-cutover-control-plane.mjs";
import { createProductionCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "../aws/production-cutover-production-adapters.mjs";
import { productionStageAIngress, productionStageAState, STAGE_A_LINEAGE, STAGE_A_STATE_OBJECT } from "./fixtures/production-stage-a-state.mjs";
import { prepare, readCurrentState } from "../../backend/scripts/security/rotate-production-signing-material.mjs";
import { validateRotationTransition } from "../security/check-production-rotation-transition.mjs";
import { assertProductionStaleSupersessionPredecessor, productionStaleSupersessionPredecessorIdentity } from "../security/production-initial-migration-source-advance.mjs";
import { createProductionEnvironmentApprovalEvidence } from "../aws/production-github-environment-approval.mjs";
import { assertApprovedStaleRotationSupersessionAuthorization, assertStaleRotationSupersessionConsumption, createApprovedStaleRotationSupersessionAuthorization, createPendingStaleRotationSupersessionAuthorization, createStaleRotationSupersessionConsumption, createStaleRotationSupersessionExecutionStart, createStaleRotationSupersessionPreparation, resolveStaleRotationSupersessionAuthorizationArtifact, resolveStaleRotationSupersessionPublication, staleRotationSupersessionSha256 } from "../aws/production-stale-rotation-supersession-contract.mjs";
import { createStaleRotationSecretsManagerSender, runCli as runStaleSupersessionCli } from "../aws/supersede-production-stale-rotation.mjs";
import { runCli as runStaleSupersessionAuthorizationCli } from "../aws/authorize-production-stale-rotation-supersession.mjs";
import { buildStageBImagePublicationIdentity, publicationIdentitySha256 } from "../aws/stage-b-image-publication-identity.mjs";

const sourceSha = "8".repeat(40);
const staleSourceSha = "e".repeat(40);
const rotationId = "rotation-new-20260817";
const staleRotationId = "rotation-old-20260812";
const arn = (name) => `arn:aws:secretsmanager:eu-west-2:368992683803:secret:${name}-AbCd12`;
const digest = (value) => createHash("sha256").update(value).digest("hex");
const requireBackend = createRequire(path.resolve("backend/package.json"));
const currentOwnerRotationId = "rotation-current-20260801";
const productionQrMetadataIdentifier = "c41ca96ab047dd25"; // ggignore: authenticated public-key fingerprint, not secret material
const currentNames = { jwt: "current-jwt", qrPrivate: "mscqr/prod/qr_sign_private_key", qrPublic: "mscqr/prod/qr_sign_public_key" };
const staleTaskDefinition = { taskDefinition: { containerDefinitions: [{ name: "backend", environment: [{ name: "QR_SIGN_ACTIVE_KEY_VERSION", value: "2026-04-20" }], secrets: [{ name: "JWT_SECRET", valueFrom: arn(currentNames.jwt) }, { name: "QR_SIGN_PRIVATE_KEY", valueFrom: `${arn(currentNames.qrPrivate)}:value::` }, { name: "QR_SIGN_PUBLIC_KEY", valueFrom: `${arn(currentNames.qrPublic)}:value::` }] }] } };
const supersessionArgs = (overrides = {}) => ({ taskDefinition: staleTaskDefinition, sourceSha, staleSourceSha, rotationId, staleRotationId, proveDescendant: ({ ancestorSha, descendantSha }) => ancestorSha === staleSourceSha && descendantSha === sourceSha, mode: "execute", authorizeWritePlan: () => true, ...overrides });
const authorizationProvenance = (authorization, overrides = {}) => {
  const body = { schemaVersion: 1, kind: "PRODUCTION_STALE_PENDING_ROTATION_SUPERSESSION_AUTHORIZATION_PROVENANCE", repository: "T-ej2003/genuine-scan-main", workflowPath: ".github/workflows/authorize-production-stale-rotation-supersession.yml", workflowRunId: "123", workflowRunAttempt: "1", event: "workflow_dispatch", headSha: sourceSha, status: "completed", conclusion: "success", artifactId: 456, artifactName: "production-stale-rotation-supersession-authorization", artifactDigest: `sha256:${"a".repeat(64)}`, authorizationFileSha256: "b".repeat(64), authorizationSha256: authorization.authorizationSha256, approvedBy: authorization.approvedBy, ...overrides };
  return { ...body, provenanceSha256: staleRotationSupersessionSha256(body) };
};
const supersessionApproval = (overrides = {}) => createProductionEnvironmentApprovalEvidence({
  repository: "T-ej2003/genuine-scan-main", environment: "production", sourceSha,
  workflowRef: "T-ej2003/genuine-scan-main/.github/workflows/authorize-production-stale-rotation-supersession.yml@refs/heads/main", eventName: "workflow_dispatch", workflowRunId: "123", workflowRunAttempt: "1", executionActor: "release-operator",
  environmentConfig: { id: 42, name: "production", can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: true, reviewers: [{ type: "User", reviewer: { id: 7, login: "T-ej2003" } }] }] },
  actualApproval: { state: "approved", environmentId: 42, environmentName: "production", userId: 7, userLogin: "T-ej2003" },
  ...overrides,
});
const publicationFixture = () => {
  const imageDigests = { backend: `sha256:${"3".repeat(64)}`, worker: `sha256:${"4".repeat(64)}`, rlsExecutor: `sha256:${"5".repeat(64)}`, rlsCanary: `sha256:${"6".repeat(64)}` };
  const records = [
    ["backend", "mscqr-backend", sourceSha, imageDigests.backend],
    ["worker", "mscqr-worker", sourceSha, imageDigests.worker],
    ["rls-executor", "mscqr-backend", `${sourceSha}-rls-executor`, imageDigests.rlsExecutor],
    ["rls-canary", "mscqr-backend", `${sourceSha}-rls-canary`, imageDigests.rlsCanary],
  ].map(([service, repository, tag, image_digest]) => ({ service, repository, image_tag: tag, image_digest, image_uri: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/${repository}:${tag}`, image_ref: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/${repository}@${image_digest}` }));
  const artifactBytes = Buffer.from(`${records.map(JSON.stringify).join("\n")}\n`);
  const identity = buildStageBImagePublicationIdentity({ observed: { workflowRunId: "34287838722", workflowDatabaseId: "900", workflowFile: ".github/workflows/production-green-stage-b-images.yml", workflowName: "Production Green Stage B Images", event: "workflow_dispatch", workflowDefinitionSha: sourceSha, imageReleaseSha: sourceSha, headBranch: "main", conclusion: "success", artifactId: "457", artifactName: "production-green-stage-b-images", artifactExpired: false, artifactArchiveFilename: null }, artifactBytes, expectedPublicationSourceSha: sourceSha, expectedReleaseSha: sourceSha, observedAt: "2026-09-09T00:00:00.000Z" });
  return { artifactBytes, publication: { runId: "34287838722", artifactSha256: digest(artifactBytes), identitySha256: publicationIdentitySha256(identity), identity, imageDigests } };
};

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

function completedProductionRebaselineStore() {
  const store = rotationStore();
  const sourceSha = PARTIAL_REBASELINE_RECOVERY_ORIGINAL_SOURCE_SHA;
  const rotationId = "rotation-20260829015311-765c8a16";
  const payloads = buildRebaselinePayloads({
    sourceSha,
    rotationId,
    generatedMaterial: {
      jwt: store.get(INITIAL_DUAL_SLOT_NAMES.jwtPending).value.value,
      qrPrivate: store.get(INITIAL_DUAL_SLOT_NAMES.qrPrivatePending).value.value,
      qrPublic: store.get(INITIAL_DUAL_SLOT_NAMES.qrPublicPending).value.value,
      qrKeyVersion: store.get(INITIAL_DUAL_SLOT_NAMES.qrPublicPending).value.keyVersion,
    },
    legacyBaseline: { jwtCurrent: arn(currentNames.jwt), qrPrivateCurrent: arn(currentNames.qrPrivate), qrPublicCurrent: arn(currentNames.qrPublic), qrCurrentVersion: "2026-04-20" },
  });
  for (const [slot, name] of Object.entries(INITIAL_DUAL_SLOT_NAMES)) store.get(name).value = payloads[slot];
  return store;
}

function completedRebaselineSupersessionArgs(directory) {
  return supersessionArgs({
    sourceSha: "a".repeat(40),
    staleSourceSha: PARTIAL_REBASELINE_RECOVERY_ORIGINAL_SOURCE_SHA,
    rotationId: "rotation-fresh-rebaseline-schema",
    staleRotationId: "rotation-20260829015311-765c8a16",
    proveDescendant: ({ ancestorSha, descendantSha }) => ancestorSha === PARTIAL_REBASELINE_RECOVERY_ORIGINAL_SOURCE_SHA && descendantSha === "a".repeat(40),
    outputFile: path.join(directory, "supersession.json"),
    repositoryRoot: "/private/tmp/mscqr-post330-exec",
  });
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
      return await onDescribe?.({ response, key, record: structuredClone(record), store }) || response;
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

async function assertCompletedRebaselineRetryContinuation({ store, sender, result, directory, suffix }) {
  const source = "a".repeat(40);
  const rotation = "rotation-fresh-rebaseline-schema";
  const binding = await bootstrapInitialDualSlotRotation({ send: sender.send, taskDefinition: staleTaskDefinition, sourceSha: source, rotationId: rotation, supersessionEvidence: result.evidence, supersessionPredecessor: result.predecessor, outputFile: path.join(directory, `${suffix}-bindings.json`), repositoryRoot: "/private/tmp/mscqr-post330-exec" });
  const origin = verifyLiveInitialDualSlotBindingWithRunner({ run: originRunner(store), bindings: binding.bindings, proveDescendant: ({ ancestorSha, descendantSha }) => ancestorSha === PARTIAL_REBASELINE_RECOVERY_ORIGINAL_SOURCE_SHA && descendantSha === source });
  const config = buildProductionRotationConfig({
    sourceSha: source,
    rotationId: rotation,
    liveCurrentKeyVersion: "2026-04-20",
    approval: { ticket: "CHG-REBASELINE-RETRY", approvedBy: "checker", approverRole: "production-independent-checker", reason: "source-only retry fixture", verificationRef: `fixture://rebaseline-retry/${suffix}`, minimumGraceSeconds: 2592000 },
    bindings: binding.bindings,
    verifyInitialBindingOrigin: () => origin,
  });
  const context = { config, sm: { send: sender.send }, identity: "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/fixture", clock: () => Date.parse("2026-09-07T00:00:00.000Z"), proveDescendant: ({ ancestorSha, descendantSha }) => ancestorSha === source && descendantSha === source, values: new Map([["state-file", path.join(directory, `${suffix}-state.json`)], ["fixture-file", path.join(directory, `${suffix}-fixture.json`)]]) };
  await prepare(context);
  assert.equal(readCurrentState(context).phase, "overlap-deploy-required");
  await prepare(context);
  const rawState = readFileSync(context.values.get("state-file"));
  assert.equal(validateRotationTransition({ mode: "rotation-overlap", sourceSha: source, rotationId: rotation, deploymentSha: readCurrentState(context).overlapDeploymentSha, rawState, stateSha256: digest(rawState), taskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:51", expectedCurrentTaskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:50", imageDigest: `sha256:${"d".repeat(64)}`, now: Date.now() }).phase, "overlap-deploy-required");
}

function convergedStageBState() {
  return { version: 4, serial: 98, lineage: "4e438e59-8b8b-194d-030c-5ede0c26344a", outputs: {}, resources: [{ mode: "managed", type: "aws_ecs_service", name: "backend", instances: [{ schema_version: 0, attributes: { id: "mscqr-backend-servi-euw2" } }] }] };
}

async function staleSupersessionCliFixture(homeDirectory) {
  const store = rotationStore();
  const sender = rotationSender(store);
  const directory = path.join(homeDirectory, ".mscqr", "production-cutover", "stale-rotation-supersession", sourceSha, staleRotationId);
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const evidenceFile = path.join(directory, "supersession.json");
  const prepared = await supersedeStalePendingRotation({ send: sender.send, ...supersessionArgs({ mode: "prepare", authorizeWritePlan: undefined }), outputFile: evidenceFile, repositoryRoot: process.cwd() });
  const publication = publicationFixture().publication;
  const liveBackendCore = { taskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:52", imageDigest: `sha256:${"7".repeat(64)}` };
  const liveBackend = { ...liveBackendCore, identitySha256: staleRotationSupersessionSha256(liveBackendCore) };
  const stageBState = { lineage: "4e438e59-8b8b-194d-030c-5ede0c26344a", serial: 104, stateSha256: "9".repeat(64) };
  const preparation = createStaleRotationSupersessionPreparation({ discovery: prepared.preparationInput, publication, liveBackend, stageBState });
  const preparationBytes = Buffer.from(`${JSON.stringify(preparation, null, 2)}\n`);
  writeFileSync(path.join(directory, "preparation.json"), preparationBytes, { mode: 0o600 });
  const authorization = createApprovedStaleRotationSupersessionAuthorization({ pendingAuthorization: createPendingStaleRotationSupersessionAuthorization(preparation), preparation, protectedEnvironmentApprovalEvidence: supersessionApproval() });
  const provenance = authorizationProvenance(authorization);
  const client = { assertCredentialIdentity: async () => true, send: sender.send };
  let currentLiveBackend = liveBackend;
  const run = (args) => {
    if (args[0] === "ecs" && args[1] === "describe-services") return JSON.stringify({ services: [{ taskDefinition: currentLiveBackend.taskDefinitionArn }] });
    if (args[0] === "ecs" && args[1] === "describe-task-definition") return JSON.stringify({ taskDefinition: { ...staleTaskDefinition.taskDefinition, containerDefinitions: staleTaskDefinition.taskDefinition.containerDefinitions.map((container) => ({ ...container, image: container.name === "backend" ? `repository@${currentLiveBackend.imageDigest}` : container.image })) } });
    throw new Error(`unexpected CLI call ${args.join(" ")}`);
  };
  const argv = ["--mode", "execute", "--source-sha", sourceSha, "--stale-source-sha", staleSourceSha, "--stale-rotation-id", staleRotationId, "--preparation-sha256", digest(preparationBytes), "--authorization-workflow-run-id", "123", "--authorization-workflow-run-attempt", "1"];
  const deps = { homeDirectory, readProtectedMain: () => true, proveDescendant: ({ ancestorSha, descendantSha }) => ancestorSha === staleSourceSha && descendantSha === sourceSha, run, client, readStageBState: () => stageBState, resolveAuthorization: async () => ({ authorization, provenance }) };
  return { argv, authorization, client, deps, directory, evidenceFile, preparation, provenance, sender, store, setLiveBackend: (value) => { currentLiveBackend = value; } };
}

function staleSupersessionPreparationInputs(directory) {
  const publication = publicationFixture().publication;
  const liveBackendCore = { taskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:52", imageDigest: `sha256:${"7".repeat(64)}` };
  const liveBackend = { ...liveBackendCore, identitySha256: staleRotationSupersessionSha256(liveBackendCore) };
  const stageBState = { lineage: "4e438e59-8b8b-194d-030c-5ede0c26344a", serial: 104, stateSha256: "9".repeat(64) };
  const files = Object.fromEntries(Object.entries({ publication, liveBackend, stageBState }).map(([name, value]) => {
    const file = path.join(directory, `${name}.json`);
    writeFileSync(file, `${JSON.stringify(value)}\n`, { mode: 0o600 });
    return [name, file];
  }));
  return { publication, liveBackend, stageBState, files };
}

function staleSupersessionPrepareCliFixture(homeDirectory) {
  const store = rotationStore();
  const sender = rotationSender(store);
  const inputs = staleSupersessionPreparationInputs(homeDirectory);
  const client = { assertCredentialIdentity: async () => true, send: sender.send };
  const run = (args) => {
    if (args[0] === "ecs" && args[1] === "describe-services") return JSON.stringify({ services: [{ taskDefinition: inputs.liveBackend.taskDefinitionArn }] });
    if (args[0] === "ecs" && args[1] === "describe-task-definition") return JSON.stringify({ taskDefinition: { ...staleTaskDefinition.taskDefinition, containerDefinitions: staleTaskDefinition.taskDefinition.containerDefinitions.map((container) => ({ ...container, image: container.name === "backend" ? `repository@${inputs.liveBackend.imageDigest}` : container.image })) } });
    throw new Error(`unexpected CLI call ${args.join(" ")}`);
  };
  const argv = ["--mode", "prepare", "--source-sha", sourceSha, "--stale-source-sha", staleSourceSha, "--stale-rotation-id", staleRotationId, "--publication", inputs.files.publication, "--live-backend", inputs.files.liveBackend, "--stage-b-state", inputs.files.stageBState];
  const deps = { homeDirectory, readProtectedMain: () => true, proveDescendant: ({ ancestorSha, descendantSha }) => ancestorSha === staleSourceSha && descendantSha === sourceSha, resolvePublication: async ({ publication }) => ({ publication }), readStageBState: () => JSON.parse(readFileSync(inputs.files.stageBState)), run, client };
  return { argv, deps, sender, store, inputs, directory: path.join(homeDirectory, ".mscqr", "production-cutover", "stale-rotation-supersession", sourceSha, staleRotationId) };
}

async function githubAuthorizationFixture(authorization, overrides = {}) {
  const zip = new JSZip();
  zip.file("authorization.json", `${JSON.stringify(overrides.authorization || authorization, null, 2)}\n`);
  const archive = await zip.generateAsync({ type: "nodebuffer", platform: "UNIX" });
  const published = publicationFixture();
  const publicationZip = new JSZip();
  publicationZip.file("stage-b-images.jsonl", published.artifactBytes);
  const publicationArchive = await publicationZip.generateAsync({ type: "nodebuffer", platform: "UNIX" });
  const workflow = { id: 123, repository: { id: 1, full_name: "T-ej2003/genuine-scan-main" }, head_repository: { full_name: "T-ej2003/genuine-scan-main" }, path: ".github/workflows/authorize-production-stale-rotation-supersession.yml", event: "workflow_dispatch", head_sha: sourceSha, status: "completed", conclusion: "success", run_attempt: 1, actor: { login: "release-operator" }, ...overrides.workflow };
  const artifact = { id: 456, name: "production-stale-rotation-supersession-authorization", expired: false, workflow_run: { id: 123, head_sha: sourceSha, repository_id: 1 }, digest: `sha256:${digest(archive)}`, ...overrides.artifact };
  const publicationWorkflow = { id: 34287838722, workflow_id: 900, repository: { id: 1, full_name: "T-ej2003/genuine-scan-main" }, head_repository: { full_name: "T-ej2003/genuine-scan-main" }, path: ".github/workflows/production-green-stage-b-images.yml", name: "Production Green Stage B Images", event: "workflow_dispatch", head_sha: sourceSha, head_branch: "main", status: "completed", conclusion: "success", run_attempt: 1 };
  const publicationArtifact = { id: 457, name: "production-green-stage-b-images", expired: false, workflow_run: { id: 34287838722, head_sha: sourceSha, repository_id: 1 }, digest: `sha256:${digest(publicationArchive)}` };
  const environment = { id: 42, name: "production", can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: true, reviewers: [{ type: "User", reviewer: { id: 7, login: "T-ej2003" } }] }], ...overrides.environment };
  const approvals = overrides.approvals || [{ state: "approved", environments: [{ id: 42, name: "production" }], user: { id: 7, login: "T-ej2003" } }];
  const run = (_command, args, options = {}) => {
    const endpoint = args[1];
    if (endpoint.endsWith("/actions/runs/34287838722")) return JSON.stringify(overrides.publicationWorkflow || publicationWorkflow);
    if (endpoint.endsWith("/actions/runs/34287838722/artifacts")) return JSON.stringify([{ artifacts: [overrides.publicationArtifact || publicationArtifact] }]);
    if (endpoint.endsWith("/actions/artifacts/457/zip")) return options.encoding === null ? (overrides.publicationArchive || publicationArchive) : (overrides.publicationArchive || publicationArchive).toString();
    if (endpoint.endsWith("/actions/runs/123")) return JSON.stringify(workflow);
    if (endpoint.endsWith("/actions/runs/123/artifacts")) return JSON.stringify([{ artifacts: [artifact] }]);
    if (endpoint.endsWith("/actions/artifacts/456/zip")) return options.encoding === null ? (overrides.archive || archive) : (overrides.archive || archive).toString();
    if (endpoint.endsWith("/environments/production")) return JSON.stringify(environment);
    if (endpoint.endsWith("/actions/runs/123/approvals")) return JSON.stringify(approvals);
    throw new Error(`unexpected GitHub endpoint ${endpoint}`);
  };
  return { archive, artifact, publicationArtifact, publicationArchive, publicationWorkflow, run, workflow };
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

test("stale supersession preparation performs ten selector reads, plans seven writes, and requires exact independent approval", async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-stale-supersession-governance-"));
  const store = rotationStore();
  const sender = rotationSender(store);
  const outputFile = path.join(directory, "supersession.json");
  const preparedResult = await supersedeStalePendingRotation({ send: sender.send, ...supersessionArgs({ mode: "prepare", authorizeWritePlan: undefined }), outputFile, repositoryRoot: "/private/tmp/mscqr-post330-exec" });
  assert.equal(sender.reads.length, 10);
  assert.equal(sender.writes, 0);
  assert.equal(preparedResult.preparationInput.writePlan.length, 7);
  assert.deepEqual(preparedResult.preparationInput.writePlan.map(({ slot }) => slot), ["jwtPending", "qrPrivatePending", "qrPublicPending", "jwtPrevious", "qrPublicPrevious", "qrCurrentVersion", "qrPreviousVersion"]);
  assert.equal(JSON.stringify(preparedResult.preparationInput).includes("PRIVATE KEY"), false);
  const publication = publicationFixture().publication;
  const liveBackendCore = { taskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:52", imageDigest: `sha256:${"7".repeat(64)}` };
  const liveBackend = { ...liveBackendCore, identitySha256: staleRotationSupersessionSha256(liveBackendCore) };
  const stageBState = { lineage: "4e438e59-8b8b-194d-030c-5ede0c26344a", serial: 104, stateSha256: "9".repeat(64) };
  const preparation = createStaleRotationSupersessionPreparation({ discovery: preparedResult.preparationInput, publication, liveBackend, stageBState });
  const pending = createPendingStaleRotationSupersessionAuthorization(preparation);
  assert.equal(pending.authorizationStatus, "PENDING");
  assert.equal(pending.approvedBy, "UNSET");
  await assert.rejects(() => supersedeStalePendingRotation({ send: sender.send, ...supersessionArgs(), outputFile, repositoryRoot: "/private/tmp/mscqr-post330-exec", authorizeWritePlan: undefined }), /authorization is required/);
  assert.equal(sender.writes, 0);
  const approval = supersessionApproval();
  const authorization = createApprovedStaleRotationSupersessionAuthorization({ pendingAuthorization: pending, preparation, protectedEnvironmentApprovalEvidence: approval });
  assert.equal(JSON.stringify(authorization).includes("PRIVATE KEY"), false);
  assert.throws(() => assertApprovedStaleRotationSupersessionAuthorization(pending, preparation, { sourceSha, materialJournalFileSha256: preparation.materialJournalFileSha256 }), /schema is invalid|not exactly approved/);
  const wrongReviewerBody = { ...authorization, approvedBy: "different-reviewer" };
  delete wrongReviewerBody.authorizationSha256;
  const wrongReviewer = { ...wrongReviewerBody, authorizationSha256: staleRotationSupersessionSha256(wrongReviewerBody) };
  assert.throws(() => assertApprovedStaleRotationSupersessionAuthorization(wrongReviewer, preparation, { sourceSha, materialJournalFileSha256: preparation.materialJournalFileSha256 }), /not exactly approved/);
  assert.throws(() => assertApprovedStaleRotationSupersessionAuthorization(authorization, preparation, { sourceSha, materialJournalFileSha256: "0".repeat(64) }), /material journal differs/);
  const alteredPreparation = structuredClone(preparation);
  alteredPreparation.writePlan[0].payloadSha256 = "0".repeat(64);
  assert.throws(() => assertApprovedStaleRotationSupersessionAuthorization(authorization, alteredPreparation, { sourceSha, materialJournalFileSha256: preparation.materialJournalFileSha256 }), /hash or write plan/);
  const result = await supersedeStalePendingRotation({
    send: sender.send, ...supersessionArgs(), outputFile, repositoryRoot: "/private/tmp/mscqr-post330-exec",
    authorizeWritePlan: (discovery) => {
      const current = createStaleRotationSupersessionPreparation({ discovery, publication, liveBackend, stageBState, preparedAt: preparation.preparedAt });
      assert.equal(current.preparationSha256, preparation.preparationSha256);
      assertApprovedStaleRotationSupersessionAuthorization(authorization, preparation, { sourceSha, materialJournalFileSha256: discovery.materialJournalFileSha256 });
      return true;
    },
  });
  assert.equal(result.writes, 7);
  assert.equal(result.preWriteAuthorizationAuthenticated, true);
  assert.equal(sender.writes, 7);
  const provenance = authorizationProvenance(authorization);
  const consumption = createStaleRotationSupersessionConsumption({ authorization, authorizationProvenance: provenance, preparation, supersessionEvidenceSha256: result.evidenceSha256, rotationBindingSha256: "b".repeat(64) });
  assert.equal(assertStaleRotationSupersessionConsumption(consumption, { authorization, authorizationProvenance: provenance, preparation }).authorizationConsumed, true);
  assert.throws(() => assertStaleRotationSupersessionConsumption({ ...consumption, authorizationSha256: "c".repeat(64) }, { authorization, authorizationProvenance: provenance, preparation }), /binding/);
  const resumed = await supersedeStalePendingRotation({
    send: sender.send, ...supersessionArgs(), outputFile, repositoryRoot: "/private/tmp/mscqr-post330-exec",
    authorizeWritePlan: () => true,
  });
  assert.equal(resumed.writes, 0);
  assert.equal(resumed.idempotentReplay, true);
  finalizeStaleRotationSupersessionMaterialJournal({ outputFile, expectedFileSha256: digest(readFileSync(`${outputFile}.material`)), repositoryRoot: "/private/tmp/mscqr-post330-exec" });
  await assert.rejects(() => supersedeStalePendingRotation({ send: sender.send, ...supersessionArgs(), outputFile, repositoryRoot: "/private/tmp/mscqr-post330-exec" }), /already durably consumed/);
  rmSync(directory, { recursive: true, force: true });
});

test("stale supersession authorization rejects altered plan, journal, reviewer, and caller-selected output path", async () => {
  await assert.rejects(() => runStaleSupersessionCli(["--mode", "execute", "--output-directory", "/tmp/alternate"]), /Invalid or duplicate argument/);
  await assert.rejects(() => runStaleSupersessionCli(["--mode", "execute", "--authorization", "/tmp/fabricated.json"]), /Invalid or duplicate argument/);
  const body = readFileSync("scripts/aws/supersede-production-stale-rotation.mjs", "utf8");
  assert.match(body, /--mode prepare or --mode execute is required/);
  assert.match(body, /os\.userInfo\(\)\.homedir/);
  assert.doesNotMatch(body, /os\.homedir\(\)/);
  assert.doesNotMatch(body, /accepted.*output-directory/);
  const workflow = readFileSync(".github/workflows/authorize-production-stale-rotation-supersession.yml", "utf8");
  assert.match(workflow, /environment: production/);
  assert.match(workflow, /permissions:\n  contents: read\n  actions: read\n\njobs:/);
  assert.match(workflow, /- run: npm ci\n\s+- run: npm --prefix backend ci\n\s+- name: Re-authenticate protected source after dependency installation/);
  assert.match(workflow, /- name: Produce approved exact authorization\n\s+env:\n\s+GITHUB_TOKEN: \$\{\{ github\.token \}\}\n\s+PREPARATION_FILE_SHA256:/);
  assert.doesNotMatch(workflow, /PutSecretValue|secretsmanager:|aws-actions\/configure-aws-credentials/);
});

test("stale supersession execution trusts only the authenticated GitHub run and artifact", async () => {
  const home = mkdtempSync(path.join(os.tmpdir(), "mscqr-stale-auth-provenance-"));
  try {
    const fixture = await staleSupersessionCliFixture(home);
    const github = await githubAuthorizationFixture(fixture.authorization);
    const resolved = await resolveStaleRotationSupersessionAuthorizationArtifact({ workflowRunId: "123", workflowRunAttempt: "1", sourceSha, preparation: fixture.preparation, run: github.run });
    assert.equal(resolved.authorization.authorizationSha256, fixture.authorization.authorizationSha256);
    assert.equal(resolved.provenance.artifactId, 456);
    assert.equal(resolved.provenance.approvedBy, "T-ej2003");

    const cases = [
      { workflow: { path: ".github/workflows/other.yml" } },
      { workflow: { repository: { id: 1, full_name: "attacker/repository" } } },
      { workflow: { head_sha: staleSourceSha } },
      { workflow: { run_attempt: 2 } },
      { workflow: { conclusion: "failure" } },
      { artifact: { name: "other-artifact" } },
      { archive: Buffer.from("changed artifact") },
      { approvals: [{ state: "approved", environments: [{ id: 42, name: "production" }], user: { id: 8, login: "other-reviewer" } }] },
    ];
    for (const changed of cases) {
      const candidate = await githubAuthorizationFixture(fixture.authorization, changed);
      await assert.rejects(() => resolveStaleRotationSupersessionAuthorizationArtifact({ workflowRunId: "123", workflowRunAttempt: "1", sourceSha, preparation: fixture.preparation, run: candidate.run }), /provenance|artifact|approval|digest|exact|authentic/i);
    }
    const rerun = await githubAuthorizationFixture(fixture.authorization, { workflow: { run_attempt: 2 } });
    await assert.rejects(() => resolveStaleRotationSupersessionAuthorizationArtifact({ workflowRunId: "123", workflowRunAttempt: "2", sourceSha, preparation: fixture.preparation, run: rerun.run }), /coordinates|provenance/i);
    const altered = { ...fixture.authorization, authorizationSha256: "0".repeat(64) };
    const changedBody = await githubAuthorizationFixture(fixture.authorization, { authorization: altered });
    await assert.rejects(() => resolveStaleRotationSupersessionAuthorizationArtifact({ workflowRunId: "123", workflowRunAttempt: "1", sourceSha, preparation: fixture.preparation, run: changedBody.run }), /hash|authorization/i);
    await assert.rejects(() => resolveStaleRotationSupersessionAuthorizationArtifact({ workflowRunId: "999", workflowRunAttempt: "1", sourceSha, preparation: fixture.preparation, run: github.run }), /malformed|unavailable|provenance/i);
    assert.equal(fixture.sender.writes, 0);
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("stale supersession independently authenticates the source-bound four-image publication", async () => {
  const home = mkdtempSync(path.join(os.tmpdir(), "mscqr-stale-publication-provenance-"));
  try {
    const fixture = await staleSupersessionCliFixture(home);
    const github = await githubAuthorizationFixture(fixture.authorization);
    const resolved = await resolveStaleRotationSupersessionPublication({ publication: fixture.preparation.publication, sourceSha, run: github.run });
    assert.equal(resolved.workflowRunId, fixture.preparation.publication.runId);
    assert.deepEqual(resolved.imageDigests, fixture.preparation.publication.imageDigests);
    for (const changed of [
      { publicationWorkflow: { ...github.publicationWorkflow, path: ".github/workflows/other.yml" } },
      { publicationWorkflow: { id: 34287838722, workflow_id: 900, repository: { id: 1, full_name: "T-ej2003/genuine-scan-main" }, head_repository: { full_name: "T-ej2003/genuine-scan-main" }, path: ".github/workflows/production-green-stage-b-images.yml", name: "Production Green Stage B Images", event: "workflow_dispatch", head_sha: staleSourceSha, head_branch: "main", status: "completed", conclusion: "success", run_attempt: 1 } },
      { publicationArchive: Buffer.from("changed publication") },
    ]) {
      const candidate = await githubAuthorizationFixture(fixture.authorization, changed);
      await assert.rejects(() => resolveStaleRotationSupersessionPublication({ publication: fixture.preparation.publication, sourceSha, run: candidate.run }), /provenance|archive|artifact|malformed|authentic/i);
    }
    const alteredIdentity = structuredClone(fixture.preparation.publication);
    alteredIdentity.identity.workflowDatabaseId = "901";
    alteredIdentity.identitySha256 = publicationIdentitySha256(alteredIdentity.identity);
    await assert.rejects(() => resolveStaleRotationSupersessionPublication({ publication: alteredIdentity, sourceSha, run: github.run }), /publication identity does not match/i);
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("authorization generation fails closed unless publication provenance is independently authenticated", async () => {
  const home = mkdtempSync(path.join(os.tmpdir(), "mscqr-stale-authorization-publication-"));
  try {
    const fixture = await staleSupersessionCliFixture(home);
    const preparationFile = path.join(fixture.directory, "preparation.json");
    const approvalFile = path.join(fixture.directory, "approval.json");
    const approvalBytes = Buffer.from(`${JSON.stringify(fixture.authorization.protectedEnvironmentApprovalEvidence, null, 2)}\n`);
    writeFileSync(approvalFile, approvalBytes, { mode: 0o600 });
    const argv = ["--authorize", "--preparation", preparationFile, "--preparation-file-sha256", digest(readFileSync(preparationFile)), "--environment-approval", approvalFile, "--environment-approval-sha256", digest(approvalBytes), "--output", path.join(fixture.directory, "authorization-output.json")];
    let checks = 0;
    await runStaleSupersessionAuthorizationCli(argv, { resolvePublication: async () => { checks += 1; return true; } });
    assert.equal(checks, 1);
    await assert.rejects(() => runStaleSupersessionAuthorizationCli([...argv.slice(0, -1), path.join(fixture.directory, "rejected-authorization.json")], { resolvePublication: async () => { throw new Error("publication provenance rejected"); } }), /publication provenance rejected/);
    assert.equal(lstatSync(path.join(fixture.directory, "rejected-authorization.json"), { throwIfNoEntry: false }), undefined);
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("stale supersession rejects dirty executed source before credentials or AWS reads", async () => {
  const home = mkdtempSync(path.join(os.tmpdir(), "mscqr-stale-dirty-source-"));
  try {
    const fixture = await staleSupersessionCliFixture(home);
    let credentialFactories = 0;
    let credentialAssertions = 0;
    let awsCalls = 0;
    await assert.rejects(() => runStaleSupersessionCli(fixture.argv, {
      ...fixture.deps,
      client: { assertCredentialIdentity: async () => { credentialAssertions += 1; }, send: fixture.client.send },
      createProductionCommandRunner: () => { credentialFactories += 1; throw new Error("credential factory reached"); },
      readProtectedMain: () => { throw new Error("Stage B tooling checkout contains an untracked file."); },
      run: (...args) => { awsCalls += 1; return fixture.deps.run(...args); },
    }), /untracked file/);
    assert.equal(credentialFactories, 0);
    assert.equal(credentialAssertions, 0);
    assert.equal(awsCalls, 0);
    assert.equal(fixture.sender.writes, 0);
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("stale supersession rejects path-shaped rotation identities before credentials or filesystem state", async () => {
  let credentialFactories = 0;
  await assert.rejects(() => runStaleSupersessionCli(["--mode", "execute", "--source-sha", sourceSha, "--stale-source-sha", staleSourceSha, "--stale-rotation-id", "../../substitution", "--preparation-sha256", "a".repeat(64), "--authorization-workflow-run-id", "123", "--authorization-workflow-run-attempt", "1"], {
    readProtectedMain: () => true,
    createProductionCommandRunner: () => { credentialFactories += 1; throw new Error("credential factory reached"); },
  }), /source\/rotation identity is invalid/);
  assert.equal(credentialFactories, 0);
});

test("stale supersession requires an exact current Stage-B state before every write plan", async () => {
  for (const [label, current] of [
    ["lineage", { lineage: "5e438e59-8b8b-194d-030c-5ede0c26344a", serial: 104, stateSha256: "9".repeat(64) }],
    ["serial", { lineage: "4e438e59-8b8b-194d-030c-5ede0c26344a", serial: 105, stateSha256: "9".repeat(64) }],
    ["sha", { lineage: "4e438e59-8b8b-194d-030c-5ede0c26344a", serial: 104, stateSha256: "a".repeat(64) }],
  ]) {
    const home = mkdtempSync(path.join(os.tmpdir(), `mscqr-stale-stage-b-${label}-`));
    try {
      const fixture = await staleSupersessionCliFixture(home);
      await assert.rejects(() => runStaleSupersessionCli(fixture.argv, { ...fixture.deps, readStageBState: () => current }), /Stage-B state changed/);
      assert.equal(fixture.sender.writes, 0);
    } finally { rmSync(home, { recursive: true, force: true }); }
  }
});

test("Stage-B drift or unreadability after an authenticated prefix cannot write a suffix", async () => {
  const home = mkdtempSync(path.join(os.tmpdir(), "mscqr-stale-stage-b-prefix-"));
  try {
    const fixture = await staleSupersessionCliFixture(home);
    let writes = 0;
    await assert.rejects(() => runStaleSupersessionCli(fixture.argv, {
      ...fixture.deps,
      client: { assertCredentialIdentity: fixture.client.assertCredentialIdentity, send: async (command) => {
        const response = await fixture.sender.send(command);
        if (command.constructor.name === "PutSecretValueCommand" && ++writes === 1) throw new Error("injected prefix failure");
        return response;
      } },
    }), /injected prefix failure/);
    assert.equal(fixture.sender.writes, 1);
    await assert.rejects(() => runStaleSupersessionCli(fixture.argv, { ...fixture.deps, readStageBState: () => { throw new Error("state backend unavailable"); } }), /state backend unavailable/);
    assert.equal(fixture.sender.writes, 1);
    await assert.rejects(() => runStaleSupersessionCli(fixture.argv, { ...fixture.deps, readStageBState: () => ({ ...fixture.preparation.stageBState, serial: 105 }) }), /Stage-B state changed/);
    assert.equal(fixture.sender.writes, 1);
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("stale supersession reauthenticates Stage-B immediately before every new write", async () => {
  const home = mkdtempSync(path.join(os.tmpdir(), "mscqr-stale-stage-b-per-write-"));
  try {
    const fixture = await staleSupersessionCliFixture(home);
    let stageReads = 0;
    let successfulWrites = 0;
    const client = { assertCredentialIdentity: fixture.client.assertCredentialIdentity, send: async (command) => {
      const response = await fixture.sender.send(command);
      if (command.constructor.name === "PutSecretValueCommand") successfulWrites += 1;
      return response;
    } };
    const result = await runStaleSupersessionCli(fixture.argv, { ...fixture.deps, client, readStageBState: () => { stageReads += 1; return fixture.preparation.stageBState; } });
    assert.equal(result.writes, 7);
    assert.equal(successfulWrites, 7);
    assert.equal(stageReads, 7);

    for (const driftAfter of [1, 3, 6]) {
      const isolated = await staleSupersessionCliFixture(mkdtempSync(path.join(os.tmpdir(), `mscqr-stale-stage-b-drift-${driftAfter}-`)));
      let writes = 0;
      await assert.rejects(() => runStaleSupersessionCli(isolated.argv, {
        ...isolated.deps,
        client: { assertCredentialIdentity: isolated.client.assertCredentialIdentity, send: async (command) => {
          const response = await isolated.sender.send(command);
          if (command.constructor.name === "PutSecretValueCommand") writes += 1;
          return response;
        } },
        readStageBState: () => writes >= driftAfter ? { ...isolated.preparation.stageBState, serial: isolated.preparation.stageBState.serial + 1 } : isolated.preparation.stageBState,
      }), /Stage-B state changed/);
      assert.equal(writes, driftAfter);
      assert.equal(isolated.sender.writes, driftAfter);
    }
    const unreadableHome = mkdtempSync(path.join(os.tmpdir(), "mscqr-stale-stage-b-read-failure-"));
    const unreadable = await staleSupersessionCliFixture(unreadableHome);
    let writesBeforeReadFailure = 0;
    await assert.rejects(() => runStaleSupersessionCli(unreadable.argv, {
      ...unreadable.deps,
      client: { assertCredentialIdentity: unreadable.client.assertCredentialIdentity, send: async (command) => {
        const response = await unreadable.sender.send(command);
        if (command.constructor.name === "PutSecretValueCommand") writesBeforeReadFailure += 1;
        return response;
      } },
      readStageBState: () => { if (writesBeforeReadFailure === 3) throw new Error("injected Stage-B read failure"); return unreadable.preparation.stageBState; },
    }), /injected Stage-B read failure/);
    assert.equal(writesBeforeReadFailure, 3);
    rmSync(unreadableHome, { recursive: true, force: true });
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("stale supersession reauthenticates secret topology immediately before every new write", async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-stale-secret-topology-per-write-"));
  try {
    const store = rotationStore();
    let writes = 0;
    const sender = rotationSender(store, { onDescribe: ({ response, key }) => {
      if (writes === 1 && key === INITIAL_DUAL_SLOT_NAMES.jwtPending) return { ...response, VersionIdsToStages: { "unexpected-version": ["AWSCURRENT"] } };
      return response;
    } });
    const send = async (command) => {
      const response = await sender.send(command);
      if (command.constructor.name === "PutSecretValueCommand") writes += 1;
      return response;
    };
    await assert.rejects(() => supersedeStalePendingRotation({ send, ...supersessionArgs(), outputFile: path.join(directory, "supersession.json"), repositoryRoot: process.cwd() }), /topology changed before write 2/);
    assert.equal(writes, 1);
    assert.equal(sender.writes, 1);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("governed supersession bootstrap cannot create an eighth secret value", async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-stale-strict-bootstrap-"));
  try {
    const store = rotationStore();
    const sender = rotationSender(store);
    const prepared = await supersedeStalePendingRotation({ send: sender.send, ...supersessionArgs({ mode: "prepare", authorizeWritePlan: undefined }), outputFile: path.join(directory, "supersession.json"), repositoryRoot: process.cwd() });
    const result = await supersedeStalePendingRotation({ send: sender.send, ...supersessionArgs(), outputFile: path.join(directory, "supersession.json"), repositoryRoot: process.cwd() });
    const failClosed = async (command) => {
      if (command.constructor.name === "GetSecretValueCommand" && command.input.SecretId === arn(INITIAL_DUAL_SLOT_NAMES.jwtPending) && !command.input.VersionId) {
        const error = new Error("not found"); error.name = "ResourceNotFoundException"; throw error;
      }
      return sender.send(command);
    };
    await assert.rejects(() => bootstrapInitialDualSlotRotation({ send: failClosed, taskDefinition: staleTaskDefinition, sourceSha, rotationId, supersessionEvidence: result.evidence, supersessionPredecessor: result.predecessor, outputFile: path.join(directory, "bindings.json"), repositoryRoot: process.cwd(), requireExisting: true, requiredWritePlan: prepared.preparationInput.writePlan }), /requires every prepared pending value/);
    assert.equal(sender.writes, 7);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("governed supersession cannot certify a payload substituted after write seven", async () => {
  const home = mkdtempSync(path.join(os.tmpdir(), "mscqr-stale-post-write-substitution-"));
  try {
    const fixture = await staleSupersessionCliFixture(home);
    let pendingReads = 0;
    await assert.rejects(() => runStaleSupersessionCli(fixture.argv, {
      ...fixture.deps,
      client: { assertCredentialIdentity: fixture.client.assertCredentialIdentity, send: async (command) => {
        if (command.constructor.name === "GetSecretValueCommand" && command.input.SecretId === arn(INITIAL_DUAL_SLOT_NAMES.jwtPending) && ++pendingReads === 3) {
          const record = fixture.store.get(INITIAL_DUAL_SLOT_NAMES.jwtPending);
          record.value = { ...record.value, value: "substituted-post-write-material", materialFingerprint: digest("substituted-post-write-material").slice(0, 16) };
        }
        return fixture.sender.send(command);
      } },
    }), /differs from the authenticated supersession write plan/);
    assert.equal(fixture.sender.writes, 7);
    assert.equal(lstatSync(path.join(fixture.directory, "consumption.json"), { throwIfNoEntry: false }), undefined);
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("stale supersession re-fetches live ECS after authorization resolution", async () => {
  const home = mkdtempSync(path.join(os.tmpdir(), "mscqr-stale-live-ecs-auth-window-"));
  try {
    const fixture = await staleSupersessionCliFixture(home);
    fixture.deps.resolveAuthorization = async () => {
      fixture.setLiveBackend({ ...fixture.preparation.liveBackend, taskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:53", imageDigest: `sha256:${"a".repeat(64)}` });
      return { authorization: fixture.authorization, provenance: fixture.provenance };
    };
    await assert.rejects(() => runStaleSupersessionCli(fixture.argv, fixture.deps), /Live backend changed after/);
    assert.equal(fixture.sender.writes, 0);
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("stale supersession reauthenticates live ECS before every new write", async () => {
  const home = mkdtempSync(path.join(os.tmpdir(), "mscqr-stale-live-ecs-per-write-"));
  try {
    const fixture = await staleSupersessionCliFixture(home);
    let writes = 0;
    const client = { assertCredentialIdentity: fixture.client.assertCredentialIdentity, send: async (command) => {
      const response = await fixture.sender.send(command);
      if (command.constructor.name === "PutSecretValueCommand" && ++writes === 1) fixture.setLiveBackend({ ...fixture.preparation.liveBackend, taskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:53" });
      return response;
    } };
    await assert.rejects(() => runStaleSupersessionCli(fixture.argv, { ...fixture.deps, client }), /Live backend changed at/);
    assert.equal(writes, 1);
    assert.equal(fixture.sender.writes, 1);
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("authenticated GitHub provenance is required on the real seven-write CLI boundary", async () => {
  const home = mkdtempSync(path.join(os.tmpdir(), "mscqr-stale-authenticated-execute-"));
  try {
    const fixture = await staleSupersessionCliFixture(home);
    const github = await githubAuthorizationFixture(fixture.authorization);
    let executionStarts = 0;
    const deps = { ...fixture.deps, githubRun: github.run, afterExecutionStart: () => { executionStarts += 1; } };
    delete deps.resolveAuthorization;
    const result = await runStaleSupersessionCli(fixture.argv, deps);
    assert.equal(result.writes, 7);
    assert.equal(fixture.sender.writes, 7);
    assert.equal(executionStarts, 1);
    assert.match(result.authorizationProvenanceSha256, /^[a-f0-9]{64}$/);
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("a resolver cannot return self-reported approval without authenticated provenance", async () => {
  const home = mkdtempSync(path.join(os.tmpdir(), "mscqr-stale-missing-provenance-"));
  try {
    const fixture = await staleSupersessionCliFixture(home);
    await assert.rejects(() => runStaleSupersessionCli(fixture.argv, { ...fixture.deps, resolveAuthorization: async () => ({ authorization: fixture.authorization }) }), /provenance/i);
    assert.equal(fixture.sender.writes, 0);
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("terminal receipt makes material-journal cleanup resumable without replaying writes", async () => {
  const home = mkdtempSync(path.join(os.tmpdir(), "mscqr-stale-terminal-cleanup-"));
  try {
    const fixture = await staleSupersessionCliFixture(home);
    await assert.rejects(() => runStaleSupersessionCli(fixture.argv, { ...fixture.deps, afterConsumptionPersist: () => { throw new Error("injected crash after receipt"); } }), /injected crash after receipt/);
    const receipt = path.join(fixture.directory, "consumption.json");
    const journal = `${fixture.evidenceFile}.material`;
    assert.ok(lstatSync(receipt));
    assert.ok(lstatSync(journal));
    assert.equal(fixture.sender.writes, 7);
    const recovered = await runStaleSupersessionCli(fixture.argv, { ...fixture.deps, now: new Date(new Date(fixture.preparation.expiresAt).getTime() + 1000) });
    assert.equal(recovered.terminalCleanupRecovered, true);
    assert.equal(recovered.writes, 0);
    assert.equal(fixture.sender.writes, 7);
    assert.equal(lstatSync(journal, { throwIfNoEntry: false }), undefined);
    await assert.rejects(() => runStaleSupersessionCli(fixture.argv, fixture.deps), /already durably consumed/);
    assert.equal(fixture.sender.writes, 7);
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("all seven authenticated writes resume through terminal receipt without regenerating material", async () => {
  const home = mkdtempSync(path.join(os.tmpdir(), "mscqr-stale-post-seven-"));
  try {
    const fixture = await staleSupersessionCliFixture(home);
    await assert.rejects(() => runStaleSupersessionCli(fixture.argv, { ...fixture.deps, afterBootstrap: () => { throw new Error("injected crash after write seven"); } }), /injected crash after write seven/);
    assert.equal(fixture.sender.writes, 7);
    assert.equal(lstatSync(path.join(fixture.directory, "consumption.json"), { throwIfNoEntry: false }), undefined);
    assert.ok(lstatSync(`${fixture.evidenceFile}.material`));
    const completed = await runStaleSupersessionCli(fixture.argv, fixture.deps);
    assert.equal(completed.writes, 0);
    assert.equal(completed.authorizationConsumed, true);
    assert.equal(fixture.sender.writes, 7);
    assert.equal(lstatSync(`${fixture.evidenceFile}.material`, { throwIfNoEntry: false }), undefined);
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("an all-new topology without the authorization-bound start record cannot terminalize", async () => {
  const home = mkdtempSync(path.join(os.tmpdir(), "mscqr-stale-all-new-no-start-"));
  try {
    const fixture = await staleSupersessionCliFixture(home);
    const direct = await supersedeStalePendingRotation({ send: fixture.sender.send, ...supersessionArgs({ rotationId: fixture.preparation.replacementRotationId }), outputFile: fixture.evidenceFile, repositoryRoot: process.cwd() });
    assert.equal(direct.writes, 7);
    assert.equal(lstatSync(path.join(fixture.directory, "execution-start.json"), { throwIfNoEntry: false }), undefined);
    await assert.rejects(() => runStaleSupersessionCli(fixture.argv, fixture.deps), /missing its authenticated execution start/);
    assert.equal(fixture.sender.writes, 7);
    assert.equal(lstatSync(path.join(fixture.directory, "consumption.json"), { throwIfNoEntry: false }), undefined);
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("terminal cleanup rejects forged receipts and substituted journals without deleting them", async () => {
  for (const attack of ["forged-receipt", "wrong-journal"]) {
    const home = mkdtempSync(path.join(os.tmpdir(), `mscqr-stale-${attack}-`));
    try {
      const fixture = await staleSupersessionCliFixture(home);
      await assert.rejects(() => runStaleSupersessionCli(fixture.argv, { ...fixture.deps, afterConsumptionPersist: () => { throw new Error("injected crash after receipt"); } }), /injected/);
      const receiptPath = path.join(fixture.directory, "consumption.json");
      const journalPath = `${fixture.evidenceFile}.material`;
      if (attack === "forged-receipt") {
        const receipt = JSON.parse(readFileSync(receiptPath));
        receipt.supersessionEvidenceSha256 = "c".repeat(64);
        receipt.terminalExecutionIdentitySha256 = staleRotationSupersessionSha256({ authorizationProvenanceSha256: fixture.provenance.provenanceSha256, preparationSha256: fixture.preparation.preparationSha256, materialJournalIdentity: fixture.preparation.materialJournalIdentity, materialJournalFileSha256: fixture.preparation.materialJournalFileSha256, writePlanSha256: fixture.preparation.writePlanSha256, supersessionEvidenceSha256: receipt.supersessionEvidenceSha256, rotationBindingSha256: receipt.rotationBindingSha256 });
        delete receipt.consumptionSha256;
        receipt.consumptionSha256 = staleRotationSupersessionSha256(receipt);
        writeFileSync(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`, { mode: 0o600 });
      } else {
        writeFileSync(journalPath, Buffer.concat([readFileSync(journalPath), Buffer.from(" ")]), { mode: 0o600 });
      }
      await assert.rejects(() => runStaleSupersessionCli(fixture.argv, fixture.deps), /receipt|journal|evidence|transaction/i);
      assert.ok(lstatSync(journalPath));
      assert.equal(fixture.sender.writes, 7);
    } finally { rmSync(home, { recursive: true, force: true }); }
  }
});

test("journal cleanup failure is safely retried after terminal consumption", async () => {
  const home = mkdtempSync(path.join(os.tmpdir(), "mscqr-stale-cleanup-retry-"));
  try {
    const fixture = await staleSupersessionCliFixture(home);
    await assert.rejects(() => runStaleSupersessionCli(fixture.argv, { ...fixture.deps, finalizeJournal: () => { throw new Error("injected cleanup failure"); } }), /injected cleanup failure/);
    assert.equal(fixture.sender.writes, 7);
    assert.ok(lstatSync(`${fixture.evidenceFile}.material`));
    const recovered = await runStaleSupersessionCli(fixture.argv, fixture.deps);
    assert.equal(recovered.terminalCleanupRecovered, true);
    assert.equal(fixture.sender.writes, 7);
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("an authenticated in-time start permits only its exact post-TTL prefix continuation", async () => {
  const home = mkdtempSync(path.join(os.tmpdir(), "mscqr-stale-post-ttl-prefix-"));
  try {
    const fixture = await staleSupersessionCliFixture(home);
    const fresh = new Date(new Date(fixture.authorization.approvedAt).getTime() + 1000);
    const expired = new Date(new Date(fixture.preparation.expiresAt).getTime() + 1000);
    let prefixWrites = 0;
    const prefixClient = { assertCredentialIdentity: fixture.client.assertCredentialIdentity, send: async (command) => {
      const response = await fixture.sender.send(command);
      if (command.constructor.name === "PutSecretValueCommand" && ++prefixWrites === 3) throw new Error("injected crash after prefix");
      return response;
    } };
    await assert.rejects(() => runStaleSupersessionCli(fixture.argv, { ...fixture.deps, client: prefixClient, now: fresh }), /injected crash after prefix/);
    assert.equal(prefixWrites, 3);
    assert.ok(lstatSync(path.join(fixture.directory, "execution-start.json")));
    const resumed = await runStaleSupersessionCli(fixture.argv, { ...fixture.deps, now: expired });
    assert.equal(resumed.writes, 4);
    assert.equal(fixture.sender.writes, 7);
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("a fresh zero-prefix execution-start retry resumes the exact transaction, but never after expiry", async () => {
  for (const expired of [false, true]) {
    const home = mkdtempSync(path.join(os.tmpdir(), `mscqr-stale-zero-prefix-${expired ? "expired" : "fresh"}-`));
    try {
      const fixture = await staleSupersessionCliFixture(home);
      const fresh = new Date(new Date(fixture.authorization.approvedAt).getTime() + 1000);
      await assert.rejects(() => runStaleSupersessionCli(fixture.argv, { ...fixture.deps, now: fresh, afterExecutionStart: () => { throw new Error("injected crash before write one"); } }), /injected crash before write one/);
      assert.ok(lstatSync(path.join(fixture.directory, "execution-start.json")));
      assert.equal(fixture.sender.writes, 0);
      const retryNow = expired ? new Date(new Date(fixture.preparation.expiresAt).getTime() + 1000) : fresh;
      if (expired) {
        await assert.rejects(() => runStaleSupersessionCli(fixture.argv, { ...fixture.deps, now: retryNow }), /expired|prefix/i);
        assert.equal(fixture.sender.writes, 0);
      } else {
        const resumed = await runStaleSupersessionCli(fixture.argv, { ...fixture.deps, now: retryNow });
        assert.equal(resumed.writes, 7);
        assert.equal(fixture.sender.writes, 7);
      }
    } finally { rmSync(home, { recursive: true, force: true }); }
  }
});

test("expired stale supersession cannot begin, cannot fake a prefix, and can terminalize an authenticated all-new transition", async () => {
  const zeroHome = mkdtempSync(path.join(os.tmpdir(), "mscqr-stale-expired-zero-"));
  const terminalHome = mkdtempSync(path.join(os.tmpdir(), "mscqr-stale-expired-terminal-"));
  try {
    const zero = await staleSupersessionCliFixture(zeroHome);
    const expired = new Date(new Date(zero.preparation.expiresAt).getTime() + 1000);
    await assert.rejects(() => runStaleSupersessionCli(zero.argv, { ...zero.deps, now: expired }), /expired/);
    assert.equal(zero.sender.writes, 0);

    const forgedPrefix = await staleSupersessionCliFixture(mkdtempSync(path.join(os.tmpdir(), "mscqr-stale-expired-forged-prefix-")));
    const fresh = new Date(new Date(forgedPrefix.authorization.approvedAt).getTime() + 1000);
    let writes = 0;
    await assert.rejects(() => runStaleSupersessionCli(forgedPrefix.argv, { ...forgedPrefix.deps, now: fresh, client: { assertCredentialIdentity: forgedPrefix.client.assertCredentialIdentity, send: async (command) => {
      const response = await forgedPrefix.sender.send(command);
      if (command.constructor.name === "PutSecretValueCommand" && ++writes === 2) throw new Error("injected prefix");
      return response;
    } } }), /injected prefix/);
    rmSync(path.join(forgedPrefix.directory, "execution-start.json"));
    await assert.rejects(() => runStaleSupersessionCli(forgedPrefix.argv, { ...forgedPrefix.deps, now: new Date(new Date(forgedPrefix.preparation.expiresAt).getTime() + 1000) }), /missing its authenticated execution start/);
    assert.equal(forgedPrefix.sender.writes, 2);
    rmSync(path.dirname(forgedPrefix.directory), { recursive: true, force: true });

    const terminal = await staleSupersessionCliFixture(terminalHome);
    const terminalFresh = new Date(new Date(terminal.authorization.approvedAt).getTime() + 1000);
    await assert.rejects(() => runStaleSupersessionCli(terminal.argv, { ...terminal.deps, now: terminalFresh, afterBootstrap: () => { throw new Error("injected post-seven crash"); } }), /injected post-seven crash/);
    const complete = await runStaleSupersessionCli(terminal.argv, { ...terminal.deps, now: new Date(new Date(terminal.preparation.expiresAt).getTime() + 1000) });
    assert.equal(complete.writes, 0);
    assert.equal(terminal.sender.writes, 7);
  } finally { rmSync(zeroHome, { recursive: true, force: true }); rmSync(terminalHome, { recursive: true, force: true }); }
});

test("replacement-ID reservation survives preparation crashes without regenerating material", async () => {
  const home = mkdtempSync(path.join(os.tmpdir(), "mscqr-stale-preparation-resume-"));
  try {
    const fixture = staleSupersessionPrepareCliFixture(home);
    await assert.rejects(() => runStaleSupersessionCli(fixture.argv, { ...fixture.deps, now: new Date("2026-09-09T00:00:00.000Z"), afterPrepareDiscovery: () => { throw new Error("injected crash after journal"); } }), /injected crash after journal/);
    const reservation = JSON.parse(readFileSync(path.join(fixture.directory, "replacement-id-reservation.json")));
    const journal = path.join(fixture.directory, "supersession.json.material");
    const materialSha = digest(readFileSync(journal));
    const retry = await runStaleSupersessionCli(fixture.argv, { ...fixture.deps, now: new Date("2026-09-09T00:01:00.000Z") });
    assert.equal(retry.rotationId, reservation.replacementRotationId);
    assert.equal(digest(readFileSync(journal)), materialSha);
    assert.equal(fixture.sender.writes, 0);
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("prepare reuses fresh preparation bytes and refreshes an expired zero-write preparation without regenerating material", async () => {
  const home = mkdtempSync(path.join(os.tmpdir(), "mscqr-stale-preparation-refresh-"));
  try {
    const fixture = staleSupersessionPrepareCliFixture(home);
    const preparedAt = new Date("2026-09-09T00:00:00.000Z");
    const first = await runStaleSupersessionCli(fixture.argv, { ...fixture.deps, now: preparedAt });
    const preparationFile = path.join(fixture.directory, "preparation.json");
    const originalBytes = readFileSync(preparationFile);
    const originalPreparation = JSON.parse(originalBytes);
    const oldAuthorization = createApprovedStaleRotationSupersessionAuthorization({ pendingAuthorization: createPendingStaleRotationSupersessionAuthorization(originalPreparation), preparation: originalPreparation, protectedEnvironmentApprovalEvidence: supersessionApproval({ observedAt: preparedAt.toISOString() }) });
    const reservation = JSON.parse(readFileSync(path.join(fixture.directory, "replacement-id-reservation.json")));
    const journal = path.join(fixture.directory, "supersession.json.material");
    const materialSha = digest(readFileSync(journal));
    const reused = await runStaleSupersessionCli(fixture.argv, { ...fixture.deps, now: new Date(preparedAt.getTime() + 1000) });
    assert.equal(reused.preparationReused, true);
    assert.equal(reused.preparationSha256, first.preparationSha256);
    assert.deepEqual(readFileSync(preparationFile), originalBytes);
    assert.equal(digest(readFileSync(journal)), materialSha);

    const refreshed = await runStaleSupersessionCli(fixture.argv, { ...fixture.deps, now: new Date(preparedAt.getTime() + 30 * 60 * 1000 + 1000) });
    assert.equal(refreshed.preparationRefreshed, true);
    assert.equal(refreshed.rotationId, reservation.replacementRotationId);
    assert.notEqual(refreshed.preparationSha256, first.preparationSha256);
    assert.equal(digest(readFileSync(journal)), materialSha);
    assert.ok(lstatSync(`${preparationFile}.${digest(originalBytes)}.expired.json`));
    const refreshedPreparation = JSON.parse(readFileSync(preparationFile));
    assert.throws(() => assertApprovedStaleRotationSupersessionAuthorization(oldAuthorization, refreshedPreparation, { sourceSha, materialJournalFileSha256: refreshedPreparation.materialJournalFileSha256, now: new Date("2026-09-09T00:31:00.000Z") }), /hash or write plan|different prepared transaction/i);
    assert.equal(fixture.sender.writes, 0);
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("expired zero-write preparation refresh adopts an authenticated current Stage-B topology", async () => {
  const home = mkdtempSync(path.join(os.tmpdir(), "mscqr-stale-preparation-topology-refresh-"));
  try {
    const fixture = staleSupersessionPrepareCliFixture(home);
    const preparedAt = new Date("2026-09-09T00:00:00.000Z");
    const first = await runStaleSupersessionCli(fixture.argv, { ...fixture.deps, now: preparedAt });
    const nextState = { ...fixture.inputs.stageBState, serial: fixture.inputs.stageBState.serial + 1, stateSha256: "a".repeat(64) };
    writeFileSync(fixture.inputs.files.stageBState, `${JSON.stringify(nextState)}\n`, { mode: 0o600 });
    const refreshed = await runStaleSupersessionCli(fixture.argv, { ...fixture.deps, now: new Date("2026-09-09T00:31:00.000Z") });
    assert.equal(refreshed.preparationRefreshed, true);
    assert.notEqual(refreshed.preparationSha256, first.preparationSha256);
    assert.equal(JSON.parse(readFileSync(path.join(fixture.directory, "preparation.json"))).stageBState.serial, nextState.serial);
    assert.equal(fixture.sender.writes, 0);
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("expired zero-write preparation refresh adopts an authenticated current live backend", async () => {
  const home = mkdtempSync(path.join(os.tmpdir(), "mscqr-stale-preparation-live-refresh-"));
  try {
    const fixture = staleSupersessionPrepareCliFixture(home);
    await runStaleSupersessionCli(fixture.argv, { ...fixture.deps, now: new Date("2026-09-09T00:00:00.000Z") });
    const nextBackend = { taskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:53", imageDigest: `sha256:${"a".repeat(64)}` };
    Object.assign(fixture.inputs.liveBackend, nextBackend, { identitySha256: staleRotationSupersessionSha256(nextBackend) });
    writeFileSync(fixture.inputs.files.liveBackend, `${JSON.stringify(fixture.inputs.liveBackend)}\n`, { mode: 0o600 });
    const refreshed = await runStaleSupersessionCli(fixture.argv, { ...fixture.deps, now: new Date("2026-09-09T00:31:00.000Z") });
    assert.equal(refreshed.preparationRefreshed, true);
    assert.equal(JSON.parse(readFileSync(path.join(fixture.directory, "preparation.json"))).liveBackend.taskDefinitionArn, fixture.inputs.liveBackend.taskDefinitionArn);
    assert.equal(fixture.sender.writes, 0);
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("expired preparation refresh rejects transaction-fixed predecessor or publication changes", async () => {
  for (const changed of ["predecessor", "publication"]) {
    const home = mkdtempSync(path.join(os.tmpdir(), `mscqr-stale-refresh-fixed-${changed}-`));
    try {
      const fixture = staleSupersessionPrepareCliFixture(home);
      const preparedAt = new Date("2026-09-09T00:00:00.000Z");
      await runStaleSupersessionCli(fixture.argv, { ...fixture.deps, now: preparedAt });
      if (changed === "predecessor") {
        const record = fixture.store.get(currentNames.jwt);
        record.value.value = "different-current-material";
        record.value.materialFingerprint = digest(record.value.value).slice(0, 16);
        record.versionId = "different-current-version";
      } else {
        writeFileSync(fixture.inputs.files.publication, `${JSON.stringify({ ...fixture.inputs.publication, identitySha256: "a".repeat(64) })}\n`, { mode: 0o600 });
      }
      await assert.rejects(() => runStaleSupersessionCli(fixture.argv, { ...fixture.deps, now: new Date("2026-09-09T00:31:00.000Z") }), /non-refreshable|another transaction/i);
      assert.equal(fixture.sender.writes, 0);
    } finally { rmSync(home, { recursive: true, force: true }); }
  }
});

test("expired zero-write preparation archives its old start and requires a new authorization epoch", async () => {
  const home = mkdtempSync(path.join(os.tmpdir(), "mscqr-stale-preparation-abandon-"));
  try {
    const fixture = staleSupersessionPrepareCliFixture(home);
    const preparedAt = new Date("2026-09-09T00:00:00.000Z");
    const first = await runStaleSupersessionCli(fixture.argv, { ...fixture.deps, now: preparedAt });
    const preparation = JSON.parse(readFileSync(path.join(fixture.directory, "preparation.json")));
    const authorization = createApprovedStaleRotationSupersessionAuthorization({ pendingAuthorization: createPendingStaleRotationSupersessionAuthorization(preparation), preparation, protectedEnvironmentApprovalEvidence: supersessionApproval({ observedAt: preparedAt.toISOString() }) });
    const provenance = authorizationProvenance(authorization);
    const start = createStaleRotationSupersessionExecutionStart({ authorization, authorizationProvenance: provenance, preparation, startedAt: new Date(preparedAt.getTime() + 1000).toISOString() });
    writeFileSync(path.join(fixture.directory, "execution-start.json"), `${JSON.stringify(start, null, 2)}\n`, { mode: 0o600 });
    const refreshed = await runStaleSupersessionCli(fixture.argv, { ...fixture.deps, now: new Date(preparedAt.getTime() + 30 * 60 * 1000 + 1000) });
    assert.equal(refreshed.preparationRefreshed, true);
    assert.notEqual(refreshed.preparationSha256, first.preparationSha256);
    assert.equal(lstatSync(path.join(fixture.directory, "execution-start.json"), { throwIfNoEntry: false }), undefined);
    assert.ok(lstatSync(path.join(fixture.directory, `execution-start.json.${digest(Buffer.from(`${JSON.stringify(start, null, 2)}\n`))}.abandoned.json`)));
    assert.equal(fixture.sender.writes, 0);
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("prepare never overwrites a corrupt artifact or refreshes after an authenticated write prefix", async () => {
  const corruptHome = mkdtempSync(path.join(os.tmpdir(), "mscqr-stale-preparation-corrupt-"));
  const prefixHome = mkdtempSync(path.join(os.tmpdir(), "mscqr-stale-preparation-prefix-"));
  try {
    const corrupt = staleSupersessionPrepareCliFixture(corruptHome);
    const preparedAt = new Date("2026-09-09T00:00:00.000Z");
    await runStaleSupersessionCli(corrupt.argv, { ...corrupt.deps, now: preparedAt });
    const corruptPreparation = path.join(corrupt.directory, "preparation.json");
    writeFileSync(corruptPreparation, "{}\n", { mode: 0o600 });
    await assert.rejects(() => runStaleSupersessionCli(corrupt.argv, { ...corrupt.deps, now: new Date(preparedAt.getTime() + 1000) }), /schema|identity/i);
    assert.equal(readFileSync(corruptPreparation, "utf8"), "{}\n");

    const prefix = staleSupersessionPrepareCliFixture(prefixHome);
    const first = await runStaleSupersessionCli(prefix.argv, { ...prefix.deps, now: preparedAt });
    let writes = 0;
    const prefixSender = { send: async (command) => {
      const response = await prefix.sender.send(command);
      if (command.constructor.name === "PutSecretValueCommand" && ++writes === 1) throw new Error("injected prefix write");
      return response;
    } };
    await assert.rejects(() => supersedeStalePendingRotation({ send: prefixSender.send, ...supersessionArgs({ mode: "execute", rotationId: first.rotationId, authorizeWritePlan: () => true }), outputFile: path.join(prefix.directory, "supersession.json"), repositoryRoot: process.cwd() }), /injected prefix write/);
    await assert.rejects(() => runStaleSupersessionCli(prefix.argv, { ...prefix.deps, now: new Date(preparedAt.getTime() + 30 * 60 * 1000 + 1000) }), /cannot refresh after mutation/i);
    assert.equal(prefix.sender.writes, 1);
  } finally { rmSync(corruptHome, { recursive: true, force: true }); rmSync(prefixHome, { recursive: true, force: true }); }
});

test("stale supersession routes reads and writes through the sanitized runner without exposing payload argv", async () => {
  const calls = [];
  const send = createStaleRotationSecretsManagerSender((args, options = {}) => {
    calls.push({ args, options });
    return JSON.stringify({ VersionId: "a".repeat(64) });
  });
  const { PutSecretValueCommand } = requireBackend("@aws-sdk/client-secrets-manager");
  await send(new PutSecretValueCommand({ SecretId: arn("mscqr/prod/rotation/jwt_pending"), ClientRequestToken: "a".repeat(64), SecretString: '{"value":"synthetic"}' }));
  assert.equal(calls.length, 1);
  assert.equal(calls[0].args.includes('{"value":"synthetic"}'), false);
  assert.equal(calls[0].args.includes("file:///dev/stdin"), true);
  assert.equal(calls[0].options.input, '{"value":"synthetic"}');
  const source = readFileSync("scripts/aws/supersede-production-stale-rotation.mjs", "utf8");
  assert.match(source, /createProductionCommandRunner/);
  assert.doesNotMatch(source, /createInitialDualSlotSecretsManagerClient/);
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
  finalizeStaleRotationSupersessionMaterialJournal({ outputFile: path.join(directory, "supersession.json"), expectedFileSha256: digest(readFileSync(path.join(directory, "supersession.json.material"))), repositoryRoot: "/private/tmp/mscqr-post330-exec" });
  await new Promise((resolve) => setTimeout(resolve, 5));
  await assert.rejects(() => supersedeStalePendingRotation({ send: sender.send, ...supersessionArgs(), outputFile: path.join(directory, "supersession.json"), repositoryRoot: "/private/tmp/mscqr-post330-exec" }), /already durably consumed/);
  assert.equal(JSON.parse(persistedEvidenceBytes).evidenceIdentitySha256, persistedEvidence.evidenceIdentitySha256);
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

test("completed production rebaseline payloads are exact stale supersession predecessors", async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-rebaseline-stale-schema-"));
  const store = completedProductionRebaselineStore();
  const sender = rotationSender(store);
  try {
    const result = await supersedeStalePendingRotation({
      send: sender.send,
      ...supersessionArgs({
        sourceSha: "a".repeat(40),
        staleSourceSha: PARTIAL_REBASELINE_RECOVERY_ORIGINAL_SOURCE_SHA,
        rotationId: "rotation-fresh-rebaseline-schema",
        staleRotationId: "rotation-20260829015311-765c8a16",
        proveDescendant: ({ ancestorSha, descendantSha }) => ancestorSha === PARTIAL_REBASELINE_RECOVERY_ORIGINAL_SOURCE_SHA && descendantSha === "a".repeat(40),
        outputFile: path.join(directory, "supersession.json"),
        repositoryRoot: "/private/tmp/mscqr-post330-exec",
      }),
    });
    assert.equal(result.writes, 7);
    assert.equal(sender.writes, 7);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("completed production rebaseline fixture preserves every historical slot schema", () => {
  const store = completedProductionRebaselineStore();
  const expected = {
    jwtPending: ["family", "materialFingerprint", "materialType", "rotationId", "slot", "sourceSha", "value"],
    qrPrivatePending: ["family", "keyVersion", "materialFingerprint", "materialType", "rotationId", "slot", "sourceSha", "value"],
    qrPublicPending: ["family", "keyVersion", "materialFingerprint", "materialType", "rotationId", "slot", "sourceSha", "value"],
    jwtPrevious: ["baselineMarker", "family", "initialMigration", "rotationId", "slot", "sourceSha", "value"],
    qrPublicPrevious: ["baselineMarker", "family", "initialMigration", "rotationId", "slot", "sourceSha", "value"],
    qrCurrentVersion: ["baselineMarker", "family", "initialMigration", "rotationId", "slot", "sourceSha", "value"],
    qrPreviousVersion: ["baselineMarker", "family", "initialMigration", "rotationId", "slot", "sourceSha", "value"],
  };
  for (const [slot, name] of Object.entries(INITIAL_DUAL_SLOT_NAMES)) {
    const value = store.get(name).value;
    assert.deepEqual(Object.keys(value).sort(), expected[slot], slot);
    assert.equal(value.sourceSha, PARTIAL_REBASELINE_RECOVERY_ORIGINAL_SOURCE_SHA, slot);
    assert.equal(value.rotationId, "rotation-20260829015311-765c8a16", slot);
  }
  assert.equal(store.get(INITIAL_DUAL_SLOT_NAMES.qrCurrentVersion).value.baselineMarker, "adopted-authenticated-legacy-active-identity");
  for (const slot of ["jwtPrevious", "qrPublicPrevious", "qrPreviousVersion"]) assert.equal(store.get(INITIAL_DUAL_SLOT_NAMES[slot]).value.baselineMarker, "empty-baseline-marker", slot);
  for (const slot of ["jwtPending", "qrPrivatePending", "qrPublicPending"]) assert.equal(store.get(INITIAL_DUAL_SLOT_NAMES[slot]).value.materialType, "fresh-generated", slot);
});

test("completed rebaseline payload schema rejects altered provenance before supersession writes", async () => {
  const mutations = [
    ["unknown extra field", (store) => { store.get(INITIAL_DUAL_SLOT_NAMES.jwtPending).value.unrecognized = true; }],
    ["missing marker", (store) => { delete store.get(INITIAL_DUAL_SLOT_NAMES.jwtPrevious).value.baselineMarker; }],
    ["forged marker", (store) => { store.get(INITIAL_DUAL_SLOT_NAMES.qrCurrentVersion).value.baselineMarker = "empty-baseline-marker"; }],
    ["wrong rotation", (store) => { store.get(INITIAL_DUAL_SLOT_NAMES.jwtPending).value.rotationId = "rotation-other-rebaseline"; }],
    ["missing rotation", (store) => { delete store.get(INITIAL_DUAL_SLOT_NAMES.jwtPrevious).value.rotationId; }],
    ["wrong source", (store) => { store.get(INITIAL_DUAL_SLOT_NAMES.jwtPending).value.sourceSha = "0".repeat(40); }],
    ["missing material type", (store) => { delete store.get(INITIAL_DUAL_SLOT_NAMES.jwtPending).value.materialType; }],
    ["wrong material type", (store) => { store.get(INITIAL_DUAL_SLOT_NAMES.jwtPending).value.materialType = "other"; }],
    ["cross-family material type", (store) => { store.get(INITIAL_DUAL_SLOT_NAMES.qrPrivatePending).value.materialType = "empty-baseline-marker"; }],
    ["wrong family", (store) => { store.get(INITIAL_DUAL_SLOT_NAMES.qrPublicPending).value.family = "jwt_secrets"; }],
    ["wrong slot", (store) => { store.get(INITIAL_DUAL_SLOT_NAMES.qrPublicPending).value.slot = "pending-private"; }],
    ["empty JWT material", (store) => { const value = store.get(INITIAL_DUAL_SLOT_NAMES.jwtPending).value; value.value = ""; value.materialFingerprint = digest("").slice(0, 16); }],
    ["wrong fingerprint", (store) => { store.get(INITIAL_DUAL_SLOT_NAMES.jwtPending).value.materialFingerprint = "0".repeat(16); }],
    ["wrong key version", (store) => { store.get(INITIAL_DUAL_SLOT_NAMES.qrPrivatePending).value.keyVersion = "0".repeat(16); }],
    ["public key in private slot", (store) => { const value = store.get(INITIAL_DUAL_SLOT_NAMES.qrPrivatePending).value; value.value = store.get(INITIAL_DUAL_SLOT_NAMES.qrPublicPending).value.value; value.materialFingerprint = digest(value.value).slice(0, 16); value.keyVersion = digest(value.value).slice(0, 16); }],
    ["private key in public slot", (store) => { const value = store.get(INITIAL_DUAL_SLOT_NAMES.qrPublicPending).value; value.value = store.get(INITIAL_DUAL_SLOT_NAMES.qrPrivatePending).value.value; value.materialFingerprint = digest(value.value).slice(0, 16); value.keyVersion = digest(store.get(INITIAL_DUAL_SLOT_NAMES.qrPublicPending).value.value).slice(0, 16); }],
    ["RSA private key", (store) => { const pair = generateKeyPairSync("rsa", { modulusLength: 2048, privateKeyEncoding: { format: "pem", type: "pkcs8" }, publicKeyEncoding: { format: "pem", type: "spki" } }); const value = store.get(INITIAL_DUAL_SLOT_NAMES.qrPrivatePending).value; value.value = pair.privateKey; value.materialFingerprint = digest(value.value).slice(0, 16); value.keyVersion = digest(pair.publicKey).slice(0, 16); }],
    ["RSA public key", (store) => { const pair = generateKeyPairSync("rsa", { modulusLength: 2048, privateKeyEncoding: { format: "pem", type: "pkcs8" }, publicKeyEncoding: { format: "pem", type: "spki" } }); const value = store.get(INITIAL_DUAL_SLOT_NAMES.qrPublicPending).value; value.value = pair.publicKey; value.materialFingerprint = digest(value.value).slice(0, 16); value.keyVersion = digest(value.value).slice(0, 16); }],
    ["empty private material", (store) => { const value = store.get(INITIAL_DUAL_SLOT_NAMES.qrPrivatePending).value; value.value = ""; value.materialFingerprint = digest("").slice(0, 16); value.keyVersion = digest("").slice(0, 16); }],
    ["empty public material", (store) => { const value = store.get(INITIAL_DUAL_SLOT_NAMES.qrPublicPending).value; value.value = ""; value.materialFingerprint = digest("").slice(0, 16); value.keyVersion = digest("").slice(0, 16); }],
    ["pending masquerades as marker", (store) => { const value = store.get(INITIAL_DUAL_SLOT_NAMES.jwtPending).value; delete value.materialType; value.baselineMarker = "empty-baseline-marker"; }],
    ["marker masquerades as pending", (store) => { const value = store.get(INITIAL_DUAL_SLOT_NAMES.jwtPrevious).value; value.materialType = "fresh-generated"; value.materialFingerprint = digest(value.value).slice(0, 16); }],
    ["hybrid payload", (store) => { store.get(INITIAL_DUAL_SLOT_NAMES.qrPublicPrevious).value.materialFingerprint = digest("").slice(0, 16); }],
    ["mixed historical and canonical schemas", (store) => { store.get(INITIAL_DUAL_SLOT_NAMES.jwtPrevious).value = rotationStore().get(INITIAL_DUAL_SLOT_NAMES.jwtPrevious).value; }],
    ["untrusted runtime marker", (store) => { store.get(INITIAL_DUAL_SLOT_NAMES.qrCurrentVersion).value.value = "2026-04-21"; }],
    ["substituted current jwt", (store) => { store.get(currentNames.jwt).value.value = "substituted-current-jwt"; }],
    ["substituted current qr", (store) => { store.get(currentNames.qrPublic).value.keyVersion = "0".repeat(16); }],
    ["extra historical-looking metadata", (store) => { store.get(INITIAL_DUAL_SLOT_NAMES.qrPreviousVersion).value.historicalMarker = "forged"; }],
  ];
  for (const [label, mutate] of mutations) {
    const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-rebaseline-stale-reject-"));
    const store = completedProductionRebaselineStore();
    const sender = rotationSender(store);
    mutate(store);
    try {
      await assert.rejects(() => supersedeStalePendingRotation({
        send: sender.send,
        ...supersessionArgs({
          sourceSha: "a".repeat(40),
          staleSourceSha: PARTIAL_REBASELINE_RECOVERY_ORIGINAL_SOURCE_SHA,
          rotationId: "rotation-fresh-rebaseline-schema",
          staleRotationId: "rotation-20260829015311-765c8a16",
          proveDescendant: ({ ancestorSha, descendantSha }) => ancestorSha === PARTIAL_REBASELINE_RECOVERY_ORIGINAL_SOURCE_SHA && descendantSha === "a".repeat(40),
          outputFile: path.join(directory, "supersession.json"),
          repositoryRoot: "/private/tmp/mscqr-post330-exec",
        }),
      }), undefined, label);
      assert.equal(sender.writes, 0, label);
    } finally { rmSync(directory, { recursive: true, force: true }); }
  }
});

test("completed rebaseline supersession resumes each deterministic prefix from seven logical predecessors", async () => {
  for (let prefix = 0; prefix <= 7; prefix += 1) {
    const directory = mkdtempSync(path.join(os.tmpdir(), `mscqr-rebaseline-prefix-${prefix}-`));
    const store = completedProductionRebaselineStore();
    const args = completedRebaselineSupersessionArgs(directory);
    try {
      if (prefix) {
        const first = rotationSender(store, { failAt: prefix });
        await assert.rejects(() => supersedeStalePendingRotation({ send: first.send, ...args }), /injected PutSecretValue failure/);
      }
      const expectedPredecessors = Object.fromEntries(Object.entries(INITIAL_DUAL_SLOT_NAMES).map(([slot, name]) => [slot, store.get(name).previous?.versionId || store.get(name).versionId]));
      const retry = rotationSender(store);
      const result = await supersedeStalePendingRotation({ send: retry.send, ...args });
      assert.equal(retry.writes, 7 - prefix, `prefix ${prefix}`);
      assert.equal(result.writes, 7 - prefix, `prefix ${prefix}`);
      assert.equal(Object.keys(result.evidence.predecessorSlotIdentities).length, 7, `prefix ${prefix}`);
      for (const [slot, identity] of Object.entries(result.evidence.predecessorSlotIdentities)) assert.equal(identity.versionId, expectedPredecessors[slot], `${prefix}:${slot}`);
      await assertCompletedRebaselineRetryContinuation({ store, sender: retry, result, directory, suffix: `prefix-${prefix}` });
    } finally { rmSync(directory, { recursive: true, force: true }); }
  }
});

test("completed rebaseline all-new replay reauthenticates every AWSPREVIOUS predecessor", async () => {
  const mutations = [
    ["previous version", (store) => { store.get(INITIAL_DUAL_SLOT_NAMES.jwtPending).previous.versionId = "substituted-previous"; }],
    ["baseline marker", (store) => { store.get(INITIAL_DUAL_SLOT_NAMES.qrCurrentVersion).previous.value.baselineMarker = "empty-baseline-marker"; }],
    ["missing baseline marker", (store) => { delete store.get(INITIAL_DUAL_SLOT_NAMES.qrCurrentVersion).previous.value.baselineMarker; }],
    ["missing material type", (store) => { delete store.get(INITIAL_DUAL_SLOT_NAMES.jwtPending).previous.value.materialType; }],
    ["wrong source", (store) => { store.get(INITIAL_DUAL_SLOT_NAMES.qrPrivatePending).previous.value.sourceSha = "0".repeat(40); }],
    ["wrong rotation", (store) => { store.get(INITIAL_DUAL_SLOT_NAMES.qrPublicPending).previous.value.rotationId = "rotation-other"; }],
    ["wrong family", (store) => { store.get(INITIAL_DUAL_SLOT_NAMES.jwtPending).previous.value.family = "qr_signing_keys"; }],
    ["wrong slot", (store) => { store.get(INITIAL_DUAL_SLOT_NAMES.jwtPending).previous.value.slot = "pending-private"; }],
    ["empty JWT material", (store) => { const value = store.get(INITIAL_DUAL_SLOT_NAMES.jwtPending).previous.value; value.value = ""; value.materialFingerprint = digest("").slice(0, 16); }],
    ["wrong fingerprint", (store) => { store.get(INITIAL_DUAL_SLOT_NAMES.jwtPending).previous.value.materialFingerprint = "0".repeat(16); }],
    ["wrong key version", (store) => { store.get(INITIAL_DUAL_SLOT_NAMES.qrPrivatePending).previous.value.keyVersion = "0".repeat(16); }],
    ["unknown field", (store) => { store.get(INITIAL_DUAL_SLOT_NAMES.jwtPending).previous.value.unexpected = true; }],
  ];
  for (const [label, mutate] of mutations) {
    const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-rebaseline-all-new-reject-"));
    const store = completedProductionRebaselineStore();
    const first = rotationSender(store, { failAt: 7 });
    const args = completedRebaselineSupersessionArgs(directory);
    try {
      await assert.rejects(() => supersedeStalePendingRotation({ send: first.send, ...args }), /injected PutSecretValue failure/);
      mutate(store);
      const retry = rotationSender(store);
      await assert.rejects(() => supersedeStalePendingRotation({ send: retry.send, ...args }), undefined, label);
      assert.equal(retry.writes, 0, label);
    } finally { rmSync(directory, { recursive: true, force: true }); }
  }
});

test("completed rebaseline supersession rejects non-prefix replacement topology before another write", async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-rebaseline-non-prefix-"));
  const store = completedProductionRebaselineStore();
  const first = rotationSender(store, { failAt: 4 });
  const args = completedRebaselineSupersessionArgs(directory);
  try {
    await assert.rejects(() => supersedeStalePendingRotation({ send: first.send, ...args }), /injected PutSecretValue failure/);
    store.set(INITIAL_DUAL_SLOT_NAMES.qrPrivatePending, store.get(INITIAL_DUAL_SLOT_NAMES.qrPrivatePending).previous);
    const retry = rotationSender(store);
    await assert.rejects(() => supersedeStalePendingRotation({ send: retry.send, ...args }), /resumable transition prefix/);
    assert.equal(retry.writes, 0);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("completed rebaseline partial replay rejects a substituted deterministic replacement before another write", async () => {
  const mutations = [
    ["payload", (record) => { record.value.value = "substituted-replacement"; record.value.materialFingerprint = digest(record.value.value).slice(0, 16); }],
    ["source", (record) => { record.value.sourceSha = "0".repeat(40); }],
  ];
  for (const [label, mutate] of mutations) {
    const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-rebaseline-prefix-new-reject-"));
    const store = completedProductionRebaselineStore();
    const first = rotationSender(store, { failAt: 1 });
    const args = completedRebaselineSupersessionArgs(directory);
    try {
      await assert.rejects(() => supersedeStalePendingRotation({ send: first.send, ...args }), /injected PutSecretValue failure/);
      mutate(store.get(INITIAL_DUAL_SLOT_NAMES.jwtPending));
      const retry = rotationSender(store);
      await assert.rejects(() => supersedeStalePendingRotation({ send: retry.send, ...args }), undefined, label);
      assert.equal(retry.writes, 0, label);
    } finally { rmSync(directory, { recursive: true, force: true }); }
  }
});

test("completed rebaseline all-new replay rejects an unrelated AWSPREVIOUS predecessor before mutation", async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-rebaseline-all-new-previous-topology-"));
  const store = completedProductionRebaselineStore();
  const first = rotationSender(store, { failAt: 7 });
  const args = completedRebaselineSupersessionArgs(directory);
  try {
    await assert.rejects(() => supersedeStalePendingRotation({ send: first.send, ...args }), /injected PutSecretValue failure/);
    const retry = rotationSender(store, { onDescribe: ({ response, key }) => {
      if (key !== INITIAL_DUAL_SLOT_NAMES.jwtPending) return undefined;
      const currentVersionId = Object.entries(response.VersionIdsToStages).find(([, stages]) => stages.includes("AWSCURRENT"))[0];
      return { ...response, VersionIdsToStages: { [currentVersionId]: ["AWSCURRENT"], "unrelated-previous": ["AWSPREVIOUS"] } };
    } });
    await assert.rejects(() => supersedeStalePendingRotation({ send: retry.send, ...args }), undefined);
    assert.equal(retry.writes, 0);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("completed rebaseline all-new replay rejects a missing AWSPREVIOUS predecessor before mutation", async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-rebaseline-all-new-missing-previous-"));
  const store = completedProductionRebaselineStore();
  const first = rotationSender(store, { failAt: 7 });
  const args = completedRebaselineSupersessionArgs(directory);
  try {
    await assert.rejects(() => supersedeStalePendingRotation({ send: first.send, ...args }), /injected PutSecretValue failure/);
    const retry = rotationSender(store, { onDescribe: ({ response, key }) => {
      if (key !== INITIAL_DUAL_SLOT_NAMES.jwtPending) return undefined;
      const currentVersionId = Object.entries(response.VersionIdsToStages).find(([, stages]) => stages.includes("AWSCURRENT"))[0];
      return { ...response, VersionIdsToStages: { [currentVersionId]: ["AWSCURRENT"] } };
    } });
    await assert.rejects(() => supersedeStalePendingRotation({ send: retry.send, ...args }), undefined);
    assert.equal(retry.writes, 0);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("completed rebaseline all-new pre-evidence replay requires its authenticated replacement journal", async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-rebaseline-all-new-journal-"));
  const store = completedProductionRebaselineStore();
  const first = rotationSender(store, { failAt: 7 });
  const args = completedRebaselineSupersessionArgs(directory);
  try {
    await assert.rejects(() => supersedeStalePendingRotation({ send: first.send, ...args }), /injected PutSecretValue failure/);
    rmSync(`${args.outputFile}.material`);
    const retry = rotationSender(store);
    await assert.rejects(() => supersedeStalePendingRotation({ send: retry.send, ...args }), /authenticated replacement material journal/);
    assert.equal(retry.writes, 0);
  } finally { rmSync(directory, { recursive: true, force: true }); }
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
    assert.notEqual(lstatSync(`${outputFile}.material`, { throwIfNoEntry: false }), undefined);
    finalizeStaleRotationSupersessionMaterialJournal({ outputFile, expectedFileSha256: digest(readFileSync(`${outputFile}.material`)), repositoryRoot: "/private/tmp/mscqr-post330-exec" });
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
  const store = completedProductionRebaselineStore();
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
      mode: "execute",
      authorizeWritePlan: () => true,
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
    await assert.rejects(() => supersedeStalePendingRotation({ send: sender.send, taskDefinition: staleTaskDefinition, sourceSha: protectedSource, staleSourceSha: productionOldSource, rotationId: freshRotationId, staleRotationId: productionOldRotationId, proveDescendant: () => true, outputFile: path.join(directory, "replay.json"), repositoryRoot: "/private/tmp/mscqr-post330-exec", mode: "execute", authorizeWritePlan: () => true }), /lineage|invalid|unknown/);
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
