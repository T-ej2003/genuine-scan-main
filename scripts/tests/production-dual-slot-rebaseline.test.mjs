import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  PRODUCTION_DUAL_SLOT_REBASELINE, REBASELINE_SLOT_ORDER, BASELINE_COMPLETE,
  buildAbandonmentEvidence, buildRebaselineIdentity, buildRebaselinePayloads, buildRebaselineWritePlan,
  buildRebaselinePreparation, assertRebaselinePreconditions, assertRebaselinePreparation,
  createProductionDualSlotRebaselineAuthorization, deterministicWriteIdentity, executeProductionDualSlotRebaseline,
  generateRebaselineMaterial, assertBaselineCompletion, canonicalSha256, historicalSlotIdentity,
  REBASELINE_HISTORICAL_SOURCE_SHAS, REBASELINE_SLOTS, assertRebaselineRotationBindings, assertProductionDualSlotRebaselineAuthorization, resolveProductionDualSlotRebaselineAuthorizationArtifact, readBoundBaselineCompletion, sha256,
} from "../aws/production-dual-slot-rebaseline-contract.mjs";
import { auditLiveProductionDualSlotReferences, readAuthenticatedRebaselineCheckout } from "../aws/rebaseline-production-dual-slot.mjs";
import { createProductionEnvironmentApprovalEvidence, PRODUCTION_ENVIRONMENT_APPROVAL } from "../aws/production-github-environment-approval.mjs";
import { assertBindings } from "../aws/production-cutover-runtime-bootstrap.mjs";

const sourceSha = "a".repeat(40);
const historicalRotationId = "rotation-20260826060632-b15b3f51";
const rotationId = "rotation-20260828000000-rebase";
const resources = Object.fromEntries(REBASELINE_SLOT_ORDER.map((slot, index) => [slot, `arn:aws:secretsmanager:eu-west-2:${PRODUCTION_DUAL_SLOT_REBASELINE.accountId}:secret:fixture/${REBASELINE_SLOTS[slot]}-${index}`]));
const currentVersionIds = Object.fromEntries(REBASELINE_SLOT_ORDER.map((slot) => [slot, sha256(`fixture-version:${slot}`)]));
const historicalTopologySha256 = canonicalSha256({ resources, versionIds: currentVersionIds });
const legacyBaseline = { jwtCurrent: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:legacy-jwt", qrPrivateCurrent: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:legacy-qr-private", qrPublicCurrent: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:legacy-qr-public", qrCurrentVersion: "legacy-v1" };
const shapes = { jwtPending: ["jwt_secrets", "pending"], qrPrivatePending: ["qr_signing_keys", "pending-private"], qrPublicPending: ["qr_signing_keys", "pending-public"], jwtPrevious: ["jwt_secrets", "empty"], qrPublicPrevious: ["qr_signing_keys", "empty"], qrCurrentVersion: ["qr_key_versions", "current"], qrPreviousVersion: ["qr_key_versions", "previous-empty"] };
function historicalPayload(slot, { source = REBASELINE_HISTORICAL_SOURCE_SHAS[0], rotation = historicalRotationId, value = `historical-${slot}` } = {}) { const [family, payloadSlot] = shapes[slot]; return { value, family, slot: payloadSlot, initialMigration: true, ...(rotation === undefined ? {} : { rotationId: rotation }), ...(source === undefined ? {} : { sourceSha: source }) }; }
const observedSlotIdentities = Object.fromEntries(REBASELINE_SLOT_ORDER.map((slot) => [slot, historicalSlotIdentity({ slot, secretArn: resources[slot], versionId: currentVersionIds[slot], stages: ["AWSCURRENT"], payload: historicalPayload(slot, { source: slot === "qrPublicPending" ? REBASELINE_HISTORICAL_SOURCE_SHAS[1] : slot === "qrPreviousVersion" ? undefined : undefined }) })]));
const audit = Object.freeze({ dualSlotReferences: 0, legacyRuntimeAuthoritative: true, auditSha256: canonicalSha256({ audit: "fixture", resources }) });
const abandoned = buildAbandonmentEvidence({ sourceSha, historicalRotationId, historicalSourceShas: REBASELINE_HISTORICAL_SOURCE_SHAS, resources, currentVersionIds, historicalTopologySha256, observedSlotIdentities, liveReferenceAudit: "PASS", liveReferenceAuditSha256: audit.auditSha256, legacyRuntimeAuthoritative: true, observedAt: "2026-08-28T10:00:00.000Z" });
const preconditions = { environment: "production", accountId: PRODUCTION_DUAL_SLOT_REBASELINE.accountId, region: PRODUCTION_DUAL_SLOT_REBASELINE.region, sourceSha, sourceCas: true, cleanWorktree: true, existingSecretResources: true, liveReferenceAudit: "PASS", liveReferenceAuditSha256: audit.auditSha256, legacyRuntimeAuthoritative: true, databaseDependencies: 0, externalConsumers: 0, dualSlotReferences: 0, runningTasks: 2, pendingTasks: 0, activeTaskDefinition: "mscqr-backend:50", resources, historicalTopologySha256, abandonmentEvidence: abandoned };
const material = generateRebaselineMaterial();
const identity = buildRebaselineIdentity({ sourceSha, rotationId, resources, abandonmentEvidenceSha256: abandoned.evidenceSha256, legacyBaseline });
const payloads = buildRebaselinePayloads({ sourceSha, rotationId, generatedMaterial: material, legacyBaseline });
const writePlan = buildRebaselineWritePlan({ sourceSha, rotationId, resources, baselineIdentitySha256: identity.identitySha256, payloads });
const temporary = () => { const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-rebaseline-test-")); chmodSync(directory, 0o700); return { directory, completionFile: path.join(directory, "completion.json"), bindingsFile: path.join(directory, "rotation-bindings.json") }; };

function environmentEvidence() { return createProductionEnvironmentApprovalEvidence({ environmentConfig: { name: "production", id: 17, can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: false, reviewers: [{ type: "User", reviewer: { id: 7, login: "checker" } }] }] }, repository: PRODUCTION_DUAL_SLOT_REBASELINE.repository, environment: "production", sourceSha, workflowRef: PRODUCTION_ENVIRONMENT_APPROVAL.dualSlotRebaselineWorkflowRef, eventName: "workflow_dispatch", workflowRunId: "123456", workflowRunAttempt: "1", executionActor: "checker", observedAt: "2026-08-28T10:01:00.000Z" }); }
function authorization() { return createProductionDualSlotRebaselineAuthorization({ protectedEnvironmentApprovalEvidence: environmentEvidence(), sourceSha, historicalRotationId, rotationId, abandonmentEvidenceSha256: abandoned.evidenceSha256, baselineIdentitySha256: identity.identitySha256, resources, writeIdentities: Object.fromEntries(writePlan.map(({ slot, clientRequestToken }) => [slot, clientRequestToken])), expectedSecretValueWrites: 7, expectedSecretDeletes: 0, liveReferenceAudit: "PASS", liveReferenceAuditSha256: audit.auditSha256, observedSlotIdentitiesSha256: abandoned.observedSlotIdentitiesSha256, reason: "Abandon pre-cutover state and establish a clean baseline", approvedBy: "checker", approverRole: "production-independent-checker", verificationRef: "ticket-rebaseline-1" }); }
function executionAdapters({ failAt = -1, liveReferenceAudit = audit } = {}) {
  const store = new Map(REBASELINE_SLOT_ORDER.map((slot) => [slot, [{
    versionId: currentVersionIds[slot], stages: ["AWSCURRENT"],
    payloadSha256: historicalSlotIdentity({ slot, secretArn: resources[slot], versionId: currentVersionIds[slot], stages: ["AWSCURRENT"], payload: historicalPayload(slot) }).payloadSha256,
  }]]));
  let calls = 0;
  return {
    store,
    readReferenceAudit: async () => liveReferenceAudit,
    readSlot: async (slot, secretArn) => ({ arn: secretArn, versions: store.get(slot) }),
    writeSlot: async ({ slot, secretArn, clientRequestToken, payload, payloadSha256 }) => {
      const entry = { versionId: clientRequestToken, stages: ["AWSCURRENT"], payloadSha256: payloadSha256 || canonicalSha256(payload) };
      store.set(slot, store.get(slot).map((version) => ({ ...version, stages: version.stages.includes("AWSCURRENT") ? ["AWSPREVIOUS"] : version.stages })).concat(entry));
      calls += 1;
      if (calls === failAt) throw new Error("injected interruption after remote write");
      return { arn: secretArn, versionId: clientRequestToken };
    },
  };
}
function execute(adapters, outputs, extra = {}) { return executeProductionDualSlotRebaseline({ preconditions, sourceSha, rotationId, baselineIdentity: identity, writePlan, authorization: authorization(), completionFile: outputs.completionFile, bindingsFile: outputs.bindingsFile, repositoryRoot: process.cwd(), ...adapters, ...extra }); }

test("observed abandonment identities bind exact payloads without plaintext", () => {
  const preparation = buildRebaselinePreparation({ preconditions, sourceSha, rotationId, baselineIdentity: identity, writePlan });
  assert.equal(preparation.writePlan.length, 7); assertRebaselinePreparation(preparation, { sourceSha, rotationId }); assert.equal(JSON.stringify(abandoned).includes(material.jwt), false);
  assert.throws(() => historicalSlotIdentity({ slot: "jwtPending", secretArn: resources.jwtPending, versionId: currentVersionIds.jwtPending, stages: ["AWSCURRENT"], payload: historicalPayload("jwtPending", { rotation: "rotation-wrong" }) }), /provenance/);
  assert.throws(() => historicalSlotIdentity({ slot: "jwtPending", secretArn: resources.jwtPending, versionId: currentVersionIds.jwtPending, stages: ["AWSCURRENT"], payload: historicalPayload("jwtPending", { source: "b".repeat(40) }) }), /source provenance/);
  assert.throws(() => historicalSlotIdentity({ slot: "jwtPending", secretArn: resources.jwtPending, versionId: currentVersionIds.jwtPending, stages: ["AWSCURRENT"], payload: { ...historicalPayload("jwtPending"), family: "unrelated_json" } }), /kind/);
  assert.throws(() => historicalSlotIdentity({ slot: "jwtPending", secretArn: resources.jwtPending, versionId: currentVersionIds.jwtPending, stages: ["AWSCURRENT"], payload: { ...historicalPayload("jwtPending"), materialFingerprint: "tampered" } }), /fingerprint/);
  assert.throws(() => historicalSlotIdentity({ slot: "jwtPending", secretArn: resources.jwtPending, versionId: currentVersionIds.jwtPending, stages: ["AWSPREVIOUS"], payload: historicalPayload("jwtPending") }), /stages/);
  assert.throws(() => buildAbandonmentEvidence({ sourceSha, historicalRotationId, historicalSourceShas: REBASELINE_HISTORICAL_SOURCE_SHAS, resources, currentVersionIds: { ...currentVersionIds, jwtPending: "changed-version" }, observedSlotIdentities, liveReferenceAudit: "PASS", liveReferenceAuditSha256: audit.auditSha256, legacyRuntimeAuthoritative: true }), /exact|identity/);
  assert.doesNotThrow(() => historicalSlotIdentity({ slot: "qrPreviousVersion", secretArn: resources.qrPreviousVersion, versionId: currentVersionIds.qrPreviousVersion, stages: ["AWSCURRENT"], payload: historicalPayload("qrPreviousVersion", { source: undefined }) }));
  assert.doesNotThrow(() => historicalSlotIdentity({ slot: "qrPublicPending", secretArn: resources.qrPublicPending, versionId: currentVersionIds.qrPublicPending, stages: ["AWSCURRENT"], payload: historicalPayload("qrPublicPending", { source: REBASELINE_HISTORICAL_SOURCE_SHAS[1] }) }));
  const tampered = structuredClone(abandoned); tampered.observedSlotIdentities.jwtPending.payloadSha256 = "0".repeat(64);
  assert.throws(() => assertRebaselinePreconditions({ ...preconditions, abandonmentEvidence: tampered }), /hash/);
});

test("authorization binds observed historical and complete ECS audit identities", () => {
  const value = authorization(); assert.equal(value.operation, PRODUCTION_DUAL_SLOT_REBASELINE.kind);
  assert.throws(() => assertProductionDualSlotRebaselineAuthorization({ ...value, observedSlotIdentitiesSha256: "0".repeat(64) }, { sourceSha, rotationId, resources }), /hash|identity/);
  assert.throws(() => assertRebaselinePreconditions({ ...preconditions, liveReferenceAuditSha256: "0".repeat(64) }), /bound|safe/);
});

test("seven-slot execution resumes at every write boundary and persists exact completion plus bindings", async () => {
  for (let failAt = 1; failAt <= 7; failAt += 1) { const outputs = temporary(); const adapters = executionAdapters({ failAt }); await assert.rejects(() => execute(adapters, outputs), /interruption/); const resumed = await execute(adapters, outputs); assert.equal(resumed.baselineComplete, true); assert.equal(JSON.stringify(resumed.completion).includes(material.jwt), false); assert.equal(readFileSync(outputs.completionFile, "utf8").includes(material.jwt), false); rmSync(outputs.directory, { recursive: true, force: true }); }
});

test("completion and bindings persistence crash windows resume with zero duplicate secret versions", async () => {
  for (const hook of ["afterCompletionPersist", "afterBindingsPersist"]) {
    const outputs = temporary(); const adapters = executionAdapters(); let injected = false;
    await assert.rejects(() => execute(adapters, outputs, { [hook]: async () => { if (!injected) { injected = true; throw new Error(`crash after ${hook}`); } } }), /crash/);
    const resumed = await execute(adapters, outputs); assert.equal(resumed.writes, 0); assert.equal(resumed.baselineComplete, true); rmSync(outputs.directory, { recursive: true, force: true });
  }
});

test("durable output preflight fails before any secret write when an existing output accompanies a partial baseline", async () => {
  const outputs = temporary(); writeFileSync(outputs.completionFile, "{}", { mode: 0o600 }); const adapters = executionAdapters();
  await assert.rejects(() => execute(adapters, outputs), /output|incomplete/i);
  assert.equal([...adapters.store.entries()].every(([slot, versions]) => versions.length === 1 && versions[0].versionId === currentVersionIds[slot]), true);
  rmSync(outputs.directory, { recursive: true, force: true });
});

test("runtime admits only a declared rebaseline producer anchored to independent authorization", async () => {
  const outputs = temporary(); const result = await execute(executionAdapters(), outputs); const auth = authorization();
  assertBaselineCompletion(result.completion, { sourceSha, rotationId, resources, authorizationBinding: auth.authorizationSha256 }); assertRebaselineRotationBindings(result.bindings, { authorization: auth }); assert.doesNotThrow(() => assertBindings(result.bindings, { rebaselineAuthorization: auth }));
  const stripped = { ...result.bindings }; delete stripped.operation; delete stripped.baselineCompletionSha256; assert.throws(() => assertBindings(stripped, { rebaselineAuthorization: auth }), /schema|producer|rebaseline/i);
  const fabricated = { ...result.completion, authorizationBinding: "f".repeat(64) }; fabricated.baselineBindingSha256 = canonicalSha256(Object.fromEntries(Object.entries(fabricated).filter(([key]) => key !== "baselineBindingSha256"))); const bad = { ...result.bindings, baselineCompletion: fabricated, baselineCompletionSha256: fabricated.baselineBindingSha256 }; assert.throws(() => assertBindings(bad, { rebaselineAuthorization: auth }), /authorization/i);
  assert.doesNotThrow(() => readBoundBaselineCompletion({ filePath: outputs.completionFile, expectedSha256: result.completionSha256, authorization: auth }));
  assert.throws(() => readBoundBaselineCompletion({ filePath: outputs.completionFile, expectedSha256: result.completionSha256, authorization: { ...auth, authorizationSha256: "f".repeat(64) } }), /hash|authorization/i);
  rmSync(outputs.directory, { recursive: true, force: true });
});

test("runtime authorization resolver derives the expected digest from GitHub provenance, never the completion", () => {
  const auth = authorization(); const archive = Buffer.from("zip-fixture"); const seen = [];
  const run = (command, args, options) => {
    seen.push({ command, args, options });
    if (command === "gh" && args[1] === "repos/T-ej2003/genuine-scan-main/actions/runs/123456") return JSON.stringify({ id: 123456, repository: { id: 9, full_name: PRODUCTION_DUAL_SLOT_REBASELINE.repository }, head_repository: { full_name: PRODUCTION_DUAL_SLOT_REBASELINE.repository }, path: ".github/workflows/authorize-production-dual-slot-rebaseline.yml", event: "workflow_dispatch", head_sha: sourceSha, status: "completed", conclusion: "success", run_attempt: 1, actor: { login: "checker" } });
    if (command === "gh" && args[1].endsWith("/artifacts")) return JSON.stringify([{ artifacts: [{ id: 91, name: "production-dual-slot-rebaseline-authorization", expired: false, workflow_run: { id: 123456, head_sha: sourceSha, repository_id: 9 }, digest: `sha256:${sha256(archive)}` }] }]);
    if (command === "gh" && args[1].endsWith("/zip")) return archive;
    if (command === "unzip" && args[0] === "-Z1") return "authorization.json\n";
    if (command === "unzip" && args[0] === "-Z") return "-  authorization.json\n";
    if (command === "unzip" && args[0] === "-p") return JSON.stringify(auth);
    throw new Error(`unexpected ${command} ${args.join(" ")}`);
  };
  const resolved = resolveProductionDualSlotRebaselineAuthorizationArtifact({ workflowRunId: "123456", workflowRunAttempt: "1", sourceSha, rotationId, resources, run });
  assert.equal(resolved.authorization.authorizationSha256, auth.authorizationSha256); const zip = seen.find(({ args }) => args[1].endsWith("/zip")); assert.equal(zip.options.encoding, null); assert.equal(zip.args.includes("--output"), false);
});

test("full live ECS audit rejects a legacy running revision when service points at a newer revision", () => {
  const old = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:50"; const current = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:51"; const legacy = [legacyBaseline.jwtCurrent, legacyBaseline.qrPrivateCurrent, legacyBaseline.qrPublicCurrent]; const definition = (arn, references = []) => ({ taskDefinition: { taskDefinitionArn: arn, containerDefinitions: [{ name: "backend", secrets: [...legacy, ...references].map((valueFrom, index) => ({ name: ["JWT_SECRET", "QR_SIGN_PRIVATE_KEY", "QR_SIGN_PUBLIC_KEY"][index] || `EXTRA_${index}`, valueFrom })), environment: [{ name: "QR_SIGN_ACTIVE_KEY_VERSION", value: "legacy-v1" }] }] } });
  const run = (args) => { if (args[1] === "describe-services") return JSON.stringify({ services: [{ serviceArn: "arn:aws:ecs:eu-west-2:368992683803:service/mscqr", taskDefinition: current, desiredCount: 2, runningCount: 1, pendingCount: 1, deployments: [{ id: "primary", status: "PRIMARY", taskDefinition: current }, { id: "rollback", status: "ACTIVE", taskDefinition: old }], deploymentController: { type: "ECS" } }] }); if (args[1] === "list-tasks") return JSON.stringify({ taskArns: args.includes("RUNNING") ? ["arn:aws:ecs:eu-west-2:368992683803:task/old"] : args.includes("PENDING") ? ["arn:aws:ecs:eu-west-2:368992683803:task/pending"] : [] }); if (args[1] === "describe-tasks") return JSON.stringify({ tasks: [{ taskArn: "arn:aws:ecs:eu-west-2:368992683803:task/old", taskDefinitionArn: old, lastStatus: "RUNNING", desiredStatus: "RUNNING" }, { taskArn: "arn:aws:ecs:eu-west-2:368992683803:task/pending", taskDefinitionArn: old, lastStatus: "PENDING", desiredStatus: "RUNNING" }] }); if (args[1] === "describe-task-definition") return JSON.stringify(args[args.indexOf("--task-definition") + 1] === old ? definition(old, [resources.jwtPending]) : definition(current)); throw new Error(`unexpected ${args.join(" ")}`); };
  const result = auditLiveProductionDualSlotReferences({ run, resources }); assert.equal(result.status, "FAIL"); assert.equal(result.dualSlotReferences, 1); assert.equal(result.evidence.taskDefinitionArns.includes(old), true);
});

test("protected checkout rejects tracked, staged, untracked, and substituted source state", () => {
  const fixture = (status = "", head = sourceSha, remote = sourceSha) => (args) => { if (args[0] === "fetch" || args[0] === "merge-base") return ""; if (args[0] === "rev-parse" && args[1] === "FETCH_HEAD") return remote; if (args[0] === "rev-parse" && args[1] === "HEAD") return head; if (args[0] === "rev-parse" && args[1] === "--is-shallow-repository") return "false"; if (args[0] === "rev-parse" && args[1] === "--git-path") return ".git/NOPE"; if (args[0] === "symbolic-ref") return "refs/remotes/origin/main"; if (args[0] === "status") return status; throw new Error(`unexpected git ${args.join(" ")}`); };
  assert.doesNotThrow(() => readAuthenticatedRebaselineCheckout({ sourceSha, gitRun: fixture(), repositoryRoot: process.cwd() })); for (const status of [" M scripts/a.mjs", "M  scripts/a.mjs", "?? node_modules/evil.mjs"]) assert.throws(() => readAuthenticatedRebaselineCheckout({ sourceSha, gitRun: fixture(status), repositoryRoot: process.cwd() }), /modification|untracked/); assert.throws(() => readAuthenticatedRebaselineCheckout({ sourceSha, gitRun: fixture("", "b".repeat(40)), repositoryRoot: process.cwd() }), /requested|match/);
});

test("the rebaseline boundary has no unrelated mutation escape hatch", () => { const contract = readFileSync(new URL("../aws/production-dual-slot-rebaseline-contract.mjs", import.meta.url), "utf8"); const executor = readFileSync(new URL("../aws/rebaseline-production-dual-slot.mjs", import.meta.url), "utf8"); assert.equal(/new\s+(DeleteSecret|UpdateSecret|RegisterTaskDefinition|PutResourcePolicy)Command|\["ecs",\s*"(update-service|register-task-definition)"\]/i.test(contract), false); assert.equal(/new\s+(DeleteSecret|UpdateSecret|RegisterTaskDefinition|PutResourcePolicy)Command|\["ecs",\s*"(update-service|register-task-definition)"\]/i.test(executor), false); assert.equal(executor.includes("PutSecretValueCommand"), true); });

test("production entrypoints pin the private historical topology digest", () => {
  const executor = readFileSync(new URL("../aws/rebaseline-production-dual-slot.mjs", import.meta.url), "utf8");
  const runtime = readFileSync(new URL("../aws/prepare-production-cutover-runtime.mjs", import.meta.url), "utf8");
  assert.match(executor, /historical topology is not the protected-source abandoned identity/);
  assert.match(runtime, /historicalTopologySha256 !== REBASELINE_ABANDONED_HISTORICAL_TOPOLOGY_SHA256/);
  assert.equal(/arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr\/prod\/rotation/.test(readFileSync(new URL("../aws/production-dual-slot-rebaseline-contract.mjs", import.meta.url), "utf8")), false);
});
