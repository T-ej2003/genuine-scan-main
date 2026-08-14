import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { runCanonicalRecoveryCli } from "../aws/recover-stage-b-backend-task-definition.mjs";
import {
  STAGE_B_BACKEND_RECOVERY,
  assertBackendRecoveryPreconditions,
  assertCanonicalBackendRecoveryReadback,
  buildCanonicalBackendRecoveryTaskDefinition,
  canonicalSha256,
  reconcileCanonicalBackendState,
  registerCanonicalBackendRecovery,
  recoveryEvidence,
  runCanonicalBackendRecovery,
  taskDefinitionFingerprint,
} from "../aws/stage-b-task-definition-recovery-contract.mjs";

const sourceSha = "084fc6eff5cfcc78d0ff2e037477f824090cb4f3";
const image = `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@sha256:${"a".repeat(64)}`;
const bindings = {
  backendImage: image,
  imageReleaseSha: sourceSha,
  sourceContractSha256: "b".repeat(64),
  migrationSetDigest: "c".repeat(64),
  packageChecksumSha256: "d".repeat(64),
  receiptBucket: "arn:aws:s3:::mscqr-prod-euw2-artifacts-368992683803-eu-west-2-an",
  executorLogGroup: "/ecs/stage-b-executor",
  canaryLogGroup: "/ecs/mscqr-production/rls-green-canary",
  backendLogGroup: "/ecs/mscqr-production/rls-green-backend",
  workerLogGroup: "/ecs/mscqr-production/rls-green-worker",
};
const state = (arn = STAGE_B_BACKEND_RECOVERY.predecessorArn, serial = STAGE_B_BACKEND_RECOVERY.serial) => ({
  version: 4,
  terraform_version: "1.9.8",
  serial,
  lineage: STAGE_B_BACKEND_RECOVERY.lineage,
  resources: [{ mode: "managed", type: "aws_ecs_task_definition", name: "candidate", instances: [{ index_key: "backend", schema_version: 1, attributes: { id: arn, arn, family: STAGE_B_BACKEND_RECOVERY.family } }] }],
});

function replacementPayload(arn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:8", options = {}) {
  const payload = buildCanonicalBackendRecoveryTaskDefinition(bindings);
  const taskDefinition = { ...structuredClone(payload.taskDefinition), taskDefinitionArn: arn, family: options.family || payload.taskDefinition.family, status: options.status || "ACTIVE", revision: Number(arn.split(":").at(-1)) };
  if (options.mutate) options.mutate(taskDefinition);
  return { taskDefinition, tags: options.tags || structuredClone(payload.tags), fingerprint: taskDefinitionFingerprint(payload.taskDefinition, payload.tags) };
}

test("recovery preconditions are exact and source-bound", () => {
  assert.deepEqual(assertBackendRecoveryPreconditions({ state: state(), sourceSha }), {
    address: STAGE_B_BACKEND_RECOVERY.address,
    family: STAGE_B_BACKEND_RECOVERY.family,
    predecessorArn: STAGE_B_BACKEND_RECOVERY.predecessorArn,
    sourceSha,
    lineage: STAGE_B_BACKEND_RECOVERY.lineage,
    serial: 93,
    newestHistoricalArn: STAGE_B_BACKEND_RECOVERY.newestHistoricalArn,
  });
  for (const mutate of [
    (value) => value.resources[0].instances[0].attributes.arn = STAGE_B_BACKEND_RECOVERY.historicalRevisionArns[0],
    (value) => value.serial = 94,
    (value) => value.lineage = "0".repeat(36),
    (value) => value.resources.push(structuredClone(value.resources[0])),
  ]) assert.throws(() => assertBackendRecoveryPreconditions({ state: (() => { const value = state(); mutate(value); return value; })(), sourceSha }));
  assert.throws(() => assertBackendRecoveryPreconditions({ state: state(), sourceSha: "0".repeat(40), expectedNewestArn: STAGE_B_BACKEND_RECOVERY.historicalRevisionArns[0] }));
});

test("canonical source rendering produces the exact immutable replacement fingerprint", () => {
  const payload = buildCanonicalBackendRecoveryTaskDefinition(bindings);
  assert.equal(payload.taskDefinition.family, STAGE_B_BACKEND_RECOVERY.family);
  assert.equal(payload.taskDefinition.containerDefinitions[0].image, image);
  assert.equal(payload.taskDefinition.containerDefinitions[0].environment.find(({ name }) => name === "RELEASE_GIT_SHA").value, sourceSha);
  assert.equal(payload.tags.find(({ key }) => key === "MSCQRExecTarget").value, "production-backend");
  assert.match(taskDefinitionFingerprint(payload.taskDefinition, payload.tags), /^[a-f0-9]{64}$/);
});

test("registration performs one dynamic canonical registration and verifies newest readback", async () => {
  const payload = replacementPayload();
  let registrations = 0;
  let newestReads = 0;
  const result = await registerCanonicalBackendRecovery({
    bindings,
    state: state(),
    sourceSha,
    expectedFingerprint: payload.fingerprint,
    register: async (value) => { registrations += 1; assert.deepEqual(value, buildCanonicalBackendRecoveryTaskDefinition(bindings)); return { taskDefinition: { taskDefinitionArn: payload.taskDefinition.taskDefinitionArn } }; },
    describe: async () => payload,
    newest: async () => { newestReads += 1; return newestReads === 1 ? STAGE_B_BACKEND_RECOVERY.newestHistoricalArn : payload.taskDefinition.taskDefinitionArn; },
  });
  assert.equal(result.registrationCalls, 1);
  assert.equal(registrations, 1);
  assert.equal(newestReads, 2);
  assert.equal(result.arn, payload.taskDefinition.taskDefinitionArn);
});

test("replacement readback rejects historical, inactive, wrong-family, stale, and malformed revisions", () => {
  const exactPayload = replacementPayload();
  assert.doesNotThrow(() => assertCanonicalBackendRecoveryReadback({ readback: exactPayload, expectedArn: exactPayload.taskDefinition.taskDefinitionArn, expectedFingerprint: exactPayload.fingerprint }));
  const cases = [
    () => ({ readback: replacementPayload(STAGE_B_BACKEND_RECOVERY.historicalRevisionArns[0]), expectedArn: STAGE_B_BACKEND_RECOVERY.historicalRevisionArns[0] }),
    () => ({ readback: replacementPayload(undefined, { status: "INACTIVE" }), expectedArn: exactPayload.taskDefinition.taskDefinitionArn }),
    () => ({ readback: replacementPayload(undefined, { family: "wrong-family" }), expectedArn: exactPayload.taskDefinition.taskDefinitionArn }),
    () => ({ readback: replacementPayload(undefined, { mutate: (value) => { value.containerDefinitions[0].image = `${image.slice(0, -64)}${"e".repeat(64)}`; } }), expectedArn: exactPayload.taskDefinition.taskDefinitionArn }),
    () => ({ readback: replacementPayload(undefined, { mutate: (value) => { value.containerDefinitions[0].portMappings[0].containerPort = 443; } }), expectedArn: exactPayload.taskDefinition.taskDefinitionArn }),
    () => ({ readback: replacementPayload(undefined, { mutate: (value) => { value.taskRoleArn = "arn:aws:iam::368992683803:role/unreviewed"; } }), expectedArn: exactPayload.taskDefinition.taskDefinitionArn }),
    () => ({ readback: replacementPayload(undefined, { tags: [{ key: "MSCQRExecTarget", value: "wrong" }] }), expectedArn: exactPayload.taskDefinition.taskDefinitionArn }),
    () => ({ readback: replacementPayload(undefined, { mutate: (value) => { value.containerDefinitions[0].environment.find(({ name }) => name === "RELEASE_GIT_SHA").value = "0".repeat(40); } }), expectedArn: exactPayload.taskDefinition.taskDefinitionArn }),
  ];
  for (const makeCase of cases) { const value = makeCase(); assert.throws(() => assertCanonicalBackendRecoveryReadback({ ...value, expectedFingerprint: exactPayload.fingerprint })); }
  assert.throws(() => assertCanonicalBackendRecoveryReadback({ readback: exactPayload, expectedArn: STAGE_B_BACKEND_RECOVERY.historicalRevisionArns[1], expectedFingerprint: exactPayload.fingerprint }));
});

test("state reconciliation is exact, minimal, and rejects historical adoption", async () => {
  const replacementArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:8";
  let current = state();
  let removes = 0;
  let imports = 0;
  const result = await reconcileCanonicalBackendState({
    sourceSha,
    replacementArn,
    readState: async () => structuredClone(current),
    removeState: async ({ address, expectedArn }) => { removes += 1; assert.equal(address, STAGE_B_BACKEND_RECOVERY.address); assert.equal(expectedArn, STAGE_B_BACKEND_RECOVERY.predecessorArn); current = { ...current, serial: 94, resources: [] }; },
    importState: async ({ address, arn }) => { imports += 1; assert.equal(address, STAGE_B_BACKEND_RECOVERY.address); assert.equal(arn, replacementArn); current = state(replacementArn, 95); },
  });
  assert.equal(removes, 1);
  assert.equal(imports, 1);
  assert.deepEqual(result, { stateLineageBefore: STAGE_B_BACKEND_RECOVERY.lineage, stateLineageAfter: STAGE_B_BACKEND_RECOVERY.lineage, stateSerialBefore: 93, stateSerialAfter: 95, stateBackendCandidate: replacementArn, liveBackendCandidate: replacementArn, stateLivePredecessorMatch: true, removeCalls: 1, importCalls: 1 });
  await assert.rejects(() => reconcileCanonicalBackendState({ sourceSha, replacementArn: STAGE_B_BACKEND_RECOVERY.historicalRevisionArns[1], readState: async () => state(), removeState: async () => { throw new Error("must not mutate"); }, importState: async () => { throw new Error("must not mutate"); } }));
});

test("end-to-end recovery orchestration registers once, then reconciles only Terraform state", async () => {
  const replacementArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:8";
  const payload = replacementPayload(replacementArn);
  let current = state();
  const calls = [];
  const result = await runCanonicalBackendRecovery({
    bindings,
    sourceSha,
    readState: async () => structuredClone(current),
    newest: async () => calls.includes("register") ? replacementArn : STAGE_B_BACKEND_RECOVERY.newestHistoricalArn,
    register: async () => { calls.push("register"); return { taskDefinition: { taskDefinitionArn: replacementArn } }; },
    describe: async () => payload,
    removeState: async () => { calls.push("remove"); current = { ...current, serial: 94, resources: [] }; },
    importState: async () => { calls.push("import"); current = state(replacementArn, 95); },
  });
  assert.deepEqual(calls, ["register", "remove", "import"]);
  assert.equal(result.registration.registrationCalls, 1);
  assert.equal(result.reconciliation.stateBackendCandidate, replacementArn);
  assert.equal(result.evidence.replacementArn, replacementArn);
});

test("recovery evidence is deterministic and binds source, image, predecessor, replacement, and state", () => {
  const payload = replacementPayload();
  const evidence = recoveryEvidence({ sourceSha, state: state(), imageDigest: image, replacement: { arn: payload.taskDefinition.taskDefinitionArn, fingerprint: payload.fingerprint, protectedSourceFingerprint: payload.fingerprint }, registrationEvent: { eventId: "reviewed-test-event" } });
  const { evidenceSha256, ...evidenceBody } = evidence;
  assert.equal(evidenceSha256, canonicalSha256(evidenceBody));
  assert.equal(evidence.predecessorArn, STAGE_B_BACKEND_RECOVERY.predecessorArn);
  assert.throws(() => recoveryEvidence({ sourceSha, state: state(), imageDigest: image, replacement: { arn: STAGE_B_BACKEND_RECOVERY.historicalRevisionArns[1], fingerprint: payload.fingerprint, protectedSourceFingerprint: payload.fingerprint } }));
});

test("generic deployment script cannot register Stage-B managed families", () => {
  const script = readFileSync("scripts/aws/deploy-ecs-service.sh", "utf8");
  assert.match(script, /reject_generic_stage_b_registration/);
  assert.match(script, /mscqr-production-rls-green-backend-candidate/);
  assert.match(script, /mscqr-production-full-rls-green-\*/);
  assert.match(script, /if \[\[ -z \"\$EXISTING_TASK_DEFINITION_ARN\" \]\]/);
});

test("recovery CLI requires explicit execution and hard-codes only the reviewed state operations", async () => {
  await assert.rejects(() => runCanonicalRecoveryCli(["--source-sha", sourceSha]), /--execute/);
  const script = readFileSync("scripts/aws/recover-stage-b-backend-task-definition.mjs", "utf8");
  assert.match(script, /--profile/);
  assert.match(script, /state\", \"rm/);
  assert.match(script, /import\", \"-lock-timeout=60s/);
  assert.match(script, /No ACTIVE backend candidate revisions/);
});
