import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { runCanonicalRecoveryCli } from "../aws/recover-stage-b-backend-task-definition.mjs";
import {
  STAGE_B_BACKEND_RECOVERY,
  assertBackendRecoveryPreconditions,
  assertCanonicalBackendRecoveryReadback,
  buildCanonicalRecoveryJournal,
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
  toolingSha: sourceSha,
  sourceSha,
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
const protectedCheckout = { mode: "production", toolingSha: sourceSha, currentHead: sourceSha, originMainHead: sourceSha, isAncestor: true, porcelainStatus: "", repositoryState: { remoteDefaultBranch: "main", shallow: false, mergeInProgress: false, rebaseInProgress: false, cherryPickInProgress: false } };
const journalAdapter = (initial) => { let value = initial ? structuredClone(initial) : null; return { read: () => value && structuredClone(value), write: (next) => { value = structuredClone(next); } }; };
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

function awsNormalizedReadback(arn) {
  const payload = replacementPayload(arn);
  const container = payload.taskDefinition.containerDefinitions[0];
  payload.taskDefinition.placementConstraints = [];
  payload.taskDefinition.volumes[0].host = {};
  container.cpu = 0;
  container.volumesFrom = [];
  container.systemControls = [];
  payload.tags.reverse();
  return payload;
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

test("AWS ECS readback projections preserve the exact protected semantic fingerprint", () => {
  const source = replacementPayload();
  const readback = awsNormalizedReadback(source.taskDefinition.taskDefinitionArn);
  assert.equal(taskDefinitionFingerprint(readback.taskDefinition, readback.tags), source.fingerprint);
  assert.doesNotThrow(() => assertCanonicalBackendRecoveryReadback({ readback, expectedArn: source.taskDefinition.taskDefinitionArn, expectedFingerprint: source.fingerprint }));
});

test("task-definition fingerprint normalization remains field-specific and fail-closed", () => {
  const source = replacementPayload();
  const mutations = [
    (value) => { value.containerDefinitions[0].cpu = 1; },
    (value) => { value.containerDefinitions[0].volumesFrom = [{ sourceContainer: "other", readOnly: true }]; },
    (value) => { value.containerDefinitions[0].systemControls = [{ namespace: "net.ipv4.ip_forward", value: "1" }]; },
    (value) => { value.containerDefinitions[0].image = `${image.slice(0, -64)}${"e".repeat(64)}`; },
    (value) => { value.containerDefinitions[0].secrets[0].valueFrom += "-other"; },
    (value) => { value.containerDefinitions[0].environment[0].value = "other"; },
    (value) => { value.containerDefinitions[0].mountPoints[0].containerPath = "/other"; },
    (value) => { value.containerDefinitions[0].logConfiguration.options["awslogs-group"] = "/ecs/other"; },
    (value) => { value.executionRoleArn = "arn:aws:iam::368992683803:role/other"; },
    (value) => { value.taskRoleArn = "arn:aws:iam::368992683803:role/other"; },
    (value) => { value.firelensConfiguration = {}; },
  ];
  for (const mutate of mutations) {
    const changed = structuredClone(source.taskDefinition);
    mutate(changed);
    assert.notEqual(taskDefinitionFingerprint(changed, source.tags), source.fingerprint);
  }
  const changedTag = structuredClone(source.tags);
  changedTag[0].value = "other";
  assert.notEqual(taskDefinitionFingerprint(source.taskDefinition, changedTag), source.fingerprint);
  const hostVolume = structuredClone(source.taskDefinition);
  hostVolume.volumes[0].host = { sourcePath: "/host" };
  assert.throws(() => taskDefinitionFingerprint(hostVolume, source.tags), /unreviewed provider field/);
});

test("registration performs one dynamic canonical registration and verifies newest readback", async () => {
  const payload = replacementPayload();
  let registrations = 0;
  let newestReads = 0;
  const result = await registerCanonicalBackendRecovery({
    bindings,
    state: state(),
    sourceSha,
    protectedCheckout,
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
  const payload = replacementPayload(replacementArn);
  const journal = buildCanonicalRecoveryJournal(current, { sourceSha, fingerprint: payload.fingerprint, imageDigest: image });
  journal.replacementArn = replacementArn;
  journal.phase = "REGISTERED";
  const result = await reconcileCanonicalBackendState({
    sourceSha,
    replacementArn,
    readState: async () => structuredClone(current),
    journal: journalAdapter(journal),
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
  const journal = journalAdapter();
  const result = await runCanonicalBackendRecovery({
    bindings,
    sourceSha,
    protectedCheckout,
    readState: async () => structuredClone(current),
    journal,
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

test("source identity and evidence destination failures happen before mutation adapters", async () => {
  const directory = `/tmp/mscqr-recovery-test-${process.pid}`;
  const { mkdirSync, rmSync, writeFileSync } = await import("node:fs");
  rmSync(directory, { recursive: true, force: true });
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const bindingsPath = `${directory}/bindings.json`;
  const evidencePath = `${directory}/evidence.json`;
  writeFileSync(bindingsPath, JSON.stringify(bindings), { mode: 0o600 });
  writeFileSync(evidencePath, "occupied\n", { mode: 0o600 });
  const calls = [];
  const exec = (command) => { calls.push(command); throw new Error("mutation adapter must not run"); };
  const terraformRoot = path.resolve("infra/aws/terraform/production-green-stage-b");
  await assert.rejects(() => runCanonicalRecoveryCli(["--execute", "--source-sha", sourceSha, "--bindings", bindingsPath, "--terraform-root", terraformRoot, "--evidence-out", evidencePath, "--aws-profile", "test"], { exec, readProtectedCheckout: () => protectedCheckout }), /occupied/);
  assert.deepEqual(calls, []);
  await assert.rejects(() => runCanonicalRecoveryCli(["--execute", "--source-sha", "0".repeat(40), "--bindings", bindingsPath, "--terraform-root", terraformRoot, "--evidence-out", `${directory}/other.json`, "--aws-profile", "test"], { exec, readProtectedCheckout: () => protectedCheckout }), /exact clean protected-main/);
  assert.deepEqual(calls, []);
  await assert.rejects(() => runCanonicalRecoveryCli(["--execute", "--source-sha", sourceSha, "--bindings", bindingsPath, "--terraform-root", terraformRoot, "--evidence-out", `${directory}/dirty.json`, "--aws-profile", "test"], { exec, readProtectedCheckout: () => ({ ...protectedCheckout, porcelainStatus: " M scripts/aws/example.mjs" }) }), /clean protected-main/);
  assert.deepEqual(calls, []);
  await assert.rejects(() => runCanonicalRecoveryCli(["--execute", "--source-sha", sourceSha, "--bindings", bindingsPath, "--terraform-root", terraformRoot, "--evidence-out", `${directory}/different-head.json`, "--aws-profile", "test"], { exec, readProtectedCheckout: () => ({ ...protectedCheckout, currentHead: "f".repeat(40) }) }), /exact clean protected-main/);
  assert.deepEqual(calls, []);
  writeFileSync(bindingsPath, JSON.stringify({ ...bindings, imageReleaseSha: "0".repeat(40) }), { mode: 0o600 });
  await assert.rejects(() => runCanonicalRecoveryCli(["--execute", "--source-sha", sourceSha, "--bindings", bindingsPath, "--terraform-root", terraformRoot, "--evidence-out", `${directory}/binding-mismatch.json`, "--aws-profile", "test"], { exec, readProtectedCheckout: () => protectedCheckout }), /source-bound/);
  assert.deepEqual(calls, []);
  writeFileSync(`${directory}/not-a-directory`, "x\n", { mode: 0o600 });
  await assert.rejects(() => runCanonicalRecoveryCli(["--execute", "--source-sha", sourceSha, "--bindings", bindingsPath, "--terraform-root", terraformRoot, "--evidence-out", `${directory}/not-a-directory/evidence.json`, "--aws-profile", "test"], { exec, readProtectedCheckout: () => protectedCheckout }), /directory/);
  assert.deepEqual(calls, []);
  rmSync(directory, { recursive: true, force: true });
});

test("retry after remote registration resumes the exact newest canonical revision without registering", async () => {
  const replacementArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:8";
  const payload = replacementPayload(replacementArn);
  let current = state();
  let newestValue = STAGE_B_BACKEND_RECOVERY.newestHistoricalArn;
  let registrationCalls = 0;
  const journal = journalAdapter();
  const common = { bindings, sourceSha, protectedCheckout, readState: async () => structuredClone(current), journal,
    newest: async () => newestValue, describe: async () => payload,
    removeState: async () => { current = { ...current, serial: 94, resources: [] }; },
    importState: async () => { current = state(replacementArn, 95); } };
  await assert.rejects(() => runCanonicalBackendRecovery({ ...common, register: async () => { registrationCalls += 1; newestValue = replacementArn; throw new Error("response lost"); } }), /response lost/);
  const result = await runCanonicalBackendRecovery({ ...common, register: async () => { registrationCalls += 1; throw new Error("must not register on retry"); } });
  assert.equal(registrationCalls, 1);
  assert.equal(result.registration.registrationCalls, 0);
  assert.equal(result.reconciliation.stateBackendCandidate, replacementArn);
});

test("REGISTERED fingerprint-blocked journal resumes existing AWS-normalized revision without registering", async () => {
  const replacementArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:8";
  const readback = awsNormalizedReadback(replacementArn);
  let current = state(); let registrations = 0;
  const initial = buildCanonicalRecoveryJournal(current, { sourceSha, fingerprint: readback.fingerprint, imageDigest: image });
  const journal = journalAdapter({ ...initial, phase: "REGISTERED", replacementArn, registrationCalls: 1, registrationMayHaveOccurred: true });
  const result = await runCanonicalBackendRecovery({ bindings, sourceSha, protectedCheckout, journal,
    readState: async () => structuredClone(current), newest: async () => replacementArn, describe: async () => readback,
    register: async () => { registrations += 1; throw new Error("must not register on resume"); },
    removeState: async () => { current = { ...current, serial: 94, resources: [] }; },
    importState: async () => { current = state(replacementArn, 95); },
  });
  assert.equal(registrations, 0);
  assert.equal(result.registration.registrationCalls, 0);
  assert.equal(result.reconciliation.stateBackendCandidate, replacementArn);
});

test("discovery failure records no registration attempt and legacy false registration journals fail closed", async () => {
  let current = state();
  const journal = journalAdapter();
  let registrations = 0;
  await assert.rejects(() => runCanonicalBackendRecovery({ bindings, sourceSha, protectedCheckout, journal,
    readState: async () => structuredClone(current), newest: async () => { throw new Error("ListTaskDefinitions denied"); },
    register: async () => { registrations += 1; }, describe: async () => {}, removeState: async () => {}, importState: async () => {},
  }), /ListTaskDefinitions denied/);
  assert.equal(journal.read().phase, "DISCOVERY");
  assert.equal(journal.read().registrationCalls, 0);
  assert.equal(journal.read().registrationMayHaveOccurred, false);
  assert.equal(registrations, 0);
  journal.write({ ...journal.read(), schemaVersion: 1, phase: "REGISTERING", registrationCalls: 1 });
  await assert.rejects(() => runCanonicalBackendRecovery({ bindings, sourceSha, protectedCheckout, journal,
    readState: async () => structuredClone(current), newest: async () => STAGE_B_BACKEND_RECOVERY.newestHistoricalArn,
    register: async () => { registrations += 1; }, describe: async () => {}, removeState: async () => {}, importState: async () => {},
  }), /Legacy recovery journal/);
  assert.equal(registrations, 0);
});

test("a sent registration that loses its response is marked ambiguous and never retried against historical newest", async () => {
  const journal = journalAdapter();
  let registrations = 0;
  await assert.rejects(() => runCanonicalBackendRecovery({ bindings, sourceSha, protectedCheckout, journal,
    readState: async () => state(), newest: async () => STAGE_B_BACKEND_RECOVERY.newestHistoricalArn,
    register: async () => { registrations += 1; throw new Error("response lost"); }, describe: async () => {}, removeState: async () => {}, importState: async () => {},
  }), /response lost/);
  assert.equal(journal.read().registrationCalls, 1);
  assert.equal(journal.read().registrationMayHaveOccurred, true);
  await assert.rejects(() => runCanonicalBackendRecovery({ bindings, sourceSha, protectedCheckout, journal,
    readState: async () => state(), newest: async () => STAGE_B_BACKEND_RECOVERY.newestHistoricalArn,
    register: async () => { registrations += 1; }, describe: async () => {}, removeState: async () => {}, importState: async () => {},
  }), /cannot prove a prior registration/);
  assert.equal(registrations, 1);
});

test("interrupted state removal resumes with import only", async () => {
  const replacementArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:8";
  const payload = replacementPayload(replacementArn);
  let current = state();
  let removes = 0;
  let imports = 0;
  const journal = journalAdapter();
  const common = { bindings, sourceSha, protectedCheckout, readState: async () => structuredClone(current), journal,
    newest: async () => replacementArn, describe: async () => payload,
    register: async () => { throw new Error("must not register while resuming"); },
    removeState: async () => { removes += 1; current = { ...current, serial: 94, resources: [] }; },
    importState: async () => { imports += 1; current = state(replacementArn, 95); } };
  let firstImport = true;
  await assert.rejects(() => runCanonicalBackendRecovery({ ...common, removeState: async () => { removes += 1; current = { ...current, serial: 94, resources: [] }; }, importState: async () => { imports += 1; if (firstImport) { firstImport = false; throw new Error("interrupted after state rm"); } current = state(replacementArn, 95); } }), /interrupted/);
  const result = await runCanonicalBackendRecovery(common);
  assert.equal(removes, 1);
  assert.equal(imports, 2);
  assert.equal(result.reconciliation.removeCalls, 0);
  assert.equal(result.reconciliation.importCalls, 1);
});

test("pre-remove checkpoint resumes when state removal never mutates state", async () => {
  const replacementArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:8";
  const payload = replacementPayload(replacementArn);
  let current = state(); let registrations = 0; let removes = 0; let imports = 0;
  const journal = journalAdapter();
  const common = { bindings, sourceSha, protectedCheckout, journal, readState: async () => structuredClone(current), newest: async () => replacementArn, describe: async () => payload,
    register: async () => { registrations += 1; return { taskDefinition: { taskDefinitionArn: replacementArn } }; },
    importState: async () => { imports += 1; current = state(replacementArn, 95); } };
  await assert.rejects(() => runCanonicalBackendRecovery({ ...common, newest: async () => registrations ? replacementArn : STAGE_B_BACKEND_RECOVERY.newestHistoricalArn,
    removeState: async () => { removes += 1; throw new Error("lock timeout"); } }), /lock timeout/);
  assert.equal(journal.read().phase, "STATE_RECONCILING_PRE_REMOVE");
  assert.equal(current.serial, 93);
  const resumed = await runCanonicalBackendRecovery({ ...common, register: async () => { throw new Error("must not register again"); }, removeState: async () => { removes += 1; current = { ...current, serial: 94, resources: [] }; } });
  assert.equal(registrations, 1);
  assert.equal(removes, 2);
  assert.equal(imports, 1);
  assert.equal(resumed.reconciliation.stateBackendCandidate, replacementArn);
});

test("persisted pre-remove journal resumes when the process dies before state removal starts", async () => {
  const replacementArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:8";
  const payload = replacementPayload(replacementArn);
  let current = state(); let removes = 0; let imports = 0;
  const initial = buildCanonicalRecoveryJournal(current, { sourceSha, fingerprint: payload.fingerprint, imageDigest: image });
  const journal = journalAdapter({ ...initial, phase: "STATE_RECONCILING_PRE_REMOVE", replacementArn, replacementFingerprint: payload.fingerprint, registrationCalls: 1, registrationMayHaveOccurred: true });
  const resumed = await runCanonicalBackendRecovery({ bindings, sourceSha, protectedCheckout, journal,
    readState: async () => structuredClone(current), newest: async () => replacementArn, describe: async () => payload,
    register: async () => { throw new Error("must not register again"); },
    removeState: async () => { removes += 1; current = { ...current, serial: 94, resources: [] }; },
    importState: async () => { imports += 1; current = state(replacementArn, 95); },
  });
  assert.equal(removes, 1);
  assert.equal(imports, 1);
  assert.equal(resumed.reconciliation.stateBackendCandidate, replacementArn);
});

test("post-remove readback resumes import when process dies before the post-remove journal write", async () => {
  const replacementArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:8";
  const payload = replacementPayload(replacementArn);
  let current = state(); let reads = 0; let imports = 0;
  const journal = journalAdapter();
  const common = { bindings, sourceSha, protectedCheckout, journal, newest: async () => replacementArn, describe: async () => payload,
    register: async () => ({ taskDefinition: { taskDefinitionArn: replacementArn } }),
    removeState: async () => { current = { ...current, serial: 94, resources: [] }; },
    importState: async () => { imports += 1; current = state(replacementArn, 95); } };
  await assert.rejects(() => runCanonicalBackendRecovery({ ...common, readState: async () => { reads += 1; if (reads === 3) throw new Error("process died after rm"); return structuredClone(current); } }), /process died/);
  assert.equal(journal.read().phase, "STATE_RECONCILING_PRE_REMOVE");
  const resumed = await runCanonicalBackendRecovery({ ...common, readState: async () => structuredClone(current), register: async () => { throw new Error("must not register again"); } });
  assert.equal(imports, 1);
  assert.equal(resumed.reconciliation.removeCalls, 0);
});

test("interrupted import resumes without registration or second state mutation", async () => {
  const replacementArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:8";
  const payload = replacementPayload(replacementArn);
  let current = state();
  let removes = 0;
  let imports = 0;
  let readCount = 0;
  const journal = journalAdapter();
  const result = await runCanonicalBackendRecovery({ bindings, sourceSha, protectedCheckout, journal,
    readState: async () => { readCount += 1; if (readCount === 4) throw new Error("interrupted after import"); return structuredClone(current); },
    newest: async () => replacementArn, describe: async () => payload,
    register: async () => ({ taskDefinition: { taskDefinitionArn: replacementArn } }),
    removeState: async () => { removes += 1; current = { ...current, serial: 94, resources: [] }; },
    importState: async () => { imports += 1; current = state(replacementArn, 95); },
  }).catch((error) => { assert.match(error.message, /interrupted/); return null; });
  assert.equal(result, null);
  const resumed = await runCanonicalBackendRecovery({ bindings, sourceSha, protectedCheckout, journal,
    readState: async () => structuredClone(current), newest: async () => replacementArn, describe: async () => payload,
    register: async () => { throw new Error("must not register on imported resume"); },
    removeState: async () => { removes += 1; }, importState: async () => { imports += 1; } });
  assert.equal(removes, 1);
  assert.equal(imports, 1);
  assert.equal(resumed.reconciliation.removeCalls, 0);
  assert.equal(resumed.reconciliation.importCalls, 0);
});

test("newer noncanonical or non-newest revisions fail closed without registration or state mutation", async () => {
  const replacementArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:8";
  for (const newestArn of [
    "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:8",
    "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:9",
  ]) {
    let registrations = 0;
    let removes = 0;
    const current = state();
    const journal = journalAdapter();
    await assert.rejects(() => runCanonicalBackendRecovery({ bindings, sourceSha, protectedCheckout, readState: async () => structuredClone(current), journal,
      newest: async () => newestArn, describe: async () => replacementPayload(newestArn, { mutate: (value) => { value.containerDefinitions[0].image = `${image.slice(0, -64)}${"e".repeat(64)}`; } }),
      register: async () => { registrations += 1; return { taskDefinition: { taskDefinitionArn: replacementArn } }; }, removeState: async () => { removes += 1; }, importState: async () => {} }), /newest|fingerprint/);
    assert.equal(registrations, 0);
    assert.equal(removes, 0);
  }
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
