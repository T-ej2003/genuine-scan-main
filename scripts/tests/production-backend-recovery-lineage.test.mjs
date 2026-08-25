import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import {
  BACKEND_HEALTH_RECOVERY,
  INTERRUPTED_RECOVERY_STATE,
  classifyInterruptedRecoveryState,
  classifyRevisionCensus,
  openInterruptedRecoveryHistory,
  reconcileAuthenticatedRevisionLineage,
  recoveryHistoryLineageSha256,
} from "../aws/production-backend-health-recovery-contract.mjs";
import { canonicalSha256, taskDefinitionFingerprint } from "../aws/stage-b-task-definition-recovery-contract.mjs";

const base = JSON.parse(fs.readFileSync(new URL("./fixtures/mscqr-backend-47.task-definition.json", import.meta.url)));
const baseArn = base.taskDefinition.taskDefinitionArn;
const baseRevision = base.taskDefinition.revision;
const sourceSha = "a".repeat(40);
const hex = (number, length = 64) => number.toString(16).padStart(length, "0").slice(-length);
const identities = (definitions) => definitions.map((item) => ({
  taskDefinitionArn: item.taskDefinition.taskDefinitionArn,
  taskDefinitionFingerprint: taskDefinitionFingerprint(item, item.tags || []),
})).sort((left, right) => left.taskDefinitionArn.localeCompare(right.taskDefinitionArn));
const censusSha256 = (definitions) => canonicalSha256(identities(definitions));

function revision(generation) {
  const revisionNumber = baseRevision + generation;
  const item = structuredClone(base);
  item.taskDefinition.taskDefinitionArn = `arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:${revisionNumber}`;
  item.taskDefinition.revision = revisionNumber;
  const backend = item.taskDefinition.containerDefinitions.find(({ name }) => name === "backend");
  const digest = `sha256:${hex(generation)}`;
  backend.image = `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@${digest}`;
  backend.environment = backend.environment.map((entry) => ["GIT_SHA", "RELEASE_GIT_SHA"].includes(entry.name)
    ? { ...entry, value: hex(generation, 40) }
    : entry);
  return item;
}

function generationRecord(generation, predecessor, candidate, overrides = {}) {
  const fingerprint = taskDefinitionFingerprint(candidate, candidate.tags || []);
  return {
    repository: "T-ej2003/genuine-scan-main",
    workflowRunId: String(33000000000 + generation),
    sourceSha,
    service: BACKEND_HEALTH_RECOVERY.service,
    releaseMode: BACKEND_HEALTH_RECOVERY.kind,
    currentTaskDefinitionArn: predecessor.at(-1).taskDefinition.taskDefinitionArn,
    taskDefinitionArn: candidate.taskDefinition.taskDefinitionArn,
    candidateFingerprint: fingerprint,
    taskDefinitionFingerprint: fingerprint,
    recoveryImageDigest: candidate.taskDefinition.containerDefinitions[0].image.split("@")[1],
    artifactSigningBindingSha256: hex(1000 + generation),
    runtimeConsumabilitySha256: hex(2000 + generation),
    predecessorHistoryReferenceSha256: generation === 1 ? null : hex(4000 + generation - 1),
    predecessorHistoryLineageSha256: null,
    status: generation % 2 ? "SERVICE_UPDATE_CONFIRMED" : "SERVICE_STABILIZATION_FAILED",
    classification: generation % 2 ? "INTERRUPTED_MUTATION" : "TERMINAL_FAILURE",
    failureClassification: generation % 2 ? null : "SERVICE_STABILIZATION_FAILED",
    initialRevisionCensusSha256: censusSha256(predecessor),
    expectedRevisionCensusSha256: censusSha256([...predecessor, candidate]),
    registrations: 1,
    updates: 1,
    evidenceFileSha256: hex(3000 + generation),
    ...overrides,
  };
}

function fixture(count) {
  const definitions = [base];
  const recoveryHistory = [];
  for (let generation = 1; generation <= count; generation += 1) {
    const candidate = revision(generation);
    recoveryHistory.push(generationRecord(generation, definitions, candidate, { predecessorHistoryLineageSha256: recoveryHistoryLineageSha256(recoveryHistory) }));
    definitions.push(candidate);
  }
  const knownFailedRevisions = recoveryHistory.filter(({ classification }) => classification === "TERMINAL_FAILURE");
  const interruptedRecoveries = recoveryHistory.filter(({ classification }) => classification === "INTERRUPTED_MUTATION");
  const next = revision(count + 1);
  return {
    definitions,
    recoveryHistory,
    next,
    eligible: {
      currentTaskDefinitionArn: baseArn,
      fingerprint: taskDefinitionFingerprint(next, next.tags || []),
      recoveryHistory,
      knownFailedRevisions,
      interruptedRecoveries,
      rollbackProof: null,
    },
  };
}

for (const count of [0, 1, 2, 3, 10, 25]) {
  test(`authenticated lineage supports ${count} prior recovery generations`, () => {
    const value = fixture(count);
    const before = classifyRevisionCensus([...value.definitions].reverse(), value.eligible);
    assert.equal(before.identitySha256, censusSha256(value.definitions));
    assert.equal(before.matches.length, 0);
    const candidate = classifyRevisionCensus([...value.definitions, value.next], value.eligible);
    assert.equal(candidate.matches[0].taskDefinitionArn, value.next.taskDefinition.taskDefinitionArn);
    assert.equal(candidate.historyResolutions.length, count);
    if (count) assert.doesNotThrow(() => classifyRevisionCensus(value.definitions, { ...value.eligible, currentTaskDefinitionArn: value.definitions.at(-1).taskDefinition.taskDefinitionArn }));
  });
}

test("only the final unclosed interruption requires current live reconciliation", () => {
  const two = fixture(2);
  assert.equal(two.recoveryHistory[0].classification, "INTERRUPTED_MUTATION");
  assert.equal(two.recoveryHistory[1].classification, "TERMINAL_FAILURE");
  assert.deepEqual(openInterruptedRecoveryHistory(two.recoveryHistory), []);
  const three = fixture(3);
  assert.deepEqual(openInterruptedRecoveryHistory(three.recoveryHistory), [three.recoveryHistory[2]]);
  assert.throws(() => openInterruptedRecoveryHistory(null), /malformed/);
});

test("ordered predecessor continuity rejects gaps, forks, conflicts, and unknown revisions", () => {
  const valid = fixture(3);
  assert.doesNotThrow(() => reconcileAuthenticatedRevisionLineage(valid.definitions, valid.eligible));
  const cases = [
    ["missing E1", (value) => value.recoveryHistory.shift()],
    ["missing E2", (value) => value.recoveryHistory.splice(1, 1)],
    ["reordered history", (value) => value.recoveryHistory.reverse()],
    ["duplicate identical generation", (value) => value.recoveryHistory.splice(1, 0, structuredClone(value.recoveryHistory[1]))],
    ["duplicate conflicting generation", (value) => value.recoveryHistory.splice(1, 0, { ...value.recoveryHistory[1], taskDefinitionArn: value.recoveryHistory[2].taskDefinitionArn })],
    ["wrong predecessor", (value) => { value.recoveryHistory[1].initialRevisionCensusSha256 = hex(91); }],
    ["wrong candidate fingerprint", (value) => { value.recoveryHistory[1].candidateFingerprint = hex(92); }],
    ["wrong task-definition fingerprint", (value) => { value.recoveryHistory[1].taskDefinitionFingerprint = hex(93); }],
    ["same candidate claimed twice", (value) => { value.recoveryHistory[2].taskDefinitionArn = value.recoveryHistory[1].taskDefinitionArn; value.recoveryHistory[2].taskDefinitionFingerprint = value.recoveryHistory[1].taskDefinitionFingerprint; value.recoveryHistory[2].candidateFingerprint = value.recoveryHistory[1].candidateFingerprint; }],
    ["two candidates claim one predecessor", (value) => { value.recoveryHistory[1].initialRevisionCensusSha256 = value.recoveryHistory[0].initialRevisionCensusSha256; }],
    ["registration zero gained revision", (value) => { value.recoveryHistory[1].registrations = 0; }],
    ["registration one lacks candidate", (value) => value.definitions.splice(2, 1)],
    ["historical candidate disappeared", (value) => value.definitions.splice(1, 1)],
    ["caller order cannot manufacture trust", (value) => value.recoveryHistory.unshift(value.recoveryHistory.pop())],
  ];
  for (const [label, mutate] of cases) {
    const value = fixture(3);
    mutate(value);
    value.eligible.recoveryHistory = value.recoveryHistory;
    assert.throws(() => reconcileAuthenticatedRevisionLineage(value.definitions, value.eligible), undefined, label);
  }

  for (const [label, insertAt] of [["unknown between generations", 2], ["unknown after final generation", 4], ["healthy unrelated newer revision", 4], ["concurrent deployment", 4]]) {
    const value = fixture(3);
    const unknown = revision(insertAt);
    unknown.taskDefinition.taskDefinitionArn = unknown.taskDefinition.taskDefinitionArn.replace(`:${47 + insertAt}`, `:${60 + insertAt}`);
    unknown.taskDefinition.revision = 60 + insertAt;
    unknown.taskDefinition.containerDefinitions[0].cpu = 999;
    if (insertAt === 2) value.definitions.splice(2, 0, unknown); else value.definitions.push(unknown);
    assert.throws(() => reconcileAuthenticatedRevisionLineage(value.definitions, value.eligible), /unknown|missing|concurrent|lineage/, label);
  }
});

test("semantic tampering cannot change an authenticated generation", () => {
  for (const [field, value] of [
    ["sourceSha", "b".repeat(40)],
    ["service", "another-service"],
    ["workflowRunId", "999"],
    ["recoveryImageDigest", `sha256:${hex(999)}`],
  ]) {
    const original = fixture(3);
    const changed = structuredClone(original.recoveryHistory);
    changed[1][field] = value;
    // The signed envelope is the authority for these fields; changing any byte changes its digest.
    assert.notEqual(canonicalSha256(changed), canonicalSha256(original.recoveryHistory), field);
  }
});

test("AWS pagination or response ordering does not alter canonical lineage", () => {
  const value = fixture(10);
  const ordered = reconcileAuthenticatedRevisionLineage(value.definitions, value.eligible);
  const shuffled = reconcileAuthenticatedRevisionLineage([...value.definitions].sort((left, right) => right.taskDefinition.revision - left.taskDefinition.revision), value.eligible);
  assert.equal(shuffled.identitySha256, ordered.identitySha256);
  assert.deepEqual(shuffled.historyResolutions, ordered.historyResolutions);
});

test("an unknown revision inserted between authenticated generations is never admitted", () => {
  const first = revision(1);
  const unknown = revision(2); unknown.taskDefinition.containerDefinitions[0].cpu = 999;
  const second = revision(3);
  const firstRecord = generationRecord(1, [base], first, { predecessorHistoryLineageSha256: recoveryHistoryLineageSha256([]) });
  const secondRecord = generationRecord(2, [base, first], second, { predecessorHistoryReferenceSha256: hex(4001), predecessorHistoryLineageSha256: recoveryHistoryLineageSha256([firstRecord]) });
  const recoveryHistory = [firstRecord, secondRecord];
  const eligible = { currentTaskDefinitionArn: baseArn, fingerprint: taskDefinitionFingerprint(revision(4), []), recoveryHistory,
    knownFailedRevisions: [firstRecord, secondRecord], interruptedRecoveries: [], rollbackProof: null };
  assert.throws(() => reconcileAuthenticatedRevisionLineage([base, first, unknown, second], eligible), /missing|concurrent|unknown/);
});

test("three sequential generations remain deterministic across every governed mutation checkpoint", () => {
  const states = ["NO_REGISTRATION", "REGISTRATION_RESPONSE_LOST", "REGISTERED_ONLY", "UPDATE_ATTEMPTED", "UPDATE_CONFIRMED"];
  const decisions = new Set(Object.values(INTERRUPTED_RECOVERY_STATE));
  for (const first of states) for (const second of states) for (const third of states) {
    const definitions = [base]; const recoveryHistory = [];
    let currentTaskDefinitionArn = baseArn; let nextRevision = 1;
    for (const [index, state] of [first, second, third].entries()) {
      const candidate = revision(nextRevision);
      candidate.taskDefinition.cpu = String(512 + index);
      const fingerprint = taskDefinitionFingerprint(candidate, candidate.tags || []);
      const registered = state !== "NO_REGISTRATION";
      const responseLost = state === "REGISTRATION_RESPONSE_LOST";
      const targetArn = !registered || responseLost ? null : candidate.taskDefinition.taskDefinitionArn;
      const status = state === "UPDATE_CONFIRMED" ? "SERVICE_UPDATE_CONFIRMED"
        : state === "UPDATE_ATTEMPTED" ? "SERVICE_UPDATE_ATTEMPTED"
          : state === "REGISTERED_ONLY" ? "TASK_DEFINITION_REGISTERED_ONLY" : "TASK_DEFINITION_REGISTRATION_ATTEMPTED";
      const record = generationRecord(index + 1, definitions, candidate, {
        currentTaskDefinitionArn, taskDefinitionArn: targetArn, candidateFingerprint: fingerprint, taskDefinitionFingerprint: fingerprint,
        predecessorHistoryLineageSha256: recoveryHistoryLineageSha256(recoveryHistory), status, classification: "INTERRUPTED_MUTATION", failureClassification: null,
        registrations: registered && !responseLost ? 1 : 0, updates: state === "UPDATE_CONFIRMED" ? 1 : 0,
        expectedRevisionCensusSha256: targetArn ? censusSha256([...definitions, candidate]) : null,
      });
      recoveryHistory.push(record);
      if (registered) { definitions.push(candidate); nextRevision += 1; }
      if (state === "UPDATE_CONFIRMED") currentTaskDefinitionArn = candidate.taskDefinition.taskDefinitionArn;
    }
    const next = revision(nextRevision); next.taskDefinition.cpu = "4096";
    const eligible = { currentTaskDefinitionArn, fingerprint: taskDefinitionFingerprint(next, next.tags || []), recoveryHistory,
      knownFailedRevisions: [], interruptedRecoveries: recoveryHistory, rollbackProof: null };
    const lineage = reconcileAuthenticatedRevisionLineage(definitions, eligible);
    const interruption = recoveryHistory.at(-1); const targetArn = lineage.historyResolutions.at(-1).targetArn;
    const progressing = interruption.status === "SERVICE_UPDATE_CONFIRMED";
    const service = { serviceName: BACKEND_HEALTH_RECOVERY.service, taskDefinition: currentTaskDefinitionArn, desiredCount: 2,
      runningCount: 0, pendingCount: progressing ? 1 : 0, networkConfiguration: {}, loadBalancers: [],
      deployments: progressing ? [{ id: "ecs-svc/3599551810517927503", taskDefinition: targetArn, rolloutState: "IN_PROGRESS", createdAt: "2026-08-24T18:00:00.000Z" }] : [] };
    const result = classifyInterruptedRecoveryState(interruption, { service, census: definitions, runningTasks: [], stoppedTasks: [], health: null }, { lineage });
    assert.equal(decisions.has(result.classification), true, `${first}/${second}/${third}`);
  }
});

test("three-generation interrupted recovery state space has one deterministic decision", () => {
  const value = fixture(3);
  const interruption = value.recoveryHistory[2];
  const targetArn = interruption.taskDefinitionArn;
  const targetImage = value.definitions[3].taskDefinition.containerDefinitions[0].image;
  const deployment = { id: "ecs-svc/3599551810517927503", taskDefinition: targetArn, rolloutState: "FAILED", createdAt: "2026-08-24T18:00:00.000Z" };
  const service = (taskDefinition, overrides = {}) => ({ serviceName: BACKEND_HEALTH_RECOVERY.service, taskDefinition, desiredCount: 2, runningCount: 0, pendingCount: 0, networkConfiguration: {}, loadBalancers: [], deployments: taskDefinition === targetArn ? [deployment] : [], ...overrides });
  const stoppedTasks = [1, 2].map((number) => ({
    taskArn: `arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/${String(number).padStart(32, "0")}`,
    startedBy: deployment.id,
    taskDefinitionArn: targetArn,
    createdAt: `2026-08-24T18:0${number}:00.000Z`,
    stoppedAt: `2026-08-24T18:0${number}:30.000Z`,
    stoppedReason: "ResourceInitializationError: exact runtime dependency denied",
    containers: [{ name: "backend", image: targetImage, imageDigest: interruption.recoveryImageDigest }],
  }));
  const cases = [
    ["service remains predecessor", service(interruption.currentTaskDefinitionArn), "RESUME_EXACT_CANDIDATE", { ...interruption, status: "SERVICE_UPDATE_ATTEMPTED", updates: 0 }],
    ["candidate healthy", service(targetArn, { runningCount: 2, deployments: [{ ...deployment, rolloutState: "COMPLETED" }] }), "ACCEPT_AUTHENTICATED_HEALTHY_CONVERGENCE", interruption, { runningTasks: [1, 2].map(() => ({ taskDefinitionArn: targetArn, imageDigest: interruption.recoveryImageDigest, healthStatus: "HEALTHY" })), health: { healthy: true, success: true, status: "ready" } }],
    ["candidate failed", service(targetArn), "SUPERSEDE_AUTHENTICATED_FAILED_CANDIDATE", interruption, { stoppedTasks }],
    ["candidate progressing", service(targetArn, { pendingCount: 1, deployments: [{ ...deployment, rolloutState: "IN_PROGRESS" }] }), "WAIT_BOUNDED_PROGRESS", interruption],
    ["concurrent revision", service(revision(9).taskDefinition.taskDefinitionArn), "FAIL_CLOSED_UNKNOWN_STATE", interruption],
  ];
  const decision = {
    [INTERRUPTED_RECOVERY_STATE.NO_EFFECT]: "RESUME_EXACT_CANDIDATE",
    [INTERRUPTED_RECOVERY_STATE.RESUMABLE]: "RESUME_EXACT_CANDIDATE",
    [INTERRUPTED_RECOVERY_STATE.FAILED]: "SUPERSEDE_AUTHENTICATED_FAILED_CANDIDATE",
    [INTERRUPTED_RECOVERY_STATE.SUCCEEDED]: "ACCEPT_AUTHENTICATED_HEALTHY_CONVERGENCE",
    [INTERRUPTED_RECOVERY_STATE.PROGRESSING]: "WAIT_BOUNDED_PROGRESS",
  };
  for (const [label, liveService, expected, record, overrides = {}] of cases) {
    const history = [...value.recoveryHistory.slice(0, -1), record];
    const lineage = reconcileAuthenticatedRevisionLineage(value.definitions, { ...value.eligible, recoveryHistory: history });
    const snapshot = { service: liveService, census: value.definitions, runningTasks: [], stoppedTasks: [], health: null, ...overrides };
    let actual;
    try { actual = decision[classifyInterruptedRecoveryState(record, snapshot, { lineage }).classification]; }
    catch { actual = "FAIL_CLOSED_UNKNOWN_STATE"; }
    assert.equal(actual, expected, label);
    assert.equal(["RESUME_EXACT_CANDIDATE", "SUPERSEDE_AUTHENTICATED_FAILED_CANDIDATE", "ACCEPT_AUTHENTICATED_HEALTHY_CONVERGENCE", "WAIT_BOUNDED_PROGRESS", "FAIL_CLOSED_UNKNOWN_STATE"].filter((item) => item === actual).length, 1, label);
  }
});
