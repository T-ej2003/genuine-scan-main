import assert from "node:assert/strict";
import test from "node:test";
import { createProductionComponentDeploymentState, createProductionComponentDeploymentStateClient, advanceProductionComponentDeploymentState, normalDeploymentLiveComponents, PRODUCTION_COMPONENT_STATE } from "../aws/production-component-deployment-state.mjs";
import { assertNormalDeploymentReceipt, NORMAL_DEPLOYABLE_COMPONENTS, NORMAL_RECEIPT_WORKFLOW } from "../aws/production-normal-receipt-contract.mjs";
import { reconcileNormalDeployment, replaceNormalDeploymentReceipt } from "../aws/production-normal-reconciliation.mjs";
import { buildNormalReleasePlan, executeNormalComponentTransaction, createNormalReconciliationAdapters } from "../aws/production-normal-release.mjs";
import { buildProductionNormalDeploymentPlan } from "../aws/prepare-production-normal-deployment.mjs";

const sha = (letter) => letter.repeat(40);
const names = ["backend", "frontend"];
const family = { backend: "mscqr-production-rls-green-backend-candidate", frontend: "mscqr-frontend" };
const identity = (name, letter, revision) => ({ sourceSha: sha(letter), establishedThroughSha: sha(letter), imageDigest: `sha256:${letter.repeat(64)}`, taskDefinitionArn: `arn:aws:ecs:eu-west-2:368992683803:task-definition/${family[name]}:${revision}`, desiredCount: 2 });
const image = (name, value) => `368992683803.dkr.ecr.eu-west-2.amazonaws.com/${name === "backend" ? "mscqr-backend" : "mscqr-web"}@${value.imageDigest}`;
const context = { updatedByWorkflow: NORMAL_RECEIPT_WORKFLOW, githubRunId: "123" };
const isAncestor = (a, b) => a <= b;

function fixture(affected = names) {
  let stored = createProductionComponentDeploymentState({ components: { backend: identity("backend", "a", 1), frontend: identity("frontend", "a", 1), database: null, security: null } });
  const live = structuredClone(stored.components), calls = [], verifiedSets = [], candidates = Object.fromEntries(affected.map((name) => [name, identity(name, "b", 2)]));
  let failure;
  // Exercise the production client, including actual low-level DynamoDB shapes.
  const client = createProductionComponentDeploymentStateClient({ run(args) {
    const get = (key) => args[args.indexOf(key) + 1];
    assert.equal(get("--table-name"), PRODUCTION_COMPONENT_STATE.table);
    assert.equal(get("--region"), PRODUCTION_COMPONENT_STATE.region);
    assert.deepEqual(JSON.parse(get("--key")), { stateKey: { S: PRODUCTION_COMPONENT_STATE.key } });
    if (args[1] === "get-item") {
      assert.ok(args.includes("--consistent-read"));
      return JSON.stringify({ Item: { stateKey: { S: PRODUCTION_COMPONENT_STATE.key }, generation: { N: String(stored.generation) }, state: { S: JSON.stringify(stored) } } });
    }
    assert.equal(args[1], "update-item");
    assert.equal(get("--condition-expression"), "#generation = :generation");
    const values = JSON.parse(get("--expression-attribute-values"));
    if (values[":generation"].N !== String(stored.generation)) throw new Error("ConditionalCheckFailedException");
    const next = JSON.parse(values[":state"].S); assert.equal(next.generation, stored.generation + 1);
    const terminal = !next.normalDeploymentReceipt && affected.every((name) => next.components[name].sourceSha === sha("b"));
    if (terminal && failure === "definite") throw new Error("DynamoDB unavailable");
    stored = next; calls.push(terminal ? "state-commit" : "receipt-write");
    if (terminal && failure === "ambiguous") throw new Error("Connection lost after write");
    return "{}";
  } });
  const receipt = { schemaVersion: 1, kind: "NORMAL_DEPLOYMENT_RECEIPT", workflow: NORMAL_RECEIPT_WORKFLOW, githubRunId: "123", sourceSha: sha("b"), planSha256: "1".repeat(64), phase: "PREPARED",
    predecessors: Object.fromEntries(affected.map((name) => [name, stored.components[name]])), images: Object.fromEntries(affected.map((name) => [name, image(name, candidates[name])])), candidates: {} };
  const adapters = {
    readLive: async (name) => structuredClone(live[name]),
    authenticateCandidate: async (name, predecessor, candidate) => { assert.deepEqual(candidate, candidates[name]); assert.deepEqual(predecessor, identity(name, "a", 1)); },
    verify: async (expected) => { verifiedSets.push(Object.keys(expected).sort()); for (const [name, value] of Object.entries(expected)) assert.deepEqual(live[name], value); calls.push("verified"); },
    rollback: async (name, predecessor, candidate) => { assert.deepEqual(live[name], candidate); live[name] = structuredClone(predecessor); calls.push(`rollback-${name}`); },
  };
  return { client, live, calls, verifiedSets, candidates, receipt, adapters, get state() { return structuredClone(stored); }, set state(value) { stored = structuredClone(value); }, fail(value) { failure = value; },
    reconcile: (source = "c") => reconcileNormalDeployment({ client, sourceSha: sha(source), isAncestor, ...adapters, writerContext: context }) };
}

async function deploy(f, affected = names, stateClient = f.client) {
  const sourceSha = f.candidates[affected[0]].sourceSha;
  const plan = buildNormalReleasePlan({ sourceSha, changedFiles: affected.map((name) => name === "backend" ? "backend/src/services/batchService.ts" : "src/App.tsx"), images: f.receipt.images });
  const component = (name) => ({ deploy: async (_, { recordCandidate }) => {
    await recordCandidate(f.candidates[name].taskDefinitionArn);
    assert.deepEqual(f.state.normalDeploymentReceipt.candidates[name], f.candidates[name]);
    f.live[name] = structuredClone(f.candidates[name]); f.calls.push(`mutate-${name}`);
    return name === "backend" ? { candidateTaskDefinition: f.candidates[name].taskDefinitionArn, deployedBackendDigest: f.candidates[name].imageDigest } : { candidateTaskDefinitionArn: f.candidates[name].taskDefinitionArn, imageRef: f.receipt.images[name] };
  }, rollback: async () => { f.live[name] = identity(name, "a", 1); f.calls.push(`rollback-${name}`); } });
  return executeNormalComponentTransaction({ plan, sourceSha, state: f.state, stateClient, backend: component("backend"), frontend: component("frontend"), smoke: async () => f.calls.push("smoke"), verifyCandidates: f.adapters.verify, isAncestor, writerContext: context });
}

for (const affected of [["backend"], ["frontend"], names]) {
  test(`${affected.join("+")} happy path persists intent before mutation and atomically commits after verified receipt`, async () => {
    const f = fixture(affected); await deploy(f, affected);
    assert.equal(f.state.normalDeploymentReceipt, undefined);
    for (const name of names) assert.equal(f.state.components[name].sourceSha, sha(affected.includes(name) ? "b" : "a"));
    assert.ok(f.calls.indexOf("receipt-write") < f.calls.indexOf(`mutate-${affected[0]}`));
    assert.ok(f.calls.indexOf("smoke") < f.calls.indexOf("state-commit"));
    assert.ok(f.verifiedSets.every((set) => JSON.stringify(set) === JSON.stringify(names)), "Every successful verification covers the complete live-component set");
  });
  for (const failure of ["definite", "ambiguous"]) test(`${affected.join("+")} ${failure} terminal: current main D reconciles B without another ECS mutation`, async () => {
    const f = fixture(affected); f.fail(failure); await assert.rejects(deploy(f, affected));
    const writes = f.calls.filter((call) => call.startsWith("mutate-")).length;
    f.fail(undefined); await f.reconcile("d"); await f.reconcile("d");
    assert.equal(f.calls.filter((call) => call.startsWith("mutate-")).length, writes);
    assert.equal(f.state.normalDeploymentReceipt, undefined);
    for (const name of affected) assert.deepEqual(f.state.components[name], f.candidates[name]);
    const ranges = [];
    buildProductionNormalDeploymentPlan({ sourceSha: sha("d"), state: f.state, isAncestor, readRange: (base, candidate) => { ranges.push([base, candidate]); return []; } });
    assert.ok(ranges.some(([base, candidate]) => base === sha("b") && candidate === sha("d")));
  });
}

for (const mutated of [[], ["backend"], ["frontend"], names]) test(`runner death before verified receipt with ${mutated.join("+") || "no"} mutations rolls back only recorded candidates`, async () => {
  const f = fixture();
  const pending = { ...f.receipt, candidates: f.candidates };
  replaceNormalDeploymentReceipt({ client: f.client, expected: undefined, receipt: pending, writerContext: context });
  for (const name of mutated) f.live[name] = structuredClone(f.candidates[name]);
  await f.reconcile();
  assert.deepEqual(f.live.backend, identity("backend", "a", 1)); assert.deepEqual(f.live.frontend, identity("frontend", "a", 1));
  assert.deepEqual(f.calls.filter((call) => call.startsWith("rollback-")), [...mutated].reverse().map((name) => `rollback-${name}`));
  assert.equal(f.state.normalDeploymentReceipt, undefined);
});

test("unknown live identity is never adopted, including current-main source with no registered mutation intent", async () => {
  const f = fixture();
  replaceNormalDeploymentReceipt({ client: f.client, expected: undefined, receipt: f.receipt, writerContext: context });
  f.live.backend = identity("backend", "b", 2);
  await assert.rejects(f.reconcile(), /LIVE_IS_UNKNOWN/);
  assert.equal(f.calls.includes("state-commit"), false);
});

test("committed component state is authenticated against live services before new classification", async () => {
  const f = fixture();
  await f.reconcile("b");
  assert.deepEqual(f.calls, ["verified"]);
  f.live.backend = identity("backend", "b", 2);
  await assert.rejects(f.reconcile("b"));
  assert.equal(f.state.normalDeploymentReceipt, undefined);
  assert.deepEqual(f.state.components.backend, identity("backend", "a", 1));
});

test("live component schema is the single source for complete-set verification", () => {
  const f = fixture(["backend"]);
  assert.deepEqual(NORMAL_DEPLOYABLE_COMPONENTS, names);
  assert.deepEqual(Object.keys(normalDeploymentLiveComponents(f.state)), names);
  assert.deepEqual(normalDeploymentLiveComponents(f.state, { backend: f.candidates.backend }), { backend: f.candidates.backend, frontend: identity("frontend", "a", 1) });
  assert.throws(() => normalDeploymentLiveComponents(f.state, { worker: {} }), /not a normal deployable component/);
  const source = reconcileNormalDeployment.toString();
  assert.equal((source.match(/\breturn\b/g) || []).length, 1, "Reconciliation must retain one verified success exit");
  assert.match(source, /await verify\(normalDeploymentLiveComponents\(state\)\);[\s\S]*return state;/);
  assert.doesNotMatch(source, /verify\(receipt\.(?:candidates|predecessors)\)/, "Receipt subsets cannot authorize reconciliation closure");
});

const unrelatedDriftCases = [
  ["backend", "frontend", "taskDefinitionArn", identity("frontend", "c", 3).taskDefinitionArn],
  ["backend", "frontend", "imageDigest", `sha256:${"c".repeat(64)}`],
  ["backend", "frontend", "missing", null],
  ["frontend", "backend", "taskDefinitionArn", identity("backend", "c", 3).taskDefinitionArn],
  ["frontend", "backend", "imageDigest", `sha256:${"c".repeat(64)}`],
  ["frontend", "backend", "missing", null],
];

for (const [affected, unrelated, drift, value] of unrelatedDriftCases) {
  for (const receiptPhase of ["PREPARED", "VERIFIED"]) test(`${affected}-only ${receiptPhase} reconciliation fails closed on unrelated ${unrelated} ${drift}`, async () => {
    const f = fixture([affected]);
    if (receiptPhase === "VERIFIED") { f.fail("definite"); await assert.rejects(deploy(f, [affected])); f.fail(undefined); }
    else replaceNormalDeploymentReceipt({ client: f.client, expected: undefined, receipt: f.receipt, writerContext: context });
    if (drift === "missing") f.live[unrelated] = null;
    else f.live[unrelated][drift] = value;
    await assert.rejects(f.reconcile(), /Expected values to be strictly deep-equal/);
    assert.ok(f.state.normalDeploymentReceipt, "Unrelated drift must retain recoverable transaction state");
  });
}

test("a component outside the receipt changing between receipt read and closure fails closed", async () => {
  const f = fixture(["backend"]); f.fail("definite"); await assert.rejects(deploy(f, ["backend"])); f.fail(undefined);
  const authenticate = f.adapters.authenticateCandidate;
  f.adapters.authenticateCandidate = async (...args) => { await authenticate(...args); f.live.frontend = identity("frontend", "c", 3); };
  await assert.rejects(f.reconcile(), /Expected values to be strictly deep-equal/);
  assert.ok(f.state.normalDeploymentReceipt);
});

test("live drift after full-set verification is caught after receipt commit and blocks the next rerun", async () => {
  const f = fixture(["backend"]); f.fail("definite"); await assert.rejects(deploy(f, ["backend"])); f.fail(undefined);
  const verify = f.adapters.verify; let first = true;
  f.adapters.verify = async (values) => { await verify(values); if (first) { first = false; f.live.frontend = identity("frontend", "c", 3); } };
  await assert.rejects(f.reconcile(), /Expected values to be strictly deep-equal/);
  assert.equal(f.state.normalDeploymentReceipt, undefined, "The exact candidate CAS may commit, but the invocation must fail on post-CAS drift");
  await assert.rejects(f.reconcile(), /Expected values to be strictly deep-equal/);
});

for (const phase of ["VERIFIED_COMMIT", "ROLLBACK_CLEAR"]) test(`${phase} loses a generation race instead of carrying verification across it`, async () => {
  const f = fixture(["backend"]);
  if (phase === "VERIFIED_COMMIT") { f.fail("definite"); await assert.rejects(deploy(f, ["backend"])); f.fail(undefined); }
  else replaceNormalDeploymentReceipt({ client: f.client, expected: undefined, receipt: f.receipt, writerContext: context });
  let raced = false;
  const client = { read: f.client.read, advance(current, next) {
    if (!raced && !next.normalDeploymentReceipt) {
      raced = true;
      f.state = advanceProductionComponentDeploymentState({ current: f.state, expectedGeneration: f.state.generation, lane: "SECURITY_INFRASTRUCTURE",
        changes: { security: { sourceSha: sha("a"), releaseIdentity: "concurrent-security" } }, ...context });
      throw new Error("ConditionalCheckFailedException");
    }
    return f.client.advance(current, next);
  } };
  await assert.rejects(reconcileNormalDeployment({ client, sourceSha: sha("c"), isAncestor, ...f.adapters, writerContext: context }), /ConditionalCheckFailedException/);
  assert.ok(f.state.normalDeploymentReceipt, "A closure CAS race must remain explicitly reconcilable");
  await f.reconcile();
  assert.equal(f.state.normalDeploymentReceipt, undefined);
});

test("normal transaction catches live drift introduced after pre-CAS verification", async () => {
  const f = fixture(["backend"]); const verify = f.adapters.verify; let candidateVerified = false;
  f.adapters.verify = async (values) => {
    await verify(values);
    if (values.backend?.sourceSha === sha("b") && !candidateVerified) { candidateVerified = true; f.live.frontend = identity("frontend", "c", 3); }
  };
  await assert.rejects(deploy(f, ["backend"]), /Expected values to be strictly deep-equal/);
  assert.equal(f.state.normalDeploymentReceipt, undefined, "The terminal CAS may linearize before external live drift is observed");
  await assert.rejects(f.reconcile(), /Expected values to be strictly deep-equal/, "Post-CAS drift must remain fail-closed on the next invocation");
});

for (const stillPredecessor of names) test(`dual-component verified receipt with only ${stillPredecessor} at predecessor rolls all candidates back`, async () => {
  const f = fixture(); f.fail("definite"); await assert.rejects(deploy(f)); f.fail(undefined);
  f.live[stillPredecessor] = identity(stillPredecessor, "a", 1);
  await f.reconcile();
  assert.deepEqual(names.map((name) => f.state.components[name].sourceSha), [sha("a"), sha("a")]);
  assert.equal(f.state.normalDeploymentReceipt, undefined);
});

test("a receipt component absent from committed state fails before any reconciliation mutation", async () => {
  const f = fixture(["backend"]);
  replaceNormalDeploymentReceipt({ client: f.client, expected: undefined, receipt: f.receipt, writerContext: context });
  const malformed = f.state; malformed.components.backend = null; delete malformed.componentProvenance.backend; f.state = malformed;
  await assert.rejects(f.reconcile(), /predecessor is stale/);
  assert.ok(f.state.normalDeploymentReceipt);
});

for (const boundary of ["VERIFIED_RECEIPT", "TERMINAL_COMMIT"]) test(`normal transaction ${boundary} CAS race retains a reconcilable receipt`, async () => {
  const f = fixture(["backend"]); let raced = false;
  const client = { read: f.client.read, advance(current, next) {
    const atBoundary = boundary === "VERIFIED_RECEIPT" ? next.normalDeploymentReceipt?.phase === "VERIFIED" : !next.normalDeploymentReceipt && next.components.backend.sourceSha === sha("b");
    if (!raced && atBoundary) {
      raced = true;
      f.state = advanceProductionComponentDeploymentState({ current: f.state, expectedGeneration: f.state.generation, lane: "SECURITY_INFRASTRUCTURE",
        changes: { security: { sourceSha: sha("a"), releaseIdentity: `race-${boundary}` } }, ...context });
      throw new Error("ConditionalCheckFailedException");
    }
    return f.client.advance(current, next);
  } };
  await assert.rejects(deploy(f, ["backend"], client), /ConditionalCheckFailedException/);
  assert.ok(f.state.normalDeploymentReceipt);
  await f.reconcile();
  assert.equal(f.state.normalDeploymentReceipt, undefined);
});

test("same-commit rerun reconciles a verified candidate before deriving an empty authoritative work set", async () => {
  const f = fixture(["backend"]); f.fail("definite");
  await assert.rejects(deploy(f, ["backend"]));
  f.fail(undefined);
  await f.reconcile("b");
  const ranges = [];
  const plan = buildProductionNormalDeploymentPlan({ sourceSha: sha("b"), state: f.state, isAncestor,
    readRange: (base, target) => { ranges.push([base, target]); return []; } });
  assert.ok(ranges.some(([base, target]) => base === sha("b") && target === sha("b")));
  assert.ok(ranges.some(([base, target]) => base === sha("a") && target === sha("b")));
  assert.equal(plan.classification.backend, false);
  assert.equal(plan.classification.frontend, false);
  assert.equal(plan.componentBaselines.backend, sha("b"));
  assert.equal(f.calls.filter((call) => call === "state-commit").length, 1);
});

for (const field of ["sourceSha", "imageDigest", "taskDefinitionArn", "desiredCount"]) test(`verified intermediate receipt rejects live ${field} mismatch`, async () => {
  const f = fixture(); f.fail("definite"); await assert.rejects(deploy(f)); f.fail(undefined);
  f.live.backend[field] = field === "desiredCount" ? 3 : "unknown";
  await assert.rejects(f.reconcile(), /LIVE_IS_UNKNOWN/);
  assert.equal(f.state.components.backend.sourceSha, sha("a"));
});

test("receipt source bounds, stale predecessor, failed verification, and forged lane evidence reject", async () => {
  const f = fixture(); f.fail("definite"); await assert.rejects(deploy(f)); f.fail(undefined);
  await assert.rejects(f.reconcile("a"), /history/);
  const valid = f.state;
  for (const mutate of [
    (r) => { r.kind = "BACKEND_HEALTH_RECOVERY_EVIDENCE"; },
    (r) => { r.workflow = "other-workflow"; },
    (r) => { r.candidates.backend.sourceSha = sha("c"); },
    (r) => { r.candidates.backend.taskDefinitionArn = r.candidates.frontend.taskDefinitionArn; },
    (r) => { delete r.verification; },
  ]) {
    const receipt = structuredClone(valid.normalDeploymentReceipt); mutate(receipt);
    assert.throws(() => assertNormalDeploymentReceipt(receipt));
  }
  f.state = { ...valid, components: { ...valid.components, backend: identity("backend", "c", 3) } };
  await assert.rejects(f.reconcile(), /predecessor is stale/);
});

test("generation conflict cannot replace a concurrent normal receipt", () => {
  const f = fixture();
  replaceNormalDeploymentReceipt({ client: f.client, expected: undefined, receipt: f.receipt, writerContext: context });
  assert.throws(() => replaceNormalDeploymentReceipt({ client: f.client, expected: undefined, receipt: { ...f.receipt, githubRunId: "456" }, writerContext: context }), /Concurrent normal receipt/);
});

test("receipt CAS retries an unrelated generation change without losing it, but rejects changed predecessors", () => {
  for (const changedComponent of ["security", "backend"]) {
    const f = fixture(["backend"]); let raced = false;
    const client = { read: f.client.read, advance(current, next) {
      if (!raced) {
        raced = true;
        const concurrent = f.state; concurrent.generation++;
        concurrent.updatedAt = "2026-01-02T00:00:00.000Z"; concurrent.updatedByLane = "SECURITY_INFRASTRUCTURE"; concurrent.updatedByWorkflow = "security/workflow.yml@refs/heads/main"; concurrent.githubRunId = "789";
        concurrent.components[changedComponent] = changedComponent === "security" ? { sourceSha: sha("a"), releaseIdentity: "independent-verified-security" } : identity("backend", "c", 3);
        concurrent.componentProvenance[changedComponent] = { lane: "SECURITY_INFRASTRUCTURE", workflow: concurrent.updatedByWorkflow, githubRunId: concurrent.githubRunId, generation: concurrent.generation, updatedAt: concurrent.updatedAt };
        f.state = concurrent;
        throw new Error("ConditionalCheckFailedException");
      }
      return f.client.advance(current, next);
    } };
    const write = () => replaceNormalDeploymentReceipt({ client, expected: undefined, receipt: f.receipt, writerContext: context });
    if (changedComponent === "backend") assert.throws(write, /predecessor changed/);
    else { write(); assert.equal(f.state.components.security.releaseIdentity, "independent-verified-security"); }
  }
});

test("failed rollback keeps durable intent and resumes only the unfinished component", async () => {
  const f = fixture();
  replaceNormalDeploymentReceipt({ client: f.client, expected: undefined, receipt: { ...f.receipt, candidates: f.candidates }, writerContext: context });
  for (const name of names) f.live[name] = structuredClone(f.candidates[name]);
  const original = f.adapters.rollback;
  f.adapters.rollback = async (name, ...args) => { if (name === "backend") throw new Error("ECS unavailable"); return original(name, ...args); };
  await assert.rejects(f.reconcile(), /ECS unavailable/);
  assert.equal(f.state.normalDeploymentReceipt.phase, "ROLLING_BACK");
  assert.deepEqual(f.live.frontend, identity("frontend", "a", 1));
  f.adapters.rollback = original; await f.reconcile();
  assert.deepEqual(f.calls.filter((value) => value.startsWith("rollback-")), ["rollback-frontend", "rollback-backend"]);
});

test("fresh verification failure never commits a previously verified receipt", async () => {
  const f = fixture(); f.fail("definite"); await assert.rejects(deploy(f)); f.fail(undefined);
  const verify = f.adapters.verify;
  f.adapters.verify = async (values) => { if (values.backend.sourceSha === sha("b")) throw new Error("Authenticated smoke failed"); await verify(values); };
  await assert.rejects(f.reconcile(), /smoke failed/);
  assert.equal(f.state.components.backend.sourceSha, sha("a"));
  assert.equal(f.state.components.frontend.sourceSha, sha("a"));
  assert.equal(f.state.normalDeploymentReceipt, undefined);
  assert.deepEqual(f.calls.filter((value) => value.startsWith("rollback-")), ["rollback-frontend", "rollback-backend"]);
});

test("a verified release partly returned to its exact predecessor is rolled back, never partially committed", async () => {
  const f = fixture(); f.fail("definite"); await assert.rejects(deploy(f)); f.fail(undefined);
  f.live.frontend = identity("frontend", "a", 1);
  await f.reconcile();
  assert.equal(f.state.components.backend.sourceSha, sha("a"));
  assert.equal(f.state.components.frontend.sourceSha, sha("a"));
  assert.equal(f.state.normalDeploymentReceipt, undefined);
  assert.deepEqual(f.calls.filter((value) => value.startsWith("rollback-")), ["rollback-backend"]);
});

test("authenticated recovery supersedes only its backend; the pending frontend remains rollback-only", async () => {
  const f = fixture(); f.fail("definite"); await assert.rejects(deploy(f)); f.fail(undefined);
  const restored = identity("backend", "a", 4); restored.establishedThroughSha = sha("c");
  f.live.backend = restored;
  f.state = advanceProductionComponentDeploymentState({ current: f.state, expectedGeneration: f.state.generation, lane: "EMERGENCY_RECOVERY", recovery: true,
    changes: { backend: restored }, authenticateRecovery: ({ next }) => assert.deepEqual(next, restored), ...context });
  assert.equal(f.state.normalDeploymentReceipt.phase, "ROLLING_BACK");
  assert.deepEqual(Object.keys(f.state.normalDeploymentReceipt.predecessors), ["frontend"]);
  await f.reconcile("d");
  assert.deepEqual(f.state.components.backend, restored);
  assert.deepEqual(f.state.components.frontend, identity("frontend", "a", 1));
  assert.deepEqual(f.calls.filter((value) => value.startsWith("rollback-")), ["rollback-frontend"]);
});

test("operator flow A -> B terminal fails -> merge C -> automatic reconcile B -> deploy C", async () => {
  const f = fixture(); f.fail("definite"); await assert.rejects(deploy(f)); f.fail(undefined);
  await f.reconcile();
  assert.deepEqual(names.map((name) => f.state.components[name].sourceSha), [sha("b"), sha("b")]);
  const preparation = buildProductionNormalDeploymentPlan({ sourceSha: sha("c"), state: f.state, isAncestor, readRange: (base) => {
    assert.equal(base, sha("b")); return ["src/App.tsx", "backend/src/services/batchService.ts"];
  } });
  assert.equal(preparation.classification.backend, true); assert.equal(preparation.classification.frontend, true);
  for (const name of names) { f.candidates[name] = identity(name, "c", 3); f.receipt.images[name] = image(name, f.candidates[name]); }
  await deploy(f);
  for (const name of names) assert.deepEqual(f.state.components[name], identity(name, "c", 3));
  assert.deepEqual(f.calls.filter((call) => call.startsWith("mutate-")), ["mutate-backend", "mutate-frontend", "mutate-backend", "mutate-frontend"]);
});

test("no-op changes neither state nor services", async () => {
  const f = fixture(); const before = f.state;
  await executeNormalComponentTransaction({ plan: buildNormalReleasePlan({ sourceSha: sha("c"), changedFiles: ["README.md"] }), sourceSha: sha("c"), state: before, stateClient: f.client });
  assert.deepEqual(f.state, before); assert.deepEqual(f.calls, []);
});

test("actual ECS/ECR read adapter rejects wrong cluster/service/account/digest/source identities", async () => {
  const prefix = "arn:aws:ecs:eu-west-2:368992683803";
  const good = { service: { clusterArn: `${prefix}:cluster/mscqr-prod-euw2-main`, serviceArn: `${prefix}:service/mscqr-prod-euw2-main/mscqr-frontend-servi-euw2`, taskDefinition: identity("frontend", "b", 2).taskDefinitionArn, desiredCount: 2 },
    definition: { taskDefinitionArn: identity("frontend", "b", 2).taskDefinitionArn, containerDefinitions: [{ name: "frontend", image: image("frontend", identity("frontend", "b", 2)) }] },
    image: { registryId: "368992683803", repositoryName: "mscqr-web", imageDigest: identity("frontend", "b", 2).imageDigest, imageTags: [sha("b")] } };
  const read = (fixture) => createNormalReconciliationAdapters({ run: (args) => {
    if (args[1] === "describe-services") return JSON.stringify({ failures: [], services: [fixture.service] });
    if (args[1] === "describe-task-definition") return JSON.stringify({ taskDefinition: fixture.definition });
    if (args[1] === "describe-images") return JSON.stringify({ imageDetails: [fixture.image] });
    throw new Error(`Unexpected AWS command ${args.slice(0, 2)}`);
  } }).readLive("frontend");
  assert.equal((await read(good)).sourceSha, sha("b"));
  for (const mutate of [
    (v) => { v.service.clusterArn += "-other"; },
    (v) => { v.service.serviceArn += "-other"; },
    (v) => { v.definition.taskDefinitionArn += "0"; },
    (v) => { v.image.registryId = "000000000000"; },
    (v) => { v.image.imageDigest = `sha256:${"c".repeat(64)}`; },
    (v) => { v.image.imageTags = [sha("a"), sha("b")]; },
  ]) { const bad = structuredClone(good); mutate(bad); await assert.rejects(read(bad)); }
});
