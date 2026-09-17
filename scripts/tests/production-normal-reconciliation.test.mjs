import assert from "node:assert/strict";
import test from "node:test";
import { createProductionComponentDeploymentState, createProductionComponentDeploymentStateClient, advanceProductionComponentDeploymentState, PRODUCTION_COMPONENT_STATE } from "../aws/production-component-deployment-state.mjs";
import { assertNormalDeploymentReceipt, NORMAL_RECEIPT_WORKFLOW } from "../aws/production-normal-receipt-contract.mjs";
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
  const live = structuredClone(stored.components), calls = [], candidates = Object.fromEntries(affected.map((name) => [name, identity(name, "b", 2)]));
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
    verify: async (expected) => { for (const [name, value] of Object.entries(expected)) assert.deepEqual(live[name], value); calls.push("verified"); },
    rollback: async (name, predecessor, candidate) => { assert.deepEqual(live[name], candidate); live[name] = structuredClone(predecessor); calls.push(`rollback-${name}`); },
  };
  return { client, live, calls, candidates, receipt, adapters, get state() { return structuredClone(stored); }, set state(value) { stored = structuredClone(value); }, fail(value) { failure = value; },
    reconcile: (source = "c") => reconcileNormalDeployment({ client, sourceSha: sha(source), isAncestor, ...adapters, writerContext: context }) };
}

async function deploy(f, affected = names) {
  const sourceSha = f.candidates[affected[0]].sourceSha;
  const plan = buildNormalReleasePlan({ sourceSha, changedFiles: affected.map((name) => name === "backend" ? "backend/src/services/batchService.ts" : "src/App.tsx"), images: f.receipt.images });
  const component = (name) => ({ deploy: async (_, { recordCandidate }) => {
    await recordCandidate(f.candidates[name].taskDefinitionArn);
    assert.deepEqual(f.state.normalDeploymentReceipt.candidates[name], f.candidates[name]);
    f.live[name] = structuredClone(f.candidates[name]); f.calls.push(`mutate-${name}`);
    return name === "backend" ? { candidateTaskDefinition: f.candidates[name].taskDefinitionArn, deployedBackendDigest: f.candidates[name].imageDigest } : { candidateTaskDefinitionArn: f.candidates[name].taskDefinitionArn, imageRef: f.receipt.images[name] };
  }, rollback: async () => { f.live[name] = identity(name, "a", 1); f.calls.push(`rollback-${name}`); } });
  return executeNormalComponentTransaction({ plan, sourceSha, state: f.state, stateClient: f.client, backend: component("backend"), frontend: component("frontend"), smoke: async () => f.calls.push("smoke"), verifyCandidates: f.adapters.verify, isAncestor, writerContext: context });
}

for (const affected of [["backend"], ["frontend"], names]) {
  test(`${affected.join("+")} happy path persists intent before mutation and atomically commits after verified receipt`, async () => {
    const f = fixture(affected); await deploy(f, affected);
    assert.equal(f.state.normalDeploymentReceipt, undefined);
    for (const name of names) assert.equal(f.state.components[name].sourceSha, sha(affected.includes(name) ? "b" : "a"));
    assert.ok(f.calls.indexOf("receipt-write") < f.calls.indexOf(`mutate-${affected[0]}`));
    assert.ok(f.calls.indexOf("smoke") < f.calls.indexOf("state-commit"));
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
        concurrent.components[changedComponent] = changedComponent === "security" ? { sourceSha: sha("a"), releaseIdentity: "independent-verified-security" } : identity("backend", "c", 3);
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
