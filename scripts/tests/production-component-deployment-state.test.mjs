import assert from "node:assert/strict";
import test from "node:test";
import { createProductionComponentDeploymentState, advanceProductionComponentDeploymentState, advanceProductionComponentDeploymentStateWithRetry, bootstrapProductionComponentDeploymentState, componentStateCasRequest, createProductionComponentDeploymentStateClient, PRODUCTION_COMPONENT_STATE } from "../aws/production-component-deployment-state.mjs";
const sha = (value) => value.repeat(40); const digest = (value) => `sha256:${value.repeat(64)}`;
const component = (name, value) => ({ sourceSha: sha(value), establishedThroughSha: sha(value), imageDigest: digest(value), taskDefinitionArn: `arn:aws:ecs:eu-west-2:368992683803:task-definition/${name}:1`, desiredCount: 2 });
const initial = () => createProductionComponentDeploymentState({ components: { backend: component("backend", "a"), frontend: component("frontend", "a"), database: null, security: null } });
test("component state CAS preserves unrelated live identities and rejects stale writers", () => {
  const state = initial(), next = advanceProductionComponentDeploymentState({ current: state, expectedGeneration: 1, lane: "NORMAL_APPLICATION", changes: { backend: component("backend", "b") } });
  assert.equal(next.components.frontend.sourceSha, sha("a")); assert.equal(next.components.frontend.establishedThroughSha, sha("a")); assert.equal(next.components.backend.sourceSha, sha("b"));
  assert.throws(() => advanceProductionComponentDeploymentState({ current: state, expectedGeneration: 2, lane: "NORMAL_APPLICATION", changes: { frontend: component("frontend", "b") } }));
  assert.throws(() => advanceProductionComponentDeploymentState({ current: state, expectedGeneration: 1, lane: "SECURITY_INFRASTRUCTURE", changes: {} }), /mutation set/);
  assert.equal(componentStateCasRequest({ current: state, next }).ConditionExpression, "#generation = :generation");
});
test("DynamoDB client fixes table/key and emits conditional initialize and update requests", () => {
  const calls = [], state = initial(); const client = createProductionComponentDeploymentStateClient({ run: (args) => { calls.push(args); return "{}"; } });
  client.initialize(state); client.advance(state, advanceProductionComponentDeploymentState({ current: state, expectedGeneration: 1, lane: "NORMAL_APPLICATION", changes: { backend: component("backend", "b") } }));
  assert(calls.every((args) => args.includes(PRODUCTION_COMPONENT_STATE.table) && args.includes(PRODUCTION_COMPONENT_STATE.region)));
  assert(calls[0].includes("attribute_not_exists(#key)")); assert(calls[1].includes("#generation = :generation"));
});

test("conditional CAS retries only an unrelated component update and rejects a same-component race", () => {
  const state = initial();
  const frontend = advanceProductionComponentDeploymentState({ current: state, expectedGeneration: 1, lane: "NORMAL_APPLICATION", changes: { frontend: component("frontend", "b") } });
  let calls = 0;
  const client = {
    advance() { calls += 1; if (calls === 1) throw Object.assign(new Error("ConditionalCheckFailedException"), { code: "ConditionalCheckFailedException" }); },
    read() { return frontend; },
  };
  const result = advanceProductionComponentDeploymentStateWithRetry({ client, current: state, lane: "NORMAL_APPLICATION", changes: { backend: component("backend", "b") }, now: () => "2026-01-01T00:00:00.000Z" });
  assert.equal(result.reconciledUnrelatedConcurrentUpdate, true); assert.equal(result.state.generation, 3);
  assert.equal(result.state.components.frontend.sourceSha, sha("b")); assert.equal(result.state.components.frontend.establishedThroughSha, sha("b")); assert.equal(result.state.components.backend.sourceSha, sha("b"));
  assert.throws(() => advanceProductionComponentDeploymentStateWithRetry({ client: { advance: () => { throw Object.assign(new Error("ConditionalCheckFailedException"), { code: "ConditionalCheckFailedException" }); }, read: () => advanceProductionComponentDeploymentState({ current: state, expectedGeneration: 1, lane: "NORMAL_APPLICATION", changes: { backend: component("backend", "c") } }) }, current: state, lane: "NORMAL_APPLICATION", changes: { backend: component("backend", "b") } }), /Concurrent update changed backend/);
});

test("an exact terminal retry is idempotent without another DynamoDB write", () => {
  const state = initial(); let writes = 0;
  const result = advanceProductionComponentDeploymentStateWithRetry({ client: { read: () => state, advance: () => { writes += 1; } }, current: state, lane: "SECURITY_INFRASTRUCTURE", changes: { security: state.components.security } });
  assert.equal(result.alreadyCurrent, true); assert.equal(result.attempts, 0); assert.equal(writes, 0);
});

test("bootstrap is conditional-only, malformed state is rejected, and recovery regression needs authenticated identity", () => {
  const state = bootstrapProductionComponentDeploymentState({ components: initial().components, now: "2026-01-01T00:00:00.000Z" });
  assert.equal(state.generation, 1);
  assert.throws(() => createProductionComponentDeploymentState({ components: { ...state.components, backend: { sourceSha: "unknown" } } }));
  assert.throws(() => createProductionComponentDeploymentState({ components: { ...state.components, backend: { ...state.components.backend, establishedThroughSha: "unknown" } } }));
  assert.throws(() => advanceProductionComponentDeploymentState({ current: state, expectedGeneration: 1, lane: "NORMAL_APPLICATION", changes: { backend: { ...component("backend", "b"), establishedThroughSha: sha("c") } } }), /must establish/);
  assert.throws(() => advanceProductionComponentDeploymentState({ current: state, expectedGeneration: 1, lane: "EMERGENCY_RECOVERY", recovery: true, changes: { backend: component("backend", "0") } }), /authenticated historical identity/);
  assert.doesNotThrow(() => advanceProductionComponentDeploymentState({ current: state, expectedGeneration: 1, lane: "EMERGENCY_RECOVERY", recovery: true, authenticateRecovery: () => true, changes: { backend: component("backend", "0") } }));
});

test("DynamoDB read decodes only the fixed exact key and initialize failure remains fail-closed", () => {
  const state = initial();
  const item = { stateKey: { S: PRODUCTION_COMPONENT_STATE.key }, generation: { N: "1" }, state: { S: JSON.stringify(state) } };
  const client = createProductionComponentDeploymentStateClient({ run: (args) => args[1] === "get-item" ? JSON.stringify({ Item: item }) : (() => { throw Object.assign(new Error("ConditionalCheckFailedException"), { code: "ConditionalCheckFailedException" }); })() });
  assert.deepEqual(client.read(), state);
  assert.throws(() => client.initialize(state), /ConditionalCheckFailedException/);
  const malformed = createProductionComponentDeploymentStateClient({ run: () => JSON.stringify({ Item: { ...item, stateKey: { S: "other" } } }) });
  assert.throws(() => malformed.read(), /production#T-ej2003/);
});
