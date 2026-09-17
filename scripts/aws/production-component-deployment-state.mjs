import assert from "node:assert/strict";
import crypto from "node:crypto";

export const PRODUCTION_COMPONENT_STATE = Object.freeze({ table: "mscqr-production-component-deployment-state", key: "production#T-ej2003/genuine-scan-main", account: "368992683803", region: "eu-west-2", repository: "T-ej2003/genuine-scan-main" });
const SHA = /^[a-f0-9]{40}$/, DIGEST = /^sha256:[a-f0-9]{64}$/;
const components = new Set(["backend", "frontend", "database", "security"]);
const canonical = (value) => JSON.stringify(value);
const clone = (value) => structuredClone(value);
const same = (left, right) => canonical(left) === canonical(right);
const conditionalFailure = (error) => /ConditionalCheckFailedException/.test(`${error?.name || ""}\n${error?.code || ""}\n${error?.message || ""}\n${error?.stderr || ""}`);

export function assertProductionComponentDeploymentState(value) {
  assert.equal(value?.schemaVersion, 1); assert.equal(value.environment, "production"); assert.equal(value.repository, PRODUCTION_COMPONENT_STATE.repository);
  assert.ok(Number.isSafeInteger(value.generation) && value.generation >= 1); assert.match(value.updatedAt || "", /^\d{4}-\d\d-\d\dT/);
  assert.ok(["BOOTSTRAP", "NORMAL_APPLICATION", "SECURITY_INFRASTRUCTURE", "EMERGENCY_RECOVERY"].includes(value.updatedByLane));
  assert.match(value.updatedByWorkflow || "", /^[A-Za-z0-9_.:/@-]{1,512}$/); assert.match(String(value.githubRunId || ""), /^(?:[1-9][0-9]*|bootstrap|local-test)$/);
  assert.deepEqual(Object.keys(value.components || {}).sort(), [...components].sort());
  for (const [name, component] of Object.entries(value.components)) {
    assert.ok(component === null || typeof component === "object", `${name} state malformed`);
    if (!component) continue;
    assert.match(component.sourceSha || "", SHA); assert.match(component.releaseIdentity || component.imageDigest || "", component.imageDigest ? DIGEST : /^.{1,512}$/);
    if (["backend", "frontend"].includes(name)) { assert.match(component.establishedThroughSha || "", SHA); assert.match(component.imageDigest || "", DIGEST); assert.match(component.taskDefinitionArn || "", /^arn:aws:ecs:eu-west-2:368992683803:task-definition\/[^:]+:[1-9][0-9]*$/); assert.ok(Number.isSafeInteger(component.desiredCount) && component.desiredCount > 0, `${name} desired count malformed`); }
  }
  return value;
}

export function createProductionComponentDeploymentState({ components: stateComponents, now = new Date().toISOString(), updatedByWorkflow = "local-test", githubRunId = "local-test" } = {}) {
  return Object.freeze(assertProductionComponentDeploymentState({ schemaVersion: 1, environment: "production", repository: PRODUCTION_COMPONENT_STATE.repository, generation: 1, updatedAt: now, updatedByLane: "BOOTSTRAP", updatedByWorkflow, githubRunId: String(githubRunId), components: stateComponents }));
}

export function advanceProductionComponentDeploymentState({ current, expectedGeneration, lane, changes, now = new Date().toISOString(), recovery = false, isAncestor, authenticateRecovery, updatedByWorkflow = "local-test", githubRunId = "local-test" } = {}) {
  assertProductionComponentDeploymentState(current); assert.equal(expectedGeneration, current.generation); assert.ok(["NORMAL_APPLICATION", "SECURITY_INFRASTRUCTURE", "EMERGENCY_RECOVERY"].includes(lane));
  assert.ok(changes && typeof changes === "object" && !Array.isArray(changes));
  assert.ok(Object.keys(changes).length > 0, "A component-state transition must declare an authenticated component mutation set");
  for (const [name, next] of Object.entries(changes)) {
    assert.ok(components.has(name)); assert.ok(next && typeof next === "object"); assert.match(next.sourceSha || "", SHA);
    if (lane === "NORMAL_APPLICATION") { assert.ok(current.components[name], "Normal deployment requires bootstrapped component state"); assert.equal(recovery, false); if (["backend", "frontend"].includes(name)) assert.equal(next.establishedThroughSha, next.sourceSha, "Normal deployment must establish the deployed candidate source"); }
    if (current.components[name]) {
      const sameSource = next.sourceSha === current.components[name].sourceSha;
      if (sameSource) {
        assert.ok(!same(current.components[name], next), "No-op component update is forbidden");
        assert.notEqual(lane, "NORMAL_APPLICATION", "Normal deployment cannot rewrite a component without a new source identity");
      }
      if (lane === "EMERGENCY_RECOVERY") {
        assert.equal(recovery, true, "Recovery source regression requires the explicit recovery lane");
        assert.equal(typeof authenticateRecovery, "function", "Recovery state changes require authenticated historical identity");
        authenticateRecovery({ component: name, current: current.components[name], next });
      } else if (typeof isAncestor === "function") {
        assert.equal(isAncestor(current.components[name].establishedThroughSha || current.components[name].sourceSha, next.establishedThroughSha || next.sourceSha), true, "Component source transition is not forward protected-main history");
      }
    }
  }
  const next = clone(current); next.generation++; next.updatedAt = now; next.updatedByLane = lane; next.updatedByWorkflow = updatedByWorkflow; next.githubRunId = String(githubRunId);
  for (const [name, value] of Object.entries(changes)) next.components[name] = clone(value);
  return Object.freeze(assertProductionComponentDeploymentState(next));
}

export function componentStateCasRequest({ current, next } = {}) {
  assertProductionComponentDeploymentState(current); assertProductionComponentDeploymentState(next); assert.equal(next.generation, current.generation + 1);
  return Object.freeze({ TableName: PRODUCTION_COMPONENT_STATE.table, Key: { stateKey: { S: PRODUCTION_COMPONENT_STATE.key } }, UpdateExpression: "SET #state = :state, #generation = :nextGeneration", ConditionExpression: "#generation = :generation", ExpressionAttributeNames: { "#state": "state", "#generation": "generation" }, ExpressionAttributeValues: { ":state": { S: canonical(next) }, ":generation": { N: String(current.generation) }, ":nextGeneration": { N: String(next.generation) } } });
}

export const stateHash = (value) => crypto.createHash("sha256").update(canonical(assertProductionComponentDeploymentState(value))).digest("hex");

const decode = (item) => {
  assert.equal(item?.stateKey?.S, PRODUCTION_COMPONENT_STATE.key); assert.match(item?.state?.S || "", /^\{/);
  const state = assertProductionComponentDeploymentState(JSON.parse(item.state.S)); assert.equal(item?.generation?.N, String(state.generation), "DynamoDB generation does not bind the state document");
  return state;
};
export function createProductionComponentDeploymentStateClient({ run } = {}) {
  assert.equal(typeof run, "function");
  const args = (tail) => ["dynamodb", ...tail, "--region", PRODUCTION_COMPONENT_STATE.region, "--output", "json", "--no-cli-pager"];
  const invoke = (tail) => JSON.parse(run(args(tail)) || "{}");
  return Object.freeze({
    read() { const result = invoke(["get-item", "--table-name", PRODUCTION_COMPONENT_STATE.table, "--consistent-read", "--key", JSON.stringify({ stateKey: { S: PRODUCTION_COMPONENT_STATE.key } })]); return result.Item ? decode(result.Item) : null; },
    initialize(state) {
      assertProductionComponentDeploymentState(state); assert.equal(state.generation, 1);
      return invoke(["put-item", "--table-name", PRODUCTION_COMPONENT_STATE.table, "--item", JSON.stringify({ stateKey: { S: PRODUCTION_COMPONENT_STATE.key }, generation: { N: "1" }, state: { S: canonical(state) } }), "--condition-expression", "attribute_not_exists(#key)", "--expression-attribute-names", JSON.stringify({ "#key": "stateKey" })]);
    },
    advance(current, next) { const request = componentStateCasRequest({ current, next }); return invoke(["update-item", "--table-name", request.TableName, "--key", JSON.stringify(request.Key), "--update-expression", request.UpdateExpression, "--condition-expression", request.ConditionExpression, "--expression-attribute-names", JSON.stringify(request.ExpressionAttributeNames), "--expression-attribute-values", JSON.stringify(request.ExpressionAttributeValues)]); },
  });
}

// DynamoDB only provides document-level conditional writes. A writer may retry
// after an unrelated component advances, but never after its own predecessor
// changed. This keeps one durable item without lost component updates.
export function advanceProductionComponentDeploymentStateWithRetry({ client, current, lane, changes, maxRetries = 2, now = () => new Date().toISOString(), recovery = false, isAncestor, authenticateRecovery, updatedByWorkflow, githubRunId } = {}) {
  assert.equal(typeof client?.read, "function"); assert.equal(typeof client?.advance, "function");
  assert.ok(Number.isSafeInteger(maxRetries) && maxRetries >= 0 && maxRetries <= 5);
  assertProductionComponentDeploymentState(current);
  assert.ok(changes && typeof changes === "object" && Object.keys(changes).length > 0);
  assertProductionComponentDeploymentState({ ...clone(current), components: { ...clone(current.components), ...changes } });
  // Terminal writers are retry-safe: after a successful conditional write the
  // exact same authenticated terminal may rerun without another state write.
  if (Object.entries(changes).every(([name, value]) => same(current.components[name], value)))
    return Object.freeze({ state: current, attempts: 0, reconciledUnrelatedConcurrentUpdate: false, alreadyCurrent: true });
  const expectedComponents = Object.fromEntries(Object.keys(changes || {}).map((name) => [name, clone(current.components[name])]));
  let observed = current;
  for (let attempt = 0; attempt <= maxRetries; attempt += 1) {
    const next = advanceProductionComponentDeploymentState({ current: observed, expectedGeneration: observed.generation, lane, changes, now: now(), recovery, isAncestor, authenticateRecovery, updatedByWorkflow, githubRunId });
    try {
      client.advance(observed, next);
      return Object.freeze({ state: next, attempts: attempt + 1, reconciledUnrelatedConcurrentUpdate: attempt > 0 });
    } catch (error) {
      if (!conditionalFailure(error) || attempt === maxRetries) throw error;
      const latest = client.read();
      assert.ok(latest, "Deployment state disappeared during conditional update"); assertProductionComponentDeploymentState(latest);
      for (const [name, expected] of Object.entries(expectedComponents))
        assert.ok(same(latest.components[name], expected), `Concurrent update changed ${name}; reconcile before retrying.`);
      observed = latest;
    }
  }
  throw new Error("Unreachable component deployment-state retry state");
}

export function bootstrapProductionComponentDeploymentState({ components: bootstrapComponents, now = new Date().toISOString(), updatedByWorkflow, githubRunId } = {}) {
  assert.ok(bootstrapComponents && typeof bootstrapComponents === "object" && !Array.isArray(bootstrapComponents));
  // The caller supplies only identities it independently read from the live
  // component. Database/security may remain explicitly unproven (`null`).
  return createProductionComponentDeploymentState({ components: bootstrapComponents, now, updatedByWorkflow, githubRunId });
}
