import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { createProductionComponentDeploymentState, advanceProductionComponentDeploymentState, advanceProductionComponentDeploymentStateWithRetry } from "../aws/production-component-deployment-state.mjs";
import { buildProductionNormalDeploymentPlan, prepareProductionNormalDeployment } from "../aws/prepare-production-normal-deployment.mjs";
import { COMPLETED_EMERGENCY_PATHS } from "../aws/production-completed-emergency-work.mjs";

const [a, b, c, d, e] = ["a", "b", "c", "d", "e"].map((letter) => letter.repeat(40));
const history = [a, b, c, d, e];
const ancestor = (left, right) => history.includes(left) && history.includes(right) && history.indexOf(left) <= history.indexOf(right);
const recovery = "scripts/aws/recover-production-backend-health.mjs";
const rotation = "scripts/aws/run-production-cutover.mjs";
const component = (name, sourceSha) => ({ sourceSha, establishedThroughSha: sourceSha, imageDigest: `sha256:${"1".repeat(64)}`, taskDefinitionArn: `arn:aws:ecs:eu-west-2:368992683803:task-definition/${name}:1`, desiredCount: 2 });
const initial = () => createProductionComponentDeploymentState({ components: { backend: component("mscqr-backend", a), frontend: component("mscqr-frontend", a), database: { sourceSha: a, releaseIdentity: "database" }, security: { sourceSha: a, releaseIdentity: "security" } } });
const completion = (mode, sourceSha = b) => ({ mode, sourceSha, evidenceSha256: "1".repeat(64) });
function complete(current, mode, sourceSha = b) {
  const changes = { backend: { ...current.components.backend, establishedThroughSha: sourceSha } };
  if (mode !== "backend-health-recovery") changes.security = { sourceSha, releaseIdentity: "1".repeat(64) };
  return advanceProductionComponentDeploymentState({ current, expectedGeneration: current.generation, lane: mode === "backend-health-recovery" ? "EMERGENCY_RECOVERY" : "SECURITY_INFRASTRUCTURE", recovery: true, authenticateRecovery: () => {}, isAncestor: ancestor, changes, emergencyCompletion: completion(mode, sourceSha) });
}
function plan(state, events, sourceSha = c, isAncestor = ancestor) {
  return buildProductionNormalDeploymentPlan({ state, sourceSha, isAncestor, readRange: (left, right) => [...new Set(events.filter(([sha]) => history.indexOf(sha) > history.indexOf(left) && history.indexOf(sha) <= history.indexOf(right)).flatMap(([, files]) => files))] });
}

for (const mode of ["backend-health-recovery", "rotation-overlap", "rotation-cleanup"]) {
  test(`${mode}: authenticated completion clears lagging frontend/database/security ranges only`, () => {
    const emergency = mode === "backend-health-recovery" ? recovery : rotation;
    const events = [[b, [emergency]], [c, ["src/App.tsx"]]];
    assert.throws(() => plan(initial(), events), /Sensitive|stronger-lane/);
    const established = complete(initial(), mode);
    const result = plan(established, events);
    assert.equal(plan(established, [[b, COMPLETED_EMERGENCY_PATHS[mode]], [c, ["src/App.tsx"]]]).classification.frontend, true);
    assert.equal(result.classification.frontend, true); assert.equal(result.classification.backend, false);
    for (const files of Object.values(result.componentFiles)) assert.ok(!files.includes(emergency));
    assert.equal(established.components.frontend.establishedThroughSha, a);
    assert.equal(established.components.database.sourceSha, a);
    const { completedEmergencyWork: _proof, ...uncommitted } = established;
    assert.throws(() => plan(uncommitted, events), /Sensitive|stronger-lane/);
    assert.throws(() => plan({ ...established, components: { ...established.components, backend: initial().components.backend } }, events), /ahead/);
    assert.throws(() => plan(established, events, c, () => false), /ancestor|history/);
    assert.throws(() => plan({ ...established, completedEmergencyWork: { [mode]: { sourceSha: "f".repeat(40), evidenceSha256: "1".repeat(64) } } }, events), /history/);
    if (mode !== "backend-health-recovery") assert.throws(() => plan({ ...established, components: { ...established.components, security: initial().components.security } }, events), /security state/);
    assert.throws(() => plan({ ...established, updatedByLane: "BOOTSTRAP" }, events), /Bootstrap/);
    // An old completion cannot hide a later edit, including an edit to the same path.
    assert.throws(() => plan(established, [...events, [d, [emergency]], [e, ["src/App.tsx"]]], e), /Sensitive|stronger-lane/);
    assert.throws(() => plan(established, [[b, [emergency, "scripts/aws/unrelated-bootstrap.mjs"]], [c, ["src/App.tsx"]]]), /Sensitive|stronger-lane/);
    assert.throws(() => plan(established, [[b, [emergency, "backend/src/middleware/rbac.ts"]], [c, ["src/App.tsx"]]]), /Sensitive|stronger-lane/);
    const ordinary = plan(established, [[b, [emergency, "src/main.tsx"]], [c, ["src/App.tsx"]]]);
    assert.ok(ordinary.componentFiles.frontendFiles.includes("src/main.tsx"));
  });
}

test("operation-specific completion survives later writers and sequential recovery/rotation in either order", () => {
  for (const modes of [["backend-health-recovery", "rotation-cleanup"], ["rotation-overlap", "backend-health-recovery"], ["backend-health-recovery", "backend-health-recovery"], ["rotation-overlap", "rotation-cleanup"]]) {
    const state = complete(complete(initial(), modes[0], b), modes[1], c);
    const pathFor = (mode) => mode === "backend-health-recovery" ? recovery : rotation;
    const events = [[b, [pathFor(modes[0])]], [c, [pathFor(modes[1])]], [d, ["src/App.tsx"]]];
    assert.equal(plan(state, events, d).classification.frontend, true);
    const next = advanceProductionComponentDeploymentState({ current: state, expectedGeneration: state.generation, lane: "NORMAL_APPLICATION", changes: { frontend: component("mscqr-frontend", d) }, isAncestor: ancestor });
    assert.deepEqual(next.completedEmergencyWork, state.completedEmergencyWork);
    assert.equal(plan(next, events, e).classification.frontend, false);
  }
  assert.throws(() => plan(complete(initial(), "backend-health-recovery"), [[b, [rotation]], [c, ["src/App.tsx"]]]), /Sensitive|stronger-lane/);
});

test("normal writers cannot manufacture completion and failed CAS never publishes it", () => {
  const current = initial(), proof = completion("backend-health-recovery");
  assert.throws(() => advanceProductionComponentDeploymentState({ current, expectedGeneration: 1, lane: "NORMAL_APPLICATION", changes: { backend: component("mscqr-backend", b) }, emergencyCompletion: proof, isAncestor: ancestor }));
  const changes = { backend: { ...current.components.backend, establishedThroughSha: b } };
  assert.throws(() => advanceProductionComponentDeploymentStateWithRetry({ current, client: { read: () => current, advance: () => { throw new Error("CAS failure"); } }, changes, emergencyCompletion: proof, lane: "EMERGENCY_RECOVERY", recovery: true, authenticateRecovery: () => {} }), /CAS failure/);
  assert.equal(current.completedEmergencyWork, undefined);
  assert.equal(complete(current, "backend-health-recovery").completedEmergencyWork[proof.mode].sourceSha, b);
  const options = { current, lane: "EMERGENCY_RECOVERY", recovery: true, authenticateRecovery: () => {}, changes, emergencyCompletion: proof };
  const unrelated = advanceProductionComponentDeploymentState({ current, expectedGeneration: 1, lane: "NORMAL_APPLICATION", changes: { frontend: component("mscqr-frontend", c) }, isAncestor: ancestor });
  let attempts = 0;
  const result = advanceProductionComponentDeploymentStateWithRetry({ ...options, client: { read: () => unrelated, advance: () => { if (attempts++ === 0) throw new Error("ConditionalCheckFailedException"); } } });
  assert.equal(result.state.components.frontend.sourceSha, c);
  assert.equal(result.state.completedEmergencyWork[proof.mode].sourceSha, b);
  const replay = advanceProductionComponentDeploymentStateWithRetry({ ...options, current: result.state, client: { read: () => result.state, advance: () => assert.fail("Duplicate terminal write") } });
  assert.equal(replay.alreadyCurrent, true);
  const conflict = { ...unrelated, completedEmergencyWork: { [proof.mode]: { sourceSha: b, evidenceSha256: "2".repeat(64) } } };
  assert.throws(() => advanceProductionComponentDeploymentStateWithRetry({ ...options, client: { read: () => conflict, advance: () => { throw new Error("ConditionalCheckFailedException"); } } }), /Concurrent emergency/);
});

test("actual Git ranges preserve later edits and merge ancestry rather than trusting a path's name", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "completed-emergency-range-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const git = (...args) => execFileSync("git", args, { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
  git("init", "-b", "main"); git("config", "user.name", "Range Test"); git("config", "user.email", "range@example.invalid");
  const commit = (file, content) => { fs.mkdirSync(path.dirname(path.join(root, file)), { recursive: true }); fs.writeFileSync(path.join(root, file), content); git("add", "--", file); git("commit", "-m", "fixture"); return git("rev-parse", "HEAD"); };
  const first = commit("README.md", "baseline");
  const done = commit(recovery, "completed source");
  git("checkout", "-b", "feature"); const next = commit("src/App.tsx", "frontend");
  git("checkout", "main"); commit("README.md", "docs"); git("merge", "--no-ff", "feature", "-m", "merge");
  const merged = git("rev-parse", "HEAD");
  const base = createProductionComponentDeploymentState({ components: { backend: component("mscqr-backend", first), frontend: component("mscqr-frontend", first), database: null, security: null } });
  const state = advanceProductionComponentDeploymentState({ current: base, expectedGeneration: 1, lane: "EMERGENCY_RECOVERY", recovery: true, authenticateRecovery: () => {}, changes: { backend: { ...base.components.backend, establishedThroughSha: done } }, emergencyCompletion: completion("backend-health-recovery", done) });
  const prepare = (sourceSha, value = state) => prepareProductionNormalDeployment({ sourceSha, repositoryRoot: root, client: { read: () => value } });
  assert.equal(prepare(merged).classification.frontend, true);
  assert.equal(prepare(next).classification.frontend, true);
  const fresh = commit(recovery, "unexecuted source");
  assert.throws(() => prepare(fresh), /Sensitive|stronger-lane/);
  assert.throws(() => prepare(first), /ancestor/);
  const { completedEmergencyWork: _proof, ...unproven } = state;
  assert.throws(() => prepare(merged, unproven), /Sensitive/);
});
