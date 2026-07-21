const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const { b03SessionAIntegrationRequests, b03WorkflowProofs } = require(
  "../../../dist/rls-waves/session-b/b03/workflowRegistry"
);

const repoRoot = path.resolve(__dirname, "../../../..");
const partition = JSON.parse(fs.readFileSync(
  path.join(repoRoot, "documents/security/rls-program/workflow-two-session-partition.json"),
  "utf8"
));
const expected = partition.assignments.filter(
  (assignment) => assignment.sessionId === "session-b" &&
    assignment.waveId === "b-03-workers-scheduled-outbox-delivery"
);

assert.equal(expected.length, 20, "partition must retain exactly 20 B03 workflows");
assert.equal(b03WorkflowProofs.length, 20, "registry must account for every B03 workflow");
assert.equal(new Set(b03WorkflowProofs.map((proof) => proof.workflowId)).size, 20, "registry IDs must be unique");
assert.deepEqual(
  [...b03WorkflowProofs.map((proof) => proof.workflowId)].sort(),
  [...expected.map((assignment) => assignment.workflowId)].sort(),
  "registry and authoritative B03 partition must match exactly"
);

const byId = new Map(expected.map((assignment) => [assignment.workflowId, assignment]));
for (const proof of b03WorkflowProofs) {
  const assignment = byId.get(proof.workflowId);
  assert.equal(proof.entryPoint, assignment.entryPoint);
  assert.ok(assignment.canonicalSourceFiles.includes(proof.productionRoot));
  assert.match(proof.localStatus, /pending/, "B03 must not claim certification before global integration");
}

assert.ok(b03SessionAIntegrationRequests.length >= 6);
for (const request of b03SessionAIntegrationRequests) {
  for (const field of ["targetSymbol", "callShape", "ordering", "invariant", "responsePreservation", "focusedTest"]) {
    assert.ok(String(request[field] || "").trim(), `integration request requires ${field}`);
  }
}

console.log("B03 20-workflow registry tests passed");

