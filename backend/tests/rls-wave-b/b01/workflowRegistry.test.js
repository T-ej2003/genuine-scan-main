const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const {
  b01InvitationApplicationPathProof,
  b01RefreshSessionApplicationPathProof,
  b01SessionAIntegrationRequests,
  b01WorkflowProofs,
} = require(
  "../../../dist/rls-waves/session-b/b01/workflowRegistry"
);

const repoRoot = path.resolve(__dirname, "../../../..");
const partition = JSON.parse(fs.readFileSync(
  path.join(repoRoot, "documents/security/rls-program/workflow-two-session-partition.json"),
  "utf8"
));
const expected = partition.assignments.filter(
  (assignment) => assignment.sessionId === "session-b" &&
    assignment.waveId === "b-01-auth-preauth-session-account-security"
);

assert.equal(expected.length, 63, "partition must retain exactly 63 B01 workflows");
assert.equal(b01WorkflowProofs.length, 63, "registry must account for every B01 workflow");
assert.equal(new Set(b01WorkflowProofs.map((proof) => proof.workflowId)).size, 63, "registry IDs must be unique");
assert.deepEqual(
  [...b01WorkflowProofs.map((proof) => proof.workflowId)].sort(),
  [...expected.map((assignment) => assignment.workflowId)].sort(),
  "registry and authoritative B01 partition must match exactly"
);

const byId = new Map(expected.map((assignment) => [assignment.workflowId, assignment]));
const invitationIds = new Set(b01InvitationApplicationPathProof.workflowIds);
for (const proof of b01WorkflowProofs) {
  const assignment = byId.get(proof.workflowId);
  assert(assignment, `unknown B01 proof ${proof.workflowId}`);
  assert.equal(proof.entryPoint, assignment.entryPoint);
  assert.ok(assignment.canonicalSourceFiles.includes(proof.productionRoot));
  assert.equal(
    proof.localStatus,
    proof.boundary === "session-credential-function" || invitationIds.has(proof.workflowId)
      ? "implemented-local-proof-passed-global-integration-pending"
      : "implementation-in-progress"
  );
  assert.match(proof.boundary, /^(pre-auth|session-credential|authenticated)-function$/);
}

const sessionCredentialWorkflowIds = b01WorkflowProofs
  .filter((proof) => proof.boundary === "session-credential-function")
  .map((proof) => proof.workflowId);
assert.deepEqual(
  [...b01RefreshSessionApplicationPathProof.workflowIds].sort(),
  [...sessionCredentialWorkflowIds].sort(),
  "refresh/session proof must automatically cover every workflow using the shared credential boundary"
);
assert.equal(b01RefreshSessionApplicationPathProof.workflowIds.length, 9);
assert.equal(b01RefreshSessionApplicationPathProof.registeredRoots.length, 5);
assert.equal(b01RefreshSessionApplicationPathProof.postgresScope, "wave-local-exact-function-contract");
assert.equal(b01InvitationApplicationPathProof.workflowIds.length, 7);
assert.equal(b01InvitationApplicationPathProof.registeredRoots.length, 4);
assert.deepEqual(b01InvitationApplicationPathProof.registeredRoots, [
  "POST /api/auth/invite",
  "POST /api/licensees/:id/admin-invite/resend",
  "GET /api/auth/invite-preview",
  "POST /api/auth/accept-invite",
]);
assert.equal(b01InvitationApplicationPathProof.postgresScope, "wave-local-exact-function-contract");

assert.ok(b01SessionAIntegrationRequests.length >= 6);
for (const request of b01SessionAIntegrationRequests) {
  for (const field of ["targetSymbol", "callShape", "ordering", "invariant", "responsePreservation", "focusedTest"]) {
    assert.ok(String(request[field] || "").trim(), `integration request requires ${field}`);
  }
}

console.log("B01 63-workflow registry tests passed");
