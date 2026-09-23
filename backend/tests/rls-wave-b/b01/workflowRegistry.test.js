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
  path.join(repoRoot, "documents/security/rls-program/workflow-three-session-partition.json"),
  "utf8"
));
const authoritativeB01Assignments = partition.assignments.filter(
  (assignment) => assignment.sessionId === "session-b"
    && assignment.waveId === "b-01-auth-preauth-session-account-security"
);

const assertExactB01Assignments = (assignments, proofs) => {
  const assignmentIds = assignments.map(({ workflowId }) => workflowId);
  const proofIds = proofs.map(({ workflowId }) => workflowId);
  assert.equal(new Set(assignmentIds).size, assignmentIds.length, "authoritative B01 workflow IDs must be unique");
  assert.equal(new Set(proofIds).size, proofIds.length, "registry B01 workflow IDs must be unique");
  assert.deepEqual([...proofIds].sort(), [...assignmentIds].sort(), "registry must exactly match authoritative B01 assignments");

  const assignmentsById = new Map(assignments.map((assignment) => [assignment.workflowId, assignment]));
  for (const proof of proofs) {
    const assignment = assignmentsById.get(proof.workflowId);
    assert.equal(proof.entryPoint, assignment.entryPoint, `B01 entry point drifted: ${proof.workflowId}`);
    assert.ok(
      assignment.canonicalSourceFiles.includes(proof.productionRoot),
      `B01 production root drifted: ${proof.workflowId}`
    );
  }
};

assert.equal(authoritativeB01Assignments.length, 46);
assertExactB01Assignments(authoritativeB01Assignments, b01WorkflowProofs);
assert.throws(
  () => assertExactB01Assignments(authoritativeB01Assignments, b01WorkflowProofs.slice(1)),
  /exactly match/
);
assert.throws(
  () => assertExactB01Assignments(authoritativeB01Assignments, [
    ...b01WorkflowProofs,
    { ...b01WorkflowProofs[0], workflowId: "workflow-obsolete-b01-assignment" },
  ]),
  /exactly match/
);
assert.throws(
  () => assertExactB01Assignments(authoritativeB01Assignments, [
    { ...b01WorkflowProofs[0], entryPoint: "http:metadataDrift" },
    ...b01WorkflowProofs.slice(1),
  ]),
  /entry point drifted/
);
assert.throws(
  () => assertExactB01Assignments(authoritativeB01Assignments, [...b01WorkflowProofs, b01WorkflowProofs[0]]),
  /registry B01 workflow IDs must be unique/
);

const invitationIds = new Set(b01InvitationApplicationPathProof.workflowIds);
for (const proof of b01WorkflowProofs) {
  assert.match(proof.workflowId, /^workflow-/);
  assert.match(proof.entryPoint, /^(http|internal|startup):/);
  assert.ok(fs.statSync(path.join(repoRoot, proof.productionRoot)).isFile(), `B01 production root must exist: ${proof.productionRoot}`);
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
assert.ok(b01RefreshSessionApplicationPathProof.workflowIds.length > 0);
assert.equal(b01RefreshSessionApplicationPathProof.registeredRoots.length, 5);
assert.equal(b01RefreshSessionApplicationPathProof.postgresScope, "wave-local-exact-function-contract");
assert.ok(b01InvitationApplicationPathProof.workflowIds.length > 0);
assert.equal(b01InvitationApplicationPathProof.registeredRoots.length, 4);
assert.deepEqual(b01InvitationApplicationPathProof.registeredRoots, [
  "POST /api/auth/invite",
  "POST /api/licensees/:id/admin-invite/resend",
  "GET /api/auth/invite-preview",
  "POST /api/auth/accept-invite",
]);
assert.equal(b01InvitationApplicationPathProof.postgresScope, "wave-local-exact-function-contract");
assert.deepEqual(b01InvitationApplicationPathProof.canonicalCertification, {
  family: "current-runtime-super-admin-invitation",
  testFile: "backend/tests/currentRuntimeSuperAdminInvitationPostgres18.test.js",
  requiredResult: "application-path-certified",
});
assert.equal(b01InvitationApplicationPathProof.integrationStatus, "current-runtime-two-admin-integration-certified");
for (const proof of [
  "backend/tests/rls-wave-b/b01/invitationPostgres18.test.js",
  "backend/tests/currentRuntimeSuperAdminInvitationPostgres18.test.js",
  "backend/tests/authAdminLoginMfaCycle.test.js",
  "backend/tests/authMfaChallengeStateMachine.test.js",
  "backend/tests/csrfSecurity.test.js",
  "backend/tests/rls-wave-b/b01/recentAdminMfaMiddleware.test.js",
]) {
  assert.ok(b01InvitationApplicationPathProof.focusedProofs.includes(proof), `onboarding gate must bind ${proof}`);
  assert.ok(fs.statSync(path.join(repoRoot, proof)).isFile(), `onboarding gate proof must exist: ${proof}`);
}

assert.ok(b01SessionAIntegrationRequests.length >= 6);
for (const request of b01SessionAIntegrationRequests) {
  for (const field of ["targetSymbol", "callShape", "ordering", "invariant", "responsePreservation", "focusedTest"]) {
    assert.ok(String(request[field] || "").trim(), `integration request requires ${field}`);
  }
}

console.log("B01 workflow registry tests passed");
