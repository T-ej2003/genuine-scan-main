import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { buildSignerBrokerAuthorization, signerLifecycleEvidenceBinding } from "../aws/component-signer-policy-transition.mjs";
import { run } from "../aws/production-signer-broker-transition-cli.mjs";

const sourceSha = "a".repeat(40), transitionId = "123e4567-e89b-42d3-a456-426614174000";
const authorization = buildSignerBrokerAuthorization({ sourceSha, transitionId, operation: "INSTALL", workflowRunId: "42",
  approvedAt: "2026-09-28T12:00:00.000Z", expiresAt: "2026-09-28T12:30:00.000Z" });
const ledger = state => ({ kind: "MSCQR_SIGNER_POLICY_BROKER_LEDGER", state, authorization });

function fixture(state = "INSTALLED") {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "signer-broker-cli-test-")); fs.chmodSync(directory, 0o700);
  const file = path.join(directory, "state.json"); fs.writeFileSync(file, JSON.stringify(ledger(state)), { mode: 0o600 });
  const calls = [], session = async binding => ({ invoke: async (operation, input = {}) => { calls.push({ binding, operation, input }); return ledger(operation === "SIGNER_REVOKE" ? "REVOKED" : operation === "SIGNER_INSTALL" ? "INSTALLED" : input.state); } });
  return { file, calls, session, close: () => fs.rmSync(directory, { recursive: true }) };
}

test("CLI exposes only fixed broker operations and binds advance to the local authoritative evidence", async () => {
  const f = fixture();
  try {
    await run(["--phase", "advance", "--state-file", f.file, "--state", "PLAN_GENERATED", "--plan-sha256", "b".repeat(64)], { installSession: f.session, loadUser: async () => ({}) });
    const call = f.calls[0]; assert.equal(call.operation, "SIGNER_ADVANCE"); assert.deepEqual(call.binding, { sourceSha, transitionId, authorizationSha256: authorization.authorizationSha256 });
    assert.equal(call.input.evidenceSha256, signerLifecycleEvidenceBinding({ state: "INSTALLED", ...call.binding }));
    assert.deepEqual({ planSha256: call.input.planSha256, approvalReference: call.input.approvalReference, signerReadbackSha256: call.input.signerReadbackSha256 }, { planSha256: "b".repeat(64), approvalReference: null, signerReadbackSha256: null });
    assert.equal(JSON.parse(fs.readFileSync(f.file)).state, "PLAN_GENERATED");
  } finally { f.close(); }
});

test("CLI rejects caller-selected policy inputs and sends abort only through the cleanup session", async () => {
  const f = fixture("PLAN_REVIEWED");
  try {
    await assert.rejects(run(["--phase", "install", "--state-file", f.file, "--policy-arn", "attacker"], { installSession: f.session }), /Unsupported/);
    await run(["--phase", "revoke", "--state-file", f.file, "--abort-before-apply-confirmed"], { revokeSession: f.session, loadUser: async () => ({}) });
    assert.equal(f.calls[0].operation, "SIGNER_REVOKE"); assert.equal(f.calls[0].input.abort, true); assert.equal(f.calls[0].input.evidenceState, "PLAN_REVIEWED");
  } finally { f.close(); }
});

test("local catch-up always reauthenticates the matching authoritative broker transition", async () => {
  const f = fixture("PLAN_GENERATED");
  try {
    fs.writeFileSync(f.file, JSON.stringify({ ...ledger("PLAN_GENERATED"), planSha256: "b".repeat(64), approvalReference: null, signerReadbackSha256: null }), { mode: 0o600 });
    await run(["--phase", "advance", "--state-file", f.file, "--state", "PLAN_GENERATED", "--plan-sha256", "b".repeat(64)], { installSession: f.session, loadUser: async () => ({}) });
    assert.equal(f.calls.length, 1); assert.equal(f.calls[0].operation, "SIGNER_ADVANCE");
    assert.equal(f.calls[0].input.evidenceSha256, signerLifecycleEvidenceBinding({ state: "INSTALLED", sourceSha, transitionId, authorizationSha256: authorization.authorizationSha256 }));
  } finally { f.close(); }
});
