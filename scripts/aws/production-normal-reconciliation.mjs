import assert from "node:assert/strict";
import { assertNormalDeploymentReceipt, normalReceiptHash, sameNormalIdentity, classifyNormalLiveComponentState, NORMAL_DEPLOYABLE_COMPONENTS, NORMAL_RECEIPT_WORKFLOW } from "./production-normal-receipt-contract.mjs";
import { assertProductionComponentDeploymentState, advanceProductionComponentDeploymentStateWithRetry, normalDeploymentLiveComponents } from "./production-component-deployment-state.mjs";

const equal = (a, b) => JSON.stringify(a) === JSON.stringify(b);

// One bounded receipt in the existing exact-key item. Generation CAS protects
// both receipt and component state; a lost response is resolved by strong read.
export function replaceNormalDeploymentReceipt({ client, expected, receipt, writerContext, maxRetries = 2 }) {
  assert.ok(Number.isSafeInteger(maxRetries) && maxRetries >= 0 && maxRetries <= 5);
  if (receipt) assertNormalDeploymentReceipt(receipt);
  assert.equal(writerContext.updatedByWorkflow, NORMAL_RECEIPT_WORKFLOW);
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    const current = assertProductionComponentDeploymentState(client.read());
    for (const [name, predecessor] of Object.entries((receipt || expected).predecessors))
      assert.deepEqual(current.components[name], predecessor, "Normal receipt component predecessor changed");
    if (equal(current.normalDeploymentReceipt, receipt)) return current;
    assert.ok(equal(current.normalDeploymentReceipt, expected), "Concurrent normal receipt changed; reconcile before mutation");
    const next = structuredClone(current);
    next.generation++; next.updatedAt = new Date().toISOString(); next.updatedByLane = "NORMAL_APPLICATION";
    next.updatedByWorkflow = writerContext.updatedByWorkflow; next.githubRunId = String(writerContext.githubRunId);
    if (receipt) next.normalDeploymentReceipt = structuredClone(receipt);
    else delete next.normalDeploymentReceipt;
    try { client.advance(current, next); return next; }
    catch (error) {
      const latest = assertProductionComponentDeploymentState(client.read());
      if (equal(latest.normalDeploymentReceipt, receipt)) return latest;
      if (attempt === maxRetries || !/ConditionalCheckFailedException/.test(`${error.name} ${error.message} ${error.stderr}`)) throw error;
    }
  }
  throw new Error("Normal receipt retry exhausted");
}

export async function reconcileNormalDeployment({ client, sourceSha, isAncestor, readLive, authenticateCandidate, verify, rollback, writerContext, writeJournal = async () => {} }) {
  let state = assertProductionComponentDeploymentState(client.read());
  const receipt = state.normalDeploymentReceipt;
  let verificationError;
  if (receipt) {
    assertNormalDeploymentReceipt(receipt);
    assert.equal(isAncestor(receipt.sourceSha, sourceSha), true, "Receipt is not current protected-main history");
    const live = {};
    for (const [name, predecessor] of Object.entries(receipt.predecessors)) {
      assert.deepEqual(state.components[name], predecessor, "Pending normal predecessor is stale");
      assert.equal(isAncestor(predecessor.establishedThroughSha, receipt.sourceSha), true, "Receipt source is outside predecessor/current-main range");
      assert.notEqual(predecessor.sourceSha, receipt.sourceSha);
      if (receipt.candidates[name]) await authenticateCandidate(name, predecessor, receipt.candidates[name]);
      live[name] = await readLive(name);
      assert.ok(sameNormalIdentity(live[name], predecessor) || (receipt.candidates[name] && sameNormalIdentity(live[name], receipt.candidates[name])), "LIVE_IS_UNKNOWN: live component has no authenticated normal mutation receipt");
    }
    if (receipt.phase === "VERIFIED" && Object.keys(receipt.candidates).every((name) => classifyNormalLiveComponentState({ live: live[name], predecessor: receipt.predecessors[name], authenticatedReceipt: receipt, component: name }) === "LIVE_IS_RECONCILABLE_NORMAL_DEPLOYMENT")) {
      try { await verify(normalDeploymentLiveComponents(state, receipt.candidates)); } catch (error) { verificationError = error; }
      if (!verificationError) {
        await writeJournal({ status: "RECONCILIATION_STATE_CAS_INTENT", reconciledSourceSha: receipt.sourceSha });
        // Full-set verification is tied to this exact generation. Never carry it
        // across a concurrent state write; the next invocation re-reads/reverifies.
        state = advanceProductionComponentDeploymentStateWithRetry({ client, current: state, lane: "NORMAL_APPLICATION", changes: receipt.candidates, normalReceiptSha256: normalReceiptHash(receipt), maxRetries: 0, isAncestor, ...writerContext }).state;
      }
    }
    if (state.normalDeploymentReceipt) {
      // An intent is NOT completion evidence. Restore exact recorded predecessors;
      // the current main release can then start normally. Persist rollback intent
      // first, so death during rollback cannot later turn into a successful commit.
      const rollingBack = { ...receipt, phase: "ROLLING_BACK" };
      delete rollingBack.verification;
      state = replaceNormalDeploymentReceipt({ client, expected: receipt, receipt: rollingBack, writerContext });
      for (const name of [...NORMAL_DEPLOYABLE_COMPONENTS].reverse().filter((name) => receipt.predecessors[name])) {
        await writeJournal({ status: "RECONCILIATION_ROLLBACK_INTENT", component: name });
        if (!sameNormalIdentity(live[name], receipt.predecessors[name])) await rollback(name, receipt.predecessors[name], receipt.candidates[name]);
        assert.ok(sameNormalIdentity(await readLive(name), receipt.predecessors[name]), "Interrupted normal rollback did not restore exact predecessor");
      }
      await verify(normalDeploymentLiveComponents(state));
      state = replaceNormalDeploymentReceipt({ client, expected: state.normalDeploymentReceipt, receipt: undefined, writerContext, maxRetries: 0 });
    }
  }
  // Single successful exit: every represented live component in the resulting
  // authoritative state is rechecked after the closure CAS. Classification can
  // never receive a receipt-scoped or stale subset.
  await verify(normalDeploymentLiveComponents(state));
  if (verificationError) throw verificationError;
  return state;
}
