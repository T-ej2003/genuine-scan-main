#!/usr/bin/env node
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { MIXED_DUAL_SLOT_PREDECESSOR_CANONICAL_ID, MIXED_DUAL_SLOT_RECOVERY_ORDER, MIXED_DUAL_SLOT_RECOVERY_POST_STATE_CANONICAL_ID, MIXED_DUAL_SLOT_RETAINED_HISTORY_CANONICAL_ID, MIXED_DUAL_SLOT_PREDECESSOR, assertMixedDualSlotPredecessor, assertMixedDualSlotRecoveryAuthorization, assertMixedDualSlotRecoveryPreparation, buildMixedDualSlotRecoveryPreparation } from "./production-mixed-dual-slot-recovery-contract.mjs";

const require = createRequire(new URL("../../backend/package.json", import.meta.url));
const { UpdateSecretVersionStageCommand, DescribeSecretCommand, GetSecretValueCommand } = require("@aws-sdk/client-secrets-manager");

const canonical = (value) => Array.isArray(value) ? `[${value.map(canonical).join(",")}]` : value && typeof value === "object" ? `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}` : JSON.stringify(value);
const sha256 = (value) => createHash("sha256").update(canonical(value)).digest("hex");
// Secrets Manager is eventually consistent and does not publish a propagation SLA.
// Bound each reviewed label transition to five minutes without ever accepting a third state.
const CONVERGENCE_DELAYS_MS = Object.freeze([1_000, 2_000, 4_000, 8_000, 15_000, 30_000, 60_000, 60_000, 60_000, 60_000]);
const sleepForConvergence = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));
const exactProgress = (topology, versionId, slot) => {
  topology ??= {};
  if (!topology || typeof topology !== "object" || Array.isArray(topology)) throw new Error(`Mixed recovery ${slot} version topology is not exact.`);
  const retained = MIXED_DUAL_SLOT_PREDECESSOR[slot].retainedPrevious;
  const completed = { [retained.versionId]: ["AWSPREVIOUS"] };
  const pending = { [versionId]: ["AWSCURRENT"], ...completed };
  if (canonical(topology) === canonical(completed)) return true;
  if (canonical(topology) === canonical(pending)) return false;
  throw new Error(`Mixed recovery ${slot} staging topology is not an exact predecessor or completed recovery state.`);
};

const safeIdentity = (payload, expected, payloadHash, slot, stagingLabels) => ({ arn: expected.arn, versionId: expected.versionId, stagingLabels, payloadSha256: payloadHash(payload, slot), schemaKeys: Object.keys(payload || {}).sort(), sourceSha: payload?.sourceSha ?? null, rotationId: payload?.rotationId ?? null, slot: payload?.slot, materialFingerprint: payload?.materialFingerprint ?? null, keyVersion: payload?.keyVersion ?? null });

async function readMixedDualSlotRecoveryState({ send, payloadHash = sha256 } = {}) {
  const observed = {};
  const progress = [];
  for (const slot of MIXED_DUAL_SLOT_RECOVERY_ORDER) {
    const expected = MIXED_DUAL_SLOT_PREDECESSOR[slot];
    const described = await send(new DescribeSecretCommand({ SecretId: expected.arn }));
    const topology = described?.VersionIdsToStages;
    progress.push(exactProgress(topology, expected.versionId, slot));
    const value = await send(new GetSecretValueCommand({ SecretId: expected.arn, VersionId: expected.versionId }));
    let payload; try { payload = JSON.parse(value?.SecretString || ""); } catch { throw new Error(`Mixed predecessor ${slot} payload is malformed.`); }
    const retained = expected.retainedPrevious;
    const previousValue = await send(new GetSecretValueCommand({ SecretId: expected.arn, VersionId: retained.versionId }));
    let previousPayload; try { previousPayload = JSON.parse(previousValue?.SecretString || ""); } catch { throw new Error(`Mixed predecessor ${slot} retained payload is malformed.`); }
    observed[slot] = { ...safeIdentity(payload, { ...expected, arn: described?.ARN, versionId: value?.VersionId }, (candidate) => payloadHash(candidate, slot, "current"), slot, ["AWSCURRENT"]), retainedPrevious: safeIdentity(previousPayload, { ...retained, arn: described?.ARN, versionId: previousValue?.VersionId }, (candidate) => payloadHash(candidate, slot, "retainedPrevious"), slot, ["AWSPREVIOUS"]) };
  }
  const predecessor = assertMixedDualSlotPredecessor(observed);
  if (progress.some((done, index) => !done && progress.slice(index + 1).some(Boolean))) throw new Error("Mixed recovery partial state is not an authenticated contiguous prefix.");
  return Object.freeze({ predecessor, completed: progress.filter(Boolean).length });
}

export async function readMixedDualSlotPredecessor({ send, payloadHash = sha256 } = {}) {
  const state = await readMixedDualSlotRecoveryState({ send, payloadHash });
  if (state.completed !== 0) throw new Error("Mixed predecessor has already entered recovery.");
  return state.predecessor;
}

export async function prepareMixedDualSlotRecovery({ send, sourceSha, livePredecessor, iamCapabilityPreflight, now = new Date(), payloadHash } = {}) {
  const state = await readMixedDualSlotRecoveryState({ send, payloadHash });
  return buildMixedDualSlotRecoveryPreparation({ sourceSha, predecessor: state.predecessor, iamCapabilityPreflight, initialCompletedStageLabelMutations: state.completed, livePredecessor, preparedAt: now.toISOString() });
}

export async function classifyMixedDualSlotRecoveryProgress({ send, payloadHash = sha256 } = {}) {
  return (await readMixedDualSlotRecoveryState({ send, payloadHash })).completed;
}

async function awaitExactProgress({ expected, observe, sleep }) {
  for (let attempt = 0; attempt <= CONVERGENCE_DELAYS_MS.length; attempt += 1) {
    const completed = await observe();
    if (completed === expected) return;
    if (completed !== expected - 1) throw new Error("Mixed recovery post-mutation topology is not the prior or expected exact prefix.");
    if (attempt < CONVERGENCE_DELAYS_MS.length) await sleep(CONVERGENCE_DELAYS_MS[attempt]);
  }
  throw new Error(`Mixed recovery stage-label mutation did not converge after ${CONVERGENCE_DELAYS_MS.length + 1} read-only observations.`);
}

// Each successful mutation removes only AWSCURRENT from the authenticated unused slot version.
// A retry is safe only for the exact contiguous completed prefix; any other topology fails closed.
export async function executeMixedDualSlotRecovery({ send, preparation, preparationFileSha256, sourceSha, authorization, payloadHash, now = new Date(), reauthenticate = async () => {}, sleep = sleepForConvergence } = {}) {
  const checked = assertMixedDualSlotRecoveryPreparation(preparation, { sourceSha });
  preparationFileSha256 ||= authorization?.preparationFileSha256;
  const authenticate = async (allowExpiredResume) => { assertMixedDualSlotRecoveryAuthorization(authorization, { preparation: checked, preparationFileSha256, sourceSha, now, allowExpiredResume }); await reauthenticate({ preparation: checked, authorization }); };
  await authenticate(true);
  let completed = await classifyMixedDualSlotRecoveryProgress({ send, payloadHash }); const initialCompleted = completed;
  if (completed < checked.initialCompletedStageLabelMutations) throw new Error("Mixed recovery topology predates the authorization-bound preparation prefix.");
  await authenticate(completed > 0);
  for (const entry of checked.mutationPlan.slice(completed)) {
    // Re-read all seven identities at every write boundary; an interrupted run can
    // continue only from the immutable contiguous prefix it itself established.
    await authenticate(completed > 0);
    if (await classifyMixedDualSlotRecoveryProgress({ send, payloadHash }) !== completed) throw new Error("Mixed recovery topology changed before mutation.");
    await send(new UpdateSecretVersionStageCommand({ SecretId: entry.secretArn, VersionStage: "AWSCURRENT", RemoveFromVersionId: entry.versionId }));
    completed += 1;
    await awaitExactProgress({ expected: completed, sleep, observe: async () => { await authenticate(true); return classifyMixedDualSlotRecoveryProgress({ send, payloadHash }); } });
  }
  if (await classifyMixedDualSlotRecoveryProgress({ send, payloadHash }) !== 7) throw new Error("Mixed recovery post-state is not exact.");
  return Object.freeze({ valid: true, writes: 0, stageLabelMutations: completed - initialCompleted, predecessorCanonicalId: MIXED_DUAL_SLOT_PREDECESSOR_CANONICAL_ID, retainedHistoryCanonicalId: MIXED_DUAL_SLOT_RETAINED_HISTORY_CANONICAL_ID, postState: "SEVEN_EXISTING_RESOURCES_WITHOUT_AWSCURRENT", postStateCanonicalId: MIXED_DUAL_SLOT_RECOVERY_POST_STATE_CANONICAL_ID });
}
