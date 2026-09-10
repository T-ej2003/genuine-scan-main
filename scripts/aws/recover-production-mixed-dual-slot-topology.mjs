#!/usr/bin/env node
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { MIXED_DUAL_SLOT_RECOVERY_ORDER, MIXED_DUAL_SLOT_PREDECESSOR, assertMixedDualSlotPredecessor, assertMixedDualSlotRecoveryAuthorization, assertMixedDualSlotRecoveryPreparation, buildMixedDualSlotRecoveryPreparation } from "./production-mixed-dual-slot-recovery-contract.mjs";

const require = createRequire(new URL("../../backend/package.json", import.meta.url));
const { UpdateSecretVersionStageCommand, DescribeSecretCommand, GetSecretValueCommand } = require("@aws-sdk/client-secrets-manager");

const canonical = (value) => Array.isArray(value) ? `[${value.map(canonical).join(",")}]` : value && typeof value === "object" ? `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}` : JSON.stringify(value);
const sha256 = (value) => createHash("sha256").update(canonical(value)).digest("hex");
const exactProgress = (topology, versionId, slot) => {
  topology ??= {};
  if (!topology || typeof topology !== "object" || Array.isArray(topology)) throw new Error(`Mixed recovery ${slot} version topology is not exact.`);
  const versionIds = Object.keys(topology);
  if (versionIds.length === 0) return true;
  if (JSON.stringify(versionIds) === JSON.stringify([versionId]) && JSON.stringify(topology[versionId]) === JSON.stringify(["AWSCURRENT"])) return false;
  throw new Error(`Mixed recovery ${slot} staging topology is not an exact predecessor or completed recovery state.`);
};

export async function readMixedDualSlotPredecessor({ send, payloadHash = sha256 } = {}) {
  const observed = {};
  for (const slot of MIXED_DUAL_SLOT_RECOVERY_ORDER) {
    const expected = MIXED_DUAL_SLOT_PREDECESSOR[slot];
    const described = await send(new DescribeSecretCommand({ SecretId: expected.arn }));
    const topology = described?.VersionIdsToStages;
    if (!topology || JSON.stringify(Object.keys(topology).sort()) !== JSON.stringify([expected.versionId])) throw new Error(`Mixed predecessor ${slot} version topology is not exact.`);
    const stages = topology[expected.versionId];
    const value = await send(new GetSecretValueCommand({ SecretId: expected.arn, VersionId: expected.versionId }));
    let payload; try { payload = JSON.parse(value?.SecretString || ""); } catch { throw new Error(`Mixed predecessor ${slot} payload is malformed.`); }
    observed[slot] = { arn: described?.ARN, versionId: value?.VersionId, stagingLabels: stages, payloadSha256: payloadHash(payload, slot), schemaKeys: Object.keys(payload || {}).sort(), sourceSha: payload?.sourceSha ?? null, rotationId: payload?.rotationId, slot: payload?.slot, materialFingerprint: payload?.materialFingerprint ?? null, keyVersion: payload?.keyVersion ?? null };
  }
  return assertMixedDualSlotPredecessor(observed);
}

export async function prepareMixedDualSlotRecovery({ send, sourceSha, livePredecessor, now = new Date(), payloadHash } = {}) {
  return buildMixedDualSlotRecoveryPreparation({ sourceSha, predecessor: await readMixedDualSlotPredecessor({ send, payloadHash }), livePredecessor, preparedAt: now.toISOString() });
}

export async function classifyMixedDualSlotRecoveryProgress({ send, payloadHash = sha256 } = {}) {
  const observed = await Promise.all(MIXED_DUAL_SLOT_RECOVERY_ORDER.map(async (slot) => {
    const expected = MIXED_DUAL_SLOT_PREDECESSOR[slot];
    const described = await send(new DescribeSecretCommand({ SecretId: expected.arn }));
    const topology = described?.VersionIdsToStages;
    const done = exactProgress(topology, expected.versionId, slot);
    const value = await send(new GetSecretValueCommand({ SecretId: expected.arn, VersionId: expected.versionId }));
    let payload; try { payload = JSON.parse(value?.SecretString || ""); } catch { throw new Error(`Mixed recovery ${slot} payload is malformed.`); }
    const identity = { arn: described?.ARN, versionId: value?.VersionId, stagingLabels: ["AWSCURRENT"], payloadSha256: payloadHash(payload, slot), schemaKeys: Object.keys(payload || {}).sort(), sourceSha: payload?.sourceSha ?? null, rotationId: payload?.rotationId, slot: payload?.slot, materialFingerprint: payload?.materialFingerprint ?? null, keyVersion: payload?.keyVersion ?? null };
    // Validate every immutable field before treating only its label as progress.
    assertMixedDualSlotPredecessor({ ...MIXED_DUAL_SLOT_PREDECESSOR, [slot]: identity });
    return done;
  }));
  if (observed.some((done, index) => !done && observed.slice(index + 1).some(Boolean))) throw new Error("Mixed recovery partial state is not an authenticated contiguous prefix.");
  return observed.filter(Boolean).length;
}

// Each successful mutation removes only AWSCURRENT from the authenticated unused slot version.
// A retry is safe only for the exact contiguous completed prefix; any other topology fails closed.
export async function executeMixedDualSlotRecovery({ send, preparation, preparationFileSha256, sourceSha, authorization, payloadHash, now = new Date(), reauthenticate = async () => {} } = {}) {
  const checked = assertMixedDualSlotRecoveryPreparation(preparation, { sourceSha });
  preparationFileSha256 ||= authorization?.preparationFileSha256;
  const authenticate = async (allowExpiredResume) => { assertMixedDualSlotRecoveryAuthorization(authorization, { preparation: checked, preparationFileSha256, sourceSha, now, allowExpiredResume }); await reauthenticate({ preparation: checked, authorization }); };
  await authenticate(true);
  let completed = await classifyMixedDualSlotRecoveryProgress({ send, payloadHash }); const initialCompleted = completed;
  await authenticate(completed > 0);
  for (const entry of checked.mutationPlan.slice(completed)) {
    // Re-read all seven identities at every write boundary; an interrupted run can
    // continue only from the immutable contiguous prefix it itself established.
    await authenticate(completed > 0);
    if (await classifyMixedDualSlotRecoveryProgress({ send, payloadHash }) !== completed) throw new Error("Mixed recovery topology changed before mutation.");
    await send(new UpdateSecretVersionStageCommand({ SecretId: entry.secretArn, VersionStage: "AWSCURRENT", RemoveFromVersionId: entry.versionId }));
    completed += 1;
    await authenticate(true);
    if (await classifyMixedDualSlotRecoveryProgress({ send, payloadHash }) !== completed) throw new Error("Mixed recovery topology changed during mutation.");
  }
  if (await classifyMixedDualSlotRecoveryProgress({ send, payloadHash }) !== 7) throw new Error("Mixed recovery post-state is not exact.");
  return Object.freeze({ valid: true, writes: 0, stageLabelMutations: completed - initialCompleted, postState: "SEVEN_EXISTING_RESOURCES_WITHOUT_AWSCURRENT" });
}
