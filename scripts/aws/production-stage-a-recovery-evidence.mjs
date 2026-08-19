import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { assertStageBPrivateFile, writeStageBPrivateFileAtomic } from "./stage-b-artifact-contract.mjs";
import { assertStageAStateContract, STAGE_A_EXPECTED_STATE_LINEAGE, STAGE_A_STATE_IDENTITY_VERSION, stageAStateSemanticSha256, STAGE_A_STATE_OBJECT } from "./generate-production-green-stage-a-prerequisites.mjs";
import { STAGE_B } from "./production-green-stage-b-contract.mjs";

const SHA40 = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const read = (filePath, repositoryRoot, label) => { const checked = assertStageBPrivateFile({ filePath, repositoryRoot, label }); const bytes = readFileSync(checked.path); return { file: checked.path, bytes, value: JSON.parse(bytes.toString("utf8")) }; };

export function readAuthenticatedStageARecoverySources({ stageAStatePath, stageAHandoffPath, stageBStatePath, repositoryRoot = process.cwd() } = {}) {
  const stageAState = read(stageAStatePath, repositoryRoot, "Stage-A state");
  const stageAHandoff = read(stageAHandoffPath, repositoryRoot, "Stage-A handoff");
  const stageBState = read(stageBStatePath, repositoryRoot, "Stage-B state");
  return Object.freeze({ stageAState, stageAHandoff, stageBState });
}

function assertAuthenticatedSources(authenticated, { sourceSha, expectedStageBLineage, expectedStageBSerial, expectedIngress } = {}) {
  if (!authenticated?.stageAState?.bytes || !authenticated?.stageAHandoff?.bytes || !authenticated?.stageBState?.bytes || !authenticated.ingress) throw new Error("Stage-A recovery requires independently authenticated source artifacts and live ingress evidence.");
  const { stageAState, stageAHandoff, stageBState, ingress } = authenticated;
  const stageAContract = assertStageAStateContract(stageAState.value, { stateObject: STAGE_A_STATE_OBJECT, phase: "POST_APPLY" });
  if (stageAState.value.lineage !== STAGE_A_EXPECTED_STATE_LINEAGE || stageAState.value.serial !== stageAContract.stateSerial) throw new Error("Authenticated Stage-A state identity is inconsistent.");
  if (stageAHandoff.value.toolingSha !== sourceSha || stageAHandoff.value.stageAStateIdentityVersion !== STAGE_A_STATE_IDENTITY_VERSION || stageAHandoff.value.stageAStateObject !== STAGE_A_STATE_OBJECT || stageAHandoff.value.stageAStateLineage !== STAGE_A_EXPECTED_STATE_LINEAGE || stageAHandoff.value.stageAStateSerial !== stageAState.value.serial || stageAHandoff.value.stageAStateSha256 !== stageAStateSemanticSha256(stageAState.value)) throw new Error("Authenticated Stage-A handoff does not bind the exact Stage-A state and protected source.");
  if (stageBState.value?.version !== 4 || !Array.isArray(stageBState.value.resources) || stageBState.value.resources.length === 0 || !stageBState.value.outputs || typeof stageBState.value.outputs !== "object") throw new Error("Authenticated Stage-B state is truncated or incomplete.");
  if (stageBState.value.lineage !== expectedStageBLineage || stageBState.value.serial !== expectedStageBSerial) throw new Error("Authenticated Stage-B state does not match the converged lineage and serial.");
  if (ingress.present !== true || ingress.endpointSecurityGroupId !== stageAContract.endpointSecurityGroupId || ingress.runtimeSecurityGroupId !== stageAContract.executorSecurityGroupId || ingress.direction !== "ingress" || ingress.protocol !== "tcp" || ingress.fromPort !== 443 || ingress.toPort !== 443) throw new Error("Live Stage-A ingress does not match the exact state-derived TCP/443 relationship.");
  if (expectedIngress && JSON.stringify(ingress) !== JSON.stringify(expectedIngress)) throw new Error("Live Stage-A ingress does not match independently authenticated recovery evidence.");
  return { stageAStateIdentityVersion: STAGE_A_STATE_IDENTITY_VERSION, stageAStateSha256: stageAStateSemanticSha256(stageAState.value), stageAHandoffSha256: hash(stageAHandoff.bytes), stageBStateSha256: hash(stageBState.bytes), ingress, stageAContract };
}

export function assertPostApplyStageAPlanRecovery(evidence, { sourceSha, expectedStageBLineage, expectedStageBSerial, authenticated, now = Date.now(), maxAgeMs = 24 * 60 * 60 * 1000 } = {}) {
  if (!evidence || evidence.schemaVersion !== 1 || evidence.mode !== "POST_APPLY_STAGE_A_PLAN_RECOVERY" || evidence.valid !== true || evidence.sourceSha !== sourceSha || !SHA40.test(sourceSha || "")) throw new Error("Stage-A recovery evidence is not source-bound.");
  if (evidence.stageAStateIdentityVersion !== STAGE_A_STATE_IDENTITY_VERSION || evidence.stageAStateObject !== STAGE_A_STATE_OBJECT || evidence.stageAStateLineage !== STAGE_A_EXPECTED_STATE_LINEAGE || !Number.isSafeInteger(evidence.stageAStateSerial) || evidence.stageAStateSerial < 1 || !SHA256.test(evidence.stageAStateSha256 || "") || !SHA256.test(evidence.stageAHandoffSha256 || "")) throw new Error("Stage-A recovery evidence has incomplete historical state identity.");
  if (evidence.stageBStateLineage !== expectedStageBLineage || !Number.isSafeInteger(evidence.stageBStateSerial) || evidence.stageBStateSerial !== expectedStageBSerial || !SHA256.test(evidence.stageBStateSha256 || "")) throw new Error("Stage-A recovery evidence is not bound to the converged Stage-B state.");
  const authenticatedSources = assertAuthenticatedSources(authenticated, { sourceSha, expectedStageBLineage, expectedStageBSerial, expectedIngress: evidence.ingress });
  if (evidence.stageAStateSha256 !== authenticatedSources.stageAStateSha256 || evidence.stageAHandoffSha256 !== authenticatedSources.stageAHandoffSha256 || evidence.stageBStateSha256 !== authenticatedSources.stageBStateSha256 || JSON.stringify(evidence.ingress) !== JSON.stringify(authenticatedSources.ingress)) throw new Error("Stage-A recovery evidence does not match independently authenticated source and live observations.");
  if (evidence.postApplyConvergence?.status !== "PASS" || evidence.postApplyConvergence.sourceSha !== sourceSha || evidence.postApplyConvergence.stateLineage !== expectedStageBLineage || evidence.postApplyConvergence.stateSerial !== expectedStageBSerial || evidence.postApplyConvergence.stateSha256 !== evidence.stageBStateSha256) throw new Error("Stage-A recovery evidence lacks the converged post-apply proof.");
  if (!Number.isSafeInteger(Date.parse(evidence.generatedAt)) || Math.abs(now - Date.parse(evidence.generatedAt)) > maxAgeMs) throw new Error("Stage-A recovery evidence is stale.");
  if (!SHA256.test(evidence.evidenceSha256 || "")) throw new Error("Stage-A recovery evidence hash is invalid.");
  const unsigned = { ...evidence }; delete unsigned.evidenceSha256;
  if (hash(Buffer.from(JSON.stringify(unsigned))) !== evidence.evidenceSha256) throw new Error("Stage-A recovery evidence hash does not match its contents.");
  return Object.freeze({ valid: true, recoveryMode: evidence.mode, sourceSha, evidenceRef: evidence.evidenceRef, evidenceSha256: evidence.evidenceSha256, postconditionVerified: true, alreadyConverged: true, appliedExactSavedPlan: false, mutationCount: 0 });
}

export function producePostApplyStageAPlanRecovery({ sourceSha, stageAStatePath, stageAHandoffPath, stageBStatePath, ingress, outputPath, repositoryRoot = process.cwd(), now = new Date().toISOString(), expectedStageBSerial = 98 } = {}) {
  if (!SHA40.test(sourceSha || "") || !outputPath) throw new Error("Stage-A recovery evidence inputs are incomplete.");
  const { stageAState, stageAHandoff, stageBState } = readAuthenticatedStageARecoverySources({ stageAStatePath, stageAHandoffPath, stageBStatePath, repositoryRoot });
  const stageAContract = assertStageAStateContract(stageAState.value, { stateObject: STAGE_A_STATE_OBJECT, phase: "POST_APPLY" });
  if (stageAHandoff.value.toolingSha !== sourceSha || stageAHandoff.value.stageAStateIdentityVersion !== STAGE_A_STATE_IDENTITY_VERSION || stageAHandoff.value.stageAStateObject !== STAGE_A_STATE_OBJECT || stageAHandoff.value.stageAStateLineage !== STAGE_A_EXPECTED_STATE_LINEAGE || stageAHandoff.value.stageAStateSerial !== stageAState.value.serial || stageAHandoff.value.stageAStateSha256 !== stageAStateSemanticSha256(stageAState.value)) throw new Error("Stage-A handoff does not authenticate its state backup and protected source.");
  if (stageBState.value.serial !== expectedStageBSerial) throw new Error("Stage-B state is not the expected serial-98 converged state.");
  if (ingress?.present !== true || ingress.endpointSecurityGroupId !== stageAContract.endpointSecurityGroupId || ingress.runtimeSecurityGroupId !== stageAContract.executorSecurityGroupId || ingress.direction !== "ingress" || ingress.protocol !== "tcp" || ingress.fromPort !== 443 || ingress.toPort !== 443) throw new Error("Stage-A recovery ingress is not the exact state-derived TCP/443 endpoint relationship.");
  const stageBStateSha256 = hash(stageBState.bytes);
  const evidence = {
    schemaVersion: 1, mode: "POST_APPLY_STAGE_A_PLAN_RECOVERY", valid: true, evidenceRef: `stage-a-recovery:${sourceSha}:${hash(stageAHandoff.bytes).slice(0, 16)}`,
    sourceSha, generatedAt: now, stageAStateIdentityVersion: STAGE_A_STATE_IDENTITY_VERSION, stageAStateObject: STAGE_A_STATE_OBJECT, stageAStateLineage: stageAState.value.lineage, stageAStateSerial: stageAState.value.serial, stageAStateSha256: stageAStateSemanticSha256(stageAState.value), stageAHandoffSha256: hash(stageAHandoff.bytes), stageBStateLineage: stageBState.value.lineage, stageBStateSerial: stageBState.value.serial, stageBStateSha256, ingress, postApplyConvergence: { status: "PASS", sourceSha, stateLineage: stageBState.value.lineage, stateSerial: stageBState.value.serial, stateSha256: stageBStateSha256 }, historicalPlanPresent: false,
  };
  const unsigned = { ...evidence };
  evidence.evidenceSha256 = hash(Buffer.from(JSON.stringify(unsigned)));
  assertPostApplyStageAPlanRecovery(evidence, { sourceSha, expectedStageBLineage: stageBState.value.lineage, expectedStageBSerial, authenticated: { stageAState, stageAHandoff, stageBState, ingress }, now: Date.parse(now) });
  const persisted = writeStageBPrivateFileAtomic({ filePath: outputPath, bytes: Buffer.from(`${JSON.stringify(evidence, null, 2)}\n`), repositoryRoot, label: "Post-apply Stage-A plan recovery evidence" });
  return { ...evidence, path: persisted.path, fileSha256: persisted.sha256 };
}
