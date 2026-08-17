import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { assertStageBPrivateFile, writeStageBPrivateFileAtomic } from "./stage-b-artifact-contract.mjs";
import { STAGE_A_EXPECTED_STATE_LINEAGE, STAGE_A_STATE_OBJECT } from "./generate-production-green-stage-a-prerequisites.mjs";

const SHA40 = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const read = (filePath, repositoryRoot, label) => { const checked = assertStageBPrivateFile({ filePath, repositoryRoot, label }); return { file: checked.path, bytes: readFileSync(checked.path), value: JSON.parse(readFileSync(checked.path, "utf8")) }; };

export function assertPostApplyStageAPlanRecovery(evidence, { sourceSha, expectedStageBLineage, expectedStageBSerial, now = Date.now(), maxAgeMs = 24 * 60 * 60 * 1000 } = {}) {
  if (!evidence || evidence.schemaVersion !== 1 || evidence.mode !== "POST_APPLY_STAGE_A_PLAN_RECOVERY" || evidence.valid !== true || evidence.sourceSha !== sourceSha || !SHA40.test(sourceSha || "")) throw new Error("Stage-A recovery evidence is not source-bound.");
  if (evidence.stageAStateObject !== STAGE_A_STATE_OBJECT || evidence.stageAStateLineage !== STAGE_A_EXPECTED_STATE_LINEAGE || !Number.isSafeInteger(evidence.stageAStateSerial) || evidence.stageAStateSerial < 1 || !SHA256.test(evidence.stageAStateSha256 || "") || !SHA256.test(evidence.stageAHandoffSha256 || "")) throw new Error("Stage-A recovery evidence has incomplete historical state identity.");
  if (evidence.stageBStateLineage !== expectedStageBLineage || !Number.isSafeInteger(evidence.stageBStateSerial) || evidence.stageBStateSerial !== expectedStageBSerial || !SHA256.test(evidence.stageBStateSha256 || "")) throw new Error("Stage-A recovery evidence is not bound to the converged Stage-B state.");
  if (evidence.ingress?.present !== true || typeof evidence.ingress.endpointSecurityGroupId !== "string" || typeof evidence.ingress.runtimeSecurityGroupId !== "string") throw new Error("Stage-A recovery evidence lacks the authenticated ingress postcondition.");
  if (evidence.postApplyConvergence?.status !== "PASS" || evidence.postApplyConvergence.sourceSha !== sourceSha || evidence.postApplyConvergence.stateLineage !== expectedStageBLineage || evidence.postApplyConvergence.stateSerial !== expectedStageBSerial || evidence.postApplyConvergence.stateSha256 !== evidence.stageBStateSha256) throw new Error("Stage-A recovery evidence lacks the converged post-apply proof.");
  if (!Number.isSafeInteger(Date.parse(evidence.generatedAt)) || Math.abs(now - Date.parse(evidence.generatedAt)) > maxAgeMs) throw new Error("Stage-A recovery evidence is stale.");
  if (!SHA256.test(evidence.evidenceSha256 || "")) throw new Error("Stage-A recovery evidence hash is invalid.");
  const unsigned = { ...evidence }; delete unsigned.evidenceSha256;
  if (hash(Buffer.from(JSON.stringify(unsigned))) !== evidence.evidenceSha256) throw new Error("Stage-A recovery evidence hash does not match its contents.");
  return Object.freeze({ valid: true, recoveryMode: evidence.mode, sourceSha, evidenceRef: evidence.evidenceRef, evidenceSha256: evidence.evidenceSha256, postconditionVerified: true, alreadyConverged: true, appliedExactSavedPlan: false, mutationCount: 0 });
}

export function producePostApplyStageAPlanRecovery({ sourceSha, stageAStatePath, stageAHandoffPath, stageBStatePath, ingress, outputPath, repositoryRoot = process.cwd(), now = new Date().toISOString(), expectedStageBSerial = 98 } = {}) {
  if (!SHA40.test(sourceSha || "") || !outputPath) throw new Error("Stage-A recovery evidence inputs are incomplete.");
  const stageAState = read(stageAStatePath, repositoryRoot, "Stage-A state");
  const stageAHandoff = read(stageAHandoffPath, repositoryRoot, "Stage-A handoff");
  const stageBState = read(stageBStatePath, repositoryRoot, "Stage-B converged state");
  if (stageAHandoff.value.toolingSha !== sourceSha || stageAHandoff.value.stageAStateObject !== STAGE_A_STATE_OBJECT || stageAHandoff.value.stageAStateLineage !== STAGE_A_EXPECTED_STATE_LINEAGE || stageAHandoff.value.stageAStateSerial !== stageAState.value.serial || stageAHandoff.value.stageAStateSha256 !== hash(stageAState.bytes)) throw new Error("Stage-A handoff does not authenticate its state backup and protected source.");
  if (stageBState.value.serial !== expectedStageBSerial) throw new Error("Stage-B state is not the expected serial-98 converged state.");
  const stageBStateSha256 = hash(stageBState.bytes);
  const evidence = {
    schemaVersion: 1, mode: "POST_APPLY_STAGE_A_PLAN_RECOVERY", valid: true, evidenceRef: `stage-a-recovery:${sourceSha}:${hash(stageAHandoff.bytes).slice(0, 16)}`,
    sourceSha, generatedAt: now, stageAStateObject: STAGE_A_STATE_OBJECT, stageAStateLineage: stageAState.value.lineage, stageAStateSerial: stageAState.value.serial, stageAStateSha256: hash(stageAState.bytes), stageAHandoffSha256: hash(stageAHandoff.bytes), stageBStateLineage: stageBState.value.lineage, stageBStateSerial: stageBState.value.serial, stageBStateSha256, ingress, postApplyConvergence: { status: "PASS", sourceSha, stateLineage: stageBState.value.lineage, stateSerial: stageBState.value.serial, stateSha256: stageBStateSha256 }, historicalPlanPresent: false,
  };
  const unsigned = { ...evidence };
  evidence.evidenceSha256 = hash(Buffer.from(JSON.stringify(unsigned)));
  const persisted = writeStageBPrivateFileAtomic({ filePath: outputPath, bytes: Buffer.from(`${JSON.stringify(evidence, null, 2)}\n`), repositoryRoot, label: "Post-apply Stage-A plan recovery evidence" });
  return { ...evidence, path: persisted.path, fileSha256: persisted.sha256 };
}
