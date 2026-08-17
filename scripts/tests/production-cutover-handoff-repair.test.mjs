import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { assertRootDropEvidence, buildRootDropEvidence } from "../aws/production-root-drop-evidence.mjs";
import { assertPostApplyStageAPlanRecovery, producePostApplyStageAPlanRecovery } from "../aws/production-stage-a-recovery-evidence.mjs";
import { INITIAL_DUAL_SLOT_NAMES, supersedeStalePendingRotation } from "../aws/production-initial-dual-slot-bootstrap.mjs";
import { fixtureInput, sourceSha as rehearsalSourceSha } from "./production-cutover-rehearsal.test.mjs";
import { runProductionCutoverControlPlane } from "../aws/production-cutover-control-plane.mjs";

const sourceSha = "8".repeat(40);
const staleSourceSha = "e".repeat(40);
const rotationId = "rotation-new-20260817";
const staleRotationId = "rotation-old-20260812";
const arn = (name) => `arn:aws:secretsmanager:eu-west-2:368992683803:secret:${name.replaceAll("/", "-")}-abc`;
const digest = (value) => createHash("sha256").update(value).digest("hex");

test("root-drop evidence is exact, source-bound, fresh, and tamper-evident", () => {
  const evidence = buildRootDropEvidence({ sourceSha, callerArn: "arn:aws:iam::368992683803:root", now: new Date().toISOString(), nonce: "nonce-1" });
  assert.equal(assertRootDropEvidence(evidence, { sourceSha }).valid, true);
  assert.throws(() => assertRootDropEvidence({ ...evidence, sourceSha: staleSourceSha }, { sourceSha }), /source/);
  assert.throws(() => assertRootDropEvidence({ ...evidence, callerArn: "arn:aws:iam::368992683803:user:admin" }, { sourceSha }), /source/);
  assert.throws(() => assertRootDropEvidence({ ...evidence, evidenceSha256: "0".repeat(64) }, { sourceSha }), /hash/);
});

test("post-apply Stage-A recovery is distinct from and stricter than a historical plan", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-stage-a-recovery-"));
  const stateBytes = Buffer.from(JSON.stringify({ version: 4, serial: 42, lineage: "02afb75a-f902-ab8a-f4c1-751d4aef7837" }));
  const statePath = path.join(directory, "stage-a-state.json");
  const handoffPath = path.join(directory, "stage-a-handoff.json");
  const stageBPath = path.join(directory, "stage-b-state.json");
  const outputPath = path.join(directory, "recovery-evidence.json");
  writeFileSync(statePath, stateBytes, { mode: 0o600 });
  writeFileSync(handoffPath, JSON.stringify({ toolingSha: sourceSha, stageAStateObject: "mscqr/production/rls-green/stage-a/terraform.tfstate", stageAStateLineage: "02afb75a-f902-ab8a-f4c1-751d4aef7837", stageAStateSerial: 42, stageAStateSha256: digest(stateBytes) }), { mode: 0o600 });
  writeFileSync(stageBPath, JSON.stringify({ serial: 98, lineage: "4e438e59-8b8b-194d-030c-5ede0c26344a" }), { mode: 0o600 });
  const evidence = producePostApplyStageAPlanRecovery({ sourceSha, stageAStatePath: statePath, stageAHandoffPath: handoffPath, stageBStatePath: stageBPath, ingress: { present: true, endpointSecurityGroupId: "sg-endpoint", runtimeSecurityGroupId: "sg-runtime" }, outputPath, repositoryRoot: "/private/tmp/mscqr-post330-exec" });
  assert.equal(evidence.historicalPlanPresent, false);
  assert.equal(assertPostApplyStageAPlanRecovery(JSON.parse(readFileSync(outputPath)), { sourceSha, expectedStageBLineage: "4e438e59-8b8b-194d-030c-5ede0c26344a", expectedStageBSerial: 98 }).alreadyConverged, true);
  assert.throws(() => assertPostApplyStageAPlanRecovery({ ...JSON.parse(readFileSync(outputPath)), sourceSha: staleSourceSha }, { sourceSha, expectedStageBLineage: "4e438e59-8b8b-194d-030c-5ede0c26344a", expectedStageBSerial: 98 }), /source/);
});

test("stale rotation supersession requires exact old topology and writes a new identity", async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-rotation-supersession-"));
  const store = new Map();
  for (const [slot, name] of Object.entries(INITIAL_DUAL_SLOT_NAMES)) {
    const value = ["jwtPending", "qrPrivatePending", "qrPublicPending"].includes(slot)
      ? { value: `${slot}-old`, sourceSha: staleSourceSha, rotationId: staleRotationId, family: slot === "jwtPending" ? "jwt_secrets" : "qr_signing_keys", slot: slot === "jwtPending" ? "pending" : slot === "qrPrivatePending" ? "pending-private" : "pending-public", materialFingerprint: digest(`${slot}-old`).slice(0, 16) }
      : { value: slot === "qrCurrentVersion" ? "v1" : "", sourceSha: staleSourceSha, family: slot === "qrCurrentVersion" || slot === "qrPreviousVersion" ? "qr_key_versions" : slot === "jwtPrevious" ? "jwt_secrets" : "qr_signing_keys", slot: "old", initialMigration: true };
    store.set(name, { value, versionId: `${slot}-old` });
  }
  const send = async (command) => {
    const name = command.input.SecretId;
    const key = [...store.keys()].find((candidate) => candidate === name || arn(candidate) === name);
    if (command.constructor.name === "DescribeSecretCommand") return { Name: key, ARN: arn(key), VersionIdsToStages: { [store.get(key).versionId]: ["AWSCURRENT"] } };
    if (command.constructor.name === "GetSecretValueCommand") return { SecretString: JSON.stringify(store.get(key).value) };
    if (command.constructor.name === "PutSecretValueCommand") { const versionId = command.input.ClientRequestToken; store.set(key, { value: JSON.parse(command.input.SecretString), versionId }); return { VersionId: versionId }; }
    throw new Error(`unexpected command ${command.constructor.name}`);
  };
  const result = await supersedeStalePendingRotation({ send, sourceSha, staleSourceSha, rotationId, staleRotationId, outputFile: path.join(directory, "supersession.json"), repositoryRoot: "/private/tmp/mscqr-post330-exec" });
  assert.equal(result.writes, 7);
  await assert.rejects(() => supersedeStalePendingRotation({ send, sourceSha: "7".repeat(40), staleSourceSha, rotationId: "rotation-new-20260818", staleRotationId, outputFile: path.join(directory, "second.json"), repositoryRoot: "/private/tmp/mscqr-post330-exec" }), /mixed|stale/i);
});

test("serial-98 Stage-A recovery evidence traverses the real cutover spine without an apply", async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-serial-98-twin-"));
  const state = { version: 4, serial: 42, lineage: "02afb75a-f902-ab8a-f4c1-751d4aef7837" };
  const stateBytes = Buffer.from(JSON.stringify(state));
  const statePath = path.join(directory, "stage-a-state.json");
  const handoffPath = path.join(directory, "stage-a-handoff.json");
  const stageBPath = path.join(directory, "stage-b-state.json");
  const evidencePath = path.join(directory, "stage-a-recovery.json");
  writeFileSync(statePath, stateBytes, { mode: 0o600 });
  writeFileSync(handoffPath, JSON.stringify({ toolingSha: rehearsalSourceSha, stageAStateObject: "mscqr/production/rls-green/stage-a/terraform.tfstate", stageAStateLineage: state.lineage, stageAStateSerial: state.serial, stageAStateSha256: digest(stateBytes) }), { mode: 0o600 });
  writeFileSync(stageBPath, JSON.stringify({ serial: 98, lineage: "4e438e59-8b8b-194d-030c-5ede0c26344a" }), { mode: 0o600 });
  const recovery = producePostApplyStageAPlanRecovery({ sourceSha: rehearsalSourceSha, stageAStatePath: statePath, stageAHandoffPath: handoffPath, stageBStatePath: stageBPath, ingress: { present: true, endpointSecurityGroupId: "sg-endpoint", runtimeSecurityGroupId: "sg-runtime" }, outputPath: evidencePath, repositoryRoot: "/private/tmp/mscqr-post330-exec" });
  const result = await runProductionCutoverControlPlane({ ...fixtureInput({ stageA: { recoveryEvidence: JSON.parse(readFileSync(evidencePath, "utf8")) } }), sourceSha: rehearsalSourceSha });
  assert.equal(result.results.stageA.recoveryMode, "POST_APPLY_STAGE_A_PLAN_RECOVERY");
  assert.equal(result.mutationSequence.some(({ name }) => name === "M2_STAGE_A_APPLY"), false);
  assert.equal(result.readyForOnboarding, true);
});
