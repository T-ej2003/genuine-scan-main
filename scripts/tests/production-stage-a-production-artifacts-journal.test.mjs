import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import {
  createStageAProductionArtifactsJournal,
  createStageAProductionArtifactsJournalResult,
  createStageAProductionArtifactsReservation,
  assertStageAProductionArtifactsReservation,
} from "../aws/production-stage-a-production-artifacts-journal.mjs";

const identity = Object.freeze({
  operation: "STAGE_A_PRODUCTION_ARTIFACTS_STATE_RECONCILIATION",
  sourceSha: "a".repeat(40), account: "368992683803", region: "eu-west-2",
  executionPrincipal: "arn:aws:iam::368992683803:role/mscqr-production-release-deployer",
  authorizationSha256: "b".repeat(64), recoveryCompletionSha256: "c".repeat(64),
  savedPlanSha256: "d".repeat(64), preStateLineage: "02afb75a-f902-ab8a-f4c1-751d4aef7837",
  preStateSerial: 35, preStateSha256: "e".repeat(64), desiredPolicySha256: "f".repeat(64),
});

function memoryS3() {
  const objects = new Map(); const calls = [];
  const run = (args) => {
    calls.push([...args]); const operation = args[1]; const key = args[args.indexOf("--key") + 1];
    if (operation === "put-object") {
      assert.equal(args[args.indexOf("--if-none-match") + 1], "*");
      if (objects.has(key)) { const error = new Error("PreconditionFailed"); error.stderr = "PreconditionFailed"; throw error; }
      objects.set(key, fs.readFileSync(args[args.indexOf("--body") + 1])); return JSON.stringify({ ETag: "exact" });
    }
    if (operation === "get-object") {
      if (!objects.has(key)) { const error = new Error("NoSuchKey"); error.stderr = "NoSuchKey"; throw error; }
      fs.writeFileSync(args.at(-1), objects.get(key)); return JSON.stringify({});
    }
    throw new Error(`unexpected S3 journal operation ${operation}`);
  };
  return { run, calls, objects };
}

test("Stage A reconciliation journal atomically reserves once and never overwrites or deletes", async () => {
  const s3 = memoryS3(); const journal = createStageAProductionArtifactsJournal({ run: s3.run });
  const attempts = await Promise.allSettled([Promise.resolve().then(() => journal.reserve(identity)), Promise.resolve().then(() => journal.reserve(identity))]);
  assert.equal(attempts.filter(({ status }) => status === "fulfilled").length, 1);
  assert.equal(attempts.filter(({ status }) => status === "rejected").length, 1);
  const reservation = attempts.find(({ status }) => status === "fulfilled").value.reservation;
  const completion = journal.finalize({ reservation, status: "COMPLETED", postState: { lineage: identity.preStateLineage, serial: 36, stateSha256: "1".repeat(64) }, postLivePolicySha256: identity.desiredPolicySha256 });
  assert.equal(completion.result.status, "COMPLETED");
  assert.throws(() => journal.finalize({ reservation, status: "COMPLETED", postState: { lineage: identity.preStateLineage, serial: 36, stateSha256: "1".repeat(64) }, postLivePolicySha256: identity.desiredPolicySha256 }), /terminal journal result/);
  assert(s3.calls.every((args) => ["get-object", "put-object"].includes(args[1])));
  assert(s3.calls.filter((args) => args[1] === "put-object").every((args) => args.includes("--if-none-match") && args.includes("*")));
});

test("Stage A reconciliation journal makes non-success terminal and rejects substituted identities", () => {
  const reservation = createStageAProductionArtifactsReservation(identity);
  const result = createStageAProductionArtifactsJournalResult({ reservation, status: "FAILED_OR_INDETERMINATE" });
  assert.equal(result.refreshOnlyApplyCount, 0);
  assert.equal(result.postStateSha256, null);
  const substituted = createStageAProductionArtifactsReservation({ ...identity, preStateSha256: "0".repeat(64) });
  assert.throws(() => assertStageAProductionArtifactsReservation(substituted, { preStateSha256: identity.preStateSha256 }), /authorized operation/);
  assert.throws(() => createStageAProductionArtifactsJournalResult({ reservation, status: "COMPLETED", postState: { lineage: reservation.preStateLineage, serial: reservation.preStateSerial, stateSha256: "1".repeat(64) }, postLivePolicySha256: reservation.desiredPolicySha256 }), /completed result/);
});

test("Stage A recovery attempt is immutable and authorization-namespaced", () => {
  const s3 = memoryS3(); const journal = createStageAProductionArtifactsJournal({ run: s3.run }); const bytes = Buffer.from('{"signed":"attempt"}\n');
  const first = journal.writeRecoveryAttempt({ recoveryAuthorizationSha256: "9".repeat(64), bytes });
  assert.match(first.key, /recovery\/9{64}\/attempt\.json$/);
  assert.deepEqual(journal.readRecoveryAttempt("9".repeat(64)).bytes, bytes);
  assert.throws(() => journal.writeRecoveryAttempt({ recoveryAuthorizationSha256: "9".repeat(64), bytes }), /already exists/);
  assert.equal(s3.calls.filter((args) => args[1] === "put-object").every((args) => args.includes("--if-none-match") && args.includes("*")), true);
});

test("Stage A reconciliation journal reads only the authorization-derived exact record key", () => {
  const s3 = memoryS3(); const journal = createStageAProductionArtifactsJournal({ run: s3.run });
  assert.equal(journal.readReservation(identity.authorizationSha256), null);
  const read = s3.calls.at(-1); const key = read[read.indexOf("--key") + 1]; const bucket = read[read.indexOf("--bucket") + 1];
  assert.equal(bucket, "mscqr-prod-euw2-artifacts-368992683803-eu-west-2-an");
  assert.equal(key, `production-stage-a-production-artifacts-reconciliation/${identity.authorizationSha256}/reservation.json`);
  for (const substituted of ["x".repeat(64), `${identity.authorizationSha256}0`]) assert.throws(() => journal.readReservation(substituted), /journal key/);
});
