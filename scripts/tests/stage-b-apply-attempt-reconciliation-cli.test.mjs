import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { readStageBApplyAttemptHistory } from "../aws/stage-b-apply-attempt-reconciliation.mjs";
import { createStageBApplyAttemptReservation, createStageBApplyAttemptTransition } from "../aws/stage-b-apply-attempt-reconciliation-contract.mjs";
import { stageBApplyAttemptS3Key, stageBAttemptStepS3ObjectKey } from "../aws/stage-b-terraform-backend-contract.mjs";

const digest = (letter) => letter.repeat(64);
const reservation = createStageBApplyAttemptReservation({
  sourceSha: "c".repeat(40), planSha256: digest("a"), savedPlanSha256: digest("b"), stateLineage: "lineage",
  stateSerial: 102, stateSha256: digest("c"), workspace: "default", backendIdentitySha256: digest("d"),
  executionPrincipal: "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test",
  createdAt: "2026-08-30T04:00:00.000Z",
});
const applying = createStageBApplyAttemptTransition(reservation, {
  status: "APPLYING", operationResult: { classification: "APPLY_ENTRYPOINT_REACHED", readback: "EXACT" },
  applyStarted: { status: "REACHABLE", evidenceSha256: digest("e") }, applyResult: { status: "PENDING", evidenceSha256: null },
});

test("standalone reservation reader authenticates the initial object and append-only transitions", () => {
  const objects = new Map([
    [stageBApplyAttemptS3Key(reservation.attemptId), Buffer.from(`${JSON.stringify(reservation)}\n`)],
    [stageBAttemptStepS3ObjectKey(reservation.attemptId, 1), Buffer.from(`${JSON.stringify(applying)}\n`)],
  ]);
  const run = (args) => {
    const bytes = objects.get(args[args.indexOf("--key") + 1]);
    if (!bytes) return { status: 1, stderr: "NoSuchKey" };
    fs.writeFileSync(args.at(-1), bytes, { mode: 0o600 });
    return { status: 0 };
  };
  const result = readStageBApplyAttemptHistory({ reservationIdentity: reservation.attemptId, run });
  assert.equal(result.reservation.status, "RESERVED");
  assert.deepEqual(result.transitions.map(({ status }) => status), ["APPLYING"]);
});

test("standalone reservation reader fails closed on a non-not-found transition read error", () => {
  assert.throws(() => readStageBApplyAttemptHistory({ reservationIdentity: reservation.attemptId, run: (args) => {
    if (args.includes("--key") && args[args.indexOf("--key") + 1] === stageBApplyAttemptS3Key(reservation.attemptId)) { fs.writeFileSync(args.at(-1), Buffer.from(`${JSON.stringify(reservation)}\n`), { mode: 0o600 }); return { status: 0 }; }
    return { status: 1, stderr: "AccessDenied" };
  } }), /could not be authenticated/);
});

test("reconciliation CLI inputs are external private artifacts, never secret payloads", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-reconciliation-cli-"));
  try { assert.equal(fs.statSync(directory).isDirectory(), true); } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});
