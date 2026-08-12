import assert from "node:assert/strict";
import test from "node:test";
import { assertMergedStageBRelease } from "../aws/stage-b-release-gate.mjs";

const sha = "a".repeat(40);
const run = (calls, failures = new Set()) => (_file, args) => {
  calls.push(args);
  if (failures.has(args.join(" "))) throw new Error("git rejected release");
  return ["rev-parse FETCH_HEAD", "rev-parse HEAD"].includes(args.join(" ")) ? `${sha}\n` : "";
};

test("Stage B accepts only a checked-out release SHA merged into origin/main", () => {
  const calls = [];
  assert.doesNotThrow(() => assertMergedStageBRelease(sha, { run: run(calls) }));
  assert.deepEqual(calls.map((args) => args.join(" ")), ["fetch --no-tags origin main", "rev-parse FETCH_HEAD", "rev-parse HEAD", `cat-file -e ${sha}^{commit}`, `merge-base --is-ancestor ${sha} ${sha}`]);
  assert.throws(() => assertMergedStageBRelease(sha.slice(0, 12), { run: run([]) }), /40-character/);
  assert.throws(() => assertMergedStageBRelease(sha, { run: run([], new Set([`cat-file -e ${sha}^{commit}`])) }), /git rejected/);
  assert.throws(() => assertMergedStageBRelease(sha, { run: run([], new Set([`merge-base --is-ancestor ${sha} ${sha}`])) }), /git rejected/);
  assert.throws(() => assertMergedStageBRelease(sha, { run: (_file, args) => args.join(" ") === "rev-parse HEAD" ? "b".repeat(40) : args.join(" ") === "rev-parse FETCH_HEAD" ? `${sha}\n` : "" }), /does not equal/);
  assert.throws(() => assertMergedStageBRelease(sha, { run: (_file, args) => { if (args[0] === "fetch") throw new Error("network unavailable"); return ""; } }), /Fresh protected-main fetch failed/);
});
