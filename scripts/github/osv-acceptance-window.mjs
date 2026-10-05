import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { validateException } from "../lib/dependency-risk-acceptance.mjs";

const recordPath = "documents/security/osv-non-runtime-acceptance.json";
export function assertDeploymentAcceptanceWindow(record, today = new Date().toISOString().slice(0, 10)) {
  assert.equal(record.schemaVersion, 1);
  assert.ok(Array.isArray(record.entries), "Missing deployment acceptance evidence");
  for (const entry of record.entries) assert.equal(validateException(entry, today, ["frontend-build-only/non-runtime"]), null, "Deployment acceptance expired/invalid; rerun audit only after remediation or reviewed renewal");
  return record.entries.map(({ advisory, expiresOn }) => ({ advisory, expiresOn }));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  let record;
  if (args.length) {
    assert.equal(args.length, 2); assert.equal(args[0], "--revision"); assert.match(args[1], /^[a-f0-9]{40}$/);
    // The final required-gate check authenticates this same immutable target SHA.
    // Read its acceptance blob, never a newer branch or user-supplied deadline.
    const listed = execFileSync("git", ["ls-tree", args[1], "--", recordPath], { encoding: "utf8" });
    record = listed.trim() ? JSON.parse(execFileSync("git", ["show", `${args[1]}:${recordPath}`], { encoding: "utf8" })) : { schemaVersion: 1, entries: [] };
  } else record = existsSync(recordPath) ? JSON.parse(readFileSync(recordPath, "utf8")) : { schemaVersion: 1, entries: [] };
  console.log(JSON.stringify({ deploymentAcceptanceWindow: assertDeploymentAcceptanceWindow(record) }));
}
