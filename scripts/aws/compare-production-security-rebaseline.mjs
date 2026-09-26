import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { parseArgs } from "node:util";
import { fileURLToPath, pathToFileURL } from "node:url";
import { assertProtectedCheckout } from "./prepare-production-initial-activation-reconciler-installation.mjs";
import { readStageBPrivateFileBytes, writeStageBPrivateFileExclusive } from "./stage-b-artifact-contract.mjs";
import { assertSecurityRebaselineInventory, diffSecurityRebaselineInventories, securityRebaselineLogSummary } from "./production-security-rebaseline-inventory.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url));

export function compareProductionSecurityRebaseline({ sourceSha, livePath, canonicalPath, outPath, repositoryRoot = root, assertCheckout = assertProtectedCheckout }) {
  assert.match(sourceSha || "", /^[a-f0-9]{40}$/); assertCheckout({ sourceSha, repositoryRoot });
  const read = (filePath) => JSON.parse(readStageBPrivateFileBytes({ filePath, repositoryRoot }).bytes);
  const live = assertSecurityRebaselineInventory(read(livePath), { protectedMainSha: sourceSha });
  const canonical = assertSecurityRebaselineInventory(read(canonicalPath), { protectedMainSha: sourceSha });
  assert.equal(live.kind, "PRODUCTION_SECURITY_REBASELINE_LIVE_INVENTORY"); assert.equal(canonical.kind, "PRODUCTION_SECURITY_REBASELINE_CANONICAL_INVENTORY");
  const diff = diffSecurityRebaselineInventories(live, canonical); const file = writeStageBPrivateFileExclusive({ filePath: outPath, bytes: Buffer.from(`${JSON.stringify(diff)}\n`), repositoryRoot });
  return Object.freeze({ status: "PRODUCTION_SECURITY_REBASELINE_COMPARED", artifactPath: file.path, ...securityRebaselineLogSummary(diff) });
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  try { const { values } = parseArgs({ options: { "source-sha": { type: "string" }, live: { type: "string" }, canonical: { type: "string" }, out: { type: "string" } }, strict: true });
    assert.ok(values.live && values.canonical && values.out); process.stdout.write(`${JSON.stringify(compareProductionSecurityRebaseline({ sourceSha: values["source-sha"], livePath: values.live, canonicalPath: values.canonical, outPath: values.out }))}\n`);
  } catch { process.stderr.write("Production security rebaseline comparison failed closed; no mutation was attempted.\n"); process.exitCode = 1; }
}
