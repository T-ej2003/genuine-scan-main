import { createHash, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { STAGE_B } from "./production-green-stage-b-contract.mjs";

const SHA40 = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const ROOT_ARN = `arn:aws:iam::${STAGE_B.account}:root`;
const canonical = (value) => Array.isArray(value) ? `[${value.map(canonical).join(",")}]` : value && typeof value === "object" ? `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}` : JSON.stringify(value);
const hash = (value) => createHash("sha256").update(canonical(value)).digest("hex");

export function assertRootDropEvidence(evidence, { sourceSha, now = Date.now(), maxAgeMs = 15 * 60 * 1000 } = {}) {
  if (!evidence || evidence.schemaVersion !== 1 || evidence.valid !== true || evidence.callerArn !== ROOT_ARN || evidence.accountId !== STAGE_B.account || evidence.region !== STAGE_B.region || evidence.sourceSha !== sourceSha) throw new Error("Root-drop evidence is not bound to the exact administrator, account, region, and protected source.");
  if (typeof evidence.evidenceRef !== "string" || !evidence.evidenceRef.startsWith("root-drop:")) throw new Error("Root-drop evidence reference is invalid.");
  if (!SHA256.test(evidence.evidenceSha256 || "") || !SHA256.test(evidence.nonceHash || "")) throw new Error("Root-drop evidence hashes are invalid.");
  if (!Number.isSafeInteger(Date.parse(evidence.generatedAt)) || Math.abs(now - Date.parse(evidence.generatedAt)) > maxAgeMs) throw new Error("Root-drop evidence is stale.");
  const unsigned = { ...evidence }; delete unsigned.evidenceSha256;
  if (hash(unsigned) !== evidence.evidenceSha256) throw new Error("Root-drop evidence hash does not match its contents.");
  return Object.freeze({ valid: true, evidenceRef: evidence.evidenceRef, evidenceSha256: evidence.evidenceSha256, callerArn: ROOT_ARN, sourceSha, accountId: STAGE_B.account, region: STAGE_B.region });
}

export function buildRootDropEvidence({ sourceSha, callerArn, accountId = STAGE_B.account, region = STAGE_B.region, now = new Date().toISOString(), nonce = randomUUID() } = {}) {
  if (!SHA40.test(sourceSha || "") || callerArn !== ROOT_ARN || accountId !== STAGE_B.account || region !== STAGE_B.region) throw new Error("Exact root administrator identity is required.");
  const unsigned = { schemaVersion: 1, valid: true, evidenceRef: `root-drop:${sourceSha}:${nonce}`, callerArn, accountId, region, sourceSha, generatedAt: now, nonceHash: hash(nonce) };
  return { ...unsigned, evidenceSha256: hash(unsigned) };
}

export function readRootDropEvidence(filePath) {
  return JSON.parse(readFileSync(filePath, "utf8"));
}
