import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { STAGE_B, STAGE_B_APPROVAL_ALGORITHM } from "./production-green-stage-b-contract.mjs";

const SHA40 = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const ROOT_ARN = `arn:aws:iam::${STAGE_B.account}:root`;
export const ROOT_DROP_SIGNING_KEY_ARN = STAGE_B.approvalKmsKeyArn;
export const ROOT_DROP_SIGNING_ALGORITHM = STAGE_B_APPROVAL_ALGORITHM;
export const ROOT_DROP_VERIFY_PROFILE = "mscqr-production-release-deployer";
const canonical = (value) => Array.isArray(value) ? `[${value.map(canonical).join(",")}]` : value && typeof value === "object" ? `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}` : JSON.stringify(value);
const hash = (value) => createHash("sha256").update(typeof value === "string" || Buffer.isBuffer(value) ? value : canonical(value)).digest("hex");
const unsignedFields = ["schemaVersion", "valid", "evidenceRef", "callerArn", "accountId", "region", "sourceSha", "generatedAt", "nonceHash"];
const signedFields = [...unsignedFields, "signingKeyArn", "signingAlgorithm", "signedPayloadSha256", "signatureBase64"];
export const canonicalRootDropPayload = (value) => canonical(value);

export function buildRootDropPayload({ sourceSha, callerArn, accountId = STAGE_B.account, region = STAGE_B.region, now = new Date().toISOString(), nonce } = {}) {
  if (!SHA40.test(sourceSha || "") || callerArn !== ROOT_ARN || accountId !== STAGE_B.account || region !== STAGE_B.region || typeof nonce !== "string" || nonce.length < 16) throw new Error("Exact root administrator identity is required.");
  return { schemaVersion: 1, valid: true, evidenceRef: `root-drop:${sourceSha}:${hash(nonce).slice(0, 16)}`, callerArn, accountId, region, sourceSha, generatedAt: now, nonceHash: hash(nonce) };
}

export function buildRootDropEvidence({ sourceSha, callerArn, accountId = STAGE_B.account, region = STAGE_B.region, now = new Date().toISOString(), nonce, signatureBase64, signingKeyArn = ROOT_DROP_SIGNING_KEY_ARN, signingAlgorithm = ROOT_DROP_SIGNING_ALGORITHM } = {}) {
  const unsigned = buildRootDropPayload({ sourceSha, callerArn, accountId, region, now, nonce });
  if (signingKeyArn !== ROOT_DROP_SIGNING_KEY_ARN || signingAlgorithm !== ROOT_DROP_SIGNING_ALGORITHM || !/^[A-Za-z0-9+/]+={0,2}$/.test(signatureBase64 || "")) throw new Error("Root-drop evidence requires the reviewed KMS signature.");
  const signed = { ...unsigned, signingKeyArn, signingAlgorithm, signedPayloadSha256: hash(unsigned), signatureBase64 };
  return { ...signed, evidenceSha256: hash(signed) };
}

export function verifyRootDropEvidenceWithKms({ message, signature, keyArn = ROOT_DROP_SIGNING_KEY_ARN, signingAlgorithm = ROOT_DROP_SIGNING_ALGORITHM, profile = ROOT_DROP_VERIFY_PROFILE } = {}) {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-root-drop-verify-"));
  const messagePath = path.join(directory, "message");
  const signaturePath = path.join(directory, "signature");
  try {
    writeFileSync(messagePath, message, { mode: 0o600, flag: "wx" });
    writeFileSync(signaturePath, signature, { mode: 0o600, flag: "wx" });
    const result = JSON.parse(execFileSync("aws", ["kms", "verify", "--key-id", keyArn, "--message", `fileb://${messagePath}`, "--message-type", "RAW", "--signature", `fileb://${signaturePath}`, "--signing-algorithm", signingAlgorithm, "--profile", profile, "--region", STAGE_B.region, "--output", "json", "--no-cli-pager"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }));
    return result.SignatureValid === true;
  } finally { rmSync(directory, { recursive: true, force: true }); }
}

export function assertRootDropEvidence(evidence, { sourceSha, now = Date.now(), maxAgeMs = 15 * 60 * 1000, verifySignature = verifyRootDropEvidenceWithKms } = {}) {
  if (!evidence || Object.keys(evidence).sort().join(",") !== [...signedFields, "evidenceSha256"].sort().join(",") || evidence.schemaVersion !== 1 || evidence.valid !== true || evidence.callerArn !== ROOT_ARN || evidence.accountId !== STAGE_B.account || evidence.region !== STAGE_B.region || evidence.sourceSha !== sourceSha) throw new Error("Root-drop evidence is not bound to the exact administrator, account, region, and protected source.");
  if (typeof evidence.evidenceRef !== "string" || !evidence.evidenceRef.startsWith("root-drop:") || !SHA256.test(evidence.evidenceSha256 || "") || !SHA256.test(evidence.nonceHash || "") || evidence.signingKeyArn !== ROOT_DROP_SIGNING_KEY_ARN || evidence.signingAlgorithm !== ROOT_DROP_SIGNING_ALGORITHM || !SHA256.test(evidence.signedPayloadSha256 || "") || !/^[A-Za-z0-9+/]+={0,2}$/.test(evidence.signatureBase64 || "")) throw new Error("Root-drop evidence signature envelope is invalid.");
  const parsedTime = Date.parse(evidence.generatedAt);
  if (!Number.isSafeInteger(parsedTime) || Math.abs(now - parsedTime) > maxAgeMs) throw new Error("Root-drop evidence is stale.");
  const unsigned = Object.fromEntries(unsignedFields.map((field) => [field, evidence[field]]));
  const signed = Object.fromEntries(signedFields.map((field) => [field, evidence[field]]));
  if (hash(unsigned) !== evidence.signedPayloadSha256 || hash(signed) !== evidence.evidenceSha256) throw new Error("Root-drop evidence hash does not match its contents.");
  if (typeof verifySignature !== "function" || verifySignature({ message: Buffer.from(canonical(unsigned)), signature: Buffer.from(evidence.signatureBase64, "base64"), keyArn: evidence.signingKeyArn, signingAlgorithm: evidence.signingAlgorithm }) !== true) throw new Error("Root-drop evidence KMS signature verification failed.");
  return Object.freeze({ valid: true, evidenceRef: evidence.evidenceRef, evidenceSha256: evidence.evidenceSha256, callerArn: ROOT_ARN, sourceSha, accountId: STAGE_B.account, region: STAGE_B.region });
}

export function readRootDropEvidence(filePath) { return JSON.parse(readFileSync(filePath, "utf8")); }
