import { constants, createHash, createPublicKey, verify } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { STAGE_B, STAGE_B_APPROVAL_ALGORITHM } from "./production-green-stage-b-contract.mjs";
import { createProductionAwsCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";

const SHA40 = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const ROTATION_ID = /^[A-Za-z0-9._-]{8,128}$/;
const ROOT_ARN = `arn:aws:iam::${STAGE_B.account}:root`;
export const ROOT_DROP_SIGNING_KEY_ARN = STAGE_B.rootDropKmsKeyArn;
export const ROOT_DROP_SIGNING_ALGORITHM = STAGE_B_APPROVAL_ALGORITHM;
export const ROOT_DROP_VERIFY_PROFILE = "mscqr-production-release-deployer";
const canonical = (value) => Array.isArray(value) ? `[${value.map(canonical).join(",")}]` : value && typeof value === "object" ? `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}` : JSON.stringify(value);
const hash = (value) => createHash("sha256").update(typeof value === "string" || Buffer.isBuffer(value) ? value : canonical(value)).digest("hex");
const unsignedFields = ["schemaVersion", "valid", "evidenceRef", "callerArn", "accountId", "region", "sourceSha", "rotationId", "imageAuthorizationSha256", "successorRecoveryAuthorizationSha256", "administratorEvidenceSha256", "administratorSignatureSha256", "generatedAt", "nonceHash"];
const signedFields = [...unsignedFields, "signingKeyArn", "signingAlgorithm", "signedPayloadSha256", "signatureBase64"];
export const canonicalRootDropPayload = (value) => canonical(value);

function assertContinuity({ rotationId, imageAuthorizationSha256, successorRecoveryAuthorizationSha256, administratorEvidenceSha256, administratorSignatureSha256 } = {}) {
  if (!ROTATION_ID.test(rotationId || "") || !SHA256.test(imageAuthorizationSha256 || "") || !(successorRecoveryAuthorizationSha256 === null || SHA256.test(successorRecoveryAuthorizationSha256 || "")) || !SHA256.test(administratorEvidenceSha256 || "") || !SHA256.test(administratorSignatureSha256 || "")) throw new Error("Root-drop evidence continuity bindings are incomplete.");
  return { rotationId, imageAuthorizationSha256, successorRecoveryAuthorizationSha256, administratorEvidenceSha256, administratorSignatureSha256 };
}

export function buildRootDropPayload({ sourceSha, callerArn, accountId = STAGE_B.account, region = STAGE_B.region, now = new Date().toISOString(), nonce, ...continuity } = {}) {
  if (!SHA40.test(sourceSha || "") || callerArn !== ROOT_ARN || accountId !== STAGE_B.account || region !== STAGE_B.region || typeof nonce !== "string" || nonce.length < 16) throw new Error("Exact root administrator identity is required.");
  const bindings = assertContinuity(continuity);
  return { schemaVersion: 2, valid: true, evidenceRef: `root-drop:${sourceSha}:${bindings.rotationId}:${hash(nonce).slice(0, 16)}`, callerArn, accountId, region, sourceSha, ...bindings, generatedAt: now, nonceHash: hash(nonce) };
}

export function buildRootDropEvidence({ payload, signatureBase64, signingKeyArn = ROOT_DROP_SIGNING_KEY_ARN, signingAlgorithm = ROOT_DROP_SIGNING_ALGORITHM } = {}) {
  if (!payload || typeof payload !== "object" || Object.keys(payload).sort().join(",") !== unsignedFields.sort().join(",")) throw new Error("Root-drop evidence requires one canonical unsigned payload.");
  const unsigned = { ...payload };
  if (signingKeyArn !== ROOT_DROP_SIGNING_KEY_ARN || signingAlgorithm !== ROOT_DROP_SIGNING_ALGORITHM || !/^[A-Za-z0-9+/]+={0,2}$/.test(signatureBase64 || "")) throw new Error("Root-drop evidence requires the reviewed KMS signature.");
  const signed = { ...unsigned, signingKeyArn, signingAlgorithm, signedPayloadSha256: hash(unsigned), signatureBase64 };
  return { ...signed, evidenceSha256: hash(signed) };
}

export function verifyRootDropEvidenceWithKms({ message, signature, keyArn = ROOT_DROP_SIGNING_KEY_ARN, signingAlgorithm = ROOT_DROP_SIGNING_ALGORITHM, run } = {}) {
  const releaseRun = run || createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: ROOT_DROP_VERIFY_PROFILE });
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-root-drop-verify-"));
  const messagePath = path.join(directory, "message");
  const signaturePath = path.join(directory, "signature");
  try {
    writeFileSync(messagePath, message, { mode: 0o600, flag: "wx" });
    writeFileSync(signaturePath, signature, { mode: 0o600, flag: "wx" });
    const result = JSON.parse(releaseRun(["kms", "get-public-key", "--key-id", keyArn, "--output", "json", "--no-cli-pager"]));
    if (typeof result.PublicKey !== "string") return false;
    const publicKey = createPublicKey({ key: Buffer.from(result.PublicKey, "base64"), format: "der", type: "spki" });
    return verify("sha256", message, { key: publicKey, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }, signature);
  } finally { rmSync(directory, { recursive: true, force: true }); }
}

export function assertRootDropEvidence(evidence, { sourceSha, rotationId, imageAuthorizationSha256, successorRecoveryAuthorizationSha256, administratorEvidenceSha256, administratorSignatureSha256, now = Date.now(), maxAgeMs = 15 * 60 * 1000, verifySignature = verifyRootDropEvidenceWithKms } = {}) {
  const continuity = assertContinuity({ rotationId, imageAuthorizationSha256, successorRecoveryAuthorizationSha256, administratorEvidenceSha256, administratorSignatureSha256 });
  if (!evidence || Object.keys(evidence).sort().join(",") !== [...signedFields, "evidenceSha256"].sort().join(",") || evidence.schemaVersion !== 2 || evidence.valid !== true || evidence.callerArn !== ROOT_ARN || evidence.accountId !== STAGE_B.account || evidence.region !== STAGE_B.region || evidence.sourceSha !== sourceSha || evidence.rotationId !== continuity.rotationId || evidence.imageAuthorizationSha256 !== continuity.imageAuthorizationSha256 || evidence.successorRecoveryAuthorizationSha256 !== continuity.successorRecoveryAuthorizationSha256 || evidence.administratorEvidenceSha256 !== continuity.administratorEvidenceSha256 || evidence.administratorSignatureSha256 !== continuity.administratorSignatureSha256) throw new Error("Root-drop evidence is not bound to the exact administrator, source, rotation, image, recovery, and administrator-evidence chain.");
  if (typeof evidence.evidenceRef !== "string" || !evidence.evidenceRef.startsWith("root-drop:") || !SHA256.test(evidence.evidenceSha256 || "") || !SHA256.test(evidence.nonceHash || "") || evidence.signingKeyArn !== ROOT_DROP_SIGNING_KEY_ARN || evidence.signingAlgorithm !== ROOT_DROP_SIGNING_ALGORITHM || !SHA256.test(evidence.signedPayloadSha256 || "") || !/^[A-Za-z0-9+/]+={0,2}$/.test(evidence.signatureBase64 || "")) throw new Error("Root-drop evidence signature envelope is invalid.");
  const parsedTime = Date.parse(evidence.generatedAt);
  if (!Number.isSafeInteger(parsedTime) || Math.abs(now - parsedTime) > maxAgeMs) throw new Error("Root-drop evidence is stale.");
  const unsigned = Object.fromEntries(unsignedFields.map((field) => [field, evidence[field]]));
  const signed = Object.fromEntries(signedFields.map((field) => [field, evidence[field]]));
  if (hash(unsigned) !== evidence.signedPayloadSha256 || hash(signed) !== evidence.evidenceSha256) throw new Error("Root-drop evidence hash does not match its contents.");
  if (typeof verifySignature !== "function" || verifySignature({ message: Buffer.from(canonical(unsigned)), signature: Buffer.from(evidence.signatureBase64, "base64"), keyArn: evidence.signingKeyArn, signingAlgorithm: evidence.signingAlgorithm }) !== true) throw new Error("Root-drop evidence KMS signature verification failed.");
  return Object.freeze({ valid: true, evidenceRef: evidence.evidenceRef, evidenceSha256: evidence.evidenceSha256, callerArn: ROOT_ARN, sourceSha, accountId: STAGE_B.account, region: STAGE_B.region, ...continuity });
}

export function readRootDropEvidence(filePath) { return JSON.parse(readFileSync(filePath, "utf8")); }
