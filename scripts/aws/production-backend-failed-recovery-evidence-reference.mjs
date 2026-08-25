import crypto from "node:crypto";
import { canonicalSha256 } from "./stage-b-task-definition-recovery-contract.mjs";
import { FAILED_RECOVERY_EVIDENCE } from "./production-backend-failed-recovery-evidence.mjs";

const KIND = "IMMUTABLE_GITHUB_RELEASE_FAILED_RECOVERY_EVIDENCE";
const REPOSITORY = "T-ej2003/genuine-scan-main";
const SHA = /^[a-f0-9]{40}$/;
const HEX = /^[a-f0-9]{64}$/;
const INTEGER = /^[1-9][0-9]*$/;
const FIELDS = ["assetDigest", "assetId", "assetName", "assetSize", "evidenceByteSha256", "evidenceEnvelopeSha256", "kind", "referenceSha256", "releaseId", "releaseTag", "repository", "schemaVersion", "sourceSha"];
const hash = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const assetName = (sha256) => `backend-failed-recovery-evidence-${sha256}.json`;
const releaseTag = (sha256) => `mscqr-backend-failed-recovery-evidence-${sha256}`;

export function createFailedRecoveryEvidenceReference({ sourceSha, evidenceBytes, release, asset } = {}) {
  if (!SHA.test(sourceSha || "") || !Buffer.isBuffer(evidenceBytes) || !evidenceBytes.length) throw new Error("Failed-recovery evidence publication inputs are invalid.");
  const evidenceByteSha256 = hash(evidenceBytes);
  let envelope;
  try { envelope = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(evidenceBytes)); }
  catch { throw new Error("Failed-recovery evidence publication bytes are malformed."); }
  if (!HEX.test(envelope?.envelopeSha256 || "") || release?.immutable !== true || release?.draft !== false
    || String(release?.id || "") === "" || !INTEGER.test(String(release.id))
    || release.tag_name !== releaseTag(envelope.envelopeSha256) || release.target_commitish !== sourceSha
    || String(asset?.id || "") === "" || !INTEGER.test(String(asset.id)) || asset?.name !== assetName(envelope.envelopeSha256)
    || asset?.state !== "uploaded" || asset?.size !== evidenceBytes.length || asset?.digest !== `sha256:${evidenceByteSha256}`
    || !Array.isArray(release.assets) || release.assets.length !== 1 || String(release.assets[0]?.id || "") !== String(asset.id)) {
    throw new Error("Failed-recovery evidence release is not exact, immutable, or content-addressed.");
  }
  const body = { schemaVersion: 1, kind: KIND, repository: REPOSITORY, sourceSha, releaseId: String(release.id), releaseTag: release.tag_name, assetId: String(asset.id), assetName: asset.name, assetSize: asset.size, assetDigest: asset.digest, evidenceByteSha256, evidenceEnvelopeSha256: envelope.envelopeSha256 };
  return Object.freeze({ ...body, referenceSha256: canonicalSha256(body) });
}

export function assertFailedRecoveryEvidenceReference(reference, { sourceSha, evidenceBytes } = {}) {
  if (reference === null) {
    if (evidenceBytes && !Buffer.from(evidenceBytes).equals(Buffer.from("null"))) throw new Error("Null failed-recovery history has unexpected evidence bytes.");
    return null;
  }
  const { referenceSha256, ...body } = reference || {};
  if (JSON.stringify(Object.keys(reference || {}).sort()) !== JSON.stringify(FIELDS) || reference?.schemaVersion !== 1 || reference.kind !== KIND || reference.repository !== REPOSITORY
    || reference.sourceSha !== sourceSha || !SHA.test(sourceSha || "") || !INTEGER.test(reference.releaseId || "") || !INTEGER.test(reference.assetId || "")
    || !HEX.test(reference.evidenceByteSha256 || "") || !HEX.test(reference.evidenceEnvelopeSha256 || "")
    || reference.releaseTag !== releaseTag(reference.evidenceEnvelopeSha256) || reference.assetName !== assetName(reference.evidenceEnvelopeSha256)
    || !Number.isSafeInteger(reference.assetSize) || reference.assetSize < 1 || reference.assetSize > FAILED_RECOVERY_EVIDENCE.maxHistoryBytes || reference.assetDigest !== `sha256:${reference.evidenceByteSha256}`
    || !HEX.test(referenceSha256 || "") || canonicalSha256(body) !== referenceSha256) throw new Error("Failed-recovery evidence reference is malformed or bound to another transaction.");
  if (evidenceBytes) {
    if (!Buffer.isBuffer(evidenceBytes) || evidenceBytes.length !== reference.assetSize || hash(evidenceBytes) !== reference.evidenceByteSha256) throw new Error("Resolved failed-recovery evidence bytes do not match the immutable reference.");
    let envelope;
    try { envelope = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(evidenceBytes)); }
    catch { throw new Error("Resolved failed-recovery evidence is malformed."); }
    if (envelope?.envelopeSha256 !== reference.evidenceEnvelopeSha256) throw new Error("Resolved failed-recovery evidence envelope differs from the immutable reference.");
  }
  return reference;
}

export function assertFailedRecoveryEvidenceReleaseReadback(reference, { release, asset, evidenceBytes } = {}) {
  assertFailedRecoveryEvidenceReference(reference, { sourceSha: reference?.sourceSha, evidenceBytes });
  const releaseAsset = release?.assets?.find(({ id }) => String(id) === reference.assetId);
  if (release?.immutable !== true || release?.draft !== false || String(release?.id || "") !== reference.releaseId || release.tag_name !== reference.releaseTag || release.target_commitish !== reference.sourceSha
    || !Array.isArray(release.assets) || release.assets.length !== 1 || String(release.assets[0]?.id || "") !== reference.assetId
    || releaseAsset?.name !== reference.assetName || releaseAsset?.state !== "uploaded" || releaseAsset?.size !== reference.assetSize || releaseAsset?.digest !== reference.assetDigest
    || String(asset?.id || "") !== reference.assetId || asset?.name !== reference.assetName || asset?.state !== "uploaded"
    || asset?.size !== reference.assetSize || asset?.digest !== reference.assetDigest) throw new Error("Immutable failed-recovery evidence release readback changed or is unavailable.");
  return reference;
}

export const FAILED_RECOVERY_EVIDENCE_REFERENCE = Object.freeze({ kind: KIND, repository: REPOSITORY, assetName, releaseTag });
