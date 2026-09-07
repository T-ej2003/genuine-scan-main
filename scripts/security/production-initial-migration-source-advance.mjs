import { createHash } from "node:crypto";

export const PRODUCTION_INITIAL_MIGRATION_SOURCE_ADVANCE_KIND = "PRODUCTION_INITIAL_MIGRATION_SOURCE_ADVANCE";
export const PRODUCTION_STALE_SUPERSESSION_PREDECESSOR_KIND = "PRODUCTION_STALE_SUPERSESSION_PREDECESSOR";
export const PRODUCTION_SUPERSESSION_SLOTS = Object.freeze([
  "jwtPending", "qrPrivatePending", "qrPublicPending", "jwtPrevious",
  "qrPublicPrevious", "qrCurrentVersion", "qrPreviousVersion",
]);
const SHA40 = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const ROTATION_ID = /^[A-Za-z0-9._-]{8,128}$/;
const SECRET_ARN = /^arn:aws:secretsmanager:eu-west-2:368992683803:secret:[A-Za-z0-9/_+=.@-]+$/;
const VERSION_ID = /^[A-Za-z0-9+=/:._-]{7,256}$/;
const KEY_VERSION = /^[A-Za-z0-9._:-]{1,128}$/;
const FINGERPRINT = /^[a-f0-9]{16}$/;
const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const canonical = (value) => Array.isArray(value) ? `[${value.map(canonical).join(",")}]` : value && typeof value === "object" ? `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}` : JSON.stringify(value);
const exact = (value, keys, label) => {
  if (!value || typeof value !== "object" || Array.isArray(value) || canonical(Object.keys(value).sort()) !== canonical([...keys].sort())) throw new Error(`${label} schema is invalid.`);
};

export const productionSupersessionVersionId = (sourceSha, rotationId, slot) =>
  sha256(`${sourceSha}:${rotationId}:${slot}`);

export const productionSupersessionEvidenceIdentity = ({ sourceSha, staleSourceSha, rotationId, staleRotationId, resources, predecessorSlotIdentities }) =>
  sha256(JSON.stringify({ schemaVersion: 1, transition: "SUPERSEDE_STALE_PENDING", sourceSha, staleSourceSha, rotationId, staleRotationId, resources, ...(predecessorSlotIdentities ? { predecessorSlotIdentities } : {}) }));

const assertSupersessionSlotIdentities = (value, label = "Rotation supersession predecessor") => {
  exact(value, PRODUCTION_SUPERSESSION_SLOTS, `${label} slots`);
  for (const slot of PRODUCTION_SUPERSESSION_SLOTS) {
    const identity = value[slot];
    exact(identity, ["secretArn", "versionId", "payloadSha256", "materialFingerprint", "keyVersion"], `${label} ${slot}`);
    if (!SECRET_ARN.test(identity.secretArn) || !VERSION_ID.test(identity.versionId) || !SHA256.test(identity.payloadSha256) || (identity.materialFingerprint !== null && !FINGERPRINT.test(identity.materialFingerprint)) || (identity.keyVersion !== null && !KEY_VERSION.test(identity.keyVersion))) throw new Error(`${label} ${slot} identity is invalid.`);
  }
  return value;
};

export function assertProductionSupersessionEvidence(evidence) {
  const keys = ["schemaVersion", "transition", "sourceSha", "staleSourceSha", "rotationId", "staleRotationId", "generatedAt", "resources", "evidenceIdentitySha256", ...(evidence?.predecessorSlotIdentities === undefined ? [] : ["predecessorSlotIdentities"])];
  if (!evidence || Object.keys(evidence).sort().join(",") !== keys.sort().join(",") || evidence.schemaVersion !== 1 || evidence.transition !== "SUPERSEDE_STALE_PENDING") throw new Error("Rotation supersession evidence schema is invalid.");
  if (!SHA40.test(evidence.sourceSha) || !SHA40.test(evidence.staleSourceSha) || evidence.sourceSha === evidence.staleSourceSha || !ROTATION_ID.test(evidence.rotationId) || !ROTATION_ID.test(evidence.staleRotationId) || evidence.rotationId === evidence.staleRotationId || !Number.isFinite(Date.parse(evidence.generatedAt))) throw new Error("Rotation supersession evidence identity is invalid.");
  if (!evidence.resources || Object.keys(evidence.resources).sort().join(",") !== [...PRODUCTION_SUPERSESSION_SLOTS].sort().join(",")) throw new Error("Rotation supersession evidence resources are invalid.");
  for (const slot of PRODUCTION_SUPERSESSION_SLOTS) {
    const resource = evidence.resources[slot];
    if (!resource || Object.keys(resource).sort().join(",") !== "arn,stages,versionId" || typeof resource.arn !== "string" || !resource.arn || resource.versionId !== productionSupersessionVersionId(evidence.sourceSha, evidence.rotationId, slot) || JSON.stringify(resource.stages) !== '["AWSCURRENT"]') throw new Error(`Rotation supersession evidence ${slot} binding is invalid.`);
  }
  if (evidence.predecessorSlotIdentities !== undefined) {
    const predecessors = assertSupersessionSlotIdentities(evidence.predecessorSlotIdentities);
    for (const slot of PRODUCTION_SUPERSESSION_SLOTS) if (predecessors[slot].secretArn !== evidence.resources[slot].arn || predecessors[slot].versionId === evidence.resources[slot].versionId) throw new Error(`Rotation supersession predecessor ${slot} binding is invalid.`);
  }
  // This only validates deterministic evidence shape. Live slot readback is the producer-authentication boundary.
  if (!SHA256.test(evidence.evidenceIdentitySha256) || evidence.evidenceIdentitySha256 !== productionSupersessionEvidenceIdentity(evidence)) throw new Error("Rotation supersession evidence identity hash is invalid.");
  return evidence;
}

export function assertProductionInitialMigrationSourceAdvance(bridge) {
  const keys = ["schemaVersion", "kind", "currentSourceSha", "supersessionEvidence"];
  if (!bridge || Object.keys(bridge).sort().join(",") !== keys.sort().join(",") || bridge.schemaVersion !== 1 || bridge.kind !== PRODUCTION_INITIAL_MIGRATION_SOURCE_ADVANCE_KIND || !SHA40.test(bridge.currentSourceSha)) throw new Error("Initial-migration source-advance binding is invalid.");
  const evidence = assertProductionSupersessionEvidence(bridge.supersessionEvidence);
  if (evidence.sourceSha === bridge.currentSourceSha) throw new Error("Initial-migration source-advance evidence is invalid.");
  return bridge;
}

export const productionStaleSupersessionPredecessorIdentity = (value) => {
  const body = { ...value };
  delete body.predecessorIdentitySha256;
  return sha256(canonical(body));
};

export function assertProductionStaleSupersessionPredecessor(value, { sourceSha, rotationId, supersessionEvidence } = {}) {
  exact(value, ["schemaVersion", "kind", "sourceSha", "rotationId", "staleSourceSha", "staleRotationId", "supersessionEvidenceIdentitySha256", "runtimeQrVersionLabel", "currentRotationId", "current", "slotIdentities", "predecessorIdentitySha256"], "Stale-supersession predecessor");
  if (value.schemaVersion !== 1 || value.kind !== PRODUCTION_STALE_SUPERSESSION_PREDECESSOR_KIND || !SHA40.test(value.sourceSha) || !SHA40.test(value.staleSourceSha) || !ROTATION_ID.test(value.rotationId) || !ROTATION_ID.test(value.staleRotationId) || !ROTATION_ID.test(value.currentRotationId)) throw new Error("Stale-supersession predecessor identity is invalid.");
  if (value.sourceSha === value.staleSourceSha || value.rotationId === value.staleRotationId || value.currentRotationId === value.rotationId || value.currentRotationId === value.staleRotationId || !KEY_VERSION.test(value.runtimeQrVersionLabel)) throw new Error("Stale-supersession predecessor lineage is invalid.");
  exact(value.current, ["jwt", "qrPrivate", "qrPublic"], "Stale-supersession current predecessor");
  for (const [name, expected] of Object.entries({ jwt: ["jwt_secrets", "current"], qrPrivate: ["qr_signing_keys", "current-private"], qrPublic: ["qr_signing_keys", "current-public"] })) {
    const record = value.current[name];
    const keys = name === "jwt" ? ["secretArn", "versionId", "rotationId", "family", "slot", "materialFingerprint"] : ["secretArn", "versionId", "rotationId", "family", "slot", "keyVersion", "materialFingerprint"];
    exact(record, keys, `Stale-supersession ${name} predecessor`);
    if (!SECRET_ARN.test(record.secretArn) || !VERSION_ID.test(record.versionId) || record.rotationId !== value.currentRotationId || record.family !== expected[0] || record.slot !== expected[1] || !FINGERPRINT.test(record.materialFingerprint)) throw new Error(`Stale-supersession ${name} predecessor identity is invalid.`);
    if (name !== "jwt" && !KEY_VERSION.test(record.keyVersion)) throw new Error(`Stale-supersession ${name} key version is invalid.`);
  }
  if (new Set(Object.values(value.current).map(({ secretArn }) => secretArn)).size !== 3 || value.current.qrPrivate.keyVersion !== value.current.qrPublic.keyVersion) throw new Error("Stale-supersession current predecessor resources or QR identities are inconsistent.");
  assertSupersessionSlotIdentities(value.slotIdentities, "Stale-supersession slot predecessor");
  const evidence = supersessionEvidence ? assertProductionSupersessionEvidence(supersessionEvidence) : undefined;
  if ((sourceSha !== undefined && value.sourceSha !== sourceSha) || (rotationId !== undefined && value.rotationId !== rotationId) || (evidence && (evidence.sourceSha !== value.sourceSha || evidence.staleSourceSha !== value.staleSourceSha || evidence.rotationId !== value.rotationId || evidence.staleRotationId !== value.staleRotationId || evidence.evidenceIdentitySha256 !== value.supersessionEvidenceIdentitySha256 || PRODUCTION_SUPERSESSION_SLOTS.some((slot) => value.slotIdentities[slot].secretArn !== evidence.resources[slot].arn) || (evidence.predecessorSlotIdentities !== undefined && canonical(value.slotIdentities) !== canonical(evidence.predecessorSlotIdentities))))) throw new Error("Stale-supersession predecessor does not match the authenticated transition.");
  if (!SHA256.test(value.supersessionEvidenceIdentitySha256) || value.predecessorIdentitySha256 !== productionStaleSupersessionPredecessorIdentity(value)) throw new Error("Stale-supersession predecessor binding is invalid.");
  return value;
}
