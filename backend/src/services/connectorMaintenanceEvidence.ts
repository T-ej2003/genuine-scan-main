import { createPublicKey, verify, createHash } from "crypto";

// This trust anchor is server configuration, never supplied by the caller.
// No default key or production bypass is permitted. Provisioning it is a
// separately governed operation; fixtures use their own disposable authority.
export const verifyConnectorIsolationEvidence = (envelope: unknown, purpose = "mscqr-legacy-connector-isolation-v1") => {
  const value = envelope as { statement?: string; signature?: string };
  const keyPem = process.env.CONNECTOR_ISOLATION_AUTHORITY_PUBLIC_KEY_PEM;
  if (!keyPem) throw new Error("ISOLATION_AUTHORITY_NOT_CONFIGURED");
  if (typeof value?.statement !== "string" || value.statement.length > 100000 ||
      typeof value.signature !== "string" || !/^[A-Za-z0-9+/]+={0,2}$/.test(value.signature)) {
    throw new Error("ISOLATION_EVIDENCE_INVALID");
  }
  const key = createPublicKey(keyPem);
  if (key.asymmetricKeyType !== "ed25519" ||
      !verify(null, Buffer.from(value.statement), key, Buffer.from(value.signature, "base64"))) {
    throw new Error("ISOLATION_EVIDENCE_INVALID");
  }
  const statement = JSON.parse(value.statement);
  if (statement?.purpose !== purpose ||
      !Number.isFinite(Date.parse(statement.expiresAt)) ||
      !Number.isFinite(Date.parse(statement.verifiedAt)) ||
      Date.parse(statement.expiresAt) <= Date.now() ||
      Date.parse(statement.expiresAt) > Date.now() + 15 * 60_000 ||
      Date.parse(statement.verifiedAt) > Date.now() ||
      Date.parse(statement.verifiedAt) < Date.now() - 15 * 60_000 ||
      !Array.isArray(statement.reconciliations) ||
      !Array.isArray(statement.isolationEvidence) || statement.isolationEvidence.length < 2 ||
      !statement.isolationEvidence.every((entry: any) =>
        ["dispatch-isolation", "connector-work-inventory"].includes(entry?.kind) &&
        /^[a-f0-9]{64}$/.test(entry?.sha256) && typeof entry.reference === "string" && entry.reference.length > 0) ||
      !["dispatch-isolation", "connector-work-inventory"].every(kind =>
        statement.isolationEvidence.some((entry: any) => entry.kind === kind))) {
    throw new Error("ISOLATION_EVIDENCE_INVALID");
  }
  return { ...statement, evidenceSha256: createHash("sha256").update(value.statement).digest("hex") };
};
