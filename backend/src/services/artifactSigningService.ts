import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign as cryptoSign,
  verify as cryptoVerify,
} from "node:crypto";

const ARTIFACT_ALGORITHM = "Ed25519" as const;
export const ARTIFACT_PERSISTED_SIGNATURE_ALGORITHM = "ed25519" as const;
const VERSION_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const MAX_HISTORICAL_PUBLIC_KEYS = 64;

export type ArtifactSignatureEnvelope = {
  algorithm: typeof ARTIFACT_ALGORITHM;
  keyVersion: string;
  signature: string;
};

type ArtifactKeyRegistry = {
  activeKeyVersion: string;
  currentPrivateKey: ReturnType<typeof createPrivateKey>;
  publicKeys: Map<string, ReturnType<typeof createPublicKey>>;
};

const readEnv = (name: string) => String(process.env[name] || "").trim();

const normalizePem = (value: string, name: string) => {
  const normalized = value.replace(/\\n/g, "\n").trim();
  if (normalized.includes("-----BEGIN")) return normalized;
  const decoded = Buffer.from(normalized, "base64").toString("utf8").trim();
  if (!decoded.includes("-----BEGIN")) throw new Error(`${name} must be an Ed25519 PEM or base64-wrapped PEM`);
  return decoded;
};

const requireEnv = (name: string) => {
  const value = readEnv(name);
  if (!value) throw new Error(`${name} is required for production artifact signing`);
  return value;
};

const publicKeyFingerprint = (key: ReturnType<typeof createPublicKey>) =>
  createHash("sha256").update(key.export({ format: "der", type: "spki" })).digest("hex");

const parseRegistry = (raw: string) => {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("ARTIFACT_SIGN_PUBLIC_KEYS_JSON must be valid JSON");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("ARTIFACT_SIGN_PUBLIC_KEYS_JSON must be an object keyed by version");
  }

  const publicKeys = new Map<string, ReturnType<typeof createPublicKey>>();
  const fingerprints = new Set<string>();
  for (const [version, value] of Object.entries(parsed)) {
    if (!VERSION_PATTERN.test(version) || typeof value !== "string" || !value.trim()) {
      throw new Error("ARTIFACT_SIGN_PUBLIC_KEYS_JSON contains an invalid key version or public key");
    }
    if (/PRIVATE KEY/i.test(value)) throw new Error("ARTIFACT_SIGN_PUBLIC_KEYS_JSON must not contain private keys");
    let key: ReturnType<typeof createPublicKey>;
    try {
      key = createPublicKey(normalizePem(value, `ARTIFACT_SIGN_PUBLIC_KEYS_JSON.${version}`));
    } catch {
      throw new Error("ARTIFACT_SIGN_PUBLIC_KEYS_JSON contains an invalid public key");
    }
    if (key.asymmetricKeyType !== "ed25519") throw new Error("Artifact signing public keys must be Ed25519");
    const fingerprint = publicKeyFingerprint(key);
    if (fingerprints.has(fingerprint)) throw new Error("Artifact signing public keys must not duplicate a version");
    fingerprints.add(fingerprint);
    publicKeys.set(version, key);
  }
  if (publicKeys.size === 0) throw new Error("ARTIFACT_SIGN_PUBLIC_KEYS_JSON must contain at least one public key");
  if (publicKeys.size > MAX_HISTORICAL_PUBLIC_KEYS) throw new Error("ARTIFACT_SIGN_PUBLIC_KEYS_JSON exceeds the 64-key retention bound");
  return publicKeys;
};

const loadRegistry = (): ArtifactKeyRegistry => {
  const activeKeyVersion = requireEnv("ARTIFACT_SIGN_ACTIVE_KEY_VERSION");
  if (!VERSION_PATTERN.test(activeKeyVersion)) throw new Error("ARTIFACT_SIGN_ACTIVE_KEY_VERSION is invalid");

  const currentPrivateKey = createPrivateKey(normalizePem(requireEnv("ARTIFACT_SIGN_PRIVATE_KEY_CURRENT"), "ARTIFACT_SIGN_PRIVATE_KEY_CURRENT"));
  const currentPublicKey = createPublicKey(normalizePem(requireEnv("ARTIFACT_SIGN_PUBLIC_KEY_CURRENT"), "ARTIFACT_SIGN_PUBLIC_KEY_CURRENT"));
  if (currentPrivateKey.asymmetricKeyType !== "ed25519" || currentPublicKey.asymmetricKeyType !== "ed25519") {
    throw new Error("Artifact signing keys must be Ed25519");
  }

  const publicKeys = parseRegistry(requireEnv("ARTIFACT_SIGN_PUBLIC_KEYS_JSON"));
  const registryCurrent = publicKeys.get(activeKeyVersion);
  if (!registryCurrent || publicKeyFingerprint(registryCurrent) !== publicKeyFingerprint(currentPublicKey)) {
    throw new Error("Artifact signing active public key does not match the historical registry");
  }

  const probe = Buffer.from("mscqr-artifact-signing-startup-validation", "utf8");
  const probeSignature = cryptoSign(null, probe, currentPrivateKey);
  if (!cryptoVerify(null, probe, currentPublicKey, probeSignature)) {
    throw new Error("Artifact signing private/public key pair failed validation");
  }

  return { activeKeyVersion, currentPrivateKey, publicKeys };
};

export const validateArtifactSigningConfiguration = () => loadRegistry();

export const signArtifactPayload = (payload: string): ArtifactSignatureEnvelope => {
  const registry = loadRegistry();
  const payloadHash = createHash("sha256").update(payload).digest();
  return {
    algorithm: ARTIFACT_ALGORITHM,
    keyVersion: registry.activeKeyVersion,
    signature: cryptoSign(null, payloadHash, registry.currentPrivateKey).toString("base64url"),
  };
};

export const verifyArtifactPayload = (payload: string, envelope: unknown) => {
  if (!envelope || typeof envelope !== "object" || Array.isArray(envelope)) return false;
  const candidate = envelope as Partial<ArtifactSignatureEnvelope>;
  if (candidate.algorithm !== ARTIFACT_ALGORITHM || typeof candidate.keyVersion !== "string" || !VERSION_PATTERN.test(candidate.keyVersion)) return false;
  if (typeof candidate.signature !== "string" || !candidate.signature) return false;

  let registry: ArtifactKeyRegistry;
  try {
    registry = loadRegistry();
  } catch {
    return false;
  }
  const publicKey = registry.publicKeys.get(candidate.keyVersion);
  if (!publicKey) return false;
  try {
    return cryptoVerify(
      null,
      createHash("sha256").update(payload).digest(),
      publicKey,
      Buffer.from(candidate.signature, "base64url")
    );
  } catch {
    return false;
  }
};
