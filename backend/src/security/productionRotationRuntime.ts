import { createHash, createPrivateKey, sign as cryptoSign } from "node:crypto";
import jwt from "jsonwebtoken";
import { signQrPayload, verifyQrToken } from "../services/qrTokenService";
import { verifyJwtWithCurrentOrPrevious } from "../utils/security";

type RuntimeInput = {
  currentJwtToken: string;
  previousJwtToken: string;
  previousQrToken: string;
  healthEvidence: HealthEvidence;
  now?: () => number;
};

type HealthEvidence = {
  serviceHealthy: boolean;
  healthHttpStatus: number;
  healthReleaseGitSha: string;
  expectedReleaseGitSha: string;
  healthObservedAt: string;
};

const requiredEnv = (name: string) => {
  const value = String(process.env[name] || "").trim();
  if (!value) throw new Error(`${name} is required for runtime rotation verification`);
  return value;
};

const requiredInput = (value: string, name: string) => {
  const normalized = String(value || "").trim();
  if (!normalized) throw new Error(`${name} is required for runtime rotation verification`);
  return normalized;
};

const verifyJwtFixtureInSlot = (token: string, secret: string, slot: string) => {
  const preparedToken = requiredInput(token, `${slot} JWT fixture`);
  jwt.verify(preparedToken, secret, { algorithms: ["HS256"] });
  return preparedToken;
};

const validateHealthEvidence = (health: HealthEvidence, now: () => number) => {
  if (health?.serviceHealthy !== true || health.healthHttpStatus !== 200) throw new Error("runtime health proof is unhealthy");
  if (!/^[a-f0-9]{40}$/.test(health.healthReleaseGitSha) || health.healthReleaseGitSha !== health.expectedReleaseGitSha) {
    throw new Error("runtime health proof release SHA is invalid");
  }
  const observedAt = Date.parse(String(health.healthObservedAt || ""));
  const age = now() - observedAt;
  if (!Number.isFinite(observedAt) || age < 0 || age > 300_000) throw new Error("runtime health proof timestamp is invalid");
  return health;
};

const tokenWithPayload = (token: string, mutate: (payload: Record<string, unknown>) => Record<string, unknown>) => {
  const [payloadPart, signaturePart] = token.split(".");
  const payload = JSON.parse(Buffer.from(payloadPart, "base64url").toString("utf8"));
  return `${Buffer.from(JSON.stringify(mutate(payload))).toString("base64url")}.${signaturePart}`;
};

const encodeBase64Url = (value: Buffer) => value.toString("base64url");
const normalizePrivateKey = (value: string) => {
  const normalized = value.replace(/\\n/g, "\n").trim();
  if (normalized.includes("-----BEGIN")) return normalized;
  const decoded = Buffer.from(normalized, "base64").toString("utf8");
  if (!decoded.includes("-----BEGIN")) throw new Error("current QR private key is not a PEM key");
  return decoded;
};

const signUnknownKidFixture = (currentQrToken: string) => {
  const [payloadPart] = currentQrToken.split(".");
  const payload = JSON.parse(Buffer.from(payloadPart, "base64url").toString("utf8")) as Record<string, unknown>;
  payload.kid = "unknown-runtime-key";
  const payloadBytes = Buffer.from(JSON.stringify(payload), "utf8");
  const privateKey = createPrivateKey(normalizePrivateKey(requiredEnv("QR_SIGN_PRIVATE_KEY_CURRENT")));
  const signature = cryptoSign(null, createHash("sha256").update(payloadBytes).digest(), privateKey);
  return `${encodeBase64Url(payloadBytes)}.${encodeBase64Url(signature)}`;
};

export const verifyProductionRotationRuntime = ({ currentJwtToken, previousJwtToken, previousQrToken, healthEvidence, now = Date.now }: RuntimeInput) => {
  const health = validateHealthEvidence(healthEvidence, now);
  const currentJwt = requiredEnv("JWT_SECRET_CURRENT");
  const previousJwt = requiredEnv("JWT_SECRET_PREVIOUS");
  const preparedCurrentJwtToken = verifyJwtFixtureInSlot(currentJwtToken, currentJwt, "current");
  const preparedPreviousJwtToken = verifyJwtFixtureInSlot(previousJwtToken, previousJwt, "previous");
  const invalidToken = jwt.sign({ rotationId: "runtime-verification" }, "runtime-invalid-secret", { algorithm: "HS256" });

  verifyJwtWithCurrentOrPrevious(preparedCurrentJwtToken, (secret) => jwt.verify(preparedCurrentJwtToken, secret, { algorithms: ["HS256"] }));
  verifyJwtWithCurrentOrPrevious(preparedPreviousJwtToken, (secret) => jwt.verify(preparedPreviousJwtToken, secret, { algorithms: ["HS256"] }));
  let invalidRejected = false;
  try {
    verifyJwtWithCurrentOrPrevious(invalidToken, (secret) => jwt.verify(invalidToken, secret, { algorithms: ["HS256"] }));
  } catch {
    invalidRejected = true;
  }

  const currentQrToken = signQrPayload({ qr_id: "rotation-runtime", batch_id: null, licensee_id: "rotation", iat: Math.floor(now() / 1000), nonce: createHash("sha256").update("rotation-runtime").digest("hex").slice(0, 24) });
  verifyQrToken(currentQrToken);
  verifyQrToken(previousQrToken);

  const tamperedCurrent = tokenWithPayload(currentQrToken, (payload) => ({ ...payload, qr_id: "rotation-runtime-tampered" }));
  let tamperRejected = false;
  try {
    verifyQrToken(tamperedCurrent);
  } catch {
    tamperRejected = true;
  }

  const unknownKey = signUnknownKidFixture(currentQrToken);
  let unknownRejected = false;
  try {
    verifyQrToken(unknownKey);
  } catch {
    unknownRejected = true;
  }

  return {
    jwtCurrentRuntimeVerify: true,
    jwtPreviousRuntimeVerify: true,
    jwtInvalidRuntimeRejected: invalidRejected,
    qrCurrentRuntimeVerify: true,
    qrPreviousRuntimeVerify: true,
    qrTamperMatchingKeyTest: tamperRejected,
    qrUnknownKeyRejected: unknownRejected,
    ...health,
  };
};

export const verifyProductionRotationCleanupRuntime = ({ currentJwtToken, previousJwtToken, previousQrToken, healthEvidence, now = Date.now }: RuntimeInput) => {
  const health = validateHealthEvidence(healthEvidence, now);
  const currentJwt = requiredEnv("JWT_SECRET_CURRENT");
  const preparedCurrentJwtToken = verifyJwtFixtureInSlot(currentJwtToken, currentJwt, "current");
  verifyJwtWithCurrentOrPrevious(preparedCurrentJwtToken, (secret) => jwt.verify(preparedCurrentJwtToken, secret, { algorithms: ["HS256"] }));
  let previousJwtRejected = false;
  try {
    verifyJwtWithCurrentOrPrevious(previousJwtToken, (secret) => jwt.verify(previousJwtToken, secret, { algorithms: ["HS256"] }));
  } catch {
    previousJwtRejected = true;
  }

  const currentQrToken = signQrPayload({ qr_id: "rotation-cleanup-runtime", batch_id: null, licensee_id: "rotation", iat: Math.floor(now() / 1000), nonce: createHash("sha256").update("rotation-cleanup-runtime").digest("hex").slice(0, 24) });
  verifyQrToken(currentQrToken);
  let previousQrRejected = false;
  try {
    verifyQrToken(previousQrToken);
  } catch {
    previousQrRejected = true;
  }
  const unknownKey = signUnknownKidFixture(currentQrToken);
  let unknownRejected = false;
  try {
    verifyQrToken(unknownKey);
  } catch {
    unknownRejected = true;
  }

  return {
    jwtCurrentRuntimeVerify: true,
    jwtPreviousRuntimeRejected: previousJwtRejected,
    qrCurrentRuntimeVerify: true,
    qrPreviousRuntimeRejected: previousQrRejected,
    qrUnknownKeyRejected: unknownRejected,
    ...health,
  };
};
