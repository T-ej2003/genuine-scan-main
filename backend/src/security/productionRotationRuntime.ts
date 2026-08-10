import { createHash } from "node:crypto";
import jwt from "jsonwebtoken";
import { signQrPayload, verifyQrToken } from "../services/qrTokenService";
import { verifyJwtWithCurrentOrPrevious } from "../utils/security";

type RuntimeInput = {
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

export const verifyProductionRotationRuntime = ({ previousJwtToken, previousQrToken, healthEvidence, now = Date.now }: RuntimeInput) => {
  const health = validateHealthEvidence(healthEvidence, now);
  const currentJwt = requiredEnv("JWT_SECRET_CURRENT");
  requiredEnv("JWT_SECRET_PREVIOUS");
  const preparedPreviousJwtToken = requiredInput(previousJwtToken, "previousJwtToken");
  const currentToken = jwt.sign({ rotationId: "runtime-verification" }, currentJwt, { algorithm: "HS256" });
  const invalidToken = jwt.sign({ rotationId: "runtime-verification" }, "runtime-invalid-secret", { algorithm: "HS256" });

  verifyJwtWithCurrentOrPrevious(currentToken, (secret) => jwt.verify(currentToken, secret, { algorithms: ["HS256"] }));
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

  const unknownKey = tokenWithPayload(currentQrToken, (payload) => ({ ...payload, kid: "unknown-runtime-key" }));
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

export const verifyProductionRotationCleanupRuntime = ({ previousJwtToken, previousQrToken, healthEvidence, now = Date.now }: RuntimeInput) => {
  const health = validateHealthEvidence(healthEvidence, now);
  const currentJwt = requiredEnv("JWT_SECRET_CURRENT");
  const currentToken = jwt.sign({ rotationId: "runtime-cleanup-verification" }, currentJwt, { algorithm: "HS256" });
  verifyJwtWithCurrentOrPrevious(currentToken, (secret) => jwt.verify(currentToken, secret, { algorithms: ["HS256"] }));
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
  const unknownKey = tokenWithPayload(currentQrToken, (payload) => ({ ...payload, kid: "unknown-cleanup-key" }));
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
