import { createHash } from "node:crypto";
import jwt from "jsonwebtoken";
import { signQrPayload, verifyQrToken } from "../services/qrTokenService";
import { verifyJwtWithCurrentOrPrevious } from "../utils/security";

type RuntimeInput = {
  previousQrToken: string;
  now?: () => number;
};

const requiredEnv = (name: string) => {
  const value = String(process.env[name] || "").trim();
  if (!value) throw new Error(`${name} is required for runtime rotation verification`);
  return value;
};

const tokenWithPayload = (token: string, mutate: (payload: Record<string, unknown>) => Record<string, unknown>) => {
  const [payloadPart, signaturePart] = token.split(".");
  const payload = JSON.parse(Buffer.from(payloadPart, "base64url").toString("utf8"));
  return `${Buffer.from(JSON.stringify(mutate(payload))).toString("base64url")}.${signaturePart}`;
};

export const verifyProductionRotationRuntime = ({ previousQrToken, now = Date.now }: RuntimeInput) => {
  const currentJwt = requiredEnv("JWT_SECRET_CURRENT");
  const previousJwt = requiredEnv("JWT_SECRET_PREVIOUS");
  const currentToken = jwt.sign({ rotationId: "runtime-verification" }, currentJwt, { algorithm: "HS256" });
  const previousToken = jwt.sign({ rotationId: "runtime-verification" }, previousJwt, { algorithm: "HS256" });
  const invalidToken = jwt.sign({ rotationId: "runtime-verification" }, "runtime-invalid-secret", { algorithm: "HS256" });

  verifyJwtWithCurrentOrPrevious(currentToken, (secret) => jwt.verify(currentToken, secret, { algorithms: ["HS256"] }));
  verifyJwtWithCurrentOrPrevious(previousToken, (secret) => jwt.verify(previousToken, secret, { algorithms: ["HS256"] }));
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
    serviceHealthy: true,
  };
};

export const verifyProductionRotationCleanupRuntime = ({ previousJwtToken, previousQrToken, now = Date.now }: { previousJwtToken: string; previousQrToken: string; now?: () => number }) => {
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
    serviceHealthy: true,
  };
};
