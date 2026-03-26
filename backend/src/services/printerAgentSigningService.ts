import { createPublicKey, createPrivateKey, sign as cryptoSign, verify as cryptoVerify } from "crypto";

const normalizePem = (value: string) => String(value || "").replace(/\\n/g, "\n").trim();

const decodeBase64Url = (value: string): Buffer => {
  const normalized = String(value || "").trim();
  if (!normalized) throw new Error("Empty signature");

  const padded = normalized.replace(/-/g, "+").replace(/_/g, "/");
  const padLength = (4 - (padded.length % 4)) % 4;
  return Buffer.from(`${padded}${"=".repeat(padLength)}`, "base64");
};

const encodeBase64Url = (value: Buffer) =>
  value.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");

const parsePositiveIntEnv = (name: string, fallback: number, min = 10, max = 900) => {
  const raw = Number(String(process.env[name] || "").trim());
  if (!Number.isFinite(raw) || raw <= 0) return fallback;
  return Math.max(min, Math.min(max, Math.floor(raw)));
};

const MAX_SKEW_SECONDS = parsePositiveIntEnv("PRINT_AGENT_ACTION_MAX_SIGNATURE_SKEW_SECONDS", 180);

export const buildPrinterAgentHeartbeatPayload = (input: {
  userId: string;
  agentId: string;
  deviceFingerprint: string;
  printerId: string;
  connected: boolean;
  heartbeatNonce: string;
  heartbeatIssuedAt: string;
}) =>
  [
    "v1",
    input.userId,
    input.agentId,
    input.deviceFingerprint,
    input.printerId,
    input.connected ? "1" : "0",
    input.heartbeatNonce,
    input.heartbeatIssuedAt,
  ].join("|");

export const buildPrinterAgentActionPayload = (input: {
  action: "claim" | "confirm" | "fail";
  agentId: string;
  deviceFingerprint: string;
  printerId: string;
  nonce: string;
  issuedAt: string;
  printJobId?: string | null;
  printItemId?: string | null;
}) =>
  [
    "v1",
    input.action,
    input.agentId,
    input.deviceFingerprint,
    input.printerId,
    input.printJobId || "",
    input.printItemId || "",
    input.nonce,
    input.issuedAt,
  ].join("|");

export const signPrinterAgentPayload = (privateKeyPem: string, payload: string) => {
  const key = createPrivateKey(normalizePem(privateKeyPem));
  const data = Buffer.from(payload, "utf8");

  try {
    return encodeBase64Url(cryptoSign(null, data, key));
  } catch {
    return encodeBase64Url(cryptoSign("sha256", data, key));
  }
};

export const verifyPrinterAgentPayloadSignature = (params: {
  publicKeyPem: string;
  payload: string;
  signature: string;
}) => {
  const key = createPublicKey(normalizePem(params.publicKeyPem));
  const signature = decodeBase64Url(params.signature);
  const payload = Buffer.from(params.payload, "utf8");

  try {
    if (cryptoVerify("sha256", payload, key, signature)) return true;
  } catch {
    // fall through
  }

  try {
    return cryptoVerify(null, payload, key, signature);
  } catch {
    return false;
  }
};

export const isPrinterAgentIssuedAtFresh = (issuedAt: string) => {
  const issuedAtMs = new Date(issuedAt).getTime();
  if (!Number.isFinite(issuedAtMs)) return false;
  const skewSeconds = Math.abs(Date.now() - issuedAtMs) / 1000;
  return skewSeconds <= MAX_SKEW_SECONDS;
};
