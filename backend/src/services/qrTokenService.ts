import {
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  randomBytes,
  sign as cryptoSign,
  timingSafeEqual,
  verify as cryptoVerify,
} from "crypto";
import { getQrSigningHmacSecretSet } from "../utils/secretConfig";

export type QrTokenPayload = {
  qr_id: string;
  batch_id: string | null;
  licensee_id: string;
  manufacturer_id?: string | null;
  epoch?: number;
  kid?: string;
  iat: number;
  exp?: number;
  nonce: string;
};

export const PRINTER_TEST_QR_ID_PREFIX = "printer-test:";

export type QrSigningMode = "ed25519" | "hmac";
export type QrSigningProvider = "env" | "kms-bridge";
export type QrSigningMetadata = {
  mode: QrSigningMode;
  keyVersion: string;
  provider: QrSigningProvider;
  keyRef: string | null;
  payloadKeyVersion?: string | null;
  legacyHmacFallback?: boolean;
};

type SignMode = QrSigningMode;
export type ManagedQrSignerBridge = {
  keyVersion?: string | null;
  keyRef?: string | null;
  sign: (payloadHash: Buffer, payload: QrTokenPayload) => Buffer;
  verify: (params: {
    payloadHash: Buffer;
    signature: Buffer;
    payload: QrTokenPayload;
    payloadKeyVersion: string | null;
  }) => {
    valid: boolean;
    keyVersion?: string | null;
    keyRef?: string | null;
  };
};

const MS_PER_DAY = 24 * 60 * 60 * 1000;
let managedQrSignerBridge: ManagedQrSignerBridge | null = null;

const parseQrTokenExpiryDays = () => {
  const raw = Number(String(process.env.QR_TOKEN_EXP_DAYS || "").trim() || "365");
  if (!Number.isFinite(raw)) return 365;
  return Math.max(30, Math.min(365, Math.floor(raw)));
};

const toBase64Url = (buf: Buffer) =>
  buf
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");

const fromBase64Url = (input: string) => {
  const padded = input.replace(/-/g, "+").replace(/_/g, "/");
  const pad = padded.length % 4;
  const withPad = pad ? padded + "=".repeat(4 - pad) : padded;
  return Buffer.from(withPad, "base64");
};

const decodeBase64UrlStrict = (input: string) => {
  if (!/^[A-Za-z0-9_-]+$/.test(input)) {
    throw new Error("Invalid token encoding");
  }
  const buf = fromBase64Url(input);
  // Reject non-canonical variants so mutated tokens cannot decode to the same bytes.
  if (toBase64Url(buf) !== input) {
    throw new Error("Invalid token encoding");
  }
  return buf;
};

const normalizePem = (value: string) => value.replace(/\\n/g, "\n").trim();

const hasEd25519KeyPair = () => Boolean(process.env.QR_SIGN_PRIVATE_KEY && process.env.QR_SIGN_PUBLIC_KEY);
const normalizeProviderSetting = () => String(process.env.QR_SIGN_PROVIDER || "").trim().toLowerCase();
const managedQrSignerRequested = () => ["managed", "kms", "kms-bridge", "hsm"].includes(normalizeProviderSetting());

export const hasEd25519QrSigningKeys = () => hasEd25519KeyPair();
export const isManagedQrSignerRequested = () => managedQrSignerRequested();
export const hasManagedQrSignerRefs = () => kmsBackedSigningConfigured();
export const hasManagedQrSignerBridgeRegistered = () => Boolean(managedQrSignerBridge);
export const registerManagedQrSignerBridge = (bridge: ManagedQrSignerBridge | null) => {
  managedQrSignerBridge = bridge;
};
export const clearManagedQrSignerBridge = () => {
  managedQrSignerBridge = null;
};

const kmsBackedSigningConfigured = () =>
  Boolean(String(process.env.QR_SIGN_KMS_KEY_REF || "").trim() || String(process.env.QR_SIGN_KMS_VERIFY_KEY_REF || "").trim());

const getEd25519KeyVersion = () =>
  String(process.env.QR_SIGN_ACTIVE_KEY_VERSION || "").trim() ||
  createHash("sha256").update(normalizePem(String(process.env.QR_SIGN_PUBLIC_KEY || ""))).digest("hex").slice(0, 12);

const getEd25519KeyRef = () =>
  String(process.env.QR_SIGN_KMS_VERIFY_KEY_REF || process.env.QR_SIGN_KMS_KEY_REF || "").trim() || "env:QR_SIGN_PUBLIC_KEY";

const stableStringify = (obj: any): string => {
  if (obj === null || typeof obj !== "object") {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    return `[${obj.map((v) => stableStringify(v)).join(",")}]`;
  }
  const keys = Object.keys(obj).sort();
  const body = keys.map((k) => `${JSON.stringify(k)}:${stableStringify(obj[k])}`).join(",");
  return `{${body}}`;
};

const getSignMode = (): { mode: SignMode; key: string } => {
  if (hasEd25519KeyPair()) return { mode: "ed25519", key: "ed25519" };

  try {
    const hmac = getQrSigningHmacSecretSet().current.value;
    if (hmac) return { mode: "hmac", key: "hmac" };
  } catch {
    // handled by final error below
  }

  throw new Error("Missing QR signing keys. Set QR_SIGN_PRIVATE_KEY + QR_SIGN_PUBLIC_KEY (preferred) or QR_SIGN_HMAC_SECRET.");
};

const getEd25519Keys = () => {
  const priv = process.env.QR_SIGN_PRIVATE_KEY;
  const pub = process.env.QR_SIGN_PUBLIC_KEY;
  if (!priv || !pub) throw new Error("Missing QR_SIGN_PRIVATE_KEY / QR_SIGN_PUBLIC_KEY");
  const privateKey = createPrivateKey(normalizePem(priv));
  const publicKey = createPublicKey(normalizePem(pub));
  return { privateKey, publicKey };
};

const requireManagedQrSignerBridge = () => {
  if (!managedQrSignerRequested()) return null;
  if (!kmsBackedSigningConfigured()) {
    throw new Error("Managed QR signing requested but QR_SIGN_KMS_KEY_REF / QR_SIGN_KMS_VERIFY_KEY_REF are not configured.");
  }
  if (!managedQrSignerBridge) {
    throw new Error("Managed QR signing requested but no managed signer bridge is registered in this build.");
  }
  return managedQrSignerBridge;
};

export const getQrSigningProfile = (): QrSigningMetadata => {
  const managedBridge = requireManagedQrSignerBridge();
  if (managedBridge) {
    return {
      mode: "ed25519",
      keyVersion:
        String(managedBridge.keyVersion || "").trim() ||
        String(process.env.QR_SIGN_ACTIVE_KEY_VERSION || "").trim() ||
        "managed-ed25519",
      provider: "kms-bridge",
      keyRef:
        String(managedBridge.keyRef || "").trim() ||
        String(process.env.QR_SIGN_KMS_VERIFY_KEY_REF || process.env.QR_SIGN_KMS_KEY_REF || "").trim() ||
        null,
    };
  }

  const { mode } = getSignMode();
  if (mode === "ed25519") {
    return {
      mode,
      keyVersion: getEd25519KeyVersion(),
      provider: "env",
      keyRef: "env:QR_SIGN_PUBLIC_KEY",
    };
  }

  const current = getQrSigningHmacSecretSet().current;
  return {
    mode,
    keyVersion: current.id,
    provider: "env",
    keyRef: current.source || "env:QR_SIGN_HMAC_SECRET_CURRENT",
    legacyHmacFallback: current.source === "JWT_SECRET",
  };
};

export const randomNonce = () => randomBytes(16).toString("base64url");

export const hashToken = (token: string) =>
  createHash("sha256").update(token).digest("hex");

export const getQrTokenExpiryDate = (issuedAt: Date = new Date()) =>
  new Date(issuedAt.getTime() + parseQrTokenExpiryDays() * MS_PER_DAY);

export const signQrPayload = (payload: QrTokenPayload): string => {
  const managedBridge = requireManagedQrSignerBridge();
  const signingProfile = getQrSigningProfile();
  const sanitized: Record<string, any> = {};
  for (const [k, v] of Object.entries({
    ...payload,
    kid: payload.kid ?? signingProfile.keyVersion,
  })) {
    if (v !== undefined) sanitized[k] = v;
  }
  const payloadJson = stableStringify(sanitized);
  const payloadBuf = Buffer.from(payloadJson, "utf8");
  const payloadHash = createHash("sha256").update(payloadBuf).digest();

  let sig: Buffer;
  if (managedBridge) {
    sig = managedBridge.sign(payloadHash, sanitized as QrTokenPayload);
  } else if (getSignMode().mode === "ed25519") {
    const { privateKey } = getEd25519Keys();
    sig = cryptoSign(null, payloadHash, privateKey);
  } else {
    const secret = getQrSigningHmacSecretSet().current.value;
    sig = createHmac("sha256", secret).update(payloadHash).digest();
  }

  return `${toBase64Url(payloadBuf)}.${toBase64Url(sig)}`;
};

export const verifyQrToken = (token: string): { payload: QrTokenPayload; signing: QrSigningMetadata } => {
  const tokenStr = String(token || "").trim();
  const parts = tokenStr.split(".");
  if (parts.length !== 2) throw new Error("Invalid token format");
  const [payloadPart, sigPart] = parts;
  if (!payloadPart || !sigPart) throw new Error("Invalid token format");

  const payloadBuf = decodeBase64UrlStrict(payloadPart);
  const payloadJson = payloadBuf.toString("utf8");
  const payload = JSON.parse(payloadJson) as QrTokenPayload;

  const payloadHash = createHash("sha256").update(payloadBuf).digest();

  const activeProfile = getQrSigningProfile();
  const managedBridge = requireManagedQrSignerBridge();
  if (managedBridge) {
    const verification = managedBridge.verify({
      payloadHash,
      signature: decodeBase64UrlStrict(sigPart),
      payload,
      payloadKeyVersion: String(payload.kid || "").trim() || null,
    });
    if (!verification?.valid) throw new Error("Signature verification failed");
    return {
      payload,
      signing: {
        ...activeProfile,
        keyVersion: String(verification.keyVersion || activeProfile.keyVersion || "").trim(),
        keyRef: String(verification.keyRef || activeProfile.keyRef || "").trim() || null,
        payloadKeyVersion: String(payload.kid || "").trim() || null,
      },
    };
  }

  const { mode } = getSignMode();
  if (mode === "ed25519") {
    const { publicKey } = getEd25519Keys();
    const ok = cryptoVerify(null, payloadHash, publicKey, decodeBase64UrlStrict(sigPart));
    if (!ok) throw new Error("Signature verification failed");
    return {
      payload,
      signing: {
        ...activeProfile,
        payloadKeyVersion: String(payload.kid || "").trim() || null,
      },
    };
  } else {
    const got = decodeBase64UrlStrict(sigPart);
    let valid = false;
    let matchedVersion: ReturnType<typeof getQrSigningHmacSecretSet>["all"][number] | null = null;
    for (const version of getQrSigningHmacSecretSet().all) {
      const expected = createHmac("sha256", version.value).update(payloadHash).digest();
      if (expected.length === got.length && timingSafeEqual(expected, got)) {
        valid = true;
        matchedVersion = version;
        break;
      }
    }
    if (!valid) {
      throw new Error("Signature verification failed");
    }
    return {
      payload,
      signing: {
        mode: activeProfile.mode,
        keyVersion: matchedVersion?.id || activeProfile.keyVersion,
        provider: activeProfile.provider,
        keyRef: matchedVersion?.source || activeProfile.keyRef,
        payloadKeyVersion: String(payload.kid || "").trim() || null,
        legacyHmacFallback: matchedVersion?.source === "JWT_SECRET",
      },
    };
  }
};

export const buildScanUrl = (token: string) => {
  const base =
    String(process.env.PUBLIC_SCAN_WEB_BASE_URL || "").trim() ||
    String(process.env.PUBLIC_VERIFY_WEB_BASE_URL || "").trim() ||
    String(process.env.CORS_ORIGIN || "").trim() ||
    "http://localhost:8080";
  const normalized = base.replace(/\/+$/, "");
  return `${normalized}/scan?t=${encodeURIComponent(token)}`;
};

export const isPrinterTestQrId = (qrId: string | null | undefined) =>
  String(qrId || "").trim().startsWith(PRINTER_TEST_QR_ID_PREFIX);
