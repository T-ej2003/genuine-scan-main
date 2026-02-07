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

export type QrTokenPayload = {
  qr_id: string;
  batch_id: string | null;
  licensee_id: string;
  manufacturer_id?: string | null;
  iat: number;
  exp?: number;
  nonce: string;
};

type SignMode = "ed25519" | "hmac";

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
  const priv = process.env.QR_SIGN_PRIVATE_KEY;
  const pub = process.env.QR_SIGN_PUBLIC_KEY;
  if (priv && pub) return { mode: "ed25519", key: "ed25519" };

  const hmac = process.env.QR_SIGN_HMAC_SECRET;
  if (hmac) return { mode: "hmac", key: "hmac" };

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

export const randomNonce = () => randomBytes(16).toString("base64url");

export const hashToken = (token: string) =>
  createHash("sha256").update(token).digest("hex");

export const signQrPayload = (payload: QrTokenPayload): string => {
  const sanitized: Record<string, any> = {};
  for (const [k, v] of Object.entries(payload)) {
    if (v !== undefined) sanitized[k] = v;
  }
  const payloadJson = stableStringify(sanitized);
  const payloadBuf = Buffer.from(payloadJson, "utf8");
  const payloadHash = createHash("sha256").update(payloadBuf).digest();

  const { mode } = getSignMode();

  let sig: Buffer;
  if (mode === "ed25519") {
    const { privateKey } = getEd25519Keys();
    sig = cryptoSign(null, payloadHash, privateKey);
  } else {
    const secret = String(process.env.QR_SIGN_HMAC_SECRET || "");
    sig = createHmac("sha256", secret).update(payloadHash).digest();
  }

  return `${toBase64Url(payloadBuf)}.${toBase64Url(sig)}`;
};

export const verifyQrToken = (token: string): { payload: QrTokenPayload } => {
  const tokenStr = String(token || "").trim();
  const parts = tokenStr.split(".");
  if (parts.length !== 2) throw new Error("Invalid token format");
  const [payloadPart, sigPart] = parts;
  if (!payloadPart || !sigPart) throw new Error("Invalid token format");

  const payloadBuf = decodeBase64UrlStrict(payloadPart);
  const payloadJson = payloadBuf.toString("utf8");
  const payload = JSON.parse(payloadJson) as QrTokenPayload;

  const payloadHash = createHash("sha256").update(payloadBuf).digest();

  const { mode } = getSignMode();
  if (mode === "ed25519") {
    const { publicKey } = getEd25519Keys();
    const ok = cryptoVerify(null, payloadHash, publicKey, decodeBase64UrlStrict(sigPart));
    if (!ok) throw new Error("Signature verification failed");
  } else {
    const secret = String(process.env.QR_SIGN_HMAC_SECRET || "");
    const expected = createHmac("sha256", secret).update(payloadHash).digest();
    const got = decodeBase64UrlStrict(sigPart);
    if (expected.length !== got.length || !timingSafeEqual(expected, got)) {
      throw new Error("Signature verification failed");
    }
  }

  return { payload };
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
