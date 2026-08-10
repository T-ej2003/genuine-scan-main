import { createCipheriv, createDecipheriv, createHmac, randomBytes } from "crypto";

import { getJwtSecretSet } from "../../utils/secretConfig";

type CookieTokenPurpose =
  | "auth.access"
  | "auth.refresh"
  | "auth.database-session"
  | "customer-verify.session";

const COOKIE_TOKEN_VERSION = "v1";
const COOKIE_TOKEN_IV_BYTES = 12;

const deriveCookieTokenKey = (secret: string, purpose: CookieTokenPurpose) =>
  createHmac("sha256", secret)
    .update(`mscqr-cookie-token:${purpose}:${COOKIE_TOKEN_VERSION}`)
    .digest()
    .subarray(0, 32);

const encodeBase64Url = (value: Buffer) => value.toString("base64url");
const decodeBase64Url = (value: string) => Buffer.from(String(value || "").trim(), "base64url");

const parseProtectedToken = (value: string) => {
  const [version, iv, authTag, ciphertext] = String(value || "").trim().split(".");
  if (version !== COOKIE_TOKEN_VERSION || !iv || !authTag || !ciphertext) {
    throw new Error("INVALID_COOKIE_TOKEN_FORMAT");
  }

  return {
    iv: decodeBase64Url(iv),
    authTag: decodeBase64Url(authTag),
    ciphertext: decodeBase64Url(ciphertext),
  };
};

export const sealCookieToken = (rawValue: string, purpose: CookieTokenPurpose) => {
  const normalized = String(rawValue || "").trim();
  if (!normalized) {
    throw new Error("COOKIE_TOKEN_VALUE_REQUIRED");
  }

  const iv = randomBytes(COOKIE_TOKEN_IV_BYTES);
  const cipher = createCipheriv("aes-256-gcm", deriveCookieTokenKey(getJwtSecretSet().current.value, purpose), iv);
  const ciphertext = Buffer.concat([cipher.update(normalized, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return [
    COOKIE_TOKEN_VERSION,
    encodeBase64Url(iv),
    encodeBase64Url(authTag),
    encodeBase64Url(ciphertext),
  ].join(".");
};

export const openCookieToken = (sealedValue: string, purpose: CookieTokenPurpose) => {
  const normalized = String(sealedValue || "").trim();
  if (!normalized) return null;

  try {
    const parsed = parseProtectedToken(normalized);
    const secrets = getJwtSecretSet();
    for (const secret of [secrets.current.value, secrets.previous?.value].filter((value): value is string => Boolean(value))) {
      try {
        const decipher = createDecipheriv("aes-256-gcm", deriveCookieTokenKey(secret, purpose), parsed.iv);
        decipher.setAuthTag(parsed.authTag);
        const plaintext = Buffer.concat([decipher.update(parsed.ciphertext), decipher.final()]).toString("utf8").trim();
        if (plaintext) return plaintext;
      } catch {
        // Try the one configured compatibility key, then fail closed.
      }
    }
    return null;
  } catch {
    return null;
  }
};

export const isProtectedCookieToken = (value: string | null | undefined) => {
  const normalized = String(value || "").trim();
  if (!normalized) return false;
  return normalized.startsWith(`${COOKIE_TOKEN_VERSION}.`);
};
