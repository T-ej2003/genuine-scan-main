import { createHmac } from "node:crypto";

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const TOTP_PERIOD_MS = 30_000;
const TOTP_DIGITS = 6;
const MIN_PERIOD_REMAINING_MS = 3_000;
const BASE32_PADDING_BY_REMAINDER = { 0: 0, 2: 6, 4: 4, 5: 3, 7: 1 };

const invalidBase32Secret = () =>
  new Error("SMOKE_ADMIN_MFA_SECRET must be a valid Base32 secret.");

export const decodeBase32Secret = (secret) => {
  const normalized = String(secret || "").trim().toUpperCase();
  if (!/^[A-Z2-7]+={0,6}$/.test(normalized)) throw invalidBase32Secret();

  const unpadded = normalized.replace(/=+$/, "");
  const paddingLength = normalized.length - unpadded.length;
  const expectedPadding = BASE32_PADDING_BY_REMAINDER[unpadded.length % 8];
  if (expectedPadding === undefined || (paddingLength > 0 && paddingLength !== expectedPadding)) {
    throw invalidBase32Secret();
  }

  let bits = 0;
  let value = 0;
  const bytes = [];
  for (const character of unpadded) {
    value = (value << 5) | BASE32_ALPHABET.indexOf(character);
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((value >>> bits) & 0xff);
      value &= (1 << bits) - 1;
    }
  }

  if (value !== 0 || bytes.length === 0) throw invalidBase32Secret();
  return Buffer.from(bytes);
};

export const generateTotpCode = (secret, atMs = Date.now()) => {
  if (!Number.isFinite(atMs) || atMs < 0) throw new Error("TOTP time must be a non-negative finite timestamp.");

  const counter = BigInt(Math.floor(atMs / TOTP_PERIOD_MS));
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeBigUInt64BE(counter);
  const digest = createHmac("sha1", decodeBase32Secret(secret)).update(counterBuffer).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary =
    ((digest[offset] & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8) |
    (digest[offset + 3] & 0xff);
  return String(binary % 10 ** TOTP_DIGITS).padStart(TOTP_DIGITS, "0");
};

export const calculateTotpBoundaryWaitMs = (atMs) => {
  if (!Number.isFinite(atMs) || atMs < 0) throw new Error("TOTP time must be a non-negative finite timestamp.");
  const remainingMs = TOTP_PERIOD_MS - (atMs % TOTP_PERIOD_MS);
  return remainingMs < MIN_PERIOD_REMAINING_MS ? remainingMs + 1 : 0;
};

export const resolveSmokeAdminMfaCode = async ({
  code,
  secret,
  now = Date.now,
  wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
}) => {
  const staticCode = String(code || "").trim();
  if (staticCode) return staticCode;

  const totpSecret = String(secret || "").trim();
  if (!totpSecret) return "";

  const waitMs = calculateTotpBoundaryWaitMs(now());
  if (waitMs > 0) await wait(waitMs);
  return generateTotpCode(totpSecret, now());
};
