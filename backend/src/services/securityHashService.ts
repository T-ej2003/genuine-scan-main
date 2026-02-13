import { createHash } from "crypto";

const hashSalt = String(process.env.INCIDENT_HASH_SALT || process.env.JWT_SECRET || "authenticqr-salt");

const normalize = (value?: string | null) => String(value || "").trim().toLowerCase();

export const sha256Hash = (value?: string | null) => {
  const input = normalize(value);
  if (!input) return null;
  return createHash("sha256").update(`${hashSalt}:${input}`).digest("hex");
};

export const deviceFingerprintFromRequest = (ip?: string | null, userAgent?: string | null, extra?: string | null) => {
  const raw = [normalize(ip), normalize(userAgent), normalize(extra)].filter(Boolean).join("|");
  if (!raw) return null;
  return createHash("sha256").update(`${hashSalt}:device:${raw}`).digest("hex");
};
