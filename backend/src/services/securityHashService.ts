import { createHash } from "crypto";
import { getIncidentHashSalt } from "../utils/secretConfig";

const normalize = (value?: string | null) => String(value || "").trim().toLowerCase();

export const sha256Hash = (value?: string | null) => {
  const input = normalize(value);
  if (!input) return null;
  return createHash("sha256").update(`${getIncidentHashSalt()}:${input}`).digest("hex");
};

export const deviceFingerprintFromRequest = (ip?: string | null, userAgent?: string | null, extra?: string | null) => {
  const raw = [normalize(ip), normalize(userAgent), normalize(extra)].filter(Boolean).join("|");
  if (!raw) return null;
  return createHash("sha256").update(`${getIncidentHashSalt()}:device:${raw}`).digest("hex");
};
