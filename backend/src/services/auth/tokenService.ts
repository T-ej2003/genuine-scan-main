import jwt from "jsonwebtoken";
import type { SignOptions } from "jsonwebtoken";
import type { JWTPayload, MfaBootstrapPayload } from "../../types";
import { getJwtSecret, hashToken, randomOpaqueToken } from "../../utils/security";

export const ACCESS_TOKEN_COOKIE = "aq_access";
export const REFRESH_TOKEN_COOKIE = "aq_refresh";
export const CSRF_TOKEN_COOKIE = "aq_csrf";

const parseIntEnv = (key: string, fallback: number) => {
  const raw = String(process.env[key] || "").trim();
  const n = Number(raw);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : fallback;
};

export const getAccessTokenTtlMinutes = () => parseIntEnv("ACCESS_TOKEN_TTL_MINUTES", 15);
export const getRefreshTokenTtlDays = () => parseIntEnv("REFRESH_TOKEN_TTL_DAYS", 30);
export const getMfaBootstrapTtlMinutes = () => parseIntEnv("AUTH_MFA_BOOTSTRAP_TTL_MINUTES", 10);

export const signAccessToken = (payload: JWTPayload) => {
  const jwtSecret = getJwtSecret();
  const expiresInMinutes = getAccessTokenTtlMinutes();
  const opts: SignOptions = { expiresIn: `${expiresInMinutes}m` };
  return jwt.sign(payload, jwtSecret, opts);
};

export const verifyAccessToken = (token: string): JWTPayload => {
  const jwtSecret = getJwtSecret();
  return jwt.verify(token, jwtSecret) as JWTPayload;
};

export const signMfaBootstrapToken = (payload: Omit<MfaBootstrapPayload, "stage">) => {
  const jwtSecret = getJwtSecret();
  const opts: SignOptions = { expiresIn: `${getMfaBootstrapTtlMinutes()}m` };
  return jwt.sign({ ...payload, stage: "MFA_BOOTSTRAP" } satisfies MfaBootstrapPayload, jwtSecret, opts);
};

export const verifyMfaBootstrapToken = (token: string): MfaBootstrapPayload => {
  const jwtSecret = getJwtSecret();
  const payload = jwt.verify(token, jwtSecret) as Partial<MfaBootstrapPayload>;
  if (payload?.stage !== "MFA_BOOTSTRAP" || !payload.userId || !payload.email || !payload.role) {
    throw new Error("INVALID_MFA_BOOTSTRAP_TOKEN");
  }
  return payload as MfaBootstrapPayload;
};

export const newRefreshToken = () => randomOpaqueToken(48);
export const hashRefreshToken = (token: string) => hashToken(token);

export const newCsrfToken = () => randomOpaqueToken(24);
