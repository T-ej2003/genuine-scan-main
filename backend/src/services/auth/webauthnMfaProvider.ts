import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type RegistrationResponseJSON,
} from "@simplewebauthn/server";
import { Prisma } from "@prisma/client";

import prisma from "../../config/database";
import { buildTokenHashCandidates, hashToken, normalizeUserAgent, randomOpaqueToken } from "../../utils/security";
import {
  completeAdminWebAuthnAuthenticationBoundary,
  completeAdminWebAuthnRegistrationBoundary,
  createAdminWebAuthnChallengeBoundary,
  loadAdminWebAuthnChallengeBoundary,
  loadAdminWebAuthnCredentials,
} from "../../rls-waves/session-b/b01/adminMfaRepository";

type WebAuthnChallengePurpose = "ENROLLMENT" | "LOGIN" | "STEP_UP";
type WebAuthnDbClient = Pick<Prisma.TransactionClient, "$queryRaw">;

const parsePositiveIntEnv = (key: string, fallback: number) => {
  const raw = Number(String(process.env[key] || "").trim());
  return Number.isFinite(raw) ? Math.max(1, Math.floor(raw)) : fallback;
};

const toBase64Url = (value: Uint8Array | Buffer | ArrayBuffer) => Buffer.from(value as any).toString("base64url");
const fromBase64Url = (value: string) => Buffer.from(String(value || "").trim(), "base64url");

const webAuthnRpName = () => String(process.env.WEBAUTHN_RP_NAME || process.env.APP_NAME || "MSCQR").trim() || "MSCQR";

const tryParseUrl = (value: string) => {
  try {
    return new URL(value);
  } catch {
    return null;
  }
};

export const deriveWebAuthnRpId = () => {
  const explicit = String(process.env.WEBAUTHN_RP_ID || "").trim();
  if (explicit) return explicit;

  const cookieDomain = String(process.env.COOKIE_DOMAIN || "").trim().replace(/^\./, "");
  if (cookieDomain) return cookieDomain;

  const appUrl =
    tryParseUrl(String(process.env.WEBAUTHN_ORIGIN || "").trim()) ||
    tryParseUrl(String(process.env.APP_URL || "").trim()) ||
    tryParseUrl(String(process.env.PUBLIC_APP_URL || "").trim()) ||
    tryParseUrl(String(process.env.FRONTEND_URL || "").trim());
  if (appUrl?.hostname) return appUrl.hostname;

  return "localhost";
};

export const deriveWebAuthnOrigins = () => {
  const explicit = String(process.env.WEBAUTHN_ORIGIN || process.env.WEBAUTHN_ALLOWED_ORIGINS || process.env.WEBAUTHN_ORIGINS || "").trim();
  if (explicit) {
    return Array.from(new Set(explicit.split(",").map((value) => value.trim()).filter(Boolean)));
  }

  const derived = [
    String(process.env.APP_URL || "").trim(),
    String(process.env.PUBLIC_APP_URL || "").trim(),
    String(process.env.FRONTEND_URL || "").trim(),
  ]
    .map((value) => tryParseUrl(value)?.origin || "")
    .filter(Boolean);

  if (derived.length) return Array.from(new Set(derived));
  const rpId = deriveWebAuthnRpId();
  return process.env.NODE_ENV === "production"
    ? [`https://${rpId}`]
    : ["http://localhost:8080", "http://127.0.0.1:8080", "http://localhost:5173", "http://127.0.0.1:5173", `https://${rpId}`];
};

const challengeTtlMinutes = () => parsePositiveIntEnv("AUTH_WEBAUTHN_CHALLENGE_TTL_MINUTES", 5);

export const beginWebAuthnFactorRegistration = async (params: {
  userId: string;
  email: string;
  displayName: string;
  ipHash?: string | null;
  userAgent?: string | null;
}, db?: Prisma.TransactionClient) => {
  if (!db) throw new Error("B01 MFA capability transaction is required");
  const ticket = randomOpaqueToken(36);
  const rpID = deriveWebAuthnRpId();
  const state = await loadAdminWebAuthnCredentials(db);
  const existing = [...state.factors, ...state.legacy]
    .filter((row) => row.credentialId)
    .map((row) => ({ credentialId: String(row.credentialId), transports: Array.isArray(row.transports) ? row.transports : [] }));

  const options = await generateRegistrationOptions({
    rpName: webAuthnRpName(),
    rpID,
    userID: Buffer.from(params.userId, "utf8"),
    userName: params.email,
    userDisplayName: params.displayName || params.email,
    timeout: challengeTtlMinutes() * 60_000,
    attestationType: "none",
    authenticatorSelection: {
      residentKey: "preferred",
      userVerification: "preferred",
    },
    excludeCredentials: existing
      .map((row) => row.credentialId ? { id: row.credentialId, transports: row.transports as any } : null)
      .filter((entry): entry is { id: string; transports: any } => Boolean(entry)),
  });

  const expiresAt = new Date(Date.now() + challengeTtlMinutes() * 60_000);
  await createAdminWebAuthnChallengeBoundary(db, {
    purpose: "ENROLLMENT",
    ticketHash: hashToken(ticket),
    challengeHash: hashToken(options.challenge),
    ipHash: params.ipHash || null,
    userAgentHash: params.userAgent ? hashToken(normalizeUserAgent(params.userAgent) || params.userAgent) : null,
    origin: deriveWebAuthnOrigins()[0] || null,
    rpId: rpID,
    createdAt: new Date(),
    expiresAt,
  });

  return { ticket, options, expiresAt };
};

export const completeWebAuthnFactorRegistration = async (params: {
  userId: string;
  ticket: string;
  label?: string | null;
  credential: RegistrationResponseJSON;
}, db?: Prisma.TransactionClient) => {
  if (!db) throw new Error("B01 MFA capability transaction is required");
  const loaded = await loadAdminWebAuthnChallengeBoundary(db, {
    ticketHashes: buildTokenHashCandidates(params.ticket),
    purpose: "ENROLLMENT",
    credentialId: null,
    checkedAt: new Date(),
  });
  if (!loaded?.challenge) throw new Error("WEBAUTHN_CHALLENGE_NOT_FOUND");
  const challenge = loaded.challenge;
  if (challenge.userId !== params.userId) throw new Error("WEBAUTHN_CHALLENGE_USER_MISMATCH");

  const verification = await verifyRegistrationResponse({
    response: params.credential,
    expectedChallenge: (value) => buildTokenHashCandidates(value).includes(challenge.challengeHash),
    expectedOrigin: deriveWebAuthnOrigins(),
    expectedRPID: challenge.rpId || deriveWebAuthnRpId(),
    requireUserVerification: false,
  });

  if (!verification.verified || !verification.registrationInfo) {
    throw new Error("WEBAUTHN_REGISTRATION_NOT_VERIFIED");
  }

  const info = verification.registrationInfo;
  const credential = info.credential;
  const label = String(params.label || "").trim() || "Passkey";

  return completeAdminWebAuthnRegistrationBoundary(db, {
    challengeId: challenge.id,
    credentialId: credential.id,
    label,
    publicKey: toBase64Url(credential.publicKey),
    counter: credential.counter,
    transports: credential.transports || [],
    deviceType: info.credentialDeviceType,
    backedUp: info.credentialBackedUp,
    completedAt: new Date(),
  });
};

export const beginWebAuthnFactorAuthentication = async (params: {
  userId: string;
  purpose: Exclude<WebAuthnChallengePurpose, "ENROLLMENT">;
  ipHash?: string | null;
  userAgent?: string | null;
}, db?: Prisma.TransactionClient) => {
  if (!db) throw new Error("B01 MFA capability transaction is required");
  const state = await loadAdminWebAuthnCredentials(db);
  const credentials = [...state.factors, ...state.legacy]
    .filter((row) => row.credentialId)
    .map((row) => ({ credentialId: String(row.credentialId), transports: Array.isArray(row.transports) ? row.transports : [] }));
  if (!credentials.length) throw new Error("WEBAUTHN_NOT_ENROLLED");

  const ticket = randomOpaqueToken(36);
  const rpID = deriveWebAuthnRpId();
  const options = await generateAuthenticationOptions({
    rpID,
    timeout: challengeTtlMinutes() * 60_000,
    userVerification: "preferred",
    allowCredentials: credentials
      .map((row) => row.credentialId ? { id: row.credentialId, transports: row.transports as any } : null)
      .filter((entry): entry is { id: string; transports: any } => Boolean(entry)),
  });
  const expiresAt = new Date(Date.now() + challengeTtlMinutes() * 60_000);

  await createAdminWebAuthnChallengeBoundary(db, {
    purpose: params.purpose,
    ticketHash: hashToken(ticket),
    challengeHash: hashToken(options.challenge),
    ipHash: params.ipHash || null,
    userAgentHash: params.userAgent ? hashToken(normalizeUserAgent(params.userAgent) || params.userAgent) : null,
    origin: deriveWebAuthnOrigins()[0] || null,
    rpId: rpID,
    createdAt: new Date(),
    expiresAt,
  });

  return { ticket, options, expiresAt };
};

export const completeWebAuthnFactorAuthentication = async (params: {
  userId: string;
  ticket: string;
  credential: AuthenticationResponseJSON;
}, db?: Prisma.TransactionClient): Promise<{ ok: true; purpose: WebAuthnChallengePurpose }> => {
  if (!db) throw new Error("B01 MFA capability transaction is required");
  const credentialId = String(params.credential.rawId || params.credential.id || "").trim();
  let loaded = await loadAdminWebAuthnChallengeBoundary(db, {
    ticketHashes: buildTokenHashCandidates(params.ticket),
    purpose: "LOGIN",
    credentialId,
    checkedAt: new Date(),
  });
  if (!loaded) loaded = await loadAdminWebAuthnChallengeBoundary(db, {
    ticketHashes: buildTokenHashCandidates(params.ticket),
    purpose: "STEP_UP",
    credentialId,
    checkedAt: new Date(),
  });
  if (!loaded?.challenge) throw new Error("WEBAUTHN_CHALLENGE_NOT_FOUND");
  const challenge = loaded.challenge;
  if (challenge.userId !== params.userId) throw new Error("WEBAUTHN_CHALLENGE_USER_MISMATCH");
  const factor = loaded.factor;
  if (!factor?.credentialId || !factor.publicKey) throw new Error("WEBAUTHN_CREDENTIAL_NOT_FOUND");

  const verification = await verifyAuthenticationResponse({
    response: params.credential,
    expectedChallenge: (value) => buildTokenHashCandidates(value).includes(challenge.challengeHash),
    expectedOrigin: deriveWebAuthnOrigins(),
    expectedRPID: challenge.rpId || deriveWebAuthnRpId(),
    credential: {
      id: factor.credentialId,
      publicKey: fromBase64Url(factor.publicKey),
      counter: factor.counter,
      transports: factor.transports as any,
    },
    requireUserVerification: false,
  });

  if (!verification.verified) throw new Error("WEBAUTHN_ASSERTION_NOT_VERIFIED");
  const completed = await completeAdminWebAuthnAuthenticationBoundary(db, {
    challengeId: challenge.id,
    credentialKind: "FACTOR",
    credentialRowId: factor.id,
    expectedCounter: factor.counter,
    nextCounter: Math.max(factor.counter, verification.authenticationInfo.newCounter),
    deviceType: verification.authenticationInfo.credentialDeviceType,
    backedUp: verification.authenticationInfo.credentialBackedUp,
    completedAt: new Date(),
  });
  return { ok: true as const, purpose: completed.purpose as WebAuthnChallengePurpose };
};
