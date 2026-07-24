import { createHash, createPublicKey, randomBytes, verify as cryptoVerify } from "crypto";
import { Prisma } from "@prisma/client";

import prisma from "../../config/database";
import { buildTokenHashCandidates, hashToken, normalizeUserAgent, randomOpaqueToken } from "../../utils/security";
import {
  beginWebAuthnFactorAuthentication,
  beginWebAuthnFactorRegistration,
  completeWebAuthnFactorAuthentication,
  completeWebAuthnFactorRegistration,
} from "./webauthnMfaProvider";
import { lockMfaState } from "./mfaAdapter";
import {
  completeAdminWebAuthnAuthenticationBoundary,
  completeAdminWebAuthnRegistrationBoundary,
  deleteAdminWebAuthnCredentialBoundary,
  loadAdminWebAuthnChallengeBoundary,
  loadAdminWebAuthnCredentials,
} from "../../rls-waves/session-b/b01/adminMfaRepository";

type WebAuthnChallengePurpose = "ENROLLMENT" | "LOGIN" | "STEP_UP";
type WebAuthnDbClient = Pick<
  Prisma.TransactionClient,
  "$executeRaw" | "$queryRaw"
>;

type StoredChallenge = {
  id: string;
  userId: string;
  purpose: string;
  challengeHash: string;
  expiresAt: Date;
  consumedAt: Date | null;
  credentialIds: string[];
  origin: string | null;
  rpId: string | null;
};

const parsePositiveIntEnv = (key: string, fallback: number) => {
  const raw = Number(String(process.env[key] || "").trim());
  return Number.isFinite(raw) ? Math.max(1, Math.floor(raw)) : fallback;
};

const toBase64Url = (value: Buffer | ArrayBuffer | Uint8Array) => Buffer.from(value as any).toString("base64url");
const fromBase64Url = (value: string) => Buffer.from(String(value || "").trim(), "base64url");
const sha256Buffer = (value: string | Buffer) => createHash("sha256").update(value).digest();
const sha256Base64Url = (value: string | Buffer) => sha256Buffer(value).toString("base64url");

const webAuthnRpName = () => String(process.env.WEBAUTHN_RP_NAME || process.env.APP_NAME || "MSCQR").trim() || "MSCQR";

const tryParseUrl = (value: string) => {
  try {
    return new URL(value);
  } catch {
    return null;
  }
};

const deriveRpId = () => {
  const explicit = String(process.env.WEBAUTHN_RP_ID || "").trim();
  if (explicit) return explicit;

  const cookieDomain = String(process.env.COOKIE_DOMAIN || "").trim().replace(/^\./, "");
  if (cookieDomain) return cookieDomain;

  const appUrl =
    tryParseUrl(String(process.env.APP_URL || "").trim()) ||
    tryParseUrl(String(process.env.PUBLIC_APP_URL || "").trim()) ||
    tryParseUrl(String(process.env.FRONTEND_URL || "").trim());
  if (appUrl?.hostname) return appUrl.hostname;

  return process.env.NODE_ENV === "production" ? "localhost" : "localhost";
};

const deriveAllowedOrigins = () => {
  const explicit = String(process.env.WEBAUTHN_ALLOWED_ORIGINS || process.env.WEBAUTHN_ORIGINS || "").trim();
  if (explicit) {
    return Array.from(
      new Set(
        explicit
          .split(",")
          .map((value) => String(value || "").trim())
          .filter(Boolean)
      )
    );
  }

  const derived = [
    String(process.env.APP_URL || "").trim(),
    String(process.env.PUBLIC_APP_URL || "").trim(),
    String(process.env.FRONTEND_URL || "").trim(),
  ]
    .map((value) => {
      const parsed = tryParseUrl(value);
      return parsed ? parsed.origin : "";
    })
    .filter(Boolean);

  if (derived.length) return Array.from(new Set(derived));

  const rpId = deriveRpId();
  if (process.env.NODE_ENV === "production") {
    return [`https://${rpId}`];
  }

  return [
    "http://localhost:8080",
    "http://127.0.0.1:8080",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    `http://${rpId}`,
    `https://${rpId}`,
  ];
};

const challengeTtlMinutes = () => parsePositiveIntEnv("AUTH_WEBAUTHN_CHALLENGE_TTL_MINUTES", 5);

const buildUserHandle = (userId: string) => Buffer.from(String(userId || "").trim(), "utf8").toString("base64url");

const verifyOrigin = (origin: string, expectedOrigin?: string | null) => {
  const allowed = deriveAllowedOrigins();
  if (expectedOrigin && origin === expectedOrigin) return true;
  return allowed.includes(origin);
};

const parseClientData = (encoded: string) => {
  const buffer = fromBase64Url(encoded);
  const parsed = JSON.parse(buffer.toString("utf8"));
  return {
    raw: buffer,
    parsed,
  };
};

const parseAuthenticatorData = (encoded: string) => {
  const raw = fromBase64Url(encoded);
  if (raw.length < 37) {
    throw new Error("INVALID_WEBAUTHN_AUTH_DATA");
  }

  return {
    raw,
    rpIdHash: raw.subarray(0, 32),
    flags: raw[32],
    signCount: raw.readUInt32BE(33),
  };
};

const verifyRpIdHash = (rpIdHash: Buffer, expectedRpId?: string | null) => {
  const rpId = expectedRpId || deriveRpId();
  return rpIdHash.equals(sha256Buffer(rpId));
};

const assertUserPresence = (flags: number) => {
  if ((flags & 0x01) !== 0x01) {
    throw new Error("WEBAUTHN_USER_PRESENCE_REQUIRED");
  }
};

export const listAdminWebAuthnCredentials = async (userId: string, db?: Prisma.TransactionClient) => {
  if (!db) throw new Error("B01 MFA capability transaction is required");
  const state = await loadAdminWebAuthnCredentials(db);
  return [...state.factors, ...state.legacy].map((row) => ({
    id: row.id,
    label: row.label || "Passkey",
    credentialId: row.credentialId,
    transports: row.transports,
    lastUsedAt: row.lastUsedAt,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  }));
};

export const beginAdminWebAuthnRegistration = async (params: {
  userId: string;
  email: string;
  displayName: string;
  ipHash?: string | null;
  userAgent?: string | null;
}, db?: Prisma.TransactionClient) => {
  return beginWebAuthnFactorRegistration(params, db);
};

export const completeAdminWebAuthnRegistration = async (params: {
  userId: string;
  ticket: string;
  label?: string | null;
  credential: {
    id: string;
    rawId: string;
    type: string;
    response: {
      clientDataJSON: string;
      attestationObject: string;
      authenticatorData?: string;
      publicKey?: string;
      publicKeyAlgorithm?: number;
      transports?: string[];
    };
  };
}, db?: Prisma.TransactionClient) => {
  try {
    return await completeWebAuthnFactorRegistration({
      ...params,
      credential: params.credential as any,
    }, db);
  } catch (error) {
    if (!(error instanceof Error) || !["WEBAUTHN_CHALLENGE_NOT_FOUND", "WEBAUTHN_CHALLENGE_USER_MISMATCH"].includes(error.message)) {
      throw error;
    }
  }

  const legacyResponse = params.credential.response;
  if (!legacyResponse.authenticatorData || !legacyResponse.publicKey) {
    throw new Error("WEBAUTHN_LEGACY_REGISTRATION_PAYLOAD_UNSUPPORTED");
  }

  if (!db) throw new Error("B01 MFA capability transaction is required");
  const loaded = await loadAdminWebAuthnChallengeBoundary(db, {
    ticketHashes: buildTokenHashCandidates(params.ticket),
    purpose: "ENROLLMENT",
    credentialId: null,
    checkedAt: new Date(),
  });
  if (!loaded?.challenge) throw new Error("WEBAUTHN_CHALLENGE_NOT_FOUND");
  const challenge = loaded.challenge as StoredChallenge;
  if (challenge.userId !== params.userId) {
    throw new Error("WEBAUTHN_CHALLENGE_USER_MISMATCH");
  }

  const clientData = parseClientData(params.credential.response.clientDataJSON);
  if (clientData.parsed.type !== "webauthn.create") {
    throw new Error("INVALID_WEBAUTHN_TYPE");
  }
  if (!verifyOrigin(String(clientData.parsed.origin || ""), challenge.origin || null)) {
    throw new Error("INVALID_WEBAUTHN_ORIGIN");
  }
  if (!buildTokenHashCandidates(String(clientData.parsed.challenge || "")).includes(challenge.challengeHash)) {
    throw new Error("INVALID_WEBAUTHN_CHALLENGE");
  }

  const authenticatorData = parseAuthenticatorData(legacyResponse.authenticatorData);
  if (!verifyRpIdHash(authenticatorData.rpIdHash, challenge.rpId || null)) {
    throw new Error("INVALID_WEBAUTHN_RP_ID");
  }
  assertUserPresence(authenticatorData.flags);

  const credentialId = String(params.credential.rawId || params.credential.id || "").trim();
  if (!credentialId) throw new Error("INVALID_WEBAUTHN_CREDENTIAL_ID");

  return completeAdminWebAuthnRegistrationBoundary(db, {
    challengeId: challenge.id,
    credentialId,
    label: String(params.label || "").trim() || "Security key",
    publicKey: legacyResponse.publicKey,
    counter: authenticatorData.signCount,
    transports: Array.isArray(params.credential.response.transports)
      ? params.credential.response.transports.map((value) => String(value || "").trim()).filter(Boolean)
      : [],
    deviceType: null,
    backedUp: null,
    completedAt: new Date(),
  });
};

export const beginAdminWebAuthnChallenge = async (params: {
  userId: string;
  purpose: Exclude<WebAuthnChallengePurpose, "ENROLLMENT">;
  ipHash?: string | null;
  userAgent?: string | null;
}, db?: Prisma.TransactionClient) => {
  return beginWebAuthnFactorAuthentication(params, db);
};

const verifyAssertionSignature = (params: {
  publicKeySpki: string;
  authenticatorData: Buffer;
  clientDataJson: Buffer;
  signature: Buffer;
}) => {
  const publicKey = createPublicKey({
    key: fromBase64Url(params.publicKeySpki),
    format: "der",
    type: "spki",
  });
  const signedPayload = Buffer.concat([params.authenticatorData, sha256Buffer(params.clientDataJson)]);
  return cryptoVerify("sha256", signedPayload, publicKey, params.signature);
};

export const completeAdminWebAuthnChallenge = async (params: {
  userId: string;
  ticket: string;
  credential: {
    id: string;
    rawId: string;
    type: string;
    response: {
      clientDataJSON: string;
      authenticatorData: string;
      signature: string;
      userHandle?: string | null;
    };
  };
}, db?: Prisma.TransactionClient): Promise<{ ok: true; purpose: WebAuthnChallengePurpose }> => {
  if (!db) throw new Error("B01 MFA capability transaction is required");
  try {
    return await completeWebAuthnFactorAuthentication({
      ...params,
      credential: params.credential as any,
    }, db);
  } catch (error) {
    if (
      !(error instanceof Error) ||
      !["WEBAUTHN_CREDENTIAL_NOT_FOUND", "WEBAUTHN_CHALLENGE_NOT_FOUND", "WEBAUTHN_CHALLENGE_USER_MISMATCH"].includes(error.message)
    ) {
      throw error;
    }
  }

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
  const challenge = loaded.challenge as StoredChallenge;
  if (challenge.userId !== params.userId) {
    throw new Error("WEBAUTHN_CHALLENGE_USER_MISMATCH");
  }

  const storedCredential = loaded.legacy;
  if (!storedCredential) throw new Error("WEBAUTHN_CREDENTIAL_NOT_FOUND");

  const clientData = parseClientData(params.credential.response.clientDataJSON);
  if (clientData.parsed.type !== "webauthn.get") {
    throw new Error("INVALID_WEBAUTHN_TYPE");
  }
  if (!verifyOrigin(String(clientData.parsed.origin || ""), challenge.origin || null)) {
    throw new Error("INVALID_WEBAUTHN_ORIGIN");
  }
  if (!buildTokenHashCandidates(String(clientData.parsed.challenge || "")).includes(challenge.challengeHash)) {
    throw new Error("INVALID_WEBAUTHN_CHALLENGE");
  }

  const authenticatorData = parseAuthenticatorData(params.credential.response.authenticatorData);
  if (!verifyRpIdHash(authenticatorData.rpIdHash, challenge.rpId || null)) {
    throw new Error("INVALID_WEBAUTHN_RP_ID");
  }
  assertUserPresence(authenticatorData.flags);

  const signatureValid = verifyAssertionSignature({
    publicKeySpki: storedCredential.publicKeySpki,
    authenticatorData: authenticatorData.raw,
    clientDataJson: clientData.raw,
    signature: fromBase64Url(params.credential.response.signature),
  });
  if (!signatureValid) {
    throw new Error("INVALID_WEBAUTHN_SIGNATURE");
  }

  const nextCounter = authenticatorData.signCount;
  if (nextCounter > 0 && storedCredential.counter > 0 && nextCounter <= storedCredential.counter) {
    throw new Error("WEBAUTHN_COUNTER_REPLAY");
  }

  const completed = await completeAdminWebAuthnAuthenticationBoundary(db, {
    challengeId: challenge.id,
    credentialKind: "LEGACY",
    credentialRowId: storedCredential.id,
    expectedCounter: storedCredential.counter,
    nextCounter: nextCounter > storedCredential.counter ? nextCounter : storedCredential.counter,
    deviceType: null,
    backedUp: null,
    completedAt: new Date(),
  });

  return {
    ok: true as const,
    purpose: completed.purpose as WebAuthnChallengePurpose,
  };
};

export const deleteAdminWebAuthnCredential = async (params: {
  userId: string;
  credentialId: string;
}, db?: Prisma.TransactionClient) => {
  if (!db) throw new Error("B01 MFA capability transaction is required");
  return deleteAdminWebAuthnCredentialBoundary(db, params.credentialId, new Date());
};
