import { createHash, createPublicKey, randomBytes, randomUUID, verify as cryptoVerify } from "crypto";

import { getB01PreAuthPrisma } from "../rls-waves/session-b/b01/runtimeClients";
import {
  beginCustomerPasskey,
  deleteCustomerPasskey,
  finishCustomerPasskey,
  listCustomerPasskeys,
  loadCustomerPasskey,
} from "../rls-waves/session-b/b02/publicBoundaryRepository";
import { buildTokenHashCandidates, hashToken, normalizeUserAgent, randomOpaqueToken } from "../utils/security";

type CustomerWebAuthnChallengePurpose = "ENROLLMENT" | "LOGIN" | "STEP_UP";

type StoredCustomerChallenge = {
  id: string;
  customerUserId: string;
  customerEmail: string | null;
  purpose: string;
  challengeHash: string;
  expiresAt: Date;
  consumedAt: Date | null;
  credentialIds: string[];
  origin: string | null;
  rpId: string | null;
};

const store = () => getB01PreAuthPrisma();
const requestId = (value?: string) => String(value || randomUUID()).trim();

const parsePositiveIntEnv = (key: string, fallback: number) => {
  const raw = Number(String(process.env[key] || "").trim());
  return Number.isFinite(raw) ? Math.max(1, Math.floor(raw)) : fallback;
};

const toBase64Url = (value: Buffer | ArrayBuffer | Uint8Array) => Buffer.from(value as any).toString("base64url");
const fromBase64Url = (value: string) => Buffer.from(String(value || "").trim(), "base64url");
const sha256Buffer = (value: string | Buffer) => createHash("sha256").update(value).digest();

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

  return "localhost";
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
  return [
    "http://localhost:8080",
    "http://127.0.0.1:8080",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    `http://${rpId}`,
    `https://${rpId}`,
  ];
};

const challengeTtlMinutes = () =>
  parsePositiveIntEnv(
    "CUSTOMER_WEBAUTHN_CHALLENGE_TTL_MINUTES",
    parsePositiveIntEnv("AUTH_WEBAUTHN_CHALLENGE_TTL_MINUTES", 5)
  );

const buildUserHandle = (customerUserId: string) => Buffer.from(String(customerUserId || "").trim(), "utf8").toString("base64url");

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

const loadChallengeByTicket = async (
  ticket: string,
  purpose?: CustomerWebAuthnChallengePurpose,
  credentialId?: string | null,
  currentRequestId?: string
) => {
  const ticketHashCandidates = buildTokenHashCandidates(ticket);
  const row = await loadCustomerPasskey(store(), {
    ticketHashCandidates,
    purpose: purpose || null,
    credentialId: credentialId || null,
    checkedAt: new Date(),
    requestId: requestId(currentRequestId),
  });
  return row as StoredCustomerChallenge;
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

export const listCustomerWebAuthnCredentials = async (params: {
  customerCapability: string;
  requestId?: string;
}) => {
  const rows = await listCustomerPasskeys(store(), {
    customerCapability: params.customerCapability,
    checkedAt: new Date(),
    requestId: requestId(params.requestId),
  });

  return rows.map((row: any) => ({
    id: row.id,
    label: row.label || "Passkey",
    credentialId: row.credentialId,
    transports: row.transports,
    lastUsedAt: row.lastUsedAt,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  }));
};

export const beginCustomerWebAuthnRegistration = async (params: {
  customerCapability: string;
  customerUserId: string;
  email: string;
  displayName?: string | null;
  ipHash?: string | null;
  userAgent?: string | null;
  requestId?: string;
}) => {
  const ticket = randomOpaqueToken(36);
  const challenge = toBase64Url(randomBytes(32));
  const rpId = deriveRpId();
  const origin = deriveAllowedOrigins()[0] || null;
  const expiresAt = new Date(Date.now() + challengeTtlMinutes() * 60_000);
  const boundary = await beginCustomerPasskey(store(), {
    customerCapability: params.customerCapability,
    customerUserId: params.customerUserId,
    customerEmail: params.email,
    purpose: "ENROLLMENT",
    ticketHash: hashToken(ticket),
    challengeHash: hashToken(challenge),
    ipHash: params.ipHash || null,
    userAgentHash: params.userAgent ? hashToken(normalizeUserAgent(params.userAgent) || params.userAgent) : null,
    origin,
    rpId,
    expiresAt,
    checkedAt: new Date(),
    requestId: requestId(params.requestId),
  });
  const existingCredentials = Array.isArray(boundary.credentials) ? boundary.credentials as Array<any> : [];

  return {
    ticket,
    options: {
      rp: {
        name: webAuthnRpName(),
        id: rpId,
      },
      user: {
        id: buildUserHandle(params.customerUserId),
        name: params.email,
        displayName: params.displayName || params.email,
      },
      challenge,
      timeout: challengeTtlMinutes() * 60_000,
      attestation: "none" as const,
      authenticatorSelection: {
        residentKey: "preferred" as const,
        userVerification: "preferred" as const,
      },
      pubKeyCredParams: [
        { alg: -7, type: "public-key" as const },
        { alg: -257, type: "public-key" as const },
      ],
      excludeCredentials: existingCredentials.map((row: any) => ({
        id: row.credentialId,
        type: "public-key" as const,
      })),
    },
    expiresAt,
  };
};

export const completeCustomerWebAuthnRegistration = async (params: {
  customerCapability: string;
  customerUserId: string;
  ticket: string;
  label?: string | null;
  credential: {
    id: string;
    rawId: string;
    type: string;
    response: {
      clientDataJSON: string;
      attestationObject: string;
      authenticatorData: string;
      publicKey: string;
      publicKeyAlgorithm: number;
      transports?: string[];
    };
  };
  requestId?: string;
}) => {
  const challenge = await loadChallengeByTicket(params.ticket, "ENROLLMENT", null, params.requestId);
  if (challenge.customerUserId !== params.customerUserId) {
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

  const authenticatorData = parseAuthenticatorData(params.credential.response.authenticatorData);
  if (!verifyRpIdHash(authenticatorData.rpIdHash, challenge.rpId || null)) {
    throw new Error("INVALID_WEBAUTHN_RP_ID");
  }
  assertUserPresence(authenticatorData.flags);

  const credentialId = String(params.credential.rawId || params.credential.id || "").trim();
  if (!credentialId) throw new Error("INVALID_WEBAUTHN_CREDENTIAL_ID");

  await finishCustomerPasskey(store(), {
    customerCapability: params.customerCapability,
    ticketHashCandidates: buildTokenHashCandidates(params.ticket),
    purpose: "ENROLLMENT",
    payload: {
      credentialId,
      publicKeySpki: params.credential.response.publicKey,
      publicKeyAlgorithm: Number(params.credential.response.publicKeyAlgorithm || -7),
      counter: authenticatorData.signCount,
      transports: Array.isArray(params.credential.response.transports)
        ? params.credential.response.transports.map((value) => String(value || "").trim()).filter(Boolean)
        : [],
      label: String(params.label || "").trim() || "Passkey",
    },
    checkedAt: new Date(),
    requestId: requestId(params.requestId),
  });

  return {
    ok: true as const,
    credentialId,
  };
};

export const beginCustomerWebAuthnAssertion = async (params: {
  customerCapability?: string | null;
  customerUserId: string;
  email?: string | null;
  purpose?: Exclude<CustomerWebAuthnChallengePurpose, "ENROLLMENT">;
  ipHash?: string | null;
  userAgent?: string | null;
  requestId?: string;
}) => {
  const ticket = randomOpaqueToken(36);
  const challenge = toBase64Url(randomBytes(32));
  const rpId = deriveRpId();
  const origin = deriveAllowedOrigins()[0] || null;
  const expiresAt = new Date(Date.now() + challengeTtlMinutes() * 60_000);

  const boundary = await beginCustomerPasskey(store(), {
    customerCapability: params.customerCapability || null,
    customerUserId: params.customerUserId,
    customerEmail: params.email || "",
    purpose: params.purpose || "LOGIN",
    ticketHash: hashToken(ticket),
    challengeHash: hashToken(challenge),
    ipHash: params.ipHash || null,
    userAgentHash: params.userAgent ? hashToken(normalizeUserAgent(params.userAgent) || params.userAgent) : null,
    origin,
    rpId,
    expiresAt,
    checkedAt: new Date(),
    requestId: requestId(params.requestId),
  });
  const credentials = Array.isArray(boundary.credentials) ? boundary.credentials as Array<any> : [];

  return {
    ticket,
    options: {
      challenge,
      timeout: challengeTtlMinutes() * 60_000,
      rpId,
      userVerification: "preferred" as const,
      allowCredentials: credentials.map((row: any) => ({
        id: row.credentialId,
        type: "public-key" as const,
        transports: row.transports,
      })),
    },
    expiresAt,
  };
};

export const completeCustomerWebAuthnAssertion = async (params: {
  customerCapability?: string | null;
  ticket: string;
  customerUserId?: string | null;
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
  requestId?: string;
}) => {
  const credentialId = String(params.credential.rawId || params.credential.id || "").trim();
  const challenge = await loadChallengeByTicket(params.ticket, undefined, credentialId, params.requestId) as StoredCustomerChallenge & {
    credential?: {
      id: string; customerUserId: string; customerEmail: string | null;
      credentialId: string; publicKeySpki: string; counter: number;
    } | null;
  };
  if (params.customerUserId && challenge.customerUserId !== params.customerUserId) {
    throw new Error("WEBAUTHN_CHALLENGE_USER_MISMATCH");
  }

  const storedCredential = challenge.credential;
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

  const assertedAt = new Date();
  await finishCustomerPasskey(store(), {
    customerCapability: params.customerCapability || null,
    ticketHashCandidates: buildTokenHashCandidates(params.ticket),
    purpose: challenge.purpose as CustomerWebAuthnChallengePurpose,
    payload: { credentialId, nextCounter },
    checkedAt: assertedAt,
    requestId: requestId(params.requestId),
  });

  return {
    ok: true as const,
    purpose: challenge.purpose as CustomerWebAuthnChallengePurpose,
    customerUserId: storedCredential.customerUserId,
    customerEmail: storedCredential.customerEmail,
    assertedAt,
  };
};

export const deleteCustomerWebAuthnCredential = async (params: {
  customerCapability: string;
  credentialId: string;
  requestId?: string;
}) => {
  const deleted = await deleteCustomerPasskey(store(), {
    customerCapability: params.customerCapability,
    credentialRowId: params.credentialId,
    checkedAt: new Date(),
    requestId: requestId(params.requestId),
  });
  return { deleted: Boolean(deleted?.deleted) };
};
