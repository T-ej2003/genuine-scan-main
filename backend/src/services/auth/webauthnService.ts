import { createHash, createPublicKey, randomBytes, verify as cryptoVerify } from "crypto";

import prisma from "../../config/database";
import { buildTokenHashCandidates, hashToken, normalizeUserAgent, randomOpaqueToken } from "../../utils/security";

type WebAuthnChallengePurpose = "ENROLLMENT" | "LOGIN" | "STEP_UP";

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

const loadChallengeByTicket = async (ticket: string, purpose?: WebAuthnChallengePurpose) => {
  const ticketHashCandidates = buildTokenHashCandidates(ticket);
  const now = new Date();
  const row = await prisma.authWebAuthnChallenge.findFirst({
    where: {
      ticketHash: { in: ticketHashCandidates },
      purpose: purpose || undefined,
      consumedAt: null,
      expiresAt: { gt: now },
    },
  });

  if (!row) throw new Error("WEBAUTHN_CHALLENGE_NOT_FOUND");
  return row as StoredChallenge;
};

const consumeChallenge = async (id: string) => {
  await prisma.authWebAuthnChallenge.update({
    where: { id },
    data: {
      consumedAt: new Date(),
    },
  });
};

export const listAdminWebAuthnCredentials = async (userId: string) => {
  const rows = await prisma.adminWebAuthnCredential.findMany({
    where: { userId },
    orderBy: [{ lastUsedAt: "desc" }, { createdAt: "desc" }],
    select: {
      id: true,
      label: true,
      credentialId: true,
      transports: true,
      lastUsedAt: true,
      createdAt: true,
      updatedAt: true,
    },
  });

  return rows.map((row) => ({
    id: row.id,
    label: row.label || "Security key",
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
}) => {
  const ticket = randomOpaqueToken(36);
  const challenge = toBase64Url(randomBytes(32));
  const rpId = deriveRpId();
  const origin = deriveAllowedOrigins()[0] || null;
  const expiresAt = new Date(Date.now() + challengeTtlMinutes() * 60_000);
  const existingCredentials = await prisma.adminWebAuthnCredential.findMany({
    where: { userId: params.userId },
    select: { credentialId: true },
  });

  await prisma.authWebAuthnChallenge.create({
    data: {
      userId: params.userId,
      purpose: "ENROLLMENT",
      ticketHash: hashToken(ticket),
      challengeHash: hashToken(challenge),
      credentialIds: existingCredentials.map((row) => row.credentialId),
      createdIpHash: params.ipHash || null,
      createdUserAgentHash: params.userAgent ? hashToken(normalizeUserAgent(params.userAgent) || params.userAgent) : null,
      origin,
      rpId,
      expiresAt,
    },
  });

  return {
    ticket,
    options: {
      rp: {
        name: webAuthnRpName(),
        id: rpId,
      },
      user: {
        id: buildUserHandle(params.userId),
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
      excludeCredentials: existingCredentials.map((row) => ({
        id: row.credentialId,
        type: "public-key" as const,
      })),
    },
    expiresAt,
  };
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
      authenticatorData: string;
      publicKey: string;
      publicKeyAlgorithm: number;
      transports?: string[];
    };
  };
}) => {
  const challenge = await loadChallengeByTicket(params.ticket, "ENROLLMENT");
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

  const authenticatorData = parseAuthenticatorData(params.credential.response.authenticatorData);
  if (!verifyRpIdHash(authenticatorData.rpIdHash, challenge.rpId || null)) {
    throw new Error("INVALID_WEBAUTHN_RP_ID");
  }
  assertUserPresence(authenticatorData.flags);

  const credentialId = String(params.credential.rawId || params.credential.id || "").trim();
  if (!credentialId) throw new Error("INVALID_WEBAUTHN_CREDENTIAL_ID");

  await prisma.adminWebAuthnCredential.upsert({
    where: { credentialId },
    update: {
      userId: params.userId,
      label: String(params.label || "").trim() || "Security key",
      publicKeySpki: params.credential.response.publicKey,
      publicKeyAlgorithm: Number(params.credential.response.publicKeyAlgorithm || -7),
      counter: authenticatorData.signCount,
      transports: Array.isArray(params.credential.response.transports)
        ? params.credential.response.transports.map((value) => String(value || "").trim()).filter(Boolean)
        : [],
      lastUsedAt: new Date(),
    },
    create: {
      userId: params.userId,
      label: String(params.label || "").trim() || "Security key",
      credentialId,
      publicKeySpki: params.credential.response.publicKey,
      publicKeyAlgorithm: Number(params.credential.response.publicKeyAlgorithm || -7),
      counter: authenticatorData.signCount,
      transports: Array.isArray(params.credential.response.transports)
        ? params.credential.response.transports.map((value) => String(value || "").trim()).filter(Boolean)
        : [],
      lastUsedAt: new Date(),
    },
  });

  await consumeChallenge(challenge.id);

  return {
    ok: true as const,
    credentialId,
  };
};

export const beginAdminWebAuthnChallenge = async (params: {
  userId: string;
  purpose: Exclude<WebAuthnChallengePurpose, "ENROLLMENT">;
  ipHash?: string | null;
  userAgent?: string | null;
}) => {
  const credentials = await prisma.adminWebAuthnCredential.findMany({
    where: { userId: params.userId },
    select: {
      credentialId: true,
      transports: true,
    },
  });

  if (!credentials.length) {
    throw new Error("WEBAUTHN_NOT_ENROLLED");
  }

  const ticket = randomOpaqueToken(36);
  const challenge = toBase64Url(randomBytes(32));
  const rpId = deriveRpId();
  const origin = deriveAllowedOrigins()[0] || null;
  const expiresAt = new Date(Date.now() + challengeTtlMinutes() * 60_000);

  await prisma.authWebAuthnChallenge.create({
    data: {
      userId: params.userId,
      purpose: params.purpose,
      ticketHash: hashToken(ticket),
      challengeHash: hashToken(challenge),
      credentialIds: credentials.map((row) => row.credentialId),
      createdIpHash: params.ipHash || null,
      createdUserAgentHash: params.userAgent ? hashToken(normalizeUserAgent(params.userAgent) || params.userAgent) : null,
      origin,
      rpId,
      expiresAt,
    },
  });

  return {
    ticket,
    options: {
      challenge,
      timeout: challengeTtlMinutes() * 60_000,
      rpId,
      userVerification: "preferred" as const,
      allowCredentials: credentials.map((row) => ({
        id: row.credentialId,
        type: "public-key" as const,
        transports: row.transports,
      })),
    },
    expiresAt,
  };
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
}) => {
  const challenge = await loadChallengeByTicket(params.ticket);
  if (challenge.userId !== params.userId) {
    throw new Error("WEBAUTHN_CHALLENGE_USER_MISMATCH");
  }

  const credentialId = String(params.credential.rawId || params.credential.id || "").trim();
  const storedCredential = await prisma.adminWebAuthnCredential.findFirst({
    where: {
      userId: params.userId,
      credentialId,
    },
    select: {
      id: true,
      credentialId: true,
      publicKeySpki: true,
      counter: true,
    },
  });
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

  await prisma.adminWebAuthnCredential.update({
    where: { id: storedCredential.id },
    data: {
      counter: nextCounter > storedCredential.counter ? nextCounter : storedCredential.counter,
      lastUsedAt: new Date(),
    },
  });

  await consumeChallenge(challenge.id);

  return {
    ok: true as const,
    purpose: challenge.purpose as WebAuthnChallengePurpose,
  };
};

export const deleteAdminWebAuthnCredential = async (params: {
  userId: string;
  credentialId: string;
}) => {
  const deleted = await prisma.adminWebAuthnCredential.deleteMany({
    where: {
      id: params.credentialId,
      userId: params.userId,
    },
  });

  return {
    deleted: deleted.count > 0,
  };
};
