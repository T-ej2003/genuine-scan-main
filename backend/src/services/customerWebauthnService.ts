import { createHash, createPublicKey, randomBytes, verify as cryptoVerify } from "crypto";

import prisma from "../config/database";
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

const challengeStore = () => (prisma as any).customerWebAuthnChallenge;
const credentialStore = () => (prisma as any).customerWebAuthnCredential;

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

const loadChallengeByTicket = async (ticket: string, purpose?: CustomerWebAuthnChallengePurpose) => {
  const store = challengeStore();
  if (!store?.findFirst) throw new Error("WEBAUTHN_STORAGE_UNAVAILABLE");

  const ticketHashCandidates = buildTokenHashCandidates(ticket);
  const now = new Date();
  const row = await store.findFirst({
    where: {
      ticketHash: { in: ticketHashCandidates },
      purpose: purpose || undefined,
      consumedAt: null,
      expiresAt: { gt: now },
    },
  });

  if (!row) throw new Error("WEBAUTHN_CHALLENGE_NOT_FOUND");
  return row as StoredCustomerChallenge;
};

const consumeChallenge = async (id: string) => {
  const store = challengeStore();
  if (!store?.update) return;
  await store.update({
    where: { id },
    data: {
      consumedAt: new Date(),
    },
  });
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

export const listCustomerWebAuthnCredentials = async (customerUserId: string) => {
  const store = credentialStore();
  if (!store?.findMany) return [];

  const rows = await store.findMany({
    where: { customerUserId },
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
  customerUserId: string;
  email: string;
  displayName?: string | null;
  ipHash?: string | null;
  userAgent?: string | null;
}) => {
  const store = credentialStore();
  const challenges = challengeStore();
  if (!store?.findMany || !challenges?.create) throw new Error("WEBAUTHN_STORAGE_UNAVAILABLE");

  const ticket = randomOpaqueToken(36);
  const challenge = toBase64Url(randomBytes(32));
  const rpId = deriveRpId();
  const origin = deriveAllowedOrigins()[0] || null;
  const expiresAt = new Date(Date.now() + challengeTtlMinutes() * 60_000);
  const existingCredentials = await store.findMany({
    where: { customerUserId: params.customerUserId },
    select: { credentialId: true },
  });

  await challenges.create({
    data: {
      customerUserId: params.customerUserId,
      customerEmail: params.email,
      purpose: "ENROLLMENT",
      ticketHash: hashToken(ticket),
      challengeHash: hashToken(challenge),
      credentialIds: existingCredentials.map((row: any) => row.credentialId),
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
}) => {
  const store = credentialStore();
  if (!store?.upsert) throw new Error("WEBAUTHN_STORAGE_UNAVAILABLE");

  const challenge = await loadChallengeByTicket(params.ticket, "ENROLLMENT");
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

  await store.upsert({
    where: { credentialId },
    update: {
      customerUserId: params.customerUserId,
      label: String(params.label || "").trim() || "Passkey",
      publicKeySpki: params.credential.response.publicKey,
      publicKeyAlgorithm: Number(params.credential.response.publicKeyAlgorithm || -7),
      counter: authenticatorData.signCount,
      transports: Array.isArray(params.credential.response.transports)
        ? params.credential.response.transports.map((value) => String(value || "").trim()).filter(Boolean)
        : [],
      lastUsedAt: new Date(),
    },
    create: {
      customerUserId: params.customerUserId,
      customerEmail: challenge.customerEmail,
      label: String(params.label || "").trim() || "Passkey",
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

export const beginCustomerWebAuthnAssertion = async (params: {
  customerUserId: string;
  email?: string | null;
  purpose?: Exclude<CustomerWebAuthnChallengePurpose, "ENROLLMENT">;
  ipHash?: string | null;
  userAgent?: string | null;
}) => {
  const store = credentialStore();
  const challenges = challengeStore();
  if (!store?.findMany || !challenges?.create) throw new Error("WEBAUTHN_STORAGE_UNAVAILABLE");

  const credentials = await store.findMany({
    where: { customerUserId: params.customerUserId },
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

  await challenges.create({
    data: {
      customerUserId: params.customerUserId,
      customerEmail: params.email || null,
      purpose: params.purpose || "LOGIN",
      ticketHash: hashToken(ticket),
      challengeHash: hashToken(challenge),
      credentialIds: credentials.map((row: any) => row.credentialId),
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
}) => {
  const store = credentialStore();
  if (!store?.findFirst || !store?.update) throw new Error("WEBAUTHN_STORAGE_UNAVAILABLE");

  const challenge = await loadChallengeByTicket(params.ticket);
  if (params.customerUserId && challenge.customerUserId !== params.customerUserId) {
    throw new Error("WEBAUTHN_CHALLENGE_USER_MISMATCH");
  }

  const credentialId = String(params.credential.rawId || params.credential.id || "").trim();
  const storedCredential = await store.findFirst({
    where: {
      customerUserId: challenge.customerUserId,
      credentialId,
    },
    select: {
      id: true,
      customerUserId: true,
      customerEmail: true,
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

  await store.update({
    where: { id: storedCredential.id },
    data: {
      counter: nextCounter > storedCredential.counter ? nextCounter : storedCredential.counter,
      lastUsedAt: new Date(),
    },
  });

  await consumeChallenge(challenge.id);

  return {
    ok: true as const,
    purpose: challenge.purpose as CustomerWebAuthnChallengePurpose,
    customerUserId: storedCredential.customerUserId,
    customerEmail: storedCredential.customerEmail,
    assertedAt: new Date(),
  };
};

export const deleteCustomerWebAuthnCredential = async (params: {
  customerUserId: string;
  credentialId: string;
}) => {
  const store = credentialStore();
  if (!store?.deleteMany) return { deleted: false };

  const deleted = await store.deleteMany({
    where: {
      id: params.credentialId,
      customerUserId: params.customerUserId,
    },
  });

  return {
    deleted: deleted.count > 0,
  };
};
