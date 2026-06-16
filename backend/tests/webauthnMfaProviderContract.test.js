const assert = require("assert");
const path = require("path");

process.env.NODE_ENV = "test";
process.env.JWT_SECRET = process.env.JWT_SECRET || "webauthn-provider-contract-jwt-secret";
process.env.JWT_SECRET_CURRENT = process.env.JWT_SECRET_CURRENT || process.env.JWT_SECRET;
process.env.TOKEN_HASH_SECRET_CURRENT = process.env.TOKEN_HASH_SECRET_CURRENT || "webauthn-provider-contract-token-secret";
process.env.WEBAUTHN_RP_ID = "mscqr.com";
process.env.WEBAUTHN_ORIGIN = "https://www.mscqr.com,https://mscqr.com";
process.env.AUTH_WEBAUTHN_CHALLENGE_TTL_MINUTES = "5";

const distRoot = path.resolve(__dirname, "../dist");
const mockModule = (relativePath, exportsValue) => {
  const resolved = require.resolve(path.join(distRoot, relativePath));
  require.cache[resolved] = {
    id: resolved,
    filename: resolved,
    loaded: true,
    exports: exportsValue,
  };
};

let factors = [
  {
    id: "factor-passkey-1",
    userId: "admin-1",
    type: "WEBAUTHN",
    label: "Primary passkey",
    credentialId: "credential-1",
    publicKey: Buffer.from("public-key").toString("base64url"),
    counter: 3,
    transports: ["internal"],
    disabledAt: null,
    lastUsedAt: null,
  },
];
let challenges = [];
let authOptionsInput = null;
let authVerifyInput = null;
let registrationOptionsInput = null;
let registrationVerifyInput = null;

const prismaMock = {
  userMfaFactor: {
    findMany: async ({ where }) => factors.filter((row) => {
      if (where.userId && row.userId !== where.userId) return false;
      if (where.type && row.type !== where.type) return false;
      if (where.disabledAt === null && row.disabledAt) return false;
      if (where.credentialId?.not === null && !row.credentialId) return false;
      if (where.publicKey?.not === null && !row.publicKey) return false;
      return true;
    }).map((row) => ({ ...row })),
    findFirst: async ({ where }) => factors.find((row) => {
      if (where.userId && row.userId !== where.userId) return false;
      if (where.type && row.type !== where.type) return false;
      if (where.disabledAt === null && row.disabledAt) return false;
      if (where.credentialId && row.credentialId !== where.credentialId) return false;
      return true;
    }) || null,
    update: async ({ where, data }) => {
      const row = factors.find((entry) => entry.id === where.id);
      if (!row) throw new Error("factor not found");
      Object.assign(row, data);
      return { ...row };
    },
    upsert: async ({ where, update, create }) => {
      const row = factors.find((entry) => entry.credentialId === where.credentialId);
      if (row) {
        Object.assign(row, update);
        return { ...row };
      }
      const created = { id: `factor-${factors.length + 1}`, ...create, disabledAt: null };
      factors.push(created);
      return { ...created };
    },
  },
  authWebAuthnChallenge: {
    create: async ({ data }) => {
      const row = {
        id: `challenge-${challenges.length + 1}`,
        ...data,
        consumedAt: null,
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      challenges.push(row);
      return { ...row };
    },
    findFirst: async ({ where }) => {
      const hashes = where.ticketHash?.in || [];
      const now = new Date();
      const row = challenges.find((entry) => {
        if (hashes.length && !hashes.includes(entry.ticketHash)) return false;
        if (where.purpose && entry.purpose !== where.purpose) return false;
        if (where.consumedAt === null && entry.consumedAt) return false;
        if (where.expiresAt?.gt && entry.expiresAt.getTime() <= now.getTime()) return false;
        return true;
      });
      return row ? { ...row } : null;
    },
    update: async ({ where, data }) => {
      const row = challenges.find((entry) => entry.id === where.id);
      if (!row) throw new Error("challenge not found");
      Object.assign(row, data);
      return { ...row };
    },
  },
};

mockModule("config/database.js", { __esModule: true, default: prismaMock });

const simpleWebAuthnPath = require.resolve("@simplewebauthn/server");
require.cache[simpleWebAuthnPath] = {
  id: simpleWebAuthnPath,
  filename: simpleWebAuthnPath,
  loaded: true,
  exports: {
    generateAuthenticationOptions: async (input) => {
      authOptionsInput = input;
      return { challenge: "auth-challenge", allowCredentials: input.allowCredentials, userVerification: input.userVerification };
    },
    verifyAuthenticationResponse: async (input) => {
      authVerifyInput = input;
      return {
        verified: true,
        authenticationInfo: {
          newCounter: 9,
          credentialDeviceType: "singleDevice",
          credentialBackedUp: false,
        },
      };
    },
    generateRegistrationOptions: async (input) => {
      registrationOptionsInput = input;
      return { challenge: "registration-challenge", rp: { id: input.rpID, name: input.rpName } };
    },
    verifyRegistrationResponse: async (input) => {
      registrationVerifyInput = input;
      return {
        verified: true,
        registrationInfo: {
          credential: {
            id: "credential-2",
            publicKey: Buffer.from("registered-public-key"),
            counter: 1,
            transports: ["usb"],
          },
          credentialDeviceType: "multiDevice",
          credentialBackedUp: true,
        },
      };
    },
  },
};

const {
  beginWebAuthnFactorAuthentication,
  completeWebAuthnFactorAuthentication,
  beginWebAuthnFactorRegistration,
  completeWebAuthnFactorRegistration,
} = require("../dist/services/auth/webauthnMfaProvider");

const run = async () => {
  const authBegin = await beginWebAuthnFactorAuthentication({
    userId: "admin-1",
    purpose: "LOGIN",
    ipHash: "ip-hash",
    userAgent: "Mozilla/5.0",
  });
  assert.strictEqual(authOptionsInput.rpID, "mscqr.com");
  assert.strictEqual(authOptionsInput.userVerification, "preferred");
  assert.deepStrictEqual(authOptionsInput.allowCredentials, [{ id: "credential-1", transports: ["internal"] }]);

  const authComplete = await completeWebAuthnFactorAuthentication({
    userId: "admin-1",
    ticket: authBegin.ticket,
    credential: {
      id: "credential-1",
      rawId: "credential-1",
      type: "public-key",
      response: {
        clientDataJSON: "client-data",
        authenticatorData: "authenticator-data",
        signature: "signature",
      },
    },
  });
  assert.deepStrictEqual(authComplete, { ok: true, purpose: "LOGIN" });
  assert(authVerifyInput.expectedChallenge("auth-challenge"), "authentication verification should validate the stored challenge");
  assert.deepStrictEqual(authVerifyInput.expectedOrigin, ["https://www.mscqr.com", "https://mscqr.com"]);
  assert.strictEqual(authVerifyInput.expectedRPID, "mscqr.com");
  assert.strictEqual(authVerifyInput.credential.id, "credential-1");
  assert.strictEqual(authVerifyInput.credential.counter, 3);
  assert.strictEqual(Buffer.from(authVerifyInput.credential.publicKey).toString(), "public-key");
  assert.strictEqual(factors[0].counter, 9);
  assert(challenges[0].consumedAt, "authentication challenge should be consumed");

  const registrationBegin = await beginWebAuthnFactorRegistration({
    userId: "admin-1",
    email: "admin@example.com",
    displayName: "Admin",
  });
  assert.strictEqual(registrationOptionsInput.rpID, "mscqr.com");
  assert.strictEqual(registrationOptionsInput.userName, "admin@example.com");
  assert.strictEqual(registrationOptionsInput.authenticatorSelection.userVerification, "preferred");

  const registrationComplete = await completeWebAuthnFactorRegistration({
    userId: "admin-1",
    ticket: registrationBegin.ticket,
    label: "Laptop passkey",
    credential: {
      id: "credential-2",
      rawId: "credential-2",
      type: "public-key",
      response: {
        clientDataJSON: "client-data",
        attestationObject: "attestation",
      },
    },
  });
  assert.deepStrictEqual(registrationComplete, { ok: true, credentialId: "credential-2" });
  assert(registrationVerifyInput.expectedChallenge("registration-challenge"), "registration verification should validate the stored challenge");
  assert.deepStrictEqual(registrationVerifyInput.expectedOrigin, ["https://www.mscqr.com", "https://mscqr.com"]);
  assert.strictEqual(registrationVerifyInput.expectedRPID, "mscqr.com");
  assert(factors.some((row) => row.credentialId === "credential-2" && row.label === "Laptop passkey"));
  assert(challenges[1].consumedAt, "registration challenge should be consumed");

  console.log("WebAuthn MFA provider contract tests passed");
};

run().catch((error) => {
  console.error(error);
  process.exit(1);
});
