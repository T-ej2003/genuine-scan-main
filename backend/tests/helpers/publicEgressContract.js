const assert = require("assert");

const BASE_FORBIDDEN_PUBLIC_KEYS = new Set([
  "decisionId",
  "decision_id",
  "sessionId",
  "session_id",
  "sessionReference",
  "decisionReference",
  "proofSource",
  "proof_source",
  "proofTier",
  "proof_tier",
  "riskScore",
  "risk_score",
  "riskBand",
  "risk_band",
  "reasonCodes",
  "reason_codes",
  "classification",
  "printTrustState",
  "print_trust_state",
  "licenseeId",
  "licensee_id",
  "manufacturerId",
  "manufacturer_id",
  "batchId",
  "batch_id",
  "internalAuditId",
  "internal_audit_id",
  "auditId",
  "audit_id",
  "registryLookupMode",
  "registry_lookup_mode",
  "manualLookupReason",
  "manual_lookup_reason",
  "supportNotes",
  "support_notes",
  "debug",
  "debugFlags",
  "debug_flags",
  "raw",
  "metadata",
  "trace",
  "traceId",
  "trace_id",
  "internal",
  "stack",
  "stackTrace",
  "stack_trace",
  "sql",
  "query",
  "params",
  "password",
  "passwordHash",
  "password_hash",
  "secret",
  "tokenHash",
  "token_hash",
  "apiKey",
  "api_key",
  "privateKey",
  "private_key",
  "confidenceInternalName",
  "sourceCheckInternalName",
]);

const BASE_FORBIDDEN_PUBLIC_STRINGS = [
  "Manual Registry Lookup",
  "Manual Code Lookup",
  "Technical details for support",
  "Decision reference",
  "Session reference",
  "Support notes",
  "Not available",
  "stack trace",
  "SQL",
  "Prisma",
  "Sequelize",
  "ECONNREFUSED",
  "JWT_SECRET",
  "DATABASE_URL",
  "undefined",
  "null",
];

const isPlainObject = (value) => Boolean(value) && typeof value === "object" && !Array.isArray(value);

const toArray = (value) => {
  if (!value) return [];
  return Array.isArray(value) ? value : Array.from(value);
};

const pathFor = (basePath, key) => (basePath ? `${basePath}.${key}` : key);

const walk = (value, visitor, path) => {
  visitor(value, path);
  if (Array.isArray(value)) {
    value.forEach((entry, index) => walk(entry, visitor, `${path}[${index}]`));
    return;
  }
  if (!isPlainObject(value)) return;
  Object.entries(value).forEach(([key, entry]) => walk(entry, visitor, pathFor(path, key)));
};

const buildKeySets = (options = {}) => {
  const allowedKeys = new Set(toArray(options.allowedKeys));
  const forbiddenKeys = new Set([...BASE_FORBIDDEN_PUBLIC_KEYS, ...toArray(options.forbiddenKeysExtra)]);
  return { allowedKeys, forbiddenKeys };
};

const buildStringSets = (options = {}) => {
  const allowedStrings = toArray(options.allowedStrings).map((value) => String(value));
  const forbiddenStrings = [...BASE_FORBIDDEN_PUBLIC_STRINGS, ...toArray(options.forbiddenStringsExtra)].map((value) =>
    String(value)
  );
  return { allowedStrings, forbiddenStrings };
};

const expectNoForbiddenPublicKeys = (payload, options = {}) => {
  const { allowedKeys, forbiddenKeys } = buildKeySets(options);
  const pathPrefix = options.pathPrefix || "response";

  walk(
    payload,
    (value, path) => {
      if (!isPlainObject(value)) return;
      for (const key of Object.keys(value)) {
        if (allowedKeys.has(key)) continue;
        assert(!forbiddenKeys.has(key), `Forbidden public key found at ${pathFor(path, key)}`);
      }
    },
    pathPrefix
  );
};

const isForbiddenStringMatch = (value, forbidden) => {
  if (forbidden === "null" || forbidden === "undefined") {
    return value.trim().toLowerCase() === forbidden;
  }
  return value.toLowerCase().includes(forbidden.toLowerCase());
};

const expectNoForbiddenPublicStrings = (payload, options = {}) => {
  const { allowedStrings, forbiddenStrings } = buildStringSets(options);
  const pathPrefix = options.pathPrefix || "response";

  walk(
    payload,
    (value, path) => {
      if (typeof value !== "string") return;
      if (allowedStrings.some((allowed) => value.includes(allowed))) return;
      for (const forbidden of forbiddenStrings) {
        assert(
          !isForbiddenStringMatch(value, forbidden),
          `Forbidden public string found at ${path}: "${forbidden}"`
        );
      }
    },
    pathPrefix
  );
};

const expectPublicResponseSafe = (payload, options = {}) => {
  assert.notStrictEqual(payload, undefined, "Public response payload must be defined");
  expectNoForbiddenPublicKeys(payload, options);
  expectNoForbiddenPublicStrings(payload, options);
};

const looksLikeTimestamp = (value) =>
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value);

const looksLikeUuid = (value) =>
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);

const looksLikeUrl = (value) => /^https?:\/\//i.test(value);

const looksLikeOpaqueToken = (value) =>
  /^[A-Za-z0-9_-]{24,}$/.test(value) || /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(value);

const looksLikeTokenKey = (key) => /token|otp|challenge/i.test(key);

const looksLikeGeneratedCode = (value) => /^[A-Z]{2,8}-?\d{4,}[-A-Z0-9]*$/.test(value);

const stablePublicContract = (payload, options = {}, key = "") => {
  if (Array.isArray(payload)) {
    return payload.map((entry) => stablePublicContract(entry, options));
  }
  if (isPlainObject(payload)) {
    return Object.fromEntries(
      Object.keys(payload)
        .sort()
        .map((entryKey) => [entryKey, stablePublicContract(payload[entryKey], options, entryKey)])
    );
  }
  if (typeof payload !== "string") return payload;
  if (looksLikeTimestamp(payload)) return "<timestamp>";
  if (looksLikeUuid(payload)) return "<uuid>";
  if (looksLikeTokenKey(key) || looksLikeOpaqueToken(payload)) return "<token>";
  if (looksLikeUrl(payload)) return "<url>";
  if (options.normalizeCodeLike && looksLikeGeneratedCode(payload)) return "<code>";
  return payload;
};

module.exports = {
  BASE_FORBIDDEN_PUBLIC_KEYS,
  BASE_FORBIDDEN_PUBLIC_STRINGS,
  expectNoForbiddenPublicKeys,
  expectNoForbiddenPublicStrings,
  expectPublicResponseSafe,
  stablePublicContract,
};
