import { Prisma, UserRole } from "@prisma/client";

import type { CanonicalAssurance } from "../../../lib/canonicalDbContext";

export type SessionCredentialClient = Pick<Prisma.TransactionClient, "$queryRaw">;

const HASH = /^(?:[a-f0-9]{12}:)?[a-f0-9]{64}$/;
const PRINTABLE = /^[\x21-\x7e]+$/;
const REASON = /^[A-Z0-9_:-]+$/;
const refreshAssuranceLevels = new Set<CanonicalAssurance>(["password-verified", "mfa-verified"]);
const userRoles = new Set<string>(Object.values(UserRole));
const manufacturerRoles = new Set<UserRole>([
  UserRole.MANUFACTURER,
  UserRole.MANUFACTURER_ADMIN,
  UserRole.MANUFACTURER_USER,
]);
const tenantAdminRoles = new Set<UserRole>([UserRole.LICENSEE_ADMIN, UserRole.ORG_ADMIN]);

type FieldKind = "string" | "number" | "boolean" | "date" | "object";
type Projection = ReadonlyArray<readonly [string, FieldKind, boolean?]>;

const text = (value: unknown, label: string, maximum = 191) => {
  const normalized = String(value || "").trim();
  if (!normalized || normalized.length > maximum) {
    throw new Error(`B01 session credential boundary requires ${label}`);
  }
  return normalized;
};

const optionalText = (value: unknown, label: string, maximum = 191) =>
  value == null || value === "" ? null : text(value, label, maximum);

const timestamp = (value: unknown, label: string) => {
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
    throw new Error(`B01 session credential boundary requires ${label}`);
  }
  return value;
};

const optionalTimestamp = (value: unknown, label: string) =>
  value == null ? null : timestamp(value, label);

const tokenHash = (value: unknown) => {
  const normalized = text(value, "a token hash", 77).toLowerCase();
  if (!HASH.test(normalized)) throw new Error("B01 session credential boundary received a malformed token hash");
  return normalized;
};

const tokenHashes = (values: unknown) => {
  if (!Array.isArray(values) || values.length < 1 || values.length > 3) {
    throw new Error("B01 session credential boundary requires 1..3 token hashes");
  }
  const normalized = values.map(tokenHash);
  if (new Set(normalized).size !== normalized.length) {
    throw new Error("B01 session credential boundary requires unique token hashes");
  }
  return normalized;
};

const requestId = (value: unknown) => {
  const normalized = text(value, "a request ID", 128);
  if (!PRINTABLE.test(normalized)) throw new Error("B01 session credential boundary received a malformed request ID");
  return normalized;
};

const reason = (value: unknown) => {
  const normalized = text(value, "a revocation reason", 128);
  if (!REASON.test(normalized)) throw new Error("B01 session credential boundary received a malformed reason");
  return normalized;
};

const exact = <T extends Record<string, unknown>>(row: T, functionName: string, projection: Projection) => {
  const expected = projection.map(([key]) => key).sort();
  const actual = Object.keys(row).sort();
  if (expected.length !== actual.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error(`${functionName} returned an unexpected projection`);
  }
  for (const [key, kind, nullable] of projection) {
    const value = row[key];
    if (nullable && value == null) continue;
    const valid = kind === "date"
      ? value instanceof Date && Number.isFinite(value.getTime())
      : kind === "object"
        ? typeof value === "object" && value !== null
        : typeof value === kind;
    if (!valid) throw new Error(`${functionName} returned an invalid ${key}`);
  }
  return row;
};

const one = <T extends Record<string, unknown>>(rows: T[], functionName: string, projection: Projection) => {
  if (rows.length !== 1) throw new Error(`${functionName} returned an invalid row count`);
  return exact(rows[0], functionName, projection);
};

const oneOrNone = <T extends Record<string, unknown>>(rows: T[], functionName: string, projection: Projection) => {
  if (rows.length > 1) throw new Error(`${functionName} returned an invalid row count`);
  return rows[0] ? exact(rows[0], functionName, projection) : null;
};

const many = <T extends Record<string, unknown>>(
  rows: T[],
  functionName: string,
  projection: Projection,
  maximum: number
) => {
  if (rows.length > maximum) throw new Error(`${functionName} returned too many rows`);
  return rows.map((row) => exact(row, functionName, projection));
};

export type RefreshRotationClaim = {
  disposition: "ACTIVE" | "EXPIRED" | "REVOKED" | "REUSE_DETECTED";
  tokenId: string | null;
  userId: string | null;
  role: UserRole | null;
  organizationId: string | null;
  licenseeId: string | null;
  manufacturerId: string | null;
  authAssurance: CanonicalAssurance | null;
  expiresAt: Date | null;
  authenticatedAt: Date | null;
  mfaVerifiedAt: Date | null;
};

const rotationClaimProjection: Projection = [
  ["disposition", "string"], ["tokenId", "string", true], ["userId", "string", true],
  ["role", "string", true], ["organizationId", "string", true], ["licenseeId", "string", true],
  ["manufacturerId", "string", true], ["authAssurance", "string", true], ["expiresAt", "date", true],
  ["authenticatedAt", "date", true], ["mfaVerifiedAt", "date", true],
];

export const claimRefreshTokenRotation = async (
  db: SessionCredentialClient,
  input: { tokenHashCandidates: string[]; checkedAt: Date; requestId: string }
) => {
  const candidates = tokenHashes(input.tokenHashCandidates);
  const checkedAt = timestamp(input.checkedAt, "a checked-at timestamp");
  const validatedRequestId = requestId(input.requestId);
  const row = oneOrNone(await db.$queryRaw<RefreshRotationClaim[]>`
    SELECT * FROM app_auth.claim_refresh_token_rotation(
      ${candidates}::text[],
      ${checkedAt}::timestamp without time zone,
      ${validatedRequestId}
    )
  `, "app_auth.claim_refresh_token_rotation", rotationClaimProjection);
  if (!row) return null;
  if (!["ACTIVE", "EXPIRED", "REVOKED", "REUSE_DETECTED"].includes(row.disposition)) {
    throw new Error("app_auth.claim_refresh_token_rotation returned an unsupported disposition");
  }
  if (row.role && !userRoles.has(row.role)) {
    throw new Error("app_auth.claim_refresh_token_rotation returned an unsupported role");
  }
  if (row.authAssurance && !refreshAssuranceLevels.has(row.authAssurance)) {
    throw new Error("app_auth.claim_refresh_token_rotation returned an unsupported assurance");
  }
  if (row.disposition === "ACTIVE") {
    text(row.tokenId, "an active token ID");
    text(row.userId, "an active actor ID");
    text(row.role, "an active actor role", 64);
    timestamp(row.expiresAt, "an active token expiry");
    if (!row.authAssurance) throw new Error("app_auth.claim_refresh_token_rotation omitted active assurance");
  }
  return row;
};

export type RefreshLinkedLicensee = {
  id: string;
  name: string;
  prefix: string;
  brandName: string | null;
  orgId: string;
  isPrimary: boolean;
  scopeVersion: string;
};

export type RefreshSessionState = {
  userId: string;
  email: string;
  name: string;
  role: UserRole;
  legacyLicenseeId: string | null;
  legacyOrganizationId: string | null;
  emailVerifiedAt: Date | null;
  sessionLicenseeId: string | null;
  sessionOrganizationId: string | null;
  scopeVersion: string | null;
  selectedLicenseeId: string | null;
  selectedLicenseeName: string | null;
  selectedLicenseePrefix: string | null;
  selectedLicenseeBrandName: string | null;
  selectedLicenseeOrganizationId: string | null;
  linkedLicensees: RefreshLinkedLicensee[];
  mfaRequired: boolean;
  mfaEnabled: boolean;
  mfaEnrolled: boolean;
  mfaLastUsedAt: Date | null;
  mfaMethods: Array<"WEBAUTHN" | "TOTP" | "BACKUP_CODE">;
  mfaPreferredMethod: "WEBAUTHN" | "TOTP" | null;
};

const refreshStateProjection: Projection = [
  ["userId", "string"], ["email", "string"], ["name", "string"], ["role", "string"],
  ["legacyLicenseeId", "string", true], ["legacyOrganizationId", "string", true],
  ["emailVerifiedAt", "date", true], ["sessionLicenseeId", "string", true],
  ["sessionOrganizationId", "string", true], ["scopeVersion", "string", true],
  ["selectedLicenseeId", "string", true], ["selectedLicenseeName", "string", true],
  ["selectedLicenseePrefix", "string", true], ["selectedLicenseeBrandName", "string", true],
  ["selectedLicenseeOrganizationId", "string", true], ["linkedLicensees", "object"],
  ["mfaRequired", "boolean"], ["mfaEnabled", "boolean"], ["mfaEnrolled", "boolean"],
  ["mfaLastUsedAt", "date", true], ["mfaMethods", "object"], ["mfaPreferredMethod", "string", true],
];

const refreshLinkedLicensees = (value: unknown) => {
  if (!Array.isArray(value) || value.length > 100) {
    throw new Error("app_auth.load_refresh_session_state returned invalid linked licensees");
  }
  const expected = ["brandName", "id", "isPrimary", "name", "orgId", "prefix", "scopeVersion"];
  const rows = value.map((raw) => {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
      throw new Error("app_auth.load_refresh_session_state returned an invalid linked licensee");
    }
    const row = raw as Record<string, unknown>;
    const actual = Object.keys(row).sort();
    if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
      throw new Error("app_auth.load_refresh_session_state returned an unexpected linked-licensee projection");
    }
    if (typeof row.isPrimary !== "boolean") {
      throw new Error("app_auth.load_refresh_session_state returned an invalid linked-licensee primary flag");
    }
    return {
      id: text(row.id, "a linked licensee ID"),
      name: text(row.name, "a linked licensee name", 200),
      prefix: text(row.prefix, "a linked licensee prefix", 64),
      brandName: optionalText(row.brandName, "a linked licensee brand", 200),
      orgId: text(row.orgId, "a linked organization ID"),
      isPrimary: row.isPrimary,
      scopeVersion: text(row.scopeVersion, "a linked scope version", 64),
    };
  });
  if (new Set(rows.map((row) => row.id)).size !== rows.length) {
    throw new Error("app_auth.load_refresh_session_state returned duplicate linked licensees");
  }
  return rows;
};

const refreshMfaMethods = (value: unknown) => {
  if (!Array.isArray(value) || value.length > 3) {
    throw new Error("app_auth.load_refresh_session_state returned invalid MFA methods");
  }
  const allowed = new Set(["WEBAUTHN", "TOTP", "BACKUP_CODE"]);
  const methods = value.map((entry) => text(entry, "an MFA method", 32));
  if (new Set(methods).size !== methods.length || methods.some((method) => !allowed.has(method))) {
    throw new Error("app_auth.load_refresh_session_state returned unsupported MFA methods");
  }
  return methods as RefreshSessionState["mfaMethods"];
};

export const loadRefreshSessionState = async (
  db: SessionCredentialClient,
  input: {
    tokenId: string;
    tokenHashCandidates: string[];
    requestedLicenseeId: string | null;
    requestedScopeVersion: string | null;
    checkedAt: Date;
    requestId: string;
  }
) => {
  const row = one(await db.$queryRaw<RefreshSessionState[]>`
    SELECT * FROM app_auth.load_refresh_session_state(
      ${text(input.tokenId, "a claimed token ID")},
      ${tokenHashes(input.tokenHashCandidates)}::text[],
      ${optionalText(input.requestedLicenseeId, "a requested licensee ID")},
      ${optionalText(input.requestedScopeVersion, "a requested scope version", 64)},
      ${timestamp(input.checkedAt, "a checked-at timestamp")}::timestamp without time zone,
      ${requestId(input.requestId)}
    )
  `, "app_auth.load_refresh_session_state", refreshStateProjection);
  if (!userRoles.has(row.role)) throw new Error("app_auth.load_refresh_session_state returned an unsupported role");
  row.linkedLicensees = refreshLinkedLicensees(row.linkedLicensees);
  row.mfaMethods = refreshMfaMethods(row.mfaMethods);
  if (row.mfaPreferredMethod && !["WEBAUTHN", "TOTP"].includes(row.mfaPreferredMethod)) {
    throw new Error("app_auth.load_refresh_session_state returned an unsupported preferred MFA method");
  }
  const manufacturer = manufacturerRoles.has(row.role);
  const tenantAdmin = tenantAdminRoles.has(row.role);
  if (row.selectedLicenseeId) {
    const selectedName = text(row.selectedLicenseeName, "a selected licensee name", 200);
    const selectedPrefix = text(row.selectedLicenseePrefix, "a selected licensee prefix", 64);
    const selectedOrganizationId = text(row.selectedLicenseeOrganizationId, "a selected organization ID");
    if (row.sessionLicenseeId !== row.selectedLicenseeId || row.sessionOrganizationId !== selectedOrganizationId) {
      throw new Error("app_auth.load_refresh_session_state returned inconsistent selected scope");
    }
    if (manufacturer) {
      const selected = row.linkedLicensees.find((licensee) => licensee.id === row.selectedLicenseeId);
      if (
        !selected || !row.scopeVersion || selected.orgId !== selectedOrganizationId ||
        selected.scopeVersion !== row.scopeVersion || selected.name !== selectedName ||
        selected.prefix !== selectedPrefix || selected.brandName !== row.selectedLicenseeBrandName
      ) {
        throw new Error("app_auth.load_refresh_session_state returned inconsistent selected scope");
      }
    } else if (!tenantAdmin || row.scopeVersion || row.linkedLicensees.length) {
      throw new Error("app_auth.load_refresh_session_state returned unauthorized linked scope");
    }
  } else if (
    manufacturer || tenantAdmin || row.sessionLicenseeId || row.scopeVersion ||
    row.selectedLicenseeName || row.selectedLicenseePrefix || row.selectedLicenseeBrandName ||
    row.selectedLicenseeOrganizationId || row.linkedLicensees.length
  ) {
    throw new Error("app_auth.load_refresh_session_state returned partial selected scope");
  }
  return row;
};

export const createRefreshMfaChallengeRecord = async (
  db: SessionCredentialClient,
  input: {
    tokenId: string;
    tokenHashCandidates: string[];
    userId: string;
    ticketHash: string;
    sessionBindingHash: string;
    riskScore: number;
    riskLevel: string;
    reasons: string[];
    ipHash: string | null;
    userAgentHash: string | null;
    maxAttempts: number;
    expiresAt: Date;
    createdAt: Date;
    requestId: string;
  }
) => {
  if (!Number.isInteger(input.riskScore) || input.riskScore < 0 || input.riskScore > 100) {
    throw new Error("B01 refresh MFA challenge requires a bounded risk score");
  }
  const riskLevel = text(input.riskLevel, "an MFA risk level", 32);
  if (!["LOW", "MEDIUM", "HIGH", "CRITICAL"].includes(riskLevel)) {
    throw new Error("B01 refresh MFA challenge received an unsupported risk level");
  }
  if (!Array.isArray(input.reasons) || input.reasons.length < 1 || input.reasons.length > 12) {
    throw new Error("B01 refresh MFA challenge requires 1..12 reasons");
  }
  const reasons = input.reasons.map((entry) => text(entry, "an MFA reason", 500));
  if (!Number.isInteger(input.maxAttempts) || input.maxAttempts < 1 || input.maxAttempts > 10) {
    throw new Error("B01 refresh MFA challenge requires 1..10 attempts");
  }
  const createdAt = timestamp(input.createdAt, "a challenge creation timestamp");
  const expiresAt = timestamp(input.expiresAt, "a challenge expiry timestamp");
  if (expiresAt.getTime() <= createdAt.getTime()) throw new Error("B01 refresh MFA challenge expiry is invalid");
  return one(await db.$queryRaw<Array<{ challengeId: string; created: boolean }>>`
    SELECT * FROM app_auth.create_refresh_mfa_challenge(
      ${text(input.tokenId, "a claimed token ID")},
      ${tokenHashes(input.tokenHashCandidates)}::text[],
      ${text(input.userId, "an actor user ID")},
      ${tokenHash(input.ticketHash)},
      ${tokenHash(input.sessionBindingHash)},
      ${input.riskScore}::integer,
      ${riskLevel},
      ${reasons}::text[],
      ${optionalText(input.ipHash, "an IP hash", 77)},
      ${optionalText(input.userAgentHash, "a user-agent hash", 77)},
      ${input.maxAttempts}::integer,
      ${expiresAt}::timestamp without time zone,
      ${createdAt}::timestamp without time zone,
      ${requestId(input.requestId)}
    )
  `, "app_auth.create_refresh_mfa_challenge", [["challengeId", "string"], ["created", "boolean"]]);
};

export type RefreshSessionRecord = {
  id: string;
  userId: string;
  orgId: string | null;
  expiresAt: Date;
  createdAt: Date;
  createdIpHash: string | null;
  createdUserAgent: string | null;
  authenticatedAt: Date | null;
  mfaVerifiedAt: Date | null;
  lastUsedAt: Date | null;
  revokedAt: Date | null;
  revokedReason: string | null;
};

const sessionProjection: Projection = [
  ["id", "string"], ["userId", "string"], ["orgId", "string", true], ["expiresAt", "date"],
  ["createdAt", "date"], ["createdIpHash", "string", true], ["createdUserAgent", "string", true],
  ["authenticatedAt", "date", true], ["mfaVerifiedAt", "date", true], ["lastUsedAt", "date", true],
  ["revokedAt", "date", true], ["revokedReason", "string", true],
];

export const createRefreshTokenRecord = async (
  db: SessionCredentialClient,
  input: {
    userId: string;
    orgId: string | null;
    tokenHash: string;
    expiresAt: Date;
    ipHash: string | null;
    userAgent: string | null;
    authenticatedAt: Date;
    mfaVerifiedAt: Date | null;
    createdAt: Date;
  }
) => {
  const userId = text(input.userId, "a user ID");
  const orgId = optionalText(input.orgId, "an organization ID");
  const hash = tokenHash(input.tokenHash);
  const expiresAt = timestamp(input.expiresAt, "an expiry timestamp");
  const createdAt = timestamp(input.createdAt, "a creation timestamp");
  if (expiresAt.getTime() <= createdAt.getTime()) throw new Error("B01 refresh token expiry must follow creation");
  const ipHash = optionalText(input.ipHash, "an IP hash", 77);
  const userAgent = optionalText(input.userAgent, "a user agent", 300);
  const authenticatedAt = timestamp(input.authenticatedAt, "an authentication timestamp");
  const mfaVerifiedAt = optionalTimestamp(input.mfaVerifiedAt, "an MFA timestamp");
  return one(await db.$queryRaw<Array<{ id: string; expiresAt: Date }>>`
    SELECT * FROM app_rls.create_refresh_token(
      ${userId}, ${orgId}, ${hash}, ${expiresAt}::timestamp without time zone,
      ${ipHash}, ${userAgent}, ${authenticatedAt}::timestamp without time zone,
      ${mfaVerifiedAt}::timestamp without time zone, ${createdAt}::timestamp without time zone
    )
  `, "app_rls.create_refresh_token", [["id", "string"], ["expiresAt", "date"]]);
};

export const findRefreshTokenByHashes = async (
  db: SessionCredentialClient,
  input: { tokenHashCandidates: string[] }
) => {
  const candidates = tokenHashes(input.tokenHashCandidates);
  return oneOrNone(await db.$queryRaw<RefreshSessionRecord[]>`
    SELECT * FROM app_rls.find_refresh_token_by_hashes(${candidates}::text[])
  `, "app_rls.find_refresh_token_by_hashes", sessionProjection);
};

export const findRefreshTokenByIdentifier = async (
  db: SessionCredentialClient,
  input: { sessionId: string; userId: string }
) => oneOrNone(await db.$queryRaw<RefreshSessionRecord[]>`
  SELECT * FROM app_rls.find_refresh_token_by_id(
    ${text(input.sessionId, "a session ID")},
    ${text(input.userId, "a target user ID")}
  )
`, "app_rls.find_refresh_token_by_id", sessionProjection);

export const listActiveRefreshTokenRecords = async (
  db: SessionCredentialClient,
  input: { userId: string; checkedAt: Date }
) => {
  const userId = text(input.userId, "a target user ID");
  const checkedAt = timestamp(input.checkedAt, "a checked-at timestamp");
  return many(await db.$queryRaw<RefreshSessionRecord[]>`
    SELECT * FROM app_rls.list_active_refresh_tokens(
      ${userId}, ${checkedAt}::timestamp without time zone
    )
  `, "app_rls.list_active_refresh_tokens", sessionProjection, 200);
};

const revokedCountProjection: Projection = [["revokedCount", "number"]];

const checkedRevokedCount = (
  rows: Array<{ revokedCount: number }>,
  functionName: string,
  minimum = 0
) => {
  const result = one(rows, functionName, revokedCountProjection);
  if (!Number.isSafeInteger(result.revokedCount) || result.revokedCount < minimum) {
    throw new Error(`${functionName} returned an invalid revokedCount`);
  }
  return result;
};

export const revokeRefreshTokenByHashes = async (
  db: SessionCredentialClient,
  input: { tokenHashCandidates: string[]; reason: string; revokedAt: Date }
) => checkedRevokedCount(await db.$queryRaw<Array<{ revokedCount: number }>>`
  SELECT * FROM app_rls.revoke_refresh_token_by_hashes(
    ${tokenHashes(input.tokenHashCandidates)}::text[],
    ${reason(input.reason)},
    ${timestamp(input.revokedAt, "a revocation timestamp")}::timestamp without time zone
  )
`, "app_rls.revoke_refresh_token_by_hashes");

export const revokeAllRefreshTokenRecords = async (
  db: SessionCredentialClient,
  input: { userId: string; reason: string; revokedAt: Date }
) => checkedRevokedCount(await db.$queryRaw<Array<{ revokedCount: number }>>`
  SELECT * FROM app_rls.revoke_all_refresh_tokens(
    ${text(input.userId, "a target user ID")},
    ${reason(input.reason)},
    ${timestamp(input.revokedAt, "a revocation timestamp")}::timestamp without time zone
  )
`, "app_rls.revoke_all_refresh_tokens");

export const revokePasswordOnlyRefreshTokenRecords = async (
  db: SessionCredentialClient,
  input: { userId: string; reason: string; revokedAt: Date }
) => checkedRevokedCount(await db.$queryRaw<Array<{ revokedCount: number }>>`
  SELECT * FROM app_rls.revoke_password_only_refresh_tokens(
    ${text(input.userId, "a target user ID")},
    ${reason(input.reason)},
    ${timestamp(input.revokedAt, "a revocation timestamp")}::timestamp without time zone
  )
`, "app_rls.revoke_password_only_refresh_tokens");

export const revokeRefreshTokenByIdentifier = async (
  db: SessionCredentialClient,
  input: { sessionId: string; userId: string; reason: string; revokedAt: Date }
) => one(await db.$queryRaw<Array<{ revoked: boolean }>>`
  SELECT * FROM app_rls.revoke_refresh_token_by_id(
    ${text(input.sessionId, "a session ID")},
    ${text(input.userId, "a target user ID")},
    ${reason(input.reason)},
    ${timestamp(input.revokedAt, "a revocation timestamp")}::timestamp without time zone
  )
`, "app_rls.revoke_refresh_token_by_id", [["revoked", "boolean"]]);

export const revokeRefreshTokenRotationScope = async (
  db: SessionCredentialClient,
  input: {
    tokenId: string;
    tokenHashCandidates: string[];
    userId: string;
    scope: "token" | "password-only" | "all";
    reason: string;
    revokedAt: Date;
  }
) => {
  if (!["token", "password-only", "all"].includes(input.scope)) {
    throw new Error("B01 session credential boundary received an invalid revocation scope");
  }
  return checkedRevokedCount(await db.$queryRaw<Array<{ revokedCount: number }>>`
    SELECT * FROM app_auth.revoke_refresh_token_scope(
      ${text(input.tokenId, "a token ID")},
      ${tokenHashes(input.tokenHashCandidates)}::text[],
      ${text(input.userId, "a target user ID")},
      ${input.scope},
      ${reason(input.reason)},
      ${timestamp(input.revokedAt, "a revocation timestamp")}::timestamp without time zone
    )
  `, "app_auth.revoke_refresh_token_scope", 1);
};

export const completeRefreshTokenRotation = async (
  db: SessionCredentialClient,
  input: {
    tokenId: string;
    tokenHashCandidates: string[];
    userId: string;
    orgId: string | null;
    tokenHash: string;
    expiresAt: Date;
    ipHash: string | null;
    userAgent: string | null;
    authenticatedAt: Date;
    mfaVerifiedAt: Date | null;
    rotatedAt: Date;
  }
) => {
  const rotatedAt = timestamp(input.rotatedAt, "a rotation timestamp");
  const expiresAt = timestamp(input.expiresAt, "a successor expiry");
  if (expiresAt.getTime() <= rotatedAt.getTime()) throw new Error("B01 successor expiry must follow rotation");
  return one(await db.$queryRaw<Array<{ id: string; expiresAt: Date }>>`
    SELECT * FROM app_auth.complete_refresh_token_rotation(
      ${text(input.tokenId, "a token ID")},
      ${tokenHashes(input.tokenHashCandidates)}::text[],
      ${text(input.userId, "a target user ID")},
      ${optionalText(input.orgId, "an organization ID")},
      ${tokenHash(input.tokenHash)},
      ${expiresAt}::timestamp without time zone,
      ${optionalText(input.ipHash, "an IP hash", 77)},
      ${optionalText(input.userAgent, "a user agent", 300)},
      ${timestamp(input.authenticatedAt, "an authentication timestamp")}::timestamp without time zone,
      ${optionalTimestamp(input.mfaVerifiedAt, "an MFA timestamp")}::timestamp without time zone,
      ${rotatedAt}::timestamp without time zone
    )
  `, "app_auth.complete_refresh_token_rotation", [["id", "string"], ["expiresAt", "date"]]);
};
