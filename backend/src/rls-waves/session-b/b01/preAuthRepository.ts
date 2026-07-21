import { Prisma, UserRole, UserStatus } from "@prisma/client";

import { getB01PreAuthPrisma } from "./runtimeClients";

type PreAuthQueryClient = Pick<Prisma.TransactionClient, "$queryRaw">;
const HASH_PATTERN = /^(?:[a-f0-9]{12}:)?[a-f0-9]{64}$/;
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const oneOrNone = <T>(rows: T[], boundary: string) => {
  if (rows.length > 1) throw new Error(`${boundary} returned an invalid row count`);
  return rows[0] || null;
};

const requireNormalizedEmail = (value: string) => {
  const email = String(value || "");
  if (email.length < 3 || email.length > 320 || email !== email.trim().toLowerCase() || !EMAIL_PATTERN.test(email)) {
    throw new Error("Pre-auth boundary requires a normalized email");
  }
  return email;
};

const tokenHash = (value: string, field = "token hash") => {
  const hash = String(value || "");
  if (!HASH_PATTERN.test(hash)) throw new Error(`Pre-auth boundary requires a fixed-format ${field}`);
  return hash;
};

const optionalHash = (value: string | null, field: string) => value == null ? null : tokenHash(value, field);

const tokenHashCandidates = (values: string[]) => {
  if (!Array.isArray(values) || values.length < 1 || values.length > 3) {
    throw new Error("Pre-auth boundary requires 1..3 token hash candidates");
  }
  const hashes = values.map((value) => tokenHash(value));
  if (new Set(hashes).size !== hashes.length) throw new Error("Pre-auth token hash candidates must be unique");
  return hashes;
};

const validDate = (value: Date, field: string) => {
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
    throw new Error(`Pre-auth boundary requires ${field}`);
  }
  return value;
};

const approvedPasswordHash = (value: string) => {
  const hash = String(value || "");
  if (hash.length > 512 || !hash.startsWith("$argon2id$")) {
    throw new Error("Pre-auth boundary requires an approved password hash");
  }
  return hash;
};

export type PasswordBootstrapUser = {
  id: string;
  email: string;
  passwordHash: string | null;
  name: string;
  role: UserRole;
  licenseeId: string | null;
  orgId: string | null;
  status: UserStatus;
  isActive: boolean;
  disabledAt: Date | null;
  deletedAt: Date | null;
  failedLoginAttempts: number;
  lockedUntil: Date | null;
  lastLoginAt: Date | null;
  emailVerifiedAt: Date | null;
};

export const lookupPasswordBootstrapUser = async (
  normalizedEmail: string,
  db: PreAuthQueryClient = getB01PreAuthPrisma()
) => {
  const email = requireNormalizedEmail(normalizedEmail);
  const rows = await db.$queryRaw<PasswordBootstrapUser[]>`
    SELECT * FROM app_auth.lookup_password_user(${email})
  `;
  return oneOrNone(rows, "app_auth.lookup_password_user");
};

export const recordPasswordLoginFailure = async (
  input: {
    normalizedEmail: string;
    attemptedAt: Date;
    maxAttempts: number;
    lockoutMinutes: number;
  },
  db: PreAuthQueryClient = getB01PreAuthPrisma()
) => {
  const email = requireNormalizedEmail(input.normalizedEmail);
  const attemptedAt = validDate(input.attemptedAt, "attempted_at");
  if (!Number.isInteger(input.maxAttempts) || input.maxAttempts < 1 || input.maxAttempts > 100) {
    throw new Error("Pre-auth boundary requires max_attempts in 1..100");
  }
  if (!Number.isInteger(input.lockoutMinutes) || input.lockoutMinutes < 1 || input.lockoutMinutes > 1440) {
    throw new Error("Pre-auth boundary requires lockout_minutes in 1..1440");
  }
  const rows = await db.$queryRaw<Array<{ failedLoginAttempts: number; lockedUntil: Date | null }>>`
    SELECT * FROM app_auth.record_password_failure(
      ${email},
      ${attemptedAt}::timestamp without time zone,
      ${input.maxAttempts}::integer,
      ${input.lockoutMinutes}::integer
    )
  `;
  return oneOrNone(rows, "app_auth.record_password_failure");
};

export const requestPasswordResetBoundary = async (
  input: {
    normalizedEmail: string;
    tokenHash: string;
    expiresAt: Date;
    requestedAt: Date;
    ipHash: string | null;
    userAgentHash: string | null;
  },
  db: PreAuthQueryClient = getB01PreAuthPrisma()
) => {
  const email = requireNormalizedEmail(input.normalizedEmail);
  const resetTokenHash = tokenHash(input.tokenHash);
  const requestedAt = validDate(input.requestedAt, "requested_at");
  const expiresAt = validDate(input.expiresAt, "expires_at");
  const lifetimeMs = expiresAt.getTime() - requestedAt.getTime();
  if (lifetimeMs <= 0 || lifetimeMs > 1440 * 60_000) {
    throw new Error("Pre-auth password-reset expiry is outside the reviewed ceiling");
  }
  const rows = await db.$queryRaw<Array<{
    accepted: boolean;
    deliveryRequired: boolean;
    userId: string | null;
    email: string | null;
    licenseeId: string | null;
    orgId: string | null;
    expiresAt: Date | null;
  }>>`
    SELECT * FROM app_auth.request_password_reset(
      ${email},
      ${resetTokenHash},
      ${expiresAt}::timestamp without time zone,
      ${requestedAt}::timestamp without time zone,
      ${optionalHash(input.ipHash, "IP hash")},
      ${optionalHash(input.userAgentHash, "user-agent hash")}
    )
  `;
  return oneOrNone(rows, "app_auth.request_password_reset");
};

export const consumePasswordResetBoundary = async (
  input: { tokenHashCandidates: string[]; passwordHash: string; consumedAt: Date },
  db: PreAuthQueryClient = getB01PreAuthPrisma()
) => {
  const candidates = tokenHashCandidates(input.tokenHashCandidates);
  const passwordHash = approvedPasswordHash(input.passwordHash);
  const consumedAt = validDate(input.consumedAt, "consumed_at");
  const rows = await db.$queryRaw<Array<{
    id: string;
    email: string;
    name: string;
    role: UserRole;
    licenseeId: string | null;
    orgId: string | null;
  }>>`
    SELECT * FROM app_auth.consume_password_reset_token(
      ${candidates}::text[],
      ${passwordHash},
      ${consumedAt}::timestamp without time zone
    )
  `;
  return oneOrNone(rows, "app_auth.consume_password_reset_token");
};

export const consumeEmailVerificationBoundary = async (
  input: { tokenHashCandidates: string[]; consumedAt: Date },
  db: PreAuthQueryClient = getB01PreAuthPrisma()
) => {
  const candidates = tokenHashCandidates(input.tokenHashCandidates);
  const consumedAt = validDate(input.consumedAt, "consumed_at");
  const rows = await db.$queryRaw<Array<{
    verified: boolean;
    purpose: string;
    userId: string;
    email: string;
  }>>`
    SELECT * FROM app_auth.consume_email_verification_token(
      ${candidates}::text[],
      ${consumedAt}::timestamp without time zone
    )
  `;
  return oneOrNone(rows, "app_auth.consume_email_verification_token");
};

export const lookupInvitationBoundary = async (
  input: { tokenHashCandidates: string[]; checkedAt: Date },
  db: PreAuthQueryClient = getB01PreAuthPrisma()
) => {
  const candidates = tokenHashCandidates(input.tokenHashCandidates);
  const checkedAt = validDate(input.checkedAt, "checked_at");
  const rows = await db.$queryRaw<Array<{
    email: string;
    role: UserRole;
    expiresAt: Date;
    licenseeName: string | null;
    requiresConnector: boolean;
  }>>`
    SELECT * FROM app_auth.lookup_invitation_token(
      ${candidates}::text[],
      ${checkedAt}::timestamp without time zone
    )
  `;
  return oneOrNone(rows, "app_auth.lookup_invitation_token");
};

export const consumeInvitationBoundary = async (
  input: {
    tokenHashCandidates: string[];
    passwordHash: string;
    requestedName: string | null;
    consumedAt: Date;
  },
  db: PreAuthQueryClient = getB01PreAuthPrisma()
) => {
  const candidates = tokenHashCandidates(input.tokenHashCandidates);
  const passwordHash = approvedPasswordHash(input.passwordHash);
  const requestedName = input.requestedName == null ? null : String(input.requestedName).trim();
  if (requestedName && requestedName.length > 80) throw new Error("Pre-auth invite name exceeds the product limit");
  const consumedAt = validDate(input.consumedAt, "consumed_at");
  const rows = await db.$queryRaw<Array<{
    inviteId: string;
    id: string;
    email: string;
    name: string;
    role: UserRole;
    licenseeId: string | null;
    orgId: string | null;
    status: UserStatus;
  }>>`
    SELECT * FROM app_auth.consume_invitation_token(
      ${candidates}::text[],
      ${passwordHash},
      ${requestedName},
      ${consumedAt}::timestamp without time zone
    )
  `;
  const result = oneOrNone(rows, "app_auth.consume_invitation_token");
  if (result && !String(result.inviteId || "").trim()) {
    throw new Error("app_auth.consume_invitation_token omitted required inviteId attribution");
  }
  return result;
};
