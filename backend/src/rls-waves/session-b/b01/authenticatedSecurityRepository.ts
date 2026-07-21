import { Prisma, UserRole, UserStatus } from "@prisma/client";

type AuthQueryClient = Pick<Prisma.TransactionClient, "$queryRaw">;

const one = <T>(rows: T[], boundary: string) => {
  if (rows.length !== 1) throw new Error(`${boundary} returned an invalid row count`);
  return rows[0];
};

export type AuthenticatedActorRecord = {
  id: string;
  email: string;
  name: string;
  role: UserRole;
  licenseeId: string | null;
  orgId: string | null;
  emailVerifiedAt: Date | null;
  pendingEmail: string | null;
  pendingEmailRequestedAt: Date | null;
  isActive: boolean;
  status: UserStatus;
  deletedAt: Date | null;
  disabledAt: Date | null;
  createdAt: Date;
  licenseeRecordId: string | null;
  licenseeName: string | null;
  licenseePrefix: string | null;
  licenseeBrandName: string | null;
  licenseeOrgId: string | null;
};

export const loadAuthenticatedActor = async (db: AuthQueryClient) => {
  const rows = await db.$queryRaw<AuthenticatedActorRecord[]>`
    SELECT * FROM app_rls.load_authenticated_actor()
  `;
  return one(rows, "app_rls.load_authenticated_actor");
};

export const loadAuthenticatedPasswordActor = async (db: AuthQueryClient) => {
  const rows = await db.$queryRaw<Array<{
    id: string;
    passwordHash: string | null;
    role: UserRole;
    status: UserStatus;
    isActive: boolean;
    disabledAt: Date | null;
    deletedAt: Date | null;
  }>>`
    SELECT * FROM app_rls.load_authenticated_password_actor()
  `;
  return one(rows, "app_rls.load_authenticated_password_actor");
};

export const requireRecentMfaSession = async (
  input: { sessionId: string; checkedAt: Date; maxAgeMinutes: number },
  db: AuthQueryClient
) => {
  if (!String(input.sessionId || "").trim()) throw new Error("Recent MFA validation requires a session ID");
  if (!Number.isInteger(input.maxAgeMinutes) || input.maxAgeMinutes < 1 || input.maxAgeMinutes > 1440) {
    throw new Error("Recent MFA validation received an invalid maximum age");
  }
  const rows = await db.$queryRaw<Array<{ verifiedAt: Date }>>`
    SELECT * FROM app_rls.require_recent_mfa_session(
      ${input.sessionId},
      ${input.checkedAt}::timestamp without time zone,
      ${input.maxAgeMinutes}::integer
    )
  `;
  return one(rows, "app_rls.require_recent_mfa_session");
};

export const loadRecentAuthSessionRiskInputs = async (db: AuthQueryClient) => {
  const rows = await db.$queryRaw<Array<{
    createdIpHash: string | null;
    createdUserAgent: string | null;
    createdAt: Date;
  }>>`
    SELECT * FROM app_rls.load_recent_auth_session_risk_inputs(5::integer)
  `;
  if (rows.length > 5) throw new Error("app_rls.load_recent_auth_session_risk_inputs returned too many rows");
  return rows;
};

export const recordAuthSessionRiskSignal = async (
  input: {
    riskScore: number;
    riskLevel: string;
    reasons: string[];
    ipHash: string | null;
    userAgentHash: string | null;
    recordedAt: Date;
  },
  db: AuthQueryClient
) => {
  if (!Number.isInteger(input.riskScore) || input.riskScore < 0 || input.riskScore > 100) {
    throw new Error("Invalid auth-session risk score");
  }
  if (input.reasons.length > 12) throw new Error("Too many auth-session risk reasons");
  const rows = await db.$queryRaw<Array<{ recorded: boolean }>>`
    SELECT * FROM app_rls.record_auth_session_risk_signal(
      ${input.riskScore}::integer,
      ${input.riskLevel},
      ${input.reasons}::text[],
      ${input.ipHash},
      ${input.userAgentHash},
      ${input.recordedAt}::timestamp without time zone
    )
  `;
  const result = one(rows, "app_rls.record_auth_session_risk_signal");
  if (!result.recorded) throw new Error("Auth-session risk signal was not recorded");
};

export const updateAuthenticatedProfile = async (
  input: { name: string | null; emailChangeRequested: boolean; auditPendingEmail: string | null; changedAt: Date },
  db: AuthQueryClient
) => {
  const name = input.name == null ? null : String(input.name).trim();
  if (name != null && (name.length < 2 || name.length > 80)) throw new Error("Invalid profile name");
  const rows = await db.$queryRaw<AuthenticatedActorRecord[]>`
    SELECT * FROM app_rls.update_authenticated_profile(
      ${name},
      ${input.emailChangeRequested},
      ${input.auditPendingEmail},
      ${input.changedAt}::timestamp without time zone
    )
  `;
  return one(rows, "app_rls.update_authenticated_profile");
};

export const prepareAuthenticatedEmailChange = async (
  input: {
    nextEmail: string;
    tokenHash: string;
    secretVersion: string;
    expiresAt: Date;
    requestedAt: Date;
    ipHash: string | null;
    userAgentHash: string | null;
  },
  db: AuthQueryClient
) => {
  const rows = await db.$queryRaw<Array<{
    changed: boolean;
    verificationRequired: boolean;
    userId: string;
    currentEmail: string;
    pendingEmail: string | null;
    orgId: string | null;
    licenseeId: string | null;
    expiresAt: Date | null;
  }>>`
    SELECT * FROM app_rls.request_authenticated_email_change(
      ${input.nextEmail},
      ${input.tokenHash},
      ${input.secretVersion},
      ${input.expiresAt}::timestamp without time zone,
      ${input.requestedAt}::timestamp without time zone,
      ${input.ipHash},
      ${input.userAgentHash}
    )
  `;
  return one(rows, "app_rls.request_authenticated_email_change");
};

export const proveAuthenticatedPasswordStepUp = async (
  input: { sessionId: string; expectedPasswordHash: string; verifiedAt: Date },
  db: AuthQueryClient
) => {
  const rows = await db.$queryRaw<Array<{ authorized: boolean }>>`
    SELECT * FROM app_rls.prove_authenticated_password_step_up(
      ${input.sessionId},
      ${input.expectedPasswordHash},
      ${input.verifiedAt}::timestamp without time zone
    )
  `;
  const result = one(rows, "app_rls.prove_authenticated_password_step_up");
  if (!result.authorized) throw new Error("PASSWORD_CHANGE_CONFLICT");
};

export const requireRecentSensitiveSession = async (
  input: { sessionId: string; checkedAt: Date; maxPasswordAgeMinutes: number; maxMfaAgeMinutes: number },
  db: AuthQueryClient
) => {
  const rows = await db.$queryRaw<Array<{ authorized: boolean }>>`
    SELECT * FROM app_rls.require_recent_sensitive_session(
      ${input.sessionId},
      ${input.checkedAt}::timestamp without time zone,
      ${input.maxPasswordAgeMinutes}::integer,
      ${input.maxMfaAgeMinutes}::integer
    )
  `;
  const result = one(rows, "app_rls.require_recent_sensitive_session");
  if (!result.authorized) throw new Error("STEP_UP_REQUIRED");
};

export const changeAuthenticatedPassword = async (
  input: { expectedPasswordHash: string; passwordHash: string; changedAt: Date },
  db: AuthQueryClient
) => {
  const rows = await db.$queryRaw<Array<{ changed: boolean }>>`
    SELECT * FROM app_rls.change_authenticated_password(
      ${input.expectedPasswordHash},
      ${input.passwordHash},
      ${input.changedAt}::timestamp without time zone
    )
  `;
  const result = one(rows, "app_rls.change_authenticated_password");
  if (!result.changed) throw new Error("PASSWORD_CHANGE_CONFLICT");
  return result;
};
