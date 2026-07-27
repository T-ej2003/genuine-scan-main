import { Prisma } from "@prisma/client";

type QueryClient = Pick<Prisma.TransactionClient, "$queryRaw">;

const scalar = async <T>(query: Promise<Array<{ result: T }>>, name: string) => {
  const rows = await query;
  if (rows.length !== 1 || rows[0]?.result == null) throw new Error(`${name} returned an invalid result`);
  return rows[0].result;
};

export const loadAdminMfaState = (db: QueryClient) =>
  scalar(db.$queryRaw<Array<{ result: Record<string, unknown> }>>`
    SELECT app_rls.load_admin_mfa_state() AS result
  `, "app_rls.load_admin_mfa_state");

export const beginAdminTotpEnrollment = (
  db: QueryClient,
  input: {
    mode: string;
    secretCiphertext: string;
    secretIv: string;
    secretTag: string;
    backupHashes: string[];
    pendingCutoff: Date;
    createdAt: Date;
  }
) => scalar(db.$queryRaw<Array<{ result: { factorId: string } }>>`
  SELECT app_rls.begin_admin_totp_enrollment(
    ${input.mode},${input.secretCiphertext},${input.secretIv},${input.secretTag},
    ${input.backupHashes}::text[],${input.pendingCutoff}::timestamp without time zone,
    ${input.createdAt}::timestamp without time zone
  ) AS result
`, "app_rls.begin_admin_totp_enrollment");

export const loadAdminTotpEnrollment = (db: QueryClient, input: { mode: string; pendingCutoff: Date }) =>
  scalar(db.$queryRaw<Array<{ result: Record<string, unknown> }>>`
    SELECT app_rls.load_admin_totp_enrollment(
      ${input.mode},${input.pendingCutoff}::timestamp without time zone
    ) AS result
  `, "app_rls.load_admin_totp_enrollment");

export const completeAdminTotpEnrollment = (
  db: QueryClient,
  input: {
    mode: string;
    factorId: string;
    secretCiphertext: string;
    secretIv: string;
    secretTag: string;
    completedAt: Date;
    ipHash: string | null;
    userAgent: string | null;
  }
) => scalar(db.$queryRaw<Array<{ result: { enabled: true } }>>`
  SELECT app_rls.complete_admin_totp_enrollment(
    ${input.mode},${input.factorId},${input.secretCiphertext},${input.secretIv},${input.secretTag},
    ${input.completedAt}::timestamp without time zone,${input.ipHash},${input.userAgent}
  ) AS result
`, "app_rls.complete_admin_totp_enrollment");

export const loadAdminMfaVerifiers = (db: QueryClient) =>
  scalar(db.$queryRaw<Array<{ result: Record<string, unknown> }>>`
    SELECT app_rls.load_admin_mfa_verifiers() AS result
  `, "app_rls.load_admin_mfa_verifiers");

export const consumeAdminMfaVerifier = (
  db: QueryClient,
  input: {
    method: "TOTP_FACTOR" | "TOTP_LEGACY" | "BACKUP_CODE" | "BACKUP_LEGACY";
    recordId?: string | null;
    expectedLegacyHashes?: string[];
    nextLegacyHashes?: string[];
    usedAt: Date;
  }
) => scalar(db.$queryRaw<Array<{ result: { consumed: boolean } }>>`
  SELECT app_rls.consume_admin_mfa_verifier(
    ${input.method},${input.recordId || null},${input.expectedLegacyHashes || []}::text[],
    ${input.nextLegacyHashes || []}::text[],${input.usedAt}::timestamp without time zone
  ) AS result
`, "app_rls.consume_admin_mfa_verifier");

export const replaceAdminBackupCodes = (db: QueryClient, hashes: string[], replacedAt: Date) =>
  scalar(db.$queryRaw<Array<{ result: { replaced: boolean } }>>`
    SELECT app_rls.replace_admin_backup_codes(
      ${hashes}::text[],${replacedAt}::timestamp without time zone
    ) AS result
  `, "app_rls.replace_admin_backup_codes");

export const disableAdminMfaBoundary = (
  db: QueryClient,
  input: { disabledAt: Date; ipHash: string | null; userAgent: string | null }
) => scalar(db.$queryRaw<Array<{ result: { enabled: false } }>>`
  SELECT app_rls.disable_admin_mfa(
    ${input.disabledAt}::timestamp without time zone,${input.ipHash},${input.userAgent}
  ) AS result
`, "app_rls.disable_admin_mfa");

export const createAdminMfaChallengeBoundary = (
  db: QueryClient,
  input: {
    kind: "LOGIN" | "SESSION";
    ticketHash: string;
    sessionBindingHash: string | null;
    purpose: string;
    riskScore: number;
    riskLevel: string;
    reasons: string[];
    ipHash: string | null;
    userAgentHash: string | null;
    maxAttempts: number;
    createdAt: Date;
    expiresAt: Date;
  }
) => scalar(db.$queryRaw<Array<{ result: { challengeId: string } }>>`
  SELECT app_rls.create_admin_mfa_challenge(
    ${input.kind},${input.ticketHash},${input.sessionBindingHash},${input.purpose},
    ${input.riskScore}::integer,${input.riskLevel},${input.reasons}::text[],${input.ipHash},
    ${input.userAgentHash},${input.maxAttempts}::integer,
    ${input.createdAt}::timestamp without time zone,${input.expiresAt}::timestamp without time zone
  ) AS result
`, "app_rls.create_admin_mfa_challenge");

export type AdminMfaChallengeRecord = {
  kind: "LOGIN" | "SESSION";
  id: string;
  userId: string;
  purpose: string;
  riskScore: number;
  riskLevel: string;
  reasons: string[];
  attempts: number;
  maxAttempts: number;
  createdIpHash: string | null;
  createdUserAgentHash: string | null;
  expiresAt: string;
  consumedAt: string | null;
  supersededAt: string | null;
};

export const loadAdminMfaChallengeBoundary = async (
  db: QueryClient,
  input: { ticketHashes: string[]; sessionBindingHashes: string[]; checkedAt: Date }
) => {
  const rows = await db.$queryRaw<Array<{ result: AdminMfaChallengeRecord | null }>>`
  SELECT app_rls.load_admin_mfa_challenge(
    ${input.ticketHashes}::text[],${input.sessionBindingHashes}::text[],
    ${input.checkedAt}::timestamp without time zone
  ) AS result
  `;
  if (rows.length !== 1) throw new Error("app_rls.load_admin_mfa_challenge returned an invalid result");
  return rows[0].result;
};

export const recordAdminMfaChallengeFailure = (
  db: QueryClient,
  input: {
    kind: "LOGIN" | "SESSION";
    challengeId: string;
    action: "AUTH_MFA_CHALLENGE_EXPIRED" | "AUTH_MFA_FAILURE" | "AUTH_MFA_TOO_MANY_ATTEMPTS";
    attempts: number;
    failedAt: Date;
    ipHash: string | null;
    userAgent: string | null;
  }
) => scalar(db.$queryRaw<Array<{ result: { recorded: boolean; attempts: number } }>>`
  SELECT app_rls.record_admin_mfa_challenge_failure(
    ${input.kind},${input.challengeId},${input.action},${input.attempts}::integer,
    ${input.failedAt}::timestamp without time zone,${input.ipHash},${input.userAgent}
  ) AS result
`, "app_rls.record_admin_mfa_challenge_failure");

export const completeAdminMfaChallengeBoundary = (
  db: QueryClient,
  input: {
    kind: "LOGIN" | "SESSION";
    challengeId: string;
    method: "TOTP" | "BACKUP_CODE";
    completedAt: Date;
    ipHash: string | null;
    userAgent: string | null;
  }
) => scalar(db.$queryRaw<Array<{ result: { completed: boolean } }>>`
  SELECT app_rls.complete_admin_mfa_challenge(
    ${input.kind},${input.challengeId},${input.method},
    ${input.completedAt}::timestamp without time zone,${input.ipHash},${input.userAgent}
  ) AS result
`, "app_rls.complete_admin_mfa_challenge");

export const loadAdminWebAuthnCredentials = (db: QueryClient) =>
  scalar(db.$queryRaw<Array<{ result: { factors: any[]; legacy: any[] } }>>`
    SELECT app_rls.load_admin_webauthn_credentials() AS result
  `, "app_rls.load_admin_webauthn_credentials");

export const createAdminWebAuthnChallengeBoundary = (
  db: QueryClient,
  input: {
    purpose: "ENROLLMENT" | "LOGIN" | "STEP_UP";
    ticketHash: string;
    challengeHash: string;
    ipHash: string | null;
    userAgentHash: string | null;
    origin: string | null;
    rpId: string;
    createdAt: Date;
    expiresAt: Date;
  }
) => scalar(db.$queryRaw<Array<{ result: { challengeId: string; credentialIds: string[] } }>>`
  SELECT app_rls.create_admin_webauthn_challenge(
    ${input.purpose},${input.ticketHash},${input.challengeHash},${input.ipHash},${input.userAgentHash},
    ${input.origin},${input.rpId},${input.createdAt}::timestamp without time zone,
    ${input.expiresAt}::timestamp without time zone
  ) AS result
`, "app_rls.create_admin_webauthn_challenge");

export const loadAdminWebAuthnChallengeBoundary = async (
  db: QueryClient,
  input: {
    ticketHashes: string[];
    purpose: "ENROLLMENT" | "LOGIN" | "STEP_UP";
    credentialId: string | null;
    checkedAt: Date;
  }
) => {
  const rows = await db.$queryRaw<Array<{ result: { challenge: any; factor: any; legacy: any } | null }>>`
    SELECT app_rls.load_admin_webauthn_challenge(
      ${input.ticketHashes}::text[],${input.purpose},${input.credentialId},
      ${input.checkedAt}::timestamp without time zone
    ) AS result
  `;
  if (rows.length !== 1) throw new Error("app_rls.load_admin_webauthn_challenge returned an invalid result");
  return rows[0].result;
};

export const completeAdminWebAuthnRegistrationBoundary = (
  db: QueryClient,
  input: {
    challengeId: string;
    credentialId: string;
    label: string;
    publicKey: string;
    counter: number;
    transports: string[];
    deviceType: string | null;
    backedUp: boolean | null;
    completedAt: Date;
  }
) => scalar(db.$queryRaw<Array<{ result: { ok: true; credentialId: string } }>>`
  SELECT app_rls.complete_admin_webauthn_registration(
    ${input.challengeId},${input.credentialId},${input.label},${input.publicKey},${input.counter}::integer,
    ${input.transports}::text[],${input.deviceType},${input.backedUp},
    ${input.completedAt}::timestamp without time zone
  ) AS result
`, "app_rls.complete_admin_webauthn_registration");

export const completeAdminWebAuthnAuthenticationBoundary = (
  db: QueryClient,
  input: {
    challengeId: string;
    credentialKind: "FACTOR" | "LEGACY";
    credentialRowId: string;
    expectedCounter: number;
    nextCounter: number;
    deviceType: string | null;
    backedUp: boolean | null;
    completedAt: Date;
  }
) => scalar(db.$queryRaw<Array<{ result: { ok: true; purpose: string } }>>`
  SELECT app_rls.complete_admin_webauthn_authentication(
    ${input.challengeId},${input.credentialKind},${input.credentialRowId},${input.expectedCounter}::integer,
    ${input.nextCounter}::integer,${input.deviceType},${input.backedUp},
    ${input.completedAt}::timestamp without time zone
  ) AS result
`, "app_rls.complete_admin_webauthn_authentication");

export const deleteAdminWebAuthnCredentialBoundary = (db: QueryClient, credentialRowId: string, deletedAt: Date) =>
  scalar(db.$queryRaw<Array<{ result: { deleted: boolean } }>>`
    SELECT app_rls.delete_admin_webauthn_credential(
      ${credentialRowId},${deletedAt}::timestamp without time zone
    ) AS result
  `, "app_rls.delete_admin_webauthn_credential");
