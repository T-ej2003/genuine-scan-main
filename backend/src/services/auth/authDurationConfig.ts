const ADMIN_MFA_CHALLENGE_TTL_ENV = "AUTH_MFA_CHALLENGE_TTL_MINUTES";
const DEFAULT_ADMIN_MFA_CHALLENGE_TTL_MINUTES = 5;
const MIN_ADMIN_MFA_CHALLENGE_TTL_MS = 60_000;

export type AuthDurationSource = "default" | "env" | "safe_default" | "runtime_guard_default";

export type AuthDurationConfig = {
  envKey: string;
  minutes: number;
  ttlMs: number;
  defaultMinutes: number;
  minTtlMs: number;
  envRawPresent: boolean;
  source: AuthDurationSource;
};

export class AuthDurationConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AuthDurationConfigError";
  }
}

const isProduction = () => process.env.NODE_ENV === "production";

const defaultAdminMfaChallengeTtl = (source: AuthDurationSource, envRawPresent: boolean): AuthDurationConfig => ({
  envKey: ADMIN_MFA_CHALLENGE_TTL_ENV,
  minutes: DEFAULT_ADMIN_MFA_CHALLENGE_TTL_MINUTES,
  ttlMs: DEFAULT_ADMIN_MFA_CHALLENGE_TTL_MINUTES * 60_000,
  defaultMinutes: DEFAULT_ADMIN_MFA_CHALLENGE_TTL_MINUTES,
  minTtlMs: MIN_ADMIN_MFA_CHALLENGE_TTL_MS,
  envRawPresent,
  source,
});

export const getAdminMfaChallengeTtlConfig = (): AuthDurationConfig => {
  const raw = process.env[ADMIN_MFA_CHALLENGE_TTL_ENV];
  const envRawPresent = raw !== undefined;
  const value = String(raw ?? "").trim();

  if (!value) return defaultAdminMfaChallengeTtl("default", envRawPresent);

  if (/^[1-9]\d*$/.test(value)) {
    const minutes = Number(value);
    if (Number.isSafeInteger(minutes) && minutes >= 1) {
      return {
        envKey: ADMIN_MFA_CHALLENGE_TTL_ENV,
        minutes,
        ttlMs: minutes * 60_000,
        defaultMinutes: DEFAULT_ADMIN_MFA_CHALLENGE_TTL_MINUTES,
        minTtlMs: MIN_ADMIN_MFA_CHALLENGE_TTL_MS,
        envRawPresent,
        source: "env",
      };
    }
  }

  if (isProduction()) {
    throw new AuthDurationConfigError(`${ADMIN_MFA_CHALLENGE_TTL_ENV} must be an integer number of minutes greater than or equal to 1`);
  }

  return defaultAdminMfaChallengeTtl("safe_default", envRawPresent);
};

export const buildAdminMfaChallengeExpiry = (now: Date) => {
  const config = getAdminMfaChallengeTtlConfig();
  const expiresAt = new Date(now.getTime() + config.ttlMs);
  const validityMs = expiresAt.getTime() - now.getTime();

  if (validityMs >= MIN_ADMIN_MFA_CHALLENGE_TTL_MS) {
    return { expiresAt, config };
  }

  if (isProduction()) {
    throw new AuthDurationConfigError(`${ADMIN_MFA_CHALLENGE_TTL_ENV} produced an unsafe admin MFA challenge TTL`);
  }

  const safeConfig = defaultAdminMfaChallengeTtl("runtime_guard_default", config.envRawPresent);
  return {
    expiresAt: new Date(now.getTime() + safeConfig.ttlMs),
    config: safeConfig,
  };
};

export const buildAdminMfaChallengeTtlAuditDetails = (config: AuthDurationConfig, createdAt: Date, expiresAt: Date) => ({
  createdAt: createdAt.toISOString(),
  expiresAt: expiresAt.toISOString(),
  ttlMs: config.ttlMs,
  ttlMinutes: config.minutes,
  ttlEnvRawPresent: config.envRawPresent,
  ttlSource: config.source,
});
