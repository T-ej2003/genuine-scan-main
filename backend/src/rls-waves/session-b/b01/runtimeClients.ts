import { PrismaClient } from "@prisma/client";

import prisma from "../../../config/database";

export const PREAUTH_DATABASE_URL_ENV = "PREAUTH_DATABASE_URL";
export const AUTHENTICATED_APP_DATABASE_URL_ENV = "AUTHENTICATED_APP_DATABASE_URL";

type RuntimeClient = Pick<PrismaClient, "$queryRaw" | "$transaction">;

export class B01RuntimeConfigurationError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
    this.name = "B01RuntimeConfigurationError";
  }
}

const parseDatabaseUrl = (value: string, name: string) => {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new B01RuntimeConfigurationError("B01_RUNTIME_DATABASE_URL_INVALID", `${name} must be a valid PostgreSQL URL`);
  }
  if (!["postgres:", "postgresql:"].includes(parsed.protocol)) {
    throw new B01RuntimeConfigurationError("B01_RUNTIME_DATABASE_URL_INVALID", `${name} must use postgres:// or postgresql://`);
  }
  if (!parsed.hostname || !parsed.username || !parsed.pathname.replace(/^\//, "")) {
    throw new B01RuntimeConfigurationError(
      "B01_RUNTIME_DATABASE_CREDENTIAL_INCOMPLETE",
      `${name} must include a host, runtime role username, and database name`
    );
  }
  return parsed;
};

const credentialIdentity = (url: URL) =>
  `${decodeURIComponent(url.username)}@${url.hostname}:${url.port || "5432"}/${url.pathname.replace(/^\//, "")}`;

const runtimeRole = (url: URL, suffix: "preauth" | "app") => {
  const role = decodeURIComponent(url.username);
  const match = role.match(new RegExp(`^mscqr_(dev|stg|prd)_rls_[a-z][a-z0-9_]{0,15}_${suffix}$`));
  if (!match) {
    throw new B01RuntimeConfigurationError(
      "B01_RUNTIME_DATABASE_ROLE_INVALID",
      `${suffix === "preauth" ? PREAUTH_DATABASE_URL_ENV : AUTHENTICATED_APP_DATABASE_URL_ENV} must use an environment-scoped ${suffix} runtime role`
    );
  }
  return match[1];
};

export const resolveB01RuntimeDatabaseConfiguration = (env: NodeJS.ProcessEnv = process.env) => {
  const preAuthValue = String(env[PREAUTH_DATABASE_URL_ENV] || "").trim();
  const authenticatedValue = String(env[AUTHENTICATED_APP_DATABASE_URL_ENV] || "").trim();
  const testFallbackAllowed = env.NODE_ENV === "test";

  if (!preAuthValue && !authenticatedValue && testFallbackAllowed) {
    return { preAuthDatabaseUrl: null, authenticatedDatabaseUrl: null } as const;
  }
  if (!preAuthValue || !authenticatedValue) {
    throw new B01RuntimeConfigurationError(
      "B01_RUNTIME_DATABASE_URL_MISSING",
      `${PREAUTH_DATABASE_URL_ENV} and ${AUTHENTICATED_APP_DATABASE_URL_ENV} must be configured together`
    );
  }

  const preAuth = parseDatabaseUrl(preAuthValue, PREAUTH_DATABASE_URL_ENV);
  const authenticated = parseDatabaseUrl(authenticatedValue, AUTHENTICATED_APP_DATABASE_URL_ENV);
  if (credentialIdentity(preAuth) === credentialIdentity(authenticated)) {
    throw new B01RuntimeConfigurationError(
      "B01_RUNTIME_DATABASE_CREDENTIAL_REUSED",
      "Pre-authentication and authenticated application database credentials must be distinct"
    );
  }

  if (!testFallbackAllowed) {
    const preAuthEnvironment = runtimeRole(preAuth, "preauth");
    const authenticatedEnvironment = runtimeRole(authenticated, "app");
    if (preAuthEnvironment !== authenticatedEnvironment) {
      throw new B01RuntimeConfigurationError(
        "B01_RUNTIME_DATABASE_ENVIRONMENT_MISMATCH",
        "B01 runtime database credentials must target the same environment"
      );
    }
  }

  const defaultValue = String(env.DATABASE_URL || "").trim();
  if (defaultValue) {
    const defaultIdentity = credentialIdentity(parseDatabaseUrl(defaultValue, "DATABASE_URL"));
    if (credentialIdentity(preAuth) === defaultIdentity) {
      throw new B01RuntimeConfigurationError(
        "B01_RUNTIME_DATABASE_REUSES_DEFAULT",
        "The pre-authentication database credential must not reuse DATABASE_URL"
      );
    }
  }

  return { preAuthDatabaseUrl: preAuthValue, authenticatedDatabaseUrl: authenticatedValue } as const;
};

let preAuthClient: RuntimeClient | null = null;
let authenticatedClient: RuntimeClient | null = null;

const client = (databaseUrl: string) => new PrismaClient({ datasources: { db: { url: databaseUrl } } });

export const getB01PreAuthPrisma = (env: NodeJS.ProcessEnv = process.env): RuntimeClient => {
  const configuration = resolveB01RuntimeDatabaseConfiguration(env);
  if (!configuration.preAuthDatabaseUrl) return prisma;
  return preAuthClient ||= client(configuration.preAuthDatabaseUrl);
};

export const getB01AuthenticatedPrisma = (env: NodeJS.ProcessEnv = process.env): RuntimeClient => {
  const configuration = resolveB01RuntimeDatabaseConfiguration(env);
  if (!configuration.authenticatedDatabaseUrl) return prisma;
  return authenticatedClient ||= client(configuration.authenticatedDatabaseUrl);
};
