import { warnStorageUnavailableOnce } from "./prismaStorageGuard";

const FAIL_CLOSED_ENV_KEYS = [
  "PUBLIC_VERIFICATION_FAIL_CLOSED",
  "PUBLIC_VERIFY_FAIL_CLOSED",
  "PUBLIC_SCAN_FAIL_CLOSED",
] as const;

const readExplicitFailClosed = () => {
  for (const key of FAIL_CLOSED_ENV_KEYS) {
    const value = String(process.env[key] || "").trim().toLowerCase();
    if (value === "true") return true;
    if (value === "false") return false;
  }
  return null;
};

export const shouldFailClosedForPublicIntegrity = () => {
  const explicit = readExplicitFailClosed();
  if (explicit !== null) return explicit;
  return String(process.env.NODE_ENV || "").trim().toLowerCase() === "production";
};

export class PublicIntegrityDependencyError extends Error {
  code: string;
  statusCode: number;

  constructor(message: string, code = "PUBLIC_VERIFICATION_DEGRADED", statusCode = 503) {
    super(message);
    this.name = "PublicIntegrityDependencyError";
    this.code = code;
    this.statusCode = statusCode;
  }
}

export const isPublicIntegrityDependencyError = (error: unknown): error is PublicIntegrityDependencyError => {
  return error instanceof PublicIntegrityDependencyError;
};

export const guardPublicIntegrityFallback = (params: {
  strictStorage?: boolean;
  warningKey: string;
  warningMessage: string;
  degradedMessage?: string;
  degradedCode?: string;
}) => {
  if (params.strictStorage && shouldFailClosedForPublicIntegrity()) {
    throw new PublicIntegrityDependencyError(
      params.degradedMessage || "Verification is temporarily unavailable while integrity storage recovers.",
      params.degradedCode
    );
  }

  warnStorageUnavailableOnce(params.warningKey, params.warningMessage);
};

export const buildPublicIntegrityErrorBody = (message?: string, code = "PUBLIC_VERIFICATION_DEGRADED") => ({
  success: false,
  degraded: true,
  code,
  error: message || "Verification is temporarily unavailable while integrity checks recover. Please try again shortly.",
});
