const PUBLIC_VERIFY_STATIC_ROOTS = new Set([
  "auth",
  "feedback",
  "report-fraud",
  "session",
  "transfer",
]);

export const sanitizeRequestTelemetryPath = (rawPath: unknown): string => {
  const path = String(rawPath || "/").split("?", 1)[0] || "/";
  const sessionPath = path.replace(
    /^\/api\/verify\/session\/[^/]+/,
    "/api/verify/session/:id",
  );
  if (sessionPath !== path) return sessionPath;

  const credentialPath = path.replace(
    /^\/api\/verify\/auth\/passkey\/credentials\/[^/]+/,
    "/api/verify/auth/passkey/credentials/:id",
  );
  if (credentialPath !== path) return credentialPath;

  const match = path.match(/^\/api\/verify\/([^/]+)(\/.*)?$/);
  if (!match || PUBLIC_VERIFY_STATIC_ROOTS.has(match[1])) return path;
  return `/api/verify/:code${match[2] || ""}`;
};
