const object = (value) => value && typeof value === "object" && !Array.isArray(value);

export const CANONICAL_PRODUCTION_ORIGIN = "https://www.mscqr.com";
export const CANONICAL_PRODUCTION_READINESS_URL = `${CANONICAL_PRODUCTION_ORIGIN}/api/health/ready`;

export function assertProductionBackendReadiness(payload, { expectedReleaseSha } = {}) {
  if (!object(payload) || payload.success !== true || payload.status !== "ready") {
    throw new Error("Production backend readiness did not report success=true and status=ready.");
  }
  const dependencies = payload.dependencies;
  if (!object(dependencies)
    || dependencies.database?.ready !== true
    || dependencies.redis?.configured !== true || dependencies.redis?.ready !== true
    || dependencies.objectStorage?.configured !== true || dependencies.objectStorage?.ready !== true) {
    throw new Error("Production backend readiness dependencies are degraded.");
  }
  if (expectedReleaseSha !== undefined && (!/^[a-f0-9]{40}$/.test(expectedReleaseSha) || payload.release?.gitSha !== expectedReleaseSha)) {
    throw new Error("Production backend readiness release identity is wrong.");
  }
  if (typeof payload.timestamp !== "string" || !Number.isFinite(Date.parse(payload.timestamp))) throw new Error("Production backend readiness timestamp is invalid.");
  return Object.freeze({
    healthy: true,
    success: true,
    status: "ready",
    dependencies: Object.freeze({ database: "ready", redis: "ready", objectStorage: "ready" }),
    release: object(payload.release) ? structuredClone(payload.release) : null,
    timestamp: typeof payload.timestamp === "string" ? payload.timestamp : null,
  });
}

export function parseProductionBackendReadiness(bytes, options) {
  const text = new TextDecoder("utf-8", { fatal: true }).decode(Buffer.from(bytes));
  return assertProductionBackendReadiness(JSON.parse(text), options);
}

export function assertProductionBackendReadinessUrl(value) {
  try { new URL(value); } catch { throw new Error("Backend recovery readiness URL is invalid."); }
  if (value !== CANONICAL_PRODUCTION_READINESS_URL) {
    throw new Error("Backend recovery must use the canonical public HTTPS readiness endpoint.");
  }
  return CANONICAL_PRODUCTION_READINESS_URL;
}
