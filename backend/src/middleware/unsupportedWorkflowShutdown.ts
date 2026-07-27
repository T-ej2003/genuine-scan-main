import { createHash } from "crypto";
import type { Request, RequestHandler } from "express";
import { MemoryStore, type Options as RateLimitOptions, type Store } from "express-rate-limit";

import {
  createRedisRateLimitStore,
  createSharedRateLimiter,
  parsePositiveIntEnv,
} from "./publicRateLimit";
import { normalizeClientIp } from "../utils/ipAddress";
import { logger } from "../utils/logger";
import { hashIp } from "../utils/security";

export const reducedSurfaceEnabledRoutes = [] as const;

const testOverrideName = "MSCQR_TEST_ALLOW_UNSUPPORTED_WORKFLOWS";
const activationName = "MSCQR_FULL_RLS_REDUCED_SURFACE_ENABLED";
const unresolvedRoute = "UNRESOLVED_PROTECTED_ROUTE";
const limiterProperty = "unsupportedWorkflowDenialLimit";
const parameter = /^:[A-Za-z_][A-Za-z0-9_]*$/;

export const reducedSurfaceDedicatedBoundaryPrefixes = [
  "/auth",
  "/fraud-report",
  "/health",
  "/healthz",
  "/incidents/report",
  "/public",
  "/scan",
  "/support/tickets/track",
  "/verify",
] as const;

export const reducedSurfaceDedicatedBoundaryRoutes = [
  "POST /telemetry/csp-report",
  "POST /telemetry/route-transition",
] as const;

const denialCounters = {
  denied: 0,
  rateLimited: 0,
  logsEmitted: 0,
  logsSuppressed: 0,
  sharedStoreFallbacks: 0,
};

type DenialRequest = Request & {
  requestId?: string;
  unsupportedWorkflowDenial?: true;
  unsupportedWorkflowDenialLimit?: {
    key: string;
    used: number;
    resetTime?: Date;
  };
};

const incrementCounter = (name: keyof typeof denialCounters) => {
  denialCounters[name] = Math.min(Number.MAX_SAFE_INTEGER, denialCounters[name] + 1);
};

export const getUnsupportedWorkflowDenialCounters = () => ({ ...denialCounters });

export const __resetUnsupportedWorkflowDenialCountersForTests = () => {
  for (const name of Object.keys(denialCounters) as Array<keyof typeof denialCounters>) denialCounters[name] = 0;
};

const normalizePath = (value: string) => {
  const normalized = `/${String(value || "").split("?")[0].replace(/^\/+|\/+$/g, "")}`;
  return normalized === "/" ? normalized : normalized.replace(/\/+$/g, "");
};

const segments = (value: string, template = false) => normalizePath(value).split("/").slice(1).map((part) => {
  if (template && parameter.test(part)) return part;
  if (template && (/[*?()+]/.test(part) || part.includes(":"))) throw new Error(`Unsupported protected route template: ${value}`);
  let decoded: string;
  try { decoded = decodeURIComponent(part); } catch { throw new Error(`Invalid encoded protected route: ${value}`); }
  if (!decoded || decoded.includes("/") || decoded.includes("\\")) throw new Error(`Unsafe protected route segment: ${value}`);
  return decoded;
});

type CompiledRoute = { key: string; method: string; template: string; parts: string[]; signature: string; staticCount: number };

export const compileEnabledRoutes = (routes: readonly string[]): CompiledRoute[] => {
  const keys = new Set<string>();
  const signatures = new Set<string>();
  const compiled = routes.map((entry) => {
    const match = String(entry).trim().match(/^([A-Z]+)\s+(\/\S*)$/);
    if (!match) throw new Error(`Invalid protected route entry: ${entry}`);
    const method = match[1];
    const template = normalizePath(match[2]);
    const parts = segments(template, true);
    const key = `${method} ${template}`;
    const signature = `${method} /${parts.map((part) => parameter.test(part) ? ":" : part).join("/")}`;
    if (keys.has(key) || signatures.has(signature)) throw new Error(`Duplicate or ambiguous protected route template: ${entry}`);
    keys.add(key);
    signatures.add(signature);
    return { key, method, template, parts, signature, staticCount: parts.filter((part) => !parameter.test(part)).length };
  });
  return compiled.sort((a, b) => b.staticCount - a.staticCount || b.parts.length - a.parts.length || a.key.localeCompare(b.key));
};

const matches = (route: CompiledRoute, method: string, value: string) => {
  if (route.method !== method.toUpperCase()) return false;
  let actual: string[];
  try { actual = segments(value); } catch { return false; }
  return actual.length === route.parts.length && route.parts.every((part, index) => parameter.test(part) || part === actual[index]);
};

const isDedicatedBoundaryPrefix = (value: string) => {
  const path = normalizePath(value).toLowerCase();
  return reducedSurfaceDedicatedBoundaryPrefixes.some((prefix) => path === prefix || path.startsWith(`${prefix}/`));
};

const configuredBoolean = (name: string, fallback = false) => {
  const raw = String(process.env[name] || "").trim().toLowerCase();
  if (!raw) return fallback;
  if (raw === "true") return true;
  if (raw === "false") return false;
  throw new Error(`${name} must be exactly true or false`);
};

const mergeHits = (
  local: { totalHits: number; resetTime: Date | undefined },
  shared: { totalHits: number; resetTime: Date | undefined }
) => {
  const resetAt = Math.max(local.resetTime?.getTime() || 0, shared.resetTime?.getTime() || 0);
  return {
    totalHits: Math.max(local.totalHits, shared.totalHits),
    resetTime: resetAt ? new Date(resetAt) : undefined,
  };
};

const createFailSafeStore = (shared: Store | undefined): Store => {
  const local = new MemoryStore();
  const sharedFailure = () => incrementCounter("sharedStoreFallbacks");

  return {
    localKeys: !shared,
    prefix: "unsupported-workflow-denial:",
    init(options: RateLimitOptions) {
      local.init(options);
      try { shared?.init?.(options); } catch { sharedFailure(); }
    },
    async get(key) {
      const localResult = await local.get(key);
      if (!shared?.get) return localResult;
      try {
        const sharedResult = await shared.get(key);
        if (!localResult) return sharedResult;
        if (!sharedResult) return localResult;
        return mergeHits(localResult, sharedResult);
      } catch {
        sharedFailure();
        return localResult;
      }
    },
    async increment(key) {
      const localResult = await local.increment(key);
      if (!shared) return localResult;
      try {
        return mergeHits(localResult, await shared.increment(key));
      } catch {
        sharedFailure();
        return localResult;
      }
    },
    async decrement(key) {
      await local.decrement(key);
      if (!shared) return;
      try { await shared.decrement(key); } catch { sharedFailure(); }
    },
    async resetKey(key) {
      await local.resetKey(key);
      if (!shared) return;
      try { await shared.resetKey(key); } catch { sharedFailure(); }
    },
  };
};

export const buildUnsupportedWorkflowDenialBucket = (req: Request) => {
  const ip = normalizeClientIp(req.ip || req.socket?.remoteAddress || "", { fallback: "unknown" });
  const versionedIpHash = hashIp(ip);
  if (!versionedIpHash) throw new Error("Unsupported-workflow denial limiter could not hash the client network");
  return `unsupported-workflow-denial:ip:${versionedIpHash}:resource:global`;
};

const privacyRef = (value: unknown) => {
  const normalized = String(value || "").trim();
  return normalized ? createHash("sha256").update(normalized).digest("hex").slice(0, 16) : null;
};

const networkBucketRef = (req: DenialRequest) => {
  const key = req.unsupportedWorkflowDenialLimit?.key || buildUnsupportedWorkflowDenialBucket(req);
  return key.match(/:ip:[^:]+:([a-f0-9]{64}):/)?.[1]?.slice(0, 16) || "unknown";
};

const markDeniedTelemetry = (req: DenialRequest) => {
  req.unsupportedWorkflowDenial = true;
};

const configuredPositiveInt = (key: string, fallback: number, min: number, max: number) =>
  String(process.env[key] || "").trim() ? parsePositiveIntEnv(key, fallback, min, max) : fallback;

export const createUnsupportedWorkflowShutdown = (
  options: {
    enabledRoutes?: readonly string[];
    active?: boolean;
    environment?: string;
    testOverride?: boolean;
    denialWindowMs?: number;
    denialMax?: number;
    denialLogMax?: number;
    sharedStore?: Store | null;
  } = {}
): RequestHandler => {
  const environment = options.environment || process.env.NODE_ENV || "development";
  const requestedTestOverride = options.testOverride === true || process.env[testOverrideName] === "true";
  if (environment === "production" && requestedTestOverride) throw new Error(`${testOverrideName} is prohibited in production`);

  const enabled = compileEnabledRoutes(options.enabledRoutes || reducedSurfaceEnabledRoutes);
  const dedicatedRoutes = compileEnabledRoutes(reducedSurfaceDedicatedBoundaryRoutes);
  const active = options.active ?? configuredBoolean(activationName);
  if (active && enabled.length === 0) {
    throw new Error(`${activationName}=true requires at least one reviewed protected route`);
  }
  const windowMs = Math.max(
    1000,
    Math.floor(
      options.denialWindowMs ?? configuredPositiveInt("UNSUPPORTED_WORKFLOW_DENIAL_WINDOW_MS", 60_000, 1000, 3_600_000)
    )
  );
  const max = Math.max(
    1,
    Math.floor(
      options.denialMax ?? configuredPositiveInt("UNSUPPORTED_WORKFLOW_DENIAL_MAX_PER_NETWORK", 60, 1, 10_000)
    )
  );
  const logMax = Math.min(
    max,
    Math.max(
      1,
      Math.floor(
        options.denialLogMax ?? configuredPositiveInt("UNSUPPORTED_WORKFLOW_DENIAL_LOG_MAX_PER_NETWORK", 5, 1, 100)
      )
    )
  );
  const sharedStore = options.sharedStore === undefined ? createRedisRateLimitStore() : options.sharedStore || undefined;
  const limiter = createSharedRateLimiter({
    windowMs,
    max,
    standardHeaders: true,
    legacyHeaders: false,
    requestPropertyName: limiterProperty,
    keyGenerator: buildUnsupportedWorkflowDenialBucket,
    store: createFailSafeStore(sharedStore),
    validate: false,
    handler: (request, response) => {
      const req = request as DenialRequest;
      markDeniedTelemetry(req);
      incrementCounter("denied");
      incrementCounter("rateLimited");
      incrementCounter("logsSuppressed");
      const resetAt = req.unsupportedWorkflowDenialLimit?.resetTime?.getTime() || Date.now() + windowMs;
      const retryAfterSec = Math.max(1, Math.ceil((resetAt - Date.now()) / 1000));
      response.setHeader("Retry-After", String(retryAfterSec));
      return response.status(429).json({
        error: "Too many temporarily unavailable operation requests",
        code: "RATE_LIMITED",
        requestId: req.requestId || undefined,
        retryAfterSec,
      });
    },
  });

  return (req, res, next) => {
    if (!active) return next();
    if (requestedTestOverride && environment === "test") return next();

    const localPath = normalizePath(req.path);
    const mountedPath = normalizePath(`${req.baseUrl || ""}${localPath}`);
    if (
      isDedicatedBoundaryPrefix(localPath) ||
      isDedicatedBoundaryPrefix(mountedPath) ||
      dedicatedRoutes.some((route) => matches(route, req.method, localPath) || matches(route, req.method, mountedPath))
    ) return next();
    if (enabled.some((route) => matches(route, req.method, localPath) || matches(route, req.method, mountedPath))) return next();
    const deniedReq = req as DenialRequest;
    markDeniedTelemetry(deniedReq);

    return limiter(req, res, () => {
      incrementCounter("denied");
      const count = deniedReq.unsupportedWorkflowDenialLimit?.used || 1;
      const logMeta = {
        method: req.method.toUpperCase(),
        route: unresolvedRoute,
        requestRef: privacyRef(deniedReq.requestId),
        networkBucket: networkBucketRef(deniedReq),
        denialsInBucketWindow: count,
        windowMs,
        outcome: "DENIED",
        reason: "full-database-rls-reduced-surface",
      };

      if (count <= logMax) {
        incrementCounter("logsEmitted");
        logger.warn("unsupported_workflow_disabled", {
          event: "UNSUPPORTED_WORKFLOW_DISABLED",
          ...logMeta,
          aggregateCounters: getUnsupportedWorkflowDenialCounters(),
        });
      } else {
        incrementCounter("logsSuppressed");
        if (count === logMax + 1) {
          incrementCounter("logsEmitted");
          logger.warn("unsupported_workflow_denial_logs_suppressed", {
            event: "UNSUPPORTED_WORKFLOW_DENIAL_LOGS_SUPPRESSED",
            ...logMeta,
            logThreshold: logMax,
            aggregateCounters: getUnsupportedWorkflowDenialCounters(),
          });
        }
      }

      return res.status(503).json({
        error: "This operation is temporarily unavailable",
        code: "WORKFLOW_DISABLED",
        requestId: deniedReq.requestId || undefined,
      });
    });
  };
};

export const unsupportedWorkflowShutdown = createUnsupportedWorkflowShutdown();
