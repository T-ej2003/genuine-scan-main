import type { Request, Response } from "express";

import { logger } from "../utils/logger";
import { normalizeClientIp } from "../utils/ipAddress";
import { hashToken } from "../utils/security";

type LimiterStage = "route" | "pre-auth" | "ip" | "actor";
type AuthModel = "anonymous" | "bearer" | "cookie" | "authenticated";

type RateLimitMetric = {
  at: number;
  scope: string;
  family: string;
  stage: LimiterStage;
  method: string;
  route: string;
  authModel: AuthModel;
  offenderKind: string;
  offenderRef: string | null;
  tenantRef: string | null;
  resourceRef: string | null;
  userRole: string | null;
  retryAfterSec: number;
};

type RateLimitHandlerOptions = {
  includeRetryAfter?: boolean;
};

const MAX_RATE_LIMIT_METRICS = 2500;
const DEFAULT_WINDOW_MS = 15 * 60 * 1000;
const rateLimitMetrics: RateLimitMetric[] = [];
const ALERT_THRESHOLDS: Record<string, { threshold: number; severity: "high" | "medium" }> = {
  "licensees.read": { threshold: 20, severity: "high" },
  "governance.read": { threshold: 12, severity: "high" },
  "audit.export": { threshold: 8, severity: "high" },
  "verify.claim": { threshold: 10, severity: "high" },
  "printer-agent.heartbeat": { threshold: 25, severity: "medium" },
  "support.read": { threshold: 15, severity: "medium" },
};

const pushBounded = <T,>(arr: T[], value: T, max: number) => {
  arr.push(value);
  if (arr.length > max) {
    arr.splice(0, arr.length - max);
  }
};

const normalizeRoute = (rawPath: string) =>
  String(rawPath || "/")
    .split("?")[0]
    .replace(/\/[0-9]+(?=\/|$)/g, "/:id")
    .replace(/\/[0-9a-f]{8}-[0-9a-f-]{27,}(?=\/|$)/gi, "/:id")
    .replace(/\/[A-Za-z0-9_-]{16,}(?=\/|$)/g, "/:id")
    .replace(/\/+/g, "/");

const normalizeValue = (value: unknown, max = 512) => String(value ?? "").trim().slice(0, max);

const hashRef = (prefix: string, value: string | null) => {
  const normalized = normalizeValue(value);
  if (!normalized) return null;
  return hashToken(`${prefix}:${normalized}`).slice(0, 30);
};

const retryAfterSeconds = (req: Request) => {
  const limitedReq = req as Request & { rateLimit?: { resetTime?: Date } };
  const resetAt = limitedReq.rateLimit?.resetTime?.getTime?.() || Date.now() + 1000;
  return Math.max(1, Math.ceil((resetAt - Date.now()) / 1000));
};

const getScopeFamily = (scope: string) => scope.replace(/:(pre-auth|ip|actor)$/, "");

const getLimiterStage = (scope: string): LimiterStage => {
  if (scope.endsWith(":pre-auth")) return "pre-auth";
  if (scope.endsWith(":ip")) return "ip";
  if (scope.endsWith(":actor")) return "actor";
  return "route";
};

const detectAuthModel = (req: Request): AuthModel => {
  const authMode = String((req as any).authMode || "").trim().toLowerCase();
  if (authMode === "bearer") return "bearer";
  if (authMode === "cookie") return "cookie";
  if ((req as any).user?.userId) return "authenticated";
  const authHeader = normalizeValue(req.get("authorization"), 4096).toLowerCase();
  if (authHeader.startsWith("bearer ")) return "bearer";
  return "anonymous";
};

const getRoutePattern = (req: Request) => {
  const routePath =
    typeof (req as any).route?.path === "string"
      ? (req as any).route.path
      : typeof req.path === "string"
        ? req.path
        : req.originalUrl || "/";
  return normalizeRoute(`${req.baseUrl || ""}${routePath || ""}` || "/");
};

const detectTenantRef = (req: Request) => {
  const licenseeId =
    normalizeValue((req as any).user?.licenseeId) ||
    normalizeValue(req.get("x-licensee-id")) ||
    normalizeValue((req.query as Record<string, unknown> | undefined)?.licenseeId) ||
    null;
  return hashRef("tenant", licenseeId);
};

const detectResourceRef = (req: Request) => {
  const params = (req.params || {}) as Record<string, unknown>;
  const query = (req.query || {}) as Record<string, unknown>;
  const resource =
    normalizeValue(params.id) ||
    normalizeValue(params.code) ||
    normalizeValue(query.licenseeId) ||
    normalizeValue(query.reference) ||
    normalizeValue(query.batchId) ||
    normalizeValue(query.fileName) ||
    null;
  return hashRef("resource", resource);
};

const detectOffender = (req: Request) => {
  const userId = normalizeValue((req as any).user?.userId);
  if (userId) {
    return {
      offenderKind: "user",
      offenderRef: hashRef("user", userId),
    };
  }

  const bearerHeader = normalizeValue(req.get("authorization"), 4096);
  if (bearerHeader.toLowerCase().startsWith("bearer ")) {
    return {
      offenderKind: "bearer",
      offenderRef: hashRef("bearer", bearerHeader.slice(7).trim()),
    };
  }

  const gatewayId = normalizeValue(req.get("x-printer-gateway-id")) || normalizeValue((req.body as any)?.gatewayId);
  if (gatewayId) {
    return {
      offenderKind: "gateway",
      offenderRef: hashRef("gateway", gatewayId),
    };
  }

  const deviceFingerprint = normalizeValue(req.get("x-device-fp"));
  if (deviceFingerprint) {
    return {
      offenderKind: "device",
      offenderRef: hashRef("device", deviceFingerprint),
    };
  }

  const normalizedIp = normalizeClientIp(req.ip || req.socket?.remoteAddress || "", { fallback: "unknown" });
  const userAgent = normalizeValue(req.get("user-agent"), 256);
  return {
    offenderKind: "ip-ua",
    offenderRef: hashRef("ip-ua", `${normalizedIp}|${userAgent}`),
  };
};

export const recordRateLimitMetric = (req: Request, scope: string) => {
  const family = getScopeFamily(scope);
  const stage = getLimiterStage(scope);
  const retryAfterSec = retryAfterSeconds(req);
  const { offenderKind, offenderRef } = detectOffender(req);
  const entry: RateLimitMetric = {
    at: Date.now(),
    scope,
    family,
    stage,
    method: String(req.method || "GET").toUpperCase(),
    route: getRoutePattern(req),
    authModel: detectAuthModel(req),
    offenderKind,
    offenderRef,
    tenantRef: detectTenantRef(req),
    resourceRef: detectResourceRef(req),
    userRole: normalizeValue((req as any).user?.role) || null,
    retryAfterSec,
  };

  pushBounded(rateLimitMetrics, entry, MAX_RATE_LIMIT_METRICS);
  logger.warn("rate_limit_metric", {
    event: "rate_limit_metric",
    ...entry,
  });
  return retryAfterSec;
};

export const createRateLimitJsonHandler =
  (scope: string, message: string, _options: RateLimitHandlerOptions = {}) =>
  (req: Request, res: Response) => {
    const retryAfterSec = recordRateLimitMetric(req, scope);
    res.setHeader("Retry-After", String(retryAfterSec));

    return res.status(429).json({
      success: false,
      code: "RATE_LIMITED",
      error: message,
      scope,
      retryAfterSec,
    });
  };

const round = (value: number) => Math.round(value * 10) / 10;

const summarizeTopRoutes = (entries: RateLimitMetric[]) => {
  const byRoute = new Map<string, { family: string; count: number; lastLimitedAt: number }>();

  for (const entry of entries) {
    const key = `${entry.method} ${entry.route}`;
    const current = byRoute.get(key) || { family: entry.family, count: 0, lastLimitedAt: 0 };
    current.count += 1;
    current.lastLimitedAt = Math.max(current.lastLimitedAt, entry.at);
    byRoute.set(key, current);
  }

  return [...byRoute.entries()]
    .map(([route, stats]) => ({
      route,
      family: stats.family,
      count: stats.count,
      lastLimitedAt: new Date(stats.lastLimitedAt).toISOString(),
    }))
    .sort((left, right) => right.count - left.count)
    .slice(0, 10);
};

const summarizeRepeatedOffenders = (entries: RateLimitMetric[]) => {
  const byOffender = new Map<
    string,
    { offenderKind: string; count: number; familyCounts: Map<string, number>; lastSeenAt: number }
  >();

  for (const entry of entries) {
    if (!entry.offenderRef) continue;
    const current =
      byOffender.get(entry.offenderRef) ||
      { offenderKind: entry.offenderKind, count: 0, familyCounts: new Map<string, number>(), lastSeenAt: 0 };
    current.count += 1;
    current.familyCounts.set(entry.family, (current.familyCounts.get(entry.family) || 0) + 1);
    current.lastSeenAt = Math.max(current.lastSeenAt, entry.at);
    byOffender.set(entry.offenderRef, current);
  }

  return [...byOffender.entries()]
    .filter(([, stats]) => stats.count >= 3)
    .map(([offenderRef, stats]) => ({
      offenderRef,
      offenderKind: stats.offenderKind,
      count: stats.count,
      topFamilies: [...stats.familyCounts.entries()]
        .sort((left, right) => right[1] - left[1])
        .slice(0, 3)
        .map(([family, count]) => ({ family, count })),
      lastSeenAt: new Date(stats.lastSeenAt).toISOString(),
    }))
    .sort((left, right) => right.count - left.count)
    .slice(0, 10);
};

const summarizeTenantBurstAnomalies = (entries: RateLimitMetric[]) => {
  const byTenantFamily = new Map<string, { tenantRef: string; family: string; count: number; lastSeenAt: number }>();

  for (const entry of entries) {
    if (!entry.tenantRef) continue;
    const key = `${entry.tenantRef}:${entry.family}`;
    const current = byTenantFamily.get(key) || {
      tenantRef: entry.tenantRef,
      family: entry.family,
      count: 0,
      lastSeenAt: 0,
    };
    current.count += 1;
    current.lastSeenAt = Math.max(current.lastSeenAt, entry.at);
    byTenantFamily.set(key, current);
  }

  return [...byTenantFamily.values()]
    .filter((entry) => entry.count >= 3)
    .sort((left, right) => right.count - left.count)
    .slice(0, 10)
    .map((entry) => ({
      ...entry,
      lastSeenAt: new Date(entry.lastSeenAt).toISOString(),
      severity: entry.count >= 8 ? "high" : entry.count >= 5 ? "medium" : "low",
    }));
};

const summarizeExportAbusePatterns = (entries: RateLimitMetric[]) => {
  const exportEntries = entries.filter(
    (entry) =>
      entry.family.includes("export") ||
      entry.route.includes("/export") ||
      entry.route.includes("/download") ||
      entry.family.includes("downloads")
  );

  const byFamily = new Map<string, { count: number; offenderRefs: Set<string>; tenantRefs: Set<string> }>();
  for (const entry of exportEntries) {
    const current = byFamily.get(entry.family) || { count: 0, offenderRefs: new Set<string>(), tenantRefs: new Set<string>() };
    current.count += 1;
    if (entry.offenderRef) current.offenderRefs.add(entry.offenderRef);
    if (entry.tenantRef) current.tenantRefs.add(entry.tenantRef);
    byFamily.set(entry.family, current);
  }

  return [...byFamily.entries()]
    .map(([family, stats]) => ({
      family,
      count: stats.count,
      uniqueOffenders: stats.offenderRefs.size,
      uniqueTenants: stats.tenantRefs.size,
    }))
    .sort((left, right) => right.count - left.count)
    .slice(0, 10);
};

const summarizeFamilyTotals = (entries: RateLimitMetric[]) => {
  const byFamily = new Map<string, { count: number; preAuthCount: number; actorCount: number; ipCount: number }>();
  for (const entry of entries) {
    const current = byFamily.get(entry.family) || { count: 0, preAuthCount: 0, actorCount: 0, ipCount: 0 };
    current.count += 1;
    if (entry.stage === "pre-auth") current.preAuthCount += 1;
    if (entry.stage === "actor") current.actorCount += 1;
    if (entry.stage === "ip") current.ipCount += 1;
    byFamily.set(entry.family, current);
  }

  return [...byFamily.entries()]
    .map(([family, stats]) => ({ family, ...stats }))
    .sort((left, right) => right.count - left.count)
    .slice(0, 20);
};

export const getRateLimitAnalyticsSummary = (windowMs = DEFAULT_WINDOW_MS) => {
  const now = Date.now();
  const entries = rateLimitMetrics.filter((entry) => now - entry.at <= windowMs);
  const uniqueOffenders = new Set(entries.map((entry) => entry.offenderRef).filter(Boolean)).size;
  const uniqueTenants = new Set(entries.map((entry) => entry.tenantRef).filter(Boolean)).size;

  return {
    generatedAt: new Date(now).toISOString(),
    windowMs,
    totalEvents: entries.length,
    uniqueOffenders,
    uniqueTenants,
    familyTotals: summarizeFamilyTotals(entries),
    topLimitedRoutes: summarizeTopRoutes(entries),
    repeatedOffenders: summarizeRepeatedOffenders(entries),
    tenantBurstAnomalies: summarizeTenantBurstAnomalies(entries),
    exportAbusePatterns: summarizeExportAbusePatterns(entries),
    preAuthRate: entries.length === 0 ? 0 : round((entries.filter((entry) => entry.stage === "pre-auth").length / entries.length) * 100),
  };
};

export const getRateLimitAlertCandidates = (windowMs = DEFAULT_WINDOW_MS) => {
  const summary = getRateLimitAnalyticsSummary(windowMs);
  const alerts: Array<{ severity: "high" | "medium"; family: string; reason: string; count: number }> = [];

  for (const family of summary.familyTotals) {
    const configured = ALERT_THRESHOLDS[family.family];
    const threshold = configured?.threshold ?? 20;
    if (family.count >= threshold) {
      alerts.push({
        severity: configured?.severity ?? (family.count >= threshold * 2 ? "high" : "medium"),
        family: family.family,
        reason: "Repeated limiter hits exceeded the route-family threshold.",
        count: family.count,
      });
    }
  }

  for (const anomaly of summary.tenantBurstAnomalies) {
    alerts.push({
      severity: anomaly.severity === "high" ? "high" : "medium",
      family: anomaly.family,
      reason: `Tenant burst anomaly detected for ${anomaly.tenantRef}.`,
      count: anomaly.count,
    });
  }

  return {
    ...summary,
    alerts: alerts.slice(0, 20),
  };
};

export const __resetRateLimitMetricsForTests = () => {
  rateLimitMetrics.splice(0, rateLimitMetrics.length);
};
