type RequestMetric = {
  at: number;
  method: string;
  route: string;
  status: number;
  durationMs: number;
};

const MAX_REQUEST_METRICS = 1500;
const DEFAULT_WINDOW_MS = 15 * 60 * 1000;
const requestMetrics: RequestMetric[] = [];

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

const round = (value: number) => Math.round(value * 10) / 10;

const percentile = (values: number[], percentileValue: number) => {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const index = Math.min(sorted.length - 1, Math.max(0, Math.ceil(sorted.length * percentileValue) - 1));
  return round(sorted[index]);
};

export const recordRequestMetric = (entry: Omit<RequestMetric, "route"> & { route: string }) => {
  pushBounded(
    requestMetrics,
    {
      ...entry,
      route: normalizeRoute(entry.route),
      durationMs: round(entry.durationMs),
    },
    MAX_REQUEST_METRICS
  );
};

export const getLatencySummary = (windowMs = DEFAULT_WINDOW_MS) => {
  const now = Date.now();
  const entries = requestMetrics.filter((entry) => now - entry.at <= windowMs);
  const durations = entries.map((entry) => entry.durationMs);
  const errorCount = entries.filter((entry) => entry.status >= 500).length;
  const slowRequestCount = entries.filter((entry) => entry.durationMs >= 1500).length;
  const byRoute = new Map<
    string,
    {
      count: number;
      errorCount: number;
      durations: number[];
    }
  >();

  for (const entry of entries) {
    const key = `${entry.method} ${entry.route}`;
    const current = byRoute.get(key) || { count: 0, errorCount: 0, durations: [] };
    current.count += 1;
    if (entry.status >= 500) current.errorCount += 1;
    current.durations.push(entry.durationMs);
    byRoute.set(key, current);
  }

  const topRoutes = [...byRoute.entries()]
    .map(([route, stats]) => {
      const averageMs =
        stats.durations.length === 0
          ? 0
          : round(stats.durations.reduce((sum, value) => sum + value, 0) / stats.durations.length);

      return {
        route,
        count: stats.count,
        errorCount: stats.errorCount,
        averageMs,
        p95Ms: percentile(stats.durations, 0.95),
      };
    })
    .sort((left, right) => right.count - left.count || right.p95Ms - left.p95Ms)
    .slice(0, 5);

  return {
    windowMs,
    totalRequests: entries.length,
    errorCount,
    errorRate: entries.length === 0 ? 0 : round((errorCount / entries.length) * 100),
    slowRequestCount,
    p50Ms: percentile(durations, 0.5),
    p95Ms: percentile(durations, 0.95),
    topRoutes,
  };
};
