import { afterEach, describe, expect, it, vi } from "vitest";

import {
  clearDashboardReadCache,
  controlledDashboardGet,
  getDashboardRequestControlState,
} from "@/lib/api/internal-client-dashboard-request-control";

describe("dashboard request control", () => {
  afterEach(() => {
    clearDashboardReadCache();
    vi.restoreAllMocks();
  });

  it("dedupes simultaneous dashboard GET requests", async () => {
    const fetcher = vi.fn(
      () =>
        new Promise<{ success: true; data: { total: number }; status: number }>((resolve) => {
          setTimeout(() => resolve({ success: true, data: { total: 1 }, status: 200 }), 10);
        })
    );

    const [first, second] = await Promise.all([
      controlledDashboardGet("dashboard:stats:test", fetcher),
      controlledDashboardGet("dashboard:stats:test", fetcher),
    ]);

    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(first.data).toEqual({ total: 1 });
    expect(second.data).toEqual({ total: 1 });
  });

  it("reuses last-known-good data during a 429 cooldown", async () => {
    const fetcher = vi
      .fn()
      .mockResolvedValueOnce({ success: true, data: { logs: [{ id: "audit-1" }] }, status: 200 })
      .mockResolvedValueOnce({
        success: false,
        status: 429,
        code: "RATE_LIMITED",
        retryAfterSec: 42,
        error: "Too many audit read requests. Please wait before retrying.",
      });

    const first = await controlledDashboardGet("audit:logs:test", fetcher, { ttlMs: 0, minRefreshMs: 0 });
    const second = await controlledDashboardGet("audit:logs:test", fetcher, {
      ttlMs: 0,
      minRefreshMs: 0,
      bypassCache: true,
    });
    const state = getDashboardRequestControlState().find((entry) => entry.key === "audit:logs:test");

    expect(first.success).toBe(true);
    expect(second.success).toBe(true);
    expect(second.degraded).toBe(true);
    expect(second.code).toBe("RATE_LIMITED");
    expect(second.data).toEqual({ logs: [{ id: "audit-1" }] });
    expect(second.message).toBe("Activity is refreshing too often. Please try again in a moment.");
    expect(state?.hasLastGood).toBe(true);
    expect(fetcher).toHaveBeenCalledTimes(2);
  });
});
