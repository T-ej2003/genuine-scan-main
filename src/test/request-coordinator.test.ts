import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  clearRequestCoordinator,
  coordinateProtectedRead,
  getRequestCoordinatorState,
} from "@/lib/api/request-coordinator";

describe("request coordinator", () => {
  beforeEach(() => {
    clearRequestCoordinator();
    window.localStorage.clear();
    vi.useRealTimers();
  });

  it("dedupes in-flight reads by family and params", async () => {
    let calls = 0;
    const pending = coordinateProtectedRead(
      { family: "dashboard:stats", params: { scope: "all" }, ttlMs: 1 },
      async () => {
        calls += 1;
        await new Promise((resolve) => setTimeout(resolve, 5));
        return { success: true, data: { total: 1 } };
      }
    );

    const duplicate = coordinateProtectedRead(
      { family: "dashboard:stats", params: { scope: "all" }, ttlMs: 1 },
      async () => {
        calls += 1;
        return { success: true, data: { total: 2 } };
      }
    );

    await expect(Promise.all([pending, duplicate])).resolves.toEqual([
      { success: true, data: { total: 1 } },
      { success: true, data: { total: 1 } },
    ]);
    expect(calls).toBe(1);
  });

  it("returns stale cached data during 429 cooldown and persists cooldown", async () => {
    const keyOptions = { family: "manufacturer-print-job-status", params: { jobId: "job-1" }, ttlMs: 1, minRefreshMs: 0 };
    await coordinateProtectedRead(keyOptions, async () => ({ success: true, data: { status: "SENT" } }));

    const response = await coordinateProtectedRead(
      { ...keyOptions, force: true },
      async () => ({ success: false, status: 429, code: "RATE_LIMITED", retryAfterSec: 45, error: "Too many" })
    );

    expect(response.success).toBe(true);
    expect(response.degraded).toBe(true);
    expect(response.code).toBe("RATE_LIMITED");
    expect(response.data).toEqual({ status: "SENT" });
    expect(getRequestCoordinatorState().some((entry) => entry.cooldownUntil > Date.now())).toBe(true);
  });
});
