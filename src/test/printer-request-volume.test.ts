import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { clearRequestCoordinator, coordinateProtectedRead, setRequestCoordinatorScope } from "@/lib/api/request-coordinator";

describe("printer status request budget", () => {
  beforeEach(() => {
    clearRequestCoordinator();
    setRequestCoordinatorScope(null);
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-10-28T12:00:00Z"));
  });
  afterEach(() => vi.useRealTimers());

  it("deduplicates mounted consumers and honors Retry-After even on forced refresh", async () => {
    const read = { family: "manufacturer-printer-status", params: "current", ttlMs: 0, minRefreshMs: 0 };
    const fetch = vi.fn().mockImplementation(async () => ({ success: true, data: { connected: true } }));
    for (let minute = 0; minute < 5; minute += 1) {
      await Promise.all(Array.from({ length: 3 }, () => coordinateProtectedRead(read, fetch)));
      vi.advanceTimersByTime(60_000);
    }
    expect(fetch).toHaveBeenCalledTimes(5);
    await Promise.all(Array.from({ length: 3 }, () => coordinateProtectedRead({ ...read, force: true }, fetch)));
    expect(fetch).toHaveBeenCalledTimes(6);

    const rateLimited = vi.fn().mockResolvedValue({ success: false, status: 429,
      code: "RATE_LIMITED", retryAfterSec: 90 });
    await coordinateProtectedRead({ ...read, force: true }, rateLimited);
    expect(rateLimited).toHaveBeenCalledTimes(1);
    const blocked = await Promise.all(Array.from({ length: 20 }, () =>
      coordinateProtectedRead({ ...read, force: true }, fetch)));
    expect(fetch).toHaveBeenCalledTimes(6);
    expect(blocked.every((response) => response.code === "RATE_LIMITED" && response.degraded)).toBe(true);
    vi.advanceTimersByTime(90_000);
    await coordinateProtectedRead({ ...read, force: true }, fetch);
    expect(fetch).toHaveBeenCalledTimes(7);
    expect(fetch.mock.calls.length).toBeLessThan(40);
  });
});
