import { describe, expect, it } from "vitest";

import {
  getLivePrintStatusRefreshDecision,
  getLivePrintStatusRetryAfterMs,
} from "@/features/batches/print-status-refresh-control";

describe("live print status refresh control", () => {
  it("throttles manual refresh for 30 seconds", () => {
    const firstDecision = getLivePrintStatusRefreshDecision(30_000, 0, 0);
    const throttled = getLivePrintStatusRefreshDecision(45_000, 30_000, 0);
    const allowedAgain = getLivePrintStatusRefreshDecision(60_000, 30_000, 0);

    expect(firstDecision.allowed).toBe(true);
    expect(throttled.allowed).toBe(false);
    expect(throttled.waitSeconds).toBe(15);
    expect(allowedAgain.allowed).toBe(true);
  });

  it("uses Retry-After or a 30 second fallback for 429 cooldowns", () => {
    expect(getLivePrintStatusRetryAfterMs(12)).toBe(12_000);
    expect(getLivePrintStatusRetryAfterMs(undefined)).toBe(30_000);
  });
});
