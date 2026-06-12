import { describe, expect, it } from "vitest";

import { canPollVisibleDocument, visibleRefetchInterval } from "@/lib/query-polling-policy";

const setVisibilityState = (value: DocumentVisibilityState) => {
  Object.defineProperty(document, "visibilityState", {
    configurable: true,
    value,
  });
};

describe("query polling policy", () => {
  it("pauses interval polling while the tab is hidden", () => {
    setVisibilityState("hidden");

    expect(canPollVisibleDocument()).toBe(false);
    expect(visibleRefetchInterval(30_000)()).toBe(false);
  });

  it("allows bounded jittered polling while the tab is visible", () => {
    setVisibilityState("visible");

    const interval = visibleRefetchInterval(30_000)();

    expect(canPollVisibleDocument()).toBe(true);
    expect(typeof interval).toBe("number");
    expect(interval).toBeGreaterThanOrEqual(27_000);
    expect(interval).toBeLessThanOrEqual(33_000);
  });
});
