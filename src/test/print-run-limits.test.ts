import { describe, expect, it } from "vitest";

import { clampPrintRunQuantityInput, resolveMaxPrintRunQuantity } from "@/features/batches/print-run-limits";

describe("print run quantity limits", () => {
  it("uses min of 2000 and remaining printable labels", () => {
    expect(resolveMaxPrintRunQuantity(919)).toBe(919);
    expect(resolveMaxPrintRunQuantity(5000)).toBe(2000);
  });

  it("clamps typed or pasted values above remaining labels", () => {
    expect(clampPrintRunQuantityInput("2000", 919)).toBe("919");
  });

  it("allows 2000 when at least 2000 labels remain and blocks 2001", () => {
    expect(clampPrintRunQuantityInput("2000", 5000)).toBe("2000");
    expect(clampPrintRunQuantityInput("2001", 5000)).toBe("2000");
  });
});
