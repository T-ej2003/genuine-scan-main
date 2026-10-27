import { describe, expect, it } from "vitest";

import { allocationSuccessHint } from "@/features/batches/useBatchOperationsController";

describe("allocation confirmation", () => {
  it("uses committed counts and label boundaries without exposing internal IDs or claiming contiguity", () => {
    const hint = allocationSuccessHint({
      allocated: 10, startCode: "LAB0001", endCode: "LAB0012", sourceRemainingCodes: 140,
    }, "Factory A");
    expect(hint.title).toBe("Allocation successful");
    expect(hint.body).toBe("10 QR labels assigned to Factory A. First label: LAB0001; last label: LAB0012. Remaining available: 140.");
    expect(hint.body).not.toMatch(/batch id|uuid|continuous range/i);
  });
});
