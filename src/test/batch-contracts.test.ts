import { describe, expect, it } from "vitest";

import { batchArraySchema } from "../../shared/contracts/runtime/batches";

describe("batch contracts", () => {
  it("accepts source batches with a null manufacturer relation", () => {
    const result = batchArraySchema.safeParse([
      {
        id: "batch-parent-1",
        name: "Source Batch",
        licenseeId: "lic-1",
        manufacturerId: null,
        batchKind: "RECEIVED_PARENT",
        parentBatchId: null,
        rootBatchId: null,
        startCode: "A0001",
        endCode: "A0100",
        totalCodes: 100,
        printedAt: null,
        createdAt: "2026-03-24T10:00:00.000Z",
        updatedAt: "2026-03-24T10:00:00.000Z",
        licensee: {
          id: "lic-1",
          name: "Licensee One",
          prefix: "LIC",
        },
        manufacturer: null,
        _count: { qrCodes: 100 },
        availableCodes: 100,
        unassignedRemainingCodes: 100,
        assignedCodes: 0,
        printableCodes: 0,
        printedCodes: 0,
        redeemedCodes: 0,
        blockedCodes: 0,
        remainingStartCode: "A0001",
        remainingEndCode: "A0100",
      },
    ]);

    expect(result.success).toBe(true);
  });
});
