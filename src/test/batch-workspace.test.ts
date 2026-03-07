import { describe, expect, it } from "vitest";

import { buildStableBatchOverviewRows, type BatchWorkspaceRow } from "@/lib/batch-workspace";

describe("buildStableBatchOverviewRows", () => {
  it("collapses source and allocated rows into one stable source-batch row", () => {
    const rows: BatchWorkspaceRow[] = [
      {
        id: "source-1",
        name: "Received AADS0001",
        licenseeId: "lic-1",
        batchKind: "RECEIVED_PARENT",
        startCode: "AADS0000001601",
        endCode: "AADS0000001700",
        totalCodes: 40,
        createdAt: "2026-03-03T10:00:00.000Z",
        updatedAt: "2026-03-06T10:00:00.000Z",
        printedAt: null,
        unassignedRemainingCodes: 40,
        remainingStartCode: "AADS0000001601",
        remainingEndCode: "AADS0000001700",
        licensee: { id: "lic-1", name: "sad", prefix: "AADS" },
      },
      {
        id: "alloc-1",
        name: "Received AADS0001 -> Factory A",
        licenseeId: "lic-1",
        manufacturerId: "manu-1",
        batchKind: "MANUFACTURER_CHILD",
        parentBatchId: "source-1",
        rootBatchId: "source-1",
        startCode: "AADS0000001501",
        endCode: "AADS0000001600",
        totalCodes: 100,
        createdAt: "2026-03-06T09:00:00.000Z",
        updatedAt: "2026-03-06T09:00:00.000Z",
        printedAt: null,
        printableCodes: 57,
        printedCodes: 43,
        redeemedCodes: 0,
        blockedCodes: 0,
        manufacturer: { id: "manu-1", name: "Factory A", email: "a@example.com" },
        licensee: { id: "lic-1", name: "sad", prefix: "AADS" },
      },
      {
        id: "alloc-2",
        name: "Received AADS0001 -> Factory B",
        licenseeId: "lic-1",
        manufacturerId: "manu-2",
        batchKind: "MANUFACTURER_CHILD",
        parentBatchId: "source-1",
        rootBatchId: "source-1",
        startCode: "AADS0000001401",
        endCode: "AADS0000001500",
        totalCodes: 100,
        createdAt: "2026-03-05T09:00:00.000Z",
        updatedAt: "2026-03-05T09:00:00.000Z",
        printedAt: null,
        printableCodes: 10,
        printedCodes: 90,
        redeemedCodes: 2,
        blockedCodes: 1,
        manufacturer: { id: "manu-2", name: "Factory B", email: "b@example.com" },
        licensee: { id: "lic-1", name: "sad", prefix: "AADS" },
      },
    ];

    const [group] = buildStableBatchOverviewRows(rows);
    expect(group).toBeTruthy();
    expect(group.sourceBatchId).toBe("source-1");
    expect(group.originalTotalCodes).toBe(240);
    expect(group.remainingUnassignedCodes).toBe(40);
    expect(group.assignedCodes).toBe(200);
    expect(group.pendingPrintableCodes).toBe(67);
    expect(group.printedCodes).toBe(133);
    expect(group.redeemedCodes).toBe(2);
    expect(group.blockedCodes).toBe(1);
    expect(group.manufacturerCount).toBe(2);
    expect(group.sourceOriginalRangeStart).toBe("AADS0000001401");
    expect(group.sourceOriginalRangeEnd).toBe("AADS0000001700");
    expect(group.manufacturerSummary[0].manufacturerName).toBe("Factory A");
  });
});
