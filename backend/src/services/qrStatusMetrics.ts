export type QrStatusCountMap = Record<string, number | null | undefined>;

const count = (counts: QrStatusCountMap, key: string) => Number(counts[key] || 0);

export const countDormantInventory = (counts: QrStatusCountMap) => count(counts, "DORMANT") + count(counts, "ACTIVE");

export const countAllocatedInventory = (counts: QrStatusCountMap) =>
  count(counts, "ALLOCATED") + count(counts, "ACTIVATED");

export const countPrintedInventory = (counts: QrStatusCountMap) => count(counts, "PRINTED");

export const countRedeemedInventory = (counts: QrStatusCountMap) =>
  count(counts, "REDEEMED") + count(counts, "SCANNED");

export const countBlockedInventory = (counts: QrStatusCountMap) => count(counts, "BLOCKED");

export const summarizeQrStatusCounts = (counts: QrStatusCountMap) => ({
  dormant: countDormantInventory(counts),
  allocated: countAllocatedInventory(counts),
  printed: countPrintedInventory(counts),
  redeemed: countRedeemedInventory(counts),
  blocked: countBlockedInventory(counts),
});
