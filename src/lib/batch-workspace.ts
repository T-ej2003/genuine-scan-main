export type BatchWorkspaceRow = {
  id: string;
  name: string;
  licenseeId: string;
  manufacturerId?: string | null;
  batchKind?: "RECEIVED_PARENT" | "MANUFACTURER_CHILD";
  parentBatchId?: string | null;
  rootBatchId?: string | null;
  startCode: string;
  endCode: string;
  totalCodes: number;
  printedAt: string | null;
  createdAt: string;
  updatedAt?: string;
  licensee?: { id: string; name: string; prefix: string } | null;
  manufacturer?: { id: string; name: string; email: string } | null;
  availableCodes?: number;
  unassignedRemainingCodes?: number;
  assignedCodes?: number;
  printableCodes?: number;
  printedCodes?: number;
  redeemedCodes?: number;
  blockedCodes?: number;
  remainingStartCode?: string | null;
  remainingEndCode?: string | null;
};

export type BatchWorkspaceAllocation = {
  batchId: string;
  batchName: string;
  manufacturerId: string;
  manufacturerName: string;
  manufacturerEmail?: string | null;
  allocatedCodes: number;
  printableCodes: number;
  printedCodes: number;
  redeemedCodes: number;
  blockedCodes: number;
  createdAt: string;
  batchRangeStart: string;
  batchRangeEnd: string;
  currentRangeStart?: string | null;
  currentRangeEnd?: string | null;
};

export type StableBatchOverviewRow = {
  sourceBatchId: string;
  focusBatchId: string;
  sourceBatchName: string;
  sourceBatchRow: BatchWorkspaceRow | null;
  licensee?: { id: string; name: string; prefix: string } | null;
  sourceCreatedAt: string;
  sourceUpdatedAt: string;
  sourceOriginalRangeStart: string;
  sourceOriginalRangeEnd: string;
  originalTotalCodes: number;
  remainingUnassignedCodes: number;
  remainingRangeStart?: string | null;
  remainingRangeEnd?: string | null;
  assignedCodes: number;
  pendingPrintableCodes: number;
  printedCodes: number;
  redeemedCodes: number;
  blockedCodes: number;
  manufacturerCount: number;
  allocations: BatchWorkspaceAllocation[];
  manufacturerSummary: BatchWorkspaceAllocation[];
  printedAt?: string | null;
};

type BatchWorkspaceGroup = {
  sourceBatchId: string;
  focusBatchId: string;
  sourceBatchName: string;
  sourceBatchRow: BatchWorkspaceRow | null;
  licensee?: { id: string; name: string; prefix: string } | null;
  sourceCreatedAt: string;
  sourceUpdatedAt: string;
  sourceOriginalRangeStart: string | null;
  sourceOriginalRangeEnd: string | null;
  originalTotalCodes: number;
  remainingUnassignedCodes: number;
  remainingRangeStart: string | null;
  remainingRangeEnd: string | null;
  assignedCodes: number;
  pendingPrintableCodes: number;
  printedCodes: number;
  redeemedCodes: number;
  blockedCodes: number;
  allocations: BatchWorkspaceAllocation[];
  allocationsByManufacturer: Map<string, BatchWorkspaceAllocation>;
  latestTouchedAt: string;
  printedAt?: string | null;
};

const compareCode = (left?: string | null, right?: string | null) => {
  const a = String(left || "").trim();
  const b = String(right || "").trim();
  if (!a && !b) return 0;
  if (!a) return 1;
  if (!b) return -1;
  return a.localeCompare(b, undefined, { numeric: true, sensitivity: "base" });
};

const minCode = (current: string | null, next?: string | null) => {
  const value = String(next || "").trim();
  if (!value) return current;
  if (!current) return value;
  return compareCode(current, value) <= 0 ? current : value;
};

const maxCode = (current: string | null, next?: string | null) => {
  const value = String(next || "").trim();
  if (!value) return current;
  if (!current) return value;
  return compareCode(current, value) >= 0 ? current : value;
};

const asNumber = (value: unknown) => {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : 0;
};

const batchSourceKey = (row: BatchWorkspaceRow) => String(row.rootBatchId || row.parentBatchId || row.id).trim();

export const buildStableBatchOverviewRows = (rows: BatchWorkspaceRow[]) => {
  const groups = new Map<string, BatchWorkspaceGroup>();

  for (const row of rows) {
    const groupKey = batchSourceKey(row);
    const current: BatchWorkspaceGroup =
      groups.get(groupKey) ||
      {
        sourceBatchId: groupKey,
        focusBatchId: row.id,
        sourceBatchName: row.name,
        sourceBatchRow: null,
        licensee: row.licensee,
        sourceCreatedAt: row.createdAt,
        sourceUpdatedAt: row.updatedAt || row.createdAt,
        sourceOriginalRangeStart: null,
        sourceOriginalRangeEnd: null,
        originalTotalCodes: 0,
        remainingUnassignedCodes: 0,
        remainingRangeStart: null,
        remainingRangeEnd: null,
        assignedCodes: 0,
        pendingPrintableCodes: 0,
        printedCodes: 0,
        redeemedCodes: 0,
        blockedCodes: 0,
        allocations: [],
        allocationsByManufacturer: new Map<string, BatchWorkspaceAllocation>(),
        latestTouchedAt: row.updatedAt || row.createdAt,
        printedAt: null,
      };

    current.licensee = current.licensee || row.licensee;
    current.originalTotalCodes += asNumber(row.totalCodes);
    current.sourceOriginalRangeStart = minCode(current.sourceOriginalRangeStart, row.startCode);
    current.sourceOriginalRangeEnd = maxCode(current.sourceOriginalRangeEnd, row.endCode);

    const rowTouchedAt = row.updatedAt || row.createdAt;
    if (new Date(rowTouchedAt).getTime() >= new Date(current.latestTouchedAt).getTime()) {
      current.latestTouchedAt = rowTouchedAt;
      current.focusBatchId = row.id;
    }

    if (!row.manufacturerId || row.batchKind !== "MANUFACTURER_CHILD") {
      current.sourceBatchRow = row;
      current.sourceBatchName = row.name;
      current.sourceCreatedAt = row.createdAt;
      current.sourceUpdatedAt = row.updatedAt || row.createdAt;
      current.remainingUnassignedCodes = asNumber(row.unassignedRemainingCodes ?? row.availableCodes ?? row.totalCodes);
      current.remainingRangeStart = row.remainingStartCode || null;
      current.remainingRangeEnd = row.remainingEndCode || null;
      current.printedAt = row.printedAt;
    } else {
      const allocation: BatchWorkspaceAllocation = {
        batchId: row.id,
        batchName: row.name,
        manufacturerId: String(row.manufacturer?.id || row.manufacturerId || "").trim(),
        manufacturerName: row.manufacturer?.name || "Assigned manufacturer",
        manufacturerEmail: row.manufacturer?.email || null,
        allocatedCodes: asNumber(row.totalCodes),
        printableCodes: asNumber(row.printableCodes ?? row.availableCodes),
        printedCodes: asNumber(row.printedCodes),
        redeemedCodes: asNumber(row.redeemedCodes),
        blockedCodes: asNumber(row.blockedCodes),
        createdAt: row.createdAt,
        batchRangeStart: row.startCode,
        batchRangeEnd: row.endCode,
        currentRangeStart: row.remainingStartCode || null,
        currentRangeEnd: row.remainingEndCode || null,
      };
      current.allocations.push(allocation);
      current.assignedCodes += allocation.allocatedCodes;
      current.pendingPrintableCodes += allocation.printableCodes;
      current.printedCodes += allocation.printedCodes;
      current.redeemedCodes += allocation.redeemedCodes;
      current.blockedCodes += allocation.blockedCodes;

      const manufacturerKey = allocation.manufacturerId || allocation.batchId;
      const existing = current.allocationsByManufacturer.get(manufacturerKey);
      if (existing) {
        existing.allocatedCodes += allocation.allocatedCodes;
        existing.printableCodes += allocation.printableCodes;
        existing.printedCodes += allocation.printedCodes;
        existing.redeemedCodes += allocation.redeemedCodes;
        existing.blockedCodes += allocation.blockedCodes;
        existing.currentRangeStart = minCode(existing.currentRangeStart || null, allocation.currentRangeStart || allocation.batchRangeStart);
        existing.currentRangeEnd = maxCode(existing.currentRangeEnd || null, allocation.currentRangeEnd || allocation.batchRangeEnd);
        if (new Date(allocation.createdAt).getTime() > new Date(existing.createdAt).getTime()) {
          existing.createdAt = allocation.createdAt;
        }
      } else {
        current.allocationsByManufacturer.set(manufacturerKey, { ...allocation });
      }
    }

    groups.set(groupKey, current);
  }

  return Array.from(groups.values())
    .map((group) => ({
      sourceBatchId: group.sourceBatchId,
      focusBatchId: group.sourceBatchRow?.id || group.focusBatchId,
      sourceBatchName: group.sourceBatchName,
      sourceBatchRow: group.sourceBatchRow,
      licensee: group.licensee,
      sourceCreatedAt: group.sourceCreatedAt,
      sourceUpdatedAt: group.sourceUpdatedAt,
      sourceOriginalRangeStart: group.sourceOriginalRangeStart || group.sourceBatchRow?.startCode || "—",
      sourceOriginalRangeEnd: group.sourceOriginalRangeEnd || group.sourceBatchRow?.endCode || "—",
      originalTotalCodes: group.originalTotalCodes,
      remainingUnassignedCodes: group.remainingUnassignedCodes,
      remainingRangeStart: group.remainingRangeStart,
      remainingRangeEnd: group.remainingRangeEnd,
      assignedCodes: group.assignedCodes,
      pendingPrintableCodes: group.pendingPrintableCodes,
      printedCodes: group.printedCodes,
      redeemedCodes: group.redeemedCodes,
      blockedCodes: group.blockedCodes,
      manufacturerCount: group.allocationsByManufacturer.size,
      allocations: group.allocations.sort((left, right) => new Date(right.createdAt).getTime() - new Date(left.createdAt).getTime()),
      manufacturerSummary: Array.from(group.allocationsByManufacturer.values()).sort(
        (left, right) => right.allocatedCodes - left.allocatedCodes || left.manufacturerName.localeCompare(right.manufacturerName)
      ),
      printedAt: group.printedAt,
    }))
    .sort((left, right) => new Date(right.sourceUpdatedAt).getTime() - new Date(left.sourceUpdatedAt).getTime());
};
