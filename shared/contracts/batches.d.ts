export interface BatchDTO {
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
  licensee?: { id: string; name: string; prefix: string };
  manufacturer?: { id: string; name: string; email: string };
  _count?: { qrCodes: number };
  availableCodes?: number;
  unassignedRemainingCodes?: number;
  assignedCodes?: number;
  printableCodes?: number;
  printedCodes?: number;
  redeemedCodes?: number;
  blockedCodes?: number;
  remainingStartCode?: string | null;
  remainingEndCode?: string | null;
}

export interface ManufacturerDTO {
  id: string;
  name: string;
  email: string;
  isActive: boolean;
}

export interface BatchTraceEventDTO {
  id: string;
  eventType?: "COMMISSIONED" | "ASSIGNED" | "PRINTED" | "REDEEMED" | "BLOCKED";
  action?: string;
  sourceAction?: string | null;
  createdAt: string;
  details?: unknown;
  user?: { id: string; name?: string | null; email?: string | null } | null;
  manufacturer?: { id: string; name?: string | null; email?: string | null } | null;
  qrCode?: { id: string; code?: string | null } | null;
  userId?: string | null;
}

export interface BatchAllocationMapDTO {
  sourceBatchId: string;
  focusBatchId: string;
  sourceBatch: unknown | null;
  selectedBatch: unknown | null;
  allocations: unknown[];
  totals: {
    totalDistributedCodes: number;
    sourceRemainingCodes: number;
    pendingPrintableCodes: number;
    printedCodes: number;
  };
}
