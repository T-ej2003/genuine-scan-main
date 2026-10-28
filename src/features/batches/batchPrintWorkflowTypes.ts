import type { BatchRow } from "./types";

type ToastLike = (options: { title?: string; description?: string; variant?: "default" | "destructive" }) => unknown;

export type ReleaseApprovalState = {
  approvalRequired: boolean;
  approvalId: string;
  status: string;
  expiresAt?: string | null;
  threshold?: number | null;
};

export type PrintControlAction = "pause" | "stop";

export type UseBatchPrintWorkflowParams = {
  isManufacturer: boolean;
  userId?: string | null;
  toast: ToastLike;
  getAvailableInventory: (batch: BatchRow) => number;
  onBatchesChanged?: () => Promise<void> | void;
};
