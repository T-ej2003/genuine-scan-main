import { PrintJobStatus, UserRole } from "@prisma/client";

import { AuthRequest } from "../middleware/auth";
import { getEffectiveLicenseeId } from "../middleware/tenantIsolation";
import { getRedisInstanceId, publishRedisJson, subscribeRedisJson } from "./redisService";

export type PrintJobRealtimeEvent = {
  printJobId: string;
  manufacturerId: string;
  licenseeId: string | null;
  batchId: string | null;
  type: string;
  reason: string;
  occurredAt: string;
  view?: any;
  patch?: Record<string, unknown>;
};

const PRINT_JOB_EVENT_CHANNEL = "mscqr:realtime:print-job";
const listeners = new Set<(event: PrintJobRealtimeEvent) => void>();
let printJobChannelReady = false;

const notifyListeners = (event: PrintJobRealtimeEvent) => {
  for (const listener of listeners) {
    try {
      listener(event);
    } catch {
      // Ignore listener failures.
    }
  }
};

export const onPrintJobRealtimeEvent = (listener: (event: PrintJobRealtimeEvent) => void) => {
  if (!printJobChannelReady) {
    printJobChannelReady = true;
    void subscribeRedisJson(PRINT_JOB_EVENT_CHANNEL, (payload) => {
      if (!payload || payload.origin === getRedisInstanceId()) return;
      if (payload.event) notifyListeners(payload.event as PrintJobRealtimeEvent);
    });
  }
  listeners.add(listener);
  return () => listeners.delete(listener);
};

export const publishPrintJobRealtimeEvent = (event: PrintJobRealtimeEvent) => {
  notifyListeners(event);
  void publishRedisJson(PRINT_JOB_EVENT_CHANNEL, {
    origin: getRedisInstanceId(),
    event,
  }).catch(() => undefined);
};

export const publishPrintJobViewEvent = async (params: {
  printJobId: string;
  manufacturerId: string;
  licenseeId?: string | null;
  batchId?: string | null;
  type: string;
  reason: string;
}) => {
  publishPrintJobRealtimeEvent({
    printJobId: params.printJobId,
    manufacturerId: params.manufacturerId,
    licenseeId: params.licenseeId || null,
    batchId: params.batchId || null,
    type: params.type,
    reason: params.reason,
    occurredAt: new Date().toISOString(),
  });
};

export const canUserReceivePrintJobEvent = (req: AuthRequest, event: PrintJobRealtimeEvent) => {
  const user = req.user;
  if (!user) return false;
  if (user.role === UserRole.SUPER_ADMIN || user.role === UserRole.PLATFORM_SUPER_ADMIN) {
    const scopedLicenseeId = getEffectiveLicenseeId(req);
    return !scopedLicenseeId || scopedLicenseeId === event.licenseeId;
  }
  if (
    user.role === UserRole.MANUFACTURER_ADMIN
  ) {
    return user.userId === event.manufacturerId;
  }
  return Boolean(user.licenseeId && event.licenseeId && user.licenseeId === event.licenseeId);
};

export const isRealtimeTerminalPrintStatus = (status?: string | null) =>
  [
    PrintJobStatus.CONFIRMED,
    PrintJobStatus.PARTIALLY_COMPLETED,
    PrintJobStatus.FAILED,
    PrintJobStatus.CANCELLED,
    PrintJobStatus.STOPPED,
  ].some((terminalStatus) => terminalStatus === status);
