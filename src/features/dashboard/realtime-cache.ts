import type { QueryClient } from "@tanstack/react-query";

import { queryKeys } from "@/lib/query-keys";
import { getAuthenticatedStreamScope } from "@/lib/api/request-coordinator";
import type { AuditLogDTO, DashboardStatsDTO, QrStatsDTO } from "../../../shared/contracts/runtime/dashboard.ts";

export const normalizeDashboardSummary = (payload: Record<string, unknown>): DashboardStatsDTO => {
  const summary = payload.summary && typeof payload.summary === "object" ? (payload.summary as Record<string, unknown>) : {};
  return {
    totalQRCodes: Number(summary.totalQRCodes ?? 0),
    activeLicensees: Number(summary.activeLicensees ?? 0),
    manufacturers: Number(summary.manufacturers ?? 0),
    totalBatches: Number(summary.totalBatches ?? 0),
  };
};

export const applyDashboardSnapshotToCache = (
  queryClient: QueryClient,
  scopedLicenseeId: string | undefined,
  payload: Record<string, unknown>
) => {
  const summary = normalizeDashboardSummary(payload);
  const queryKey = [...queryKeys.dashboard.stats(scopedLicenseeId), getAuthenticatedStreamScope()];
  const previous = queryClient.getQueryData<{ qrStats?: QrStatsDTO | null }>(queryKey)?.qrStats;
  const qrStats = (payload.qrStats || {}) as QrStatsDTO;
  if (qrStats.scansToday == null && previous?.scansToday != null) qrStats.scansToday = previous.scansToday;
  queryClient.setQueryData(queryKey, { summary, qrStats, refreshPaused: false });
  return { summary, qrStats };
};

export const applyAuditDeltaToCache = (
  queryClient: QueryClient,
  log: AuditLogDTO,
  latestLogs: AuditLogDTO[],
  scopedLicenseeId?: string
) => {
  const logs = [log, ...latestLogs.filter((entry) => entry.id !== log.id)]
    .sort((left, right) => Date.parse(right.createdAt) - Date.parse(left.createdAt))
    .slice(0, 10);
  queryClient.setQueryData([...queryKeys.dashboard.audit(5), scopedLicenseeId || null, getAuthenticatedStreamScope()], { logs, refreshPaused: false });
  return logs;
};
