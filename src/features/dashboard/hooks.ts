import { useQuery } from "@tanstack/react-query";
import { z } from "zod";

import apiClient from "@/lib/api-client";
import { useActivePrintSessionSuppression } from "@/lib/active-print-session";
import type { ApiResponse } from "@/lib/api-client";
import { unwrapParsedApiResponse } from "@/lib/api/query-utils";
import { pollingPolicy } from "@/lib/query-polling-policy";
import { queryKeys } from "@/lib/query-keys";
import { getAuthenticatedStreamScope } from "@/lib/api/request-coordinator";

import {
  auditLogArraySchema,
  dashboardStatsSchema,
  qrStatsSchema,
  type AuditLogDTO,
  type DashboardStatsDTO,
  type QrStatsDTO,
} from "../../../shared/contracts/runtime/dashboard.ts";

type DashboardStatsResult = {
  summary: DashboardStatsDTO | null;
  qrStats: QrStatsDTO | null;
  summaryError?: string;
  qrStatsError?: string;
  refreshPaused?: boolean;
};

type DashboardAuditLogsResult = {
  logs: AuditLogDTO[];
  refreshPaused?: boolean;
};

const isPausedResponse = (response: ApiResponse<unknown>) =>
  Boolean(response.success && response.degraded && String(response.code || "").toUpperCase() === "RATE_LIMITED");

export function useDashboardStats(licenseeId?: string, manufacturer = false) {
  const activePrintSuppressed = useActivePrintSessionSuppression();
  return useQuery({
    queryKey: [...queryKeys.dashboard.stats(licenseeId), getAuthenticatedStreamScope()],
    enabled: !activePrintSuppressed,
    staleTime: pollingPolicy.dashboardFallbackMs,
    refetchOnWindowFocus: false,
    queryFn: async (): Promise<DashboardStatsResult> => {
      if (manufacturer) {
        const response = await apiClient.getDashboardStats(licenseeId);
        if (response.degraded && !isPausedResponse(response)) {
          throw new Error("Operations overview is temporarily unavailable.");
        }
        const summary = unwrapParsedApiResponse(response, dashboardStatsSchema, "Failed to load dashboard stats");
        const qrStats = summary.qrStats;
        return {
          summary,
          qrStats: qrStats?.total == null ? null : qrStats,
          qrStatsError: qrStats?.total == null ? "QR statistics are temporarily unavailable." : undefined,
          refreshPaused: isPausedResponse(response),
        };
      }
      const [summary, qrStats] = await Promise.allSettled([
        apiClient.getDashboardStats(licenseeId).then((response) => ({
          data: unwrapParsedApiResponse(response, dashboardStatsSchema, "Failed to load dashboard stats"),
          refreshPaused: isPausedResponse(response),
        })),
        apiClient.getQRStats(licenseeId).then((response) => ({
          data: unwrapParsedApiResponse(response, qrStatsSchema, "Failed to load QR stats"),
          refreshPaused: isPausedResponse(response),
        })),
      ]);

      return {
        summary: summary.status === "fulfilled" ? summary.value.data : null,
        qrStats: qrStats.status === "fulfilled" ? qrStats.value.data : null,
        summaryError: summary.status === "rejected" ? "Operations overview is temporarily unavailable." : undefined,
        qrStatsError: qrStats.status === "rejected" ? "QR statistics are temporarily unavailable." : undefined,
        refreshPaused: (summary.status === "fulfilled" && summary.value.refreshPaused) ||
          (qrStats.status === "fulfilled" && qrStats.value.refreshPaused),
      };
    },
  });
}

export function useDashboardAuditLogs(enabled: boolean, limit = 5, licenseeId?: string, personal = false) {
  const activePrintSuppressed = useActivePrintSessionSuppression();
  return useQuery({
    queryKey: [...queryKeys.dashboard.audit(limit), licenseeId || null, getAuthenticatedStreamScope(), ...(personal ? ["personal"] : [])],
    enabled: enabled && Boolean(licenseeId) && !activePrintSuppressed,
    staleTime: pollingPolicy.dashboardFallbackMs,
    refetchOnWindowFocus: false,
    queryFn: async (): Promise<DashboardAuditLogsResult> => {
      if (!licenseeId) throw new Error("Select a brand before loading audit history");
      const response = await apiClient.getAuditLogs({
        limit, licenseeId, purpose: personal ? "dashboard-personal-activity" : "dashboard-activity-review",
      });
      if (personal && response.degraded && !isPausedResponse(response)) {
        throw new Error("Recent activity is temporarily unavailable.");
      }
      const payload = unwrapParsedApiResponse(
        response,
        auditLogArraySchema.or(z.object({ logs: auditLogArraySchema }).passthrough()),
        "Failed to load dashboard activity"
      );
      return {
        logs: Array.isArray(payload) ? payload : payload.logs,
        refreshPaused: isPausedResponse(response),
      };
    },
  });
}
