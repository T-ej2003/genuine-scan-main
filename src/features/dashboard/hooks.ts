import { useQuery } from "@tanstack/react-query";
import { z } from "zod";

import apiClient from "@/lib/api-client";
import { useActivePrintSessionSuppression } from "@/lib/active-print-session";
import type { ApiResponse } from "@/lib/api-client";
import { parseWithSchema, unwrapParsedApiResponse } from "@/lib/api/query-utils";
import { pollingPolicy } from "@/lib/query-polling-policy";
import { queryKeys } from "@/lib/query-keys";

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

export function useDashboardStats(licenseeId?: string) {
  const activePrintSuppressed = useActivePrintSessionSuppression();
  return useQuery({
    queryKey: queryKeys.dashboard.stats(licenseeId),
    enabled: !activePrintSuppressed,
    staleTime: pollingPolicy.dashboardFallbackMs,
    refetchOnWindowFocus: false,
    queryFn: async (): Promise<DashboardStatsResult> => {
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

export function useDashboardAuditLogs(enabled: boolean, limit = 5, licenseeId?: string) {
  const activePrintSuppressed = useActivePrintSessionSuppression();
  return useQuery({
    queryKey: [...queryKeys.dashboard.audit(limit), licenseeId || null],
    enabled: enabled && Boolean(licenseeId) && !activePrintSuppressed,
    staleTime: pollingPolicy.dashboardFallbackMs,
    refetchOnWindowFocus: false,
    queryFn: async (): Promise<DashboardAuditLogsResult> => {
      if (!licenseeId) throw new Error("Select a brand before loading audit history");
      const response = await apiClient.getAuditLogs({ limit, licenseeId, purpose: "dashboard-activity-review" });
      const payload = unwrapParsedApiResponse(
        response,
        auditLogArraySchema.or(z.object({ logs: auditLogArraySchema }).passthrough()),
        "Failed to load dashboard activity"
      );
      return {
        logs: Array.isArray(payload)
          ? payload
          : parseWithSchema(auditLogArraySchema, payload.logs || [], "Failed to load dashboard activity"),
        refreshPaused: isPausedResponse(response),
      };
    },
  });
}
