import { useQuery } from "@tanstack/react-query";
import { z } from "zod";

import apiClient from "@/lib/api-client";
import type { ApiResponse } from "@/lib/api-client";
import { parseWithSchema, unwrapParsedApiResponse } from "@/lib/api/query-utils";
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
  summary: DashboardStatsDTO;
  qrStats: QrStatsDTO;
  refreshPaused?: boolean;
};

type DashboardAuditLogsResult = {
  logs: AuditLogDTO[];
  refreshPaused?: boolean;
};

const isPausedResponse = (response: ApiResponse<unknown>) =>
  Boolean(response.success && response.degraded && String(response.code || "").toUpperCase() === "RATE_LIMITED");

export function useDashboardStats(licenseeId?: string) {
  return useQuery({
    queryKey: queryKeys.dashboard.stats(licenseeId),
    queryFn: async (): Promise<DashboardStatsResult> => {
      const [summaryResponse, qrStatsResponse] = await Promise.all([
        apiClient.getDashboardStats(licenseeId),
        apiClient.getQRStats(licenseeId),
      ]);

      return {
        summary: unwrapParsedApiResponse(summaryResponse, dashboardStatsSchema, "Failed to load dashboard stats"),
        qrStats: unwrapParsedApiResponse(qrStatsResponse, qrStatsSchema, "Failed to load QR stats"),
        refreshPaused: isPausedResponse(summaryResponse) || isPausedResponse(qrStatsResponse),
      };
    },
  });
}

export function useDashboardAuditLogs(enabled: boolean, limit = 5) {
  return useQuery({
    queryKey: queryKeys.dashboard.audit(limit),
    enabled,
    queryFn: async (): Promise<DashboardAuditLogsResult> => {
      const response = await apiClient.getAuditLogs({ limit });
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
