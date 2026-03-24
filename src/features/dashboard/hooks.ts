import { useQuery } from "@tanstack/react-query";
import { z } from "zod";

import apiClient from "@/lib/api-client";
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
};

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
      };
    },
  });
}

export function useDashboardAuditLogs(enabled: boolean, limit = 5) {
  return useQuery({
    queryKey: queryKeys.dashboard.audit(limit),
    enabled,
    queryFn: async (): Promise<AuditLogDTO[]> => {
      const payload = unwrapParsedApiResponse(
        await apiClient.getAuditLogs({ limit }),
        auditLogArraySchema.or(z.object({ logs: auditLogArraySchema }).passthrough()),
        "Failed to load dashboard activity"
      );
      return Array.isArray(payload) ? payload : parseWithSchema(auditLogArraySchema, payload.logs || [], "Failed to load dashboard activity");
    },
  });
}
