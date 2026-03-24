import { useQuery } from "@tanstack/react-query";

import apiClient from "@/lib/api-client";
import { unwrapApiResponse, unwrapArrayResponse } from "@/lib/api/query-utils";
import { queryKeys } from "@/lib/query-keys";

import type { AuditLogDTO, DashboardStatsDTO, QrStatsDTO } from "../../../shared/contracts/dashboard";

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
        summary: unwrapApiResponse<DashboardStatsDTO>(summaryResponse, "Failed to load dashboard stats"),
        qrStats: unwrapApiResponse<QrStatsDTO>(qrStatsResponse, "Failed to load QR stats"),
      };
    },
  });
}

export function useDashboardAuditLogs(enabled: boolean, limit = 5) {
  return useQuery({
    queryKey: queryKeys.dashboard.audit(limit),
    enabled,
    queryFn: async (): Promise<AuditLogDTO[]> => {
      const response = await apiClient.getAuditLogs({ limit });
      const payload = unwrapApiResponse<unknown>(response, "Failed to load dashboard activity");
      if (Array.isArray(payload)) return payload as AuditLogDTO[];
      return Array.isArray((payload as { logs?: unknown[] })?.logs) ? ((payload as { logs: AuditLogDTO[] }).logs ?? []) : [];
    },
  });
}
