import { useQuery } from "@tanstack/react-query";

import apiClient from "@/lib/api-client";
import { unwrapApiResponse } from "@/lib/api/query-utils";
import { queryKeys } from "@/lib/query-keys";

import type { IncidentDTO, IncidentDetailDTO } from "../../../shared/contracts/incidents";

type IncidentFilters = {
  status?: string;
  severity?: string;
  qr?: string;
  search?: string;
  dateFrom?: string;
  dateTo?: string;
  assignedTo?: string;
  licenseeId?: string;
  limit?: number;
  offset?: number;
};

export function useIncidents(filters: IncidentFilters, enabled = true) {
  return useQuery({
    queryKey: queryKeys.incidents.list(filters),
    enabled,
    queryFn: async (): Promise<IncidentDTO[]> => {
      const response = await apiClient.getIncidents(filters);
      const payload = unwrapApiResponse<unknown>(response, "Failed to load incidents");
      if (Array.isArray(payload)) return payload as IncidentDTO[];
      return Array.isArray((payload as { incidents?: unknown[] })?.incidents)
        ? ((payload as { incidents: IncidentDTO[] }).incidents ?? [])
        : [];
    },
  });
}

export function useIncident(id?: string, enabled = true) {
  return useQuery({
    queryKey: queryKeys.incidents.detail(id),
    enabled: enabled && Boolean(id),
    queryFn: async (): Promise<IncidentDetailDTO | null> =>
      unwrapApiResponse<IncidentDetailDTO | null>(
        await apiClient.getIncidentById(String(id)),
        "Failed to load incident detail"
      ),
  });
}
