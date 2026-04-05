import { useQuery } from "@tanstack/react-query";

import apiClient from "@/lib/api-client";
import { parseWithSchema, unwrapParsedApiResponse } from "@/lib/api/query-utils";
import { queryKeys } from "@/lib/query-keys";

import { z } from "zod";

import {
  incidentArraySchema,
  incidentDetailSchema,
  type IncidentDTO,
  type IncidentDetailDTO,
} from "../../../shared/contracts/runtime/incidents.ts";

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
      const payload = unwrapParsedApiResponse(
        await apiClient.getIncidents(filters),
        incidentArraySchema.or(z.object({ incidents: incidentArraySchema }).passthrough()),
        "Failed to load incidents"
      );
      return Array.isArray(payload) ? payload : parseWithSchema(incidentArraySchema, payload.incidents || [], "Failed to load incidents");
    },
  });
}

export function useIncident(id?: string, enabled = true) {
  return useQuery({
    queryKey: queryKeys.incidents.detail(id),
    enabled: enabled && Boolean(id),
    queryFn: async (): Promise<IncidentDetailDTO | null> =>
      unwrapParsedApiResponse(
        await apiClient.getIncidentById(String(id)),
        incidentDetailSchema.nullable(),
        "Failed to load incident detail"
      ),
  });
}
