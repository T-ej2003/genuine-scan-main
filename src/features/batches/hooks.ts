import { useQuery } from "@tanstack/react-query";

import apiClient from "@/lib/api-client";
import { unwrapParsedApiResponse } from "@/lib/api/query-utils";
import { queryKeys } from "@/lib/query-keys";

import {
  batchAllocationMapSchema,
  batchArraySchema,
  manufacturerOptionArraySchema,
  type BatchAllocationMapDTO,
} from "../../../shared/contracts/runtime/batches.ts";

export function useBatches(licenseeId?: string, enabled = true, offset = 0) {
  return useQuery({
    queryKey: [...queryKeys.batches.list(licenseeId), offset],
    enabled,
    queryFn: async () => {
      const response = await apiClient.getBatches({ licenseeId, limit: 100, offset });
      return {
        rows: unwrapParsedApiResponse(response, batchArraySchema, "Failed to load batches"),
        meta: response.meta,
      };
    },
  });
}

export function useAssignableManufacturers(licenseeId?: string, enabled = true, offset = 0) {
  return useQuery({
    queryKey: [...queryKeys.batches.manufacturers(licenseeId), offset],
    enabled,
    queryFn: async () => {
      const response = await apiClient.getManufacturers({ licenseeId, includeInactive: false, limit: 100, offset });
      return { rows: unwrapParsedApiResponse(response, manufacturerOptionArraySchema, "Failed to load manufacturers"), meta: response.meta };
    },
  });
}

export function useBatchAllocationMap(batchId?: string, enabled = true, licenseeId?: string) {
  return useQuery({
    queryKey: [...queryKeys.batches.allocationMap(batchId), licenseeId || null],
    enabled: enabled && Boolean(batchId),
    queryFn: async (): Promise<BatchAllocationMapDTO> =>
      unwrapParsedApiResponse(
        await apiClient.getBatchAllocationMap(String(batchId), licenseeId),
        batchAllocationMapSchema,
        "Failed to load allocation map"
      ),
  });
}
