import { useQuery } from "@tanstack/react-query";

import apiClient from "@/lib/api-client";
import { unwrapParsedApiResponse } from "@/lib/api/query-utils";
import { queryKeys } from "@/lib/query-keys";

import {
  batchAllocationMapSchema,
  batchArraySchema,
  manufacturerOptionArraySchema,
  type BatchAllocationMapDTO,
  type BatchDTO,
  type ManufacturerDTO,
} from "../../../shared/contracts/runtime/batches.ts";

export function useBatches(licenseeId?: string, enabled = true) {
  return useQuery({
    queryKey: queryKeys.batches.list(licenseeId),
    enabled,
    queryFn: async (): Promise<BatchDTO[]> =>
      unwrapParsedApiResponse(
        await apiClient.getBatches(licenseeId ? { licenseeId } : undefined),
        batchArraySchema,
        "Failed to load batches"
      ),
  });
}

export function useAssignableManufacturers(licenseeId?: string, enabled = true) {
  return useQuery({
    queryKey: queryKeys.batches.manufacturers(licenseeId),
    enabled,
    queryFn: async (): Promise<ManufacturerDTO[]> =>
      unwrapParsedApiResponse(
        await apiClient.getManufacturers({
          licenseeId,
          includeInactive: false,
        }),
        manufacturerOptionArraySchema,
        "Failed to load manufacturers"
      ),
  });
}

export function useBatchAllocationMap(batchId?: string, enabled = true) {
  return useQuery({
    queryKey: queryKeys.batches.allocationMap(batchId),
    enabled: enabled && Boolean(batchId),
    queryFn: async (): Promise<BatchAllocationMapDTO> =>
      unwrapParsedApiResponse(
        await apiClient.getBatchAllocationMap(String(batchId)),
        batchAllocationMapSchema,
        "Failed to load allocation map"
      ),
  });
}
