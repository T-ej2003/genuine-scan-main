import { useQuery } from "@tanstack/react-query";

import apiClient from "@/lib/api-client";
import { unwrapApiResponse, unwrapArrayResponse } from "@/lib/api/query-utils";
import { queryKeys } from "@/lib/query-keys";

import type { BatchAllocationMapDTO, BatchDTO, ManufacturerDTO } from "../../../shared/contracts/batches";

export function useBatches(licenseeId?: string, enabled = true) {
  return useQuery({
    queryKey: queryKeys.batches.list(licenseeId),
    enabled,
    queryFn: async (): Promise<BatchDTO[]> =>
      unwrapArrayResponse<BatchDTO>(
        await apiClient.getBatches(licenseeId ? { licenseeId } : undefined),
        "Failed to load batches"
      ),
  });
}

export function useAssignableManufacturers(licenseeId?: string, enabled = true) {
  return useQuery({
    queryKey: queryKeys.batches.manufacturers(licenseeId),
    enabled,
    queryFn: async (): Promise<ManufacturerDTO[]> =>
      unwrapArrayResponse<ManufacturerDTO>(
        await apiClient.getManufacturers({
          licenseeId,
          includeInactive: false,
        }),
        "Failed to load manufacturers"
      ),
  });
}

export function useBatchAllocationMap(batchId?: string, enabled = true) {
  return useQuery({
    queryKey: queryKeys.batches.allocationMap(batchId),
    enabled: enabled && Boolean(batchId),
    queryFn: async (): Promise<BatchAllocationMapDTO> =>
      unwrapApiResponse<BatchAllocationMapDTO>(
        await apiClient.getBatchAllocationMap(String(batchId)),
        "Failed to load allocation map"
      ),
  });
}
