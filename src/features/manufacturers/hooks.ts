import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import apiClient from "@/lib/api-client";
import { unwrapArrayResponse } from "@/lib/api/query-utils";
import { emitMutationEvent } from "@/lib/mutation-events";
import { queryKeys } from "@/lib/query-keys";

import {
  emptyManufacturerStats,
  normalizeBatchRows,
  normalizeManufacturerRows,
  type LicenseeOption,
  type ManufacturerDirectoryData,
} from "@/features/manufacturers/types";

export type InviteManufacturerInput = {
  email: string;
  name: string;
  licenseeId: string;
};

export type InviteManufacturerResult = {
  linkAction?: "LINKED_EXISTING" | "ALREADY_LINKED" | string;
};

async function invalidateManufacturerQueries(
  invalidateQueries: ReturnType<typeof useQueryClient>["invalidateQueries"]
) {
  await Promise.all([
    invalidateQueries({ queryKey: queryKeys.manufacturers.licensees() }),
    invalidateQueries({ queryKey: queryKeys.manufacturers.directory() }),
    invalidateQueries({ queryKey: ["batches"] }),
  ]);
}

export function useManufacturerLicensees(enabled: boolean) {
  return useQuery({
    queryKey: queryKeys.manufacturers.licensees(),
    enabled,
    queryFn: async (): Promise<LicenseeOption[]> => {
      const rows = unwrapArrayResponse<Record<string, unknown>>(
        await apiClient.getLicensees(),
        "Failed to load licensees"
      );

      return rows.flatMap((row) => {
        const id = String(row.id || "").trim();
        const name = String(row.name || "").trim();
        const prefix = String(row.prefix || "").trim();
        if (!id || !name) return [];

        return [{ id, name, prefix }];
      });
    },
  });
}

export function useManufacturerDirectory(licenseeId?: string, enabled = true) {
  return useQuery({
    queryKey: queryKeys.manufacturers.directory(licenseeId),
    enabled: enabled && Boolean(licenseeId),
    queryFn: async (): Promise<ManufacturerDirectoryData> => {
      const scope = String(licenseeId || "").trim() || undefined;
      const [manufacturerResponse, batchResponse] = await Promise.all([
        apiClient.getManufacturers({
          licenseeId: scope,
          includeInactive: true,
        }),
        apiClient.getBatches(scope ? { licenseeId: scope } : undefined),
      ]);

      let manufacturers = manufacturerResponse.success
        ? normalizeManufacturerRows(Array.isArray(manufacturerResponse.data) ? manufacturerResponse.data : [])
        : [];

      if (manufacturers.length === 0) {
        const fallback = await apiClient.getUsers({ licenseeId: scope, role: "MANUFACTURER" });
        if (fallback.success) {
          manufacturers = normalizeManufacturerRows(Array.isArray(fallback.data) ? fallback.data : []);
        } else if (!manufacturerResponse.success) {
          throw new Error(manufacturerResponse.error || fallback.error || "Failed to load manufacturers");
        }
      }

      if (!batchResponse.success) {
        throw new Error(batchResponse.error || "Failed to load manufacturer activity");
      }

      const batches = normalizeBatchRows(Array.isArray(batchResponse.data) ? batchResponse.data : []);
      const statsById = Object.fromEntries(manufacturers.map((manufacturer) => [manufacturer.id, emptyManufacturerStats()]));

      for (const batch of batches) {
        const manufacturerId = String(batch.manufacturerId || "").trim();
        if (!manufacturerId || !statsById[manufacturerId]) continue;

        const stats = statsById[manufacturerId];
        stats.assignedBatches += 1;
        stats.assignedCodes += Number(batch.totalCodes || 0);
        if (batch.printedAt) stats.printedBatches += 1;
        else stats.pendingPrintBatches += 1;

        if (!stats.lastBatchAt || (batch.createdAt && new Date(batch.createdAt) > new Date(stats.lastBatchAt))) {
          stats.lastBatchAt = batch.createdAt || stats.lastBatchAt;
        }

        stats.recentBatches.push(batch);
      }

      for (const stats of Object.values(statsById)) {
        stats.recentBatches.sort((left, right) => {
          const leftTime = left.createdAt ? new Date(left.createdAt).getTime() : 0;
          const rightTime = right.createdAt ? new Date(right.createdAt).getTime() : 0;
          return rightTime - leftTime;
        });
        stats.recentBatches = stats.recentBatches.slice(0, 5);
      }

      return {
        manufacturers,
        statsById,
      };
    },
  });
}

export function useInviteManufacturerMutation() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (input: InviteManufacturerInput): Promise<InviteManufacturerResult> => {
      const response = await apiClient.inviteUser({
        email: input.email.trim().toLowerCase(),
        name: input.name.trim(),
        role: "MANUFACTURER",
        licenseeId: input.licenseeId,
        allowExistingInvitedUser: true,
      });

      if (!response.success) {
        throw new Error(response.error || "Failed to invite manufacturer");
      }

      return ((response.data || {}) as InviteManufacturerResult) || {};
    },
    onSuccess: async () => {
      emitMutationEvent({ endpoint: "/users/invite", method: "POST" });
      await invalidateManufacturerQueries(queryClient.invalidateQueries.bind(queryClient));
    },
  });
}

export function useDeactivateManufacturerMutation() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (manufacturerId: string) => {
      const response = await apiClient.deactivateManufacturer(manufacturerId);
      if (!response.success) throw new Error(response.error || "Failed to deactivate manufacturer");
      return response.data;
    },
    onSuccess: async () => {
      emitMutationEvent({ endpoint: "/manufacturers/deactivate", method: "POST" });
      await invalidateManufacturerQueries(queryClient.invalidateQueries.bind(queryClient));
    },
  });
}

export function useRestoreManufacturerMutation() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (manufacturerId: string) => {
      const response = await apiClient.restoreManufacturer(manufacturerId);
      if (!response.success) throw new Error(response.error || "Failed to restore manufacturer");
      return response.data;
    },
    onSuccess: async () => {
      emitMutationEvent({ endpoint: "/manufacturers/restore", method: "POST" });
      await invalidateManufacturerQueries(queryClient.invalidateQueries.bind(queryClient));
    },
  });
}

export function useDeleteManufacturerMutation() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (manufacturerId: string) => {
      const response = await apiClient.hardDeleteManufacturer(manufacturerId);
      if (!response.success) throw new Error(response.error || "Failed to delete manufacturer");
      return response.data;
    },
    onSuccess: async () => {
      emitMutationEvent({ endpoint: "/manufacturers/hard-delete", method: "DELETE" });
      await invalidateManufacturerQueries(queryClient.invalidateQueries.bind(queryClient));
    },
  });
}
