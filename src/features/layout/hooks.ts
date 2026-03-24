import { useQuery } from "@tanstack/react-query";

import apiClient from "@/lib/api-client";
import { queryKeys } from "@/lib/query-keys";

import type { DashboardNotificationDTO } from "../../../shared/contracts/printing";

export type NotificationsSnapshot = {
  notifications: DashboardNotificationDTO[];
  unread: number;
};

export function useDashboardNotifications(enabled: boolean, limit = 24, unreadOnly?: boolean) {
  return useQuery({
    queryKey: queryKeys.layout.notifications(limit, unreadOnly),
    enabled,
    refetchInterval: enabled ? 90_000 : false,
    queryFn: async (): Promise<NotificationsSnapshot> => {
      const response = await apiClient.getNotifications({ limit, offset: 0, unreadOnly });
      if (!response.success) {
        throw new Error(response.error || "Failed to load notifications");
      }

      const payload = (response.data && typeof response.data === "object"
        ? response.data
        : {}) as {
        notifications?: DashboardNotificationDTO[];
        unread?: number;
      };

      return {
        notifications: Array.isArray(payload.notifications) ? payload.notifications : [],
        unread: Number.isFinite(Number(payload.unread)) ? Number(payload.unread) : 0,
      };
    },
  });
}
