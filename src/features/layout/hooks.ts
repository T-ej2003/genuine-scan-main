import { useEffect, useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { z } from "zod";

import apiClient from "@/lib/api-client";
import { parseWithSchema, unwrapParsedApiResponse } from "@/lib/api/query-utils";
import { queryKeys } from "@/lib/query-keys";

import {
  dashboardNotificationArraySchema,
  type DashboardNotificationDTO,
} from "../../../shared/contracts/runtime/printing.ts";

export type NotificationsSnapshot = {
  notifications: DashboardNotificationDTO[];
  unread: number;
};

const attentionQueueItemSchema = z
  .object({
    id: z.string(),
    type: z.enum(["notification", "incident", "policy_alert", "print_job", "support_ticket", "audit_event"]),
    title: z.string(),
    body: z.string(),
    tone: z.enum(["neutral", "verified", "review", "blocked", "audit", "support", "print"]),
    route: z.string(),
    createdAt: z.string().nullable().optional(),
    count: z.number().optional(),
  })
  .passthrough();

const attentionQueueSchema = z
  .object({
    generatedAt: z.string(),
    summary: z.object({
      unreadNotifications: z.number(),
      reviewSignals: z.number(),
      printOperations: z.number(),
      supportEscalations: z.number(),
      auditEvents24h: z.number(),
    }),
    items: z.array(attentionQueueItemSchema),
  })
  .passthrough();

export type OperationalAttentionQueue = z.infer<typeof attentionQueueSchema>;

const NOTIFICATION_CLEAR_ANIMATION_MS = 260;

const notificationsResponseSchema = z
  .object({
    notifications: dashboardNotificationArraySchema.optional(),
    unread: z.number().optional(),
  })
  .passthrough();

export function useDashboardNotifications(enabled: boolean, limit = 24, unreadOnly?: boolean) {
  return useQuery({
    queryKey: queryKeys.layout.notifications(limit, unreadOnly),
    enabled,
    refetchInterval: enabled ? 90_000 : false,
    queryFn: async (): Promise<NotificationsSnapshot> => {
      const payload = unwrapParsedApiResponse(
        await apiClient.getNotifications({ limit, offset: 0, unreadOnly }),
        notificationsResponseSchema,
        "Failed to load notifications"
      );

      return {
        notifications: payload.notifications || [],
        unread: Number.isFinite(Number(payload.unread)) ? Number(payload.unread) : 0,
      };
    },
  });
}

export function useDashboardNotificationCenter(userId?: string | null, limit = 24) {
  const notificationsQuery = useDashboardNotifications(false, limit);
  const [notifications, setNotifications] = useState<DashboardNotificationDTO[]>([]);
  const [unreadNotifications, setUnreadNotifications] = useState(0);
  const [notificationsLoading, setNotificationsLoading] = useState(false);
  const [notificationsLive, setNotificationsLive] = useState(false);
  const [dismissedNotificationIds, setDismissedNotificationIds] = useState<string[]>([]);
  const [clearingNotificationIds, setClearingNotificationIds] = useState<string[]>([]);
  const [clearingNotifications, setClearingNotifications] = useState(false);
  const clearNotificationsTimerRef = useRef<number | null>(null);

  const applyNotificationSnapshot = (rows: DashboardNotificationDTO[], unread: number) => {
    setNotifications(rows);
    setUnreadNotifications(Number.isFinite(unread) ? unread : 0);

    const rowIds = new Set(rows.map((row) => String(row?.id || "")).filter(Boolean));
    setDismissedNotificationIds((prev) => prev.filter((id) => rowIds.has(id)));
  };

  const loadNotifications = async () => {
    if (!userId) return;
    setNotificationsLoading(true);
    try {
      const response = await notificationsQuery.refetch();
      if (!response.data) {
        setNotifications([]);
        setUnreadNotifications(0);
        return;
      }
      applyNotificationSnapshot(response.data.notifications, Number(response.data.unread || 0));
    } catch {
      setNotifications([]);
      setUnreadNotifications(0);
    } finally {
      setNotificationsLoading(false);
    }
  };

  useEffect(() => {
    if (!userId) return;
    void loadNotifications();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [userId]);

  useEffect(() => {
    if (notificationsQuery.data) {
      applyNotificationSnapshot(notificationsQuery.data.notifications, notificationsQuery.data.unread);
    }
  }, [notificationsQuery.data]);

  useEffect(() => {
    if (!userId) return;
    const timer = window.setInterval(() => {
      void loadNotifications();
    }, 90_000);
    return () => window.clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [userId]);

  useEffect(() => {
    if (!userId) return;
    if (clearNotificationsTimerRef.current) {
      window.clearTimeout(clearNotificationsTimerRef.current);
      clearNotificationsTimerRef.current = null;
    }

    const stop = apiClient.streamNotifications(
      (payload) => {
        if (payload.kind === "version") {
          void loadNotifications();
          return;
        }
        const parsed = parseWithSchema(notificationsResponseSchema, payload, "Failed to stream notifications");
        applyNotificationSnapshot(parsed.notifications || [], Number(parsed.unread || 0));
      },
      () => {
        setNotificationsLive(false);
      },
      () => {
        setNotificationsLive(true);
      },
      { limit }
    );

    return () => {
      setNotificationsLive(false);
      stop();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [userId, limit]);

  useEffect(() => {
    return () => {
      if (clearNotificationsTimerRef.current) {
        window.clearTimeout(clearNotificationsTimerRef.current);
      }
    };
  }, []);

  const dismissedNotificationIdSet = useMemo(() => new Set(dismissedNotificationIds), [dismissedNotificationIds]);
  const clearingNotificationIdSet = useMemo(() => new Set(clearingNotificationIds), [clearingNotificationIds]);

  const visibleNotifications = useMemo(
    () => notifications.filter((item) => item?.id && !dismissedNotificationIdSet.has(String(item.id))),
    [notifications, dismissedNotificationIdSet]
  );

  const markNotificationRead = async (id: string) => {
    if (!id) return;
    await apiClient.markNotificationRead(id);
    await loadNotifications();
  };

  const markAllNotificationsRead = async () => {
    if (notifications.length === 0 && unreadNotifications === 0) return;

    const readAt = new Date().toISOString();
    setNotifications((prev) => prev.map((item) => ({ ...item, readAt: item.readAt || readAt })));
    setUnreadNotifications(0);

    try {
      await apiClient.markAllNotificationsRead();
    } catch {
      await loadNotifications();
    }
  };

  const clearNotifications = async () => {
    if (notificationsLoading || clearingNotifications || visibleNotifications.length === 0) return;

    const idsToClear = visibleNotifications.map((item) => String(item.id)).filter(Boolean);
    if (idsToClear.length === 0) return;

    const unreadBeingCleared = visibleNotifications.reduce((count, item) => count + (!item.readAt ? 1 : 0), 0);
    const readAt = new Date().toISOString();

    setClearingNotifications(true);
    setClearingNotificationIds(idsToClear);
    setNotifications((prev) =>
      prev.map((item) => (idsToClear.includes(String(item.id)) ? { ...item, readAt: item.readAt || readAt } : item))
    );
    setUnreadNotifications((prev) => Math.max(0, prev - unreadBeingCleared));

    if (clearNotificationsTimerRef.current) {
      window.clearTimeout(clearNotificationsTimerRef.current);
    }

    clearNotificationsTimerRef.current = window.setTimeout(() => {
      setDismissedNotificationIds((prev) => Array.from(new Set([...prev, ...idsToClear])).slice(-300));
      setClearingNotificationIds([]);
      setClearingNotifications(false);
      clearNotificationsTimerRef.current = null;
    }, NOTIFICATION_CLEAR_ANIMATION_MS);

    try {
      await apiClient.markAllNotificationsRead();
    } catch {
      // Keep local panel clear smooth even if sync fails.
    }
  };

  return {
    notifications,
    unreadNotifications,
    notificationsLoading,
    notificationsLive,
    clearingNotificationIdSet,
    clearingNotifications,
    visibleNotifications,
    hasVisibleNotifications: visibleNotifications.length > 0,
    notificationPanelCleared: notifications.length > 0 && visibleNotifications.length === 0,
    canClearNotifications: visibleNotifications.length > 0 && !notificationsLoading && !clearingNotifications,
    markNotificationRead,
    markAllNotificationsRead,
    clearNotifications,
    loadNotifications,
  };
}

export function useOperationalAttentionQueue(enabled: boolean) {
  return useQuery({
    queryKey: queryKeys.layout.attentionQueue(),
    enabled,
    refetchInterval: enabled ? 45_000 : false,
    queryFn: async (): Promise<OperationalAttentionQueue> =>
      unwrapParsedApiResponse(
        await apiClient.getOperationalAttentionQueue(),
        attentionQueueSchema,
        "Failed to load operational attention queue"
      ),
  });
}
