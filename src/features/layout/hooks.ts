import { useEffect, useMemo, useRef, useState, useSyncExternalStore } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { z } from "zod";

import apiClient from "@/lib/api-client";
import { useAuth } from "@/contexts/AuthContext";
import { useActivePrintSessionSuppression } from "@/lib/active-print-session";
import { parseWithSchema, unwrapParsedApiResponse } from "@/lib/api/query-utils";
import { clearDashboardReadCache } from "@/lib/api/internal-client-dashboard-request-control";
import { canPollVisibleDocument, pollingPolicy, visibleRefetchInterval } from "@/lib/query-polling-policy";
import { queryKeys } from "@/lib/query-keys";
import { getAuthenticatedStreamScope, onRequestCoordinatorScopeChange } from "@/lib/api/request-coordinator";

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
const NOTIFICATION_MIN_REFRESH_MS = 60_000;

const notificationsResponseSchema = z
  .object({
    notifications: dashboardNotificationArraySchema.optional(),
    unread: z.number().optional(),
  })
  .passthrough();

export function useDashboardNotifications(enabled: boolean, limit = 24, unreadOnly?: boolean) {
  const securityScope = useSyncExternalStore(onRequestCoordinatorScopeChange, getAuthenticatedStreamScope, getAuthenticatedStreamScope);
  const activePrintSuppressed = useActivePrintSessionSuppression();
  const queryEnabled = enabled && !activePrintSuppressed;
  return useQuery({
    queryKey: [...queryKeys.layout.notifications(limit, unreadOnly), securityScope],
    enabled: queryEnabled,
    staleTime: pollingPolicy.notificationsMs,
    refetchInterval: queryEnabled ? visibleRefetchInterval(pollingPolicy.notificationsMs) : false,
    refetchOnWindowFocus: false,
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
  const { refresh } = useAuth();
  const refreshAuthRef = useRef(refresh);
  refreshAuthRef.current = refresh;
  const securityScope = useSyncExternalStore(onRequestCoordinatorScopeChange, getAuthenticatedStreamScope, getAuthenticatedStreamScope);
  const activePrintSuppressed = useActivePrintSessionSuppression();
  const queryClient = useQueryClient();
  const notificationsQuery = useDashboardNotifications(false, limit);
  const [notifications, setNotifications] = useState<DashboardNotificationDTO[]>([]);
  const [unreadNotifications, setUnreadNotifications] = useState(0);
  const [notificationsLoading, setNotificationsLoading] = useState(false);
  const [notificationsLive, setNotificationsLive] = useState(false);
  const [dismissedNotificationIds, setDismissedNotificationIds] = useState<string[]>([]);
  const [clearingNotificationIds, setClearingNotificationIds] = useState<string[]>([]);
  const [clearingNotifications, setClearingNotifications] = useState(false);
  const clearNotificationsTimerRef = useRef<number | null>(null);
  const loadNotificationsInFlightRef = useRef<Promise<void> | null>(null);
  const lastNotificationsLoadAtRef = useRef(0);
  const notificationsLiveRef = useRef(false);
  const snapshotScopeRef = useRef<string | null>(null);
  const loadScopeRef = useRef<string | null>(null);
  const snapshotSignatureRef = useRef<string | null>(null);
  const snapshotRevisionRef = useRef(0);
  const latestSnapshotRef = useRef<NotificationsSnapshot | null>(null);
  const lastServerTimeRef = useRef(0);
  const streamOpenedRef = useRef(false);
  const resyncAttentionRef = useRef(false);

  const applyNotificationSnapshot = (rows: DashboardNotificationDTO[], unread: number, scope = securityScope) => {
    if (scope !== getAuthenticatedStreamScope()) return;
    lastNotificationsLoadAtRef.current = Date.now();
    const signature = JSON.stringify([unread, rows]);
    if (snapshotScopeRef.current === scope && snapshotSignatureRef.current === signature) return;
    snapshotScopeRef.current = scope;
    snapshotSignatureRef.current = signature;
    snapshotRevisionRef.current += 1;
    latestSnapshotRef.current = { notifications: rows, unread };
    setNotifications(rows);
    setUnreadNotifications(Number.isFinite(unread) ? unread : 0);
    queryClient.setQueryData([...queryKeys.layout.notifications(limit, false), scope], {
      notifications: rows,
      unread: Number.isFinite(unread) ? unread : 0,
    });

    const rowIds = new Set(rows.map((row) => String(row?.id || "")).filter(Boolean));
    setDismissedNotificationIds((prev) => prev.filter((id) => rowIds.has(id)));
  };

  const loadNotifications = async (options?: { force?: boolean }) => {
    if (!userId) return;
    if (activePrintSuppressed && !options?.force) return;
    if (loadNotificationsInFlightRef.current && loadScopeRef.current === securityScope) return loadNotificationsInFlightRef.current;
    const elapsed = Date.now() - lastNotificationsLoadAtRef.current;
    if (!options?.force && elapsed < NOTIFICATION_MIN_REFRESH_MS) return;

    setNotificationsLoading(true);
    const requestScope = securityScope;
    const requestRevision = snapshotRevisionRef.current;
    loadScopeRef.current = requestScope;
    const load = (async () => {
      try {
        lastNotificationsLoadAtRef.current = Date.now();
        const response = await notificationsQuery.refetch();
        if (response.isSuccess && response.data) {
          if (requestRevision === snapshotRevisionRef.current) {
            applyNotificationSnapshot(response.data.notifications, Number(response.data.unread || 0), requestScope);
          } else if (latestSnapshotRef.current && requestScope === getAuthenticatedStreamScope()) {
            queryClient.setQueryData([...queryKeys.layout.notifications(limit, false), requestScope], latestSnapshotRef.current);
          }
        }
      } catch (error) {
        // Preserve the last authenticated snapshot during transient failures.
      } finally {
        if (requestScope === getAuthenticatedStreamScope()) setNotificationsLoading(false);
      }
    })();
    loadNotificationsInFlightRef.current = load;
    void load.finally(() => {
      if (loadNotificationsInFlightRef.current === load) loadNotificationsInFlightRef.current = null;
    });
    return load;
  };

  useEffect(() => {
    snapshotScopeRef.current = null;
    snapshotSignatureRef.current = null;
    snapshotRevisionRef.current = 0;
    latestSnapshotRef.current = null;
    lastServerTimeRef.current = 0;
    streamOpenedRef.current = false;
    resyncAttentionRef.current = false;
    lastNotificationsLoadAtRef.current = 0;
    setNotifications([]);
    setUnreadNotifications(0);
    setNotificationsLive(false);
  }, [securityScope]);

  useEffect(() => {
    if (!userId) return;
    if (activePrintSuppressed) return;
    void loadNotifications({ force: true });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [userId, activePrintSuppressed, securityScope]);

  useEffect(() => {
    notificationsLiveRef.current = notificationsLive;
  }, [notificationsLive]);

  useEffect(() => {
    if (!userId) return;
    if (activePrintSuppressed) return;
    const timer = window.setInterval(() => {
      if (!canPollVisibleDocument()) return;
      if (notificationsLiveRef.current && Date.now() - lastNotificationsLoadAtRef.current < pollingPolicy.sseSafetySnapshotMs) return;
      void loadNotifications();
    }, pollingPolicy.notificationsMs);
    return () => window.clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [userId, activePrintSuppressed, securityScope]);

  useEffect(() => {
    if (!userId) return;
    if (activePrintSuppressed) return;
    if (clearNotificationsTimerRef.current) {
      window.clearTimeout(clearNotificationsTimerRef.current);
      clearNotificationsTimerRef.current = null;
    }

    const stop = apiClient.streamNotifications(
      (payload) => {
        if (securityScope !== getAuthenticatedStreamScope()) return;
        if (payload.kind === "auth_expired") {
          void refreshAuthRef.current();
          return;
        }
        if (payload.kind === "version") {
          void loadNotifications({ force: true });
          return;
        }
        const parsed = parseWithSchema(notificationsResponseSchema, payload, "Failed to stream notifications");
        const serverTime = Date.parse(String(parsed.serverTime || ""));
        if (Number.isFinite(serverTime) && serverTime < lastServerTimeRef.current) return;
        if (Number.isFinite(serverTime)) lastServerTimeRef.current = serverTime;
        const priorSignature = snapshotSignatureRef.current;
        applyNotificationSnapshot(parsed.notifications || [], Number(parsed.unread || 0), securityScope);
        if (snapshotSignatureRef.current !== priorSignature || resyncAttentionRef.current) {
          resyncAttentionRef.current = false;
          void queryClient.invalidateQueries({ queryKey: queryKeys.layout.attentionQueue() });
        }
      },
      () => {
        setNotificationsLive(false);
      },
      () => {
        resyncAttentionRef.current = streamOpenedRef.current;
        streamOpenedRef.current = true;
        lastServerTimeRef.current = 0;
        setNotificationsLive(true);
      },
      { limit }
    );

    return () => {
      setNotificationsLive(false);
      stop();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [userId, limit, activePrintSuppressed, securityScope]);

  useEffect(() => {
    return () => {
      if (clearNotificationsTimerRef.current) {
        window.clearTimeout(clearNotificationsTimerRef.current);
      }
    };
  }, []);

  const dismissedNotificationIdSet = useMemo(() => new Set(dismissedNotificationIds), [dismissedNotificationIds]);
  const clearingNotificationIdSet = useMemo(() => new Set(clearingNotificationIds), [clearingNotificationIds]);

  const scopedNotifications = useMemo(
    () => snapshotScopeRef.current === securityScope ? notifications : [],
    [notifications, securityScope]
  );
  const scopedUnread = snapshotScopeRef.current === securityScope ? unreadNotifications : 0;
  const visibleNotifications = useMemo(
    () => scopedNotifications.filter((item) => item?.id && !dismissedNotificationIdSet.has(String(item.id))),
    [scopedNotifications, dismissedNotificationIdSet]
  );

  const markNotificationRead = async (id: string) => {
    if (!id) return;
    await apiClient.markNotificationRead(id);
    clearDashboardReadCache(["notifications:list", "dashboard:attention-queue"]);
    await loadNotifications({ force: true });
  };

  const markAllNotificationsRead = async () => {
    if (scopedNotifications.length === 0 && scopedUnread === 0) return;

    const readAt = new Date().toISOString();
    setNotifications((prev) => prev.map((item) => ({ ...item, readAt: item.readAt || readAt })));
    setUnreadNotifications(0);

    try {
      await apiClient.markAllNotificationsRead();
      clearDashboardReadCache(["notifications:list", "dashboard:attention-queue"]);
    } catch {
      await loadNotifications({ force: true });
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
      clearDashboardReadCache(["notifications:list", "dashboard:attention-queue"]);
    } catch {
      // Keep local panel clear smooth even if sync fails.
    }
  };

  return {
    notifications: scopedNotifications,
    unreadNotifications: scopedUnread,
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
  const securityScope = useSyncExternalStore(onRequestCoordinatorScopeChange, getAuthenticatedStreamScope, getAuthenticatedStreamScope);
  const activePrintSuppressed = useActivePrintSessionSuppression();
  const queryEnabled = enabled && !activePrintSuppressed;
  return useQuery({
    queryKey: [...queryKeys.layout.attentionQueue(), securityScope],
    enabled: queryEnabled,
    staleTime: pollingPolicy.attentionQueueMs,
    refetchInterval: queryEnabled ? visibleRefetchInterval(pollingPolicy.attentionQueueMs) : false,
    refetchOnWindowFocus: false,
    queryFn: async (): Promise<OperationalAttentionQueue> =>
      unwrapParsedApiResponse(
        await apiClient.getOperationalAttentionQueue(),
        attentionQueueSchema,
        "Failed to load operational attention queue"
      ),
  });
}
