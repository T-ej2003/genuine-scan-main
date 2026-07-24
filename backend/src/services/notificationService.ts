import {
  NotificationAudience,
  NotificationChannel,
  UserRole,
} from "@prisma/client";

import {
  B03AuthenticatedFunctionBoundary,
  createRoleNotifications as createRoleNotificationsThroughBoundary,
  createUserNotification as createUserNotificationThroughBoundary,
  listNotificationsForUser as listNotificationsForUserThroughBoundary,
  markAllNotificationsRead as markAllNotificationsReadThroughBoundary,
  markNotificationEmailed,
  markNotificationRead as markNotificationReadThroughBoundary,
  requireB03AuthenticatedFunctionBoundary,
  resolveIncidentNotificationScope,
} from "../rls-waves/session-b/b03/repositoryFunctions";
import { sendIncidentEmail } from "./incidentEmailService";
import { sendAuthEmail } from "./auth/authEmailService";
import { canAudienceReceiveNotificationType } from "./notificationVisibility";
import { getRedisInstanceId, publishRedisJson, subscribeRedisJson } from "./redisService";
import { bumpCacheNamespaceVersion } from "./versionedCacheService";
import { encodeDateCursor } from "../utils/cursorPagination";

export type NotificationRealtimeEvent = {
  type: "created" | "read" | "read_all";
  audience: NotificationAudience;
  notificationType?: string | null;
  licenseeId?: string | null;
  orgId?: string | null;
  incidentId?: string | null;
  userIds?: string[];
  notificationId?: string;
};

type NotificationListener = (event: NotificationRealtimeEvent) => void;

const listeners = new Set<NotificationListener>();
const NOTIFICATION_EVENT_CHANNEL = "mscqr:realtime:notifications";
const NOTIFICATION_CACHE_NAMESPACE = "notification-snapshot";
const NOTIFICATION_CACHE_TTL_SEC = 5;
let notificationChannelReady = false;

const parseBool = (value: unknown, fallback = false) => {
  const normalized = String(value || "").trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  return fallback;
};

const realtimeAlertEmailsEnabled = () =>
  parseBool(process.env.NOTIFICATION_REALTIME_ALERTS_EMAIL_ENABLED, true);

const realtimeAlertSubjectPrefix = () =>
  String(process.env.NOTIFICATION_REALTIME_ALERT_EMAIL_SUBJECT_PREFIX || "[MSCQR Real-time Alert]")
    .trim();

const isRealtimeAlertRole = (role: UserRole) =>
  role === UserRole.SUPER_ADMIN ||
  role === UserRole.PLATFORM_SUPER_ADMIN ||
  role === UserRole.LICENSEE_ADMIN ||
  role === UserRole.ORG_ADMIN;

const sendRealtimeAlertEmailForNotification = async (params: {
  toAddress: string;
  role: UserRole;
  title: string;
  body: string;
  type: string;
  licenseeId?: string | null;
  orgId?: string | null;
  data?: any;
}) => {
  if (!realtimeAlertEmailsEnabled()) return { delivered: false };
  if (!isRealtimeAlertRole(params.role)) return { delivered: false };

  const email = String(params.toAddress || "").trim().toLowerCase();
  if (!email) return { delivered: false };

  const subject = `${realtimeAlertSubjectPrefix()} ${params.title}`.trim();
  const text = [
    params.body,
    "",
    `Notification type: ${params.type}`,
    params.licenseeId ? `Licensee: ${params.licenseeId}` : "",
    params.orgId ? `Org: ${params.orgId}` : "",
    `Generated at: ${new Date().toISOString()}`,
    "",
    "This is an automated MSCQR real-time alert email.",
  ]
    .filter(Boolean)
    .join("\n");

  try {
    return await sendAuthEmail({
      toAddress: email,
      subject,
      text,
      template: `realtime_alert_${String(params.type || "system").slice(0, 48)}`,
      orgId: params.orgId || null,
      licenseeId: params.licenseeId || null,
    });
  } catch (error) {
    console.error("sendRealtimeAlertEmailForNotification error:", error);
    return { delivered: false, error: "Failed to send real-time alert email" };
  }
};

export const onNotificationEvent = (cb: NotificationListener) => {
  if (!notificationChannelReady) {
    notificationChannelReady = true;
    void subscribeRedisJson(NOTIFICATION_EVENT_CHANNEL, (payload) => {
      if (!payload || payload.origin === getRedisInstanceId()) return;
      notifyLocalListeners(payload.event);
    });
  }
  listeners.add(cb);
  return () => listeners.delete(cb);
};

const notifyLocalListeners = (event: NotificationRealtimeEvent) => {
  for (const cb of listeners) {
    try {
      cb(event);
    } catch {
      // ignore listener failures
    }
  }
};

const emitNotificationEvent = (event: NotificationRealtimeEvent) => {
  void bumpCacheNamespaceVersion(NOTIFICATION_CACHE_NAMESPACE).catch(() => undefined);
  void bumpCacheNamespaceVersion("attention-queue").catch(() => undefined);
  notifyLocalListeners(event);
  void publishRedisJson(NOTIFICATION_EVENT_CHANNEL, {
    origin: getRedisInstanceId(),
    event,
  }).catch(() => undefined);
};

export const createRoleNotifications = async (params: {
  audience: NotificationAudience;
  title: string;
  body: string;
  type: string;
  licenseeId?: string | null;
  orgId?: string | null;
  incidentId?: string | null;
  data?: any;
  channels?: NotificationChannel[];
  databaseBoundary?: B03AuthenticatedFunctionBoundary;
}) => {
  if (!canAudienceReceiveNotificationType(params.audience, params.type)) {
    return [] as any[];
  }

  const channels = params.channels && params.channels.length > 0 ? params.channels : [NotificationChannel.WEB];

  const boundary = requireB03AuthenticatedFunctionBoundary(params.databaseBoundary);
  const rows = await boundary.run((db) => createRoleNotificationsThroughBoundary(db, {
      audience: params.audience,
      title: params.title,
      body: params.body,
      notificationType: params.type,
      licenseeId: params.licenseeId,
      organizationId: params.orgId,
      incidentId: params.incidentId,
      data: params.data,
      channels,
      requestId: boundary.requestId,
    }));
    const created = Array.from(new Map(rows.map((row) => [row.channel, row.writeResult])).values());
    const deliveryRows = rows.filter((row) => row.sideEffectRequired);
    const users = Array.from(new Map(
      deliveryRows.filter((row) => row.userId).map((row) => [row.userId!, row])
    ).values());

    for (const channel of channels) {
      if (!deliveryRows.some((row) => row.channel === channel)) continue;
      if (channel === NotificationChannel.WEB) {
        emitNotificationEvent({
          type: "created",
          audience: params.audience,
          notificationType: params.type,
          licenseeId: params.licenseeId || null,
          orgId: params.orgId || null,
          incidentId: params.incidentId || null,
          userIds: users.length ? users.map((user) => user.userId!) : undefined,
        });
      }
      if (channel === NotificationChannel.EMAIL && params.incidentId) {
        for (const user of users) {
          if (!user.userEmail) continue;
          await sendIncidentEmail({
            incidentId: params.incidentId,
            licenseeId: params.licenseeId || user.userLicenseeId,
            toAddress: user.userEmail,
            subject: params.title,
            text: `${params.body}\n\nNotification type: ${params.type}`,
            senderMode: "system",
            template: `notify_${params.type}`,
            databaseBoundary: boundary,
          });
        }
      } else if (channel === NotificationChannel.EMAIL) {
        await Promise.allSettled(users.filter((user) => user.userEmail).map((user) => sendAuthEmail({
          toAddress: user.userEmail!,
          subject: params.title,
          text: `${params.body}\n\nNotification type: ${params.type}\nGenerated at: ${new Date().toISOString()}`,
          template: `notify_${params.type}`,
          licenseeId: params.licenseeId || user.userLicenseeId,
          orgId: params.orgId || user.userOrganizationId,
        })));
      }
    }

    if (channels.includes(NotificationChannel.WEB)) {
      await Promise.allSettled(users.filter((user) => user.userEmail && user.userRole).map((user) =>
        sendRealtimeAlertEmailForNotification({
          toAddress: user.userEmail!,
          role: user.userRole as UserRole,
          title: params.title,
          body: params.body,
          type: params.type,
          licenseeId: params.licenseeId || user.userLicenseeId,
          orgId: params.orgId || user.userOrganizationId,
          data: params.data,
        })
      ));
    }
  return created;
};

export const createUserNotification = async (params: {
  userId: string;
  title: string;
  body: string;
  type: string;
  licenseeId?: string | null;
  orgId?: string | null;
  incidentId?: string | null;
  data?: any;
  channel?: NotificationChannel;
  databaseBoundary?: B03AuthenticatedFunctionBoundary;
}) => {
  const channel = params.channel || NotificationChannel.WEB;

  const boundary = requireB03AuthenticatedFunctionBoundary(params.databaseBoundary);
    const row = await boundary.run((db) => createUserNotificationThroughBoundary(db, {
      userId: params.userId,
      title: params.title,
      body: params.body,
      notificationType: params.type,
      licenseeId: params.licenseeId,
      organizationId: params.orgId,
      incidentId: params.incidentId,
      data: params.data,
      channel,
      requestId: boundary.requestId,
    }));
    const created = row.notification as any;
    if (!row.sideEffectRequired) return created;
    if (channel === NotificationChannel.WEB) {
      emitNotificationEvent({
        type: "created",
        audience: NotificationAudience.ALL,
        notificationType: params.type,
        licenseeId: params.licenseeId || null,
        orgId: params.orgId || null,
        incidentId: params.incidentId || null,
        userIds: [params.userId],
        notificationId: row.notificationId,
      });
      if (row.userEmail && row.userRole) {
        const delivery = await sendRealtimeAlertEmailForNotification({
          toAddress: row.userEmail,
          role: row.userRole as UserRole,
          title: params.title,
          body: params.body,
          type: params.type,
          licenseeId: params.licenseeId || row.userLicenseeId,
          orgId: params.orgId || row.userOrganizationId,
          data: params.data,
        });
        if (delivery.delivered) {
          await boundary.run((db) => markNotificationEmailed(db, {
            notificationId: row.notificationId,
            emailedAt: new Date(),
            requestId: boundary.requestId,
          }));
        }
      }
    } else if (row.userEmail) {
      const delivery = await sendAuthEmail({
        toAddress: row.userEmail,
        subject: params.title,
        text: `${params.body}\n\nNotification type: ${params.type}\nGenerated at: ${new Date().toISOString()}`,
        template: `notify_${params.type}`,
        licenseeId: params.licenseeId || row.userLicenseeId,
        orgId: params.orgId || row.userOrganizationId,
      });
      if (delivery.delivered) {
        await boundary.run((db) => markNotificationEmailed(db, {
          notificationId: row.notificationId,
          emailedAt: new Date(),
          requestId: boundary.requestId,
        }));
      }
    }
  return created;
};

export const notifyIncidentLifecycle = async (params: {
  incidentId: string;
  licenseeId?: string | null;
  manufacturerOrgId?: string | null;
  title: string;
  body: string;
  type: string;
  data?: any;
  databaseBoundary?: B03AuthenticatedFunctionBoundary;
}) => {
  let manufacturerOrgId = params.manufacturerOrgId || null;
  if (!manufacturerOrgId && params.incidentId) {
    const boundary = requireB03AuthenticatedFunctionBoundary(params.databaseBoundary);
    const incidentScope = await boundary.run((db) => resolveIncidentNotificationScope(db, params.incidentId));
    if (params.licenseeId && incidentScope.licenseeId !== params.licenseeId) {
      throw new Error("B03 incident notification scope changed");
    }
    manufacturerOrgId = incidentScope.manufacturerOrganizationId;
  }

  const targets: Array<{ audience: NotificationAudience; licenseeId?: string | null; orgId?: string | null; channels?: NotificationChannel[] }> = [
    { audience: NotificationAudience.SUPER_ADMIN, licenseeId: null, orgId: null, channels: [NotificationChannel.WEB, NotificationChannel.EMAIL] },
  ];
  if (params.licenseeId) {
    targets.push({
      audience: NotificationAudience.LICENSEE_ADMIN,
      licenseeId: params.licenseeId || null,
      orgId: null,
      channels: [NotificationChannel.WEB, NotificationChannel.EMAIL],
    });
  }
  if (manufacturerOrgId) {
    targets.push({
      audience: NotificationAudience.MANUFACTURER,
      licenseeId: params.licenseeId || null,
      orgId: manufacturerOrgId,
      channels: [NotificationChannel.WEB],
    });
  }

  for (const target of targets) {
    await createRoleNotifications({
      audience: target.audience,
      title: params.title,
      body: params.body,
      type: params.type,
      licenseeId: target.licenseeId ?? null,
      orgId: target.orgId ?? null,
      incidentId: params.incidentId,
      data: params.data,
      channels: target.channels || [NotificationChannel.WEB],
      databaseBoundary: params.databaseBoundary,
    });
  }
};

const listNotificationsForUserUncached = async (params: {
  userId: string;
  role: UserRole;
  licenseeId?: string | null;
  licenseeIds?: string[] | null;
  orgId?: string | null;
  limit: number;
  offset: number;
  unreadOnly?: boolean;
  cursor?: string | null;
  databaseBoundary?: B03AuthenticatedFunctionBoundary;
}) => {
  const boundary = requireB03AuthenticatedFunctionBoundary(params.databaseBoundary);
  const result = await boundary.run((db) => listNotificationsForUserThroughBoundary(db, {
      userId: params.userId,
      limit: params.limit,
      offset: params.offset,
      unreadOnly: Boolean(params.unreadOnly),
      cursor: params.cursor,
      requestId: boundary.requestId,
    }));
  return { notifications: result.notifications as any[], total: result.total, unread: result.unread };
};

export const listNotificationsForUser = async (params: {
  userId: string;
  role: UserRole;
  licenseeId?: string | null;
  licenseeIds?: string[] | null;
  orgId?: string | null;
  limit: number;
  offset: number;
  unreadOnly?: boolean;
  cursor?: string | null;
  databaseBoundary?: B03AuthenticatedFunctionBoundary;
}) => {
  const scopeKey = [
    params.userId,
    params.role,
    params.licenseeId || "none",
    (params.licenseeIds || []).slice().sort().join(",") || "none",
    params.orgId || "none",
    params.limit,
    params.offset,
    params.unreadOnly ? "unread" : "all",
    params.cursor || "offset",
  ].join(":");

  const payload = await listNotificationsForUserUncached(params);

  const nextCursor =
    payload.notifications.length === params.limit
      ? encodeDateCursor(payload.notifications[payload.notifications.length - 1])
      : null;

  return {
    ...payload,
    nextCursor,
  };
};

export const markNotificationRead = async (params: {
  notificationId: string;
  userId: string;
  role: UserRole;
  licenseeId?: string | null;
  licenseeIds?: string[] | null;
  orgId?: string | null;
  databaseBoundary?: B03AuthenticatedFunctionBoundary;
}) => {
  const boundary = requireB03AuthenticatedFunctionBoundary(params.databaseBoundary);
  const result = await boundary.run((db) => markNotificationReadThroughBoundary(db, {
      notificationId: params.notificationId,
      userId: params.userId,
      readAt: new Date(),
      requestId: boundary.requestId,
    }));
    const notification = result.notification as any;
    if (notification) {
      emitNotificationEvent({
        type: "read",
        audience: NotificationAudience.ALL,
        licenseeId: params.licenseeId || null,
        userIds: [params.userId],
        notificationId: String(notification.id || params.notificationId),
      });
    }
  return notification;
};

export const markAllNotificationsRead = async (params: {
  userId: string;
  role: UserRole;
  licenseeId?: string | null;
  licenseeIds?: string[] | null;
  orgId?: string | null;
  databaseBoundary: B03AuthenticatedFunctionBoundary;
}) => {
  const boundary = requireB03AuthenticatedFunctionBoundary(params.databaseBoundary);
  const result = await boundary.run((db) => markAllNotificationsReadThroughBoundary(db, {
      userId: params.userId,
      readAt: new Date(),
      requestId: boundary.requestId,
    }));
    emitNotificationEvent({
      type: "read_all",
      audience: NotificationAudience.ALL,
      licenseeId: params.licenseeId || null,
      userIds: [params.userId],
    });
  return result.count;
};
