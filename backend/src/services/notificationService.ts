import {
  NotificationAudience,
  NotificationChannel,
  UserRole,
} from "@prisma/client";

import prisma from "../config/database";
import { sendIncidentEmail } from "./incidentEmailService";
import { sendAuthEmail } from "./auth/authEmailService";
import { isPrismaMissingTableError, warnStorageUnavailableOnce } from "../utils/prismaStorageGuard";
import {
  canAudienceReceiveNotificationType,
  hiddenNotificationTypesForRole,
} from "./notificationVisibility";
import { getRedisInstanceId, publishRedisJson, subscribeRedisJson } from "./redisService";
import { bumpCacheNamespaceVersion, getOrComputeVersionedCache } from "./versionedCacheService";
import { buildDateCursorWhere, encodeDateCursor } from "../utils/cursorPagination";

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
  notifyLocalListeners(event);
  void publishRedisJson(NOTIFICATION_EVENT_CHANNEL, {
    origin: getRedisInstanceId(),
    event,
  }).catch(() => undefined);
};

const normalizeRole = (role: UserRole): NotificationAudience => {
  if (role === UserRole.SUPER_ADMIN || role === UserRole.PLATFORM_SUPER_ADMIN) return NotificationAudience.SUPER_ADMIN;
  if (role === UserRole.LICENSEE_ADMIN || role === UserRole.ORG_ADMIN) return NotificationAudience.LICENSEE_ADMIN;
  return NotificationAudience.MANUFACTURER;
};

const normalizeLicenseeScope = (licenseeId?: string | null, licenseeIds?: string[] | null) =>
  Array.from(
    new Set(
      [licenseeId || null, ...(Array.isArray(licenseeIds) ? licenseeIds : [])]
        .map((value) => String(value || "").trim())
        .filter(Boolean)
    )
  );

const buildLicenseeBroadcastScope = (licenseeId?: string | null, licenseeIds?: string[] | null) => {
  const scopedLicenseeIds = normalizeLicenseeScope(licenseeId, licenseeIds);
  if (!scopedLicenseeIds.length) return null;
  return {
    OR: [
      scopedLicenseeIds.length === 1 ? { licenseeId: scopedLicenseeIds[0] } : { licenseeId: { in: scopedLicenseeIds } },
      { licenseeId: null },
    ],
  };
};

const roleFilter = (audience: NotificationAudience) => {
  if (audience === NotificationAudience.SUPER_ADMIN) {
    return { in: [UserRole.SUPER_ADMIN, UserRole.PLATFORM_SUPER_ADMIN] as UserRole[] };
  }
  if (audience === NotificationAudience.LICENSEE_ADMIN) {
    return { in: [UserRole.LICENSEE_ADMIN, UserRole.ORG_ADMIN] as UserRole[] };
  }
  if (audience === NotificationAudience.MANUFACTURER) {
    return { in: [UserRole.MANUFACTURER, UserRole.MANUFACTURER_ADMIN, UserRole.MANUFACTURER_USER] as UserRole[] };
  }
  return undefined;
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
}) => {
  if (!canAudienceReceiveNotificationType(params.audience, params.type)) {
    return [] as any[];
  }

  const channels = params.channels && params.channels.length > 0 ? params.channels : [NotificationChannel.WEB];

  const userWhere: any = {
    isActive: true,
    deletedAt: null,
  };
  const roleWhere = roleFilter(params.audience);
  if (roleWhere) userWhere.role = roleWhere;
  if (params.licenseeId) {
    if (params.audience === NotificationAudience.MANUFACTURER) {
      userWhere.OR = [
        { licenseeId: params.licenseeId },
        { manufacturerLicenseeLinks: { some: { licenseeId: params.licenseeId } } },
      ];
    } else {
      userWhere.licenseeId = params.licenseeId;
    }
  }
  if (params.orgId) userWhere.orgId = params.orgId;

  const users = await prisma.user.findMany({
    where: userWhere,
    select: {
      id: true,
      email: true,
      role: true,
      licenseeId: true,
      orgId: true,
    },
  });

  try {
    if (!users.length && params.audience !== NotificationAudience.ALL) {
      return [] as any[];
    }

    const created: any[] = [];

    const targetedUserIds = users.map((u) => u.id);

    for (const channel of channels) {
      if (users.length > 0) {
        const rows = await prisma.notification.createMany({
          data: users.map((user) => ({
            userId: user.id,
            orgId: params.orgId || user.orgId || null,
            licenseeId: params.licenseeId || user.licenseeId || null,
            incidentId: params.incidentId || null,
            audience: params.audience,
            channel,
            type: params.type,
            title: params.title,
            body: params.body,
            data: params.data || null,
          })),
        });
        created.push(rows);
      } else {
        const row = await prisma.notification.create({
          data: {
            userId: null,
            orgId: params.orgId || null,
            licenseeId: params.licenseeId || null,
            incidentId: params.incidentId || null,
            audience: params.audience,
            channel,
            type: params.type,
            title: params.title,
            body: params.body,
            data: params.data || null,
          },
        });
        created.push(row);
      }

      if (channel === NotificationChannel.WEB) {
        emitNotificationEvent({
          type: "created",
          audience: params.audience,
          notificationType: params.type,
          licenseeId: params.licenseeId || null,
          orgId: params.orgId || null,
          incidentId: params.incidentId || null,
          userIds: targetedUserIds.length > 0 ? targetedUserIds : undefined,
        });
      }

      if (channel === NotificationChannel.EMAIL && users.length > 0 && params.incidentId) {
        for (const user of users) {
          await sendIncidentEmail({
            incidentId: params.incidentId,
            licenseeId: params.licenseeId || user.licenseeId || null,
            toAddress: user.email,
            subject: params.title,
            text: `${params.body}\n\nNotification type: ${params.type}`,
            senderMode: "system",
            template: `notify_${params.type}`,
          });
        }
      } else if (channel === NotificationChannel.EMAIL && users.length > 0) {
        await Promise.allSettled(
          users.map((user) =>
            sendAuthEmail({
              toAddress: user.email,
              subject: params.title,
              text: `${params.body}\n\nNotification type: ${params.type}\nGenerated at: ${new Date().toISOString()}`,
              template: `notify_${params.type}`,
              licenseeId: params.licenseeId || user.licenseeId || null,
              orgId: params.orgId || user.orgId || null,
            })
          )
        );
      }
    }

    if (channels.includes(NotificationChannel.WEB) && users.length > 0) {
      await Promise.allSettled(
        users.map((user) =>
          sendRealtimeAlertEmailForNotification({
            toAddress: user.email,
            role: user.role,
            title: params.title,
            body: params.body,
            type: params.type,
            licenseeId: params.licenseeId || user.licenseeId || null,
            orgId: params.orgId || user.orgId || null,
            data: params.data || null,
          })
        )
      );
    }

    return created;
  } catch (error) {
    if (isPrismaMissingTableError(error, ["notification"])) {
      warnStorageUnavailableOnce(
        "notification-create",
        "[notification] Notification table is unavailable. Skipping notification persistence."
      );
      return [] as any[];
    }
    throw error;
  }
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
}) => {
  const channel = params.channel || NotificationChannel.WEB;

  try {
    const created = await prisma.notification.create({
      data: {
        userId: params.userId,
        orgId: params.orgId || null,
        licenseeId: params.licenseeId || null,
        incidentId: params.incidentId || null,
        audience: NotificationAudience.ALL,
        channel,
        type: params.type,
        title: params.title,
        body: params.body,
        data: params.data || null,
      },
    });

    const user = await prisma.user.findUnique({
      where: { id: params.userId },
      select: { email: true, role: true, licenseeId: true, orgId: true },
    });

    if (channel === NotificationChannel.WEB) {
      emitNotificationEvent({
        type: "created",
        audience: NotificationAudience.ALL,
        notificationType: params.type,
        licenseeId: params.licenseeId || null,
        orgId: params.orgId || null,
        incidentId: params.incidentId || null,
        userIds: [params.userId],
        notificationId: created.id,
      });

      try {
        if (user) {
          const delivery = await sendRealtimeAlertEmailForNotification({
            toAddress: user.email,
            role: user.role,
            title: params.title,
            body: params.body,
            type: params.type,
            licenseeId: params.licenseeId || user.licenseeId || null,
            orgId: params.orgId || user.orgId || null,
            data: params.data || null,
          });
          if (delivery.delivered) {
            await prisma.notification.update({
              where: { id: created.id },
              data: { emailedAt: new Date() },
            });
          }
        }
      } catch (emailError) {
        console.error("createUserNotification realtime email error:", emailError);
      }
    }

    if (channel === NotificationChannel.EMAIL && user?.email) {
      try {
        const delivery = await sendAuthEmail({
          toAddress: user.email,
          subject: params.title,
          text: `${params.body}\n\nNotification type: ${params.type}\nGenerated at: ${new Date().toISOString()}`,
          template: `notify_${params.type}`,
          licenseeId: params.licenseeId || user.licenseeId || null,
          orgId: params.orgId || user.orgId || null,
        });
        if (delivery.delivered) {
          await prisma.notification.update({
            where: { id: created.id },
            data: { emailedAt: new Date() },
          });
        }
      } catch (emailError) {
        console.error("createUserNotification email delivery error:", emailError);
      }
    }

    return created;
  } catch (error) {
    if (isPrismaMissingTableError(error, ["notification"])) {
      warnStorageUnavailableOnce(
        "notification-create-user",
        "[notification] Notification table is unavailable. Skipping direct user notification."
      );
      return null;
    }
    throw error;
  }
};

export const notifyIncidentLifecycle = async (params: {
  incidentId: string;
  licenseeId?: string | null;
  manufacturerOrgId?: string | null;
  title: string;
  body: string;
  type: string;
  data?: any;
}) => {
  let manufacturerOrgId = params.manufacturerOrgId || null;
  if (!manufacturerOrgId && params.incidentId) {
    const incidentScope = await prisma.incident.findUnique({
      where: { id: params.incidentId },
      select: {
        qrCode: {
          select: {
            batch: {
              select: {
                manufacturer: { select: { orgId: true } },
              },
            },
          },
        },
        scanEvent: {
          select: {
            batch: {
              select: {
                manufacturer: { select: { orgId: true } },
              },
            },
          },
        },
      },
    });

    manufacturerOrgId =
      incidentScope?.qrCode?.batch?.manufacturer?.orgId ||
      incidentScope?.scanEvent?.batch?.manufacturer?.orgId ||
      null;
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
}) => {
  const audience = normalizeRole(params.role);
  const hiddenTypes = hiddenNotificationTypesForRole(params.role);

  const scopedBroadcast: any = {
    userId: null,
    channel: NotificationChannel.WEB,
    audience: { in: [NotificationAudience.ALL, audience] },
  };

  if (params.role !== UserRole.SUPER_ADMIN && params.role !== UserRole.PLATFORM_SUPER_ADMIN) {
    const tenantFilters: any[] = [];
    const licenseeScope = buildLicenseeBroadcastScope(params.licenseeId, params.licenseeIds);
    if (licenseeScope) {
      tenantFilters.push(licenseeScope);
    } else if (audience === NotificationAudience.MANUFACTURER) {
      tenantFilters.push({ licenseeId: null });
    } else {
      tenantFilters.push({ licenseeId: null });
    }

    if (audience === NotificationAudience.MANUFACTURER) {
      if (params.orgId) {
        tenantFilters.push({ OR: [{ orgId: params.orgId }, { orgId: null }] });
      } else {
        tenantFilters.push({ orgId: null });
      }
    }

    if (tenantFilters.length) scopedBroadcast.AND = tenantFilters;
  }

  const scopedOr: any[] = [{ userId: params.userId, channel: NotificationChannel.WEB }, scopedBroadcast];

  const where: any = {
    OR: scopedOr,
  };
  if (hiddenTypes.length > 0) {
    where.type = { notIn: hiddenTypes };
  }

  if (params.unreadOnly) {
    where.readAt = null;
  }

  const cursorWhere = buildDateCursorWhere({
    cursor: params.cursor,
    createdAtField: "createdAt",
    idField: "id",
  });
  if (cursorWhere) {
    where.AND = [...(Array.isArray(where.AND) ? where.AND : []), cursorWhere];
  }

  try {
    const [notifications, total] = await Promise.all([
      prisma.notification.findMany({
        where,
        orderBy: [{ createdAt: "desc" }],
        take: params.limit,
        skip: params.cursor ? 0 : params.offset,
      }),
      params.cursor ? Promise.resolve<number | null>(null) : prisma.notification.count({ where }),
    ]);

    const unread = await prisma.notification.count({
      where: {
        OR: scopedOr,
        readAt: null,
      },
    });

    return { notifications, total, unread };
  } catch (error) {
    if (isPrismaMissingTableError(error, ["notification"])) {
      warnStorageUnavailableOnce(
        "notification-list",
        "[notification] Notification table is unavailable. Returning empty notification list."
      );
      return { notifications: [], total: 0, unread: 0 };
    }
    throw error;
  }
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

  const payload = await getOrComputeVersionedCache(NOTIFICATION_CACHE_NAMESPACE, scopeKey, NOTIFICATION_CACHE_TTL_SEC, () =>
    listNotificationsForUserUncached(params)
  );

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
}) => {
  const audience = normalizeRole(params.role);
  const hiddenTypes = hiddenNotificationTypesForRole(params.role);
  try {
    const sharedScope: any = {
      userId: null,
      channel: NotificationChannel.WEB,
      audience: { in: [NotificationAudience.ALL, audience] },
    };
    if (params.role !== UserRole.SUPER_ADMIN && params.role !== UserRole.PLATFORM_SUPER_ADMIN) {
      const tenantFilters: any[] = [];
      const licenseeScope = buildLicenseeBroadcastScope(params.licenseeId, params.licenseeIds);
      if (licenseeScope) {
        tenantFilters.push(licenseeScope);
      } else if (audience === NotificationAudience.MANUFACTURER) {
        tenantFilters.push({ licenseeId: null });
      } else {
        tenantFilters.push({ licenseeId: null });
      }
      if (audience === NotificationAudience.MANUFACTURER) {
        if (params.orgId) {
          tenantFilters.push({ OR: [{ orgId: params.orgId }, { orgId: null }] });
        } else {
          tenantFilters.push({ orgId: null });
        }
      }
      if (tenantFilters.length) sharedScope.AND = tenantFilters;
    }

    const existing = await prisma.notification.findFirst({
      where: {
        id: params.notificationId,
        ...(hiddenTypes.length > 0 ? { type: { notIn: hiddenTypes } } : {}),
        OR: [
          { userId: params.userId, channel: NotificationChannel.WEB },
          sharedScope,
        ],
      },
    });

    if (!existing) return null;

    const updated = await prisma.notification.update({
      where: { id: existing.id },
      data: {
        readAt: existing.readAt || new Date(),
      },
    });

    emitNotificationEvent({
      type: "read",
      audience: NotificationAudience.ALL,
      licenseeId: params.licenseeId || null,
      userIds: [params.userId],
      notificationId: updated.id,
    });

    return updated;
  } catch (error) {
    if (isPrismaMissingTableError(error, ["notification"])) {
      warnStorageUnavailableOnce(
        "notification-read",
        "[notification] Notification table is unavailable. Mark-read request skipped."
      );
      return null;
    }
    throw error;
  }
};

export const markAllNotificationsRead = async (params: {
  userId: string;
  role: UserRole;
  licenseeId?: string | null;
  licenseeIds?: string[] | null;
  orgId?: string | null;
}) => {
  const audience = normalizeRole(params.role);
  const hiddenTypes = hiddenNotificationTypesForRole(params.role);

  const sharedScope: any = {
    userId: null,
    channel: NotificationChannel.WEB,
    audience: { in: [NotificationAudience.ALL, audience] },
  };
  if (params.role !== UserRole.SUPER_ADMIN && params.role !== UserRole.PLATFORM_SUPER_ADMIN) {
    const tenantFilters: any[] = [];
    const licenseeScope = buildLicenseeBroadcastScope(params.licenseeId, params.licenseeIds);
    if (licenseeScope) {
      tenantFilters.push(licenseeScope);
    } else if (audience === NotificationAudience.MANUFACTURER) {
      tenantFilters.push({ licenseeId: null });
    } else {
      tenantFilters.push({ licenseeId: null });
    }
    if (audience === NotificationAudience.MANUFACTURER) {
      if (params.orgId) {
        tenantFilters.push({ OR: [{ orgId: params.orgId }, { orgId: null }] });
      } else {
        tenantFilters.push({ orgId: null });
      }
    }
    if (tenantFilters.length) sharedScope.AND = tenantFilters;
  }

  const where: any = {
    readAt: null,
    OR: [
      { userId: params.userId, channel: NotificationChannel.WEB },
      sharedScope,
    ],
  };
  if (hiddenTypes.length > 0) {
    where.type = { notIn: hiddenTypes };
  }

  try {
    const result = await prisma.notification.updateMany({
      where,
      data: { readAt: new Date() },
    });

    emitNotificationEvent({
      type: "read_all",
      audience: NotificationAudience.ALL,
      licenseeId: params.licenseeId || null,
      userIds: [params.userId],
    });

    return result.count;
  } catch (error) {
    if (isPrismaMissingTableError(error, ["notification"])) {
      warnStorageUnavailableOnce(
        "notification-read-all",
        "[notification] Notification table is unavailable. Mark-all-read request skipped."
      );
      return 0;
    }
    throw error;
  }
};
