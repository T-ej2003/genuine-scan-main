import {
  NotificationAudience,
  NotificationChannel,
  UserRole,
} from "@prisma/client";

import prisma from "../config/database";
import { sendIncidentEmail } from "./incidentEmailService";
import { isPrismaMissingTableError, warnStorageUnavailableOnce } from "../utils/prismaStorageGuard";

export type NotificationRealtimeEvent = {
  type: "created" | "read" | "read_all";
  audience: NotificationAudience;
  licenseeId?: string | null;
  orgId?: string | null;
  incidentId?: string | null;
  userIds?: string[];
  notificationId?: string;
};

type NotificationListener = (event: NotificationRealtimeEvent) => void;

const listeners = new Set<NotificationListener>();

export const onNotificationEvent = (cb: NotificationListener) => {
  listeners.add(cb);
  return () => listeners.delete(cb);
};

const emitNotificationEvent = (event: NotificationRealtimeEvent) => {
  for (const cb of listeners) {
    try {
      cb(event);
    } catch {
      // ignore listener failures
    }
  }
};

const normalizeRole = (role: UserRole): NotificationAudience => {
  if (role === UserRole.SUPER_ADMIN || role === UserRole.PLATFORM_SUPER_ADMIN) return NotificationAudience.SUPER_ADMIN;
  if (role === UserRole.LICENSEE_ADMIN || role === UserRole.ORG_ADMIN) return NotificationAudience.LICENSEE_ADMIN;
  return NotificationAudience.MANUFACTURER;
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
  const channels = params.channels && params.channels.length > 0 ? params.channels : [NotificationChannel.WEB];

  const userWhere: any = {
    isActive: true,
    deletedAt: null,
  };
  const roleWhere = roleFilter(params.audience);
  if (roleWhere) userWhere.role = roleWhere;
  if (params.licenseeId) userWhere.licenseeId = params.licenseeId;
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
      }
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

    if (channel === NotificationChannel.WEB) {
      emitNotificationEvent({
        type: "created",
        audience: NotificationAudience.ALL,
        licenseeId: params.licenseeId || null,
        orgId: params.orgId || null,
        incidentId: params.incidentId || null,
        userIds: [params.userId],
        notificationId: created.id,
      });
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
      licenseeId: null,
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

export const listNotificationsForUser = async (params: {
  userId: string;
  role: UserRole;
  licenseeId?: string | null;
  orgId?: string | null;
  limit: number;
  offset: number;
  unreadOnly?: boolean;
}) => {
  const audience = normalizeRole(params.role);

  const scopedBroadcast: any = {
    userId: null,
    channel: NotificationChannel.WEB,
    audience: { in: [NotificationAudience.ALL, audience] },
  };

  if (params.role !== UserRole.SUPER_ADMIN && params.role !== UserRole.PLATFORM_SUPER_ADMIN) {
    const tenantFilters: any[] = [];
    if (params.licenseeId) {
      tenantFilters.push({ OR: [{ licenseeId: params.licenseeId }, { licenseeId: null }] });
    } else if (audience !== NotificationAudience.MANUFACTURER) {
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

  if (params.unreadOnly) {
    where.readAt = null;
  }

  try {
    const [notifications, total] = await Promise.all([
      prisma.notification.findMany({
        where,
        orderBy: [{ createdAt: "desc" }],
        take: params.limit,
        skip: params.offset,
      }),
      prisma.notification.count({ where }),
    ]);

    const unread = await prisma.notification.count({
      where: {
        OR: scopedOr,
        readAt: null,
      },
    });

    return {
      notifications,
      total,
      unread,
    };
  } catch (error) {
    if (isPrismaMissingTableError(error, ["notification"])) {
      warnStorageUnavailableOnce(
        "notification-list",
        "[notification] Notification table is unavailable. Returning empty notification list."
      );
      return {
        notifications: [],
        total: 0,
        unread: 0,
      };
    }
    throw error;
  }
};

export const markNotificationRead = async (params: {
  notificationId: string;
  userId: string;
  role: UserRole;
  licenseeId?: string | null;
  orgId?: string | null;
}) => {
  const audience = normalizeRole(params.role);
  try {
    const sharedScope: any = {
      userId: null,
      channel: NotificationChannel.WEB,
      audience: { in: [NotificationAudience.ALL, audience] },
    };
    if (params.role !== UserRole.SUPER_ADMIN && params.role !== UserRole.PLATFORM_SUPER_ADMIN) {
      const tenantFilters: any[] = [];
      if (params.licenseeId) {
        tenantFilters.push({ OR: [{ licenseeId: params.licenseeId }, { licenseeId: null }] });
      } else if (audience !== NotificationAudience.MANUFACTURER) {
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
  orgId?: string | null;
}) => {
  const audience = normalizeRole(params.role);

  const sharedScope: any = {
    userId: null,
    channel: NotificationChannel.WEB,
    audience: { in: [NotificationAudience.ALL, audience] },
  };
  if (params.role !== UserRole.SUPER_ADMIN && params.role !== UserRole.PLATFORM_SUPER_ADMIN) {
    const tenantFilters: any[] = [];
    if (params.licenseeId) {
      tenantFilters.push({ OR: [{ licenseeId: params.licenseeId }, { licenseeId: null }] });
    } else if (audience !== NotificationAudience.MANUFACTURER) {
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
