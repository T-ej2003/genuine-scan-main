import {
  NotificationAudience,
  NotificationChannel,
  UserRole,
} from "@prisma/client";

import prisma from "../config/database";
import { sendIncidentEmail } from "./incidentEmailService";
import { isPrismaMissingTableError, warnStorageUnavailableOnce } from "../utils/prismaStorageGuard";

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

export const notifyIncidentLifecycle = async (params: {
  incidentId: string;
  licenseeId?: string | null;
  title: string;
  body: string;
  type: string;
  data?: any;
}) => {
  const audiences: NotificationAudience[] = [NotificationAudience.SUPER_ADMIN];
  if (params.licenseeId) audiences.push(NotificationAudience.LICENSEE_ADMIN);

  for (const audience of audiences) {
    await createRoleNotifications({
      audience,
      title: params.title,
      body: params.body,
      type: params.type,
      licenseeId: audience === NotificationAudience.LICENSEE_ADMIN ? params.licenseeId || null : null,
      incidentId: params.incidentId,
      data: params.data,
      channels: [NotificationChannel.WEB, NotificationChannel.EMAIL],
    });
  }
};

export const listNotificationsForUser = async (params: {
  userId: string;
  role: UserRole;
  licenseeId?: string | null;
  limit: number;
  offset: number;
  unreadOnly?: boolean;
}) => {
  const audience = normalizeRole(params.role);

  const scopedOr: any[] = [
    { userId: params.userId },
    {
      userId: null,
      audience: { in: [NotificationAudience.ALL, audience] },
      ...(params.role === UserRole.SUPER_ADMIN || params.role === UserRole.PLATFORM_SUPER_ADMIN
        ? {}
        : {
            OR: [{ licenseeId: params.licenseeId || "__none__" }, { licenseeId: null }],
          }),
    },
  ];

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
}) => {
  const audience = normalizeRole(params.role);
  try {
    const existing = await prisma.notification.findFirst({
      where: {
        id: params.notificationId,
        OR: [
          { userId: params.userId },
          {
            userId: null,
            audience: { in: [NotificationAudience.ALL, audience] },
            ...(params.role === UserRole.SUPER_ADMIN || params.role === UserRole.PLATFORM_SUPER_ADMIN
              ? {}
              : { OR: [{ licenseeId: params.licenseeId || "__none__" }, { licenseeId: null }] }),
          },
        ],
      },
    });

    if (!existing) return null;

    return prisma.notification.update({
      where: { id: existing.id },
      data: {
        readAt: existing.readAt || new Date(),
      },
    });
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
}) => {
  const audience = normalizeRole(params.role);

  const where: any = {
    readAt: null,
    OR: [
      { userId: params.userId },
      {
        userId: null,
        audience: { in: [NotificationAudience.ALL, audience] },
        ...(params.role === UserRole.SUPER_ADMIN || params.role === UserRole.PLATFORM_SUPER_ADMIN
          ? {}
          : { OR: [{ licenseeId: params.licenseeId || "__none__" }, { licenseeId: null }] }),
      },
    ],
  };

  try {
    const result = await prisma.notification.updateMany({
      where,
      data: { readAt: new Date() },
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
