import { NotificationAudience, UserRole } from "@prisma/client";
import { Response } from "express";

import { AuthRequest } from "../middleware/auth";
import { b03BoundaryForRequest } from "../rls-waves/session-b/b03/requestBoundary";
import { resolveAccessibleLicenseeIdsForUser } from "../services/manufacturerScopeService";
import { listNotificationsForUser, onNotificationEvent, type NotificationRealtimeEvent } from "../services/notificationService";
import { canRoleViewNotificationType } from "../services/notificationVisibility";
import { closeSseAtTokenExpiry, writeSseRealtimeEnvelope } from "../utils/realtime";
const toInt = (value: unknown, fallback: number, min: number, max: number) => {
  const n = Number.parseInt(String(value ?? ""), 10);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, n));
};

const isPlatform = (role: UserRole) => role === UserRole.SUPER_ADMIN || role === UserRole.PLATFORM_SUPER_ADMIN;

const audienceForRole = (role: UserRole): NotificationAudience => {
  if (role === UserRole.SUPER_ADMIN || role === UserRole.PLATFORM_SUPER_ADMIN) return NotificationAudience.SUPER_ADMIN;
  if (role === UserRole.LICENSEE_ADMIN || role === UserRole.ORG_ADMIN) return NotificationAudience.LICENSEE_ADMIN;
  return NotificationAudience.MANUFACTURER;
};

const shouldDeliver = (
  event: NotificationRealtimeEvent,
  user: NonNullable<AuthRequest["user"]>,
  accessibleLicenseeIds: string[]
) => {
  if (event.notificationType && !canRoleViewNotificationType(user.role, event.notificationType)) {
    return false;
  }

  if (event.userIds?.length && event.userIds.includes(user.userId)) return true;

  if (event.audience !== NotificationAudience.ALL) {
    const requiredAudience = audienceForRole(user.role);
    if (event.audience !== requiredAudience) return false;
  }

  if (!isPlatform(user.role)) {
    const userLicenseeId = user.licenseeId || null;
    const scopedLicenseeIds = Array.from(new Set(accessibleLicenseeIds.length ? accessibleLicenseeIds : userLicenseeId ? [userLicenseeId] : []));
    const userOrgId = user.orgId || null;
    const userAudience = audienceForRole(user.role);

    if (event.orgId) {
      if (!userOrgId || event.orgId !== userOrgId) return false;
    }

    if (event.licenseeId && scopedLicenseeIds.length > 0 && !scopedLicenseeIds.includes(event.licenseeId)) return false;
    if (event.licenseeId && !scopedLicenseeIds.length && userLicenseeId && event.licenseeId !== userLicenseeId) return false;
    if (event.licenseeId && !scopedLicenseeIds.length && !userLicenseeId) {
      // Manufacturer users can be scoped by org only (legacy rows may still carry licenseeId).
      if (!(userAudience === NotificationAudience.MANUFACTURER && event.orgId && userOrgId && event.orgId === userOrgId)) {
        return false;
      }
    }
  }

  return true;
};

export const notificationEvents = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user) return res.status(401).json({ success: false, error: "Not authenticated" });

    const limit = toInt(req.query.limit, 8, 1, 40);
    const accessibleLicenseeIds = await resolveAccessibleLicenseeIdsForUser(req.user);
    const databaseBoundary = b03BoundaryForRequest(req, "notification-events");

    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache, no-transform");
    res.setHeader("Connection", "keep-alive");
    res.flushHeaders?.();

    let closed = false;
    let sending = true;
    let pendingReason: string | null = null;
    let refreshTimer: ReturnType<typeof setTimeout> | null = null;
    let keepAlive: ReturnType<typeof setInterval> | null = null;
    const closeExpiry = closeSseAtTokenExpiry(req, res, "notifications");

    const sendSnapshot = async (reason: string) => {
      const payload = await listNotificationsForUser({
        userId: req.user!.userId,
        role: req.user!.role,
        licenseeId: req.user!.licenseeId,
        licenseeIds: accessibleLicenseeIds,
        orgId: req.user!.orgId,
        limit,
        offset: 0,
        databaseBoundary,
      });

      if (closed) return;
      writeSseRealtimeEnvelope(res, {
        channel: "notifications",
        type: "snapshot",
        payload: {
          reason,
          ...payload,
          limit,
          offset: 0,
          serverTime: new Date().toISOString(),
        },
      });
    };

    const flush = async () => {
      if (sending || closed) return;
      sending = true;
      try {
        while (pendingReason && !closed) {
          const reason = pendingReason;
          pendingReason = null;
          await sendSnapshot(reason);
        }
      } catch {
        // Reconnect and resnapshot after a failed governed read.
        res.end();
      } finally {
        sending = false;
        if (pendingReason && !closed) queueSnapshot(pendingReason);
      }
    };
    const queueSnapshot = (reason: string) => {
      if (closed) return;
      pendingReason = reason;
      if (sending || refreshTimer) return;
      refreshTimer = setTimeout(() => {
        refreshTimer = null;
        void flush();
      }, 100);
    };
    const off = onNotificationEvent((event) => {
      if (shouldDeliver(event, req.user!, accessibleLicenseeIds)) queueSnapshot(event.type);
    });
    const cleanup = () => {
      if (closed) return;
      closed = true;
      if (keepAlive) clearInterval(keepAlive);
      if (refreshTimer) clearTimeout(refreshTimer);
      closeExpiry();
      off();
    };
    res.on("close", cleanup);

    try {
      await sendSnapshot("initial");
    } finally {
      sending = false;
    }
    if (closed) return;
    if (pendingReason) queueSnapshot(pendingReason);
    keepAlive = setInterval(() => {
      res.write(": ping\n\n");
    }, 25_000);

  } catch (error) {
    console.error("notificationEvents error:", error);
    if (res.headersSent) return res.end();
    return res.status(500).end();
  }
};
