import { NotificationAudience, UserRole } from "@prisma/client";
import { Response } from "express";

import { AuthRequest } from "../middleware/auth";
import { listNotificationsForUser, onNotificationEvent, type NotificationRealtimeEvent } from "../services/notificationService";

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

const writeSse = (res: Response, event: string, data: any) => {
  res.write(`event: ${event}\n`);
  res.write(`data: ${JSON.stringify(data)}\n\n`);
};

const shouldDeliver = (event: NotificationRealtimeEvent, user: NonNullable<AuthRequest["user"]>) => {
  if (event.userIds?.length && event.userIds.includes(user.userId)) return true;

  if (event.audience !== NotificationAudience.ALL) {
    const requiredAudience = audienceForRole(user.role);
    if (event.audience !== requiredAudience) return false;
  }

  if (!isPlatform(user.role)) {
    const userLicenseeId = user.licenseeId || null;
    const userOrgId = user.orgId || null;
    const userAudience = audienceForRole(user.role);

    if (event.orgId) {
      if (!userOrgId || event.orgId !== userOrgId) return false;
    }

    if (event.licenseeId && userLicenseeId && event.licenseeId !== userLicenseeId) return false;
    if (event.licenseeId && !userLicenseeId) {
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

    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache, no-transform");
    res.setHeader("Connection", "keep-alive");
    res.flushHeaders?.();

    const sendSnapshot = async (reason: string) => {
      const payload = await listNotificationsForUser({
        userId: req.user!.userId,
        role: req.user!.role,
        licenseeId: req.user!.licenseeId,
        orgId: req.user!.orgId,
        limit,
        offset: 0,
      });

      writeSse(res, "notifications", {
        reason,
        ...payload,
        limit,
        offset: 0,
        serverTime: new Date().toISOString(),
      });
    };

    await sendSnapshot("initial");

    const keepAlive = setInterval(() => {
      res.write(": ping\n\n");
    }, 25_000);

    const off = onNotificationEvent(async (event) => {
      try {
        if (!shouldDeliver(event, req.user!)) return;
        await sendSnapshot(event.type);
      } catch {
        // ignore per-event failures
      }
    });

    req.on("close", () => {
      clearInterval(keepAlive);
      off();
      res.end();
    });
  } catch (error) {
    console.error("notificationEvents error:", error);
    return res.status(500).end();
  }
};
