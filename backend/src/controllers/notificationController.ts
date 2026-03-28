import { Response } from "express";
import { z } from "zod";

import { AuthRequest } from "../middleware/auth";
import { resolveAccessibleLicenseeIdsForUser } from "../services/manufacturerScopeService";
import {
  listNotificationsForUser,
  markAllNotificationsRead,
  markNotificationRead,
} from "../services/notificationService";

const toInt = (value: unknown, fallback: number, min: number, max: number) => {
  const n = Number.parseInt(String(value ?? ""), 10);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, n));
};

const parseBool = (value: unknown) => {
  if (typeof value === "boolean") return value;
  const normalized = String(value || "").trim().toLowerCase();
  if (["1", "true", "yes"].includes(normalized)) return true;
  if (["0", "false", "no"].includes(normalized)) return false;
  return false;
};

const notificationIdParamSchema = z.object({
  id: z.string().uuid("Invalid notification id"),
}).strict();

const cursorSchema = z
  .string()
  .trim()
  .max(512)
  .optional();

export const listNotifications = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user) return res.status(401).json({ success: false, error: "Not authenticated" });

    const limit = toInt(req.query.limit, 40, 1, 200);
    const offset = toInt(req.query.offset, 0, 0, 2000);
    const unreadOnly = parseBool(req.query.unreadOnly);
    const cursor = cursorSchema.safeParse(req.query.cursor).success ? String(req.query.cursor || "").trim() || undefined : undefined;
    const licenseeIds = await resolveAccessibleLicenseeIdsForUser(req.user);

    const data = await listNotificationsForUser({
      userId: req.user.userId,
      role: req.user.role,
      licenseeId: req.user.licenseeId,
      licenseeIds,
      orgId: req.user.orgId,
      limit,
      offset,
      unreadOnly,
      cursor,
    });

    return res.json({
      success: true,
      data: {
        ...data,
        limit,
        offset,
        cursor: cursor || null,
      },
    });
  } catch (error) {
    console.error("listNotifications error:", error);
    return res.status(500).json({ success: false, error: "Failed to load notifications" });
  }
};

export const readNotification = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user) return res.status(401).json({ success: false, error: "Not authenticated" });

    const paramsParsed = notificationIdParamSchema.safeParse(req.params || {});
    if (!paramsParsed.success) {
      return res.status(400).json({ success: false, error: paramsParsed.error.errors[0]?.message || "Notification ID is required" });
    }
    const id = paramsParsed.data.id;
    const licenseeIds = await resolveAccessibleLicenseeIdsForUser(req.user);

    const updated = await markNotificationRead({
      notificationId: id,
      userId: req.user.userId,
      role: req.user.role,
      licenseeId: req.user.licenseeId,
      licenseeIds,
      orgId: req.user.orgId,
    });

    if (!updated) return res.status(404).json({ success: false, error: "Notification not found" });
    return res.json({ success: true, data: updated });
  } catch (error) {
    console.error("readNotification error:", error);
    return res.status(500).json({ success: false, error: "Failed to mark notification" });
  }
};

export const readAllNotifications = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user) return res.status(401).json({ success: false, error: "Not authenticated" });
    const licenseeIds = await resolveAccessibleLicenseeIdsForUser(req.user);

    const updatedCount = await markAllNotificationsRead({
      userId: req.user.userId,
      role: req.user.role,
      licenseeId: req.user.licenseeId,
      licenseeIds,
      orgId: req.user.orgId,
    });

    return res.json({
      success: true,
      data: { updatedCount },
    });
  } catch (error) {
    console.error("readAllNotifications error:", error);
    return res.status(500).json({ success: false, error: "Failed to mark all notifications" });
  }
};
