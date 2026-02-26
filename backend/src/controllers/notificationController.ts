import { Response } from "express";

import { AuthRequest } from "../middleware/auth";
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

export const listNotifications = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user) return res.status(401).json({ success: false, error: "Not authenticated" });

    const limit = toInt(req.query.limit, 40, 1, 200);
    const offset = toInt(req.query.offset, 0, 0, 2000);
    const unreadOnly = parseBool(req.query.unreadOnly);

    const data = await listNotificationsForUser({
      userId: req.user.userId,
      role: req.user.role,
      licenseeId: req.user.licenseeId,
      orgId: req.user.orgId,
      limit,
      offset,
      unreadOnly,
    });

    return res.json({
      success: true,
      data: {
        ...data,
        limit,
        offset,
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

    const id = String(req.params.id || "").trim();
    if (!id) return res.status(400).json({ success: false, error: "Notification ID is required" });

    const updated = await markNotificationRead({
      notificationId: id,
      userId: req.user.userId,
      role: req.user.role,
      licenseeId: req.user.licenseeId,
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

    const updatedCount = await markAllNotificationsRead({
      userId: req.user.userId,
      role: req.user.role,
      licenseeId: req.user.licenseeId,
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
