import { Response } from "express";
import { z } from "zod";
import prisma from "../config/database";
import { AuthRequest } from "../middleware/auth";
import { createAuditLog } from "../services/auditService";
import { hashPassword, verifyPassword } from "../services/auth/passwordService";

const updateProfileSchema = z.object({
  name: z.string().trim().min(2).max(80).optional(),
  email: z.string().trim().email().max(320).optional(),
}).strict();

const changePasswordSchema = z.object({
  currentPassword: z.string().min(1),
  newPassword: z.string().min(6).max(200),
}).strict();

export const updateMyProfile = async (req: AuthRequest, res: Response) => {
  try {
    const userId = req.user?.userId;
    if (!userId) return res.status(401).json({ success: false, error: "Not authenticated" });

    const parsed = updateProfileSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0].message });
    }

    const data: any = {};
    if (parsed.data.name !== undefined) data.name = parsed.data.name;
    if (parsed.data.email !== undefined) data.email = parsed.data.email.toLowerCase();

    if (!Object.keys(data).length) {
      return res.status(400).json({ success: false, error: "No changes provided" });
    }

    // email uniqueness check (if changing email)
    if (data.email) {
      const exists = await prisma.user.findUnique({ where: { email: data.email } });
      if (exists && exists.id !== userId) {
        return res.status(409).json({ success: false, error: "Email already in use" });
      }
    }

    const updated = await prisma.user.update({
      where: { id: userId },
      data,
      select: { id: true, name: true, email: true, role: true, licenseeId: true, isActive: true, createdAt: true },
    });

    await createAuditLog({
      userId,
      action: "UPDATE_MY_PROFILE",
      entityType: "User",
      entityId: userId,
      details: { changed: Object.keys(data) },
      ipAddress: req.ip,
    });

    return res.json({ success: true, data: updated });
  } catch (e) {
    console.error("updateMyProfile error:", e);
    return res.status(500).json({ success: false, error: "Internal server error" });
  }
};

export const changeMyPassword = async (req: AuthRequest, res: Response) => {
  try {
    const userId = req.user?.userId;
    if (!userId) return res.status(401).json({ success: false, error: "Not authenticated" });

    const parsed = changePasswordSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0].message });
    }

    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { id: true, passwordHash: true },
    });

    if (!user) return res.status(404).json({ success: false, error: "User not found" });

    if (!user.passwordHash) {
      return res.status(400).json({ success: false, error: "Account has no password set. Use password reset." });
    }

    const ok = await verifyPassword(user.passwordHash, parsed.data.currentPassword);
    if (!ok) {
      return res.status(400).json({ success: false, error: "Current password is incorrect" });
    }

    const passwordHash = await hashPassword(parsed.data.newPassword);

    await prisma.user.update({
      where: { id: userId },
      data: { passwordHash },
    });

    await createAuditLog({
      userId,
      action: "CHANGE_MY_PASSWORD",
      entityType: "User",
      entityId: userId,
      details: {},
      ipAddress: req.ip,
    });

    return res.json({ success: true, data: { changed: true } });
  } catch (e) {
    console.error("changeMyPassword error:", e);
    return res.status(500).json({ success: false, error: "Internal server error" });
  }
};
