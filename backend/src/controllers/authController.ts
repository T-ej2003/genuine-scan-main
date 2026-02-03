import { Request, Response } from "express";
import bcrypt from "bcryptjs";
import jwt, { type SignOptions } from "jsonwebtoken";
import { z } from "zod";
import prisma from "../config/database";
import { createAuditLog } from "../services/auditService";

const loginSchema = z.object({
  email: z.string().email("Invalid email format"),
  password: z.string().min(6, "Password must be at least 6 characters"),
});

export const login = async (req: Request, res: Response) => {
  try {
    const validation = loginSchema.safeParse(req.body);

    if (!validation.success) {
      return res.status(400).json({
        success: false,
        error: validation.error.errors[0]?.message ?? "Invalid request",
      });
    }

    const { email, password } = validation.data;

    const user = await prisma.user.findUnique({
      where: { email: email.toLowerCase() },
      include: { licensee: true },
    });

    if (!user) {
      return res.status(401).json({ success: false, error: "Invalid email or password" });
    }

    const isValidPassword = await bcrypt.compare(password, user.passwordHash);
    if (!isValidPassword) {
      return res.status(401).json({ success: false, error: "Invalid email or password" });
    }

    if (user.deletedAt || user.isActive === false) {
      return res.status(403).json({
        success: false,
        error: "Account is deactivated. Contact administrator.",
      });
    }

    const jwtSecret = process.env.JWT_SECRET;
    if (!jwtSecret) {
      return res.status(500).json({ success: false, error: "JWT secret not configured" });
    }

    const expiresIn = process.env.JWT_EXPIRES_IN || "7d";
    const signOptions: SignOptions = { expiresIn: expiresIn as SignOptions["expiresIn"] };

    const token = jwt.sign(
      {
        userId: user.id,
        email: user.email,
        role: user.role,
        licenseeId: user.licenseeId,
      },
      jwtSecret,
      signOptions
    );

    await createAuditLog({
      userId: user.id,
      licenseeId: user.licenseeId ?? undefined,
      action: "LOGIN",
      entityType: "User",
      entityId: user.id,
      ipAddress: req.ip,
    });

    return res.json({
      success: true,
      data: {
        token,
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          role: user.role,
          licenseeId: user.licenseeId,
          licensee: user.licensee
            ? { id: user.licensee.id, name: user.licensee.name, prefix: user.licensee.prefix }
            : null,
        },
      },
    });
  } catch (error) {
    console.error("Login error:", error);
    return res.status(500).json({ success: false, error: "Internal server error" });
  }
};

export const me = async (req: Request, res: Response) => {
  try {
    const authReq = req as any;
    const userId = authReq.user?.userId;

    if (!userId) {
      return res.status(401).json({ success: false, error: "Not authenticated" });
    }

    const user = await prisma.user.findUnique({
      where: { id: userId },
      include: { licensee: true },
    });

    if (!user) {
      return res.status(404).json({ success: false, error: "User not found" });
    }

    return res.json({
      success: true,
      data: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        licenseeId: user.licenseeId,
        licensee: user.licensee
          ? { id: user.licensee.id, name: user.licensee.name, prefix: user.licensee.prefix }
          : null,
      },
    });
  } catch (error) {
    console.error("Me error:", error);
    return res.status(500).json({ success: false, error: "Internal server error" });
  }
};
