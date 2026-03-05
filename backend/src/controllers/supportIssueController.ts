import fs from "fs";
import path from "path";
import { NotificationAudience, NotificationChannel, UserRole } from "@prisma/client";
import { Request, Response } from "express";
import { z } from "zod";

import prisma from "../config/database";
import { AuthRequest } from "../middleware/auth";
import { createAuditLog } from "../services/auditService";
import { createRoleNotifications } from "../services/notificationService";
import { resolveSupportIssueUploadPath } from "../middleware/supportIssueUpload";
import { isPrismaMissingTableError, warnStorageUnavailableOnce } from "../utils/prismaStorageGuard";

const toInt = (value: unknown, fallback: number, min: number, max: number) => {
  const n = Number.parseInt(String(value ?? ""), 10);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, n));
};

const createSchema = z.object({
  title: z.string().trim().min(5).max(160),
  description: z.string().trim().max(5000).optional().or(z.literal("")),
  sourcePath: z.string().trim().max(500).optional().or(z.literal("")),
  pageUrl: z.string().trim().max(1200).optional().or(z.literal("")),
  autoDetected: z.string().trim().toLowerCase().optional(),
  diagnostics: z.string().trim().max(250_000).optional().or(z.literal("")),
});

const parseDiagnostics = (raw?: string | null) => {
  const text = String(raw || "").trim();
  if (!text) return null;
  try {
    const parsed = JSON.parse(text);
    if (parsed && typeof parsed === "object") return parsed;
    return { raw: text };
  } catch {
    return { raw: text };
  }
};

const isPlatform = (role: UserRole) => role === UserRole.SUPER_ADMIN || role === UserRole.PLATFORM_SUPER_ADMIN;

export const createSupportIssueReport = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user) return res.status(401).json({ success: false, error: "Not authenticated" });

    const parsed = createSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid payload" });
    }

    const file = (req as any).file as Express.Multer.File | undefined;
    const screenshotPath = file?.filename || null;
    const screenshotMime = file?.mimetype || null;
    const screenshotSize = file?.size || null;
    const diagnostics = parseDiagnostics(parsed.data.diagnostics);

    const created = await prisma.supportIssueReport.create({
      data: {
        reporterUserId: req.user.userId,
        reporterRole: req.user.role,
        licenseeId: req.user.licenseeId || null,
        title: parsed.data.title,
        description: parsed.data.description?.trim() || null,
        sourcePath: parsed.data.sourcePath?.trim() || null,
        pageUrl: parsed.data.pageUrl?.trim() || null,
        autoDetected: parsed.data.autoDetected === "true" || parsed.data.autoDetected === "1",
        screenshotPath,
        screenshotMime,
        screenshotSize,
        diagnostics: diagnostics as any,
      },
      include: {
        reporterUser: { select: { id: true, name: true, email: true, role: true } },
      },
    });

    await createAuditLog({
      userId: req.user.userId,
      licenseeId: req.user.licenseeId || undefined,
      orgId: req.user.orgId || undefined,
      action: "SUPPORT_ISSUE_REPORTED",
      entityType: "SupportIssueReport",
      entityId: created.id,
      details: {
        autoDetected: created.autoDetected,
        sourcePath: created.sourcePath,
        screenshotAttached: Boolean(created.screenshotPath),
      },
      ipAddress: req.ip,
    });

    await createRoleNotifications({
      audience: NotificationAudience.SUPER_ADMIN,
      type: "support_issue_reported",
      title: "New support issue reported",
      body: `${created.reporterUser?.name || created.reporterUser?.email || "User"} submitted: ${created.title}`,
      licenseeId: created.licenseeId || null,
      data: {
        supportReportId: created.id,
        sourcePath: created.sourcePath,
        pageUrl: created.pageUrl,
        reporterUserId: created.reporterUserId,
        reporterRole: created.reporterRole,
        targetRoute: "/support",
      },
      channels: [NotificationChannel.WEB, NotificationChannel.EMAIL],
    });

    return res.status(201).json({
      success: true,
      data: {
        id: created.id,
        status: created.status,
        createdAt: created.createdAt,
      },
    });
  } catch (error) {
    if (isPrismaMissingTableError(error, ["supportissuereport"])) {
      warnStorageUnavailableOnce(
        "support-issue-storage",
        "[support-issue] support issue storage is unavailable. Report was not persisted."
      );
      return res.status(503).json({ success: false, error: "Support report storage unavailable" });
    }
    console.error("createSupportIssueReport error:", error);
    return res.status(500).json({ success: false, error: "Failed to submit support report" });
  }
};

export const listSupportIssueReports = async (req: AuthRequest, res: Response) => {
  const limit = toInt(req.query.limit, 50, 1, 200);
  const offset = toInt(req.query.offset, 0, 0, 5000);
  try {
    if (!req.user) return res.status(401).json({ success: false, error: "Not authenticated" });

    const where: any = {};
    if (!isPlatform(req.user.role)) {
      where.reporterUserId = req.user.userId;
    } else if (req.query.licenseeId) {
      where.licenseeId = String(req.query.licenseeId);
    }

    const [reports, total] = await Promise.all([
      prisma.supportIssueReport.findMany({
        where,
        orderBy: [{ createdAt: "desc" }],
        take: limit,
        skip: offset,
        include: {
          reporterUser: { select: { id: true, name: true, email: true, role: true } },
          licensee: { select: { id: true, name: true, prefix: true } },
        },
      }),
      prisma.supportIssueReport.count({ where }),
    ]);

    return res.json({
      success: true,
      data: {
        reports,
        total,
        limit,
        offset,
      },
    });
  } catch (error) {
    if (isPrismaMissingTableError(error, ["supportissuereport"])) {
      warnStorageUnavailableOnce(
        "support-issue-list-storage",
        "[support-issue] support issue storage is unavailable. Returning empty report list."
      );
      return res.json({
        success: true,
        data: { reports: [], total: 0, limit, offset, storageUnavailable: true },
      });
    }
    console.error("listSupportIssueReports error:", error);
    return res.status(500).json({ success: false, error: "Failed to load support reports" });
  }
};

export const serveSupportIssueScreenshot = async (req: Request, res: Response) => {
  try {
    const authReq = req as AuthRequest;
    if (!authReq.user) return res.status(401).json({ success: false, error: "Not authenticated" });

    const fileName = String(req.params.fileName || "").trim();
    if (!fileName) return res.status(404).json({ success: false, error: "File not found" });

    const report = await prisma.supportIssueReport.findFirst({
      where: { screenshotPath: fileName },
      select: {
        reporterUserId: true,
        licenseeId: true,
      },
    });
    if (!report) return res.status(404).json({ success: false, error: "File not found" });

    if (!isPlatform(authReq.user.role)) {
      const sameReporter = report.reporterUserId === authReq.user.userId;
      const sameLicensee =
        Boolean(report.licenseeId) &&
        Boolean(authReq.user.licenseeId) &&
        String(report.licenseeId) === String(authReq.user.licenseeId);
      if (!sameReporter && !sameLicensee) {
        return res.status(403).json({ success: false, error: "Access denied" });
      }
    }

    const resolved = resolveSupportIssueUploadPath(fileName);
    const uploadsRoot = path.resolve(__dirname, "../../uploads/support-issues");
    if (!resolved.startsWith(uploadsRoot)) {
      return res.status(400).json({ success: false, error: "Invalid file path" });
    }
    if (!fs.existsSync(resolved)) return res.status(404).json({ success: false, error: "File not found" });
    return res.sendFile(resolved);
  } catch (error) {
    console.error("serveSupportIssueScreenshot error:", error);
    return res.status(500).json({ success: false, error: "Failed to read file" });
  }
};
