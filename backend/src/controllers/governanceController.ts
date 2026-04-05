import { Response } from "express";
import { UserRole } from "@prisma/client";
import { z } from "zod";

import { AuthRequest } from "../middleware/auth";
import {
  buildIncidentEvidenceAuditBundle,
  generateComplianceReport,
  getOrCreateRetentionPolicy,
  listTenantFeatureFlags,
  runRetentionLifecycle,
  updateRetentionPolicy,
  upsertTenantFeatureFlag,
} from "../services/governanceService";
import { createAuditLog } from "../services/auditService";
import prisma from "../config/database";
import { listCompliancePackJobs, loadCompliancePackJobBuffer, runCompliancePackJob } from "../services/compliancePackService";
import { createSensitiveActionApproval, SENSITIVE_ACTION_KEYS } from "../services/sensitiveActionApprovalService";

const flagUpdateSchema = z.object({
  licenseeId: z.string().uuid().optional(),
  key: z.string().trim().min(3).max(120),
  enabled: z.boolean(),
  config: z.unknown().optional(),
}).strict();

const retentionPatchSchema = z.object({
  licenseeId: z.string().uuid().optional(),
  retentionDays: z.number().int().min(30).max(3650).optional(),
  purgeEnabled: z.boolean().optional(),
  exportBeforePurge: z.boolean().optional(),
  legalHoldTags: z.array(z.string().trim().min(1).max(40)).max(20).optional(),
}).strict();

const retentionRunSchema = z.object({
  licenseeId: z.string().uuid().optional(),
  mode: z.enum(["PREVIEW", "APPLY"]).default("PREVIEW"),
}).strict();

const compliancePackRunSchema = z.object({
  licenseeId: z.string().uuid().optional(),
  from: z.string().optional(),
  to: z.string().optional(),
}).strict();

const incidentIdParamSchema = z.object({
  id: z.string().uuid("Invalid incident id"),
}).strict();

const governanceQuerySchema = z.object({
  licenseeId: z.string().uuid().optional(),
}).strict();

const complianceReportQuerySchema = z.object({
  licenseeId: z.string().uuid().optional(),
  from: z.string().trim().max(64).optional(),
  to: z.string().trim().max(64).optional(),
}).strict();

const compliancePackJobsQuerySchema = z.object({
  licenseeId: z.string().uuid().optional(),
  limit: z.coerce.number().int().min(1).max(200).optional(),
  offset: z.coerce.number().int().min(0).max(20000).optional(),
}).strict();

const compliancePackJobParamSchema = z.object({
  id: z.string().uuid("Invalid compliance pack job id"),
}).strict();

const resolveLicenseeScope = (req: AuthRequest, value?: string) => {
  if (!req.user) return null;
  if (req.user.role === UserRole.SUPER_ADMIN || req.user.role === UserRole.PLATFORM_SUPER_ADMIN) {
    return value || String(req.query.licenseeId || "").trim() || null;
  }
  return req.user.licenseeId || null;
};

const toDate = (value: unknown) => {
  const raw = String(value || "").trim();
  if (!raw) return null;
  const dt = new Date(raw);
  return Number.isFinite(dt.getTime()) ? dt : null;
};

export const getFeatureFlags = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user) return res.status(401).json({ success: false, error: "Not authenticated" });
    const parsed = governanceQuerySchema.safeParse(req.query || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid filters" });
    }

    const licenseeId = resolveLicenseeScope(req, parsed.data.licenseeId);
    if (!licenseeId) {
      return res.status(400).json({ success: false, error: "licenseeId is required" });
    }

    const flags = await listTenantFeatureFlags(licenseeId);
    return res.json({ success: true, data: { licenseeId, flags } });
  } catch (error) {
    console.error("getFeatureFlags error:", error);
    return res.status(500).json({ success: false, error: "Failed to load feature flags" });
  }
};

export const upsertFeatureFlag = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user) return res.status(401).json({ success: false, error: "Not authenticated" });

    const parsed = flagUpdateSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid payload" });
    }

    const licenseeId = resolveLicenseeScope(req, parsed.data.licenseeId);
    if (!licenseeId) {
      return res.status(400).json({ success: false, error: "licenseeId is required" });
    }

    const approval = await createSensitiveActionApproval({
      actionKey: SENSITIVE_ACTION_KEYS.FEATURE_FLAG_UPSERT,
      actor: {
        userId: req.user.userId,
        role: req.user.role,
        orgId: req.user.orgId || null,
        licenseeId: req.user.licenseeId || null,
      },
      orgId: req.user.orgId || null,
      licenseeId,
      entityType: "TenantFeatureFlag",
      entityId: `${licenseeId}:${parsed.data.key}`,
      summary: {
        key: parsed.data.key,
        enabled: parsed.data.enabled,
      },
      payload: {
        licenseeId,
        key: parsed.data.key,
        enabled: parsed.data.enabled,
        config: parsed.data.config,
      },
      ipAddress: req.ip,
      userAgent: req.get("user-agent") || null,
    });

    return res.status(202).json({
      success: true,
      data: {
        approvalRequired: true,
        approvalId: approval.id,
        status: approval.status,
        expiresAt: approval.expiresAt,
      },
    });
  } catch (error) {
    console.error("upsertFeatureFlag error:", error);
    return res.status(500).json({ success: false, error: "Failed to save feature flag" });
  }
};

export const getRetentionPolicyController = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user) return res.status(401).json({ success: false, error: "Not authenticated" });
    const parsed = governanceQuerySchema.safeParse(req.query || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid filters" });
    }

    const licenseeId = resolveLicenseeScope(req, parsed.data.licenseeId);
    if (!licenseeId) {
      return res.status(400).json({ success: false, error: "licenseeId is required" });
    }

    const policy = await getOrCreateRetentionPolicy(licenseeId);
    return res.json({ success: true, data: policy });
  } catch (error) {
    console.error("getRetentionPolicyController error:", error);
    return res.status(500).json({ success: false, error: "Failed to load retention policy" });
  }
};

export const patchRetentionPolicyController = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user) return res.status(401).json({ success: false, error: "Not authenticated" });

    const parsed = retentionPatchSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid payload" });
    }

    const licenseeId = resolveLicenseeScope(req, parsed.data.licenseeId);
    if (!licenseeId) {
      return res.status(400).json({ success: false, error: "licenseeId is required" });
    }

    const approval = await createSensitiveActionApproval({
      actionKey: SENSITIVE_ACTION_KEYS.RETENTION_POLICY_PATCH,
      actor: {
        userId: req.user.userId,
        role: req.user.role,
        orgId: req.user.orgId || null,
        licenseeId: req.user.licenseeId || null,
      },
      orgId: req.user.orgId || null,
      licenseeId,
      entityType: "EvidenceRetentionPolicy",
      entityId: licenseeId,
      summary: {
        retentionDays: parsed.data.retentionDays ?? null,
        purgeEnabled: parsed.data.purgeEnabled ?? null,
        exportBeforePurge: parsed.data.exportBeforePurge ?? null,
      },
      payload: {
        licenseeId,
        retentionDays: parsed.data.retentionDays,
        purgeEnabled: parsed.data.purgeEnabled,
        exportBeforePurge: parsed.data.exportBeforePurge,
        legalHoldTags: parsed.data.legalHoldTags,
      },
      ipAddress: req.ip,
      userAgent: req.get("user-agent") || null,
    });

    return res.status(202).json({
      success: true,
      data: {
        approvalRequired: true,
        approvalId: approval.id,
        status: approval.status,
        expiresAt: approval.expiresAt,
      },
    });
  } catch (error) {
    console.error("patchRetentionPolicyController error:", error);
    return res.status(500).json({ success: false, error: "Failed to update retention policy" });
  }
};

export const runRetentionJobController = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user) return res.status(401).json({ success: false, error: "Not authenticated" });

    const parsed = retentionRunSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid payload" });
    }

    const licenseeId = resolveLicenseeScope(req, parsed.data.licenseeId);
    if (!licenseeId) {
      return res.status(400).json({ success: false, error: "licenseeId is required" });
    }

    if (parsed.data.mode === "APPLY") {
      const approval = await createSensitiveActionApproval({
        actionKey: SENSITIVE_ACTION_KEYS.RETENTION_APPLY,
        actor: {
          userId: req.user.userId,
          role: req.user.role,
          orgId: req.user.orgId || null,
          licenseeId: req.user.licenseeId || null,
        },
        orgId: req.user.orgId || null,
        licenseeId,
        entityType: "EvidenceRetentionJob",
        entityId: licenseeId,
        summary: {
          mode: parsed.data.mode,
        },
        payload: {
          licenseeId,
        },
        ipAddress: req.ip,
        userAgent: req.get("user-agent") || null,
      });

      return res.status(202).json({
        success: true,
        data: {
          approvalRequired: true,
          approvalId: approval.id,
          status: approval.status,
          expiresAt: approval.expiresAt,
        },
      });
    }

    const result = await runRetentionLifecycle({
      licenseeId,
      startedByUserId: req.user.userId,
      mode: parsed.data.mode,
    });

    await createAuditLog({
      userId: req.user.userId,
      licenseeId,
      action: "EVIDENCE_RETENTION_JOB_RUN",
      entityType: "EvidenceRetentionJob",
      entityId: result.job.id,
      ipAddress: req.ip,
      details: {
        mode: parsed.data.mode,
        evaluated: result.evaluated,
        purged: result.purged,
      },
    });

    return res.status(201).json({ success: true, data: result });
  } catch (error) {
    console.error("runRetentionJobController error:", error);
    return res.status(500).json({ success: false, error: "Failed to run retention job" });
  }
};

export const exportIncidentEvidenceBundleController = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user) return res.status(401).json({ success: false, error: "Not authenticated" });

    const paramsParsed = incidentIdParamSchema.safeParse(req.params || {});
    if (!paramsParsed.success) {
      return res.status(400).json({ success: false, error: paramsParsed.error.errors[0]?.message || "Incident ID is required" });
    }
    const incidentId = paramsParsed.data.id;

    const incident = await prisma.incident.findFirst({
      where:
        req.user.role === UserRole.SUPER_ADMIN || req.user.role === UserRole.PLATFORM_SUPER_ADMIN
          ? { id: incidentId }
          : { id: incidentId, licenseeId: req.user.licenseeId || "__none__" },
      select: { id: true, licenseeId: true },
    });

    if (!incident) return res.status(404).json({ success: false, error: "Incident not found" });

    const bundle = await buildIncidentEvidenceAuditBundle(incident.id);

    await createAuditLog({
      userId: req.user.userId,
      licenseeId: incident.licenseeId || undefined,
      action: "INCIDENT_EVIDENCE_BUNDLE_EXPORTED",
      entityType: "Incident",
      entityId: incident.id,
      ipAddress: req.ip,
      details: bundle.metadata,
    });

    res.setHeader("Content-Type", "application/zip");
    res.setHeader("Content-Disposition", `attachment; filename=\"${bundle.fileName}\"`);
    return res.status(200).send(bundle.buffer);
  } catch (error) {
    console.error("exportIncidentEvidenceBundleController error:", error);
    return res.status(500).json({ success: false, error: "Failed to export incident evidence bundle" });
  }
};

export const generateComplianceReportController = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user) return res.status(401).json({ success: false, error: "Not authenticated" });
    const parsed = complianceReportQuerySchema.safeParse(req.query || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid filters" });
    }

    const licenseeId = resolveLicenseeScope(req, parsed.data.licenseeId);
    const from = toDate(parsed.data.from);
    const to = toDate(parsed.data.to);

    const report = await generateComplianceReport({
      actor: {
        userId: req.user.userId,
        role: req.user.role,
        licenseeId: req.user.licenseeId,
      },
      licenseeId,
      from,
      to,
    });

    return res.json({ success: true, data: report });
  } catch (error) {
    console.error("generateComplianceReportController error:", error);
    return res.status(500).json({ success: false, error: "Failed to generate compliance report" });
  }
};

export const runCompliancePackController = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user) return res.status(401).json({ success: false, error: "Not authenticated" });

    const parsed = compliancePackRunSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid payload" });
    }

    const licenseeId = resolveLicenseeScope(req, parsed.data.licenseeId);
    const from = toDate(parsed.data.from || req.query.from);
    const to = toDate(parsed.data.to || req.query.to);

    const out = await runCompliancePackJob({
      triggerType: "MANUAL",
      actor: {
        userId: req.user.userId,
        role: req.user.role,
        licenseeId: req.user.licenseeId,
      },
      licenseeId,
      from,
      to,
    });

    return res.status(201).json({ success: true, data: out.job });
  } catch (error) {
    console.error("runCompliancePackController error:", error);
    return res.status(500).json({ success: false, error: "Failed to generate compliance pack" });
  }
};

export const listCompliancePackJobsController = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user) return res.status(401).json({ success: false, error: "Not authenticated" });
    const parsed = compliancePackJobsQuerySchema.safeParse(req.query || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid filters" });
    }

    const limit = parsed.data.limit ?? 20;
    const offset = parsed.data.offset ?? 0;
    const licenseeId = resolveLicenseeScope(req, parsed.data.licenseeId);

    const result = await listCompliancePackJobs({
      licenseeId,
      limit,
      offset,
    });

    return res.json({
      success: true,
      data: {
        jobs: result.jobs,
        total: result.total,
        limit,
        offset,
      },
    });
  } catch (error) {
    console.error("listCompliancePackJobsController error:", error);
    return res.status(500).json({ success: false, error: "Failed to list compliance pack jobs" });
  }
};

export const downloadCompliancePackJobController = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user) return res.status(401).json({ success: false, error: "Not authenticated" });
    const paramsParsed = compliancePackJobParamSchema.safeParse(req.params || {});
    if (!paramsParsed.success) {
      return res.status(400).json({ success: false, error: paramsParsed.error.errors[0]?.message || "Compliance pack job ID is required" });
    }

    const row = await prisma.compliancePackJob.findFirst({
      where:
        req.user.role === UserRole.SUPER_ADMIN || req.user.role === UserRole.PLATFORM_SUPER_ADMIN
          ? { id: paramsParsed.data.id }
          : { id: paramsParsed.data.id, licenseeId: req.user.licenseeId || "__none__" },
      select: {
        id: true,
        licenseeId: true,
        fileName: true,
        storageKey: true,
        status: true,
      },
    });
    if (!row) return res.status(404).json({ success: false, error: "Compliance pack job not found" });
    if (row.status !== "COMPLETED" || !row.storageKey || !row.fileName) {
      return res.status(409).json({ success: false, error: "Compliance pack is not ready" });
    }

    const buffer = loadCompliancePackJobBuffer(row.storageKey);
    if (!buffer) {
      return res.status(404).json({ success: false, error: "Compliance pack file not found" });
    }

    await createAuditLog({
      userId: req.user.userId,
      licenseeId: row.licenseeId || undefined,
      action: "COMPLIANCE_PACK_DOWNLOADED",
      entityType: "CompliancePackJob",
      entityId: row.id,
      ipAddress: req.ip,
    });

    res.setHeader("Content-Type", "application/zip");
    res.setHeader("Content-Disposition", `attachment; filename=\"${row.fileName}\"`);
    return res.status(200).send(buffer);
  } catch (error) {
    console.error("downloadCompliancePackJobController error:", error);
    return res.status(500).json({ success: false, error: "Failed to download compliance pack" });
  }
};
