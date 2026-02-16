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

const flagUpdateSchema = z.object({
  licenseeId: z.string().uuid().optional(),
  key: z.string().trim().min(3).max(120),
  enabled: z.boolean(),
  config: z.any().optional(),
});

const retentionPatchSchema = z.object({
  licenseeId: z.string().uuid().optional(),
  retentionDays: z.number().int().min(30).max(3650).optional(),
  purgeEnabled: z.boolean().optional(),
  exportBeforePurge: z.boolean().optional(),
  legalHoldTags: z.array(z.string().trim().min(1).max(40)).max(20).optional(),
});

const retentionRunSchema = z.object({
  licenseeId: z.string().uuid().optional(),
  mode: z.enum(["PREVIEW", "APPLY"]).default("PREVIEW"),
});

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

    const licenseeId = resolveLicenseeScope(req);
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

    const row = await upsertTenantFeatureFlag({
      licenseeId,
      key: parsed.data.key,
      enabled: parsed.data.enabled,
      config: parsed.data.config,
      updatedByUserId: req.user.userId,
    });

    await createAuditLog({
      userId: req.user.userId,
      licenseeId,
      action: "TENANT_FEATURE_FLAG_UPSERT",
      entityType: "TenantFeatureFlag",
      entityId: row.id,
      ipAddress: req.ip,
      details: {
        key: row.key,
        enabled: row.enabled,
      },
    });

    return res.status(201).json({ success: true, data: row });
  } catch (error) {
    console.error("upsertFeatureFlag error:", error);
    return res.status(500).json({ success: false, error: "Failed to save feature flag" });
  }
};

export const getRetentionPolicyController = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user) return res.status(401).json({ success: false, error: "Not authenticated" });

    const licenseeId = resolveLicenseeScope(req);
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

    const policy = await updateRetentionPolicy({
      licenseeId,
      retentionDays: parsed.data.retentionDays,
      purgeEnabled: parsed.data.purgeEnabled,
      exportBeforePurge: parsed.data.exportBeforePurge,
      legalHoldTags: parsed.data.legalHoldTags,
      updatedByUserId: req.user.userId,
    });

    await createAuditLog({
      userId: req.user.userId,
      licenseeId,
      action: "EVIDENCE_RETENTION_POLICY_UPDATED",
      entityType: "EvidenceRetentionPolicy",
      entityId: policy.id,
      ipAddress: req.ip,
      details: {
        retentionDays: policy.retentionDays,
        purgeEnabled: policy.purgeEnabled,
      },
    });

    return res.json({ success: true, data: policy });
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

    const incidentId = String(req.params.id || "").trim();
    if (!incidentId) return res.status(400).json({ success: false, error: "Incident ID is required" });

    const incident = await prisma.incident.findUnique({
      where: { id: incidentId },
      select: { id: true, licenseeId: true },
    });

    if (!incident) return res.status(404).json({ success: false, error: "Incident not found" });

    if (
      req.user.role !== UserRole.SUPER_ADMIN &&
      req.user.role !== UserRole.PLATFORM_SUPER_ADMIN &&
      req.user.licenseeId !== incident.licenseeId
    ) {
      return res.status(403).json({ success: false, error: "Access denied" });
    }

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

    const licenseeId = resolveLicenseeScope(req);
    const from = toDate(req.query.from);
    const to = toDate(req.query.to);

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
