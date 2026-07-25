import { Response } from "express";
import { UserRole } from "@prisma/client";
import { z } from "zod";

import { AuthRequest } from "../middleware/auth";
import {
  buildIncidentEvidenceAuditBundle,
  deleteCommittedRetentionArtifacts,
  generateComplianceReport,
  getOrCreateRetentionPolicy,
  loadIncidentEvidenceAuditSnapshot,
  listTenantFeatureFlags,
  runRetentionLifecycle,
  updateRetentionPolicy,
  upsertTenantFeatureFlag,
} from "../services/governanceService";
import { createAuditLogInTransaction } from "../services/auditService";
import {
  listCompliancePackJobs,
  loadCompliancePackJobBuffer,
  rebuildCompliancePackArtifactForJob,
  runCompliancePackJob,
} from "../services/compliancePackService";
import { createSensitiveActionApproval, SENSITIVE_ACTION_KEYS } from "../services/sensitiveActionApprovalService";
import {
  C03AccessError,
  c03CanonicalDbContext,
  c03DatabaseSessionCapability,
  c03RequestId,
  withC03ActorTransaction,
  withC03ResourceTransaction,
} from "../rls-waves/session-c/c03/c03ActorBoundary";
import { loadCompliancePackJobInTransaction } from "../rls-waves/session-c/c03/c03CompliancePackRepository";

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

const compliancePackReadRoles = Object.values(UserRole);

const compliancePackReadAssurance = (role: UserRole) =>
  role === UserRole.SUPER_ADMIN || role === UserRole.PLATFORM_SUPER_ADMIN
    ? "mfa-verified" as const
    : "password-verified" as const;

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

    const flags = await withC03ActorTransaction(
      {
        databaseSessionCapability: c03DatabaseSessionCapability(req),
        requestId: c03RequestId(req),
        purpose: "governance-feature-flag-list",
        licenseeId,
        allowedRoles: [UserRole.SUPER_ADMIN, UserRole.PLATFORM_SUPER_ADMIN],
        requiredAssurance: "mfa-verified",
      },
      async (tx, context) => {
        const rows = await listTenantFeatureFlags(licenseeId, tx);
        await createAuditLogInTransaction(tx, c03CanonicalDbContext(context), {
          action: "TENANT_FEATURE_FLAGS_LISTED",
          entityType: "TenantFeatureFlag",
          entityId: licenseeId,
          details: { count: rows.length },
          ipAddress: req.ip,
        });
        return rows;
      }
    );
    return res.json({ success: true, data: { licenseeId, flags } });
  } catch (error) {
    console.error("getFeatureFlags error:", error);
    if (error instanceof C03AccessError) return res.status(error.statusCode).json({ success: false, error: error.message });
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
      securityContext: { databaseSessionCapability: c03DatabaseSessionCapability(req), requestId: c03RequestId(req) },
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
    if (error instanceof C03AccessError) return res.status(error.statusCode).json({ success: false, error: error.message });
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

    const policy = await withC03ActorTransaction(
      {
        databaseSessionCapability: c03DatabaseSessionCapability(req),
        requestId: c03RequestId(req),
        purpose: "governance-retention-policy-read",
        licenseeId,
        allowedRoles: [UserRole.SUPER_ADMIN, UserRole.PLATFORM_SUPER_ADMIN],
        requiredAssurance: "mfa-verified",
      },
      async (tx, context) => {
        const row = await getOrCreateRetentionPolicy(licenseeId, tx);
        await createAuditLogInTransaction(tx, c03CanonicalDbContext(context), {
          action: "EVIDENCE_RETENTION_POLICY_READ",
          entityType: "EvidenceRetentionPolicy",
          entityId: row.id,
          ipAddress: req.ip,
        });
        return row;
      }
    );
    return res.json({ success: true, data: policy });
  } catch (error) {
    console.error("getRetentionPolicyController error:", error);
    if (error instanceof C03AccessError) return res.status(error.statusCode).json({ success: false, error: error.message });
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
      securityContext: { databaseSessionCapability: c03DatabaseSessionCapability(req), requestId: c03RequestId(req) },
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
    if (error instanceof C03AccessError) return res.status(error.statusCode).json({ success: false, error: error.message });
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
        securityContext: { databaseSessionCapability: c03DatabaseSessionCapability(req), requestId: c03RequestId(req) },
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

    const result = await withC03ActorTransaction(
      {
        databaseSessionCapability: c03DatabaseSessionCapability(req),
        requestId: c03RequestId(req),
        purpose: "governance-retention-preview",
        licenseeId,
        allowedRoles: [UserRole.SUPER_ADMIN, UserRole.PLATFORM_SUPER_ADMIN],
        requiredAssurance: "mfa-verified",
      },
      async (tx, context) => {
        const row = await runRetentionLifecycle({
          licenseeId,
          startedByUserId: req.user!.userId,
          mode: parsed.data.mode,
        }, tx);
        await createAuditLogInTransaction(tx, c03CanonicalDbContext(context), {
          action: "EVIDENCE_RETENTION_JOB_RUN",
          entityType: "EvidenceRetentionJob",
          entityId: row.job.id,
          ipAddress: req.ip,
          details: { mode: parsed.data.mode, evaluated: row.evaluated, purged: row.purged },
        });
        return row;
      }
    );
    deleteCommittedRetentionArtifacts(result.storageKeysToDelete);
    const { storageKeysToDelete: _storageKeys, ...response } = result;
    return res.status(201).json({ success: true, data: response });
  } catch (error) {
    console.error("runRetentionJobController error:", error);
    if (error instanceof C03AccessError) return res.status(error.statusCode).json({ success: false, error: error.message });
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

    const snapshot = await withC03ResourceTransaction(
      {
        databaseSessionCapability: c03DatabaseSessionCapability(req),
        requestId: c03RequestId(req),
        purpose: "incident-evidence-audit-export",
        resourceId: incidentId,
        resourceType: "incident",
        allowedRoles: [UserRole.SUPER_ADMIN, UserRole.PLATFORM_SUPER_ADMIN],
        requiredAssurance: "mfa-verified",
      },
      async (tx, context) => {
        const row = await loadIncidentEvidenceAuditSnapshot(incidentId, tx);
        await createAuditLogInTransaction(tx, c03CanonicalDbContext(context), {
          action: "INCIDENT_EVIDENCE_BUNDLE_EXPORTED",
          entityType: "Incident",
          entityId: incidentId,
          ipAddress: req.ip,
          details: {
            evidenceCount: row.evidence.length,
            eventsCount: row.events.length,
            fingerprintCount: row.evidenceFingerprints.length,
          },
        });
        return row;
      }
    );
    const bundle = await buildIncidentEvidenceAuditBundle(snapshot);

    res.setHeader("Content-Type", "application/zip");
    res.setHeader("Content-Disposition", `attachment; filename="${bundle.fileName}"`);
    return res.status(200).send(bundle.buffer);
  } catch (error) {
    console.error("exportIncidentEvidenceBundleController error:", error);
    if (error instanceof C03AccessError) return res.status(error.statusCode).json({ success: false, error: error.message });
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
    if (!licenseeId) return res.status(400).json({ success: false, error: "licenseeId is required" });
    const from = toDate(parsed.data.from);
    const to = toDate(parsed.data.to);

    const report = await withC03ActorTransaction(
      {
        databaseSessionCapability: c03DatabaseSessionCapability(req),
        requestId: c03RequestId(req),
        purpose: "governance-compliance-report",
        licenseeId,
        allowedRoles: [UserRole.SUPER_ADMIN, UserRole.PLATFORM_SUPER_ADMIN],
        requiredAssurance: "mfa-verified",
      },
      async (tx, context) => {
        const row = await generateComplianceReport({
          actor: {
            userId: req.user!.userId,
            role: req.user!.role,
            licenseeId: req.user!.licenseeId,
          },
          licenseeId,
          from,
          to,
        }, tx);
        await createAuditLogInTransaction(tx, c03CanonicalDbContext(context), {
          action: "COMPLIANCE_REPORT_GENERATED",
          entityType: "ComplianceReport",
          entityId: licenseeId,
          details: { from: from?.toISOString() || null, to: to?.toISOString() || null },
          ipAddress: req.ip,
        });
        return row;
      }
    );

    return res.json({ success: true, data: report });
  } catch (error) {
    console.error("generateComplianceReportController error:", error);
    if (error instanceof C03AccessError) return res.status(error.statusCode).json({ success: false, error: error.message });
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
      securityContext: { databaseSessionCapability: c03DatabaseSessionCapability(req), requestId: c03RequestId(req) },
    });

    return res.status(201).json({ success: true, data: out.job });
  } catch (error) {
    console.error("runCompliancePackController error:", error);
    if (error instanceof C03AccessError) return res.status(error.statusCode).json({ success: false, error: error.message });
    const rawMessage = error instanceof Error ? String(error.message || "").trim() : "";
    const safeMessage =
      rawMessage && /missing|invalid|not configured|failed|error|denied|unavailable|timeout|encryption|signature/i.test(rawMessage)
        ? rawMessage
        : "Failed to generate compliance pack";
    return res.status(500).json({ success: false, error: safeMessage });
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
    if (!licenseeId) return res.status(400).json({ success: false, error: "licenseeId is required" });

    const result = await listCompliancePackJobs({
      licenseeId,
      limit,
      offset,
      actor: {
        userId: req.user.userId,
        role: req.user.role,
        licenseeId: req.user.licenseeId,
      },
      securityContext: { databaseSessionCapability: c03DatabaseSessionCapability(req), requestId: c03RequestId(req) },
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
    if (error instanceof C03AccessError) return res.status(error.statusCode).json({ success: false, error: error.message });
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

    const snapshot = await withC03ResourceTransaction(
      {
        databaseSessionCapability: c03DatabaseSessionCapability(req),
        requestId: c03RequestId(req),
        purpose: "compliance-pack-download",
        resourceId: paramsParsed.data.id,
        resourceType: "compliancePackJob",
        allowedRoles: compliancePackReadRoles,
        requiredAssurance: compliancePackReadAssurance(req.user.role),
      },
      async (tx, context) => {
        const result = await loadCompliancePackJobInTransaction<any>(tx, context, paramsParsed.data.id);
        await createAuditLogInTransaction(tx, c03CanonicalDbContext(context), {
          action: "COMPLIANCE_PACK_DOWNLOADED",
          entityType: "CompliancePackJob",
          entityId: paramsParsed.data.id,
          ipAddress: req.ip,
        });
        return result;
      }
    );
    const row = snapshot.job;
    if (row.status !== "COMPLETED" || !row.storageKey || !row.fileName) {
      return res.status(409).json({ success: false, error: "Compliance pack is not ready" });
    }

    let buffer = await loadCompliancePackJobBuffer(row.storageKey);
    if (!buffer) {
      try {
        const rebuilt = await rebuildCompliancePackArtifactForJob({
          jobId: row.id,
          actor: {
            userId: req.user.userId,
            role: req.user.role,
            licenseeId: req.user.licenseeId || null,
          },
          securityContext: { databaseSessionCapability: c03DatabaseSessionCapability(req), requestId: c03RequestId(req) },
        });
        buffer = await loadCompliancePackJobBuffer(rebuilt.job.storageKey || "");
      } catch (rebuildError) {
        console.error("downloadCompliancePackJobController rebuild error:", rebuildError);
      }
    }
    if (!buffer) {
      return res.status(404).json({
        success: false,
        error: "Compliance pack artifact is unavailable. Regenerate the pack and try download again.",
      });
    }

    res.setHeader("Content-Type", "application/zip");
    res.setHeader("Content-Disposition", `attachment; filename="${row.fileName}"`);
    return res.status(200).send(buffer);
  } catch (error) {
    console.error("downloadCompliancePackJobController error:", error);
    if (error instanceof C03AccessError) return res.status(error.statusCode).json({ success: false, error: error.message });
    return res.status(500).json({ success: false, error: "Failed to download compliance pack" });
  }
};
