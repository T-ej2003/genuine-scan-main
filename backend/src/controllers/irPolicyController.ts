import { Response } from "express";
import { z } from "zod";
import { AlertSeverity, PolicyRuleType, Prisma, UserRole } from "@prisma/client";

import { AuthRequest } from "../middleware/auth";
import type { CanonicalDbContext } from "../lib/canonicalDbContext";
import { createAuditLogInTransaction } from "../services/auditService";
import {
  C03AccessError,
  c03CanonicalDbContext,
  c03DatabaseSessionCapability,
  c03RequestId,
  withC03ActorTransaction,
  withC03PlatformTransaction,
  withC03ResourceTransaction,
} from "../rls-waves/session-c/c03/c03ActorBoundary";
import {
  createPolicyRuleInTransaction,
  listPlatformPolicyRulesInTransaction,
  listPolicyRulesInTransaction,
  updatePolicyRuleInTransaction,
} from "../rls-waves/session-c/c03/c03PolicyRepository";

const paginationSchema = z.object({
  limit: z.coerce.number().int().min(1).max(200).catch(50),
  offset: z.coerce.number().int().min(0).catch(0),
});

const createPolicyRuleSchema = z.object({
  name: z.string().trim().min(3).max(120),
  description: z.string().trim().max(500).optional(),
  ruleType: z.nativeEnum(PolicyRuleType),
  isActive: z.boolean().optional(),
  threshold: z.number().int().min(1).max(100000),
  windowMinutes: z.number().int().min(1).max(60 * 24 * 30),
  severity: z.nativeEnum(AlertSeverity).optional(),
  autoCreateIncident: z.boolean().optional(),
  incidentSeverity: z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]).optional(),
  incidentPriority: z.enum(["P1", "P2", "P3", "P4"]).optional(),
  licenseeId: z.string().uuid().optional(),
  actionConfig: z.unknown().optional(),
}).strict();

const updatePolicyRuleSchema = createPolicyRuleSchema
  .omit({ licenseeId: true })
  .partial()
  .extend({
    name: z.string().trim().min(3).max(120).optional(),
    threshold: z.number().int().min(1).max(100000).optional(),
    windowMinutes: z.number().int().min(1).max(60 * 24 * 30).optional(),
  })
  .strict()
  .refine((val) => Object.keys(val).length > 0, { message: "No fields provided" });

const policyIdParamSchema = z.object({
  id: z.string().uuid("Invalid policy id"),
}).strict();

const isPolicyReplayConflict = (error: unknown) =>
  error instanceof Prisma.PrismaClientKnownRequestError &&
  error.code === "P2010" &&
  String(error.meta?.code || "") === "40001" &&
  String(error.meta?.message || "").includes("C03_POLICY_REPLAY_CONFLICT");

export const listIrPolicies = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user) return res.status(401).json({ success: false, error: "Not authenticated" });

    const paged = paginationSchema.safeParse(req.query || {});
    if (!paged.success) return res.status(400).json({ success: false, error: "Invalid pagination" });

    const licenseeId = String(req.query.licenseeId || "").trim() || null;
    if (licenseeId && !z.string().uuid().safeParse(licenseeId).success) {
      return res.status(400).json({ success: false, error: "A valid licenseeId is required" });
    }
    const ruleTypeRaw = String(req.query.ruleType || "").trim().toUpperCase();
    const isActiveRaw = String(req.query.isActive || "").trim().toLowerCase();

    const readPolicies = async (tx: Prisma.TransactionClient, context: CanonicalDbContext) => {
      const input = {
        ruleType: ruleTypeRaw && ruleTypeRaw in PolicyRuleType ? (ruleTypeRaw as PolicyRuleType) : undefined,
        isActive: isActiveRaw === "true" || isActiveRaw === "false" ? isActiveRaw === "true" : undefined,
        limit: paged.data.limit,
        offset: paged.data.offset,
      };
      const data = licenseeId
        ? await listPolicyRulesInTransaction<{ rules: any[]; total: number }>(tx, input)
        : await listPlatformPolicyRulesInTransaction<{ rules: any[]; total: number }>(tx, input);
      await createAuditLogInTransaction(tx, c03CanonicalDbContext(context), {
        action: "IR_POLICY_RULES_LISTED",
        entityType: "PolicyRule",
        entityId: licenseeId || "PLATFORM",
        details: { ruleType: ruleTypeRaw || null, isActive: isActiveRaw || null, count: data.rules.length },
        ipAddress: req.ip,
      });
      return data;
    };
    const boundary = {
      databaseSessionCapability: c03DatabaseSessionCapability(req),
      requestId: c03RequestId(req),
      purpose: "incident-response-policy-list",
      allowedRoles: [UserRole.SUPER_ADMIN, UserRole.PLATFORM_SUPER_ADMIN],
      requiredAssurance: "mfa-verified" as const,
    };
    const result = licenseeId
      ? await withC03ActorTransaction(
          { ...boundary, licenseeId },
          readPolicies,
          Prisma.TransactionIsolationLevel.ReadCommitted
        )
      : await withC03PlatformTransaction(
          boundary,
          readPolicies,
          Prisma.TransactionIsolationLevel.ReadCommitted
        );

    return res.json({ success: true, data: { ...result, limit: paged.data.limit, offset: paged.data.offset } });
  } catch (e) {
    console.error("listIrPolicies error:", e);
    if (e instanceof C03AccessError) return res.status(e.statusCode).json({ success: false, error: e.message });
    return res.status(500).json({ success: false, error: "Failed to list policies" });
  }
};

export const createIrPolicy = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user) return res.status(401).json({ success: false, error: "Not authenticated" });

    const parsed = createPolicyRuleSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid payload" });
    }

    const licenseeId = parsed.data.licenseeId || "";
    if (!licenseeId) return res.status(400).json({ success: false, error: "licenseeId is required" });
    const created = await withC03ActorTransaction(
      {
        databaseSessionCapability: c03DatabaseSessionCapability(req),
        requestId: c03RequestId(req),
        purpose: "incident-response-policy-create",
        licenseeId,
        allowedRoles: [UserRole.SUPER_ADMIN, UserRole.PLATFORM_SUPER_ADMIN],
        requiredAssurance: "mfa-verified",
      },
      async (tx, context) => {
        const raw = await createPolicyRuleInTransaction<any>(tx, {
          name: parsed.data.name,
          description: parsed.data.description || null,
          ruleType: parsed.data.ruleType,
          isActive: parsed.data.isActive ?? true,
          threshold: parsed.data.threshold,
          windowMinutes: parsed.data.windowMinutes,
          severity: parsed.data.severity || AlertSeverity.MEDIUM,
          autoCreateIncident: parsed.data.autoCreateIncident ?? false,
          incidentSeverity: parsed.data.incidentSeverity || null,
          incidentPriority: parsed.data.incidentPriority || null,
          actionConfig: parsed.data.actionConfig ?? null,
        });
        const { __c03Replay, ...result } = raw;
        if (!__c03Replay) {
          await createAuditLogInTransaction(tx, c03CanonicalDbContext(context), {
            action: "POLICY_RULE_CREATED",
            entityType: "PolicyRule",
            entityId: result.id,
            details: {
              name: result.name,
              ruleType: result.ruleType,
              threshold: result.threshold,
              windowMinutes: result.windowMinutes,
              severity: result.severity,
              autoCreateIncident: result.autoCreateIncident,
              manufacturerId: result.manufacturerId,
            },
            ipAddress: req.ip,
          });
        }
        return result;
      },
      Prisma.TransactionIsolationLevel.ReadCommitted
    );

    return res.status(201).json({ success: true, data: created });
  } catch (e: any) {
    console.error("createIrPolicy error:", e);
    if (e instanceof C03AccessError) return res.status(e.statusCode).json({ success: false, error: e.message });
    if (isPolicyReplayConflict(e)) return res.status(409).json({ success: false, error: "Policy request conflicts with a prior replay" });
    return res.status(500).json({ success: false, error: "Failed to create policy" });
  }
};

export const patchIrPolicy = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user) return res.status(401).json({ success: false, error: "Not authenticated" });
    const paramsParsed = policyIdParamSchema.safeParse(req.params || {});
    if (!paramsParsed.success) {
      return res.status(400).json({ success: false, error: paramsParsed.error.errors[0]?.message || "Invalid policy id" });
    }
    const id = paramsParsed.data.id;

    const parsed = updatePolicyRuleSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid payload" });
    }

    const updated = await withC03ResourceTransaction(
      {
        databaseSessionCapability: c03DatabaseSessionCapability(req),
        requestId: c03RequestId(req),
        purpose: "incident-response-policy-update",
        resourceId: id,
        resourceType: "policyRule",
        allowedRoles: [UserRole.SUPER_ADMIN, UserRole.PLATFORM_SUPER_ADMIN],
        requiredAssurance: "mfa-verified",
      },
      async (tx, context) => {
        const raw = await updatePolicyRuleInTransaction<any>(tx, id, parsed.data);
        const { __c03Replay, ...result } = raw;
        if (!__c03Replay) {
          await createAuditLogInTransaction(tx, c03CanonicalDbContext(context), {
            action: "POLICY_RULE_UPDATED",
            entityType: "PolicyRule",
            entityId: id,
            details: { changedFields: Object.keys(parsed.data) },
            ipAddress: req.ip,
          });
        }
        return result;
      },
      Prisma.TransactionIsolationLevel.ReadCommitted
    );

    return res.json({ success: true, data: updated });
  } catch (e) {
    console.error("patchIrPolicy error:", e);
    if (e instanceof C03AccessError) return res.status(e.statusCode).json({ success: false, error: e.message });
    if (isPolicyReplayConflict(e)) return res.status(409).json({ success: false, error: "Policy request conflicts with a prior replay" });
    return res.status(500).json({ success: false, error: "Failed to update policy" });
  }
};
