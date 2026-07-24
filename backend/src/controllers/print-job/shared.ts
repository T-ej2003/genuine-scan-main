import { Response } from "express";
import { createHash, randomBytes } from "crypto";
import {
  NotificationAudience,
  NotificationChannel,
  PrintDispatchMode,
  Prisma,
  UserRole,
} from "@prisma/client";
import { z } from "zod";

import { AuthRequest } from "../../middleware/auth";
import { createRoleNotifications } from "../../services/notificationService";
import {
  extractIdempotencyKey,
} from "../../services/idempotencyService";
import {
  abortPrintingIdempotency,
  beginPrintingIdempotency,
  completePrintingIdempotency,
} from "../../rls-waves/session-c/c02/printingLifecycleRepository";
import type { B03AuthenticatedFunctionBoundary } from "../../rls-waves/session-b/b03/repositoryFunctions";

const MANUFACTURER_ROLES: UserRole[] = [UserRole.MANUFACTURER_ADMIN];
export const PRINT_OPERATIONS_ROLES: UserRole[] = [
  UserRole.SUPER_ADMIN,
  UserRole.PLATFORM_SUPER_ADMIN,
  UserRole.LICENSEE_ADMIN,
  ...MANUFACTURER_ROLES,
];
export const PRINT_REISSUE_ROLES: UserRole[] = [
  UserRole.SUPER_ADMIN,
  UserRole.PLATFORM_SUPER_ADMIN,
  UserRole.LICENSEE_ADMIN,
];

const isManufacturerRole = (role?: UserRole | null) =>
  Boolean(role && MANUFACTURER_ROLES.includes(role));
const isPrintOperationsRole = (role?: UserRole | null) =>
  Boolean(role && PRINT_OPERATIONS_ROLES.includes(role));
const isPrintReissueRole = (role?: UserRole | null) =>
  Boolean(role && PRINT_REISSUE_ROLES.includes(role));

export const createPrintJobSchema = z.object({
  batchId: z.string().uuid(),
  printerId: z.string().uuid(),
  quantity: z.number().int().positive().max(200000),
  rangeStart: z.string().optional(),
  rangeEnd: z.string().optional(),
}).strict();

export const listPrintJobsQuerySchema = z.object({
  batchId: z.string().uuid().optional(),
  limit: z.coerce.number().int().min(1).max(100).optional(),
}).strict();
export const reissuePrintJobSchema = z.object({
  reason: z.string().trim().min(5).max(500),
  quantity: z.number().int().positive().max(200000).optional(),
}).strict();

export const confirmSchema = z.object({
  printLockToken: z.string().min(10).optional(),
  operatorNote: z.string().trim().max(500).optional(),
}).strict();

export const sampleScanSchema = z.object({
  publicCode: z.string().trim().min(2).max(1024),
}).strict();

export const issueDirectPrintTokensSchema = z.object({
  printLockToken: z.string().min(10),
  count: z.number().int().min(1).max(500).optional(),
}).strict();

export const resolveDirectPrintTokenSchema = z.object({
  printLockToken: z.string().min(10),
  renderToken: z.string().min(16),
}).strict();

export const confirmDirectPrintItemSchema = z.object({
  printLockToken: z.string().min(10),
  printItemId: z.string().uuid(),
  agentMetadata: z.any().optional(),
}).strict();

export const reportDirectPrintFailureSchema = z.object({
  printLockToken: z.string().min(10),
  reason: z.string().trim().min(3).max(500),
  printItemId: z.string().uuid().optional(),
  retries: z.number().int().min(0).max(20).optional(),
  agentMetadata: z.any().optional(),
}).strict();

export const printJobIdParamSchema = z.object({
  id: z.string().uuid("Invalid print job id"),
}).strict();

export const hashLockToken = (raw: string) =>
  createHash("sha256").update(raw).digest("hex");

const parsePositiveIntEnv = (name: string, fallback: number, hardMax: number) => {
  const raw = Number(String(process.env[name] || "").trim());
  if (!Number.isFinite(raw) || raw <= 0) return fallback;
  return Math.max(1, Math.min(hardMax, Math.floor(raw)));
};

export const DIRECT_PRINT_LOCK_TTL_MINUTES = parsePositiveIntEnv("PRINT_JOB_LOCK_TTL_MINUTES", 45, 24 * 60);
export const DIRECT_PRINT_RENDER_TOKEN_TTL_SECONDS = parsePositiveIntEnv("DIRECT_PRINT_TOKEN_TTL_SECONDS", 90, 900);
export const DIRECT_PRINT_MAX_BATCH = parsePositiveIntEnv("DIRECT_PRINT_MAX_BATCH", 250, 500);

export const describePrintDispatchMode = (mode: PrintDispatchMode) => {
  if (mode === PrintDispatchMode.NETWORK_DIRECT) return "Network-direct";
  if (mode === PrintDispatchMode.NETWORK_IPP) return "Network IPP";
  return "Local-agent";
};

export const getLockExpiresAt = (createdAt: Date) =>
  new Date(createdAt.getTime() + DIRECT_PRINT_LOCK_TTL_MINUTES * 60 * 1000);

export const isLockExpired = (createdAt: Date, now: Date = new Date()) =>
  getLockExpiresAt(createdAt).getTime() <= now.getTime();

export const ensureManufacturerUser = (req: AuthRequest, res: Response) => {
  if (!req.user || !isManufacturerRole(req.user.role)) {
    res.status(403).json({ success: false, error: "Access denied" });
    return null;
  }
  return req.user;
};

export const ensurePrintOperationsUser = (req: AuthRequest, res: Response) => {
  if (!req.user || !isPrintOperationsRole(req.user.role)) {
    res.status(403).json({ success: false, error: "Access denied" });
    return null;
  }
  return req.user;
};

export const ensurePrintReissueApprover = (req: AuthRequest, res: Response) => {
  if (!req.user || !isPrintReissueRole(req.user.role)) {
    res.status(403).json({ success: false, error: "Only super-admin and licensee admin roles can authorize reissue." });
    return null;
  }
  return req.user;
};

export const generatePrintJobNumber = () =>
  `PJ-${new Date().toISOString().slice(0, 10).replace(/-/g, "")}-${randomBytes(4).toString("hex").toUpperCase()}`;

export const notifySystemPrintEvent = async (params: {
  licenseeId?: string | null;
  orgId?: string | null;
  type: string;
  title: string;
  body: string;
  data?: any;
  channels?: NotificationChannel[];
  databaseBoundary: B03AuthenticatedFunctionBoundary;
}) => {
  const channels = params.channels && params.channels.length > 0 ? params.channels : [NotificationChannel.WEB];

  await Promise.allSettled([
    createRoleNotifications({
      databaseBoundary: params.databaseBoundary,
      audience: NotificationAudience.SUPER_ADMIN,
      type: params.type,
      title: params.title,
      body: params.body,
      licenseeId: params.licenseeId || null,
      orgId: params.orgId || null,
      data: params.data || null,
      channels,
    }),
    Promise.resolve([] as any[]),
    params.orgId
      ? createRoleNotifications({
          databaseBoundary: params.databaseBoundary,
          audience: NotificationAudience.MANUFACTURER,
          licenseeId: params.licenseeId || null,
          orgId: params.orgId,
          type: params.type,
          title: params.title,
          body: params.body,
          data: params.data || null,
          channels: [NotificationChannel.WEB],
        })
      : Promise.resolve([] as any[]),
  ]);
};

export const handleIdempotencyError = (error: unknown, res: Response) => {
  const message = String((error as any)?.message || "");
  if (message.includes("IDEMPOTENCY_KEY_REQUIRED")) {
    res.status(400).json({ success: false, error: "Missing x-idempotency-key header" });
    return true;
  }
  if (message.includes("IDEMPOTENCY_KEY_IN_PROGRESS")) {
    res.status(409).json({ success: false, error: "Request with this idempotency key is already in progress" });
    return true;
  }
  if (message.includes("IDEMPOTENCY_KEY_PAYLOAD_MISMATCH")) {
    res.status(409).json({ success: false, error: "Idempotency key was already used for a different payload" });
    return true;
  }
  return false;
};

export const beginPrintActionIdempotency = async (params: {
  req: AuthRequest;
  action: string;
  scope: string;
  payload?: any;
}) => {
  if (params.action !== "print_job_create") throw new Error("IDEMPOTENCY_ACTION_REQUIRED");
  const key = String(extractIdempotencyKey(params.req.headers as any, params.req.body as any) || "").trim();
  if (!key) throw new Error("IDEMPOTENCY_KEY_REQUIRED");
  const context = {
    capability: String(params.req.databaseSessionCapability || ""),
    requestId: String((params.req as AuthRequest & { requestId?: string }).requestId || ""),
    action: "PRINT_JOB_CREATE" as const,
    actorScope: params.scope,
    key,
    payload: params.payload ?? null,
  };
  return { ...(await beginPrintingIdempotency(context)), context };
};

export const completePrintActionIdempotency = (
  idempotency: Awaited<ReturnType<typeof beginPrintActionIdempotency>>,
  statusCode: number,
  responsePayload: Record<string, unknown>
) => completePrintingIdempotency({ ...idempotency.context, statusCode, responsePayload });

export const abortPrintActionIdempotency = (
  idempotency: Awaited<ReturnType<typeof beginPrintActionIdempotency>>
) => abortPrintingIdempotency(idempotency.context);

export const replayIdempotentResponseIfAny = (
  idempotency: Awaited<ReturnType<typeof beginPrintActionIdempotency>>,
  res: Response
) => {
  if (!idempotency.replayed) return false;
  return res.status(idempotency.statusCode || 200).json(idempotency.responsePayload || { success: true });
};
