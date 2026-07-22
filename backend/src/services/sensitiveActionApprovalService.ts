import { UserRole } from "@prisma/client";

import { hashIp, hashToken, normalizeUserAgent } from "../utils/security";
import {
  C03AccessError,
  withC03ActorTransaction,
  withC03ResourceTransaction,
} from "../rls-waves/session-c/c03/c03ActorBoundary";
import {
  approveSensitiveApprovalInTransaction,
  createSensitiveApprovalInTransaction,
  listSensitiveApprovalsInTransaction,
  rejectSensitiveApprovalInTransaction,
} from "../rls-waves/session-c/c03/c03ApprovalRepository";

export const SENSITIVE_ACTION_KEYS = {
  FEATURE_FLAG_UPSERT: "FEATURE_FLAG_UPSERT",
  RETENTION_POLICY_PATCH: "RETENTION_POLICY_PATCH",
  RETENTION_APPLY: "RETENTION_APPLY",
  QR_BLOCK: "QR_BLOCK",
  BATCH_BLOCK: "BATCH_BLOCK",
  BATCH_RELEASE: "BATCH_RELEASE",
  PRINTER_GATEWAY_SECRET_ROTATION: "PRINTER_GATEWAY_SECRET_ROTATION",
} as const;

export type SensitiveActionKey = (typeof SENSITIVE_ACTION_KEYS)[keyof typeof SENSITIVE_ACTION_KEYS];

type ApprovalActor = {
  userId: string;
  role: UserRole;
  orgId?: string | null;
  licenseeId?: string | null;
};

type SecurityContext = {
  databaseSessionCapability: string;
  requestId: string;
};

type CreateApprovalInput = {
  actionKey: SensitiveActionKey;
  actor: ApprovalActor;
  payload: Record<string, unknown>;
  summary?: Record<string, unknown> | null;
  entityType?: string | null;
  entityId?: string | null;
  orgId?: string | null;
  licenseeId?: string | null;
  ipAddress?: string | null;
  userAgent?: string | null;
  securityContext?: SecurityContext;
};

const allApplicationRoles = Object.values(UserRole);
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const actionKeys = new Set<string>(Object.values(SENSITIVE_ACTION_KEYS));
const approvalStatuses = new Set(["PENDING", "APPROVED", "REJECTED", "EXECUTED", "FAILED", "EXPIRED"]);

const requireSecurityContext = (actor: ApprovalActor, context?: SecurityContext) => {
  const requestId = String(context?.requestId || "").trim();
  const databaseSessionCapability = String(context?.databaseSessionCapability || "").trim();
  if (!databaseSessionCapability || !requestId) throw new C03AccessError("Canonical sensitive-approval actor context is required", 401);
  if (!uuidPattern.test(requestId)) throw new C03AccessError("Canonical sensitive-approval request id is invalid", 400);
  return { databaseSessionCapability, requestId };
};

const requireLicenseeScope = (input: { licenseeId?: string | null; actor: ApprovalActor }) => {
  const licenseeId = String(input.licenseeId || input.actor.licenseeId || "").trim();
  if (!uuidPattern.test(licenseeId)) {
    throw new C03AccessError("A bounded sensitive-approval licensee scope is required", 400);
  }
  return licenseeId;
};

const requireActionKey = (value: unknown): SensitiveActionKey => {
  const actionKey = String(value || "").trim();
  if (!actionKeys.has(actionKey)) throw new C03AccessError("Unsupported sensitive approval action", 400);
  return actionKey as SensitiveActionKey;
};

const boundedInteger = (value: unknown, fallback: number, minimum: number, maximum: number) => {
  if (value == null) return fallback;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new C03AccessError("Sensitive approval pagination is invalid", 400);
  }
  return parsed;
};

const approvalStatus = (value?: string | null) => {
  const status = String(value || "").trim().toUpperCase();
  if (!status) return null;
  if (!approvalStatuses.has(status)) throw new C03AccessError("Sensitive approval status is invalid", 400);
  return status;
};

const reviewNote = (value?: string | null) => {
  const note = String(value || "").trim();
  if (note.length > 500) throw new C03AccessError("Sensitive approval review note is too long", 400);
  return note || null;
};

const userAgentHash = (value?: string | null) => {
  const normalized = normalizeUserAgent(value || undefined);
  return normalized ? hashToken(normalized) : null;
};

export const createSensitiveActionApproval = async (input: CreateApprovalInput) => {
  const security = requireSecurityContext(input.actor, input.securityContext);
  const licenseeId = requireLicenseeScope(input);
  const actionKey = requireActionKey(input.actionKey);
  if (!input.payload || typeof input.payload !== "object" || Array.isArray(input.payload)) {
    throw new C03AccessError("Sensitive approval payload is invalid", 400);
  }
  return withC03ActorTransaction(
    {
      databaseSessionCapability: security.databaseSessionCapability,
      requestId: security.requestId,
      purpose: "sensitive-action-approval-request",
      licenseeId,
      allowedRoles: allApplicationRoles,
      requiredAssurance: "password-verified",
    },
    (tx) =>
      createSensitiveApprovalInTransaction<any>(tx, {
        actionKey,
        entityType: input.entityType || null,
        entityId: input.entityId || null,
        payload: input.payload,
        summary: input.summary || null,
        requestIpHash: hashIp(input.ipAddress || undefined) || null,
        requestUserAgentHash: userAgentHash(input.userAgent),
      })
  );
};

export const listSensitiveActionApprovals = async (input: {
  actor: ApprovalActor;
  status?: string | null;
  limit?: number;
  offset?: number;
  licenseeId?: string | null;
  securityContext?: SecurityContext;
}) => {
  const security = requireSecurityContext(input.actor, input.securityContext);
  const licenseeId = requireLicenseeScope(input);
  const limit = boundedInteger(input.limit, 50, 1, 200);
  const offset = boundedInteger(input.offset, 0, 0, 20_000);
  const status = approvalStatus(input.status);
  return withC03ActorTransaction(
    {
      databaseSessionCapability: security.databaseSessionCapability,
      requestId: security.requestId,
      purpose: "sensitive-action-approval-list",
      licenseeId,
      allowedRoles: allApplicationRoles,
      requiredAssurance: "password-verified",
    },
    (tx) => listSensitiveApprovalsInTransaction<any>(tx, {
      status,
      limit,
      offset,
    })
  );
};

export const approveSensitiveActionApproval = async (input: {
  approvalId: string;
  actor: ApprovalActor;
  reviewNote?: string | null;
  ipAddress?: string | null;
  userAgent?: string | null;
  securityContext?: SecurityContext;
}) => {
  const security = requireSecurityContext(input.actor, input.securityContext);
  const note = reviewNote(input.reviewNote);
  return withC03ResourceTransaction(
    {
      databaseSessionCapability: security.databaseSessionCapability,
      requestId: security.requestId,
      purpose: "sensitive-action-approval-approve",
      resourceId: input.approvalId,
      resourceType: "sensitiveActionApproval",
      allowedRoles: allApplicationRoles,
      requiredAssurance: "mfa-verified",
    },
    (tx) => approveSensitiveApprovalInTransaction<any>(tx, input.approvalId, note)
  );
};

export const rejectSensitiveActionApproval = async (input: {
  approvalId: string;
  actor: ApprovalActor;
  reviewNote?: string | null;
  ipAddress?: string | null;
  userAgent?: string | null;
  securityContext?: SecurityContext;
}) => {
  const security = requireSecurityContext(input.actor, input.securityContext);
  const note = reviewNote(input.reviewNote);
  return withC03ResourceTransaction(
    {
      databaseSessionCapability: security.databaseSessionCapability,
      requestId: security.requestId,
      purpose: "sensitive-action-approval-reject",
      resourceId: input.approvalId,
      resourceType: "sensitiveActionApproval",
      allowedRoles: allApplicationRoles,
      requiredAssurance: "mfa-verified",
    },
    (tx) => rejectSensitiveApprovalInTransaction<any>(tx, input.approvalId, note)
  );
};
