import { ReissueRequestStatus } from "@prisma/client";

import {
  mutatePrintingReissueRequest,
  readPrintingProjection,
} from "../rls-waves/session-c/c02/printingLifecycleRepository";
import type { PrintJobScope } from "./printJobScopeService";

type Boundary = { capability: string; requestId: string };

const note = (value: string, label: string) => {
  const normalized = String(value || "").replace(/\s+/g, " ").trim();
  if (normalized.length < 8) {
    throw Object.assign(new Error(`${label} is required.`), { statusCode: 400 });
  }
  return normalized.slice(0, 500);
};

export const createScopedPrintReissueRequest = async (params: {
  scope: PrintJobScope;
  boundary: Boundary;
  originalPrintJobId: string;
  reason: string;
  quantity?: number | null;
  affectedRangeStart?: string | null;
  affectedRangeEnd?: string | null;
}) => {
  const request = await mutatePrintingReissueRequest({
    ...params.boundary,
    operation: "CREATE",
    originalJobId: params.originalPrintJobId,
    quantity: params.quantity,
    rangeStart: params.affectedRangeStart,
    rangeEnd: params.affectedRangeEnd,
    reason: note(params.reason, "A clear reason"),
  });
  return { request, idempotent: Boolean(request?.idempotent) };
};

export const listScopedPrintReissueRequests = (params: {
  scope: PrintJobScope;
  boundary: Boundary;
  status?: ReissueRequestStatus | null;
  limit?: number | null;
}) =>
  readPrintingProjection({
    ...params.boundary,
    operation: "REISSUE_LIST",
    subjectId: "00000000-0000-4000-8000-000000000000",
    options: { status: params.status || null, limit: params.limit || 50 },
  });

export const decideScopedPrintReissueRequest = async (params: {
  scope: PrintJobScope;
  boundary: Boundary;
  requestId: string;
  decision: "approve" | "reject";
  decisionNote: string;
  ipAddress?: string | null;
  userAgent?: string | null;
}) => {
  const current = await readPrintingProjection({
    ...params.boundary,
    operation: "REISSUE_REQUEST",
    subjectId: params.requestId,
  });
  const forward = params.decision === "approve" && current?.targetApproverRole === "LICENSEE_ADMIN";
  return mutatePrintingReissueRequest({
    ...params.boundary,
    operation: params.decision === "reject" ? "REJECT" : forward ? "FORWARD" : "APPROVE",
    reissueId: params.requestId,
    reason: params.decision === "reject" ? note(params.decisionNote, "A clear rejection reason") : null,
    decisionNote: note(params.decisionNote, "A clear decision note"),
  });
};

export const startApprovedPrintReissueRequest = async (params: {
  scope: PrintJobScope;
  boundary: Boundary;
  requestId: string;
  ipAddress?: string | null;
  userAgent?: string | null;
}) => {
  const result = await mutatePrintingReissueRequest({
    ...params.boundary,
    operation: "EXECUTE",
    reissueId: params.requestId,
  });
  return {
    ...result,
    reissueRequestId: result.id,
    replacementPrintJobId: result.replacementPrintJobId,
    idempotent: Boolean(result.idempotent),
  };
};
