import {
  controlPrintingJob,
  readPrintingProjection,
} from "../rls-waves/session-c/c02/printingLifecycleRepository";
import type { PrintJobScope } from "./printJobScopeService";

const MIN_REASON_LENGTH = 8;

export const validatePrintOperationReason = (reason: string) => {
  const trimmed = String(reason || "").replace(/\s+/g, " ").trim();
  if (trimmed.length < MIN_REASON_LENGTH) {
    throw Object.assign(new Error("A clear reason is required."), { statusCode: 400 });
  }
  return trimmed.slice(0, 500);
};

type Boundary = { capability: string; requestId: string };

const control = async (params: {
  printJobId: string;
  scope: PrintJobScope;
  boundary: Boundary;
  operation: "PAUSE" | "RESUME" | "STOP";
  reason?: string;
}) => {
  const result = await controlPrintingJob({
    capability: params.boundary.capability,
    requestId: params.boundary.requestId,
    jobId: params.printJobId,
    operation: params.operation,
    reason: params.reason || null,
  });
  const view = await readPrintingProjection({
    capability: params.boundary.capability,
    requestId: params.boundary.requestId,
    operation: "JOB",
    subjectId: params.printJobId,
  });
  return { view, idempotent: result.idempotent === true };
};

export const pausePrintJob = (params: {
  printJobId: string;
  scope: PrintJobScope;
  boundary: Boundary;
  reason: string;
}) => control({ ...params, operation: "PAUSE", reason: validatePrintOperationReason(params.reason) });

export const resumePrintJob = (params: {
  printJobId: string;
  scope: PrintJobScope;
  boundary: Boundary;
}) => control({ ...params, operation: "RESUME" });
export const stopPrintJob = (params: {
  printJobId: string;
  scope: PrintJobScope;
  boundary: Boundary;
  reason: string;
}) => control({ ...params, operation: "STOP", reason: validatePrintOperationReason(params.reason) });
