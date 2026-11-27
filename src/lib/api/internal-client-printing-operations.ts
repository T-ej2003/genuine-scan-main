import { type ApiClientCore } from "@/lib/api/internal-client-core";
import type { PrintRetirementRow, TraceEventRow } from "@/features/batches/types";
import {
  controlledPrinterGet,
  controlledPrinterMutation,
  PRINTER_STATUS_MIN_REFRESH_MS,
} from "@/lib/api/internal-client-printing-request-control";

const normalizeIdempotencyPart = (value: unknown) =>
  String(value ?? "")
    .trim()
    .replace(/[^a-zA-Z0-9._:-]+/g, "_")
    .slice(0, 96);

const buildPrinterActionKey = (action: string, parts: unknown[]) =>
  [action, ...parts.map(normalizeIdempotencyPart)].join(":");

const stablePrinterPayloadSignature = (value: unknown): string => {
  if (value === null || value === undefined) return "null";
  if (typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stablePrinterPayloadSignature).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${stablePrinterPayloadSignature(record[key])}`)
    .join(",")}}`;
};

export const createPrintingOperationsApi = (core: ApiClientCore) => ({
  getManufacturerBatchHistory(batchId: string, licenseeId: string, cursor?: string) {
    const query = new URLSearchParams({ licenseeId });
    if (cursor) query.set("cursor", cursor);
    return core.request<{ events: TraceEventRow[]; incomplete: boolean; nextCursor: string | null }>(
      `/manufacturer/batches/${encodeURIComponent(batchId)}/history?${query}`
    );
  },

  getPrintRetirements(jobId: string, cursor?: string) {
    const query = cursor ? `?cursor=${encodeURIComponent(cursor)}` : "";
    return core.request<PrintRetirementRow[]>(`/manufacturer/print-jobs/${encodeURIComponent(jobId)}/retirement${query}`);
  },

  decidePrintRetirement(jobId: string, input: { itemId: string; action: "REQUEST" | "APPROVE" | "REJECT"; reason: string }) {
    return core.request(`/manufacturer/print-jobs/${encodeURIComponent(jobId)}/retirement`, {
      method: "POST",
      body: JSON.stringify(input),
    });
  },

  requestPrintJobReissue(jobId: string, payload: { reason: string; quantity?: number }) {
    return core.request<any>(`/manufacturer/print-jobs/${encodeURIComponent(jobId)}/reissue`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
  },

  createPrintReissueRequest(
    jobId: string,
    payload: {
      reason: string;
      quantity?: number;
      affectedRangeStart?: string;
      affectedRangeEnd?: string;
    }
  ) {
    const actionKey = buildPrinterActionKey("print-reissue-request", [
      jobId,
      payload.quantity,
      payload.affectedRangeStart,
      payload.affectedRangeEnd,
      stablePrinterPayloadSignature(payload.reason),
    ]);
    return controlledPrinterMutation(actionKey, () =>
      core.request<any>(`/manufacturer/print-jobs/${encodeURIComponent(jobId)}/reissue-request`, {
        method: "POST",
        headers: { "x-idempotency-key": actionKey },
        body: JSON.stringify(payload),
      })
    );
  },

  listPrintReissueRequests(options?: { status?: string; limit?: number; force?: boolean }) {
    const params = new URLSearchParams();
    if (options?.status) params.append("status", options.status);
    if (options?.limit) params.append("limit", String(options.limit));
    const query = params.toString() ? `?${params.toString()}` : "";
    return controlledPrinterGet<any[]>(
      `print-reissue-requests:${query || "all"}`,
      PRINTER_STATUS_MIN_REFRESH_MS,
      () => core.request<any[]>(`/manufacturer/print-reissue-requests${query}`),
      { force: Boolean(options?.force) }
    );
  },

  decidePrintReissueRequest(requestId: string, decision: "approve" | "reject", decisionNote: string) {
    const actionKey = buildPrinterActionKey("print-reissue-decision", [
      requestId,
      decision,
      stablePrinterPayloadSignature(decisionNote),
    ]);
    const endpoint =
      decision === "approve"
        ? `/manufacturer/print-reissue-requests/${encodeURIComponent(requestId)}/approve`
        : `/manufacturer/print-reissue-requests/${encodeURIComponent(requestId)}/reject`;
    return controlledPrinterMutation(actionKey, () =>
      core.request<any>(endpoint, {
        method: "POST",
        headers: { "x-idempotency-key": actionKey },
        body: JSON.stringify({ decisionNote }),
      })
    );
  },

  printApprovedReissueRequest(requestId: string) {
    const actionKey = buildPrinterActionKey("print-approved-reissue", [requestId]);
    return controlledPrinterMutation(actionKey, () =>
      core.request<any>(`/manufacturer/print-reissue-requests/${encodeURIComponent(requestId)}/print`, {
        method: "POST",
        headers: { "x-idempotency-key": actionKey },
        suppressMutationEvent: true,
      })
    );
  },

  pausePrintJob(jobId: string, reason: string) {
    const actionKey = buildPrinterActionKey("print-job-pause", [jobId, stablePrinterPayloadSignature(reason)]);
    return controlledPrinterMutation(actionKey, () =>
      core.request<any>(`/manufacturer/print-jobs/${encodeURIComponent(jobId)}/pause`, {
        method: "POST",
        headers: { "x-idempotency-key": actionKey },
        body: JSON.stringify({ reason }),
        suppressMutationEvent: true,
      })
    );
  },

  resumePrintJob(jobId: string) {
    const actionKey = buildPrinterActionKey("print-job-resume", [jobId]);
    return controlledPrinterMutation(actionKey, () =>
      core.request<any>(`/manufacturer/print-jobs/${encodeURIComponent(jobId)}/resume`, {
        method: "POST",
        headers: { "x-idempotency-key": actionKey },
        suppressMutationEvent: true,
      })
    );
  },

  stopPrintJob(jobId: string, reason: string) {
    const actionKey = buildPrinterActionKey("print-job-stop", [jobId, stablePrinterPayloadSignature(reason)]);
    return controlledPrinterMutation(actionKey, () =>
      core.request<any>(`/manufacturer/print-jobs/${encodeURIComponent(jobId)}/stop`, {
        method: "POST",
        headers: { "x-idempotency-key": actionKey },
        body: JSON.stringify({ reason }),
        suppressMutationEvent: true,
      })
    );
  },
});
