import { type ApiClientCore } from "@/lib/api/internal-client-core";
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

  listPrintReissueRequests(options?: { status?: string; limit?: number }) {
    const params = new URLSearchParams();
    if (options?.status) params.append("status", options.status);
    if (options?.limit) params.append("limit", String(options.limit));
    const query = params.toString() ? `?${params.toString()}` : "";
    return controlledPrinterGet<any[]>(
      `print-reissue-requests:${query || "all"}`,
      PRINTER_STATUS_MIN_REFRESH_MS,
      () => core.request<any[]>(`/manufacturer/print-reissue-requests${query}`)
    );
  },

  decidePrintReissueRequest(requestId: string, decision: "approve" | "reject", decisionNote: string) {
    const actionKey = buildPrinterActionKey("print-reissue-decision", [
      requestId,
      decision,
      stablePrinterPayloadSignature(decisionNote),
    ]);
    return controlledPrinterMutation(actionKey, () =>
      core.request<any>(`/manufacturer/print-reissue-requests/${encodeURIComponent(requestId)}/${decision}`, {
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
