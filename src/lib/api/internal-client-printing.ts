import { type ApiClientCore } from "@/lib/api/internal-client-core";
import { createLocalAgentPrintingApi } from "@/lib/api/internal-client-local-agent";
import { createPrintingOperationsApi } from "@/lib/api/internal-client-printing-operations";
import {
  controlledPrinterMutation,
  controlledPrinterGet,
  PRINTER_HEARTBEAT_MIN_REFRESH_MS,
  PRINTER_LIST_MIN_REFRESH_MS,
  PRINTER_STATUS_MIN_REFRESH_MS,
  type ControlledPrinterGetOptions,
} from "@/lib/api/internal-client-printing-request-control";

type BatchReleaseResponse = {
  approvalRequired?: boolean;
  approvalId?: string;
  status?: string;
  expiresAt?: string;
  approvalPolicy?: {
    required?: boolean;
    reason?: string | null;
    threshold?: number | null;
  };
  batch?: {
    id: string;
    lifecycleState?: string;
    releasedAt?: string | null;
    releasedByUserId?: string | null;
  };
  readiness?: {
    releasable?: boolean;
    failures?: Array<{ code?: string; message?: string }>;
    sampleScanPolicy?: {
      satisfied: boolean;
      required: number;
      passed: number;
      missing: number;
    } | null;
  };
};

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

export const createPrintingApi = (core: ApiClientCore) => ({
  async createPrintJob(payload: {
    batchId: string;
    printerId: string;
    quantity: number;
    rangeStart?: string;
    rangeEnd?: string;
    reprintOfJobId?: string;
    reprintReason?: string;
  }) {
    const actionKey = buildPrinterActionKey("print-job-create", [
      payload.batchId,
      payload.printerId,
      payload.quantity,
      payload.rangeStart,
      payload.rangeEnd,
      payload.reprintOfJobId,
    ]);
    return controlledPrinterMutation(actionKey, () =>
      core.request<{
        printJobId?: string;
        printSessionId?: string;
        tokenCount?: number;
        mode?: string;
        pipelineState?: string;
        printer?: { id?: string; name?: string };
      }>("/manufacturer/print-jobs", {
        method: "POST",
        headers: { "x-idempotency-key": actionKey },
        body: JSON.stringify(payload),
      })
    );
  },

  async listRegisteredPrinters(includeInactive = false, options?: ControlledPrinterGetOptions) {
    const query = includeInactive ? "?includeInactive=true" : "";
    return controlledPrinterGet<any[]>(
      `registered-printers:${includeInactive ? "include-inactive" : "active"}`,
      PRINTER_LIST_MIN_REFRESH_MS,
      () => core.request<any[]>(`/manufacturer/printers${query}`),
      options
    );
  },

  async createNetworkPrinter(payload: {
    name: string;
    vendor?: string;
    model?: string;
    licenseeId?: string;
    connectionType?: "NETWORK_DIRECT" | "NETWORK_IPP";
    commandLanguage?:
      | "ZPL"
      | "TSPL"
      | "SBPL"
      | "EPL"
      | "DPL"
      | "HONEYWELL_DP"
      | "HONEYWELL_FINGERPRINT"
      | "IPL"
      | "ZSIM"
      | "CPCL";
    ipAddress?: string;
    host?: string;
    port?: number;
    resourcePath?: string;
    tlsEnabled?: boolean;
    printerUri?: string;
    deliveryMode?: "DIRECT" | "SITE_GATEWAY";
    rotateGatewaySecret?: boolean;
    capabilitySummary?: Record<string, unknown>;
    calibrationProfile?: Record<string, unknown>;
    isActive?: boolean;
    isDefault?: boolean;
  }) {
    return core.request(`/manufacturer/printers`, { method: "POST", body: JSON.stringify(payload) });
  },

  async updateNetworkPrinter(
    printerId: string,
    payload: Partial<{
      name: string;
      vendor: string;
      model: string;
      connectionType: "NETWORK_DIRECT" | "NETWORK_IPP";
      commandLanguage:
        | "ZPL"
        | "TSPL"
        | "SBPL"
        | "EPL"
        | "DPL"
        | "HONEYWELL_DP"
        | "HONEYWELL_FINGERPRINT"
        | "IPL"
        | "ZSIM"
        | "CPCL";
      ipAddress: string;
      host: string;
      port: number;
      resourcePath: string;
      tlsEnabled: boolean;
      printerUri: string;
      deliveryMode: "DIRECT" | "SITE_GATEWAY";
      rotateGatewaySecret: boolean;
      capabilitySummary: Record<string, unknown>;
      calibrationProfile: Record<string, unknown>;
      isActive: boolean;
      isDefault: boolean;
    }>
  ) {
    return core.request(`/manufacturer/printers/${encodeURIComponent(printerId)}`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    });
  },

  async testRegisteredPrinter(printerId: string) {
    const actionKey = buildPrinterActionKey("printer-test", [printerId]);
    return controlledPrinterMutation(actionKey, () =>
      core.request(`/manufacturer/printers/${encodeURIComponent(printerId)}/test`, {
        method: "POST",
        headers: { "x-idempotency-key": actionKey },
      })
    );
  },

  async testPrinterLabel(printerId: string) {
    const actionKey = buildPrinterActionKey("printer-test-label", [printerId]);
    return controlledPrinterMutation(actionKey, () =>
      core.request<any>(`/manufacturer/printers/${encodeURIComponent(printerId)}/test-label`, {
        method: "POST",
        headers: { "x-idempotency-key": actionKey },
      })
    );
  },

  async relinkLocalAgentPrinter(printerId: string) {
    return core.request<any>(`/manufacturer/printers/${encodeURIComponent(printerId)}/relink-local-agent`, {
      method: "POST",
    });
  },

  async discoverRegisteredPrinter(printerId: string) {
    return core.request(`/manufacturer/printers/${encodeURIComponent(printerId)}/discover`, { method: "POST" });
  },

  async deleteRegisteredPrinter(printerId: string) {
    return core.request(`/manufacturer/printers/${encodeURIComponent(printerId)}`, { method: "DELETE" });
  },

  async listPrintJobs(options?: { batchId?: string; limit?: number }) {
    const params = new URLSearchParams();
    if (options?.batchId) params.append("batchId", options.batchId);
    if (options?.limit) params.append("limit", String(options.limit));
    const query = params.toString() ? `?${params.toString()}` : "";
    return controlledPrinterGet<any[]>(`manufacturer-print-jobs:${query}`, 30_000, () => core.request<any[]>(`/manufacturer/print-jobs${query}`));
  },

  async getPrintJobStatus(jobId: string, options?: ControlledPrinterGetOptions) {
    return controlledPrinterGet<any>(
      `manufacturer-print-job-status:${jobId}`,
      options?.minIntervalMs ?? 30_000,
      () => core.request<any>(`/manufacturer/print-jobs/${encodeURIComponent(jobId)}`),
      options
    );
  },

  ...createPrintingOperationsApi(core),

  async abandonPrintJob(jobId: string) {
    return core.request<any>(`/manufacturer/print-jobs/${encodeURIComponent(jobId)}/abandon`, {
      method: "POST",
    });
  },

  async confirmPrintJobPrinted(
    jobId: string,
    payload: { operatorNote?: string; printLockToken?: string } = {}
  ) {
    return core.request<any>(`/manufacturer/print-jobs/${encodeURIComponent(jobId)}/confirm`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
  },

  async capturePrintJobSampleScan(jobId: string, publicCode: string) {
    return core.request<any>(`/manufacturer/print-jobs/${encodeURIComponent(jobId)}/sample-scan`, {
      method: "POST",
      body: JSON.stringify({ publicCode }),
    });
  },

  async releaseBatch(batchId: string) {
    return core.request<BatchReleaseResponse>(`/qr/batches/${encodeURIComponent(batchId)}/release`, {
      method: "POST",
    });
  },

  async reportPrinterHeartbeat(payload: {
    connected: boolean;
    printerName?: string;
    printerId?: string;
    selectedPrinterId?: string;
    selectedPrinterName?: string;
    deviceName?: string;
    agentVersion?: string;
    protocolVersion?: string;
    buildVersion?: string;
    transportDiagnosticsVersion?: string; capabilities?: Record<string, unknown> | null;
    error?: string;
    agentId?: string;
    deviceFingerprint?: string;
    publicKeyPem?: string;
    clientCertFingerprint?: string;
    heartbeatNonce?: string;
    heartbeatIssuedAt?: string;
    heartbeatSignature?: string;
    capabilitySummary?: {
      transports?: string[];
      protocols?: string[];
      languages?: string[];
      supportsRaster?: boolean;
      supportsPdf?: boolean;
      dpiOptions?: number[];
      mediaSizes?: string[];
    } | null;
    printers?: Array<{
      printerId: string;
      printerName: string;
      model?: string | null;
      connection?: string | null;
      online?: boolean;
      isDefault?: boolean;
      protocols?: string[];
      languages?: string[];
      mediaSizes?: string[];
      dpi?: number | null;
    }>;
    calibrationProfile?: Record<string, unknown> | null;
  }) {
    const heartbeatKey = `printer-agent-heartbeat:${stablePrinterPayloadSignature({
      connected: payload.connected,
      printerId: payload.printerId,
      selectedPrinterId: payload.selectedPrinterId,
      deviceFingerprint: payload.deviceFingerprint,
      error: payload.error,
    })}`;
    return controlledPrinterGet<{
      connected: boolean;
      trusted: boolean;
      compatibilityMode: boolean;
      degraded?: boolean;
      compatibilityReason?: string | null;
      eligibleForPrinting: boolean;
      connectionClass: "TRUSTED" | "COMPATIBILITY" | "BLOCKED";
      stale: boolean;
      requiredForPrinting: boolean;
      trustStatus: string;
      trustReason?: string | null;
      lastHeartbeatAt: string | null;
      ageSeconds: number | null;
      registrationId?: string | null;
      agentId?: string | null;
      deviceFingerprint?: string | null;
      mtlsFingerprint?: string | null;
      printerName?: string | null;
      printerId?: string | null;
      selectedPrinterId?: string | null;
      selectedPrinterName?: string | null;
      deviceName?: string | null;
      agentVersion?: string | null;
      protocolVersion?: string | null;
      buildVersion?: string | null;
      transportDiagnosticsVersion?: string | null; capabilities?: Record<string, unknown> | null;
      connectorUpdateRequired?: boolean;
      capabilitySummary?: {
        transports: string[];
        protocols: string[];
        languages: string[];
        supportsRaster: boolean;
        supportsPdf: boolean;
        dpiOptions: number[];
        mediaSizes: string[];
      } | null;
      printers?: Array<{
        printerId: string;
        printerName: string;
        model?: string | null;
        connection?: string | null;
        online?: boolean;
        isDefault?: boolean;
        protocols?: string[];
        languages?: string[];
        mediaSizes?: string[];
        dpi?: number | null;
      }>;
      calibrationProfile?: Record<string, unknown> | null;
      error?: string | null;
    }>(
      heartbeatKey,
      PRINTER_HEARTBEAT_MIN_REFRESH_MS,
      () =>
        core.request(`/manufacturer/printer-agent/heartbeat`, {
          method: "POST",
          body: JSON.stringify(payload),
          suppressMutationEvent: true,
        })
    );
  },

  async getPrinterConnectionStatus(options?: ControlledPrinterGetOptions) {
    return controlledPrinterGet<{
      connected: boolean;
      trusted: boolean;
      compatibilityMode: boolean;
      degraded?: boolean;
      compatibilityReason?: string | null;
      eligibleForPrinting: boolean;
      connectionClass: "TRUSTED" | "COMPATIBILITY" | "BLOCKED";
      stale: boolean;
      requiredForPrinting: boolean;
      trustStatus: string;
      trustReason?: string | null;
      lastHeartbeatAt: string | null;
      ageSeconds: number | null;
      registrationId?: string | null;
      agentId?: string | null;
      deviceFingerprint?: string | null;
      mtlsFingerprint?: string | null;
      printerName?: string | null;
      printerId?: string | null;
      selectedPrinterId?: string | null;
      selectedPrinterName?: string | null;
      deviceName?: string | null;
      agentVersion?: string | null;
      protocolVersion?: string | null;
      buildVersion?: string | null;
      transportDiagnosticsVersion?: string | null; capabilities?: Record<string, unknown> | null;
      connectorUpdateRequired?: boolean;
      capabilitySummary?: {
        transports: string[];
        protocols: string[];
        languages: string[];
        supportsRaster: boolean;
        supportsPdf: boolean;
        dpiOptions: number[];
        mediaSizes: string[];
      } | null;
      printers?: Array<{
        printerId: string;
        printerName: string;
        model?: string | null;
        connection?: string | null;
        online?: boolean;
        isDefault?: boolean;
        protocols?: string[];
        languages?: string[];
        mediaSizes?: string[];
        dpi?: number | null;
      }>;
      calibrationProfile?: Record<string, unknown> | null;
      error?: string | null;
      refreshPaused?: boolean;
      rateLimited?: boolean;
      retryAfterSec?: number;
      notice?: string;
    }>(
      "printer-agent-status",
      PRINTER_STATUS_MIN_REFRESH_MS,
      () => core.request(`/manufacturer/printer-agent/status`),
      options
    );
  },

  ...createLocalAgentPrintingApi(),

  async getManufacturers(arg?: string | { licenseeId?: string; includeInactive?: boolean }) {
    let licenseeId: string | undefined;
    let includeInactive = false;

    if (typeof arg === "string") licenseeId = arg;
    else if (arg) {
      licenseeId = arg.licenseeId;
      includeInactive = !!arg.includeInactive;
    }

    const params = new URLSearchParams();
    if (licenseeId) params.append("licenseeId", licenseeId);
    if (includeInactive) params.append("includeInactive", "true");

    const query = params.toString() ? `?${params.toString()}` : "";
    return core.request<any[]>(`/manufacturers${query}`);
  },

  async deactivateManufacturer(id: string) {
    return core.request(`/manufacturers/${id}/deactivate`, { method: "PATCH" });
  },

  async restoreManufacturer(id: string) {
    return core.request(`/manufacturers/${id}/restore`, { method: "PATCH" });
  },

  async hardDeleteManufacturer(id: string) {
    return core.request(`/manufacturers/${id}`, { method: "DELETE" });
  },
});
