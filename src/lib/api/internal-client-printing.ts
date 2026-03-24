import { type ApiClientCore } from "@/lib/api/internal-client-core";

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
    return core.request("/manufacturer/print-jobs", { method: "POST", body: JSON.stringify(payload) });
  },

  async listRegisteredPrinters(includeInactive = false) {
    const query = includeInactive ? "?includeInactive=true" : "";
    return core.request<any[]>(`/manufacturer/printers${query}`);
  },

  async createNetworkPrinter(payload: {
    name: string;
    vendor?: string;
    model?: string;
    licenseeId?: string;
    connectionType?: "NETWORK_DIRECT" | "NETWORK_IPP";
    commandLanguage?: "ZPL" | "TSPL" | "EPL" | "CPCL";
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
      commandLanguage: "ZPL" | "TSPL" | "EPL" | "CPCL";
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
    return core.request(`/manufacturer/printers/${encodeURIComponent(printerId)}/test`, { method: "POST" });
  },

  async deleteRegisteredPrinter(printerId: string) {
    return core.request(`/manufacturer/printers/${encodeURIComponent(printerId)}`, { method: "DELETE" });
  },

  async listPrintJobs(options?: { batchId?: string; limit?: number }) {
    const params = new URLSearchParams();
    if (options?.batchId) params.append("batchId", options.batchId);
    if (options?.limit) params.append("limit", String(options.limit));
    const query = params.toString() ? `?${params.toString()}` : "";
    return core.request<any[]>(`/manufacturer/print-jobs${query}`);
  },

  async getPrintJobStatus(jobId: string) {
    return core.request<any>(`/manufacturer/print-jobs/${encodeURIComponent(jobId)}`);
  },

  async requestDirectPrintTokens(jobId: string, printLockToken: string, count = 1) {
    return core.request<{
      printJobId: string;
      printSessionId?: string;
      lockExpiresAt?: string;
      directPrintTokenExpiresAt?: string;
      remainingToPrint: number;
      items: Array<{
        printItemId: string;
        qrId: string;
        code: string;
        renderToken: string;
        expiresAt: string;
      }>;
    }>(`/manufacturer/print-jobs/${encodeURIComponent(jobId)}/direct-print/tokens`, {
      method: "POST",
      body: JSON.stringify({ printLockToken, count }),
    });
  },

  async resolveDirectPrintToken(jobId: string, payload: { printLockToken: string; renderToken: string }) {
    return core.request<{
      printJobId: string;
      printSessionId?: string;
      printItemId: string;
      qrId: string;
      code: string;
      renderResolvedAt: string;
      remainingToPrint: number;
      jobConfirmed: boolean;
      confirmedAt: string | null;
      printMode: "LOCAL_AGENT" | "NETWORK_DIRECT";
      payloadType: "ZPL" | "TSPL" | "SBPL" | "EPL" | "CPCL" | "ESC_POS" | "JSON" | "OTHER";
      payloadContent: string;
      payloadHash: string;
      previewLabel: string;
      commandLanguage: string;
      scanToken: string;
      scanUrl: string;
      printer: {
        id: string;
        name: string;
        connectionType: "LOCAL_AGENT" | "NETWORK_DIRECT";
        commandLanguage: string;
        nativePrinterId?: string | null;
      };
    }>(`/manufacturer/print-jobs/${encodeURIComponent(jobId)}/direct-print/resolve`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
  },

  async confirmDirectPrintItem(
    jobId: string,
    payload: {
      printLockToken: string;
      printItemId: string;
      agentMetadata?: any;
    }
  ) {
    return core.request<{
      printJobId: string;
      printSessionId?: string;
      printItemId: string;
      qrId: string;
      code: string;
      printConfirmedAt: string;
      remainingToPrint: number;
      jobConfirmed: boolean;
      confirmedAt: string | null;
    }>(`/manufacturer/print-jobs/${encodeURIComponent(jobId)}/direct-print/confirm-item`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
  },

  async reportDirectPrintFailure(
    jobId: string,
    payload: {
      printLockToken: string;
      reason: string;
      printItemId?: string;
      retries?: number;
      agentMetadata?: any;
    }
  ) {
    return core.request<{
      printJobId: string;
      printSessionId?: string;
      incidentId?: string;
      frozenCount?: number;
      reason: string;
    }>(`/manufacturer/print-jobs/${encodeURIComponent(jobId)}/direct-print/fail`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
  },

  async confirmPrintJob(jobId: string, printLockToken: string) {
    return core.request(`/manufacturer/print-jobs/${encodeURIComponent(jobId)}/confirm`, {
      method: "POST",
      body: JSON.stringify({ printLockToken }),
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
    return core.request<{
      connected: boolean;
      trusted: boolean;
      compatibilityMode: boolean;
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
    }>(`/manufacturer/printer-agent/heartbeat`, {
      method: "POST",
      body: JSON.stringify(payload),
      suppressMutationEvent: true,
    });
  },

  async getPrinterConnectionStatus() {
    return core.request<{
      connected: boolean;
      trusted: boolean;
      compatibilityMode: boolean;
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
    }>(`/manufacturer/printer-agent/status`);
  },

  async getLocalPrintAgentStatus() {
    const base = String(import.meta.env.VITE_PRINT_AGENT_URL || "http://127.0.0.1:17866")
      .trim()
      .replace(/\/+$/, "");
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), 2500);
    try {
      const response = await fetch(`${base}/status`, {
        method: "GET",
        cache: "no-store",
        mode: "cors",
        signal: controller.signal,
      });
      if (!response.ok) {
        return { success: false, error: `Local print agent status failed: HTTP ${response.status}` };
      }
      const payload = await response.json().catch(() => ({}));
      const data = payload && typeof payload === "object" ? payload : {};
      const printers = Array.isArray((data as any).printers)
        ? (data as any).printers
        : Array.isArray((data as any).devices)
          ? (data as any).devices
          : [];
      const selectedPrinterId = String((data as any).selectedPrinterId || (data as any).printerId || "").trim() || null;
      const selectedPrinterName =
        String((data as any).selectedPrinterName || (data as any).printerName || "").trim() || null;
      return {
        success: true,
        data: {
          connected: Boolean((data as any).connected),
          printerName: String((data as any).printerName || "").trim() || null,
          printerId: String((data as any).printerId || "").trim() || null,
          selectedPrinterId,
          selectedPrinterName,
          deviceName: String((data as any).deviceName || "").trim() || null,
          agentVersion: String((data as any).agentVersion || "").trim() || null,
          error: String((data as any).error || "").trim() || null,
          agentId: String((data as any).agentId || "").trim() || null,
          deviceFingerprint: String((data as any).deviceFingerprint || "").trim() || null,
          publicKeyPem: String((data as any).publicKeyPem || "").trim() || null,
          clientCertFingerprint: String((data as any).clientCertFingerprint || "").trim() || null,
          heartbeatNonce: String((data as any).heartbeatNonce || "").trim() || null,
          heartbeatIssuedAt: String((data as any).heartbeatIssuedAt || "").trim() || null,
          heartbeatSignature: String((data as any).heartbeatSignature || "").trim() || null,
          compatibilityMode: Boolean((data as any).compatibilityMode),
          capabilitySummary:
            (data as any).capabilitySummary && typeof (data as any).capabilitySummary === "object"
              ? ((data as any).capabilitySummary as Record<string, unknown>)
              : (data as any).capabilities && typeof (data as any).capabilities === "object"
                ? ((data as any).capabilities as Record<string, unknown>)
                : null,
          printers: Array.isArray(printers) ? printers : [],
          calibrationProfile:
            (data as any).calibrationProfile && typeof (data as any).calibrationProfile === "object"
              ? ((data as any).calibrationProfile as Record<string, unknown>)
              : null,
        },
      };
    } catch (error: any) {
      const aborted = error?.name === "AbortError";
      return { success: false, error: aborted ? "Local print agent status timed out" : "Local print agent is unavailable" };
    } finally {
      window.clearTimeout(timeout);
    }
  },

  async getLocalPrinters() {
    const base = String(import.meta.env.VITE_PRINT_AGENT_URL || "http://127.0.0.1:17866")
      .trim()
      .replace(/\/+$/, "");
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), 3000);
    try {
      const response = await fetch(`${base}/printers`, {
        method: "GET",
        cache: "no-store",
        mode: "cors",
        signal: controller.signal,
      });
      if (response.ok) {
        const payload = await response.json().catch(() => ({}));
        const rows = Array.isArray((payload as any)?.printers)
          ? (payload as any).printers
          : Array.isArray(payload)
            ? payload
            : [];
        return { success: true, data: { printers: rows } };
      }

      if (response.status !== 404) {
        return { success: false, error: `Local printer discovery failed: HTTP ${response.status}` };
      }

      const fallback = await this.getLocalPrintAgentStatus();
      if (!fallback.success || !fallback.data) {
        return { success: false, error: fallback.error || "Local printer discovery unavailable" };
      }
      const printers = Array.isArray((fallback.data as any).printers) ? (fallback.data as any).printers : [];
      return { success: true, data: { printers } };
    } catch (error: any) {
      const aborted = error?.name === "AbortError";
      return { success: false, error: aborted ? "Local printer discovery timed out" : "Local print agent is unavailable" };
    } finally {
      window.clearTimeout(timeout);
    }
  },

  async selectLocalPrinter(printerId: string) {
    const selected = String(printerId || "").trim();
    if (!selected) return { success: false, error: "printerId is required" };
    const base = String(import.meta.env.VITE_PRINT_AGENT_URL || "http://127.0.0.1:17866")
      .trim()
      .replace(/\/+$/, "");
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), 4500);
    const body = JSON.stringify({ printerId: selected });
    try {
      for (const path of ["/printer/select", "/printers/select"]) {
        const response = await fetch(`${base}${path}`, {
          method: "POST",
          mode: "cors",
          headers: { "Content-Type": "application/json" },
          body,
          signal: controller.signal,
        });
        if (response.ok) {
          const payload = await response.json().catch(() => ({}));
          return { success: true, data: payload };
        }
        if (response.status !== 404) {
          const payload = await response.json().catch(() => ({}));
          return { success: false, error: String((payload as any)?.error || `Printer switch failed: HTTP ${response.status}`) };
        }
      }
      return { success: false, error: "Local print agent does not expose printer switching endpoint" };
    } catch (error: any) {
      const aborted = error?.name === "AbortError";
      return { success: false, error: aborted ? "Local printer switch timed out" : "Local print agent is unavailable" };
    } finally {
      window.clearTimeout(timeout);
    }
  },

  async applyLocalPrinterCalibration(payload: {
    printerId: string;
    dpi?: number;
    labelWidthMm?: number;
    labelHeightMm?: number;
    offsetXmm?: number;
    offsetYmm?: number;
    darkness?: number;
    speed?: number;
  }) {
    const printerId = String(payload.printerId || "").trim();
    if (!printerId) return { success: false, error: "printerId is required" };

    const base = String(import.meta.env.VITE_PRINT_AGENT_URL || "http://127.0.0.1:17866")
      .trim()
      .replace(/\/+$/, "");
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), 6000);
    try {
      const normalizedPayload = {
        printerId,
        dpi: Number(payload.dpi || 0) || undefined,
        labelWidthMm: Number(payload.labelWidthMm || 0) || undefined,
        labelHeightMm: Number(payload.labelHeightMm || 0) || undefined,
        offsetXmm: Number(payload.offsetXmm || 0) || 0,
        offsetYmm: Number(payload.offsetYmm || 0) || 0,
        darkness: Number(payload.darkness || 0) || undefined,
        speed: Number(payload.speed || 0) || undefined,
      };
      for (const path of ["/printer/calibration", "/printers/calibration"]) {
        const response = await fetch(`${base}${path}`, {
          method: "POST",
          mode: "cors",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(normalizedPayload),
          signal: controller.signal,
        });
        if (response.ok) {
          const body = await response.json().catch(() => ({}));
          return { success: true, data: body };
        }
        if (response.status !== 404) {
          const body = await response.json().catch(() => ({}));
          return { success: false, error: String((body as any)?.error || `Calibration failed: HTTP ${response.status}`) };
        }
      }
      return { success: false, error: "Local print agent does not expose calibration endpoint" };
    } catch (error: any) {
      const aborted = error?.name === "AbortError";
      return { success: false, error: aborted ? "Local calibration request timed out" : "Local print agent is unavailable" };
    } finally {
      window.clearTimeout(timeout);
    }
  },

  async printWithLocalAgent(payload: {
    printJobId: string;
    qrId: string;
    code: string;
    scanUrl: string;
    payloadType?: "ZPL" | "TSPL" | "SBPL" | "EPL" | "CPCL" | "ESC_POS" | "JSON" | "OTHER";
    payloadContent?: string;
    payloadHash?: string;
    previewLabel?: string;
    commandLanguage?: string;
    copies?: number;
    printerId?: string;
    printPath?: "auto" | "spooler" | "raw-9100" | "label-language" | "pdf-raster";
    labelLanguage?: "AUTO" | "ZPL" | "EPL" | "CPCL" | "TSPL" | "ESC_POS";
    mediaSize?: string;
    calibrationProfile?: Record<string, unknown> | null;
  }) {
    const base = String(import.meta.env.VITE_PRINT_AGENT_URL || "http://127.0.0.1:17866")
      .trim()
      .replace(/\/+$/, "");
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), 8000);
    try {
      const response = await fetch(`${base}/print`, {
        method: "POST",
        mode: "cors",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          printJobId: payload.printJobId,
          qrId: payload.qrId,
          code: payload.code,
          scanUrl: payload.scanUrl,
          payloadType: payload.payloadType || undefined,
          payloadContent: payload.payloadContent || undefined,
          payloadHash: payload.payloadHash || undefined,
          previewLabel: payload.previewLabel || undefined,
          commandLanguage: payload.commandLanguage || undefined,
          copies: Math.max(1, Math.min(5, Number(payload.copies || 1))),
          printerId: payload.printerId || undefined,
          printPath: payload.printPath || "auto",
          labelLanguage: payload.labelLanguage || "AUTO",
          mediaSize: payload.mediaSize || undefined,
          calibrationProfile:
            payload.calibrationProfile && typeof payload.calibrationProfile === "object"
              ? payload.calibrationProfile
              : undefined,
          fallbackRaster: true,
        }),
        signal: controller.signal,
      });
      const body = await response.json().catch(() => ({}));
      if (!response.ok || body?.success === false) {
        return {
          success: false,
          error: String(body?.error || "").trim() || `Local print failed: HTTP ${response.status}`,
        };
      }
      return {
        success: true,
        data: {
          queued: Boolean(body?.queued ?? true),
          printerName: body?.printerName || null,
          jobRef: body?.jobRef || null,
          printPath: body?.printPath || payload.printPath || "auto",
          labelLanguage: body?.labelLanguage || payload.labelLanguage || "AUTO",
        },
      };
    } catch (error: any) {
      const aborted = error?.name === "AbortError";
      return { success: false, error: aborted ? "Local print request timed out" : "Local print agent is unavailable" };
    } finally {
      window.clearTimeout(timeout);
    }
  },

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
