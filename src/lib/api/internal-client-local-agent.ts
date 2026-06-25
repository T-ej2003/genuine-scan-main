const localPrintAgentBaseUrl = () =>
  String(import.meta.env.VITE_PRINT_AGENT_URL || "http://127.0.0.1:17866")
    .trim()
    .replace(/\/+$/, "");

export const createLocalAgentPrintingApi = () => {
  const api = {
    async getLocalPrintAgentStatus() {
      const base = localPrintAgentBaseUrl();
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
            protocolVersion: String((data as any).protocolVersion || "").trim() || null,
            buildVersion: String((data as any).buildVersion || "").trim() || null,
            transportDiagnosticsVersion: String((data as any).transportDiagnosticsVersion || "").trim() || null,
            capabilities:
              (data as any).capabilities && typeof (data as any).capabilities === "object"
                ? ((data as any).capabilities as Record<string, unknown>)
                : null,
            error: String((data as any).error || "").trim() || null,
            agentId: String((data as any).agentId || "").trim() || null,
            deviceFingerprint: String((data as any).deviceFingerprint || "").trim() || null,
            publicKeyPem: String((data as any).publicKeyPem || "").trim() || null,
            clientCertFingerprint: String((data as any).clientCertFingerprint || "").trim() || null,
            heartbeatNonce: String((data as any).heartbeatNonce || "").trim() || null,
            heartbeatIssuedAt: String((data as any).heartbeatIssuedAt || "").trim() || null,
            heartbeatSignature: String((data as any).heartbeatSignature || "").trim() || null,
            compatibilityMode: Boolean((data as any).compatibilityMode),
            websocket:
              (data as any).websocket && typeof (data as any).websocket === "object"
                ? ((data as any).websocket as Record<string, unknown>)
                : null,
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
        return {
          success: false,
          error: aborted ? "Local print agent status timed out" : "Local print agent is unavailable",
        };
      } finally {
        window.clearTimeout(timeout);
      }
    },

    async configureLocalPrintAgentBackend(backendUrl: string) {
      const base = localPrintAgentBaseUrl();
      const normalizedBackendUrl = String(backendUrl || "").trim().replace(/\/+$/, "");
      if (!normalizedBackendUrl) return { success: false, error: "backendUrl is required" };
      const controller = new AbortController();
      const timeout = window.setTimeout(() => controller.abort(), 3500);
      try {
        const response = await fetch(`${base}/backend/config`, {
          method: "POST",
          mode: "cors",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ backendUrl: normalizedBackendUrl }),
          signal: controller.signal,
        });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok) {
          return {
            success: false,
            error: String((payload as any)?.error || `Local print backend configuration failed: HTTP ${response.status}`),
          };
        }
        return { success: true, data: payload };
      } catch (error: any) {
        const aborted = error?.name === "AbortError";
        return {
          success: false,
          error: aborted ? "Local print backend configuration timed out" : "Local print agent is unavailable",
        };
      } finally {
        window.clearTimeout(timeout);
      }
    },

    async wakeLocalPrintAgent(reason = "user_print_job_created") {
      const base = localPrintAgentBaseUrl();
      const controller = new AbortController();
      const timeout = window.setTimeout(() => controller.abort(), 1500);
      try {
        const response = await fetch(`${base}/wake`, {
          method: "POST",
          mode: "cors",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ reason }),
          signal: controller.signal,
        });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok) {
          return {
            success: false,
            status: response.status,
            error: String((payload as any)?.error || `Local print wake failed: HTTP ${response.status}`),
          };
        }
        return { success: true, data: payload?.data || payload };
      } catch (error: any) {
        const aborted = error?.name === "AbortError";
        return {
          success: false,
          error: aborted ? "Local print wake timed out" : "Local print agent is unavailable",
        };
      } finally {
        window.clearTimeout(timeout);
      }
    },

    async getLocalPrinters() {
      const base = localPrintAgentBaseUrl();
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

        const fallback = await api.getLocalPrintAgentStatus();
        if (!fallback.success || !fallback.data) {
          return { success: false, error: fallback.error || "Local printer discovery unavailable" };
        }
        const printers = Array.isArray((fallback.data as any).printers) ? (fallback.data as any).printers : [];
        return { success: true, data: { printers } };
      } catch (error: any) {
        const aborted = error?.name === "AbortError";
        return {
          success: false,
          error: aborted ? "Local printer discovery timed out" : "Local print agent is unavailable",
        };
      } finally {
        window.clearTimeout(timeout);
      }
    },

    async selectLocalPrinter(printerId: string) {
      const selected = String(printerId || "").trim();
      if (!selected) return { success: false, error: "printerId is required" };
      const base = localPrintAgentBaseUrl();
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
            return {
              success: false,
              error: String((payload as any)?.error || `Printer switch failed: HTTP ${response.status}`),
            };
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

      const base = localPrintAgentBaseUrl();
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
        return { success: false, error: aborted ? "Printer setup check timed out" : "Printer helper is unavailable" };
      } finally {
        window.clearTimeout(timeout);
      }
    },
  };

  return api;
};
