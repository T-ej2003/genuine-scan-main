import { emitMutationEvent } from "@/lib/mutation-events";
import { recordSupportNetworkLog, reportSupportRuntimeIssue } from "@/lib/support-diagnostics";

const BASE_URL = import.meta.env.VITE_API_URL || "/api";

export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  error?: string;
  message?: string;
}

type RequestOptions = RequestInit & {
  skipJson?: boolean;
  timeoutMs?: number;
  skipAuthRefresh?: boolean;
  suppressMutationEvent?: boolean;
};

class ApiClient {
  private token: string | null = null;
  private readonly getCache = new Map<string, unknown>();
  private refreshInFlight: Promise<ApiResponse<{ token: string; user: any }>> | null = null;

  constructor() {
    // Access tokens are stored in HttpOnly cookies (server-managed).
    // We keep an in-memory access token for SSE compatibility flows.
    this.token = null;
  }

  setToken(token: string | null) {
    this.token = token;
  }

  getToken(): string | null {
    return this.token;
  }

  logout() {
    this.setToken(null);
    this.getCache.clear();
  }

  private emitLogout() {
    window.dispatchEvent(new Event("auth:logout"));
  }

  private readCookie(name: string) {
    try {
      const match = document.cookie
        .split(";")
        .map((c) => c.trim())
        .find((c) => c.startsWith(`${name}=`));
      if (!match) return "";
      return decodeURIComponent(match.split("=").slice(1).join("="));
    } catch {
      return "";
    }
  }

  private isAuthRefreshEndpoint(endpoint: string) {
    return endpoint === "/auth/login" || endpoint === "/auth/refresh" || endpoint === "/auth/logout" || endpoint === "/auth/accept-invite";
  }

  private async refreshOnce() {
    if (this.refreshInFlight) return this.refreshInFlight;
    this.refreshInFlight = this.request<{ token: string; user: any }>("/auth/refresh", {
      method: "POST",
      skipAuthRefresh: true,
    }).finally(() => {
      this.refreshInFlight = null;
    });
    const res = await this.refreshInFlight;
    if (res.success && res.data?.token) this.setToken(res.data.token);
    return res;
  }

  private async request<T>(endpoint: string, options: RequestOptions = {}): Promise<ApiResponse<T>> {
    const headers: Record<string, string> = {
      ...(options.headers as Record<string, string>),
    };

    const method = String(options.method || "GET").toUpperCase();
    const cacheKey = `${this.token || "cookie"}:${endpoint}`;

    const hasBody = options.body !== undefined && options.body !== null;
    const isForm = typeof FormData !== "undefined" && options.body instanceof FormData;

    if (!options.skipJson && hasBody && !isForm) {
      headers["Content-Type"] = "application/json";
    }
    const hasAuthorizationHeader = Object.keys(headers).some((key) => key.toLowerCase() === "authorization");
    if (this.token && !hasAuthorizationHeader) headers["Authorization"] = `Bearer ${this.token}`;

    // Double-submit CSRF: server sets `aq_csrf` cookie; client mirrors it in header.
    const isStateChanging = !["GET", "HEAD", "OPTIONS"].includes(method);
    if (isStateChanging) {
      const hasIdempotencyHeader = Object.keys(headers).some((key) => key.toLowerCase() === "x-idempotency-key");
      if (!hasIdempotencyHeader) {
        const generatedKey =
          typeof crypto !== "undefined" && typeof crypto.randomUUID === "function"
            ? crypto.randomUUID()
            : `${Date.now()}-${Math.random().toString(36).slice(2)}`;
        headers["x-idempotency-key"] = generatedKey;
      }

      const csrf = this.readCookie("aq_csrf");
      if (csrf && !headers["x-csrf-token"] && !headers["X-CSRF-Token"]) {
        headers["x-csrf-token"] = csrf;
      }
    }

    const controller = new AbortController();
    const timeoutMs = options.timeoutMs ?? 20_000;
    const t = window.setTimeout(() => controller.abort(), timeoutMs);
    const startedAt = typeof performance !== "undefined" ? performance.now() : Date.now();

    const elapsedMs = () => {
      const now = typeof performance !== "undefined" ? performance.now() : Date.now();
      return Math.max(1, Math.round(now - startedAt));
    };

    const pushNetworkLog = (entry: { status: number | null; ok: boolean; error?: string }) => {
      recordSupportNetworkLog({
        method,
        endpoint,
        status: entry.status,
        ok: entry.ok,
        durationMs: elapsedMs(),
        error: entry.error,
      });
    };

    try {
      const res = await fetch(`${BASE_URL}${endpoint}`, {
        ...options,
        headers,
        cache: "no-store",
        credentials: "include",
        signal: controller.signal,
      });

      if (res.status === 304 && method === "GET") {
        pushNetworkLog({ status: res.status, ok: true });
        const cached = this.getCache.get(cacheKey);
        if (cached !== undefined) return { success: true, data: cached as T };
        return { success: false, error: "Stale cache miss (HTTP 304)" };
      }

      const contentType = res.headers.get("content-type") || "";
      const isJson = contentType.includes("application/json");

      const payload: any = isJson ? await res.json().catch(() => null) : await res.text().catch(() => "");

      if (res.status === 401 && !options.skipAuthRefresh && !this.isAuthRefreshEndpoint(endpoint)) {
        const msg =
          (payload && typeof payload === "object" && (payload.error || payload.message)) ||
          (typeof payload === "string" && payload) ||
          "Not authenticated";

        // No in-memory token and no CSRF cookie means we almost certainly have no session
        // to refresh (common on a fresh /login page load).
        if (!this.token && !this.readCookie("aq_csrf")) {
          pushNetworkLog({ status: res.status, ok: false, error: msg });
          return { success: false, error: msg };
        }

        // Attempt to rotate refresh token and retry once (cookie-based sessions).
        const refreshed = await this.refreshOnce();
        if (refreshed.success) {
          return this.request<T>(endpoint, { ...options, skipAuthRefresh: true });
        }

        this.logout();
        this.emitLogout();
        pushNetworkLog({ status: res.status, ok: false, error: msg });
        return { success: false, error: msg };
      }

      if (!res.ok) {
        const msg =
          (payload && typeof payload === "object" && (payload.error || payload.message)) ||
          (typeof payload === "string" && payload) ||
          `HTTP ${res.status}`;
        pushNetworkLog({ status: res.status, ok: false, error: msg });
        if (res.status >= 500) {
          reportSupportRuntimeIssue({
            source: "network",
            message: `Server error (${res.status}) on ${method} ${endpoint}`,
          });
        }
        return { success: false, error: msg };
      }

      pushNetworkLog({ status: res.status, ok: true });

      if (payload && typeof payload === "object" && "success" in payload) {
        if (method === "GET" && payload.success) {
          this.getCache.set(cacheKey, (payload as ApiResponse<T>).data as T);
        }
        if (method !== "GET" && method !== "HEAD" && payload.success && !options.suppressMutationEvent) {
          emitMutationEvent({ endpoint, method });
        }
        return payload as ApiResponse<T>;
      }

      if (method === "GET") {
        this.getCache.set(cacheKey, payload as T);
      }

      if (method !== "GET" && method !== "HEAD" && !options.suppressMutationEvent) {
        emitMutationEvent({ endpoint, method });
      }
      return { success: true, data: payload as T };
    } catch (err: any) {
      const isAbort = err?.name === "AbortError";
      const msg = isAbort ? "Request timed out" : "Network error - is the backend running?";
      pushNetworkLog({ status: null, ok: false, error: msg });
      reportSupportRuntimeIssue({
        source: "network",
        message: `${method} ${endpoint}: ${msg}`,
      });
      return { success: false, error: isAbort ? "Request timed out" : "Network error - is the backend running?" };
    } finally {
      window.clearTimeout(t);
    }
  }

  // ==================== AUTH ====================
  async login(email: string, password: string) {
    const res = await this.request<{
      token?: string;
      user?: any;
      mfaRequired?: boolean;
      mfaTicket?: string;
      mfaExpiresAt?: string;
      riskScore?: number;
      riskLevel?: string;
      reasons?: string[];
    }>("/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    });

    if (res.success && res.data?.token) this.setToken(res.data.token);
    return res;
  }

  async completeMfaLogin(ticket: string, code: string) {
    const res = await this.request<{ token: string; user: any; mfaCompleted: boolean }>("/auth/mfa/complete", {
      method: "POST",
      body: JSON.stringify({ ticket, code }),
    });
    if (res.success && res.data?.token) this.setToken(res.data.token);
    return res;
  }

  async getMfaStatus() {
    return this.request<{
      enrolled: boolean;
      enabled: boolean;
      verifiedAt: string | null;
      lastUsedAt: string | null;
      backupCodesRemaining: number;
      createdAt: string | null;
      updatedAt: string | null;
    }>("/auth/mfa/status");
  }

  async beginMfaSetup() {
    return this.request<{
      secret: string;
      otpauthUri: string;
      backupCodes: string[];
    }>("/auth/mfa/setup", { method: "POST" });
  }

  async confirmMfaSetup(code: string) {
    return this.request<{ enabled: boolean }>("/auth/mfa/enable", {
      method: "POST",
      body: JSON.stringify({ code }),
    });
  }

  async disableMfa() {
    return this.request<{ enabled: boolean }>("/auth/mfa/disable", { method: "POST" });
  }

  async getCurrentUser() {
    return this.request("/auth/me");
  }

  async refreshSession() {
    const res = await this.request<{ token: string; user: any }>("/auth/refresh", { method: "POST" });
    if (res.success && res.data?.token) this.setToken(res.data.token);
    return res;
  }

  async logoutSession() {
    const res = await this.request("/auth/logout", { method: "POST" });
    this.logout();
    return res;
  }

  async forgotPassword(email: string) {
    return this.request("/auth/forgot-password", { method: "POST", body: JSON.stringify({ email }) });
  }

  async resetPassword(token: string, password: string) {
    return this.request("/auth/reset-password", { method: "POST", body: JSON.stringify({ token, password }) });
  }

  async acceptInvite(payload: { token: string; password: string; name?: string }) {
    const res = await this.request<{ token: string; user: any }>("/auth/accept-invite", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    if (res.success && res.data?.token) this.setToken(res.data.token);
    return res;
  }

  async inviteUser(payload: {
    email: string;
    role: string;
    name?: string;
    licenseeId?: string;
    manufacturerId?: string;
    allowExistingInvitedUser?: boolean;
  }) {
    return this.request("/auth/invite", { method: "POST", body: JSON.stringify(payload) });
  }

  // ==================== LICENSEES ====================
  async getLicensees() {
    return this.request<any[]>("/licensees");
  }

  async getLicensee(id: string) {
    return this.request(`/licensees/${id}`);
  }

  async createLicenseeWithAdmin(payload: {
    licensee: {
      name: string;
      prefix: string;
      description?: string;
      brandName?: string;
      location?: string;
      website?: string;
      supportEmail?: string;
      supportPhone?: string;
      isActive?: boolean;
    };
    admin: { name: string; email: string; password?: string; sendInvite?: boolean };
  }) {
    return this.request("/licensees", { method: "POST", body: JSON.stringify(payload) });
  }

  async updateLicensee(
    id: string,
    payload: Partial<{
      name: string;
      description: string;
      brandName: string;
      location: string;
      website: string;
      supportEmail: string;
      supportPhone: string;
      isActive: boolean;
    }>
  ) {
    return this.request(`/licensees/${id}`, { method: "PATCH", body: JSON.stringify(payload) });
  }

  async deleteLicensee(id: string) {
    return this.request(`/licensees/${id}`, { method: "DELETE" });
  }

  async resendLicenseeAdminInvite(licenseeId: string, email?: string) {
    return this.request(`/licensees/${encodeURIComponent(licenseeId)}/admin-invite/resend`, {
      method: "POST",
      body: JSON.stringify({ email }),
    });
  }

  async exportLicenseesCsv() {
    const headers: Record<string, string> = {};
    if (this.token) headers["Authorization"] = `Bearer ${this.token}`;

    const resp = await fetch(`${BASE_URL}/licensees/export`, { headers, credentials: "include" });
    if (!resp.ok) throw new Error(`Export failed: HTTP ${resp.status}`);
    return resp.blob();
  }

  // ==================== QR RANGE ====================
  async allocateQRRange(payload: { licenseeId: string; startNumber: number; endNumber: number }) {
    return this.request("/qr/ranges/allocate", { method: "POST", body: JSON.stringify(payload) });
  }

  async generateQRCodes(payload: { licenseeId: string; quantity: number }) {
    return this.request("/qr/generate", { method: "POST", body: JSON.stringify(payload) });
  }

  async allocateLicenseeQrRange(
    licenseeId: string,
    payload:
      | { startNumber: number; endNumber: number; receivedBatchName?: string }
      | { quantity: number; receivedBatchName?: string }
  ) {
    return this.request(`/admin/licensees/${licenseeId}/qr-allocate-range`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
  }

  // ==================== QR CODES ====================
  async getQRCodes(options?: { licenseeId?: string; status?: string; limit?: number; offset?: number; q?: string }) {
    const params = new URLSearchParams();
    if (options?.licenseeId) params.append("licenseeId", options.licenseeId);
    if (options?.status) params.append("status", options.status);
    if (options?.limit != null) params.append("limit", String(options.limit));
    if (options?.offset != null) params.append("offset", String(options.offset));
    if (options?.q) params.append("q", options.q);

    const query = params.toString() ? `?${params.toString()}` : "";
    return this.request(`/qr/codes${query}`);
  }

  async generateSignedQrLinks(codes: string[]) {
    return this.request<{
      issuedAt: string;
      expiresAt: string;
      links: Array<{ code: string; scanUrl: string; expiresAt: string }>;
    }>("/qr/codes/signed-links", {
      method: "POST",
      body: JSON.stringify({ codes }),
    });
  }

  async getQRStats(licenseeId?: string) {
    const query = licenseeId ? `?licenseeId=${encodeURIComponent(licenseeId)}` : "";
    return this.request(`/qr/stats${query}`);
  }

  async getDashboardStats(licenseeId?: string) {
    const query = licenseeId ? `?licenseeId=${encodeURIComponent(licenseeId)}` : "";
    return this.request(`/dashboard/stats${query}`);
  }

  async deleteQRCodes(payload: { ids?: string[]; codes?: string[] }) {
    return this.request<{ deleted: number }>("/qr/codes", { method: "DELETE", body: JSON.stringify(payload) });
  }

  async exportQRCodesCsv(options?: { licenseeId?: string; status?: string; q?: string }) {
    const params = new URLSearchParams();
    if (options?.licenseeId) params.append("licenseeId", options.licenseeId);
    if (options?.status && options.status !== "all") params.append("status", options.status);
    if (options?.q) params.append("q", options.q);

    const url = `/qr/codes/export${params.toString() ? `?${params.toString()}` : ""}`;
    const headers: Record<string, string> = {};
    if (this.token) headers["Authorization"] = `Bearer ${this.token}`;

    const resp = await fetch(`${BASE_URL}${url}`, { headers, credentials: "include" });
    if (!resp.ok) throw new Error(`Export failed: HTTP ${resp.status}`);
    return resp.blob();
  }

  // ==================== BATCHES ====================
  async getBatches(options?: { licenseeId?: string }) {
    const params = new URLSearchParams();
    if (options?.licenseeId) params.append("licenseeId", options.licenseeId);
    const query = params.toString() ? `?${params.toString()}` : "";
    return this.request<any[]>(`/qr/batches${query}`);
  }

  async deleteBatch(batchId: string) {
    return this.request(`/qr/batches/${batchId}`, { method: "DELETE" });
  }

  async bulkDeleteBatches(payload: { ids: string[] }) {
    return this.request<{ deleted: number }>("/qr/batches/bulk-delete", { method: "POST", body: JSON.stringify(payload) });
  }

  async assignBatchManufacturer(payload: { batchId: string; manufacturerId: string; quantity: number; name?: string }) {
    return this.request(`/qr/batches/${payload.batchId}/assign-manufacturer`, {
      method: "POST",
      body: JSON.stringify({
        manufacturerId: payload.manufacturerId,
        quantity: payload.quantity,
        name: payload.name,
      }),
    });
  }

  async renameBatch(batchId: string, name: string) {
    return this.request(`/qr/batches/${encodeURIComponent(batchId)}/rename`, {
      method: "PATCH",
      body: JSON.stringify({ name }),
    });
  }

  async getBatchAllocationMap(batchId: string) {
    return this.request<{
      sourceBatchId: string;
      focusBatchId: string;
      sourceBatch: any | null;
      selectedBatch: any | null;
      allocations: any[];
      totals: {
        totalDistributedCodes: number;
        sourceRemainingCodes: number;
        pendingPrintableCodes: number;
        printedCodes: number;
      };
    }>(`/qr/batches/${encodeURIComponent(batchId)}/allocation-map`);
  }

  // ==================== PRINT JOBS (MANUFACTURER) ====================
  async createPrintJob(payload: {
    batchId: string;
    printerId: string;
    quantity: number;
    rangeStart?: string;
    rangeEnd?: string;
    reprintOfJobId?: string;
    reprintReason?: string;
  }) {
    return this.request("/manufacturer/print-jobs", { method: "POST", body: JSON.stringify(payload) });
  }

  async listRegisteredPrinters(includeInactive = false) {
    const query = includeInactive ? "?includeInactive=true" : "";
    return this.request<any[]>(`/manufacturer/printers${query}`);
  }

  async createNetworkPrinter(payload: {
    name: string;
    vendor?: string;
    model?: string;
    licenseeId?: string;
    connectionType?: "NETWORK_DIRECT";
    commandLanguage?: "ZPL" | "TSPL" | "EPL" | "CPCL";
    ipAddress: string;
    port?: number;
    capabilitySummary?: Record<string, unknown>;
    calibrationProfile?: Record<string, unknown>;
    isActive?: boolean;
    isDefault?: boolean;
  }) {
    return this.request(`/manufacturer/printers`, { method: "POST", body: JSON.stringify(payload) });
  }

  async updateNetworkPrinter(
    printerId: string,
    payload: Partial<{
      name: string;
      vendor: string;
      model: string;
      commandLanguage: "ZPL" | "TSPL" | "EPL" | "CPCL";
      ipAddress: string;
      port: number;
      capabilitySummary: Record<string, unknown>;
      calibrationProfile: Record<string, unknown>;
      isActive: boolean;
      isDefault: boolean;
    }>
  ) {
    return this.request(`/manufacturer/printers/${encodeURIComponent(printerId)}`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    });
  }

  async testRegisteredPrinter(printerId: string) {
    return this.request(`/manufacturer/printers/${encodeURIComponent(printerId)}/test`, {
      method: "POST",
    });
  }

  async listPrintJobs(options?: { batchId?: string; limit?: number }) {
    const params = new URLSearchParams();
    if (options?.batchId) params.append("batchId", options.batchId);
    if (options?.limit) params.append("limit", String(options.limit));
    const query = params.toString() ? `?${params.toString()}` : "";
    return this.request<any[]>(`/manufacturer/print-jobs${query}`);
  }

  async getPrintJobStatus(jobId: string) {
    return this.request<any>(`/manufacturer/print-jobs/${encodeURIComponent(jobId)}`);
  }

  async requestDirectPrintTokens(jobId: string, printLockToken: string, count = 1) {
    return this.request<{
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
  }

  async resolveDirectPrintToken(jobId: string, payload: { printLockToken: string; renderToken: string }) {
    return this.request<{
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
  }

  async confirmDirectPrintItem(
    jobId: string,
    payload: {
      printLockToken: string;
      printItemId: string;
      agentMetadata?: any;
    }
  ) {
    return this.request<{
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
  }

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
    return this.request<{
      printJobId: string;
      printSessionId?: string;
      incidentId?: string;
      frozenCount?: number;
      reason: string;
    }>(`/manufacturer/print-jobs/${encodeURIComponent(jobId)}/direct-print/fail`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
  }

  async confirmPrintJob(jobId: string, printLockToken: string) {
    return this.request(`/manufacturer/print-jobs/${encodeURIComponent(jobId)}/confirm`, {
      method: "POST",
      body: JSON.stringify({ printLockToken }),
    });
  }

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
    return this.request<{
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
  }

  async getPrinterConnectionStatus() {
    return this.request<{
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
  }

  async getLocalPrintAgentStatus() {
    const base = String(import.meta.env.VITE_PRINT_AGENT_URL || "http://127.0.0.1:17866")
      .trim()
      .replace(/\/+$/, "");
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), 2500);
    try {
      const resp = await fetch(`${base}/status`, {
        method: "GET",
        cache: "no-store",
        mode: "cors",
        signal: controller.signal,
      });
      if (!resp.ok) {
        return { success: false, error: `Local print agent status failed: HTTP ${resp.status}` };
      }
      const payload = await resp.json().catch(() => ({}));
      const data = payload && typeof payload === "object" ? payload : {};
      const printers = Array.isArray((data as any).printers)
        ? (data as any).printers
        : Array.isArray((data as any).devices)
          ? (data as any).devices
          : [];
      const selectedPrinterId =
        String((data as any).selectedPrinterId || (data as any).printerId || "").trim() || null;
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
      return {
        success: false,
        error: aborted
          ? "Local print agent status timed out"
          : "Local print agent is unavailable",
      };
    } finally {
      window.clearTimeout(timeout);
    }
  }

  async getLocalPrinters() {
    const base = String(import.meta.env.VITE_PRINT_AGENT_URL || "http://127.0.0.1:17866")
      .trim()
      .replace(/\/+$/, "");
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), 3000);
    try {
      const resp = await fetch(`${base}/printers`, {
        method: "GET",
        cache: "no-store",
        mode: "cors",
        signal: controller.signal,
      });
      if (resp.ok) {
        const payload = await resp.json().catch(() => ({}));
        const rows = Array.isArray((payload as any)?.printers)
          ? (payload as any).printers
          : Array.isArray(payload)
            ? payload
            : [];
        return { success: true, data: { printers: rows } };
      }

      if (resp.status !== 404) {
        return { success: false, error: `Local printer discovery failed: HTTP ${resp.status}` };
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
  }

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
        const resp = await fetch(`${base}${path}`, {
          method: "POST",
          mode: "cors",
          headers: { "Content-Type": "application/json" },
          body,
          signal: controller.signal,
        });
        if (resp.ok) {
          const payload = await resp.json().catch(() => ({}));
          return { success: true, data: payload };
        }
        if (resp.status !== 404) {
          const payload = await resp.json().catch(() => ({}));
          return { success: false, error: String((payload as any)?.error || `Printer switch failed: HTTP ${resp.status}`) };
        }
      }
      return { success: false, error: "Local print agent does not expose printer switching endpoint" };
    } catch (error: any) {
      const aborted = error?.name === "AbortError";
      return { success: false, error: aborted ? "Local printer switch timed out" : "Local print agent is unavailable" };
    } finally {
      window.clearTimeout(timeout);
    }
  }

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
        const resp = await fetch(`${base}${path}`, {
          method: "POST",
          mode: "cors",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(normalizedPayload),
          signal: controller.signal,
        });
        if (resp.ok) {
          const body = await resp.json().catch(() => ({}));
          return { success: true, data: body };
        }
        if (resp.status !== 404) {
          const body = await resp.json().catch(() => ({}));
          return { success: false, error: String((body as any)?.error || `Calibration failed: HTTP ${resp.status}`) };
        }
      }
      return { success: false, error: "Local print agent does not expose calibration endpoint" };
    } catch (error: any) {
      const aborted = error?.name === "AbortError";
      return { success: false, error: aborted ? "Local calibration request timed out" : "Local print agent is unavailable" };
    } finally {
      window.clearTimeout(timeout);
    }
  }

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
      const resp = await fetch(`${base}/print`, {
        method: "POST",
        mode: "cors",
        headers: {
          "Content-Type": "application/json",
        },
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
      const body = await resp.json().catch(() => ({}));
      if (!resp.ok || body?.success === false) {
        return {
          success: false,
          error:
            String(body?.error || "").trim() ||
            `Local print failed: HTTP ${resp.status}`,
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
      return {
        success: false,
        error: aborted
          ? "Local print request timed out"
          : "Local print agent is unavailable",
      };
    } finally {
      window.clearTimeout(timeout);
    }
  }

  // ==================== MANUFACTURERS ====================
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
    return this.request<any[]>(`/manufacturers${query}`);
  }

  async deactivateManufacturer(id: string) {
    return this.request(`/manufacturers/${id}/deactivate`, { method: "PATCH" });
  }

  async restoreManufacturer(id: string) {
    return this.request(`/manufacturers/${id}/restore`, { method: "PATCH" });
  }

  async hardDeleteManufacturer(id: string) {
    return this.request(`/manufacturers/${id}`, { method: "DELETE" });
  }

  // ==================== USERS ====================
  async createUser(payload: {
    email: string;
    password: string;
    name: string;
    role: "LICENSEE_ADMIN" | "MANUFACTURER";
    licenseeId: string;
    location?: string;
    website?: string;
  }) {
    return this.request("/users", { method: "POST", body: JSON.stringify(payload) });
  }

  async getUsers(options?: { licenseeId?: string; role?: string }) {
    const params = new URLSearchParams();
    if (options?.licenseeId) params.append("licenseeId", options.licenseeId);
    if (options?.role) params.append("role", options.role);

    const query = params.toString() ? `?${params.toString()}` : "";
    return this.request<any[]>(`/users${query}`);
  }

  async updateUser(
    id: string,
    payload: Partial<{
      email: string;
      name: string;
      password: string;
      isActive: boolean;
      licenseeId: string;
      location: string;
      website: string;
    }>
  ) {
    return this.request(`/users/${id}`, { method: "PATCH", body: JSON.stringify(payload) });
  }

  async deleteUser(id: string, hard?: boolean) {
    const query = hard ? `?hard=true` : "";
    return this.request(`/users/${id}${query}`, { method: "DELETE" });
  }

  // ==================== AUDIT ====================
  async getAuditLogs(opts?: { entityType?: string; entityId?: string; licenseeId?: string; limit?: number; offset?: number }) {
    const params = new URLSearchParams();
    if (opts?.entityType) params.append("entityType", opts.entityType);
    if (opts?.entityId) params.append("entityId", opts.entityId);
    if (opts?.licenseeId) params.append("licenseeId", opts.licenseeId);
    if (opts?.limit) params.append("limit", String(opts.limit));
    if (opts?.offset) params.append("offset", String(opts.offset));
    return this.request(`/audit/logs?${params.toString()}`);
  }

  async getFraudReports(opts?: {
    status?: "ALL" | "OPEN" | "REVIEWED" | "RESOLVED" | "DISMISSED";
    licenseeId?: string;
    limit?: number;
    offset?: number;
  }) {
    const params = new URLSearchParams();
    if (opts?.status) params.append("status", opts.status);
    if (opts?.licenseeId) params.append("licenseeId", opts.licenseeId);
    if (opts?.limit != null) params.append("limit", String(opts.limit));
    if (opts?.offset != null) params.append("offset", String(opts.offset));
    return this.request(`/audit/fraud-reports${params.toString() ? `?${params.toString()}` : ""}`);
  }

  async respondToFraudReport(
    reportId: string,
    payload: {
      status: "REVIEWED" | "RESOLVED" | "DISMISSED";
      message?: string;
      notifyCustomer?: boolean;
    }
  ) {
    return this.request(`/audit/fraud-reports/${encodeURIComponent(reportId)}/respond`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
  }

  streamAuditLogs(onMessage: (log: any) => void, onError?: () => void) {
    const token = this.getToken();
    const query = token ? `?token=${encodeURIComponent(token)}` : "";
    const url = `${BASE_URL}/audit/stream${query}`;

    let es: EventSource;
    try {
      es = new EventSource(url, { withCredentials: true });
    } catch {
      es = new EventSource(url);
    }

    es.addEventListener("audit", (e: MessageEvent) => {
      try {
        onMessage(JSON.parse(e.data));
      } catch {
        // Ignore malformed events.
      }
    });

    es.onerror = () => {
      onError?.();
      es.close();
    };

    return () => es.close();
  }

  streamNotifications(
    onSnapshot: (payload: { notifications: any[]; unread: number; total: number; reason?: string }) => void,
    onError?: () => void,
    onOpen?: () => void,
    options?: { limit?: number }
  ) {
    const token = this.getToken();
    const params = new URLSearchParams();
    params.set("limit", String(options?.limit ?? 8));
    if (token) params.set("token", token);
    const query = params.toString() ? `?${params.toString()}` : "";
    const url = `${BASE_URL}/events/notifications${query}`;

    let es: EventSource;
    try {
      es = new EventSource(url, { withCredentials: true });
    } catch {
      es = new EventSource(url);
    }

    es.addEventListener("notifications", (e: MessageEvent) => {
      try {
        const payload = JSON.parse(e.data || "{}");
        const notifications = Array.isArray(payload.notifications) ? payload.notifications : [];
        const unread = Number(payload.unread || 0);
        const total = Number(payload.total || notifications.length);
        onSnapshot({
          notifications,
          unread,
          total,
          reason: typeof payload.reason === "string" ? payload.reason : undefined,
        });
      } catch {
        // ignore malformed snapshots
      }
    });

    es.onerror = () => {
      onError?.();
    };
    es.onopen = () => {
      onOpen?.();
    };

    return () => es.close();
  }

  streamPrinterConnectionStatus(
    onSnapshot: (payload: {
      reason?: string;
      serverTime?: string;
      status: {
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
      };
    }) => void,
    onError?: () => void,
    onOpen?: () => void
  ) {
    const token = this.getToken();
    const params = new URLSearchParams();
    if (token) params.set("token", token);
    const query = params.toString() ? `?${params.toString()}` : "";
    const url = `${BASE_URL}/manufacturer/printer-agent/events${query}`;

    let es: EventSource;
    try {
      es = new EventSource(url, { withCredentials: true });
    } catch {
      es = new EventSource(url);
    }

    es.addEventListener("printer_status", (e: MessageEvent) => {
      try {
        const payload = JSON.parse(e.data || "{}");
        if (!payload || typeof payload !== "object" || !payload.status || typeof payload.status !== "object") return;
        onSnapshot({
          reason: typeof payload.reason === "string" ? payload.reason : undefined,
          serverTime: typeof payload.serverTime === "string" ? payload.serverTime : undefined,
          status: payload.status,
        });
      } catch {
        // ignore malformed snapshots
      }
    });

    es.onerror = () => {
      onError?.();
    };
    es.onopen = () => {
      onOpen?.();
    };

    return () => es.close();
  }

  // product batches removed

  // ==================== QR REQUESTS ====================
  async createQrAllocationRequest(payload: {
    quantity: number;
    batchName: string;
    note?: string;
    licenseeId?: string;
  }) {
    return this.request("/qr/requests", { method: "POST", body: JSON.stringify(payload) });
  }

  async getQrAllocationRequests(options?: { licenseeId?: string; status?: string }) {
    const params = new URLSearchParams();
    if (options?.licenseeId) params.append("licenseeId", options.licenseeId);
    if (options?.status) params.append("status", options.status);
    const query = params.toString() ? `?${params.toString()}` : "";
    return this.request<any[]>(`/qr/requests${query}`);
  }

  async approveQrAllocationRequest(id: string, payload?: { decisionNote?: string }) {
    return this.request(`/qr/requests/${id}/approve`, { method: "POST", body: JSON.stringify(payload || {}) });
  }

  async rejectQrAllocationRequest(id: string, payload?: { decisionNote?: string }) {
    return this.request(`/qr/requests/${id}/reject`, { method: "POST", body: JSON.stringify(payload || {}) });
  }

  // ==================== ACCOUNT ====================
  async updateMyProfile(payload: { name?: string; email?: string }) {
    return this.request("/account/profile", { method: "PATCH", body: JSON.stringify(payload) });
  }

  async changeMyPassword(payload: { currentPassword: string; newPassword: string }) {
    return this.request("/account/password", { method: "PATCH", body: JSON.stringify(payload) });
  }

  async exportAuditLogsCsv() {
    const headers: Record<string, string> = {};
    if (this.token) headers["Authorization"] = `Bearer ${this.token}`;

    const resp = await fetch(`${BASE_URL}/audit/logs/export`, { headers, credentials: "include" });
    if (!resp.ok) throw new Error("Export failed");
    return resp.blob();
  }

  // ==================== PUBLIC VERIFY ====================
  // Public endpoint, no auth required. Still works if token exists.
  async verifyQRCode(
    code: string,
    opts?: { device?: string; lat?: number; lon?: number; acc?: number; customerToken?: string; transferToken?: string }
  ) {
    const c = String(code || "").trim();
    const params = new URLSearchParams();
    if (opts?.device) params.append("device", opts.device);
    if (opts?.lat != null) params.append("lat", String(opts.lat));
    if (opts?.lon != null) params.append("lon", String(opts.lon));
    if (opts?.acc != null) params.append("acc", String(opts.acc));
    if (opts?.transferToken) params.append("transfer", opts.transferToken);
    const query = params.toString() ? `?${params.toString()}` : "";
    const headers = opts?.customerToken ? { Authorization: `Bearer ${opts.customerToken}` } : undefined;
    return this.request(`/verify/${encodeURIComponent(c)}${query}`, { method: "GET", headers });
  }

  async reportFraud(payload: {
    code: string;
    reason: string;
    notes?: string;
    contactEmail?: string;
    observedStatus?: string;
    observedOutcome?: string;
    pageUrl?: string;
  }) {
    return this.request(`/fraud-report`, { method: "POST", body: JSON.stringify(payload) });
  }

  async submitProductFeedback(payload: {
    code: string;
    rating: number;
    satisfaction: "very_satisfied" | "satisfied" | "neutral" | "disappointed" | "very_disappointed";
    notes?: string;
    observedStatus?: string;
    observedOutcome?: string;
    pageUrl?: string;
  }) {
    return this.request(`/verify/feedback`, { method: "POST", body: JSON.stringify(payload) });
  }

  async scanToken(
    token: string,
    opts?: { device?: string; lat?: number; lon?: number; acc?: number; customerToken?: string }
  ) {
    const params = new URLSearchParams();
    params.append("t", token);
    if (opts?.device) params.append("device", opts.device);
    if (opts?.lat != null) params.append("lat", String(opts.lat));
    if (opts?.lon != null) params.append("lon", String(opts.lon));
    if (opts?.acc != null) params.append("acc", String(opts.acc));
    const query = params.toString() ? `?${params.toString()}` : "";
    const headers = opts?.customerToken ? { Authorization: `Bearer ${opts.customerToken}` } : undefined;
    return this.request(`/scan${query}`, { method: "GET", headers });
  }

  async requestVerifyEmailOtp(email: string) {
    return this.request<{
      challengeToken: string;
      expiresAt: string;
      maskedEmail: string;
    }>(`/verify/auth/email-otp/request`, {
      method: "POST",
      body: JSON.stringify({ email }),
    });
  }

  async verifyEmailOtp(challengeToken: string, otp: string) {
    return this.request<{
      token: string;
      customer: {
        userId: string;
        email: string;
        maskedEmail: string;
      };
    }>(`/verify/auth/email-otp/verify`, {
      method: "POST",
      body: JSON.stringify({ challengeToken, otp }),
    });
  }

  async claimVerifiedProduct(code: string, customerToken?: string) {
    const headers = customerToken ? { Authorization: `Bearer ${customerToken}` } : undefined;
    return this.request<{
      claimResult: string;
      message?: string;
      conflict?: boolean;
      classification?: string;
      reasons?: string[];
      warningMessage?: string;
      claimTimestamp?: string | null;
      ownershipStatus?: {
        isClaimed: boolean;
        claimedAt: string | null;
        isOwnedByRequester: boolean;
        isClaimedByAnother: boolean;
        canClaim: boolean;
      };
    }>(`/verify/${encodeURIComponent(code)}/claim`, {
      method: "POST",
      headers,
    });
  }

  async linkDeviceClaimToUser(code: string, customerToken: string) {
    return this.request<{
      linkResult: string;
      message?: string;
      ownershipStatus?: {
        isClaimed: boolean;
        claimedAt: string | null;
        isOwnedByRequester: boolean;
        isClaimedByAnother: boolean;
        canClaim: boolean;
      };
    }>(`/verify/${encodeURIComponent(code)}/link-claim`, {
      method: "POST",
      headers: { Authorization: `Bearer ${customerToken}` },
    });
  }

  async createOwnershipTransfer(code: string, payload: { recipientEmail?: string }, customerToken: string) {
    return this.request<{
      message?: string;
      transferLink: string;
      transferToken: string;
      ownershipStatus?: any;
      ownershipTransfer?: any;
    }>(`/verify/${encodeURIComponent(code)}/transfer`, {
      method: "POST",
      headers: { Authorization: `Bearer ${customerToken}` },
      body: JSON.stringify(payload),
    });
  }

  async cancelOwnershipTransfer(code: string, payload: { transferId?: string }, customerToken: string) {
    return this.request<{
      message?: string;
      ownershipTransfer?: any;
    }>(`/verify/${encodeURIComponent(code)}/transfer/cancel`, {
      method: "POST",
      headers: { Authorization: `Bearer ${customerToken}` },
      body: JSON.stringify(payload),
    });
  }

  async acceptOwnershipTransfer(payload: { token: string }, customerToken: string) {
    return this.request<{
      message?: string;
      code?: string;
      ownershipStatus?: any;
      ownershipTransfer?: any;
    }>(`/verify/transfer/accept`, {
      method: "POST",
      headers: { Authorization: `Bearer ${customerToken}` },
      body: JSON.stringify(payload),
    });
  }

  async submitFraudReport(formData: FormData, customerToken?: string) {
    const headers: Record<string, string> = {};
    if (customerToken) headers["Authorization"] = `Bearer ${customerToken}`;
    return this.request(`/fraud-report`, {
      method: "POST",
      body: formData,
      headers,
      skipJson: true,
      timeoutMs: 45_000,
    });
  }

  async getScanLogs(options?: {
    licenseeId?: string;
    batchId?: string;
    code?: string;
    status?: "DORMANT" | "ACTIVE" | "ALLOCATED" | "ACTIVATED" | "PRINTED" | "REDEEMED" | "BLOCKED" | "SCANNED";
    onlyFirstScan?: boolean;
    from?: string;
    to?: string;
    limit?: number;
    offset?: number;
  }) {
    const params = new URLSearchParams();
    if (options?.licenseeId) params.append("licenseeId", options.licenseeId);
    if (options?.batchId) params.append("batchId", options.batchId);
    if (options?.code) params.append("code", options.code);
    if (options?.status) params.append("status", options.status);
    if (options?.onlyFirstScan != null) params.append("onlyFirstScan", String(options.onlyFirstScan));
    if (options?.from) params.append("from", options.from);
    if (options?.to) params.append("to", options.to);
    if (options?.limit != null) params.append("limit", String(options.limit));
    if (options?.offset != null) params.append("offset", String(options.offset));
    const query = params.toString() ? `?${params.toString()}` : "";
    return this.request(`/admin/qr/scan-logs${query}`);
  }

  async getBatchSummary(options?: { licenseeId?: string; manufacturerId?: string }) {
    const params = new URLSearchParams();
    if (options?.licenseeId) params.append("licenseeId", options.licenseeId);
    if (options?.manufacturerId) params.append("manufacturerId", options.manufacturerId);
    const query = params.toString() ? `?${params.toString()}` : "";
    return this.request(`/admin/qr/batch-summary${query}`);
  }

  async getQrTrackingAnalytics(options?: {
    licenseeId?: string;
    batchQuery?: string;
    code?: string;
    status?: "DORMANT" | "ACTIVE" | "ALLOCATED" | "ACTIVATED" | "PRINTED" | "REDEEMED" | "BLOCKED" | "SCANNED";
    onlyFirstScan?: boolean;
    from?: string;
    to?: string;
    limit?: number;
    offset?: number;
  }) {
    const params = new URLSearchParams();
    if (options?.licenseeId) params.append("licenseeId", options.licenseeId);
    if (options?.batchQuery) params.append("batchQuery", options.batchQuery);
    if (options?.code) params.append("code", options.code);
    if (options?.status) params.append("status", options.status);
    if (options?.onlyFirstScan != null) params.append("onlyFirstScan", String(options.onlyFirstScan));
    if (options?.from) params.append("from", options.from);
    if (options?.to) params.append("to", options.to);
    if (options?.limit != null) params.append("limit", String(options.limit));
    if (options?.offset != null) params.append("offset", String(options.offset));
    const query = params.toString() ? `?${params.toString()}` : "";
    return this.request(`/admin/qr/analytics${query}`);
  }

  // ==================== TRACE / ANALYTICS / POLICY ====================
  async getTraceTimeline(options?: {
    licenseeId?: string;
    eventType?: string;
    batchId?: string;
    manufacturerId?: string;
    qrCodeId?: string;
    limit?: number;
    offset?: number;
  }) {
    const params = new URLSearchParams();
    if (options?.licenseeId) params.append("licenseeId", options.licenseeId);
    if (options?.eventType) params.append("eventType", options.eventType);
    if (options?.batchId) params.append("batchId", options.batchId);
    if (options?.manufacturerId) params.append("manufacturerId", options.manufacturerId);
    if (options?.qrCodeId) params.append("qrCodeId", options.qrCodeId);
    if (options?.limit != null) params.append("limit", String(options.limit));
    if (options?.offset != null) params.append("offset", String(options.offset));
    const query = params.toString() ? `?${params.toString()}` : "";
    return this.request(`/trace/timeline${query}`);
  }

  async getBatchSlaAnalytics(options?: { licenseeId?: string; limit?: number; stuckBatchHours?: number }) {
    const params = new URLSearchParams();
    if (options?.licenseeId) params.append("licenseeId", options.licenseeId);
    if (options?.limit != null) params.append("limit", String(options.limit));
    if (options?.stuckBatchHours != null) params.append("stuckBatchHours", String(options.stuckBatchHours));
    const query = params.toString() ? `?${params.toString()}` : "";
    return this.request(`/analytics/batch-sla${query}`);
  }

  async getRiskScores(options?: { licenseeId?: string; lookbackHours?: number; limit?: number }) {
    const params = new URLSearchParams();
    if (options?.licenseeId) params.append("licenseeId", options.licenseeId);
    if (options?.lookbackHours != null) params.append("lookbackHours", String(options.lookbackHours));
    if (options?.limit != null) params.append("limit", String(options.limit));
    const query = params.toString() ? `?${params.toString()}` : "";
    return this.request(`/analytics/risk-scores${query}`);
  }

  async getPolicyConfig(licenseeId?: string) {
    const query = licenseeId ? `?licenseeId=${encodeURIComponent(licenseeId)}` : "";
    return this.request(`/policy/config${query}`);
  }

  async updatePolicyConfig(
    payload: Partial<{
      licenseeId: string;
      autoBlockEnabled: boolean;
      autoBlockBatchOnVelocity: boolean;
      multiScanThreshold: number;
      geoDriftThresholdKm: number;
      velocitySpikeThresholdPerMin: number;
      stuckBatchHours: number;
    }>
  ) {
    return this.request(`/policy/config`, { method: "PATCH", body: JSON.stringify(payload) });
  }

  async getPolicyAlerts(options?: {
    licenseeId?: string;
    alertType?: string;
    severity?: string;
    acknowledged?: boolean;
    limit?: number;
    offset?: number;
  }) {
    const params = new URLSearchParams();
    if (options?.licenseeId) params.append("licenseeId", options.licenseeId);
    if (options?.alertType) params.append("alertType", options.alertType);
    if (options?.severity) params.append("severity", options.severity);
    if (options?.acknowledged != null) params.append("acknowledged", String(options.acknowledged));
    if (options?.limit != null) params.append("limit", String(options.limit));
    if (options?.offset != null) params.append("offset", String(options.offset));
    const query = params.toString() ? `?${params.toString()}` : "";
    return this.request(`/policy/alerts${query}`);
  }

  async acknowledgePolicyAlert(id: string) {
    return this.request(`/policy/alerts/${encodeURIComponent(id)}/ack`, { method: "POST" });
  }

  async exportBatchAuditPackage(batchId: string) {
    const headers: Record<string, string> = {};
    if (this.token) headers["Authorization"] = `Bearer ${this.token}`;
    const resp = await fetch(`${BASE_URL}/audit/export/batches/${encodeURIComponent(batchId)}/package`, {
      headers,
      credentials: "include",
    });
    if (!resp.ok) throw new Error(`Export failed: HTTP ${resp.status}`);
    return resp.blob();
  }

  // ==================== INCIDENT RESPONSE ====================
  async submitIncidentReport(formData: FormData, captchaToken?: string) {
    const headers: Record<string, string> = {};
    if (captchaToken) headers["x-captcha-token"] = captchaToken;
    return this.request(`/incidents/report`, {
      method: "POST",
      body: formData,
      headers,
      skipJson: true,
      timeoutMs: 45_000,
    });
  }

  async getIncidents(options?: {
    status?: string;
    severity?: string;
    qr?: string;
    search?: string;
    dateFrom?: string;
    dateTo?: string;
    assignedTo?: string;
    licenseeId?: string;
    limit?: number;
    offset?: number;
  }) {
    const params = new URLSearchParams();
    if (options?.status) params.append("status", options.status);
    if (options?.severity) params.append("severity", options.severity);
    if (options?.qr) params.append("qr", options.qr);
    if (options?.search) params.append("search", options.search);
    if (options?.dateFrom) params.append("date_from", options.dateFrom);
    if (options?.dateTo) params.append("date_to", options.dateTo);
    if (options?.assignedTo) params.append("assigned_to", options.assignedTo);
    if (options?.licenseeId) params.append("licenseeId", options.licenseeId);
    if (options?.limit != null) params.append("limit", String(options.limit));
    if (options?.offset != null) params.append("offset", String(options.offset));
    const query = params.toString() ? `?${params.toString()}` : "";
    return this.request(`/incidents${query}`);
  }

  async getIncidentById(id: string) {
    return this.request(`/incidents/${encodeURIComponent(id)}`);
  }

  async patchIncident(
    id: string,
    payload: Partial<{
      status: string;
      assignedToUserId: string | null;
      internalNotes: string;
      tags: string[];
      severity: string;
      resolutionSummary: string;
      resolutionOutcome: "CONFIRMED_FRAUD" | "NOT_FRAUD" | "INCONCLUSIVE" | null;
    }>
  ) {
    return this.request(`/incidents/${encodeURIComponent(id)}`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    });
  }

  async addIncidentNote(id: string, note: string) {
    return this.request(`/incidents/${encodeURIComponent(id)}/events`, {
      method: "POST",
      body: JSON.stringify({ note }),
    });
  }

  async uploadIncidentEvidence(id: string, file: File) {
    const form = new FormData();
    form.append("file", file);
    return this.request(`/incidents/${encodeURIComponent(id)}/evidence`, {
      method: "POST",
      body: form,
      skipJson: true,
      timeoutMs: 45_000,
    });
  }

  async sendIncidentEmail(
    id: string,
    payload: { subject: string; message: string; senderMode?: "actor" | "system" }
  ) {
    const normalizeDelivery = <T extends ApiResponse<any>>(resp: T): T => {
      if (!resp.success) return resp;
      const delivered = (resp.data as any)?.delivered;
      if (typeof delivered === "boolean" && !delivered) {
        const reason = (resp.data as any)?.error || resp.error || "Email delivery failed";
        return {
          ...resp,
          success: false,
          error: String(reason),
        } as T;
      }
      return resp;
    };

    const primary = normalizeDelivery(
      await this.request(`/incidents/${encodeURIComponent(id)}/email`, {
        method: "POST",
        body: JSON.stringify(payload),
      })
    );

    if (primary.success) return primary;

    const errorText = String(primary.error || "").toLowerCase();
    const isEndpointMissing =
      errorText.includes("endpoint not found") ||
      errorText.includes("cannot post") ||
      errorText.includes("not found") ||
      errorText.includes("http 404");

    if (!isEndpointMissing) return primary;

    return normalizeDelivery(
      await this.request(`/incidents/${encodeURIComponent(id)}/notify-customer`, {
        method: "POST",
        body: JSON.stringify(payload),
      })
    );
  }

  async notifyIncidentCustomer(id: string, payload: { subject: string; message: string }) {
    const resp = await this.request(`/incidents/${encodeURIComponent(id)}/notify-customer`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
    if (!resp.success) return resp;
    const delivered = (resp.data as any)?.delivered;
    if (typeof delivered === "boolean" && !delivered) {
      return {
        ...resp,
        success: false,
        error: String((resp.data as any)?.error || resp.error || "Email delivery failed"),
      };
    }
    return resp;
  }

  async downloadIncidentEvidence(fileName: string) {
    const headers: Record<string, string> = {};
    if (this.token) headers["Authorization"] = `Bearer ${this.token}`;
    const resp = await fetch(`${BASE_URL}/incidents/evidence-files/${encodeURIComponent(fileName)}`, {
      headers,
      credentials: "include",
    });
    if (!resp.ok) throw new Error(`Download failed: HTTP ${resp.status}`);
    return resp.blob();
  }

  async requestIncidentPdfExport(id: string) {
    const headers: Record<string, string> = {};
    if (this.token) headers["Authorization"] = `Bearer ${this.token}`;
    const resp = await fetch(`${BASE_URL}/incidents/${encodeURIComponent(id)}/export-pdf`, {
      headers,
      credentials: "include",
    });
    if (!resp.ok) throw new Error(`Export failed: HTTP ${resp.status}`);
    return resp.blob();
  }

  // ==================== IR (PLATFORM SUPERADMIN) ====================
  async getIrIncidents(options?: {
    status?: string;
    severity?: string;
    priority?: string;
    licenseeId?: string;
    manufacturerId?: string;
    qr?: string;
    search?: string;
    dateFrom?: string;
    dateTo?: string;
    assignedTo?: string;
    limit?: number;
    offset?: number;
  }) {
    const params = new URLSearchParams();
    if (options?.status) params.append("status", options.status);
    if (options?.severity) params.append("severity", options.severity);
    if (options?.priority) params.append("priority", options.priority);
    if (options?.licenseeId) params.append("licenseeId", options.licenseeId);
    if (options?.manufacturerId) params.append("manufacturerId", options.manufacturerId);
    if (options?.qr) params.append("qr", options.qr);
    if (options?.search) params.append("search", options.search);
    if (options?.dateFrom) params.append("date_from", options.dateFrom);
    if (options?.dateTo) params.append("date_to", options.dateTo);
    if (options?.assignedTo) params.append("assigned_to", options.assignedTo);
    if (options?.limit != null) params.append("limit", String(options.limit));
    if (options?.offset != null) params.append("offset", String(options.offset));
    const query = params.toString() ? `?${params.toString()}` : "";
    return this.request(`/ir/incidents${query}`);
  }

  async createIrIncident(payload: {
    qrCodeValue: string;
    incidentType: "COUNTERFEIT_SUSPECTED" | "DUPLICATE_SCAN" | "TAMPERED_LABEL" | "WRONG_PRODUCT" | "OTHER";
    description: string;
    severity?: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
    priority?: "P1" | "P2" | "P3" | "P4";
    licenseeId?: string;
    tags?: string[];
  }) {
    return this.request(`/ir/incidents`, { method: "POST", body: JSON.stringify(payload) });
  }

  async getIrIncidentById(id: string) {
    return this.request(`/ir/incidents/${encodeURIComponent(id)}`);
  }

  async patchIrIncident(
    id: string,
    payload: Partial<{
      status: string;
      severity: string;
      priority: string;
      assignedToUserId: string | null;
      internalNotes: string | null;
      tags: string[];
      resolutionSummary: string | null;
      resolutionOutcome: "CONFIRMED_FRAUD" | "NOT_FRAUD" | "INCONCLUSIVE" | null;
    }>
  ) {
    return this.request(`/ir/incidents/${encodeURIComponent(id)}`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    });
  }

  async addIrIncidentNote(id: string, note: string) {
    return this.request(`/ir/incidents/${encodeURIComponent(id)}/events`, {
      method: "POST",
      body: JSON.stringify({ note }),
    });
  }

  async applyIrIncidentAction(
    id: string,
    payload: {
      action:
        | "FLAG_QR_UNDER_INVESTIGATION"
        | "UNFLAG_QR_UNDER_INVESTIGATION"
        | "SUSPEND_BATCH"
        | "REINSTATE_BATCH"
        | "SUSPEND_ORG"
        | "REINSTATE_ORG"
        | "SUSPEND_MANUFACTURER_USERS"
        | "REINSTATE_MANUFACTURER_USERS";
      reason: string;
      qrCodeId?: string;
      batchId?: string;
      licenseeId?: string;
      manufacturerUserIds?: string[];
    }
  ) {
    return this.request(`/ir/incidents/${encodeURIComponent(id)}/actions`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
  }

  async sendIrIncidentCommunication(
    id: string,
    payload: {
      recipient?: "reporter" | "org_admin";
      toAddress?: string;
      subject: string;
      message: string;
      template?: string;
      senderMode?: "actor" | "system";
    }
  ) {
    return this.request(`/ir/incidents/${encodeURIComponent(id)}/communications`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
  }

  async uploadIrIncidentAttachment(id: string, file: File) {
    const form = new FormData();
    form.append("file", file);
    return this.request(`/ir/incidents/${encodeURIComponent(id)}/attachments`, {
      method: "POST",
      body: form,
      skipJson: true,
      timeoutMs: 45_000,
    });
  }

  async getIrPolicies(options?: { licenseeId?: string; ruleType?: string; isActive?: boolean; limit?: number; offset?: number }) {
    const params = new URLSearchParams();
    if (options?.licenseeId) params.append("licenseeId", options.licenseeId);
    if (options?.ruleType) params.append("ruleType", options.ruleType);
    if (options?.isActive != null) params.append("isActive", String(options.isActive));
    if (options?.limit != null) params.append("limit", String(options.limit));
    if (options?.offset != null) params.append("offset", String(options.offset));
    const query = params.toString() ? `?${params.toString()}` : "";
    return this.request(`/ir/policies${query}`);
  }

  async createIrPolicy(payload: {
    name: string;
    description?: string;
    ruleType: "DISTINCT_DEVICES" | "MULTI_COUNTRY" | "BURST_SCANS" | "TOO_MANY_REPORTS";
    isActive?: boolean;
    threshold: number;
    windowMinutes: number;
    severity?: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
    autoCreateIncident?: boolean;
    incidentSeverity?: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
    incidentPriority?: "P1" | "P2" | "P3" | "P4";
    licenseeId?: string;
    manufacturerId?: string;
    actionConfig?: any;
  }) {
    return this.request(`/ir/policies`, { method: "POST", body: JSON.stringify(payload) });
  }

  async patchIrPolicy(id: string, payload: any) {
    return this.request(`/ir/policies/${encodeURIComponent(id)}`, { method: "PATCH", body: JSON.stringify(payload) });
  }

  async getIrAlerts(options?: {
    licenseeId?: string;
    alertType?: string;
    severity?: string;
    acknowledged?: boolean;
    policyRuleId?: string;
    qrCodeId?: string;
    batchId?: string;
    manufacturerId?: string;
    limit?: number;
    offset?: number;
  }) {
    const params = new URLSearchParams();
    if (options?.licenseeId) params.append("licenseeId", options.licenseeId);
    if (options?.alertType) params.append("alertType", options.alertType);
    if (options?.severity) params.append("severity", options.severity);
    if (options?.acknowledged != null) params.append("acknowledged", String(options.acknowledged));
    if (options?.policyRuleId) params.append("policyRuleId", options.policyRuleId);
    if (options?.qrCodeId) params.append("qrCodeId", options.qrCodeId);
    if (options?.batchId) params.append("batchId", options.batchId);
    if (options?.manufacturerId) params.append("manufacturerId", options.manufacturerId);
    if (options?.limit != null) params.append("limit", String(options.limit));
    if (options?.offset != null) params.append("offset", String(options.offset));
    const query = params.toString() ? `?${params.toString()}` : "";
    return this.request(`/ir/alerts${query}`);
  }

  async patchIrAlert(id: string, payload: { acknowledged?: boolean; incidentId?: string | null }) {
    return this.request(`/ir/alerts/${encodeURIComponent(id)}`, { method: "PATCH", body: JSON.stringify(payload) });
  }

  // ==================== NOTIFICATIONS ====================
  async getNotifications(options?: { unreadOnly?: boolean; limit?: number; offset?: number }) {
    const params = new URLSearchParams();
    if (options?.unreadOnly != null) params.append("unreadOnly", String(options.unreadOnly));
    if (options?.limit != null) params.append("limit", String(options.limit));
    if (options?.offset != null) params.append("offset", String(options.offset));
    const query = params.toString() ? `?${params.toString()}` : "";
    return this.request(`/notifications${query}`);
  }

  async markNotificationRead(id: string) {
    return this.request(`/notifications/${encodeURIComponent(id)}/read`, { method: "POST" });
  }

  async markAllNotificationsRead() {
    return this.request(`/notifications/read-all`, { method: "POST" });
  }

  // ==================== SUPPORT TICKETS ====================
  async getSupportTickets(options?: {
    status?: "OPEN" | "IN_PROGRESS" | "WAITING_CUSTOMER" | "RESOLVED" | "CLOSED";
    priority?: "P1" | "P2" | "P3" | "P4";
    licenseeId?: string;
    search?: string;
    limit?: number;
    offset?: number;
  }) {
    const params = new URLSearchParams();
    if (options?.status) params.append("status", options.status);
    if (options?.priority) params.append("priority", options.priority);
    if (options?.licenseeId) params.append("licenseeId", options.licenseeId);
    if (options?.search) params.append("search", options.search);
    if (options?.limit != null) params.append("limit", String(options.limit));
    if (options?.offset != null) params.append("offset", String(options.offset));
    const query = params.toString() ? `?${params.toString()}` : "";
    return this.request(`/support/tickets${query}`);
  }

  async getSupportTicket(id: string) {
    return this.request(`/support/tickets/${encodeURIComponent(id)}`);
  }

  async patchSupportTicket(
    id: string,
    payload: Partial<{
      status: "OPEN" | "IN_PROGRESS" | "WAITING_CUSTOMER" | "RESOLVED" | "CLOSED";
      assignedToUserId: string | null;
    }>
  ) {
    return this.request(`/support/tickets/${encodeURIComponent(id)}`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    });
  }

  async addSupportTicketMessage(id: string, payload: { message: string; isInternal?: boolean }) {
    return this.request(`/support/tickets/${encodeURIComponent(id)}/messages`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
  }

  async trackSupportTicket(reference: string, email?: string) {
    const query = email ? `?email=${encodeURIComponent(email)}` : "";
    return this.request(`/support/tickets/track/${encodeURIComponent(reference)}${query}`);
  }

  async createSupportIssueReport(formData: FormData) {
    return this.request(`/support/reports`, {
      method: "POST",
      body: formData,
      skipJson: true,
      timeoutMs: 45_000,
    });
  }

  async getSupportIssueReports(options?: { limit?: number; offset?: number; licenseeId?: string }) {
    const params = new URLSearchParams();
    if (options?.limit != null) params.append("limit", String(options.limit));
    if (options?.offset != null) params.append("offset", String(options.offset));
    if (options?.licenseeId) params.append("licenseeId", options.licenseeId);
    const query = params.toString() ? `?${params.toString()}` : "";
    return this.request(`/support/reports${query}`);
  }

  async respondToSupportIssueReport(
    reportId: string,
    payload: {
      message: string;
      status?: "OPEN" | "RESPONDED" | "CLOSED";
    }
  ) {
    return this.request(`/support/reports/${encodeURIComponent(reportId)}/respond`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
  }

  getSupportIssueScreenshotUrl(fileName: string) {
    return `${BASE_URL}/support/reports/files/${encodeURIComponent(fileName)}`;
  }

  // ==================== GOVERNANCE ====================
  async getGovernanceFeatureFlags(licenseeId?: string) {
    const query = licenseeId ? `?licenseeId=${encodeURIComponent(licenseeId)}` : "";
    return this.request(`/governance/feature-flags${query}`);
  }

  async upsertGovernanceFeatureFlag(payload: {
    licenseeId?: string;
    key: string;
    enabled: boolean;
    config?: any;
  }) {
    return this.request(`/governance/feature-flags`, { method: "POST", body: JSON.stringify(payload) });
  }

  async getEvidenceRetentionPolicy(licenseeId?: string) {
    const query = licenseeId ? `?licenseeId=${encodeURIComponent(licenseeId)}` : "";
    return this.request(`/governance/evidence-retention${query}`);
  }

  async patchEvidenceRetentionPolicy(payload: {
    licenseeId?: string;
    retentionDays?: number;
    purgeEnabled?: boolean;
    exportBeforePurge?: boolean;
    legalHoldTags?: string[];
  }) {
    return this.request(`/governance/evidence-retention`, { method: "PATCH", body: JSON.stringify(payload) });
  }

  async runEvidenceRetentionJob(payload: { licenseeId?: string; mode: "PREVIEW" | "APPLY" }) {
    return this.request(`/governance/evidence-retention/run`, { method: "POST", body: JSON.stringify(payload) });
  }

  async getComplianceReport(options?: { licenseeId?: string; from?: string; to?: string }) {
    const params = new URLSearchParams();
    if (options?.licenseeId) params.append("licenseeId", options.licenseeId);
    if (options?.from) params.append("from", options.from);
    if (options?.to) params.append("to", options.to);
    const query = params.toString() ? `?${params.toString()}` : "";
    return this.request(`/governance/compliance/report${query}`);
  }

  async runCompliancePack(payload?: { licenseeId?: string; from?: string; to?: string }) {
    return this.request(`/governance/compliance/pack/run`, {
      method: "POST",
      body: JSON.stringify(payload || {}),
    });
  }

  async getCompliancePackJobs(options?: { limit?: number; offset?: number }) {
    const params = new URLSearchParams();
    if (options?.limit != null) params.append("limit", String(options.limit));
    if (options?.offset != null) params.append("offset", String(options.offset));
    const query = params.toString() ? `?${params.toString()}` : "";
    return this.request(`/governance/compliance/pack/jobs${query}`);
  }

  async downloadCompliancePackJob(id: string) {
    const headers: Record<string, string> = {};
    if (this.token) headers["Authorization"] = `Bearer ${this.token}`;
    const resp = await fetch(`${BASE_URL}/governance/compliance/pack/jobs/${encodeURIComponent(id)}/download`, {
      headers,
      credentials: "include",
    });
    if (!resp.ok) throw new Error(`Download failed: HTTP ${resp.status}`);
    return resp.blob();
  }

  async exportIncidentEvidenceBundle(id: string) {
    const headers: Record<string, string> = {};
    if (this.token) headers["Authorization"] = `Bearer ${this.token}`;
    const resp = await fetch(`${BASE_URL}/audit/export/incidents/${encodeURIComponent(id)}/bundle`, {
      headers,
      credentials: "include",
    });
    if (!resp.ok) throw new Error(`Export failed: HTTP ${resp.status}`);
    return resp.blob();
  }

  // ==================== TELEMETRY ====================
  async captureRouteTransition(payload: {
    routeFrom?: string | null;
    routeTo: string;
    source?: string;
    transitionMs: number;
    verifyCodePresent?: boolean;
    verifyResult?: string | null;
    dropped?: boolean;
    deviceType?: string;
    networkType?: string;
    online?: boolean;
  }) {
    return this.request(`/telemetry/route-transition`, {
      method: "POST",
      body: JSON.stringify(payload),
      timeoutMs: 8000,
      suppressMutationEvent: true,
    });
  }

  async getRouteTransitionSummary(options?: { licenseeId?: string; from?: string; to?: string }) {
    const params = new URLSearchParams();
    if (options?.licenseeId) params.append("licenseeId", options.licenseeId);
    if (options?.from) params.append("from", options.from);
    if (options?.to) params.append("to", options.to);
    const query = params.toString() ? `?${params.toString()}` : "";
    return this.request(`/telemetry/route-transition/summary${query}`);
  }
}

const apiClient = new ApiClient();
export default apiClient;
export { apiClient };
