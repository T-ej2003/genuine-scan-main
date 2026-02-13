import { emitMutationEvent } from "@/lib/mutation-events";

const BASE_URL = import.meta.env.VITE_API_URL || "/api";

export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  error?: string;
  message?: string;
}

export type DownloadProgress = {
  loadedBytes: number;
  totalBytes: number | null;
  percent: number | null;
  elapsedMs: number;
};

type RequestOptions = RequestInit & {
  skipJson?: boolean;
  timeoutMs?: number;
};

class ApiClient {
  private token: string | null = null;
  private readonly getCache = new Map<string, unknown>();

  constructor() {
    this.token = localStorage.getItem("auth_token");
  }

  setToken(token: string | null) {
    this.token = token;
    if (token) localStorage.setItem("auth_token", token);
    else localStorage.removeItem("auth_token");
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

  private async request<T>(endpoint: string, options: RequestOptions = {}): Promise<ApiResponse<T>> {
    const headers: Record<string, string> = {
      ...(options.headers as Record<string, string>),
    };

    const method = String(options.method || "GET").toUpperCase();
    const cacheKey = `${this.token || "anon"}:${endpoint}`;

    const hasBody = options.body !== undefined && options.body !== null;
    const isForm = typeof FormData !== "undefined" && options.body instanceof FormData;

    if (!options.skipJson && hasBody && !isForm) {
      headers["Content-Type"] = "application/json";
    }
    if (this.token) headers["Authorization"] = `Bearer ${this.token}`;

    const controller = new AbortController();
    const timeoutMs = options.timeoutMs ?? 20_000;
    const t = window.setTimeout(() => controller.abort(), timeoutMs);

    try {
      const res = await fetch(`${BASE_URL}${endpoint}`, {
        ...options,
        headers,
        cache: "no-store",
        credentials: "include",
        signal: controller.signal,
      });

      if (res.status === 304 && method === "GET") {
        const cached = this.getCache.get(cacheKey);
        if (cached !== undefined) return { success: true, data: cached as T };
        return { success: false, error: "Stale cache miss (HTTP 304)" };
      }

      if (res.status === 401) {
        this.logout();
        this.emitLogout();
      }

      const contentType = res.headers.get("content-type") || "";
      const isJson = contentType.includes("application/json");

      const payload: any = isJson ? await res.json().catch(() => null) : await res.text().catch(() => "");

      if (!res.ok) {
        const msg =
          (payload && typeof payload === "object" && (payload.error || payload.message)) ||
          (typeof payload === "string" && payload) ||
          `HTTP ${res.status}`;
        return { success: false, error: msg };
      }

      if (payload && typeof payload === "object" && "success" in payload) {
        if (method === "GET" && payload.success) {
          this.getCache.set(cacheKey, (payload as ApiResponse<T>).data as T);
        }
        if (method !== "GET" && method !== "HEAD" && payload.success) {
          emitMutationEvent({ endpoint, method });
        }
        return payload as ApiResponse<T>;
      }

      if (method === "GET") {
        this.getCache.set(cacheKey, payload as T);
      }

      if (method !== "GET" && method !== "HEAD") {
        emitMutationEvent({ endpoint, method });
      }
      return { success: true, data: payload as T };
    } catch (err: any) {
      const isAbort = err?.name === "AbortError";
      return { success: false, error: isAbort ? "Request timed out" : "Network error - is the backend running?" };
    } finally {
      window.clearTimeout(t);
    }
  }

  // ==================== AUTH ====================
  async login(email: string, password: string) {
    const res = await this.request<{ token: string; user: any }>("/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    });

    if (res.success && res.data?.token) this.setToken(res.data.token);
    return res;
  }

  async getCurrentUser() {
    return this.request("/auth/me");
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
    admin: { name: string; email: string; password: string };
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

  // ==================== PRINT JOBS (MANUFACTURER) ====================
  async createPrintJob(payload: { batchId: string; quantity: number; rangeStart?: string; rangeEnd?: string }) {
    return this.request("/manufacturer/print-jobs", { method: "POST", body: JSON.stringify(payload) });
  }

  async downloadPrintJobPack(jobId: string, printLockToken: string, onProgress?: (progress: DownloadProgress) => void) {
    const headers: Record<string, string> = {};
    if (this.token) headers["Authorization"] = `Bearer ${this.token}`;
    const query = `?token=${encodeURIComponent(printLockToken)}`;
    const resp = await fetch(`${BASE_URL}/manufacturer/print-jobs/${encodeURIComponent(jobId)}/pack${query}`, {
      headers,
      credentials: "include",
    });
    if (!resp.ok) throw new Error(`Download failed: HTTP ${resp.status}`);

    const totalHeader = resp.headers.get("content-length");
    const totalBytes = totalHeader ? Number(totalHeader) : NaN;
    const resolvedTotal = Number.isFinite(totalBytes) && totalBytes > 0 ? totalBytes : null;

    if (!resp.body || typeof resp.body.getReader !== "function") {
      const blob = await resp.blob();
      onProgress?.({
        loadedBytes: blob.size,
        totalBytes: resolvedTotal,
        percent: resolvedTotal ? 100 : null,
        elapsedMs: 0,
      });
      return blob;
    }

    const reader = resp.body.getReader();
    const chunks: Uint8Array[] = [];
    let loadedBytes = 0;
    const startedAt = typeof performance !== "undefined" ? performance.now() : Date.now();

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      chunks.push(value);
      loadedBytes += value.byteLength;

      const now = typeof performance !== "undefined" ? performance.now() : Date.now();
      const elapsedMs = Math.max(1, now - startedAt);
      onProgress?.({
        loadedBytes,
        totalBytes: resolvedTotal,
        percent: resolvedTotal ? Math.min(100, (loadedBytes / resolvedTotal) * 100) : null,
        elapsedMs,
      });
    }

    const now = typeof performance !== "undefined" ? performance.now() : Date.now();
    const elapsedMs = Math.max(1, now - startedAt);
    onProgress?.({
      loadedBytes,
      totalBytes: resolvedTotal,
      percent: resolvedTotal ? 100 : null,
      elapsedMs,
    });

    return new Blob(chunks, { type: resp.headers.get("content-type") || "application/zip" });
  }

  async confirmPrintJob(jobId: string, printLockToken: string) {
    return this.request(`/manufacturer/print-jobs/${encodeURIComponent(jobId)}/confirm`, {
      method: "POST",
      body: JSON.stringify({ printLockToken }),
    });
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

  streamAuditLogs(onMessage: (log: any) => void) {
    const token = this.getToken();
    if (!token) throw new Error("No auth token");

    const url = `${BASE_URL}/audit/stream?token=${encodeURIComponent(token)}`;
    const es = new EventSource(url);

    es.addEventListener("audit", (e: MessageEvent) => onMessage(JSON.parse(e.data)));
    return () => es.close();
  }

  // product batches removed

  // ==================== QR REQUESTS ====================
  async createQrAllocationRequest(payload: {
    quantity: number;
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
  async verifyQRCode(code: string, opts?: { device?: string; lat?: number; lon?: number; acc?: number }) {
    const c = String(code || "").trim();
    const params = new URLSearchParams();
    if (opts?.device) params.append("device", opts.device);
    if (opts?.lat != null) params.append("lat", String(opts.lat));
    if (opts?.lon != null) params.append("lon", String(opts.lon));
    if (opts?.acc != null) params.append("acc", String(opts.acc));
    const query = params.toString() ? `?${params.toString()}` : "";
    return this.request(`/verify/${encodeURIComponent(c)}${query}`, { method: "GET" });
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
    return this.request(`/verify/report-fraud`, { method: "POST", body: JSON.stringify(payload) });
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

  async scanToken(token: string, opts?: { device?: string; lat?: number; lon?: number; acc?: number }) {
    const params = new URLSearchParams();
    params.append("t", token);
    if (opts?.device) params.append("device", opts.device);
    if (opts?.lat != null) params.append("lat", String(opts.lat));
    if (opts?.lon != null) params.append("lon", String(opts.lon));
    if (opts?.acc != null) params.append("acc", String(opts.acc));
    const query = params.toString() ? `?${params.toString()}` : "";
    return this.request(`/scan${query}`, { method: "GET" });
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
}

const apiClient = new ApiClient();
export default apiClient;
export { apiClient };
