const BASE_URL = import.meta.env.VITE_API_URL || "http://localhost:4000/api";

export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  error?: string;
  message?: string;
}

type RequestOptions = RequestInit & {
  skipJson?: boolean;
  timeoutMs?: number;
};

class ApiClient {
  private token: string | null = null;

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
  }

  private emitLogout() {
    window.dispatchEvent(new Event("auth:logout"));
  }

  private async request<T>(endpoint: string, options: RequestOptions = {}): Promise<ApiResponse<T>> {
    const headers: Record<string, string> = {
      ...(options.headers as Record<string, string>),
    };

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
        credentials: "include",
        signal: controller.signal,
      });

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
        return payload as ApiResponse<T>;
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
    licensee: { name: string; prefix: string; description?: string; isActive?: boolean };
    admin: { name: string; email: string; password: string };
  }) {
    return this.request("/licensees", { method: "POST", body: JSON.stringify(payload) });
  }

  async updateLicensee(id: string, payload: Partial<{ name: string; description: string; isActive: boolean }>) {
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
  async getBatches() {
    return this.request<any[]>("/qr/batches");
  }

  async deleteBatch(batchId: string) {
    return this.request(`/qr/batches/${batchId}`, { method: "DELETE" });
  }

  async bulkDeleteBatches(payload: { ids: string[] }) {
    return this.request<{ deleted: number }>("/qr/batches/bulk-delete", { method: "POST", body: JSON.stringify(payload) });
  }

  async adminAllocateBatch(payload: { licenseeId: string; manufacturerId: string; quantity: number; name?: string; requestNote?: string }) {
    return this.request("/qr/batches/admin-allocate", { method: "POST", body: JSON.stringify(payload) });
  }

  async assignBatchManufacturer(payload: { batchId: string; manufacturerId: string }) {
    return this.request(`/qr/batches/${payload.batchId}/assign-manufacturer`, {
      method: "POST",
      body: JSON.stringify({ manufacturerId: payload.manufacturerId }),
    });
  }

  async confirmBatchPrint(batchId: string) {
    return this.request(`/qr/batches/${batchId}/confirm-print`, { method: "POST" });
  }

  async markQRCodePrinted(code: string) {
    return this.request(`/qr/${encodeURIComponent(code)}/mark-printed`, { method: "POST" });
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

  async updateUser(id: string, payload: Partial<{ email: string; name: string; password: string; isActive: boolean; licenseeId: string }>) {
    return this.request(`/users/${id}`, { method: "PATCH", body: JSON.stringify(payload) });
  }

  async deleteUser(id: string, hard?: boolean) {
    const query = hard ? `?hard=true` : "";
    return this.request(`/users/${id}${query}`, { method: "DELETE" });
  }

  // ==================== AUDIT ====================
  async getAuditLogs(opts?: { entityType?: string; licenseeId?: string; limit?: number; offset?: number }) {
    const params = new URLSearchParams();
    if (opts?.entityType) params.append("entityType", opts.entityType);
    if (opts?.licenseeId) params.append("licenseeId", opts.licenseeId);
    if (opts?.limit) params.append("limit", String(opts.limit));
    if (opts?.offset) params.append("offset", String(opts.offset));
    return this.request(`/audit/logs?${params.toString()}`);
  }

  streamAuditLogs(onMessage: (log: any) => void) {
    const token = this.getToken();
    if (!token) throw new Error("No auth token");

    const url = `${BASE_URL}/audit/stream?token=${encodeURIComponent(token)}`;
    const es = new EventSource(url);

    es.addEventListener("audit", (e: MessageEvent) => onMessage(JSON.parse(e.data)));
    return () => es.close();
  }

  // ==================== PRODUCT BATCHES ====================
  async getProductBatches(options?: { licenseeId?: string }) {
    const params = new URLSearchParams();
    if (options?.licenseeId) params.append("licenseeId", options.licenseeId);
    const q = params.toString() ? `?${params.toString()}` : "";
    return this.request<any[]>(`/qr/product-batches${q}`);
  }

  async createProductBatch(payload: {
    parentBatchId: string;
    productName: string;
    productCode?: string;
    description?: string;
    startNumber: number;
    endNumber: number;
    serialStart: number;
    serialEnd: number;
    serialFormat?: string;
  }) {
    return this.request("/qr/product-batches", { method: "POST", body: JSON.stringify(payload) });
  }

  async assignProductBatchManufacturer(payload: { productBatchId: string; manufacturerId: string }) {
    return this.request(`/qr/product-batches/${payload.productBatchId}/assign-manufacturer`, {
      method: "POST",
      body: JSON.stringify({ manufacturerId: payload.manufacturerId }),
    });
  }

  async confirmProductBatchPrint(productBatchId: string) {
    return this.request(`/qr/product-batches/${productBatchId}/confirm-print`, { method: "POST" });
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
}

const apiClient = new ApiClient();
export default apiClient;
export { apiClient };

