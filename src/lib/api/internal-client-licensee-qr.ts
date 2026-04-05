import { BASE_URL, type ApiClientCore } from "@/lib/api/internal-client-core";

export const createLicenseeQrApi = (core: ApiClientCore) => ({
  async getLicensees() {
    return core.request<any[]>("/licensees");
  },

  async getLicensee(id: string) {
    return core.request(`/licensees/${id}`);
  },

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
    return core.request("/licensees", { method: "POST", body: JSON.stringify(payload) });
  },

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
    return core.request(`/licensees/${id}`, { method: "PATCH", body: JSON.stringify(payload) });
  },

  async deleteLicensee(id: string) {
    return core.request(`/licensees/${id}`, { method: "DELETE" });
  },

  async resendLicenseeAdminInvite(licenseeId: string, email?: string) {
    return core.request(`/licensees/${encodeURIComponent(licenseeId)}/admin-invite/resend`, {
      method: "POST",
      body: JSON.stringify({ email }),
    });
  },

  async exportLicenseesCsv() {
    const headers: Record<string, string> = {};
    if (core.getToken()) headers["Authorization"] = `Bearer ${core.getToken()}`;

    const response = await fetch(`${BASE_URL}/licensees/export`, { headers, credentials: "include" });
    if (!response.ok) throw new Error(`Export failed: HTTP ${response.status}`);
    return response.blob();
  },

  async allocateQRRange(payload: { licenseeId: string; startNumber: number; endNumber: number }) {
    return core.request("/qr/ranges/allocate", { method: "POST", body: JSON.stringify(payload) });
  },

  async generateQRCodes(payload: { licenseeId: string; quantity: number }) {
    return core.request("/qr/generate", { method: "POST", body: JSON.stringify(payload) });
  },

  async allocateLicenseeQrRange(
    licenseeId: string,
    payload:
      | { startNumber: number; endNumber: number; receivedBatchName?: string }
      | { quantity: number; receivedBatchName?: string }
  ) {
    return core.request(`/admin/licensees/${licenseeId}/qr-allocate-range`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
  },

  async getQRCodes(options?: { licenseeId?: string; status?: string; limit?: number; offset?: number; q?: string }) {
    const params = new URLSearchParams();
    if (options?.licenseeId) params.append("licenseeId", options.licenseeId);
    if (options?.status) params.append("status", options.status);
    if (options?.limit != null) params.append("limit", String(options.limit));
    if (options?.offset != null) params.append("offset", String(options.offset));
    if (options?.q) params.append("q", options.q);

    const query = params.toString() ? `?${params.toString()}` : "";
    return core.request(`/qr/codes${query}`);
  },

  async getQRStats(licenseeId?: string) {
    const query = licenseeId ? `?licenseeId=${encodeURIComponent(licenseeId)}` : "";
    return core.request(`/qr/stats${query}`);
  },

  async getDashboardStats(licenseeId?: string) {
    const query = licenseeId ? `?licenseeId=${encodeURIComponent(licenseeId)}` : "";
    return core.request(`/dashboard/stats${query}`);
  },

  async deleteQRCodes(payload: { ids?: string[]; codes?: string[] }) {
    return core.request<{ deleted: number }>("/qr/codes", { method: "DELETE", body: JSON.stringify(payload) });
  },

  async exportQRCodesCsv(options?: { licenseeId?: string; status?: string; q?: string }) {
    const params = new URLSearchParams();
    if (options?.licenseeId) params.append("licenseeId", options.licenseeId);
    if (options?.status && options.status !== "all") params.append("status", options.status);
    if (options?.q) params.append("q", options.q);

    const url = `/qr/codes/export${params.toString() ? `?${params.toString()}` : ""}`;
    const headers: Record<string, string> = {};
    if (core.getToken()) headers["Authorization"] = `Bearer ${core.getToken()}`;

    const response = await fetch(`${BASE_URL}${url}`, { headers, credentials: "include" });
    if (!response.ok) throw new Error(`Export failed: HTTP ${response.status}`);
    return response.blob();
  },

  async getBatches(options?: { licenseeId?: string }) {
    const params = new URLSearchParams();
    if (options?.licenseeId) params.append("licenseeId", options.licenseeId);
    const query = params.toString() ? `?${params.toString()}` : "";
    return core.request<any[]>(`/qr/batches${query}`);
  },

  async deleteBatch(batchId: string) {
    return core.request(`/qr/batches/${batchId}`, { method: "DELETE" });
  },

  async bulkDeleteBatches(payload: { ids: string[] }) {
    return core.request<{ deleted: number }>("/qr/batches/bulk-delete", { method: "POST", body: JSON.stringify(payload) });
  },

  async assignBatchManufacturer(payload: { batchId: string; manufacturerId: string; quantity: number; name?: string }) {
    return core.request(`/qr/batches/${payload.batchId}/assign-manufacturer`, {
      method: "POST",
      body: JSON.stringify({
        manufacturerId: payload.manufacturerId,
        quantity: payload.quantity,
        name: payload.name,
      }),
    });
  },

  async renameBatch(batchId: string, name: string) {
    return core.request(`/qr/batches/${encodeURIComponent(batchId)}/rename`, {
      method: "PATCH",
      body: JSON.stringify({ name }),
    });
  },

  async getBatchAllocationMap(batchId: string) {
    return core.request<{
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
  },

  async createQrAllocationRequest(payload: {
    quantity: number;
    batchName: string;
    note?: string;
    licenseeId?: string;
  }) {
    return core.request("/qr/requests", { method: "POST", body: JSON.stringify(payload) });
  },

  async getQrAllocationRequests(options?: { licenseeId?: string; status?: string }) {
    const params = new URLSearchParams();
    if (options?.licenseeId) params.append("licenseeId", options.licenseeId);
    if (options?.status) params.append("status", options.status);
    const query = params.toString() ? `?${params.toString()}` : "";
    return core.request<any[]>(`/qr/requests${query}`);
  },

  async approveQrAllocationRequest(id: string, payload?: { decisionNote?: string }) {
    return core.request(`/qr/requests/${id}/approve`, { method: "POST", body: JSON.stringify(payload || {}) });
  },

  async rejectQrAllocationRequest(id: string, payload?: { decisionNote?: string }) {
    return core.request(`/qr/requests/${id}/reject`, { method: "POST", body: JSON.stringify(payload || {}) });
  },

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
    return core.request(`/admin/qr/scan-logs${query}`);
  },

  async getBatchSummary(options?: { licenseeId?: string; manufacturerId?: string }) {
    const params = new URLSearchParams();
    if (options?.licenseeId) params.append("licenseeId", options.licenseeId);
    if (options?.manufacturerId) params.append("manufacturerId", options.manufacturerId);
    const query = params.toString() ? `?${params.toString()}` : "";
    return core.request(`/admin/qr/batch-summary${query}`);
  },

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
    return core.request(`/admin/qr/analytics${query}`);
  },
});
