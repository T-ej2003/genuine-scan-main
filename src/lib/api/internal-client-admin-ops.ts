import { BASE_URL, type ApiClientCore, type ApiResponse } from "@/lib/api/internal-client-core";

export const createAdminOpsApi = (core: ApiClientCore) => ({
  async createUser(payload: {
    email: string;
    password: string;
    name: string;
    role: "LICENSEE_ADMIN" | "MANUFACTURER";
    licenseeId: string;
    location?: string;
    website?: string;
  }) {
    return core.request("/users", { method: "POST", body: JSON.stringify(payload) });
  },

  async getUsers(options?: { licenseeId?: string; role?: string }) {
    const params = new URLSearchParams();
    if (options?.licenseeId) params.append("licenseeId", options.licenseeId);
    if (options?.role) params.append("role", options.role);

    const query = params.toString() ? `?${params.toString()}` : "";
    return core.request<any[]>(`/users${query}`);
  },

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
    return core.request(`/users/${id}`, { method: "PATCH", body: JSON.stringify(payload) });
  },

  async deleteUser(id: string, hard?: boolean) {
    const query = hard ? `?hard=true` : "";
    return core.request(`/users/${id}${query}`, { method: "DELETE" });
  },

  async getAuditLogs(opts?: { entityType?: string; entityId?: string; licenseeId?: string; limit?: number; offset?: number }) {
    const params = new URLSearchParams();
    if (opts?.entityType) params.append("entityType", opts.entityType);
    if (opts?.entityId) params.append("entityId", opts.entityId);
    if (opts?.licenseeId) params.append("licenseeId", opts.licenseeId);
    if (opts?.limit) params.append("limit", String(opts.limit));
    if (opts?.offset) params.append("offset", String(opts.offset));
    return core.request(`/audit/logs?${params.toString()}`);
  },

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
    return core.request(`/audit/fraud-reports${params.toString() ? `?${params.toString()}` : ""}`);
  },

  async respondToFraudReport(
    reportId: string,
    payload: {
      status: "REVIEWED" | "RESOLVED" | "DISMISSED";
      message?: string;
      notifyCustomer?: boolean;
    }
  ) {
    return core.request(`/audit/fraud-reports/${encodeURIComponent(reportId)}/respond`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
  },

  streamAuditLogs(onMessage: (log: any) => void, onError?: () => void) {
    const url = `${BASE_URL}/audit/stream`;

    let eventSource: EventSource;
    try {
      eventSource = new EventSource(url, { withCredentials: true });
    } catch {
      eventSource = new EventSource(url);
    }

    eventSource.addEventListener("audit", (event: MessageEvent) => {
      try {
        onMessage(JSON.parse(event.data));
      } catch {
        // Ignore malformed events.
      }
    });

    eventSource.onerror = () => {
      onError?.();
      eventSource.close();
    };

    return () => eventSource.close();
  },

  streamNotifications(
    onEvent: (payload: { kind: "snapshot"; notifications: any[]; unread: number; total: number; reason?: string } | { kind: "version"; reason?: string }) => void,
    onError?: () => void,
    onOpen?: () => void,
    options?: { limit?: number }
  ) {
    const params = new URLSearchParams();
    params.set("limit", String(options?.limit ?? 8));
    const query = params.toString() ? `?${params.toString()}` : "";
    const url = `${BASE_URL}/events/notifications${query}`;

    let eventSource: EventSource;
    try {
      eventSource = new EventSource(url, { withCredentials: true });
    } catch {
      eventSource = new EventSource(url);
    }

    eventSource.addEventListener("realtime", (event: MessageEvent) => {
      try {
        const envelope = JSON.parse(event.data || "{}");
        if (envelope?.channel !== "notifications") return;
        const payload = envelope?.payload || {};
        if (envelope?.type === "snapshot") {
          const notifications = Array.isArray(payload.notifications) ? payload.notifications : [];
          const unread = Number(payload.unread || 0);
          const total = Number(payload.total || notifications.length);
          onEvent({
            kind: "snapshot",
            notifications,
            unread,
            total,
            reason: typeof payload.reason === "string" ? payload.reason : undefined,
          });
          return;
        }
        if (envelope?.type === "version.bump") {
          onEvent({
            kind: "version",
            reason: typeof payload.reason === "string" ? payload.reason : undefined,
          });
        }
      } catch {
        // ignore malformed events
      }
    });

    eventSource.onerror = () => {
      onError?.();
    };
    eventSource.onopen = () => {
      onOpen?.();
    };

    return () => eventSource.close();
  },

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
    const url = `${BASE_URL}/manufacturer/printer-agent/events`;

    let eventSource: EventSource;
    try {
      eventSource = new EventSource(url, { withCredentials: true });
    } catch {
      eventSource = new EventSource(url);
    }

    eventSource.addEventListener("realtime", (event: MessageEvent) => {
      try {
        const envelope = JSON.parse(event.data || "{}");
        if (envelope?.channel !== "printer" || envelope?.type !== "snapshot") return;
        const payload = envelope?.payload || {};
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

    eventSource.onerror = () => {
      onError?.();
    };
    eventSource.onopen = () => {
      onOpen?.();
    };

    return () => eventSource.close();
  },

  async updateMyProfile(payload: { name?: string; email?: string }) {
    return core.request("/account/profile", { method: "PATCH", body: JSON.stringify(payload) });
  },

  async changeMyPassword(payload: { currentPassword: string; newPassword: string }) {
    return core.request("/account/password", { method: "PATCH", body: JSON.stringify(payload) });
  },

  async exportAuditLogsCsv() {
    const headers: Record<string, string> = {};
    if (core.getToken()) headers["Authorization"] = `Bearer ${core.getToken()}`;

    const response = await fetch(`${BASE_URL}/audit/logs/export`, { headers, credentials: "include" });
    if (!response.ok) throw new Error("Export failed");
    return response.blob();
  },

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
    return core.request(`/trace/timeline${query}`);
  },

  async getBatchSlaAnalytics(options?: { licenseeId?: string; limit?: number; stuckBatchHours?: number }) {
    const params = new URLSearchParams();
    if (options?.licenseeId) params.append("licenseeId", options.licenseeId);
    if (options?.limit != null) params.append("limit", String(options.limit));
    if (options?.stuckBatchHours != null) params.append("stuckBatchHours", String(options.stuckBatchHours));
    const query = params.toString() ? `?${params.toString()}` : "";
    return core.request(`/analytics/batch-sla${query}`);
  },

  async getRiskScores(options?: { licenseeId?: string; lookbackHours?: number; limit?: number }) {
    const params = new URLSearchParams();
    if (options?.licenseeId) params.append("licenseeId", options.licenseeId);
    if (options?.lookbackHours != null) params.append("lookbackHours", String(options.lookbackHours));
    if (options?.limit != null) params.append("limit", String(options.limit));
    const query = params.toString() ? `?${params.toString()}` : "";
    return core.request(`/analytics/risk-scores${query}`);
  },

  async getPolicyConfig(licenseeId?: string) {
    const query = licenseeId ? `?licenseeId=${encodeURIComponent(licenseeId)}` : "";
    return core.request(`/policy/config${query}`);
  },

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
    return core.request(`/policy/config`, { method: "PATCH", body: JSON.stringify(payload) });
  },

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
    return core.request(`/policy/alerts${query}`);
  },

  async acknowledgePolicyAlert(id: string) {
    return core.request(`/policy/alerts/${encodeURIComponent(id)}/ack`, { method: "POST" });
  },

  async exportBatchAuditPackage(batchId: string) {
    const headers: Record<string, string> = {};
    if (core.getToken()) headers["Authorization"] = `Bearer ${core.getToken()}`;
    const response = await fetch(`${BASE_URL}/audit/export/batches/${encodeURIComponent(batchId)}/package`, {
      headers,
      credentials: "include",
    });
    if (!response.ok) throw new Error(`Export failed: HTTP ${response.status}`);
    return response.blob();
  },

  async getNotifications(options?: { unreadOnly?: boolean; limit?: number; offset?: number }) {
    const params = new URLSearchParams();
    if (options?.unreadOnly != null) params.append("unreadOnly", String(options.unreadOnly));
    if (options?.limit != null) params.append("limit", String(options.limit));
    if (options?.offset != null) params.append("offset", String(options.offset));
    const query = params.toString() ? `?${params.toString()}` : "";
    return core.request(`/notifications${query}`);
  },

  async markNotificationRead(id: string) {
    return core.request(`/notifications/${encodeURIComponent(id)}/read`, { method: "POST" });
  },

  async markAllNotificationsRead() {
    return core.request(`/notifications/read-all`, { method: "POST" });
  },

  async getGovernanceFeatureFlags(licenseeId?: string) {
    const query = licenseeId ? `?licenseeId=${encodeURIComponent(licenseeId)}` : "";
    return core.request(`/governance/feature-flags${query}`);
  },

  async upsertGovernanceFeatureFlag(payload: {
    licenseeId?: string;
    key: string;
    enabled: boolean;
    config?: any;
  }) {
    return core.request(`/governance/feature-flags`, { method: "POST", body: JSON.stringify(payload) });
  },

  async getEvidenceRetentionPolicy(licenseeId?: string) {
    const query = licenseeId ? `?licenseeId=${encodeURIComponent(licenseeId)}` : "";
    return core.request(`/governance/evidence-retention${query}`);
  },

  async patchEvidenceRetentionPolicy(payload: {
    licenseeId?: string;
    retentionDays?: number;
    purgeEnabled?: boolean;
    exportBeforePurge?: boolean;
    legalHoldTags?: string[];
  }) {
    return core.request(`/governance/evidence-retention`, { method: "PATCH", body: JSON.stringify(payload) });
  },

  async runEvidenceRetentionJob(payload: { licenseeId?: string; mode: "PREVIEW" | "APPLY" }) {
    return core.request(`/governance/evidence-retention/run`, { method: "POST", body: JSON.stringify(payload) });
  },

  async getComplianceReport(options?: { licenseeId?: string; from?: string; to?: string }) {
    const params = new URLSearchParams();
    if (options?.licenseeId) params.append("licenseeId", options.licenseeId);
    if (options?.from) params.append("from", options.from);
    if (options?.to) params.append("to", options.to);
    const query = params.toString() ? `?${params.toString()}` : "";
    return core.request(`/governance/compliance/report${query}`);
  },

  async runCompliancePack(payload?: { licenseeId?: string; from?: string; to?: string }) {
    return core.request(`/governance/compliance/pack/run`, {
      method: "POST",
      body: JSON.stringify(payload || {}),
    });
  },

  async getCompliancePackJobs(options?: { limit?: number; offset?: number }) {
    const params = new URLSearchParams();
    if (options?.limit != null) params.append("limit", String(options.limit));
    if (options?.offset != null) params.append("offset", String(options.offset));
    const query = params.toString() ? `?${params.toString()}` : "";
    return core.request(`/governance/compliance/pack/jobs${query}`);
  },

  async downloadCompliancePackJob(id: string) {
    const headers: Record<string, string> = {};
    if (core.getToken()) headers["Authorization"] = `Bearer ${core.getToken()}`;
    const response = await fetch(`${BASE_URL}/governance/compliance/pack/jobs/${encodeURIComponent(id)}/download`, {
      headers,
      credentials: "include",
    });
    if (!response.ok) throw new Error(`Download failed: HTTP ${response.status}`);
    return response.blob();
  },

  async exportIncidentEvidenceBundle(id: string) {
    const headers: Record<string, string> = {};
    if (core.getToken()) headers["Authorization"] = `Bearer ${core.getToken()}`;
    const response = await fetch(`${BASE_URL}/audit/export/incidents/${encodeURIComponent(id)}/bundle`, {
      headers,
      credentials: "include",
    });
    if (!response.ok) throw new Error(`Export failed: HTTP ${response.status}`);
    return response.blob();
  },

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
    return core.request(`/telemetry/route-transition`, {
      method: "POST",
      body: JSON.stringify(payload),
      timeoutMs: 8000,
      suppressMutationEvent: true,
    });
  },

  async getRouteTransitionSummary(options?: { licenseeId?: string; from?: string; to?: string }) {
    const params = new URLSearchParams();
    if (options?.licenseeId) params.append("licenseeId", options.licenseeId);
    if (options?.from) params.append("from", options.from);
    if (options?.to) params.append("to", options.to);
    const query = params.toString() ? `?${params.toString()}` : "";
    return core.request(`/telemetry/route-transition/summary${query}`);
  },
});

export type { ApiResponse };
