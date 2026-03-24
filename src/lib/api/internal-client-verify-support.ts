import { BASE_URL, type ApiClientCore, type ApiResponse } from "@/lib/api/internal-client-core";

export const createVerifySupportApi = (core: ApiClientCore) => ({
  async verifyQRCode(
    code: string,
    options?: { device?: string; lat?: number; lon?: number; acc?: number; customerToken?: string; transferToken?: string }
  ) {
    const normalizedCode = String(code || "").trim();
    const params = new URLSearchParams();
    if (options?.device) params.append("device", options.device);
    if (options?.lat != null) params.append("lat", String(options.lat));
    if (options?.lon != null) params.append("lon", String(options.lon));
    if (options?.acc != null) params.append("acc", String(options.acc));
    if (options?.transferToken) params.append("transfer", options.transferToken);
    const query = params.toString() ? `?${params.toString()}` : "";
    const headers = options?.customerToken ? { Authorization: `Bearer ${options.customerToken}` } : undefined;
    return core.request(`/verify/${encodeURIComponent(normalizedCode)}${query}`, { method: "GET", headers });
  },

  async reportFraud(payload: {
    code: string;
    reason: string;
    notes?: string;
    contactEmail?: string;
    observedStatus?: string;
    observedOutcome?: string;
    pageUrl?: string;
  }) {
    return core.request(`/fraud-report`, { method: "POST", body: JSON.stringify(payload) });
  },

  async submitProductFeedback(payload: {
    code: string;
    rating: number;
    satisfaction: "very_satisfied" | "satisfied" | "neutral" | "disappointed" | "very_disappointed";
    notes?: string;
    observedStatus?: string;
    observedOutcome?: string;
    pageUrl?: string;
  }) {
    return core.request(`/verify/feedback`, { method: "POST", body: JSON.stringify(payload) });
  },

  async scanToken(token: string, options?: { device?: string; lat?: number; lon?: number; acc?: number; customerToken?: string }) {
    const params = new URLSearchParams();
    params.append("t", token);
    if (options?.device) params.append("device", options.device);
    if (options?.lat != null) params.append("lat", String(options.lat));
    if (options?.lon != null) params.append("lon", String(options.lon));
    if (options?.acc != null) params.append("acc", String(options.acc));
    const query = params.toString() ? `?${params.toString()}` : "";
    const headers = options?.customerToken ? { Authorization: `Bearer ${options.customerToken}` } : undefined;
    return core.request(`/scan${query}`, { method: "GET", headers });
  },

  async requestVerifyEmailOtp(email: string) {
    return core.request<{
      challengeToken: string;
      expiresAt: string;
      maskedEmail: string;
    }>(`/verify/auth/email-otp/request`, {
      method: "POST",
      body: JSON.stringify({ email }),
    });
  },

  async verifyEmailOtp(challengeToken: string, otp: string) {
    return core.request<{
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
  },

  async claimVerifiedProduct(code: string, customerToken?: string) {
    const headers = customerToken ? { Authorization: `Bearer ${customerToken}` } : undefined;
    return core.request<{
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
  },

  async linkDeviceClaimToUser(code: string, customerToken: string) {
    return core.request<{
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
  },

  async createOwnershipTransfer(code: string, payload: { recipientEmail?: string }, customerToken: string) {
    return core.request<{
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
  },

  async cancelOwnershipTransfer(code: string, payload: { transferId?: string }, customerToken: string) {
    return core.request<{
      message?: string;
      ownershipTransfer?: any;
    }>(`/verify/${encodeURIComponent(code)}/transfer/cancel`, {
      method: "POST",
      headers: { Authorization: `Bearer ${customerToken}` },
      body: JSON.stringify(payload),
    });
  },

  async acceptOwnershipTransfer(payload: { token: string }, customerToken: string) {
    return core.request<{
      message?: string;
      code?: string;
      ownershipStatus?: any;
      ownershipTransfer?: any;
    }>(`/verify/transfer/accept`, {
      method: "POST",
      headers: { Authorization: `Bearer ${customerToken}` },
      body: JSON.stringify(payload),
    });
  },

  async submitFraudReport(formData: FormData, customerToken?: string) {
    const headers: Record<string, string> = {};
    if (customerToken) headers["Authorization"] = `Bearer ${customerToken}`;
    return core.request(`/fraud-report`, {
      method: "POST",
      body: formData,
      headers,
      skipJson: true,
      timeoutMs: 45_000,
    });
  },

  async submitIncidentReport(formData: FormData, captchaToken?: string) {
    const headers: Record<string, string> = {};
    if (captchaToken) headers["x-captcha-token"] = captchaToken;
    return core.request(`/incidents/report`, {
      method: "POST",
      body: formData,
      headers,
      skipJson: true,
      timeoutMs: 45_000,
    });
  },

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
    return core.request(`/incidents${query}`);
  },

  async getIncidentById(id: string) {
    return core.request(`/incidents/${encodeURIComponent(id)}`);
  },

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
    return core.request(`/incidents/${encodeURIComponent(id)}`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    });
  },

  async addIncidentNote(id: string, note: string) {
    return core.request(`/incidents/${encodeURIComponent(id)}/events`, {
      method: "POST",
      body: JSON.stringify({ note }),
    });
  },

  async uploadIncidentEvidence(id: string, file: File) {
    const form = new FormData();
    form.append("file", file);
    return core.request(`/incidents/${encodeURIComponent(id)}/evidence`, {
      method: "POST",
      body: form,
      skipJson: true,
      timeoutMs: 45_000,
    });
  },

  async sendIncidentEmail(
    id: string,
    payload: { subject: string; message: string; senderMode?: "actor" | "system" }
  ) {
    const normalizeDelivery = <T extends ApiResponse<any>>(response: T): T => {
      if (!response.success) return response;
      const delivered = (response.data as any)?.delivered;
      if (typeof delivered === "boolean" && !delivered) {
        const reason = (response.data as any)?.error || response.error || "Email delivery failed";
        return { ...response, success: false, error: String(reason) } as T;
      }
      return response;
    };

    const primary = normalizeDelivery(
      await core.request(`/incidents/${encodeURIComponent(id)}/email`, {
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
      await core.request(`/incidents/${encodeURIComponent(id)}/notify-customer`, {
        method: "POST",
        body: JSON.stringify(payload),
      })
    );
  },

  async notifyIncidentCustomer(id: string, payload: { subject: string; message: string }) {
    const response = await core.request(`/incidents/${encodeURIComponent(id)}/notify-customer`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
    if (!response.success) return response;
    const delivered = (response.data as any)?.delivered;
    if (typeof delivered === "boolean" && !delivered) {
      return {
        ...response,
        success: false,
        error: String((response.data as any)?.error || response.error || "Email delivery failed"),
      };
    }
    return response;
  },

  async downloadIncidentEvidence(fileName: string) {
    const headers: Record<string, string> = {};
    if (core.getToken()) headers["Authorization"] = `Bearer ${core.getToken()}`;
    const response = await fetch(`${BASE_URL}/incidents/evidence-files/${encodeURIComponent(fileName)}`, {
      headers,
      credentials: "include",
    });
    if (!response.ok) throw new Error(`Download failed: HTTP ${response.status}`);
    return response.blob();
  },

  async requestIncidentPdfExport(id: string) {
    const headers: Record<string, string> = {};
    if (core.getToken()) headers["Authorization"] = `Bearer ${core.getToken()}`;
    const response = await fetch(`${BASE_URL}/incidents/${encodeURIComponent(id)}/export-pdf`, {
      headers,
      credentials: "include",
    });
    if (!response.ok) throw new Error(`Export failed: HTTP ${response.status}`);
    return response.blob();
  },

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
    return core.request(`/ir/incidents${query}`);
  },

  async createIrIncident(payload: {
    qrCodeValue: string;
    incidentType: "COUNTERFEIT_SUSPECTED" | "DUPLICATE_SCAN" | "TAMPERED_LABEL" | "WRONG_PRODUCT" | "OTHER";
    description: string;
    severity?: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
    priority?: "P1" | "P2" | "P3" | "P4";
    licenseeId?: string;
    tags?: string[];
  }) {
    return core.request(`/ir/incidents`, { method: "POST", body: JSON.stringify(payload) });
  },

  async getIrIncidentById(id: string) {
    return core.request(`/ir/incidents/${encodeURIComponent(id)}`);
  },

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
    return core.request(`/ir/incidents/${encodeURIComponent(id)}`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    });
  },

  async addIrIncidentNote(id: string, note: string) {
    return core.request(`/ir/incidents/${encodeURIComponent(id)}/events`, {
      method: "POST",
      body: JSON.stringify({ note }),
    });
  },

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
    return core.request(`/ir/incidents/${encodeURIComponent(id)}/actions`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
  },

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
    return core.request(`/ir/incidents/${encodeURIComponent(id)}/communications`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
  },

  async uploadIrIncidentAttachment(id: string, file: File) {
    const form = new FormData();
    form.append("file", file);
    return core.request(`/ir/incidents/${encodeURIComponent(id)}/attachments`, {
      method: "POST",
      body: form,
      skipJson: true,
      timeoutMs: 45_000,
    });
  },

  async getIrPolicies(options?: { licenseeId?: string; ruleType?: string; isActive?: boolean; limit?: number; offset?: number }) {
    const params = new URLSearchParams();
    if (options?.licenseeId) params.append("licenseeId", options.licenseeId);
    if (options?.ruleType) params.append("ruleType", options.ruleType);
    if (options?.isActive != null) params.append("isActive", String(options.isActive));
    if (options?.limit != null) params.append("limit", String(options.limit));
    if (options?.offset != null) params.append("offset", String(options.offset));
    const query = params.toString() ? `?${params.toString()}` : "";
    return core.request(`/ir/policies${query}`);
  },

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
    return core.request(`/ir/policies`, { method: "POST", body: JSON.stringify(payload) });
  },

  async patchIrPolicy(id: string, payload: any) {
    return core.request(`/ir/policies/${encodeURIComponent(id)}`, { method: "PATCH", body: JSON.stringify(payload) });
  },

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
    return core.request(`/ir/alerts${query}`);
  },

  async patchIrAlert(id: string, payload: { acknowledged?: boolean; incidentId?: string | null }) {
    return core.request(`/ir/alerts/${encodeURIComponent(id)}`, { method: "PATCH", body: JSON.stringify(payload) });
  },

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
    return core.request(`/support/tickets${query}`);
  },

  async getSupportTicket(id: string) {
    return core.request(`/support/tickets/${encodeURIComponent(id)}`);
  },

  async patchSupportTicket(
    id: string,
    payload: Partial<{
      status: "OPEN" | "IN_PROGRESS" | "WAITING_CUSTOMER" | "RESOLVED" | "CLOSED";
      assignedToUserId: string | null;
    }>
  ) {
    return core.request(`/support/tickets/${encodeURIComponent(id)}`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    });
  },

  async addSupportTicketMessage(id: string, payload: { message: string; isInternal?: boolean }) {
    return core.request(`/support/tickets/${encodeURIComponent(id)}/messages`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
  },

  async trackSupportTicket(reference: string, email?: string) {
    const query = email ? `?email=${encodeURIComponent(email)}` : "";
    return core.request(`/support/tickets/track/${encodeURIComponent(reference)}${query}`);
  },

  async createSupportIssueReport(formData: FormData) {
    return core.request(`/support/reports`, {
      method: "POST",
      body: formData,
      skipJson: true,
      timeoutMs: 45_000,
    });
  },

  async getSupportIssueReports(options?: { limit?: number; offset?: number; licenseeId?: string }) {
    const params = new URLSearchParams();
    if (options?.limit != null) params.append("limit", String(options.limit));
    if (options?.offset != null) params.append("offset", String(options.offset));
    if (options?.licenseeId) params.append("licenseeId", options.licenseeId);
    const query = params.toString() ? `?${params.toString()}` : "";
    return core.request(`/support/reports${query}`);
  },

  async respondToSupportIssueReport(
    reportId: string,
    payload: {
      message: string;
      status?: "OPEN" | "RESPONDED" | "CLOSED";
    }
  ) {
    return core.request(`/support/reports/${encodeURIComponent(reportId)}/respond`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
  },

  getSupportIssueScreenshotUrl(fileName: string) {
    return `${BASE_URL}/support/reports/files/${encodeURIComponent(fileName)}`;
  },
});

export type { ApiResponse };
