import type { ApiClientCore } from "@/lib/api/internal-client-core";

export const createSupportIntakeApi = (core: ApiClientCore) => ({
  async submitRequestAccess(payload: {
    fullName: string;
    workEmail: string;
    companyName: string;
    role: string;
    country: string;
    monthlyGarmentVolume: string;
    message: string;
    sourcePage?: string;
    referrer?: string;
    website?: string;
  }) {
    return core.request<{
      referenceCode: string;
      status: string;
      emailDeliveryStatus: string;
      acknowledgementEmailDeliveryStatus: string;
      message: string;
    }>(`/public/request-access`, {
      method: "POST",
      body: JSON.stringify(payload),
      skipAuthRefresh: true,
    });
  },

  async submitPublicSupportIssue(payload: {
    name: string;
    email: string;
    issueType: "verification_result" | "scan_problem" | "product_concern" | "platform_access" | "privacy" | "other";
    title: string;
    message: string;
    verificationCode?: string;
    productReference?: string;
    sourcePath?: string;
    pageUrl?: string;
    website?: string;
  }) {
    return core.request<{
      referenceCode: string;
      status: string;
      emailDeliveryStatus: string;
      acknowledgementEmailDeliveryStatus: string;
      message: string;
    }>(`/public/support`, {
      method: "POST",
      body: JSON.stringify(payload),
      skipAuthRefresh: true,
    });
  },

  async getRequestAccessRecords(options?: { status?: string; limit?: number; offset?: number }) {
    const params = new URLSearchParams();
    if (options?.status) params.append("status", options.status);
    if (options?.limit != null) params.append("limit", String(options.limit));
    if (options?.offset != null) params.append("offset", String(options.offset));
    const query = params.toString() ? `?${params.toString()}` : "";
    return core.request(`/support/request-access${query}`);
  },

  async patchRequestAccessRecord(
    id: string,
    payload: {
      status?: "NEW" | "REVIEWING" | "CONTACTED" | "QUALIFIED" | "CLOSED";
      internalNote?: string | null;
      assignedToUserId?: string | null;
    }
  ) {
    return core.request(`/support/request-access/${encodeURIComponent(id)}`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    });
  },
});
