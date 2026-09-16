import { afterEach, describe, expect, it, vi } from "vitest";
import { createAdminOpsApi } from "@/lib/api/internal-client-admin-ops";
import { createVerifySupportApi } from "@/lib/api/internal-client-verify-support";
import type { ApiClientCore } from "@/lib/api/internal-client-core";
import { createLicenseeQrApi } from "@/lib/api/internal-client-licensee-qr";
import { createPrintingApi } from "@/lib/api/internal-client-printing";

const core = (request: ApiClientCore["request"]): ApiClientCore => ({
  request, setToken: vi.fn(), getToken: () => null, logout: vi.fn(),
});
afterEach(() => vi.unstubAllGlobals());

describe("G11 reviewed request and response contracts", () => {
  it("preserves the platform's explicit allocation-map tenant and encoded batch identity", async () => {
    const request = vi.fn().mockResolvedValue({ success: false, error: "Batch not found" });
    const api = createLicenseeQrApi(core(request));
    await api.getBatchAllocationMap("batch/fixture", "tenant & fixture");
    expect(request).toHaveBeenCalledWith("/qr/batches/batch%2Ffixture/allocation-map?licenseeId=tenant%20%26%20fixture");
  });
  it("preserves exact export scope and surfaces a denied/retired export instead of enabling it", async () => {
    const fetch = vi.fn().mockResolvedValue({ ok: false, status: 410 });
    vi.stubGlobal("fetch", fetch);
    const api = createAdminOpsApi(core(vi.fn()));
    await expect(api.exportAuditLogsCsv({ licenseeId: "tenant & fixture", purpose: "review/export" })).rejects.toThrow("Export failed");
    const url = new URL(fetch.mock.calls[0][0], "https://fixture.invalid");
    expect(url.pathname).toMatch(/\/audit\/logs\/export$/);
    expect(Object.fromEntries(url.searchParams)).toEqual({ licenseeId: "tenant & fixture", purpose: "review/export" });
  });

  it("all incident upload/report wrappers request the exact header and keep multipart and CAPTCHA intact", async () => {
    const request = vi.fn().mockResolvedValue({ success: false, error: "Forbidden" });
    const api = createVerifySupportApi(core(request));
    const file = new File(["fixture"], "fixture.txt");
    await api.uploadIncidentEvidence("id/one", file);
    await api.uploadIrIncidentAttachment("id/two", file);
    await api.submitIncidentReport(new FormData(), "test-only-captcha");
    expect(request.mock.calls.map(([url]) => url)).toEqual(["/incidents/id%2Fone/evidence", "/ir/incidents/id%2Ftwo/attachments", "/incidents/report"]);
    for (const [, options] of request.mock.calls) {
      expect(options).toMatchObject({ method: "POST", idempotencyHeader: "idempotency-key", skipJson: true });
      expect(options.body).toBeInstanceOf(FormData);
    }
    expect(request.mock.calls[2][1].headers).toEqual({ "x-captcha-token": "test-only-captcha" });
  });
  it.each([0, 1, 100, 101])("preserves bounded pagination metadata for %i records across all four list wrappers", async (total) => {
    const request = vi.fn().mockImplementation(async (path: string) => {
      const url = new URL(path, "https://fixture.invalid");
      const offset = Number(url.searchParams.get("offset"));
      const limit = Number(url.searchParams.get("limit"));
      return { success: true, data: Array.from({ length: Math.min(limit, Math.max(0, total - offset)) }, (_, i) => ({ id: String(offset + i) })), meta: { total, limit, offset } };
    });
    const client = core(request);
    const admin = createAdminOpsApi(client), qr = createLicenseeQrApi(client), printing = createPrintingApi(client);
    for (const [index, getPage] of [admin.getUsers, qr.getBatches, qr.getBatchSummary, printing.getManufacturers].entries()) {
      const licenseeId = `page-fixture-${total}-${index}`;
      const first = await getPage({ licenseeId, limit: 100, offset: 0 });
      expect(first.meta).toEqual({ total, limit: 100, offset: 0 });
      expect(first.data).toHaveLength(Math.min(total, 100));
      const next = await getPage({ licenseeId, limit: 100, offset: 100 });
      expect(next.meta).toEqual({ total, limit: 100, offset: 100 });
      expect(next.data).toHaveLength(Math.max(0, total - 100));
      const query = new URL(request.mock.calls[request.mock.calls.length - 1][0], "https://fixture.invalid").searchParams;
      expect(query.get("licenseeId")).toBe(licenseeId);
      expect(query.get("offset")).toBe("100");
    }
  });

  it("serializes bounded scope and purpose without translating backend denial", async () => {
    const denial = { success: false, code: "FORBIDDEN", error: "Forbidden" };
    const request = vi.fn().mockResolvedValue(denial);
    const api = createAdminOpsApi(core(request));
    for (const call of [api.getAuditLogs, api.getFraudReports, api.getTraceTimeline]) {
      expect(await call({ licenseeId: "tenant-contract", purpose: "review & investigate", limit: 1 })).toEqual(denial);
      const url = new URL(request.mock.calls[request.mock.calls.length - 1][0], "https://fixture.invalid");
      expect(url.searchParams.get("licenseeId")).toBe("tenant-contract");
      expect(url.searchParams.get("purpose")).toBe("review & investigate");
    }
    await api.getCompliancePackJobs({ licenseeId: "tenant-contract", limit: 1, offset: 0 });
    expect(request).toHaveBeenLastCalledWith("/governance/compliance/pack/jobs?licenseeId=tenant-contract&limit=1&offset=0");
  });

  it("adapts the real top-level internal release envelope without changing failures", async () => {
    const wire = { success: true, name: "backend", version: "1", gitSha: "a".repeat(40),
      environment: "production", release: "backend@1", signing: null };
    const request = vi.fn().mockResolvedValueOnce(wire).mockResolvedValueOnce({ success: false, error: "Forbidden" });
    const api = createAdminOpsApi(core(request));
    expect((await api.getInternalReleaseMetadata()).data).toEqual({
      name: wire.name, version: wire.version, gitSha: wire.gitSha,
      environment: wire.environment, release: wire.release, signing: null,
    });
    expect(await api.getInternalReleaseMetadata()).toEqual({ success: false, error: "Forbidden" });
  });

  it("uses the backend's manufacturer administrator enum without rewriting authority", async () => {
    const request = vi.fn().mockResolvedValue({ success: false, error: "Forbidden" });
    const api = createAdminOpsApi(core(request));
    const payload: Parameters<typeof api.createUser>[0] = {
      email: "fixture@example.test", password: "test-only-unused", name: "Fixture",
      role: "MANUFACTURER_ADMIN", licenseeId: "tenant-fixture",
    };
    await api.createUser(payload);
    expect(request).toHaveBeenCalledWith("/users", { method: "POST", body: JSON.stringify(payload) });
    // @ts-expect-error The retired role is not part of the strict backend DTO.
    const rejected: Parameters<typeof api.createUser>[0]["role"] = "MANUFACTURER";
    expect(rejected).toBe("MANUFACTURER");
  });

  it("policy creation does not advertise a manufacturer selector", async () => {
    const request = vi.fn().mockResolvedValue({ success: true });
    const api = createVerifySupportApi(core(request));
    const payload: Parameters<typeof api.createIrPolicy>[0] = {
      name: "Fixture policy", ruleType: "BURST_SCANS", threshold: 5, windowMinutes: 10,
      licenseeId: "tenant-fixture",
    };
    await api.createIrPolicy(payload);
    expect(request).toHaveBeenCalledWith("/ir/policies", { method: "POST", body: JSON.stringify(payload) });
    // @ts-expect-error Manufacturer scope is not a canonical policy-create field.
    const rejected: keyof typeof payload = "manufacturerId";
    expect(rejected).toBe("manufacturerId");
  });
});
