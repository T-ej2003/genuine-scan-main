import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  clearRequestCoordinator,
  coordinateProtectedRead,
  getRequestCoordinatorState,
  buildRequestFamilyKey,
  clientSecurityScope,
  getRequestCoordinatorScope,
  isRequestCoordinatorScopeReady,
  setRequestCoordinatorScope,
} from "@/lib/api/request-coordinator";
import { createLicenseeQrApi } from "@/lib/api/internal-client-licensee-qr";

describe("request coordinator", () => {
  beforeEach(() => {
    clearRequestCoordinator();
    setRequestCoordinatorScope(null);
    window.localStorage.clear();
    vi.useRealTimers();
  });

  const actor = (licenseeId = "A", extra = {}) => ({ id: "actor", role: "manufacturer" as const, rawRole: "MANUFACTURER_ADMIN", licenseeId, orgId: "org", scopeVersion: "1", ...extra });
  const options = { family: "qr:analytics", params: "mode=inventory", ttlMs: 60000 };

  it.each(["qr:analytics", "qr:stats", "qr:batches", "dashboard:stats", "licensees:list"])("isolates cached and deduplicated %s across effective tenants", async family => {
    const read = { ...options, family };
    setRequestCoordinatorScope(actor());
    let finish!: (value: any) => void;
    const a = coordinateProtectedRead(read, () => new Promise<any>(resolve => { finish = resolve; }));
    setRequestCoordinatorScope(actor("B"));
    const b = await coordinateProtectedRead(read, async () => ({ success: true, data: "B" }));
    finish({ success: true, data: "A" });
    expect(b.data).toBe("B");
    expect((await a).code).toBe("REQUEST_SCOPE_CHANGED");
    const fetch = vi.fn();
    expect((await coordinateProtectedRead(read, fetch)).data).toBe("B");
    expect(fetch).not.toHaveBeenCalled();
    expect(JSON.stringify(getRequestCoordinatorState())).not.toContain("hasLastGood\":false");
  });

  it.each([
    { id: "other" }, { role: "licensee_admin", rawRole: "LICENSEE_ADMIN" }, { orgId: "other" },
    { scopeVersion: "2" }, { isActive: false }, { auth: { sessionId: "new-session" } },
    { linkedLicensees: [{ id: "B", orgId: "org", scopeVersion: "2", isPrimary: true }] },
  ])("separates changed authenticated identity %j", async extra => {
    setRequestCoordinatorScope(actor());
    const key = buildRequestFamilyKey(options.family, options.params);
    await coordinateProtectedRead(options, async () => ({ success: true, data: "A" }));
    setRequestCoordinatorScope(actor("A", extra));
    expect(buildRequestFamilyKey(options.family, options.params)).not.toBe(key);
    expect((await coordinateProtectedRead(options, async () => ({ success: false, status: 500 }))).data).toBeUndefined();
  });

  it("invalidates A→B→A, logout, failure fallback and late cache resurrection", async () => {
    setRequestCoordinatorScope(actor());
    let finish!: (value: any) => void;
    const oldA = coordinateProtectedRead(options, () => new Promise<any>(resolve => { finish = resolve; }));
    setRequestCoordinatorScope(actor("B"));
    expect((await coordinateProtectedRead(options, async () => ({ success: false, status: 429 }))).data).toBeUndefined();
    setRequestCoordinatorScope(actor());
    finish({ success: true, data: "OLD-A" });
    expect((await oldA).success).toBe(false);
    expect((await coordinateProtectedRead(options, async () => ({ success: true, data: "NEW-A" }))).data).toBe("NEW-A");
    setRequestCoordinatorScope(null);
    expect((await coordinateProtectedRead(options, async () => ({ success: false, status: 403 }))).data).toBeUndefined();
  });

  it("preserves same-scope caching, revalidation and lossless long query identity", async () => {
    setRequestCoordinatorScope(actor());
    const a = buildRequestFamilyKey("qr:analytics", "x".repeat(300) + "&code=A/B");
    const b = buildRequestFamilyKey("qr:analytics", "x".repeat(300) + "&code=A?B");
    expect(a).not.toBe(b);
    const fetch = vi.fn().mockResolvedValue({ success: true, data: "A" });
    await coordinateProtectedRead(options, fetch);
    await coordinateProtectedRead(options, fetch);
    expect(fetch).toHaveBeenCalledTimes(1);
    await coordinateProtectedRead({ ...options, force: true }, fetch);
    expect(fetch).toHaveBeenCalledTimes(2);
    vi.useFakeTimers(); vi.advanceTimersByTime(60001);
    await coordinateProtectedRead({ ...options, minRefreshMs: 0 }, fetch);
    expect(fetch).toHaveBeenCalledTimes(3);
    vi.useRealTimers();
  });

  it("treats cross-tab scope markers as invalidation, not authorization", async () => {
    setRequestCoordinatorScope(actor());
    const before = getRequestCoordinatorScope();
    const forged = clientSecurityScope(actor("FOREIGN"));
    window.dispatchEvent(new StorageEvent("storage", { key: "mscqr:request-coordinator:v1:scope", newValue: JSON.stringify({ scopeIdentity: forged }) }));
    expect(isRequestCoordinatorScopeReady()).toBe(false);
    const fetch = vi.fn();
    expect((await coordinateProtectedRead(options, fetch)).code).toBe("REQUEST_SCOPE_CHANGED");
    expect(fetch).not.toHaveBeenCalled();
    expect(getRequestCoordinatorScope()).not.toContain("FOREIGN");
    expect(getRequestCoordinatorScope()).not.toBe(before);
    setRequestCoordinatorScope(actor());
    expect(isRequestCoordinatorScopeReady()).toBe(true);
  });

  it("separates concurrent platform explicit selectors without disabling useful same-scope dedup", async () => {
    setRequestCoordinatorScope({ id: "platform", role: "super_admin", rawRole: "SUPER_ADMIN" });
    const finish: Array<(value: any) => void> = [];
    const core = { request: vi.fn(() => new Promise<any>(resolve => finish.push(resolve))) };
    const api = createLicenseeQrApi(core as any);
    const a = api.getQrTrackingAnalytics({ licenseeId: "A" });
    const b = api.getQrTrackingAnalytics({ licenseeId: "B" });
    const duplicateB = api.getQrTrackingAnalytics({ licenseeId: "B" });
    expect(core.request).toHaveBeenCalledTimes(2);
    finish[1]({ success: true, data: "B" }); finish[0]({ success: true, data: "A" });
    expect((await a).data).toBe("A"); expect((await b).data).toBe("B"); expect((await duplicateB).data).toBe("B");
  });

  it("separates default manufacturer tenant selection through live-link scope versions", async () => {
    const defaults = { licenseeId: undefined, linkedLicensees: [{ id: "A", orgId: "org", scopeVersion: "1", isPrimary: true }] };
    setRequestCoordinatorScope(actor("A", defaults));
    await coordinateProtectedRead(options, async () => ({ success: true, data: "A" }));
    setRequestCoordinatorScope(actor("A", { ...defaults, linkedLicensees: [{ id: "B", orgId: "org", scopeVersion: "2", isPrimary: true }] }));
    expect((await coordinateProtectedRead(options, async () => ({ success: true, data: "B" }))).data).toBe("B");
  });

  it("dedupes in-flight reads by family and params", async () => {
    let calls = 0;
    const pending = coordinateProtectedRead(
      { family: "dashboard:stats", params: { scope: "all" }, ttlMs: 1 },
      async () => {
        calls += 1;
        await new Promise((resolve) => setTimeout(resolve, 5));
        return { success: true, data: { total: 1 } };
      }
    );

    const duplicate = coordinateProtectedRead(
      { family: "dashboard:stats", params: { scope: "all" }, ttlMs: 1 },
      async () => {
        calls += 1;
        return { success: true, data: { total: 2 } };
      }
    );

    await expect(Promise.all([pending, duplicate])).resolves.toEqual([
      { success: true, data: { total: 1 } },
      { success: true, data: { total: 1 } },
    ]);
    expect(calls).toBe(1);
  });

  it("returns stale cached data during 429 cooldown and persists cooldown", async () => {
    const keyOptions = { family: "manufacturer-print-job-status", params: { jobId: "job-1" }, ttlMs: 1, minRefreshMs: 0 };
    await coordinateProtectedRead(keyOptions, async () => ({ success: true, data: { status: "SENT" } }));

    const response = await coordinateProtectedRead(
      { ...keyOptions, force: true },
      async () => ({ success: false, status: 429, code: "RATE_LIMITED", retryAfterSec: 45, error: "Too many" })
    );

    expect(response.success).toBe(true);
    expect(response.degraded).toBe(true);
    expect(response.code).toBe("RATE_LIMITED");
    expect(response.data).toEqual({ status: "SENT" });
    expect(getRequestCoordinatorState().some((entry) => entry.cooldownUntil > Date.now())).toBe(true);
  });
});
