import { afterEach, describe, expect, it, vi } from "vitest";

import { createApiClientCore } from "@/lib/api/internal-client-core";
import { getRequestCoordinatorScope, setRequestCoordinatorScope } from "@/lib/api/request-coordinator";

const originalFetch = globalThis.fetch;
const originalDomParser = globalThis.DOMParser;

describe("internal client core HTML error handling", () => {
  afterEach(() => {
    globalThis.fetch = originalFetch;
    globalThis.DOMParser = originalDomParser;
    vi.restoreAllMocks();
    setRequestCoordinatorScope(null);
  });

  it("keeps the session after refresh throttling and respects Retry-After", async () => {
    setRequestCoordinatorScope({ id: "actor" });
    const logout = vi.fn();
    window.addEventListener("auth:logout", logout);
    globalThis.fetch = vi.fn()
      .mockResolvedValueOnce(new Response("", { status: 401 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ code: "RATE_LIMITED" }), { status: 429, headers: { "content-type": "application/json", "retry-after": "30" } }))
      .mockResolvedValueOnce(new Response("", { status: 401 }));
    const client = createApiClientCore();
    const result = await client.request("/dashboard/stats");
    expect(result.status).toBe(429);
    expect(result.retryAfterSec).toBe(30);
    expect(logout).not.toHaveBeenCalled();
    expect((await client.request("/dashboard/stats")).status).toBe(429);
    expect(globalThis.fetch).toHaveBeenCalledTimes(3);
    window.removeEventListener("auth:logout", logout);
  });

  it("logs out on a revoked refresh token", async () => {
    setRequestCoordinatorScope({ id: "actor" });
    const logout = vi.fn();
    window.addEventListener("auth:logout", logout);
    globalThis.fetch = vi.fn()
      .mockResolvedValueOnce(new Response("", { status: 401 }))
      .mockResolvedValueOnce(new Response("", { status: 401 }));
    expect((await createApiClientCore().request("/dashboard/stats")).code).toBe("UNAUTHENTICATED");
    expect(logout).toHaveBeenCalledOnce();
    window.removeEventListener("auth:logout", logout);
  });

  it("treats explicit scope denial as terminal but keeps CSRF 403 nonterminal", async () => {
    setRequestCoordinatorScope({ id: "actor" });
    const logout = vi.fn();
    window.addEventListener("auth:logout", logout);
    try {
      globalThis.fetch = vi.fn()
        .mockResolvedValueOnce(new Response("", { status: 401 }))
        .mockResolvedValueOnce(new Response(JSON.stringify({ code: "CSRF_DENIED" }), { status: 403, headers: { "content-type": "application/json" } }));
      expect((await createApiClientCore().request("/dashboard/stats")).status).toBe(403);
      expect(logout).not.toHaveBeenCalled();
      globalThis.fetch = vi.fn()
        .mockResolvedValueOnce(new Response("", { status: 401 }))
        .mockResolvedValueOnce(new Response(JSON.stringify({ code: "AUTH_SCOPE_UNAVAILABLE" }), { status: 403, headers: { "content-type": "application/json" } }));
      expect((await createApiClientCore().request("/dashboard/stats")).code).toBe("UNAUTHENTICATED");
      expect(logout).toHaveBeenCalledOnce();
    } finally {
      window.removeEventListener("auth:logout", logout);
    }
  });

  it("does not log out or replay a protected operation after a refresh timeout", async () => {
    setRequestCoordinatorScope({ id: "actor" });
    const logout = vi.fn();
    window.addEventListener("auth:logout", logout);
    globalThis.fetch = vi.fn()
      .mockResolvedValueOnce(new Response("", { status: 401 }))
      .mockRejectedValueOnce(Object.assign(new Error("timeout"), { name: "AbortError" }));
    const result = await createApiClientCore().request("/dashboard/stats");
    expect(result.code).toBe("REQUEST_TIMEOUT");
    expect(logout).not.toHaveBeenCalled();
    expect(globalThis.fetch).toHaveBeenCalledTimes(2);
    window.removeEventListener("auth:logout", logout);
  });

  it("serializes refresh rotation across client instances when Web Locks are available", async () => {
    setRequestCoordinatorScope({ id: "actor" });
    window.localStorage.removeItem("mscqr:auth-refresh-version");
    const previousLocks = Object.getOwnPropertyDescriptor(navigator, "locks");
    let tail = Promise.resolve<unknown>(undefined);
    Object.defineProperty(navigator, "locks", { configurable: true, value: {
      request: (_name: string, run: () => Promise<unknown>) => {
        const next = tail.then(run);
        tail = next.catch(() => undefined);
        return next;
      },
    } });
    let release!: () => void;
    const firstResponse = new Promise<Response>((resolve) => { release = () => resolve(new Response(JSON.stringify({ success: true, data: { user: { id: "actor" } } }), { headers: { "content-type": "application/json" } })); });
    globalThis.fetch = vi.fn().mockReturnValueOnce(firstResponse);
    try {
      const first = createApiClientCore().request("/auth/refresh", { method: "POST" });
      const second = createApiClientCore().request("/auth/refresh", { method: "POST" });
      await vi.waitFor(() => expect(globalThis.fetch).toHaveBeenCalledTimes(1));
      release();
      expect((await first).success).toBe(true);
      expect((await second).code).toBe("REQUEST_SCOPE_CHANGED");
      expect(globalThis.fetch).toHaveBeenCalledTimes(1);
    } finally {
      window.localStorage.removeItem("mscqr:auth-refresh-version");
      if (previousLocks) Object.defineProperty(navigator, "locks", previousLocks);
      else Reflect.deleteProperty(navigator, "locks");
    }
  });

  it("does not start a queued refresh after logout", async () => {
    setRequestCoordinatorScope({ id: "actor" });
    const previousLocks = Object.getOwnPropertyDescriptor(navigator, "locks");
    let releaseLock!: () => void;
    const held = new Promise<void>((resolve) => { releaseLock = resolve; });
    Object.defineProperty(navigator, "locks", { configurable: true, value: {
      request: (_name: string, run: () => Promise<unknown>) => held.then(run),
    } });
    globalThis.fetch = vi.fn();
    try {
      const client = createApiClientCore();
      const pending = client.request("/auth/refresh", { method: "POST" });
      client.logout();
      releaseLock();
      expect((await pending).code).toBe("REQUEST_SCOPE_CHANGED");
      expect(globalThis.fetch).not.toHaveBeenCalled();
    } finally {
      if (previousLocks) Object.defineProperty(navigator, "locks", previousLocks);
      else Reflect.deleteProperty(navigator, "locks");
    }
  });

  it("does not replay a second tab request after another tab rotates the cookie", async () => {
    setRequestCoordinatorScope({ id: "actor" });
    window.localStorage.removeItem("mscqr:auth-refresh-version");
    const previousLocks = Object.getOwnPropertyDescriptor(navigator, "locks");
    let tail = Promise.resolve<unknown>(undefined);
    Object.defineProperty(navigator, "locks", { configurable: true, value: {
      request: (_name: string, run: () => Promise<unknown>) => {
        const next = tail.then(run);
        tail = next.catch(() => undefined);
        return next;
      },
    } });
    let release!: () => void;
    const rotation = new Promise<Response>((resolve) => { release = () => resolve(new Response(JSON.stringify({ success: true, data: { user: { id: "actor" } } }), { headers: { "content-type": "application/json" } })); });
    let protectedCalls = 0;
    let refreshCalls = 0;
    globalThis.fetch = vi.fn((url: string) => {
      if (url.endsWith("/auth/refresh")) { refreshCalls += 1; return rotation; }
      protectedCalls += 1;
      return Promise.resolve(new Response(protectedCalls <= 2 ? "" : JSON.stringify({ success: true, data: [] }), {
        status: protectedCalls <= 2 ? 401 : 200,
        headers: { "content-type": "application/json" },
      }));
    }) as typeof fetch;
    try {
      const first = createApiClientCore().request("/dashboard/stats");
      const second = createApiClientCore().request("/dashboard/stats");
      await vi.waitFor(() => expect(refreshCalls).toBe(1));
      release();
      expect((await first).success).toBe(true);
      expect((await second).code).toBe("REQUEST_SCOPE_CHANGED");
      expect(refreshCalls).toBe(1);
      expect(protectedCalls).toBe(3);
      for (const [, init] of vi.mocked(globalThis.fetch).mock.calls) {
        expect(new Headers(init?.headers).has("authorization")).toBe(false);
        expect(init?.credentials).toBe("include");
      }
    } finally {
      window.localStorage.removeItem("mscqr:auth-refresh-version");
      if (previousLocks) Object.defineProperty(navigator, "locks", previousLocks);
      else Reflect.deleteProperty(navigator, "locks");
    }
  });

  it("does not refresh again or clear a newer token after a stale protected 401", async () => {
    setRequestCoordinatorScope({ id: "actor" });
    window.localStorage.removeItem("mscqr:auth-refresh-version");
    const pending: Array<(response: Response) => void> = [];
    let refreshCalls = 0;
    globalThis.fetch = vi.fn((url: string) => {
      if (url.endsWith("/auth/refresh")) {
        refreshCalls += 1;
        return Promise.resolve(new Response(JSON.stringify({ success: true, data: { user: { id: "actor" }, accessToken: "new-token" } }), {
          headers: { "content-type": "application/json" },
        }));
      }
      if (pending.length < 2) return new Promise<Response>((resolve) => { pending.push(resolve); });
      return Promise.resolve(new Response(JSON.stringify({ success: true, data: [] }), {
        headers: { "content-type": "application/json" },
      }));
    }) as typeof fetch;
    const client = createApiClientCore();
    try {
      client.setToken("old-token");
      const first = client.request("/dashboard/stats");
      const stale = client.request("/dashboard/stats");
      await vi.waitFor(() => expect(pending).toHaveLength(2));
      pending[0](new Response(null, { status: 401 }));
      expect((await first).success).toBe(true);
      expect(client.getToken()).toBe("new-token");
      pending[1](new Response(null, { status: 401 }));
      expect((await stale).code).toBe("REQUEST_SCOPE_CHANGED");
      expect(refreshCalls).toBe(1);
      expect(client.getToken()).toBe("new-token");
    } finally {
      window.localStorage.removeItem("mscqr:auth-refresh-version");
    }
  });

  it("does not restore an auth scope from a refresh response arriving after logout", async () => {
    setRequestCoordinatorScope(null);
    let release!: (response: Response) => void;
    globalThis.fetch = vi.fn().mockReturnValue(new Promise<Response>((resolve) => { release = resolve; }));
    const client = createApiClientCore();
    const pending = client.request("/auth/refresh", { method: "POST" });
    await vi.waitFor(() => expect(globalThis.fetch).toHaveBeenCalledOnce());
    client.logout();
    const loggedOutScope = getRequestCoordinatorScope();
    release(new Response(JSON.stringify({ success: true, data: { user: { id: "stale-actor" } } }), { headers: { "content-type": "application/json" } }));
    expect((await pending).code).toBe("REQUEST_SCOPE_CHANGED");
    expect(getRequestCoordinatorScope()).toBe(loggedOutScope);
  });

  it("refuses refresh when another actor changes the shared version while queued", async () => {
    setRequestCoordinatorScope({ id: "actor-A", licenseeId: "tenant-A" });
    window.localStorage.setItem("mscqr:auth-refresh-version", "before");
    const previousLocks = Object.getOwnPropertyDescriptor(navigator, "locks");
    let releaseLock!: () => void;
    const held = new Promise<void>((resolve) => { releaseLock = resolve; });
    Object.defineProperty(navigator, "locks", { configurable: true, value: { request: (_name: string, run: () => Promise<unknown>) => held.then(run) } });
    globalThis.fetch = vi.fn();
    try {
      const pending = createApiClientCore().request("/auth/refresh", { method: "POST" });
      window.localStorage.setItem("mscqr:auth-refresh-version", "actor-B-rotated");
      releaseLock();
      expect((await pending).code).toBe("REQUEST_SCOPE_CHANGED");
      expect(globalThis.fetch).not.toHaveBeenCalled();
    } finally {
      window.localStorage.removeItem("mscqr:auth-refresh-version");
      if (previousLocks) Object.defineProperty(navigator, "locks", previousLocks);
      else Reflect.deleteProperty(navigator, "locks");
    }
  });

  it("cannot resurrect cookie-auth A through a B HTTP 304 cache hit", async () => {
    const client = createApiClientCore();
    setRequestCoordinatorScope({ id: "actor", licenseeId: "A" });
    globalThis.fetch = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ success: true, data: "A" }), { headers: { "content-type": "application/json" } }))
      .mockResolvedValueOnce(new Response(null, { status: 304 }));
    expect((await client.request("/admin/qr/analytics")).data).toBe("A");
    setRequestCoordinatorScope({ id: "actor", licenseeId: "B" });
    expect((await client.request("/admin/qr/analytics")).success).toBe(false);
  });

  it("rejects a previous scope even when it changes during asynchronous JSON parsing", async () => {
    setRequestCoordinatorScope({ id: "actor", licenseeId: "A" });
    let finish!: (value: any) => void;
    globalThis.fetch = vi.fn().mockResolvedValue({ ok: true, status: 200, headers: new Headers({ "content-type": "application/json" }), json: () => new Promise(resolve => { finish = resolve; }) });
    const pending = createApiClientCore().request("/auth/me");
    await vi.waitFor(() => expect(finish).toBeDefined());
    setRequestCoordinatorScope({ id: "actor", licenseeId: "B" });
    finish({ success: true, data: { user: { id: "actor", licenseeId: "A" } } });
    expect((await pending).code).toBe("REQUEST_SCOPE_CHANGED");
  });

  it("does not replay an A mutation automatically after auth refresh establishes B", async () => {
    setRequestCoordinatorScope({ id: "A" });
    globalThis.fetch = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ success: false }), { status: 401, headers: { "content-type": "application/json" } }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ success: true, data: { user: { id: "B" } } }), { headers: { "content-type": "application/json" } }));
    const response = await createApiClientCore().request("/qr/requests/id/reject", { method: "POST", body: "{}" });
    expect(response.code).toBe("REQUEST_SCOPE_CHANGED");
    expect(globalThis.fetch).toHaveBeenCalledTimes(2);
  });

  it("uses the selected canonical idempotency header for multipart and retains it on auth retry", async () => {
    setRequestCoordinatorScope({ id: "fixture" });
    globalThis.fetch = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ success: false }), { status: 401, headers: { "content-type": "application/json" } }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ success: true, data: { user: { id: "fixture" } } }), { headers: { "content-type": "application/json" } }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ success: true }), { headers: { "content-type": "application/json" } }));
    const form = new FormData();
    form.append("file", new Blob(["fixture"]), "fixture.txt");
    const response = await createApiClientCore().request("/incidents/report", {
      method: "POST", body: form, idempotencyHeader: "idempotency-key", skipJson: true,
    });
    expect(response.success).toBe(true);
    const calls = vi.mocked(globalThis.fetch).mock.calls;
    const original = new Headers(calls[0][1]?.headers);
    const retried = new Headers(calls[2][1]?.headers);
    expect(original.get("idempotency-key")).toBeTruthy();
    expect(retried.get("idempotency-key")).toBe(original.get("idempotency-key"));
    expect(original.has("x-idempotency-key")).toBe(false);
    expect(original.has("content-type")).toBe(false);
    expect(calls[2][1]?.body).toBe(form);
  });

  it("extracts readable text from HTML responses without leaking markup", async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 500,
      headers: new Headers({ "content-type": "text/html" }),
      text: async () =>
        "<html><body><h1>Server Error</h1><script>window.alert('secret');</script><p>Try again &amp; contact support.</p></body></html>",
    } as Response);

    const client = createApiClientCore();
    const response = await client.request("/broken", { method: "GET", skipAuthRefresh: true });

    expect(response.success).toBe(false);
    expect(response.error).toBe("Server Error Try again & contact support.");
  });

  it("falls back to a linear parser when DOM parsing APIs are unavailable", async () => {
    globalThis.DOMParser = undefined as unknown as typeof DOMParser;
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 502,
      headers: new Headers({ "content-type": "text/html" }),
      text: async () => "<div>Proxy <strong>timeout</strong><style>body{display:none}</style>&nbsp;retry later</div>",
    } as Response);

    const client = createApiClientCore();
    const response = await client.request("/timeout", { method: "GET", skipAuthRefresh: true });

    expect(response.success).toBe(false);
    expect(response.error).toBe("Proxy timeout retry later");
  });

  it("preserves rate-limit metadata from standard 429 responses", async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 429,
      headers: new Headers({ "content-type": "application/json", "retry-after": "42" }),
      json: async () => ({
        success: false,
        code: "RATE_LIMITED",
        error: "Too many dashboard refreshes. Please wait before retrying.",
      }),
    } as Response);

    const client = createApiClientCore();
    const response = await client.request("/dashboard/stats", { method: "GET", skipAuthRefresh: true });

    expect(response.success).toBe(false);
    expect(response.code).toBe("RATE_LIMITED");
    expect(response.retryAfterSec).toBe(42);
  });

  it("pauses protected read route families after 429 responses", async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 429,
      headers: new Headers({ "content-type": "application/json", "retry-after": "15" }),
      json: async () => ({
        success: false,
        code: "RATE_LIMITED",
        error: "Too many print status reads. Please wait before retrying.",
      }),
    } as Response);

    const client = createApiClientCore();
    const first = await client.request("/manufacturer/print-jobs/c25aa149-2b0c-4f53-a207-f85ce69f2b79", {
      method: "GET",
      skipAuthRefresh: true,
    });
    const second = await client.request("/manufacturer/print-jobs/43dd820a-1a13-4bb2-a4dc-35a8ad362129", {
      method: "GET",
      skipAuthRefresh: true,
    });

    expect(first.status).toBe(429);
    expect(second.status).toBe(429);
    expect(second.retryAfterSec).toBeGreaterThan(0);
    expect(globalThis.fetch).toHaveBeenCalledTimes(1);
  });

  it("uses exponential protected-read backoff when Retry-After is absent", async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 429,
      headers: new Headers({ "content-type": "application/json" }),
      json: async () => ({
        success: false,
        code: "RATE_LIMITED",
        error: "Too many batch reads. Please wait before retrying.",
      }),
    } as Response);

    const client = createApiClientCore();
    await client.request("/qr/batches?page=1", { method: "GET", skipAuthRefresh: true });
    const paused = await client.request("/qr/batches?page=2", { method: "GET", skipAuthRefresh: true });

    expect(paused.status).toBe(429);
    expect(paused.retryAfterSec).toBeGreaterThanOrEqual(9);
    expect(paused.retryAfterSec).toBeLessThanOrEqual(10);
    expect(globalThis.fetch).toHaveBeenCalledTimes(1);
  });

  it("marks state-changing timeouts as unknown outcome", async () => {
    globalThis.fetch = vi.fn().mockRejectedValue(Object.assign(new Error("aborted"), { name: "AbortError" }));

    const client = createApiClientCore();
    const response = await client.request("/licensees", {
      method: "POST",
      body: JSON.stringify({ name: "Acme" }),
      skipAuthRefresh: true,
    });

    expect(response.success).toBe(false);
    expect(response.code).toBe("REQUEST_TIMEOUT");
    expect(response.status).toBe(0);
    expect(response.unknownOutcome).toBe(true);
  });

  it("refreshes after a 401 even when refresh cookies are HttpOnly and invisible to document.cookie", async () => {
    setRequestCoordinatorScope({ id: "user-1", auth: { sessionStage: "ACTIVE" } } as any);
    Object.defineProperty(document, "cookie", {
      configurable: true,
      writable: true,
      value: "aq_csrf=csrf-1",
    });

    globalThis.fetch = vi
      .fn()
      .mockResolvedValueOnce({
        ok: false,
        status: 401,
        headers: new Headers({ "content-type": "application/json" }),
        json: async () => ({ success: false, error: "No token provided" }),
      } as Response)
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Headers({ "content-type": "application/json" }),
        json: async () => ({ success: true, data: { user: { id: "user-1" }, auth: { sessionStage: "ACTIVE" } } }),
      } as Response)
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Headers({ "content-type": "application/json" }),
        json: async () => ({ success: true, data: [] }),
      } as Response);

    const client = createApiClientCore();
    const response = await client.request("/qr/batches", { method: "GET" });

    expect(response.success).toBe(true);
    expect(globalThis.fetch).toHaveBeenCalledTimes(3);
    expect(String(vi.mocked(globalThis.fetch).mock.calls[1][0])).toBe("/api/auth/refresh");
    expect((vi.mocked(globalThis.fetch).mock.calls[1][1]?.headers as Record<string, string>)["x-csrf-token"]).toBe("csrf-1");
  });

  it("coalesces direct and 401-triggered session refreshes", async () => {
    let releaseRefresh!: () => void;
    const refreshPending = new Promise<void>((resolve) => {
      releaseRefresh = resolve;
    });
    globalThis.fetch = vi.fn(async (input) => {
      const url = String(input);
      if (url.endsWith("/auth/refresh")) {
        await refreshPending;
        return {
          ok: true,
          status: 200,
          headers: new Headers({ "content-type": "application/json" }),
          json: async () => ({ success: true, data: { user: { id: "user-1" } } }),
        } as Response;
      }
      return {
        ok: false,
        status: 401,
        headers: new Headers({ "content-type": "application/json" }),
        json: async () => ({ success: false, error: "Not authenticated" }),
      } as Response;
    });

    const client = createApiClientCore();
    const direct = client.request("/auth/refresh", { method: "POST" });
    const protectedRead = client.request("/qr/batches", { method: "GET" });
    await vi.waitFor(() => expect(globalThis.fetch).toHaveBeenCalledTimes(2));
    releaseRefresh();
    await Promise.all([direct, protectedRead]);

    expect(
      vi.mocked(globalThis.fetch).mock.calls.filter(([input]) => String(input).endsWith("/auth/refresh")),
    ).toHaveLength(1);
  });

  it("clears stale bearer state before retrying a protected request after session restore", async () => {
    setRequestCoordinatorScope({ id: "user-1", auth: { sessionStage: "ACTIVE" } } as any);
    Object.defineProperty(document, "cookie", {
      configurable: true,
      writable: true,
      value: "aq_csrf=csrf-2",
    });

    globalThis.fetch = vi
      .fn()
      .mockResolvedValueOnce({
        ok: false,
        status: 401,
        headers: new Headers({ "content-type": "application/json" }),
        json: async () => ({ success: false, error: "No token provided" }),
      } as Response)
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Headers({ "content-type": "application/json" }),
        json: async () => ({
          success: true,
          data: { user: { id: "user-1" }, auth: { sessionStage: "ACTIVE" }, accessToken: "fresh-token" },
        }),
      } as Response)
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Headers({ "content-type": "application/json" }),
        json: async () => ({ success: true, data: [] }),
      } as Response);

    const client = createApiClientCore();
    client.setToken("stale-token");

    const response = await client.request("/qr/batches", { method: "GET" });

    expect(response.success).toBe(true);
    const firstHeaders = vi.mocked(globalThis.fetch).mock.calls[0][1]?.headers as Record<string, string>;
    const refreshHeaders = vi.mocked(globalThis.fetch).mock.calls[1][1]?.headers as Record<string, string>;
    const retryHeaders = vi.mocked(globalThis.fetch).mock.calls[2][1]?.headers as Record<string, string>;
    expect(firstHeaders.Authorization).toBe("Bearer stale-token");
    expect(refreshHeaders.Authorization).toBeUndefined();
    expect(retryHeaders.Authorization).toBe("Bearer fresh-token");
  });
});
