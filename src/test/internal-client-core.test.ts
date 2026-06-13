import { afterEach, describe, expect, it, vi } from "vitest";

import { createApiClientCore } from "@/lib/api/internal-client-core";

const originalFetch = globalThis.fetch;
const originalDomParser = globalThis.DOMParser;

describe("internal client core HTML error handling", () => {
  afterEach(() => {
    globalThis.fetch = originalFetch;
    globalThis.DOMParser = originalDomParser;
    vi.restoreAllMocks();
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
});
