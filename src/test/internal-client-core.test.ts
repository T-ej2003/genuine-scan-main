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
});
