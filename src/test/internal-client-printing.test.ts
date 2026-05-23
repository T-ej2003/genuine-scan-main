import { describe, expect, it, vi } from "vitest";

import { createPrintingApi } from "@/lib/api/internal-client-printing";
import type { ApiClientCore, ApiResponse } from "@/lib/api/internal-client-core";

type RequestPayload = {
  connected?: boolean;
  eligibleForPrinting?: boolean;
  selectedPrinterId?: string;
  selectedPrinterName?: string;
};

const createCore = (request: (endpoint: string, options?: RequestInit) => Promise<ApiResponse<unknown>>): ApiClientCore => ({
  setToken: vi.fn(),
  getToken: () => null,
  logout: vi.fn(),
  request: <T>(endpoint: string, options?: RequestInit) => request(endpoint, options) as Promise<ApiResponse<T>>,
});

describe("printing api request control", () => {
  it("sends the print job creation payload with the saved printer profile UUID only", async () => {
    const request = vi.fn(async () => ({ success: true, data: { printJobId: "job-1" } }));
    const api = createPrintingApi(createCore(request));

    await api.createPrintJob({
      batchId: "c9dabd08-9393-4be3-bb33-0269b543285d",
      printerId: "62eea666-5a7f-444a-94fb-8fa040396874",
      quantity: 1,
    });

    const firstCall = request.mock.calls[0] as unknown as [string, RequestInit | undefined];
    const body = JSON.parse(String(firstCall[1]?.body || "{}"));
    expect(body).not.toHaveProperty("selectedPrinterId");
    expect(body).not.toHaveProperty("deviceFingerprint");
    expect(body).not.toHaveProperty("agentId");
    expect(request).toHaveBeenCalledWith(
      "/manufacturer/print-jobs",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({
          batchId: "c9dabd08-9393-4be3-bb33-0269b543285d",
          printerId: "62eea666-5a7f-444a-94fb-8fa040396874",
          quantity: 1,
        }),
      })
    );
  });

  it("posts local printer relink requests without browser-supplied connector identity", async () => {
    const request = vi.fn(async () => ({ success: true, data: { repaired: true } }));
    const api = createPrintingApi(createCore(request));

    await api.relinkLocalAgentPrinter("62eea666-5a7f-444a-94fb-8fa040396874");

    expect(request).toHaveBeenCalledWith(
      "/manufacturer/printers/62eea666-5a7f-444a-94fb-8fa040396874/relink-local-agent",
      expect.objectContaining({ method: "POST" })
    );
    const body = (request.mock.calls[0] as unknown as [string, RequestInit | undefined])[1]?.body;
    expect(body).toBeUndefined();
  });

  it("posts safe abandon requests for unconfirmed print jobs", async () => {
    const request = vi.fn(async () => ({ success: true, data: { status: "CANCELLED" } }));
    const api = createPrintingApi(createCore(request));

    await api.abandonPrintJob("9c7a03d6-db68-4f65-96c2-efb23f83cc08");

    expect(request).toHaveBeenCalledWith(
      "/manufacturer/print-jobs/9c7a03d6-db68-4f65-96c2-efb23f83cc08/abandon",
      expect.objectContaining({ method: "POST" })
    );
  });

  it("posts diagnostic test-label requests for saved printer profiles", async () => {
    const request = vi.fn(async () => ({ success: true, data: { outcome: "confirmed" } }));
    const api = createPrintingApi(createCore(request));

    await api.testPrinterLabel("62eea666-5a7f-444a-94fb-8fa040396874");

    expect(request).toHaveBeenCalledWith(
      "/manufacturer/printers/62eea666-5a7f-444a-94fb-8fa040396874/test-label",
      expect.objectContaining({ method: "POST" })
    );
  });

  it("deduplicates concurrent printer status requests", async () => {
    let resolveRequest: ((response: ApiResponse<RequestPayload>) => void) | null = null;
    const request = vi.fn(
      () =>
        new Promise<ApiResponse<RequestPayload>>((resolve) => {
          resolveRequest = resolve;
        })
    );
    const api = createPrintingApi(createCore(request));

    const first = api.getPrinterConnectionStatus({ force: true });
    const second = api.getPrinterConnectionStatus({ force: true });
    const resolveStatus = resolveRequest as ((response: ApiResponse<RequestPayload>) => void) | null;
    expect(resolveStatus).not.toBeNull();
    resolveStatus?.({
      success: true,
      data: {
        connected: true,
        eligibleForPrinting: true,
        selectedPrinterId: "zdesigner-zt410",
        selectedPrinterName: "ZDesigner ZT410-300dpi ZPL",
      },
    });

    const [firstResult, secondResult] = await Promise.all([first, second]);
    expect(request).toHaveBeenCalledTimes(1);
    expect(firstResult.data?.selectedPrinterId).toBe("zdesigner-zt410");
    expect(secondResult.data?.selectedPrinterId).toBe("zdesigner-zt410");
  });

  it("reuses fresh cached printer lists instead of refetching on route changes", async () => {
    const request = vi.fn(async () => ({
      success: true,
      data: [{ id: "printer-1", name: "ZDesigner ZT410-300dpi ZPL" }],
    }));
    const api = createPrintingApi(createCore(request));

    const first = await api.listRegisteredPrinters(true, { force: true });
    const second = await api.listRegisteredPrinters(true);

    expect(request).toHaveBeenCalledTimes(1);
    expect(first.data?.[0]?.name).toBe("ZDesigner ZT410-300dpi ZPL");
    expect(second.data?.[0]?.name).toBe("ZDesigner ZT410-300dpi ZPL");
  });

  it("returns last-known-good status with a paused notice after 429", async () => {
    const request = vi
      .fn()
      .mockResolvedValueOnce({
        success: true,
        data: {
          connected: true,
          eligibleForPrinting: true,
          selectedPrinterId: "zdesigner-zt410",
          selectedPrinterName: "ZDesigner ZT410-300dpi ZPL",
        },
      })
      .mockResolvedValueOnce({
        success: false,
        status: 429,
        code: "RATE_LIMITED",
        retryAfterSec: 42,
        error: "Too many printer status requests. Please wait before retrying.",
      });
    const api = createPrintingApi(createCore(request));

    await api.getPrinterConnectionStatus({ force: true });
    const rateLimited = await api.getPrinterConnectionStatus({ force: true });

    expect(request).toHaveBeenCalledTimes(2);
    expect(rateLimited.success).toBe(true);
    expect(rateLimited.data?.selectedPrinterName).toBe("ZDesigner ZT410-300dpi ZPL");
    expect(rateLimited.data?.refreshPaused).toBe(true);
    expect(rateLimited.data?.notice).toBe("Printer status refresh is temporarily paused. Printing can continue if the printer was already ready.");
  });
});
