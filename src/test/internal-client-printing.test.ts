import { describe, expect, it, vi } from "vitest";

import { createPrintingApi } from "@/lib/api/internal-client-printing";
import type { ApiClientCore, ApiResponse } from "@/lib/api/internal-client-core";

type RequestPayload = {
  connected?: boolean;
  eligibleForPrinting?: boolean;
  selectedPrinterId?: string;
  selectedPrinterName?: string;
};

const createCore = (request: (endpoint: string) => Promise<ApiResponse<unknown>>): ApiClientCore => ({
  setToken: vi.fn(),
  getToken: () => null,
  logout: vi.fn(),
  request: <T>(endpoint: string) => request(endpoint) as Promise<ApiResponse<T>>,
});

describe("printing api request control", () => {
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
