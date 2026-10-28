import { act, renderHook, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import apiClient from "@/lib/api-client";
import { useManufacturerPrinterConnection } from "@/features/layout/useManufacturerPrinterConnection";
import { defaultPrinterStatus } from "@/features/layout/manufacturerPrinterConnectionUtils";
import type { User } from "@/types";

vi.mock("@/lib/api-client", () => ({ default: new Proxy({
  listRegisteredPrinters: vi.fn(), streamPrinterConnectionStatus: vi.fn(),
  getLocalPrintAgentStatus: vi.fn(), reportPrinterHeartbeat: vi.fn(),
  getPrinterConnectionStatus: vi.fn(),
}, { get: (target, key) => key in target ? target[key as keyof typeof target] : vi.fn() }) }));

const user = { id: "manufacturer-1", role: "manufacturer" } as User;
const ready = { ...defaultPrinterStatus, connected: true, trusted: true, eligibleForPrinting: true,
  securePrinterSession: true, freshHelperHeartbeat: true, helperConnection: true, eligiblePrinter: true,
  stale: false, connectionClass: "TRUSTED" as const, trustStatus: "TRUSTED" };
const expired = { ...ready, trusted: false, eligibleForPrinting: false, stale: true,
  trustReason: "Printer attestation expired" };

describe("manufacturer header event ordering", () => {
  let snapshot: Parameters<typeof apiClient.streamPrinterConnectionStatus>[0];
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(apiClient.listRegisteredPrinters).mockResolvedValue({ success: true, data: [] });
    vi.mocked(apiClient.streamPrinterConnectionStatus).mockImplementation((onSnapshot) => {
      snapshot = onSnapshot;
      return () => undefined;
    });
  });

  it("does not let an older ready event undo newer expired verification", async () => {
    const view = renderHook(() => useManufacturerPrinterConnection({ user, contextualHelpRoute: "/",
      currentPath: "/", navigate: vi.fn(), toast: vi.fn() }));
    await waitFor(() => expect(snapshot).toBeDefined());
    act(() => snapshot({ serverTime: "2026-10-28T12:00:02.000Z", status: expired }));
    expect(view.result.current.securePrintReadiness.ready).toBe(false);
    act(() => snapshot({ serverTime: "2026-10-28T12:00:01.000Z", status: ready }));
    expect(view.result.current.securePrintReadiness.ready).toBe(false);
    view.unmount();
  });

  it("does not promise Ready for a different locally selected printer", async () => {
    const view = renderHook(() => useManufacturerPrinterConnection({ user, contextualHelpRoute: "/",
      currentPath: "/", navigate: vi.fn(), toast: vi.fn() }));
    await waitFor(() => expect(snapshot).toBeDefined());
    act(() => snapshot({ serverTime: "2026-10-28T12:00:01.000Z", status: {
      ...ready, selectedPrinterId: "queue-1", printerId: "queue-1",
      printers: [{ printerId: "queue-1", printerName: "Printer 1" },
        { printerId: "queue-2", printerName: "Printer 2" }] } }));
    expect(view.result.current.securePrintReadiness.ready).toBe(true);
    act(() => view.result.current.setSelectedLocalPrinterId("queue-2"));
    expect(view.result.current.securePrintReadiness.ready).toBe(false);
    view.unmount();
  });

  it.each([
    { label: "success", eventStatus: expired, reply: { success: true, data: ready }, expected: false },
    { label: "failure", eventStatus: ready, reply: { success: false, status: 500 }, expected: true },
  ])("ignores an older $label response after a newer event", async ({ eventStatus, reply, expected }) => {
    vi.mocked(apiClient.getLocalPrintAgentStatus).mockResolvedValue({ success: false, error: "Unavailable" });
    vi.mocked(apiClient.reportPrinterHeartbeat).mockResolvedValue({ success: false, error: "Unavailable" });
    let finish: ((value: Awaited<ReturnType<typeof apiClient.getPrinterConnectionStatus>>) => void) | undefined;
    vi.mocked(apiClient.getPrinterConnectionStatus).mockImplementationOnce(() =>
      new Promise((resolve) => { finish = resolve; }));
    const view = renderHook(() => useManufacturerPrinterConnection({ user, contextualHelpRoute: "/",
      currentPath: "/", navigate: vi.fn(), toast: vi.fn() }));
    act(() => view.result.current.refreshPrinterConnectionStatus());
    await waitFor(() => expect(finish).toBeDefined());
    act(() => snapshot({ serverTime: "2026-10-28T12:00:03.000Z", status: eventStatus }));
    await act(async () => { finish?.(reply); });
    expect(view.result.current.securePrintReadiness.ready).toBe(expected);
    view.unmount();
  });

  it("does not let an older status response undo a later stream failure", async () => {
    let onError: (() => void) | undefined;
    vi.mocked(apiClient.streamPrinterConnectionStatus).mockImplementation((onSnapshot, error) => {
      snapshot = onSnapshot;
      onError = error;
      return () => undefined;
    });
    vi.mocked(apiClient.getLocalPrintAgentStatus).mockResolvedValue({ success: false, error: "Unavailable" });
    vi.mocked(apiClient.reportPrinterHeartbeat).mockResolvedValue({ success: false, error: "Unavailable" });
    let finishOld: ((value: Awaited<ReturnType<typeof apiClient.getPrinterConnectionStatus>>) => void) | undefined;
    vi.mocked(apiClient.getPrinterConnectionStatus).mockImplementationOnce(() =>
      new Promise((resolve) => { finishOld = resolve; }));
    const view = renderHook(() => useManufacturerPrinterConnection({ user, contextualHelpRoute: "/",
      currentPath: "/", navigate: vi.fn(), toast: vi.fn() }));
    act(() => view.result.current.refreshPrinterConnectionStatus());
    await waitFor(() => expect(finishOld).toBeDefined());
    act(() => onError?.());
    await act(async () => { finishOld?.({ success: true, data: ready }); });
    expect(view.result.current.securePrintReadiness.ready).toBe(false);
    expect(view.result.current.securePrintReadiness.reasonCode).toBe("VERIFICATION_UNAVAILABLE");
    view.unmount();
  });

  it("rejects events from the previous tenant after the effective scope changes", async () => {
    const callbacks: Array<Parameters<typeof apiClient.streamPrinterConnectionStatus>[0]> = [];
    vi.mocked(apiClient.streamPrinterConnectionStatus).mockImplementation((onSnapshot) => {
      callbacks.push(onSnapshot);
      return () => undefined;
    });
    const tenantA = { ...user, licenseeId: "tenant-a" } as User;
    const tenantB = { ...user, licenseeId: "tenant-b" } as User;
    const view = renderHook(({ currentUser }) => useManufacturerPrinterConnection({ user: currentUser,
      contextualHelpRoute: "/", currentPath: "/", navigate: vi.fn(), toast: vi.fn() }),
    { initialProps: { currentUser: tenantA } });
    await waitFor(() => expect(callbacks).toHaveLength(1));
    act(() => callbacks[0]({ serverTime: "2026-10-28T12:00:01.000Z", status: ready }));
    expect(view.result.current.securePrintReadiness.ready).toBe(true);
    view.rerender({ currentUser: tenantB });
    await waitFor(() => expect(callbacks).toHaveLength(2));
    expect(view.result.current.securePrintReadiness.ready).toBe(false);
    act(() => callbacks[0]({ serverTime: "2026-10-28T12:00:03.000Z", status: ready }));
    expect(view.result.current.securePrintReadiness.ready).toBe(false);
    act(() => callbacks[1]({ serverTime: "2026-10-28T12:00:04.000Z", status: expired }));
    expect(view.result.current.securePrintReadiness.ready).toBe(false);
    view.unmount();
  });

  it("does not install an older tenant's delayed printer profiles after a scope change", async () => {
    let finishOld: ((value: Awaited<ReturnType<typeof apiClient.listRegisteredPrinters>>) => void) | undefined;
    vi.mocked(apiClient.listRegisteredPrinters)
      .mockImplementationOnce(() => new Promise((resolve) => { finishOld = resolve; }))
      .mockResolvedValue({ success: true, data: [{ id: "printer-b", name: "Tenant B printer",
        connectionType: "NETWORK_DIRECT", isActive: true }] });
    const tenantA = { ...user, licenseeId: "tenant-a" } as User;
    const tenantB = { ...user, licenseeId: "tenant-b" } as User;
    const view = renderHook(({ currentUser }) => useManufacturerPrinterConnection({ user: currentUser,
      contextualHelpRoute: "/", currentPath: "/", navigate: vi.fn(), toast: vi.fn() }),
    { initialProps: { currentUser: tenantA } });
    await waitFor(() => expect(finishOld).toBeDefined());
    view.rerender({ currentUser: tenantB });
    await waitFor(() => expect(view.result.current.managedNetworkPrinters[0]?.id).toBe("printer-b"));
    await act(async () => { finishOld?.({ success: true, data: [{ id: "printer-a", name: "Tenant A printer",
      connectionType: "NETWORK_DIRECT", isActive: true }] }); });
    expect(view.result.current.managedNetworkPrinters.map((printer) => printer.id)).toEqual(["printer-b"]);
    view.unmount();
  });

  it("blocks stale readiness on stream loss and stops fallback polling after reconnect", async () => {
    vi.useFakeTimers();
    let onError: (() => void) | undefined;
    let onOpen: (() => void) | undefined;
    vi.mocked(apiClient.streamPrinterConnectionStatus).mockImplementation((onSnapshot, error, open) => {
      snapshot = onSnapshot;
      onError = error;
      onOpen = open;
      return () => undefined;
    });
    vi.mocked(apiClient.getLocalPrintAgentStatus).mockResolvedValue({ success: false, error: "Unavailable" });
    vi.mocked(apiClient.reportPrinterHeartbeat).mockResolvedValue({ success: false, error: "Unavailable" });
    vi.mocked(apiClient.getPrinterConnectionStatus).mockResolvedValue({ success: false, status: 503 });
    const view = renderHook(() => useManufacturerPrinterConnection({ user, contextualHelpRoute: "/",
      currentPath: "/", navigate: vi.fn(), toast: vi.fn() }));
    act(() => snapshot({ serverTime: "2026-10-28T12:00:01.000Z", status: ready }));
    expect(view.result.current.securePrintReadiness.ready).toBe(true);
    act(() => onError?.());
    expect(view.result.current.securePrintReadiness.reasonCode).toBe("VERIFICATION_UNAVAILABLE");
    await act(async () => { await vi.advanceTimersByTimeAsync(60_000); });
    expect(apiClient.getPrinterConnectionStatus).toHaveBeenCalledTimes(1);
    act(() => onOpen?.());
    await act(async () => { await vi.advanceTimersByTimeAsync(120_000); });
    expect(apiClient.getPrinterConnectionStatus).toHaveBeenCalledTimes(1);
    act(() => snapshot({ serverTime: "2026-10-28T12:03:01.000Z", status: ready }));
    expect(view.result.current.securePrintReadiness.ready).toBe(true);
    view.unmount();
    vi.useRealTimers();
  });

  it("does not reauthorize the header from events received while the tab is hidden", async () => {
    vi.mocked(apiClient.getLocalPrintAgentStatus).mockResolvedValue({ success: false, error: "Unavailable" });
    vi.mocked(apiClient.reportPrinterHeartbeat).mockResolvedValue({ success: false, error: "Unavailable" });
    vi.mocked(apiClient.getPrinterConnectionStatus).mockResolvedValue({ success: false, status: 503 });
    const view = renderHook(() => useManufacturerPrinterConnection({ user, contextualHelpRoute: "/",
      currentPath: "/", navigate: vi.fn(), toast: vi.fn() }));
    await waitFor(() => expect(snapshot).toBeDefined());
    act(() => snapshot({ serverTime: "2026-10-28T12:00:01.000Z", status: ready }));
    expect(view.result.current.securePrintReadiness.ready).toBe(true);
    Object.defineProperty(document, "visibilityState", { configurable: true, value: "hidden" });
    act(() => document.dispatchEvent(new Event("visibilitychange")));
    expect(view.result.current.securePrintReadiness.ready).toBe(false);
    act(() => snapshot({ serverTime: "2026-10-28T12:00:02.000Z", status: ready }));
    expect(view.result.current.securePrintReadiness.ready).toBe(false);
    Object.defineProperty(document, "visibilityState", { configurable: true, value: "visible" });
    act(() => document.dispatchEvent(new Event("visibilitychange")));
    await waitFor(() => expect(apiClient.getPrinterConnectionStatus).toHaveBeenCalledTimes(1));
    expect(view.result.current.securePrintReadiness.ready).toBe(false);
    view.unmount();
  });

  it("starts a new verification after visibility returns while an older request is unresolved", async () => {
    vi.mocked(apiClient.getLocalPrintAgentStatus).mockResolvedValue({ success: false, error: "Unavailable" });
    vi.mocked(apiClient.reportPrinterHeartbeat).mockResolvedValue({ success: false, error: "Unavailable" });
    let finishOld: ((value: Awaited<ReturnType<typeof apiClient.getPrinterConnectionStatus>>) => void) | undefined;
    vi.mocked(apiClient.getPrinterConnectionStatus)
      .mockImplementationOnce(() => new Promise((resolve) => { finishOld = resolve; }))
      .mockResolvedValue({ success: true, data: ready });
    const view = renderHook(() => useManufacturerPrinterConnection({ user, contextualHelpRoute: "/",
      currentPath: "/", navigate: vi.fn(), toast: vi.fn() }));
    act(() => view.result.current.refreshPrinterConnectionStatus());
    await waitFor(() => expect(finishOld).toBeDefined());
    Object.defineProperty(document, "visibilityState", { configurable: true, value: "hidden" });
    act(() => document.dispatchEvent(new Event("visibilitychange")));
    Object.defineProperty(document, "visibilityState", { configurable: true, value: "visible" });
    act(() => document.dispatchEvent(new Event("visibilitychange")));
    await waitFor(() => expect(apiClient.getPrinterConnectionStatus).toHaveBeenCalledTimes(2));
    expect(view.result.current.securePrintReadiness.ready).toBe(true);
    await act(async () => { finishOld?.({ success: false, status: 500 }); });
    expect(view.result.current.securePrintReadiness.ready).toBe(true);
    view.unmount();
  });
});
