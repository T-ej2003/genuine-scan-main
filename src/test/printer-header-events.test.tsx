import { StrictMode, type ReactNode } from "react";
import { act, render, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import apiClient from "@/lib/api-client";
import { clearActivePrintSession, updateActivePrintSession } from "@/lib/active-print-session";
import { setRequestCoordinatorScope } from "@/lib/api/request-coordinator";
import { useManufacturerPrinterConnection } from "@/features/layout/useManufacturerPrinterConnection";
import { defaultPrinterStatus } from "@/features/layout/manufacturerPrinterConnectionUtils";
import { ManufacturerPrinterRuntimeProvider, useManufacturerPrinterRuntime } from "@/features/printing/manufacturer-printer-runtime";
import type { User } from "@/types";

vi.mock("@/lib/api-client", () => ({ default: {
  listRegisteredPrinters: vi.fn(), streamPrinterConnectionStatus: vi.fn(),
  getLocalPrintAgentStatus: vi.fn(), reportPrinterHeartbeat: vi.fn(),
  getPrinterConnectionStatus: vi.fn(), configureLocalPrintAgentBackend: vi.fn(),
  selectLocalPrinter: vi.fn(), createSupportIssueReport: vi.fn(),
} }));

const user = { id: "manufacturer-1", role: "manufacturer", licenseeId: "brand-a" } as User;
const printer = { printerId: "queue-1", printerName: "Factory printer", online: true };
type CloudReply = Awaited<ReturnType<typeof apiClient.getPrinterConnectionStatus>>;
type Stream = Parameters<typeof apiClient.streamPrinterConnectionStatus>;
const ready = () => ({
  ...defaultPrinterStatus, connected: true, trusted: true, eligibleForPrinting: true,
  securePrinterSession: true, freshHelperHeartbeat: true, helperConnection: true, eligiblePrinter: true,
  stale: false, connectionClass: "TRUSTED" as const, trustStatus: "TRUSTED",
  lastHeartbeatAt: new Date().toISOString(), registrationId: "reg-1", agentId: "agent-1",
  deviceFingerprint: "device-1", selectedPrinterId: printer.printerId, printerId: printer.printerId,
  printers: [printer],
  signedAttestation: { required: true, signatureValid: true, present: true, fresh: true, issuedAt: new Date().toISOString() },
});
const ok = (): CloudReply => ({ success: true, data: ready() });
const flush = () => act(async () => {});
const wrapper = ({ children }: { children: ReactNode }) =>
  <ManufacturerPrinterRuntimeProvider user={user}>{children}</ManufacturerPrinterRuntimeProvider>;
const useHeader = () => useManufacturerPrinterConnection({
  user, contextualHelpRoute: "/", currentPath: "/", navigate: vi.fn(), toast: vi.fn(),
});
const mount = () => renderHook(() => ({ header: useHeader(), runtime: useManufacturerPrinterRuntime()! }), { wrapper });

describe("shared manufacturer printer readiness", () => {
  let stream: Stream[0];
  let disconnect: Stream[1];
  let unsubscribe: ReturnType<typeof vi.fn<() => void>>;
  beforeEach(() => {
    vi.useFakeTimers();
    setRequestCoordinatorScope(user);
    unsubscribe = vi.fn();
    vi.mocked(apiClient.streamPrinterConnectionStatus).mockImplementation((onSnapshot, onError) => {
      stream = onSnapshot;
      disconnect = onError;
      return unsubscribe;
    });
    vi.mocked(apiClient.getPrinterConnectionStatus).mockImplementation(async () => ok());
    vi.mocked(apiClient.listRegisteredPrinters).mockResolvedValue({ success: true, data: [{
      id: "profile-1", name: printer.printerName, connectionType: "LOCAL_AGENT", isActive: true,
      nativePrinterId: printer.printerId, printerRegistrationId: "reg-1",
    }] } as Awaited<ReturnType<typeof apiClient.listRegisteredPrinters>>);
    vi.mocked(apiClient.getLocalPrintAgentStatus).mockResolvedValue({ success: true, data: {
      connected: true, selectedPrinterId: printer.printerId, agentId: "agent-1", deviceFingerprint: "device-1", printers: [printer],
    } } as Awaited<ReturnType<typeof apiClient.getLocalPrintAgentStatus>>);
    vi.mocked(apiClient.selectLocalPrinter).mockResolvedValue({ success: true, data: {} });
    vi.mocked(apiClient.configureLocalPrintAgentBackend).mockResolvedValue({ success: true, data: {} });
  });

  afterEach(() => {
    setRequestCoordinatorScope(null);
    clearActivePrintSession();
    vi.useRealTimers();
    vi.resetAllMocks();
  });

  it("serves the header and all route consumers from one owner through StrictMode, navigation and cleanup", async () => {
    let refresh!: () => Promise<unknown>;
    function Consumer() {
      const runtime = useManufacturerPrinterRuntime()!;
      refresh = () => runtime.refresh({ force: true });
      return <span>{String(runtime.snapshot.remoteStatus.trusted)}</span>;
    }
    function Header() { return <span>{String(useHeader().effectivePrinterReady)}</span>; }
    const app = (page: string, dialog = false) => <StrictMode><ManufacturerPrinterRuntimeProvider user={user}>
      <Header /><Consumer key={page} />{dialog && <Consumer />}
    </ManufacturerPrinterRuntimeProvider></StrictMode>;

    const view = render(app("dashboard"));
    await flush();
    expect(view.getAllByText("true")).toHaveLength(2);
    view.rerender(app("batches"));
    view.rerender(app("batches", true));
    const first = refresh();
    expect(refresh()).toBe(first);
    await flush();
    expect(view.getAllByText("true")).toHaveLength(3);
    view.rerender(app("batches"));
    view.rerender(app("printing"));
    view.rerender(app("batches"));
    expect(apiClient.getPrinterConnectionStatus).toHaveBeenCalledTimes(2);
    expect(apiClient.getLocalPrintAgentStatus).toHaveBeenCalledTimes(2);
    expect(apiClient.listRegisteredPrinters).toHaveBeenCalledTimes(2);
    expect(apiClient.streamPrinterConnectionStatus).toHaveBeenCalledTimes(1);
    expect(apiClient.reportPrinterHeartbeat).not.toHaveBeenCalled();
    view.unmount();
    expect(unsubscribe).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(120_000);
    expect(apiClient.getPrinterConnectionStatus).toHaveBeenCalledTimes(2);
  });

  it("waits for a forced refresh behind an older compatible read without publishing the older evidence", async () => {
    const view = mount();
    await flush();
    let finish!: (value: CloudReply) => void;
    vi.mocked(apiClient.getPrinterConnectionStatus).mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
    let weak!: Promise<unknown>;
    let strong!: Promise<unknown>;
    act(() => {
      weak = view.result.current.runtime.refresh();
      strong = view.result.current.runtime.refresh({ force: true });
      expect(view.result.current.runtime.refresh({ force: true })).toBe(strong);
    });
    expect(view.result.current.header.securePrintReadiness.reasonCode).toBe("VERIFICATION_PENDING");
    expect(apiClient.getPrinterConnectionStatus).toHaveBeenCalledTimes(2);
    await act(async () => { finish(ok()); expect(await weak).toBeNull(); await strong; });
    expect(apiClient.getPrinterConnectionStatus).toHaveBeenCalledTimes(3);
    expect(apiClient.getPrinterConnectionStatus).toHaveBeenLastCalledWith({ force: true, minIntervalMs: 0 });
    expect(view.result.current.header.effectivePrinterReady).toBe(true);
  });

  it("invalidates an old in-flight reply on a physical selection change", async () => {
    const view = mount();
    await flush();
    let finish!: (value: CloudReply) => void;
    vi.mocked(apiClient.getPrinterConnectionStatus).mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
    act(() => { void view.result.current.runtime.refresh(); });
    act(() => { void view.result.current.runtime.changePrinter("queue-2"); });
    expect(view.result.current.header.effectivePrinterReady).toBe(false);
    await act(async () => finish(ok()));
    expect(apiClient.selectLocalPrinter).toHaveBeenCalledExactlyOnceWith("queue-2");
    expect(view.result.current.header.effectivePrinterReady).toBe(false);
  });

  it("ignores old responses and stream messages after the authenticated workspace changes and after logout", async () => {
    let finish!: (value: CloudReply) => void;
    vi.mocked(apiClient.getPrinterConnectionStatus).mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
    const Probe = ({ workspace }: { workspace: User }) => <ManufacturerPrinterRuntimeProvider user={workspace}><Readiness /></ManufacturerPrinterRuntimeProvider>;
    function Readiness() { return <span>{String(useManufacturerPrinterRuntime()!.snapshot.remoteStatus.trusted)}</span>; }
    const view = render(<Probe workspace={user} />);
    await flush();
    const oldStream = stream;
    const nextUser = { ...user, licenseeId: "brand-b", scopeVersion: "2" } as User;
    act(() => setRequestCoordinatorScope(nextUser));
    vi.mocked(apiClient.getPrinterConnectionStatus).mockResolvedValue({ success: false, status: 403 });
    view.rerender(<Probe workspace={nextUser} />);
    await flush();
    await act(async () => {
      finish(ok());
      oldStream({ serverTime: new Date().toISOString(), status: ready() });
    });
    expect(view.getByText("false")).toBeInTheDocument();
    expect(apiClient.streamPrinterConnectionStatus).toHaveBeenCalledTimes(2);
    act(() => setRequestCoordinatorScope(null));
    expect(view.getByText("false")).toBeInTheDocument();
    expect(unsubscribe).toHaveBeenCalledTimes(2);
  });

  it("invalidates on stream failure, rejects out-of-order events and falls back to one poll", async () => {
    const view = mount();
    await flush();
    const status = ready();
    act(() => stream({ serverTime: new Date().toISOString(), status }));
    act(() => disconnect?.());
    expect(view.result.current.header.securePrintReadiness.reasonCode).toBe("VERIFICATION_UNAVAILABLE");
    act(() => stream({ serverTime: new Date(Date.now() - 1000).toISOString(), status }));
    expect(view.result.current.header.effectivePrinterReady).toBe(false);
    await act(async () => { await vi.advanceTimersByTimeAsync(60_000); });
    expect(apiClient.getPrinterConnectionStatus).toHaveBeenCalledTimes(2);
    expect(view.result.current.header.effectivePrinterReady).toBe(true);
  });

  it("preserves saved profiles on transient roster failure and clears them on authorization denial", async () => {
    const view = mount();
    await flush();
    const profiles = view.result.current.runtime.snapshot.registeredPrinters;
    expect(profiles).toHaveLength(1);

    vi.mocked(apiClient.listRegisteredPrinters).mockResolvedValueOnce({ success: false, status: 503 });
    await act(async () => { await view.result.current.runtime.refresh({ force: true }); });
    expect(view.result.current.runtime.snapshot.registeredPrinters).toEqual(profiles);
    expect(view.result.current.runtime.snapshot.rosterUnavailable).toBe(true);
    expect(view.result.current.header.effectivePrinterReady).toBe(false);

    await act(async () => { await view.result.current.runtime.refresh({ force: true }); });
    expect(view.result.current.header.effectivePrinterReady).toBe(true);

    vi.mocked(apiClient.listRegisteredPrinters).mockResolvedValueOnce({ success: false, status: 403 });
    await act(async () => { await view.result.current.runtime.refresh({ force: true }); });
    expect(view.result.current.runtime.snapshot.registeredPrinters).toEqual([]);
    expect(view.result.current.header.effectivePrinterReady).toBe(false);
  });

  it.each([403, 429, 503])("blocks a failed HTTP %i refresh and permits a later fresh result", async status => {
    const view = mount();
    await flush();
    vi.mocked(apiClient.getPrinterConnectionStatus).mockResolvedValueOnce({ success: false, status });
    await act(async () => { await view.result.current.runtime.refresh({ force: true }); });
    expect(view.result.current.header.effectivePrinterReady).toBe(false);
    expect(view.result.current.header.securePrintReadiness.reasonCode).toBe("VERIFICATION_UNAVAILABLE");
    await act(async () => { await view.result.current.runtime.refresh({ force: true }); });
    expect(view.result.current.header.effectivePrinterReady).toBe(true);
  });

  it.each([
    ["invalid signature", () => ({ ...ready(), signedAttestation: { ...ready().signedAttestation, signatureValid: false } })],
    ["wrong device", () => ({ ...ready(), deviceFingerprint: "another-device" })],
    ["unsupported version", () => ({ ...ready(), connectorUpdateRequired: true })],
    ["expired signed evidence", () => ({ ...ready(), lastHeartbeatAt: new Date(Date.now() - 36_000).toISOString() })],
  ] as const)("fails closed for %s evidence", async (_label, status) => {
    vi.mocked(apiClient.getPrinterConnectionStatus).mockImplementation(async () => ({ success: true, data: status() }));
    const view = mount();
    await flush();
    expect(view.result.current.header.effectivePrinterReady).toBe(false);
  });

  it("blocks a disconnected local connector and requires a fresh bound snapshot to reconnect", async () => {
    const view = mount();
    await flush();
    vi.mocked(apiClient.getLocalPrintAgentStatus).mockResolvedValueOnce({ success: false, error: "Offline" });
    await act(async () => { await view.result.current.runtime.refresh({ force: true }); });
    expect(view.result.current.header.effectivePrinterReady).toBe(false);
    act(() => stream({ serverTime: new Date().toISOString(), status: ready() }));
    expect(view.result.current.header.effectivePrinterReady).toBe(false);
    await flush();
    expect(view.result.current.header.effectivePrinterReady).toBe(true);
  });

  it("lets trust expire without probing during an active print and refreshes after it settles", async () => {
    const view = mount();
    await flush();
    act(() => updateActivePrintSession({ jobId: "job-1", active: true, terminal: false }));
    await act(async () => {
      await view.result.current.runtime.refresh({ force: true });
      await vi.advanceTimersByTimeAsync(60_000);
    });
    expect(apiClient.getPrinterConnectionStatus).toHaveBeenCalledTimes(1);
    expect(view.result.current.header.effectivePrinterReady).toBe(false);
    expect(unsubscribe).toHaveBeenCalledTimes(1);
    act(() => clearActivePrintSession());
    await flush();
    expect(apiClient.getPrinterConnectionStatus).toHaveBeenCalledTimes(2);
    expect(view.result.current.header.effectivePrinterReady).toBe(true);
  });
});
