import React from "react";
import { act, fireEvent, render, renderHook, screen, waitFor } from "@testing-library/react";
import { QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import apiClient from "@/lib/api-client";
import { useBatchPrintWorkflow } from "@/features/batches/useBatchPrintWorkflow";
import { defaultPrinterStatus } from "@/features/batches/print-workflow-utils";
import { BatchPrintJobDialog } from "@/features/batches/components/BatchDialogs";
import { queryClient } from "@/lib/query-client";
import type { BatchRow } from "@/features/batches/types";

vi.mock("@/lib/api-client", () => ({ default: new Proxy({
  getPrinterConnectionStatus: vi.fn(), getLocalPrintAgentStatus: vi.fn(),
  listRegisteredPrinters: vi.fn(), listPrintJobs: vi.fn(), createPrintJob: vi.fn(),
}, { get: (target, key) => key in target ? target[key as keyof typeof target] : vi.fn() }) }));

type RemoteStatus = NonNullable<Awaited<ReturnType<typeof apiClient.getPrinterConnectionStatus>>["data"]>;
type LocalStatus = NonNullable<Awaited<ReturnType<typeof apiClient.getLocalPrintAgentStatus>>["data"]>;

const verified: RemoteStatus = { ...defaultPrinterStatus, connected: true, trusted: true, eligibleForPrinting: true,
  securePrinterSession: true, freshHelperHeartbeat: true, helperConnection: true, eligiblePrinter: true,
  stale: false, connectionClass: "TRUSTED", registrationId: "registration-1", selectedPrinterId: "queue-1",
  printerId: "queue-1", selectedPrinterName: "Generic ZPL printer", trustStatus: "TRUSTED",
  requiredForPrinting: true, lastHeartbeatAt: "2026-10-28T12:00:00.000Z", ageSeconds: 0 };
const printer = { printerId: "queue-1", printerName: "Generic ZPL printer", online: true };
const localStatus: LocalStatus = {
  connected: true, printerName: printer.printerName, printerId: printer.printerId,
  selectedPrinterId: printer.printerId, selectedPrinterName: printer.printerName,
  deviceName: null, agentVersion: "2026.6.26", protocolVersion: null,
  buildVersion: "2026.6.26", transportDiagnosticsVersion: null,
  capabilities: null, error: null, agentId: null, deviceFingerprint: null,
  publicKeyPem: null, clientCertFingerprint: null, heartbeatNonce: null,
  heartbeatIssuedAt: null, heartbeatSignature: null, compatibilityMode: false,
  websocket: null, capabilitySummary: null, printers: [printer], calibrationProfile: null,
};
const profile = { id: "profile-1", name: "Generic ZPL printer", connectionType: "LOCAL_AGENT",
  commandLanguage: "ZPL", nativePrinterId: "queue-1", printerRegistrationId: "registration-1",
  isActive: true, isDefault: true };
const batch: BatchRow = { id: "batch-1", name: "Batch 1", licenseeId: "licensee-1",
  startCode: "A", endCode: "Z", totalCodes: 10, printedAt: null, createdAt: "2026-10-28T00:00:00.000Z" };

const useWorkflow = () => useBatchPrintWorkflow({ isManufacturer: true, userId: "manufacturer-1",
  toast: vi.fn(), getAvailableInventory: () => 10 });

function MountedPrintDialog() {
  const workflow = useWorkflow();
  return <>
    <button onClick={() => workflow.openPrintPack(batch)}>Open print run</button>
    <span data-testid="selected-profile">{workflow.dialogProps.selectedPrinterProfileId}</span>
    <MemoryRouter><BatchPrintJobDialog {...workflow.dialogProps} isManufacturerMode /></MemoryRouter>
  </>;
}

const mount = () => {
  const wrapper = ({ children }: { children: React.ReactNode }) =>
    <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>;
  return renderHook(useWorkflow, { wrapper });
};

describe("Start print run dialogue lifecycle", () => {
  beforeEach(() => {
    queryClient.clear();
    vi.clearAllMocks();
    vi.mocked(apiClient.getPrinterConnectionStatus).mockResolvedValue({ success: true, data: verified });
    vi.mocked(apiClient.getLocalPrintAgentStatus).mockResolvedValue({ success: true, data: localStatus });
    vi.mocked(apiClient.listRegisteredPrinters).mockResolvedValue({ success: true, data: [profile] });
    vi.mocked(apiClient.listPrintJobs).mockResolvedValue({ success: true, data: [] });
  });
  afterEach(() => vi.clearAllMocks());

  it("opens without submitting and performs one forced status verification", async () => {
    const view = mount();
    await waitFor(() => expect(apiClient.getPrinterConnectionStatus).toHaveBeenCalled());
    vi.mocked(apiClient.getPrinterConnectionStatus).mockClear();
    act(() => view.result.current.openPrintPack(batch));
    await waitFor(() => expect(apiClient.getPrinterConnectionStatus).toHaveBeenCalledTimes(1));
    expect(view.result.current.dialogProps.open).toBe(true);
    expect(apiClient.createPrintJob).not.toHaveBeenCalled();
    view.unmount();
  });

  it("mounts the real dialog, verifies once on opening, and never submits a job", async () => {
    const view = render(<QueryClientProvider client={queryClient}><MountedPrintDialog /></QueryClientProvider>);
    await waitFor(() => expect(apiClient.getPrinterConnectionStatus).toHaveBeenCalled());
    vi.mocked(apiClient.getPrinterConnectionStatus).mockClear();
    fireEvent.click(screen.getByRole("button", { name: "Open print run" }));
    await waitFor(() => expect(screen.getByRole("dialog")).toBeInTheDocument());
    await waitFor(() => expect(apiClient.getPrinterConnectionStatus).toHaveBeenCalledTimes(1));
    expect(apiClient.createPrintJob).not.toHaveBeenCalled();
    view.unmount();
  });

  it.each([401, 429, 500])("renders verification unavailable in the mounted dialog after HTTP %i", async (status) => {
    const view = render(<QueryClientProvider client={queryClient}><MountedPrintDialog /></QueryClientProvider>);
    await waitFor(() => expect(screen.getByTestId("selected-profile")).toHaveTextContent("profile-1"));
    vi.mocked(apiClient.getPrinterConnectionStatus).mockResolvedValueOnce({ success: false, status,
      error: "Verification unavailable" });
    fireEvent.click(screen.getByRole("button", { name: "Open print run" }));
    await waitFor(() => expect(screen.getByText("Printer verification unavailable.")).toBeInTheDocument());
    expect(screen.getByTestId("print-job-start-button")).toBeDisabled();
    expect(apiClient.createPrintJob).not.toHaveBeenCalled();
    view.unmount();
  });

  it("keeps a matching verified printer eligible in the mounted dialog", async () => {
    const view = render(<QueryClientProvider client={queryClient}><MountedPrintDialog /></QueryClientProvider>);
    await waitFor(() => expect(screen.getByTestId("selected-profile")).toHaveTextContent("profile-1"));
    fireEvent.click(screen.getByRole("button", { name: "Open print run" }));
    await waitFor(() => expect(screen.getByTestId("print-job-start-button")).not.toBeDisabled());
    expect(apiClient.createPrintJob).not.toHaveBeenCalled();
    view.unmount();
  });

  it("does not expire verification when the already selected printer is selected again", async () => {
    const view = mount();
    await waitFor(() => expect(view.result.current.dialogProps.selectedPrinterProfileId).toBe("profile-1"));
    act(() => view.result.current.openPrintPack(batch));
    await waitFor(() => expect(view.result.current.dialogProps.selectedPrinterCanPrint).toBe(true));
    act(() => view.result.current.dialogProps.onSelectedPrinterProfileIdChange("profile-1"));
    expect(view.result.current.dialogProps.selectedPrinterCanPrint).toBe(true);
    expect(apiClient.createPrintJob).not.toHaveBeenCalled();
    view.unmount();
  });

  it("keeps connected hardware blocked when the mounted dialog sees expired attestation", async () => {
    const view = render(<QueryClientProvider client={queryClient}><MountedPrintDialog /></QueryClientProvider>);
    await waitFor(() => expect(screen.getByTestId("selected-profile")).toHaveTextContent("profile-1"));
    vi.mocked(apiClient.getPrinterConnectionStatus).mockResolvedValueOnce({ success: true,
      data: { ...verified, trusted: true, eligibleForPrinting: false, stale: false,
        signedAttestation: { required: true, present: true, signatureValid: true, fresh: false },
        trustReason: "Printer attestation expired" } });
    fireEvent.click(screen.getByRole("button", { name: "Open print run" }));
    await waitFor(() => expect(screen.getByText(/Printer security verification expired/i)).toBeInTheDocument());
    expect(screen.getByTestId("print-job-start-button")).toBeDisabled();
    expect(apiClient.createPrintJob).not.toHaveBeenCalled();
    view.unmount();
  });

  it("recovers in the same mounted dialog after a transient server failure", async () => {
    const view = render(<QueryClientProvider client={queryClient}><MountedPrintDialog /></QueryClientProvider>);
    await waitFor(() => expect(screen.getByTestId("selected-profile")).toHaveTextContent("profile-1"));
    vi.mocked(apiClient.getPrinterConnectionStatus).mockResolvedValueOnce({ success: false, status: 500 });
    fireEvent.click(screen.getByRole("button", { name: "Open print run" }));
    await waitFor(() => expect(screen.getByText("Printer verification unavailable.")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Retry printer verification" }));
    await waitFor(() => expect(screen.getByTestId("print-job-start-button")).not.toBeDisabled());
    expect(apiClient.createPrintJob).not.toHaveBeenCalled();
    view.unmount();
  });

  it("presents pending verification while the mounted dialog waits for the server", async () => {
    const view = render(<QueryClientProvider client={queryClient}><MountedPrintDialog /></QueryClientProvider>);
    await waitFor(() => expect(screen.getByTestId("selected-profile")).toHaveTextContent("profile-1"));
    let finish: ((value: Awaited<ReturnType<typeof apiClient.getPrinterConnectionStatus>>) => void) | undefined;
    vi.mocked(apiClient.getPrinterConnectionStatus).mockImplementationOnce(() =>
      new Promise((resolve) => { finish = resolve; }));
    fireEvent.click(screen.getByRole("button", { name: "Open print run" }));
    await waitFor(() => expect(finish).toBeDefined());
    expect(screen.getByText(/Checking current printer verification/i)).toBeInTheDocument();
    expect(screen.getByTestId("print-job-start-button")).toBeDisabled();
    expect(screen.getByRole("button", { name: "Retry printer verification" })).toBeDisabled();
    expect(apiClient.createPrintJob).not.toHaveBeenCalled();
    await act(async () => { finish?.({ success: false, status: 429, error: "Rate limited" }); });
    expect(screen.getByTestId("print-job-start-button")).toBeDisabled();
    view.unmount();
  });

  it.each([401, 429, 500])("blocks printing when dialogue verification returns %i", async (status) => {
    const view = mount();
    await waitFor(() => expect(apiClient.getPrinterConnectionStatus).toHaveBeenCalled());
    vi.mocked(apiClient.getPrinterConnectionStatus).mockResolvedValueOnce({ success: false, status, error: "Verification unavailable" });
    act(() => view.result.current.openPrintPack(batch));
    await waitFor(() => expect(view.result.current.dialogProps.selectedPrinterCanPrint).toBe(false));
    await waitFor(() => expect(view.result.current.dialogProps.securePrintReadiness.reasonCode).toBe("VERIFICATION_UNAVAILABLE"));
    expect(apiClient.createPrintJob).not.toHaveBeenCalled();
    view.unmount();
  });

  it("keeps connected hardware blocked after attestation expires and recovers on refresh", async () => {
    const view = mount();
    await waitFor(() => expect(apiClient.getPrinterConnectionStatus).toHaveBeenCalled());
    vi.mocked(apiClient.getPrinterConnectionStatus).mockResolvedValueOnce({ success: true,
      data: { ...verified, trusted: false, eligibleForPrinting: false, stale: true,
        trustReason: "Printer attestation stale" } });
    act(() => view.result.current.openPrintPack(batch));
    await waitFor(() => expect(view.result.current.dialogProps.selectedPrinterCanPrint).toBe(false));
    expect(apiClient.createPrintJob).not.toHaveBeenCalled();
    act(() => view.result.current.dialogProps.onRefreshPrinters());
    await waitFor(() => expect(apiClient.getPrinterConnectionStatus).toHaveBeenCalledTimes(3));
    view.unmount();
  });

  it("ignores a delayed ready response after the tab becomes hidden", async () => {
    const view = mount();
    await waitFor(() => expect(apiClient.getPrinterConnectionStatus).toHaveBeenCalled());
    let finish: ((value: { success: boolean; data: typeof verified }) => void) | undefined;
    vi.mocked(apiClient.getPrinterConnectionStatus).mockImplementationOnce(() =>
      new Promise((resolve) => { finish = resolve as typeof finish; }));
    act(() => view.result.current.openPrintPack(batch));
    await waitFor(() => expect(finish).toBeDefined());
    Object.defineProperty(document, "visibilityState", { configurable: true, value: "hidden" });
    act(() => document.dispatchEvent(new Event("visibilitychange")));
    await act(async () => { finish?.({ success: true, data: verified }); });
    expect(view.result.current.dialogProps.selectedPrinterCanPrint).toBe(false);
    Object.defineProperty(document, "visibilityState", { configurable: true, value: "visible" });
    view.unmount();
  });

  it("ignores an old ready response after the selected device changes", async () => {
    const view = mount();
    await waitFor(() => expect(view.result.current.dialogProps.selectedPrinterProfileId).toBe("profile-1"));
    let finish: ((value: Awaited<ReturnType<typeof apiClient.getPrinterConnectionStatus>>) => void) | undefined;
    vi.mocked(apiClient.getPrinterConnectionStatus).mockImplementationOnce(() =>
      new Promise((resolve) => { finish = resolve; }));
    act(() => view.result.current.openPrintPack(batch));
    await waitFor(() => expect(finish).toBeDefined());
    act(() => view.result.current.dialogProps.onSelectedPrinterIdChange("another-queue"));
    await act(async () => { finish?.({ success: true, data: verified }); });
    expect(view.result.current.dialogProps.securePrintReadiness.ready).toBe(false);
    expect(view.result.current.dialogProps.selectedPrinterCanPrint).toBe(false);
    expect(apiClient.createPrintJob).not.toHaveBeenCalled();
    view.unmount();
  });

  it("reverifies a saved-profile change instead of leaving the opening request invalidated", async () => {
    const alternative = { ...profile, id: "profile-alternative", isDefault: false };
    vi.mocked(apiClient.listRegisteredPrinters).mockResolvedValue({ success: true, data: [profile, alternative] });
    const view = mount();
    await waitFor(() => expect(view.result.current.dialogProps.selectedPrinterProfileId).toBe("profile-1"));
    act(() => view.result.current.openPrintPack(batch));
    await waitFor(() => expect(view.result.current.dialogProps.selectedPrinterCanPrint).toBe(true));
    act(() => view.result.current.dialogProps.onSelectedPrinterProfileIdChange(alternative.id));
    await waitFor(() => expect(view.result.current.dialogProps.selectedPrinterCanPrint).toBe(true));
    expect(view.result.current.dialogProps.selectedPrinterProfileId).toBe(alternative.id);
    expect(apiClient.createPrintJob).not.toHaveBeenCalled();
    view.unmount();
  });

  it("blocks a saved profile when fresh status belongs to another selected queue", async () => {
    const secondPrinter = { printerId: "queue-2", printerName: "Another ZPL printer", online: true };
    const secondProfile = { ...profile, id: "profile-2", name: secondPrinter.printerName,
      nativePrinterId: secondPrinter.printerId };
    vi.mocked(apiClient.getLocalPrintAgentStatus).mockResolvedValue({ success: true,
      data: { ...localStatus, printers: [printer, secondPrinter] } });
    vi.mocked(apiClient.listRegisteredPrinters).mockResolvedValue({ success: true,
      data: [profile, secondProfile] });
    const view = mount();
    await waitFor(() => expect(view.result.current.dialogProps.selectedPrinterProfileId).toBe("profile-1"));
    act(() => {
      view.result.current.dialogProps.onSelectedPrinterIdChange("queue-2");
      view.result.current.dialogProps.onSelectedPrinterProfileIdChange("profile-2");
    });
    await waitFor(() => expect(apiClient.getPrinterConnectionStatus).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(view.result.current.dialogProps.selectedPrinterCanPrint).toBe(false));
    act(() => view.result.current.openPrintPack(batch));
    await waitFor(() => expect(apiClient.getPrinterConnectionStatus).toHaveBeenCalledTimes(3));
    expect(view.result.current.dialogProps.selectedPrinterProfileId).toBe("profile-2");
    expect(view.result.current.dialogProps.selectedPrinterCanPrint).toBe(false);
    expect(apiClient.createPrintJob).not.toHaveBeenCalled();
    view.unmount();
  });

  it("closes the dialog and invalidates old verification when the account changes", async () => {
    const wrapper = ({ children }: { children: React.ReactNode }) =>
      <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>;
    const view = renderHook(({ manufacturerId }) => useBatchPrintWorkflow({
      isManufacturer: true, userId: manufacturerId, toast: vi.fn(), getAvailableInventory: () => 10,
    }), { wrapper, initialProps: { manufacturerId: "manufacturer-1" } });
    await waitFor(() => expect(view.result.current.dialogProps.securePrintReadiness.ready).toBe(true));
    act(() => view.result.current.openPrintPack(batch));
    await waitFor(() => expect(view.result.current.dialogProps.open).toBe(true));
    view.rerender({ manufacturerId: "manufacturer-2" });
    expect(view.result.current.dialogProps.open).toBe(false);
    expect(view.result.current.dialogProps.securePrintReadiness.ready).toBe(false);
    expect(view.result.current.dialogProps.selectedPrinterCanPrint).toBe(false);
    view.unmount();
  });

  it("revalidates on visibility restoration and recovers after a failed check", async () => {
    const view = mount();
    await waitFor(() => expect(apiClient.getPrinterConnectionStatus).toHaveBeenCalled());
    act(() => view.result.current.openPrintPack(batch));
    await waitFor(() => expect(view.result.current.dialogProps.securePrintReadiness.ready).toBe(true));
    Object.defineProperty(document, "visibilityState", { configurable: true, value: "hidden" });
    act(() => document.dispatchEvent(new Event("visibilitychange")));
    expect(view.result.current.dialogProps.securePrintReadiness.ready).toBe(false);
    vi.mocked(apiClient.getPrinterConnectionStatus).mockResolvedValueOnce({ success: false, status: 500, error: "Unavailable" });
    Object.defineProperty(document, "visibilityState", { configurable: true, value: "visible" });
    act(() => document.dispatchEvent(new Event("visibilitychange")));
    await waitFor(() => expect(view.result.current.dialogProps.securePrintReadiness.ready).toBe(false));
    act(() => view.result.current.dialogProps.onRefreshPrinters());
    await waitFor(() => expect(view.result.current.dialogProps.securePrintReadiness.ready).toBe(true));
    view.unmount();
  });

  it("does not restore an older ready query snapshot when the dialog closes after failed verification", async () => {
    const view = mount();
    await waitFor(() => expect(view.result.current.dialogProps.securePrintReadiness.ready).toBe(true));
    vi.mocked(apiClient.getPrinterConnectionStatus).mockResolvedValueOnce({ success: false,
      status: 500, error: "Verification unavailable" });
    act(() => view.result.current.openPrintPack(batch));
    await waitFor(() => expect(view.result.current.dialogProps.securePrintReadiness.ready).toBe(false));
    act(() => view.result.current.dialogProps.onClose());
    expect(view.result.current.dialogProps.securePrintReadiness.ready).toBe(false);
    view.unmount();
  });

  it("requires a new verification when a previously ready dialog is reopened", async () => {
    const view = mount();
    await waitFor(() => expect(view.result.current.dialogProps.selectedPrinterProfileId).toBe("profile-1"));
    act(() => view.result.current.openPrintPack(batch));
    await waitFor(() => expect(view.result.current.dialogProps.securePrintReadiness.ready).toBe(true));
    act(() => view.result.current.dialogProps.onClose());
    let finish: ((value: Awaited<ReturnType<typeof apiClient.getPrinterConnectionStatus>>) => void) | undefined;
    vi.mocked(apiClient.getPrinterConnectionStatus).mockImplementationOnce(() =>
      new Promise((resolve) => { finish = resolve; }));
    act(() => view.result.current.openPrintPack(batch));
    await waitFor(() => expect(finish).toBeDefined());
    expect(view.result.current.dialogProps.securePrintReadiness.ready).toBe(false);
    await act(async () => { finish?.({ success: false, status: 500 }); });
    expect(view.result.current.dialogProps.securePrintReadiness.reasonCode).toBe("VERIFICATION_UNAVAILABLE");
    expect(apiClient.createPrintJob).not.toHaveBeenCalled();
    view.unmount();
  });
});
