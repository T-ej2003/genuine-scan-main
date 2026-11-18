import React from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { act, render, screen } from "@testing-library/react";

import apiClient from "@/lib/api-client";
import { PrintProgressDialog } from "@/components/printing/PrintProgressDialog";
import { clearActivePrintSession, getActivePrintSessionSnapshot } from "@/lib/active-print-session";
import { useActivePrintJobPolling } from "@/features/batches/useActivePrintJobPolling";
import { getPrintJobRealtimeDebugState, resetPrintJobRealtimeStoreForTests } from "@/lib/print-job-realtime-store";
import { setRequestCoordinatorScope } from "@/lib/api/request-coordinator";

vi.mock("@/lib/api-client", () => ({
  default: {
    getPrintJobStatus: vi.fn(),
    streamPrintJobStatus: vi.fn(),
    createPrintJob: vi.fn(),
    resumePrintJob: vi.fn(),
  },
}));

const baseJob = {
  id: "job-live",
  status: "SENT",
  pipelineState: "PRINT_CONFIRMED",
  printMode: "LOCAL_AGENT",
  quantity: 10,
  itemCount: 10,
  createdAt: new Date().toISOString(),
  printer: { name: "ZDesigner ZT410-300dpi ZPL" },
  session: { status: "ACTIVE", totalItems: 10, confirmedItems: 4, remainingToPrint: 6 },
};

function PollingProbe({ job, open = true, showDialog = false, onRecentJobsRefresh }: {
  job: Record<string, unknown>; open?: boolean; showDialog?: boolean; onRecentJobsRefresh?: () => Promise<void>;
}) {
  const liveJob = useActivePrintJobPolling({
    printJobId: "job-live",
    printProgressOpen: open,
    printProgressPhase: "Local print session active",
    printProgressPrinted: 4,
    printProgressTotal: 10,
    printing: false,
    progressStateSetters: {
      setPrintProgressOpen: vi.fn(),
      setPrintProgressPhase: vi.fn(),
      setPrintProgressTotal: vi.fn(),
      setPrintProgressPrinted: vi.fn(),
      setPrintProgressRemaining: vi.fn(),
      setPrintProgressCurrentCode: vi.fn(),
      setPrintProgressError: vi.fn(),
      setPrintProgressNotice: vi.fn(),
      setPrintProgressPrinterName: vi.fn(),
      setPrintProgressDispatchMode: vi.fn(),
      setDirectRemainingToPrint: vi.fn(),
    },
    setPrintProgressNotice: vi.fn(),
    loadRecentPrintJobs: onRecentJobsRefresh || vi.fn(),
    onBatchesChanged: vi.fn(),
  });
  return <div>
    {String(job.id)}<span data-testid="live-job-status">{liveJob?.status || ""}</span>
    <span data-testid="live-job-confirmed">{liveJob?.session?.confirmedItems ?? ""}</span>
    <span data-testid="live-job-items">{liveJob?.items?.length ?? ""}</span>
    {showDialog ? <PrintProgressDialog open phase="Waiting for printer confirmation" total={10} printed={4} remaining={6} confirmedJob={liveJob} /> : null}
  </div>;
}

const confirmedBackendProjection = () => ({
  job: {
    id: "job-live", status: "CONFIRMED", pipelineState: "PRINT_CONFIRMED", printMode: "LOCAL_AGENT",
    quantity: 10, itemCount: 10, createdAt: baseJob.createdAt,
    updatedAt: new Date(Date.now() + 1_000).toISOString(),
  },
  session: { id: "session-live", printJobId: "job-live", status: "COMPLETED", totalItems: 10, confirmedItems: 10 },
  items: Array.from({ length: 10 }, (_, index) => ({
    id: `item-${index + 1}`, printSessionId: "session-live", state: "PRINT_CONFIRMED", printConfirmedAt: new Date().toISOString(),
  })),
});

const stoppedBackendProjection = () => ({
  job: { ...baseJob, status: "STOPPED", pipelineState: "STOPPED", updatedAt: new Date().toISOString() },
  session: { ...baseJob.session, status: "STOPPED", confirmedItems: 4 },
  items: [],
});

const stoppedStatusView = () => {
  const { job, session, items } = stoppedBackendProjection();
  return { ...job, session, items };
};

const confirmedStatusView = () => {
  const { job, session, items } = confirmedBackendProjection();
  return { ...job, session, items };
};

describe("active print job polling", () => {
  afterEach(() => {
    clearActivePrintSession();
    resetPrintJobRealtimeStoreForTests();
    setRequestCoordinatorScope(null);
    vi.useRealTimers();
    vi.clearAllMocks();
  });

  const flush = async () => {
    await act(async () => {
      await Promise.resolve();
      await Promise.resolve();
    });
  };

  it.each([
    ["PARTIALLY_COMPLETED status", { ...baseJob, status: "PARTIALLY_COMPLETED" }],
    ["STOPPED pipeline state", { ...baseJob, pipelineState: "STOPPED" }],
    ["STOPPED session status", { ...baseJob, session: { ...baseJob.session, status: "STOPPED" } }],
  ])("stops polling after %s", async (_label, job) => {
    vi.useFakeTimers();
    vi.mocked(apiClient.getPrintJobStatus).mockResolvedValue({ success: true, data: job } as any);

    render(<PollingProbe job={job} />);

    await flush();
    expect(apiClient.getPrintJobStatus).toHaveBeenCalledTimes(1);
    expect(getActivePrintSessionSnapshot()).toMatchObject({
      active: false,
      jobId: "job-live",
      modalOpen: true,
      terminal: true,
    });

    await act(async () => {
      await vi.advanceTimersByTimeAsync(30_000);
    });
    expect(apiClient.getPrintJobStatus).toHaveBeenCalledTimes(1);
  });

  it("uses a slow fallback polling interval instead of tight polling", async () => {
    vi.useFakeTimers();
    vi.mocked(apiClient.getPrintJobStatus).mockResolvedValue({ success: true, data: baseJob } as any);

    render(<PollingProbe job={baseJob} />);

    await flush();
    expect(apiClient.getPrintJobStatus).toHaveBeenCalledTimes(1);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(30_000);
    });
    expect(apiClient.getPrintJobStatus).toHaveBeenCalledTimes(1);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(40_000);
    });
    expect(apiClient.getPrintJobStatus).toHaveBeenCalledTimes(2);
  });

  it("backs fallback polling off on 429", async () => {
    vi.useFakeTimers();
    vi.mocked(apiClient.getPrintJobStatus)
      .mockResolvedValueOnce({ success: false, status: 429, retryAfterSec: 10, code: "RATE_LIMITED" } as any)
      .mockResolvedValue({ success: true, data: baseJob } as any);

    render(<PollingProbe job={baseJob} />);

    await flush();
    expect(apiClient.getPrintJobStatus).toHaveBeenCalledTimes(1);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(15_000);
    });
    expect(apiClient.getPrintJobStatus).toHaveBeenCalledTimes(1);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(55_000);
    });
    expect(apiClient.getPrintJobStatus).toHaveBeenCalledTimes(2);
  });

  it("continues tracking an active print job after the progress dialog is dismissed", async () => {
    vi.useFakeTimers();
    vi.mocked(apiClient.getPrintJobStatus).mockResolvedValue({ success: true, data: baseJob } as any);

    render(<PollingProbe job={baseJob} open={false} />);

    await flush();
    expect(apiClient.getPrintJobStatus).toHaveBeenCalledTimes(1);
    expect(getActivePrintSessionSnapshot()).toMatchObject({
      active: true,
      jobId: "job-live",
      modalOpen: false,
      terminal: false,
    });

    await act(async () => {
      await vi.advanceTimersByTimeAsync(70_000);
    });
    expect(apiClient.getPrintJobStatus).toHaveBeenCalledTimes(2);
  });

  it("receives realtime print job updates through one shared stream", async () => {
    vi.useFakeTimers();
    let realtimeMessage: ((payload: any) => void) | null = null;
    const streamStop = vi.fn();
    vi.mocked(apiClient.streamPrintJobStatus).mockImplementation((_jobId: string, onMessage: (payload: any) => void) => {
      realtimeMessage = onMessage;
      return streamStop;
    });
    vi.mocked(apiClient.getPrintJobStatus).mockResolvedValue({ success: true, data: baseJob } as any);

    const first = render(<PollingProbe job={baseJob} />);
    const second = render(<PollingProbe job={baseJob} open={false} />);
    await flush();

    expect(apiClient.streamPrintJobStatus).toHaveBeenCalledTimes(1);
    expect(getPrintJobRealtimeDebugState().subscriptions).toEqual([{ jobId: "job-live", refs: 2 }]);

    await act(async () => {
      realtimeMessage?.({
        envelope: "MSCQR_SSE_V1",
        channel: "printJob",
        type: "snapshot",
        payload: {
          printJobId: "job-live",
          view: {
            ...baseJob,
            status: "PARTIALLY_COMPLETED",
            session: { ...baseJob.session, remainingToPrint: 6 },
          },
        },
      });
    });
    expect(getActivePrintSessionSnapshot()).toMatchObject({ active: false, terminal: true });

    first.unmount();
    expect(getPrintJobRealtimeDebugState().subscriptions).toEqual([{ jobId: "job-live", refs: 1 }]);
    second.unmount();
    expect(streamStop).toHaveBeenCalledTimes(1);
    expect(getPrintJobRealtimeDebugState().subscriptions).toEqual([]);
  });

  it("discards the old print-job stream and snapshot after an authenticated scope change", async () => {
    vi.useFakeTimers();
    const stops: Array<ReturnType<typeof vi.fn>> = [];
    vi.mocked(apiClient.streamPrintJobStatus).mockImplementation(() => {
      const stop = vi.fn(); stops.push(stop); return stop;
    });
    vi.mocked(apiClient.getPrintJobStatus).mockResolvedValue({ success: true, data: baseJob } as any);
    act(() => setRequestCoordinatorScope({ id: "operator-a", role: "manufacturer" }));
    render(<PollingProbe job={baseJob} />);
    await flush();
    expect(stops).toHaveLength(1);
    expect(screen.getByTestId("live-job-status")).toHaveTextContent("SENT");

    act(() => setRequestCoordinatorScope({ id: "operator-b", role: "manufacturer" }));
    await flush();
    expect(stops[0]).toHaveBeenCalledOnce();
    expect(stops).toHaveLength(2);
    expect(screen.getByTestId("live-job-status")).toBeEmptyDOMElement();
    expect(getPrintJobRealtimeDebugState().subscriptions).toEqual([{ jobId: "job-live", refs: 1 }]);
  });

  it("accepts a committed JOB projection from the production SSE snapshot", async () => {
    vi.useFakeTimers();
    let realtimeMessage: ((payload: any) => void) | null = null;
    vi.mocked(apiClient.streamPrintJobStatus).mockImplementation((_jobId: string, onMessage: (payload: any) => void) => {
      realtimeMessage = onMessage;
      return vi.fn();
    });
    vi.mocked(apiClient.getPrintJobStatus).mockResolvedValue({ success: true, data: baseJob } as any);
    render(<PollingProbe job={baseJob} showDialog />);
    await flush();
    await act(async () => {
      realtimeMessage?.({ envelope: "MSCQR_SSE_V1", channel: "printJob", type: "snapshot",
        payload: { printJobId: "job-live", view: confirmedBackendProjection() } });
    });
    expect(screen.getByTestId("live-job-status")).toHaveTextContent("CONFIRMED");
    expect(screen.getByTestId("live-job-confirmed")).toHaveTextContent("10");
    expect(screen.getByTestId("live-job-items")).toHaveTextContent("10");
    expect(screen.getByText("Print completed")).toBeInTheDocument();
    expect(getActivePrintSessionSnapshot()).toMatchObject({ active: false, terminal: true });
  });

  it("recovers a committed JOB projection through authoritative status reconciliation", async () => {
    vi.useFakeTimers();
    let realtimeMessage: ((payload: any) => void) | null = null;
    vi.mocked(apiClient.streamPrintJobStatus).mockImplementation((_jobId: string, onMessage: (payload: any) => void) => {
      realtimeMessage = onMessage;
      return vi.fn();
    });
    vi.mocked(apiClient.getPrintJobStatus)
      .mockResolvedValueOnce({ success: true, data: baseJob } as any)
      .mockResolvedValue({ success: true, data: confirmedBackendProjection() } as any);
    render(<PollingProbe job={baseJob} showDialog />);
    await flush();
    await act(async () => {
      realtimeMessage?.({ envelope: "MSCQR_SSE_V1", channel: "printJob", type: "label_confirmed",
        payload: { printJobId: "job-live", reason: "printer_session_progress" } });
      await vi.advanceTimersByTimeAsync(10_001);
    });
    expect(screen.getByTestId("live-job-status")).toHaveTextContent("CONFIRMED");
    expect(screen.getByTestId("live-job-confirmed")).toHaveTextContent("10");
    expect(screen.getByTestId("live-job-items")).toHaveTextContent("10");
    expect(screen.getByText("Print completed")).toBeInTheDocument();
    expect(getActivePrintSessionSnapshot()).toMatchObject({ active: false, terminal: true });
  });

  it("reconciles STOPPED to CONFIRMED from an identity-only SSE event without printing again", async () => {
    vi.useFakeTimers();
    let onMessage: ((payload: any) => void) | undefined;
    const refreshRecentJobs = vi.fn().mockResolvedValue(undefined);
    vi.mocked(apiClient.streamPrintJobStatus).mockImplementation((_jobId, message) => {
      onMessage = message;
      return vi.fn();
    });
    vi.mocked(apiClient.getPrintJobStatus)
      .mockResolvedValueOnce({ success: true, data: stoppedStatusView() } as any)
      .mockResolvedValue({ success: true, data: confirmedBackendProjection() } as any);
    render(<PollingProbe job={baseJob} showDialog onRecentJobsRefresh={refreshRecentJobs} />);
    await flush();
    expect(refreshRecentJobs).not.toHaveBeenCalled();

    await act(async () => {
      onMessage?.({ envelope: "MSCQR_SSE_V1", type: "label_confirmed",
        payload: { printJobId: "job-live", view: null } });
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(screen.getByTestId("live-job-status")).toHaveTextContent("CONFIRMED");
    expect(screen.getByText("Print completed")).toBeInTheDocument();
    expect(refreshRecentJobs).toHaveBeenCalledTimes(1);
    expect(apiClient.createPrintJob).not.toHaveBeenCalled();
    expect(apiClient.resumePrintJob).not.toHaveBeenCalled();
  });

  it("reconciles a stopped job after SSE reconnect and displays committed success", async () => {
    vi.useFakeTimers();
    let onOpen: (() => void) | undefined;
    let onError: (() => void) | undefined;
    vi.mocked(apiClient.streamPrintJobStatus).mockImplementation((_jobId, _message, options) => {
      onOpen = options?.onOpen;
      onError = options?.onError;
      return vi.fn();
    });
    vi.mocked(apiClient.getPrintJobStatus)
      .mockResolvedValueOnce({ success: true, data: stoppedStatusView() } as any)
      .mockResolvedValue({ success: true, data: confirmedStatusView() } as any);
    render(<PollingProbe job={baseJob} showDialog />);
    await flush();
    expect(screen.getByTestId("live-job-status")).toHaveTextContent("STOPPED");

    await act(async () => {
      onError?.();
      onOpen?.();
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(apiClient.getPrintJobStatus).toHaveBeenCalledTimes(2);
    expect(apiClient.getPrintJobStatus).toHaveBeenLastCalledWith("job-live", expect.objectContaining({ force: true }));
    expect(screen.getByTestId("live-job-status")).toHaveTextContent("CONFIRMED");
    expect(screen.getByTestId("live-job-confirmed")).toHaveTextContent("10");
    expect(screen.getByText("Print completed")).toBeInTheDocument();
    expect(apiClient.createPrintJob).not.toHaveBeenCalled();
    expect(apiClient.resumePrintJob).not.toHaveBeenCalled();
  });

  it("coalesces duplicate reconnects and does not poll a stopped job forever", async () => {
    vi.useFakeTimers();
    let onOpen: (() => void) | undefined;
    vi.mocked(apiClient.streamPrintJobStatus).mockImplementation((_jobId, _message, options) => {
      onOpen = options?.onOpen;
      return vi.fn();
    });
    vi.mocked(apiClient.getPrintJobStatus).mockResolvedValue({ success: true, data: stoppedStatusView() } as any);
    render(<PollingProbe job={baseJob} />);
    await flush();
    await act(async () => {
      onOpen?.(); onOpen?.(); onOpen?.();
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(apiClient.getPrintJobStatus).toHaveBeenCalledTimes(2);
    await act(async () => { await vi.advanceTimersByTimeAsync(60_000); });
    expect(apiClient.getPrintJobStatus).toHaveBeenCalledTimes(2);
    expect(screen.getByTestId("live-job-status")).toHaveTextContent("STOPPED");
  });

  it("cannot regress a newer CONFIRMED view with a delayed STOPPED response", async () => {
    vi.useFakeTimers();
    let onOpen: (() => void) | undefined;
    let onMessage: ((payload: any) => void) | undefined;
    let resolveDelayed: ((value: any) => void) | undefined;
    vi.mocked(apiClient.streamPrintJobStatus).mockImplementation((_jobId, message, options) => {
      onMessage = message;
      onOpen = options?.onOpen;
      return vi.fn();
    });
    vi.mocked(apiClient.getPrintJobStatus)
      .mockResolvedValueOnce({ success: true, data: stoppedStatusView() } as any)
      .mockImplementationOnce(() => new Promise(resolve => { resolveDelayed = resolve; }));
    render(<PollingProbe job={baseJob} showDialog />);
    await flush();
    await act(async () => { onOpen?.(); vi.runOnlyPendingTimers(); });
    expect(apiClient.getPrintJobStatus).toHaveBeenCalledTimes(2);
    await act(async () => {
      onMessage?.({ envelope: "MSCQR_SSE_V1", type: "label_confirmed",
        payload: { printJobId: "job-live", view: confirmedBackendProjection() } });
      resolveDelayed?.({ success: true, data: { ...stoppedBackendProjection(),
        job: { ...stoppedBackendProjection().job, updatedAt: new Date(Date.now() + 5_000).toISOString() } } });
      await Promise.resolve();
    });
    expect(screen.getByTestId("live-job-status")).toHaveTextContent("CONFIRMED");
    expect(screen.getByText("Print completed")).toBeInTheDocument();
  });

  it("does not reconcile or continuously poll an already confirmed job on reconnect", async () => {
    vi.useFakeTimers();
    let onOpen: (() => void) | undefined;
    vi.mocked(apiClient.streamPrintJobStatus).mockImplementation((_jobId, _message, options) => {
      onOpen = options?.onOpen;
      return vi.fn();
    });
    vi.mocked(apiClient.getPrintJobStatus).mockResolvedValue({ success: true, data: confirmedStatusView() } as any);
    render(<PollingProbe job={baseJob} />);
    await flush();
    await act(async () => { onOpen?.(); onOpen?.(); await vi.advanceTimersByTimeAsync(120_000); });
    expect(apiClient.getPrintJobStatus).toHaveBeenCalledTimes(1);
    expect(screen.getByTestId("live-job-status")).toHaveTextContent("CONFIRMED");
  });

  it("refetches authoritative status for a production notification without a view", async () => {
    vi.useFakeTimers();
    let realtimeMessage: ((payload: any) => void) | null = null;
    vi.mocked(apiClient.streamPrintJobStatus).mockImplementation((_jobId: string, onMessage: (payload: any) => void) => {
      realtimeMessage = onMessage;
      return vi.fn();
    });
    vi.mocked(apiClient.getPrintJobStatus)
      .mockResolvedValueOnce({ success: true, data: baseJob } as any)
      .mockResolvedValue({ success: true, data: {
        ...baseJob, status: "CONFIRMED", updatedAt: new Date(Date.now() + 1_000).toISOString(),
        session: { ...baseJob.session, status: "COMPLETED", confirmedItems: 10, remainingToPrint: 0 },
      } } as any);

    render(<PollingProbe job={baseJob} />);
    await flush();
    await act(async () => {
      realtimeMessage?.({ envelope: "MSCQR_SSE_V1", channel: "printJob", type: "label_confirmed",
        payload: { printJobId: "job-live", view: null, reason: "printer_session_progress" } });
      await vi.advanceTimersByTimeAsync(10_001);
    });
    expect(apiClient.getPrintJobStatus).toHaveBeenCalledWith("job-live", expect.objectContaining({ force: true }));
    expect(getActivePrintSessionSnapshot()).toMatchObject({ active: false, terminal: true });
  });

  it("contains a failed status request and retries without false success", async () => {
    vi.useFakeTimers();
    vi.mocked(apiClient.getPrintJobStatus)
      .mockRejectedValueOnce(new Error("temporary network failure"))
      .mockResolvedValue({ success: true, data: baseJob } as any);
    render(<PollingProbe job={baseJob} />);
    await flush();
    expect(getActivePrintSessionSnapshot()).toMatchObject({ active: true, terminal: false });
    await act(async () => { await vi.advanceTimersByTimeAsync(120_001); });
    expect(apiClient.getPrintJobStatus).toHaveBeenCalledTimes(2);
    expect(getActivePrintSessionSnapshot()).toMatchObject({ active: true, terminal: false });
  });

  it("does not regress committed success on delayed or cross-job events", async () => {
    vi.useFakeTimers();
    let realtimeMessage: ((payload: any) => void) | null = null;
    vi.mocked(apiClient.streamPrintJobStatus).mockImplementation((_jobId: string, onMessage: (payload: any) => void) => {
      realtimeMessage = onMessage;
      return vi.fn();
    });
    vi.mocked(apiClient.getPrintJobStatus).mockResolvedValue({ success: true, data: baseJob } as any);
    render(<PollingProbe job={baseJob} />);
    await flush();
    const confirmed = {
      ...baseJob, status: "CONFIRMED", updatedAt: new Date(Date.now() + 2_000).toISOString(),
      session: { ...baseJob.session, status: "COMPLETED", confirmedItems: 10, remainingToPrint: 0 },
    };
    await act(async () => {
      realtimeMessage?.({ envelope: "MSCQR_SSE_V1", type: "label_confirmed",
        payload: { printJobId: "job-live", view: confirmed } });
      realtimeMessage?.({ envelope: "MSCQR_SSE_V1", type: "label_acknowledged",
        payload: { printJobId: "job-live", view: baseJob } });
      realtimeMessage?.({ envelope: "MSCQR_SSE_V1", type: "label_confirmed",
        payload: { printJobId: "other-job", view: baseJob } });
    });
    expect(getActivePrintSessionSnapshot()).toMatchObject({ active: false, terminal: true });
    expect(apiClient.getPrintJobStatus).toHaveBeenCalledTimes(1);
  });

  it("clears fallback timers and realtime subscriptions after unmount", async () => {
    vi.useFakeTimers();
    const streamStop = vi.fn();
    vi.mocked(apiClient.streamPrintJobStatus).mockReturnValue(streamStop);
    vi.mocked(apiClient.getPrintJobStatus).mockResolvedValue({ success: true, data: baseJob } as any);

    const view = render(<PollingProbe job={baseJob} />);
    await flush();
    expect(apiClient.getPrintJobStatus).toHaveBeenCalledTimes(1);

    view.unmount();
    expect(streamStop).toHaveBeenCalledTimes(1);
    expect(getPrintJobRealtimeDebugState().subscriptions).toEqual([]);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(120_000);
    });
    expect(apiClient.getPrintJobStatus).toHaveBeenCalledTimes(1);
  });
});
