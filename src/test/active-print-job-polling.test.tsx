import React from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { act, render } from "@testing-library/react";

import apiClient from "@/lib/api-client";
import { clearActivePrintSession, getActivePrintSessionSnapshot } from "@/lib/active-print-session";
import { useActivePrintJobPolling } from "@/features/batches/useActivePrintJobPolling";
import { getPrintJobRealtimeDebugState, resetPrintJobRealtimeStoreForTests } from "@/lib/print-job-realtime-store";

vi.mock("@/lib/api-client", () => ({
  default: {
    getPrintJobStatus: vi.fn(),
    streamPrintJobStatus: vi.fn(),
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

function PollingProbe({ job, open = true }: { job: Record<string, unknown>; open?: boolean }) {
  useActivePrintJobPolling({
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
    loadRecentPrintJobs: vi.fn(),
    onBatchesChanged: vi.fn(),
  });
  return <div>{String(job.id)}</div>;
}

describe("active print job polling", () => {
  afterEach(() => {
    clearActivePrintSession();
    resetPrintJobRealtimeStoreForTests();
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
