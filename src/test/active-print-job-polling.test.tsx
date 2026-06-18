import React from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { render } from "@testing-library/react";

import apiClient from "@/lib/api-client";
import { clearActivePrintSession, getActivePrintSessionSnapshot } from "@/lib/active-print-session";
import { useActivePrintJobPolling } from "@/features/batches/useActivePrintJobPolling";

vi.mock("@/lib/api-client", () => ({
  default: {
    getPrintJobStatus: vi.fn(),
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
    vi.useRealTimers();
    vi.clearAllMocks();
  });

  it.each([
    ["PARTIALLY_COMPLETED status", { ...baseJob, status: "PARTIALLY_COMPLETED" }],
    ["STOPPED pipeline state", { ...baseJob, pipelineState: "STOPPED" }],
    ["STOPPED session status", { ...baseJob, session: { ...baseJob.session, status: "STOPPED" } }],
  ])("stops polling after %s", async (_label, job) => {
    vi.useFakeTimers();
    vi.mocked(apiClient.getPrintJobStatus).mockResolvedValue({ success: true, data: job } as any);

    render(<PollingProbe job={job} />);

    await Promise.resolve();
    await Promise.resolve();
    expect(apiClient.getPrintJobStatus).toHaveBeenCalledTimes(1);
    expect(getActivePrintSessionSnapshot()).toMatchObject({
      active: false,
      jobId: "job-live",
      modalOpen: true,
      terminal: true,
    });

    await vi.advanceTimersByTimeAsync(30_000);
    expect(apiClient.getPrintJobStatus).toHaveBeenCalledTimes(1);
  });

  it("backs active polling off after the bounded observation window", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-06-17T21:14:32.000Z"));
    vi.mocked(apiClient.getPrintJobStatus).mockResolvedValue({ success: true, data: baseJob } as any);

    render(<PollingProbe job={baseJob} />);

    await Promise.resolve();
    await Promise.resolve();
    await vi.advanceTimersByTimeAsync(190_000);
    const callsAfterTimeout = vi.mocked(apiClient.getPrintJobStatus).mock.calls.length;

    await vi.advanceTimersByTimeAsync(60_000);
    expect(apiClient.getPrintJobStatus).toHaveBeenCalledTimes(callsAfterTimeout);
    expect(callsAfterTimeout).toBeLessThanOrEqual(38);
  });

  it("continues tracking an active print job after the progress dialog is dismissed", async () => {
    vi.useFakeTimers();
    vi.mocked(apiClient.getPrintJobStatus).mockResolvedValue({ success: true, data: baseJob } as any);

    render(<PollingProbe job={baseJob} open={false} />);

    await Promise.resolve();
    await Promise.resolve();
    expect(apiClient.getPrintJobStatus).toHaveBeenCalledTimes(1);
    expect(getActivePrintSessionSnapshot()).toMatchObject({
      active: true,
      jobId: "job-live",
      modalOpen: false,
      terminal: false,
    });

    await vi.advanceTimersByTimeAsync(10_000);
    expect(apiClient.getPrintJobStatus).toHaveBeenCalledTimes(2);
  });
});
