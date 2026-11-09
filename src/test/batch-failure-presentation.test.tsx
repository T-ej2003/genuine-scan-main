import React from "react";
import { act, cleanup, render, renderHook, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, expect, it, vi } from "vitest";

import apiClient from "@/lib/api-client";
import { emitMutationEvent } from "@/lib/mutation-events";
import { setRequestCoordinatorScope } from "@/lib/api/request-coordinator";
import { useBatchOperationsController } from "@/features/batches/useBatchOperationsController";
import { BatchesWorkspaceTable } from "@/features/batches/components/BatchesWorkspaceTable";
import type { BatchRow } from "@/features/batches/types";

vi.mock("@/lib/api-client", () => ({ default: { getBatches: vi.fn(), getManufacturers: vi.fn() } }));
afterEach(() => { cleanup(); setRequestCoordinatorScope(null); vi.resetAllMocks(); });

const row = (id: string, licenseeId = "tenant-a"): BatchRow => ({
  id, name: id, licenseeId, startCode: "1", endCode: "1", totalCodes: 1,
  printedAt: null, createdAt: "2026-01-01T00:00:00Z",
});
const response = (rows: BatchRow[]) => ({ success: true as const, data: rows, meta: { total: rows.length, limit: 100, offset: 0 } });
const failed = { success: false as const, status: 500, error: "Internal server error" };
const params = { role: "manufacturer", searchParams: new URLSearchParams(), canAssignManufacturer: false, canDelete: false,
  toast: vi.fn(), progress: { start: vi.fn(), close: vi.fn(), complete: vi.fn().mockResolvedValue(undefined) } };
const makeWrapper = () => {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return ({ children }: { children: React.ReactNode }) => <QueryClientProvider client={client}>{children}</QueryClientProvider>;
};

it("retains same-page rows on a failed refetch and recovers with fresh rows", async () => {
  vi.mocked(apiClient.getBatches).mockResolvedValueOnce(response([row("old")])).mockResolvedValueOnce(failed).mockResolvedValueOnce(response([row("fresh")]));
  const { result } = renderHook(() => useBatchOperationsController({ ...params, userLicenseeId: "tenant-a" }), { wrapper: makeWrapper() });
  await waitFor(() => expect(result.current.rows.map((batch) => batch.id)).toEqual(["old"]));
  await act(async () => { await result.current.fetchBatches(); });
  expect(result.current.error).toBe("Internal server error");
  expect(result.current.rows.map((batch) => batch.id)).toEqual(["old"]);
  await act(async () => { await result.current.fetchBatches(); });
  expect(result.current.error).toBeNull();
  expect(result.current.rows.map((batch) => batch.id)).toEqual(["fresh"]);
});

it("does not show previous tenant or page rows while their replacements load", async () => {
  let finish!: (value: ReturnType<typeof response>) => void;
  vi.mocked(apiClient.getBatches).mockImplementation(async (options) =>
    options?.licenseeId === "tenant-a" && options?.offset === 0
      ? response([row("old")])
      : new Promise((resolve) => { finish = resolve; }));
  const { result, rerender } = renderHook(({ tenant }) => useBatchOperationsController({ ...params, userLicenseeId: tenant }), {
    wrapper: makeWrapper(), initialProps: { tenant: "tenant-a" },
  });
  await waitFor(() => expect(result.current.rows.map((batch) => batch.id)).toEqual(["old"]));
  rerender({ tenant: "tenant-b" });
  expect(result.current.rows).toEqual([]);
  await waitFor(() => expect(finish).toBeDefined());
  await act(async () => { finish(response([row("new", "tenant-b")])); });
  await waitFor(() => expect(result.current.rows.map((batch) => batch.id)).toEqual(["new"]));
  await act(async () => { result.current.setBatchOffset(100); });
  expect(result.current.rows).toEqual([]);
});

it("ignores unrelated mutations while preserving batch and printing refreshes", async () => {
  vi.mocked(apiClient.getBatches).mockResolvedValue(response([row("batch")]));
  const { result } = renderHook(() => useBatchOperationsController({ ...params, userLicenseeId: "tenant-a" }), { wrapper: makeWrapper() });
  await waitFor(() => expect(result.current.rows).toHaveLength(1));
  const initial = vi.mocked(apiClient.getBatches).mock.calls.length;
  await act(async () => {
    emitMutationEvent({ endpoint: "/telemetry/route-transition", method: "POST" });
    emitMutationEvent({ endpoint: "/auth/refresh", method: "POST" });
    emitMutationEvent({ endpoint: "/notifications/read", method: "POST" });
    emitMutationEvent({ endpoint: "/manufacturer/printer-agent/heartbeat", method: "POST" });
    emitMutationEvent({ endpoint: "/manufacturer/printers/id/test-label", method: "POST" });
  });
  expect(apiClient.getBatches).toHaveBeenCalledTimes(initial);
  await act(async () => { emitMutationEvent({ endpoint: "/qr/batches/id/assign-manufacturer", method: "POST" }); });
  await waitFor(() => expect(apiClient.getBatches).toHaveBeenCalledTimes(initial + 1));
  await act(async () => { emitMutationEvent({ endpoint: "/manufacturer/print-jobs", method: "POST" }); });
  await waitFor(() => expect(apiClient.getBatches).toHaveBeenCalledTimes(initial + 2));
  await act(async () => { emitMutationEvent({ endpoint: "/admin/licensees/id/qr-allocate-range", method: "POST" }); });
  await waitFor(() => expect(apiClient.getBatches).toHaveBeenCalledTimes(initial + 3));
});

it("keeps batch mutation refreshes after a same-actor scope change", async () => {
  setRequestCoordinatorScope({ id: "actor", licenseeId: "tenant-a" });
  let finish!: (value: ReturnType<typeof response>) => void;
  vi.mocked(apiClient.getBatches).mockResolvedValueOnce(response([row("batch")]))
    .mockImplementationOnce(() => new Promise((resolve) => { finish = resolve; }))
    .mockResolvedValue(response([row("batch")]));
  const { result } = renderHook(() => useBatchOperationsController({ ...params, userLicenseeId: "tenant-a" }), { wrapper: makeWrapper() });
  await waitFor(() => expect(result.current.rows).toHaveLength(1));
  act(() => setRequestCoordinatorScope({ id: "actor", licenseeId: "tenant-a", scopeVersion: "2" }));
  expect(result.current.rows).toEqual([]);
  await act(async () => { finish(response([row("batch")])) });
  await waitFor(() => expect(result.current.rows).toHaveLength(1));
  const initial = vi.mocked(apiClient.getBatches).mock.calls.length;
  await act(async () => { emitMutationEvent({ endpoint: "/qr/batches/id/rename", method: "PATCH" }); });
  await waitFor(() => expect(apiClient.getBatches).toHaveBeenCalledTimes(initial + 1));
});

it("separates a failed load from a successful empty inventory", () => {
  const props = {
    role: "manufacturer", isManufacturer: true, loading: false, error: "Internal server error", allocationHint: null,
    q: "", assignmentFilter: "all" as const, printFilter: "all" as const,
    rows: [] as BatchRow[], filteredRows: [] as BatchRow[], stableRows: [], filteredStableRows: [],
    printerDiagnostics: { tone: "neutral" as const, summary: "Pending", badgeLabel: "Pending" as const },
    onDismissAllocationHint: vi.fn(), onSearchChange: vi.fn(), onAssignmentFilterChange: vi.fn(), onPrintFilterChange: vi.fn(),
    onRefreshPrinterStatus: vi.fn(), onRefreshBatches: vi.fn(), onOpenPrintPack: vi.fn(), onOpenWorkspace: vi.fn(),
    getAvailableInventory: () => 1, getAvailabilityTone: () => "default" as const, getAvailabilityTitle: () => "Available",
  };
  const { rerender } = render(<BatchesWorkspaceTable {...props} />);
  expect(screen.getByText("Internal server error")).toBeInTheDocument();
  expect(screen.queryByText("No batches found.")).not.toBeInTheDocument();
  rerender(<BatchesWorkspaceTable {...props} error={null} />);
  expect(screen.getByText("No batches found.")).toBeInTheDocument();
  rerender(<BatchesWorkspaceTable {...props} rows={[row("old")]} filteredRows={[row("old")]} />);
  expect(screen.getByText("Showing previously loaded batches.")).toBeInTheDocument();
});
