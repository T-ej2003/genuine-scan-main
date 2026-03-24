import { useEffect, useMemo, useState } from "react";

import { buildStableBatchOverviewRows, type StableBatchOverviewRow } from "@/lib/batch-workspace";
import apiClient from "@/lib/api-client";
import { onMutationEvent } from "@/lib/mutation-events";

import { useAssignableManufacturers, useBatches } from "./hooks";
import type { BatchRow, ManufacturerRow } from "./types";

const LARGE_ALLOCATION_THRESHOLD = 25_000;

type ToastLike = (options: {
  title?: string;
  description?: string;
  variant?: "default" | "destructive";
}) => unknown;

type ProgressLike = {
  start: (options: {
    title: string;
    description: string;
    phaseLabel?: string;
    detail?: string;
    initialValue?: number;
    mode?: "simulated" | "determinate";
  }) => void;
  complete: (detail?: string) => Promise<void>;
  close: () => void;
};

type UseBatchOperationsControllerParams = {
  role?: string | null;
  userLicenseeId?: string | null;
  searchParams: URLSearchParams;
  canAssignManufacturer: boolean;
  canDelete: boolean;
  progress: ProgressLike;
  toast: ToastLike;
  onAssignmentComplete?: () => Promise<void> | void;
};

export function useBatchOperationsController({
  role,
  userLicenseeId,
  searchParams,
  canAssignManufacturer,
  canDelete,
  progress,
  toast,
  onAssignmentComplete,
}: UseBatchOperationsControllerParams) {
  const isManufacturer = role === "manufacturer";

  const [loading, setLoading] = useState(false);
  const [rows, setRows] = useState<BatchRow[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [q, setQ] = useState("");
  const [assignmentFilter, setAssignmentFilter] = useState<"all" | "assigned" | "unassigned">("all");
  const [printFilter, setPrintFilter] = useState<"all" | "printed" | "unprinted">("all");
  const [manufacturers, setManufacturers] = useState<ManufacturerRow[]>([]);
  const [assignBatch, setAssignBatch] = useState<BatchRow | null>(null);
  const [assignManufacturerId, setAssignManufacturerId] = useState("");
  const [assignQuantity, setAssignQuantity] = useState("");
  const [allocationHint, setAllocationHint] = useState<{ title: string; body: string } | null>(null);
  const [renameOpen, setRenameOpen] = useState(false);
  const [renameBatch, setRenameBatch] = useState<BatchRow | null>(null);
  const [renameValue, setRenameValue] = useState("");
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [deleteBatch, setDeleteBatch] = useState<BatchRow | null>(null);

  const batchesQuery = useBatches(undefined, false);
  const manufacturersQuery = useAssignableManufacturers(userLicenseeId || undefined, false);

  const fetchBatches = async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await batchesQuery.refetch();
      if (!result.data) {
        setRows([]);
        setError(result.error instanceof Error ? result.error.message : "Failed to load batches");
        return;
      }

      setRows(Array.isArray(result.data) ? (result.data as BatchRow[]) : []);
    } catch (error) {
      setRows([]);
      setError(error instanceof Error ? error.message : "Failed to load batches");
    } finally {
      setLoading(false);
    }
  };

  const fetchManufacturersForAssign = async () => {
    if (!canAssignManufacturer) return;
    const result = await manufacturersQuery.refetch();
    setManufacturers(Array.isArray(result.data) ? (result.data as ManufacturerRow[]) : []);
  };

  useEffect(() => {
    if (batchesQuery.data) {
      setRows(Array.isArray(batchesQuery.data) ? (batchesQuery.data as BatchRow[]) : []);
      setError(null);
    }
  }, [batchesQuery.data]);

  useEffect(() => {
    if (batchesQuery.error instanceof Error) {
      setRows([]);
      setError(batchesQuery.error.message);
    }
  }, [batchesQuery.error]);

  useEffect(() => {
    void fetchBatches();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    const manufacturerName = String(searchParams.get("manufacturerName") || "").trim();
    const printState = String(searchParams.get("printState") || "").trim().toLowerCase();
    if (manufacturerName) {
      setQ(manufacturerName);
      setAssignmentFilter("assigned");
    }
    if (printState === "printed" || printState === "pending") {
      setPrintFilter(printState === "printed" ? "printed" : "unprinted");
    }
  }, [searchParams]);

  useEffect(() => {
    const off = onMutationEvent(() => {
      void fetchBatches();
      void fetchManufacturersForAssign();
    });
    return off;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [canAssignManufacturer, userLicenseeId]);

  useEffect(() => {
    if (canAssignManufacturer) {
      void fetchManufacturersForAssign();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [canAssignManufacturer, userLicenseeId]);

  useEffect(() => {
    if (manufacturersQuery.data) {
      setManufacturers(Array.isArray(manufacturersQuery.data) ? (manufacturersQuery.data as ManufacturerRow[]) : []);
    }
  }, [manufacturersQuery.data]);

  const filteredRows = useMemo(() => {
    const search = q.trim().toLowerCase();
    const manufacturerIdFilter = String(searchParams.get("manufacturerId") || "").trim();

    return rows.filter((batch) => {
      if (manufacturerIdFilter && String(batch.manufacturer?.id || batch.manufacturerId || "").trim() !== manufacturerIdFilter) {
        return false;
      }

      if (isManufacturer) {
        if (printFilter === "printed" && !batch.printedAt) return false;
        if (printFilter === "unprinted" && batch.printedAt) return false;
      } else {
        const isAssignedRow = batch.batchKind === "MANUFACTURER_CHILD" || Boolean(batch.manufacturer);
        if (assignmentFilter === "assigned" && !isAssignedRow) return false;
        if (assignmentFilter === "unassigned" && isAssignedRow) return false;
      }

      if (!search) return true;

      const haystack = [
        batch.name,
        batch.startCode,
        batch.endCode,
        batch.licensee?.name,
        batch.licensee?.prefix,
        batch.manufacturer?.name,
        batch.manufacturer?.email,
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();

      return haystack.includes(search);
    });
  }, [assignmentFilter, isManufacturer, printFilter, q, rows, searchParams]);

  const stableRows = useMemo(() => buildStableBatchOverviewRows(rows), [rows]);

  const filteredStableRows = useMemo(() => {
    const search = q.trim().toLowerCase();
    const manufacturerIdFilter = String(searchParams.get("manufacturerId") || "").trim();

    return stableRows.filter((row) => {
      if (manufacturerIdFilter) {
        const matchesManufacturer = row.manufacturerSummary.some(
          (allocation) => allocation.manufacturerId === manufacturerIdFilter
        );
        if (!matchesManufacturer) return false;
      }

      if (assignmentFilter === "assigned" && row.assignedCodes <= 0) return false;
      if (assignmentFilter === "unassigned" && row.remainingUnassignedCodes <= 0) return false;
      if (!search) return true;

      const haystack = [
        row.sourceBatchName,
        row.sourceBatchId,
        row.sourceOriginalRangeStart,
        row.sourceOriginalRangeEnd,
        row.licensee?.name,
        row.licensee?.prefix,
        ...row.manufacturerSummary.flatMap((allocation) => [
          allocation.manufacturerName,
          allocation.manufacturerEmail,
          allocation.batchName,
          allocation.batchId,
        ]),
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();

      return haystack.includes(search);
    });
  }, [assignmentFilter, q, searchParams, stableRows]);

  const getAvailableInventory = (batch: BatchRow) =>
    batch.batchKind === "MANUFACTURER_CHILD"
      ? Number(batch.printableCodes ?? batch.availableCodes ?? 0)
      : Number(batch.unassignedRemainingCodes ?? batch.availableCodes ?? 0);

  const getAvailabilityTitle = (batch: BatchRow) =>
    batch.batchKind === "MANUFACTURER_CHILD" ? "Ready to print" : "Unassigned remaining";

  const getAvailabilityTone = (value: number) => (value > 0 ? "default" : "secondary");

  const resetAssignDraft = () => {
    setAssignManufacturerId("");
    setAssignQuantity("");
  };

  const openRename = (batch: BatchRow) => {
    setRenameBatch(batch);
    setRenameValue(batch.name || "");
    setRenameOpen(true);
  };

  const resetRenameState = () => {
    setRenameBatch(null);
    setRenameValue("");
    setRenameOpen(false);
  };

  const requestDelete = (batch: BatchRow) => {
    if (!canDelete) return;
    setDeleteBatch(batch);
    setDeleteOpen(true);
  };

  const resetDeleteState = () => {
    setDeleteBatch(null);
    setDeleteOpen(false);
  };

  const submitRename = async () => {
    if (!renameBatch) return;
    const nextName = renameValue.trim();

    if (nextName.length < 2) {
      toast({
        title: "Batch name too short",
        description: "Enter at least 2 characters.",
        variant: "destructive",
      });
      return;
    }

    setLoading(true);
    try {
      const response = await apiClient.renameBatch(renameBatch.id, nextName);
      if (!response.success) {
        toast({ title: "Rename failed", description: response.error || "Error", variant: "destructive" });
        return;
      }

      toast({ title: "Batch renamed", description: `Updated to "${nextName}".` });
      resetRenameState();
      await fetchBatches();
    } finally {
      setLoading(false);
    }
  };

  const confirmDelete = async () => {
    if (!deleteBatch || !canDelete) return;

    setLoading(true);
    setError(null);
    try {
      const response = await apiClient.deleteBatch(deleteBatch.id);
      if (!response.success) {
        setError(response.error || "Delete failed");
        toast({
          title: "Delete failed",
          description: response.error || "The batch could not be deleted.",
          variant: "destructive",
        });
        return;
      }

      toast({ title: "Batch deleted", description: `"${deleteBatch.name}" was removed and its codes were unassigned.` });
      resetDeleteState();
      await fetchBatches();
    } catch (error) {
      const message = error instanceof Error ? error.message : "Delete failed";
      setError(message);
      toast({ title: "Delete failed", description: message, variant: "destructive" });
    } finally {
      setLoading(false);
    }
  };

  const submitAssign = async () => {
    if (!assignBatch) return;
    if (!assignManufacturerId) {
      toast({ title: "Select a manufacturer", variant: "destructive" });
      return;
    }

    const quantity = parseInt(assignQuantity, 10);
    if (!Number.isFinite(quantity) || quantity <= 0) {
      toast({ title: "Enter a valid quantity", variant: "destructive" });
      return;
    }

    const availableInventory = getAvailableInventory(assignBatch);
    if (availableInventory > 0 && quantity > availableInventory) {
      toast({
        title: "Quantity too large",
        description: `Unassigned remaining: ${availableInventory}.`,
        variant: "destructive",
      });
      return;
    }

    const showLargeAllocationProgress = quantity >= LARGE_ALLOCATION_THRESHOLD;
    if (showLargeAllocationProgress) {
      progress.start({
        title: "Allocating batch",
        description: "Validating remainder, assigning manufacturer, and creating allocated batch.",
        phaseLabel: "Allocation",
        detail: `Allocating ${quantity.toLocaleString()} codes to the selected manufacturer.`,
        mode: "simulated",
        initialValue: 12,
      });
    }

    setLoading(true);
    try {
      const response = await apiClient.assignBatchManufacturer({
        batchId: assignBatch.id,
        manufacturerId: assignManufacturerId,
        quantity,
      });

      if (!response.success) {
        if (showLargeAllocationProgress) progress.close();
        const raw = String(response.error || "Error").toLowerCase();
        const isBusy = raw.includes("busy") || raw.includes("retry") || raw.includes("conflict");
        toast({
          title: isBusy ? "Batch busy" : "Assign failed",
          description: isBusy
            ? "These codes were just allocated by another action. Please retry."
            : response.error || "Error",
          variant: "destructive",
        });
        return;
      }

      const data = (response.data || {}) as {
        newBatchName?: string;
        message?: { title?: string; body?: string };
      };

      if (showLargeAllocationProgress) {
        await progress.complete(
          `Allocated ${quantity.toLocaleString()} codes. The new manufacturer batch is ready for print.`
        );
      }

      if (data.message?.title || data.message?.body) {
        setAllocationHint({
          title: data.message?.title || "Allocation complete",
          body:
            data.message?.body ||
            "The source batch retains the remainder and the allocated batch is ready for print.",
        });
      }

      toast({
        title: "Assigned",
        description: `${data.newBatchName || "Allocated batch"} was created for controlled printing.`,
      });
      resetAssignDraft();
      await fetchBatches();
      await onAssignmentComplete?.();
    } catch (error) {
      if (showLargeAllocationProgress) progress.close();
      toast({
        title: "Assign failed",
        description: error instanceof Error ? error.message : "Error",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  return {
    loading,
    rows,
    error,
    q,
    assignmentFilter,
    printFilter,
    manufacturers,
    assignBatch,
    assignManufacturerId,
    assignQuantity,
    allocationHint,
    renameOpen,
    renameBatch,
    renameValue,
    deleteOpen,
    deleteBatch,
    filteredRows,
    stableRows,
    filteredStableRows,
    setQ,
    setAssignmentFilter,
    setPrintFilter,
    setAssignBatch,
    setAssignManufacturerId,
    setAssignQuantity,
    setAllocationHint,
    setRenameOpen,
    setRenameValue,
    setDeleteOpen,
    fetchBatches,
    fetchManufacturersForAssign,
    openRename,
    resetRenameState,
    submitRename,
    requestDelete,
    resetDeleteState,
    confirmDelete,
    resetAssignDraft,
    submitAssign,
    getAvailableInventory,
    getAvailabilityTitle,
    getAvailabilityTone,
  };
}

export type BatchOperationsController = ReturnType<typeof useBatchOperationsController>;
export type BatchWorkspaceRows = StableBatchOverviewRow[];
