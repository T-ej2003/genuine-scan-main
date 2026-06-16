import { useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";

import { BatchAllocationMapDialog } from "@/components/batches/BatchAllocationMapDialog";
import { LicenseeBatchWorkspaceDialog } from "@/components/batches/LicenseeBatchWorkspaceDialog";
import { OperationProgressDialog } from "@/components/feedback/OperationProgressDialog";
import { PrintProgressDialog } from "@/components/printing/PrintProgressDialog";
import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { useAuth } from "@/contexts/AuthContext";
import { useBatchPrintWorkflow } from "@/features/batches/useBatchPrintWorkflow";
import { useBatchOperationsController } from "@/features/batches/useBatchOperationsController";
import { useBatchWorkspaceController } from "@/features/batches/useBatchWorkspaceController";
import {
  BatchPrintJobDialog,
  DeleteBatchDialog,
  RenameBatchDialog,
} from "@/features/batches/components/BatchDialogs";
import { BatchesWorkspaceTable } from "@/features/batches/components/BatchesWorkspaceTable";
import { useOperationProgress } from "@/hooks/useOperationProgress";
import { useToast } from "@/hooks/use-toast";
import { APP_PATHS } from "@/app/route-metadata";
import { usePrintJobs } from "@/features/printing/hooks";
import apiClient from "@/lib/api-client";

export default function BatchesPage() {
  const { toast } = useToast();
  const { user } = useAuth();
  const progress = useOperationProgress();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();

  const role = user?.role;
  const canDelete = role === "super_admin" || role === "licensee_admin";
  const canAssignManufacturer = role === "licensee_admin";
  const canRequestReissue = role === "super_admin" || role === "licensee_admin" || role === "manufacturer";
  const isManufacturer = role === "manufacturer";
  const [reissueReason, setReissueReason] = useState("");
  const [reissuingJobId, setReissuingJobId] = useState<string | null>(null);
  const [reissueRequests, setReissueRequests] = useState<any[]>([]);
  const [reissueRequestsLoading, setReissueRequestsLoading] = useState(false);
  const [reissueDecisionNote, setReissueDecisionNote] = useState("");
  const [decidingReissueRequestId, setDecidingReissueRequestId] = useState<string | null>(null);

  const operations = useBatchOperationsController({
    role,
    userLicenseeId: user?.licenseeId,
    searchParams,
    canAssignManufacturer,
    canDelete,
    progress,
    toast,
  });

  const workspace = useBatchWorkspaceController({
    rows: operations.rows,
    stableRows: operations.stableRows,
    toast,
    onWorkspaceBatchChange: operations.setAssignBatch,
    onWorkspaceDraftReset: operations.resetAssignDraft,
  });

  const printWorkflow = useBatchPrintWorkflow({
    isManufacturer,
    userId: user?.id,
    toast,
    getAvailableInventory: operations.getAvailableInventory,
    onBatchesChanged: operations.fetchBatches,
  });

  const workspacePrintJobsQuery = usePrintJobs(
    workspace.workspaceBatch?.sourceBatchRow?.id,
    12,
    workspace.workspaceOpen && canRequestReissue
  );

  const fetchReissueRequests = async () => {
    if (!canRequestReissue) return;
    setReissueRequestsLoading(true);
    try {
      const response = await apiClient.listPrintReissueRequests({ status: "PENDING", limit: 25 });
      setReissueRequests(response.success && Array.isArray(response.data) ? response.data : []);
    } finally {
      setReissueRequestsLoading(false);
    }
  };

  useEffect(() => {
    if (!workspace.workspaceOpen || !canRequestReissue) return;
    void fetchReissueRequests();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [workspace.workspaceOpen, canRequestReissue, role]);

  const requestPrintJobReissue = async (jobId: string) => {
    const reason = reissueReason.trim();
    if (!reason) {
      toast({
        title: "Reason required",
        description: "Enter a clear authorization reason before creating a controlled reissue.",
        variant: "destructive",
      });
      return;
    }

    setReissuingJobId(jobId);
    try {
      const response =
        role === "super_admin"
          ? await apiClient.requestPrintJobReissue(jobId, { reason })
          : await apiClient.createPrintReissueRequest(jobId, { reason });
      if (!response.success) {
        toast({
          title: "Reissue not submitted",
          description: response.error || "MSCQR could not submit the replacement label request.",
          variant: "destructive",
        });
        return;
      }

      setReissueReason("");
      toast({
        title: role === "super_admin" ? "Reissue authorized" : "Reissue request submitted",
        description:
          role === "super_admin"
            ? "A controlled replacement print job was created and added to the audit trail."
            : "The request is waiting for the required approval before replacement labels can be printed.",
      });

      await Promise.allSettled([
        fetchReissueRequests(),
        workspacePrintJobsQuery.refetch(),
        operations.fetchBatches(),
        workspace.workspaceBatch ? workspace.fetchWorkspaceHistory(workspace.workspaceBatch) : Promise.resolve(),
      ]);
    } finally {
      setReissuingJobId(null);
    }
  };

  const decideReissueRequest = async (requestId: string, decision: "approve" | "reject") => {
    const decisionNote = reissueDecisionNote.trim();
    if (decisionNote.length < 8) {
      toast({
        title: "Decision note required",
        description: "Enter a clear approval or rejection note for the audit trail.",
        variant: "destructive",
      });
      return;
    }
    setDecidingReissueRequestId(requestId);
    try {
      const response = await apiClient.decidePrintReissueRequest(requestId, decision, decisionNote);
      if (!response.success) {
        toast({
          title: "Review not saved",
          description: response.error || "MSCQR could not update the reissue request.",
          variant: "destructive",
        });
        return;
      }
      setReissueDecisionNote("");
      toast({
        title: decision === "approve" ? "Reissue approved" : "Reissue rejected",
        description:
          decision === "approve"
            ? "MSCQR queued the approved replacement workflow and updated the audit trail."
            : "MSCQR recorded the rejection and notified the requester.",
      });
      await Promise.allSettled([fetchReissueRequests(), workspacePrintJobsQuery.refetch(), operations.fetchBatches()]);
    } finally {
      setDecidingReissueRequestId(null);
    }
  };

  return (
    <DashboardLayout>
      <BatchesWorkspaceTable
        role={role}
        isManufacturer={isManufacturer}
        loading={operations.loading}
        error={operations.error}
        allocationHint={operations.allocationHint}
        q={operations.q}
        assignmentFilter={operations.assignmentFilter}
        printFilter={operations.printFilter}
        rows={operations.rows}
        filteredRows={operations.filteredRows}
        stableRows={operations.stableRows}
        filteredStableRows={operations.filteredStableRows}
        printerDiagnostics={
          printWorkflow.dialogProps.selectedPrinterNotice.tone === "success"
            ? {
                tone: "success",
                summary: printWorkflow.dialogProps.selectedPrinterNotice.summary,
                badgeLabel: "Ready",
              }
            : printWorkflow.dialogProps.selectedPrinterNotice.tone === "warning"
              ? {
                  tone: "warning",
                  summary: printWorkflow.dialogProps.selectedPrinterNotice.summary,
                  badgeLabel: "Needs check",
                }
              : printWorkflow.dialogProps.selectedPrinterNotice.tone === "danger"
                ? {
                    tone: "danger",
                    summary: printWorkflow.dialogProps.selectedPrinterNotice.summary,
                    badgeLabel: "Blocked",
                  }
                : {
                    tone: "neutral",
                    summary: printWorkflow.dialogProps.selectedPrinterNotice.summary,
                    badgeLabel: "Pending",
                  }
        }
        onDismissAllocationHint={() => operations.setAllocationHint(null)}
        onSearchChange={operations.setQ}
        onAssignmentFilterChange={operations.setAssignmentFilter}
        onPrintFilterChange={operations.setPrintFilter}
        onRefreshPrinterStatus={printWorkflow.dialogProps.onRefreshPrinters}
        onRefreshBatches={() => {
          void operations.fetchBatches({ force: true });
        }}
        onOpenPrintPack={printWorkflow.openPrintPack}
        onOpenWorkspace={(stableWorkspace) => {
          void workspace.openWorkspace(stableWorkspace);
        }}
        getAvailableInventory={operations.getAvailableInventory}
        getAvailabilityTone={operations.getAvailabilityTone}
        getAvailabilityTitle={operations.getAvailabilityTitle}
      />

      <LicenseeBatchWorkspaceDialog
        open={workspace.workspaceOpen}
        onOpenChange={(open) => {
          if (!open) {
            workspace.closeWorkspace();
            setReissueReason("");
          }
        }}
        workspace={workspace.workspaceBatch}
        manufacturers={operations.manufacturers}
        assignManufacturerId={operations.assignManufacturerId}
        assignQuantity={operations.assignQuantity}
        assigning={operations.loading}
        onAssignManufacturerChange={operations.setAssignManufacturerId}
        onAssignQuantityChange={operations.setAssignQuantity}
        onSubmitAssign={operations.submitAssign}
        onOpenRename={() => {
          if (workspace.workspaceBatch?.sourceBatchRow) {
            operations.openRename(workspace.workspaceBatch.sourceBatchRow);
          }
        }}
        onOpenAllocationMap={() => {
          if (workspace.workspaceBatch?.sourceBatchRow) {
            void workspace.openAllocationMap(workspace.workspaceBatch.sourceBatchRow);
          }
        }}
        onDownloadAudit={() => {
          if (workspace.workspaceBatch?.sourceBatchRow) {
            void workspace.downloadAuditPackage(workspace.workspaceBatch.sourceBatchRow);
          }
        }}
        onDelete={() => {
          if (workspace.workspaceBatch?.sourceBatchRow) {
            operations.requestDelete(workspace.workspaceBatch.sourceBatchRow);
          }
        }}
        canAssignManufacturer={canAssignManufacturer}
        canDelete={canDelete}
        exportingAudit={workspace.exportingBatchId === workspace.workspaceBatch?.sourceBatchRow?.id}
        historyLoading={workspace.workspaceHistoryLoading}
        historyLogs={workspace.workspaceHistoryLogs}
        historyLastUpdatedAt={workspace.workspaceHistoryLastUpdatedAt}
        onRefreshHistory={() => {
          if (workspace.workspaceBatch) {
            void workspace.fetchWorkspaceHistory(workspace.workspaceBatch);
          }
        }}
        recentPrintJobs={workspacePrintJobsQuery.data || []}
        printJobsLoading={workspacePrintJobsQuery.isLoading || workspacePrintJobsQuery.isFetching}
        canRequestReissue={canRequestReissue}
        reissueReason={reissueReason}
        onReissueReasonChange={setReissueReason}
        onRequestReissue={(jobId) => {
          void requestPrintJobReissue(jobId);
        }}
        reissuingJobId={reissuingJobId}
        reissueRequests={reissueRequests}
        reissueRequestsLoading={reissueRequestsLoading}
        reissueDecisionNote={reissueDecisionNote}
        decidingReissueRequestId={decidingReissueRequestId}
        onReissueDecisionNoteChange={setReissueDecisionNote}
        onRefreshReissueRequests={() => {
          void fetchReissueRequests();
        }}
        onDecideReissueRequest={(requestId, decision) => {
          void decideReissueRequest(requestId, decision);
        }}
      />

      <RenameBatchDialog
        open={operations.renameOpen}
        onOpenChange={(open) => {
          if (!open) {
            operations.resetRenameState();
          }
        }}
        batch={operations.renameBatch}
        value={operations.renameValue}
        onValueChange={operations.setRenameValue}
        onSubmit={operations.submitRename}
        saving={operations.loading}
      />

      <DeleteBatchDialog
        open={operations.deleteOpen}
        onOpenChange={(open) => {
          if (!open) {
            operations.resetDeleteState();
          }
        }}
        batch={operations.deleteBatch}
        deleting={operations.loading}
        onConfirm={() => {
          void operations.confirmDelete();
        }}
      />

      <BatchPrintJobDialog
        {...printWorkflow.dialogProps}
      />

      <BatchAllocationMapDialog
        open={workspace.allocationMapOpen}
        onOpenChange={(open) => {
          if (!open) {
            workspace.closeAllocationMap();
          }
        }}
        loading={workspace.allocationMapLoading}
        payload={workspace.allocationMap}
        onOpenBatches={(batchId) => {
          void workspace.openBatchContextFromAllocationMap(batchId);
        }}
      />

      <OperationProgressDialog
        open={progress.state.open}
        title={progress.state.title}
        description={progress.state.description}
        phaseLabel={progress.state.phaseLabel}
        detail={progress.state.detail}
        speedLabel={progress.state.speedLabel}
        value={progress.state.value}
        indeterminate={progress.state.indeterminate}
      />

      <PrintProgressDialog {...printWorkflow.progressDialogProps} />
    </DashboardLayout>
  );
}
