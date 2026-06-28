import React from "react";
import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

import { PrintProgressDialog } from "@/components/printing/PrintProgressDialog";
import { LicenseeBatchWorkspaceDialog } from "@/components/batches/LicenseeBatchWorkspaceDialog";
import { BatchPrintJobDialog, DeleteBatchDialog, RenameBatchDialog } from "@/features/batches/components/BatchDialogs";
import { LicenseeDialogs } from "@/features/licensees/components/LicenseeDialogs";
import { ManufacturerDetailsDialog } from "@/features/manufacturers/components/ManufacturerDetailsDialog";

describe("dialog recovery states", () => {
  const manufacturerOperational = (overrides: Record<string, unknown> = {}) => ({
    assignedLabelCount: 0,
    confirmedPrintedCount: 0,
    scannedCount: 0,
    blockedCount: 0,
    remainingLabelCount: 0,
    originalAssignedRangeStart: null,
    originalAssignedRangeEnd: null,
    remainingPrintableRangeStart: null,
    remainingPrintableRangeEnd: null,
    nextPrintableLabelCode: null,
    ...overrides,
  });
  const readyBatch = {
    id: "batch-1",
    name: "Smoke batch",
    totalCodes: 10,
    printedCodes: 0,
    allocatedCodes: 10,
    availableToPrint: 10,
  };
  const readyLocalPrinterProfile = {
    id: "printer-profile-1",
    name: "E2E Local Agent Printer",
    connectionType: "LOCAL_AGENT",
    isActive: true,
    nativePrinterId: "e2e-local-printer",
  };
  const readyLocalPrinter = {
    printerId: "e2e-local-printer",
    printerName: "E2E Local Agent Printer",
    online: true,
  };
  const renderPrintDialog = (overrides: Partial<React.ComponentProps<typeof BatchPrintJobDialog>> = {}) =>
    render(
      <MemoryRouter>
        <BatchPrintJobDialog
          open
          onOpenChange={() => undefined}
          printBatch={readyBatch as any}
          selectedPrinterNotice={{
            title: "Printer is ready",
            summary: "E2E Local Agent Printer is ready.",
            detail: "This printer is ready for approved MSCQR printing.",
            tone: "success",
          }}
          printQuantity="1"
          onPrintQuantityChange={() => undefined}
          readyToPrintCount={10}
          maxRunQuantity={10}
          registeredPrinters={[readyLocalPrinterProfile as any]}
          onRefreshPrinters={() => undefined}
          selectedPrinterProfileId="printer-profile-1"
          onSelectedPrinterProfileIdChange={() => undefined}
          selectedPrinterProfile={readyLocalPrinterProfile as any}
          detectedPrinters={[readyLocalPrinter as any]}
          selectedPrinterId="e2e-local-printer"
          onSelectedPrinterIdChange={() => undefined}
          switchingPrinter={false}
          onSwitchSelectedPrinter={() => undefined}
          relinkingPrinter={false}
          selectedLocalProfileRegistrationStale={false}
          onRelinkSelectedPrinter={() => undefined}
          onPrintDiagnosticTestLabel={() => undefined}
          printing={false}
          onStartPrint={() => undefined}
          selectedPrinterCanPrint
          printJobId={null}
          printProgressPrinterName={null}
          printProgressDispatchMode={null}
          formatDispatchModeLabel={() => "Local connector"}
          directRemainingToPrint={null}
          onRefreshPrintStatus={() => undefined}
          recentPrintJobs={[]}
          onAbandonPrintJob={() => undefined}
          onClose={() => undefined}
          {...overrides}
        />
      </MemoryRouter>,
    );

  it("shows max per-run print quantity and constrains the quantity input", () => {
    renderPrintDialog({ readyToPrintCount: 919, maxRunQuantity: 919, printQuantity: "919" });

    const input = screen.getByTestId("print-job-quantity-input");
    expect(input).toHaveAttribute("max", "919");
    expect(screen.getByText("Maximum per run: 919 labels")).toBeInTheDocument();
    expect(screen.getByText("QR labels ready to print: 919")).toBeInTheDocument();
  });

  it("allows 2000 labels when more than 2000 remain", () => {
    renderPrintDialog({ readyToPrintCount: 5000, maxRunQuantity: 2000, printQuantity: "2000" });

    const input = screen.getByTestId("print-job-quantity-input");
    expect(input).toHaveAttribute("max", "2000");
    expect(input).toHaveValue(2000);
    expect(screen.getByText("Maximum per run: 2,000 labels")).toBeInTheDocument();
  });

  it("passes typed quantity changes through the caller clamp", () => {
    const onPrintQuantityChange = vi.fn();
    renderPrintDialog({ readyToPrintCount: 5000, maxRunQuantity: 2000, printQuantity: "2000", onPrintQuantityChange });

    fireEvent.change(screen.getByTestId("print-job-quantity-input"), { target: { value: "2001" } });
    expect(onPrintQuantityChange).toHaveBeenCalledWith("2001");
  });

  const noop = () => undefined;

  it("enables print start when an E2E local helper-ready printer is selected", () => {
    renderPrintDialog();

    expect(screen.getByTestId("print-job-start-button")).toBeEnabled();
    expect(screen.getByText("Stop and refresh appear after a print run starts.")).toBeInTheDocument();
  });

  it("keeps print start disabled when backend lifecycle readiness blocks the batch", () => {
    renderPrintDialog({
      printBatch: {
        ...readyBatch,
        lifecycleState: "DRAFT",
        printReadiness: {
          printable: false,
          batchId: "batch-1",
          currentLifecycleState: "DRAFT",
          requiredPreviousStep: "Allocate QR labels to this manufacturer before printing.",
          userMessage: "This batch needs to be allocated before printing.",
          recoveryAction: "complete_previous_batch_step",
          canRetry: false,
          canRepairAutomatically: false,
          reasonCode: "batch_lifecycle_blocked",
          availableToPrint: 10,
        },
      } as any,
      readyToPrintCount: 10,
    });

    expect(screen.getByText("QR labels ready to print: 10")).toBeInTheDocument();
    expect(screen.getAllByText("This batch needs to be allocated before printing.").length).toBeGreaterThan(0);
    expect(screen.getByTestId("print-job-start-button")).toBeDisabled();
  });

  it("keeps print start disabled when the local helper is unavailable", () => {
    renderPrintDialog({
      selectedPrinterCanPrint: false,
      selectedPrinterNotice: {
        title: "Printer helper is not available",
        summary: "MSCQR could not reach the printer helper on this computer.",
        detail: "The printer helper is not available on this computer right now.",
        tone: "danger",
      },
    });

    expect(screen.getByTestId("print-job-start-button")).toBeDisabled();
    expect(screen.getByTestId("print-job-start-button")).toHaveAttribute(
      "aria-description",
      "The printer helper is not available on this computer right now.",
    );
  });

  it("shows relink CTA and keeps print start disabled when saved local printer registration is stale", () => {
    const onRelink = vi.fn();
    renderPrintDialog({
      selectedPrinterCanPrint: false,
      selectedLocalProfileRegistrationStale: true,
      onRelinkSelectedPrinter: onRelink,
      selectedPrinterNotice: {
        title: "Printer is ready",
        summary: "The printer is ready on this computer, but the saved printer link belongs to an older connector install.",
        detail: "Relink this saved printer to the current connector before starting the print run.",
        tone: "warning",
      },
    });

    expect(screen.getByText("Saved printer link is stale")).toBeInTheDocument();
    expect(screen.getByTestId("print-job-start-button")).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: "Relink saved printer" }));
    expect(onRelink).toHaveBeenCalled();
  });

  it("offers a safe close action for failed print runs with no confirmed items", () => {
    const onAbandon = vi.fn();
    renderPrintDialog({
      recentPrintJobs: [
        {
          id: "job-failed",
          status: "FAILED",
          printMode: "LOCAL_AGENT",
          quantity: 1,
          createdAt: new Date().toISOString(),
          failureReason: "Printer agent did not acknowledge issued label before deadline.",
          printer: { name: "E2E Local Agent Printer" },
          session: { confirmedItems: 0, remainingToPrint: 1 },
        } as any,
      ],
      onAbandonPrintJob: onAbandon,
    });

    fireEvent.click(screen.getByRole("button", { name: "Close and release labels" }));
    expect(onAbandon).toHaveBeenCalledWith("job-failed");
  });

  it("shows pause, resume, stop, cooldown, and reissue controls for print operations", () => {
    const onOpenControl = vi.fn();
    const onResume = vi.fn();
    const onOpenReissue = vi.fn();
    renderPrintDialog({
      printCooldownRemainingSeconds: 90,
      recentPrintJobs: [
        {
          id: "job-active",
          jobNumber: "PJ-ACTIVE",
          status: "SENT",
          printMode: "LOCAL_AGENT",
          quantity: 12,
          itemCount: 12,
          awaitingConfirmation: true,
          createdAt: new Date().toISOString(),
          printer: { name: "E2E Local Agent Printer" },
          session: { status: "ACTIVE", confirmedItems: 4, remainingToPrint: 8, failedItems: 1 },
        } as any,
        {
          id: "job-paused",
          jobNumber: "PJ-PAUSED",
          status: "PAUSED",
          printMode: "LOCAL_AGENT",
          quantity: 10,
          itemCount: 10,
          createdAt: new Date().toISOString(),
          printer: { name: "E2E Local Agent Printer" },
          session: { status: "PAUSED", confirmedItems: 5, remainingToPrint: 5 },
        } as any,
        {
          id: "job-confirmed",
          jobNumber: "PJ-CONFIRMED",
          status: "CONFIRMED",
          pipelineState: "LOCKED",
          printMode: "LOCAL_AGENT",
          quantity: 10,
          itemCount: 10,
          createdAt: new Date().toISOString(),
          printer: { name: "E2E Local Agent Printer" },
          session: { confirmedItems: 10, remainingToPrint: 0 },
        } as any,
      ],
      onOpenPrintControlDialog: onOpenControl,
      onResumePrintJob: onResume,
      onOpenPrintReissueDialog: onOpenReissue,
    });

    expect(screen.getByText(/Printing is cooling down/i)).toBeInTheDocument();
    expect(screen.getByText(/Try again after 90 seconds/i)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Pause printing" }));
    fireEvent.click(screen.getAllByRole("button", { name: "Stop printing" })[0]);
    expect(onOpenControl).toHaveBeenCalledWith("pause", expect.objectContaining({ id: "job-active" }));
    expect(onOpenControl).toHaveBeenCalledWith("stop", expect.objectContaining({ id: "job-active" }));
    expect(screen.getByRole("button", { name: "Resume printing" })).toBeDisabled();
    expect(screen.queryByRole("button", { name: /Labels physically printed/i })).not.toBeInTheDocument();
    expect(screen.getByText(/Waiting for connector physical confirmation/i)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Request reissue" }));
    expect(onOpenReissue).toHaveBeenCalledWith(expect.objectContaining({ id: "job-confirmed" }));
  });

  it("shows exact recovery range and captured operator in the batch operations modal", () => {
    render(
      <MemoryRouter>
        <LicenseeBatchWorkspaceDialog
          open
          onOpenChange={noop}
          workspace={{
            sourceBatchId: "batch-1",
            focusBatchId: "batch-1",
            sourceBatchName: "Launch batch",
            sourceBatchRow: null,
            licensee: { id: "lic-1", name: "Acme", prefix: "ACM" },
            sourceCreatedAt: "2026-06-18T10:00:00.000Z",
            sourceUpdatedAt: "2026-06-18T10:00:00.000Z",
            sourceOriginalRangeStart: "QR-000001",
            sourceOriginalRangeEnd: "QR-000100",
            originalTotalCodes: 100,
            remainingUnassignedCodes: 0,
            remainingRangeStart: null,
            remainingRangeEnd: null,
            assignedCodes: 100,
            pendingPrintableCodes: 95,
            printedCodes: 5,
            redeemedCodes: 0,
            blockedCodes: 0,
            manufacturerCount: 1,
            allocations: [],
            manufacturerSummary: [],
            manufacturerOperational: manufacturerOperational({
              assignedLabelCount: 100,
              confirmedPrintedCount: 5,
              remainingLabelCount: 95,
              originalAssignedRangeStart: "QR-000001",
              originalAssignedRangeEnd: "QR-000100",
              remainingPrintableRangeStart: "QR-000006",
              remainingPrintableRangeEnd: "QR-000100",
              nextPrintableLabelCode: "QR-000006",
            }),
            printedAt: null,
          }}
          manufacturers={[]}
          assignManufacturerId=""
          assignQuantity=""
          assigning={false}
          onAssignManufacturerChange={noop}
          onAssignQuantityChange={noop}
          onSubmitAssign={noop}
          onOpenRename={noop}
          onOpenAllocationMap={noop}
          onDownloadAudit={noop}
          onDelete={noop}
          canAssignManufacturer={false}
          canDelete={false}
          exportingAudit={false}
          historyLoading={false}
          historyLogs={[]}
          historyLastUpdatedAt={null}
          onRefreshHistory={noop}
          recentPrintJobs={[
            {
              id: "job-1",
              jobNumber: "PJ-1",
              status: "PARTIALLY_COMPLETED",
              pipelineState: "STOPPED",
              printMode: "LOCAL_AGENT",
              quantity: 10,
              itemCount: 10,
              createdAt: "2026-06-18T10:01:00.000Z",
              printer: { name: "ZDesigner" },
              operator: { name: "Priya Operator" },
              session: {
                confirmedItems: 5,
                pendingUnconfirmedItems: 5,
                failedItems: 0,
                remainingToPrint: 5,
                recoveryNeeded: true,
                recoveryRange: { startCode: "QR-000006", endCode: "QR-000010", count: 5 },
                nextPrintableIndex: "QR-000006",
              },
            } as any,
          ]}
          printJobsLoading={false}
          canRequestReissue
          reissueReason="Damaged stock"
          onReissueReasonChange={noop}
          onRequestReissue={noop}
          reissuingJobId={null}
          initialTab="operations"
        />
      </MemoryRouter>
    );

    expect(screen.getByText("Continue from label QR-000006.")).toBeInTheDocument();
    expect(screen.getByText("Recover unconfirmed label range QR-000006 to QR-000010. Do not start a later range until this recovery is resolved.")).toBeInTheDocument();
    expect(screen.getByText("Pending/unconfirmed 5")).toBeInTheDocument();
    expect(screen.getByText("Operator: Priya Operator")).toBeInTheDocument();
  });

  it("renders manufacturer batch modal with remaining labels, requested range, and no source-batch sample proof", () => {
    render(
      <MemoryRouter>
        <LicenseeBatchWorkspaceDialog
          open
          onOpenChange={noop}
          role="manufacturer"
          workspace={{
            sourceBatchId: "batch-mfg",
            focusBatchId: "batch-mfg",
            sourceBatchName: "Manufacturer Launch Batch",
            sourceBatchRow: null,
            licensee: { id: "lic-1", name: "Acme", prefix: "ACM" },
            sourceCreatedAt: "2026-06-18T10:00:00.000Z",
            sourceUpdatedAt: "2026-06-18T10:00:00.000Z",
            sourceOriginalRangeStart: "QR-000001",
            sourceOriginalRangeEnd: "QR-001000",
            originalTotalCodes: 1000,
            remainingUnassignedCodes: 0,
            remainingRangeStart: "QR-000075",
            remainingRangeEnd: "QR-001000",
            assignedCodes: 1000,
            pendingPrintableCodes: 925,
            printedCodes: 74,
            redeemedCodes: 1,
            blockedCodes: 0,
            manufacturerCount: 1,
            allocations: [
              {
                batchId: "batch-mfg",
                batchName: "Manufacturer Launch Batch",
                manufacturerId: "mfg-1",
                manufacturerName: "Factory",
                allocatedCodes: 1000,
                printableCodes: 925,
                printedCodes: 74,
                redeemedCodes: 1,
                blockedCodes: 0,
                createdAt: "2026-06-18T10:00:00.000Z",
                batchRangeStart: "QR-000001",
                batchRangeEnd: "QR-001000",
                currentRangeStart: "QR-000075",
                currentRangeEnd: "QR-001000",
              },
            ],
            manufacturerSummary: [],
            manufacturerOperational: manufacturerOperational({
              assignedLabelCount: 1000,
              confirmedPrintedCount: 74,
              scannedCount: 1,
              blockedCount: 0,
              remainingLabelCount: 925,
              originalAssignedRangeStart: "QR-000001",
              originalAssignedRangeEnd: "QR-001000",
              remainingPrintableRangeStart: "QR-000075",
              remainingPrintableRangeEnd: "QR-001000",
              nextPrintableLabelCode: "QR-000075",
            }),
            printedAt: null,
          }}
          manufacturers={[]}
          assignManufacturerId=""
          assignQuantity=""
          assigning={false}
          onAssignManufacturerChange={noop}
          onAssignQuantityChange={noop}
          onSubmitAssign={noop}
          onOpenRename={noop}
          onOpenAllocationMap={noop}
          onDownloadAudit={noop}
          onDelete={noop}
          canAssignManufacturer={false}
          canDelete={false}
          exportingAudit={false}
          historyLoading={false}
          historyLogs={[]}
          historyLastUpdatedAt={null}
          onRefreshHistory={noop}
          recentPrintJobs={[
            {
              id: "job-range",
              jobNumber: "PJ-RANGE",
              status: "CONFIRMED",
              pipelineState: "PRINT_CONFIRMED",
              printMode: "LOCAL_AGENT",
              quantity: 10,
              itemCount: 10,
              rangeStart: "QR-000065",
              rangeEnd: "QR-000074",
              createdAt: "2026-06-18T10:01:00.000Z",
              printer: { name: "ZDesigner" },
              operator: { name: "Priya Operator" },
              session: { confirmedItems: 10, remainingToPrint: 0 },
            } as any,
          ]}
          printJobsLoading={false}
          canRequestReissue
          reissueReason="Damaged labels"
          onReissueReasonChange={noop}
          onRequestReissue={noop}
            reissuingJobId={null}
            reissueRequests={[
              {
                id: "reissue-ready",
                status: "APPROVED",
                reason: "Damaged labels",
                printJobId: "job-range",
                printJob: { jobNumber: "PJ-RANGE" },
              },
            ]}
            reissueRequestsMode="print"
            initialTab="operations"
            securePrinterReady={false}
          />
      </MemoryRouter>
    );

    expect(screen.getAllByText(/remaining labels/i).length).toBeGreaterThan(0);
    expect(screen.getByText((_, element) => element?.textContent === "925 remaining labels")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Confirmed prints/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Stopped prints/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Replacement labels/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Pending re-issue requests/i })).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /Confirmed prints/i }));
    expect(screen.getByText("QR-000065 to QR-000074")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Back to operations/i }));
    fireEvent.click(screen.getByRole("button", { name: /Replacement labels/i }));
    expect(screen.queryByText(/source batch/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Sample scan proof/i)).not.toBeInTheDocument();
    expect(screen.getByText(/Printer verification expired\. Refresh printer helper before printing\./)).toBeInTheDocument();
  });

  it("renders super-admin governance modal without manufacturer-local print controls", () => {
    const onDecide = vi.fn();
    render(
      <MemoryRouter>
        <LicenseeBatchWorkspaceDialog
          open
          onOpenChange={noop}
          role="super_admin"
          workspace={{
            sourceBatchId: "batch-super",
            focusBatchId: "batch-super",
            sourceBatchName: "Platform Batch",
            sourceBatchRow: null,
            licensee: { id: "lic-1", name: "Acme", prefix: "ACM" },
            sourceCreatedAt: "2026-06-18T10:00:00.000Z",
            sourceUpdatedAt: "2026-06-18T10:00:00.000Z",
            sourceOriginalRangeStart: "QR-000001",
            sourceOriginalRangeEnd: "QR-000100",
            originalTotalCodes: 100,
            remainingUnassignedCodes: 0,
            remainingRangeStart: "QR-000076",
            remainingRangeEnd: "QR-000100",
            assignedCodes: 100,
            pendingPrintableCodes: 25,
            printedCodes: 75,
            redeemedCodes: 0,
            blockedCodes: 2,
            manufacturerCount: 1,
            allocations: [],
            manufacturerSummary: [],
            manufacturerOperational: manufacturerOperational({
              assignedLabelCount: 100,
              confirmedPrintedCount: 75,
              blockedCount: 2,
              remainingLabelCount: 25,
              originalAssignedRangeStart: "QR-000001",
              originalAssignedRangeEnd: "QR-000100",
              remainingPrintableRangeStart: "QR-000076",
              remainingPrintableRangeEnd: "QR-000100",
              nextPrintableLabelCode: "QR-000076",
            }),
            printedAt: null,
          }}
          manufacturers={[]}
          assignManufacturerId=""
          assignQuantity=""
          assigning={false}
          onAssignManufacturerChange={noop}
          onAssignQuantityChange={noop}
          onSubmitAssign={noop}
          onOpenRename={noop}
          onOpenAllocationMap={noop}
          onDownloadAudit={noop}
          onDelete={noop}
          canAssignManufacturer={false}
          canDelete={false}
          exportingAudit={false}
          historyLoading={false}
          historyLogs={[]}
          historyLastUpdatedAt={null}
          onRefreshHistory={noop}
          recentPrintJobs={[]}
          printJobsLoading={false}
          canRequestReissue
          reissueReason=""
          onReissueReasonChange={noop}
          onRequestReissue={noop}
          reissuingJobId={null}
          reissueDecisionNote="Approved after review"
          onReissueDecisionNoteChange={noop}
          onDecideReissueRequest={onDecide}
          reissueRequests={[
            {
              id: "reissue-1",
              status: "PENDING",
              targetApproverRole: "SUPER_ADMIN",
              quantity: 2,
              reason: "Damaged confirmed labels",
              requestedBy: { name: "Licensee Admin" },
              batch: { name: "Platform Batch" },
            },
          ]}
          initialTab="operations"
        />
      </MemoryRouter>
    );

    expect(screen.getByText(/Super admin approves or rejects replacement allocation/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Approve replacement allocation" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Print replacement labels" })).not.toBeInTheDocument();
    expect(screen.queryByText(/Sample scan proof/i)).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Approve replacement allocation" }));
    expect(onDecide).toHaveBeenCalledWith("reissue-1", "approve");
  });

  it("shows active local-agent print controls without waiting for recent jobs", () => {
    const onOpenControl = vi.fn();
    const onRefresh = vi.fn();
    renderPrintDialog({
      printJobId: "job-live",
      printProgressPhase: "Local print session active",
      printProgressTotal: 30,
      printProgressPrinted: 5,
      printProgressPrinterName: "ZDesigner ZT410-300dpi ZPL",
      printProgressDispatchMode: "LOCAL_AGENT",
      directRemainingToPrint: 25,
      recentPrintJobs: [],
      onOpenPrintControlDialog: onOpenControl,
      onRefreshPrintStatus: onRefresh,
    });

    expect(screen.getByText("5 printed")).toBeInTheDocument();
    expect(screen.getByText("25 remaining")).toBeInTheDocument();
    expect(screen.getByText("30 total labels")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Stop print run" }));
    fireEvent.click(screen.getByRole("button", { name: "Refresh status" }));
    expect(onOpenControl).toHaveBeenCalledWith("stop", expect.objectContaining({ id: "job-live" }));
    expect(onRefresh).toHaveBeenCalled();
    expect(screen.queryByRole("button", { name: "Pause print run" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Resume print run" })).not.toBeInTheDocument();
  });

  it("shows manufacturer recovery context in start print without release checklist", () => {
    renderPrintDialog({
      isManufacturerMode: true,
      manufacturerRecoveryContext: {
        printJobId: "job-recovery",
        jobNumber: "PJ-RECOVERY",
        rangeLabel: "Recovery labels QR-000006 to QR-000010",
      },
      selectedPrinterCanPrint: false,
      selectedPrinterNotice: {
        title: "Printer verification expired",
        summary: "Printer verification expired. Refresh printer helper before printing.",
        detail: "Refresh printer helper before starting this print run.",
        tone: "danger",
      },
    });

    expect(screen.getByText("Manufacturer print readiness")).toBeInTheDocument();
    expect(screen.getByText(/PJ-RECOVERY/)).toBeInTheDocument();
    expect(screen.getByText(/Recovery labels QR-000006 to QR-000010/)).toBeInTheDocument();
    expect(screen.queryByText("Batch release checklist")).not.toBeInTheDocument();
    expect(screen.queryByText("Sample verified")).not.toBeInTheDocument();
    expect(screen.getByTestId("print-job-start-button")).toBeDisabled();
    expect(screen.getAllByText("Refresh printer helper before starting this print run.").length).toBeGreaterThan(0);
  });

  it.each([0, 1, 6])("shows only stop and refresh in the progress modal at %i/10 confirmed labels", (printed) => {
    const onStop = vi.fn();
    const onRefresh = vi.fn();
    const activeJob = {
      id: `job-${printed}`,
      status: "SENT",
      pipelineState: printed === 0 ? "QUEUED" : "PRINT_CONFIRMED",
      printMode: "LOCAL_AGENT",
      quantity: 10,
      itemCount: 10,
      createdAt: new Date().toISOString(),
      printer: { name: "ZDesigner ZT410-300dpi ZPL" },
      session: { status: "ACTIVE", totalItems: 10, confirmedItems: printed, remainingToPrint: 10 - printed },
    } as any;

    render(
      <PrintProgressDialog
        open
        phase={printed === 0 ? "Waiting for connector to claim job" : "Local print session active"}
        total={10}
        printed={printed}
        remaining={10 - printed}
        printerName="ZDesigner ZT410-300dpi ZPL"
        modeLabel="Printer on this computer"
        activeJob={activeJob}
        onStop={onStop}
        onRefresh={onRefresh}
      />,
    );

    expect(screen.queryByRole("button", { name: "Pause print run" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Resume print run" })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Stop print run" }));
    fireEvent.click(screen.getByRole("button", { name: "Refresh status" }));
    expect(onStop).toHaveBeenCalledWith(expect.objectContaining({ id: activeJob.id }));
    expect(onRefresh).toHaveBeenCalled();
  });

  it("shows progress modal controls while waiting for printer confirmation", () => {
    render(
      <PrintProgressDialog
        open
        phase="Waiting for printer confirmation"
        total={10}
        printed={6}
        remaining={4}
        printerName="ZDesigner ZT410-300dpi ZPL"
        modeLabel="Printer on this computer"
        activeJob={{
          id: "job-confirming",
          status: "SENT",
          pipelineState: "PRINTER_ACKNOWLEDGED",
          printMode: "LOCAL_AGENT",
          quantity: 10,
          itemCount: 10,
          createdAt: new Date().toISOString(),
          printer: { name: "ZDesigner ZT410-300dpi ZPL" },
          awaitingConfirmation: true,
          session: { status: "ACTIVE", totalItems: 10, confirmedItems: 6, remainingToPrint: 4 },
        } as any}
      />,
    );

    expect(screen.queryByRole("button", { name: "Pause print run" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Resume print run" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Stop print run" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Refresh status" })).toBeInTheDocument();
  });

  it("shows payload rejection as a failed-before-print state with recoverable labels", () => {
    render(
      <PrintProgressDialog
        open
        phase="Failed before print"
        total={10}
        printed={0}
        remaining={10}
        printerName="ZDesigner ZT410-300dpi ZPL"
        modeLabel="Printer on this computer"
        error="The print payload was blocked before reaching the printer. No labels were printed. Use diagnostic test label or contact admin."
        activeJob={{
          id: "job-rejected",
          status: "FAILED",
          pipelineState: "NEEDS_OPERATOR_ACTION",
          printMode: "LOCAL_AGENT",
          quantity: 10,
          itemCount: 10,
          failureReason: "Generated ZPL looks unsafe for this Zebra profile.",
          createdAt: new Date().toISOString(),
          printer: { name: "ZDesigner ZT410-300dpi ZPL" },
          session: { status: "FAILED", totalItems: 10, confirmedItems: 0, remainingToPrint: 10 },
        } as any}
      />,
    );

    expect(screen.getByText("Print did not start")).toBeInTheDocument();
    expect(screen.getByText("Failed before print")).toBeInTheDocument();
    expect(screen.getByText("0 printed")).toBeInTheDocument();
    expect(screen.getByText("10 remaining")).toBeInTheDocument();
    expect(screen.getByText(/10 labels remain recoverable after the payload fix/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Stop print run" })).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Open printer setup" })).toHaveAttribute("href", "/printer-setup");
    expect(screen.getByRole("button", { name: "Refresh connector" })).toBeInTheDocument();
  });

  it("shows stopped partially completed progress as recoverable without live controls", () => {
    render(
      <PrintProgressDialog
        open
        phase="Partially completed"
        total={10}
        printed={4}
        remaining={6}
        printerName="ZDesigner ZT410-300dpi ZPL"
        modeLabel="Printer on this computer"
        activeJob={{
          id: "job-stopped",
          status: "PARTIALLY_COMPLETED",
          pipelineState: "STOPPED",
          printMode: "LOCAL_AGENT",
          quantity: 10,
          itemCount: 10,
          createdAt: new Date().toISOString(),
          printer: { name: "ZDesigner ZT410-300dpi ZPL" },
          session: { status: "STOPPED", totalItems: 10, confirmedItems: 4, remainingToPrint: 6 },
        } as any}
      />,
    );

    expect(screen.getByText("Print run stopped")).toBeInTheDocument();
    expect(screen.getByText("4 of 10 labels confirmed. Unprinted labels remain recoverable.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Pause print run" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Resume print run" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Stop print run" })).not.toBeInTheDocument();
  });

  it("shows stopped partially completed current print run as recoverable without live controls", () => {
    renderPrintDialog({
      printJobId: "job-stopped",
      printProgressPhase: "Partially completed",
      printProgressTotal: 10,
      printProgressPrinted: 4,
      printProgressPrinterName: "ZDesigner ZT410-300dpi ZPL",
      printProgressDispatchMode: "LOCAL_AGENT",
      directRemainingToPrint: 6,
      recentPrintJobs: [
        {
          id: "job-stopped",
          status: "PARTIALLY_COMPLETED",
          pipelineState: "STOPPED",
          printMode: "LOCAL_AGENT",
          quantity: 10,
          itemCount: 10,
          createdAt: new Date().toISOString(),
          printer: { name: "ZDesigner ZT410-300dpi ZPL" },
          session: { status: "STOPPED", totalItems: 10, confirmedItems: 4, remainingToPrint: 6 },
        } as any,
      ],
    });

    expect(screen.getByText("Print run stopped")).toBeInTheDocument();
    expect(screen.getByText("Confirmed labels stay printed. Unprinted labels remain recoverable through the controlled recovery flow.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Pause print run" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Resume print run" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Stop print run" })).not.toBeInTheDocument();
  });

  it("uses backend completed session state for active local-agent progress", () => {
    renderPrintDialog({
      printJobId: "job-live",
      printProgressPhase: "Print job completed",
      printProgressTotal: 10,
      printProgressPrinted: 7,
      printProgressPrinterName: "ZDesigner ZT410-300dpi ZPL",
      printProgressDispatchMode: "LOCAL_AGENT",
      directRemainingToPrint: 3,
      recentPrintJobs: [
        {
          id: "job-live",
          status: "SENT",
          printMode: "LOCAL_AGENT",
          quantity: 10,
          itemCount: 10,
          createdAt: new Date().toISOString(),
          printer: { name: "ZDesigner ZT410-300dpi ZPL" },
          session: { status: "COMPLETED", totalItems: 10, confirmedItems: 10, remainingToPrint: 0 },
        } as any,
      ],
    });

    expect(screen.getByText("Print run completed")).toBeInTheDocument();
    expect(screen.getByText("10 printed")).toBeInTheDocument();
    expect(screen.getByText("0 remaining")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Pause print run" })).not.toBeInTheDocument();
  });

  it("requires audit reasons before submitting pause and reissue dialogs", () => {
    renderPrintDialog({
      printControlDialog: {
        action: "pause",
        job: {
          id: "job-active",
          status: "SENT",
          printMode: "LOCAL_AGENT",
          quantity: 3,
          createdAt: new Date().toISOString(),
          session: { confirmedItems: 1, remainingToPrint: 2 },
        } as any,
        reason: "",
        submitting: false,
      },
      printReissueDialog: {
        job: {
          id: "job-confirmed",
          status: "CONFIRMED",
          printMode: "LOCAL_AGENT",
          quantity: 3,
          createdAt: new Date().toISOString(),
        } as any,
        reason: "",
        submitting: false,
      },
    });

    expect(screen.getByRole("button", { name: "Pause print run", hidden: true })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Submit request", hidden: true })).toBeDisabled();
    expect(screen.getAllByText(/reason is required|enter a clear/i).length).toBeGreaterThan(0);
  });

  it("shows queue confirmation unavailable without stale compatible-setup copy", () => {
    renderPrintDialog({
      recentPrintJobs: [
        {
          id: "job-awaiting",
          status: "SENT",
          pipelineState: "NEEDS_OPERATOR_ACTION",
          printMode: "LOCAL_AGENT",
          quantity: 1,
          createdAt: new Date().toISOString(),
          failureReason:
            "Sent to printer queue, but local queue confirmation is unavailable. Operator confirmation is required before labels are treated as printed.",
          printer: { name: "E2E Local Agent Printer" },
          awaitingConfirmation: true,
          session: { confirmedItems: 0, remainingToPrint: 0, awaitingConfirmationCount: 1 },
        } as any,
      ],
    });

    expect(screen.getByText(/Sent to printer, awaiting\/manual confirmation/i)).toBeInTheDocument();
    expect(screen.queryByText(/compatible setup/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Remaining 0/i)).not.toBeInTheDocument();
  });

  it("offers a diagnostic test label action for local-agent printers", () => {
    const onDiagnostic = vi.fn();
    renderPrintDialog({ onPrintDiagnosticTestLabel: onDiagnostic });

    fireEvent.click(screen.getByRole("button", { name: "Print diagnostic test label" }));
    expect(onDiagnostic).toHaveBeenCalled();
  });

  it("lets users close the rename dialog when batch context is missing", () => {
    const onOpenChange = vi.fn();

    render(
      <RenameBatchDialog
        open
        onOpenChange={onOpenChange}
        batch={null}
        value=""
        onValueChange={() => undefined}
        onSubmit={() => undefined}
        saving={false}
      />,
    );

    expect(screen.getByText("Choose a batch to rename")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Close dialog" }));
    expect(onOpenChange).toHaveBeenCalledWith(false);
  });

  it("lets users close the delete dialog when batch context is missing", () => {
    const onOpenChange = vi.fn();

    render(
      <DeleteBatchDialog
        open
        onOpenChange={onOpenChange}
        batch={null}
        deleting={false}
        onConfirm={() => undefined}
      />,
    );

    expect(screen.getByText("Choose a batch to delete")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Close dialog" }));
    expect(onOpenChange).toHaveBeenCalledWith(false);
  });

  it("lets users exit the print dialog when no batch is selected", () => {
    const onClose = vi.fn();

    render(
      <MemoryRouter>
        <BatchPrintJobDialog
          open
          onOpenChange={() => undefined}
          printBatch={null}
          selectedPrinterNotice={{
            title: "Printer status unavailable",
            summary: "No printer selected.",
            detail: "Choose a printer before continuing.",
            tone: "warning",
          }}
          printQuantity=""
          onPrintQuantityChange={() => undefined}
          readyToPrintCount={0}
          maxRunQuantity={0}
          registeredPrinters={[]}
          onRefreshPrinters={() => undefined}
          selectedPrinterProfileId=""
          onSelectedPrinterProfileIdChange={() => undefined}
          selectedPrinterProfile={null}
          detectedPrinters={[]}
          selectedPrinterId=""
          onSelectedPrinterIdChange={() => undefined}
          switchingPrinter={false}
          onSwitchSelectedPrinter={() => undefined}
          relinkingPrinter={false}
          selectedLocalProfileRegistrationStale={false}
          onRelinkSelectedPrinter={() => undefined}
          onPrintDiagnosticTestLabel={() => undefined}
          printing={false}
          onStartPrint={() => undefined}
          selectedPrinterCanPrint={false}
          printJobId={null}
          printProgressPrinterName={null}
          printProgressDispatchMode={null}
          formatDispatchModeLabel={() => "Local connector"}
          directRemainingToPrint={null}
          onRefreshPrintStatus={() => undefined}
          recentPrintJobs={[]}
          onAbandonPrintJob={() => undefined}
          onClose={onClose}
        />
      </MemoryRouter>,
    );

    expect(screen.getByText("Choose a batch before starting a print run")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Close dialog" }));
    expect(onClose).toHaveBeenCalled();
  });

  it("lets users close the allocate range dialog when licensee context is missing", () => {
    const onRangeDialogOpenChange = vi.fn();

    render(
      <LicenseeDialogs
        isCreateOpen={false}
        onCreateDialogOpenChange={() => undefined}
        creating={false}
        latestInviteLink=""
        onCopyInviteLink={() => undefined}
        createForm={{
          name: "",
          prefix: "",
          description: "",
          isActive: true,
          brandName: "",
          location: "",
          website: "",
          supportEmail: "",
          supportPhone: "",
          adminName: "",
          adminEmail: "",
          rangeStart: "",
          rangeEnd: "",
          createManufacturerNow: false,
          manufacturerName: "",
          manufacturerEmail: "",
        }}
        onCreateFormChange={() => undefined}
        onCreateSubmit={() => undefined}
        isEditOpen={false}
        onEditDialogOpenChange={() => undefined}
        savingEdit={false}
        editForm={null}
        onEditFormChange={() => undefined}
        onEditSubmit={() => undefined}
        isUserOpen={false}
        onUserDialogOpenChange={() => undefined}
        creatingUser={false}
        userForm={null}
        onUserFormChange={() => undefined}
        onUserSubmit={() => undefined}
        rangeOpen
        onRangeDialogOpenChange={onRangeDialogOpenChange}
        rangeLoading={false}
        rangeForm={null}
        onRangeFormChange={() => undefined}
        onRangeSubmit={() => undefined}
        progressState={{ open: false }}
      />,
    );

    expect(screen.getByText("Select a brand before adding QR labels")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Close dialog" }));
    expect(onRangeDialogOpenChange).toHaveBeenCalledWith(false);
  });

  it("lets users close the manufacturer dialog when no manufacturer is selected", () => {
    const onOpenChange = vi.fn();

    render(
      <ManufacturerDetailsDialog
        open
        onOpenChange={onOpenChange}
        manufacturer={null}
        stats={undefined}
        onOpenBatches={() => undefined}
      />,
    );

    expect(screen.getByText("Choose a manufacturer to review")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Close dialog" }));
    expect(onOpenChange).toHaveBeenCalledWith(false);
  });
});
