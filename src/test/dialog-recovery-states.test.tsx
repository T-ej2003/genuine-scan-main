import React from "react";
import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

import { PrintProgressDialog } from "@/components/printing/PrintProgressDialog";
import { BatchPrintJobDialog, DeleteBatchDialog, RenameBatchDialog } from "@/features/batches/components/BatchDialogs";
import { LicenseeDialogs } from "@/features/licensees/components/LicenseeDialogs";
import { ManufacturerDetailsDialog } from "@/features/manufacturers/components/ManufacturerDetailsDialog";

describe("dialog recovery states", () => {
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
    fireEvent.click(screen.getByRole("button", { name: "Request reissue" }));
    expect(onOpenReissue).toHaveBeenCalledWith(expect.objectContaining({ id: "job-confirmed" }));
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
