import React from "react";
import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

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
