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
