import { describe, expect, it } from "vitest";

import { printJobCreateFailureMessage } from "@/features/batches/batch-print-operations";
import { chooseStablePrinterSelection, getPrinterDiagnosticSummary } from "@/lib/printer-diagnostics";
import { buildPrinterSupportSummary, sanitizePrinterUiError } from "@/lib/printer-user-facing";

describe("printer user-facing helpers", () => {
  it("redacts localhost and trust details from printer errors", () => {
    expect(sanitizePrinterUiError("The browser could not reach localhost:17866")).toBe(
      "The printer helper is not available on this computer right now."
    );

    expect(sanitizePrinterUiError("Heartbeat signature verification failed")).toBe(
      "MSCQR is still checking the secure printer connection. Refresh and try again in a moment."
    );

    expect(sanitizePrinterUiError("mTLS client certificate fingerprint header missing")).toBe(
      "Advanced secure printer verification is not set up yet. Printing can stay available while setup finishes."
    );

    expect(sanitizePrinterUiError("Too many printer status requests. Please wait before retrying.")).toBe(
      "Printer status refresh is temporarily paused. Printing can continue if the printer was already ready."
    );

    expect(
      sanitizePrinterUiError("Label sent to Windows spooler, but Get-PrintJob rejected print job id as UInt32.")
    ).toBe("Label was sent to Windows spooler but confirmation failed.");
  });

  it("redacts duplicate printer registration errors", () => {
    expect(
      sanitizePrinterUiError(
        "Invalid `prisma.printer.create()` invocation: Unique constraint failed on the fields: (`licenseeId`, `ipAddress`, `port`)"
      )
    ).toBe("A saved printer profile already uses this connection. Open the existing setup to edit it or remove it first.");
  });

  it("maps structured print-job creation errors to specific user guidance", () => {
    expect(printJobCreateFailureMessage({ errorCode: "missing_printer_session" })).toBe(
      "Refresh the printer connection, then start the print run again."
    );
    expect(printJobCreateFailureMessage({ errorCode: "printer_not_verified" })).toBe(
      "Finish printer verification or choose a verified printer before starting this print run."
    );
    expect(printJobCreateFailureMessage({ errorCode: "batch_not_printable" })).toBe(
      "There are no labels ready to print in this batch."
    );
    expect(printJobCreateFailureMessage({ errorCode: "invalid_printer" })).toBe(
      "Choose the ZDesigner printer under Printer on this computer, then refresh printer setup."
    );
    expect(
      printJobCreateFailureMessage({
        errorCode: "printer_selection_mismatch",
        message: "Fax/PDF printers cannot be used for MSCQR labels. Choose the ZDesigner label printer.",
      })
    ).toBe(
      "Fax/PDF printers cannot be used for MSCQR labels. Choose the ZDesigner label printer."
    );
    expect(printJobCreateFailureMessage({ errorCode: "printer_mapping_missing" })).toBe(
      "The saved printer is not linked to this computer's Zebra printer. Choose the ZDesigner printer again or refresh printer setup."
    );
    expect(printJobCreateFailureMessage({ errorCode: "printer_status_unavailable" })).toBe(
      "Printer status is temporarily unavailable."
    );
    expect(printJobCreateFailureMessage({ errorCode: "print_job_transaction_failed", requestId: "req-123" })).toBe(
      "Print job could not be saved. Request ID: req-123."
    );
    expect(printJobCreateFailureMessage({ errorCode: "print_item_reservation_failed" })).toBe(
      "Some labels are still locked by a failed print run. Close and release the failed run, then start printing again."
    );
    expect(printJobCreateFailureMessage({ errorCode: "print_signing_configuration_invalid", requestId: "req-456" })).toBe(
      "Print token signing is not configured correctly. Request ID: req-456. Contact support with this request ID."
    );
    expect(printJobCreateFailureMessage({ status: 401 })).toBe(
      "Your session expired. Refresh or sign in again, then start the print run."
    );
  });

  it("does not claim missing fields for invalid_payload without validation details", () => {
    expect(printJobCreateFailureMessage({ errorCode: "invalid_payload", requestId: "req-print-1" })).toBe(
      "Print job could not be started. Request ID: req-print-1. Please refresh printer setup and try again."
    );

    expect(
      printJobCreateFailureMessage({
        errorCode: "invalid_payload",
        details: { missingFields: ["printerId"], validationIssuePaths: ["printerId"] },
      })
    ).toBe("The print job request is missing required information. Refresh the page and try again.");
  });

  it("prefers ZDesigner over persisted Fax in printer diagnostics", () => {
    const printers = [
      {
        printerId: "Fax",
        printerName: "Fax",
        model: "Microsoft Shared Fax Driver",
        connection: "spooler",
        online: true,
        isDefault: false,
        languages: [],
        protocols: [],
        mediaSizes: [],
      },
      {
        printerId: "ZDesigner ZT410-300dpi ZPL",
        printerName: "ZDesigner ZT410-300dpi ZPL",
        model: "ZDesigner ZT410-300dpi ZPL",
        connection: "usb",
        online: true,
        isDefault: true,
        languages: ["ZPL"],
        protocols: ["usb"],
        mediaSizes: [],
      },
    ];

    expect(chooseStablePrinterSelection(printers, "Fax")?.printerId).toBe("ZDesigner ZT410-300dpi ZPL");

    const summary = getPrinterDiagnosticSummary({
      localAgent: { reachable: true, connected: true, checkedAt: "2026-05-18T17:17:40.725Z" },
      remoteStatus: {
        connected: true,
        trusted: false,
        compatibilityMode: true,
        eligibleForPrinting: true,
        stale: false,
        lastHeartbeatAt: "2026-05-18T17:17:40.725Z",
        ageSeconds: 15,
        printerId: "Fax",
        printerName: "Fax",
        selectedPrinterId: "Fax",
        selectedPrinterName: "Fax",
      },
      printers,
      selectedPrinterId: "Fax",
    });

    expect(summary.summary).toContain("ZDesigner ZT410-300dpi ZPL");
    expect(summary.summary).not.toContain("Fax");
  });

  it("builds a redacted support summary", () => {
    const summary = buildPrinterSupportSummary({
      localAgent: {
        reachable: false,
        connected: false,
        error: "Local print agent unavailable on localhost",
        checkedAt: null,
      },
      remoteStatus: {
        connected: false,
        trusted: false,
        compatibilityMode: false,
        eligibleForPrinting: false,
        stale: true,
        lastHeartbeatAt: "2026-03-12T10:00:00.000Z",
        ageSeconds: 20,
        error: "Heartbeat signature verification failed",
      },
      selectedPrinterName: "Canon TS4100i series",
      printerSummaryTitle: "Printer helper is not available",
      printerSummaryBody: "MSCQR could not reach the printer helper on this computer.",
      managedPrinter: {
        name: "Canon TS4100i series",
        connectionType: "NETWORK_IPP",
        deliveryMode: "DIRECT",
      },
    });

    expect(summary).toContain("MSCQR printing support summary");
    expect(summary).toContain("Printer found on this computer: No");
    expect(summary).toContain("Saved printer type: Saved shared printer");
    expect(summary).toContain("Current status: Printer helper is not available");
    expect(summary).not.toContain("localhost");
    expect(summary).not.toContain("signature verification");
    expect(summary).not.toContain("workstation connector");
  });
});
