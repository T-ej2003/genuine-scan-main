import { describe, expect, it } from "vitest";

import { printJobCreateFailureMessage } from "@/features/batches/batch-print-operations";
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
      "The saved printer is not linked to this computer's Zebra printer. Choose the ZDesigner printer again or refresh printer setup."
    );
    expect(printJobCreateFailureMessage({ errorCode: "printer_mapping_missing" })).toBe(
      "The saved printer is not linked to this computer's Zebra printer. Choose the ZDesigner printer again or refresh printer setup."
    );
    expect(printJobCreateFailureMessage({ status: 401 })).toBe(
      "Your session expired. Refresh or sign in again, then start the print run."
    );
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
