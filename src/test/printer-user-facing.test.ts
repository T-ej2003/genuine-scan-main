import { describe, expect, it } from "vitest";

import { buildPrinterSupportSummary, sanitizePrinterUiError } from "@/lib/printer-user-facing";

describe("printer user-facing helpers", () => {
  it("redacts localhost and trust details from printer errors", () => {
    expect(sanitizePrinterUiError("The browser could not reach localhost:17866")).toBe(
      "The printer helper is not available on this computer right now."
    );

    expect(sanitizePrinterUiError("Heartbeat signature verification failed")).toBe(
      "MSCQR is still checking the secure printer connection. Refresh and try again in a moment."
    );
  });

  it("redacts duplicate printer registration errors", () => {
    expect(
      sanitizePrinterUiError(
        "Invalid `prisma.printer.create()` invocation: Unique constraint failed on the fields: (`licenseeId`, `ipAddress`, `port`)"
      )
    ).toBe("A saved printer profile already uses this connection. Open the existing setup to edit it or remove it first.");
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
    expect(summary).toContain("Saved printer type: Saved office printer");
    expect(summary).toContain("Current status: Printer helper is not available");
    expect(summary).not.toContain("localhost");
    expect(summary).not.toContain("signature verification");
    expect(summary).not.toContain("workstation connector");
  });
});
