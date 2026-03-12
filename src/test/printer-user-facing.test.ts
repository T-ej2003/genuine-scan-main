import { describe, expect, it } from "vitest";

import { buildPrinterSupportSummary, sanitizePrinterUiError } from "@/lib/printer-user-facing";

describe("printer user-facing helpers", () => {
  it("redacts localhost and trust details from printer errors", () => {
    expect(sanitizePrinterUiError("The browser could not reach localhost:17866")).toBe(
      "The workstation connector is not available on this device right now."
    );

    expect(sanitizePrinterUiError("Heartbeat signature verification failed")).toBe(
      "The secure printer connection is not ready yet. Refresh and try again in a moment."
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
      printerSummaryTitle: "Workstation connector is not available",
      printerSummaryBody: "MSCQR could not reach the printing connector on this workstation.",
      managedPrinter: {
        name: "Canon TS4100i series",
        connectionType: "NETWORK_IPP",
        deliveryMode: "DIRECT",
      },
    });

    expect(summary).toContain("MSCQR printing support summary");
    expect(summary).toContain("Managed printer type: Office / AirPrint printer");
    expect(summary).not.toContain("localhost");
    expect(summary).not.toContain("signature verification");
  });
});
