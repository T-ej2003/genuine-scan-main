import { describe, expect, it } from "vitest";

import { getPrinterDiagnosticSummary } from "@/lib/printer-diagnostics";

describe("printer diagnostics summary", () => {
  it("flags agent unreachable when local agent cannot be reached", () => {
    const summary = getPrinterDiagnosticSummary({
      localAgent: {
        reachable: false,
        connected: false,
        error: "Local print agent is unavailable",
      },
      remoteStatus: null,
      printers: [],
      selectedPrinterId: null,
    });

    expect(summary.state).toBe("agent_unreachable");
    expect(summary.badgeLabel).toBe("Agent offline");
  });

  it("flags no printers detected when agent is reachable without printer inventory", () => {
    const summary = getPrinterDiagnosticSummary({
      localAgent: {
        reachable: true,
        connected: false,
        error: null,
      },
      remoteStatus: {
        connected: false,
        trusted: false,
        compatibilityMode: false,
        eligibleForPrinting: false,
        connectionClass: "BLOCKED",
        stale: false,
        trustStatus: "UNREGISTERED",
        trustReason: "No trusted printer registration",
        lastHeartbeatAt: null,
        ageSeconds: null,
        printers: [],
        error: "No printer registration",
      },
      printers: [],
      selectedPrinterId: null,
    });

    expect(summary.state).toBe("no_printers_detected");
    expect(summary.title).toBe("No printer connection detected");
  });

  it("flags trust blocked when printer is visible but server validation rejects it", () => {
    const summary = getPrinterDiagnosticSummary({
      localAgent: {
        reachable: true,
        connected: true,
        error: null,
      },
      remoteStatus: {
        connected: false,
        trusted: false,
        compatibilityMode: false,
        eligibleForPrinting: false,
        connectionClass: "BLOCKED",
        stale: false,
        trustStatus: "BLOCKED",
        trustReason: "Heartbeat signature verification failed",
        lastHeartbeatAt: new Date().toISOString(),
        ageSeconds: 4,
        printerName: "Zebra ZD421",
        printerId: "printer-1",
        selectedPrinterId: "printer-1",
        selectedPrinterName: "Zebra ZD421",
        printers: [
          {
            printerId: "printer-1",
            printerName: "Zebra ZD421",
            online: true,
          },
        ],
        error: "Heartbeat signature verification failed",
      },
      printers: [
        {
          printerId: "printer-1",
          printerName: "Zebra ZD421",
          online: true,
        },
      ],
      selectedPrinterId: "printer-1",
    });

    expect(summary.state).toBe("trust_blocked");
    expect(summary.badgeLabel).toBe("Trust blocked");
  });
});
