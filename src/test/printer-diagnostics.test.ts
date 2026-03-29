import { describe, expect, it } from "vitest";

import {
  deriveManagedPrinterAutoDetect,
  getPrinterDiagnosticSummary,
  shouldPreferNetworkDirectSummary,
} from "@/lib/printer-diagnostics";

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
    expect(summary.badgeLabel).toBe("Helper offline");
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
    expect(summary.badgeLabel).toBe("Needs attention");
  });

  it("keeps the live local printer summary primary when local inventory exists", () => {
    expect(
      shouldPreferNetworkDirectSummary({
        printers: [
          {
            printerId: "canon-1",
            printerName: "Canon TS4100i series",
            online: true,
          },
        ],
        networkPrinter: {
          registryStatus: {
            state: "READY",
            summary: "Network printer validated",
          },
        },
      })
    ).toBe(false);
  });

  it("allows the network-direct summary when there is no local printer inventory", () => {
    expect(
      shouldPreferNetworkDirectSummary({
        printers: [],
        networkPrinter: {
          registryStatus: {
            state: "READY",
            summary: "Network printer validated",
          },
        },
      })
    ).toBe(true);
  });

  it("also prefers the managed-network summary for NETWORK_IPP profiles when no local printer inventory exists", () => {
    expect(
      shouldPreferNetworkDirectSummary({
        printers: [],
        networkPrinter: {
          registryStatus: {
            state: "READY",
            summary: "Site gateway online",
            detail: "Gateway heartbeat is current.",
          },
        },
      })
    ).toBe(true);
  });

  it("detects a raw TCP printer and prepares a network-direct route suggestion", () => {
    const suggestion = deriveManagedPrinterAutoDetect({
      printerId: "zebra-1",
      printerName: "Zebra ZD421",
      connection: "network",
      protocols: ["raw-9100"],
      languages: ["ZPL"],
      deviceUri: "socket://192.168.1.55:9100",
      online: true,
    });

    expect(suggestion.routeType).toBe("NETWORK_DIRECT");
    expect(suggestion.readiness).toBe("READY");
    expect(suggestion.host).toBe("192.168.1.55");
    expect(suggestion.port).toBe(9100);
    expect(suggestion.commandLanguage).toBe("ZPL");
  });

  it("detects an IPP printer and prepares a managed IPP suggestion", () => {
    const suggestion = deriveManagedPrinterAutoDetect({
      printerId: "canon-1",
      printerName: "Canon Office Printer",
      connection: "ipps",
      protocols: ["ipp", "ipps"],
      languages: [],
      deviceUri: "ipps://canon-office.local:631/ipp/print",
      online: true,
    });

    expect(suggestion.routeType).toBe("NETWORK_IPP");
    expect(suggestion.readiness).toBe("READY");
    expect(suggestion.host).toBe("canon-office.local");
    expect(suggestion.printerUri).toBe("ipps://canon-office.local:631/ipp/print");
    expect(suggestion.resourcePath).toBe("/ipp/print");
  });

  it("surfaces a template-only IPP suggestion when Bonjour is visible without a stable URI", () => {
    const suggestion = deriveManagedPrinterAutoDetect({
      printerId: "airprint-1",
      printerName: "Canon TS4100i series",
      connection: "bonjour",
      protocols: ["dnssd", "ipps"],
      languages: [],
      deviceUri: "dnssd://Canon%20TS4100i%20series._ipps._tcp.local./?uuid=123",
      online: true,
    });

    expect(suggestion.routeType).toBe("NETWORK_IPP");
    expect(suggestion.readiness).toBe("NEEDS_DETAILS");
    expect(suggestion.host || null).toBeNull();
  });
});
