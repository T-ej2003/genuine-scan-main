import { describe, expect, it } from "vitest";

import {
  deriveManagedPrinterAutoDetect,
  buildPrinterReadinessDisplay,
  getPrinterDiagnosticSummary,
  shouldPreferNetworkDirectSummary,
} from "@/lib/printer-diagnostics";

describe("printer diagnostics summary", () => {
  it("blocks old connectors even when a printer is visible", () => {
    const summary = getPrinterDiagnosticSummary({
      localAgent: { reachable: true, connected: true, error: null },
      remoteStatus: {
        connected: false,
        trusted: false,
        compatibilityMode: false,
        eligibleForPrinting: false,
        connectionClass: "BLOCKED",
        stale: false,
        lastHeartbeatAt: new Date().toISOString(),
        ageSeconds: 2,
        agentVersion: "2026.5.23",
        buildVersion: "2026.5.23",
        connectorUpdateRequired: true,
        printers: [{ printerId: "zebra-wifi", printerName: "MSCQR Zebra ZT410 WiFi", online: true }],
      },
      printers: [{ printerId: "zebra-wifi", printerName: "MSCQR Zebra ZT410 WiFi", online: true }],
      selectedPrinterId: "zebra-wifi",
    });

    expect(summary.state).toBe("connector_update_required");
    expect(summary.title).toBe("Connector update required");
    expect(summary.detail).toContain("Detected: 2026.5.23");
  });

  it("recommends the USB Zebra when the saved WiFi queue is blocked", () => {
    const summary = getPrinterDiagnosticSummary({
      localAgent: { reachable: true, connected: true, error: null },
      remoteStatus: {
        connected: false,
        trusted: false,
        compatibilityMode: false,
        eligibleForPrinting: false,
        connectionClass: "BLOCKED",
        stale: false,
        lastHeartbeatAt: new Date().toISOString(),
        ageSeconds: 2,
        printers: [],
      },
      printers: [
        {
          printerId: "MSCQR Zebra ZT410 WiFi",
          printerName: "MSCQR Zebra ZT410 WiFi",
          model: "ZDesigner ZT410-300dpi ZPL",
          connection: "network",
          languages: ["ZPL"],
          online: false,
          windowsPortName: "MSCQR-ZT410-WIFI-9100",
          windowsPortHost: "10.45.144.9",
          windowsPortNumber: 9100,
          queueStatus: "Error",
          queueHasErrors: true,
          stuckJobCount: 1,
        },
        {
          printerId: "ZDesigner ZT410-300dpi ZPL",
          printerName: "ZDesigner ZT410-300dpi ZPL",
          model: "ZDesigner ZT410-300dpi ZPL",
          connection: "usb",
          portName: "USB001",
          languages: ["ZPL"],
          online: true,
          usbAvailable: true,
        },
      ],
      selectedPrinterId: "MSCQR Zebra ZT410 WiFi",
    });

    expect(summary.state).toBe("blocked_with_alternative");
    expect(summary.title).toBe("Network Zebra queue is broken");
    expect(summary.summary).toContain("10.45.144.9:9100");
    expect(summary.detail).toContain("USB001");
    expect(summary.recommendedPrinter?.printerId).toBe("ZDesigner ZT410-300dpi ZPL");
  });

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

  it("keeps a known-ready printer as refreshing during transient rate limits", () => {
    const summary = getPrinterDiagnosticSummary({
      localAgent: { reachable: true, connected: true, error: null },
      remoteStatus: {
        connected: true,
        trusted: true,
        compatibilityMode: false,
        eligibleForPrinting: true,
        connectionClass: "TRUSTED",
        stale: false,
        lastHeartbeatAt: new Date().toISOString(),
        ageSeconds: 3,
        selectedPrinterId: "printer-1",
        selectedPrinterName: "Zebra ZD421",
        refreshPaused: true,
        rateLimited: true,
      },
      printers: [{ printerId: "printer-1", printerName: "Zebra ZD421", online: true }],
      selectedPrinterId: "printer-1",
    });
    const display = buildPrinterReadinessDisplay({
      diagnostics: summary,
      ready: true,
      refreshPaused: true,
      rateLimited: true,
      stale: false,
      trusted: true,
      compatibilityMode: false,
      identityLabel: "Zebra ZD421",
    });

    expect(display.modeLabel).toBe("Refreshing");
    expect(display.badgeLabel).toBe("Refreshing");
    expect(display.tone).toBe("success");
    expect(display.blocksPrintStart).toBe(false);
  });

  it("blocks print start when trust is stale even if a printer was selected", () => {
    const summary = getPrinterDiagnosticSummary({
      localAgent: { reachable: true, connected: true, error: null },
      remoteStatus: {
        connected: true,
        trusted: true,
        compatibilityMode: false,
        eligibleForPrinting: false,
        connectionClass: "BLOCKED",
        stale: true,
        lastHeartbeatAt: new Date(Date.now() - 120_000).toISOString(),
        ageSeconds: 120,
        selectedPrinterId: "printer-1",
        selectedPrinterName: "Zebra ZD421",
      },
      printers: [{ printerId: "printer-1", printerName: "Zebra ZD421", online: true }],
      selectedPrinterId: "printer-1",
    });
    const display = buildPrinterReadinessDisplay({
      diagnostics: summary,
      ready: false,
      refreshPaused: false,
      rateLimited: false,
      stale: true,
      trusted: true,
      compatibilityMode: false,
      identityLabel: "Zebra ZD421",
    });

    expect(summary.state).toBe("heartbeat_stale");
    expect(display.blocksPrintStart).toBe(true);
    expect(display.modeLabel).toBe("Needs review");
  });

  it("does not show ready when secure printer verification is missing mTLS evidence", () => {
    const summary = getPrinterDiagnosticSummary({
      localAgent: { reachable: true, connected: true, error: null },
      remoteStatus: {
        connected: false,
        trusted: false,
        compatibilityMode: false,
        eligibleForPrinting: false,
        connectionClass: "BLOCKED",
        stale: true,
        trustStatus: "FAILED",
        trustReason: "mTLS client certificate fingerprint header missing",
        lastHeartbeatAt: new Date(Date.now() - 145_000).toISOString(),
        ageSeconds: 145,
        selectedPrinterId: "ZDesigner ZT410-300dpi ZPL",
        selectedPrinterName: "ZDesigner ZT410-300dpi ZPL",
        printers: [{ printerId: "ZDesigner ZT410-300dpi ZPL", printerName: "ZDesigner ZT410-300dpi ZPL", online: true }],
      },
      printers: [{ printerId: "ZDesigner ZT410-300dpi ZPL", printerName: "ZDesigner ZT410-300dpi ZPL", online: true }],
      selectedPrinterId: "ZDesigner ZT410-300dpi ZPL",
    });
    const display = buildPrinterReadinessDisplay({
      diagnostics: summary,
      ready: false,
      stale: true,
      trusted: false,
      compatibilityMode: false,
      identityLabel: "ZDesigner ZT410-300dpi ZPL",
    });

    expect(display.badgeLabel).toBe("Needs check");
    expect(display.modeLabel).toBe("Needs review");
    expect(display.summary).toBe("Printer verification expired. Refresh printer helper before printing.");
    expect(display.blocksPrintStart).toBe(true);
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
