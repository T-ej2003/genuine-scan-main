import type { MutableRefObject } from "react";
import apiClient from "@/lib/api-client";
import { buildSupportDiagnosticsPayload, captureSupportScreenshot } from "@/lib/support-diagnostics";
import { PRINTER_FAILURE_AUTO_REPORT_COOLDOWN_MS } from "./print-workflow-utils";
import type { LocalPrinterRow, PrinterConnectionStatus } from "./types";

export function createBatchPrinterFailureReporter({ selectedPrinterId, printerStatus, detectedPrinters, printerFailureReportRef, printerFailureInFlightRef }: {
  selectedPrinterId: string;
  printerStatus: PrinterConnectionStatus;
  detectedPrinters: LocalPrinterRow[];
  printerFailureReportRef: MutableRefObject<{ signature: string; at: number }>;
  printerFailureInFlightRef: MutableRefObject<boolean>;
}) {
  return async (params: {
    context: string;
    reason: string;
    diagnostics?: Record<string, unknown>;
  }) => {
    const now = Date.now();
    const signature = `${params.context}|${params.reason}|${
      selectedPrinterId || printerStatus.selectedPrinterId || printerStatus.printerId || ""
    }`;

    if (
      printerFailureReportRef.current.signature === signature &&
      now - printerFailureReportRef.current.at < PRINTER_FAILURE_AUTO_REPORT_COOLDOWN_MS
    ) {
      return true;
    }
    if (printerFailureInFlightRef.current) return true;

    printerFailureInFlightRef.current = true;
    printerFailureReportRef.current = { signature, at: now };

    try {
      const screenshot = await captureSupportScreenshot();
      const form = new FormData();
      form.append(
        "title",
        `Auto printer failure (${params.context}): ${printerStatus.selectedPrinterName || printerStatus.printerName || "Unknown printer"}`
      );
      form.append("description", params.reason);
      form.append("sourcePath", `${window.location.pathname}${window.location.search}`);
      form.append("pageUrl", window.location.href);
      form.append("autoDetected", "true");
      form.append(
        "diagnostics",
        JSON.stringify({
          ...buildSupportDiagnosticsPayload(),
          printerStatus,
          selectedPrinterId,
          detectedPrinters,
          context: params.context,
          details: params.diagnostics || null,
        })
      );
      if (screenshot) form.append("screenshot", screenshot);
      const response = await apiClient.createSupportIssueReport(form);
      return Boolean(response.success);
    } catch {
      // Avoid interrupting print flow when auto-reporting fails.
      return false;
    } finally {
      printerFailureInFlightRef.current = false;
    }
  };

}
