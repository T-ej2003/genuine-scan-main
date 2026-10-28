import type { MutableRefObject } from "react";
import apiClient from "@/lib/api-client";
import { buildSecurePrintReadiness } from "@/lib/secure-printer-readiness";
import { buildSupportDiagnosticsPayload, captureSupportScreenshot } from "@/lib/support-diagnostics";
import { PRINTER_FAILURE_REPORT_COOLDOWN_MS } from "./manufacturerPrinterConnectionUtils";
import type { User } from "@/types";
import type { PrinterConnectionStatusDTO } from "../../../shared/contracts/runtime/printing.ts";

export function createManufacturerPrinterFailureReporter({ user, printerFailureReportRef, printerFailureInFlightRef }: {
  user: User | null;
  printerFailureReportRef: MutableRefObject<{ signature: string; at: number }>;
  printerFailureInFlightRef: MutableRefObject<boolean>;
}) {
  const isSecurePrinterStatusReady = (status?: PrinterConnectionStatusDTO | null) => buildSecurePrintReadiness(status).ready;
  return async (params: {
    localResult: Awaited<ReturnType<typeof apiClient.getLocalPrintAgentStatus>>;
    remoteStatus: PrinterConnectionStatusDTO | null;
    printers: Array<{ printerId: string; printerName: string }>;
  }) => {
    if (!user || user.role !== "manufacturer") return;
    const remoteReady = isSecurePrinterStatusReady(params.remoteStatus);
    if (remoteReady) {
      printerFailureReportRef.current = { signature: "", at: 0 };
      return;
    }

    const localReady = Boolean(params.localResult.success && (params.localResult.data as { connected?: boolean } | undefined)?.connected);
    if (localReady && params.remoteStatus?.compatibilityMode) return;

    const localError = String(params.localResult.error || "").trim();
    const remoteError = String(params.remoteStatus?.error || "").trim();
    const hasKnownPrinter =
      params.printers.length > 0 ||
      Boolean(params.remoteStatus?.selectedPrinterId || params.remoteStatus?.printerId);
    const errorSummary = `${localError} ${remoteError} ${String(params.remoteStatus?.trustReason || "")}`.toLowerCase();
    const agentUnavailable =
      errorSummary.includes("local print agent unavailable") ||
      errorSummary.includes("local print agent is unavailable") ||
      errorSummary.includes("heartbeat failed");

    if (!hasKnownPrinter && agentUnavailable) return;
    if (!hasKnownPrinter) return;

    const signature = [
      localError || "no-local-error",
      remoteError || "no-remote-error",
      String(params.remoteStatus?.trustReason || ""),
      String(params.remoteStatus?.connectionClass || ""),
      String(params.remoteStatus?.selectedPrinterId || params.remoteStatus?.printerId || ""),
    ].join("|");
    const now = Date.now();
    if (
      printerFailureReportRef.current.signature === signature &&
      now - printerFailureReportRef.current.at < PRINTER_FAILURE_REPORT_COOLDOWN_MS
    ) {
      return;
    }
    if (printerFailureInFlightRef.current) return;

    printerFailureInFlightRef.current = true;
    printerFailureReportRef.current = { signature, at: now };
    try {
      const screenshot = await captureSupportScreenshot();
      const form = new FormData();
      form.append(
        "title",
        `Auto printer connection failure: ${
          params.remoteStatus?.selectedPrinterName || params.remoteStatus?.printerName || "Unknown printer"
        }`
      );
      form.append(
        "description",
        [
          "Automatic printer failure report from manufacturer console.",
          `Local agent: ${params.localResult.success ? "reachable" : "unreachable"}`,
          `Server class: ${params.remoteStatus?.connectionClass || "BLOCKED"}`,
          localError ? `Local error: ${localError}` : "",
          remoteError ? `Server error: ${remoteError}` : "",
        ]
          .filter(Boolean)
          .join("\n")
      );
      form.append("sourcePath", `${window.location.pathname}${window.location.search}`);
      form.append("pageUrl", window.location.href);
      form.append("autoDetected", "true");
      form.append(
        "diagnostics",
        JSON.stringify({
          ...buildSupportDiagnosticsPayload(),
          printer: {
            local: params.localResult.success ? params.localResult.data : null,
            remote: params.remoteStatus,
            discoveredPrinters: params.printers,
          },
        })
      );
      if (screenshot) form.append("screenshot", screenshot);
      await apiClient.createSupportIssueReport(form);
    } catch {
      // Keep the normal UX path clear.
    } finally {
      printerFailureInFlightRef.current = false;
    }
  };

}
