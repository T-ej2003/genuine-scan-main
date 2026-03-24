import { useQuery } from "@tanstack/react-query";

import apiClient from "@/lib/api-client";
import { parseWithSchema, unwrapParsedApiResponse } from "@/lib/api/query-utils";
import { queryKeys } from "@/lib/query-keys";
import type { LocalPrinterAgentSnapshot } from "@/lib/printer-diagnostics";

import {
  localPrinterArraySchema,
  printJobArraySchema,
  printerConnectionStatusSchema,
  registeredPrinterArraySchema,
  LocalPrinterDTO,
  PrintJobDTO,
  PrinterConnectionStatusDTO,
  RegisteredPrinterDTO,
} from "../../../shared/contracts/runtime/printing.ts";

export type ManufacturerPrinterRuntime = {
  localAgent: LocalPrinterAgentSnapshot;
  remoteStatus: PrinterConnectionStatusDTO;
  detectedPrinters: LocalPrinterDTO[];
  registeredPrinters: RegisteredPrinterDTO[];
  preferredPrinterId: string | null;
};

export function normalizeLocalPrinterRows(rows: unknown): LocalPrinterDTO[] {
  if (!Array.isArray(rows)) return [];

  const result: LocalPrinterDTO[] = [];
  for (const row of rows) {
    if (!row || typeof row !== "object") continue;

    const printerId = String((row as { printerId?: unknown; id?: unknown }).printerId || (row as { id?: unknown }).id || "").trim();
    const printerName = String((row as { printerName?: unknown; name?: unknown }).printerName || (row as { name?: unknown }).name || "").trim();
    if (!printerId || !printerName) continue;

    result.push({
      printerId,
      printerName,
      model: String((row as { model?: unknown }).model || "").trim() || null,
      connection: String((row as { connection?: unknown; transport?: unknown }).connection || (row as { transport?: unknown }).transport || "").trim() || null,
      online: Boolean((row as { online?: unknown }).online ?? true),
      isDefault: Boolean((row as { isDefault?: unknown }).isDefault),
      protocols: Array.isArray((row as { protocols?: unknown[] }).protocols) ? ((row as { protocols: string[] }).protocols ?? []) : [],
      languages: Array.isArray((row as { languages?: unknown[] }).languages) ? ((row as { languages: string[] }).languages ?? []) : [],
      mediaSizes: Array.isArray((row as { mediaSizes?: unknown[] }).mediaSizes) ? ((row as { mediaSizes: string[] }).mediaSizes ?? []) : [],
      dpi: Number.isFinite(Number((row as { dpi?: unknown }).dpi)) ? Number((row as { dpi?: unknown }).dpi) : null,
    });

    if (result.length >= 40) break;
  }

  return result;
}

function buildFallbackPrinterStatus(printers: LocalPrinterDTO[], error?: string | null): PrinterConnectionStatusDTO {
  return {
    connected: false,
    trusted: false,
    compatibilityMode: false,
    compatibilityReason: null,
    eligibleForPrinting: false,
    connectionClass: "BLOCKED",
    stale: true,
    requiredForPrinting: true,
    trustStatus: "UNREGISTERED",
    trustReason: "No trusted printer registration",
    lastHeartbeatAt: null,
    ageSeconds: null,
    registrationId: null,
    agentId: null,
    deviceFingerprint: null,
    mtlsFingerprint: null,
    printerName: null,
    printerId: null,
    selectedPrinterId: null,
    selectedPrinterName: null,
    deviceName: null,
    agentVersion: null,
    capabilitySummary: null,
    printers,
    calibrationProfile: null,
    error: error || "Printer status unavailable",
  };
}

export function usePrintJobs(batchId?: string, limit = 8, enabled = true) {
  return useQuery({
    queryKey: queryKeys.printing.jobs(batchId, limit),
    enabled,
    queryFn: async (): Promise<PrintJobDTO[]> =>
      unwrapParsedApiResponse(
        await apiClient.listPrintJobs({ batchId, limit }),
        printJobArraySchema,
        "Failed to load print jobs"
      ),
  });
}

export function useManufacturerPrinterRuntime(includeInactive = true, enabled = true) {
  return useQuery({
    queryKey: queryKeys.printing.runtime(includeInactive),
    enabled,
    refetchInterval: enabled ? 6_000 : false,
    queryFn: async (): Promise<ManufacturerPrinterRuntime> => {
      const [remoteResponse, localResponse, registeredPrinterResponse] = await Promise.all([
        apiClient.getPrinterConnectionStatus(),
        apiClient.getLocalPrintAgentStatus(),
        apiClient.listRegisteredPrinters(includeInactive),
      ]);

      const localPrinters = normalizeLocalPrinterRows((localResponse.data as { printers?: unknown[] } | undefined)?.printers || []);
      const parsedRemoteStatus =
        remoteResponse.success && remoteResponse.data
          ? unwrapParsedApiResponse(remoteResponse, printerConnectionStatusSchema, "Printer status unavailable")
          : null;
      const remoteStatus =
        parsedRemoteStatus
          ? ({
              ...parsedRemoteStatus,
              printers:
                normalizeLocalPrinterRows(parsedRemoteStatus.printers || []).length > 0
                  ? normalizeLocalPrinterRows(parsedRemoteStatus.printers || [])
                  : localPrinters,
            } satisfies PrinterConnectionStatusDTO)
          : buildFallbackPrinterStatus(localPrinters, remoteResponse.error || localResponse.error || "Printer status unavailable");

      const detectedPrinters = remoteStatus.printers && remoteStatus.printers.length > 0 ? remoteStatus.printers : localPrinters;
      const preferredPrinterId = String(
        remoteStatus.selectedPrinterId ||
          (localResponse.data as { selectedPrinterId?: string; printerId?: string } | undefined)?.selectedPrinterId ||
          detectedPrinters.find((row) => row.isDefault)?.printerId ||
          detectedPrinters[0]?.printerId ||
          ""
      ).trim() || null;

      return {
        localAgent: {
          reachable: Boolean(localResponse.success),
          connected: Boolean((localResponse.data as { connected?: boolean } | undefined)?.connected),
          error: localResponse.success
            ? String((localResponse.data as { error?: string } | undefined)?.error || "").trim() || null
            : String(localResponse.error || "Local print agent is unavailable"),
          checkedAt: new Date().toISOString(),
        },
        remoteStatus,
        detectedPrinters,
        registeredPrinters: registeredPrinterResponse.success
          ? parseWithSchema(
              registeredPrinterArraySchema,
              Array.isArray(registeredPrinterResponse.data) ? registeredPrinterResponse.data : [],
              "Failed to load printers"
            )
          : [],
        preferredPrinterId,
      };
    },
  });
}
