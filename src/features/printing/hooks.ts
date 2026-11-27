import { useQuery } from "@tanstack/react-query";

import apiClient from "@/lib/api-client";
import { unwrapParsedApiResponse } from "@/lib/api/query-utils";
import { queryKeys } from "@/lib/query-keys";
import { chooseStablePrinterSelection, type LocalPrinterAgentSnapshot } from "@/lib/printer-diagnostics";

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
  localInventory: unknown[];
  localBinding: { printerId: string | null; agentId: string | null; deviceFingerprint: string | null } | null;
  authorizationRejected?: boolean;
  deviceVerified?: boolean;
  localResult?: Awaited<ReturnType<typeof apiClient.getLocalPrintAgentStatus>>;
};

type PrinterRuntimeLoadOptions = {
  force?: boolean;
  previous?: Pick<ManufacturerPrinterRuntime, "remoteStatus" | "registeredPrinters" | "localAgent" | "detectedPrinters" | "preferredPrinterId">;
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

function buildFallbackPrinterStatus(printers: LocalPrinterDTO[], error?: string | null, previous?: PrinterConnectionStatusDTO): PrinterConnectionStatusDTO {
  return {
    ...previous,
    connected: false,
    trusted: false,
    compatibilityMode: false,
    degraded: true,
    compatibilityReason: null,
    eligibleForPrinting: false,
    connectionClass: "BLOCKED",
    trustMode: "SIGNED_ATTESTATION",
    securePrinterSession: false,
    freshHelperHeartbeat: false,
    helperConnection: false,
    eligiblePrinter: false,
    signedAttestation: { required: true, present: false, signatureValid: false, fresh: false, issuedAt: null },
    missingFields: ["printerRegistration", "freshHelperHeartbeat", "helperConnection", "eligiblePrinter", "securePrinterSession", "selectedPrinter"],
    recoveryAction: "refresh_printer_status",
    stale: true,
    requiredForPrinting: true,
    trustStatus: "UNAVAILABLE",
    trustReason: "Printer verification is unavailable. Refresh printer status and try again.",
    lastHeartbeatAt: previous?.lastHeartbeatAt || null,
    ageSeconds: null,
    registrationId: previous?.registrationId || null,
    agentId: previous?.agentId || null,
    deviceFingerprint: previous?.deviceFingerprint || null,
    mtlsFingerprint: previous?.mtlsFingerprint || null,
    printerName: previous?.printerName || null,
    printerId: previous?.printerId || null,
    selectedPrinterId: previous?.selectedPrinterId || null,
    selectedPrinterName: previous?.selectedPrinterName || null,
    deviceName: previous?.deviceName || null,
    agentVersion: previous?.agentVersion || null,
    capabilitySummary: previous?.capabilitySummary || null,
    printers: previous?.printers?.length ? previous.printers : printers,
    calibrationProfile: previous?.calibrationProfile || null,
    refreshPaused: true,
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

export async function loadManufacturerPrinterRuntimeSnapshot(
  includeInactive = true,
  options: PrinterRuntimeLoadOptions = {}
): Promise<ManufacturerPrinterRuntime> {
  const printerRequestOptions = options.force ? { force: true, minIntervalMs: 0 } : undefined;
  const [remoteResponse, localResponse, registeredPrinterResponse] = await Promise.all([
    apiClient.getPrinterConnectionStatus(printerRequestOptions).catch(() => ({ success: false, data: undefined, error: "Printer verification unavailable", status: 0, degraded: false, code: undefined, errorCode: undefined })),
    apiClient.getLocalPrintAgentStatus().catch(() => ({ success: false, data: undefined, error: "Local print agent is unavailable" })),
    apiClient.listRegisteredPrinters(includeInactive, printerRequestOptions).catch(() => ({ success: false, data: undefined, error: "Printer roster unavailable", status: 0 })),
  ]);

  const local = localResponse.success ? localResponse.data : undefined;
  const localInventory = local?.printers || [];
  const localPrinters = normalizeLocalPrinterRows(localInventory);
  const verificationUnavailable = Boolean(
    remoteResponse.degraded ||
    String(remoteResponse.code || remoteResponse.errorCode || "").toUpperCase() === "RATE_LIMITED" ||
    (remoteResponse.data as { refreshPaused?: boolean; rateLimited?: boolean } | undefined)?.refreshPaused ||
    (remoteResponse.data as { refreshPaused?: boolean; rateLimited?: boolean } | undefined)?.rateLimited
  );
  const parsedRemoteStatus = remoteResponse.success && remoteResponse.data && !verificationUnavailable
    ? printerConnectionStatusSchema.safeParse(remoteResponse.data)
    : null;
  const authorizationRejected = [remoteResponse, registeredPrinterResponse].some((response) => [401, 403].includes(Number(response.status || 0)));
  const previous = authorizationRejected ? undefined : options.previous;
  const remoteStatus =
    parsedRemoteStatus?.success && !authorizationRejected
      ? ({
          ...parsedRemoteStatus.data,
          printers:
            normalizeLocalPrinterRows(parsedRemoteStatus.data.printers || []).length > 0
              ? normalizeLocalPrinterRows(parsedRemoteStatus.data.printers || [])
              : localPrinters,
        } satisfies PrinterConnectionStatusDTO)
      : buildFallbackPrinterStatus(authorizationRejected ? [] : localPrinters, "Printer verification unavailable", previous?.remoteStatus);

  const detectedPrinters = localPrinters.length ? localPrinters : remoteStatus.printers || [];
  const preferredPrinterId =
    String(
      chooseStablePrinterSelection(
        detectedPrinters,
        (localResponse.data as { selectedPrinterId?: string; printerId?: string } | undefined)?.selectedPrinterId ||
          null,
        remoteStatus.selectedPrinterId,
        remoteStatus.printerId
      )?.printerId || ""
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
    detectedPrinters: authorizationRejected ? [] : detectedPrinters,
    registeredPrinters: authorizationRejected ? [] : registeredPrinterResponse.success
      ? registeredPrinterArraySchema.safeParse(registeredPrinterResponse.data).data || []
      : [],
    preferredPrinterId: authorizationRejected ? null : preferredPrinterId,
    localInventory: authorizationRejected ? [] : localInventory,
    localBinding: !authorizationRejected && local ? {
      printerId: local.selectedPrinterId || local.printerId || null,
      agentId: local.agentId || null, deviceFingerprint: local.deviceFingerprint || null,
    } : null,
    authorizationRejected,
    localResult: authorizationRejected ? undefined : localResponse,
  };
}
