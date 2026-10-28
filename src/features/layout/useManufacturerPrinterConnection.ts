import { useEffect, useMemo, useRef, useState } from "react";

import { APP_PATHS } from "@/app/route-metadata";
import apiClient from "@/lib/api-client";
import { useActivePrintSessionSuppression } from "@/lib/active-print-session";
import { getOrCreateAnonDeviceId } from "@/lib/anon-device";
import {
  removeOptionalLocalStorageItem,
  removeOptionalSessionStorageItem,
  setOptionalLocalStorageItem,
} from "@/lib/consent";
import {
  chooseStablePrinterSelection,
  buildPrinterReadinessDisplay,
  getManagedPrinterDiagnosticSummary,
  getPrinterDiagnosticSummary,
  selectPreferredManagedPrinter,
  shouldPreferNetworkDirectSummary,
  type LocalPrinterAgentSnapshot,
} from "@/lib/printer-diagnostics";
import { sanitizePrinterUiError } from "@/lib/printer-user-facing";
import { buildSecurePrintReadiness } from "@/lib/secure-printer-readiness";
import { canPollVisibleDocument } from "@/lib/query-polling-policy";
import { buildSupportDiagnosticsPayload, captureSupportScreenshot } from "@/lib/support-diagnostics";
import { normalizeLocalPrinterRows } from "@/features/printing/hooks";
import {
  derivePrinterIdentity,
  formatPrinterTimestamp,
  type ManagedPrinterProfile,
} from "@/features/layout/components/PrinterDialogs";
import {
  buildHeartbeatPayloadFromLocalStatus,
  resolvePreferredLocalPrinter,
  type LocalPrinterStatusPayload,
} from "@/features/layout/printer-heartbeat-payload";
import {
  defaultPrinterStatus,
  DISABLE_E2E_PRINTER_AGENT_POLLING,
  PRINTER_DIALOG_SESSION_STORAGE_VERSION,
  PRINTER_FAILURE_REPORT_COOLDOWN_MS,
  PRINTER_ONBOARDING_STORAGE_VERSION,
} from "@/features/layout/manufacturerPrinterConnectionUtils";
import { usePrinterOnboardingAutoOpen } from "@/features/layout/usePrinterOnboardingAutoOpen";
import type { User } from "@/types";
import type { PrinterConnectionStatusDTO } from "../../../shared/contracts/runtime/printing.ts";

type ToastLike = (options: {
  title?: string;
  description?: string;
  variant?: "default" | "destructive";
}) => unknown;

const isSecurePrinterStatusReady = (status?: PrinterConnectionStatusDTO | null) =>
  buildSecurePrintReadiness(status).ready;

type UseManufacturerPrinterConnectionParams = {
  user: User | null;
  contextualHelpRoute: string;
  currentPath: string;
  navigate: (to: string) => void;
  toast: ToastLike;
};

export function useManufacturerPrinterConnection({
  user,
  contextualHelpRoute,
  currentPath,
  navigate,
  toast,
}: UseManufacturerPrinterConnectionParams) {
  const activePrintSuppressed = useActivePrintSessionSuppression();
  const detectedPrintersRef = useRef<NonNullable<PrinterConnectionStatusDTO["printers"]>>([]);
  const printerFailureReportRef = useRef<{ signature: string; at: number }>({ signature: "", at: 0 });
  const printerFailureInFlightRef = useRef(false);
  const configuredBackendUrlRef = useRef("");
  const printerStatusRef = useRef<PrinterConnectionStatusDTO>(defaultPrinterStatus);
  const syncInFlightRef = useRef<Promise<void> | null>(null);
  const syncRunIdRef = useRef(0);
  const statusRevisionRef = useRef(0);
  const lastEventServerTimeMsRef = useRef(0);
  const printerScope = JSON.stringify([
    user?.id, user?.role, user?.licenseeId, user?.orgId, user?.scopeVersion,
    user?.linkedLicensees?.map((link) => [link.id, link.orgId, link.scopeVersion, Boolean(link.isPrimary)]),
  ]);
  const activePrinterScopeRef = useRef(printerScope);
  activePrinterScopeRef.current = printerScope;
  const appliedPrinterScopeRef = useRef(printerScope);

  const [printerStatus, setPrinterStatus] = useState<PrinterConnectionStatusDTO>(defaultPrinterStatus);
  const [printerDialogOpen, setPrinterDialogOpen] = useState(false);
  const [printerOnboardingOpen, setPrinterOnboardingOpen] = useState(false);
  const [printerSwitching, setPrinterSwitching] = useState(false);
  const [printerStatusChecking, setPrinterStatusChecking] = useState(false);
  const [printerStatusLive, setPrinterStatusLive] = useState(false);
  const [printerStatusUpdatedAt, setPrinterStatusUpdatedAt] = useState<string | null>(null);
  const [localPrinterAgent, setLocalPrinterAgent] = useState<LocalPrinterAgentSnapshot>({
    reachable: false,
    connected: false,
    error: "Local print agent has not been checked yet.",
    checkedAt: null,
  });
  const [detectedPrinters, setDetectedPrinters] = useState<NonNullable<PrinterConnectionStatusDTO["printers"]>>([]);
  const [selectedLocalPrinterId, setSelectedLocalPrinterId] = useState("");
  const [managedPrinterProfiles, setManagedPrinterProfiles] = useState<ManagedPrinterProfile[]>([]);
  const [managedPrinterProfilesLoaded, setManagedPrinterProfilesLoaded] = useState(false);

  useEffect(() => {
    if (appliedPrinterScopeRef.current === printerScope) return;
    appliedPrinterScopeRef.current = printerScope;
    ++statusRevisionRef.current;
    ++syncRunIdRef.current;
    syncInFlightRef.current = null;
    lastEventServerTimeMsRef.current = 0;
    printerStatusRef.current = defaultPrinterStatus;
    setPrinterStatus(defaultPrinterStatus);
    setDetectedPrinters([]);
    setManagedPrinterProfiles([]);
    setManagedPrinterProfilesLoaded(false);
  }, [printerScope]);

  const printerDialogSessionKey =
    user?.role === "manufacturer" && user?.id
      ? `manufacturer-printer-dialog-opened:${PRINTER_DIALOG_SESSION_STORAGE_VERSION}:${user.id}`
      : null;
  const printerOnboardingStorageKey =
    user?.role === "manufacturer" && user?.id
      ? `manufacturer-printer-onboarding:${PRINTER_ONBOARDING_STORAGE_VERSION}:${user.id}:${getOrCreateAnonDeviceId()}`
      : null;

  const clearPrinterDialogSession = () => {
    if (!printerDialogSessionKey) return;
    try {
      removeOptionalSessionStorageItem(printerDialogSessionKey);
    } catch {
      // Ignore storage failures.
    }
  };

  const applyPrinterStatusSnapshot = (
    nextStatus: PrinterConnectionStatusDTO,
    options?: {
      fallbackPrinters?: NonNullable<PrinterConnectionStatusDTO["printers"]>;
      updatedAt?: string | null;
      revision?: number;
    }
  ) => {
    if (options?.revision !== undefined && options.revision !== statusRevisionRef.current) return;
    const fallbackPrinters = Array.isArray(options?.fallbackPrinters)
      ? options?.fallbackPrinters
      : detectedPrintersRef.current;
    const remotePrinters = normalizeLocalPrinterRows(nextStatus.printers || []);
    const mergedPrinters = remotePrinters.length > 0 ? remotePrinters : fallbackPrinters;

    setPrinterStatus((previous) => {
      if (options?.revision !== undefined && options.revision !== statusRevisionRef.current) return previous;
      const ready = isSecurePrinterStatusReady(nextStatus);
      const merged = {
        ...previous,
        ...nextStatus,
        degraded: ready ? false : typeof nextStatus.degraded === "boolean" ? nextStatus.degraded : Boolean(previous.degraded),
        refreshPaused: ready ? false : Boolean(nextStatus.refreshPaused ?? previous.refreshPaused),
        rateLimited: ready ? false : Boolean(nextStatus.rateLimited ?? previous.rateLimited),
        printers: mergedPrinters,
      };
      printerStatusRef.current = merged;
      return merged;
    });
    setDetectedPrinters(mergedPrinters);
    setPrinterStatusUpdatedAt(options?.updatedAt || nextStatus.lastHeartbeatAt || new Date().toISOString());

    setSelectedLocalPrinterId((previous) => {
      if (options?.revision !== undefined && options.revision !== statusRevisionRef.current) return previous;
      const fallbackPrinter = chooseStablePrinterSelection(
        mergedPrinters,
        previous,
        nextStatus.selectedPrinterId,
        nextStatus.printerId
      );
      return fallbackPrinter?.printerId || previous;
    });
  };

  const maybeAutoReportPrinterFailure = async (params: {
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

  const loadManagedPrinterProfiles = async (options?: { force?: boolean }) => {
    if (!user || user.role !== "manufacturer") return;

    const scope = printerScope;
    const response = await apiClient.listRegisteredPrinters(false, { force: Boolean(options?.force) });
    if (activePrinterScopeRef.current !== scope) return;
    if (!response.success) {
      setManagedPrinterProfiles([]);
      setManagedPrinterProfilesLoaded(true);
      return;
    }

    setManagedPrinterProfiles(
      (Array.isArray(response.data) ? response.data : []).filter(
        (row): row is ManagedPrinterProfile =>
          Boolean(row && typeof row === "object" && (row as { id?: unknown }).id && (row as { name?: unknown }).name)
      )
    );
    setManagedPrinterProfilesLoaded(true);
  };

  const syncManufacturerPrinterStatus = async (options?: { silent?: boolean; force?: boolean }) => {
    if (!user || user.role !== "manufacturer") return;
    if (activePrintSuppressed && !options?.force) return;
    if (syncInFlightRef.current) return syncInFlightRef.current;
    const revision = ++statusRevisionRef.current;
    const runId = ++syncRunIdRef.current;
    const run = (async () => {
      setPrinterStatusChecking(true);
      try {
        if (DISABLE_E2E_PRINTER_AGENT_POLLING) {
      applyPrinterStatusSnapshot(
        {
          ...defaultPrinterStatus,
          refreshPaused: true,
          notice: "Printer polling is disabled for this automated test run.",
        } as PrinterConnectionStatusDTO,
        { fallbackPrinters: [], updatedAt: new Date().toISOString(), revision }
      );
      setLocalPrinterAgent({
        reachable: false,
        connected: false,
        error: null,
        checkedAt: new Date().toISOString(),
      });
      setManagedPrinterProfilesLoaded(true);
      return;
        }

    await loadManagedPrinterProfiles({ force: Boolean(options?.force) });
    if (activePrinterScopeRef.current !== printerScope) return;

    let local = await apiClient.getLocalPrintAgentStatus();
    if (activePrinterScopeRef.current !== printerScope) return;
    const browserBackendUrl = window.location.origin;
    if (local.success && configuredBackendUrlRef.current !== browserBackendUrl) {
      const backendConfiguration = await apiClient.configureLocalPrintAgentBackend(browserBackendUrl);
      if (activePrinterScopeRef.current !== printerScope) return;
      if (!backendConfiguration.success) {
        console.warn("Local print agent backend configuration failed:", backendConfiguration.error);
      } else {
        configuredBackendUrlRef.current = browserBackendUrl;
      }
    }
    let localPrinters = normalizeLocalPrinterRows(
      ((local.data as { printers?: unknown[] } | undefined)?.printers) || []
    );
    const localData = local.data as LocalPrinterStatusPayload | undefined;
    const preferredLocalPrinter = resolvePreferredLocalPrinter(localPrinters, localData);
    const localSelectedId = String(localData?.selectedPrinterId || localData?.printerId || "").trim();
    if (local.success && preferredLocalPrinter?.printerId && preferredLocalPrinter.printerId !== localSelectedId) {
      const switched = await apiClient.selectLocalPrinter(preferredLocalPrinter.printerId);
      if (activePrinterScopeRef.current !== printerScope) return;
      if (switched.success) {
        local = await apiClient.getLocalPrintAgentStatus();
        if (activePrinterScopeRef.current !== printerScope) return;
        localPrinters = normalizeLocalPrinterRows(
          ((local.data as { printers?: unknown[] } | undefined)?.printers) || localPrinters
        );
      }
    }
    setLocalPrinterAgent({
      reachable: Boolean(local.success),
      connected: Boolean((local.data as { connected?: boolean } | undefined)?.connected),
      error: local.success
        ? String((local.data as { error?: string } | undefined)?.error || "").trim() || null
        : String(local.error || "Local print agent is unavailable"),
      checkedAt: new Date().toISOString(),
    });

    const heartbeatPayload = local.success
      ? buildHeartbeatPayloadFromLocalStatus(local.data as LocalPrinterStatusPayload | undefined, localPrinters)
      : {
          connected: false,
          error: String(local.error || "Local print agent unavailable"),
        };

    const heartbeat = await apiClient.reportPrinterHeartbeat(heartbeatPayload);
    if (activePrinterScopeRef.current !== printerScope) return;
    const heartbeatStatus =
      heartbeat.success && heartbeat.data ? (heartbeat.data as PrinterConnectionStatusDTO) : null;
    const heartbeatDegraded = Boolean(heartbeat.degraded || heartbeatStatus?.degraded);

    if (heartbeatStatus) {
      const localSelectedPrinter = resolvePreferredLocalPrinter(localPrinters, localData);
      const degradedStatus: PrinterConnectionStatusDTO = {
        ...heartbeatStatus,
        printers: localPrinters.length > 0 ? localPrinters : heartbeatStatus.printers,
        printerName: localSelectedPrinter?.printerName || heartbeatStatus.printerName,
        printerId: localSelectedPrinter?.printerId || heartbeatStatus.printerId,
        selectedPrinterId: localSelectedPrinter?.printerId || heartbeatStatus.selectedPrinterId,
        selectedPrinterName: localSelectedPrinter?.printerName || heartbeatStatus.selectedPrinterName,
        degraded: heartbeatDegraded && !isSecurePrinterStatusReady(heartbeatStatus),
      };
      applyPrinterStatusSnapshot(degradedStatus, {
        fallbackPrinters: localPrinters,
        updatedAt: degradedStatus.lastHeartbeatAt || new Date().toISOString(),
        revision,
      });

      if (!isSecurePrinterStatusReady(degradedStatus)) {
        void maybeAutoReportPrinterFailure({
          localResult: local,
          remoteStatus: degradedStatus,
          printers: localPrinters.map((item) => ({ printerId: item.printerId, printerName: item.printerName })),
        });
      }
      return;
    }

    const remote = await apiClient.getPrinterConnectionStatus({ force: Boolean(options?.force) });
    if (activePrinterScopeRef.current !== printerScope) return;
    if (remote.success && remote.data) {
      const nextStatus = {
        ...(remote.data as PrinterConnectionStatusDTO),
        degraded: Boolean((remote.data as PrinterConnectionStatusDTO).degraded) && !isSecurePrinterStatusReady(remote.data as PrinterConnectionStatusDTO),
      } satisfies PrinterConnectionStatusDTO;
      applyPrinterStatusSnapshot(nextStatus, {
        fallbackPrinters: localPrinters,
        updatedAt: nextStatus.lastHeartbeatAt || new Date().toISOString(),
        revision,
      });

      const mergedPrinters =
        normalizeLocalPrinterRows(nextStatus.printers || []).length > 0
          ? normalizeLocalPrinterRows(nextStatus.printers || [])
          : localPrinters;
      const nowConnected = isSecurePrinterStatusReady(nextStatus);
      if (!nowConnected) {
        void maybeAutoReportPrinterFailure({
          localResult: local,
          remoteStatus: nextStatus,
          printers: mergedPrinters.map((item) => ({ printerId: item.printerId, printerName: item.printerName })),
        });
      }
      return;
    }

    const previous = printerStatusRef.current;
    if (isSecurePrinterStatusReady(previous)) {
      applyPrinterStatusSnapshot(
        {
          ...previous,
          printers: previous.printers && previous.printers.length > 0 ? previous.printers : localPrinters,
          error: null,
          degraded: false,
          refreshPaused: true,
          rateLimited: remote.status === 429 || String(remote.code || "").toUpperCase() === "RATE_LIMITED",
          notice: "Printer status refresh is temporarily paused. Last trusted status is retained.",
        } as PrinterConnectionStatusDTO,
        {
          fallbackPrinters: previous.printers && previous.printers.length > 0 ? previous.printers : localPrinters,
          updatedAt: previous.lastHeartbeatAt || printerStatusUpdatedAt || new Date().toISOString(),
          revision,
        }
      );
      return;
    }

    const fallbackStatus: PrinterConnectionStatusDTO = {
      ...defaultPrinterStatus,
      printers: localPrinters,
      error: String(remote.error || local.error || "Printer heartbeat failed"),
    };

    applyPrinterStatusSnapshot(fallbackStatus, {
      fallbackPrinters: localPrinters,
      updatedAt: new Date().toISOString(),
      revision,
    });
    if (!options?.silent) {
      void maybeAutoReportPrinterFailure({
        localResult: local,
        remoteStatus: fallbackStatus,
        printers: localPrinters.map((item) => ({ printerId: item.printerId, printerName: item.printerName })),
      });
    }
      } finally {
        if (runId === syncRunIdRef.current) {
          setPrinterStatusChecking(false);
          syncInFlightRef.current = null;
        }
      }
    })();
    syncInFlightRef.current = run;
    return run;
  };

  const switchLocalPrinter = async (targetOverride?: string) => {
    const targetPrinterId = String(targetOverride || selectedLocalPrinterId || "").trim();
    if (!targetPrinterId) return;
    setSelectedLocalPrinterId(targetPrinterId);
    setPrinterSwitching(true);
    try {
      const switched = await apiClient.selectLocalPrinter(targetPrinterId);
      if (!switched.success) {
        toast({
          title: "Printer switch failed",
          description: sanitizePrinterUiError(switched.error, "Could not switch the workstation printer."),
          variant: "destructive",
        });
        return;
      }
      toast({
        title: "Printer switched",
        description: "The workstation printer has been updated.",
      });
      await syncManufacturerPrinterStatus({ silent: true });
    } finally {
      setPrinterSwitching(false);
    }
  };

  useEffect(() => {
    if (!user || user.role !== "manufacturer") return;
    void loadManagedPrinterProfiles();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [printerScope]);

  useEffect(() => {
    if (!user || user.role !== "manufacturer") return;
    if (activePrintSuppressed || printerStatusLive) return;
    const timer = window.setInterval(() => {
      if (!canPollVisibleDocument()) return;
      void syncManufacturerPrinterStatus({ silent: true });
    }, 60_000);
    return () => window.clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [printerScope, activePrintSuppressed, printerStatusLive]);

  useEffect(() => {
    detectedPrintersRef.current = detectedPrinters;
  }, [detectedPrinters]);

  useEffect(() => {
    if (!user || user.role !== "manufacturer") return;
    const onVisibilityChange = () => {
      if (document.visibilityState === "hidden") {
        ++statusRevisionRef.current;
        ++syncRunIdRef.current;
        syncInFlightRef.current = null;
        setPrinterStatusChecking(false);
        setPrinterStatus((previous) => ({ ...previous, trusted: false, eligibleForPrinting: false,
          stale: true, refreshPaused: true,
          trustReason: "Printer verification expired while this tab was hidden." }));
      } else {
        void syncManufacturerPrinterStatus({ silent: true, force: true });
      }
    };
    document.addEventListener("visibilitychange", onVisibilityChange);
    return () => document.removeEventListener("visibilitychange", onVisibilityChange);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [printerScope]);

  useEffect(() => {
    if (!user || user.role !== "manufacturer") return;
    if (DISABLE_E2E_PRINTER_AGENT_POLLING) return;
    if (activePrintSuppressed) return;
    const streamScope = printerScope;

    const stop = apiClient.streamPrinterConnectionStatus(
      (payload) => {
        if (activePrinterScopeRef.current !== streamScope) return;
        if (document.visibilityState === "hidden") return;
        const serverTimeMs = Date.parse(payload.serverTime || "");
        if (!Number.isFinite(serverTimeMs) || serverTimeMs <= lastEventServerTimeMsRef.current) return;
        lastEventServerTimeMsRef.current = serverTimeMs;
        ++statusRevisionRef.current;
        setPrinterStatusLive(true);
        applyPrinterStatusSnapshot(payload.status as PrinterConnectionStatusDTO, {
          updatedAt: payload.serverTime || payload.status.lastHeartbeatAt || new Date().toISOString(),
        });
      },
      () => {
        if (activePrinterScopeRef.current !== streamScope) return;
        ++statusRevisionRef.current;
        setPrinterStatusLive(false);
        setPrinterStatus((previous) => ({ ...previous, trusted: false, eligibleForPrinting: false,
          stale: true, refreshPaused: true,
          trustReason: "Printer verification is unavailable. Refresh printer status and try again." }));
      },
      () => {
        if (activePrinterScopeRef.current !== streamScope) return;
        setPrinterStatusLive(true);
      }
    );

    return () => {
      setPrinterStatusLive(false);
      stop();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [printerScope, activePrintSuppressed]);

  useEffect(() => {
    if (!printerStatus) return;
    const next = String(
      chooseStablePrinterSelection(
        detectedPrinters,
        selectedLocalPrinterId,
        printerStatus.selectedPrinterId,
        printerStatus.printerId
      )?.printerId || ""
    ).trim();
    if (next && next !== selectedLocalPrinterId) setSelectedLocalPrinterId(next);
  }, [detectedPrinters, printerStatus, selectedLocalPrinterId]);

  const securePrintReadiness = useMemo(() => {
    if (selectedLocalPrinterId && selectedLocalPrinterId !== printerStatus.selectedPrinterId) {
      return buildSecurePrintReadiness({ ...printerStatus, trusted: false, eligibleForPrinting: false,
        stale: true, trustReason: "Printer selection changed. Refresh printer verification." });
    }
    return buildSecurePrintReadiness(printerStatus);
  }, [printerStatus, selectedLocalPrinterId]);
  const printerReady = securePrintReadiness.ready;
  const managedNetworkPrinters = useMemo(
    () => managedPrinterProfiles.filter((printer) => printer.connectionType !== "LOCAL_AGENT" && printer.isActive),
    [managedPrinterProfiles]
  );
  const preferredManagedNetworkPrinter = useMemo(
    () => selectPreferredManagedPrinter(managedNetworkPrinters),
    [managedNetworkPrinters]
  );
  const managedPrinterDiagnostics = useMemo(
    () => getManagedPrinterDiagnosticSummary(preferredManagedNetworkPrinter),
    [preferredManagedNetworkPrinter]
  );
  const printerHasInventory =
    detectedPrinters.length > 0 || Boolean(printerStatus.selectedPrinterId || printerStatus.printerId);
  const localHelperHasPrinter =
    localPrinterAgent.reachable &&
    (detectedPrinters.length > 0 || Boolean(printerStatus.selectedPrinterId || printerStatus.printerId));
  const printerDiagnostics = useMemo(
    () =>
      getPrinterDiagnosticSummary({
        localAgent: localPrinterAgent,
        remoteStatus: printerStatus,
        printers: detectedPrinters,
        selectedPrinterId: selectedLocalPrinterId,
      }),
    [detectedPrinters, localPrinterAgent, printerStatus, selectedLocalPrinterId]
  );
  const shouldUseManagedPrinterSummary = Boolean(
    managedPrinterDiagnostics &&
      !localHelperHasPrinter &&
      (!printerReady ||
        shouldPreferNetworkDirectSummary({
          printers: detectedPrinters,
          networkPrinter: preferredManagedNetworkPrinter,
        }))
  );
  const effectivePrinterDiagnostics =
    shouldUseManagedPrinterSummary && managedPrinterDiagnostics ? managedPrinterDiagnostics : printerDiagnostics;
  const effectivePrinterReady = printerReady;
  const printerUnavailable = !effectivePrinterReady && !printerHasInventory && managedNetworkPrinters.length === 0;
  const selectedPrinter =
    chooseStablePrinterSelection(
      detectedPrinters,
      selectedLocalPrinterId,
      printerStatus.selectedPrinterId,
      printerStatus.printerId
    ) ||
    detectedPrinters[0] ||
    null;
  const activePrinterId = String(selectedPrinter?.printerId || printerStatus.selectedPrinterId || printerStatus.printerId || "").trim();
  const printerIdentity = derivePrinterIdentity({
    printerName: shouldUseManagedPrinterSummary
      ? preferredManagedNetworkPrinter?.name
      : selectedPrinter?.printerName || printerStatus.printerName,
    selectedPrinterName: shouldUseManagedPrinterSummary
      ? preferredManagedNetworkPrinter?.name
      : selectedPrinter?.printerName || printerStatus.selectedPrinterName,
    model: shouldUseManagedPrinterSummary
      ? preferredManagedNetworkPrinter?.model || null
      : selectedPrinter?.model || null,
    deviceName: shouldUseManagedPrinterSummary ? null : printerStatus.deviceName,
  });
  const printerFeedLabel = printerStatusLive ? "Live updates" : "Checking status";
  const printerUpdatedLabel = formatPrinterTimestamp(printerStatusUpdatedAt || printerStatus.lastHeartbeatAt);
  const printerRefreshPaused = Boolean((printerStatus as PrinterConnectionStatusDTO & { refreshPaused?: boolean }).refreshPaused);
  const printerRateLimited = Boolean((printerStatus as PrinterConnectionStatusDTO & { rateLimited?: boolean }).rateLimited);
  const printerReadinessDisplay = buildPrinterReadinessDisplay({
    diagnostics: effectivePrinterDiagnostics,
    ready: Boolean(effectivePrinterReady),
    refreshPaused: printerRefreshPaused,
    rateLimited: printerRateLimited,
    stale: Boolean(printerStatus.stale),
    trusted: Boolean(printerStatus.trusted),
    compatibilityMode: Boolean(printerStatus.compatibilityMode),
    identityLabel: shouldUseManagedPrinterSummary ? preferredManagedNetworkPrinter?.name : printerIdentity.displayName,
  });
  const printerModeLabel = printerReadinessDisplay.modeLabel;
  const printerToneClass = printerReadinessDisplay.toneClass;
  const printerTitle = printerReadinessDisplay.summary;
  const printerDegraded = Boolean(printerStatus.degraded && !effectivePrinterReady);
  const printerDegradedMessage = printerDegraded
    ? sanitizePrinterUiError(
        printerStatus.compatibilityReason || printerStatus.trustReason || printerStatus.error,
        "MSCQR needs a fresh trusted helper session before printing."
      )
    : "";
  const printerNoticeMessage = printerRefreshPaused
    ? printerReadinessDisplay.notice
    : effectivePrinterReady && (!printerStatus.trusted || printerStatus.compatibilityMode)
      ? printerReadinessDisplay.notice
      : "";
  const printerSummaryMessage = printerReadinessDisplay.summary;
  const printerNextStep = effectivePrinterReady
    ? shouldUseManagedPrinterSummary
      ? "Open batches and choose this saved printer when you are ready to print."
      : "You can go back to batches and start printing."
    : printerReadinessDisplay.blocksPrintStart
      ? "Refresh printer helper before starting a print run."
      : effectivePrinterDiagnostics.nextSteps[0] || "Refresh printer status before starting a print run.";
  const selectedPrinterIsActive = Boolean(selectedPrinter && selectedPrinter.printerId === activePrinterId);
  const printerDiscoveryCountLabel =
    detectedPrinters.length === 1 ? "1 printer detected" : `${detectedPrinters.length} printers detected`;

  const openPrinterConnectionDialog = () => {
    setPrinterDialogOpen(true);
    void syncManufacturerPrinterStatus({ silent: true, force: true });
  };

  const refreshPrinterConnectionStatus = () => {
    void syncManufacturerPrinterStatus({ silent: true, force: true });
  };

  usePrinterOnboardingAutoOpen({
    storageKey: printerOnboardingStorageKey,
    enabled: currentPath === APP_PATHS.batches,
    managedProfilesLoaded: managedPrinterProfilesLoaded,
    printerReady,
    managedPrinterReady: false,
    managedNetworkPrinterCount: managedNetworkPrinters.length,
    setOpen: setPrinterOnboardingOpen,
  });

  const dismissPrinterOnboarding = () => {
    if (printerOnboardingStorageKey) {
      try {
        setOptionalLocalStorageItem("functional", printerOnboardingStorageKey, "dismissed");
      } catch {
        // Ignore storage failures.
      }
    }
    setPrinterOnboardingOpen(false);
  };

  const setPrinterOnboardingOpenFromUi = (open: boolean) => {
    if (!open) {
      dismissPrinterOnboarding();
      return;
    }
    setPrinterOnboardingOpen(true);
  };

  const reopenPrinterOnboarding = () => {
    if (printerOnboardingStorageKey) {
      try {
        removeOptionalLocalStorageItem(printerOnboardingStorageKey);
      } catch {
        // Ignore storage failures.
      }
    }
    setPrinterOnboardingOpen(true);
  };

  const goToHelp = () => navigate(contextualHelpRoute);
  const goToConnectorDownload = () => navigate(APP_PATHS.connectorDownload);
  const goToPrinterSetup = () => navigate(APP_PATHS.printerSetup);
  const goToBatches = () => navigate(APP_PATHS.batches);

  return {
    isManufacturer: user?.role === "manufacturer",
    clearPrinterDialogSession,
    printerDialogOpen,
    setPrinterDialogOpen,
    printerOnboardingOpen,
    setPrinterOnboardingOpen: setPrinterOnboardingOpenFromUi,
    printerSwitching,
    printerStatusChecking,
    printerStatusLive,
    localPrinterAgent,
    printerHasInventory,
    selectedPrinterName: selectedPrinter?.printerName || printerStatus.selectedPrinterName || printerStatus.printerName || "None yet",
    printerName: selectedPrinter?.printerName || printerStatus.printerName,
    openPrinterConnectionDialog,
    refreshPrinterConnectionStatus,
    dismissPrinterOnboarding,
    reopenPrinterOnboarding,
    goToHelp,
    goToConnectorDownload,
    goToPrinterSetup,
    goToBatches,
    printerToneClass,
    printerTitle,
    printerModeLabel,
    securePrintReadiness,
    printerDegraded,
    printerDegradedMessage,
    printerNoticeMessage,
    managedNetworkPrinters,
    detectedPrinters,
    effectivePrinterReady,
    effectivePrinterDiagnostics,
    printerUnavailable,
    printerIdentity,
    printerSummaryMessage,
    printerNextStep,
    printerUpdatedLabel,
    printerFeedLabel,
    selectedPrinter,
    shouldUseManagedPrinterSummary,
    preferredManagedNetworkPrinter,
    activePrinterId,
    selectedLocalPrinterId,
    printerAgeSeconds: printerStatus.ageSeconds,
    selectedPrinterIsActive,
    printerDiscoveryCountLabel,
    setSelectedLocalPrinterId,
    switchLocalPrinter,
    workstationDeviceName: printerStatus.deviceName,
  };
}

export type ManufacturerPrinterConnection = ReturnType<typeof useManufacturerPrinterConnection>;
