import { useEffect, useMemo, useRef, useState } from "react";

import apiClient from "@/lib/api-client";
import {
  getManagedPrinterDiagnosticSummary,
  getPrinterDiagnosticSummary,
  selectPreferredManagedPrinter,
  shouldPreferNetworkDirectSummary,
  type LocalPrinterAgentSnapshot,
} from "@/lib/printer-diagnostics";
import { sanitizePrinterUiError } from "@/lib/printer-user-facing";
import { buildSupportDiagnosticsPayload, captureSupportScreenshot } from "@/lib/support-diagnostics";
import { normalizeLocalPrinterRows } from "@/features/printing/hooks";
import {
  derivePrinterIdentity,
  formatPrinterTimestamp,
  type ManagedPrinterProfile,
} from "@/features/layout/components/PrinterDialogs";
import type { User } from "@/types";
import type { PrinterConnectionStatusDTO } from "../../../shared/contracts/runtime/printing.ts";

type ToastLike = (options: {
  title?: string;
  description?: string;
  variant?: "default" | "destructive";
}) => unknown;

type UseManufacturerPrinterConnectionParams = {
  user: User | null;
  contextualHelpRoute: string;
  navigate: (to: string) => void;
  toast: ToastLike;
};

const PRINTER_FAILURE_REPORT_COOLDOWN_MS = 3 * 60 * 1000;
const PRINTER_DIALOG_SESSION_STORAGE_VERSION = "v1";
const PRINTER_ONBOARDING_STORAGE_VERSION = "v1";

const defaultPrinterStatus: PrinterConnectionStatusDTO = {
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
  printers: [],
  calibrationProfile: null,
  error: "No trusted printer heartbeat yet",
};

export function useManufacturerPrinterConnection({
  user,
  contextualHelpRoute,
  navigate,
  toast,
}: UseManufacturerPrinterConnectionParams) {
  const printerConnectedRef = useRef(false);
  const detectedPrintersRef = useRef<NonNullable<PrinterConnectionStatusDTO["printers"]>>([]);
  const printerFailureReportRef = useRef<{ signature: string; at: number }>({ signature: "", at: 0 });
  const printerFailureInFlightRef = useRef(false);
  const configuredBackendUrlRef = useRef("");

  const [printerStatus, setPrinterStatus] = useState<PrinterConnectionStatusDTO>(defaultPrinterStatus);
  const [printerDialogOpen, setPrinterDialogOpen] = useState(false);
  const [printerOnboardingOpen, setPrinterOnboardingOpen] = useState(false);
  const [printerSwitching, setPrinterSwitching] = useState(false);
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

  const printerDialogSessionKey =
    user?.role === "manufacturer" && user?.id
      ? `manufacturer-printer-dialog-opened:${PRINTER_DIALOG_SESSION_STORAGE_VERSION}:${user.id}`
      : null;
  const printerOnboardingStorageKey =
    user?.role === "manufacturer" && user?.id
      ? `manufacturer-printer-onboarding:${PRINTER_ONBOARDING_STORAGE_VERSION}:${user.id}`
      : null;

  const hasSeenPrinterDialogThisSession = () => {
    if (!printerDialogSessionKey) return false;
    try {
      return String(window.sessionStorage.getItem(printerDialogSessionKey) || "").trim().toLowerCase() === "shown";
    } catch {
      return false;
    }
  };

  const markPrinterDialogSeenThisSession = () => {
    if (!printerDialogSessionKey) return;
    try {
      window.sessionStorage.setItem(printerDialogSessionKey, "shown");
    } catch {
      // Ignore storage failures.
    }
  };

  const clearPrinterDialogSession = () => {
    if (!printerDialogSessionKey) return;
    try {
      window.sessionStorage.removeItem(printerDialogSessionKey);
    } catch {
      // Ignore storage failures.
    }
  };

  const applyPrinterStatusSnapshot = (
    nextStatus: PrinterConnectionStatusDTO,
    options?: {
      fallbackPrinters?: NonNullable<PrinterConnectionStatusDTO["printers"]>;
      updatedAt?: string | null;
    }
  ) => {
    const fallbackPrinters = Array.isArray(options?.fallbackPrinters)
      ? options?.fallbackPrinters
      : detectedPrintersRef.current;
    const remotePrinters = normalizeLocalPrinterRows(nextStatus.printers || []);
    const mergedPrinters = remotePrinters.length > 0 ? remotePrinters : fallbackPrinters;

    setPrinterStatus({
      ...nextStatus,
      printers: mergedPrinters,
    });
    setDetectedPrinters(mergedPrinters);
    setPrinterStatusUpdatedAt(options?.updatedAt || nextStatus.lastHeartbeatAt || new Date().toISOString());

    setSelectedLocalPrinterId((previous) => {
      if (previous && mergedPrinters.some((row) => row.printerId === previous)) return previous;
      const fallbackPrinter =
        mergedPrinters.find((row) => row.printerId === nextStatus.selectedPrinterId) ||
        mergedPrinters.find((row) => row.printerId === nextStatus.printerId) ||
        mergedPrinters.find((row) => row.isDefault) ||
        mergedPrinters[0];
      return fallbackPrinter?.printerId || previous;
    });

    const nowConnected = Boolean(nextStatus.connected && nextStatus.eligibleForPrinting);
    if (nowConnected && !printerConnectedRef.current && !hasSeenPrinterDialogThisSession()) {
      setPrinterDialogOpen(true);
      markPrinterDialogSeenThisSession();
    }
    printerConnectedRef.current = nowConnected;
  };

  const maybeAutoReportPrinterFailure = async (params: {
    localResult: Awaited<ReturnType<typeof apiClient.getLocalPrintAgentStatus>>;
    remoteStatus: PrinterConnectionStatusDTO | null;
    printers: Array<{ printerId: string; printerName: string }>;
  }) => {
    if (!user || user.role !== "manufacturer") return;
    const remoteReady = Boolean(params.remoteStatus?.connected && params.remoteStatus?.eligibleForPrinting);
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

  const loadManagedPrinterProfiles = async () => {
    if (!user || user.role !== "manufacturer") return;

    const response = await apiClient.listRegisteredPrinters(false);
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

  const syncManufacturerPrinterStatus = async (options?: { silent?: boolean }) => {
    if (!user || user.role !== "manufacturer") return;

    await loadManagedPrinterProfiles();

    const local = await apiClient.getLocalPrintAgentStatus();
    const browserBackendUrl = window.location.origin;
    if (local.success && configuredBackendUrlRef.current !== browserBackendUrl) {
      const backendConfiguration = await apiClient.configureLocalPrintAgentBackend(browserBackendUrl);
      if (!backendConfiguration.success) {
        console.warn("Local print agent backend configuration failed:", backendConfiguration.error);
      } else {
        configuredBackendUrlRef.current = browserBackendUrl;
      }
    }
    const localPrinters = normalizeLocalPrinterRows(
      ((local.data as { printers?: unknown[] } | undefined)?.printers) || []
    );
    setLocalPrinterAgent({
      reachable: Boolean(local.success),
      connected: Boolean((local.data as { connected?: boolean } | undefined)?.connected),
      error: local.success
        ? String((local.data as { error?: string } | undefined)?.error || "").trim() || null
        : String(local.error || "Local print agent is unavailable"),
      checkedAt: new Date().toISOString(),
    });

    const heartbeatPayload = local.success
      ? {
          connected: Boolean((local.data as { connected?: boolean } | undefined)?.connected),
          printerName: (local.data as { printerName?: string } | undefined)?.printerName || undefined,
          printerId: (local.data as { printerId?: string } | undefined)?.printerId || undefined,
          selectedPrinterId:
            (local.data as { selectedPrinterId?: string } | undefined)?.selectedPrinterId || undefined,
          selectedPrinterName:
            (local.data as { selectedPrinterName?: string } | undefined)?.selectedPrinterName || undefined,
          deviceName: (local.data as { deviceName?: string } | undefined)?.deviceName || undefined,
          agentVersion: (local.data as { agentVersion?: string } | undefined)?.agentVersion || undefined,
          error: (local.data as { error?: string } | undefined)?.error || undefined,
          agentId: (local.data as { agentId?: string } | undefined)?.agentId || undefined,
          deviceFingerprint:
            (local.data as { deviceFingerprint?: string } | undefined)?.deviceFingerprint || undefined,
          publicKeyPem: (local.data as { publicKeyPem?: string } | undefined)?.publicKeyPem || undefined,
          clientCertFingerprint:
            (local.data as { clientCertFingerprint?: string } | undefined)?.clientCertFingerprint || undefined,
          heartbeatNonce: (local.data as { heartbeatNonce?: string } | undefined)?.heartbeatNonce || undefined,
          heartbeatIssuedAt:
            (local.data as { heartbeatIssuedAt?: string } | undefined)?.heartbeatIssuedAt || undefined,
          heartbeatSignature:
            (local.data as { heartbeatSignature?: string } | undefined)?.heartbeatSignature || undefined,
          capabilitySummary:
            (local.data as { capabilitySummary?: Record<string, unknown> } | undefined)?.capabilitySummary ||
            undefined,
          printers: localPrinters,
          calibrationProfile:
            (local.data as { calibrationProfile?: Record<string, unknown> } | undefined)?.calibrationProfile ||
            undefined,
        }
      : {
          connected: false,
          error: String(local.error || "Local print agent unavailable"),
        };

    await apiClient.reportPrinterHeartbeat(heartbeatPayload);
    const remote = await apiClient.getPrinterConnectionStatus();
    if (remote.success && remote.data) {
      const nextStatus = remote.data as PrinterConnectionStatusDTO;
      applyPrinterStatusSnapshot(nextStatus, {
        fallbackPrinters: localPrinters,
        updatedAt: nextStatus.lastHeartbeatAt || new Date().toISOString(),
      });

      const mergedPrinters =
        normalizeLocalPrinterRows(nextStatus.printers || []).length > 0
          ? normalizeLocalPrinterRows(nextStatus.printers || [])
          : localPrinters;
      const nowConnected = Boolean(nextStatus.connected && nextStatus.eligibleForPrinting);
      if (!nowConnected) {
        void maybeAutoReportPrinterFailure({
          localResult: local,
          remoteStatus: nextStatus,
          printers: mergedPrinters.map((item) => ({ printerId: item.printerId, printerName: item.printerName })),
        });
      }
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
    });
    if (!options?.silent) {
      void maybeAutoReportPrinterFailure({
        localResult: local,
        remoteStatus: fallbackStatus,
        printers: localPrinters.map((item) => ({ printerId: item.printerId, printerName: item.printerName })),
      });
    }
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
    void syncManufacturerPrinterStatus({ silent: true });
    const timer = window.setInterval(() => {
      void syncManufacturerPrinterStatus({ silent: true });
    }, 6000);

    return () => window.clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user?.id, user?.role]);

  useEffect(() => {
    detectedPrintersRef.current = detectedPrinters;
  }, [detectedPrinters]);

  useEffect(() => {
    if (!user || user.role !== "manufacturer") return;

    const stop = apiClient.streamPrinterConnectionStatus(
      (payload) => {
        setPrinterStatusLive(true);
        applyPrinterStatusSnapshot(payload.status as PrinterConnectionStatusDTO, {
          updatedAt: payload.serverTime || payload.status.lastHeartbeatAt || new Date().toISOString(),
        });
      },
      () => {
        setPrinterStatusLive(false);
      },
      () => {
        setPrinterStatusLive(true);
      }
    );

    return () => {
      setPrinterStatusLive(false);
      stop();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user?.id, user?.role]);

  useEffect(() => {
    if (!printerStatus) return;
    if (!selectedLocalPrinterId) {
      const next = String(
        printerStatus.selectedPrinterId ||
          printerStatus.printerId ||
          detectedPrinters.find((item) => item.isDefault)?.printerId ||
          detectedPrinters[0]?.printerId ||
          ""
      ).trim();
      if (next) setSelectedLocalPrinterId(next);
    }
  }, [detectedPrinters, printerStatus, selectedLocalPrinterId]);

  const printerReady = printerStatus.connected && printerStatus.eligibleForPrinting;
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
      (!printerReady ||
        shouldPreferNetworkDirectSummary({
          printers: detectedPrinters,
          networkPrinter: preferredManagedNetworkPrinter,
        }))
  );
  const effectivePrinterDiagnostics =
    shouldUseManagedPrinterSummary && managedPrinterDiagnostics ? managedPrinterDiagnostics : printerDiagnostics;
  const effectivePrinterReady = printerReady || managedPrinterDiagnostics?.tone === "success";
  const printerUnavailable = !effectivePrinterReady && !printerHasInventory && managedNetworkPrinters.length === 0;
  const printerModeLabel = effectivePrinterDiagnostics.badgeLabel;
  const printerToneClass =
    effectivePrinterDiagnostics.tone === "success"
      ? "border-emerald-300 bg-emerald-50 text-emerald-700 hover:bg-emerald-100"
      : effectivePrinterDiagnostics.tone === "warning"
        ? "border-amber-300 bg-amber-50 text-amber-700 hover:bg-amber-100"
        : effectivePrinterDiagnostics.tone === "neutral"
          ? "border-slate-300 bg-slate-100 text-slate-700 hover:bg-slate-200"
          : "border-red-300 bg-red-50 text-red-700 hover:bg-red-100";
  const printerTitle = effectivePrinterDiagnostics.summary;
  const selectedPrinter =
    detectedPrinters.find((row) => row.printerId === selectedLocalPrinterId) ||
    detectedPrinters.find((row) => row.printerId === printerStatus.selectedPrinterId) ||
    detectedPrinters[0] ||
    null;
  const activePrinterId = String(printerStatus.selectedPrinterId || printerStatus.printerId || "").trim();
  const printerIdentity = derivePrinterIdentity({
    printerName: shouldUseManagedPrinterSummary ? preferredManagedNetworkPrinter?.name : printerStatus.printerName,
    selectedPrinterName: shouldUseManagedPrinterSummary
      ? preferredManagedNetworkPrinter?.name
      : printerStatus.selectedPrinterName,
    model: shouldUseManagedPrinterSummary
      ? preferredManagedNetworkPrinter?.model || null
      : selectedPrinter?.model || null,
    deviceName: shouldUseManagedPrinterSummary ? null : printerStatus.deviceName,
  });
  const printerFeedLabel = printerStatusLive ? "Live updates" : "Automatic refresh";
  const printerUpdatedLabel = formatPrinterTimestamp(printerStatusUpdatedAt || printerStatus.lastHeartbeatAt);
  const printerSummaryMessage = effectivePrinterReady
    ? shouldUseManagedPrinterSummary
      ? effectivePrinterDiagnostics.summary
      : `${printerIdentity.displayName} is ready to print.`
    : effectivePrinterDiagnostics.summary;
  const printerNextStep = effectivePrinterReady
    ? shouldUseManagedPrinterSummary
      ? "Open batches and choose the managed printer profile when you are ready to print."
      : "You can continue to batch operations."
    : effectivePrinterDiagnostics.nextSteps[0] || "Refresh printer status before starting a print job.";
  const selectedPrinterIsActive = Boolean(selectedPrinter && selectedPrinter.printerId === activePrinterId);
  const printerDiscoveryCountLabel =
    detectedPrinters.length === 1 ? "1 printer detected" : `${detectedPrinters.length} printers detected`;

  const openPrinterConnectionDialog = () => {
    setPrinterDialogOpen(true);
    void syncManufacturerPrinterStatus({ silent: true });
  };

  const refreshPrinterConnectionStatus = () => {
    void syncManufacturerPrinterStatus({ silent: true });
  };

  useEffect(() => {
    if (!printerOnboardingStorageKey) return;
    if (!managedPrinterProfilesLoaded) return;
    if (printerReady || managedPrinterDiagnostics?.tone === "success") {
      try {
        window.localStorage.setItem(printerOnboardingStorageKey, "completed");
      } catch {
        // Ignore storage failures.
      }
      setPrinterOnboardingOpen(false);
      return;
    }
    if (managedNetworkPrinters.length > 0) {
      setPrinterOnboardingOpen(false);
      return;
    }

    let stored = "";
    try {
      stored = String(window.localStorage.getItem(printerOnboardingStorageKey) || "").trim().toLowerCase();
    } catch {
      stored = "";
    }
    if (!stored) {
      setPrinterOnboardingOpen(true);
    }
  }, [
    managedNetworkPrinters.length,
    managedPrinterDiagnostics?.tone,
    managedPrinterProfilesLoaded,
    printerOnboardingStorageKey,
    printerReady,
  ]);

  const dismissPrinterOnboarding = () => {
    if (printerOnboardingStorageKey) {
      try {
        window.localStorage.setItem(printerOnboardingStorageKey, "dismissed");
      } catch {
        // Ignore storage failures.
      }
    }
    setPrinterOnboardingOpen(false);
  };

  const reopenPrinterOnboarding = () => {
    if (printerOnboardingStorageKey) {
      try {
        window.localStorage.removeItem(printerOnboardingStorageKey);
      } catch {
        // Ignore storage failures.
      }
    }
    setPrinterOnboardingOpen(true);
  };

  const goToHelp = () => navigate(contextualHelpRoute);
  const goToConnectorDownload = () => navigate("/connector-download");
  const goToBatches = () => navigate("/batches");

  return {
    isManufacturer: user?.role === "manufacturer",
    clearPrinterDialogSession,
    printerDialogOpen,
    setPrinterDialogOpen,
    printerOnboardingOpen,
    setPrinterOnboardingOpen,
    printerSwitching,
    printerStatusLive,
    localPrinterAgent,
    printerHasInventory,
    selectedPrinterName: printerStatus.selectedPrinterName || printerStatus.printerName || "None yet",
    printerName: printerStatus.printerName,
    openPrinterConnectionDialog,
    refreshPrinterConnectionStatus,
    dismissPrinterOnboarding,
    reopenPrinterOnboarding,
    goToHelp,
    goToConnectorDownload,
    goToBatches,
    printerToneClass,
    printerTitle,
    printerModeLabel,
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
