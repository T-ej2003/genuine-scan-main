import { useEffect, useMemo, useState } from "react";

import { APP_PATHS } from "@/app/route-metadata";
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
} from "@/lib/printer-diagnostics";
import { sanitizePrinterUiError } from "@/lib/printer-user-facing";
import { buildSecurePrintReadiness } from "@/lib/secure-printer-readiness";
import {
  derivePrinterIdentity,
  formatPrinterTimestamp,
  type ManagedPrinterProfile,
} from "@/features/layout/components/PrinterDialogs";
import { useManufacturerPrinterRuntime } from "@/features/printing/manufacturer-printer-runtime";
import {
  defaultPrinterStatus,
  PRINTER_DIALOG_SESSION_STORAGE_VERSION,
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
  const runtime = useManufacturerPrinterRuntime();
  const printerStatus = runtime?.snapshot.remoteStatus ?? defaultPrinterStatus;
  const localPrinterAgent = runtime?.snapshot.localAgent ?? { reachable: false, connected: false, error: null, checkedAt: null };
  const detectedPrinters = runtime?.snapshot.detectedPrinters ?? [];
  const managedPrinterProfiles = (runtime?.snapshot.registeredPrinters ?? []) as ManagedPrinterProfile[];
  const printerStatusChecking = Boolean(runtime?.checking);
  const printerStatusLive = Boolean(runtime?.live);
  const [printerDialogOpen, setPrinterDialogOpen] = useState(false);
  const [printerOnboardingOpen, setPrinterOnboardingOpen] = useState(false);
  const [printerSwitching, setPrinterSwitching] = useState(false);
  const [selectedLocalPrinterId, setDraftPrinterId] = useState("");
  const setSelectedLocalPrinterId = (id: string) => {
    setDraftPrinterId(id);
    if (id && id !== printerStatus.selectedPrinterId) {
      runtime?.invalidate("Printer selection changed. Refresh printer verification.");
    }
  };

  useEffect(() => setDraftPrinterId(""), [runtime?.scope]);

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

  const switchLocalPrinter = async (targetOverride?: string) => {
    const target = targetOverride || selectedLocalPrinterId;
    if (!target || printerSwitching || !runtime) return;
    setPrinterSwitching(true);
    try {
      const response = await runtime.changePrinter(target);
      toast(response?.success
        ? { title: "Printer switched", description: "The workstation printer has been updated." }
        : { title: "Printer switch failed", description: sanitizePrinterUiError(response?.error,
          "Could not switch the workstation printer."), variant: "destructive" });
    } finally {
      setPrinterSwitching(false);
    }
  };

  const securePrintReadiness = buildSecurePrintReadiness(printerStatus);
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
  const activePrinterId = String(runtime?.snapshot.localBinding?.printerId || printerStatus.selectedPrinterId || printerStatus.printerId || "").trim();
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
  const printerUpdatedLabel = formatPrinterTimestamp(printerStatus.lastHeartbeatAt);
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
  const printerDegraded = Boolean(printerStatus.degraded && !printerStatus.refreshPaused && !effectivePrinterReady);
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
    void runtime?.refresh({ force: true });
  };

  const refreshPrinterConnectionStatus = () => {
    void runtime?.refresh({ force: true });
  };

  usePrinterOnboardingAutoOpen({
    storageKey: printerOnboardingStorageKey,
    enabled: currentPath === APP_PATHS.batches,
    managedProfilesLoaded: Boolean(runtime?.snapshot.localAgent.checkedAt),
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
