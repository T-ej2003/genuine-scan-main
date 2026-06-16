import { useEffect } from "react";

import { getOptionalLocalStorageItem, setOptionalLocalStorageItem } from "@/lib/consent";

type PrinterOnboardingAutoOpenParams = {
  storageKey: string | null;
  enabled: boolean;
  managedProfilesLoaded: boolean;
  printerReady: boolean;
  managedPrinterReady: boolean;
  managedNetworkPrinterCount: number;
  setOpen: (open: boolean) => void;
};

export const usePrinterOnboardingAutoOpen = ({
  storageKey,
  enabled,
  managedProfilesLoaded,
  printerReady,
  managedPrinterReady,
  managedNetworkPrinterCount,
  setOpen,
}: PrinterOnboardingAutoOpenParams) => {
  useEffect(() => {
    if (!enabled) return;
    if (!storageKey || !managedProfilesLoaded) return;
    if (printerReady || managedPrinterReady) {
      try {
        setOptionalLocalStorageItem("functional", storageKey, "completed");
      } catch {
        // Ignore storage failures.
      }
      setOpen(false);
      return;
    }
    if (managedNetworkPrinterCount > 0) {
      setOpen(false);
      return;
    }
    const stored = String(getOptionalLocalStorageItem("functional", storageKey) || "").trim().toLowerCase();
    if (stored) return;
    setOpen(true);
    try {
      setOptionalLocalStorageItem("functional", storageKey, "shown");
    } catch {
      // Ignore storage failures.
    }
  }, [enabled, managedNetworkPrinterCount, managedPrinterReady, managedProfilesLoaded, printerReady, setOpen, storageKey]);
};
