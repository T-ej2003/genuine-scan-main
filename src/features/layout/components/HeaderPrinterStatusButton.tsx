import { Printer } from "lucide-react";

import { APP_PATHS } from "@/app/route-metadata";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  getActivePrintRecoveryLabel,
  hasRecoverableActivePrintSession,
  requestActivePrintSessionRecovery,
  useActivePrintSession,
} from "@/lib/active-print-session";
import { cn } from "@/lib/utils";

type HeaderPrinterStatusButtonProps = {
  isManufacturer: boolean;
  currentPath: string;
  navigate: (path: string) => void;
  printerToneClass: string;
  printerTitle: string;
  printerModeLabel: string;
  printerDegraded: boolean;
  onOpenPrinterStatus: () => void;
};

export function HeaderPrinterStatusButton({
  isManufacturer,
  currentPath,
  navigate,
  printerToneClass,
  printerTitle,
  printerModeLabel,
  printerDegraded,
  onOpenPrinterStatus,
}: HeaderPrinterStatusButtonProps) {
  const activePrintSession = useActivePrintSession();
  const canRecoverPrintProgress = isManufacturer && hasRecoverableActivePrintSession(activePrintSession);
  const printRecoveryLabel = getActivePrintRecoveryLabel(activePrintSession);
  const title = canRecoverPrintProgress
    ? activePrintSession.terminal
      ? "Recover interrupted view for the completed or stopped print run."
      : activePrintSession.modalOpen
        ? "View the active print progress dialog."
        : "Print is still running. Resume print progress."
    : printerTitle;

  const openPrinterStatusOrPrintRecovery = () => {
    if (canRecoverPrintProgress) {
      if (currentPath !== APP_PATHS.batches) navigate(APP_PATHS.batches);
      requestActivePrintSessionRecovery();
      return;
    }
    onOpenPrinterStatus();
  };

  if (!isManufacturer) return null;

  return (
    <Button
      variant="outline"
      size="sm"
      onClick={openPrinterStatusOrPrintRecovery}
      className={cn("mr-1 gap-2", printerToneClass)}
      title={title}
    >
      <Printer className="h-4 w-4" />
      <span className="hidden md:inline">
        {canRecoverPrintProgress ? printRecoveryLabel : `Printing ${printerModeLabel}`}
      </span>
      <span className="md:hidden">
        {canRecoverPrintProgress ? (activePrintSession.terminal ? "Result" : "Progress") : printerModeLabel}
      </span>
      {printerDegraded ? (
        <Badge
          variant="outline"
          className="border-amber-300 bg-amber-100/80 text-[10px] font-semibold uppercase tracking-[0.14em] text-amber-800"
        >
          Recovery mode
        </Badge>
      ) : null}
    </Button>
  );
}
