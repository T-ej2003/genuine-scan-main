import { AlertTriangle, CheckCircle2, Monitor, RefreshCw, Wifi } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { cn } from "@/lib/utils";
import {
  type LocalPrinterAgentSnapshot,
  type PrinterDiagnosticSummary,
  type PrinterInventoryRow,
} from "@/lib/printer-diagnostics";
import { getPrinterDispatchLabel, sanitizePrinterUiError } from "@/lib/printer-user-facing";

export type ManagedPrinterProfile = {
  id: string;
  name: string;
  vendor?: string | null;
  model?: string | null;
  connectionType: "LOCAL_AGENT" | "NETWORK_DIRECT" | "NETWORK_IPP";
  commandLanguage?: string | null;
  deliveryMode?: "DIRECT" | "SITE_GATEWAY";
  isActive: boolean;
  isDefault?: boolean;
  registryStatus?: {
    state: "READY" | "ATTENTION" | "OFFLINE" | "BLOCKED";
    summary: string;
    detail?: string | null;
  } | null;
};

export type PrinterIdentity = {
  displayName: string;
  vendor: string;
  model: string | null;
  monogram: string;
};

const KNOWN_PRINTER_VENDORS = [
  "Zebra",
  "Brother",
  "Epson",
  "Canon",
  "HP",
  "TSC",
  "SATO",
  "Citizen",
  "Bixolon",
  "Honeywell",
  "Datamax",
  "Godex",
  "Star",
  "Toshiba",
  "Xprinter",
];

export const formatPrinterTimestamp = (value?: string | null) => {
  if (!value) return "Waiting for update";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return "Waiting for update";
  return parsed.toLocaleString();
};

const formatPrinterAge = (seconds?: number | null) => {
  if (seconds == null || !Number.isFinite(seconds)) return "Waiting for update";
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m ago`;
  return `${Math.round(seconds / 3600)}h ago`;
};

export const derivePrinterIdentity = (params: {
  printerName?: string | null;
  selectedPrinterName?: string | null;
  model?: string | null;
  deviceName?: string | null;
}): PrinterIdentity => {
  const displayName =
    String(params.selectedPrinterName || params.printerName || params.deviceName || "Printer").trim() || "Printer";
  const combined = [displayName, params.model || "", params.deviceName || ""].join(" ").trim();
  const vendor =
    KNOWN_PRINTER_VENDORS.find((candidate) => new RegExp(`\\b${candidate}\\b`, "i").test(combined)) ||
    displayName.split(/[\s/-]+/).filter(Boolean)[0] ||
    "Printer";
  const model =
    String(params.model || "")
      .trim()
      .replace(new RegExp(`^${vendor}\\s+`, "i"), "") || null;
  const monogram =
    vendor
      .split(/[^A-Za-z0-9]+/)
      .filter(Boolean)
      .slice(0, 2)
      .map((part) => part.charAt(0).toUpperCase())
      .join("")
      .slice(0, 2) || "PR";

  return {
    displayName,
    vendor,
    model,
    monogram,
  };
};

type PrinterOnboardingDialogProps = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  localPrinterAgent: LocalPrinterAgentSnapshot;
  printerHasInventory: boolean;
  selectedPrinterName?: string | null;
  onInstallConnector: () => void;
  onCheckAgain: () => void;
  onOpenHelp: () => void;
  onCloseForNow: () => void;
};

export function PrinterOnboardingDialog({
  open,
  onOpenChange,
  localPrinterAgent,
  printerHasInventory,
  selectedPrinterName,
  onInstallConnector,
  onCheckAgain,
  onOpenHelp,
  onCloseForNow,
}: PrinterOnboardingDialogProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[680px]">
        <DialogHeader>
          <DialogTitle>Set up printing on this computer</DialogTitle>
          <DialogDescription>
            Install the MSCQR printer helper once on the computer that prints. After that it starts automatically and
            MSCQR can find the printer without any extra launch steps.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 text-sm text-slate-700">
          <div className="rounded-xl border border-amber-200 bg-amber-50 p-4">
            <div className="font-semibold text-slate-950">What this does not do</div>
            <p className="mt-2 leading-6">
              The browser cannot install printers, drivers, or desktop apps by itself. Those still need to be set up on
              the computer first.
            </p>
          </div>

          <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
            <div className="font-semibold text-slate-950">What to do once on each printing computer</div>
            <ol className="mt-3 list-decimal space-y-2 pl-5">
              <li>Make sure the printer already appears in the computer&apos;s printer list.</li>
              <li>Open <strong>Install printer helper</strong> and download the Mac or Windows installer for this computer.</li>
              <li>Run the installer once. The helper starts automatically after that.</li>
              <li>Return here and use <strong>Check again</strong>.</li>
              <li>If the computer can see the printer, MSCQR will pick it up automatically.</li>
            </ol>
          </div>

          <div className="rounded-xl border border-slate-200 bg-white p-4">
            <div className="font-semibold text-slate-950">Current readiness</div>
            <ul className="mt-3 list-disc space-y-2 pl-5">
              <li>Printer helper online: {localPrinterAgent.reachable ? "Yes" : "No"}</li>
              <li>Printer detected: {printerHasInventory ? "Yes" : "No"}</li>
              <li>Selected printer: {selectedPrinterName || "None yet"}</li>
            </ul>
          </div>

          <div className="flex flex-wrap gap-3">
            <Button variant="outline" onClick={onInstallConnector}>
              Install printer helper
            </Button>
            <Button onClick={onCheckAgain}>Check again</Button>
            <Button variant="ghost" onClick={onOpenHelp}>
              Open help
            </Button>
            <Button variant="ghost" onClick={onCloseForNow}>
              Close for now
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

type PrinterStatusDialogProps = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  effectivePrinterDiagnostics: PrinterDiagnosticSummary;
  effectivePrinterReady: boolean;
  printerUnavailable: boolean;
  printerIdentity: PrinterIdentity;
  printerSummaryMessage: string;
  printerNextStep: string;
  printerUpdatedLabel: string;
  printerFeedLabel: string;
  printerStatusLive: boolean;
  printerDegraded: boolean;
  printerDegradedMessage: string;
  selectedPrinter?: PrinterInventoryRow | null;
  shouldUseManagedPrinterSummary: boolean;
  preferredManagedNetworkPrinter?: ManagedPrinterProfile | null;
  selectedPrinterName?: string | null;
  printerName?: string | null;
  printerAgeSeconds?: number | null;
  managedNetworkPrinters: ManagedPrinterProfile[];
  detectedPrinters: PrinterInventoryRow[];
  activePrinterId: string;
  selectedLocalPrinterId: string;
  selectedPrinterIsActive: boolean;
  printerDiscoveryCountLabel: string;
  printerSwitching: boolean;
  onSelectedLocalPrinterChange: (printerId: string) => void;
  onRefreshStatus: () => void;
  onInstallConnector: () => void;
  onOpenBatches: () => void;
  onOpenHelp: () => void;
  onClose: () => void;
  onSwitchLocalPrinter: (printerId?: string) => void;
  workstationDeviceName?: string | null;
};

export function PrinterStatusDialog({
  open,
  onOpenChange,
  effectivePrinterDiagnostics,
  effectivePrinterReady,
  printerUnavailable,
  printerIdentity,
  printerSummaryMessage,
  printerNextStep,
  printerUpdatedLabel,
  printerFeedLabel,
  printerStatusLive,
  printerDegraded,
  printerDegradedMessage,
  selectedPrinter,
  shouldUseManagedPrinterSummary,
  preferredManagedNetworkPrinter,
  selectedPrinterName,
  printerName,
  printerAgeSeconds,
  managedNetworkPrinters,
  detectedPrinters,
  activePrinterId,
  selectedLocalPrinterId,
  selectedPrinterIsActive,
  printerDiscoveryCountLabel,
  printerSwitching,
  onSelectedLocalPrinterChange,
  onRefreshStatus,
  onInstallConnector,
  onOpenBatches,
  onOpenHelp,
  onClose,
  onSwitchLocalPrinter,
  workstationDeviceName,
}: PrinterStatusDialogProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[88vh] overflow-y-auto sm:max-w-[860px]">
        <DialogHeader>
          <DialogTitle>Printing Status</DialogTitle>
          <DialogDescription>
            Check whether printing is ready, switch printers on this computer when needed, and keep saved network
            printers visible before you start a print run.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-5">
          <div className="grid gap-4 lg:grid-cols-[1.2fr_0.8fr]">
            <div
              className={cn(
                "rounded-2xl border p-4 shadow-sm",
                effectivePrinterDiagnostics.tone === "success"
                  ? "border-emerald-200 bg-[linear-gradient(135deg,#ecfdf5_0%,#f8fffc_100%)]"
                  : effectivePrinterDiagnostics.tone === "warning"
                    ? "border-amber-200 bg-[linear-gradient(135deg,#fffbeb_0%,#fffdf7_100%)]"
                    : effectivePrinterDiagnostics.tone === "neutral"
                      ? "border-slate-200 bg-[linear-gradient(135deg,#f8fafc_0%,#ffffff_100%)]"
                      : "border-red-200 bg-[linear-gradient(135deg,#fef2f2_0%,#fff8f8_100%)]"
              )}
            >
              <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
                <div className="flex items-start gap-4">
                  <div className="flex h-16 w-16 shrink-0 items-center justify-center rounded-2xl border border-slate-200 bg-white text-lg font-semibold tracking-[0.24em] text-slate-700 shadow-sm">
                    {printerIdentity.monogram}
                  </div>
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-lg font-semibold text-slate-950">{printerIdentity.displayName}</span>
                      <Badge
                        variant={
                          effectivePrinterDiagnostics.tone === "success"
                            ? "default"
                            : effectivePrinterDiagnostics.tone === "warning" || effectivePrinterDiagnostics.tone === "neutral"
                              ? "secondary"
                              : "destructive"
                        }
                      >
                        {effectivePrinterDiagnostics.badgeLabel}
                      </Badge>
                      {selectedPrinter?.online === false && !shouldUseManagedPrinterSummary ? <Badge variant="destructive">Offline</Badge> : null}
                      {shouldUseManagedPrinterSummary && preferredManagedNetworkPrinter ? (
                        <Badge variant="secondary">{getPrinterDispatchLabel(preferredManagedNetworkPrinter)}</Badge>
                      ) : null}
                      {printerDegraded ? (
                        <Badge
                          variant="outline"
                          className="border-amber-300 bg-amber-100 text-amber-900"
                        >
                          Recovery mode
                        </Badge>
                      ) : null}
                    </div>
                    <p className="mt-1 text-sm font-medium text-slate-700">
                      {printerIdentity.vendor}
                      {printerIdentity.model ? ` · ${printerIdentity.model}` : ""}
                    </p>
                    <p
                      className={cn(
                        "mt-3 text-sm leading-6",
                        printerUnavailable ? "text-slate-700" : effectivePrinterReady ? "text-emerald-800" : "text-slate-700"
                      )}
                    >
                      {printerSummaryMessage}
                    </p>
                    <p className="mt-2 text-xs leading-5 text-slate-600">{effectivePrinterDiagnostics.detail}</p>
                    <p className="mt-2 text-xs leading-5 text-slate-600">{printerNextStep}</p>
                    {printerDegraded ? (
                      <div className="mt-3 rounded-xl border border-amber-200 bg-amber-50 px-3 py-2 text-xs leading-5 text-amber-900">
                        {printerDegradedMessage}
                      </div>
                    ) : null}
                  </div>
                </div>

                <div className="grid gap-2 text-xs text-slate-600 sm:min-w-[15rem]">
                  <div className="rounded-xl border border-white/80 bg-white/85 px-3 py-2">
                    <div className="font-medium text-slate-500">Active printer</div>
                    <div className="mt-1 font-semibold text-slate-900">
                      {shouldUseManagedPrinterSummary
                        ? preferredManagedNetworkPrinter?.name || "Managed printer"
                        : selectedPrinterName || printerName || "Not selected"}
                    </div>
                  </div>
                  <div className="rounded-xl border border-white/80 bg-white/85 px-3 py-2">
                    <div className="font-medium text-slate-500">Last checked</div>
                    <div className="mt-1 font-semibold text-slate-900">{printerUpdatedLabel}</div>
                  </div>
                </div>
              </div>
            </div>

            <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <div className="text-xs font-semibold uppercase tracking-[0.22em] text-slate-500">Status updates</div>
                  <div className="mt-1 text-lg font-semibold text-slate-950">{printerFeedLabel}</div>
                </div>
                <div
                  className={cn(
                    "inline-flex items-center gap-2 rounded-full px-3 py-1 text-xs font-medium",
                    printerStatusLive ? "bg-emerald-50 text-emerald-700" : "bg-slate-100 text-slate-700"
                  )}
                >
                  <Wifi className="h-3.5 w-3.5" />
                  {printerStatusLive ? "Connected" : "Refreshing"}
                </div>
              </div>

              <div className="mt-4 grid gap-3 text-sm text-slate-700">
                <div className="flex items-start gap-3 rounded-xl border border-slate-200 bg-slate-50 px-3 py-2.5">
                  <Monitor className="mt-0.5 h-4 w-4 text-slate-500" />
                  <div>
                    <div className="font-medium text-slate-900">Last status update</div>
                    <div className="text-xs text-slate-600">{printerUpdatedLabel}</div>
                  </div>
                </div>
                <div className="flex items-start gap-3 rounded-xl border border-slate-200 bg-slate-50 px-3 py-2.5">
                  <RefreshCw className="mt-0.5 h-4 w-4 text-slate-500" />
                  <div>
                    <div className="font-medium text-slate-900">Connection refresh</div>
                    <div className="text-xs text-slate-600">{formatPrinterAge(printerAgeSeconds)}</div>
                  </div>
                </div>
                <div className="flex items-start gap-3 rounded-xl border border-slate-200 bg-slate-50 px-3 py-2.5">
                  {effectivePrinterReady ? (
                    <CheckCircle2 className="mt-0.5 h-4 w-4 text-emerald-600" />
                  ) : (
                    <AlertTriangle className="mt-0.5 h-4 w-4 text-amber-600" />
                  )}
                  <div>
                    <div className="font-medium text-slate-900">Current state</div>
                    <div className="text-xs text-slate-600">{effectivePrinterDiagnostics.badgeLabel}</div>
                  </div>
                </div>
                {printerDegraded ? (
                  <div className="flex items-start gap-3 rounded-xl border border-amber-200 bg-amber-50 px-3 py-2.5">
                    <AlertTriangle className="mt-0.5 h-4 w-4 text-amber-700" />
                    <div>
                      <div className="font-medium text-amber-950">Recovery mode</div>
                      <div className="text-xs text-amber-800">Printing is staying available while secure printer settings catch up</div>
                    </div>
                  </div>
                ) : null}
              </div>
            </div>
          </div>

          {managedNetworkPrinters.length > 0 ? (
            <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
              <div>
                <div>
                  <div className="text-xs font-semibold uppercase tracking-[0.22em] text-slate-500">Saved network printers</div>
                  <div className="mt-1 text-lg font-semibold text-slate-950">
                    {managedNetworkPrinters.length === 1 ? "1 saved network printer" : `${managedNetworkPrinters.length} saved network printers`}
                  </div>
                  <p className="mt-1 text-sm text-slate-600">
                    These saved printers work through MSCQR without depending on the printer list on this computer.
                  </p>
                </div>
              </div>

              <div className="mt-4 grid gap-3 md:grid-cols-2">
                {managedNetworkPrinters.slice(0, 4).map((printer) => {
                  const statusState = printer.registryStatus?.state || "ATTENTION";
                  const statusVariant =
                    statusState === "READY"
                      ? "default"
                      : statusState === "BLOCKED" || statusState === "OFFLINE"
                        ? "destructive"
                        : "secondary";

                  return (
                    <div key={printer.id} className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                      <div className="flex flex-wrap items-start justify-between gap-2">
                        <div>
                          <div className="font-semibold text-slate-950">{printer.name}</div>
                          <div className="mt-1 text-xs text-slate-600">
                            {getPrinterDispatchLabel(printer)}
                            {printer.vendor || printer.model ? ` · ${[printer.vendor, printer.model].filter(Boolean).join(" ")}` : ""}
                          </div>
                        </div>
                        <Badge variant={statusVariant}>{printer.registryStatus?.summary || statusState}</Badge>
                      </div>
                      <div className="mt-3 text-xs leading-5 text-slate-600">
                        {sanitizePrinterUiError(
                          printer.registryStatus?.detail,
                          "This saved printer needs attention before it can be used."
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          ) : null}

          <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <div className="text-xs font-semibold uppercase tracking-[0.22em] text-slate-500">Printer roster</div>
                <div className="mt-1 text-lg font-semibold text-slate-950">
                  {detectedPrinters.length > 0 ? printerDiscoveryCountLabel : "No printer connection detected"}
                </div>
                <p className="mt-1 text-sm text-slate-600">
                  Review the printers available on this computer and choose the one you want MSCQR to use.
                </p>
              </div>
              <Button variant="outline" className="gap-2" onClick={onRefreshStatus} disabled={printerSwitching}>
                <RefreshCw className="h-4 w-4" />
                Refresh status
              </Button>
            </div>

            {detectedPrinters.length === 0 ? (
              <div className="mt-4 rounded-2xl border border-dashed border-slate-300 bg-slate-50 p-6">
                <div className="text-base font-semibold text-slate-950">
                  {managedNetworkPrinters.length > 0 ? "No workstation printer detected" : "No printer connection detected"}
                </div>
                <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-600">
                  {managedNetworkPrinters.length > 0
                    ? "The printer helper is not reporting a local printer right now, but your saved network printers are still available above."
                    : "MSCQR could not find a ready printer on this computer. Make sure the printer is available in the operating system, then refresh the status."}
                </p>
                <div className="mt-4 flex flex-wrap gap-3">
                  <Button onClick={onRefreshStatus} disabled={printerSwitching}>
                    Refresh status
                  </Button>
                  <Button variant="outline" onClick={onOpenBatches}>
                    Go to batches
                  </Button>
                  <Button variant="ghost" onClick={onOpenHelp}>
                    Open help
                  </Button>
                </div>
              </div>
            ) : (
              <div className="mt-4 grid gap-3 md:grid-cols-2">
                {detectedPrinters.map((row) => {
                  const rowIdentity = derivePrinterIdentity({
                    printerName: row.printerName,
                    selectedPrinterName: row.printerName,
                    model: row.model || null,
                    deviceName: workstationDeviceName,
                  });
                  const isActive = row.printerId === activePrinterId;
                  const isSelected = row.printerId === selectedLocalPrinterId;

                  return (
                    <div
                      key={row.printerId}
                      className={cn(
                        "rounded-2xl border p-4 transition",
                        isActive
                          ? "border-emerald-200 bg-emerald-50/70 shadow-[0_10px_24px_-22px_rgba(16,185,129,0.85)]"
                          : isSelected
                            ? "border-sky-200 bg-sky-50/70"
                            : "border-slate-200 bg-slate-50 hover:border-slate-300"
                      )}
                    >
                      <div className="flex items-start justify-between gap-3">
                        <button
                          type="button"
                          className="flex min-w-0 flex-1 items-start gap-3 text-left"
                          onClick={() => onSelectedLocalPrinterChange(row.printerId)}
                        >
                          <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-2xl border border-white bg-white text-sm font-semibold tracking-[0.2em] text-slate-700">
                            {rowIdentity.monogram}
                          </div>
                          <div className="min-w-0">
                            <div className="flex flex-wrap items-center gap-2">
                              <div className="truncate font-semibold text-slate-950">{row.printerName}</div>
                              {isActive ? <Badge variant="default">Active</Badge> : null}
                              {row.online === false ? <Badge variant="destructive">Offline</Badge> : null}
                            </div>
                            <div className="mt-1 text-xs text-slate-600">
                              {rowIdentity.vendor}
                              {row.model ? ` · ${row.model}` : ""}
                              {row.connection ? ` · ${row.connection}` : ""}
                            </div>
                            <div className="mt-2 text-xs text-slate-500">
                              {row.languages?.join(", ") || "Automatic"} · {row.mediaSizes?.join(", ") || "Auto paper size"}
                            </div>
                          </div>
                        </button>

                        <Button
                          size="sm"
                          variant={isActive ? "secondary" : "outline"}
                          disabled={printerSwitching || isActive}
                          onClick={() => onSwitchLocalPrinter(row.printerId)}
                        >
                          {isActive ? "Active printer" : "Use this printer"}
                        </Button>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
            <div className="flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
              <div className="space-y-2">
                <Label className="text-sm font-medium text-slate-900">Select printer</Label>
                <Select value={selectedLocalPrinterId} onValueChange={onSelectedLocalPrinterChange}>
                  <SelectTrigger className="md:w-[24rem]">
                    <SelectValue placeholder="Choose a printer on this computer" />
                  </SelectTrigger>
                  <SelectContent>
                    {detectedPrinters.length === 0 ? (
                      <SelectItem value="__none__" disabled>
                        No printers discovered
                      </SelectItem>
                    ) : (
                      detectedPrinters.map((row) => (
                        <SelectItem key={row.printerId} value={row.printerId}>
                          {row.printerName}
                          {row.connection ? ` · ${row.connection}` : ""}
                          {row.online === false ? " · offline" : ""}
                        </SelectItem>
                      ))
                    )}
                  </SelectContent>
                </Select>
              </div>

              <div className="flex flex-wrap gap-2">
                <Button
                  size="sm"
                  variant="outline"
                  disabled={printerSwitching || !selectedLocalPrinterId || selectedPrinterIsActive}
                  onClick={() => onSwitchLocalPrinter()}
                >
                  {printerSwitching ? "Saving..." : "Use selected printer"}
                </Button>
                <Button size="sm" variant="ghost" onClick={onOpenBatches}>
                  Go to batches
                </Button>
              </div>
            </div>
          </div>

          <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
            <div className="text-sm font-semibold text-slate-950">Need help getting ready?</div>
            <p className="mt-1 text-sm text-slate-600">
              Use these quick actions if the printer helper or printer still needs attention before you print.
            </p>
            <div className="mt-4 flex flex-wrap gap-2">
              {managedNetworkPrinters.length === 0 ? (
                <Button variant="outline" onClick={onInstallConnector}>
                  Install printer helper
                </Button>
              ) : null}
              <Button variant="ghost" onClick={onOpenHelp}>
                Open help
              </Button>
            </div>
          </div>

          <div className="flex flex-wrap justify-end gap-2">
            <Button variant="outline" onClick={onOpenHelp}>
              Open help
            </Button>
            <Button variant="outline" onClick={onClose}>
              Close
            </Button>
            <Button variant="outline" className="gap-2" onClick={onRefreshStatus} disabled={printerSwitching}>
              <RefreshCw className="h-4 w-4" />
              Refresh status
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
