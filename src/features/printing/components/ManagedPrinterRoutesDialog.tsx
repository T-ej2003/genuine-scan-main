import React from "react";
import { RefreshCw, Trash2 } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { sanitizePrinterUiError, getPrinterDispatchLabel } from "@/lib/printer-user-facing";
import type { PrinterInventoryRow } from "@/lib/printer-diagnostics";
import {
  buildEmptyNetworkPrinterForm,
  getManagedSetupTypeLabel,
  isSupportedNetworkDirectLanguage,
  NETWORK_DIRECT_SUPPORTED_LANGUAGES,
  type NetworkPrinterFormState,
  type RegisteredPrinterRow,
} from "@/features/printing/advanced-types";

type AutoDetectedManagedPrinter = {
  printer: PrinterInventoryRow;
  suggestion: any;
};

type ManagedPrinterRoutesDialogProps = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  managedPrinterReadyCount: number;
  managedNetworkPrinterCount: number;
  autoDetectedManagedPrinters: AutoDetectedManagedPrinter[];
  registeredPrinters: RegisteredPrinterRow[];
  loading: boolean;
  setupFormOpen: boolean;
  editingPrinterId: string | null;
  networkPrinterForm: NetworkPrinterFormState;
  setNetworkPrinterForm: React.Dispatch<React.SetStateAction<NetworkPrinterFormState>>;
  gatewayProvisioningSecret: string | null;
  savingNetworkPrinter: boolean;
  testingPrinterId: string | null;
  deletingPrinterId: string | null;
  onRefreshNow: () => Promise<void> | void;
  onUseAutoDetectedPrinter: (printer: PrinterInventoryRow) => void;
  onOpenManagedProfilesDialog: (params?: {
    printer?: RegisteredPrinterRow | null;
    createType?: Extract<RegisteredPrinterRow["connectionType"], "NETWORK_DIRECT" | "NETWORK_IPP">;
    deliveryMode?: NonNullable<RegisteredPrinterRow["deliveryMode"]>;
  }) => void;
  onClose: () => void;
  onResetNetworkPrinterForm: () => void;
  onSaveNetworkPrinter: () => Promise<void> | void;
  onRunPrinterTest: (printerId: string) => Promise<void> | void;
  onRemoveNetworkPrinter: (printer: RegisteredPrinterRow) => Promise<void> | void;
};

function RegisteredPrinterCard({
  printer,
  testingPrinterId,
  deletingPrinterId,
  onOpenManagedProfilesDialog,
  onRunPrinterTest,
  onRemoveNetworkPrinter,
}: {
  printer: RegisteredPrinterRow;
  testingPrinterId: string | null;
  deletingPrinterId: string | null;
  onOpenManagedProfilesDialog: ManagedPrinterRoutesDialogProps["onOpenManagedProfilesDialog"];
  onRunPrinterTest: ManagedPrinterRoutesDialogProps["onRunPrinterTest"];
  onRemoveNetworkPrinter: ManagedPrinterRoutesDialogProps["onRemoveNetworkPrinter"];
}) {
  const isManagedPrinter = printer.connectionType !== "LOCAL_AGENT";

  return (
    <div
      className={`rounded-xl border p-4 transition ${
        isManagedPrinter ? "cursor-pointer hover:border-emerald-200 hover:bg-emerald-50/40" : ""
      }`}
      onClick={isManagedPrinter ? () => onOpenManagedProfilesDialog({ printer }) : undefined}
      role={isManagedPrinter ? "button" : undefined}
      tabIndex={isManagedPrinter ? 0 : undefined}
      onKeyDown={
        isManagedPrinter
          ? (event) => {
              if (event.key === "Enter" || event.key === " ") {
                event.preventDefault();
                onOpenManagedProfilesDialog({ printer });
              }
            }
          : undefined
      }
    >
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="font-semibold">{printer.name}</div>
          <div className="mt-1 text-xs text-muted-foreground">
            {getPrinterDispatchLabel(printer)}
            {printer.vendor || printer.model ? ` · ${[printer.vendor, printer.model].filter(Boolean).join(" ")}` : ""}
            {printer.connectionType === "LOCAL_AGENT" ? " · Managed on the workstation" : ""}
          </div>
        </div>
        <div className="flex flex-wrap gap-2">
          <Badge variant={printer.registryStatus?.state === "BLOCKED" ? "destructive" : "secondary"}>
            {getPrinterDispatchLabel(printer)}
          </Badge>
          <Badge variant={printer.isActive ? "default" : "secondary"}>{printer.isActive ? "Active" : "Inactive"}</Badge>
          {printer.registryStatus?.summary ? <Badge variant="secondary">{printer.registryStatus.summary}</Badge> : null}
        </div>
      </div>
      <div className="mt-3 text-xs text-muted-foreground">
        {sanitizePrinterUiError(
          printer.registryStatus?.detail || printer.lastValidationMessage,
          "No readiness note has been recorded yet."
        )}
      </div>
      {printer.connectionType === "NETWORK_IPP" && printer.deliveryMode === "SITE_GATEWAY" ? (
        <div className="mt-2 text-[11px] text-muted-foreground">
          Site connector mode keeps this printer on a private network while MSCQR dispatches jobs securely.
        </div>
      ) : null}
      <div className="mt-3 flex flex-wrap justify-end gap-2">
        <Button
          variant="outline"
          size="sm"
          disabled={testingPrinterId === printer.id}
          onClick={(event) => {
            event.stopPropagation();
            void onRunPrinterTest(printer.id);
          }}
        >
          {testingPrinterId === printer.id ? "Checking..." : "Check"}
        </Button>
        {isManagedPrinter ? (
          <Button
            variant="outline"
            size="sm"
            onClick={(event) => {
              event.stopPropagation();
              onOpenManagedProfilesDialog({ printer });
            }}
          >
            Edit
          </Button>
        ) : null}
        {isManagedPrinter ? (
          <Button
            variant="outline"
            size="sm"
            disabled={deletingPrinterId === printer.id}
            onClick={(event) => {
              event.stopPropagation();
              void onRemoveNetworkPrinter(printer);
            }}
          >
            <Trash2 className="mr-1 h-4 w-4" />
            {deletingPrinterId === printer.id ? "Removing..." : "Remove"}
          </Button>
        ) : null}
      </div>
    </div>
  );
}

function ManagedPrinterSetupPanel({
  networkPrinterForm,
  setNetworkPrinterForm,
  gatewayProvisioningSecret,
  savingNetworkPrinter,
  editingPrinterId,
  onResetNetworkPrinterForm,
  onSaveNetworkPrinter,
}: {
  networkPrinterForm: NetworkPrinterFormState;
  setNetworkPrinterForm: React.Dispatch<React.SetStateAction<NetworkPrinterFormState>>;
  gatewayProvisioningSecret: string | null;
  savingNetworkPrinter: boolean;
  editingPrinterId: string | null;
  onResetNetworkPrinterForm: () => void;
  onSaveNetworkPrinter: () => Promise<void> | void;
}) {
  const networkPrinterLanguageSupported = isSupportedNetworkDirectLanguage(networkPrinterForm.commandLanguage);

  return (
    <>
      <div className="rounded-xl border bg-muted/20 p-3 text-xs text-muted-foreground">
        <div className="font-medium text-foreground">Managed network setup</div>
        <div className="mt-1 leading-5">
          Save a controlled printer route for <strong>{getManagedSetupTypeLabel(networkPrinterForm)}</strong>. This setup surface is for deployment and printer administration, not everyday print operations.
        </div>
      </div>
      <div className="space-y-1">
        <Label className="text-xs">Name</Label>
        <Input value={networkPrinterForm.name} onChange={(e) => setNetworkPrinterForm((prev) => ({ ...prev, name: e.target.value }))} placeholder="Factory line printer" />
      </div>
      <div className="grid gap-3 sm:grid-cols-2">
        <div className="space-y-1">
          <Label className="text-xs">Vendor</Label>
          <Input value={networkPrinterForm.vendor} onChange={(e) => setNetworkPrinterForm((prev) => ({ ...prev, vendor: e.target.value }))} placeholder="Zebra" />
        </div>
        <div className="space-y-1">
          <Label className="text-xs">Model</Label>
          <Input value={networkPrinterForm.model} onChange={(e) => setNetworkPrinterForm((prev) => ({ ...prev, model: e.target.value }))} placeholder="ZT411" />
        </div>
      </div>
      <div className="space-y-1">
        <Label className="text-xs">Printer type</Label>
        <Select
          value={networkPrinterForm.connectionType}
          onValueChange={(value) =>
            setNetworkPrinterForm((prev) => ({
              ...prev,
              connectionType: value as RegisteredPrinterRow["connectionType"],
              port: value === "NETWORK_IPP" ? "631" : "9100",
            }))
          }
        >
          <SelectTrigger>
            <SelectValue placeholder="Printer type" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="NETWORK_DIRECT">Factory label printer (LAN)</SelectItem>
            <SelectItem value="NETWORK_IPP">Office / AirPrint printer</SelectItem>
          </SelectContent>
        </Select>
      </div>
      <div className="grid gap-3 sm:grid-cols-2">
        <div className="space-y-1">
          <Label className="text-xs">{networkPrinterForm.connectionType === "NETWORK_IPP" ? "Host or printer name" : "IP address or host"}</Label>
          {networkPrinterForm.connectionType === "NETWORK_IPP" ? (
            <Input value={networkPrinterForm.host} onChange={(e) => setNetworkPrinterForm((prev) => ({ ...prev, host: e.target.value }))} placeholder="canon-office.local" />
          ) : (
            <Input value={networkPrinterForm.ipAddress} onChange={(e) => setNetworkPrinterForm((prev) => ({ ...prev, ipAddress: e.target.value }))} placeholder="192.168.1.50 or printer-lan-01" />
          )}
        </div>
        <div className="space-y-1">
          <Label className="text-xs">{networkPrinterForm.connectionType === "NETWORK_IPP" ? "IPP port" : "TCP port"}</Label>
          <Input value={networkPrinterForm.port} onChange={(e) => setNetworkPrinterForm((prev) => ({ ...prev, port: e.target.value }))} placeholder={networkPrinterForm.connectionType === "NETWORK_IPP" ? "631" : "9100"} />
        </div>
      </div>
      {networkPrinterForm.connectionType === "NETWORK_DIRECT" ? (
        <>
          <div className="space-y-1">
            <Label className="text-xs">Printer language</Label>
            <Select
              value={networkPrinterForm.commandLanguage}
              onValueChange={(value) => setNetworkPrinterForm((prev) => ({ ...prev, commandLanguage: value as RegisteredPrinterRow["commandLanguage"] }))}
            >
              <SelectTrigger>
                <SelectValue placeholder="Printer language" />
              </SelectTrigger>
              <SelectContent>
                {!networkPrinterLanguageSupported && networkPrinterForm.commandLanguage ? (
                  <SelectItem value={networkPrinterForm.commandLanguage} disabled>
                    {networkPrinterForm.commandLanguage} (legacy unsupported)
                  </SelectItem>
                ) : null}
                {NETWORK_DIRECT_SUPPORTED_LANGUAGES.map((language) => (
                  <SelectItem key={language} value={language}>
                    {language}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          {!networkPrinterLanguageSupported ? (
            <div className="rounded-xl border border-red-200 bg-red-50 p-3 text-xs text-red-800">
              This profile currently uses <strong>{networkPrinterForm.commandLanguage}</strong>, which is not allowed for
              factory label printer dispatch. Change it to ZPL, TSPL, EPL, or CPCL before saving or checking.
            </div>
          ) : null}
        </>
      ) : (
        <>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="space-y-1">
              <Label className="text-xs">Resource path</Label>
              <Input value={networkPrinterForm.resourcePath} onChange={(e) => setNetworkPrinterForm((prev) => ({ ...prev, resourcePath: e.target.value }))} placeholder="/ipp/print" />
            </div>
            <div className="space-y-1">
              <Label className="text-xs">Printer URI (optional)</Label>
              <Input value={networkPrinterForm.printerUri} onChange={(e) => setNetworkPrinterForm((prev) => ({ ...prev, printerUri: e.target.value }))} placeholder="ipps://canon.local:631/ipp/print" />
            </div>
          </div>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="space-y-1">
              <Label className="text-xs">Delivery mode</Label>
              <Select
                value={networkPrinterForm.deliveryMode}
                onValueChange={(value) => setNetworkPrinterForm((prev) => ({ ...prev, deliveryMode: value as NonNullable<RegisteredPrinterRow["deliveryMode"]> }))}
              >
                <SelectTrigger>
                  <SelectValue placeholder="Delivery mode" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="DIRECT">Backend direct</SelectItem>
                  <SelectItem value="SITE_GATEWAY">Site connector</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="flex items-end">
              <label className="flex items-center gap-2 text-xs text-muted-foreground">
                <input type="checkbox" checked={Boolean(networkPrinterForm.tlsEnabled)} onChange={(e) => setNetworkPrinterForm((prev) => ({ ...prev, tlsEnabled: e.target.checked }))} />
                Prefer TLS / IPPS
              </label>
            </div>
          </div>
          {networkPrinterForm.deliveryMode === "SITE_GATEWAY" ? (
            <div className="space-y-2 rounded-xl border border-amber-200 bg-amber-50 p-3 text-xs text-amber-900">
              <div>Site connector mode keeps the printer on a private network and uses secure outbound job pickup.</div>
              {editingPrinterId ? (
                <label className="flex items-center gap-2">
                  <input type="checkbox" checked={Boolean(networkPrinterForm.rotateGatewaySecret)} onChange={(e) => setNetworkPrinterForm((prev) => ({ ...prev, rotateGatewaySecret: e.target.checked }))} />
                  Rotate connector secret on save
                </label>
              ) : null}
              {gatewayProvisioningSecret ? (
                <div className="space-y-2 rounded-lg border border-amber-300 bg-white/70 p-3 text-[11px]">
                  <div className="font-medium text-foreground">One-time connector bootstrap secret</div>
                  <div className="break-all font-mono text-foreground">{gatewayProvisioningSecret}</div>
                  <div>Provision this secret into the workstation connector once. It will not be shown again.</div>
                </div>
              ) : null}
            </div>
          ) : null}
        </>
      )}
      <div className="flex flex-wrap justify-end gap-2">
        <Button variant="outline" onClick={onResetNetworkPrinterForm}>
          {editingPrinterId ? "Cancel edit" : "Close setup"}
        </Button>
        <Button onClick={() => void onSaveNetworkPrinter()} disabled={savingNetworkPrinter || (networkPrinterForm.connectionType === "NETWORK_DIRECT" && !networkPrinterLanguageSupported)}>
          {savingNetworkPrinter ? "Saving..." : editingPrinterId ? "Update setup" : "Save setup"}
        </Button>
      </div>
      <div className="text-xs text-muted-foreground">
        Factory label printers use approved saved LAN targets only. Office / AirPrint printers use standards-based IPP/IPPS and can run directly or through a site connector.
      </div>
    </>
  );
}

export function ManagedPrinterRoutesDialog({
  open,
  onOpenChange,
  title,
  managedPrinterReadyCount,
  managedNetworkPrinterCount,
  autoDetectedManagedPrinters,
  registeredPrinters,
  loading,
  setupFormOpen,
  editingPrinterId,
  networkPrinterForm,
  setNetworkPrinterForm,
  gatewayProvisioningSecret,
  savingNetworkPrinter,
  testingPrinterId,
  deletingPrinterId,
  onRefreshNow,
  onUseAutoDetectedPrinter,
  onOpenManagedProfilesDialog,
  onClose,
  onResetNetworkPrinterForm,
  onSaveNetworkPrinter,
  onRunPrinterTest,
  onRemoveNetworkPrinter,
}: ManagedPrinterRoutesDialogProps) {
  return (
    <Dialog
      open={open}
      onOpenChange={(nextOpen) => {
        if (!nextOpen) {
          onClose();
          return;
        }
        onOpenChange(true);
      }}
    >
      <DialogContent className="max-h-[88vh] overflow-y-auto sm:max-w-[1080px]">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>
            Create, update, delete, and validate `NETWORK_DIRECT` and `NETWORK_IPP` profiles from one workspace. These managed routes are the end-to-end controls for backend and site-gateway printing.
          </DialogDescription>
        </DialogHeader>

        <div className="grid gap-4 lg:grid-cols-[1.15fr_0.85fr]">
          <div className="space-y-4">
            <div className="flex flex-wrap gap-2">
              <Badge variant="secondary">Live checks every 6 seconds</Badge>
              <Badge variant={managedPrinterReadyCount > 0 ? "default" : "secondary"}>{managedPrinterReadyCount} ready</Badge>
              <Badge variant="secondary">{managedNetworkPrinterCount} saved routes</Badge>
            </div>

            <div className="grid gap-3 sm:grid-cols-3">
              <button
                type="button"
                onClick={() => onOpenManagedProfilesDialog({ createType: "NETWORK_DIRECT" })}
                className="rounded-2xl border bg-muted/20 p-4 text-left transition hover:border-emerald-200 hover:bg-emerald-50/40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500"
              >
                <div className="text-sm font-semibold text-foreground">New factory route</div>
                <div className="mt-2 text-xs leading-5 text-muted-foreground">Save a raw TCP endpoint for ZPL, TSPL, EPL, or CPCL dispatch.</div>
              </button>
              <button
                type="button"
                onClick={() => onOpenManagedProfilesDialog({ createType: "NETWORK_IPP", deliveryMode: "DIRECT" })}
                className="rounded-2xl border bg-muted/20 p-4 text-left transition hover:border-emerald-200 hover:bg-emerald-50/40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500"
              >
                <div className="text-sm font-semibold text-foreground">New IPP route</div>
                <div className="mt-2 text-xs leading-5 text-muted-foreground">Save a backend-direct IPP or IPPS endpoint for an office printer.</div>
              </button>
              <button
                type="button"
                onClick={() => onOpenManagedProfilesDialog({ createType: "NETWORK_IPP", deliveryMode: "SITE_GATEWAY" })}
                className="rounded-2xl border bg-muted/20 p-4 text-left transition hover:border-emerald-200 hover:bg-emerald-50/40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500"
              >
                <div className="text-sm font-semibold text-foreground">New gateway route</div>
                <div className="mt-2 text-xs leading-5 text-muted-foreground">Keep the printer private and validate it through the site connector flow.</div>
              </button>
            </div>

            <div className="rounded-2xl border bg-background p-4">
              <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                <div>
                  <div className="text-sm font-semibold text-foreground">Auto-detected connected printers</div>
                  <div className="text-xs text-muted-foreground">
                    The workstation connector can prefill managed routes when a connected printer exposes usable IPP/IPPS or raw TCP details.
                  </div>
                </div>
                <Badge variant="secondary">
                  {autoDetectedManagedPrinters.length === 1 ? "1 detected" : `${autoDetectedManagedPrinters.length} detected`}
                </Badge>
              </div>

              <div className="mt-4 space-y-3">
                {autoDetectedManagedPrinters.length === 0 ? (
                  <div className="rounded-xl border border-dashed bg-muted/20 p-4 text-sm text-muted-foreground">
                    No connected printers are available for auto-detect right now. Manual managed profile entry still works below.
                  </div>
                ) : (
                  autoDetectedManagedPrinters.map(({ printer, suggestion }) => {
                    const routeLabel =
                      suggestion.routeType === "NETWORK_DIRECT"
                        ? "NETWORK_DIRECT"
                        : suggestion.routeType === "NETWORK_IPP"
                          ? "NETWORK_IPP"
                          : "LOCAL_AGENT";

                    return (
                      <div key={printer.printerId} className="rounded-xl border bg-muted/20 p-4">
                        <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                          <div>
                            <div className="font-medium text-foreground">{printer.printerName}</div>
                            <div className="mt-1 text-xs text-muted-foreground">
                              {printer.model || "Detected printer"}
                              {printer.connection ? ` · ${printer.connection}` : ""}
                              {printer.online === false ? " · offline" : ""}
                            </div>
                          </div>
                          <div className="flex flex-wrap gap-2">
                            <Badge variant={suggestion.routeType === "LOCAL_ONLY" ? "secondary" : "outline"}>{routeLabel}</Badge>
                            <Badge variant={suggestion.readiness === "READY" ? "default" : "secondary"}>
                              {suggestion.readiness === "READY" ? "Detected route ready" : "Needs manual review"}
                            </Badge>
                          </div>
                        </div>
                        <div className="mt-3 text-sm text-foreground">{suggestion.summary}</div>
                        <div className="mt-1 text-xs leading-5 text-muted-foreground">{suggestion.detail}</div>
                        <div className="mt-2 text-[11px] text-muted-foreground">
                          Protocols: {(printer.protocols || []).join(", ") || "Unknown"} · Languages: {(printer.languages || []).join(", ") || "Unknown"}
                        </div>
                        {suggestion.routeType !== "LOCAL_ONLY" ? (
                          <div className="mt-3 flex justify-end">
                            <Button variant="outline" size="sm" disabled={printer.online === false} onClick={() => onUseAutoDetectedPrinter(printer)}>
                              {suggestion.readiness === "READY" ? "Use detected route" : "Use as template"}
                            </Button>
                          </div>
                        ) : null}
                      </div>
                    );
                  })
                )}
              </div>
            </div>

            <div className="rounded-2xl border bg-background p-4">
              <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                <div>
                  <div className="text-sm font-semibold text-foreground">Registered printer profiles</div>
                  <div className="text-xs text-muted-foreground">Click any managed profile to edit it, then use Check to confirm readiness.</div>
                </div>
                <Button variant="outline" size="sm" onClick={() => void onRefreshNow()} disabled={loading}>
                  <RefreshCw className="mr-2 h-4 w-4" />
                  {loading ? "Refreshing..." : "Refresh now"}
                </Button>
              </div>

              <div className="mt-4 space-y-3">
                {registeredPrinters.length === 0 ? (
                  <div className="rounded-xl border border-dashed bg-muted/20 p-4 text-sm text-muted-foreground">
                    No printer profiles are registered yet. Add a managed printer route here and MSCQR will validate it for batch operations.
                  </div>
                ) : (
                  registeredPrinters.map((printer) => (
                    <RegisteredPrinterCard
                      key={printer.id}
                      printer={printer}
                      testingPrinterId={testingPrinterId}
                      deletingPrinterId={deletingPrinterId}
                      onOpenManagedProfilesDialog={onOpenManagedProfilesDialog}
                      onRunPrinterTest={onRunPrinterTest}
                      onRemoveNetworkPrinter={onRemoveNetworkPrinter}
                    />
                  ))
                )}
              </div>
            </div>
          </div>

          <div className="space-y-4">
            {!setupFormOpen && !editingPrinterId ? (
              <div className="rounded-2xl border border-dashed bg-muted/20 p-5 text-sm text-muted-foreground">
                <div className="font-medium text-foreground">Choose what you want to set up</div>
                <div className="mt-2 leading-6">
                  Start a new factory or office printer route, or click a saved route to edit, remove, or re-check it.
                </div>
                <div className="mt-4 text-xs leading-5">
                  Use factory label printer for raw TCP devices on a controlled LAN. Use office / AirPrint printer for IPP or IPPS devices.
                </div>
              </div>
            ) : (
              <div className="rounded-2xl border bg-background p-4">
                <ManagedPrinterSetupPanel
                  networkPrinterForm={networkPrinterForm}
                  setNetworkPrinterForm={setNetworkPrinterForm}
                  gatewayProvisioningSecret={gatewayProvisioningSecret}
                  savingNetworkPrinter={savingNetworkPrinter}
                  editingPrinterId={editingPrinterId}
                  onResetNetworkPrinterForm={onResetNetworkPrinterForm}
                  onSaveNetworkPrinter={onSaveNetworkPrinter}
                />
              </div>
            )}
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
