import { useEffect, useMemo, useState } from "react";
import { CheckCircle2, Copy, ExternalLink, RefreshCw, ShieldAlert, Wifi, Wrench } from "lucide-react";
import { useNavigate } from "react-router-dom";

import { APP_PATHS } from "@/app/route-metadata";
import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { PageEmptyState, PageInlineNotice, PageSection, SettingsPagePattern } from "@/components/page-patterns/PagePatterns";
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useAuth } from "@/contexts/AuthContext";
import { useManufacturerPrinterRuntime } from "@/features/printing/hooks";
import { getContextualHelpRoute } from "@/help/contextual-help";
import { useToast } from "@/hooks/use-toast";
import apiClient from "@/lib/api-client";
import {
  getManagedPrinterDiagnosticSummary,
  getPrinterDiagnosticSummary,
  selectPreferredManagedPrinter,
  shouldPreferNetworkDirectSummary,
} from "@/lib/printer-diagnostics";
import { buildPrinterSupportSummary, getPrinterDispatchLabel, sanitizePrinterUiError } from "@/lib/printer-user-facing";

const STEP_CARD_BASE = "rounded-2xl border bg-card p-5 shadow-sm";

const toneClasses = (tone: "success" | "warning" | "neutral" | "danger") => {
  if (tone === "success") return "border-emerald-200 bg-emerald-50";
  if (tone === "warning") return "border-amber-200 bg-amber-50";
  if (tone === "danger") return "border-red-200 bg-red-50";
  return "border-slate-200 bg-slate-50";
};

export default function PrinterSetupPage() {
  const navigate = useNavigate();
  const { toast } = useToast();
  const { user } = useAuth();
  const contextualHelpRoute = getContextualHelpRoute(APP_PATHS.printerSetup, user?.role);

  const runtimeQuery = useManufacturerPrinterRuntime(true, user?.role === "manufacturer");
  const localAgent = runtimeQuery.data?.localAgent || {
    reachable: false,
    connected: false,
    error: "Workstation connector has not been checked yet.",
    checkedAt: null,
  };
  const remoteStatus = runtimeQuery.data?.remoteStatus || null;
  const detectedPrinters = runtimeQuery.data?.detectedPrinters || [];
  const registeredPrinters = runtimeQuery.data?.registeredPrinters || [];

  const [selectedPrinterId, setSelectedPrinterId] = useState("");
  const [switchingPrinter, setSwitchingPrinter] = useState(false);
  const [runningCheck, setRunningCheck] = useState(false);

  useEffect(() => {
    const preferredPrinterId = String(runtimeQuery.data?.preferredPrinterId || "").trim();
    if (!preferredPrinterId) return;

    setSelectedPrinterId((current) => {
      if (current && detectedPrinters.some((printer) => printer.printerId === current)) return current;
      return preferredPrinterId;
    });
  }, [detectedPrinters, runtimeQuery.data?.preferredPrinterId]);

  const managedPrinters = useMemo(
    () => registeredPrinters.filter((printer) => printer.connectionType !== "LOCAL_AGENT" && printer.isActive),
    [registeredPrinters]
  );

  const preferredManagedPrinter = useMemo(() => selectPreferredManagedPrinter(managedPrinters), [managedPrinters]);
  const localSummary = useMemo(
    () =>
      getPrinterDiagnosticSummary({
        localAgent,
        remoteStatus,
        printers: detectedPrinters,
        selectedPrinterId,
      }),
    [detectedPrinters, localAgent, remoteStatus, selectedPrinterId]
  );
  const managedSummary = useMemo(() => getManagedPrinterDiagnosticSummary(preferredManagedPrinter), [preferredManagedPrinter]);
  const shouldUseManagedSummary = shouldPreferNetworkDirectSummary({
    printers: detectedPrinters,
    networkPrinter: preferredManagedPrinter,
  });
  const effectiveSummary = shouldUseManagedSummary && managedSummary ? managedSummary : localSummary;

  const selectedPrinter =
    detectedPrinters.find((printer) => printer.printerId === selectedPrinterId) ||
    effectiveSummary.selectedPrinter ||
    null;

  const managedReadyCount = managedPrinters.filter((printer) => printer.registryStatus?.state === "READY").length;
  const managedAttentionCount = managedPrinters.filter((printer) => printer.registryStatus?.state !== "READY").length;

  const copySupportSummary = async () => {
    try {
      const summary = buildPrinterSupportSummary({
        localAgent,
        remoteStatus,
        selectedPrinterName:
          selectedPrinter?.printerName || remoteStatus?.selectedPrinterName || remoteStatus?.printerName || null,
        printerSummaryTitle: effectiveSummary.title,
        printerSummaryBody: effectiveSummary.summary,
        managedPrinter: preferredManagedPrinter,
      });
      await navigator.clipboard.writeText(summary);
      toast({
        title: "Support summary copied",
        description: "A redacted printer status summary is now in your clipboard.",
      });
    } catch {
      toast({
        title: "Copy failed",
        description: "Could not copy the support summary.",
        variant: "destructive",
      });
    }
  };

  const refreshStatus = async () => {
    await runtimeQuery.refetch();
  };

  const switchPrinter = async () => {
    if (!selectedPrinterId) return;

    setSwitchingPrinter(true);
    try {
      const response = await apiClient.selectLocalPrinter(selectedPrinterId);
      if (!response.success) {
        toast({
          title: "Printer switch failed",
          description: sanitizePrinterUiError(response.error, "Could not switch the active workstation printer."),
          variant: "destructive",
        });
        return;
      }

      toast({
        title: "Printer updated",
        description: "MSCQR will use the selected workstation printer for the next print job.",
      });
      await runtimeQuery.refetch();
    } finally {
      setSwitchingPrinter(false);
    }
  };

  const runReadinessCheck = async () => {
    if (!preferredManagedPrinter?.id) {
      await refreshStatus();
      toast({
        title: "Status refreshed",
        description: "MSCQR re-checked the current printer connection.",
      });
      return;
    }

    setRunningCheck(true);
    try {
      const response = await apiClient.testRegisteredPrinter(preferredManagedPrinter.id);
      if (!response.success) {
        toast({
          title: "Readiness check failed",
          description: sanitizePrinterUiError(response.error, "Could not confirm this saved printer route."),
          variant: "destructive",
        });
        return;
      }

      const detail =
        (response.data as { registryStatus?: { detail?: string; summary?: string } } | undefined)?.registryStatus?.detail ||
        (response.data as { registryStatus?: { detail?: string; summary?: string } } | undefined)?.registryStatus?.summary ||
        "Saved printer route checked successfully.";

      toast({
        title: "Readiness check complete",
        description: detail,
      });
      await runtimeQuery.refetch();
    } finally {
      setRunningCheck(false);
    }
  };

  const actions = (
    <>
      <Button variant="outline" onClick={() => void refreshStatus()} disabled={runtimeQuery.isFetching}>
        <RefreshCw className="mr-2 h-4 w-4" />
        {runtimeQuery.isFetching ? "Refreshing..." : "Refresh status"}
      </Button>
      <Button variant="outline" onClick={() => void copySupportSummary()}>
        <Copy className="mr-2 h-4 w-4" />
        Copy support summary
      </Button>
      <Button variant="outline" onClick={() => navigate(contextualHelpRoute)}>
        Open help
      </Button>
    </>
  );

  return (
    <DashboardLayout>
      <SettingsPagePattern
        eyebrow="Printing"
        title="Printer Setup"
        description="Install the connector once, choose the right printer on this workstation, and confirm readiness before printing."
        actions={actions}
      >
        {runtimeQuery.error ? (
          <PageInlineNotice
            variant="destructive"
            title="Could not load printer setup"
            description={runtimeQuery.error instanceof Error ? runtimeQuery.error.message : "Please refresh and try again."}
          />
        ) : null}

        <div className="grid gap-4 lg:grid-cols-3">
          <Card className={toneClasses(effectiveSummary.tone)}>
            <CardContent className="pt-6">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <div className="text-sm font-medium uppercase tracking-[0.16em] text-muted-foreground">Status now</div>
                  <div className="mt-2 text-xl font-semibold">{effectiveSummary.title}</div>
                </div>
                <Badge variant={effectiveSummary.tone === "danger" ? "destructive" : "secondary"}>
                  {effectiveSummary.badgeLabel}
                </Badge>
              </div>
              <p className="mt-3 text-sm text-foreground">{effectiveSummary.summary}</p>
              <p className="mt-2 text-xs text-muted-foreground">{effectiveSummary.detail}</p>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="pt-6">
              <div className="text-sm font-medium uppercase tracking-[0.16em] text-muted-foreground">Selected printer</div>
              <div className="mt-2 text-xl font-semibold">
                {selectedPrinter?.printerName || preferredManagedPrinter?.name || "None selected yet"}
              </div>
              <div className="mt-3 flex flex-wrap gap-2">
                {selectedPrinter?.online === false ? <Badge variant="destructive">Offline</Badge> : null}
                {selectedPrinter?.isDefault ? <Badge variant="secondary">OS default</Badge> : null}
                {preferredManagedPrinter ? (
                  <Badge variant={managedReadyCount > 0 ? "default" : "secondary"}>
                    {getPrinterDispatchLabel(preferredManagedPrinter)}
                  </Badge>
                ) : null}
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="pt-6">
              <div className="text-sm font-medium uppercase tracking-[0.16em] text-muted-foreground">Saved routes</div>
              <div className="mt-2 text-xl font-semibold">{managedPrinters.length}</div>
              <div className="mt-3 flex flex-wrap gap-2">
                <Badge variant={managedReadyCount > 0 ? "default" : "secondary"}>{managedReadyCount} ready</Badge>
                <Badge variant="secondary">{managedAttentionCount} need review</Badge>
              </div>
            </CardContent>
          </Card>
        </div>

        <PageSection
          title="Complete setup"
          description="Finish these steps in order. Most manufacturer admins should only need this section."
          action={<Button onClick={() => navigate(APP_PATHS.batches)}>Open batches</Button>}
        >
          <div className="grid gap-4 lg:grid-cols-3">
            <div className={`${STEP_CARD_BASE} ${localAgent.reachable ? "border-emerald-200 bg-emerald-50/70" : ""}`}>
              <div className="flex items-center justify-between gap-3">
                <div className="text-sm font-semibold">1. Install connector</div>
                {localAgent.reachable ? <CheckCircle2 className="h-5 w-5 text-emerald-600" /> : <ShieldAlert className="h-5 w-5 text-amber-600" />}
              </div>
              <p className="mt-3 text-sm text-muted-foreground">
                Install the MSCQR Connector once on the printing computer so the app can detect the printer.
              </p>
              <div className="mt-3 text-sm font-medium">
                {localAgent.reachable ? "Connector detected on this workstation." : "Connector still needs to be installed or started."}
              </div>
              <div className="mt-4">
                <Button variant={localAgent.reachable ? "outline" : "default"} onClick={() => navigate(APP_PATHS.connectorDownload)}>
                  Install connector
                </Button>
              </div>
            </div>

            <div className={`${STEP_CARD_BASE} ${selectedPrinter || preferredManagedPrinter ? "border-emerald-200 bg-emerald-50/70" : ""}`}>
              <div className="flex items-center justify-between gap-3">
                <div className="text-sm font-semibold">2. Choose printer</div>
                {selectedPrinter || preferredManagedPrinter ? <CheckCircle2 className="h-5 w-5 text-emerald-600" /> : <Wifi className="h-5 w-5 text-amber-600" />}
              </div>
              <p className="mt-3 text-sm text-muted-foreground">
                Select the workstation printer for everyday printing, or use a saved network route for managed setups.
              </p>
              <div className="mt-3 text-sm font-medium">
                {selectedPrinter?.printerName || preferredManagedPrinter?.name || "No active printer selected yet."}
              </div>
              <div className="mt-4">
                <Button variant="outline" onClick={() => navigate(`${APP_PATHS.printerSetupAdvanced}?managedProfiles=open`)}>
                  Manage saved routes
                </Button>
              </div>
            </div>

            <div className={`${STEP_CARD_BASE} ${effectiveSummary.tone === "success" ? "border-emerald-200 bg-emerald-50/70" : ""}`}>
              <div className="flex items-center justify-between gap-3">
                <div className="text-sm font-semibold">3. Confirm readiness</div>
                {effectiveSummary.tone === "success" ? <CheckCircle2 className="h-5 w-5 text-emerald-600" /> : <Wrench className="h-5 w-5 text-amber-600" />}
              </div>
              <p className="mt-3 text-sm text-muted-foreground">
                Run one readiness check before the next batch to make sure the connector, printer, and cloud state agree.
              </p>
              <div className="mt-3 text-sm font-medium">{effectiveSummary.badgeLabel}</div>
              <div className="mt-4">
                <Button onClick={() => void runReadinessCheck()} disabled={runningCheck}>
                  {runningCheck ? "Checking..." : "Run readiness check"}
                </Button>
              </div>
            </div>
          </div>
        </PageSection>

        <PageSection
          title="Choose printer"
          description="Pick the active workstation printer here, then return to batches when the status is ready."
          action={
            <Button variant="outline" onClick={() => void switchPrinter()} disabled={!selectedPrinterId || switchingPrinter || detectedPrinters.length === 0}>
              {switchingPrinter ? "Switching..." : "Use selected printer"}
            </Button>
          }
        >
          {detectedPrinters.length === 0 ? (
            <PageEmptyState
              title={preferredManagedPrinter ? "No workstation printers detected" : "No printers detected yet"}
              description={
                preferredManagedPrinter
                  ? "A saved network route is available, so you can still print from batches after its readiness check passes."
                  : "Make sure the printer is installed in the operating system, then refresh this page."
              }
              actionLabel="Refresh status"
              onAction={() => void refreshStatus()}
            />
          ) : (
            <div className="space-y-4">
              <div className="max-w-md">
                <Select value={selectedPrinterId || "__none__"} onValueChange={(value) => setSelectedPrinterId(value === "__none__" ? "" : value)}>
                  <SelectTrigger>
                    <SelectValue placeholder="Choose a printer" />
                  </SelectTrigger>
                  <SelectContent>
                    {detectedPrinters.map((printer) => (
                      <SelectItem key={printer.printerId} value={printer.printerId}>
                        {printer.printerName}
                        {printer.connection ? ` · ${printer.connection}` : ""}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              <div className="grid gap-3 md:grid-cols-2">
                {detectedPrinters.map((printer) => (
                  <div key={printer.printerId} className="rounded-2xl border bg-muted/20 p-4">
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <div className="font-semibold">{printer.printerName}</div>
                        <div className="mt-1 text-xs text-muted-foreground">
                          {printer.model || "Unknown model"}
                          {printer.connection ? ` · ${printer.connection}` : ""}
                        </div>
                      </div>
                      <div className="flex flex-wrap gap-2">
                        {printer.printerId === selectedPrinterId ? <Badge variant="default">Selected</Badge> : null}
                        {printer.isDefault ? <Badge variant="secondary">OS default</Badge> : null}
                        <Badge variant={printer.online === false ? "destructive" : "secondary"}>
                          {printer.online === false ? "Offline" : "Online"}
                        </Badge>
                      </div>
                    </div>
                    <p className="mt-3 text-sm text-muted-foreground">
                      {printer.online === false
                        ? "This printer is currently unavailable on the workstation."
                        : "This printer is available for MSCQR print jobs on this workstation."}
                    </p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </PageSection>

        <PageSection
          title="Saved route status"
          description="Factory and office network routes stay available here for managed environments. Most daily printing does not need this area."
          action={
            <Button variant="outline" onClick={() => navigate(`${APP_PATHS.printerSetupAdvanced}?managedProfiles=open`)}>
              <ExternalLink className="mr-2 h-4 w-4" />
              Open advanced route manager
            </Button>
          }
        >
          {preferredManagedPrinter ? (
            <div className="grid gap-4 lg:grid-cols-[1.2fr_0.8fr]">
              <div className="rounded-2xl border bg-muted/20 p-5">
                <div className="flex flex-wrap items-center gap-2">
                  <div className="text-lg font-semibold">{preferredManagedPrinter.name}</div>
                  <Badge variant={managedReadyCount > 0 ? "default" : "secondary"}>
                    {getPrinterDispatchLabel(preferredManagedPrinter)}
                  </Badge>
                </div>
                <p className="mt-3 text-sm text-muted-foreground">
                  {managedSummary?.summary || "MSCQR is keeping the saved printer route available for managed printing."}
                </p>
                <p className="mt-2 text-xs text-muted-foreground">
                  {managedSummary?.detail || "Open the advanced route manager to update or re-check this printer route."}
                </p>
              </div>
              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-1">
                <div className="rounded-2xl border p-4">
                  <div className="text-sm text-muted-foreground">Ready routes</div>
                  <div className="mt-2 text-2xl font-semibold">{managedReadyCount}</div>
                </div>
                <div className="rounded-2xl border p-4">
                  <div className="text-sm text-muted-foreground">Routes needing review</div>
                  <div className="mt-2 text-2xl font-semibold">{managedAttentionCount}</div>
                </div>
              </div>
            </div>
          ) : (
            <PageEmptyState
              title="No saved network routes yet"
              description="If your team uses factory LAN printers or office IPP printers, add the route from the advanced manager. Otherwise you can keep printing through the workstation connector."
              actionLabel="Open advanced route manager"
              onAction={() => navigate(`${APP_PATHS.printerSetupAdvanced}?managedProfiles=open`)}
            />
          )}
        </PageSection>

        <PageSection title="Advanced troubleshooting" description="Only use these details when setup is blocked or support asks for them.">
          <Accordion type="single" collapsible className="w-full">
            <AccordionItem value="connector">
              <AccordionTrigger>Connector and cloud details</AccordionTrigger>
              <AccordionContent className="space-y-4">
                <div className="grid gap-4 md:grid-cols-2">
                  <div className="rounded-2xl border bg-muted/20 p-4">
                    <div className="text-sm font-semibold">Workstation connector</div>
                    <div className="mt-3 space-y-2 text-sm text-muted-foreground">
                      <div>Reachable: {localAgent.reachable ? "Yes" : "No"}</div>
                      <div>Printer detected: {localAgent.connected ? "Yes" : "No"}</div>
                      <div>{sanitizePrinterUiError(localAgent.error, "Connector is available.")}</div>
                    </div>
                  </div>
                  <div className="rounded-2xl border bg-muted/20 p-4">
                    <div className="text-sm font-semibold">Cloud readiness</div>
                    <div className="mt-3 space-y-2 text-sm text-muted-foreground">
                      <div>Eligible for printing: {remoteStatus?.eligibleForPrinting ? "Yes" : "No"}</div>
                      <div>Trusted connection: {remoteStatus?.trusted ? "Yes" : "No"}</div>
                      <div>{sanitizePrinterUiError(remoteStatus?.error || remoteStatus?.trustReason, "MSCQR will update this state automatically.")}</div>
                    </div>
                  </div>
                </div>
              </AccordionContent>
            </AccordionItem>

            <AccordionItem value="support">
              <AccordionTrigger>Support handoff</AccordionTrigger>
              <AccordionContent className="space-y-4">
                <p className="text-sm text-muted-foreground">
                  Copy the support summary before you contact support. It includes the current printer state without exposing unnecessary system details.
                </p>
                <div className="flex flex-wrap gap-2">
                  <Button variant="outline" onClick={() => void copySupportSummary()}>
                    <Copy className="mr-2 h-4 w-4" />
                    Copy support summary
                  </Button>
                  <Button variant="outline" onClick={() => navigate(APP_PATHS.printerSetupAdvanced)}>
                    <ExternalLink className="mr-2 h-4 w-4" />
                    Open advanced diagnostics
                  </Button>
                </div>
              </AccordionContent>
            </AccordionItem>
          </Accordion>
        </PageSection>
      </SettingsPagePattern>
    </DashboardLayout>
  );
}
