import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { ArrowLeft, CheckCircle2, CircleHelp, Loader2, Network, PlugZap, ShieldCheck } from "lucide-react";

import { ActionButton } from "@/components/ui/action-button";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { Switch } from "@/components/ui/switch";
import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { useToast } from "@/hooks/use-toast";
import apiClient from "@/lib/api-client";
import { deriveManagedPrinterAutoDetect, normalizePrinterInventoryRows, type PrinterInventoryRow } from "@/lib/printer-diagnostics";
import { getPrinterDispatchLabel, sanitizePrinterUiError } from "@/lib/printer-user-facing";
import { createUiActionState } from "@/lib/ui-actions";
import { useManufacturerPrinterRuntime } from "@/features/printing/hooks";
import { APP_PATHS } from "@/app/route-metadata";
import type { RegisteredPrinterDTO } from "../../shared/contracts/runtime/printing";

type ManagedRouteForm = {
  name: string;
  vendor: string;
  model: string;
  connectionType: "NETWORK_DIRECT" | "NETWORK_IPP";
  ipAddress: string;
  host: string;
  port: string;
  resourcePath: string;
  tlsEnabled: boolean;
  printerUri: string;
  commandLanguage: "ZPL" | "TSPL" | "SBPL" | "EPL" | "DPL" | "HONEYWELL_DP" | "HONEYWELL_FINGERPRINT" | "IPL" | "ZSIM" | "CPCL";
  deliveryMode: "DIRECT" | "SITE_GATEWAY";
};

type PrinterTestLabelResponse = {
  outcome?: "confirmed" | "needs_attention";
  message?: string | null;
};

type LatestConnectorReleaseInfo = {
  latestVersion?: string;
  release?: {
    platforms?: {
      macos?: unknown;
      windows?: unknown;
    };
  };
} | null;

const NETWORK_DIRECT_LANGUAGES: ManagedRouteForm["commandLanguage"][] = [
  "ZPL",
  "TSPL",
  "SBPL",
  "EPL",
  "DPL",
  "HONEYWELL_DP",
  "HONEYWELL_FINGERPRINT",
  "IPL",
  "ZSIM",
  "CPCL",
];

const detectVendor = (printer: PrinterInventoryRow | null) => {
  const combined = `${printer?.printerName || ""} ${printer?.model || ""}`;
  const vendors = ["Zebra", "SATO", "Honeywell", "TSC", "Brother", "Godex", "Bixolon", "Citizen", "Toshiba", "Epson"];
  return vendors.find((candidate) => new RegExp(`\\b${candidate}\\b`, "i").test(combined)) || "";
};

const recommendedDeliveryMode = (printer: PrinterInventoryRow | null, routeType: "NETWORK_DIRECT" | "NETWORK_IPP") => {
  if (routeType === "NETWORK_IPP") return "DIRECT" as const;
  const combined = `${printer?.printerName || ""} ${printer?.model || ""}`.toLowerCase();
  return combined.includes("zebra") ? "DIRECT" : "SITE_GATEWAY";
};

const defaultForm: ManagedRouteForm = {
  name: "",
  vendor: "",
  model: "",
  connectionType: "NETWORK_DIRECT",
  ipAddress: "",
  host: "",
  port: "9100",
  resourcePath: "/ipp/print",
  tlsEnabled: true,
  printerUri: "",
  commandLanguage: "ZPL",
  deliveryMode: "DIRECT",
};

const detectCurrentPlatform = (): "macos" | "windows" | "unknown" => {
  if (typeof navigator === "undefined") return "unknown";
  const source = `${navigator.userAgent || ""} ${(navigator as { platform?: string }).platform || ""}`.toLowerCase();
  if (source.includes("mac")) return "macos";
  if (source.includes("win")) return "windows";
  return "unknown";
};

const getSuggestedPathTitle = (form: ManagedRouteForm, suggestion: ReturnType<typeof deriveManagedPrinterAutoDetect> | null) => {
  if (!suggestion) return "Choose a printer to see the safest setup.";
  if (suggestion.routeType === "LOCAL_ONLY") return "Best fit: keep using the printer already set up on this computer.";
  if (suggestion.routeType === "NETWORK_IPP") return "Best fit: save this as an office printer.";
  return form.deliveryMode === "SITE_GATEWAY"
    ? "Best fit: save this as a label printer through the site print link."
    : "Best fit: save this as a direct label printer.";
};

const getSuggestedPathState = (suggestion: ReturnType<typeof deriveManagedPrinterAutoDetect> | null) => {
  if (!suggestion) return { label: "Waiting", tone: "secondary" as const };
  if (suggestion.routeType === "LOCAL_ONLY") return { label: "Use this computer", tone: "default" as const };
  if (suggestion.readiness === "READY") return { label: "Ready to save", tone: "default" as const };
  return { label: "Needs one more detail", tone: "secondary" as const };
};

const joinHumanList = (items: string[]) => {
  if (items.length === 0) return "";
  if (items.length === 1) return items[0];
  if (items.length === 2) return `${items[0]} and ${items[1]}`;
  return `${items.slice(0, -1).join(", ")}, and ${items[items.length - 1]}`;
};

const getMissingSetupDetails = (
  form: ManagedRouteForm,
  suggestion: ReturnType<typeof deriveManagedPrinterAutoDetect> | null,
) => {
  const missing: string[] = [];

  if (!form.name.trim()) missing.push("a saved printer name");
  if (!suggestion || suggestion.routeType === "LOCAL_ONLY") return missing;

  if (form.connectionType === "NETWORK_IPP") {
    if (!form.host.trim() && !form.printerUri.trim()) missing.push("a printer address");
    if (!form.printerUri.trim() && !String(form.port || "").trim()) missing.push("a printer port");
    if (!form.printerUri.trim() && !form.resourcePath.trim()) missing.push("a printer path");
    return missing;
  }

  if (!form.ipAddress.trim()) missing.push("a printer IP address");
  if (!String(form.port || "").trim()) missing.push("a printer port");
  if (!form.commandLanguage.trim()) missing.push("the label type");
  return missing;
};

const buildRecommendedPrinterForm = (
  printer: PrinterInventoryRow,
  suggestion: NonNullable<ReturnType<typeof deriveManagedPrinterAutoDetect>>,
): ManagedRouteForm => {
  const vendor = detectVendor(printer);
  return {
    name: printer.printerName,
    vendor,
    model: printer.model || "",
    connectionType: suggestion.routeType === "NETWORK_IPP" ? "NETWORK_IPP" : "NETWORK_DIRECT",
    ipAddress: suggestion.host || "",
    host: suggestion.host || "",
    port: String(suggestion.port || (suggestion.routeType === "NETWORK_IPP" ? 631 : 9100)),
    resourcePath: suggestion.resourcePath || "/ipp/print",
    tlsEnabled: suggestion.tlsEnabled ?? true,
    printerUri: suggestion.printerUri || "",
    commandLanguage: (suggestion.commandLanguage as ManagedRouteForm["commandLanguage"] | null) || "ZPL",
    deliveryMode:
      suggestion.routeType === "LOCAL_ONLY"
        ? "DIRECT"
        : recommendedDeliveryMode(printer, suggestion.routeType === "NETWORK_IPP" ? "NETWORK_IPP" : "NETWORK_DIRECT"),
  };
};

const buildRecommendedPrinterSignature = (
  printer: PrinterInventoryRow,
  suggestion: NonNullable<ReturnType<typeof deriveManagedPrinterAutoDetect>>,
) =>
  JSON.stringify({
    printerId: printer.printerId,
    printerName: printer.printerName,
    model: printer.model || "",
    routeType: suggestion.routeType,
    readiness: suggestion.readiness,
    host: suggestion.host || "",
    port: suggestion.port || "",
    resourcePath: suggestion.resourcePath || "",
    printerUri: suggestion.printerUri || "",
    commandLanguage: suggestion.commandLanguage || "",
    tlsEnabled: suggestion.tlsEnabled ?? null,
  });

export default function PrinterSetupPage() {
  const navigate = useNavigate();
  const { toast } = useToast();
  const detectedPlatform = useMemo(() => detectCurrentPlatform(), []);
  const runtimeQuery = useManufacturerPrinterRuntime(true, true);
  const inventoryQuery = useQuery({
    queryKey: ["printer-setup", "inventory"],
    refetchInterval: 5000,
    queryFn: async () => {
      const response = await apiClient.getLocalPrintAgentStatus();
      if (!response.success) return [] as PrinterInventoryRow[];
      return normalizePrinterInventoryRows((response.data as { printers?: unknown[] } | undefined)?.printers || []);
    },
  });
  const connectorReleaseQuery = useQuery({
    queryKey: ["printer-setup", "connector-release"],
    staleTime: 60_000,
    queryFn: async () => {
      const response = await apiClient.getLatestConnectorRelease();
      return response.success && response.data ? (response.data as LatestConnectorReleaseInfo) : null;
    },
  });

  const [selectedPrinterId, setSelectedPrinterId] = useState("");
  const [form, setForm] = useState<ManagedRouteForm>(defaultForm);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [saving, setSaving] = useState(false);
  const [testingPrinterId, setTestingPrinterId] = useState<string | null>(null);
  const lastRecommendedSignatureRef = useRef("");

  const inventory = inventoryQuery.data || [];
  const registeredPrinters = (runtimeQuery.data?.registeredPrinters || []) as RegisteredPrinterDTO[];
  const remoteStatus = runtimeQuery.data?.remoteStatus || null;
  const localReady = Boolean(remoteStatus?.connected && remoteStatus?.eligibleForPrinting);
  const helperVersion = String(remoteStatus?.agentVersion || "").trim();
  const latestHelperVersion = String(connectorReleaseQuery.data?.latestVersion || "").trim();
  const detectedPlatformRelease =
    detectedPlatform === "unknown"
      ? null
      : connectorReleaseQuery.data?.release?.platforms?.[detectedPlatform] || null;
  const helperNeedsUpdate = Boolean(helperVersion && latestHelperVersion && helperVersion !== latestHelperVersion);

  useEffect(() => {
    if (selectedPrinterId) return;
    const preferred = inventory.find((row) => row.isDefault) || inventory[0];
    if (preferred) setSelectedPrinterId(preferred.printerId);
  }, [inventory, selectedPrinterId]);

  const selectedPrinter = useMemo(
    () =>
      inventory.find((row) => row.printerId === selectedPrinterId) ||
      inventory.find((row) => row.isDefault) ||
      inventory[0] ||
      null,
    [inventory, selectedPrinterId]
  );
  const suggestion = useMemo(
    () => (selectedPrinter ? deriveManagedPrinterAutoDetect(selectedPrinter) : null),
    [selectedPrinter]
  );
  const recommendedSignature = useMemo(
    () => (selectedPrinter && suggestion ? buildRecommendedPrinterSignature(selectedPrinter, suggestion) : ""),
    [selectedPrinter, suggestion]
  );

  useEffect(() => {
    if (!selectedPrinter || !suggestion || !recommendedSignature) return;
    if (lastRecommendedSignatureRef.current === recommendedSignature) return;
    lastRecommendedSignatureRef.current = recommendedSignature;

    setForm(buildRecommendedPrinterForm(selectedPrinter, suggestion));
    setShowAdvanced(suggestion.readiness !== "READY");
  }, [recommendedSignature, selectedPrinter, suggestion]);

  const recommendedPathLabel = useMemo(() => {
    if (!suggestion) return "Select a printer to begin";
    if (suggestion.routeType === "LOCAL_ONLY") return "Recommended: use the printer already set up on this computer";
    if (suggestion.routeType === "NETWORK_IPP") return "Recommended: save this as an office printer";
    return form.deliveryMode === "SITE_GATEWAY"
      ? "Recommended: save this as a label printer through the site print link"
      : "Recommended: save this as a direct label printer";
  }, [form.deliveryMode, suggestion]);

  const suggestedPathState = getSuggestedPathState(suggestion);
  const missingSetupDetails = useMemo(() => getMissingSetupDetails(form, suggestion), [form, suggestion]);

  const saveActionState = useMemo(() => {
    if (!selectedPrinter) {
      return createUiActionState("disabled", "Choose the printer this computer is already using first.");
    }
    if (!suggestion) {
      return createUiActionState("disabled", "Wait for MSCQR to finish checking the selected printer.");
    }
    if (suggestion.routeType === "LOCAL_ONLY") {
      return createUiActionState("hidden");
    }
    if (saving) {
      return createUiActionState("pending", "Saving the printer and running one live test label.");
    }
    if (missingSetupDetails.length > 0) {
      return createUiActionState(
        "disabled",
        `Finish ${joinHumanList(missingSetupDetails)} before you save this printer.`,
      );
    }
    return createUiActionState("enabled");
  }, [missingSetupDetails, saving, selectedPrinter, suggestion]);

  const saveRecommendedPrinter = async () => {
    if (!suggestion || suggestion.routeType === "LOCAL_ONLY") {
      toast({
        title: "This printer is already ready to use here",
        description: "Keep using the printer already set up on this computer. You do not need to save a separate network printer.",
      });
      return;
    }

    setSaving(true);
    try {
      const payload =
        form.connectionType === "NETWORK_IPP"
          ? {
              name: form.name,
              vendor: form.vendor || undefined,
              model: form.model || undefined,
              connectionType: "NETWORK_IPP" as const,
              host: form.host,
              port: Number(form.port || 631) || 631,
              resourcePath: form.resourcePath || "/ipp/print",
              tlsEnabled: form.tlsEnabled,
              printerUri: form.printerUri || undefined,
              deliveryMode: form.deliveryMode,
              isDefault: true,
            }
          : {
              name: form.name,
              vendor: form.vendor || undefined,
              model: form.model || undefined,
              connectionType: "NETWORK_DIRECT" as const,
              ipAddress: form.ipAddress,
              port: Number(form.port || 9100) || 9100,
              commandLanguage: form.commandLanguage,
              deliveryMode: form.deliveryMode,
              isDefault: true,
            };

      const saveResponse = await apiClient.createNetworkPrinter(payload);
      if (!saveResponse.success || !saveResponse.data) {
        toast({
          title: "Printer setup failed",
          description: sanitizePrinterUiError(saveResponse.error, "MSCQR could not save this printer route yet."),
          variant: "destructive",
        });
        return;
      }

      const printerId = String((saveResponse.data as { id?: string }).id || "").trim();
      if (!printerId) {
        toast({
          title: "Printer saved without validation",
          description: "Refresh the page to review the new printer profile.",
        });
        return;
      }

      await Promise.allSettled([
        apiClient.discoverRegisteredPrinter(printerId),
        runtimeQuery.refetch(),
      ]);

      setTestingPrinterId(printerId);
      const testResponse = await apiClient.testPrinterLabel(printerId);
      const testData = (testResponse.data as PrinterTestLabelResponse | undefined) || undefined;
      if (testResponse.success && testData?.outcome === "confirmed") {
        toast({
          title: "Printer is ready",
          description: testData.message || "The recommended route was saved and the live test label completed successfully.",
        });
      } else {
        toast({
          title: "Printer saved, but the live test needs attention",
          description: sanitizePrinterUiError(
            testData?.message || testResponse.error,
            "The profile was saved, but the live test label still needs attention."
          ),
          variant: "destructive",
        });
      }

      await runtimeQuery.refetch();
    } finally {
      setTestingPrinterId(null);
      setSaving(false);
    }
  };

  const testExistingPrinter = async (printerId: string) => {
    setTestingPrinterId(printerId);
    try {
      const response = await apiClient.testPrinterLabel(printerId);
      const data = (response.data as PrinterTestLabelResponse | undefined) || undefined;
      toast({
        title: response.success && data?.outcome === "confirmed" ? "Live test label printed" : "Printer needs attention",
        description:
          response.success && data?.outcome === "confirmed"
            ? data.message || "MSCQR printed the live test label and the printer confirmed completion."
            : sanitizePrinterUiError(data?.message || response.error, "This printer route still needs attention."),
        variant: response.success && data?.outcome === "confirmed" ? "default" : "destructive",
      });
      await runtimeQuery.refetch();
    } finally {
      setTestingPrinterId(null);
    }
  };

  return (
    <DashboardLayout>
      <div className="mx-auto flex w-full max-w-6xl flex-col gap-6 px-4 py-6">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
          <div>
            <div className="text-sm font-medium text-muted-foreground">Manufacturer Printer Setup</div>
            <h1 className="text-3xl font-semibold tracking-tight">Connect a printer in one pass</h1>
            <p className="mt-2 max-w-3xl text-sm text-muted-foreground">
              Choose the printer this computer already sees, let MSCQR recommend the safest setup, save it, and print one live test label.
            </p>
          </div>
          <div className="flex gap-2">
            <Button variant="outline" onClick={() => navigate(APP_PATHS.connectorDownload)}>
              Install printer helper
            </Button>
            <Button variant="outline" asChild>
              <Link to={APP_PATHS.settings}>
                <ArrowLeft className="h-4 w-4" />
                Back to settings
              </Link>
            </Button>
            <Button asChild>
              <Link to={APP_PATHS.dashboard}>Back to dashboard</Link>
            </Button>
          </div>
        </div>

        <div className="grid gap-4 lg:grid-cols-[1.1fr_0.9fr]">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <PlugZap className="h-5 w-5" />
                Printer helper
              </CardTitle>
              <CardDescription>The printer helper should be online before you save or test a printer.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3 text-sm">
              <div className="flex items-center justify-between rounded-lg border p-3">
                <div>
                  <div className="font-medium">Helper status</div>
                  <div className="text-xs text-muted-foreground">
                    {remoteStatus?.error || (localReady ? "The helper is online and can see the printer." : "MSCQR is waiting for the next printer update.")}
                  </div>
                </div>
                <Badge variant={localReady ? "default" : "secondary"}>{localReady ? "Ready" : "Waiting"}</Badge>
              </div>
              <div className="flex items-center justify-between rounded-lg border p-3">
                <div>
                  <div className="font-medium">Installed helper version</div>
                  <div className="text-xs text-muted-foreground">
                    {helperVersion || "MSCQR will show the installed version after the printer helper checks in."}
                  </div>
                </div>
                <Badge variant={helperVersion ? "outline" : "secondary"}>
                  {latestHelperVersion ? `Latest ${latestHelperVersion}` : "Checking release"}
                </Badge>
              </div>
              <div className="flex items-center justify-between rounded-lg border p-3">
                <div>
                  <div className="font-medium">Printers found on this computer</div>
                  <div className="text-xs text-muted-foreground">
                    {inventory.length > 0 ? `${inventory.length} printers detected on this device.` : "No printers detected on this device yet."}
                  </div>
                </div>
                <Badge variant={inventory.length > 0 ? "default" : "secondary"}>{inventory.length}</Badge>
              </div>
              {helperNeedsUpdate && detectedPlatformRelease ? (
                <div className="rounded-lg border border-amber-200 bg-amber-50 p-3 text-xs text-amber-950">
                  A newer printer helper is published for this {detectedPlatform === "macos" ? "Mac" : "Windows"} device.
                  <div className="mt-2">
                    <Button size="sm" variant="outline" onClick={() => navigate(APP_PATHS.connectorDownload)}>
                      Open helper download
                    </Button>
                  </div>
                </div>
              ) : null}
              {helperNeedsUpdate && detectedPlatform === "macos" && !detectedPlatformRelease ? (
                <div className="rounded-lg border border-amber-200 bg-amber-50 p-3 text-xs text-amber-950">
                  This Mac is still running an older printer helper, but the latest signed Mac installer is not published yet.
                  Keep using the current helper on this Mac until the signed update is available.
                </div>
              ) : null}
              <div className="rounded-lg border border-emerald-200 bg-emerald-50 p-3 text-xs text-emerald-950">
                Once the helper shows the printer here, most people can finish setup without typing network details manually.
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <ShieldCheck className="h-5 w-5" />
                Recommended Path
              </CardTitle>
              <CardDescription>{recommendedPathLabel}</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3 text-sm">
              {suggestion ? (
                <>
                  <div className="rounded-lg border p-3">
                    <div className="flex flex-wrap items-center gap-2">
                      <div className="font-medium">{getSuggestedPathTitle(form, suggestion)}</div>
                      <Badge variant={suggestedPathState.tone}>{suggestedPathState.label}</Badge>
                    </div>
                    <div className="mt-2 text-xs text-muted-foreground">{suggestion.summary}</div>
                    <div className="mt-1 text-xs text-muted-foreground">{suggestion.detail}</div>
                  </div>
                  {missingSetupDetails.length > 0 ? (
                    <div className="rounded-lg border border-amber-200 bg-amber-50 p-3 text-xs text-amber-950">
                      MSCQR still needs {joinHumanList(missingSetupDetails)} before it can finish this setup.
                    </div>
                  ) : null}
                </>
              ) : (
                <div className="rounded-lg border p-3 text-xs text-muted-foreground">
                  Choose the printer this computer can already see and MSCQR will recommend the safest setup automatically.
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Network className="h-5 w-5" />
                {suggestion?.routeType === "LOCAL_ONLY" ? "Use the printer on this computer" : "Save this printer"}
              </CardTitle>
              <CardDescription>
                {suggestion?.routeType === "LOCAL_ONLY"
                  ? "This printer works best on this computer without saving a shared setup."
                  : "Advanced fields stay hidden unless MSCQR still needs one more printer detail."}
              </CardDescription>
            </CardHeader>
          <CardContent className="space-y-5">
            <div className="grid gap-4 md:grid-cols-[1fr_auto]">
              <div className="space-y-2">
                <Label htmlFor="detected-printer">Printer already available on this computer</Label>
                <Select value={selectedPrinterId} onValueChange={setSelectedPrinterId}>
                  <SelectTrigger id="detected-printer">
                    <SelectValue placeholder="Choose a printer" />
                  </SelectTrigger>
                  <SelectContent>
                    {inventory.length === 0 ? (
                      <SelectItem value="__none__">No printers detected yet</SelectItem>
                    ) : (
                      inventory.map((printer) => (
                        <SelectItem key={printer.printerId} value={printer.printerId}>
                          {printer.printerName}
                          {printer.online === false ? " · offline" : ""}
                        </SelectItem>
                      ))
                    )}
                  </SelectContent>
                </Select>
              </div>
              <div className="flex items-end">
                <Button variant="outline" onClick={() => inventoryQuery.refetch()} disabled={inventoryQuery.isFetching}>
                  {inventoryQuery.isFetching ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
                  Refresh detection
                </Button>
              </div>
            </div>

            {suggestion?.routeType === "LOCAL_ONLY" ? (
              <div className="rounded-lg border border-emerald-200 bg-emerald-50 p-4 text-sm text-emerald-950">
                This printer is best kept on the built-in printer helper path. Once the helper is ready, go back to batches and start printing without saving a separate shared printer.
                <div className="mt-4 flex flex-wrap gap-2">
                  <Button variant="outline" onClick={() => navigate(APP_PATHS.dashboard)}>
                    Back to dashboard
                  </Button>
                  <Button onClick={() => navigate(APP_PATHS.batches)}>Go to batches</Button>
                </div>
              </div>
            ) : (
              <>
                <div className="grid gap-4 md:grid-cols-2">
                  <div className="space-y-2">
                    <Label htmlFor="route-name">Saved printer name</Label>
                    <Input id="route-name" value={form.name} onChange={(event) => setForm((current) => ({ ...current, name: event.target.value }))} />
                  </div>
                  {form.connectionType === "NETWORK_DIRECT" ? (
                    <div className="space-y-2">
                      <Label htmlFor="delivery-mode">Connection path</Label>
                      <Select
                        value={form.deliveryMode}
                        onValueChange={(value: "DIRECT" | "SITE_GATEWAY") => setForm((current) => ({ ...current, deliveryMode: value }))}
                      >
                        <SelectTrigger id="delivery-mode">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="DIRECT">Connect directly from MSCQR</SelectItem>
                          <SelectItem value="SITE_GATEWAY">Send through the site print link</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  ) : (
                    <div className="rounded-lg border p-3 text-sm">
                      <div className="font-medium">Shared office printer</div>
                      <div className="mt-1 text-xs text-muted-foreground">
                        MSCQR will save this as a shared office printer and use the printer address shown here.
                      </div>
                    </div>
                  )}
                </div>

                <div className="flex items-center justify-between rounded-lg border p-3">
                  <div>
                    <div className="font-medium">Edit printer details manually</div>
                    <div className="text-xs text-muted-foreground">
                      Only open this if MSCQR still needs one more printer detail or the detected address looks wrong.
                    </div>
                  </div>
                  <Switch checked={showAdvanced} onCheckedChange={setShowAdvanced} />
                </div>

                {showAdvanced ? (
                  <div className="grid gap-4 md:grid-cols-2">
                    <div className="space-y-2">
                      <Label htmlFor="vendor">Vendor</Label>
                      <Input id="vendor" value={form.vendor} onChange={(event) => setForm((current) => ({ ...current, vendor: event.target.value }))} />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="model">Model</Label>
                      <Input id="model" value={form.model} onChange={(event) => setForm((current) => ({ ...current, model: event.target.value }))} />
                    </div>
                    {form.connectionType === "NETWORK_IPP" ? (
                      <>
                        <div className="space-y-2">
                          <Label htmlFor="host">Host</Label>
                          <Input id="host" value={form.host} onChange={(event) => setForm((current) => ({ ...current, host: event.target.value }))} />
                        </div>
                        <div className="space-y-2">
                          <Label htmlFor="port">Port</Label>
                          <Input id="port" value={form.port} onChange={(event) => setForm((current) => ({ ...current, port: event.target.value }))} />
                        </div>
                        <div className="space-y-2">
                          <Label htmlFor="resource-path">Resource path</Label>
                          <Input
                            id="resource-path"
                            value={form.resourcePath}
                            onChange={(event) => setForm((current) => ({ ...current, resourcePath: event.target.value }))}
                          />
                        </div>
                        <div className="space-y-2">
                          <Label htmlFor="printer-uri">Printer URI</Label>
                          <Input
                            id="printer-uri"
                            value={form.printerUri}
                            onChange={(event) => setForm((current) => ({ ...current, printerUri: event.target.value }))}
                          />
                        </div>
                      </>
                    ) : (
                      <>
                        <div className="space-y-2">
                          <Label htmlFor="ip-address">Printer IP</Label>
                          <Input
                            id="ip-address"
                            value={form.ipAddress}
                            onChange={(event) => setForm((current) => ({ ...current, ipAddress: event.target.value }))}
                          />
                        </div>
                        <div className="space-y-2">
                          <Label htmlFor="raw-port">Raw TCP port</Label>
                          <Input id="raw-port" value={form.port} onChange={(event) => setForm((current) => ({ ...current, port: event.target.value }))} />
                        </div>
                        <div className="space-y-2">
                          <Label htmlFor="command-language">Label language</Label>
                          <Select
                            value={form.commandLanguage}
                            onValueChange={(value: ManagedRouteForm["commandLanguage"]) =>
                              setForm((current) => ({ ...current, commandLanguage: value }))
                            }
                          >
                            <SelectTrigger id="command-language">
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              {NETWORK_DIRECT_LANGUAGES.map((language) => (
                                <SelectItem key={language} value={language}>
                                  {language}
                                </SelectItem>
                              ))}
                            </SelectContent>
                          </Select>
                        </div>
                      </>
                    )}
                  </div>
                ) : null}

                <div className="flex flex-wrap gap-2">
                  <ActionButton
                    data-testid="save-printer-setup"
                    onClick={saveRecommendedPrinter}
                    state={saveActionState}
                    idleLabel="Save and print live test label"
                    pendingLabel="Saving and testing..."
                  />
                  <Button variant="outline" onClick={() => navigate(APP_PATHS.batches)}>
                    Go to batches
                  </Button>
                  <Button variant="ghost" onClick={() => navigate(APP_PATHS.settings)}>
                    <CircleHelp className="h-4 w-4" />
                    Back to settings
                  </Button>
                </div>
              </>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Saved printers</CardTitle>
            <CardDescription>These printers are already ready to choose from the batch workflow.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {registeredPrinters.length === 0 ? (
              <div className="rounded-lg border p-4 text-sm text-muted-foreground">
                No saved printers yet. Use the recommendation above to save the first one.
              </div>
            ) : (
              registeredPrinters.map((printer) => (
                <div key={printer.id} className="rounded-lg border p-4">
                  <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                    <div>
                      <div className="flex items-center gap-2">
                        <div className="font-medium">{printer.name}</div>
                        <Badge variant={printer.registryStatus?.state === "READY" ? "default" : "secondary"}>
                          {printer.registryStatus?.state || "PENDING"}
                        </Badge>
                        {printer.isDefault ? <Badge variant="outline">Default</Badge> : null}
                      </div>
                      <div className="mt-1 text-xs text-muted-foreground">
                        {getPrinterDispatchLabel(printer)}
                        {printer.deliveryMode ? ` · ${printer.deliveryMode === "SITE_GATEWAY" ? "site print link" : "direct"}` : ""}
                        {printer.commandLanguage ? ` · ${printer.commandLanguage}` : ""}
                      </div>
                      <div className="mt-2 text-xs text-muted-foreground">
                        {sanitizePrinterUiError(printer.registryStatus?.detail, printer.registryStatus?.summary || "Printer route saved.")}
                      </div>
                    </div>
                    <div className="flex gap-2">
                      <Button
                        data-testid="run-test-print"
                        variant="outline"
                        onClick={() => testExistingPrinter(printer.id)}
                        disabled={testingPrinterId === printer.id}
                      >
                        {testingPrinterId === printer.id ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
                        Print live test label
                      </Button>
                    </div>
                  </div>
                </div>
              ))
            )}
          </CardContent>
        </Card>

        <Separator />

        <div className="rounded-xl border border-emerald-200 bg-emerald-50 p-4 text-sm text-emerald-950">
          <div className="flex items-start gap-3">
            <CheckCircle2 className="mt-0.5 h-5 w-5" />
            <div>
              <div className="font-medium">How duplicates stay blocked</div>
              <div className="mt-1 text-xs leading-5">
                Once a print run is active, MSCQR will resume that job instead of creating a second one for the same batch. A label only becomes printed after the printer route confirms completion.
              </div>
            </div>
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
}
