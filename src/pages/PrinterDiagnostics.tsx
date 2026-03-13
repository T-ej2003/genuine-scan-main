import React, { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { formatDistanceToNow } from "date-fns";
import { Activity, Copy, RefreshCw, ShieldAlert, Trash2, Wifi, Wrench } from "lucide-react";

import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useAuth } from "@/contexts/AuthContext";
import { getContextualHelpRoute } from "@/help/contextual-help";
import { useToast } from "@/hooks/use-toast";
import apiClient from "@/lib/api-client";
import {
  getManagedPrinterDiagnosticSummary,
  getPrinterDiagnosticSummary,
  normalizePrinterInventoryRows,
  selectPreferredManagedPrinter,
  shouldPreferNetworkDirectSummary,
  type LocalPrinterAgentSnapshot,
  type PrinterConnectionStatusLike,
  type PrinterInventoryRow,
} from "@/lib/printer-diagnostics";
import { buildPrinterSupportSummary, getPrinterDispatchLabel, sanitizePrinterUiError } from "@/lib/printer-user-facing";

const EMPTY_LOCAL_AGENT: LocalPrinterAgentSnapshot = {
  reachable: false,
  connected: false,
  error: "Workstation connector has not been checked yet.",
  checkedAt: null,
};

type RegisteredPrinterRow = {
  id: string;
  name: string;
  vendor?: string | null;
  model?: string | null;
  connectionType: "LOCAL_AGENT" | "NETWORK_DIRECT" | "NETWORK_IPP";
  commandLanguage: "AUTO" | "ZPL" | "TSPL" | "SBPL" | "EPL" | "CPCL" | "ESC_POS" | "OTHER";
  ipAddress?: string | null;
  host?: string | null;
  port?: number | null;
  resourcePath?: string | null;
  tlsEnabled?: boolean | null;
  printerUri?: string | null;
  deliveryMode?: "DIRECT" | "SITE_GATEWAY";
  gatewayId?: string | null;
  gatewayStatus?: string | null;
  gatewayLastSeenAt?: string | null;
  gatewayProvisioningSecret?: string | null;
  nativePrinterId?: string | null;
  isActive: boolean;
  isDefault?: boolean;
  lastValidationStatus?: string | null;
  lastValidationMessage?: string | null;
  registryStatus?: {
    state: "READY" | "ATTENTION" | "OFFLINE" | "BLOCKED";
    summary: string;
    detail?: string | null;
  } | null;
};

const NETWORK_DIRECT_SUPPORTED_LANGUAGES = ["ZPL", "TSPL", "EPL", "CPCL"] as const;
type NetworkDirectCommandLanguage = (typeof NETWORK_DIRECT_SUPPORTED_LANGUAGES)[number];

const isSupportedNetworkDirectLanguage = (
  value: RegisteredPrinterRow["commandLanguage"] | string | null | undefined
): value is NetworkDirectCommandLanguage =>
  NETWORK_DIRECT_SUPPORTED_LANGUAGES.includes(String(value || "").trim().toUpperCase() as NetworkDirectCommandLanguage);

const buildEmptyNetworkPrinterForm = () => ({
  connectionType: "NETWORK_DIRECT" as RegisteredPrinterRow["connectionType"],
  name: "",
  vendor: "",
  model: "",
  ipAddress: "",
  host: "",
  port: "9100",
  resourcePath: "/ipp/print",
  tlsEnabled: true,
  printerUri: "",
  deliveryMode: "DIRECT" as NonNullable<RegisteredPrinterRow["deliveryMode"]>,
  rotateGatewaySecret: false,
  commandLanguage: "ZPL" as RegisteredPrinterRow["commandLanguage"],
});

const getManagedSetupTypeLabel = (params: {
  connectionType?: RegisteredPrinterRow["connectionType"] | null;
  deliveryMode?: RegisteredPrinterRow["deliveryMode"] | null;
}) => getPrinterDispatchLabel({ connectionType: params.connectionType, deliveryMode: params.deliveryMode });

export default function PrinterDiagnostics() {
  const { user } = useAuth();
  const { toast } = useToast();
  const navigate = useNavigate();
  const contextualHelpRoute = getContextualHelpRoute("/printer-diagnostics", user?.role);

  const [loading, setLoading] = useState(false);
  const [localAgent, setLocalAgent] = useState<LocalPrinterAgentSnapshot>(EMPTY_LOCAL_AGENT);
  const [remoteStatus, setRemoteStatus] = useState<PrinterConnectionStatusLike | null>(null);
  const [detectedPrinters, setDetectedPrinters] = useState<PrinterInventoryRow[]>([]);
  const [selectedPrinterId, setSelectedPrinterId] = useState("");
  const [registeredPrinters, setRegisteredPrinters] = useState<RegisteredPrinterRow[]>([]);
  const [savingNetworkPrinter, setSavingNetworkPrinter] = useState(false);
  const [testingPrinterId, setTestingPrinterId] = useState<string | null>(null);
  const [deletingPrinterId, setDeletingPrinterId] = useState<string | null>(null);
  const [editingPrinterId, setEditingPrinterId] = useState<string | null>(null);
  const [networkPrinterForm, setNetworkPrinterForm] = useState(buildEmptyNetworkPrinterForm);
  const [gatewayProvisioningSecret, setGatewayProvisioningSecret] = useState<string | null>(null);
  const [setupFormOpen, setSetupFormOpen] = useState(false);
  const [managedProfilesDialogOpen, setManagedProfilesDialogOpen] = useState(false);

  const networkPrinterLanguageSupported = isSupportedNetworkDirectLanguage(networkPrinterForm.commandLanguage);

  const loadRegisteredPrinters = async () => {
    if (user?.role !== "manufacturer") return;
    const response = await apiClient.listRegisteredPrinters(false);
    if (!response.success) {
      setRegisteredPrinters([]);
      return;
    }
    setRegisteredPrinters((Array.isArray(response.data) ? response.data : []) as RegisteredPrinterRow[]);
  };

  const loadDiagnostics = async () => {
    setLoading(true);
    try {
      const local = await apiClient.getLocalPrintAgentStatus();
      const localPrinters = normalizePrinterInventoryRows((local as any)?.data?.printers || []);
      const nextLocalAgent: LocalPrinterAgentSnapshot = {
        reachable: Boolean(local.success),
        connected: Boolean((local as any)?.data?.connected),
        error: local.success ? String((local as any)?.data?.error || "").trim() || null : String(local.error || "Local print agent is unavailable"),
        checkedAt: new Date().toISOString(),
      };
      setLocalAgent(nextLocalAgent);
      setDetectedPrinters(localPrinters);

      const preferredPrinterId = String(
        (local as any)?.data?.selectedPrinterId ||
          (local as any)?.data?.printerId ||
          localPrinters.find((row) => row.isDefault)?.printerId ||
          localPrinters[0]?.printerId ||
          ""
      ).trim();
      if (preferredPrinterId) setSelectedPrinterId((prev) => prev || preferredPrinterId);

      if (user?.role === "manufacturer") {
        const heartbeatPayload = local.success
          ? {
              connected: Boolean((local.data as any)?.connected),
              printerName: (local.data as any)?.printerName || undefined,
              printerId: (local.data as any)?.printerId || undefined,
              selectedPrinterId: (local.data as any)?.selectedPrinterId || undefined,
              selectedPrinterName: (local.data as any)?.selectedPrinterName || undefined,
              deviceName: (local.data as any)?.deviceName || undefined,
              agentVersion: (local.data as any)?.agentVersion || undefined,
              error: (local.data as any)?.error || undefined,
              agentId: (local.data as any)?.agentId || undefined,
              deviceFingerprint: (local.data as any)?.deviceFingerprint || undefined,
              publicKeyPem: (local.data as any)?.publicKeyPem || undefined,
              clientCertFingerprint: (local.data as any)?.clientCertFingerprint || undefined,
              heartbeatNonce: (local.data as any)?.heartbeatNonce || undefined,
              heartbeatIssuedAt: (local.data as any)?.heartbeatIssuedAt || undefined,
              heartbeatSignature: (local.data as any)?.heartbeatSignature || undefined,
              capabilitySummary: (local.data as any)?.capabilitySummary || undefined,
              printers: localPrinters,
              calibrationProfile: (local.data as any)?.calibrationProfile || undefined,
            }
          : {
              connected: false,
              error: String(local.error || "Local print agent unavailable"),
            };

        await apiClient.reportPrinterHeartbeat(heartbeatPayload);
        const remote = await apiClient.getPrinterConnectionStatus();
        if (remote.success && remote.data) {
          const normalizedRemote = remote.data as PrinterConnectionStatusLike;
          const remotePrinters = normalizePrinterInventoryRows(normalizedRemote.printers || []);
          setRemoteStatus({
            ...normalizedRemote,
            printers: remotePrinters.length > 0 ? remotePrinters : localPrinters,
          });
          if (!preferredPrinterId) {
            const remotePreferred = String(
              normalizedRemote.selectedPrinterId || normalizedRemote.printerId || remotePrinters.find((row) => row.isDefault)?.printerId || ""
            ).trim();
            if (remotePreferred) setSelectedPrinterId(remotePreferred);
          }
        } else {
          setRemoteStatus({
            connected: false,
            trusted: false,
            compatibilityMode: false,
            eligibleForPrinting: false,
            connectionClass: "BLOCKED",
            stale: true,
            trustStatus: "UNREGISTERED",
            trustReason: remote.error || "Printer diagnostics unavailable",
            lastHeartbeatAt: null,
            ageSeconds: null,
            printers: localPrinters,
            error: remote.error || "Printer diagnostics unavailable",
          });
        }
        await loadRegisteredPrinters();
      } else {
        setRemoteStatus(null);
      }
    } finally {
      setLoading(false);
    }
  };

  const switchSelectedPrinter = async () => {
    const targetPrinterId = String(selectedPrinterId || "").trim();
    if (!targetPrinterId) return;
    const response = await apiClient.selectLocalPrinter(targetPrinterId);
    if (!response.success) {
      toast({
        title: "Printer switch failed",
        description: sanitizePrinterUiError(response.error, "Could not switch the workstation printer."),
        variant: "destructive",
      });
      return;
    }
    toast({
      title: "Printer switched",
      description: "The workstation printer has been updated.",
    });
    await loadDiagnostics();
  };

  const copySupportSummary = async () => {
    const summary = buildPrinterSupportSummary({
      localAgent,
      remoteStatus,
      selectedPrinterName: effectiveSummary.selectedPrinter?.printerName || remoteStatus?.selectedPrinterName || remoteStatus?.printerName || null,
      printerSummaryTitle: effectiveSummary.title,
      printerSummaryBody: effectiveSummary.summary,
      managedPrinter: preferredManagedNetworkPrinter,
    });
    await navigator.clipboard.writeText(summary);
    toast({
      title: "Support summary copied",
      description: "A redacted printer support summary is now in your clipboard.",
    });
  };

  useEffect(() => {
    loadDiagnostics();
    const timer = window.setInterval(() => {
      loadDiagnostics();
    }, 6000);
    return () => window.clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user?.id, user?.role]);

  const summary = useMemo(
    () =>
      getPrinterDiagnosticSummary({
        localAgent,
        remoteStatus,
        printers: detectedPrinters,
        selectedPrinterId,
      }),
    [detectedPrinters, localAgent, remoteStatus, selectedPrinterId]
  );

  const managedNetworkPrinters = useMemo(
    () => registeredPrinters.filter((printer) => printer.connectionType !== "LOCAL_AGENT" && printer.isActive),
    [registeredPrinters]
  );

  const effectiveLicenseeId = useMemo(() => {
    const directLicenseeId = String(user?.licenseeId || "").trim();
    if (directLicenseeId) return directLicenseeId;

    const primaryLinkedLicensee = user?.linkedLicensees?.find((entry) => entry.isPrimary)?.id;
    const fallbackLinkedLicensee = user?.linkedLicensees?.[0]?.id;
    const linkedLicenseeId = String(primaryLinkedLicensee || fallbackLinkedLicensee || "").trim();
    return linkedLicenseeId || undefined;
  }, [user?.licenseeId, user?.linkedLicensees]);

  const preferredManagedNetworkPrinter = useMemo(
    () => selectPreferredManagedPrinter(managedNetworkPrinters),
    [managedNetworkPrinters]
  );

  const preferredManagedSummary = useMemo(
    () => getManagedPrinterDiagnosticSummary(preferredManagedNetworkPrinter),
    [preferredManagedNetworkPrinter]
  );

  const preferNetworkDirectSummary = shouldPreferNetworkDirectSummary({
    printers: detectedPrinters,
    networkPrinter: preferredManagedNetworkPrinter,
  });

  const effectiveSummary = useMemo(() => {
    if (!preferNetworkDirectSummary || !preferredManagedSummary) return summary;
    return preferredManagedSummary;
  }, [preferNetworkDirectSummary, preferredManagedSummary, summary]);

  const managedPrinterReadyCount = useMemo(
    () => managedNetworkPrinters.filter((printer) => printer.registryStatus?.state === "READY").length,
    [managedNetworkPrinters]
  );

  const managedPrinterAttentionCount = useMemo(
    () =>
      managedNetworkPrinters.filter((printer) => printer.registryStatus?.state && printer.registryStatus.state !== "READY").length,
    [managedNetworkPrinters]
  );

  const statusClasses =
    effectiveSummary.tone === "success"
      ? "border-emerald-200 bg-emerald-50 text-emerald-800"
      : effectiveSummary.tone === "warning"
        ? "border-amber-200 bg-amber-50 text-amber-800"
        : effectiveSummary.tone === "neutral"
          ? "border-slate-200 bg-slate-50 text-slate-700"
          : "border-red-200 bg-red-50 text-red-800";

  const checkedLabel = localAgent.checkedAt
    ? `${formatDistanceToNow(new Date(localAgent.checkedAt), { addSuffix: true })}`
    : "not checked yet";

  const resetNetworkPrinterForm = () => {
    setEditingPrinterId(null);
    setNetworkPrinterForm(buildEmptyNetworkPrinterForm());
    setGatewayProvisioningSecret(null);
    setSetupFormOpen(false);
  };

  const closeManagedProfilesDialog = () => {
    setManagedProfilesDialogOpen(false);
    resetNetworkPrinterForm();
  };

  const openManagedProfilesDialog = (params?: {
    printer?: RegisteredPrinterRow | null;
    createType?: Extract<RegisteredPrinterRow["connectionType"], "NETWORK_DIRECT" | "NETWORK_IPP">;
    deliveryMode?: NonNullable<RegisteredPrinterRow["deliveryMode"]>;
  }) => {
    setManagedProfilesDialogOpen(true);

    if (params?.printer) {
      editNetworkPrinter(params.printer);
      return;
    }

    if (params?.createType) {
      setEditingPrinterId(null);
      setGatewayProvisioningSecret(null);
      setSetupFormOpen(true);
      setNetworkPrinterForm({
        ...buildEmptyNetworkPrinterForm(),
        connectionType: params.createType,
        port: params.createType === "NETWORK_IPP" ? "631" : "9100",
        deliveryMode: params.deliveryMode || "DIRECT",
      });
      return;
    }

    resetNetworkPrinterForm();
  };

  const persistNetworkPrinter = async (params?: {
    printerId?: string | null;
    formOverride?: typeof networkPrinterForm;
    successTitle?: string;
    resetAfterSave?: boolean;
  }) => {
    const source = params?.formOverride || networkPrinterForm;
    const name = source.name.trim();
    const isNetworkDirect = source.connectionType === "NETWORK_DIRECT";
    const ipAddress = source.ipAddress.trim();
    const host = source.host.trim();
    const printerUri = source.printerUri.trim();
    const port = Number(source.port || 0);

    if (!name || !Number.isFinite(port) || port <= 0) {
      toast({
        title: "Incomplete printer profile",
        description: "Name and port are required.",
        variant: "destructive",
      });
      return null;
    }

    if (isNetworkDirect && !ipAddress) {
      toast({
        title: "Incomplete network-direct profile",
        description: "A host or IP address is required for network-direct printers.",
        variant: "destructive",
      });
      return null;
    }

    if (!isNetworkDirect && !host && !printerUri) {
      toast({
        title: "Incomplete IPP profile",
        description: "Enter a host/FQDN or a full printer URI for IPP/AirPrint printers.",
        variant: "destructive",
      });
      return null;
    }

    if (isNetworkDirect && !isSupportedNetworkDirectLanguage(source.commandLanguage)) {
      toast({
        title: "Unsupported network-direct language",
        description: "Choose ZPL, TSPL, EPL, or CPCL. Use the workstation or office printer path for other printer types.",
        variant: "destructive",
      });
      return null;
    }

    setSavingNetworkPrinter(true);
    try {
      const hasActiveDefault = registeredPrinters.some((printer) => printer.isActive && printer.isDefault && printer.id !== params?.printerId);
      const payload = {
        name,
        vendor: source.vendor.trim() || undefined,
        model: source.model.trim() || undefined,
        licenseeId: effectiveLicenseeId,
        connectionType: source.connectionType,
        ipAddress: isNetworkDirect ? ipAddress : undefined,
        host: !isNetworkDirect ? host || undefined : undefined,
        port,
        resourcePath: !isNetworkDirect ? source.resourcePath.trim() || "/ipp/print" : undefined,
        tlsEnabled: !isNetworkDirect ? Boolean(source.tlsEnabled) : undefined,
        printerUri: !isNetworkDirect ? printerUri || undefined : undefined,
        deliveryMode: !isNetworkDirect ? source.deliveryMode : undefined,
        rotateGatewaySecret: !isNetworkDirect ? Boolean(source.rotateGatewaySecret) : undefined,
        commandLanguage: isNetworkDirect ? source.commandLanguage : undefined,
        isDefault: params?.printerId ? undefined : !hasActiveDefault,
      };

      const response = params?.printerId
        ? await apiClient.updateNetworkPrinter(params.printerId, payload)
        : await apiClient.createNetworkPrinter(payload);
      if (!response.success) {
        toast({
          title: params?.printerId ? "Could not update printer setup" : "Could not save printer setup",
          description: sanitizePrinterUiError(response.error, "Could not save this printer profile."),
          variant: "destructive",
        });
        return null;
      }

      const savedPrinter = (response.data || {}) as RegisteredPrinterRow;
      setGatewayProvisioningSecret(savedPrinter.gatewayProvisioningSecret || null);
      const savedPrinterId = String(savedPrinter.id || params?.printerId || "").trim();
      let validated = false;
      let detail = "Printer profile saved.";

      if (savedPrinterId) {
        setTestingPrinterId(savedPrinterId);
        const validation = await apiClient.testRegisteredPrinter(savedPrinterId);
        if (validation.success) {
          validated = true;
          detail =
            (validation.data as any)?.registryStatus?.detail ||
            (validation.data as any)?.registryStatus?.summary ||
            "Printer profile saved and validated.";
        } else {
          detail = sanitizePrinterUiError(validation.error, "Printer profile saved, but the connection still needs attention.");
        }
      }

      toast({
        title:
          params?.successTitle ||
          (validated
            ? params?.printerId
              ? "Printer updated and validated"
              : "Printer registered and validated"
            : params?.printerId
              ? "Printer updated"
              : "Printer registered"),
        description: detail,
        variant: validated ? "default" : "destructive",
      });

      if (params?.resetAfterSave !== false) {
        setEditingPrinterId(null);
        setNetworkPrinterForm(buildEmptyNetworkPrinterForm());
        setSetupFormOpen(false);
      }
      await loadDiagnostics();
      return { savedPrinterId, validated };
    } finally {
      setTestingPrinterId(null);
      setSavingNetworkPrinter(false);
    }
  };

  const saveNetworkPrinter = async () => {
    await persistNetworkPrinter({
      printerId: editingPrinterId,
      resetAfterSave: true,
    });
  };

  const editNetworkPrinter = (printer: RegisteredPrinterRow) => {
    setEditingPrinterId(printer.id);
    setGatewayProvisioningSecret(null);
    setSetupFormOpen(true);
    setManagedProfilesDialogOpen(true);
    setNetworkPrinterForm({
      connectionType: printer.connectionType,
      name: printer.name || "",
      vendor: printer.vendor || "",
      model: printer.model || "",
      ipAddress: printer.ipAddress || "",
      host: printer.host || "",
      port: String(printer.port || (printer.connectionType === "NETWORK_IPP" ? 631 : 9100)),
      resourcePath: printer.resourcePath || "/ipp/print",
      tlsEnabled: printer.tlsEnabled !== false,
      printerUri: printer.printerUri || "",
      deliveryMode: printer.deliveryMode || "DIRECT",
      rotateGatewaySecret: false,
      commandLanguage: printer.commandLanguage || "AUTO",
    });
  };

  const runPrinterTest = async (printerId: string) => {
    setTestingPrinterId(printerId);
    try {
      const response = await apiClient.testRegisteredPrinter(printerId);
      if (!response.success) {
        toast({
          title: "Printer check failed",
          description: sanitizePrinterUiError(response.error, "Could not confirm this printer right now."),
          variant: "destructive",
        });
        return;
      }
      const detail =
        (response.data as any)?.registryStatus?.detail ||
        (response.data as any)?.registryStatus?.summary ||
        "Printer validation completed.";
      toast({
        title: "Printer check complete",
        description: detail,
      });
      await loadRegisteredPrinters();
    } finally {
      setTestingPrinterId(null);
    }
  };

  const removeNetworkPrinter = async (printer: RegisteredPrinterRow) => {
    if (printer.connectionType === "LOCAL_AGENT") return;
    const confirmed = window.confirm(
      `Remove ${printer.name}? This deletes the saved printer profile and frees its registered endpoint for a new connection.`
    );
    if (!confirmed) return;

    setDeletingPrinterId(printer.id);
    try {
      const response = await apiClient.deleteRegisteredPrinter(printer.id);
      if (!response.success) {
        toast({
          title: "Could not remove printer",
          description: sanitizePrinterUiError(response.error, "This printer profile could not be removed."),
          variant: "destructive",
        });
        return;
      }

      toast({
        title: "Printer removed",
        description: `${printer.name} was removed. Its saved endpoint can now be reused.`,
      });
      if (editingPrinterId === printer.id) resetNetworkPrinterForm();
      await loadDiagnostics();
    } finally {
      setDeletingPrinterId(null);
    }
  };

  const managedDialogTitle = editingPrinterId
    ? "Update managed printer profile"
    : setupFormOpen
      ? `Create ${getManagedSetupTypeLabel(networkPrinterForm).toLowerCase()}`
      : "Managed printer profiles";

  const renderRegisteredPrinterCard = (printer: RegisteredPrinterRow) => {
    const isManagedPrinter = printer.connectionType !== "LOCAL_AGENT";

    return (
      <div
        key={printer.id}
        className={`rounded-xl border p-4 transition ${
          isManagedPrinter ? "cursor-pointer hover:border-emerald-200 hover:bg-emerald-50/40" : ""
        }`}
        onClick={isManagedPrinter ? () => openManagedProfilesDialog({ printer }) : undefined}
        role={isManagedPrinter ? "button" : undefined}
        tabIndex={isManagedPrinter ? 0 : undefined}
        onKeyDown={
          isManagedPrinter
            ? (event) => {
                if (event.key === "Enter" || event.key === " ") {
                  event.preventDefault();
                  openManagedProfilesDialog({ printer });
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
            <Badge variant={printer.isActive ? "default" : "secondary"}>
              {printer.isActive ? "Active" : "Inactive"}
            </Badge>
            {printer.registryStatus?.summary && <Badge variant="secondary">{printer.registryStatus.summary}</Badge>}
          </div>
        </div>
        <div className="mt-3 text-xs text-muted-foreground">
          {sanitizePrinterUiError(
            printer.registryStatus?.detail || printer.lastValidationMessage,
            "No readiness note has been recorded yet."
          )}
        </div>
        {printer.connectionType === "NETWORK_IPP" && printer.deliveryMode === "SITE_GATEWAY" && (
          <div className="mt-2 text-[11px] text-muted-foreground">
            Site connector mode keeps this printer on a private network while MSCQR dispatches jobs securely.
          </div>
        )}
        <div className="mt-3 flex flex-wrap justify-end gap-2">
          <Button
            variant="outline"
            size="sm"
            disabled={testingPrinterId === printer.id}
            onClick={(event) => {
              event.stopPropagation();
              void runPrinterTest(printer.id);
            }}
          >
            {testingPrinterId === printer.id ? "Checking..." : "Check"}
          </Button>
          {isManagedPrinter && (
            <Button
              variant="outline"
              size="sm"
              onClick={(event) => {
                event.stopPropagation();
                openManagedProfilesDialog({ printer });
              }}
            >
              Edit
            </Button>
          )}
          {isManagedPrinter && (
            <Button
              variant="outline"
              size="sm"
              disabled={deletingPrinterId === printer.id}
              onClick={(event) => {
                event.stopPropagation();
                void removeNetworkPrinter(printer);
              }}
            >
              <Trash2 className="mr-1 h-4 w-4" />
              {deletingPrinterId === printer.id ? "Removing..." : "Remove"}
            </Button>
          )}
        </div>
      </div>
    );
  };

  const renderManagedPrinterSetup = () => (
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
          <Label className="text-xs">
            {networkPrinterForm.connectionType === "NETWORK_IPP" ? "Host or printer name" : "IP address or host"}
          </Label>
          {networkPrinterForm.connectionType === "NETWORK_IPP" ? (
            <Input
              value={networkPrinterForm.host}
              onChange={(e) => setNetworkPrinterForm((prev) => ({ ...prev, host: e.target.value }))}
              placeholder="canon-office.local"
            />
          ) : (
            <Input
              value={networkPrinterForm.ipAddress}
              onChange={(e) => setNetworkPrinterForm((prev) => ({ ...prev, ipAddress: e.target.value }))}
              placeholder="192.168.1.50 or printer-lan-01"
            />
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
              onValueChange={(value) =>
                setNetworkPrinterForm((prev) => ({ ...prev, commandLanguage: value as RegisteredPrinterRow["commandLanguage"] }))
              }
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
          {!networkPrinterLanguageSupported && (
            <div className="rounded-xl border border-red-200 bg-red-50 p-3 text-xs text-red-800">
              This profile currently uses <strong>{networkPrinterForm.commandLanguage}</strong>, which is not allowed for
              factory label printer dispatch. Change it to ZPL, TSPL, EPL, or CPCL before saving or checking.
            </div>
          )}
        </>
      ) : (
        <>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="space-y-1">
              <Label className="text-xs">Resource path</Label>
              <Input
                value={networkPrinterForm.resourcePath}
                onChange={(e) => setNetworkPrinterForm((prev) => ({ ...prev, resourcePath: e.target.value }))}
                placeholder="/ipp/print"
              />
            </div>
            <div className="space-y-1">
              <Label className="text-xs">Printer URI (optional)</Label>
              <Input
                value={networkPrinterForm.printerUri}
                onChange={(e) => setNetworkPrinterForm((prev) => ({ ...prev, printerUri: e.target.value }))}
                placeholder="ipps://canon.local:631/ipp/print"
              />
            </div>
          </div>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="space-y-1">
              <Label className="text-xs">Delivery mode</Label>
              <Select
                value={networkPrinterForm.deliveryMode}
                onValueChange={(value) =>
                  setNetworkPrinterForm((prev) => ({ ...prev, deliveryMode: value as NonNullable<RegisteredPrinterRow["deliveryMode"]> }))
                }
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
                <input
                  type="checkbox"
                  checked={Boolean(networkPrinterForm.tlsEnabled)}
                  onChange={(e) => setNetworkPrinterForm((prev) => ({ ...prev, tlsEnabled: e.target.checked }))}
                />
                Prefer TLS / IPPS
              </label>
            </div>
          </div>
          {networkPrinterForm.deliveryMode === "SITE_GATEWAY" && (
            <div className="space-y-2 rounded-xl border border-amber-200 bg-amber-50 p-3 text-xs text-amber-900">
              <div>Site connector mode keeps the printer on a private network and uses secure outbound job pickup.</div>
              {editingPrinterId && (
                <label className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    checked={Boolean(networkPrinterForm.rotateGatewaySecret)}
                    onChange={(e) => setNetworkPrinterForm((prev) => ({ ...prev, rotateGatewaySecret: e.target.checked }))}
                  />
                  Rotate connector secret on save
                </label>
              )}
              {gatewayProvisioningSecret && (
                <div className="space-y-2 rounded-lg border border-amber-300 bg-white/70 p-3 text-[11px]">
                  <div className="font-medium text-foreground">One-time connector bootstrap secret</div>
                  <div className="break-all font-mono text-foreground">{gatewayProvisioningSecret}</div>
                  <div>Provision this secret into the workstation connector once. It will not be shown again.</div>
                </div>
              )}
            </div>
          )}
        </>
      )}
      <div className="flex flex-wrap justify-end gap-2">
        <Button variant="outline" onClick={resetNetworkPrinterForm}>
          {editingPrinterId ? "Cancel edit" : "Close setup"}
        </Button>
        <Button
          onClick={() => void saveNetworkPrinter()}
          disabled={savingNetworkPrinter || (networkPrinterForm.connectionType === "NETWORK_DIRECT" && !networkPrinterLanguageSupported)}
        >
          {savingNetworkPrinter ? "Saving..." : editingPrinterId ? "Update setup" : "Save setup"}
        </Button>
      </div>
      <div className="text-xs text-muted-foreground">
        Factory label printers use approved saved LAN targets only. Office / AirPrint printers use standards-based IPP/IPPS and can run directly or through a site connector.
      </div>
    </>
  );

  return (
    <DashboardLayout>
      <div className="space-y-6">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h1 className="text-3xl font-bold">Printer Setup & Support</h1>
            <p className="text-muted-foreground">
              Review printer readiness, guided setup steps, and support-safe status summaries for this workstation.
            </p>
          </div>

          <div className="flex flex-wrap gap-2">
            <Button variant="outline" onClick={() => navigate("/connector-download")}>
              Install Connector
            </Button>
            <Button variant="outline" onClick={() => void loadDiagnostics()} disabled={loading} className="gap-2">
              <RefreshCw className="h-4 w-4" />
              {loading ? "Refreshing..." : "Refresh status"}
            </Button>
            <Button variant="outline" onClick={copySupportSummary} className="gap-2">
              <Copy className="h-4 w-4" />
              Copy support summary
            </Button>
            <Button variant="outline" onClick={() => navigate("/batches")}>
              Open batches
            </Button>
            <Button variant="outline" onClick={() => navigate(contextualHelpRoute)}>
              Open help
            </Button>
          </div>
        </div>

        <Card className={statusClasses}>
          <CardContent className="pt-6">
            <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
              <div className="space-y-2">
                <div className="flex flex-wrap items-center gap-2">
                  <div className="text-lg font-semibold">{effectiveSummary.title}</div>
                  <Badge variant={effectiveSummary.tone === "danger" ? "destructive" : "secondary"}>{effectiveSummary.badgeLabel}</Badge>
                </div>
                <p className="text-sm leading-6">{effectiveSummary.summary}</p>
                <p className="text-xs leading-5 opacity-90">{effectiveSummary.detail}</p>
              </div>

              <div className="grid gap-2 text-xs lg:min-w-[16rem]">
                <div className="rounded-xl border border-white/60 bg-white/60 px-3 py-2">
                  <div className="font-medium opacity-70">Agent check</div>
                  <div className="mt-1 font-semibold">{checkedLabel}</div>
                </div>
                <div className="rounded-xl border border-white/60 bg-white/60 px-3 py-2">
                  <div className="font-medium opacity-70">Selected printer</div>
                  <div className="mt-1 font-semibold">{effectiveSummary.selectedPrinter?.printerName || remoteStatus?.selectedPrinterName || "—"}</div>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>

        <div className="grid gap-4 lg:grid-cols-3">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base">
                <Activity className="h-4 w-4" />
                Workstation connector
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3 text-sm">
              <div className="flex items-center justify-between">
                <span className="text-muted-foreground">Reachable</span>
                <Badge variant={localAgent.reachable ? "default" : "destructive"}>{localAgent.reachable ? "Yes" : "No"}</Badge>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-muted-foreground">Connected</span>
                <Badge variant={localAgent.connected ? "default" : "secondary"}>{localAgent.connected ? "Yes" : "No"}</Badge>
              </div>
              <div>
                <div className="text-muted-foreground">Status note</div>
                <div className="mt-1 break-words text-xs">
                  {sanitizePrinterUiError(localAgent.error, localAgent.reachable ? "Connector is available." : "Connector is currently unavailable.")}
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base">
                <ShieldAlert className="h-4 w-4" />
                Cloud connection
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3 text-sm">
              <div className="flex items-center justify-between">
                <span className="text-muted-foreground">Status</span>
                <Badge variant={remoteStatus?.connected && remoteStatus?.eligibleForPrinting ? "default" : "secondary"}>
                  {remoteStatus?.connected && remoteStatus?.eligibleForPrinting ? "Ready" : "Needs attention"}
                </Badge>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-muted-foreground">Last update</span>
                <Badge variant="secondary">{remoteStatus?.lastHeartbeatAt ? formatDistanceToNow(new Date(remoteStatus.lastHeartbeatAt), { addSuffix: true }) : "Unavailable"}</Badge>
              </div>
              <div>
                <div className="text-muted-foreground">What to know</div>
                <div className="mt-1 break-words text-xs">
                  {sanitizePrinterUiError(remoteStatus?.error || remoteStatus?.trustReason, "MSCQR will update this status automatically when the connection is ready.")}
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base">
                <Wifi className="h-4 w-4" />
                Next steps
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 text-sm">
              {effectiveSummary.nextSteps.map((step) => (
                <div key={step} className="rounded-lg border bg-muted/40 px-3 py-2">
                  {step}
                </div>
              ))}
            </CardContent>
          </Card>
        </div>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Workstation requirements</CardTitle>
          </CardHeader>
          <CardContent className="grid gap-4 lg:grid-cols-2">
            <div className="space-y-3 text-sm text-muted-foreground">
              <div className="rounded-xl border bg-muted/30 p-4">
                <div className="font-medium text-foreground">What must be ready on this workstation</div>
                <ul className="mt-3 list-disc space-y-2 pl-5">
                  <li>The MSCQR Connector must be installed once on the workstation.</li>
                  <li>The operating system must already see the printer in its printer list.</li>
                  <li>The printer driver or spooler path must be working before the browser can show a ready state.</li>
                  <li>The connector should auto-start at login and stay in the background.</li>
                  <li>Use MDM or your IT rollout process for fleet installs. End users should never need terminal commands to print.</li>
                </ul>
              </div>
              <div className="rounded-xl border bg-muted/30 p-4">
                <div className="font-medium text-foreground">Quick readiness check</div>
                <ol className="mt-3 list-decimal space-y-2 pl-5">
                  <li>Confirm the printer is visible in the operating system first.</li>
                  <li>Use <strong>Install Connector</strong> if this computer does not already have the MSCQR Connector.</li>
                  <li>Return here and use <strong>Refresh status</strong>.</li>
                  <li>If the printer still does not appear, restart the connector or printer.</li>
                  <li>If the issue continues, copy the support summary and send it to support.</li>
                </ol>
                <div className="mt-4">
                  <Button variant="outline" size="sm" onClick={() => navigate("/connector-download")}>
                    Install Connector
                  </Button>
                </div>
              </div>
              <button
                type="button"
                onClick={() => openManagedProfilesDialog()}
                className="w-full rounded-xl border bg-muted/30 p-4 text-left transition hover:border-emerald-200 hover:bg-emerald-50/50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500"
              >
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <div className="font-medium text-foreground">Saved managed printer</div>
                    <div className="mt-3 text-sm leading-6 text-muted-foreground">
                      {preferredManagedNetworkPrinter ? (
                        <>
                          Registered profile: <span className="font-medium text-foreground">{preferredManagedNetworkPrinter.name}</span>
                          <br />
                          Type: <span className="font-medium text-foreground">{getPrinterDispatchLabel(preferredManagedNetworkPrinter)}</span>
                        </>
                      ) : (
                        "Open managed printer profiles to create factory LAN or office IPP printer routes."
                      )}
                    </div>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <Badge variant="secondary">{managedNetworkPrinters.length} saved</Badge>
                    <Badge variant={managedPrinterReadyCount > 0 ? "default" : "secondary"}>
                      {managedPrinterReadyCount > 0 ? `${managedPrinterReadyCount} ready` : "No ready route"}
                    </Badge>
                  </div>
                </div>
                <div className="mt-3 text-xs text-muted-foreground">
                  Saved managed printers do not depend on the workstation printer list. Click here to create, update, delete, or re-check those profiles in one dialog.
                </div>
              </button>
            </div>

            <div className="space-y-3 text-sm text-muted-foreground">
              <div className="rounded-xl border bg-muted/30 p-4">
                <div className="font-medium text-foreground">How to read the result</div>
                <ul className="mt-3 list-disc space-y-2 pl-5">
                  <li><strong>Ready</strong>: the printer connection is good to use.</li>
                  <li><strong>Preparing</strong>: MSCQR is still finishing setup for this printer.</li>
                  <li><strong>Offline</strong>: the connector, printer, or site connector is not reachable right now.</li>
                  <li><strong>Needs attention</strong>: the printer setup needs an update before printing.</li>
                </ul>
              </div>
              <div className="rounded-xl border bg-muted/30 p-4">
                <div className="font-medium text-foreground">Escalation path</div>
                <p className="mt-3 leading-6">
                  Use <strong>Copy support summary</strong> from this page and attach it to a support ticket. The copied text is redacted for business-safe support handoff.
                </p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Printer compatibility matrix</CardTitle>
          </CardHeader>
          <CardContent className="grid gap-4 lg:grid-cols-3">
            <div className="rounded-xl border bg-muted/20 p-4 text-sm text-muted-foreground">
              <div className="font-semibold text-foreground">LOCAL_AGENT</div>
              <p className="mt-2 leading-6">
                Best for USB-connected printers, Wi-Fi printers, home and office devices, and industrial printers that
                depend on the workstation driver or spooler path.
              </p>
              <ul className="mt-3 list-disc space-y-2 pl-5 text-xs">
                <li>Supports operating-system managed printers discovered by the local agent.</li>
                <li>Recommended when the printer is installed on Windows, macOS, or Linux.</li>
                <li>Use this path for SBPL, ESC/POS, or other device-specific drivers.</li>
              </ul>
            </div>
            <div className="rounded-xl border bg-muted/20 p-4 text-sm text-muted-foreground">
              <div className="font-semibold text-foreground">NETWORK_DIRECT</div>
              <p className="mt-2 leading-6">
                Best for controlled factory LAN printers with a stable IP address and approved raw TCP access.
              </p>
              <ul className="mt-3 list-disc space-y-2 pl-5 text-xs">
                <li>Current direct-dispatch languages: ZPL, TSPL, EPL, and CPCL.</li>
                <li>Printer must be registered here first. Freeform IP/port entry during print is not allowed.</li>
                <li>Use <strong>Check</strong> after registration to confirm connectivity and language readiness.</li>
              </ul>
              <div className="mt-4 flex flex-wrap gap-2">
                <Button variant="outline" size="sm" onClick={() => openManagedProfilesDialog({ createType: "NETWORK_DIRECT" })}>
                  Register factory printer
                </Button>
                <Button variant="ghost" size="sm" onClick={() => openManagedProfilesDialog()}>
                  Manage saved routes
                </Button>
              </div>
            </div>
            <div className="rounded-xl border bg-muted/20 p-4 text-sm text-muted-foreground">
              <div className="font-semibold text-foreground">NETWORK_IPP</div>
              <p className="mt-2 leading-6">
                Best for AirPrint and IPP Everywhere office printers that accept standards-based PDF jobs over IPP/IPPS.
              </p>
              <ul className="mt-3 list-disc space-y-2 pl-5 text-xs">
                <li>Use backend-direct when the application server can safely reach the printer URI.</li>
                <li>Use site-gateway mode when the printer stays on a private manufacturer LAN.</li>
                <li>Prefer TLS and a stable printer URI whenever the device supports it.</li>
              </ul>
              <div className="mt-4 flex flex-wrap gap-2">
                <Button variant="outline" size="sm" onClick={() => openManagedProfilesDialog({ createType: "NETWORK_IPP", deliveryMode: "DIRECT" })}>
                  Add backend-direct
                </Button>
                <Button variant="outline" size="sm" onClick={() => openManagedProfilesDialog({ createType: "NETWORK_IPP", deliveryMode: "SITE_GATEWAY" })}>
                  Add site gateway
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <CardTitle className="text-base">Managed printer controls</CardTitle>
              <div className="mt-1 text-sm text-muted-foreground">
                `NETWORK_DIRECT` and `NETWORK_IPP` already dispatch through the backend. Use this control surface to manage the saved profiles, validate them, and keep their live readiness visible.
              </div>
            </div>
            <Button variant="outline" onClick={() => openManagedProfilesDialog()}>
              Open managed profiles
            </Button>
          </CardHeader>
          <CardContent className="grid gap-4 lg:grid-cols-[1fr_1.15fr]">
            <div className="rounded-2xl border bg-muted/20 p-4">
              <div className="flex flex-wrap items-center gap-2">
                <Badge variant="secondary">{managedNetworkPrinters.length} active profiles</Badge>
                <Badge variant={managedPrinterReadyCount > 0 ? "default" : "secondary"}>{managedPrinterReadyCount} ready</Badge>
                <Badge variant={managedPrinterAttentionCount > 0 ? "secondary" : "outline"}>{managedPrinterAttentionCount} needs review</Badge>
              </div>
              <div className="mt-4 text-sm leading-6 text-muted-foreground">
                {preferredManagedSummary
                  ? preferredManagedSummary.summary
                  : "No managed network route is saved yet. Add one here and MSCQR will keep polling the saved status every few seconds."}
              </div>
              <div className="mt-3 text-xs text-muted-foreground">
                Live profile status refreshes automatically every 6 seconds on this page. Use Check after changes to confirm the route end to end before printing from batches.
              </div>
            </div>

            <div className="grid gap-3 sm:grid-cols-3">
              <button
                type="button"
                onClick={() => openManagedProfilesDialog({ createType: "NETWORK_DIRECT" })}
                className="rounded-2xl border bg-background p-4 text-left transition hover:border-emerald-200 hover:bg-emerald-50/40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500"
              >
                <div className="text-sm font-semibold text-foreground">Factory label printer</div>
                <div className="mt-2 text-xs leading-5 text-muted-foreground">Save a ZPL, TSPL, EPL, or CPCL network route and validate it before batch printing.</div>
              </button>
              <button
                type="button"
                onClick={() => openManagedProfilesDialog({ createType: "NETWORK_IPP", deliveryMode: "DIRECT" })}
                className="rounded-2xl border bg-background p-4 text-left transition hover:border-emerald-200 hover:bg-emerald-50/40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500"
              >
                <div className="text-sm font-semibold text-foreground">Office / AirPrint printer</div>
                <div className="mt-2 text-xs leading-5 text-muted-foreground">Register a backend-direct IPP or IPPS endpoint for PDF-capable office printers.</div>
              </button>
              <button
                type="button"
                onClick={() => openManagedProfilesDialog({ createType: "NETWORK_IPP", deliveryMode: "SITE_GATEWAY" })}
                className="rounded-2xl border bg-background p-4 text-left transition hover:border-emerald-200 hover:bg-emerald-50/40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500"
              >
                <div className="text-sm font-semibold text-foreground">Private site gateway</div>
                <div className="mt-2 text-xs leading-5 text-muted-foreground">Keep the printer on a private LAN and let the site connector pull jobs securely.</div>
              </button>
            </div>
          </CardContent>
        </Card>

        <Dialog
          open={managedProfilesDialogOpen}
          onOpenChange={(open) => {
            if (!open) {
              closeManagedProfilesDialog();
              return;
            }
            setManagedProfilesDialogOpen(true);
          }}
        >
          <DialogContent className="max-h-[88vh] overflow-y-auto sm:max-w-[1080px]">
            <DialogHeader>
              <DialogTitle>{managedDialogTitle}</DialogTitle>
              <DialogDescription>
                Create, update, delete, and validate `NETWORK_DIRECT` and `NETWORK_IPP` profiles from one workspace. These managed routes are the end-to-end controls for backend and site-gateway printing.
              </DialogDescription>
            </DialogHeader>

            <div className="grid gap-4 lg:grid-cols-[1.15fr_0.85fr]">
              <div className="space-y-4">
                <div className="flex flex-wrap gap-2">
                  <Badge variant="secondary">Live checks every 6 seconds</Badge>
                  <Badge variant={managedPrinterReadyCount > 0 ? "default" : "secondary"}>{managedPrinterReadyCount} ready</Badge>
                  <Badge variant="secondary">{managedNetworkPrinters.length} saved routes</Badge>
                </div>

                <div className="grid gap-3 sm:grid-cols-3">
                  <button
                    type="button"
                    onClick={() => openManagedProfilesDialog({ createType: "NETWORK_DIRECT" })}
                    className="rounded-2xl border bg-muted/20 p-4 text-left transition hover:border-emerald-200 hover:bg-emerald-50/40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500"
                  >
                    <div className="text-sm font-semibold text-foreground">New factory route</div>
                    <div className="mt-2 text-xs leading-5 text-muted-foreground">Save a raw TCP endpoint for ZPL, TSPL, EPL, or CPCL dispatch.</div>
                  </button>
                  <button
                    type="button"
                    onClick={() => openManagedProfilesDialog({ createType: "NETWORK_IPP", deliveryMode: "DIRECT" })}
                    className="rounded-2xl border bg-muted/20 p-4 text-left transition hover:border-emerald-200 hover:bg-emerald-50/40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500"
                  >
                    <div className="text-sm font-semibold text-foreground">New IPP route</div>
                    <div className="mt-2 text-xs leading-5 text-muted-foreground">Save a backend-direct IPP or IPPS endpoint for an office printer.</div>
                  </button>
                  <button
                    type="button"
                    onClick={() => openManagedProfilesDialog({ createType: "NETWORK_IPP", deliveryMode: "SITE_GATEWAY" })}
                    className="rounded-2xl border bg-muted/20 p-4 text-left transition hover:border-emerald-200 hover:bg-emerald-50/40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500"
                  >
                    <div className="text-sm font-semibold text-foreground">New gateway route</div>
                    <div className="mt-2 text-xs leading-5 text-muted-foreground">Keep the printer private and validate it through the site connector flow.</div>
                  </button>
                </div>

                <div className="rounded-2xl border bg-background p-4">
                  <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                    <div>
                      <div className="text-sm font-semibold text-foreground">Registered printer profiles</div>
                      <div className="text-xs text-muted-foreground">Click any managed profile to edit it, then use Check to confirm readiness.</div>
                    </div>
                    <Button variant="outline" size="sm" onClick={() => void loadDiagnostics()} disabled={loading}>
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
                      registeredPrinters.map((printer) => renderRegisteredPrinterCard(printer))
                    )}
                  </div>
                </div>
              </div>

              <div className="space-y-4">
                {!setupFormOpen && !editingPrinterId ? (
                  <div className="rounded-2xl border border-dashed bg-muted/20 p-5 text-sm text-muted-foreground">
                    <div className="font-medium text-foreground">Select a managed printer action</div>
                    <div className="mt-2 leading-6">
                      Pick a quick action to create a new network route, or click an existing managed profile to update, delete, or re-check it.
                    </div>
                    <div className="mt-4 text-xs leading-5">
                      `NETWORK_DIRECT` and `NETWORK_IPP` are already wired end to end in MSCQR. This dialog is the control surface for those routes.
                    </div>
                  </div>
                ) : (
                  <div className="rounded-2xl border bg-background p-4">
                    {renderManagedPrinterSetup()}
                  </div>
                )}
              </div>
            </div>
          </DialogContent>
        </Dialog>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Wrench className="h-4 w-4" />
              Discovered printers
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
              <div className="space-y-2">
                <div className="text-sm text-muted-foreground">Active printer selection</div>
                <Select value={selectedPrinterId || "__none__"} onValueChange={(value) => setSelectedPrinterId(value === "__none__" ? "" : value)}>
                  <SelectTrigger className="sm:w-[24rem]">
                    <SelectValue placeholder="Select printer" />
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

              <Button variant="outline" disabled={!selectedPrinterId || detectedPrinters.length === 0} onClick={switchSelectedPrinter}>
                Switch active printer
              </Button>
            </div>

            {detectedPrinters.length === 0 ? (
              <div className="rounded-xl border border-dashed bg-muted/20 p-4 text-sm text-muted-foreground">
                {preferredManagedNetworkPrinter ? (
                  <>
                    No local-agent printers were reported. The registered network printer
                    <span className="mx-1 font-medium text-foreground">{preferredManagedNetworkPrinter.name}</span>
                    can still be used from batch operations once it validates successfully.
                  </>
                ) : (
                  "No workstation printers were reported by the connector."
                )}
              </div>
            ) : (
              <div className="grid gap-3 md:grid-cols-2">
                {detectedPrinters.map((printer) => {
                  const active = printer.printerId === selectedPrinterId;
                  return (
                    <div key={printer.printerId} className="rounded-xl border p-4">
                      <div className="flex items-start justify-between gap-2">
                        <div>
                          <div className="font-semibold">{printer.printerName}</div>
                          <div className="mt-1 text-xs text-muted-foreground">
                            {printer.model || "Unknown model"}
                            {printer.connection ? ` · ${printer.connection}` : ""}
                          </div>
                        </div>
                        <div className="flex flex-wrap gap-2">
                          {active && <Badge variant="default">Selected</Badge>}
                          {printer.isDefault && <Badge variant="secondary">Default</Badge>}
                          {printer.online === false ? <Badge variant="destructive">Offline</Badge> : <Badge variant="secondary">Online</Badge>}
                        </div>
                      </div>
                      <div className="mt-3 text-xs text-muted-foreground">
                        {printer.online === false
                          ? "This printer is currently unavailable on the workstation."
                          : "Available on this workstation for printer selection and print jobs."}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </DashboardLayout>
  );
}
