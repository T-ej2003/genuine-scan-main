import React, { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { formatDistanceToNow } from "date-fns";
import { Activity, Copy, RefreshCw, ShieldAlert, Wifi, Wrench } from "lucide-react";

import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useAuth } from "@/contexts/AuthContext";
import { getContextualHelpRoute } from "@/help/contextual-help";
import { useToast } from "@/hooks/use-toast";
import apiClient from "@/lib/api-client";
import {
  deriveManagedPrinterAutoDetect,
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
import {
  buildEmptyNetworkPrinterForm,
  getManagedSetupTypeLabel,
  isSupportedNetworkDirectLanguage,
  NETWORK_DIRECT_SUPPORTED_LANGUAGE_LABEL,
  type RegisteredPrinterRow,
} from "@/features/printing/advanced-types";
import { ManagedPrinterRoutesDialog } from "@/features/printing/components/ManagedPrinterRoutesDialog";

const EMPTY_LOCAL_AGENT: LocalPrinterAgentSnapshot = {
  reachable: false,
  connected: false,
  error: "Workstation connector has not been checked yet.",
  checkedAt: null,
};

export default function PrinterDiagnostics() {
  const { user } = useAuth();
  const { toast } = useToast();
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const contextualHelpRoute = getContextualHelpRoute("/printer-diagnostics", user?.role);
  const rawRole = String(user?.rawRole || "").trim().toUpperCase();
  const isManufacturerUser = user?.role === "manufacturer" && rawRole !== "MANUFACTURER_USER";
  const isGlobalPrinterAdmin = user?.role === "super_admin";
  const canInspectManagedProfiles = isManufacturerUser || isGlobalPrinterAdmin;

  const [loading, setLoading] = useState(false);
  const [localAgent, setLocalAgent] = useState<LocalPrinterAgentSnapshot>(EMPTY_LOCAL_AGENT);
  const [remoteStatus, setRemoteStatus] = useState<PrinterConnectionStatusLike | null>(null);
  const [detectedPrinters, setDetectedPrinters] = useState<PrinterInventoryRow[]>([]);
  const [selectedPrinterId, setSelectedPrinterId] = useState("");
  const [registeredPrinters, setRegisteredPrinters] = useState<RegisteredPrinterRow[]>([]);
  const [savingNetworkPrinter, setSavingNetworkPrinter] = useState(false);
  const [testingPrinterId, setTestingPrinterId] = useState<string | null>(null);
  const [discoveringPrinterId, setDiscoveringPrinterId] = useState<string | null>(null);
  const [deletingPrinterId, setDeletingPrinterId] = useState<string | null>(null);
  const [editingPrinterId, setEditingPrinterId] = useState<string | null>(null);
  const [networkPrinterForm, setNetworkPrinterForm] = useState(buildEmptyNetworkPrinterForm);
  const [gatewayProvisioningSecret, setGatewayProvisioningSecret] = useState<string | null>(null);
  const [setupFormOpen, setSetupFormOpen] = useState(false);
  const [managedProfilesDialogOpen, setManagedProfilesDialogOpen] = useState(false);
  const configuredBackendUrlRef = useRef("");

  const networkPrinterLanguageSupported = isSupportedNetworkDirectLanguage(networkPrinterForm.commandLanguage);

  const loadRegisteredPrinters = async () => {
    if (!canInspectManagedProfiles) {
      setRegisteredPrinters([]);
      return;
    }
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
      if (!isManufacturerUser) {
        setLocalAgent({
          ...EMPTY_LOCAL_AGENT,
          error: "Workstation connector diagnostics are shown only on manufacturer workstations.",
          checkedAt: new Date().toISOString(),
        });
        setDetectedPrinters([]);
        setRemoteStatus(null);
        await loadRegisteredPrinters();
        return;
      }

      const local = await apiClient.getLocalPrintAgentStatus();
      const browserBackendUrl = window.location.origin;
      if (
        local.success &&
        configuredBackendUrlRef.current !== browserBackendUrl &&
        typeof apiClient.configureLocalPrintAgentBackend === "function"
      ) {
        const backendConfiguration = await apiClient.configureLocalPrintAgentBackend(browserBackendUrl);
        if (!backendConfiguration.success) {
          console.warn("Local print agent backend configuration failed:", backendConfiguration.error);
        } else {
          configuredBackendUrlRef.current = browserBackendUrl;
        }
      }
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

      if (isManufacturerUser) {
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
      }
      await loadRegisteredPrinters();
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

  const autoDetectedManagedPrinters = useMemo(() => {
    const rows = detectedPrinters.map((printer) => ({
      printer,
      suggestion: deriveManagedPrinterAutoDetect(printer),
    }));

    const routeRank = (value: "LOCAL_ONLY" | "NETWORK_DIRECT" | "NETWORK_IPP") =>
      value === "NETWORK_DIRECT" ? 0 : value === "NETWORK_IPP" ? 1 : 2;
    const readinessRank = (value: "READY" | "NEEDS_DETAILS") => (value === "READY" ? 0 : 1);

    return rows.sort((left, right) => {
      const readinessDelta = readinessRank(left.suggestion.readiness) - readinessRank(right.suggestion.readiness);
      if (readinessDelta !== 0) return readinessDelta;
      const routeDelta = routeRank(left.suggestion.routeType) - routeRank(right.suggestion.routeType);
      if (routeDelta !== 0) return routeDelta;
      return left.printer.printerName.localeCompare(right.printer.printerName);
    });
  }, [detectedPrinters]);

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

  const recommendedAction = useMemo(() => {
    if (isGlobalPrinterAdmin) {
      return {
        title: "Review printer certification",
        description: "Open the managed profiles workspace to inspect capability discovery, mismatches, and certification readiness.",
        label: "Open network routes",
        run: () => openManagedProfilesDialog(),
      };
    }

    if (managedPrinterAttentionCount > 0) {
      return {
        title: "Review saved network routes",
        description: "A saved office or factory printer route needs attention before batch printing is reliable.",
        label: "Open network routes",
        run: () => openManagedProfilesDialog(),
      };
    }

    if (effectiveSummary.state === "agent_unreachable") {
      return {
        title: "Install the connector on this computer",
        description: "This workstation still needs the MSCQR Connector before local printer printing can work.",
        label: "Install Connector",
        run: () => navigate("/connector-download"),
      };
    }

    if (effectiveSummary.state === "no_printers_detected" || effectiveSummary.state === "selection_required") {
      return {
        title: "Refresh the printer list on this workstation",
        description: "Make sure the operating system already sees the printer, then refresh MSCQR.",
        label: "Refresh status",
        run: () => void loadDiagnostics(),
      };
    }

    if (
      effectiveSummary.state === "heartbeat_stale" ||
      effectiveSummary.state === "server_sync_pending" ||
      effectiveSummary.state === "trust_blocked" ||
      effectiveSummary.state === "printer_offline"
    ) {
      return {
        title: "Re-check the connection",
        description: "MSCQR needs a fresh connector heartbeat before it can trust this printer again.",
        label: "Refresh status",
        run: () => void loadDiagnostics(),
      };
    }

    return {
      title: "Continue to printing",
      description: "This setup is ready enough for the next batch step.",
      label: "Open batches",
      run: () => navigate("/batches"),
    };
  }, [effectiveSummary.state, isGlobalPrinterAdmin, managedPrinterAttentionCount, navigate]);

  useEffect(() => {
    if (searchParams.get("managedProfiles") !== "open") return;

    openManagedProfilesDialog();

    const nextParams = new URLSearchParams(searchParams);
    nextParams.delete("managedProfiles");
    setSearchParams(nextParams, { replace: true });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchParams, setSearchParams]);

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
        description: `Choose a certified raw TCP language. Supported today: ${NETWORK_DIRECT_SUPPORTED_LANGUAGE_LABEL}. Use the connector-managed or IPP path for other printers.`,
        variant: "destructive",
      });
      return null;
    }

    setSavingNetworkPrinter(true);
    try {
      const hasActiveDefault = registeredPrinters.some((printer) => printer.isActive && printer.isDefault && printer.id !== params?.printerId);
      const payload = isNetworkDirect
        ? {
            name,
            vendor: source.vendor.trim() || undefined,
            model: source.model.trim() || undefined,
            licenseeId: effectiveLicenseeId,
            connectionType: "NETWORK_DIRECT" as const,
            ipAddress,
            port,
            commandLanguage: source.commandLanguage as
              | "ZPL"
              | "TSPL"
              | "SBPL"
              | "EPL"
              | "DPL"
              | "HONEYWELL_DP"
              | "HONEYWELL_FINGERPRINT"
              | "IPL"
              | "ZSIM"
              | "CPCL",
            isDefault: params?.printerId ? undefined : !hasActiveDefault,
          }
        : {
            name,
            vendor: source.vendor.trim() || undefined,
            model: source.model.trim() || undefined,
            licenseeId: effectiveLicenseeId,
            connectionType: "NETWORK_IPP" as const,
            host: host || undefined,
            port,
            resourcePath: source.resourcePath.trim() || "/ipp/print",
            tlsEnabled: Boolean(source.tlsEnabled),
            printerUri: printerUri || undefined,
            deliveryMode: source.deliveryMode,
            rotateGatewaySecret: Boolean(source.rotateGatewaySecret),
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

      if (validated && savedPrinterId) {
        const certified = await runPrinterDiscovery(savedPrinterId);
        detail = certified
          ? "Printer profile saved, validated, and certified for controlled production dispatch."
          : "Printer profile saved and validated, but discovery flagged it for review before production print.";
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

  const useAutoDetectedPrinter = (printer: PrinterInventoryRow) => {
    const suggestion = deriveManagedPrinterAutoDetect(printer);
    if (suggestion.routeType === "LOCAL_ONLY") {
      toast({
        title: "Detected as workstation-managed",
        description: suggestion.detail,
      });
      return;
    }

    setEditingPrinterId(null);
    setGatewayProvisioningSecret(null);
    setSetupFormOpen(true);
    setManagedProfilesDialogOpen(true);
    setNetworkPrinterForm({
      ...buildEmptyNetworkPrinterForm(),
      connectionType: suggestion.routeType,
      name: printer.printerName,
      vendor: "",
      model: printer.model || "",
      ipAddress: suggestion.routeType === "NETWORK_DIRECT" ? suggestion.host || "" : "",
      host: suggestion.routeType === "NETWORK_IPP" ? suggestion.host || "" : "",
      port: String(suggestion.port || (suggestion.routeType === "NETWORK_IPP" ? 631 : 9100)),
      resourcePath: suggestion.routeType === "NETWORK_IPP" ? suggestion.resourcePath || "/ipp/print" : "/ipp/print",
      tlsEnabled: suggestion.routeType === "NETWORK_IPP" ? Boolean(suggestion.tlsEnabled ?? true) : true,
      printerUri: suggestion.routeType === "NETWORK_IPP" ? suggestion.printerUri || "" : "",
      deliveryMode: "DIRECT",
      rotateGatewaySecret: false,
      commandLanguage: suggestion.routeType === "NETWORK_DIRECT" ? suggestion.commandLanguage || "ZPL" : "ZPL",
    });

    toast({
      title: suggestion.readiness === "READY" ? "Detected printer loaded" : "Detected printer template loaded",
      description: suggestion.detail,
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

  const runPrinterDiscovery = async (printerId: string) => {
    setDiscoveringPrinterId(printerId);
    try {
      const response = await apiClient.discoverRegisteredPrinter(printerId);
      if (!response.success) {
        toast({
          title: "Discovery needs attention",
          description: sanitizePrinterUiError(response.error, "Capability discovery could not complete right now."),
          variant: "destructive",
        });
        return false;
      }

      const certification = (response.data as { certification?: { summary?: string; warnings?: string[]; mismatches?: string[] } } | undefined)
        ?.certification;
      const mismatchCount = Array.isArray(certification?.mismatches) ? certification.mismatches.length : 0;
      const warningCount = Array.isArray(certification?.warnings) ? certification.warnings.length : 0;
      const summary =
        certification?.summary ||
        (mismatchCount > 0
          ? "This printer still needs review before production print."
          : warningCount > 0
            ? "Discovery completed with warnings."
            : "Printer discovery and certification completed.");

      toast({
        title: mismatchCount > 0 ? "Printer needs review" : "Discovery complete",
        description: summary,
        variant: mismatchCount > 0 ? "destructive" : "default",
      });
      await loadRegisteredPrinters();
      return mismatchCount === 0;
    } finally {
      setDiscoveringPrinterId(null);
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
    ? "Update network printer route"
    : setupFormOpen
      ? `Create ${getManagedSetupTypeLabel(networkPrinterForm).toLowerCase()}`
      : "Network printer routes";

  return (
    <DashboardLayout>
      <div className="space-y-6">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h1 className="text-3xl font-bold">
              {isGlobalPrinterAdmin ? "Printer Profiles & Certification" : "Printer Setup & Support"}
            </h1>
            <p className="text-muted-foreground">
              {isGlobalPrinterAdmin
                ? "Review certified profiles, capability discovery, and controlled network routes without exposing raw label payloads."
                : "Review printer readiness, guided setup steps, and support-safe status summaries for this workstation."}
            </p>
          </div>

          <div className="flex flex-wrap gap-2">
            {isManufacturerUser ? (
              <Button variant="outline" onClick={() => navigate("/connector-download")}>
                Install Connector
              </Button>
            ) : null}
            <Button variant="outline" onClick={() => void loadDiagnostics()} disabled={loading} className="gap-2">
              <RefreshCw className="h-4 w-4" />
              {loading ? "Refreshing..." : isGlobalPrinterAdmin ? "Refresh inventory" : "Refresh status"}
            </Button>
            {isManufacturerUser ? (
              <>
                <Button variant="outline" onClick={copySupportSummary} className="gap-2">
                  <Copy className="h-4 w-4" />
                  Copy support summary
                </Button>
                <Button variant="outline" onClick={() => navigate("/batches")}>
                  Open batches
                </Button>
              </>
            ) : null}
            <Button variant="outline" onClick={() => navigate(contextualHelpRoute)}>
              Open help
            </Button>
          </div>
        </div>

        {isManufacturerUser ? (
          <>
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
                Recommended next step
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 text-sm">
              <div className="rounded-lg border bg-muted/40 px-3 py-3">
                <div className="font-medium text-foreground">{recommendedAction.title}</div>
                <div className="mt-1 text-muted-foreground">{recommendedAction.description}</div>
                <Button variant="outline" size="sm" className="mt-3" onClick={recommendedAction.run}>
                  {recommendedAction.label}
                </Button>
              </div>
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
                    <div className="font-medium text-foreground">Saved network route</div>
                    <div className="mt-3 text-sm leading-6 text-muted-foreground">
                      {preferredManagedNetworkPrinter ? (
                        <>
                          Registered profile: <span className="font-medium text-foreground">{preferredManagedNetworkPrinter.name}</span>
                          <br />
                          Type: <span className="font-medium text-foreground">{getPrinterDispatchLabel(preferredManagedNetworkPrinter)}</span>
                        </>
                      ) : (
                        "Open network routes to create factory LAN or office IPP printer setups."
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
                  Saved network routes do not depend on the workstation printer list. Click here to create, update, remove, or re-check them in one place.
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
          </>
        ) : (
          <Card className="border-slate-200 bg-slate-50">
            <CardContent className="pt-6 text-sm text-slate-700">
              <div className="font-semibold text-slate-900">Global printer inventory</div>
              <p className="mt-2 max-w-3xl leading-6">
                This admin view is focused on certified routes, capability discovery, and mismatch review. Workstation connector diagnostics stay in the manufacturer setup flow.
              </p>
              <div className="mt-4 flex flex-wrap gap-2">
                <Badge variant="secondary">{managedNetworkPrinters.length} managed routes</Badge>
                <Badge variant={managedPrinterReadyCount > 0 ? "default" : "secondary"}>{managedPrinterReadyCount} certified / ready</Badge>
                <Badge variant={managedPrinterAttentionCount > 0 ? "secondary" : "outline"}>{managedPrinterAttentionCount} needs review</Badge>
              </div>
            </CardContent>
          </Card>
        )}

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
              <div className="font-semibold text-foreground">Factory label printer</div>
              <p className="mt-2 leading-6">
                Best for controlled factory LAN printers with a stable IP address and approved raw TCP access.
              </p>
              <ul className="mt-3 list-disc space-y-2 pl-5 text-xs">
                <li>Current direct-dispatch languages: {NETWORK_DIRECT_SUPPORTED_LANGUAGE_LABEL}.</li>
                <li>Printer must be registered here first. Freeform IP/port entry during print is not allowed.</li>
                <li>Use <strong>Check</strong> after registration to confirm connectivity and language readiness.</li>
              </ul>
              <div className="mt-4 flex flex-wrap gap-2">
                <Button variant="outline" size="sm" onClick={() => openManagedProfilesDialog({ createType: "NETWORK_DIRECT" })}>
                  Register factory printer
                </Button>
                <Button variant="ghost" size="sm" onClick={() => openManagedProfilesDialog()}>
                  Open network routes
                </Button>
              </div>
            </div>
            <div className="rounded-xl border bg-muted/20 p-4 text-sm text-muted-foreground">
              <div className="font-semibold text-foreground">Office / AirPrint printer</div>
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
              <CardTitle className="text-base">Saved network routes</CardTitle>
              <div className="mt-1 text-sm text-muted-foreground">
                Factory and office network printers are saved here so MSCQR can validate them and keep their readiness visible.
              </div>
            </div>
            <Button variant="outline" onClick={() => openManagedProfilesDialog()}>
              Open network routes
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
                <div className="mt-2 text-xs leading-5 text-muted-foreground">
                  Save a raw TCP industrial printer route for {NETWORK_DIRECT_SUPPORTED_LANGUAGE_LABEL} and validate it before batch printing.
                </div>
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

        <ManagedPrinterRoutesDialog
          open={managedProfilesDialogOpen}
          onOpenChange={setManagedProfilesDialogOpen}
          title={managedDialogTitle}
          managedPrinterReadyCount={managedPrinterReadyCount}
          managedNetworkPrinterCount={managedNetworkPrinters.length}
          autoDetectedManagedPrinters={autoDetectedManagedPrinters}
          registeredPrinters={registeredPrinters}
          loading={loading}
          setupFormOpen={setupFormOpen}
          editingPrinterId={editingPrinterId}
          networkPrinterForm={networkPrinterForm}
          setNetworkPrinterForm={setNetworkPrinterForm}
          gatewayProvisioningSecret={gatewayProvisioningSecret}
          savingNetworkPrinter={savingNetworkPrinter}
          testingPrinterId={testingPrinterId}
          discoveringPrinterId={discoveringPrinterId}
          deletingPrinterId={deletingPrinterId}
          onRefreshNow={loadDiagnostics}
          onUseAutoDetectedPrinter={useAutoDetectedPrinter}
          onOpenManagedProfilesDialog={openManagedProfilesDialog}
          onClose={closeManagedProfilesDialog}
          onResetNetworkPrinterForm={resetNetworkPrinterForm}
          onSaveNetworkPrinter={saveNetworkPrinter}
          onRunPrinterTest={runPrinterTest}
          onRunPrinterDiscovery={runPrinterDiscovery}
          onRemoveNetworkPrinter={removeNetworkPrinter}
        />

        {isManufacturerUser ? (
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
        ) : null}
      </div>
    </DashboardLayout>
  );
}
