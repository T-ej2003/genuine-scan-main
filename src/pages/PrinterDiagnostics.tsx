import React, { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { formatDistanceToNow } from "date-fns";
import { Activity, Copy, RefreshCw, ShieldAlert, Wifi, Wrench } from "lucide-react";

import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useAuth } from "@/contexts/AuthContext";
import { getContextualHelpRoute } from "@/help/contextual-help";
import { useToast } from "@/hooks/use-toast";
import apiClient from "@/lib/api-client";
import {
  getPrinterDiagnosticSummary,
  normalizePrinterInventoryRows,
  type LocalPrinterAgentSnapshot,
  type PrinterConnectionStatusLike,
  type PrinterInventoryRow,
} from "@/lib/printer-diagnostics";

const EMPTY_LOCAL_AGENT: LocalPrinterAgentSnapshot = {
  reachable: false,
  connected: false,
  error: "Local print agent has not been checked yet.",
  checkedAt: null,
};

type RegisteredPrinterRow = {
  id: string;
  name: string;
  vendor?: string | null;
  model?: string | null;
  connectionType: "LOCAL_AGENT" | "NETWORK_DIRECT";
  commandLanguage: "AUTO" | "ZPL" | "TSPL" | "SBPL" | "EPL" | "CPCL" | "ESC_POS" | "OTHER";
  ipAddress?: string | null;
  port?: number | null;
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
  const [editingPrinterId, setEditingPrinterId] = useState<string | null>(null);
  const [networkPrinterForm, setNetworkPrinterForm] = useState({
    name: "",
    vendor: "",
    model: "",
    ipAddress: "",
    port: "9100",
    commandLanguage: "AUTO" as RegisteredPrinterRow["commandLanguage"],
  });

  const loadRegisteredPrinters = async () => {
    if (user?.role !== "manufacturer") return;
    const response = await apiClient.listRegisteredPrinters(true);
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
        description: response.error || "Could not switch active printer.",
        variant: "destructive",
      });
      return;
    }
    toast({
      title: "Printer switched",
      description: "The local print agent updated the active printer.",
    });
    await loadDiagnostics();
  };

  const copyDiagnostics = async () => {
    const payload = {
      localAgent,
      remoteStatus,
      detectedPrinters,
      selectedPrinterId,
      registeredPrinters,
      copiedAt: new Date().toISOString(),
    };
    await navigator.clipboard.writeText(JSON.stringify(payload, null, 2));
    toast({
      title: "Diagnostics copied",
      description: "Printer diagnostics JSON is now in your clipboard.",
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

  const statusClasses =
    summary.tone === "success"
      ? "border-emerald-200 bg-emerald-50 text-emerald-800"
      : summary.tone === "warning"
        ? "border-amber-200 bg-amber-50 text-amber-800"
        : summary.tone === "neutral"
          ? "border-slate-200 bg-slate-50 text-slate-700"
          : "border-red-200 bg-red-50 text-red-800";

  const checkedLabel = localAgent.checkedAt
    ? `${formatDistanceToNow(new Date(localAgent.checkedAt), { addSuffix: true })}`
    : "not checked yet";

  const resetNetworkPrinterForm = () => {
    setEditingPrinterId(null);
    setNetworkPrinterForm({
      name: "",
      vendor: "",
      model: "",
      ipAddress: "",
      port: "9100",
      commandLanguage: "AUTO",
    });
  };

  const saveNetworkPrinter = async () => {
    const name = networkPrinterForm.name.trim();
    const ipAddress = networkPrinterForm.ipAddress.trim();
    const port = Number(networkPrinterForm.port || 0);

    if (!name || !ipAddress || !Number.isFinite(port) || port <= 0) {
      toast({
        title: "Incomplete printer profile",
        description: "Name, IP address, and TCP port are required.",
        variant: "destructive",
      });
      return;
    }

    setSavingNetworkPrinter(true);
    try {
      const payload = {
        name,
        vendor: networkPrinterForm.vendor.trim() || undefined,
        model: networkPrinterForm.model.trim() || undefined,
        ipAddress,
        port,
        commandLanguage: networkPrinterForm.commandLanguage,
      };
      const response = editingPrinterId
        ? await apiClient.updateNetworkPrinter(editingPrinterId, payload)
        : await apiClient.createNetworkPrinter(payload);
      if (!response.success) {
        toast({
          title: editingPrinterId ? "Update failed" : "Create failed",
          description: response.error || "Could not save printer profile.",
          variant: "destructive",
        });
        return;
      }
      toast({
        title: editingPrinterId ? "Printer updated" : "Printer registered",
        description: `${name} is ready for validation.`,
      });
      resetNetworkPrinterForm();
      await loadDiagnostics();
    } finally {
      setSavingNetworkPrinter(false);
    }
  };

  const editNetworkPrinter = (printer: RegisteredPrinterRow) => {
    setEditingPrinterId(printer.id);
    setNetworkPrinterForm({
      name: printer.name || "",
      vendor: printer.vendor || "",
      model: printer.model || "",
      ipAddress: printer.ipAddress || "",
      port: String(printer.port || 9100),
      commandLanguage: printer.commandLanguage || "AUTO",
    });
  };

  const runPrinterTest = async (printerId: string) => {
    setTestingPrinterId(printerId);
    try {
      const response = await apiClient.testRegisteredPrinter(printerId);
      if (!response.success) {
        toast({
          title: "Printer test failed",
          description: response.error || "Could not validate printer connectivity.",
          variant: "destructive",
        });
        return;
      }
      const detail =
        (response.data as any)?.registryStatus?.detail ||
        (response.data as any)?.registryStatus?.summary ||
        "Printer validation completed.";
      toast({
        title: "Printer test complete",
        description: detail,
      });
      await loadRegisteredPrinters();
    } finally {
      setTestingPrinterId(null);
    }
  };

  return (
    <DashboardLayout>
      <div className="space-y-6">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h1 className="text-3xl font-bold">Printer Diagnostics</h1>
            <p className="text-muted-foreground">
              Separate workstation agent issues, operating-system printer visibility, and backend trust or heartbeat failures.
            </p>
          </div>

          <div className="flex flex-wrap gap-2">
            <Button variant="outline" onClick={() => void loadDiagnostics()} disabled={loading} className="gap-2">
              <RefreshCw className="h-4 w-4" />
              {loading ? "Refreshing..." : "Refresh diagnostics"}
            </Button>
            <Button variant="outline" onClick={copyDiagnostics} className="gap-2">
              <Copy className="h-4 w-4" />
              Copy diagnostics
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
                  <div className="text-lg font-semibold">{summary.title}</div>
                  <Badge variant={summary.tone === "danger" ? "destructive" : "secondary"}>{summary.badgeLabel}</Badge>
                </div>
                <p className="text-sm leading-6">{summary.summary}</p>
                <p className="text-xs leading-5 opacity-90">{summary.detail}</p>
              </div>

              <div className="grid gap-2 text-xs lg:min-w-[16rem]">
                <div className="rounded-xl border border-white/60 bg-white/60 px-3 py-2">
                  <div className="font-medium opacity-70">Agent check</div>
                  <div className="mt-1 font-semibold">{checkedLabel}</div>
                </div>
                <div className="rounded-xl border border-white/60 bg-white/60 px-3 py-2">
                  <div className="font-medium opacity-70">Selected printer</div>
                  <div className="mt-1 font-semibold">{summary.selectedPrinter?.printerName || remoteStatus?.selectedPrinterName || "—"}</div>
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
                Local agent
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
                <div className="text-muted-foreground">Agent error</div>
                <div className="mt-1 break-words text-xs">{localAgent.error || "None"}</div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base">
                <ShieldAlert className="h-4 w-4" />
                Server trust
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3 text-sm">
              <div className="flex items-center justify-between">
                <span className="text-muted-foreground">Connection class</span>
                <Badge variant={remoteStatus?.connectionClass === "BLOCKED" ? "destructive" : "secondary"}>
                  {remoteStatus?.connectionClass || "Unavailable"}
                </Badge>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-muted-foreground">Trust status</span>
                <Badge variant="secondary">{remoteStatus?.trustStatus || "Unavailable"}</Badge>
              </div>
              <div>
                <div className="text-muted-foreground">Trust reason</div>
                <div className="mt-1 break-words text-xs">{remoteStatus?.error || remoteStatus?.trustReason || "No remote trust message available."}</div>
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
              {summary.nextSteps.map((step) => (
                <div key={step} className="rounded-lg border bg-muted/40 px-3 py-2">
                  {step}
                </div>
              ))}
            </CardContent>
          </Card>
        </div>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Client workstation requirements</CardTitle>
          </CardHeader>
          <CardContent className="grid gap-4 lg:grid-cols-2">
            <div className="space-y-3 text-sm text-muted-foreground">
              <div className="rounded-xl border bg-muted/30 p-4">
                <div className="font-medium text-foreground">What must exist on the client machine</div>
                <ul className="mt-3 list-disc space-y-2 pl-5">
                  <li>The local MSCQR print agent must be installed and running on the workstation.</li>
                  <li>The operating system must already see the printer in its printer list.</li>
                  <li>The printer driver or spooler path must be working before the browser can show a ready state.</li>
                  <li>The local agent must answer <code>http://127.0.0.1:17866/status</code> from the same device.</li>
                </ul>
              </div>
              <div className="rounded-xl border bg-muted/30 p-4">
                <div className="font-medium text-foreground">Fast client-side test</div>
                <ol className="mt-3 list-decimal space-y-2 pl-5">
                  <li>Open <code>http://127.0.0.1:17866/status</code> in the local browser.</li>
                  <li>Confirm the response loads and lists at least one printer.</li>
                  <li>If it fails, fix the agent or OS printer setup first.</li>
                  <li>If it succeeds but this page still shows blocked, copy diagnostics and send them to support.</li>
                </ol>
              </div>
            </div>

            <div className="space-y-3 text-sm text-muted-foreground">
              <div className="rounded-xl border bg-muted/30 p-4">
                <div className="font-medium text-foreground">How to read the result</div>
                <ul className="mt-3 list-disc space-y-2 pl-5">
                  <li><strong>Agent offline</strong>: browser cannot reach the workstation print agent.</li>
                  <li><strong>No printer connection detected</strong>: agent is running but did not find a printer.</li>
                  <li><strong>Printer offline</strong>: a configured printer exists but is not online.</li>
                  <li><strong>Sync pending</strong>: local printer exists, but server registration or heartbeat is not complete yet.</li>
                  <li><strong>Trust blocked</strong>: server rejected the heartbeat or identity material.</li>
                </ul>
              </div>
              <div className="rounded-xl border bg-muted/30 p-4">
                <div className="font-medium text-foreground">Escalation path</div>
                <p className="mt-3 leading-6">
                  Use <strong>Copy diagnostics</strong> from this page and attach it to a support ticket. That payload contains
                  the local agent view, discovered printers, and server trust response in one snapshot.
                </p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Printer compatibility matrix</CardTitle>
          </CardHeader>
          <CardContent className="grid gap-4 lg:grid-cols-2">
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
                <li>Use <strong>Test</strong> after registration to confirm connectivity and language readiness.</li>
              </ul>
            </div>
          </CardContent>
        </Card>

        <div className="grid gap-4 lg:grid-cols-[1.2fr_0.8fr]">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Registered printer profiles</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              {registeredPrinters.length === 0 ? (
                <div className="rounded-xl border border-dashed bg-muted/20 p-4 text-sm text-muted-foreground">
                  No printer profiles are registered yet. Local-agent printers appear after a trusted heartbeat. Network-direct printers can be added here.
                </div>
              ) : (
                <div className="space-y-3">
                  {registeredPrinters.map((printer) => (
                    <div key={printer.id} className="rounded-xl border p-4">
                      <div className="flex flex-wrap items-start justify-between gap-3">
                        <div>
                          <div className="font-semibold">{printer.name}</div>
                          <div className="mt-1 text-xs text-muted-foreground">
                            {printer.connectionType === "NETWORK_DIRECT"
                              ? `${printer.ipAddress || "—"}:${printer.port || 9100}`
                              : printer.nativePrinterId || "Local agent printer"}
                            {" · "}
                            {printer.commandLanguage}
                          </div>
                        </div>
                        <div className="flex flex-wrap gap-2">
                          <Badge variant={printer.registryStatus?.state === "BLOCKED" ? "destructive" : "secondary"}>
                            {printer.connectionType === "NETWORK_DIRECT" ? "Network-direct" : "Local agent"}
                          </Badge>
                          <Badge variant={printer.isActive ? "default" : "secondary"}>
                            {printer.isActive ? "Active" : "Inactive"}
                          </Badge>
                          {printer.registryStatus?.summary && <Badge variant="secondary">{printer.registryStatus.summary}</Badge>}
                        </div>
                      </div>
                      <div className="mt-3 text-xs text-muted-foreground">
                        {printer.registryStatus?.detail || printer.lastValidationMessage || "No validation details recorded yet."}
                      </div>
                      <div className="mt-3 flex flex-wrap justify-end gap-2">
                        <Button
                          variant="outline"
                          size="sm"
                          disabled={testingPrinterId === printer.id}
                          onClick={() => void runPrinterTest(printer.id)}
                        >
                          {testingPrinterId === printer.id ? "Testing..." : "Test"}
                        </Button>
                        {printer.connectionType === "NETWORK_DIRECT" && (
                          <Button variant="outline" size="sm" onClick={() => editNetworkPrinter(printer)}>
                            Edit
                          </Button>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-base">
                {editingPrinterId ? "Update network-direct printer" : "Add network-direct printer"}
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
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
              <div className="grid gap-3 sm:grid-cols-2">
                <div className="space-y-1">
                  <Label className="text-xs">IP address</Label>
                  <Input value={networkPrinterForm.ipAddress} onChange={(e) => setNetworkPrinterForm((prev) => ({ ...prev, ipAddress: e.target.value }))} placeholder="192.168.1.50" />
                </div>
                <div className="space-y-1">
                  <Label className="text-xs">TCP port</Label>
                  <Input value={networkPrinterForm.port} onChange={(e) => setNetworkPrinterForm((prev) => ({ ...prev, port: e.target.value }))} placeholder="9100" />
                </div>
              </div>
              <div className="space-y-1">
                <Label className="text-xs">Command language</Label>
                <Select
                  value={networkPrinterForm.commandLanguage}
                  onValueChange={(value) =>
                    setNetworkPrinterForm((prev) => ({ ...prev, commandLanguage: value as RegisteredPrinterRow["commandLanguage"] }))
                  }
                >
                  <SelectTrigger>
                    <SelectValue placeholder="Command language" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="AUTO">Auto</SelectItem>
                    <SelectItem value="ZPL">ZPL</SelectItem>
                    <SelectItem value="TSPL">TSPL</SelectItem>
                    <SelectItem value="SBPL">SBPL</SelectItem>
                    <SelectItem value="EPL">EPL</SelectItem>
                    <SelectItem value="CPCL">CPCL</SelectItem>
                    <SelectItem value="ESC_POS">ESC/POS</SelectItem>
                    <SelectItem value="OTHER">Other</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="flex flex-wrap justify-end gap-2">
                {editingPrinterId && (
                  <Button variant="outline" onClick={resetNetworkPrinterForm}>
                    Cancel edit
                  </Button>
                )}
                <Button onClick={() => void saveNetworkPrinter()} disabled={savingNetworkPrinter}>
                  {savingNetworkPrinter ? "Saving..." : editingPrinterId ? "Update printer" : "Register printer"}
                </Button>
              </div>
              <div className="text-xs text-muted-foreground">
                Network-direct printing is restricted to registered IP/port targets only. Freeform socket destinations are not allowed. Direct dispatch currently supports ZPL, TSPL, EPL, and CPCL.
              </div>
            </CardContent>
          </Card>
        </div>

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
                No printers were reported by the local agent.
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
                        {printer.languages?.join(", ") || "AUTO"} · {printer.mediaSizes?.join(", ") || "Auto media"} ·{" "}
                        {printer.dpi ? `${printer.dpi} dpi` : "Auto dpi"}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Diagnostic snapshot</CardTitle>
          </CardHeader>
          <CardContent>
            <pre className="max-h-[26rem] overflow-auto rounded-xl border bg-muted/20 p-4 text-xs">
              {JSON.stringify(
                {
                  localAgent,
                  remoteStatus,
                  detectedPrinters,
                  selectedPrinterId,
                  registeredPrinters,
                },
                null,
                2
              )}
            </pre>
          </CardContent>
        </Card>
      </div>
    </DashboardLayout>
  );
}
