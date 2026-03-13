import React, { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate, useLocation, Link } from "react-router-dom";
import { useAuth } from "@/contexts/AuthContext";
import { friendlyReferenceLabel, friendlyReferenceWords } from "@/lib/friendly-reference";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { getContextualHelpRoute } from "@/help/contextual-help";
import apiClient from "@/lib/api-client";
import { useToast } from "@/hooks/use-toast";
import {
  LayoutDashboard,
  Building2,
  Factory,
  FileText,
  Settings,
  LogOut,
  Menu,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  Shield,
  ScanEye,
  ShieldAlert,
  CircleHelp,
  Bell,
  Sparkles,
  SlidersHorizontal,
  Trash2,
  Inbox,
  Printer,
  RefreshCw,
  Monitor,
  Wifi,
  CheckCircle2,
  AlertTriangle,
} from "lucide-react";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Slider } from "@/components/ui/slider";
import { SupportIssueLauncher } from "@/components/support/SupportIssueLauncher";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { buildSupportDiagnosticsPayload, captureSupportScreenshot } from "@/lib/support-diagnostics";
import {
  getManagedPrinterDiagnosticSummary,
  getPrinterDiagnosticSummary,
  selectPreferredManagedPrinter,
  shouldPreferNetworkDirectSummary,
  type LocalPrinterAgentSnapshot,
} from "@/lib/printer-diagnostics";
import { getPrinterDispatchLabel, sanitizePrinterUiError } from "@/lib/printer-user-facing";

interface NavItem {
  label: string;
  href: string;
  icon: React.ElementType;
  roles: string[];
}

type DashboardNotification = {
  id: string;
  type?: string | null;
  title?: string | null;
  body?: string | null;
  createdAt?: string | null;
  readAt?: string | null;
  data?: unknown;
  incidentId?: string | null;
};

type PrinterConnectionStatus = {
  connected: boolean;
  trusted: boolean;
  compatibilityMode: boolean;
  compatibilityReason?: string | null;
  eligibleForPrinting: boolean;
  connectionClass?: "TRUSTED" | "COMPATIBILITY" | "BLOCKED";
  stale: boolean;
  requiredForPrinting: boolean;
  trustStatus?: string;
  trustReason?: string | null;
  lastHeartbeatAt: string | null;
  ageSeconds: number | null;
  registrationId?: string | null;
  agentId?: string | null;
  deviceFingerprint?: string | null;
  mtlsFingerprint?: string | null;
  printerName?: string | null;
  printerId?: string | null;
  selectedPrinterId?: string | null;
  selectedPrinterName?: string | null;
  deviceName?: string | null;
  agentVersion?: string | null;
  capabilitySummary?: {
    transports: string[];
    protocols: string[];
    languages: string[];
    supportsRaster: boolean;
    supportsPdf: boolean;
    dpiOptions: number[];
    mediaSizes: string[];
  } | null;
  printers?: Array<{
    printerId: string;
    printerName: string;
    model?: string | null;
    connection?: string | null;
    online?: boolean;
    isDefault?: boolean;
    protocols?: string[];
    languages?: string[];
    mediaSizes?: string[];
    dpi?: number | null;
  }>;
  calibrationProfile?: Record<string, unknown> | null;
  error?: string | null;
};

type RegisteredManagedPrinter = {
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

const NOTIFICATION_FETCH_LIMIT = 24;
const NOTIFICATION_WINDOW_SIZE = 4;
const NOTIFICATION_CLEAR_ANIMATION_MS = 260;
const PRINTER_FAILURE_REPORT_COOLDOWN_MS = 3 * 60 * 1000;
const PRINTER_ONBOARDING_STORAGE_VERSION = "v1";

const navItems: NavItem[] = [
  { label: "Dashboard", href: "/dashboard", icon: LayoutDashboard, roles: ["super_admin", "licensee_admin", "manufacturer"] },
  { label: "Licensees", href: "/licensees", icon: Building2, roles: ["super_admin"] },
  { label: "QR Requests", href: "/qr-requests", icon: FileText, roles: ["super_admin", "licensee_admin"] },
  { label: "Batches", href: "/batches", icon: FileText, roles: ["super_admin", "licensee_admin", "manufacturer"] },
  { label: "Manufacturers", href: "/manufacturers", icon: Factory, roles: ["super_admin", "licensee_admin"] },
  { label: "QR Tracking", href: "/qr-tracking", icon: ScanEye, roles: ["super_admin", "licensee_admin", "manufacturer"] },
  { label: "Support", href: "/support", icon: CircleHelp, roles: ["super_admin"] },
  { label: "IR Center", href: "/ir", icon: Shield, roles: ["super_admin"] },
  { label: "Incidents", href: "/incidents", icon: ShieldAlert, roles: ["super_admin"] },
  { label: "Governance", href: "/governance", icon: Shield, roles: ["super_admin"] },
  { label: "Audit Logs", href: "/audit-logs", icon: FileText, roles: ["super_admin", "licensee_admin", "manufacturer"] },
];

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

const formatPrinterTimestamp = (value?: string | null) => {
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

const derivePrinterIdentity = (params: {
  printerName?: string | null;
  selectedPrinterName?: string | null;
  model?: string | null;
  deviceName?: string | null;
}) => {
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
  const monogram = vendor
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

export function DashboardLayout({ children }: { children: React.ReactNode }) {
  const { user, logout } = useAuth();
  const { toast } = useToast();
  const navigate = useNavigate();
  const location = useLocation();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [notifications, setNotifications] = useState<DashboardNotification[]>([]);
  const [unreadNotifications, setUnreadNotifications] = useState(0);
  const [notificationsLoading, setNotificationsLoading] = useState(false);
  const [notificationsLive, setNotificationsLive] = useState(false);
  const [dismissedNotificationIds, setDismissedNotificationIds] = useState<string[]>([]);
  const [clearingNotificationIds, setClearingNotificationIds] = useState<string[]>([]);
  const [clearingNotifications, setClearingNotifications] = useState(false);
  const [notificationWindowStart, setNotificationWindowStart] = useState(0);
  const [notificationMotionSeed, setNotificationMotionSeed] = useState(0);
  const clearNotificationsTimerRef = useRef<number | null>(null);
  const printerConnectedRef = useRef(false);
  const detectedPrintersRef = useRef<
    Array<{
      printerId: string;
      printerName: string;
      model?: string | null;
      connection?: string | null;
      online?: boolean;
      isDefault?: boolean;
      protocols?: string[];
      languages?: string[];
      mediaSizes?: string[];
      dpi?: number | null;
    }>
  >([]);
  const printerFailureReportRef = useRef<{ signature: string; at: number }>({ signature: "", at: 0 });
  const printerFailureInFlightRef = useRef(false);
  const [printerStatus, setPrinterStatus] = useState<PrinterConnectionStatus>({
    connected: false,
    trusted: false,
    compatibilityMode: false,
    compatibilityReason: null,
    eligibleForPrinting: false,
    connectionClass: "BLOCKED",
    stale: true,
    requiredForPrinting: true,
    trustStatus: "UNREGISTERED",
    trustReason: "No trusted printer registration",
    lastHeartbeatAt: null,
    ageSeconds: null,
    registrationId: null,
    agentId: null,
    deviceFingerprint: null,
    mtlsFingerprint: null,
    printerName: null,
    printerId: null,
    selectedPrinterId: null,
    selectedPrinterName: null,
    deviceName: null,
    agentVersion: null,
    capabilitySummary: null,
    printers: [],
    calibrationProfile: null,
    error: "No trusted printer heartbeat yet",
  });
  const [printerDialogOpen, setPrinterDialogOpen] = useState(false);
  const [printerOnboardingOpen, setPrinterOnboardingOpen] = useState(false);
  const [printerSwitching, setPrinterSwitching] = useState(false);
  const [printerStatusLive, setPrinterStatusLive] = useState(false);
  const [printerStatusUpdatedAt, setPrinterStatusUpdatedAt] = useState<string | null>(null);
  const [localPrinterAgent, setLocalPrinterAgent] = useState<LocalPrinterAgentSnapshot>({
    reachable: false,
    connected: false,
    error: "Local print agent has not been checked yet.",
    checkedAt: null,
  });
  const [detectedPrinters, setDetectedPrinters] = useState<
    Array<{
      printerId: string;
      printerName: string;
      model?: string | null;
      connection?: string | null;
      online?: boolean;
      isDefault?: boolean;
      protocols?: string[];
      languages?: string[];
      mediaSizes?: string[];
      dpi?: number | null;
    }>
  >([]);
  const [selectedLocalPrinterId, setSelectedLocalPrinterId] = useState("");
  const [managedPrinterProfiles, setManagedPrinterProfiles] = useState<RegisteredManagedPrinter[]>([]);
  const [managedPrinterProfilesLoaded, setManagedPrinterProfilesLoaded] = useState(false);

  const filteredNavItems = navItems.filter((item) => user && item.roles.includes(user.role));
  const contextualHelpRoute = getContextualHelpRoute(location.pathname, user?.role);

  const applyNotificationSnapshot = (rows: DashboardNotification[], unread: number) => {
    setNotifications(rows);
    setUnreadNotifications(Number.isFinite(unread) ? unread : 0);

    const rowIds = new Set(rows.map((row) => String(row?.id || "")).filter(Boolean));
    setDismissedNotificationIds((prev) => prev.filter((id) => rowIds.has(id)));
  };

  const loadNotifications = async () => {
    if (!user) return;
    setNotificationsLoading(true);
    try {
      const response = await apiClient.getNotifications({ limit: NOTIFICATION_FETCH_LIMIT, offset: 0 });
      if (!response.success) {
        setNotifications([]);
        setUnreadNotifications(0);
        return;
      }
      const payload = (response.data && typeof response.data === "object" ? response.data : {}) as {
        notifications?: DashboardNotification[];
        unread?: number;
      };
      const rows = Array.isArray(payload.notifications) ? payload.notifications : [];
      applyNotificationSnapshot(rows, Number(payload.unread || 0));
    } catch {
      setNotifications([]);
      setUnreadNotifications(0);
    } finally {
      setNotificationsLoading(false);
    }
  };

  useEffect(() => {
    loadNotifications();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user?.id]);

  useEffect(() => {
    if (!user) return;
    const timer = window.setInterval(() => {
      loadNotifications();
    }, 90_000);
    return () => window.clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user?.id]);

  const normalizePrinterRows = (rows: unknown): Array<{
    printerId: string;
    printerName: string;
    model?: string | null;
    connection?: string | null;
    online?: boolean;
    isDefault?: boolean;
    protocols?: string[];
    languages?: string[];
    mediaSizes?: string[];
    dpi?: number | null;
  }> => {
    if (!Array.isArray(rows)) return [];
    const result: Array<{
      printerId: string;
      printerName: string;
      model?: string | null;
      connection?: string | null;
      online?: boolean;
      isDefault?: boolean;
      protocols?: string[];
      languages?: string[];
      mediaSizes?: string[];
      dpi?: number | null;
    }> = [];
    for (const row of rows) {
      if (!row || typeof row !== "object") continue;
      const printerId = String((row as any).printerId || (row as any).id || "").trim();
      const printerName = String((row as any).printerName || (row as any).name || "").trim();
      if (!printerId || !printerName) continue;
      result.push({
        printerId,
        printerName,
        model: String((row as any).model || "").trim() || null,
        connection: String((row as any).connection || (row as any).transport || "").trim() || null,
        online: Boolean((row as any).online ?? true),
        isDefault: Boolean((row as any).isDefault),
        protocols: Array.isArray((row as any).protocols) ? (row as any).protocols : [],
        languages: Array.isArray((row as any).languages) ? (row as any).languages : [],
        mediaSizes: Array.isArray((row as any).mediaSizes) ? (row as any).mediaSizes : [],
        dpi: Number.isFinite(Number((row as any).dpi)) ? Number((row as any).dpi) : null,
      });
      if (result.length >= 40) break;
    }
    return result;
  };

  const applyPrinterStatusSnapshot = (
    nextStatus: PrinterConnectionStatus,
    options?: {
      fallbackPrinters?: Array<{
        printerId: string;
        printerName: string;
        model?: string | null;
        connection?: string | null;
        online?: boolean;
        isDefault?: boolean;
        protocols?: string[];
        languages?: string[];
        mediaSizes?: string[];
        dpi?: number | null;
      }>;
      updatedAt?: string | null;
    }
  ) => {
    const fallbackPrinters = Array.isArray(options?.fallbackPrinters) ? options?.fallbackPrinters : detectedPrintersRef.current;
    const remotePrinters = normalizePrinterRows(nextStatus.printers || []);
    const mergedPrinters = remotePrinters.length > 0 ? remotePrinters : fallbackPrinters;

    setPrinterStatus({
      ...nextStatus,
      printers: mergedPrinters,
    });
    setDetectedPrinters(mergedPrinters);
    setPrinterStatusUpdatedAt(options?.updatedAt || nextStatus.lastHeartbeatAt || new Date().toISOString());

    setSelectedLocalPrinterId((prev) => {
      if (prev && mergedPrinters.some((row) => row.printerId === prev)) return prev;
      const fallbackPrinter =
        mergedPrinters.find((row) => row.printerId === nextStatus.selectedPrinterId) ||
        mergedPrinters.find((row) => row.printerId === nextStatus.printerId) ||
        mergedPrinters.find((row) => row.isDefault) ||
        mergedPrinters[0];
      return fallbackPrinter?.printerId || prev;
    });

    const nowConnected = Boolean(nextStatus.connected && nextStatus.eligibleForPrinting);
    if (nowConnected && !printerConnectedRef.current) {
      setPrinterDialogOpen(true);
    }
    printerConnectedRef.current = nowConnected;
  };

  const maybeAutoReportPrinterFailure = async (params: {
    localResult: Awaited<ReturnType<typeof apiClient.getLocalPrintAgentStatus>>;
    remoteStatus: PrinterConnectionStatus | null;
    printers: Array<{ printerId: string; printerName: string }>;
  }) => {
    if (!user || user.role !== "manufacturer") return;
    const remoteReady = Boolean(params.remoteStatus?.connected && params.remoteStatus?.eligibleForPrinting);
    if (remoteReady) {
      printerFailureReportRef.current = { signature: "", at: 0 };
      return;
    }
    const localReady = Boolean((params.localResult as any)?.success && (params.localResult as any)?.data?.connected);
    if (localReady && params.remoteStatus?.compatibilityMode) return;

    const localError = String(params.localResult.error || "").trim();
    const remoteError = String(params.remoteStatus?.error || "").trim();
    const hasKnownPrinter =
      params.printers.length > 0 ||
      Boolean(params.remoteStatus?.selectedPrinterId || params.remoteStatus?.printerId);
    const errorSummary = `${localError} ${remoteError} ${String(params.remoteStatus?.trustReason || "")}`.toLowerCase();
    const agentUnavailable =
      errorSummary.includes("local print agent unavailable") ||
      errorSummary.includes("local print agent is unavailable") ||
      errorSummary.includes("heartbeat failed");
    if (!hasKnownPrinter && agentUnavailable) return;
    if (!hasKnownPrinter) return;

    const signature = [
      localError || "no-local-error",
      remoteError || "no-remote-error",
      String(params.remoteStatus?.trustReason || ""),
      String(params.remoteStatus?.connectionClass || ""),
      String(params.remoteStatus?.selectedPrinterId || params.remoteStatus?.printerId || ""),
    ].join("|");
    const now = Date.now();
    if (
      printerFailureReportRef.current.signature === signature &&
      now - printerFailureReportRef.current.at < PRINTER_FAILURE_REPORT_COOLDOWN_MS
    ) {
      return;
    }
    if (printerFailureInFlightRef.current) return;

    printerFailureInFlightRef.current = true;
    printerFailureReportRef.current = { signature, at: now };
    try {
      const screenshot = await captureSupportScreenshot();
      const form = new FormData();
      form.append(
        "title",
        `Auto printer connection failure: ${params.remoteStatus?.selectedPrinterName || params.remoteStatus?.printerName || "Unknown printer"}`
      );
      form.append(
        "description",
        [
          "Automatic printer failure report from manufacturer console.",
          `Local agent: ${params.localResult.success ? "reachable" : "unreachable"}`,
          `Server class: ${params.remoteStatus?.connectionClass || "BLOCKED"}`,
          localError ? `Local error: ${localError}` : "",
          remoteError ? `Server error: ${remoteError}` : "",
        ]
          .filter(Boolean)
          .join("\n")
      );
      form.append("sourcePath", `${window.location.pathname}${window.location.search}`);
      form.append("pageUrl", window.location.href);
      form.append("autoDetected", "true");
      form.append(
        "diagnostics",
        JSON.stringify({
          ...buildSupportDiagnosticsPayload(),
          printer: {
            local: params.localResult.success ? params.localResult.data : null,
            remote: params.remoteStatus,
            discoveredPrinters: params.printers,
          },
        })
      );
      if (screenshot) {
        form.append("screenshot", screenshot);
      }
      await apiClient.createSupportIssueReport(form);
    } catch {
      // avoid surfacing auto-report failures in normal UX loop
    } finally {
      printerFailureInFlightRef.current = false;
    }
  };

  const loadManagedPrinterProfiles = async () => {
    if (!user || user.role !== "manufacturer") return;

    const response = await apiClient.listRegisteredPrinters(false);
    if (!response.success) {
      setManagedPrinterProfiles([]);
      setManagedPrinterProfilesLoaded(true);
      return;
    }

    setManagedPrinterProfiles(
      (Array.isArray(response.data) ? response.data : []).filter(
        (row): row is RegisteredManagedPrinter => Boolean(row && typeof row === "object" && (row as any).id && (row as any).name)
      )
    );
    setManagedPrinterProfilesLoaded(true);
  };

  const syncManufacturerPrinterStatus = async (opts?: { silent?: boolean }) => {
    if (!user || user.role !== "manufacturer") return;

    await loadManagedPrinterProfiles();

    const local = await apiClient.getLocalPrintAgentStatus();
    const localPrinters = normalizePrinterRows((local as any)?.data?.printers || []);
    setLocalPrinterAgent({
      reachable: Boolean(local.success),
      connected: Boolean((local as any)?.data?.connected),
      error: local.success ? String((local as any)?.data?.error || "").trim() || null : String(local.error || "Local print agent is unavailable"),
      checkedAt: new Date().toISOString(),
    });

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
      const nextStatus = remote.data as PrinterConnectionStatus;
      applyPrinterStatusSnapshot(nextStatus, {
        fallbackPrinters: localPrinters,
        updatedAt: nextStatus.lastHeartbeatAt || new Date().toISOString(),
      });
      const mergedPrinters =
        normalizePrinterRows(nextStatus.printers || []).length > 0
          ? normalizePrinterRows(nextStatus.printers || [])
          : localPrinters;
      const nowConnected = Boolean(nextStatus.connected && nextStatus.eligibleForPrinting);
      if (!nowConnected) {
        void maybeAutoReportPrinterFailure({
          localResult: local,
          remoteStatus: nextStatus,
          printers: mergedPrinters.map((item) => ({ printerId: item.printerId, printerName: item.printerName })),
        });
      }
      return;
    }

    const fallbackStatus: PrinterConnectionStatus = {
      connected: false,
      trusted: false,
      compatibilityMode: false,
      compatibilityReason: null,
      eligibleForPrinting: false,
      connectionClass: "BLOCKED",
      stale: true,
      requiredForPrinting: true,
      trustStatus: "UNREGISTERED",
      trustReason: "No trusted printer registration",
      lastHeartbeatAt: null,
      ageSeconds: null,
      registrationId: null,
      agentId: null,
      deviceFingerprint: null,
      mtlsFingerprint: null,
      printerName: null,
      printerId: null,
      selectedPrinterId: null,
      selectedPrinterName: null,
      deviceName: null,
      agentVersion: null,
      capabilitySummary: null,
      printers: localPrinters,
      calibrationProfile: null,
      error: String(remote.error || local.error || "Printer heartbeat failed"),
    };

    applyPrinterStatusSnapshot(fallbackStatus, {
      fallbackPrinters: localPrinters,
      updatedAt: new Date().toISOString(),
    });
    if (!opts?.silent) {
      void maybeAutoReportPrinterFailure({
        localResult: local,
        remoteStatus: fallbackStatus,
        printers: localPrinters.map((item) => ({ printerId: item.printerId, printerName: item.printerName })),
      });
    }
  };

  const switchLocalPrinter = async (targetOverride?: string) => {
    const targetPrinterId = String(targetOverride || selectedLocalPrinterId || "").trim();
    if (!targetPrinterId) return;
    setSelectedLocalPrinterId(targetPrinterId);
    setPrinterSwitching(true);
    try {
      const switched = await apiClient.selectLocalPrinter(targetPrinterId);
      if (!switched.success) {
        toast({
          title: "Printer switch failed",
          description: sanitizePrinterUiError(switched.error, "Could not switch the workstation printer."),
          variant: "destructive",
        });
        return;
      }
      toast({
        title: "Printer switched",
        description: "The workstation printer has been updated.",
      });
      await syncManufacturerPrinterStatus({ silent: true });
    } finally {
      setPrinterSwitching(false);
    }
  };

  useEffect(() => {
    if (!user || user.role !== "manufacturer") return;

    syncManufacturerPrinterStatus({ silent: true });
    const timer = window.setInterval(() => {
      syncManufacturerPrinterStatus({ silent: true });
    }, 6000);
    return () => window.clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user?.id, user?.role]);

  useEffect(() => {
    detectedPrintersRef.current = detectedPrinters;
  }, [detectedPrinters]);

  useEffect(() => {
    if (!user || user.role !== "manufacturer") return;

    const stop = apiClient.streamPrinterConnectionStatus(
      (payload) => {
        setPrinterStatusLive(true);
        applyPrinterStatusSnapshot(payload.status as PrinterConnectionStatus, {
          updatedAt: payload.serverTime || payload.status.lastHeartbeatAt || new Date().toISOString(),
        });
      },
      () => {
        setPrinterStatusLive(false);
      },
      () => {
        setPrinterStatusLive(true);
      }
    );

    return () => {
      setPrinterStatusLive(false);
      stop();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user?.id, user?.role]);

  useEffect(() => {
    if (!printerStatus) return;
    if (!selectedLocalPrinterId) {
      const next = String(
        printerStatus.selectedPrinterId ||
          printerStatus.printerId ||
          detectedPrinters.find((item) => item.isDefault)?.printerId ||
          detectedPrinters[0]?.printerId ||
          ""
      ).trim();
      if (next) setSelectedLocalPrinterId(next);
    }
  }, [printerStatus, detectedPrinters, selectedLocalPrinterId]);

  useEffect(() => {
    if (!user) return;
    if (clearNotificationsTimerRef.current) {
      window.clearTimeout(clearNotificationsTimerRef.current);
      clearNotificationsTimerRef.current = null;
    }

    const stop = apiClient.streamNotifications(
      (payload) => {
        const rows = Array.isArray(payload.notifications) ? payload.notifications : [];
        applyNotificationSnapshot(rows, Number(payload.unread || 0));
      },
      () => {
        setNotificationsLive(false);
      },
      () => {
        setNotificationsLive(true);
      },
      { limit: NOTIFICATION_FETCH_LIMIT }
    );

    return () => {
      setNotificationsLive(false);
      stop();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user?.id]);

  const markNotificationRead = async (id: string) => {
    if (!id) return;
    await apiClient.markNotificationRead(id);
    await loadNotifications();
  };

  const notificationTarget = (notification: DashboardNotification) => {
    const data = (notification?.data && typeof notification.data === "object" ? notification.data : {}) as Record<string, unknown>;
    if (typeof data.targetRoute === "string" && data.targetRoute.trim()) return data.targetRoute.trim();
    if (data.ticketId) return `/support?ticketId=${encodeURIComponent(String(data.ticketId))}`;
    if (data.ticketReference) return `/support?reference=${encodeURIComponent(String(data.ticketReference))}`;
    if (notification?.incidentId) return `/incidents?incidentId=${encodeURIComponent(String(notification.incidentId))}`;
    return "/dashboard";
  };

  const dismissedNotificationIdSet = useMemo(() => new Set(dismissedNotificationIds), [dismissedNotificationIds]);
  const clearingNotificationIdSet = useMemo(() => new Set(clearingNotificationIds), [clearingNotificationIds]);

  const visibleNotifications = useMemo(
    () => notifications.filter((item) => item?.id && !dismissedNotificationIdSet.has(String(item.id))),
    [notifications, dismissedNotificationIdSet]
  );

  const notificationTimelineMax = Math.max(0, visibleNotifications.length - NOTIFICATION_WINDOW_SIZE);

  useEffect(() => {
    setNotificationWindowStart((prev) => Math.min(prev, notificationTimelineMax));
  }, [notificationTimelineMax]);

  useEffect(() => {
    setNotificationMotionSeed((prev) => prev + 1);
  }, [notificationWindowStart, visibleNotifications.length]);

  useEffect(() => {
    return () => {
      if (clearNotificationsTimerRef.current) {
        window.clearTimeout(clearNotificationsTimerRef.current);
      }
    };
  }, []);

  const notificationItems = useMemo(
    () => visibleNotifications.slice(notificationWindowStart, notificationWindowStart + NOTIFICATION_WINDOW_SIZE),
    [visibleNotifications, notificationWindowStart]
  );

  const handleMarkAllNotificationsRead = async () => {
    if (notifications.length === 0 && unreadNotifications === 0) return;

    const readAt = new Date().toISOString();
    setNotifications((prev) => prev.map((item) => ({ ...item, readAt: item.readAt || readAt })));
    setUnreadNotifications(0);

    try {
      await apiClient.markAllNotificationsRead();
    } catch {
      await loadNotifications();
    }
  };

  const handleClearNotifications = async () => {
    if (notificationsLoading || clearingNotifications || visibleNotifications.length === 0) return;

    const idsToClear = visibleNotifications.map((item) => String(item.id)).filter(Boolean);
    if (idsToClear.length === 0) return;

    const unreadBeingCleared = visibleNotifications.reduce((count, item) => count + (!item.readAt ? 1 : 0), 0);
    const readAt = new Date().toISOString();

    setClearingNotifications(true);
    setClearingNotificationIds(idsToClear);
    setNotifications((prev) =>
      prev.map((item) => (idsToClear.includes(String(item.id)) ? { ...item, readAt: item.readAt || readAt } : item))
    );
    setUnreadNotifications((prev) => Math.max(0, prev - unreadBeingCleared));

    if (clearNotificationsTimerRef.current) {
      window.clearTimeout(clearNotificationsTimerRef.current);
    }

    clearNotificationsTimerRef.current = window.setTimeout(() => {
      setDismissedNotificationIds((prev) => Array.from(new Set([...prev, ...idsToClear])).slice(-300));
      setClearingNotificationIds([]);
      setClearingNotifications(false);
      clearNotificationsTimerRef.current = null;
    }, NOTIFICATION_CLEAR_ANIMATION_MS);

    try {
      await apiClient.markAllNotificationsRead();
    } catch {
      // Local clear is non-destructive UI state; keep it smooth even if network sync fails.
    }
  };

  const stepNotificationTimeline = (direction: "newer" | "older") => {
    setNotificationWindowStart((prev) => {
      if (direction === "newer") return Math.max(0, prev - 1);
      return Math.min(notificationTimelineMax, prev + 1);
    });
  };

  const canMoveTimelineToNewer = notificationWindowStart > 0;
  const canMoveTimelineToOlder = notificationWindowStart < notificationTimelineMax;
  const hasVisibleNotifications = visibleNotifications.length > 0;
  const notificationPanelCleared = notifications.length > 0 && visibleNotifications.length === 0;
  const canClearNotifications = hasVisibleNotifications && !notificationsLoading && !clearingNotifications;
  const timelineVisibleStart = hasVisibleNotifications ? notificationWindowStart + 1 : 0;
  const timelineVisibleEnd = hasVisibleNotifications ? notificationWindowStart + notificationItems.length : 0;

  const formatNotificationDate = (value?: string | null) => {
    if (!value) return "Time unavailable";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return "Time unavailable";
    return date.toLocaleString();
  };

  const isNotificationUnread = (notification: DashboardNotification) => !notification.readAt;

  const notificationToneClasses = (notification: DashboardNotification) => {
    const text = `${notification.title || ""} ${notification.body || ""}`.toLowerCase();
    if (text.includes("incident")) {
      return {
        accent: "bg-amber-400/90",
        border: "border-amber-300/35",
        glow: "shadow-[0_0_0_1px_rgba(251,191,36,0.12)_inset]",
        chip: "bg-amber-400/15 text-amber-900 dark:text-amber-200 border-amber-300/30",
      };
    }
    if (text.includes("request")) {
      return {
        accent: "bg-sky-400/90",
        border: "border-sky-300/35",
        glow: "shadow-[0_0_0_1px_rgba(56,189,248,0.12)_inset]",
        chip: "bg-sky-400/15 text-sky-900 dark:text-sky-200 border-sky-300/30",
      };
    }
    return {
      accent: "bg-emerald-400/90",
      border: "border-emerald-300/35",
      glow: "shadow-[0_0_0_1px_rgba(16,185,129,0.12)_inset]",
      chip: "bg-emerald-400/15 text-emerald-900 dark:text-emerald-200 border-emerald-300/30",
    };
  };

  const toHumanWords = (value?: string | null) =>
    String(value || "")
      .trim()
      .replace(/_/g, " ")
      .replace(/\s+/g, " ")
      .toLowerCase()
      .replace(/\b\w/g, (c) => c.toUpperCase());

  const escapeRegExp = (value: string) => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

  const replaceOpaqueRefs = (text: string, notification: DashboardNotification) => {
    const raw = String(text || "");
    if (!raw) return raw;

    const data =
      notification?.data && typeof notification.data === "object"
        ? (notification.data as Record<string, unknown>)
        : ({} as Record<string, unknown>);

    let out = raw;

    const exactReplacements: Array<{ value?: unknown; label: string }> = [
      { value: notification.incidentId, label: notification.incidentId ? friendlyReferenceLabel(String(notification.incidentId), "Case") : "Case" },
      { value: data.ticketReference, label: data.ticketReference ? friendlyReferenceLabel(String(data.ticketReference), "Ticket") : "Ticket" },
      { value: data.referenceCode, label: data.referenceCode ? friendlyReferenceLabel(String(data.referenceCode), "Ticket") : "Ticket" },
      { value: data.requestId, label: "QR request" },
      { value: data.batchId, label: "Batch" },
      { value: data.printJobId, label: "Print job" },
    ];

    for (const entry of exactReplacements) {
      const value = String(entry.value || "").trim();
      if (!value) continue;
      out = out.replace(new RegExp(escapeRegExp(value), "g"), entry.label);
    }

    out = out.replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, (m) =>
      friendlyReferenceLabel(m, "Case")
    );

    out = out.replace(/\b[0-9a-f]{8}\b/gi, (m) => `Ref ${friendlyReferenceWords(m, 2)}`);

    out = out.replace(/\bAUTH_[A-Z0-9_]+\b/g, (m) => toHumanWords(m));
    return out;
  };

  const notificationCopy = (notification: DashboardNotification) => {
    const data =
      notification?.data && typeof notification.data === "object"
        ? (notification.data as Record<string, unknown>)
        : ({} as Record<string, unknown>);
    const type = String(notification.type || "").trim();

    if (type === "manufacturer_batch_assigned") {
      const batchName = String(data.batchName || "assigned batch").trim();
      const qty = Number(data.quantity || 0);
      return {
        title: "New batch assigned",
        body: `${batchName}${qty > 0 ? ` is ready for printing (${qty} codes).` : " is ready for printing."}`,
      };
    }
    if (type === "manufacturer_print_job_created") {
      const batchName = String(data.batchName || "batch").trim();
      const qty = Number(data.quantity || 0);
      return {
        title: "Direct-print job prepared",
        body: `${batchName}${qty > 0 ? ` ready for secure direct-print (${qty} codes).` : " ready for secure direct-print."}`,
      };
    }
    if (type === "manufacturer_print_job_confirmed") {
      const batchName = String(data.batchName || "batch").trim();
      const qty = Number(data.printedCodes || 0);
      return {
        title: "Printing confirmed",
        body: `${batchName}${qty > 0 ? ` confirmed with ${qty} printed codes.` : " printing was confirmed."}`,
      };
    }

    const fallbackTitle = notification.title?.trim() || (type ? toHumanWords(type) : "Notification");
    const fallbackBody = notification.body?.trim() || "Open to view details.";
    return {
      title: replaceOpaqueRefs(fallbackTitle, notification),
      body: replaceOpaqueRefs(fallbackBody, notification),
    };
  };

  const handleLogout = () => {
    logout();
    navigate("/login");
  };

  const getRoleLabel = (role?: string) => {
    if (!role) return "User";
    switch (role) {
      case "super_admin":
        return "Super User";
      case "licensee_admin":
        return "Licensee User";
      case "manufacturer":
        return "Manufacturer User";
      default:
        return role;
    }
  };

  const printerReady = printerStatus.connected && printerStatus.eligibleForPrinting;
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
      (!printerReady ||
        shouldPreferNetworkDirectSummary({
          printers: detectedPrinters,
          networkPrinter: preferredManagedNetworkPrinter,
        }))
  );
  const effectivePrinterDiagnostics = shouldUseManagedPrinterSummary && managedPrinterDiagnostics ? managedPrinterDiagnostics : printerDiagnostics;
  const effectivePrinterReady = printerReady || managedPrinterDiagnostics?.tone === "success";
  const printerUnavailable = !effectivePrinterReady && !printerHasInventory && managedNetworkPrinters.length === 0;
  const printerModeLabel = effectivePrinterDiagnostics.badgeLabel;
  const printerToneClass =
    effectivePrinterDiagnostics.tone === "success"
      ? "border-emerald-300 bg-emerald-50 text-emerald-700 hover:bg-emerald-100"
      : effectivePrinterDiagnostics.tone === "warning"
        ? "border-amber-300 bg-amber-50 text-amber-700 hover:bg-amber-100"
        : effectivePrinterDiagnostics.tone === "neutral"
          ? "border-slate-300 bg-slate-100 text-slate-700 hover:bg-slate-200"
          : "border-red-300 bg-red-50 text-red-700 hover:bg-red-100";
  const printerTitle = effectivePrinterDiagnostics.summary;
  const selectedPrinter =
    detectedPrinters.find((row) => row.printerId === selectedLocalPrinterId) ||
    detectedPrinters.find((row) => row.printerId === printerStatus.selectedPrinterId) ||
    detectedPrinters[0] ||
    null;
  const activePrinterId = String(printerStatus.selectedPrinterId || printerStatus.printerId || "").trim();
  const printerIdentity = derivePrinterIdentity({
    printerName: shouldUseManagedPrinterSummary ? preferredManagedNetworkPrinter?.name : printerStatus.printerName,
    selectedPrinterName: shouldUseManagedPrinterSummary ? preferredManagedNetworkPrinter?.name : printerStatus.selectedPrinterName,
    model: shouldUseManagedPrinterSummary ? preferredManagedNetworkPrinter?.model || null : selectedPrinter?.model || null,
    deviceName: shouldUseManagedPrinterSummary ? null : printerStatus.deviceName,
  });
  const printerFeedLabel = printerStatusLive ? "Live updates" : "Automatic refresh";
  const printerUpdatedLabel = formatPrinterTimestamp(printerStatusUpdatedAt || printerStatus.lastHeartbeatAt);
  const printerSummaryMessage = effectivePrinterReady
    ? shouldUseManagedPrinterSummary
      ? effectivePrinterDiagnostics.summary
      : `${printerIdentity.displayName} is ready to print.`
    : effectivePrinterDiagnostics.summary;
  const printerNextStep = effectivePrinterReady
    ? shouldUseManagedPrinterSummary
      ? "Open batches and choose the managed printer profile when you are ready to print."
      : "You can continue to batch operations."
    : effectivePrinterDiagnostics.nextSteps[0] || "Refresh printer status before starting a print job.";
  const selectedPrinterIsActive = Boolean(selectedPrinter && selectedPrinter.printerId === activePrinterId);
  const printerDiscoveryCountLabel =
    detectedPrinters.length === 1 ? "1 printer detected" : `${detectedPrinters.length} printers detected`;
  const printerOnboardingStorageKey =
    user?.role === "manufacturer" && user?.id
      ? `manufacturer-printer-onboarding:${PRINTER_ONBOARDING_STORAGE_VERSION}:${user.id}`
      : null;
  const openPrinterConnectionDialog = () => {
    setPrinterDialogOpen(true);
    void syncManufacturerPrinterStatus({ silent: true });
  };
  const openPrinterSetup = (options?: { managedProfiles?: boolean }) => {
    setPrinterDialogOpen(false);

    if (options?.managedProfiles) {
      navigate("/printer-diagnostics?managedProfiles=open");
      return;
    }

    if (location.pathname === "/printer-diagnostics") {
      return;
    }

    navigate("/printer-diagnostics");
  };
  const refreshPrinterConnectionStatus = () => {
    void syncManufacturerPrinterStatus({ silent: true });
  };

  useEffect(() => {
    if (!printerOnboardingStorageKey) return;
    if (!managedPrinterProfilesLoaded) return;
    if (printerReady || managedPrinterDiagnostics?.tone === "success") {
      try {
        window.localStorage.setItem(printerOnboardingStorageKey, "completed");
      } catch {
        // ignore storage failures
      }
      setPrinterOnboardingOpen(false);
      return;
    }
    if (managedNetworkPrinters.length > 0) {
      setPrinterOnboardingOpen(false);
      return;
    }

    let stored = "";
    try {
      stored = String(window.localStorage.getItem(printerOnboardingStorageKey) || "").trim().toLowerCase();
    } catch {
      stored = "";
    }
    if (!stored) {
      setPrinterOnboardingOpen(true);
    }
  }, [managedNetworkPrinters.length, managedPrinterDiagnostics?.tone, managedPrinterProfilesLoaded, printerOnboardingStorageKey, printerReady]);

  const dismissPrinterOnboarding = () => {
    if (printerOnboardingStorageKey) {
      try {
        window.localStorage.setItem(printerOnboardingStorageKey, "dismissed");
      } catch {
        // ignore storage failures
      }
    }
    setPrinterOnboardingOpen(false);
  };

  const reopenPrinterOnboarding = () => {
    if (printerOnboardingStorageKey) {
      try {
        window.localStorage.removeItem(printerOnboardingStorageKey);
      } catch {
        // ignore storage failures
      }
    }
    setPrinterOnboardingOpen(true);
  };

  return (
    <div className="min-h-screen bg-background">
      {sidebarOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/50 lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      <aside
        className={cn(
          "fixed top-0 left-0 z-50 h-full w-64 bg-sidebar text-sidebar-foreground transform transition-transform duration-200 ease-in-out lg:translate-x-0",
          sidebarOpen ? "translate-x-0" : "-translate-x-full"
        )}
      >
        <div className="flex h-full flex-col">
          <div className="flex h-16 items-center gap-2 px-6 border-b border-sidebar-border">
            <img src="/brand/mscqr-mark.svg" alt="MSCQR logo" className="h-8 w-8" />
            <span className="font-bold text-lg">MSCQR</span>
          </div>

          <nav className="flex-1 px-4 py-6 space-y-1 overflow-y-auto">
            {filteredNavItems.map((item) => {
              const isActive = location.pathname === item.href;
              return (
                <Link
                  key={item.href}
                  to={item.href}
                  onClick={() => setSidebarOpen(false)}
                  className={cn(
                    "flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-colors",
                    isActive
                      ? "bg-sidebar-primary text-sidebar-primary-foreground"
                      : "text-sidebar-foreground/70 hover:bg-sidebar-accent hover:text-sidebar-accent-foreground"
                  )}
                >
                  <item.icon className="h-5 w-5" />
                  {item.label}
                </Link>
              );
            })}
          </nav>

          <div className="border-t border-sidebar-border p-4">
            <div className="flex items-center gap-3 px-2 py-2">
              <div className="h-10 w-10 rounded-full bg-sidebar-accent flex items-center justify-center">
                <span className="text-sm font-semibold text-sidebar-accent-foreground">
                  {user?.name?.charAt(0) || "U"}
                </span>
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium truncate">{user?.name || "User"}</p>
                <p className="text-xs text-sidebar-foreground/60 truncate">{getRoleLabel(user?.role)}</p>
              </div>
            </div>
          </div>
        </div>
      </aside>

      <div className="lg:pl-64">
        {user?.role === "manufacturer" && (
          <Dialog open={printerOnboardingOpen} onOpenChange={setPrinterOnboardingOpen}>
            <DialogContent className="sm:max-w-[680px]">
              <DialogHeader>
                <DialogTitle>Set up printing on this workstation</DialogTitle>
                <DialogDescription>
                  Install the MSCQR Connector once on the printing computer. After that it starts automatically and MSCQR can detect the printer without any manual launch steps.
                </DialogDescription>
              </DialogHeader>

              <div className="space-y-4 text-sm text-slate-700">
                <div className="rounded-xl border border-amber-200 bg-amber-50 p-4">
                  <div className="font-semibold text-slate-950">What this does not do</div>
                  <p className="mt-2 leading-6">
                    The browser cannot install printers, drivers, or native apps by itself. Those remain workstation setup steps.
                  </p>
                </div>

                <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
                  <div className="font-semibold text-slate-950">What the manufacturer should do once per device</div>
                  <ol className="mt-3 list-decimal space-y-2 pl-5">
                    <li>Install or connect the printer in the operating system first.</li>
                    <li>Open <strong>Install Connector</strong> and download the Mac or Windows installer for that same device.</li>
                    <li>Run the installer once. The connector will auto-start at sign-in after that.</li>
                    <li>Return here and use <strong>Check again</strong>.</li>
                    <li>If the OS can see the printer, MSCQR will detect it and it will appear automatically.</li>
                  </ol>
                </div>

                <div className="rounded-xl border border-slate-200 bg-white p-4">
                  <div className="font-semibold text-slate-950">Current readiness</div>
                  <ul className="mt-3 list-disc space-y-2 pl-5">
                    <li>Connector online: {localPrinterAgent.reachable ? "Yes" : "No"}</li>
                    <li>Printer detected: {printerHasInventory ? "Yes" : "No"}</li>
                    <li>Selected printer: {printerStatus.selectedPrinterName || printerStatus.printerName || "None yet"}</li>
                  </ul>
                </div>

                <div className="flex flex-wrap gap-3">
                  <Button
                    variant="outline"
                    onClick={() => {
                      setPrinterOnboardingOpen(false);
                      navigate("/connector-download");
                    }}
                  >
                    Install Connector
                  </Button>
                  <Button
                    onClick={() => {
                      void syncManufacturerPrinterStatus({ silent: true });
                    }}
                  >
                    Check again
                  </Button>
                  <Button
                    variant="outline"
                    onClick={() => {
                      setPrinterOnboardingOpen(false);
                      openPrinterConnectionDialog();
                    }}
                  >
                    Open Printer Setup
                  </Button>
                  <Button variant="ghost" onClick={() => navigate(contextualHelpRoute)}>
                    Open Help
                  </Button>
                  <Button variant="ghost" onClick={dismissPrinterOnboarding}>
                    Close for now
                  </Button>
                </div>
              </div>
            </DialogContent>
          </Dialog>
        )}

        <header className="sticky top-0 z-30 h-16 bg-card border-b border-border flex items-center justify-between px-4 lg:px-6">
          <button
            onClick={() => setSidebarOpen(true)}
            className="lg:hidden p-2 rounded-md hover:bg-muted"
            aria-label="Open sidebar"
          >
            <Menu className="h-6 w-6" />
          </button>

          <div className="flex-1" />

          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button
                variant="ghost"
                size="icon"
                className="relative mr-1 overflow-visible rounded-full border-white/50 bg-white/65 shadow-[0_12px_22px_-18px_rgba(15,23,42,0.45)] dark:border-white/10 dark:bg-white/5"
                aria-label="Open notifications"
              >
                <Bell className="h-4 w-4 text-muted-foreground" />
                {unreadNotifications > 0 ? (
                  <span className="pointer-events-none absolute -right-1.5 -top-1.5 z-20 inline-flex min-h-5 min-w-5 items-center justify-center rounded-full border-2 border-card bg-emerald-500 px-1.5 text-[10px] font-bold leading-none text-white shadow-[0_14px_20px_-14px_rgba(16,185,129,0.95),0_0_0_1px_rgba(16,185,129,0.25)] ring-1 ring-emerald-300/30 dark:border-slate-900">
                    {unreadNotifications > 9 ? "9+" : unreadNotifications}
                  </span>
                ) : null}
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent
              align="end"
              sideOffset={10}
              className="w-[92vw] max-w-[27rem] rounded-2xl border border-white/35 bg-white/78 p-0 text-foreground shadow-[0_26px_60px_-28px_rgba(2,6,23,0.48),0_18px_28px_-22px_rgba(15,23,42,0.35)] backdrop-blur-2xl dark:border-white/10 dark:bg-slate-950/78"
            >
              <div className="relative overflow-hidden rounded-2xl">
                <div className="pointer-events-none absolute inset-x-0 top-0 h-24 bg-[linear-gradient(180deg,rgba(16,185,129,0.12),rgba(59,130,246,0.04),transparent)]" />

                <div className="relative border-b border-white/25 px-4 py-3 dark:border-white/10">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <p className="text-base font-semibold tracking-tight">Notifications</p>
                        <span className="inline-flex h-6 items-center rounded-full border border-white/40 bg-white/45 px-2 text-[11px] font-medium text-foreground/80 dark:border-white/10 dark:bg-white/5 dark:text-foreground/70">
                          {visibleNotifications.length}
                        </span>
                      </div>
                      <div className="mt-1 flex flex-wrap items-center gap-2 text-[11px] text-muted-foreground">
                        <span className="inline-flex items-center gap-1.5 rounded-full border border-white/35 bg-white/45 px-2 py-0.5 dark:border-white/10 dark:bg-white/5">
                          <span
                            className={cn(
                              "inline-block h-2 w-2 rounded-full transition-colors",
                              notificationsLive ? "bg-emerald-500 shadow-[0_0_0_3px_rgba(16,185,129,0.12)]" : "bg-slate-300"
                            )}
                          />
                          {notificationsLive ? "Live feed active" : "Polling mode"}
                        </span>
                        {hasVisibleNotifications ? (
                          <span className="rounded-full border border-white/25 bg-white/35 px-2 py-0.5 dark:border-white/10 dark:bg-white/5">
                            Showing {timelineVisibleStart}-{timelineVisibleEnd} of {visibleNotifications.length}
                          </span>
                        ) : null}
                      </div>
                    </div>

                    <Button
                      variant="outline"
                      size="sm"
                      className="h-8 rounded-full px-3 text-[11px]"
                      disabled={notificationsLoading || unreadNotifications === 0}
                      onClick={handleMarkAllNotificationsRead}
                    >
                      <Sparkles className="h-3.5 w-3.5" />
                      Mark all read
                    </Button>
                  </div>

                  <div className="mt-3 rounded-xl border border-white/25 bg-white/40 p-3 dark:border-white/10 dark:bg-white/5">
                    <div className="mb-2 flex items-center justify-between text-[11px] font-medium text-muted-foreground">
                      <div className="inline-flex items-center gap-1.5">
                        <SlidersHorizontal className="h-3.5 w-3.5" />
                        Recent
                      </div>
                      <span className="text-foreground/80 dark:text-foreground/70">
                        {hasVisibleNotifications ? `${timelineVisibleStart}-${timelineVisibleEnd}` : "0"}
                      </span>
                      <span>Older</span>
                    </div>

                    <div className="flex items-center gap-2">
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-8 w-8 rounded-full"
                        disabled={!canMoveTimelineToNewer || notificationsLoading || clearingNotifications}
                        onClick={() => stepNotificationTimeline("newer")}
                        aria-label="Move toward most recent notifications"
                      >
                        <ChevronLeft className="h-3.5 w-3.5" />
                      </Button>
                      <Slider
                        value={[notificationWindowStart]}
                        min={0}
                        max={Math.max(notificationTimelineMax, 1)}
                        step={1}
                        disabled={notificationTimelineMax === 0 || notificationsLoading || clearingNotifications}
                        onValueChange={(value) => {
                          const next = Math.max(0, Math.min(notificationTimelineMax, Number(value?.[0] ?? 0)));
                          setNotificationWindowStart(next);
                        }}
                        className="flex-1"
                        aria-label="Notification timeline from recent to older"
                      />
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-8 w-8 rounded-full"
                        disabled={!canMoveTimelineToOlder || notificationsLoading || clearingNotifications}
                        onClick={() => stepNotificationTimeline("older")}
                        aria-label="Move toward older notifications"
                      >
                        <ChevronRight className="h-3.5 w-3.5" />
                      </Button>
                    </div>
                  </div>
                </div>

                <div className="relative p-3 pt-2">
                  <div className="relative rounded-2xl border border-white/25 bg-white/38 p-2 shadow-[0_10px_24px_-20px_rgba(15,23,42,0.35)] dark:border-white/10 dark:bg-white/5">
                    <div className="pointer-events-none absolute inset-x-4 top-0 h-10 bg-gradient-to-b from-white/35 to-transparent dark:from-white/5" />

                    <div className="relative min-h-[18.5rem] pb-16">
                      {notificationsLoading ? (
                        <div className="space-y-2 p-1">
                          {Array.from({ length: 4 }).map((_, index) => (
                            <div
                              key={`notification-skeleton-${index}`}
                              className="rounded-xl border border-white/20 bg-white/55 p-3 dark:border-white/10 dark:bg-white/5"
                            >
                              <div className="h-4 w-2/3 animate-pulse rounded bg-slate-200/80 dark:bg-slate-700/70" />
                              <div className="mt-2 h-3 w-full animate-pulse rounded bg-slate-200/70 dark:bg-slate-700/60" />
                              <div className="mt-1 h-3 w-5/6 animate-pulse rounded bg-slate-200/60 dark:bg-slate-700/50" />
                              <div className="mt-2 h-3 w-1/3 animate-pulse rounded bg-slate-200/60 dark:bg-slate-700/50" />
                            </div>
                          ))}
                        </div>
                      ) : hasVisibleNotifications ? (
                        <div
                          key={`${notificationMotionSeed}-${notificationWindowStart}-${visibleNotifications.length}`}
                          className="space-y-2 p-1 animate-in fade-in-0 slide-in-from-bottom-1 duration-200"
                        >
                          {notificationItems.map((item, index) => {
                            const isUnread = isNotificationUnread(item);
                            const itemId = String(item.id);
                            const isClearingItem = clearingNotificationIdSet.has(itemId);
                            const tone = notificationToneClasses(item);
                            const copy = notificationCopy(item);

                            return (
                              <div
                                key={itemId}
                                className={cn(
                                  "overflow-hidden transition-[max-height,opacity,transform,margin] duration-300 ease-out",
                                  isClearingItem ? "max-h-0 opacity-0 -translate-y-2" : "max-h-56 opacity-100 translate-y-0"
                                )}
                                style={{ transitionDelay: isClearingItem ? `${index * 24}ms` : undefined }}
                              >
                                <DropdownMenuItem
                                  disabled={isClearingItem || clearingNotifications}
                                  onClick={async () => {
                                    await markNotificationRead(item.id);
                                    navigate(notificationTarget(item));
                                  }}
                                  className={cn(
                                    "group relative flex cursor-pointer flex-col items-start gap-1.5 rounded-xl border px-3 py-3 pr-10 transition-all duration-200 ease-out focus-visible:ring-1 focus-visible:ring-emerald-300/60",
                                    tone.border,
                                    tone.glow,
                                    isUnread
                                      ? "bg-white/80 hover:bg-white/95 dark:bg-slate-900/70 dark:hover:bg-slate-900/90"
                                      : "bg-white/55 hover:bg-white/75 dark:bg-slate-900/45 dark:hover:bg-slate-900/70"
                                  )}
                                >
                                  <span
                                    className={cn(
                                      "absolute inset-y-2 left-0 w-1 rounded-r-full transition-opacity",
                                      tone.accent,
                                      isUnread ? "opacity-100" : "opacity-35"
                                    )}
                                  />
                                  <div className="flex w-full items-start justify-between gap-2 pl-2">
                                    <p className={cn("line-clamp-1 text-sm font-semibold tracking-tight", isUnread ? "text-foreground" : "text-foreground/90")}>
                                      {copy.title}
                                    </p>
                                    <span
                                      className={cn(
                                        "inline-flex h-5 shrink-0 items-center rounded-full border px-1.5 text-[10px] font-semibold uppercase tracking-wide",
                                        isUnread
                                          ? tone.chip
                                          : "border-white/30 bg-white/40 text-muted-foreground dark:border-white/10 dark:bg-white/5"
                                      )}
                                    >
                                      {isUnread ? "New" : "Read"}
                                    </span>
                                  </div>

                                  <p className="line-clamp-2 pl-2 text-xs leading-5 text-muted-foreground">{copy.body}</p>
                                  <p className="pl-2 text-[11px] font-medium text-muted-foreground/90">{formatNotificationDate(item.createdAt)}</p>
                                </DropdownMenuItem>
                              </div>
                            );
                          })}
                        </div>
                      ) : (
                        <div className="flex min-h-[18.5rem] items-center justify-center p-3 animate-in fade-in-0 slide-in-from-bottom-1 duration-200">
                          <div className="w-full rounded-2xl border border-dashed border-white/30 bg-white/50 px-4 py-8 text-center dark:border-white/10 dark:bg-white/5">
                            <div className="mx-auto mb-3 flex h-12 w-12 items-center justify-center rounded-2xl border border-white/40 bg-white/70 text-emerald-600 shadow-[0_10px_24px_-18px_rgba(16,185,129,0.55)] dark:border-white/10 dark:bg-white/5 dark:text-emerald-300">
                              <Inbox className="h-5 w-5" />
                            </div>
                            <p className="text-sm font-semibold tracking-tight">
                              {notificationPanelCleared ? "Notifications cleared" : "No notifications right now"}
                            </p>
                            <p className="mt-1 text-xs leading-5 text-muted-foreground">
                              {notificationPanelCleared
                                ? "New alerts will appear here automatically as activity happens."
                                : "Your latest alerts, policy events, and incident updates will appear here."}
                            </p>
                          </div>
                        </div>
                      )}
                    </div>

                    <div className="pointer-events-none absolute inset-x-0 bottom-0 h-20 rounded-b-2xl bg-gradient-to-t from-white/75 via-white/40 to-transparent dark:from-slate-950/70 dark:via-slate-950/30" />

                    <div className="absolute bottom-3 right-3 flex items-center gap-2">
                      <Button
                        variant="outline"
                        size="sm"
                        className="h-10 rounded-full border-white/45 bg-white/75 px-3.5 text-xs font-semibold shadow-[0_16px_24px_-16px_rgba(15,23,42,0.5)] dark:border-white/15 dark:bg-slate-900/70"
                        disabled={!canClearNotifications}
                        onClick={handleClearNotifications}
                        aria-label="Clear notifications from the panel"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                        {clearingNotifications ? "Clearing..." : "Clear notifications"}
                      </Button>
                    </div>
                  </div>
                </div>
              </div>
            </DropdownMenuContent>
          </DropdownMenu>

          {user?.role === "manufacturer" && (
            <Button
              variant="outline"
              size="sm"
              onClick={openPrinterConnectionDialog}
              className={cn("mr-1 gap-2", printerToneClass)}
              title={printerTitle}
            >
              <Printer className="h-4 w-4" />
              <span className="hidden md:inline">
                {`Printer ${printerModeLabel}`}
              </span>
              <span className="md:hidden">{printerModeLabel}</span>
            </Button>
          )}

          {user?.role === "manufacturer" && !effectivePrinterReady && managedNetworkPrinters.length === 0 && (
            <Button variant="ghost" size="sm" onClick={() => navigate("/connector-download")} className="mr-1 hidden md:inline-flex">
              Install Connector
            </Button>
          )}

          {user?.role === "manufacturer" && managedNetworkPrinters.length > 0 && (
            <Button variant="ghost" size="sm" onClick={() => navigate("/printer-diagnostics")} className="mr-1 hidden md:inline-flex">
              Printer Setup
            </Button>
          )}

          <SupportIssueLauncher />

          <Button asChild variant="ghost" className="mr-1 gap-2">
            <Link to={contextualHelpRoute}>
              <CircleHelp className="h-4 w-4 text-muted-foreground" />
              <span className="hidden sm:inline">Help</span>
            </Link>
          </Button>

          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" className="gap-2">
                <div className="h-8 w-8 rounded-full bg-primary/10 flex items-center justify-center">
                  <span className="text-sm font-semibold text-primary">
                    {user?.name?.charAt(0) || "U"}
                  </span>
                </div>
                <span className="hidden sm:inline">{user?.name || "User"}</span>
                <ChevronDown className="h-4 w-4 text-muted-foreground" />
              </Button>
            </DropdownMenuTrigger>

            <DropdownMenuContent align="end" className="w-56">
              <div className="px-3 py-2">
                <p className="text-sm font-medium">{user?.name}</p>
                <p className="text-xs text-muted-foreground">{user?.email}</p>
              </div>

              <DropdownMenuSeparator />

              <DropdownMenuItem onClick={() => navigate("/account")}>
                <Settings className="mr-2 h-4 w-4" />
                Account
              </DropdownMenuItem>

              <DropdownMenuSeparator />

              <DropdownMenuItem onClick={handleLogout} className="text-destructive">
                <LogOut className="mr-2 h-4 w-4" />
                Log out
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </header>

        {user?.role === "manufacturer" && (
          <Dialog open={printerDialogOpen} onOpenChange={setPrinterDialogOpen}>
            <DialogContent className="max-h-[88vh] overflow-y-auto sm:max-w-[860px]">
              <DialogHeader>
                <DialogTitle>Printing Status</DialogTitle>
                <DialogDescription>
                  Review live printer readiness, switch workstation printers when needed, and keep managed `NETWORK_DIRECT` and `NETWORK_IPP` routes visible before you print.
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
                            {selectedPrinter?.online === false && !shouldUseManagedPrinterSummary && <Badge variant="destructive">Offline</Badge>}
                            {shouldUseManagedPrinterSummary && preferredManagedNetworkPrinter && (
                              <Badge variant="secondary">{getPrinterDispatchLabel(preferredManagedNetworkPrinter)}</Badge>
                            )}
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
                        </div>
                      </div>

                      <div className="grid gap-2 text-xs text-slate-600 sm:min-w-[15rem]">
                        <div className="rounded-xl border border-white/80 bg-white/85 px-3 py-2">
                          <div className="font-medium text-slate-500">Active printer</div>
                          <div className="mt-1 font-semibold text-slate-900">
                            {shouldUseManagedPrinterSummary
                              ? preferredManagedNetworkPrinter?.name || "Managed printer"
                              : printerStatus.selectedPrinterName || printerStatus.printerName || "Not selected"}
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
                      <div className={cn("inline-flex items-center gap-2 rounded-full px-3 py-1 text-xs font-medium", printerStatusLive ? "bg-emerald-50 text-emerald-700" : "bg-slate-100 text-slate-700")}>
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
                          <div className="text-xs text-slate-600">{formatPrinterAge(printerStatus.ageSeconds)}</div>
                        </div>
                      </div>
                      <div className="flex items-start gap-3 rounded-xl border border-slate-200 bg-slate-50 px-3 py-2.5">
                        {effectivePrinterReady ? <CheckCircle2 className="mt-0.5 h-4 w-4 text-emerald-600" /> : <AlertTriangle className="mt-0.5 h-4 w-4 text-amber-600" />}
                        <div>
                          <div className="font-medium text-slate-900">Current state</div>
                          <div className="text-xs text-slate-600">{effectivePrinterDiagnostics.badgeLabel}</div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>

                {managedNetworkPrinters.length > 0 && (
                  <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
                    <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                      <div>
                        <div className="text-xs font-semibold uppercase tracking-[0.22em] text-slate-500">Managed network routes</div>
                        <div className="mt-1 text-lg font-semibold text-slate-950">
                          {managedNetworkPrinters.length === 1 ? "1 managed printer route" : `${managedNetworkPrinters.length} managed printer routes`}
                        </div>
                        <p className="mt-1 text-sm text-slate-600">
                          These saved `NETWORK_DIRECT` and `NETWORK_IPP` routes print through MSCQR without depending on the workstation printer list.
                        </p>
                      </div>
                      <Button variant="outline" onClick={() => openPrinterSetup({ managedProfiles: true })}>
                        Manage profiles
                      </Button>
                    </div>

                    <div className="mt-4 grid gap-3 md:grid-cols-2">
                      {managedNetworkPrinters.slice(0, 4).map((printer) => {
                        const statusState = printer.registryStatus?.state || "ATTENTION";
                        const statusVariant = statusState === "READY" ? "default" : statusState === "BLOCKED" || statusState === "OFFLINE" ? "destructive" : "secondary";

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
                                "Open Printer Setup to check, update, or remove this managed route."
                              )}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}

                <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
                  <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-[0.22em] text-slate-500">Printer roster</div>
                      <div className="mt-1 text-lg font-semibold text-slate-950">
                        {detectedPrinters.length > 0 ? printerDiscoveryCountLabel : "No printer connection detected"}
                      </div>
                      <p className="mt-1 text-sm text-slate-600">
                        Review the printers available on this workstation and choose the one you want MSCQR to use.
                      </p>
                    </div>
                    <Button variant="outline" className="gap-2" onClick={refreshPrinterConnectionStatus} disabled={printerSwitching}>
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
                          ? "The workstation connector is not reporting a local printer right now, but your managed network routes are still available above and in Printer Setup."
                          : "MSCQR could not find a ready printer on this workstation. Make sure the printer is available in the operating system, then refresh the connection status."}
                      </p>
                      <div className="mt-4 flex flex-wrap gap-3">
                        <Button onClick={refreshPrinterConnectionStatus} disabled={printerSwitching}>
                          Refresh status
                        </Button>
                        <Button variant="outline" onClick={() => navigate("/batches")}>
                          Open batches
                        </Button>
                        <Button variant="outline" onClick={openPrinterSetup}>
                          Open printer setup
                        </Button>
                        <Button variant="ghost" onClick={() => navigate(contextualHelpRoute)}>
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
                          deviceName: printerStatus.deviceName,
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
                                onClick={() => setSelectedLocalPrinterId(row.printerId)}
                              >
                                <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-2xl border border-white bg-white text-sm font-semibold tracking-[0.2em] text-slate-700">
                                  {rowIdentity.monogram}
                                </div>
                                <div className="min-w-0">
                                  <div className="flex flex-wrap items-center gap-2">
                                    <div className="truncate font-semibold text-slate-950">{row.printerName}</div>
                                    {isActive && <Badge variant="default">Active</Badge>}
                                    {row.online === false && <Badge variant="destructive">Offline</Badge>}
                                  </div>
                                  <div className="mt-1 text-xs text-slate-600">
                                    {rowIdentity.vendor}
                                    {row.model ? ` · ${row.model}` : ""}
                                    {row.connection ? ` · ${row.connection}` : ""}
                                  </div>
                                  <div className="mt-2 text-xs text-slate-500">
                                    {row.languages?.join(", ") || "AUTO"} · {row.mediaSizes?.join(", ") || "Auto media"}
                                  </div>
                                </div>
                              </button>

                              <Button
                                size="sm"
                                variant={isActive ? "secondary" : "outline"}
                                disabled={printerSwitching || isActive}
                                onClick={() => void switchLocalPrinter(row.printerId)}
                              >
                                {isActive ? "Active printer" : "Make active"}
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
                      <Select value={selectedLocalPrinterId} onValueChange={setSelectedLocalPrinterId}>
                        <SelectTrigger className="md:w-[24rem]">
                          <SelectValue placeholder="Select connected printer" />
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
                        onClick={() => void switchLocalPrinter()}
                      >
                        {printerSwitching ? "Switching..." : "Switch printer"}
                      </Button>
                      <Button size="sm" variant="ghost" onClick={() => navigate("/batches")}>
                        Open batches
                      </Button>
                    </div>
                  </div>
                </div>

                <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
                  <div className="text-sm font-semibold text-slate-950">Need setup help?</div>
                  <p className="mt-1 text-sm text-slate-600">
                    Use Printer Setup & Support to validate managed network routes or workstation printers, then return here for live status and final checks before batch printing.
                  </p>
                  <div className="mt-4 flex flex-wrap gap-2">
                    <Button variant="outline" onClick={openPrinterSetup}>
                      Open printer setup
                    </Button>
                    {managedNetworkPrinters.length === 0 && (
                      <Button variant="outline" onClick={() => navigate("/connector-download")}>
                        Install Connector
                      </Button>
                    )}
                    <Button variant="ghost" onClick={() => navigate(contextualHelpRoute)}>
                      Open help
                    </Button>
                  </div>
                </div>

                <div className="flex flex-wrap justify-end gap-2">
                  <Button variant="outline" onClick={openPrinterSetup}>
                    Open printer setup
                  </Button>
                  <Button variant="outline" onClick={() => navigate(contextualHelpRoute)}>
                    Open help
                  </Button>
                  <Button variant="outline" onClick={() => setPrinterDialogOpen(false)}>
                    Close
                  </Button>
                  <Button variant="outline" className="gap-2" onClick={refreshPrinterConnectionStatus} disabled={printerSwitching}>
                    <RefreshCw className="h-4 w-4" />
                    Refresh status
                  </Button>
                </div>
              </div>
            </DialogContent>
          </Dialog>
        )}

        <main className="p-4 lg:p-6">{children}</main>
        <footer className="px-4 pb-6 lg:px-6">
          <div className="text-center text-xs text-muted-foreground">
            Need guidance on this page?{" "}
            <Link to={contextualHelpRoute} className="text-foreground underline-offset-4 hover:underline">
              Open the relevant help section
            </Link>
            .
          </div>
        </footer>
      </div>
    </div>
  );
}
