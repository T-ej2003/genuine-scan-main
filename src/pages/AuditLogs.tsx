import React, { useEffect, useMemo, useState } from "react";
import { format } from "date-fns";
import { Activity, AlertTriangle, Ban, CheckCircle2, ChevronDown, ChevronUp, Mail, RefreshCw, Search, ShieldAlert } from "lucide-react";

import { DashboardLayout } from "@/components/layout/DashboardLayout";
import apiClient from "@/lib/api-client";
import { useAuth } from "@/contexts/AuthContext";
import { onMutationEvent } from "@/lib/mutation-events";
import { useToast } from "@/hooks/use-toast";
import { sanitizePrinterUiError } from "@/lib/printer-user-facing";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";

type FraudStatus = "OPEN" | "REVIEWED" | "RESOLVED" | "DISMISSED";
type FraudResponseStatus = Exclude<FraudStatus, "OPEN">;

type FraudReportQueueItem = {
  id: string;
  createdAt: string;
  licenseeId?: string | null;
  status: FraudStatus;
  report: {
    code?: string | null;
    reason?: string | null;
    notes?: string | null;
    contactEmail?: string | null;
    observedStatus?: string | null;
    observedOutcome?: string | null;
    pageUrl?: string | null;
    ipAddress?: string | null;
  };
  response?: {
    id: string;
    createdAt: string;
    message?: string | null;
    notifyCustomer?: boolean;
    recipientEmail?: string | null;
    delivery?: { delivered?: boolean; reason?: string | null } | null;
    actorUserId?: string | null;
  } | null;
};

const ACTION_TONES: Array<{ test: RegExp; className: string; icon: React.ReactNode }> = [
  { test: /BLOCK|FRAUD|VERIFY_FAILED|REJECT/i, className: "border-red-200 bg-red-50 text-red-700", icon: <Ban className="mr-1 h-3 w-3" /> },
  { test: /WARNING|SUSPICIOUS|REDEEMED|ALLOCATE|DELETE/i, className: "border-amber-200 bg-amber-50 text-amber-700", icon: <AlertTriangle className="mr-1 h-3 w-3" /> },
  { test: /CREATE|APPROVE|LOGIN|VERIFY_SUCCESS|PRINT|RESTORE|UPDATE/i, className: "border-emerald-200 bg-emerald-50 text-emerald-700", icon: <CheckCircle2 className="mr-1 h-3 w-3" /> },
];

const FRAUD_STATUS_TONE: Record<FraudStatus, string> = {
  OPEN: "border-red-200 bg-red-50 text-red-700",
  REVIEWED: "border-amber-200 bg-amber-50 text-amber-700",
  RESOLVED: "border-emerald-200 bg-emerald-50 text-emerald-700",
  DISMISSED: "border-slate-300 bg-slate-100 text-slate-700",
};

const actionTone = (action: string) => {
  const hit = ACTION_TONES.find((t) => t.test.test(action));
  return hit || { className: "border-slate-300 bg-slate-100 text-slate-700", icon: <Activity className="mr-1 h-3 w-3" /> };
};

const asObject = (value: unknown): Record<string, any> => {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  return value as Record<string, any>;
};

const humanKey = (key: string) =>
  key
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/_/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/\b\w/g, (c) => c.toUpperCase());

const toLabel = (value: string) =>
  String(value || "")
    .toLowerCase()
    .replace(/_/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());

const PRINTER_AUDIT_ACTION_LABELS: Record<string, string> = {
  PRINTER_CONNECTION_COMPAT_MODE_ONLINE: "Printer connected in recovery mode",
  PRINTER_CONNECTION_TRUSTED_ONLINE: "Printer connected",
  PRINTER_CONNECTION_UNTRUSTED_OR_OFFLINE: "Printer connection needs attention",
};

const formatAuditActionLabel = (value?: string | null) =>
  PRINTER_AUDIT_ACTION_LABELS[String(value || "").trim().toUpperCase()] || String(value || "");

const isPrinterAuditEntry = (log: any) =>
  String(log?.entityType || "").trim().toLowerCase() === "printeragent" ||
  String(log?.action || "").trim().toUpperCase().startsWith("PRINTER_CONNECTION_");

const formatAuditDetailValue = (log: any, key: string, rawValue: unknown) => {
  if (rawValue == null || rawValue === "") return "";

  if (typeof rawValue === "boolean") {
    return rawValue ? "Yes" : "No";
  }

  const normalizedKey = String(key || "").trim().toLowerCase();
  if (isPrinterAuditEntry(log) && ["error", "trustreason", "compatibilityreason"].includes(normalizedKey)) {
    return sanitizePrinterUiError(String(rawValue), "Printer connection needs attention.");
  }
  if (isPrinterAuditEntry(log) && normalizedKey === "connectionclass") {
    const value = String(rawValue || "").trim().toUpperCase();
    if (value === "TRUSTED") return "Trusted";
    if (value === "COMPATIBILITY") return "Recovery mode";
    if (value === "BLOCKED") return "Blocked";
  }
  if (Array.isArray(rawValue)) {
    if (rawValue.length === 0) return "";
    if (rawValue.every((item) => item && typeof item === "object")) {
      return rawValue
        .map((item) => {
          const row = item as Record<string, unknown>;
          return String(row.printerName || row.name || row.printerId || row.id || "").trim();
        })
        .filter(Boolean)
        .join(", ");
    }
    return rawValue.map((value) => String(value)).join(", ");
  }

  return String(rawValue);
};

const readableDetailEntries = (log: any, details: Record<string, any>) => {
  const entries: Array<{ label: string; value: string }> = [];
  for (const [key, rawValue] of Object.entries(details || {})) {
    if (rawValue == null || rawValue === "") continue;
    if (typeof rawValue === "object" && !Array.isArray(rawValue)) {
      const nested = Object.entries(rawValue)
        .filter(([, v]) => v != null && v !== "")
        .map(([nestedKey, nestedValue]) => `${humanKey(nestedKey)}: ${formatAuditDetailValue(log, nestedKey, nestedValue)}`);
      if (nested.length > 0) entries.push({ label: humanKey(key), value: nested.join(" • ") });
      continue;
    }
    const formattedValue = formatAuditDetailValue(log, key, rawValue);
    if (!formattedValue) continue;
    entries.push({ label: humanKey(key), value: formattedValue });
  }
  return entries;
};

export default function AuditLogs() {
  const { user } = useAuth();
  const { toast } = useToast();

  const [logs, setLogs] = useState<any[]>([]);
  const [search, setSearch] = useState("");
  const [action, setAction] = useState("all");
  const [live, setLive] = useState(true);
  const [licensees, setLicensees] = useState<any[]>([]);
  const [licenseeFilter, setLicenseeFilter] = useState<string>("all");
  const [expandedRows, setExpandedRows] = useState<Record<string, boolean>>({});

  const [fraudStatusFilter, setFraudStatusFilter] = useState<"ALL" | FraudStatus>("OPEN");
  const [fraudReports, setFraudReports] = useState<FraudReportQueueItem[]>([]);
  const [fraudLoading, setFraudLoading] = useState(false);

  const [respondDialogOpen, setRespondDialogOpen] = useState(false);
  const [selectedFraudReport, setSelectedFraudReport] = useState<FraudReportQueueItem | null>(null);
  const [responseStatus, setResponseStatus] = useState<FraudResponseStatus>("REVIEWED");
  const [responseMessage, setResponseMessage] = useState("");
  const [notifyCustomer, setNotifyCustomer] = useState(true);
  const [responding, setResponding] = useState(false);

  const isSuperAdmin = user?.role === "super_admin";

  const summarizeDetails = (log: any) => {
    const d = asObject(log?.details);
    if (typeof log?.details === "string") return log.details;
    if (!d || Object.keys(d).length === 0) return "—";

    const actionCode = String(log?.action || "").toUpperCase();
    const range =
      d.startCode || d.endCode
        ? `${d.startCode || "?"}–${d.endCode || "?"}`
        : d.startNumber || d.endNumber
        ? `${d.startNumber || "?"}–${d.endNumber || "?"}`
        : null;

    switch (actionCode) {
      case "DIRECT_PRINT_TOKEN_ISSUED":
        return `Issued ${d.issuedCount || d.count || "secure"} direct-print token(s)${d.expiresAt ? ` (expires ${d.expiresAt})` : ""}.`;
      case "VERIFY_FAILED":
        return `Verification failed${d.reason ? `: ${d.reason}` : "."}`;
      case "VERIFY_SUCCESS":
        return `Verification succeeded${d.isFirstScan ? " (first scan)" : ""}${d.scanCount != null ? `; scan count ${d.scanCount}` : ""}.`;
      case "PRINTED":
        if (String(d.mode || "").toUpperCase() === "DIRECT_PRINT") {
          return `Secure direct-print rendered${d.code ? ` for ${d.code}` : ""}${d.remainingToPrint != null ? `; ${d.remainingToPrint} remaining` : ""}.`;
        }
        return `Print completed${d.printedCodes != null ? ` (${d.printedCodes} codes)` : ""}.`;
      case "CUSTOMER_FRAUD_REPORT":
        return `Fraud report for ${d.code || "—"}${d.reason ? ` (${d.reason})` : ""}.`;
      case "CUSTOMER_FRAUD_REPORT_RESPONSE":
        return `Fraud report ${d.status || "REVIEWED"}${d.notifyCustomer ? "; customer notified" : "; customer not notified"}.`;
      case "CUSTOMER_PRODUCT_FEEDBACK":
        return `Customer feedback for ${d.code || "—"}: ${d.rating || "—"}★, ${d.satisfaction || "unlabeled"}.`;
      case "INCIDENT_CREATED":
        return `Incident created for ${d.qrCodeValue || "unknown code"} (${toLabel(String(d.incidentType || "other"))}).`;
      case "INCIDENT_UPDATED":
        return `Incident updated${Array.isArray(d.changedFields) ? ` (${d.changedFields.join(", ")})` : ""}.`;
      case "INCIDENT_NOTE_ADDED":
        return "Investigation note added.";
      case "INCIDENT_EVIDENCE_ADDED":
        return "Evidence attached to incident.";
      case "INCIDENT_EMAIL_SENT":
        return `Incident email ${String(d.status || "processed").toLowerCase()}${d.toAddress ? ` to ${d.toAddress}` : ""}.`;
      case "ALLOCATE_QR_RANGE":
      case "ALLOCATE_QR_RANGE_LICENSEE":
        return `Allocated QR range ${range || "—"}${d.created || d.quantity ? ` (${d.created || d.quantity} codes)` : ""}.`;
      case "PRINTER_CONNECTION_COMPAT_MODE_ONLINE":
        return "Printer connected in recovery mode while advanced secure verification is still being set up.";
      case "PRINTER_CONNECTION_TRUSTED_ONLINE":
        return "Printer connected and trusted for secure printing.";
      case "PRINTER_CONNECTION_UNTRUSTED_OR_OFFLINE":
        return "Printer connection needs attention before secure printing can continue.";
      default: {
        const name = d.name || d.batchName || d.licenseeName || d.manufacturerName || null;
        const parts: string[] = [];
        if (name) parts.push(`name ${name}`);
        if (d.quantity) parts.push(`qty ${d.quantity}`);
        if (range) parts.push(`range ${range}`);
        if (d.manufacturerId) parts.push(`manufacturer ${d.manufacturerId}`);
        if (d.licenseeId) parts.push(`licensee ${d.licenseeId}`);
        return parts.length ? parts.join(" • ") : "Activity recorded.";
      }
    }
  };

  const userLabel = (log: any) => {
    const id = log?.user?.id || log?.userId;
    if (log?.user?.name) {
      const email = log.user.email ? ` • ${log.user.email}` : "";
      return `${log.user.name}${email}${id ? ` • ${id}` : ""}`;
    }
    if (log?.user?.email) return `${log.user.email}${id ? ` • ${id}` : ""}`;
    if (id) return id;
    return "System";
  };

  const load = async () => {
    const res = await apiClient.getAuditLogs({
      limit: 150,
      licenseeId: isSuperAdmin && licenseeFilter !== "all" ? licenseeFilter : undefined,
    });

    if (!res.success) {
      setLogs([]);
      return;
    }

    const payload: any = res.data;
    const list = Array.isArray(payload)
      ? payload
      : Array.isArray(payload?.logs)
      ? payload.logs
      : Array.isArray(payload?.data)
      ? payload.data
      : [];
    setLogs(list);
  };

  const loadFraudReports = async (opts?: { silent?: boolean }) => {
    if (!isSuperAdmin) return;
    if (!opts?.silent) setFraudLoading(true);

    try {
      const res = await apiClient.getFraudReports({
        status: fraudStatusFilter,
        licenseeId: licenseeFilter !== "all" ? licenseeFilter : undefined,
        limit: 100,
      });
      if (!res.success) {
        setFraudReports([]);
        return;
      }
      const payload: any = res.data;
      const list = Array.isArray(payload) ? payload : Array.isArray(payload?.reports) ? payload.reports : [];
      setFraudReports(list);
    } finally {
      if (!opts?.silent) setFraudLoading(false);
    }
  };

  const refreshAll = async () => {
    await Promise.all([load(), loadFraudReports()]);
  };

  useEffect(() => {
    refreshAll();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [licenseeFilter, fraudStatusFilter, isSuperAdmin]);

  useEffect(() => {
    const off = onMutationEvent(() => {
      refreshAll();
    });
    return off;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [licenseeFilter, fraudStatusFilter, isSuperAdmin]);

  useEffect(() => {
    if (!isSuperAdmin) return;
    apiClient.getLicensees().then((res) => {
      if (res.success) setLicensees((res.data as any[]) || []);
    });
  }, [isSuperAdmin]);

  useEffect(() => {
    if (!live) return;
    const stop = apiClient.streamAuditLogs(
      (log) => {
        if (isSuperAdmin && licenseeFilter !== "all" && log.licenseeId !== licenseeFilter) return;
        setLogs((prev) => [log, ...prev].slice(0, 200));
        if (isSuperAdmin && (log.action === "CUSTOMER_FRAUD_REPORT" || log.action === "CUSTOMER_FRAUD_REPORT_RESPONSE")) {
          loadFraudReports({ silent: true });
        }
      },
      () => {
        setLive(false);
        toast({
          title: "Live audit stream unavailable",
          description: "Realtime updates were paused. Use Refresh to reload latest logs.",
          variant: "destructive",
        });
      }
    );
    return stop;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [live, licenseeFilter, isSuperAdmin, fraudStatusFilter]);

  const actions = useMemo(() => Array.from(new Set(logs.map((l) => l.action))), [logs]);

  const filtered = useMemo(() => {
    const q = search.toLowerCase();
    return logs.filter((l) => {
      if (action !== "all" && l.action !== action) return false;
      if (isSuperAdmin && licenseeFilter !== "all" && l.licenseeId !== licenseeFilter) return false;
      return JSON.stringify(l).toLowerCase().includes(q);
    });
  }, [logs, search, action, licenseeFilter, isSuperAdmin]);

  const openRespondDialog = (report: FraudReportQueueItem, status: FraudResponseStatus) => {
    setSelectedFraudReport(report);
    setResponseStatus(status);
    setNotifyCustomer(Boolean(report?.report?.contactEmail));
    setResponseMessage("");
    setRespondDialogOpen(true);
  };

  const submitFraudResponse = async () => {
    if (!selectedFraudReport) return;
    setResponding(true);
    try {
      const res = await apiClient.respondToFraudReport(selectedFraudReport.id, {
        status: responseStatus,
        message: responseMessage.trim() || undefined,
        notifyCustomer,
      });
      if (!res.success) {
        toast({
          title: "Action failed",
          description: res.error || "Could not update fraud report.",
          variant: "destructive",
        });
        return;
      }
      toast({
        title: "Fraud report updated",
        description: notifyCustomer
          ? "Status updated and automated reply prepared for the reported email."
          : "Status updated without customer notification.",
      });
      setRespondDialogOpen(false);
      setSelectedFraudReport(null);
      await refreshAll();
    } finally {
      setResponding(false);
    }
  };

  return (
    <>
      <DashboardLayout>
        <div className="space-y-6">
        <div className="flex flex-col gap-3 rounded-2xl border border-slate-200 bg-gradient-to-r from-slate-50 via-white to-cyan-50 p-4 sm:flex-row sm:items-center sm:justify-between">
          <h1 className="flex items-center gap-2 text-3xl font-bold tracking-tight text-slate-900">
            Audit History
            <Badge className={live ? "border-emerald-200 bg-emerald-50 text-emerald-700" : "border-slate-200 bg-white text-slate-600"}>
              {live ? "LIVE" : "PAUSED"}
            </Badge>
          </h1>
          <div className="flex gap-2">
            <Button variant="outline" onClick={refreshAll}>
              <RefreshCw className="mr-1 h-4 w-4" />
              Refresh
            </Button>
            <Button variant="outline" onClick={() => setLive((v) => !v)}>
              {live ? "Pause" : "Resume"}
            </Button>
          </div>
        </div>

        {isSuperAdmin && (
          <Card className="border-red-200">
            <CardHeader className="flex flex-col gap-3 border-b bg-red-50/70 sm:flex-row sm:items-center sm:justify-between">
              <div className="flex items-center gap-2">
                <ShieldAlert className="h-4 w-4 text-red-600" />
                <span className="font-semibold text-red-800">Fraud Report Queue</span>
                <Badge className="border-red-200 bg-white text-red-700">{fraudReports.length} cases</Badge>
              </div>
              <div className="flex gap-2">
                <Select value={fraudStatusFilter} onValueChange={(v) => setFraudStatusFilter(v as any)}>
                  <SelectTrigger className="w-[170px] bg-white">
                    <SelectValue placeholder="Status" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="ALL">All statuses</SelectItem>
                    <SelectItem value="OPEN">Open</SelectItem>
                    <SelectItem value="REVIEWED">Reviewed</SelectItem>
                    <SelectItem value="RESOLVED">Resolved</SelectItem>
                    <SelectItem value="DISMISSED">Dismissed</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </CardHeader>
            <CardContent className="space-y-3 pt-4">
              {fraudLoading ? (
                <div className="text-sm text-slate-500">Loading fraud reports...</div>
              ) : fraudReports.length === 0 ? (
                <div className="rounded-lg border border-slate-200 bg-slate-50 p-3 text-sm text-slate-600">
                  No fraud reports found for this filter.
                </div>
              ) : (
                fraudReports.map((fr) => {
                  const status = (fr.status || "OPEN") as FraudStatus;
                  return (
                    <div key={fr.id} className="rounded-xl border border-red-100 bg-white p-4">
                      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                        <div className="space-y-1">
                          <div className="flex flex-wrap items-center gap-2">
                            <Badge className={FRAUD_STATUS_TONE[status]}>{status}</Badge>
                            <span className="font-mono text-sm text-slate-900">{fr.report.code || "Unknown code"}</span>
                            {fr.report.reason ? (
                              <Badge className="border-amber-200 bg-amber-50 text-amber-700">{fr.report.reason}</Badge>
                            ) : null}
                          </div>
                          <p className="text-sm text-slate-700">{fr.report.notes || "No customer notes provided."}</p>
                          <div className="flex flex-wrap items-center gap-3 text-xs text-slate-500">
                            <span>Reported: {format(new Date(fr.createdAt), "PPp")}</span>
                            {fr.report.contactEmail ? (
                              <span className="inline-flex items-center gap-1">
                                <Mail className="h-3 w-3" />
                                {fr.report.contactEmail}
                              </span>
                            ) : (
                              <span>No reply email</span>
                            )}
                            {fr.report.observedStatus ? <span>Status: {fr.report.observedStatus}</span> : null}
                            {fr.report.observedOutcome ? <span>Outcome: {fr.report.observedOutcome}</span> : null}
                          </div>
                          {fr.response?.message ? (
                            <div className="rounded-md border border-slate-200 bg-slate-50 px-3 py-2 text-xs text-slate-700">
                              Last response: {fr.response.message}
                            </div>
                          ) : null}
                        </div>
                        <div className="flex flex-wrap gap-2">
                          <Button variant="outline" onClick={() => openRespondDialog(fr, "REVIEWED")}>
                            Mark reviewed
                          </Button>
                          <Button className="bg-emerald-600 text-white hover:bg-emerald-700" onClick={() => openRespondDialog(fr, "RESOLVED")}>
                            Resolve
                          </Button>
                          <Button variant="outline" className="border-slate-300 text-slate-700" onClick={() => openRespondDialog(fr, "DISMISSED")}>
                            Dismiss
                          </Button>
                        </div>
                      </div>
                    </div>
                  );
                })
              )}
            </CardContent>
          </Card>
        )}

        <Card className="border-slate-200">
          <CardHeader className="flex flex-col gap-4 border-b bg-slate-50/70 sm:flex-row">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-3 h-4 w-4 text-slate-400" />
              <Input
                placeholder="Search logs..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="border-slate-200 bg-white pl-9"
              />
            </div>
            {isSuperAdmin && (
              <Select value={licenseeFilter} onValueChange={setLicenseeFilter}>
                <SelectTrigger className="w-[220px] bg-white">
                  <SelectValue placeholder="Licensee" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All licensees</SelectItem>
                  {licensees.map((l) => (
                    <SelectItem key={l.id} value={l.id}>
                      {l.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            )}
            <Select value={action} onValueChange={setAction}>
              <SelectTrigger className="w-[220px] bg-white">
                <SelectValue placeholder="Action" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All actions</SelectItem>
                {actions.map((a) => (
                  <SelectItem key={a} value={a}>
                    {a}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </CardHeader>

          <CardContent className="pt-4">
            <div className="overflow-hidden rounded-lg border">
              <Table>
                <TableHeader>
                  <TableRow className="bg-slate-50">
                    <TableHead>Action</TableHead>
                    <TableHead>User</TableHead>
                    <TableHead>Entity</TableHead>
                    <TableHead>Details</TableHead>
                    <TableHead>Time</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filtered.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={5} className="text-slate-500">
                        No audit logs found for current filters.
                      </TableCell>
                    </TableRow>
                  ) : (
                    filtered.map((l) => {
                      const tone = actionTone(String(l.action || ""));
                      const details = asObject(l.details);
                      const detailEntries = readableDetailEntries(l, details);
                      const expanded = Boolean(expandedRows[l.id]);
                      return (
                        <TableRow key={l.id} className={String(l.action || "").includes("FRAUD") ? "bg-red-50/30" : undefined}>
                          <TableCell>
                            <Badge className={tone.className}>
                              {tone.icon}
                              {formatAuditActionLabel(l.action)}
                            </Badge>
                          </TableCell>
                          <TableCell className="text-xs text-slate-600">{userLabel(l)}</TableCell>
                          <TableCell className="text-sm text-slate-700">{l.entityType}</TableCell>
                          <TableCell className="max-w-[460px]">
                            <div className="space-y-2">
                              <div className="text-xs text-slate-600">{summarizeDetails(l)}</div>
                              <Button
                                type="button"
                                variant="ghost"
                                className="h-auto p-0 text-xs text-slate-700 hover:bg-transparent hover:text-slate-900"
                                onClick={() =>
                                  setExpandedRows((prev) => ({
                                    ...prev,
                                    [l.id]: !prev[l.id],
                                  }))
                                }
                              >
                                {expanded ? (
                                  <>
                                    <ChevronUp className="mr-1 h-3 w-3" />
                                    Hide details
                                  </>
                                ) : (
                                  <>
                                    <ChevronDown className="mr-1 h-3 w-3" />
                                    Expand details
                                  </>
                                )}
                              </Button>
                              {expanded && (
                                <div className="rounded-md border border-slate-200 bg-slate-50 p-3">
                                  <div className="grid gap-1 text-xs text-slate-700 sm:grid-cols-2">
                                    <div>
                                      <span className="font-semibold text-slate-900">Entity ID:</span>{" "}
                                      {l.entityId || "—"}
                                    </div>
                                    <div>
                                      <span className="font-semibold text-slate-900">Licensee:</span>{" "}
                                      {l.licenseeId || "—"}
                                    </div>
                                    <div>
                                      <span className="font-semibold text-slate-900">IP:</span>{" "}
                                      {l.ipAddress || "—"}
                                    </div>
                                    <div>
                                      <span className="font-semibold text-slate-900">Keys:</span>{" "}
                                      {Object.keys(details).join(", ") || "—"}
                                    </div>
                                  </div>
                                  <div className="mt-2 max-h-52 space-y-1 overflow-auto rounded border bg-white p-2 text-[11px] leading-5 text-slate-700">
                                    {detailEntries.length === 0 ? (
                                      <p className="text-slate-500">No additional details.</p>
                                    ) : (
                                      detailEntries.map((entry) => (
                                        <p key={`${l.id}-${entry.label}`}>
                                          <span className="font-semibold text-slate-900">{entry.label}:</span> {entry.value}
                                        </p>
                                      ))
                                    )}
                                  </div>
                                </div>
                              )}
                            </div>
                          </TableCell>
                          <TableCell className="text-xs text-slate-600">
                            {l.createdAt ? format(new Date(l.createdAt), "PPp") : "—"}
                          </TableCell>
                        </TableRow>
                      );
                    })
                  )}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>
        </div>
      </DashboardLayout>

      <Dialog open={respondDialogOpen} onOpenChange={setRespondDialogOpen}>
        <DialogContent className="sm:max-w-[560px]">
          <DialogHeader>
            <DialogTitle>Resolve Fraud Report</DialogTitle>
            <DialogDescription>
              Update fraud status, add investigation notes, and optionally send an automated customer response.
            </DialogDescription>
          </DialogHeader>

          {selectedFraudReport && (
            <div className="space-y-4">
              <div className="rounded-lg border bg-slate-50 p-3 text-sm">
                <div className="font-mono font-semibold text-slate-900">{selectedFraudReport.report.code || "Unknown code"}</div>
                <div className="text-slate-600">{selectedFraudReport.report.reason || "No reason provided"}</div>
              </div>

              <div className="space-y-2">
                <Label>Status</Label>
                <Select value={responseStatus} onValueChange={(v) => setResponseStatus(v as FraudResponseStatus)}>
                  <SelectTrigger>
                    <SelectValue placeholder="Select status" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="REVIEWED">Reviewed</SelectItem>
                    <SelectItem value="RESOLVED">Resolved</SelectItem>
                    <SelectItem value="DISMISSED">Dismissed</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <Label>Investigation note (optional)</Label>
                <Textarea
                  rows={4}
                  value={responseMessage}
                  onChange={(e) => setResponseMessage(e.target.value)}
                  placeholder="Add internal context or custom auto-reply text."
                />
              </div>

              <div className="rounded-md border border-slate-200 bg-slate-50 p-3 text-sm">
                <label className="flex cursor-pointer items-start gap-2">
                  <input
                    type="checkbox"
                    checked={notifyCustomer}
                    onChange={(e) => setNotifyCustomer(e.target.checked)}
                    className="mt-1 h-4 w-4 rounded border-slate-300"
                  />
                  <span>
                    Send automated customer reply{" "}
                    <span className="text-slate-500">
                      ({selectedFraudReport.report.contactEmail || "no email on report"})
                    </span>
                  </span>
                </label>
              </div>
            </div>
          )}

          <DialogFooter>
            <Button variant="outline" onClick={() => setRespondDialogOpen(false)} disabled={responding}>
              Cancel
            </Button>
            <Button className="bg-slate-900 text-white hover:bg-slate-800" onClick={submitFraudResponse} disabled={responding}>
              {responding ? "Submitting..." : "Apply action"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
