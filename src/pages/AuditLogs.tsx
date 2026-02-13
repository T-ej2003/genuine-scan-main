import React, { useEffect, useMemo, useState } from "react";
import { DashboardLayout } from "@/components/layout/DashboardLayout";
import apiClient from "@/lib/api-client";
import { useAuth } from "@/contexts/AuthContext";
import { onMutationEvent } from "@/lib/mutation-events";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Search, RefreshCw, Activity } from "lucide-react";
import { format } from "date-fns";

export default function AuditLogs() {
  const { user } = useAuth();
  const [logs, setLogs] = useState<any[]>([]);
  const [search, setSearch] = useState("");
  const [action, setAction] = useState("all");
  const [live, setLive] = useState(true);
  const [licensees, setLicensees] = useState<any[]>([]);
  const [licenseeFilter, setLicenseeFilter] = useState<string>("all");

  const load = async () => {
    const res = await apiClient.getAuditLogs({
      limit: 100,
      licenseeId: user?.role === "super_admin" && licenseeFilter !== "all" ? licenseeFilter : undefined,
    });
    if (!res.success) {
      setLogs([]);
      return;
    }

    // Support multiple backend shapes:
    // - array
    // - { logs: [...] }
    // - { data: [...] }
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

  useEffect(() => {
    load();
  }, [licenseeFilter]);

  useEffect(() => {
    const off = onMutationEvent(() => {
      load();
    });
    return off;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (user?.role !== "super_admin") return;
    apiClient.getLicensees().then((res) => {
      if (res.success) setLicensees((res.data as any) || []);
    });
  }, [user?.role]);

  useEffect(() => {
    if (!live) return;
    const stop = apiClient.streamAuditLogs((log) => {
      if (user?.role === "super_admin" && licenseeFilter !== "all") {
        if (log.licenseeId !== licenseeFilter) return;
      }
      setLogs((prev) => [log, ...prev].slice(0, 200));
    });
    return stop;
  }, [live, licenseeFilter, user?.role]);

  const actions = useMemo(
    () => Array.from(new Set(logs.map((l) => l.action))),
    [logs]
  );

  const summarizeDetails = (log: any) => {
    const d = log?.details || {};
    if (typeof d === "string") return d;
    if (!d || typeof d !== "object") return "—";

    const action = String(log?.action || "").toUpperCase();
    const range =
      d.startCode || d.endCode
        ? `${d.startCode || "?"}–${d.endCode || "?"}`
        : d.startNumber || d.endNumber
        ? `${d.startNumber || "?"}–${d.endNumber || "?"}`
        : null;
    const changed = Array.isArray(d.changed) ? d.changed.filter(Boolean).join(", ") : null;
    const name = d.name || d.batchName || d.licenseeName || d.manufacturerName || null;

    switch (action) {
      case "CREATED":
        if (log?.entityType === "PrintJob") {
          return `Created print job${d.batchId ? ` for batch ${d.batchId}` : ""}${
            d.quantity ? ` (${d.quantity} codes)` : ""
          }.`;
        }
        return `Created QR codes${range ? ` (range ${range})` : d.quantity ? ` (${d.quantity})` : ""}.`;
      case "ALLOCATED":
        return `Allocated${d.quantity ? ` ${d.quantity} codes` : ""}${range ? ` (range ${range})` : ""}${
          d.manufacturerId ? ` to manufacturer ${d.manufacturerId}` : ""
        }.`;
      case "PRINTED":
        return `Print confirmed${d.printedCodes != null ? ` (${d.printedCodes} codes)` : ""}.`;
      case "REDEEMED":
        return `Redeemed on first scan${d.scanCount != null ? ` (scan count ${d.scanCount})` : ""}.`;
      case "BLOCKED":
        return `Blocked${d.blockedCodes ? ` (${d.blockedCodes} codes)` : ""}${d.reason ? `: ${d.reason}` : "."}`;
      case "LOGIN":
        return "Signed in.";
      case "UPDATE_MY_PROFILE":
        return changed ? `Updated profile (changed: ${changed}).` : "Updated profile.";
      case "CHANGE_MY_PASSWORD":
        return "Changed account password.";
      case "CREATE_USER":
        return `Created user ${name || d.email || "new user"}${
          d.role ? ` (${d.role})` : ""
        }${d.licenseeId ? ` for licensee ${d.licenseeId}` : ""}.`;
      case "UPDATE_USER":
        return changed ? `Updated user (changed: ${changed}).` : "Updated user.";
      case "HARD_DELETE_MANUFACTURER":
        return `Permanently deleted manufacturer ${name || d.email || "unknown"}.`;
      case "SOFT_DELETE_MANUFACTURER":
        return `Deactivated manufacturer ${name || d.email || "unknown"}.`;
      case "RESTORE_MANUFACTURER":
        return `Restored manufacturer ${name || d.email || "unknown"}.`;
      case "CREATE_LICENSEE_WITH_ADMIN":
        return `Created licensee ${d.licenseeName || "new licensee"}${
          d.prefix ? ` (prefix ${d.prefix})` : ""
        } with admin ${d.adminEmail || "—"}.`;
      case "UPDATE_LICENSEE":
        return changed ? `Updated licensee (changed: ${changed}).` : "Updated licensee.";
      case "HARD_DELETE_LICENSEE":
        return "Deleted licensee.";
      case "CREATE_QR_ALLOCATION_REQUEST":
        return d.quantity
          ? `Requested ${d.quantity} QR codes.`
          : range
          ? `Requested QR range ${range}.`
          : "Requested QR allocation.";
      case "APPROVE_QR_ALLOCATION_REQUEST":
        return `${d.quantity ? `Approved ${d.quantity} QR codes.` : "Approved QR allocation."}${
          range ? ` Range ${range}.` : ""
        }`;
      case "REJECT_QR_ALLOCATION_REQUEST":
        return `Rejected QR allocation request${
          d.decisionNote ? `: ${d.decisionNote}` : "."
        }`;
      case "ALLOCATE_QR_RANGE":
      case "ALLOCATE_QR_RANGE_LICENSEE":
        return `Allocated QR range ${range || "—"}${
          d.created || d.quantity ? ` (${d.created || d.quantity} codes)` : ""
        }.`;
      case "BULK_DELETE_QR_CODES":
        return `Deleted ${d.deleted ?? d.count ?? "some"} QR codes${
          range ? ` (range ${range})` : ""
        }.`;
      case "CREATE_BATCH":
        return `Created batch ${name || "—"} with ${d.quantity ?? "—"} codes${
          d.manufacturerId ? ` for manufacturer ${d.manufacturerId}` : ""
        }.`;
      case "ADMIN_ALLOCATE_BATCH":
        return `Allocated ${d.quantity ?? "—"} codes to manufacturer ${
          d.manufacturerId || "—"
        } for licensee ${d.licenseeId || "—"}${range ? ` (range ${range})` : ""}.`;
      case "DELETE_BATCH":
        return `Deleted batch ${d.batchName || "—"}${
          d.unassignedCount != null ? `; ${d.unassignedCount} codes returned to pool` : ""
        }.`;
      case "BULK_DELETE_BATCHES":
        return `Deleted ${d.deletedCount ?? "—"} batches${
          d.unassignedCount != null ? `; ${d.unassignedCount} codes returned to pool` : ""
        }.`;
      case "ASSIGN_MANUFACTURER_QUANTITY":
        return `Assigned ${d.quantity ?? "—"} codes to manufacturer ${d.manufacturerId || "—"}.`;
      case "DOWNLOAD_BATCH_PRINT_PACK":
        return `Downloaded print pack${d.codes ? ` (${d.codes} codes)` : ""}.`;
      case "VERIFY_FAILED":
        return `Verification failed${d.reason ? `: ${d.reason}` : "."}`;
      case "VERIFY_SUCCESS":
        return `Verification succeeded${
          d.isFirstScan ? " (first scan)" : ""
        }${d.scanCount != null ? `; scan count ${d.scanCount}` : ""}.`;
      case "CUSTOMER_FRAUD_REPORT":
        return `Customer fraud report submitted for code ${d.code || "—"}${
          d.reason ? ` (${d.reason})` : ""
        }.`;
      case "CUSTOMER_PRODUCT_FEEDBACK":
        return `Customer feedback for code ${d.code || "—"}: ${d.rating || "—"}★, ${
          d.satisfaction || "no satisfaction tag"
        }.`;
      default: {
        const parts: string[] = [];
        if (name) parts.push(`name ${name}`);
        if (d.quantity) parts.push(`qty ${d.quantity}`);
        if (range) parts.push(`range ${range}`);
        if (d.manufacturerId) parts.push(`manufacturer ${d.manufacturerId}`);
        if (d.licenseeId) parts.push(`licensee ${d.licenseeId}`);
        if (d.codes) parts.push(`codes ${d.codes}`);
        if (d.unassignedCount != null) parts.push(`unassigned ${d.unassignedCount}`);
        const entity = log?.entityType ? ` on ${log.entityType}` : "";
        return parts.length ? `Updated${entity}: ${parts.join(", ")}.` : `Activity recorded${entity}.`;
      }
    }
  };

  const userLabel = (log: any) => {
    const id = log?.user?.id || log?.userId;
    if (log?.user?.name) {
      const email = log.user.email ? ` • ${log.user.email}` : "";
      const idPart = id ? ` • id: ${id}` : "";
      return `${log.user.name}${email}${idPart}`;
    }
    if (log?.user?.email) return `${log.user.email}${id ? ` • id: ${id}` : ""}`;
    if (id) return id;
    return "System";
  };

  const filtered = useMemo(() => {
    const q = search.toLowerCase();
    return logs.filter((l) => {
      if (action !== "all" && l.action !== action) return false;
      if (user?.role === "super_admin" && licenseeFilter !== "all") {
        if (l.licenseeId !== licenseeFilter) return false;
      }
      return JSON.stringify(l).toLowerCase().includes(q);
    });
  }, [logs, search, action, licenseeFilter, user?.role]);

  return (
    <DashboardLayout>
      <div className="space-y-6">
        <div className="flex justify-between items-center">
          <h1 className="text-3xl font-bold flex gap-2">
            Audit Logs
            <Badge variant="secondary">{live ? "LIVE" : "PAUSED"}</Badge>
          </h1>
          <div className="flex gap-2">
            <Button variant="outline" onClick={load}>
              <RefreshCw className="h-4 w-4 mr-1" /> Refresh
            </Button>
            <Button variant="outline" onClick={() => setLive((v) => !v)}>
              {live ? "Pause" : "Resume"}
            </Button>
          </div>
        </div>

        <Card>
          <CardHeader className="flex gap-4 sm:flex-row">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search logs..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="pl-9"
              />
            </div>
            {user?.role === "super_admin" && (
              <Select value={licenseeFilter} onValueChange={setLicenseeFilter}>
                <SelectTrigger className="w-[220px]">
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
              <SelectTrigger className="w-[200px]">
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

        <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Action</TableHead>
                  <TableHead>User</TableHead>
                  <TableHead>Entity</TableHead>
                  <TableHead>Details</TableHead>
                  <TableHead>Time</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filtered.map((l) => (
                  <TableRow key={l.id}>
                    <TableCell>
                      <Badge>
                        <Activity className="h-3 w-3 mr-1" />
                        {l.action}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {userLabel(l)}
                    </TableCell>
                    <TableCell>{l.entityType}</TableCell>
                    <TableCell>
                      <div className="text-xs text-muted-foreground">
                        {summarizeDetails(l)}
                      </div>
                    </TableCell>
                    <TableCell>
                      {format(new Date(l.createdAt), "PPp")}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </div>
    </DashboardLayout>
  );
}
