import React, { useEffect, useMemo, useState } from "react";
import { DashboardLayout } from "@/components/layout/DashboardLayout";
import apiClient from "@/lib/api-client";
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
  const [logs, setLogs] = useState<any[]>([]);
  const [search, setSearch] = useState("");
  const [action, setAction] = useState("all");
  const [live, setLive] = useState(true);

  const load = async () => {
    const res = await apiClient.getAuditLogs({ limit: 100 });
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
  }, []);

  useEffect(() => {
    if (!live) return;
    const stop = apiClient.streamAuditLogs((log) => {
      setLogs((prev) => [log, ...prev].slice(0, 200));
    });
    return stop;
  }, [live]);

  const actions = useMemo(
    () => Array.from(new Set(logs.map((l) => l.action))),
    [logs]
  );

  const summarizeDetails = (log: any) => {
    const d = log?.details || {};
    if (typeof d === "string") return d;
    if (!d || typeof d !== "object") return "—";

    const parts: string[] = [];
    if (d.name) parts.push(`Name: ${d.name}`);
    if (d.batchName) parts.push(`Batch: ${d.batchName}`);
    if (d.quantity) parts.push(`Qty: ${d.quantity}`);
    if (d.startCode || d.endCode) parts.push(`Range: ${d.startCode || "?"} → ${d.endCode || "?"}`);
    if (d.manufacturerId) parts.push(`Manufacturer: ${d.manufacturerId}`);
    if (d.licenseeId) parts.push(`Licensee: ${d.licenseeId}`);
    if (d.codes) parts.push(`Codes: ${d.codes}`);
    if (d.unassignedCount != null) parts.push(`Unassigned: ${d.unassignedCount}`);

    if (parts.length) return parts.join(" • ");
    return Object.keys(d).length ? "Additional details available" : "—";
  };

  const userLabel = (log: any) => {
    if (log?.user?.name) return `${log.user.name} (${log.user.email || log.user.id})`;
    if (log?.user?.email) return log.user.email;
    if (log?.userId) return log.userId;
    return "System";
  };

  const filtered = useMemo(() => {
    const q = search.toLowerCase();
    return logs.filter((l) => {
      if (action !== "all" && l.action !== action) return false;
      return JSON.stringify(l).toLowerCase().includes(q);
    });
  }, [logs, search, action]);

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
