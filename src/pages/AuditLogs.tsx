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
                    <TableCell>{l.entityType}</TableCell>
                    <TableCell>
                      <pre className="text-xs whitespace-pre-wrap">
                        {JSON.stringify(l.details, null, 2)}
                      </pre>
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

