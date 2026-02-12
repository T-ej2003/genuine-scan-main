// src/pages/Manufacturers.tsx

import React, { useEffect, useMemo, useState } from "react";
import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { useAuth } from "@/contexts/AuthContext";
import apiClient from "@/lib/api-client";
import { useNavigate } from "react-router-dom";

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
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";

import { Label } from "@/components/ui/label";
import { useToast } from "@/hooks/use-toast";
import { onMutationEvent } from "@/lib/mutation-events";

import {
  Plus,
  Search,
  MoreHorizontal,
  Factory,
  RefreshCw,
  Trash2,
  Power,
  Copy,
  Eye,
  PackageCheck,
  Activity,
} from "lucide-react";

import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

import { format } from "date-fns";

type LicenseeOption = { id: string; name: string; prefix: string };

type ManufacturerRow = {
  id: string;
  name: string;
  email: string;
  isActive: boolean;
  createdAt?: string;
  licenseeId?: string;
  location?: string | null;
  website?: string | null;
};

type CreateManufacturerForm = {
  licenseeId: string;
  name: string;
  email: string;
  password: string;
  location: string;
  website: string;
};

type BatchRow = {
  id: string;
  name: string;
  licenseeId?: string;
  manufacturerId?: string | null;
  totalCodes?: number;
  availableCodes?: number;
  printedAt?: string | null;
  createdAt?: string;
  startCode?: string;
  endCode?: string;
};

type ManufacturerStats = {
  assignedBatches: number;
  assignedCodes: number;
  printedBatches: number;
  pendingPrintBatches: number;
  lastBatchAt: string | null;
  recentBatches: BatchRow[];
};

export default function Manufacturers() {
  const { toast } = useToast();
  const { user } = useAuth();
  const navigate = useNavigate();

  const isSuperAdmin = user?.role === "super_admin";
  const fixedLicenseeId = user?.licenseeId || "";

  const [loading, setLoading] = useState(true);

  const [licensees, setLicensees] = useState<LicenseeOption[]>([]);
  const [licenseeFilter, setLicenseeFilter] = useState<string>(""); // super_admin only

  const [manufacturers, setManufacturers] = useState<ManufacturerRow[]>([]);
  const [manufacturerStats, setManufacturerStats] = useState<Record<string, ManufacturerStats>>({});
  const [search, setSearch] = useState("");
  const [showInactive, setShowInactive] = useState(true);

  const [createOpen, setCreateOpen] = useState(false);
  const [creating, setCreating] = useState(false);
  const [detailsOpen, setDetailsOpen] = useState(false);
  const [detailsManufacturer, setDetailsManufacturer] = useState<ManufacturerRow | null>(null);
  const [createForm, setCreateForm] = useState<CreateManufacturerForm>({
    licenseeId: "",
    name: "",
    email: "",
    password: "",
    location: "",
    website: "",
  });

  const effectiveLicenseeId = isSuperAdmin ? licenseeFilter : fixedLicenseeId;

  const normalizeManufacturerRows = (list: any[]): ManufacturerRow[] =>
    list.map((row) => ({
      id: row.id,
      name: row.name || "",
      email: row.email || "",
      isActive: typeof row.isActive === "boolean" ? row.isActive : true,
      createdAt: row.createdAt,
      licenseeId: row.licenseeId,
      location: row.location ?? null,
      website: row.website ?? null,
    }));

  const normalizeBatchRows = (list: any[]): BatchRow[] =>
    list.map((row) => ({
      id: row.id,
      name: row.name || "",
      licenseeId: row.licenseeId,
      manufacturerId: row.manufacturerId ?? row.manufacturer?.id ?? null,
      totalCodes: Number(row.totalCodes || 0),
      availableCodes: Number(row.availableCodes || 0),
      printedAt: row.printedAt || null,
      createdAt: row.createdAt,
      startCode: row.startCode,
      endCode: row.endCode,
    }));

  const emptyStats = (): ManufacturerStats => ({
    assignedBatches: 0,
    assignedCodes: 0,
    printedBatches: 0,
    pendingPrintBatches: 0,
    lastBatchAt: null,
    recentBatches: [],
  });

  const loadLicenseesIfNeeded = async () => {
    if (!isSuperAdmin) return;

    const res = await apiClient.getLicensees();
    if (!res.success) {
      toast({
        title: "Failed to load licensees",
        description: res.error || "Could not load licensees list",
        variant: "destructive",
      });
      return;
    }

    const list = (res.data as any[]) || [];
    const opts: LicenseeOption[] = list.map((l) => ({
      id: l.id,
      name: l.name,
      prefix: l.prefix,
    }));
    setLicensees(opts);

    // auto-select first licensee if none selected yet
    if (!licenseeFilter && opts.length > 0) setLicenseeFilter(opts[0].id);
  };

  const loadManufacturers = async () => {
    setLoading(true);
    try {
      // licensee_admin MUST have licenseeId
      if (!isSuperAdmin && !fixedLicenseeId) {
        setManufacturers([]);
        setManufacturerStats({});
        toast({
          title: "Missing licensee scope",
          description: "Your account is not linked to a licensee. Contact Super Admin.",
          variant: "destructive",
        });
        return;
      }

      // super_admin must pick a licensee
      if (isSuperAdmin && !effectiveLicenseeId) {
        setManufacturers([]);
        setManufacturerStats({});
        return;
      }

      const scope = effectiveLicenseeId || undefined;
      const [primary, batchRes] = await Promise.all([
        apiClient.getManufacturers({
          licenseeId: scope,
          includeInactive: true,
        }),
        apiClient.getBatches(scope ? { licenseeId: scope } : undefined),
      ]);

      let rows: ManufacturerRow[] = primary.success
        ? normalizeManufacturerRows((primary.data as any[]) || [])
        : [];

      // Fallback path if /manufacturers is unavailable or returns empty unexpectedly.
      if (rows.length === 0) {
        const fallback = await apiClient.getUsers({ licenseeId: scope, role: "MANUFACTURER" });
        if (fallback.success) {
          rows = normalizeManufacturerRows((fallback.data as any[]) || []);
        } else if (!primary.success) {
          toast({
            title: "Failed to load manufacturers",
            description: primary.error || fallback.error || "Could not load manufacturers",
            variant: "destructive",
          });
        }
      }

      setManufacturers(rows);

      const statsMap: Record<string, ManufacturerStats> = {};
      for (const m of rows) statsMap[m.id] = emptyStats();

      const batches = batchRes.success ? normalizeBatchRows((batchRes.data as any[]) || []) : [];
      for (const b of batches) {
        const manufacturerId = b.manufacturerId || "";
        if (!manufacturerId || !statsMap[manufacturerId]) continue;
        const s = statsMap[manufacturerId];
        s.assignedBatches += 1;
        s.assignedCodes += Number(b.totalCodes || 0);
        if (b.printedAt) s.printedBatches += 1;
        else s.pendingPrintBatches += 1;

        if (!s.lastBatchAt || (b.createdAt && new Date(b.createdAt) > new Date(s.lastBatchAt))) {
          s.lastBatchAt = b.createdAt || s.lastBatchAt;
        }

        s.recentBatches.push(b);
      }

      for (const key of Object.keys(statsMap)) {
        statsMap[key].recentBatches.sort((a, b) => {
          const aTs = a.createdAt ? new Date(a.createdAt).getTime() : 0;
          const bTs = b.createdAt ? new Date(b.createdAt).getTime() : 0;
          return bTs - aTs;
        });
        statsMap[key].recentBatches = statsMap[key].recentBatches.slice(0, 5);
      }

      setManufacturerStats(statsMap);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    (async () => {
      try {
        await loadLicenseesIfNeeded();
      } finally {
        // manufacturers load will run again when filter is set
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isSuperAdmin]);

  useEffect(() => {
    loadManufacturers();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [effectiveLicenseeId]);

  useEffect(() => {
    const off = onMutationEvent(() => {
      loadManufacturers();
    });
    return off;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();

    return (manufacturers || [])
      .filter((m) => (showInactive ? true : !!m.isActive))
      .filter((m) => {
        if (!q) return true;
        return (
          (m.name || "").toLowerCase().includes(q) ||
          (m.email || "").toLowerCase().includes(q)
        );
      });
  }, [manufacturers, search, showInactive]);

  const summary = useMemo(() => {
    const rows = filtered || [];
    let active = 0;
    let inactive = 0;
    let assignedBatches = 0;
    let pendingPrintBatches = 0;
    for (const m of rows) {
      if (m.isActive) active += 1;
      else inactive += 1;
      const s = manufacturerStats[m.id];
      if (!s) continue;
      assignedBatches += s.assignedBatches;
      pendingPrintBatches += s.pendingPrintBatches;
    }
    return {
      total: rows.length,
      active,
      inactive,
      assignedBatches,
      pendingPrintBatches,
    };
  }, [filtered, manufacturerStats]);

  const openDetails = (m: ManufacturerRow) => {
    setDetailsManufacturer(m);
    setDetailsOpen(true);
  };

  const copyId = async (id: string) => {
    try {
      await navigator.clipboard.writeText(id);
      toast({ title: "Copied", description: "Manufacturer ID copied to clipboard." });
    } catch {
      toast({ title: "Copy failed", description: "Could not copy ID.", variant: "destructive" });
    }
  };

  const openCreate = () => {
    const licId = effectiveLicenseeId || fixedLicenseeId || "";
    setCreateForm({
      licenseeId: licId,
      name: "",
      email: "",
      password: "",
      location: "",
      website: "",
    });
    setCreateOpen(true);
  };

  const submitCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (creating) return;

    const licId = createForm.licenseeId;
    const name = createForm.name.trim();
    const email = createForm.email.trim().toLowerCase();
    const password = createForm.password.trim();
    const location = createForm.location.trim();
    const website = createForm.website.trim();

    if (!licId) {
      toast({
        title: "Select licensee",
        description: "Choose a licensee first.",
        variant: "destructive",
      });
      return;
    }
    if (!name || !email || password.length < 6) {
      toast({
        title: "Missing fields",
        description: "Name, Email, Password (min 6 chars) are required.",
        variant: "destructive",
      });
      return;
    }

    setCreating(true);
    try {
      const res = await apiClient.createUser({
        licenseeId: licId,
        name,
        email,
        password,
        role: "MANUFACTURER",
        location: location || undefined,
        website: website || undefined,
      });

      if (!res.success) throw new Error(res.error || "Create manufacturer failed");

      toast({
        title: "Manufacturer created",
        description: `${name} added successfully.`,
      });

      setCreateOpen(false);
      setCreateForm({ licenseeId: "", name: "", email: "", password: "", location: "", website: "" });
      await loadManufacturers();
    } catch (e: any) {
      toast({
        title: "Create failed",
        description: e?.message || "Error",
        variant: "destructive",
      });
    } finally {
      setCreating(false);
    }
  };

  const deactivate = async (m: ManufacturerRow) => {
    const ok = window.confirm(`Deactivate "${m.name}"?`);
    if (!ok) return;

    const res = await apiClient.deactivateManufacturer(m.id);
    if (!res.success) {
      toast({
        title: "Action failed",
        description: res.error || "Could not deactivate",
        variant: "destructive",
      });
      return;
    }

    toast({ title: "Deactivated", description: `${m.name} is now inactive.` });
    setManufacturers((prev) => prev.map((x) => (x.id === m.id ? { ...x, isActive: false } : x)));
  };

  const restore = async (m: ManufacturerRow) => {
    const res = await apiClient.restoreManufacturer(m.id);
    if (!res.success) {
      toast({
        title: "Action failed",
        description: res.error || "Could not restore",
        variant: "destructive",
      });
      return;
    }

    toast({ title: "Restored", description: `${m.name} is active again.` });
    setManufacturers((prev) => prev.map((x) => (x.id === m.id ? { ...x, isActive: true } : x)));
  };

  const hardDelete = async (m: ManufacturerRow) => {
    const ok = window.confirm(
      `HARD DELETE "${m.name}"?\n\nThis cannot be undone. Only do this if there are no linked batches/QR data.`
    );
    if (!ok) return;

    const res = await apiClient.hardDeleteManufacturer(m.id);
    if (!res.success) {
      toast({
        title: "Delete failed",
        description: res.error || "Could not delete",
        variant: "destructive",
      });
      return;
    }

    toast({ title: "Deleted", description: `${m.name} removed.` });
    setManufacturers((prev) => prev.filter((x) => x.id !== m.id));
  };

  return (
    <DashboardLayout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div>
            <h1 className="text-3xl font-bold">Manufacturers</h1>
            <p className="text-muted-foreground">
              {isSuperAdmin
                ? "Manage manufacturers for any licensee"
                : "Manage manufacturers under your licensee"}
            </p>
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            <Button variant="outline" onClick={loadManufacturers} disabled={loading}>
              <RefreshCw className="mr-2 h-4 w-4" />
              Refresh
            </Button>

            <Dialog open={createOpen} onOpenChange={setCreateOpen}>
              <DialogTrigger asChild>
                <Button onClick={openCreate} disabled={isSuperAdmin && !effectiveLicenseeId}>
                  <Plus className="mr-2 h-4 w-4" />
                  Add Manufacturer
                </Button>
              </DialogTrigger>

              <DialogContent className="sm:max-w-[560px] max-h-[85vh] overflow-y-auto">
                <DialogHeader>
                  <DialogTitle>Create Manufacturer</DialogTitle>
                  <DialogDescription>
                    Creates a manufacturer user under the selected licensee.
                  </DialogDescription>
                </DialogHeader>

                <form className="space-y-4 mt-4" onSubmit={submitCreate}>
                  {isSuperAdmin && (
                    <div className="space-y-2">
                      <Label>Licensee</Label>
                      <Select
                        value={createForm.licenseeId}
                        onValueChange={(v) => setCreateForm((p) => ({ ...p, licenseeId: v }))}
                      >
                        <SelectTrigger>
                          <SelectValue placeholder="Select licensee" />
                        </SelectTrigger>
                        <SelectContent>
                          {licensees.map((l) => (
                            <SelectItem key={l.id} value={l.id}>
                              {l.name} ({l.prefix})
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                  )}

                  <div className="space-y-2">
                    <Label>Name</Label>
                    <Input
                      value={createForm.name}
                      onChange={(e) => setCreateForm((p) => ({ ...p, name: e.target.value }))}
                      placeholder="Factory A"
                      disabled={creating}
                    />
                  </div>

                  <div className="space-y-2">
                    <Label>Email</Label>
                    <Input
                      value={createForm.email}
                      onChange={(e) => setCreateForm((p) => ({ ...p, email: e.target.value }))}
                      placeholder="factory@example.com"
                      disabled={creating}
                    />
                  </div>

                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label>Location</Label>
                      <Input
                        value={createForm.location}
                        onChange={(e) => setCreateForm((p) => ({ ...p, location: e.target.value }))}
                        placeholder="City, Country"
                        disabled={creating}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label>Website</Label>
                      <Input
                        value={createForm.website}
                        onChange={(e) => setCreateForm((p) => ({ ...p, website: e.target.value }))}
                        placeholder="https://factory.example"
                        disabled={creating}
                      />
                    </div>
                  </div>

                  <div className="space-y-2">
                    <Label>Password</Label>
                    <Input
                      type="password"
                      value={createForm.password}
                      onChange={(e) => setCreateForm((p) => ({ ...p, password: e.target.value }))}
                      placeholder="Min 6 chars"
                      disabled={creating}
                    />
                  </div>

                  <div className="flex justify-end gap-3 pt-2">
                    <Button type="button" variant="outline" onClick={() => setCreateOpen(false)} disabled={creating}>
                      Cancel
                    </Button>
                    <Button type="submit" disabled={creating}>
                      {creating ? "Creating..." : "Create"}
                    </Button>
                  </div>
                </form>
              </DialogContent>
            </Dialog>
          </div>
        </div>

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-5">
          <Card>
            <CardContent className="pt-6">
              <div className="text-sm text-muted-foreground">Visible Manufacturers</div>
              <div className="mt-2 text-2xl font-semibold">{summary.total}</div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-6">
              <div className="text-sm text-muted-foreground">Active</div>
              <div className="mt-2 text-2xl font-semibold">{summary.active}</div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-6">
              <div className="text-sm text-muted-foreground">Inactive</div>
              <div className="mt-2 text-2xl font-semibold">{summary.inactive}</div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-6">
              <div className="text-sm text-muted-foreground">Assigned Batches</div>
              <div className="mt-2 text-2xl font-semibold">{summary.assignedBatches}</div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-6">
              <div className="text-sm text-muted-foreground">Pending Print</div>
              <div className="mt-2 text-2xl font-semibold">{summary.pendingPrintBatches}</div>
            </CardContent>
          </Card>
        </div>

        {/* Filters */}
        <Card>
          <CardHeader className="pb-4">
            <div className="flex flex-col md:flex-row md:items-center gap-3">
              <div className="relative flex-1">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Search manufacturers..."
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  className="pl-9"
                />
              </div>

              <div className="flex gap-2 flex-wrap">
                <Button
                  type="button"
                  variant={showInactive ? "default" : "secondary"}
                  onClick={() => setShowInactive((p) => !p)}
                >
                  {showInactive ? "Showing: All" : "Showing: Active"}
                </Button>

                {isSuperAdmin && (
                  <Select value={licenseeFilter} onValueChange={setLicenseeFilter}>
                    <SelectTrigger className="w-[260px]">
                      <SelectValue placeholder="Filter by licensee" />
                    </SelectTrigger>
                    <SelectContent>
                      {licensees.map((l) => (
                        <SelectItem key={l.id} value={l.id}>
                          {l.name} ({l.prefix})
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                )}
              </div>
            </div>
          </CardHeader>

          <CardContent>
            {loading ? (
              <div className="text-sm text-muted-foreground">Loading...</div>
            ) : (
              <div className="rounded-md border">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Manufacturer</TableHead>
                      <TableHead>Contact</TableHead>
                      <TableHead>Location</TableHead>
                      <TableHead>Batch Ops</TableHead>
                      <TableHead>Print Status</TableHead>
                      <TableHead>Last Assignment</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead className="w-[50px]" />
                    </TableRow>
                  </TableHeader>

                  <TableBody>
                    {filtered.map((m) => (
                      <TableRow key={m.id}>
                        <TableCell>
                          <div className="flex items-center gap-3">
                            <div className="h-10 w-10 rounded-lg bg-primary/10 flex items-center justify-center">
                              <Factory className="h-5 w-5 text-primary" />
                            </div>
                            <div>
                              <button
                                type="button"
                                className="font-medium text-left hover:underline"
                                onClick={() => openDetails(m)}
                              >
                                {m.name}
                              </button>
                              <p className="text-xs text-muted-foreground">{m.id}</p>
                            </div>
                          </div>
                        </TableCell>

                        <TableCell className="text-muted-foreground">
                          <div>{m.email}</div>
                          {m.website ? (
                            <a
                              className="text-xs text-primary hover:underline"
                              href={m.website}
                              target="_blank"
                              rel="noreferrer"
                            >
                              {m.website}
                            </a>
                          ) : (
                            <span className="text-xs">—</span>
                          )}
                        </TableCell>

                        <TableCell className="text-muted-foreground">{m.location || "—"}</TableCell>

                        <TableCell>
                          <div className="flex items-center gap-1 text-sm">
                            <PackageCheck className="h-4 w-4 text-muted-foreground" />
                            <span>{manufacturerStats[m.id]?.assignedBatches || 0} batches</span>
                          </div>
                          <div className="text-xs text-muted-foreground">
                            {manufacturerStats[m.id]?.assignedCodes || 0} codes
                          </div>
                        </TableCell>

                        <TableCell>
                          <div className="flex items-center gap-1 text-sm">
                            <Activity className="h-4 w-4 text-muted-foreground" />
                            <span>{manufacturerStats[m.id]?.printedBatches || 0} printed</span>
                          </div>
                          <div className="text-xs text-muted-foreground">
                            {manufacturerStats[m.id]?.pendingPrintBatches || 0} pending
                          </div>
                        </TableCell>

                        <TableCell className="text-muted-foreground">
                          {manufacturerStats[m.id]?.lastBatchAt
                            ? format(new Date(manufacturerStats[m.id]!.lastBatchAt!), "MMM d, yyyy HH:mm")
                            : "—"}
                        </TableCell>

                        <TableCell>
                          <Badge variant={m.isActive ? "default" : "secondary"}>
                            {m.isActive ? "Active" : "Inactive"}
                          </Badge>
                        </TableCell>

                        <TableCell>
                          <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                              <Button variant="ghost" size="icon">
                                <MoreHorizontal className="h-4 w-4" />
                              </Button>
                            </DropdownMenuTrigger>

                            <DropdownMenuContent align="end">
                              <DropdownMenuItem onClick={() => openDetails(m)}>
                                <Eye className="mr-2 h-4 w-4" />
                                View Details
                              </DropdownMenuItem>

                              <DropdownMenuItem onClick={() => copyId(m.id)}>
                                <Copy className="mr-2 h-4 w-4" />
                                Copy ID
                              </DropdownMenuItem>

                              <DropdownMenuItem onClick={() => navigate("/batches")}>
                                <PackageCheck className="mr-2 h-4 w-4" />
                                Open Batches
                              </DropdownMenuItem>

                              {m.isActive ? (
                                <DropdownMenuItem onClick={() => deactivate(m)}>
                                  <Power className="mr-2 h-4 w-4" />
                                  Deactivate
                                </DropdownMenuItem>
                              ) : (
                                <DropdownMenuItem onClick={() => restore(m)}>
                                  <Power className="mr-2 h-4 w-4" />
                                  Restore
                                </DropdownMenuItem>
                              )}

                              <DropdownMenuItem className="text-destructive" onClick={() => hardDelete(m)}>
                                <Trash2 className="mr-2 h-4 w-4" />
                                Hard Delete
                              </DropdownMenuItem>
                            </DropdownMenuContent>
                          </DropdownMenu>
                        </TableCell>
                      </TableRow>
                    ))}

                    {filtered.length === 0 && (
                      <TableRow>
                        <TableCell colSpan={8} className="text-center text-sm text-muted-foreground">
                          No manufacturers found.
                        </TableCell>
                      </TableRow>
                    )}
                  </TableBody>
                </Table>
              </div>
            )}
          </CardContent>
        </Card>

        <Dialog
          open={detailsOpen}
          onOpenChange={(v) => {
            setDetailsOpen(v);
            if (!v) setDetailsManufacturer(null);
          }}
        >
          <DialogContent className="sm:max-w-[760px] max-h-[85vh] overflow-y-auto">
            <DialogHeader>
              <DialogTitle>Manufacturer Details</DialogTitle>
              <DialogDescription>
                Operational snapshot, print status, and recent assigned batches.
              </DialogDescription>
            </DialogHeader>

            {!detailsManufacturer ? (
              <div className="text-sm text-muted-foreground">No manufacturer selected.</div>
            ) : (
              <div className="space-y-4">
                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                  <div className="rounded-md border p-3">
                    <div className="text-xs text-muted-foreground">Name</div>
                    <div className="font-medium">{detailsManufacturer.name}</div>
                  </div>
                  <div className="rounded-md border p-3">
                    <div className="text-xs text-muted-foreground">Email</div>
                    <div className="font-medium">{detailsManufacturer.email}</div>
                  </div>
                  <div className="rounded-md border p-3">
                    <div className="text-xs text-muted-foreground">Location</div>
                    <div className="font-medium">{detailsManufacturer.location || "—"}</div>
                  </div>
                  <div className="rounded-md border p-3">
                    <div className="text-xs text-muted-foreground">Status</div>
                    <div className="font-medium">{detailsManufacturer.isActive ? "Active" : "Inactive"}</div>
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                  <div className="rounded-md border p-3">
                    <div className="text-xs text-muted-foreground">Assigned Batches</div>
                    <div className="text-xl font-semibold">
                      {manufacturerStats[detailsManufacturer.id]?.assignedBatches || 0}
                    </div>
                  </div>
                  <div className="rounded-md border p-3">
                    <div className="text-xs text-muted-foreground">Assigned Codes</div>
                    <div className="text-xl font-semibold">
                      {manufacturerStats[detailsManufacturer.id]?.assignedCodes || 0}
                    </div>
                  </div>
                  <div className="rounded-md border p-3">
                    <div className="text-xs text-muted-foreground">Printed Batches</div>
                    <div className="text-xl font-semibold">
                      {manufacturerStats[detailsManufacturer.id]?.printedBatches || 0}
                    </div>
                  </div>
                  <div className="rounded-md border p-3">
                    <div className="text-xs text-muted-foreground">Pending Print</div>
                    <div className="text-xl font-semibold">
                      {manufacturerStats[detailsManufacturer.id]?.pendingPrintBatches || 0}
                    </div>
                  </div>
                </div>

                <div className="rounded-md border">
                  <div className="border-b px-4 py-3 text-sm font-medium">Recent Assigned Batches</div>
                  <div className="p-4">
                    {(manufacturerStats[detailsManufacturer.id]?.recentBatches || []).length === 0 ? (
                      <div className="text-sm text-muted-foreground">No assigned batches yet.</div>
                    ) : (
                      <div className="space-y-2">
                        {(manufacturerStats[detailsManufacturer.id]?.recentBatches || []).map((b) => (
                          <div key={b.id} className="flex items-center justify-between rounded border p-2 text-sm">
                            <div>
                              <div className="font-medium">{b.name || "Unnamed Batch"}</div>
                              <div className="text-xs text-muted-foreground">
                                {b.startCode || "?"} {"->"} {b.endCode || "?"}
                              </div>
                            </div>
                            <div className="text-right">
                              <div className="font-medium">{b.totalCodes || 0} codes</div>
                              <div className="text-xs text-muted-foreground">
                                {b.printedAt ? "Printed" : "Pending print"}
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>

                <div className="flex justify-end gap-2">
                  <Button variant="outline" onClick={() => copyId(detailsManufacturer.id)}>
                    <Copy className="mr-2 h-4 w-4" />
                    Copy ID
                  </Button>
                  <Button onClick={() => navigate("/batches")}>
                    <PackageCheck className="mr-2 h-4 w-4" />
                    Open Batches
                  </Button>
                </div>
              </div>
            )}
          </DialogContent>
        </Dialog>
      </div>
    </DashboardLayout>
  );
}
