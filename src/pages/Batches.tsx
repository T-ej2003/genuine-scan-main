// src/pages/Batches.tsx

import React, { useEffect, useMemo, useState } from "react";
import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { useAuth } from "@/contexts/AuthContext";
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
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

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

import { Label } from "@/components/ui/label";
import { useToast } from "@/hooks/use-toast";

import { format } from "date-fns";
import { Search, Trash2, RefreshCw, MoreHorizontal, Download, UserCog } from "lucide-react";

import { saveAs } from "file-saver";

type BatchRow = {
  id: string;
  name: string;
  licenseeId: string;
  startCode: string;
  endCode: string;
  totalCodes: number;
  printedAt: string | null;
  createdAt: string;
  licensee?: { id: string; name: string; prefix: string };
  manufacturer?: { id: string; name: string; email: string };
  _count?: { qrCodes: number };
  availableCodes?: number;
  remainingStartCode?: string | null;
  remainingEndCode?: string | null;
};

type ManufacturerRow = { id: string; name: string; email: string; isActive: boolean };

type QrRow = {
  code: string;
  batchId?: string | null;
  batch?: { id: string } | null;
};

function useLocalStorageState<T>(key: string, initial: T) {
  const [value, setValue] = useState<T>(() => {
    try {
      const raw = localStorage.getItem(key);
      return raw ? (JSON.parse(raw) as T) : initial;
    } catch {
      return initial;
    }
  });

  useEffect(() => {
    try {
      localStorage.setItem(key, JSON.stringify(value));
    } catch {
      // ignore
    }
  }, [key, value]);

  return [value, setValue] as const;
}

export default function Batches() {
  const { toast } = useToast();
  const { user } = useAuth();

  const role = user?.role;

  const canDelete = role === "super_admin" || role === "licensee_admin";
  const canAssignManufacturer = role === "licensee_admin";
  const isManufacturer = role === "manufacturer";

  const [loading, setLoading] = useState(false);
  const [rows, setRows] = useState<BatchRow[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [q, setQ] = useState("");

  // manufacturers for assign dropdown (licensee_admin)
  const [manufacturers, setManufacturers] = useState<ManufacturerRow[]>([]);
  const [assignOpen, setAssignOpen] = useState(false);
  const [assignBatch, setAssignBatch] = useState<BatchRow | null>(null);
  const [assignManufacturerId, setAssignManufacturerId] = useState<string>("");
  const [assignQuantity, setAssignQuantity] = useState<string>("");

  // print pack dialog
  const [printOpen, setPrintOpen] = useState(false);
  const [printBatch, setPrintBatch] = useState<BatchRow | null>(null);
  const [printing, setPrinting] = useState(false);

  // Saved settings for QR URL inside QR codes
  const [publicBaseUrl, setPublicBaseUrl] = useLocalStorageState<string>(
    "qr_public_base_url",
    typeof window !== "undefined" ? window.location.origin : "http://localhost:8080"
  );
  useEffect(() => {
    if (typeof window === "undefined") return;
    if (publicBaseUrl.includes("auth.mcs.example")) {
      setPublicBaseUrl(window.location.origin);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  const buildPublicQrUrl = (code: string) => {
    const base = String(publicBaseUrl || "").trim().replace(/\/+$/, "");
    return `${base}/verify/${encodeURIComponent(code)}`;
  };

  const fetchBatches = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await apiClient.getBatches();
      if (!res.success) {
        setRows([]);
        setError(res.error || "Failed to load batches");
        return;
      }
      setRows((Array.isArray(res.data) ? res.data : []) as BatchRow[]);
    } catch (e: any) {
      setRows([]);
      setError(e?.message || "Failed to load batches");
    } finally {
      setLoading(false);
    }
  };

  const fetchManufacturersForAssign = async () => {
    if (!canAssignManufacturer) return;
    const licenseeId = user?.licenseeId;
    const res = await apiClient.getManufacturers({
      licenseeId: licenseeId || undefined,
      includeInactive: false,
    });
    if (res.success) {
      setManufacturers(((res.data as any) || []) as ManufacturerRow[]);
    } else {
      setManufacturers([]);
    }
  };

  useEffect(() => {
    fetchBatches();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    fetchManufacturersForAssign();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user?.licenseeId, role]);

  const filtered = useMemo(() => {
    const s = q.trim().toLowerCase();
    if (!s) return rows;

    return rows.filter((b) => {
      const hay = [
        b.name,
        b.startCode,
        b.endCode,
        b.licensee?.name,
        b.licensee?.prefix,
        b.manufacturer?.name,
        b.manufacturer?.email,
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();

      return hay.includes(s);
    });
  }, [rows, q]);

  // -------- DELETE (admins) --------
  const handleDelete = async (batch: BatchRow) => {
    if (!canDelete) return;

    const ok = window.confirm(
      `Delete batch "${batch.name}"?\n\nThis will:\n- Delete the batch\n- Unassign ALL QR codes from this batch (back to DORMANT)\n\nContinue?`
    );
    if (!ok) return;

    setLoading(true);
    setError(null);
    try {
      const res = await apiClient.deleteBatch(batch.id);
      if (!res.success) {
        setError(res.error || "Delete failed");
        return;
      }
      toast({ title: "Deleted", description: `Batch "${batch.name}" deleted.` });
      await fetchBatches();
    } catch (e: any) {
      setError(e?.message || "Delete failed");
    } finally {
      setLoading(false);
    }
  };

  // -------- ASSIGN MANUFACTURER (licensee_admin) --------
  const openAssign = (b: BatchRow) => {
    setAssignBatch(b);
    setAssignManufacturerId(b.manufacturer?.id || "");
    setAssignQuantity("");
    setAssignOpen(true);
  };

  const submitAssign = async () => {
    if (!assignBatch) return;
    if (!assignManufacturerId) {
      toast({ title: "Select a manufacturer", variant: "destructive" });
      return;
    }
    const qty = parseInt(assignQuantity, 10);
    if (!Number.isFinite(qty) || qty <= 0) {
      toast({ title: "Enter a valid quantity", variant: "destructive" });
      return;
    }
    if (assignBatch.availableCodes != null && qty > assignBatch.availableCodes) {
      toast({
        title: "Quantity too large",
        description: `Available: ${assignBatch.availableCodes}.`,
        variant: "destructive",
      });
      return;
    }

    setLoading(true);
    try {
      const res = await apiClient.assignBatchManufacturer({
        batchId: assignBatch.id,
        manufacturerId: assignManufacturerId,
        quantity: qty,
      });

      if (!res.success) {
        toast({ title: "Assign failed", description: res.error || "Error", variant: "destructive" });
        return;
      }

      toast({ title: "Assigned", description: "Manufacturer assigned to batch." });
      setAssignOpen(false);
      setAssignBatch(null);
      setAssignManufacturerId("");
      setAssignQuantity("");
      await fetchBatches();
    } finally {
      setLoading(false);
    }
  };

  // -------- PRINT PACK (SERVER ZIP, ONE-TIME) --------
  const openPrintPack = (b: BatchRow) => {
    setPrintBatch(b);
    setPrintOpen(true);
  };

  const downloadBatchZip = async () => {
    if (!printBatch) return;
    const base = String(publicBaseUrl || "").trim();

    if (!base) {
      toast({
        title: "Missing URL settings",
        description: "Please set Public base URL first.",
        variant: "destructive",
      });
      return;
    }

    setPrinting(true);
    try {
      const tokenRes = await apiClient.createBatchPrintToken(printBatch.id);
      if (!tokenRes.success) {
        toast({ title: "Download blocked", description: tokenRes.error || "Error", variant: "destructive" });
        return;
      }

      const token = (tokenRes.data as any)?.token;
      if (!token) throw new Error("Download token missing");

      const blob = await apiClient.downloadBatchPrintPack(token, { publicBaseUrl: base });
      saveAs(blob, `batch-${printBatch.name || printBatch.id}-print-pack.zip`);

      toast({
        title: "Downloaded",
        description: "Print pack downloaded. This batch is now marked as printed.",
      });

      setPrintOpen(false);
      await fetchBatches();
    } catch (e: any) {
      toast({ title: "Download failed", description: e?.message || "Error", variant: "destructive" });
    } finally {
      setPrinting(false);
    }
  };

  return (
    <DashboardLayout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div>
            <h1 className="text-3xl font-bold">Batches</h1>
            <p className="text-muted-foreground">
              {isManufacturer
                ? "Your assigned QR batches (one-time print pack download auto-confirms printing)"
                : "Manage received QR batches (assign by quantity / delete / review printing)"}
            </p>
          </div>

          <Button variant="outline" onClick={fetchBatches} disabled={loading}>
            <RefreshCw className="mr-2 h-4 w-4" />
            Refresh
          </Button>
        </div>

        {error && (
          <div className="rounded-md border border-destructive/30 bg-destructive/5 p-3 text-sm text-destructive">
            {error}
          </div>
        )}

        <Card>
          <CardHeader className="pb-4">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search batches..."
                value={q}
                onChange={(e) => setQ(e.target.value)}
                className="pl-9"
              />
            </div>
          </CardHeader>

          <CardContent>
            <div className="rounded-md border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Batch</TableHead>
                    <TableHead>Licensee</TableHead>
                    <TableHead>Range</TableHead>
                    <TableHead>Total</TableHead>
                    <TableHead>Assigned QR</TableHead>
                    <TableHead>Manufacturer</TableHead>
                    <TableHead>Printed</TableHead>
                    <TableHead>Created</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>

                <TableBody>
                  {loading ? (
                    <TableRow>
                      <TableCell colSpan={9} className="text-muted-foreground">
                        Loading...
                      </TableCell>
                    </TableRow>
                  ) : filtered.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={9} className="text-muted-foreground">
                        No batches found.
                      </TableCell>
                    </TableRow>
                  ) : (
                    filtered.map((b) => {
                      const assignedCount = b._count?.qrCodes ?? 0;
                      const printed = !!b.printedAt;

                      return (
                        <TableRow key={b.id}>
                          <TableCell className="font-medium">{b.name}</TableCell>

                          <TableCell>
                            {b.licensee?.name ? (
                              <div className="space-y-1">
                                <div>{b.licensee.name}</div>
                                <div className="text-xs text-muted-foreground">
                                  Prefix: {b.licensee.prefix}
                                </div>
                              </div>
                            ) : (
                              <span className="text-muted-foreground">{b.licenseeId}</span>
                            )}
                          </TableCell>

                          <TableCell className="font-mono text-xs">
                            <div>{b.startCode}</div>
                            <div>{b.endCode}</div>
                          </TableCell>

                          <TableCell>{b.totalCodes}</TableCell>

                          <TableCell>
                            <Badge variant={assignedCount > 0 ? "default" : "secondary"}>{assignedCount}</Badge>
                          </TableCell>

                          <TableCell>
                            {b.manufacturer ? (
                              <div className="space-y-1">
                                <div>{b.manufacturer.name}</div>
                                <div className="text-xs text-muted-foreground">{b.manufacturer.email}</div>
                              </div>
                            ) : (
                              <span className="text-muted-foreground">—</span>
                            )}
                          </TableCell>

                          <TableCell>
                            {printed ? (
                              <Badge className="bg-success/10 text-success">
                                {format(new Date(b.printedAt as string), "MMM d, yyyy")}
                              </Badge>
                            ) : (
                              <Badge className="bg-muted text-muted-foreground">Not printed</Badge>
                            )}
                          </TableCell>

                          <TableCell className="text-muted-foreground">
                            {b.createdAt ? format(new Date(b.createdAt), "MMM d, yyyy") : "—"}
                          </TableCell>

                          <TableCell className="text-right">
                            {/* Manufacturer: print pack download (one-time) */}
                            {isManufacturer ? (
                              <div className="flex justify-end gap-2">
                                <Button
                                  size="sm"
                                  variant="outline"
                                  disabled={loading || printed}
                                  onClick={() => openPrintPack(b)}
                                >
                                  <Download className="mr-2 h-4 w-4" />
                                  {printed ? "Printed" : "Download pack"}
                                </Button>
                              </div>
                            ) : (
                              <DropdownMenu>
                                <DropdownMenuTrigger asChild>
                                  <Button variant="outline" size="sm">
                                    <MoreHorizontal className="mr-2 h-4 w-4" />
                                    Actions
                                  </Button>
                                </DropdownMenuTrigger>
                                <DropdownMenuContent align="end">
                                  {canAssignManufacturer && (
                                    <DropdownMenuItem onClick={() => openAssign(b)} disabled={!!b.manufacturer || !!b.printedAt}>
                                      <UserCog className="mr-2 h-4 w-4" />
                                      Assign manufacturer
                                    </DropdownMenuItem>
                                  )}

                                  {canDelete && (
                                    <DropdownMenuItem className="text-destructive" onClick={() => handleDelete(b)}>
                                      <Trash2 className="mr-2 h-4 w-4" />
                                      Delete
                                    </DropdownMenuItem>
                                  )}
                                </DropdownMenuContent>
                              </DropdownMenu>
                            )}
                          </TableCell>
                        </TableRow>
                      );
                    })
                  )}
                </TableBody>
              </Table>
            </div>

            <div className="mt-3 text-sm text-muted-foreground">
              Showing {filtered.length} of {rows.length}
            </div>
          </CardContent>
        </Card>

        {/* Assign Manufacturer Dialog */}
        <Dialog open={assignOpen} onOpenChange={(v) => { setAssignOpen(v); if (!v) { setAssignBatch(null); setAssignManufacturerId(""); setAssignQuantity(""); } }}>
          <DialogContent className="sm:max-w-[520px]">
            <DialogHeader>
              <DialogTitle>Assign Manufacturer</DialogTitle>
              <DialogDescription>
                Split this received batch by quantity and assign the new batch to a manufacturer.
              </DialogDescription>
            </DialogHeader>

            {!assignBatch ? (
              <div className="text-sm text-muted-foreground">No batch selected.</div>
            ) : (
              <div className="space-y-4 mt-2">
                <div className="rounded-md border p-3 text-sm">
                  <div className="font-medium">{assignBatch.name}</div>
                  <div className="text-muted-foreground font-mono text-xs">
                    {assignBatch.startCode} → {assignBatch.endCode}
                  </div>
                </div>

                <div className="space-y-2">
                  <Label>Manufacturer</Label>
                  <Select value={assignManufacturerId} onValueChange={setAssignManufacturerId}>
                    <SelectTrigger>
                      <SelectValue placeholder="Select manufacturer" />
                    </SelectTrigger>
                    <SelectContent>
                      {manufacturers.length === 0 ? (
                        <SelectItem value="__none__" disabled>
                          No manufacturers found
                        </SelectItem>
                      ) : (
                        manufacturers.map((m) => (
                          <SelectItem key={m.id} value={m.id}>
                            {m.name} ({m.email})
                          </SelectItem>
                        ))
                      )}
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-2">
                  <Label>Quantity to allocate</Label>
                  <Input
                    type="number"
                    min={1}
                    value={assignQuantity}
                    onChange={(e) => setAssignQuantity(e.target.value)}
                    placeholder="Enter quantity"
                  />
                  <div className="text-xs text-muted-foreground">
                    Available in this batch: {assignBatch.availableCodes ?? assignBatch.totalCodes}
                  </div>
                </div>

                <div className="flex justify-end gap-3 pt-2">
                  <Button variant="outline" onClick={() => setAssignOpen(false)} disabled={loading}>
                    Cancel
                  </Button>
                  <Button onClick={submitAssign} disabled={loading}>
                    Save
                  </Button>
                </div>
              </div>
            )}
          </DialogContent>
        </Dialog>

        {/* Print Pack Dialog */}
        <Dialog open={printOpen} onOpenChange={(v) => { setPrintOpen(v); if (!v) setPrintBatch(null); }}>
          <DialogContent className="sm:max-w-[620px] max-h-[85vh] overflow-y-auto">
            <DialogHeader>
              <DialogTitle>Download Print Pack (PNG ZIP)</DialogTitle>
              <DialogDescription>
                One-time download. Downloading marks the batch as printed automatically.
              </DialogDescription>
            </DialogHeader>

            {!printBatch ? (
              <div className="text-sm text-muted-foreground">No batch selected.</div>
            ) : (
              <div className="space-y-4 mt-2">
                {printBatch.printedAt && (
                  <div className="rounded-md border border-amber-200 bg-amber-50 p-3 text-sm text-amber-900">
                    This batch is already marked as printed. Downloads are restricted to one-time use.
                  </div>
                )}
                <div className="rounded-md border p-3 text-sm">
                  <div className="font-medium">{printBatch.name}</div>
                  <div className="text-muted-foreground font-mono text-xs">
                    {printBatch.startCode} → {printBatch.endCode}
                  </div>
                </div>

                <div className="grid gap-3 md:grid-cols-1">
                  <div className="space-y-2">
                    <Label>Public base URL</Label>
                    <Input value={publicBaseUrl} onChange={(e) => setPublicBaseUrl(e.target.value)} />
                    <div className="text-xs text-muted-foreground font-mono">
                      Example: {buildPublicQrUrl("A0000000001")}
                    </div>
                  </div>
                </div>

                <div className="flex justify-end gap-3 pt-2">
                  <Button variant="outline" onClick={() => setPrintOpen(false)} disabled={printing}>
                    Close
                  </Button>
                  <Button onClick={downloadBatchZip} disabled={printing || !!printBatch.printedAt}>
                    {printing ? "Generating..." : "Download ZIP"}
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
