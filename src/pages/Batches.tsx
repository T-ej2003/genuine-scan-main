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
import { Search, Trash2, RefreshCw, MoreHorizontal, Download, CheckCircle2, UserCog } from "lucide-react";

import QRCode from "qrcode";
import JSZip from "jszip";
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

  // print pack dialog
  const [printOpen, setPrintOpen] = useState(false);
  const [printBatch, setPrintBatch] = useState<BatchRow | null>(null);
  const [printing, setPrinting] = useState(false);

  // Saved settings for QR URL inside QR codes
  const [publicBaseUrl, setPublicBaseUrl] = useLocalStorageState<string>(
    "qr_public_base_url",
    "https://auth.mcs.example"
  );
  const [brandSlug, setBrandSlug] = useLocalStorageState<string>("qr_brand_slug", "nemesis");

  const buildPublicQrUrl = (code: string) => {
    const base = String(publicBaseUrl || "").trim().replace(/\/+$/, "");
    const slug = String(brandSlug || "").trim().replace(/^\/+|\/+$/g, "");
    return `${base}/brand/${encodeURIComponent(slug)}/verify/${encodeURIComponent(code)}`;
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
    if (!licenseeId) return;

    const res = await apiClient.getManufacturers({ licenseeId, includeInactive: false });
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
    setAssignOpen(true);
  };

  const submitAssign = async () => {
    if (!assignBatch) return;
    if (!assignManufacturerId) {
      toast({ title: "Select a manufacturer", variant: "destructive" });
      return;
    }

    setLoading(true);
    try {
      const res = await apiClient.assignBatchManufacturer({
        batchId: assignBatch.id,
        manufacturerId: assignManufacturerId,
      });

      if (!res.success) {
        toast({ title: "Assign failed", description: res.error || "Error", variant: "destructive" });
        return;
      }

      toast({ title: "Assigned", description: "Manufacturer assigned to batch." });
      setAssignOpen(false);
      setAssignBatch(null);
      setAssignManufacturerId("");
      await fetchBatches();
    } finally {
      setLoading(false);
    }
  };

  // -------- PRINT PACK (PNG ZIP) --------
  const openPrintPack = (b: BatchRow) => {
    setPrintBatch(b);
    setPrintOpen(true);
  };

  const fetchAllCodesForBatch = async (batchId: string): Promise<string[]> => {
    // No backend batch filter exists yet, so we safely paginate and filter client-side.
    // This will still respect tenant isolation + manufacturer restrictions server-side.
    const licenseeId = user?.licenseeId; // manufacturer + licensee_admin have it
    const pageSize = 1000;
    const maxTotal = 20000; // safety limit

    let offset = 0;
    const out: string[] = [];

    while (offset < maxTotal) {
      const res = await apiClient.getQRCodes({
        licenseeId: licenseeId || undefined,
        limit: pageSize,
        offset,
      });

      if (!res.success) break;

      const payload: any = res.data;
      const list: QrRow[] = Array.isArray(payload?.qrCodes)
        ? payload.qrCodes
        : Array.isArray(payload)
        ? payload
        : [];

      if (list.length === 0) break;

      for (const r of list) {
        const rid = r.batch?.id || r.batchId;
        if (rid === batchId) out.push(String(r.code));
      }

      if (list.length < pageSize) break;
      offset += pageSize;
    }

    return out;
  };

  const qrPngDataUrl = async (code: string) => {
    const urlInsideQr = buildPublicQrUrl(code);
    return QRCode.toDataURL(urlInsideQr, {
      width: 768,
      margin: 2,
      errorCorrectionLevel: "M",
    });
  };

  const downloadBatchZip = async () => {
    if (!printBatch) return;

    setPrinting(true);
    try {
      const codes = await fetchAllCodesForBatch(printBatch.id);

      if (codes.length === 0) {
        toast({
          title: "No codes found",
          description: "No QR codes were found for this batch (or batch is empty).",
          variant: "destructive",
        });
        return;
      }

      const zip = new JSZip();
      for (const code of codes) {
        const dataUrl = await qrPngDataUrl(code);
        const blob = await (await fetch(dataUrl)).blob();
        zip.file(`${code}.png`, blob);
      }

      const out = await zip.generateAsync({ type: "blob" });
      saveAs(out, `batch-${printBatch.name || printBatch.id}-png.zip`);

      toast({ title: "Downloaded", description: `Generated ${codes.length} PNG(s).` });
    } catch (e: any) {
      toast({ title: "Download failed", description: e?.message || "Error", variant: "destructive" });
    } finally {
      setPrinting(false);
    }
  };

  const confirmPrinted = async (b: BatchRow) => {
    if (!isManufacturer) return;

    const ok = window.confirm(
      `Confirm print for "${b.name}"?\n\nThis will mark the batch as PRINTED in the system.`
    );
    if (!ok) return;

    setLoading(true);
    try {
      const res = await apiClient.confirmBatchPrint(b.id);
      if (!res.success) {
        toast({ title: "Confirm failed", description: res.error || "Error", variant: "destructive" });
        return;
      }
      toast({ title: "Confirmed", description: "Batch marked as printed." });
      await fetchBatches();
    } finally {
      setLoading(false);
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
                ? "Your assigned QR batches (download print pack and confirm printing)"
                : "Manage QR batches (assign / delete / review printing)"}
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
                            {/* Manufacturer: print pack + confirm */}
                            {isManufacturer ? (
                              <div className="flex justify-end gap-2">
                                <Button
                                  size="sm"
                                  variant="outline"
                                  disabled={loading}
                                  onClick={() => openPrintPack(b)}
                                >
                                  <Download className="mr-2 h-4 w-4" />
                                  Print pack
                                </Button>
                                <Button
                                  size="sm"
                                  disabled={loading || printed === true}
                                  onClick={() => confirmPrinted(b)}
                                >
                                  <CheckCircle2 className="mr-2 h-4 w-4" />
                                  Confirm
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
                                    <DropdownMenuItem onClick={() => openAssign(b)}>
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
        <Dialog open={assignOpen} onOpenChange={(v) => { setAssignOpen(v); if (!v) { setAssignBatch(null); setAssignManufacturerId(""); } }}>
          <DialogContent className="sm:max-w-[520px]">
            <DialogHeader>
              <DialogTitle>Assign Manufacturer</DialogTitle>
              <DialogDescription>
                Assigns a manufacturer to this batch. (Licensee Admin only)
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
                Generates PNG QR images for this batch using the public URL settings. Saved locally for future use.
              </DialogDescription>
            </DialogHeader>

            {!printBatch ? (
              <div className="text-sm text-muted-foreground">No batch selected.</div>
            ) : (
              <div className="space-y-4 mt-2">
                <div className="rounded-md border p-3 text-sm">
                  <div className="font-medium">{printBatch.name}</div>
                  <div className="text-muted-foreground font-mono text-xs">
                    {printBatch.startCode} → {printBatch.endCode}
                  </div>
                </div>

                <div className="grid gap-3 md:grid-cols-2">
                  <div className="space-y-2">
                    <Label>Public base URL</Label>
                    <Input value={publicBaseUrl} onChange={(e) => setPublicBaseUrl(e.target.value)} />
                    <div className="text-xs text-muted-foreground font-mono">
                      Example: {buildPublicQrUrl("A0000000001")}
                    </div>
                  </div>

                  <div className="space-y-2">
                    <Label>Brand slug</Label>
                    <Input value={brandSlug} onChange={(e) => setBrandSlug(e.target.value)} />
                    <div className="text-xs text-muted-foreground">
                      Used in URL: <span className="font-mono">{brandSlug}</span>
                    </div>
                  </div>
                </div>

                <div className="flex justify-end gap-3 pt-2">
                  <Button variant="outline" onClick={() => setPrintOpen(false)} disabled={printing}>
                    Close
                  </Button>
                  <Button onClick={downloadBatchZip} disabled={printing}>
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

