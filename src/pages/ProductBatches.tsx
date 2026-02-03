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
import {
  Search,
  RefreshCw,
  MoreHorizontal,
  Download,
  UserCog,
  Plus,
} from "lucide-react";
import { useNavigate } from "react-router-dom";

import { saveAs } from "file-saver";

type ManufacturerRow = { id: string; name: string; email: string; isActive: boolean };

type BatchRow = {
  id: string;
  name: string;
  licenseeId: string;
  startCode: string;
  endCode: string;
  totalCodes: number;
  printedAt: string | null;
  manufacturer?: { id: string; name: string; email: string } | null;
  availableCodes?: number;
  remainingStartCode?: string | null;
  remainingEndCode?: string | null;
};

type ProductBatchRow = {
  id: string;
  licenseeId: string;
  parentBatchId: string;

  productName: string;
  productCode: string;
  description?: string | null;

  serialStart: number;
  serialEnd: number;
  serialFormat: string;

  startCode: string;
  endCode: string;
  totalCodes: number;

  manufacturerId?: string | null;
  manufacturer?: { id: string; name: string; email: string } | null;

  printedAt?: string | null;
  createdAt: string;

  parentBatch?: { id: string; name: string; startCode: string; endCode: string } | null;
  _count?: { qrCodes: number };
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

// ---------- helpers ----------
function safeFilePart(s: string) {
  return String(s || "")
    .trim()
    .replace(/[^\w.-]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, 80) || "file";
}

function parseCodeNumber(code: string): number | null {
  const m = String(code || "").match(/(\d{10})$/);
  if (!m) return null;
  const n = parseInt(m[1], 10);
  return Number.isFinite(n) ? n : null;
}


export default function ProductBatches() {
  const { toast } = useToast();
  const { user } = useAuth();
  const navigate = useNavigate();

  const role = user?.role;

  const isManufacturer = role === "manufacturer";
  const canCreate = role === "licensee_admin";
  const canAssignManufacturer = role === "licensee_admin";

  const [loading, setLoading] = useState(false);
  const [rows, setRows] = useState<ProductBatchRow[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [q, setQ] = useState("");

  // manufacturers for assign dropdown (licensee_admin)
  const [manufacturers, setManufacturers] = useState<ManufacturerRow[]>([]);
  const [assignOpen, setAssignOpen] = useState(false);
  const [assignPB, setAssignPB] = useState<ProductBatchRow | null>(null);
  const [assignManufacturerId, setAssignManufacturerId] = useState<string>("");

  // create dialog
  const [createOpen, setCreateOpen] = useState(false);
  const [parentBatches, setParentBatches] = useState<BatchRow[]>([]);
  const [parentBatchId, setParentBatchId] = useState<string>("");

  const [productName, setProductName] = useState("");
  const [productCode, setProductCode] = useState("");
  const [description, setDescription] = useState("");

  const [startNumber, setStartNumber] = useState<number>(1);
  const [endNumber, setEndNumber] = useState<number>(1);

  const [serialStart, setSerialStart] = useState<number>(1);
  const [serialEnd, setSerialEnd] = useState<number>(1);
  const [serialFormat, setSerialFormat] = useState<string>("{LIC}-{PROD}-{NNNNNN}");

  const selectedParent = useMemo(
    () => parentBatches.find((b) => b.id === parentBatchId) || null,
    [parentBatches, parentBatchId]
  );

  // print pack dialog
  const [printOpen, setPrintOpen] = useState(false);
  const [printPB, setPrintPB] = useState<ProductBatchRow | null>(null);
  const [printing, setPrinting] = useState(false);

  // Saved settings for QR URL inside QR codes (same keys as Batches page)
  const [publicBaseUrl, setPublicBaseUrl] = useLocalStorageState<string>(
    "qr_public_base_url",
    "https://auth.mcs.example"
  );
  const buildPublicQrUrl = (code: string) => {
    const base = String(publicBaseUrl || "").trim().replace(/\/+$/, "");
    return `${base}/verify/${encodeURIComponent(code)}`;
  };

  const fetchProductBatches = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await apiClient.getProductBatches(
        user?.role === "super_admin" ? undefined : { licenseeId: user?.licenseeId }
      );

      if (!res.success) {
        setRows([]);
        setError(res.error || "Failed to load product batches");
        return;
      }

      setRows((Array.isArray(res.data) ? res.data : []) as ProductBatchRow[]);
    } catch (e: any) {
      setRows([]);
      setError(e?.message || "Failed to load product batches");
    } finally {
      setLoading(false);
    }
  };

  const fetchManufacturersForAssign = async () => {
    if (!canAssignManufacturer) return;
    const licenseeId = user?.licenseeId;
    const res = await apiClient.getManufacturers({ licenseeId: licenseeId || undefined, includeInactive: false });
    if (res.success) setManufacturers(((res.data as any) || []) as ManufacturerRow[]);
    else setManufacturers([]);
  };

  const fetchParentBatchesForCreate = async () => {
    if (!canCreate) return;
    setParentBatches([]);
    try {
      const res = await apiClient.getBatches();
      if (!res.success) return;

      const list = (Array.isArray(res.data) ? res.data : []) as BatchRow[];

      // Only “received pool” batches: unprinted + unassigned + has remaining codes
      const filtered = list.filter((b) => {
        if (b.printedAt) return false;
        if (b.manufacturer?.id) return false;
        if (typeof b.availableCodes === "number") return b.availableCodes > 0;
        return true;
      });

      setParentBatches(filtered);
    } catch {
      // ignore
    }
  };

  useEffect(() => {
    fetchProductBatches();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    fetchManufacturersForAssign();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user?.licenseeId, role]);

  useEffect(() => {
    if (!selectedParent) return;
    const startCode = selectedParent.remainingStartCode || selectedParent.startCode;
    const endCode = selectedParent.remainingEndCode || selectedParent.endCode;
    const startNum = parseCodeNumber(startCode);
    const endNum = parseCodeNumber(endCode);
    if (startNum != null && endNum != null) {
      setStartNumber(startNum);
      setEndNumber(endNum);
      setSerialStart(1);
      const remaining = selectedParent.availableCodes ?? selectedParent.totalCodes ?? endNum - startNum + 1;
      setSerialEnd(remaining);
    }
  }, [selectedParent?.id]);

  const filtered = useMemo(() => {
    const s = q.trim().toLowerCase();
    if (!s) return rows;

    return rows.filter((pb) => {
      const hay = [
        pb.productName,
        pb.productCode,
        pb.startCode,
        pb.endCode,
        pb.parentBatch?.name,
        pb.manufacturer?.name,
        pb.manufacturer?.email,
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();

      return hay.includes(s);
    });
  }, [rows, q]);

  // -------- ASSIGN MANUFACTURER (licensee_admin) --------
  const openAssign = (pb: ProductBatchRow) => {
    setAssignPB(pb);
    setAssignManufacturerId(pb.manufacturer?.id || "");
    setAssignOpen(true);
  };

  const submitAssign = async () => {
    if (!assignPB) return;
    if (!assignManufacturerId) {
      toast({ title: "Select a manufacturer", variant: "destructive" });
      return;
    }

    setLoading(true);
    try {
      const res = await apiClient.assignProductBatchManufacturer({
        productBatchId: assignPB.id,
        manufacturerId: assignManufacturerId,
      });

      if (!res.success) {
        toast({ title: "Assign failed", description: res.error || "Error", variant: "destructive" });
        return;
      }

      toast({ title: "Assigned", description: "Manufacturer assigned to product batch." });
      setAssignOpen(false);
      setAssignPB(null);
      setAssignManufacturerId("");
      await fetchProductBatches();
    } finally {
      setLoading(false);
    }
  };

  // -------- CREATE PRODUCT BATCH (licensee_admin) --------
  const openCreate = async () => {
    await fetchParentBatchesForCreate();
    setParentBatchId("");
    setProductName("");
    setProductCode("");
    setDescription("");
    setStartNumber(1);
    setEndNumber(1);
    setSerialStart(1);
    setSerialEnd(1);
    setSerialFormat("{LIC}-{PROD}-{NNNNNN}");
    setCreateOpen(true);
  };

  const submitCreate = async () => {
    if (!parentBatchId) {
      toast({ title: "Select a parent batch", variant: "destructive" });
      return;
    }
    if (!productName.trim()) {
      toast({ title: "Enter product name", variant: "destructive" });
      return;
    }
    if (endNumber < startNumber) {
      toast({ title: "QR end number must be >= start number", variant: "destructive" });
      return;
    }
    if (serialEnd < serialStart) {
      toast({ title: "Serial end must be >= serial start", variant: "destructive" });
      return;
    }

    setLoading(true);
    try {
      const res = await apiClient.createProductBatch({
        parentBatchId,
        productName: productName.trim(),
        productCode: productCode.trim() ? productCode.trim() : undefined,
        description: description.trim() ? description.trim() : undefined,
        startNumber,
        endNumber,
        serialStart,
        serialEnd,
        serialFormat: serialFormat.trim() ? serialFormat.trim() : undefined,
      });

      if (!res.success) {
        toast({ title: "Create failed", description: res.error || "Error", variant: "destructive" });
        return;
      }

      toast({ title: "Created", description: "Product batch created successfully." });
      setCreateOpen(false);
      await fetchProductBatches();
    } finally {
      setLoading(false);
    }
  };

  // -------- PRINT PACK (SERVER ZIP, ONE-TIME) --------
  const openPrintPack = (pb: ProductBatchRow) => {
    setPrintPB(pb);
    setPrintOpen(true);
  };

  const downloadProductBatchZip = async () => {
    if (!printPB) return;

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
      const tokenRes = await apiClient.createProductBatchPrintToken(printPB.id);
      if (!tokenRes.success) {
        toast({ title: "Download blocked", description: tokenRes.error || "Error", variant: "destructive" });
        return;
      }

      const token = (tokenRes.data as any)?.token;
      if (!token) throw new Error("Download token missing");

      const blob = await apiClient.downloadProductBatchPrintPack(token, {
        publicBaseUrl: base,
      });

      const fileName = `product-batch-${safeFilePart(printPB.productCode || printPB.id)}-print-pack.zip`;
      saveAs(blob, fileName);

      toast({
        title: "Downloaded",
        description: "Print pack downloaded. This batch is now marked as printed.",
      });

      setPrintOpen(false);
      await fetchProductBatches();
    } catch (e: any) {
      toast({
        title: "Download failed",
        description: e?.message || "Error",
        variant: "destructive",
      });
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
            <h1 className="text-3xl font-bold">Product Batches</h1>
            <p className="text-muted-foreground">
              {isManufacturer
                ? "Your assigned product batches (one-time download; auto-confirmed on download)"
                : "Split received batches into product batches and assign manufacturers"}
            </p>
          </div>

          <div className="flex gap-2">
            {canCreate && (
              <Button onClick={openCreate} disabled={loading}>
                <Plus className="mr-2 h-4 w-4" />
                Create
              </Button>
            )}
            <Button variant="outline" onClick={fetchProductBatches} disabled={loading}>
              <RefreshCw className="mr-2 h-4 w-4" />
              Refresh
            </Button>
          </div>
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
                placeholder="Search product batches..."
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
                    <TableHead>Product</TableHead>
                    <TableHead>Parent Batch</TableHead>
                    <TableHead>QR Range</TableHead>
                    <TableHead>Total</TableHead>
                    <TableHead>Serial Range</TableHead>
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
                        No product batches found.
                      </TableCell>
                    </TableRow>
                  ) : (
                    filtered.map((pb) => {
                      const printed = !!pb.printedAt;
                      const parentName = pb.parentBatch?.name || pb.parentBatchId;

                      return (
                        <TableRow key={pb.id}>
                          <TableCell>
                            <div className="space-y-1">
                              <div className="font-medium">{pb.productName}</div>
                              <div className="text-xs text-muted-foreground font-mono">{pb.productCode}</div>
                            </div>
                          </TableCell>

                          <TableCell>
                            <div className="space-y-1">
                              <div>{parentName}</div>
                              {pb.parentBatch?.startCode && (
                                <div className="text-xs text-muted-foreground font-mono">
                                  {pb.parentBatch.startCode} → {pb.parentBatch.endCode}
                                </div>
                              )}
                            </div>
                          </TableCell>

                          <TableCell className="font-mono text-xs">
                            <div>{pb.startCode}</div>
                            <div>{pb.endCode}</div>
                          </TableCell>

                          <TableCell>
                            <Badge>{pb.totalCodes}</Badge>
                          </TableCell>

                          <TableCell className="text-sm">
                            {pb.serialStart} → {pb.serialEnd}
                          </TableCell>

                          <TableCell>
                            {pb.manufacturer ? (
                              <div className="space-y-1">
                                <div>{pb.manufacturer.name}</div>
                                <div className="text-xs text-muted-foreground">{pb.manufacturer.email}</div>
                              </div>
                            ) : (
                              <span className="text-muted-foreground">—</span>
                            )}
                          </TableCell>

                          <TableCell>
                            {printed ? (
                              <Badge className="bg-success/10 text-success">
                                {format(new Date(pb.printedAt as string), "MMM d, yyyy")}
                              </Badge>
                            ) : (
                              <Badge className="bg-muted text-muted-foreground">Not printed</Badge>
                            )}
                          </TableCell>

                          <TableCell className="text-muted-foreground">
                            {pb.createdAt ? format(new Date(pb.createdAt), "MMM d, yyyy") : "—"}
                          </TableCell>

                          <TableCell className="text-right">
                            {isManufacturer ? (
                              <div className="flex justify-end gap-2">
                                <Button
                                  size="sm"
                                  variant="outline"
                                  disabled={loading || printed}
                                  onClick={() => openPrintPack(pb)}
                                >
                                  <Download className="mr-2 h-4 w-4" />
                                  Print pack
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
                                    <DropdownMenuItem onClick={() => openAssign(pb)} disabled={!!pb.printedAt}>
                                      <UserCog className="mr-2 h-4 w-4" />
                                      Assign manufacturer
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
        <Dialog
          open={assignOpen}
          onOpenChange={(v) => {
            setAssignOpen(v);
            if (!v) {
              setAssignPB(null);
              setAssignManufacturerId("");
            }
          }}
        >
          <DialogContent className="sm:max-w-[520px]">
            <DialogHeader>
              <DialogTitle>Assign Manufacturer</DialogTitle>
              <DialogDescription>
                Assigns a manufacturer to this product batch. (Licensee Admin only)
              </DialogDescription>
            </DialogHeader>

            {!assignPB ? (
              <div className="text-sm text-muted-foreground">No product batch selected.</div>
            ) : (
              <div className="space-y-4 mt-2">
                <div className="rounded-md border p-3 text-sm">
                  <div className="font-medium">{assignPB.productName}</div>
                  <div className="text-muted-foreground font-mono text-xs">
                    {assignPB.productCode} • {assignPB.startCode} → {assignPB.endCode}
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

        {/* Create Product Batch Dialog */}
        <Dialog open={createOpen} onOpenChange={(v) => setCreateOpen(v)}>
          <DialogContent className="sm:max-w-[720px] max-h-[85vh] overflow-y-auto">
            <DialogHeader>
              <DialogTitle>Create Product Batch</DialogTitle>
              <DialogDescription>
                Split a received parent batch into a product-specific allocation and assign later to a manufacturer.
              </DialogDescription>
            </DialogHeader>

            <div className="space-y-4 mt-2">
              <div className="space-y-2">
                <Label>Parent Batch (received pool)</Label>
                <Select value={parentBatchId} onValueChange={setParentBatchId}>
                  <SelectTrigger>
                    <SelectValue placeholder="Select parent batch" />
                  </SelectTrigger>
                  <SelectContent>
                    {parentBatches.length === 0 ? (
                      <SelectItem value="__none__" disabled>
                        No eligible parent batches (must be unassigned + unprinted)
                      </SelectItem>
                    ) : (
                      parentBatches.map((b) => (
                        <SelectItem key={b.id} value={b.id}>
                          {b.name} • {b.startCode} → {b.endCode}
                          {typeof b.availableCodes === "number" ? ` • remaining ${b.availableCodes}` : ""}
                        </SelectItem>
                      ))
                    )}
                  </SelectContent>
                </Select>
                {parentBatches.length === 0 && (
                  <div className="text-xs text-muted-foreground">
                    No received pool yet. Ask Super Admin to allocate a QR range or submit a request in QR Requests.
                  </div>
                )}
                {selectedParent && (
                  <div className="text-xs text-muted-foreground">
                    Remaining codes:{" "}
                    <span className="font-medium">
                      {typeof selectedParent.availableCodes === "number"
                        ? selectedParent.availableCodes
                        : "—"}
                    </span>
                    {selectedParent.remainingStartCode && selectedParent.remainingEndCode && (
                      <>
                        {" "}
                        • Range {selectedParent.remainingStartCode} → {selectedParent.remainingEndCode}
                        {" "}
                        <span className="text-muted-foreground">(min/max; gaps possible)</span>
                      </>
                    )}
                  </div>
                )}
                <div>
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={() => navigate("/qr-requests")}
                  >
                    Request QR codes
                  </Button>
                </div>
              </div>

              <div className="grid gap-3 md:grid-cols-2">
                <div className="space-y-2">
                  <Label>Product Name</Label>
                  <Input value={productName} onChange={(e) => setProductName(e.target.value)} />
                </div>
                <div className="space-y-2">
                  <Label>Product Code (optional)</Label>
                  <Input
                    value={productCode}
                    onChange={(e) => setProductCode(e.target.value)}
                    placeholder="AUTO if empty"
                  />
                </div>
              </div>

              <div className="space-y-2">
                <Label>Description (optional)</Label>
                <Input value={description} onChange={(e) => setDescription(e.target.value)} />
              </div>

              <div className="grid gap-3 md:grid-cols-2">
                <div className="space-y-2">
                  <Label>QR Start Number</Label>
                  <Input
                    type="number"
                    value={startNumber}
                    onChange={(e) => setStartNumber(parseInt(e.target.value || "0", 10))}
                    min={
                      selectedParent
                        ? parseCodeNumber(selectedParent.remainingStartCode || selectedParent.startCode) || undefined
                        : undefined
                    }
                    max={
                      selectedParent
                        ? parseCodeNumber(selectedParent.remainingEndCode || selectedParent.endCode) || undefined
                        : undefined
                    }
                  />
                </div>
                <div className="space-y-2">
                  <Label>QR End Number</Label>
                  <Input
                    type="number"
                    value={endNumber}
                    onChange={(e) => setEndNumber(parseInt(e.target.value || "0", 10))}
                    min={
                      selectedParent
                        ? parseCodeNumber(selectedParent.remainingStartCode || selectedParent.startCode) || undefined
                        : undefined
                    }
                    max={
                      selectedParent
                        ? parseCodeNumber(selectedParent.remainingEndCode || selectedParent.endCode) || undefined
                        : undefined
                    }
                  />
                </div>
              </div>

              <div className="grid gap-3 md:grid-cols-2">
                <div className="space-y-2">
                  <Label>Serial Start</Label>
                  <Input
                    type="number"
                    value={serialStart}
                    onChange={(e) => setSerialStart(parseInt(e.target.value || "0", 10))}
                  />
                </div>
                <div className="space-y-2">
                  <Label>Serial End</Label>
                  <Input
                    type="number"
                    value={serialEnd}
                    onChange={(e) => setSerialEnd(parseInt(e.target.value || "0", 10))}
                  />
                </div>
              </div>

              <div className="space-y-2">
                <Label>Serial Format</Label>
                <Input value={serialFormat} onChange={(e) => setSerialFormat(e.target.value)} />
                <div className="text-xs text-muted-foreground">
                  Example: {"{LIC}-{PROD}-{NNNNNN}"}
                </div>
              </div>

              <div className="flex justify-end gap-3 pt-2">
                <Button variant="outline" onClick={() => setCreateOpen(false)} disabled={loading}>
                  Cancel
                </Button>
                <Button onClick={submitCreate} disabled={loading}>
                  Create
                </Button>
              </div>
            </div>
          </DialogContent>
        </Dialog>

        {/* Print Pack Dialog */}
        <Dialog
          open={printOpen}
          onOpenChange={(v) => {
            setPrintOpen(v);
            if (!v) {
              setPrintPB(null);
            }
          }}
        >
          <DialogContent className="sm:max-w-[620px] max-h-[85vh] overflow-y-auto">
            <DialogHeader>
              <DialogTitle>Download Print Pack (PNG ZIP)</DialogTitle>
              <DialogDescription>
                One-time download (PNG ZIP + manifest.csv). Downloading marks the batch as printed automatically.
              </DialogDescription>
            </DialogHeader>

            {!printPB ? (
              <div className="text-sm text-muted-foreground">No product batch selected.</div>
            ) : (
              <div className="space-y-4 mt-2">
                <div className="rounded-md border p-3 text-sm">
                  <div className="font-medium">{printPB.productName}</div>
                  <div className="text-muted-foreground font-mono text-xs">
                    {printPB.productCode} • {printPB.startCode} → {printPB.endCode}
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

                {printing && <div className="text-sm text-muted-foreground">Preparing download…</div>}

                <div className="flex justify-end gap-3 pt-2">
                  <Button variant="outline" onClick={() => setPrintOpen(false)} disabled={printing}>
                    Close
                  </Button>
                  <Button onClick={downloadProductBatchZip} disabled={printing}>
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
