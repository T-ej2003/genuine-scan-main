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
  CheckCircle2,
  UserCog,
  Plus,
} from "lucide-react";

import QRCode from "qrcode";
import JSZip from "jszip";
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

type QrRow = {
  code: string;
  batchId?: string | null;
  productBatchId?: string | null;
  productBatch?: { id: string } | null;
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

function detectLicFromCode(code: string) {
  const m = String(code).match(/^[A-Za-z]+/);
  return m?.[0] || "LIC";
}

function padNumber(n: number, width: number) {
  const s = String(Math.max(0, Math.trunc(n)));
  return s.length >= width ? s : "0".repeat(width - s.length) + s;
}

/**
 * Serial format supports:
 * {LIC} = licensee prefix (detected from code like A000... => A)
 * {PROD} = product code
 * {NNN...} = N repeated indicates padding length, uses serial number value
 *
 * Example: "{LIC}-{PROD}-{NNNNNN}" => "A-TSHIRT-000123"
 */
function renderSerial(formatStr: string, vars: { lic: string; prod: string; serial: number }) {
  let out = formatStr || "{LIC}-{PROD}-{NNNNNN}";
  out = out.replaceAll("{LIC}", vars.lic);
  out = out.replaceAll("{PROD}", vars.prod);

  // Replace any {NNN...} token with padded serial
  out = out.replace(/\{N+\}/g, (token) => {
    const nCount = token.length - 2; // remove braces
    return padNumber(vars.serial, nCount);
  });

  return out;
}

async function promisePool<T, R>(
  items: T[],
  concurrency: number,
  worker: (item: T, index: number) => Promise<R>,
  onProgress?: (done: number, total: number) => void
) {
  const total = items.length;
  const results: R[] = new Array(total);
  let nextIndex = 0;
  let done = 0;

  const runners = new Array(Math.max(1, concurrency)).fill(0).map(async () => {
    while (true) {
      const i = nextIndex++;
      if (i >= total) return;
      results[i] = await worker(items[i], i);
      done++;
      onProgress?.(done, total);
    }
  });

  await Promise.all(runners);
  return results;
}

export default function ProductBatches() {
  const { toast } = useToast();
  const { user } = useAuth();

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

  // print pack dialog
  const [printOpen, setPrintOpen] = useState(false);
  const [printPB, setPrintPB] = useState<ProductBatchRow | null>(null);
  const [printing, setPrinting] = useState(false);
  const [printProgress, setPrintProgress] = useState<{ done: number; total: number }>({
    done: 0,
    total: 0,
  });

  // Saved settings for QR URL inside QR codes (same keys as Batches page)
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
    if (!licenseeId) return;

    const res = await apiClient.getManufacturers({ licenseeId, includeInactive: false });
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

      // Only “received pool” batches: unprinted + unassigned
      const filtered = list.filter((b) => !b.printedAt && !b.manufacturer?.id);

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

  // -------- PRINT PACK (PNG ZIP) --------
  const openPrintPack = (pb: ProductBatchRow) => {
    setPrintPB(pb);
    setPrintProgress({ done: 0, total: 0 });
    setPrintOpen(true);
  };

  /**
   * ✅ Recommended: create backend endpoint to fetch only codes for a given productBatchId.
   * If apiClient.getProductBatchQRCodes exists, we use it.
   * Otherwise we fallback to your licensee-wide scan (but still faster/safer than before).
   */
  const fetchAllCodesForProductBatch = async (pb: ProductBatchRow): Promise<string[]> => {
    // If you add this method to apiClient, it will automatically be used:
    const maybeFn = (apiClient as any).getProductBatchQRCodes as
      | ((args: { productBatchId: string; limit?: number; offset?: number }) => Promise<any>)
      | undefined;

    if (typeof maybeFn === "function") {
      const pageSize = 5000;
      let offset = 0;
      const out: string[] = [];
      while (true) {
        const res = await maybeFn({ productBatchId: pb.id, limit: pageSize, offset });
        if (!res?.success) break;

        const payload = res.data;
        const list: string[] = Array.isArray(payload?.codes)
          ? payload.codes
          : Array.isArray(payload)
          ? payload
          : [];

        if (list.length === 0) break;
        out.push(...list.map(String));

        if (pb.totalCodes && out.length >= pb.totalCodes) break;
        if (list.length < pageSize) break;
        offset += pageSize;
      }
      return out;
    }

    // ---- fallback (your existing approach, but with safety + lower cap risk) ----
    const licenseeId = user?.licenseeId;
    const pageSize = 2000;
    const hardCap = 200000; // allow bigger licensees; still safe
    let offset = 0;
    const out: string[] = [];

    while (offset < hardCap) {
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
        const pid = r.productBatch?.id || r.productBatchId;
        if (pid === pb.id) out.push(String(r.code));
      }

      if (pb.totalCodes && out.length >= pb.totalCodes) break;
      if (list.length < pageSize) break;

      offset += pageSize;
    }

    return out;
  };

  const qrPngBlob = async (code: string) => {
    const urlInsideQr = buildPublicQrUrl(code);
    const dataUrl = await QRCode.toDataURL(urlInsideQr, {
      width: 768,
      margin: 2,
      errorCorrectionLevel: "M",
    });
    return await (await fetch(dataUrl)).blob();
  };

  const downloadProductBatchZip = async () => {
    if (!printPB) return;

    const base = String(publicBaseUrl || "").trim();
    const slug = String(brandSlug || "").trim();

    if (!base || !slug) {
      toast({
        title: "Missing URL settings",
        description: "Please set Public base URL and Brand slug first.",
        variant: "destructive",
      });
      return;
    }

    setPrinting(true);
    setPrintProgress({ done: 0, total: 0 });

    try {
      const codes = await fetchAllCodesForProductBatch(printPB);

      if (codes.length === 0) {
        toast({
          title: "No codes found",
          description: "No QR codes were found for this product batch.",
          variant: "destructive",
        });
        return;
      }

      // Ensure stable ordering
      const ordered = [...codes].sort((a, b) => a.localeCompare(b));

      const zip = new JSZip();
      const folder = zip.folder("png")!;
      const lic = detectLicFromCode(ordered[0] || printPB.startCode);
      const prod = String(printPB.productCode || "PROD").trim() || "PROD";

      // Prebuild CSV header
      const csvLines: string[] = ["code,url,serial"];

      setPrintProgress({ done: 0, total: ordered.length });

      const concurrency = 8; // tune if needed

      await promisePool(
        ordered,
        concurrency,
        async (code, idx) => {
          const blob = await qrPngBlob(code);
          folder.file(`${code}.png`, blob);

          const serialValue = printPB.serialStart + idx;
          const serial = renderSerial(printPB.serialFormat || "{LIC}-{PROD}-{NNNNNN}", {
            lic,
            prod,
            serial: serialValue,
          });

          const url = buildPublicQrUrl(code);

          // Basic CSV escaping (wrap in quotes if needed)
          const esc = (v: string) => {
            const s = String(v ?? "");
            return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
          };

          csvLines[idx + 1] = `${esc(code)},${esc(url)},${esc(serial)}`;
          return true;
        },
        (done, total) => setPrintProgress({ done, total })
      );

      zip.file("manifest.csv", csvLines.join("\n"));

      const out = await zip.generateAsync({ type: "blob" });

      const fileName = `product-batch-${safeFilePart(printPB.productCode || printPB.id)}-png.zip`;
      saveAs(out, fileName);

      toast({ title: "Downloaded", description: `Generated ${ordered.length} PNG(s).` });
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

  const confirmPrinted = async (pb: ProductBatchRow) => {
    if (!isManufacturer) return;

    const ok = window.confirm(
      `Confirm print for "${pb.productName}" (${pb.productCode})?\n\nThis will mark the product batch as PRINTED in the system.`
    );
    if (!ok) return;

    setLoading(true);
    try {
      const res = await apiClient.confirmProductBatchPrint(pb.id);
      if (!res.success) {
        toast({ title: "Confirm failed", description: res.error || "Error", variant: "destructive" });
        return;
      }
      toast({ title: "Confirmed", description: "Product batch marked as printed." });
      await fetchProductBatches();
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
            <h1 className="text-3xl font-bold">Product Batches</h1>
            <p className="text-muted-foreground">
              {isManufacturer
                ? "Your assigned product batches (download print pack and confirm printing)"
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
                                  disabled={loading}
                                  onClick={() => openPrintPack(pb)}
                                >
                                  <Download className="mr-2 h-4 w-4" />
                                  Print pack
                                </Button>
                                <Button
                                  size="sm"
                                  disabled={loading || printed}
                                  onClick={() => confirmPrinted(pb)}
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
                        </SelectItem>
                      ))
                    )}
                  </SelectContent>
                </Select>
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
                  />
                </div>
                <div className="space-y-2">
                  <Label>QR End Number</Label>
                  <Input
                    type="number"
                    value={endNumber}
                    onChange={(e) => setEndNumber(parseInt(e.target.value || "0", 10))}
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
              setPrintProgress({ done: 0, total: 0 });
            }
          }}
        >
          <DialogContent className="sm:max-w-[620px] max-h-[85vh] overflow-y-auto">
            <DialogHeader>
              <DialogTitle>Download Print Pack (PNG ZIP)</DialogTitle>
              <DialogDescription>
                Generates PNG QR images for this product batch using the public URL settings (and includes manifest.csv).
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

                {printing && (
                  <div className="text-sm text-muted-foreground">
                    Generating… {printProgress.done}/{printProgress.total}
                  </div>
                )}

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

