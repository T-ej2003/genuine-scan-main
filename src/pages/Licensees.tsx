// src/pages/Licensees.tsx

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
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";

import { Label } from "@/components/ui/label";
import { useToast } from "@/hooks/use-toast";

import {
  Plus,
  Search,
  Building2,
  MoreHorizontal,
  Edit,
  Trash2,
  Download,
  UserPlus,
  PackagePlus,
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
import { saveAs } from "file-saver";

/* ===================== TYPES ===================== */

type LicenseeRow = {
  id: string;
  name: string;
  prefix: string;
  description?: string | null;
  isActive: boolean;
  createdAt: string;

  _count?: { users: number; qrCodes: number; batches: number };

  latestRange?: {
    startCode: string;
    endCode: string;
    totalCodes: number;
    createdAt: string;
  } | null;
};

type CreateLicenseeForm = {
  // Licensee
  name: string;
  prefix: string;
  description: string;
  isActive: boolean;

  // Required: create licensee admin (backend expects this)
  adminName: string;
  adminEmail: string;
  adminPassword: string;

  // QR Range
  rangeStart: string;
  rangeEnd: string;

  // Optional: create manufacturer now
  createManufacturerNow: boolean;
  manufacturerName: string;
  manufacturerEmail: string;
  manufacturerPassword: string;

  // Optional: allocate initial batch now
  allocateInitialBatch: boolean;
  initialBatchQty: string;
  initialBatchName: string;
  initialRequestNote: string;
};

type EditLicenseeForm = {
  id: string;
  name: string;
  description: string;
  isActive: boolean;
};

type CreateUserForm = {
  licenseeId: string;
  name: string;
  email: string;
  password: string;
  role: "LICENSEE_ADMIN" | "MANUFACTURER";
};

type ManufacturerRow = {
  id: string;
  name: string;
  email: string;
  isActive: boolean;
};

type AllocateBatchForm = {
  licenseeId: string;
  manufacturerId: string;
  quantity: string;
  name: string;
  requestNote: string;
};

/* ===================== HELPERS ===================== */

const isValidPrefix = (prefix: string) => /^[A-Z0-9]{1,5}$/.test(prefix);

const toInt = (v: string) => {
  const n = parseInt(String(v || "").trim(), 10);
  return Number.isFinite(n) ? n : NaN;
};

/* ===================== COMPONENT ===================== */

export default function Licensees() {
  const { toast } = useToast();

  const [loading, setLoading] = useState(true);
  const [licensees, setLicensees] = useState<LicenseeRow[]>([]);
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState<"all" | "active" | "inactive">("all");

  // Create Licensee dialog
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [creating, setCreating] = useState(false);
  const [createForm, setCreateForm] = useState<CreateLicenseeForm>({
    name: "",
    prefix: "A",
    description: "",
    isActive: true,

    adminName: "",
    adminEmail: "",
    adminPassword: "",

    rangeStart: "1",
    rangeEnd: "150000",

    createManufacturerNow: true,
    manufacturerName: "",
    manufacturerEmail: "",
    manufacturerPassword: "",

    allocateInitialBatch: true,
    initialBatchQty: "1000",
    initialBatchName: "",
    initialRequestNote: "",
  });

  // Edit Licensee dialog
  const [isEditOpen, setIsEditOpen] = useState(false);
  const [savingEdit, setSavingEdit] = useState(false);
  const [editForm, setEditForm] = useState<EditLicenseeForm | null>(null);

  // Create User dialog
  const [isUserOpen, setIsUserOpen] = useState(false);
  const [creatingUser, setCreatingUser] = useState(false);
  const [userForm, setUserForm] = useState<CreateUserForm | null>(null);

  // Allocate batch dialog (existing licensee)
  const [allocOpen, setAllocOpen] = useState(false);
  const [allocLoading, setAllocLoading] = useState(false);
  const [allocManufacturers, setAllocManufacturers] = useState<ManufacturerRow[]>([]);
  const [allocStats, setAllocStats] = useState<any>(null);
  const [allocForm, setAllocForm] = useState<AllocateBatchForm | null>(null);

  /* ===================== LOAD ===================== */

  const load = async () => {
    setLoading(true);
    const res = await apiClient.getLicensees();
    if (!res.success) {
      toast({
        title: "Failed to load",
        description: res.error || "Could not load licensees",
        variant: "destructive",
      });
      setLicensees([]);
      setLoading(false);
      return;
    }
    setLicensees(((res.data as any) || []) as LicenseeRow[]);
    setLoading(false);
  };

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();

    return (licensees || [])
      .filter((l) => {
        if (statusFilter === "active") return !!l.isActive;
        if (statusFilter === "inactive") return !l.isActive;
        return true;
      })
      .filter((l) => {
        if (!q) return true;
        return (
          (l.name || "").toLowerCase().includes(q) ||
          (l.prefix || "").toLowerCase().includes(q) ||
          (l.description || "").toLowerCase().includes(q)
        );
      });
  }, [licensees, search, statusFilter]);

  /* ===================== EXPORT CSV ===================== */

  const exportCsv = async () => {
    try {
      const blob = await apiClient.exportLicenseesCsv();
      saveAs(blob, "licensees.csv");
    } catch (e: any) {
      toast({
        title: "Export failed",
        description: e?.message || "Could not export",
        variant: "destructive",
      });
    }
  };

  /* ===================== CREATE LICENSEE FLOW ===================== */

  const resetCreateForm = () => {
    setCreateForm({
      name: "",
      prefix: "A",
      description: "",
      isActive: true,

      adminName: "",
      adminEmail: "",
      adminPassword: "",

      rangeStart: "1",
      rangeEnd: "150000",

      createManufacturerNow: true,
      manufacturerName: "",
      manufacturerEmail: "",
      manufacturerPassword: "",

      allocateInitialBatch: true,
      initialBatchQty: "1000",
      initialBatchName: "",
      initialRequestNote: "",
    });
  };

  const onCreateSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (creating) return;

    const name = createForm.name.trim();
    const prefix = createForm.prefix.trim().toUpperCase();
    const description = createForm.description.trim();

    const adminName = createForm.adminName.trim();
    const adminEmail = createForm.adminEmail.trim().toLowerCase();
    const adminPassword = createForm.adminPassword.trim();

    const rangeStart = toInt(createForm.rangeStart);
    const rangeEnd = toInt(createForm.rangeEnd);

    if (!name) {
      toast({ title: "Missing fields", description: "Licensee name is required.", variant: "destructive" });
      return;
    }

    if (!isValidPrefix(prefix)) {
      toast({
        title: "Invalid prefix",
        description: "Prefix must be 1–5 characters (A–Z / 0–9).",
        variant: "destructive",
      });
      return;
    }

    // Backend requires admin credentials for licensee creation
    if (!adminName || !adminEmail || adminPassword.length < 6) {
      toast({
        title: "Admin details required",
        description: "Admin Name, Email and Password (min 6 chars) are required.",
        variant: "destructive",
      });
      return;
    }

    if (!Number.isFinite(rangeStart) || !Number.isFinite(rangeEnd) || rangeEnd < rangeStart) {
      toast({
        title: "Invalid range",
        description: "Range End must be greater than or equal to Range Start.",
        variant: "destructive",
      });
      return;
    }

    const wantMfg = !!createForm.createManufacturerNow;
    const wantInitialBatch = !!createForm.allocateInitialBatch;

    const mfgName = createForm.manufacturerName.trim();
    const mfgEmail = createForm.manufacturerEmail.trim().toLowerCase();
    const mfgPass = createForm.manufacturerPassword.trim();

    if (wantMfg) {
      if (!mfgName || !mfgEmail || mfgPass.length < 6) {
        toast({
          title: "Manufacturer details missing",
          description: "Provide Manufacturer Name, Email, and Password (min 6 chars).",
          variant: "destructive",
        });
        return;
      }
    }

    const qty = toInt(createForm.initialBatchQty);
    if (wantInitialBatch) {
      if (!Number.isFinite(qty) || qty <= 0) {
        toast({
          title: "Invalid quantity",
          description: "Initial batch quantity must be a positive number.",
          variant: "destructive",
        });
        return;
      }
      if (!wantMfg) {
        toast({
          title: "Manufacturer required",
          description: "To allocate an initial batch, you must create a manufacturer now.",
          variant: "destructive",
        });
        return;
      }
    }

    setCreating(true);

    try {
      // 1) Create licensee WITH admin (exact backend format)
      const createRes = await apiClient.createLicenseeWithAdmin({
        licensee: {
          name,
          prefix,
          description: description ? description : undefined,
          isActive: true,
        },
        admin: {
          name: adminName,
          email: adminEmail,
          password: adminPassword,
        },
      });

      if (!createRes.success) throw new Error(createRes.error || "Could not create licensee");

      const licenseeId = (createRes.data as any)?.licensee?.id as string;
      if (!licenseeId) throw new Error("Licensee created, but licenseeId was not returned.");

      // 2) Optional: create manufacturer user
      let manufacturerId: string | null = null;
      if (wantMfg) {
        const uRes = await apiClient.createUser({
          name: mfgName,
          email: mfgEmail,
          password: mfgPass,
          role: "MANUFACTURER",
          licenseeId,
        });
        if (!uRes.success) throw new Error(uRes.error || "Manufacturer create failed");
        manufacturerId = (uRes.data as any)?.id || null;
      }

      // 3) Allocate QR range (creates QRCode rows as DORMANT)
      const allocRes = await apiClient.allocateQRRange({
        licenseeId,
        startNumber: rangeStart,
        endNumber: rangeEnd,
      });
      if (!allocRes.success) throw new Error(allocRes.error || "QR range allocation failed");

      // 4) Optional: allocate initial batch by quantity (SUPER_ADMIN)
      if (wantInitialBatch) {
        if (!manufacturerId) throw new Error("Initial batch requires a manufacturer (creation failed).");

        const bRes = await apiClient.adminAllocateBatch({
          licenseeId,
          manufacturerId,
          quantity: qty,
          name: createForm.initialBatchName.trim() || undefined,
          requestNote: createForm.initialRequestNote.trim() || undefined,
        });

        if (!bRes.success) throw new Error(bRes.error || "Initial batch allocation failed");
      }

      toast({
        title: "Created",
        description: `Licensee ${name} (${prefix}) created. Range allocated: ${rangeEnd - rangeStart + 1}.`,
      });

      setIsCreateOpen(false);
      resetCreateForm();
      await load();
    } catch (e: any) {
      toast({
        title: "Create failed",
        description: e?.message || "Error",
        variant: "destructive",
      });
      await load();
    } finally {
      setCreating(false);
    }
  };

  /* ===================== EDIT / TOGGLE ACTIVE ===================== */

  const openEdit = (l: LicenseeRow) => {
    setEditForm({
      id: l.id,
      name: l.name || "",
      description: (l.description || "") as string,
      isActive: !!l.isActive,
    });
    setIsEditOpen(true);
  };

  const onEditSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editForm || savingEdit) return;

    const name = editForm.name.trim();
    const description = editForm.description.trim();

    if (!name) {
      toast({ title: "Missing name", description: "Name is required.", variant: "destructive" });
      return;
    }

    setSavingEdit(true);

    const res = await apiClient.updateLicensee(editForm.id, {
      name,
      description,
      isActive: editForm.isActive,
    });

    if (!res.success) {
      toast({
        title: "Update failed",
        description: res.error || "Could not update licensee",
        variant: "destructive",
      });
      setSavingEdit(false);
      return;
    }

    toast({ title: "Updated", description: "Licensee updated successfully." });
    setSavingEdit(false);
    setIsEditOpen(false);
    setEditForm(null);
    await load();
  };

  const toggleActive = async (l: LicenseeRow) => {
    const next = !l.isActive;
    const res = await apiClient.updateLicensee(l.id, { isActive: next });
    if (!res.success) {
      toast({
        title: "Update failed",
        description: res.error || "Could not update status",
        variant: "destructive",
      });
      return;
    }

    toast({
      title: next ? "Activated" : "Deactivated",
      description: `${l.name} is now ${next ? "active" : "inactive"}.`,
    });

    setLicensees((prev) => prev.map((x) => (x.id === l.id ? { ...x, isActive: next } : x)));
  };

  /* ===================== HARD DELETE (SAFE UI) ===================== */

  const hardDelete = async (l: LicenseeRow) => {
    const users = l._count?.users || 0;
    const batches = l._count?.batches || 0;
    const qrCodes = l._count?.qrCodes || 0;

    if (users || batches || qrCodes || l.latestRange) {
      toast({
        title: "Cannot hard delete",
        description: "This licensee has linked data. Deactivate it instead.",
        variant: "destructive",
      });
      return;
    }

    const ok = window.confirm(`HARD DELETE "${l.name}"?\n\nThis cannot be undone.`);
    if (!ok) return;

    // Optimistic remove
    setLicensees((prev) => prev.filter((x) => x.id !== l.id));

    const res = await apiClient.deleteLicensee(l.id);
    if (!res.success) {
      toast({
        title: "Delete failed",
        description: res.error || "Error",
        variant: "destructive",
      });
      await load();
      return;
    }

    toast({ title: "Deleted", description: `${l.name} removed.` });
  };

  /* ===================== CREATE USER ===================== */

  const openCreateUser = (licenseeId: string) => {
    setUserForm({
      licenseeId,
      name: "",
      email: "",
      password: "",
      role: "MANUFACTURER",
    });
    setIsUserOpen(true);
  };

  const submitCreateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!userForm || creatingUser) return;

    const name = userForm.name.trim();
    const email = userForm.email.trim().toLowerCase();
    const password = userForm.password.trim();

    if (!name || !email || password.length < 6 || !userForm.role || !userForm.licenseeId) {
      toast({
        title: "Missing fields",
        description: "Name, Email, Password (min 6), and Role are required.",
        variant: "destructive",
      });
      return;
    }

    setCreatingUser(true);

    const res = await apiClient.createUser({
      name,
      email,
      password,
      role: userForm.role,
      licenseeId: userForm.licenseeId,
    });

    if (!res.success) {
      toast({
        title: "Create user failed",
        description: res.error || "Could not create user",
        variant: "destructive",
      });
      setCreatingUser(false);
      return;
    }

    toast({ title: "User created", description: `${userForm.role} created successfully.` });
    setCreatingUser(false);
    setIsUserOpen(false);
    setUserForm(null);
    await load();
  };

  /* ===================== ALLOCATE BATCH (EXISTING LICENSEE) ===================== */

  const openAllocateBatch = async (l: LicenseeRow) => {
    setAllocOpen(true);
    setAllocLoading(true);
    setAllocManufacturers([]);
    setAllocStats(null);

    setAllocForm({
      licenseeId: l.id,
      manufacturerId: "",
      quantity: "1000",
      name: "",
      requestNote: "",
    });

    try {
      const [mRes, sRes] = await Promise.all([
        apiClient.getManufacturers({ licenseeId: l.id, includeInactive: false }),
        apiClient.getQRStats(l.id),
      ]);

      if (mRes.success) setAllocManufacturers(((mRes.data as any) || []) as ManufacturerRow[]);
      if (sRes.success) setAllocStats(sRes.data || null);
    } finally {
      setAllocLoading(false);
    }
  };

  const submitAllocateBatch = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!allocForm) return;

    const qty = toInt(allocForm.quantity);

    if (!allocForm.manufacturerId) {
      toast({
        title: "Select manufacturer",
        description: "Choose which manufacturer gets this batch.",
        variant: "destructive",
      });
      return;
    }

    if (!Number.isFinite(qty) || qty <= 0) {
      toast({
        title: "Invalid quantity",
        description: "Quantity must be a positive number.",
        variant: "destructive",
      });
      return;
    }

    const dormant = (allocStats?.dormant ?? allocStats?.byStatus?.DORMANT ?? 0) as number;
    if (dormant && qty > dormant) {
      toast({
        title: "Not enough unassigned codes",
        description: `Requested ${qty} but only ${dormant} unassigned (DORMANT) available.`,
        variant: "destructive",
      });
      return;
    }

    try {
      const res = await apiClient.adminAllocateBatch({
        licenseeId: allocForm.licenseeId,
        manufacturerId: allocForm.manufacturerId,
        quantity: qty,
        name: allocForm.name.trim() || undefined,
        requestNote: allocForm.requestNote.trim() || undefined,
      });

      if (!res.success) throw new Error(res.error || "Allocation failed");

      toast({ title: "Batch allocated", description: `Allocated ${qty} codes to manufacturer.` });
      setAllocOpen(false);
      setAllocForm(null);
      await load();
    } catch (e: any) {
      toast({
        title: "Allocation failed",
        description: e?.message || "Error",
        variant: "destructive",
      });
    }
  };

  /* ===================== RENDER ===================== */

  return (
    <DashboardLayout>
      <div className="space-y-6">
        {/* HEADER */}
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div>
            <h1 className="text-3xl font-bold">Licensees</h1>
            <p className="text-muted-foreground">Manage licensee organizations and QR allocations</p>
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            <Button variant="outline" onClick={load} disabled={loading}>
              Refresh
            </Button>

            <Button variant="outline" onClick={exportCsv}>
              <Download className="mr-2 h-4 w-4" />
              Export CSV
            </Button>

            <Dialog open={isCreateOpen} onOpenChange={setIsCreateOpen}>
              <DialogTrigger asChild>
                <Button>
                  <Plus className="mr-2 h-4 w-4" />
                  Add Licensee
                </Button>
              </DialogTrigger>

              <DialogContent className="sm:max-w-[720px] max-h-[85vh] overflow-y-auto">
                <DialogHeader>
                  <DialogTitle>Create New Licensee</DialogTitle>
                  <DialogDescription>
                    Creates the licensee + admin, allocates a QR range, and (optionally) creates a manufacturer + initial batch.
                  </DialogDescription>
                </DialogHeader>

                <form className="space-y-4 mt-4" onSubmit={onCreateSubmit}>
                  {/* Licensee basics */}
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label>Organization Name</Label>
                      <Input
                        value={createForm.name}
                        onChange={(e) => setCreateForm((p) => ({ ...p, name: e.target.value }))}
                        placeholder="Acme Corp"
                        disabled={creating}
                      />
                    </div>

                    <div className="space-y-2">
                      <Label>Prefix</Label>
                      <Input
                        value={createForm.prefix}
                        onChange={(e) => setCreateForm((p) => ({ ...p, prefix: e.target.value.toUpperCase() }))}
                        placeholder="A"
                        maxLength={5}
                        disabled={creating}
                      />
                      <p className="text-xs text-muted-foreground">1–5 chars, A–Z / 0–9 (e.g. A, ACME, 7X)</p>
                    </div>
                  </div>

                  <div className="space-y-2">
                    <Label>Description</Label>
                    <Input
                      value={createForm.description}
                      onChange={(e) => setCreateForm((p) => ({ ...p, description: e.target.value }))}
                      placeholder="Short note about this licensee"
                      disabled={creating}
                    />
                  </div>

                  {/* Required admin */}
                  <div className="rounded-md border p-3 space-y-3">
                    <p className="text-sm font-medium">Licensee Admin (required)</p>

                    <div className="grid grid-cols-2 gap-4">
                      <div className="space-y-2">
                        <Label>Admin Name</Label>
                        <Input
                          value={createForm.adminName}
                          onChange={(e) => setCreateForm((p) => ({ ...p, adminName: e.target.value }))}
                          placeholder="Admin full name"
                          disabled={creating}
                        />
                      </div>

                      <div className="space-y-2">
                        <Label>Admin Email</Label>
                        <Input
                          value={createForm.adminEmail}
                          onChange={(e) => setCreateForm((p) => ({ ...p, adminEmail: e.target.value }))}
                          placeholder="admin@licensee.com"
                          disabled={creating}
                        />
                      </div>

                      <div className="space-y-2 col-span-2">
                        <Label>Admin Password</Label>
                        <Input
                          type="password"
                          value={createForm.adminPassword}
                          onChange={(e) => setCreateForm((p) => ({ ...p, adminPassword: e.target.value }))}
                          placeholder="Min 6 chars"
                          disabled={creating}
                        />
                      </div>
                    </div>
                  </div>

                  {/* QR range */}
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label>Range Start</Label>
                      <Input
                        type="number"
                        value={createForm.rangeStart}
                        onChange={(e) => setCreateForm((p) => ({ ...p, rangeStart: e.target.value }))}
                        disabled={creating}
                      />
                    </div>

                    <div className="space-y-2">
                      <Label>Range End</Label>
                      <Input
                        type="number"
                        value={createForm.rangeEnd}
                        onChange={(e) => setCreateForm((p) => ({ ...p, rangeEnd: e.target.value }))}
                        disabled={creating}
                      />
                    </div>
                  </div>

                  {/* Optional manufacturer */}
                  <div className="rounded-md border p-3 space-y-3">
                    <div className="flex items-center justify-between gap-3">
                      <Label>Create Manufacturer now</Label>
                      <Button
                        type="button"
                        variant={createForm.createManufacturerNow ? "default" : "secondary"}
                        onClick={() => setCreateForm((p) => ({ ...p, createManufacturerNow: !p.createManufacturerNow }))}
                        disabled={creating}
                      >
                        {createForm.createManufacturerNow ? "Yes" : "No"}
                      </Button>
                    </div>

                    {createForm.createManufacturerNow && (
                      <div className="grid grid-cols-2 gap-4">
                        <div className="space-y-2">
                          <Label>Manufacturer Name</Label>
                          <Input
                            value={createForm.manufacturerName}
                            onChange={(e) => setCreateForm((p) => ({ ...p, manufacturerName: e.target.value }))}
                            placeholder="Factory A"
                            disabled={creating}
                          />
                        </div>

                        <div className="space-y-2">
                          <Label>Manufacturer Email</Label>
                          <Input
                            value={createForm.manufacturerEmail}
                            onChange={(e) => setCreateForm((p) => ({ ...p, manufacturerEmail: e.target.value }))}
                            placeholder="factory@acme.com"
                            disabled={creating}
                          />
                        </div>

                        <div className="space-y-2 col-span-2">
                          <Label>Manufacturer Password</Label>
                          <Input
                            type="password"
                            value={createForm.manufacturerPassword}
                            onChange={(e) => setCreateForm((p) => ({ ...p, manufacturerPassword: e.target.value }))}
                            placeholder="Min 6 chars"
                            disabled={creating}
                          />
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Optional initial batch */}
                  <div className="rounded-md border p-3 space-y-3">
                    <div className="flex items-center justify-between gap-3">
                      <Label>Allocate initial batch to manufacturer</Label>
                      <Button
                        type="button"
                        variant={createForm.allocateInitialBatch ? "default" : "secondary"}
                        onClick={() => setCreateForm((p) => ({ ...p, allocateInitialBatch: !p.allocateInitialBatch }))}
                        disabled={creating}
                      >
                        {createForm.allocateInitialBatch ? "Yes" : "No"}
                      </Button>
                    </div>

                    {createForm.allocateInitialBatch && (
                      <div className="grid grid-cols-2 gap-4">
                        <div className="space-y-2">
                          <Label>Quantity</Label>
                          <Input
                            type="number"
                            value={createForm.initialBatchQty}
                            onChange={(e) => setCreateForm((p) => ({ ...p, initialBatchQty: e.target.value }))}
                            disabled={creating}
                          />
                        </div>

                        <div className="space-y-2">
                          <Label>Batch Name (optional)</Label>
                          <Input
                            value={createForm.initialBatchName}
                            onChange={(e) => setCreateForm((p) => ({ ...p, initialBatchName: e.target.value }))}
                            placeholder="Launch Batch"
                            disabled={creating}
                          />
                        </div>

                        <div className="space-y-2 col-span-2">
                          <Label>Request note (optional)</Label>
                          <Input
                            value={createForm.initialRequestNote}
                            onChange={(e) => setCreateForm((p) => ({ ...p, initialRequestNote: e.target.value }))}
                            placeholder='e.g. "Manufacturer requested 1000 labels for PO#1234"'
                            disabled={creating}
                          />
                        </div>

                        {!createForm.createManufacturerNow && (
                          <p className="text-xs text-muted-foreground col-span-2">
                            Initial batch requires a manufacturer. Turn on “Create Manufacturer now”.
                          </p>
                        )}
                      </div>
                    )}
                  </div>

                  <div className="flex justify-end gap-3 pt-2">
                    <Button
                      type="button"
                      variant="outline"
                      onClick={() => setIsCreateOpen(false)}
                      disabled={creating}
                    >
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

        {/* SEARCH + FILTER */}
        <Card>
          <CardHeader className="pb-4">
            <div className="flex flex-col md:flex-row md:items-center gap-3">
              <div className="relative flex-1">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Search licensees..."
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  className="pl-9"
                />
              </div>

              <Select value={statusFilter} onValueChange={(v) => setStatusFilter(v as any)}>
                <SelectTrigger className="w-[180px]">
                  <SelectValue placeholder="Status filter" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All</SelectItem>
                  <SelectItem value="active">Active</SelectItem>
                  <SelectItem value="inactive">Inactive</SelectItem>
                </SelectContent>
              </Select>
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
                      <TableHead>Licensee</TableHead>
                      <TableHead>Prefix</TableHead>
                      <TableHead>Latest QR Range</TableHead>
                      <TableHead className="text-right">Users</TableHead>
                      <TableHead className="text-right">Batches</TableHead>
                      <TableHead className="text-right">QR Codes</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Created</TableHead>
                      <TableHead className="w-[50px]" />
                    </TableRow>
                  </TableHeader>

                  <TableBody>
                    {filtered.map((l) => {
                      const usersCount = l._count?.users ?? 0;
                      const batchesCount = l._count?.batches ?? 0;
                      const qrCount = l._count?.qrCodes ?? 0;

                      const latest = l.latestRange;
                      const latestRangeText = latest ? `${latest.startCode} → ${latest.endCode}` : "—";

                      return (
                        <TableRow key={l.id}>
                          <TableCell>
                            <div className="flex items-center gap-3">
                              <div className="h-10 w-10 rounded-lg bg-primary/10 flex items-center justify-center">
                                <Building2 className="h-5 w-5 text-primary" />
                              </div>
                              <div>
                                <p className="font-medium">{l.name}</p>
                                <p className="text-xs text-muted-foreground">{l.description || "—"}</p>
                              </div>
                            </div>
                          </TableCell>

                          <TableCell>
                            <Badge variant="outline" className="font-mono">
                              {l.prefix}
                            </Badge>
                          </TableCell>

                          <TableCell className="font-mono text-xs">{latestRangeText}</TableCell>

                          <TableCell className="text-right">{usersCount}</TableCell>
                          <TableCell className="text-right">{batchesCount}</TableCell>
                          <TableCell className="text-right">{qrCount}</TableCell>

                          <TableCell>
                            <Badge variant={l.isActive ? "default" : "secondary"}>
                              {l.isActive ? "Active" : "Inactive"}
                            </Badge>
                          </TableCell>

                          <TableCell className="text-muted-foreground">
                            {l.createdAt ? format(new Date(l.createdAt), "MMM d, yyyy") : "—"}
                          </TableCell>

                          <TableCell>
                            <DropdownMenu>
                              <DropdownMenuTrigger asChild>
                                <Button variant="ghost" size="icon">
                                  <MoreHorizontal className="h-4 w-4" />
                                </Button>
                              </DropdownMenuTrigger>

                              <DropdownMenuContent align="end">
                                <DropdownMenuItem onClick={() => openAllocateBatch(l)}>
                                  <PackagePlus className="mr-2 h-4 w-4" />
                                  Allocate Batch
                                </DropdownMenuItem>

                                <DropdownMenuItem onClick={() => openCreateUser(l.id)}>
                                  <UserPlus className="mr-2 h-4 w-4" />
                                  Create User
                                </DropdownMenuItem>

                                <DropdownMenuItem onClick={() => openEdit(l)}>
                                  <Edit className="mr-2 h-4 w-4" />
                                  Edit
                                </DropdownMenuItem>

                                <DropdownMenuItem onClick={() => toggleActive(l)}>
                                  <Trash2 className="mr-2 h-4 w-4" />
                                  {l.isActive ? "Deactivate" : "Activate"}
                                </DropdownMenuItem>

                                <DropdownMenuItem className="text-destructive" onClick={() => hardDelete(l)}>
                                  <Trash2 className="mr-2 h-4 w-4" />
                                  Hard Delete
                                </DropdownMenuItem>
                              </DropdownMenuContent>
                            </DropdownMenu>
                          </TableCell>
                        </TableRow>
                      );
                    })}

                    {filtered.length === 0 && (
                      <TableRow>
                        <TableCell colSpan={9} className="text-center text-sm text-muted-foreground">
                          No licensees found.
                        </TableCell>
                      </TableRow>
                    )}
                  </TableBody>
                </Table>
              </div>
            )}
          </CardContent>
        </Card>

        {/* EDIT DIALOG */}
        <Dialog open={isEditOpen} onOpenChange={setIsEditOpen}>
          <DialogContent className="sm:max-w-[520px] max-h-[85vh] overflow-y-auto">
            <DialogHeader>
              <DialogTitle>Edit Licensee</DialogTitle>
              <DialogDescription>Update name/description/status.</DialogDescription>
            </DialogHeader>

            {editForm && (
              <form className="space-y-4 mt-4" onSubmit={onEditSubmit}>
                <div className="space-y-2">
                  <Label>Organization Name</Label>
                  <Input value={editForm.name} onChange={(e) => setEditForm((p) => (p ? { ...p, name: e.target.value } : p))} />
                </div>

                <div className="space-y-2">
                  <Label>Description</Label>
                  <Input
                    value={editForm.description}
                    onChange={(e) => setEditForm((p) => (p ? { ...p, description: e.target.value } : p))}
                  />
                </div>

                <div className="flex items-center justify-between">
                  <Label>Status</Label>
                  <Button
                    type="button"
                    variant={editForm.isActive ? "default" : "secondary"}
                    onClick={() => setEditForm((p) => (p ? { ...p, isActive: !p.isActive } : p))}
                  >
                    {editForm.isActive ? "Active" : "Inactive"}
                  </Button>
                </div>

                <div className="flex justify-end gap-3 pt-2">
                  <Button type="button" variant="outline" onClick={() => setIsEditOpen(false)} disabled={savingEdit}>
                    Cancel
                  </Button>
                  <Button type="submit" disabled={savingEdit}>
                    {savingEdit ? "Saving..." : "Save"}
                  </Button>
                </div>
              </form>
            )}
          </DialogContent>
        </Dialog>

        {/* CREATE USER DIALOG */}
        <Dialog open={isUserOpen} onOpenChange={setIsUserOpen}>
          <DialogContent className="sm:max-w-[520px] max-h-[85vh] overflow-y-auto">
            <DialogHeader>
              <DialogTitle>Create User</DialogTitle>
              <DialogDescription>Create a LICENSEE_ADMIN or MANUFACTURER for this licensee.</DialogDescription>
            </DialogHeader>

            {userForm && (
              <form className="space-y-4 mt-4" onSubmit={submitCreateUser}>
                <div className="space-y-2">
                  <Label>Name</Label>
                  <Input
                    value={userForm.name}
                    onChange={(e) => setUserForm((p) => (p ? { ...p, name: e.target.value } : p))}
                    placeholder="Full name"
                    disabled={creatingUser}
                  />
                </div>

                <div className="space-y-2">
                  <Label>Email</Label>
                  <Input
                    value={userForm.email}
                    onChange={(e) => setUserForm((p) => (p ? { ...p, email: e.target.value } : p))}
                    placeholder="email@example.com"
                    disabled={creatingUser}
                  />
                </div>

                <div className="space-y-2">
                  <Label>Password</Label>
                  <Input
                    type="password"
                    value={userForm.password}
                    onChange={(e) => setUserForm((p) => (p ? { ...p, password: e.target.value } : p))}
                    placeholder="Min 6 chars"
                    disabled={creatingUser}
                  />
                </div>

                <div className="space-y-2">
                  <Label>Role</Label>
                  <Select
                    value={userForm.role}
                    onValueChange={(v) => setUserForm((p) => (p ? { ...p, role: v as any } : p))}
                    disabled={creatingUser}
                  >
                    <SelectTrigger>
                      <SelectValue placeholder="Select role" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="MANUFACTURER">MANUFACTURER</SelectItem>
                      <SelectItem value="LICENSEE_ADMIN">LICENSEE_ADMIN</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div className="flex justify-end gap-3 pt-2">
                  <Button type="button" variant="outline" onClick={() => setIsUserOpen(false)} disabled={creatingUser}>
                    Cancel
                  </Button>
                  <Button type="submit" disabled={creatingUser}>
                    {creatingUser ? "Creating..." : "Create User"}
                  </Button>
                </div>
              </form>
            )}
          </DialogContent>
        </Dialog>

        {/* ALLOCATE BATCH DIALOG */}
        <Dialog
          open={allocOpen}
          onOpenChange={(v) => {
            setAllocOpen(v);
            if (!v) {
              setAllocForm(null);
              setAllocManufacturers([]);
              setAllocStats(null);
            }
          }}
        >
          <DialogContent className="sm:max-w-[520px] max-h-[85vh] overflow-y-auto">
            <DialogHeader>
              <DialogTitle>Allocate Batch to Manufacturer</DialogTitle>
              <DialogDescription>
                Allocates a new batch by quantity from the unassigned pool (DORMANT codes).
              </DialogDescription>
            </DialogHeader>

            {allocLoading || !allocForm ? (
              <div className="text-sm text-muted-foreground">Loading…</div>
            ) : (
              <form className="space-y-4 mt-2" onSubmit={submitAllocateBatch}>
                <div className="rounded-md border p-3 text-sm">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Unassigned available (DORMANT):</span>
                    <span className="font-medium">
                      {allocStats?.dormant ?? allocStats?.byStatus?.DORMANT ?? 0}
                    </span>
                  </div>
                </div>

                <div className="space-y-2">
                  <Label>Manufacturer</Label>
                  <Select
                    value={allocForm.manufacturerId}
                    onValueChange={(v) => setAllocForm((p) => (p ? { ...p, manufacturerId: v } : p))}
                  >
                    <SelectTrigger>
                      <SelectValue placeholder="Select manufacturer" />
                    </SelectTrigger>
                    <SelectContent>
                      {allocManufacturers.length === 0 ? (
                        <SelectItem value="__none__" disabled>
                          No manufacturers found (create one from “Create User”)
                        </SelectItem>
                      ) : (
                        allocManufacturers.map((m) => (
                          <SelectItem key={m.id} value={m.id}>
                            {m.name} ({m.email})
                          </SelectItem>
                        ))
                      )}
                    </SelectContent>
                  </Select>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label>Quantity</Label>
                    <Input
                      type="number"
                      value={allocForm.quantity}
                      onChange={(e) => setAllocForm((p) => (p ? { ...p, quantity: e.target.value } : p))}
                    />
                  </div>

                  <div className="space-y-2">
                    <Label>Batch Name (optional)</Label>
                    <Input
                      value={allocForm.name}
                      onChange={(e) => setAllocForm((p) => (p ? { ...p, name: e.target.value } : p))}
                      placeholder="PO-1234 Batch"
                    />
                  </div>
                </div>

                <div className="space-y-2">
                  <Label>Request note (optional)</Label>
                  <Input
                    value={allocForm.requestNote}
                    onChange={(e) => setAllocForm((p) => (p ? { ...p, requestNote: e.target.value } : p))}
                    placeholder='e.g. "Allocated upon manufacturer request (PO #1234)"'
                  />
                </div>

                <div className="flex justify-end gap-3 pt-2">
                  <Button type="button" variant="outline" onClick={() => setAllocOpen(false)}>
                    Cancel
                  </Button>
                  <Button type="submit">Allocate</Button>
                </div>
              </form>
            )}
          </DialogContent>
        </Dialog>
      </div>
    </DashboardLayout>
  );
}

