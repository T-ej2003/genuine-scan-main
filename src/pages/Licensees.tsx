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
import { onMutationEvent } from "@/lib/mutation-events";

import {
  Plus,
  Search,
  Building2,
  MoreHorizontal,
  Edit,
  Trash2,
  Download,
  UserPlus,
  QrCode,
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
  brandName?: string | null;
  location?: string | null;
  website?: string | null;
  supportEmail?: string | null;
  supportPhone?: string | null;
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
  brandName: string;
  location: string;
  website: string;
  supportEmail: string;
  supportPhone: string;

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
};

type EditLicenseeForm = {
  id: string;
  name: string;
  description: string;
  isActive: boolean;
  brandName: string;
  location: string;
  website: string;
  supportEmail: string;
  supportPhone: string;
};

type CreateUserForm = {
  licenseeId: string;
  name: string;
  email: string;
  password: string;
  role: "LICENSEE_ADMIN" | "MANUFACTURER";
};

type AllocateRangeForm = {
  licenseeId: string;
  mode: "quantity" | "range";
  startNumber: string;
  endNumber: string;
  quantity: string;
  lastStartCode: string | null;
  lastEndCode: string | null;
  lastEndNumber: number | null;
  suggestedNextStart: number;
};

/* ===================== HELPERS ===================== */

const isValidPrefix = (prefix: string) => /^[A-Z0-9]{1,5}$/.test(prefix);

const toInt = (v: string) => {
  const n = parseInt(String(v || "").trim(), 10);
  return Number.isFinite(n) ? n : NaN;
};

const extractCodeIndex = (code?: string | null) => {
  const s = String(code || "").trim();
  if (!s) return null;
  const m = s.match(/(\d{10})$/);
  if (!m) return null;
  const n = parseInt(m[1], 10);
  return Number.isFinite(n) ? n : null;
};

/* ===================== COMPONENT ===================== */

export default function Licensees() {
  const { toast } = useToast();

  const [loading, setLoading] = useState(true);
  const [licensees, setLicensees] = useState<LicenseeRow[]>([]);
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState<"all" | "active" | "inactive">("all");

  const isBusyError = (msg?: string) => {
    const m = (msg || "").toLowerCase();
    return m.includes("batch busy") || m.includes("retry") || m.includes("conflict");
  };

  // Create Licensee dialog
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [creating, setCreating] = useState(false);
  const [createForm, setCreateForm] = useState<CreateLicenseeForm>({
    name: "",
    prefix: "A",
    description: "",
    isActive: true,
    brandName: "",
    location: "",
    website: "",
    supportEmail: "",
    supportPhone: "",

    adminName: "",
    adminEmail: "",
    adminPassword: "",

    rangeStart: "1",
    rangeEnd: "150000",

    createManufacturerNow: true,
    manufacturerName: "",
    manufacturerEmail: "",
    manufacturerPassword: "",
  });

  // Edit Licensee dialog
  const [isEditOpen, setIsEditOpen] = useState(false);
  const [savingEdit, setSavingEdit] = useState(false);
  const [editForm, setEditForm] = useState<EditLicenseeForm | null>(null);

  // Create User dialog
  const [isUserOpen, setIsUserOpen] = useState(false);
  const [creatingUser, setCreatingUser] = useState(false);
  const [userForm, setUserForm] = useState<CreateUserForm | null>(null);

  // Allocate QR range dialog (existing licensee)
  const [rangeOpen, setRangeOpen] = useState(false);
  const [rangeLoading, setRangeLoading] = useState(false);
  const [rangeForm, setRangeForm] = useState<AllocateRangeForm | null>(null);

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

  useEffect(() => {
    const off = onMutationEvent(() => {
      load();
    });
    return off;
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
      brandName: "",
      location: "",
      website: "",
      supportEmail: "",
      supportPhone: "",

      adminName: "",
      adminEmail: "",
      adminPassword: "",

      rangeStart: "1",
      rangeEnd: "150000",

      createManufacturerNow: true,
      manufacturerName: "",
      manufacturerEmail: "",
      manufacturerPassword: "",
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

    setCreating(true);

    try {
      // 1) Create licensee WITH admin (exact backend format)
      const createRes = await apiClient.createLicenseeWithAdmin({
        licensee: {
          name,
          prefix,
          description: description ? description : undefined,
          brandName: createForm.brandName.trim() || undefined,
          location: createForm.location.trim() || undefined,
          website: createForm.website.trim() || undefined,
          supportEmail: createForm.supportEmail.trim() || undefined,
          supportPhone: createForm.supportPhone.trim() || undefined,
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
      if (wantMfg) {
        const uRes = await apiClient.createUser({
          name: mfgName,
          email: mfgEmail,
          password: mfgPass,
          role: "MANUFACTURER",
          licenseeId,
        });
        if (!uRes.success) throw new Error(uRes.error || "Manufacturer create failed");
      }

      // 3) Allocate QR range (creates QRCode rows as DORMANT)
      const allocRes = await apiClient.allocateQRRange({
        licenseeId,
        startNumber: rangeStart,
        endNumber: rangeEnd,
      });
      if (!allocRes.success) throw new Error(allocRes.error || "QR range allocation failed");

      toast({
        title: "Created",
        description: `Licensee ${name} (${prefix}) created. Range allocated: ${rangeEnd - rangeStart + 1}.`,
      });

      setIsCreateOpen(false);
      resetCreateForm();
      await load();
    } catch (e: any) {
      const msg = e?.message || "Error";
      const busy = isBusyError(msg);
      toast({
        title: busy ? "Batch busy" : "Create failed",
        description: busy ? "Please retry — batch busy." : msg,
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
      brandName: (l as any).brandName || "",
      location: (l as any).location || "",
      website: (l as any).website || "",
      supportEmail: (l as any).supportEmail || "",
      supportPhone: (l as any).supportPhone || "",
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
      brandName: editForm.brandName.trim() || undefined,
      location: editForm.location.trim() || undefined,
      website: editForm.website.trim() || undefined,
      supportEmail: editForm.supportEmail.trim() || undefined,
      supportPhone: editForm.supportPhone.trim() || undefined,
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

  /* ===================== ALLOCATE QR RANGE (TOP-UP) ===================== */

  const openAllocateRange = (l: LicenseeRow) => {
    const lastStartCode = l.latestRange?.startCode || null;
    const lastEndCode = l.latestRange?.endCode || null;
    const lastEndNumber = extractCodeIndex(lastEndCode);
    const suggestedNextStart = (lastEndNumber ?? 0) + 1;

    setRangeForm({
      licenseeId: l.id,
      mode: "quantity",
      startNumber: String(suggestedNextStart),
      endNumber: "",
      quantity: "1000",
      lastStartCode,
      lastEndCode,
      lastEndNumber,
      suggestedNextStart,
    });
    setRangeOpen(true);
  };

  const submitAllocateRange = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!rangeForm) return;

    setRangeLoading(true);
    try {
      let res;
      if (rangeForm.mode === "quantity") {
        const quantity = toInt(rangeForm.quantity);
        if (!Number.isFinite(quantity) || quantity <= 0) {
          toast({
            title: "Invalid quantity",
            description: "Quantity must be a positive number.",
            variant: "destructive",
          });
          setRangeLoading(false);
          return;
        }
        res = await apiClient.allocateLicenseeQrRange(rangeForm.licenseeId, { quantity });
      } else {
        const startNumber = toInt(rangeForm.startNumber);
        const endNumber = toInt(rangeForm.endNumber);
        if (!Number.isFinite(startNumber) || !Number.isFinite(endNumber) || endNumber < startNumber) {
          toast({
            title: "Invalid range",
            description: "Start/End numbers are required, and End must be >= Start.",
            variant: "destructive",
          });
          setRangeLoading(false);
          return;
        }
        res = await apiClient.allocateLicenseeQrRange(rangeForm.licenseeId, {
          startNumber,
          endNumber,
        });
      }

      if (!res.success) {
        throw new Error(res.error || "Allocation failed");
      }

      const data: any = res.data || {};
      const allocatedCount =
        Number(data.totalCodes) ||
        (Number(data.endNumber) && Number(data.startNumber)
          ? Number(data.endNumber) - Number(data.startNumber) + 1
          : null);

      toast({
        title: "Range allocated",
        description: allocatedCount
          ? `Allocated ${allocatedCount} QR codes to licensee (stored as DORMANT).`
          : "Allocated QR codes to licensee (stored as DORMANT).",
      });

      setRangeOpen(false);
      setRangeForm(null);
      await load();
    } catch (e: any) {
      const msg = e?.message || "Error";
      const busy = isBusyError(msg);
      toast({
        title: busy ? "Batch busy" : "Allocation failed",
        description: busy ? "Please retry — batch busy." : msg,
        variant: "destructive",
      });
    } finally {
      setRangeLoading(false);
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
                    Creates the licensee + admin, allocates a dormant QR range, and optionally creates the first manufacturer user.
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

                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label>Brand Name</Label>
                      <Input
                        value={createForm.brandName}
                        onChange={(e) => setCreateForm((p) => ({ ...p, brandName: e.target.value }))}
                        placeholder="Brand / Label name"
                        disabled={creating}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label>Location</Label>
                      <Input
                        value={createForm.location}
                        onChange={(e) => setCreateForm((p) => ({ ...p, location: e.target.value }))}
                        placeholder="City, Country"
                        disabled={creating}
                      />
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label>Official Website</Label>
                      <Input
                        value={createForm.website}
                        onChange={(e) => setCreateForm((p) => ({ ...p, website: e.target.value }))}
                        placeholder="https://brand.example"
                        disabled={creating}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label>Support Email</Label>
                      <Input
                        value={createForm.supportEmail}
                        onChange={(e) => setCreateForm((p) => ({ ...p, supportEmail: e.target.value }))}
                        placeholder="support@brand.example"
                        disabled={creating}
                      />
                    </div>
                  </div>

                  <div className="space-y-2">
                    <Label>Support Phone</Label>
                    <Input
                      value={createForm.supportPhone}
                      onChange={(e) => setCreateForm((p) => ({ ...p, supportPhone: e.target.value }))}
                      placeholder="+1 555 123 4567"
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
                                <DropdownMenuItem onClick={() => openAllocateRange(l)}>
                                  <QrCode className="mr-2 h-4 w-4" />
                                  Allocate QR Range
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

                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label>Brand Name</Label>
                    <Input
                      value={editForm.brandName}
                      onChange={(e) => setEditForm((p) => (p ? { ...p, brandName: e.target.value } : p))}
                    />
                  </div>
                  <div className="space-y-2">
                    <Label>Location</Label>
                    <Input
                      value={editForm.location}
                      onChange={(e) => setEditForm((p) => (p ? { ...p, location: e.target.value } : p))}
                    />
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label>Official Website</Label>
                    <Input
                      value={editForm.website}
                      onChange={(e) => setEditForm((p) => (p ? { ...p, website: e.target.value } : p))}
                    />
                  </div>
                  <div className="space-y-2">
                    <Label>Support Email</Label>
                    <Input
                      value={editForm.supportEmail}
                      onChange={(e) => setEditForm((p) => (p ? { ...p, supportEmail: e.target.value } : p))}
                    />
                  </div>
                </div>

                <div className="space-y-2">
                  <Label>Support Phone</Label>
                  <Input
                    value={editForm.supportPhone}
                    onChange={(e) => setEditForm((p) => (p ? { ...p, supportPhone: e.target.value } : p))}
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

        {/* ALLOCATE QR RANGE DIALOG */}
        <Dialog
          open={rangeOpen}
          onOpenChange={(v) => {
            setRangeOpen(v);
            if (!v) setRangeForm(null);
          }}
        >
        <DialogContent className="sm:max-w-[520px] max-h-[85vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Allocate QR Range</DialogTitle>
            <DialogDescription>
                Adds new QR codes to the licensee pool in DORMANT state only.
              </DialogDescription>
            </DialogHeader>

            {!rangeForm ? (
              <div className="text-sm text-muted-foreground">No licensee selected.</div>
            ) : (
              <form className="space-y-4 mt-2" onSubmit={submitAllocateRange}>
                <div className="rounded-md border p-3 text-sm space-y-1">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Last allocated range</span>
                    <span className="font-mono">
                      {rangeForm.lastStartCode && rangeForm.lastEndCode
                        ? `${rangeForm.lastStartCode} -> ${rangeForm.lastEndCode}`
                        : "No previous range"}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Last index</span>
                    <span className="font-medium">{rangeForm.lastEndNumber ?? 0}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Suggested next start</span>
                    <span className="font-medium">{rangeForm.suggestedNextStart}</span>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <Button
                    type="button"
                    size="sm"
                    variant={rangeForm.mode === "quantity" ? "default" : "outline"}
                    onClick={() => setRangeForm((p) => (p ? { ...p, mode: "quantity" } : p))}
                  >
                    By quantity
                  </Button>
                  <Button
                    type="button"
                    size="sm"
                    variant={rangeForm.mode === "range" ? "default" : "outline"}
                    onClick={() =>
                      setRangeForm((p) =>
                        p
                          ? {
                              ...p,
                              mode: "range",
                              startNumber: p.startNumber || String(p.suggestedNextStart),
                            }
                          : p
                      )
                    }
                  >
                    By range
                  </Button>
                </div>

                {rangeForm.mode === "quantity" ? (
                  <div className="space-y-2">
                    <Label>Quantity</Label>
                    <Input
                      type="number"
                      value={rangeForm.quantity}
                      onChange={(e) => setRangeForm((p) => (p ? { ...p, quantity: e.target.value } : p))}
                    />
                    <p className="text-xs text-muted-foreground">
                      Backend will allocate from next available index automatically (no overlap).
                    </p>
                  </div>
                ) : (
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label>Start Number</Label>
                    <Input
                      type="number"
                      value={rangeForm.startNumber}
                      onChange={(e) => setRangeForm((p) => (p ? { ...p, startNumber: e.target.value } : p))}
                    />
                  </div>
                  <div className="space-y-2">
                    <Label>End Number</Label>
                    <Input
                      type="number"
                      value={rangeForm.endNumber}
                      onChange={(e) => setRangeForm((p) => (p ? { ...p, endNumber: e.target.value } : p))}
                    />
                  </div>
                </div>
                )}

                <div className="flex justify-end gap-3 pt-2">
                  <Button type="button" variant="outline" onClick={() => setRangeOpen(false)} disabled={rangeLoading}>
                    Cancel
                  </Button>
                  <Button type="submit" disabled={rangeLoading}>
                    {rangeLoading ? "Allocating..." : "Allocate QR"}
                  </Button>
                </div>
              </form>
            )}
          </DialogContent>
        </Dialog>

      </div>
    </DashboardLayout>
  );
}
