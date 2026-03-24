import React, { useMemo, useState } from "react";
import { DashboardLayout } from "@/components/layout/DashboardLayout";
import apiClient from "@/lib/api-client";
import { useOperationProgress } from "@/hooks/useOperationProgress";
import { useToast } from "@/hooks/use-toast";
import { LicenseeDialogs } from "@/features/licensees/components/LicenseeDialogs";
import { LicenseesWorkspace } from "@/features/licensees/components/LicenseesWorkspace";
import {
  createDefaultLicenseeForm,
  extractCodeIndex,
  isBusyErrorMessage,
  isValidPrefix,
  LARGE_QR_ALLOCATION_THRESHOLD,
  toInt,
} from "@/features/licensees/helpers";
import { useLicenseeDirectory } from "@/features/licensees/useLicenseeDirectory";
import type {
  AllocateRangeForm,
  CreateLicenseeForm,
  CreateUserForm,
  EditLicenseeForm,
  LicenseeRow,
} from "@/features/licensees/types";

export default function Licensees() {
  const { toast } = useToast();
  const progress = useOperationProgress();
  const {
    loading,
    licensees,
    setLicensees,
    search,
    setSearch,
    statusFilter,
    setStatusFilter,
    filtered,
    load,
    exportCsv,
  } = useLicenseeDirectory(toast);

  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [creating, setCreating] = useState(false);
  const [latestInviteLink, setLatestInviteLink] = useState<string>("");
  const [inviteActionLoadingId, setInviteActionLoadingId] = useState<string>("");
  const [createForm, setCreateForm] = useState<CreateLicenseeForm>(createDefaultLicenseeForm);
  const isCreateFormDirty = useMemo(() => {
    return (
      createForm.name.trim() !== "" ||
      createForm.prefix.trim().toUpperCase() !== "A" ||
      createForm.description.trim() !== "" ||
      createForm.brandName.trim() !== "" ||
      createForm.location.trim() !== "" ||
      createForm.website.trim() !== "" ||
      createForm.supportEmail.trim() !== "" ||
      createForm.supportPhone.trim() !== "" ||
      createForm.adminName.trim() !== "" ||
      createForm.adminEmail.trim() !== "" ||
      String(createForm.rangeStart).trim() !== "1" ||
      String(createForm.rangeEnd).trim() !== "150000" ||
      createForm.createManufacturerNow !== true ||
      createForm.manufacturerName.trim() !== "" ||
      createForm.manufacturerEmail.trim() !== ""
    );
  }, [createForm]);

  const [isEditOpen, setIsEditOpen] = useState(false);
  const [savingEdit, setSavingEdit] = useState(false);
  const [editForm, setEditForm] = useState<EditLicenseeForm | null>(null);

  const [isUserOpen, setIsUserOpen] = useState(false);
  const [creatingUser, setCreatingUser] = useState(false);
  const [userForm, setUserForm] = useState<CreateUserForm | null>(null);

  const [rangeOpen, setRangeOpen] = useState(false);
  const [rangeLoading, setRangeLoading] = useState(false);
  const [rangeForm, setRangeForm] = useState<AllocateRangeForm | null>(null);

  const copyInviteLink = async (inviteLink: string, toastTitle: string) => {
    try {
      await navigator.clipboard.writeText(inviteLink);
      toast({ title: toastTitle, description: "Invite link copied to clipboard." });
    } catch {
      toast({
        title: "Copy failed",
        description: "Could not access clipboard. Copy the link manually from the dialog.",
        variant: "destructive",
      });
    }
  };

  const resendAdminInvite = async (licensee: LicenseeRow, opts?: { copyOnly?: boolean }) => {
    const adminEmail = licensee.adminOnboarding?.adminUser?.email || licensee.adminOnboarding?.pendingInvite?.email;
    if (!adminEmail) {
      toast({
        title: "No admin email found",
        description: "This licensee does not have an admin account to invite yet.",
        variant: "destructive",
      });
      return;
    }

    setInviteActionLoadingId(licensee.id);
    const res = await apiClient.resendLicenseeAdminInvite(licensee.id, adminEmail);
    setInviteActionLoadingId("");

    if (!res.success) {
      toast({
        title: "Invite action failed",
        description: res.error || "Could not generate invite link.",
        variant: "destructive",
      });
      return;
    }

    const data: any = res.data || {};
    const inviteLink = String(data.inviteLink || "").trim();
    if (inviteLink) {
      setLatestInviteLink(inviteLink);
      if (opts?.copyOnly) {
        await copyInviteLink(inviteLink, "Invite link copied");
      }
    }

    toast({
      title:
        data.emailDelivered === false
          ? opts?.copyOnly
            ? "Invite link generated"
            : "Invite created, email not delivered"
          : opts?.copyOnly
            ? "Invite link generated"
            : "Invite resent",
      description:
        data.emailDelivered === false
          ? data.deliveryError
            ? `Invite link is ready, but email delivery failed: ${String(data.deliveryError)}`
            : "Invite link is ready, but email delivery failed. Use the copied invite link to onboard manually."
          : `Invite sent to ${adminEmail}.`,
      variant: data.emailDelivered === false ? "destructive" : undefined,
    });

    await load();
  };

  /* ===================== CREATE LICENSEE FLOW ===================== */

  const resetCreateForm = () => {
    setCreateForm(createDefaultLicenseeForm());
  };

  const handleCreateDialogOpenChange = (open: boolean) => {
    if (!open && !creating && isCreateFormDirty) {
      const shouldDiscard = window.confirm("Discard unsaved licensee setup changes?");
      if (!shouldDiscard) return;
    }
    if (!open && !creating) {
      resetCreateForm();
    }
    setIsCreateOpen(open);
  };

  const onCreateSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (creating) return;

    const name = createForm.name.trim();
    const prefix = createForm.prefix.trim().toUpperCase();
    const description = createForm.description.trim();

    const adminName = createForm.adminName.trim();
    const adminEmail = createForm.adminEmail.trim().toLowerCase();

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

    if (!adminName || !adminEmail) {
      toast({
        title: "Admin details required",
        description: "Admin name and email are required.",
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
    const requestedRangeCount = rangeEnd - rangeStart + 1;

    const mfgName = createForm.manufacturerName.trim();
    const mfgEmail = createForm.manufacturerEmail.trim().toLowerCase();

    if (wantMfg) {
      if (!mfgName || !mfgEmail) {
        toast({
          title: "Manufacturer details missing",
          description: "Provide Manufacturer Name and Email.",
          variant: "destructive",
        });
        return;
      }
    }

    const showProvisioningProgress = requestedRangeCount >= LARGE_QR_ALLOCATION_THRESHOLD;
    if (showProvisioningProgress) {
      progress.start({
        title: "Provisioning licensee",
        description: "Creating tenant records and allocating initial QR inventory.",
        phaseLabel: "Provisioning",
        detail: `Preparing ${requestedRangeCount.toLocaleString()} initial QR codes.`,
        mode: "simulated",
        initialValue: 10,
      });
    }

    setCreating(true);
    setLatestInviteLink("");

    try {
      // 1) Create licensee WITH admin (exact backend format)
      if (showProvisioningProgress) {
        progress.update({
          value: 18,
          indeterminate: false,
          phaseLabel: "Tenant setup",
          detail: "Creating licensee and secure invite...",
        });
      }
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
          sendInvite: true,
        },
      });

      if (!createRes.success) throw new Error(createRes.error || "Could not create licensee");

      const adminInvite = (createRes.data as any)?.adminInvite;
      const inviteLink = String(adminInvite?.inviteLink || "").trim();
      const inviteDeliveryError = String(adminInvite?.deliveryError || (createRes.data as any)?.warning || "").trim();
      const inviteDelivered = Boolean(adminInvite && adminInvite.emailDelivered !== false);
      if (inviteLink) setLatestInviteLink(inviteLink);

      const licenseeId = (createRes.data as any)?.licensee?.id as string;
      if (!licenseeId) throw new Error("Licensee created, but licenseeId was not returned.");

      // 2) Optional: create manufacturer user
      if (wantMfg) {
        if (showProvisioningProgress) {
          progress.update({
            value: 34,
            indeterminate: false,
            phaseLabel: "User setup",
            detail: "Creating manufacturer access user...",
          });
        }
        const uRes = await apiClient.inviteUser({
          name: mfgName,
          email: mfgEmail,
          role: "MANUFACTURER",
          licenseeId,
        });
        if (!uRes.success) throw new Error(uRes.error || "Manufacturer create failed");
      }

      // 3) Allocate QR range (creates QRCode rows as DORMANT)
      if (showProvisioningProgress) {
        progress.update({
          value: 56,
          indeterminate: true,
          phaseLabel: "Allocation",
          detail: `Allocating ${requestedRangeCount.toLocaleString()} QR codes...`,
        });
      }
      const allocRes = await apiClient.allocateQRRange({
        licenseeId,
        startNumber: rangeStart,
        endNumber: rangeEnd,
      });
      if (!allocRes.success) throw new Error(allocRes.error || "QR range allocation failed");

      if (showProvisioningProgress) {
        await progress.complete(`Provisioning complete. ${requestedRangeCount.toLocaleString()} QR codes are ready.`);
      }

      toast({
        title: inviteDelivered ? "Licensee created + invite sent" : "Licensee created + invite link ready",
        description: inviteDelivered
          ? `Licensee ${name} created. Invite sent to ${adminEmail}.`
          : inviteDeliveryError
            ? `Licensee ${name} created. Invite link generated, but email delivery failed: ${inviteDeliveryError}`
            : `Licensee ${name} created. Invite link generated for manual onboarding.`,
        variant: !inviteDelivered ? "destructive" : undefined,
      });

      setIsCreateOpen(false);
      resetCreateForm();
      await load();
    } catch (e: any) {
      if (showProvisioningProgress) progress.close();
      const msg = e?.message || "Error";
      const busy = isBusyErrorMessage(msg);
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
      role: "MANUFACTURER",
    });
    setIsUserOpen(true);
  };

  const submitCreateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!userForm || creatingUser) return;

    const name = userForm.name.trim();
    const email = userForm.email.trim().toLowerCase();
    if (!name || !email || !userForm.role || !userForm.licenseeId) {
      toast({
        title: "Missing fields",
        description: "Name, Email, and Role are required.",
        variant: "destructive",
      });
      return;
    }

    setCreatingUser(true);

    const res = await apiClient.inviteUser({
      name,
      email,
      role: userForm.role === "LICENSEE_ADMIN" ? "LICENSEE_ADMIN" : "MANUFACTURER",
      licenseeId: userForm.licenseeId,
    });

    if (!res.success) {
      toast({
        title: "Invite failed",
        description: res.error || "Could not create user",
        variant: "destructive",
      });
      setCreatingUser(false);
      return;
    }

    toast({
      title: "Invite sent",
      description: userForm.role === "LICENSEE_ADMIN" ? "Invite sent for Licensee Admin." : "Invite sent for Manufacturer Admin.",
    });
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
      receivedBatchName: "",
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

    let expectedQuantity = 0;
    let requestPayload:
      | { quantity: number; receivedBatchName?: string }
      | { startNumber: number; endNumber: number; receivedBatchName?: string };

    if (rangeForm.mode === "quantity") {
      const quantity = toInt(rangeForm.quantity);
      if (!Number.isFinite(quantity) || quantity <= 0) {
        toast({
          title: "Invalid quantity",
          description: "Quantity must be a positive number.",
          variant: "destructive",
        });
        return;
      }
      expectedQuantity = quantity;
      requestPayload = {
        quantity,
        receivedBatchName: rangeForm.receivedBatchName.trim() || undefined,
      };
    } else {
      const startNumber = toInt(rangeForm.startNumber);
      const endNumber = toInt(rangeForm.endNumber);
      if (!Number.isFinite(startNumber) || !Number.isFinite(endNumber) || endNumber < startNumber) {
        toast({
          title: "Invalid range",
          description: "Start/End numbers are required, and End must be >= Start.",
          variant: "destructive",
        });
        return;
      }
      expectedQuantity = endNumber - startNumber + 1;
      requestPayload = {
        startNumber,
        endNumber,
        receivedBatchName: rangeForm.receivedBatchName.trim() || undefined,
      };
    }

    const showAllocationProgress = expectedQuantity >= LARGE_QR_ALLOCATION_THRESHOLD;
    if (showAllocationProgress) {
      progress.start({
        title: "Allocating QR inventory",
        description: "Creating new DORMANT QR range and batch records.",
        phaseLabel: "Allocation",
        detail: `Preparing ${expectedQuantity.toLocaleString()} QR codes for this licensee.`,
        mode: "simulated",
        initialValue: 12,
      });
    }

    setRangeLoading(true);
    try {
      const res = await apiClient.allocateLicenseeQrRange(rangeForm.licenseeId, requestPayload);

      if (!res.success) {
        throw new Error(res.error || "Allocation failed");
      }

      const data: any = res.data || {};
      const allocatedCount =
        Number(data.totalCodes) ||
        (Number(data.endNumber) && Number(data.startNumber)
          ? Number(data.endNumber) - Number(data.startNumber) + 1
          : null);

      if (showAllocationProgress) {
        await progress.complete(
          allocatedCount
            ? `Allocated ${Number(allocatedCount).toLocaleString()} QR codes successfully.`
            : "Allocation completed successfully."
        );
      }

      toast({
        title: "Range allocated",
        description: allocatedCount
          ? `Allocated ${allocatedCount} QR codes (DORMANT). Batch: ${data.receivedBatchName || "auto"} (${data.receivedBatchId || "id pending"}).`
          : `Allocated QR codes (DORMANT). Batch: ${data.receivedBatchName || "auto"} (${data.receivedBatchId || "id pending"}).`,
      });

      setRangeOpen(false);
      setRangeForm(null);
      await load();
    } catch (e: any) {
      if (showAllocationProgress) progress.close();
      const msg = e?.message || "Error";
      const busy = isBusyErrorMessage(msg);
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
      <LicenseesWorkspace
        latestInviteLink={latestInviteLink}
        onCopyLatestInviteLink={() => copyInviteLink(latestInviteLink, "Invite link copied")}
        onDismissLatestInviteLink={() => setLatestInviteLink("")}
        onRefresh={load}
        loading={loading}
        onExportCsv={exportCsv}
        onOpenCreateDialog={() => setIsCreateOpen(true)}
        search={search}
        onSearchChange={setSearch}
        statusFilter={statusFilter}
        onStatusFilterChange={setStatusFilter}
        filtered={filtered}
        inviteActionLoadingId={inviteActionLoadingId}
        onOpenAllocateRange={openAllocateRange}
        onOpenCreateUser={openCreateUser}
        onOpenEdit={openEdit}
        onResendAdminInvite={resendAdminInvite}
        onToggleActive={toggleActive}
        onHardDelete={hardDelete}
      />
      <LicenseeDialogs
        isCreateOpen={isCreateOpen}
        onCreateDialogOpenChange={handleCreateDialogOpenChange}
        creating={creating}
        latestInviteLink={latestInviteLink}
        onCopyInviteLink={() => copyInviteLink(latestInviteLink, "Invite link copied")}
        createForm={createForm}
        onCreateFormChange={setCreateForm}
        onCreateSubmit={onCreateSubmit}
        isEditOpen={isEditOpen}
        onEditDialogOpenChange={setIsEditOpen}
        savingEdit={savingEdit}
        editForm={editForm}
        onEditFormChange={setEditForm}
        onEditSubmit={onEditSubmit}
        isUserOpen={isUserOpen}
        onUserDialogOpenChange={setIsUserOpen}
        creatingUser={creatingUser}
        userForm={userForm}
        onUserFormChange={setUserForm}
        onUserSubmit={submitCreateUser}
        rangeOpen={rangeOpen}
        onRangeDialogOpenChange={setRangeOpen}
        rangeLoading={rangeLoading}
        rangeForm={rangeForm}
        onRangeFormChange={setRangeForm}
        onRangeSubmit={submitAllocateRange}
        progressState={progress.state}
      />
    </DashboardLayout>
  );
}
