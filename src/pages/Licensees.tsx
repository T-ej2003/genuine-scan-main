import React, { useState } from "react";
import { DashboardLayout } from "@/components/layout/DashboardLayout";
import apiClient from "@/lib/api-client";
import { classifyApiError, friendlyEmailDeliveryMessage, getInviteDeliveryState } from "@/lib/api/friendly-errors";
import { useOperationProgress } from "@/hooks/useOperationProgress";
import { useToast } from "@/hooks/use-toast";
import { LicenseeDialogs } from "@/features/licensees/components/LicenseeDialogs";
import { LicenseesWorkspace } from "@/features/licensees/components/LicenseesWorkspace";
import {
  extractCodeIndex,
  isBusyErrorMessage,
  LARGE_QR_ALLOCATION_THRESHOLD,
  toInt,
} from "@/features/licensees/helpers";
import { useCreateLicenseeFlow } from "@/features/licensees/useCreateLicenseeFlow";
import { useLicenseeDirectory } from "@/features/licensees/useLicenseeDirectory";
import type {
  AllocateRangeForm,
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

  const createFlow = useCreateLicenseeFlow({ toast, progress, load, setLicensees });
  const {
    isCreateOpen,
    creating,
    latestInviteLink,
    createForm,
    setLatestInviteLink,
    clearLatestInviteLink,
    updateCreateForm,
    openCreateDialog,
    handleCreateDialogOpenChange,
    onCreateSubmit,
  } = createFlow;

  const [inviteActionLoadingId, setInviteActionLoadingId] = useState<string>("");

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
      const friendly = classifyApiError(res);
      toast({
        title: friendly.title,
        description: friendly.description,
        variant: friendly.destructive ? "destructive" : undefined,
      });
      return;
    }

    const data: any = res.data || {};
    const inviteState = getInviteDeliveryState(data);
    const inviteLink = inviteState.inviteLink;
    if (inviteLink) {
      setLatestInviteLink(inviteLink);
      if (opts?.copyOnly) {
        await copyInviteLink(inviteLink, "Invite link copied");
      }
    }

    toast({
      title:
        inviteState.emailSent === false
          ? opts?.copyOnly
            ? "Invite link generated"
            : "Invite created, email not delivered"
          : opts?.copyOnly
            ? "Invite link generated"
            : "Invite resent",
      description:
        inviteState.emailSent === false
          ? `${friendlyEmailDeliveryMessage(inviteState.emailErrorCode)} Use the invite link to onboard manually.`
          : `Invite sent to ${adminEmail}.`,
      variant: inviteState.emailSent === false ? "destructive" : undefined,
    });

    await load();
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
      const friendly = classifyApiError(res);
      toast({
        title: friendly.title,
        description: friendly.description,
        variant: friendly.destructive ? "destructive" : undefined,
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
      const friendly = classifyApiError(res);
      toast({
        title: friendly.title,
        description: friendly.description,
        variant: friendly.destructive ? "destructive" : undefined,
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
      const friendly = classifyApiError(res);
      toast({
        title: friendly.title,
        description: friendly.description,
        variant: friendly.destructive ? "destructive" : undefined,
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
      const friendly = classifyApiError(res);
      toast({
        title: friendly.title,
        description: friendly.description,
        variant: friendly.destructive ? "destructive" : undefined,
      });
      setCreatingUser(false);
      return;
    }

    const resultData: any = res.data || {};
    if (resultData.linkAction === "LINKED_EXISTING" || resultData.linkAction === "ALREADY_LINKED") {
      toast({
        title: resultData.linkAction === "ALREADY_LINKED" ? "Manufacturer already linked" : "Manufacturer linked",
        description:
          resultData.linkAction === "ALREADY_LINKED"
            ? "This manufacturer is already available under the brand."
            : "Existing manufacturer access was linked to this brand.",
      });
      setCreatingUser(false);
      setIsUserOpen(false);
      setUserForm(null);
      await load();
      return;
    }

    const inviteState = getInviteDeliveryState(resultData);
    if (inviteState.inviteLink) setLatestInviteLink(inviteState.inviteLink);
    toast({
      title: inviteState.emailSent ? "Invite email sent" : "Invite link created, email not sent",
      description: inviteState.emailSent
        ? userForm.role === "LICENSEE_ADMIN"
          ? "Invite sent for Licensee Admin."
          : "Invite sent for Manufacturer Admin."
        : "Copy the invite link or retry sending later.",
      variant: inviteState.emailSent ? undefined : "destructive",
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
        const friendly = classifyApiError(res);
        throw Object.assign(new Error(friendly.description), { friendly });
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
      const friendly = e?.friendly;
      const busy = isBusyErrorMessage(msg);
      toast({
        title: busy ? "Batch busy" : friendly?.title || "Allocation failed",
        description: busy ? "Please retry when the current batch operation finishes." : friendly?.description || "Please retry the allocation.",
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
        onDismissLatestInviteLink={clearLatestInviteLink}
        onRefresh={load}
        loading={loading}
        onExportCsv={exportCsv}
        onOpenCreateDialog={openCreateDialog}
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
        onCreateFormChange={updateCreateForm}
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
