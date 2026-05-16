import React, { useMemo, useState } from "react";

import apiClient from "@/lib/api-client";
import { classifyApiError, friendlyEmailDeliveryMessage, getInviteDeliveryState } from "@/lib/api/friendly-errors";
import { useOperationProgress } from "@/hooks/useOperationProgress";
import {
  createDefaultLicenseeForm,
  isBusyErrorMessage,
  isValidPrefix,
  LARGE_QR_ALLOCATION_THRESHOLD,
  toInt,
} from "@/features/licensees/helpers";
import type { CreateLicenseeForm, LicenseeRow } from "@/features/licensees/types";

type ToastLike = (options: {
  title?: string;
  description?: string;
  variant?: "default" | "destructive";
}) => unknown;

type UseCreateLicenseeFlowInput = {
  toast: ToastLike;
  progress: ReturnType<typeof useOperationProgress>;
  load: () => Promise<void>;
  setLicensees: React.Dispatch<React.SetStateAction<LicenseeRow[]>>;
};

export function useCreateLicenseeFlow({
  toast,
  progress,
  load,
  setLicensees,
}: UseCreateLicenseeFlowInput) {
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [creating, setCreating] = useState(false);
  const [latestInviteLink, setLatestInviteLink] = useState("");
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

  const resetCreateForm = () => {
    setLatestInviteLink("");
    setCreateForm(createDefaultLicenseeForm());
  };

  const updateCreateForm: React.Dispatch<React.SetStateAction<CreateLicenseeForm>> = (next) => {
    setLatestInviteLink("");
    setCreateForm(next);
  };

  const openCreateDialog = () => {
    setLatestInviteLink("");
    setIsCreateOpen(true);
  };

  const handleCreateDialogOpenChange = (open: boolean) => {
    if (!open && !creating && isCreateFormDirty) {
      const shouldDiscard = window.confirm("Discard unsaved licensee setup changes?");
      if (!shouldDiscard) return;
    }
    if (!open && !creating) resetCreateForm();
    setIsCreateOpen(open);
  };

  const refreshAndFindCreatedLicensee = async (criteria: {
    name: string;
    prefix: string;
    adminEmail: string;
  }) => {
    const response = await apiClient.getLicensees();
    if (!response.success || !Array.isArray(response.data)) return null;
    const rows = response.data as LicenseeRow[];
    setLicensees(rows);

    const normalizedName = criteria.name.trim().toLowerCase();
    const normalizedPrefix = criteria.prefix.trim().toUpperCase();
    const normalizedAdminEmail = criteria.adminEmail.trim().toLowerCase();
    return (
      rows.find((row) => String(row.prefix || "").toUpperCase() === normalizedPrefix) ||
      rows.find((row) => String(row.name || "").trim().toLowerCase() === normalizedName) ||
      rows.find((row) => {
        const pending = String(row.adminOnboarding?.pendingInvite?.email || "").toLowerCase();
        const active = String(row.adminOnboarding?.adminUser?.email || "").toLowerCase();
        return Boolean(normalizedAdminEmail && (pending === normalizedAdminEmail || active === normalizedAdminEmail));
      }) ||
      null
    );
  };

  const onCreateSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
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
        description: "Prefix must be 1-5 characters (A-Z / 0-9).",
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

    const wantMfg = Boolean(createForm.createManufacturerNow);
    const mfgName = createForm.manufacturerName.trim();
    const mfgEmail = createForm.manufacturerEmail.trim().toLowerCase();
    if (wantMfg && (!mfgName || !mfgEmail)) {
      toast({
        title: "Manufacturer details missing",
        description: "Provide Manufacturer Name and Email.",
        variant: "destructive",
      });
      return;
    }

    const requestedRangeCount = rangeEnd - rangeStart + 1;
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
          description: description || undefined,
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

      if (!createRes.success) {
        const friendly = classifyApiError(createRes);
        if (friendly.kind === "timeout_unknown") {
          const found = await refreshAndFindCreatedLicensee({ name, prefix, adminEmail });
          if (found) {
            if (showProvisioningProgress) progress.close();
            toast({
              title: "Brand created",
              description:
                "The server created the brand, but invite email status could not be confirmed. Review the brand row to copy or retry the invite.",
            });
            setIsCreateOpen(false);
            resetCreateForm();
            return;
          }
        }

        if (showProvisioningProgress) progress.close();
        toast({
          title: friendly.title,
          description: friendly.description,
          variant: friendly.destructive ? "destructive" : undefined,
        });
        return;
      }

      const createData = (createRes.data as any) || {};
      const inviteState = getInviteDeliveryState(createData);
      if (inviteState.inviteLink) setLatestInviteLink(inviteState.inviteLink);

      const licenseeId = createData?.licensee?.id as string;
      if (!licenseeId) throw new Error("Licensee created, but licenseeId was not returned.");

      const provisioningWarnings: string[] = [];
      if (wantMfg) {
        if (showProvisioningProgress) {
          progress.update({
            value: 34,
            indeterminate: false,
            phaseLabel: "User setup",
            detail: "Creating manufacturer access user...",
          });
        }

        const userRes = await apiClient.inviteUser({
          name: mfgName,
          email: mfgEmail,
          role: "MANUFACTURER",
          licenseeId,
        });
        if (!userRes.success) {
          const friendly = classifyApiError(userRes);
          provisioningWarnings.push(
            friendly.kind === "timeout_unknown"
              ? "Manufacturer invite status could not be confirmed. Open Manufacturers to review or retry."
              : "Manufacturer invite could not be completed. Open Manufacturers to retry."
          );
        } else {
          const manufacturerInvite = getInviteDeliveryState(userRes.data);
          if (manufacturerInvite.created && !manufacturerInvite.emailSent) {
            provisioningWarnings.push("Manufacturer invite link was created, but its email could not be sent.");
          }
        }
      }

      if (showProvisioningProgress) {
        progress.update({
          value: 56,
          indeterminate: true,
          phaseLabel: "Allocation",
          detail: `Allocating ${requestedRangeCount.toLocaleString()} QR codes...`,
        });
      }

      const allocRes = await apiClient.allocateQRRange({ licenseeId, startNumber: rangeStart, endNumber: rangeEnd });
      if (!allocRes.success) {
        const friendly = classifyApiError(allocRes);
        if (showProvisioningProgress) progress.close();
        toast({
          title: "Brand created, QR allocation needs retry",
          description:
            friendly.kind === "timeout_unknown"
              ? "Brand setup completed, but QR allocation status could not be confirmed. Refresh and retry allocation if the range is not present."
              : "Brand setup completed, but the initial QR range was not allocated. Allocate the range from the brand row.",
          variant: "destructive",
        });
        setIsCreateOpen(false);
        resetCreateForm();
        await load();
        return;
      }

      if (showProvisioningProgress) {
        await progress.complete(`Provisioning complete. ${requestedRangeCount.toLocaleString()} QR codes are ready.`);
      }

      const warningText = provisioningWarnings.length ? ` ${provisioningWarnings.join(" ")}` : "";
      toast({
      title: inviteState.emailSent
          ? "Brand created and invite email accepted."
          : "Brand created, but invite email delivery could not be confirmed.",
        description: inviteState.emailSent
          ? `${name} is ready. The mail provider accepted the invite for ${adminEmail}.${warningText}`
          : `${friendlyEmailDeliveryMessage(inviteState.emailErrorCode)} Copy the invite link or check SMTP settings.${warningText}`,
        variant: !inviteState.emailSent || provisioningWarnings.length ? "destructive" : undefined,
      });

      setIsCreateOpen(false);
      resetCreateForm();
      await load();
    } catch (error: any) {
      if (showProvisioningProgress) progress.close();
      const message = error?.message || "Error";
      const busy = isBusyErrorMessage(message);
      toast({
        title: busy ? "Batch busy" : "Create needs review",
        description: busy
          ? "Please retry when the current batch operation finishes."
          : "Refresh the brand list to confirm the latest state before retrying.",
        variant: "destructive",
      });
      await load();
    } finally {
      setCreating(false);
    }
  };

  return {
    isCreateOpen,
    creating,
    latestInviteLink,
    createForm,
    setLatestInviteLink,
    clearLatestInviteLink: () => setLatestInviteLink(""),
    updateCreateForm,
    openCreateDialog,
    handleCreateDialogOpenChange,
    onCreateSubmit,
  };
}
