import React from "react";

import { OperationProgressDialog } from "@/components/feedback/OperationProgressDialog";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { DialogEmptyState } from "@/components/ui/dialog-empty-state";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import type {
  AllocateRangeForm,
  CreateLicenseeForm,
  CreateUserForm,
  EditLicenseeForm,
} from "@/features/licensees/types";

type ProgressState = {
  open: boolean;
  title?: string;
  description?: string;
  phaseLabel?: string;
  detail?: string;
  speedLabel?: string;
  value?: number;
  indeterminate?: boolean;
};

type LicenseeDialogsProps = {
  isCreateOpen: boolean;
  onCreateDialogOpenChange: (open: boolean) => void;
  creating: boolean;
  latestInviteLink: string;
  onCopyInviteLink: () => void;
  createForm: CreateLicenseeForm;
  onCreateFormChange: React.Dispatch<React.SetStateAction<CreateLicenseeForm>>;
  onCreateSubmit: (event: React.FormEvent) => Promise<void> | void;
  isEditOpen: boolean;
  onEditDialogOpenChange: (open: boolean) => void;
  savingEdit: boolean;
  editForm: EditLicenseeForm | null;
  onEditFormChange: React.Dispatch<React.SetStateAction<EditLicenseeForm | null>>;
  onEditSubmit: (event: React.FormEvent) => Promise<void> | void;
  isUserOpen: boolean;
  onUserDialogOpenChange: (open: boolean) => void;
  creatingUser: boolean;
  userForm: CreateUserForm | null;
  onUserFormChange: React.Dispatch<React.SetStateAction<CreateUserForm | null>>;
  onUserSubmit: (event: React.FormEvent) => Promise<void> | void;
  rangeOpen: boolean;
  onRangeDialogOpenChange: (open: boolean) => void;
  rangeLoading: boolean;
  rangeForm: AllocateRangeForm | null;
  onRangeFormChange: React.Dispatch<React.SetStateAction<AllocateRangeForm | null>>;
  onRangeSubmit: (event: React.FormEvent) => Promise<void> | void;
  progressState: ProgressState;
};

export function LicenseeDialogs({
  isCreateOpen,
  onCreateDialogOpenChange,
  creating,
  latestInviteLink,
  onCopyInviteLink,
  createForm,
  onCreateFormChange,
  onCreateSubmit,
  isEditOpen,
  onEditDialogOpenChange,
  savingEdit,
  editForm,
  onEditFormChange,
  onEditSubmit,
  isUserOpen,
  onUserDialogOpenChange,
  creatingUser,
  userForm,
  onUserFormChange,
  onUserSubmit,
  rangeOpen,
  onRangeDialogOpenChange,
  rangeLoading,
  rangeForm,
  onRangeFormChange,
  onRangeSubmit,
  progressState,
}: LicenseeDialogsProps) {
  return (
    <>
      <Dialog open={isCreateOpen} onOpenChange={onCreateDialogOpenChange}>
        <DialogTrigger asChild>
          <span className="hidden" />
        </DialogTrigger>
        <DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-[720px]">
          <DialogHeader>
            <DialogTitle>Create New Licensee</DialogTitle>
            <DialogDescription>
              Creates the licensee + admin, allocates a dormant code range, and optionally creates the first manufacturer user.
            </DialogDescription>
          </DialogHeader>

          <form className="mt-4 space-y-4" onSubmit={onCreateSubmit}>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label>Organization Name</Label>
                <Input
                  value={createForm.name}
                  onChange={(event) => onCreateFormChange((previous) => ({ ...previous, name: event.target.value }))}
                  placeholder="Acme Corp"
                  disabled={creating}
                />
              </div>

              <div className="space-y-2">
                <Label>Prefix</Label>
                <Input
                  value={createForm.prefix}
                  onChange={(event) =>
                    onCreateFormChange((previous) => ({ ...previous, prefix: event.target.value.toUpperCase() }))
                  }
                  placeholder="A"
                  maxLength={5}
                  disabled={creating}
                />
                <p className="text-xs text-muted-foreground">1-5 chars, A-Z / 0-9 (e.g. A, ACME, 7X)</p>
              </div>
            </div>

            <div className="space-y-2">
              <Label>Description</Label>
              <Input
                value={createForm.description}
                onChange={(event) => onCreateFormChange((previous) => ({ ...previous, description: event.target.value }))}
                placeholder="Short note about this licensee"
                disabled={creating}
              />
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label>Brand Name</Label>
                <Input
                  value={createForm.brandName}
                  onChange={(event) => onCreateFormChange((previous) => ({ ...previous, brandName: event.target.value }))}
                  placeholder="Brand / label name"
                  disabled={creating}
                />
              </div>
              <div className="space-y-2">
                <Label>Location</Label>
                <Input
                  value={createForm.location}
                  onChange={(event) => onCreateFormChange((previous) => ({ ...previous, location: event.target.value }))}
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
                  onChange={(event) => onCreateFormChange((previous) => ({ ...previous, website: event.target.value }))}
                  placeholder="https://brand.example"
                  disabled={creating}
                />
              </div>
              <div className="space-y-2">
                <Label>Support Email</Label>
                <Input
                  type="email"
                  value={createForm.supportEmail}
                  onChange={(event) =>
                    onCreateFormChange((previous) => ({ ...previous, supportEmail: event.target.value }))
                  }
                  placeholder="support@brand.example"
                  disabled={creating}
                />
              </div>
            </div>

            <div className="space-y-2">
              <Label>Support Phone</Label>
              <Input
                value={createForm.supportPhone}
                onChange={(event) => onCreateFormChange((previous) => ({ ...previous, supportPhone: event.target.value }))}
                placeholder="+1 555 123 4567"
                disabled={creating}
              />
            </div>

            <div className="space-y-3 rounded-md border p-3">
              <p className="text-sm font-medium">Licensee Admin (required)</p>

              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label>Admin Name</Label>
                  <Input
                    value={createForm.adminName}
                    onChange={(event) => onCreateFormChange((previous) => ({ ...previous, adminName: event.target.value }))}
                    placeholder="Admin full name"
                    disabled={creating}
                  />
                </div>

                <div className="space-y-2">
                  <Label>Admin Email</Label>
                  <Input
                    type="email"
                    value={createForm.adminEmail}
                    onChange={(event) =>
                      onCreateFormChange((previous) => ({ ...previous, adminEmail: event.target.value }))
                    }
                    placeholder="admin@licensee.com"
                    disabled={creating}
                  />
                </div>

                <div className="col-span-2 rounded-md border border-emerald-200 bg-emerald-50 p-3 text-xs text-emerald-900">
                  Access setup: invite link only. We will email a one-time invite link so the admin can set a password securely.
                </div>
              </div>

              {latestInviteLink ? (
                <div className="rounded-md border border-emerald-200 bg-emerald-50 p-3">
                  <p className="text-sm font-medium text-emerald-900">Latest invite link ready</p>
                  <p className="mt-1 break-all text-xs text-emerald-800">{latestInviteLink}</p>
                  <Button type="button" variant="outline" className="mt-2" onClick={onCopyInviteLink}>
                    Copy invite link
                  </Button>
                </div>
              ) : null}
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label>Range Start</Label>
                <Input
                  type="number"
                  value={createForm.rangeStart}
                  onChange={(event) => onCreateFormChange((previous) => ({ ...previous, rangeStart: event.target.value }))}
                  disabled={creating}
                />
              </div>

              <div className="space-y-2">
                <Label>Range End</Label>
                <Input
                  type="number"
                  value={createForm.rangeEnd}
                  onChange={(event) => onCreateFormChange((previous) => ({ ...previous, rangeEnd: event.target.value }))}
                  disabled={creating}
                />
              </div>
            </div>

            <div className="space-y-3 rounded-md border p-3">
              <div className="flex items-center justify-between gap-3">
                <Label>Create Manufacturer now</Label>
                <Button
                  type="button"
                  variant={createForm.createManufacturerNow ? "default" : "secondary"}
                  onClick={() =>
                    onCreateFormChange((previous) => ({
                      ...previous,
                      createManufacturerNow: !previous.createManufacturerNow,
                    }))
                  }
                  disabled={creating}
                >
                  {createForm.createManufacturerNow ? "Yes" : "No"}
                </Button>
              </div>

              {createForm.createManufacturerNow ? (
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label>Manufacturer Name</Label>
                    <Input
                      value={createForm.manufacturerName}
                      onChange={(event) =>
                        onCreateFormChange((previous) => ({ ...previous, manufacturerName: event.target.value }))
                      }
                      placeholder="Factory A"
                      disabled={creating}
                    />
                  </div>

                  <div className="space-y-2">
                    <Label>Manufacturer Email</Label>
                    <Input
                      type="email"
                      value={createForm.manufacturerEmail}
                      onChange={(event) =>
                        onCreateFormChange((previous) => ({ ...previous, manufacturerEmail: event.target.value }))
                      }
                      placeholder="factory@acme.com"
                      disabled={creating}
                    />
                  </div>

                  <div className="col-span-2 rounded-md border border-emerald-200 bg-emerald-50 p-3 text-xs text-emerald-900">
                    Access setup: invite link only (expires in 24 hours).
                  </div>
                </div>
              ) : null}
            </div>

            <div className="flex justify-end gap-3 pt-2">
              <Button type="button" variant="outline" onClick={() => onCreateDialogOpenChange(false)} disabled={creating}>
                Cancel
              </Button>
              <Button type="submit" disabled={creating}>
                {creating ? "Creating..." : "Create"}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      <Dialog open={isEditOpen} onOpenChange={onEditDialogOpenChange}>
        <DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-[520px]">
          <DialogHeader>
            <DialogTitle>Edit Licensee</DialogTitle>
            <DialogDescription>Update name, support details, and status.</DialogDescription>
          </DialogHeader>

          {editForm ? (
            <form className="mt-4 space-y-4" onSubmit={onEditSubmit}>
              <div className="space-y-2">
                <Label>Organization Name</Label>
                <Input
                  value={editForm.name}
                  onChange={(event) =>
                    onEditFormChange((previous) => (previous ? { ...previous, name: event.target.value } : previous))
                  }
                />
              </div>

              <div className="space-y-2">
                <Label>Description</Label>
                <Input
                  value={editForm.description}
                  onChange={(event) =>
                    onEditFormChange((previous) =>
                      previous ? { ...previous, description: event.target.value } : previous
                    )
                  }
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label>Brand Name</Label>
                  <Input
                    value={editForm.brandName}
                    onChange={(event) =>
                      onEditFormChange((previous) =>
                        previous ? { ...previous, brandName: event.target.value } : previous
                      )
                    }
                  />
                </div>
                <div className="space-y-2">
                  <Label>Location</Label>
                  <Input
                    value={editForm.location}
                    onChange={(event) =>
                      onEditFormChange((previous) =>
                        previous ? { ...previous, location: event.target.value } : previous
                      )
                    }
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label>Official Website</Label>
                  <Input
                    value={editForm.website}
                    onChange={(event) =>
                      onEditFormChange((previous) =>
                        previous ? { ...previous, website: event.target.value } : previous
                      )
                    }
                  />
                </div>
                <div className="space-y-2">
                  <Label>Support Email</Label>
                  <Input
                    type="email"
                    value={editForm.supportEmail}
                    onChange={(event) =>
                      onEditFormChange((previous) =>
                        previous ? { ...previous, supportEmail: event.target.value } : previous
                      )
                    }
                  />
                </div>
              </div>

              <div className="space-y-2">
                <Label>Support Phone</Label>
                <Input
                  value={editForm.supportPhone}
                  onChange={(event) =>
                    onEditFormChange((previous) =>
                      previous ? { ...previous, supportPhone: event.target.value } : previous
                    )
                  }
                />
              </div>

              <div className="flex items-center justify-between">
                <Label>Status</Label>
                <Button
                  type="button"
                  variant={editForm.isActive ? "default" : "secondary"}
                  onClick={() =>
                    onEditFormChange((previous) =>
                      previous ? { ...previous, isActive: !previous.isActive } : previous
                    )
                  }
                >
                  {editForm.isActive ? "Active" : "Inactive"}
                </Button>
              </div>

              <div className="flex justify-end gap-3 pt-2">
                <Button type="button" variant="outline" onClick={() => onEditDialogOpenChange(false)} disabled={savingEdit}>
                  Cancel
                </Button>
                <Button type="submit" disabled={savingEdit}>
                  {savingEdit ? "Saving..." : "Save"}
                </Button>
              </div>
            </form>
          ) : null}
        </DialogContent>
      </Dialog>

      <Dialog open={isUserOpen} onOpenChange={onUserDialogOpenChange}>
        <DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-[520px]">
          <DialogHeader>
            <DialogTitle>Add user access</DialogTitle>
            <DialogDescription>Send a secure invite link for user onboarding.</DialogDescription>
          </DialogHeader>

          {userForm ? (
            <form className="mt-4 space-y-4" onSubmit={onUserSubmit}>
              <div className="rounded-md border border-emerald-200 bg-emerald-50 p-3 text-xs text-emerald-900">
                Access setup: invite link only (expires in 24 hours).
              </div>

              <div className="space-y-2">
                <Label>Name</Label>
                <Input
                  value={userForm.name}
                  onChange={(event) =>
                    onUserFormChange((previous) => (previous ? { ...previous, name: event.target.value } : previous))
                  }
                  placeholder="Full name"
                  disabled={creatingUser}
                />
              </div>

              <div className="space-y-2">
                <Label>Email</Label>
                <Input
                  type="email"
                  value={userForm.email}
                  onChange={(event) =>
                    onUserFormChange((previous) => (previous ? { ...previous, email: event.target.value } : previous))
                  }
                  placeholder="email@example.com"
                  disabled={creatingUser}
                />
              </div>

              <div className="space-y-2">
                <Label>Role</Label>
                <Select
                  value={userForm.role}
                  onValueChange={(value) =>
                    onUserFormChange((previous) => (previous ? { ...previous, role: value as any } : previous))
                  }
                  disabled={creatingUser}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="Select role" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="MANUFACTURER">Manufacturer user</SelectItem>
                    <SelectItem value="LICENSEE_ADMIN">Licensee user</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="flex justify-end gap-3 pt-2">
                <Button type="button" variant="outline" onClick={() => onUserDialogOpenChange(false)} disabled={creatingUser}>
                  Cancel
                </Button>
                <Button type="submit" disabled={creatingUser}>
                  {creatingUser ? "Sending invite..." : "Send invite"}
                </Button>
              </div>
            </form>
          ) : null}
        </DialogContent>
      </Dialog>

      <Dialog
        open={rangeOpen}
        onOpenChange={(open) => {
          onRangeDialogOpenChange(open);
          if (!open) onRangeFormChange(null);
        }}
      >
        <DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-[520px]">
          <DialogHeader>
            <DialogTitle>Allocate Code Range</DialogTitle>
            <DialogDescription>Adds new codes to the licensee pool in DORMANT state only.</DialogDescription>
          </DialogHeader>

          {!rangeForm ? (
            <DialogEmptyState
              title="Select a licensee before allocating codes"
              description="Close this dialog, reopen Allocate Code Range from the correct licensee row, and MSCQR will load the latest range history for that tenant."
              onClose={() => onRangeDialogOpenChange(false)}
            />
          ) : (
            <form className="mt-2 space-y-4" onSubmit={onRangeSubmit}>
              <div className="space-y-1 rounded-md border p-3 text-sm">
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
                  onClick={() => onRangeFormChange((previous) => (previous ? { ...previous, mode: "quantity" } : previous))}
                >
                  By quantity
                </Button>
                <Button
                  type="button"
                  size="sm"
                  variant={rangeForm.mode === "range" ? "default" : "outline"}
                  onClick={() =>
                    onRangeFormChange((previous) =>
                      previous
                        ? {
                            ...previous,
                            mode: "range",
                            startNumber: previous.startNumber || String(previous.suggestedNextStart),
                          }
                        : previous
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
                    onChange={(event) =>
                      onRangeFormChange((previous) => (previous ? { ...previous, quantity: event.target.value } : previous))
                    }
                  />
                  <p className="text-xs text-muted-foreground">
                    The backend allocates from the next available index automatically.
                  </p>
                </div>
              ) : (
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label>Start Number</Label>
                    <Input
                      type="number"
                      value={rangeForm.startNumber}
                      onChange={(event) =>
                        onRangeFormChange((previous) =>
                          previous ? { ...previous, startNumber: event.target.value } : previous
                        )
                      }
                    />
                  </div>
                  <div className="space-y-2">
                    <Label>End Number</Label>
                    <Input
                      type="number"
                      value={rangeForm.endNumber}
                      onChange={(event) =>
                        onRangeFormChange((previous) =>
                          previous ? { ...previous, endNumber: event.target.value } : previous
                        )
                      }
                    />
                  </div>
                </div>
              )}

              <div className="space-y-2">
                <Label>Received Batch Name (optional)</Label>
                <Input
                  value={rangeForm.receivedBatchName}
                  onChange={(event) =>
                    onRangeFormChange((previous) =>
                      previous ? { ...previous, receivedBatchName: event.target.value } : previous
                    )
                  }
                  placeholder="e.g. March-2026 Topup"
                />
                <p className="text-xs text-muted-foreground">
                  If empty, the system uses an auto name from the allocated range.
                </p>
              </div>

              <div className="flex justify-end gap-3 pt-2">
                <Button type="button" variant="outline" onClick={() => onRangeDialogOpenChange(false)} disabled={rangeLoading}>
                  Cancel
                </Button>
                <Button type="submit" disabled={rangeLoading}>
                  {rangeLoading ? "Allocating..." : "Allocate Codes"}
                </Button>
              </div>
            </form>
          )}
        </DialogContent>
      </Dialog>

      <OperationProgressDialog
        open={progressState.open}
        title={progressState.title || ""}
        description={progressState.description || ""}
        phaseLabel={progressState.phaseLabel}
        detail={progressState.detail}
        speedLabel={progressState.speedLabel}
        value={progressState.value}
        indeterminate={progressState.indeterminate}
      />
    </>
  );
}
